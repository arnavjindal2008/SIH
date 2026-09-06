import datetime
import hashlib
import json
import os
import time
import uuid
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.models.db_models import (
    Analysis,
    EmailSession,
    SecurityFinding,
    X509Certificate,
    ProtocolMetric,
)
from backend.app.core.pcap_validator import PcapValidator
from backend.app.core.packet_parser import PcapParserEngine, ParsedEmailSession, PacketProcessingMetrics
from backend.app.core.cert_inspector import CertificateInspector, InspectedCertificate
from backend.app.core.crypto_rules import CryptographicRulesEngine
from backend.app.core.ml_anomaly import SessionAnomalyDetector

class AnalyzerEngine:
    """Master pipeline orchestrating PCAP validation, parsing, cryptographic analysis, and persistence."""

    @staticmethod
    async def analyze_file(
        filepath: str,
        filename: str,
        db: AsyncSession,
        analysis_id: Optional[str] = None,
    ) -> Analysis:
        start_time = time.time()
        if not analysis_id:
            analysis_id = f"an_{uuid.uuid4().hex[:12]}"

        # Pre-validation check: Reject empty, corrupted, or unsupported files
        val_res = PcapValidator.validate_file(filepath)
        if not val_res.is_valid:
            raise ValueError(val_res.error_message or "PCAP file validation failed.")

        # Calculate file metrics
        file_size = val_res.file_size
        sha256_hash = ""
        if os.path.exists(filepath):
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha256_hash = h.hexdigest()

        # Create initial record
        analysis = Analysis(
            id=analysis_id,
            filename=filename,
            file_path=filepath,
            file_size=file_size,
            sha256_hash=sha256_hash,
            status="PROCESSING",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(analysis)
        await db.commit()

        try:
            # 1. Parse PCAP with safe frame inspection and metrics extraction
            metrics = PcapParserEngine.parse_pcap(filepath)
            parsed_sessions = metrics.sessions

            # 2. Inspect X.509 Certificates
            cert_map: dict[str, list[InspectedCertificate]] = {}
            db_certs: list[X509Certificate] = []
            for s in parsed_sessions:
                cert_map[s.session_id] = []
                for chain_idx, der in enumerate(s.raw_certificates):
                    inspected = CertificateInspector.inspect_der(der, chain_index=chain_idx)
                    if inspected:
                        cert_map[s.session_id].append(inspected)
                        cert_record = X509Certificate(
                            id=f"cert_{uuid.uuid4().hex[:12]}",
                            analysis_id=analysis_id,
                            session_id=s.session_id,
                            fingerprint_sha256=inspected.fingerprint_sha256,
                            subject_cn=inspected.subject_cn,
                            subject_org=inspected.subject_org,
                            subject_dn=inspected.subject_dn,
                            issuer_cn=inspected.issuer_cn,
                            issuer_org=inspected.issuer_org,
                            issuer_dn=inspected.issuer_dn,
                            san_list=json.dumps(inspected.san_list),
                            valid_from=inspected.valid_from,
                            valid_to=inspected.valid_to,
                            is_expired=inspected.is_expired,
                            validity_status=inspected.validity_status,
                            days_remaining=inspected.days_remaining,
                            is_self_signed=inspected.is_self_signed,
                            key_algorithm=inspected.key_algorithm,
                            key_size=inspected.key_size,
                            signature_algorithm=inspected.signature_algorithm,
                            serial_number=inspected.serial_number,
                            trust_warnings=json.dumps(inspected.trust_warnings),
                            raw_pem=inspected.raw_pem,
                            chain_index=inspected.chain_index,
                            chain_info=inspected.chain_info,
                            observed_context=inspected.observed_context,
                        )
                        db_certs.append(cert_record)

            # 3. Passive ML Anomaly Detection (scikit-learn IsolationForest)
            ml_detector = SessionAnomalyDetector()
            ml_detector.fit_and_score(parsed_sessions, cert_map=cert_map)

            # 4. Cryptographic Security Rules Evaluation
            all_findings_raw = []
            for s in parsed_sessions:
                findings_for_session = CryptographicRulesEngine.evaluate_session(
                    session=s,
                    analysis_id=analysis_id,
                    cert_map=cert_map,
                )
                all_findings_raw.extend(findings_for_session)

            # 5. Calculate Metrics and 0-100 Score Breakdown
            encrypted_sessions = sum(1 for s in parsed_sessions if s.is_encrypted)
            total_sessions = len(parsed_sessions)
            encryption_ratio = (encrypted_sessions / total_sessions) if total_sessions > 0 else 0.0
            
            score_results = CryptographicRulesEngine.calculate_detailed_security_scores(
                findings=all_findings_raw,
                total_sessions=total_sessions,
                encrypted_sessions=encrypted_sessions,
                sessions=parsed_sessions,
            )

            # 6. Build Database Session Records
            db_sessions: list[EmailSession] = []
            for idx, s in enumerate(parsed_sessions):
                db_sess = EmailSession(
                    id=s.session_id,
                    analysis_id=analysis_id,
                    session_index=idx + 1,
                    protocol=s.protocol,
                    transport_protocol=getattr(s, "transport_protocol", "TCP"),
                    tcp_stream_id=getattr(s, "tcp_stream_id", 0),
                    src_ip=s.src_ip,
                    src_port=s.src_port,
                    dst_ip=s.dst_ip,
                    dst_port=s.dst_port,
                    is_encrypted=s.is_encrypted,
                    encryption_mode=getattr(s, "encryption_mode", "UNKNOWN"),
                    tls_version=s.tls_version,
                    cipher_suite=s.cipher_suite,
                    cipher_suite_code=s.cipher_suite_code,
                    key_exchange=s.key_exchange,
                    forward_secrecy=s.forward_secrecy,
                    elliptic_curve=getattr(s, "elliptic_curve", "Not observed"),
                    signature_algorithm=getattr(s, "signature_algorithm", "Not observed"),
                    handshake_status=getattr(s, "handshake_status", "Not observed"),
                    tls_alerts=json.dumps(getattr(s, "tls_alerts", [])) if isinstance(getattr(s, "tls_alerts", []), list) else str(getattr(s, "tls_alerts", "")),
                    session_resumption=getattr(s, "session_resumption", "Not observed"),
                    starttls_supported=getattr(s, "starttls_supported", False),
                    starttls_requested=s.starttls_requested,
                    starttls_accepted=s.starttls_accepted,
                    tls_handshake_detected=getattr(s, "tls_handshake_detected", False),
                    starttls_evidence="; ".join(getattr(s, "starttls_evidence", [])) if isinstance(getattr(s, "starttls_evidence", None), list) else str(getattr(s, "starttls_evidence", "") or ""),
                    sni=s.sni,
                    alpn=s.alpn,
                    packet_count=s.packet_count,
                    byte_count=s.byte_count,
                    duration_ms=s.duration_ms,
                    client_hello_seen=s.client_hello_seen,
                    server_hello_seen=s.server_hello_seen,
                    certificate_seen=s.certificate_seen,
                    is_anomalous=s.is_anomalous,
                    anomaly_score=s.anomaly_score,
                    anomaly_status=getattr(s, "anomaly_status", "NORMAL"),
                    risk_priority=getattr(s, "risk_priority", "INFORMATIONAL"),
                    anomaly_explanation=getattr(s, "anomaly_explanation", ""),
                    timestamp_first=s.timestamp_first,
                    timestamp_last=s.timestamp_last,
                    status=getattr(s, "status", "UNKNOWN"),
                    protocol_evidence=json.dumps(getattr(s, "protocol_evidence", [])),
                )
                db_sessions.append(db_sess)

            # 7. Build Database Findings Records
            db_findings: list[SecurityFinding] = []
            for f in all_findings_raw:
                db_find = SecurityFinding(
                    id=f["id"],
                    analysis_id=analysis_id,
                    session_id=f.get("session_id"),
                    certificate_id=f.get("certificate_id"),
                    severity=f["severity"],
                    category=f["category"],
                    title=f["title"],
                    description=f["description"],
                    evidence=f.get("evidence", ""),
                    technical_details=f["technical_details"],
                    affected_component=f["affected_component"],
                    remediation=f.get("recommendation", f.get("remediation", "")),
                    recommendation=f.get("recommendation", f.get("remediation", "")),
                    cve_reference=f.get("cve_reference"),
                    created_at=datetime.datetime.now(datetime.timezone.utc),
                )
                db_findings.append(db_find)

            # 8. Protocol Summaries
            protocol_groups: dict[str, list[ParsedEmailSession]] = {}
            for s in parsed_sessions:
                protocol_groups.setdefault(s.protocol, []).append(s)

            db_protocols: list[ProtocolMetric] = []
            for proto_name, proto_sessions in protocol_groups.items():
                p_enc = sum(1 for s in proto_sessions if s.is_encrypted)
                p_plain = len(proto_sessions) - p_enc
                p_pkts = sum(s.packet_count for s in proto_sessions)
                p_bytes = sum(s.byte_count for s in proto_sessions)
                
                tls_vers: dict[str, int] = {}
                ciphers: dict[str, int] = {}
                for s in proto_sessions:
                    if s.tls_version:
                        tls_vers[s.tls_version] = tls_vers.get(s.tls_version, 0) + 1
                    if s.cipher_suite:
                        ciphers[s.cipher_suite] = ciphers.get(s.cipher_suite, 0) + 1

                pm = ProtocolMetric(
                    id=f"pm_{uuid.uuid4().hex[:12]}",
                    analysis_id=analysis_id,
                    protocol=proto_name,
                    session_count=len(proto_sessions),
                    packet_count=p_pkts,
                    byte_count=p_bytes,
                    encrypted_sessions=p_enc,
                    plaintext_sessions=p_plain,
                    tls_versions_json=json.dumps(tls_vers),
                    ciphers_json=json.dumps(ciphers),
                )
                db_protocols.append(pm)

            # Persist all objects
            db.add_all(db_sessions)
            db.add_all(db_certs)
            db.add_all(db_findings)
            db.add_all(db_protocols)

            # Update analysis record with real extracted counts and security score breakdown
            analysis.packet_count = metrics.total_packets
            analysis.total_packets = metrics.total_packets
            analysis.ip_packet_count = metrics.ip_packet_count
            analysis.tcp_packet_count = metrics.tcp_packet_count
            analysis.tcp_stream_count = metrics.tcp_stream_count
            analysis.email_packets = metrics.email_packet_count
            analysis.session_count = total_sessions
            analysis.finding_count = len(db_findings)
            analysis.cert_count = len(db_certs)
            
            # Phase 5 security posture scores
            analysis.security_score = score_results["overall_score"]
            analysis.tls_score = score_results["tls_score"]
            analysis.certificate_score = score_results["certificate_score"]
            analysis.cipher_score = score_results["cipher_score"]
            analysis.protocol_score = score_results["protocol_score"]
            analysis.starttls_score = score_results["starttls_score"]
            analysis.score_label = score_results["score_label"]
            analysis.score_confidence_note = score_results["score_confidence_note"]
            analysis.ai_mode_note = SessionAnomalyDetector.PROTOTYPE_NOTE

            analysis.encryption_ratio = round(encryption_ratio, 3)
            analysis.duration_seconds = round(time.time() - start_time, 2)
            analysis.status = "COMPLETED"
            analysis.completed_at = datetime.datetime.now(datetime.timezone.utc)

            await db.commit()
            await db.refresh(analysis)
            return analysis

        except Exception as e:
            analysis.status = "FAILED"
            analysis.error_message = str(e)
            analysis.duration_seconds = round(time.time() - start_time, 2)
            await db.commit()
            raise e
