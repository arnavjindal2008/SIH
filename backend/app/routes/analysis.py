import datetime
import json
import os
import shutil
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.db_models import (
    Analysis,
    EmailSession,
    SecurityFinding,
    X509Certificate,
    ProtocolMetric,
)
from backend.app.core.pcap_validator import PcapValidator
from backend.app.models.schemas import (
    AnalysisSummary,
    AnalysisDetailResponse,
    SessionResponse,
    FindingResponse,
    CertificateResponse,
    ProtocolSummaryResponse,
    ProtocolMetricResponse,
    RecommendationResponse,
    RecommendationItem,
    PcapValidationResponse,
)
from backend.app.core.analyzer_engine import AnalyzerEngine
from backend.app.core.report_generator import ReportGenerator

router = APIRouter()

def _format_certificate(c: X509Certificate) -> CertificateResponse:
    san = json.loads(c.san_list) if c.san_list else []
    warnings = json.loads(c.trust_warnings) if c.trust_warnings else []
    return CertificateResponse(
        id=c.id,
        certificate_id=c.id,
        analysis_id=c.analysis_id,
        session_id=c.session_id,
        fingerprint_sha256=c.fingerprint_sha256,
        subject_cn=c.subject_cn,
        subject_org=c.subject_org,
        subject_dn=c.subject_dn,
        issuer_cn=c.issuer_cn,
        issuer_org=c.issuer_org,
        issuer_dn=c.issuer_dn,
        san_list=san,
        valid_from=c.valid_from,
        valid_to=c.valid_to,
        is_expired=c.is_expired,
        validity_status=c.validity_status or ("EXPIRED" if c.is_expired else "VALID"),
        days_remaining=c.days_remaining,
        is_self_signed=c.is_self_signed,
        key_algorithm=c.key_algorithm,
        key_size=c.key_size,
        signature_algorithm=c.signature_algorithm,
        serial_number=c.serial_number,
        trust_warnings=warnings,
        raw_pem=c.raw_pem,
        chain_index=c.chain_index if c.chain_index is not None else 0,
        chain_info=c.chain_info or "Server / Leaf Certificate",
        observed_context=c.observed_context or "Certificate observed in capture",
    )

@router.post("/pcap/validate", response_model=PcapValidationResponse)
async def validate_pcap_preflight(file: UploadFile = File(...)):
    """
    Pre-flight validation for an uploaded PCAP/PCAPNG file.
    Validates magic numbers, header integrity, and decodability before full analysis.
    """
    filename = file.filename or "unknown.pcap"
    ext = os.path.splitext(filename)[1].lower()
    tshark_installed = shutil.which("tshark") is not None
    engine_note = "Wireshark CLI (tshark) is available." if tshark_installed else "Wireshark CLI (tshark) not found in PATH; falling back to Scapy native Libpcap engine."

    if ext not in [".pcap", ".pcapng", ".cap"]:
        return PcapValidationResponse(
            is_valid=False,
            filename=filename,
            file_size=0,
            format="unsupported",
            error=f"Unsupported format '{ext}'. Only .pcap and .pcapng files are supported.",
            tshark_available=tshark_installed,
            engine_note=engine_note,
        )

    temp_path = settings.UPLOADS_DIR / f"temp_val_{uuid.uuid4().hex[:8]}_{filename}"
    try:
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        val_res = PcapValidator.validate_file(str(temp_path))
        return PcapValidationResponse(
            is_valid=val_res.is_valid,
            filename=filename,
            file_size=val_res.file_size,
            format=val_res.format,
            error=val_res.error_message,
            tshark_available=tshark_installed,
            engine_note=engine_note,
        )
    finally:
        if temp_path.exists():
            try:
                os.remove(temp_path)
            except Exception:
                pass


@router.post("/analyze", response_model=AnalysisSummary)
async def analyze_pcap(
    file: Optional[UploadFile] = File(None),
    sample_path: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate forensic passive analysis on an uploaded PCAP/PCAPNG file
    or an existing sample file in data/samples.
    """
    analysis_id = f"an_{uuid.uuid4().hex[:12]}"
    
    if file:
        filename = file.filename or "capture.pcap"
        ext = os.path.splitext(filename)[1].lower()
        if ext not in [".pcap", ".pcapng", ".cap"]:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format '{ext}'. Only .pcap and .pcapng packet captures are supported."
            )

        saved_path = settings.UPLOADS_DIR / f"{analysis_id}_{filename}"
        with open(saved_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        target_path = str(saved_path)
        display_name = filename
    elif sample_path:
        target_path = sample_path
        if not os.path.exists(target_path):
            raise HTTPException(status_code=404, detail="Specified sample PCAP file does not exist.")
        display_name = os.path.basename(target_path)
    else:
        raise HTTPException(status_code=400, detail="Either a PCAP file upload or a sample_path must be provided.")

    # Strict multi-layer validation
    val_res = PcapValidator.validate_file(target_path)
    if not val_res.is_valid:
        if file and os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=val_res.error_message or "Invalid PCAP file.")

    try:
        analysis = await AnalyzerEngine.analyze_file(
            filepath=target_path,
            filename=display_name,
            db=db,
            analysis_id=analysis_id,
        )
        return analysis
    except ValueError as ve:
        if file and os.path.exists(target_path):
            try:
                os.remove(target_path)
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@router.get("/analyses", response_model=list[AnalysisSummary])
async def list_analyses(db: AsyncSession = Depends(get_db)):
    """List all historical PCAP analyses ordered by creation time."""
    stmt = select(Analysis).order_by(desc(Analysis.created_at)).limit(100)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/analysis/{analysis_id}", response_model=AnalysisDetailResponse)
async def get_analysis_detail(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve top-level forensic metadata, severity breakdown, and high-level analysis state."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # Fetch severity counts
    findings_stmt = select(SecurityFinding).where(SecurityFinding.analysis_id == analysis_id)
    findings_res = await db.execute(findings_stmt)
    findings = findings_res.scalars().all()

    breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.severity.upper()
        if sev in breakdown:
            breakdown[sev] += 1

    # Fetch recent sessions (first 10)
    sess_stmt = select(EmailSession).where(EmailSession.analysis_id == analysis_id).order_by(EmailSession.session_index).limit(10)
    sess_res = await db.execute(sess_stmt)
    recent_sessions = sess_res.scalars().all()

    # Fetch certificates
    cert_stmt = select(X509Certificate).where(X509Certificate.analysis_id == analysis_id)
    cert_res = await db.execute(cert_stmt)
    db_certs = cert_res.scalars().all()

    cert_responses = [_format_certificate(c) for c in db_certs]

    finding_responses = [FindingResponse.model_validate(f) for f in findings[:10]]
    session_responses = [SessionResponse.model_validate(s) for s in recent_sessions]

    return AnalysisDetailResponse(
        id=analysis.id,
        analysis_id=analysis.id,
        filename=analysis.filename,
        file_size=analysis.file_size,
        file_size_bytes=analysis.file_size_bytes,
        sha256_hash=analysis.sha256_hash,
        status=analysis.status,
        error_message=analysis.error_message,
        packet_count=analysis.packet_count,
        total_packets=analysis.total_packets,
        ip_packet_count=analysis.ip_packet_count or 0,
        tcp_packet_count=analysis.tcp_packet_count or 0,
        tcp_stream_count=analysis.tcp_stream_count or 0,
        email_packets=analysis.email_packets,
        session_count=analysis.session_count,
        finding_count=analysis.finding_count,
        cert_count=analysis.cert_count,
        security_score=analysis.security_score,
        encryption_ratio=analysis.encryption_ratio,
        duration_seconds=analysis.duration_seconds,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        severity_breakdown=breakdown,
        recent_findings=finding_responses,
        recent_sessions=session_responses,
        certificates=cert_responses,
    )


@router.get("/analysis/{analysis_id}/sessions", response_model=list[SessionResponse])
async def get_analysis_sessions(
    analysis_id: str,
    protocol: Optional[str] = Query(None),
    is_encrypted: Optional[bool] = Query(None),
    is_anomalous: Optional[bool] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve reconstructed communication sessions with protocol filtering (SMTP, IMAP, POP3, UNKNOWN)."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    stmt = select(EmailSession).where(EmailSession.analysis_id == analysis_id)
    if protocol and protocol.upper() != "ALL":
        proto_up = protocol.upper()
        if proto_up == "SMTP":
            stmt = stmt.where(EmailSession.protocol.in_(["SMTP", "SMTPS"]))
        elif proto_up == "IMAP":
            stmt = stmt.where(EmailSession.protocol.in_(["IMAP", "IMAPS"]))
        elif proto_up == "POP3":
            stmt = stmt.where(EmailSession.protocol.in_(["POP3", "POP3S"]))
        elif proto_up == "UNKNOWN":
            stmt = stmt.where(func.upper(EmailSession.protocol) == "UNKNOWN")
        else:
            stmt = stmt.where(func.upper(EmailSession.protocol) == proto_up)
    if is_encrypted is not None:
        stmt = stmt.where(EmailSession.is_encrypted == is_encrypted)
    if is_anomalous is not None:
        stmt = stmt.where(EmailSession.is_anomalous == is_anomalous)
    if status and status.upper() != "ALL":
        stmt = stmt.where(func.upper(EmailSession.status) == status.upper())

    stmt = stmt.order_by(EmailSession.session_index)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/analysis/{analysis_id}/findings", response_model=list[FindingResponse])
async def get_analysis_findings(
    analysis_id: str,
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    tls_version: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve cryptographic vulnerabilities and compliance findings with session protocol and TLS correlation."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    stmt = (
        select(
            SecurityFinding,
            EmailSession.protocol.label("sess_proto"),
            EmailSession.tls_version.label("sess_tls"),
        )
        .outerjoin(EmailSession, SecurityFinding.session_id == EmailSession.id)
        .where(SecurityFinding.analysis_id == analysis_id)
    )
    if severity and severity.upper() != "ALL":
        stmt = stmt.where(func.upper(SecurityFinding.severity) == severity.upper())
    if category and category.upper() != "ALL":
        stmt = stmt.where(func.upper(SecurityFinding.category) == category.upper())
    if session_id and session_id.upper() != "ALL":
        stmt = stmt.where(SecurityFinding.session_id == session_id)
    if protocol and protocol.upper() != "ALL":
        stmt = stmt.where(func.upper(EmailSession.protocol).like(f"%{protocol.upper()}%"))
    if tls_version and tls_version.upper() != "ALL":
        if tls_version.upper() == "NONE":
            stmt = stmt.where((EmailSession.tls_version.is_(None)) | (EmailSession.tls_version == "Not observed") | (EmailSession.tls_version == "None"))
        else:
            stmt = stmt.where(func.upper(EmailSession.tls_version) == tls_version.upper())
    if search:
        s_pat = f"%{search.lower()}%"
        stmt = stmt.where(
            (func.lower(SecurityFinding.title).like(s_pat))
            | (func.lower(SecurityFinding.description).like(s_pat))
            | (func.lower(SecurityFinding.evidence).like(s_pat))
            | (func.lower(SecurityFinding.rfc_reference).like(s_pat))
            | (func.lower(SecurityFinding.category).like(s_pat))
        )

    stmt = stmt.order_by(desc(SecurityFinding.created_at))
    result = await db.execute(stmt)
    rows = result.all()

    findings_out = []
    for f, sess_proto, sess_tls in rows:
        risk_label = f.cve_reference or ("HIGH EXPOSURE" if f.severity in ["Critical", "High"] else "MEDIUM CONCERN" if f.severity == "Medium" else "LOW RISK")
        p_val = sess_proto or ("SMTP" if "SMTP" in f.title.upper() else ("IMAP" if "IMAP" in f.title.upper() else ("POP3" if "POP3" in f.title.upper() else "N/A")))
        t_val = sess_tls or ("TLS 1.0" if "TLS 1.0" in f.title else ("SSL 3.0" if "SSL 3.0" in f.title else "None"))
        fr = FindingResponse(
            id=f.id,
            finding_id=f.id,
            analysis_id=f.analysis_id,
            session_id=f.session_id,
            certificate_id=f.certificate_id,
            severity=f.severity,
            category=f.category,
            title=f.title,
            description=f.description,
            evidence=f.evidence or f.technical_details,
            technical_details=f.technical_details,
            affected_component=f.affected_component,
            rfc_reference=f.rfc_reference,
            remediation=f.remediation or f.recommendation or "",
            recommendation=f.recommendation or f.remediation or "",
            cve_reference=f.cve_reference,
            created_at=f.created_at,
            protocol=p_val,
            tls_version=t_val,
            status="DETECTED",
            risk=risk_label,
        )
        findings_out.append(fr)
    return findings_out


@router.get("/analysis/{analysis_id}/certificates", response_model=list[CertificateResponse])
async def get_analysis_certificates(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve extracted X.509 certificates and trust diagnostics."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    stmt = select(X509Certificate).where(X509Certificate.analysis_id == analysis_id)
    result = await db.execute(stmt)
    certs = result.scalars().all()

    return [_format_certificate(c) for c in certs]


@router.get("/analysis/{analysis_id}/protocols", response_model=ProtocolSummaryResponse)
async def get_analysis_protocols(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve protocol-level breakdown, encryption percentages, and cipher suite distribution."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    stmt = select(ProtocolMetric).where(ProtocolMetric.analysis_id == analysis_id)
    result = await db.execute(stmt)
    metrics = result.scalars().all()

    metric_responses = []
    total_sess = 0
    enc_sess = 0
    plain_sess = 0
    tls_distribution: dict[str, int] = {}
    cipher_distribution: dict[str, int] = {}

    for m in metrics:
        total_sess += m.session_count
        enc_sess += m.encrypted_sessions
        plain_sess += m.plaintext_sessions
        
        tls_map = json.loads(m.tls_versions_json) if m.tls_versions_json else {}
        cipher_map = json.loads(m.ciphers_json) if m.ciphers_json else {}

        for v, cnt in tls_map.items():
            tls_distribution[v] = tls_distribution.get(v, 0) + cnt
        for c, cnt in cipher_map.items():
            cipher_distribution[c] = cipher_distribution.get(c, 0) + cnt

        rate = (m.encrypted_sessions / m.session_count) if m.session_count > 0 else 0.0
        metric_responses.append(ProtocolMetricResponse(
            protocol=m.protocol,
            session_count=m.session_count,
            packet_count=m.packet_count,
            byte_count=m.byte_count,
            encrypted_sessions=m.encrypted_sessions,
            plaintext_sessions=m.plaintext_sessions,
            encryption_rate=round(rate, 3),
            tls_versions=tls_map,
            ciphers=cipher_map,
        ))

    overall_ratio = (enc_sess / total_sess) if total_sess > 0 else 0.0

    return ProtocolSummaryResponse(
        analysis_id=analysis_id,
        protocols=metric_responses,
        total_sessions=total_sess,
        encrypted_sessions=enc_sess,
        plaintext_sessions=plain_sess,
        overall_encryption_ratio=round(overall_ratio, 3),
        tls_version_distribution=tls_distribution,
        cipher_suite_distribution=cipher_distribution,
    )


@router.get("/analysis/{analysis_id}/recommendations", response_model=RecommendationResponse)
async def get_analysis_recommendations(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve actionable security recommendations derived from actual detected findings."""
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    findings_stmt = select(SecurityFinding).where(SecurityFinding.analysis_id == analysis_id)
    findings_res = await db.execute(findings_stmt)
    findings = findings_res.scalars().all()

    # Group findings and affected sessions by category
    category_counts: dict[str, int] = {}
    category_sessions: dict[str, list[str]] = {}
    for f in findings:
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
        if f.session_id:
            category_sessions.setdefault(f.category, []).append(f.session_id)

    recs: list[RecommendationItem] = []

    # 1. Deprecated TLS 1.0 / 1.1 (RFC 8996)
    if "DEPRECATED_TLS_VERSION" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("DEPRECATED_TLS_VERSION", [])))
        recs.append(RecommendationItem(
            id="rec_tls_upgrade",
            priority="IMMEDIATE",
            title="Disable Obsolete TLS 1.0 and 1.1 Across Mail Transfer Agents",
            finding="TLS 1.0 / 1.1 Protocol Usage",
            finding_category="DEPRECATED_TLS_VERSION",
            recommended_action="Disable TLS 1.0 and require TLS 1.2/1.3.",
            reason="RFC 8996 formally deprecated TLS 1.0 and 1.1 due to vulnerability to BEAST/POODLE downgrade exploits and lack of modern authenticated encryption.",
            description="Deprecated TLS protocols were negotiated, exposing mail sessions to downgrade and decryption attacks.",
            remediation_steps=[
                "Explicitly set `ssl_protocols TLSv1.2 TLSv1.3;` on mail proxies/servers.",
                "Enforce TLS 1.3 as the default preferred handshake protocol.",
                "Verify compatibility with legacy external relays and configure isolated relay policies if necessary.",
            ],
            compliance_standards=["RFC 8996", "NIST SP 800-52r2 Section 3.1", "PCI-DSS 4.0 Req 8.3"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["DEPRECATED_TLS_VERSION"],
        ))

    # 2. Weak Cipher Suites (RFC 7525 / NIST SP 800-52r2)
    if "WEAK_CIPHER_SUITE" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("WEAK_CIPHER_SUITE", [])))
        recs.append(RecommendationItem(
            id="rec_cipher_hardening",
            priority="HIGH",
            title="Modernize Cipher Suite Whitelists with AEAD Algorithms",
            finding="Weak or Insecure Cipher Suite",
            finding_category="WEAK_CIPHER_SUITE",
            recommended_action="Disable deprecated/weak cipher suites and use modern authenticated encryption.",
            reason="NIST SP 800-52r2 and RFC 7525 require AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) to eliminate padding oracle and CBC weaknesses.",
            description="Legacy ciphers (RC4, 3DES, or CBC-mode ciphers) were accepted during TLS handshake negotiation.",
            remediation_steps=[
                "Remove all RC4, 3DES, and DES ciphers from MTA cipher configurations.",
                "Prioritize AES-256-GCM, AES-128-GCM, and ChaCha20-Poly1305 AEAD ciphers.",
                "Enforce ECDHE for ephemeral key exchanges to ensure forward secrecy.",
            ],
            compliance_standards=["RFC 7525", "NIST SP 800-52r2 Section 3.3"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["WEAK_CIPHER_SUITE"],
        ))

    # 3. No Forward Secrecy (Static RSA)
    if "NO_FORWARD_SECRECY" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("NO_FORWARD_SECRECY", [])))
        recs.append(RecommendationItem(
            id="rec_forward_secrecy",
            priority="HIGH",
            title="Enforce Perfect Forward Secrecy for Key Exchanges",
            finding="Absence of Perfect Forward Secrecy (PFS)",
            finding_category="NO_FORWARD_SECRECY",
            recommended_action="Prefer ephemeral key exchange such as ECDHE.",
            reason="Static RSA key exchange allows retroactive decryption of recorded PCAP traffic if the server private key is ever compromised.",
            description="Static RSA key exchange was utilized without ephemeral Diffie-Hellman parameters.",
            remediation_steps=[
                "Configure MTA to exclusively offer ECDHE or DHE key exchange groups (e.g. x25519, secp256r1).",
                "Disable static RSA key exchange cipher suites (e.g. TLS_RSA_WITH_AES_128_CBC_SHA).",
            ],
            compliance_standards=["NIST SP 800-52r2 Section 3.2", "RFC 7525 Section 4.2"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["NO_FORWARD_SECRECY"],
        ))

    # 4. Expired X.509 Certificate
    if "EXPIRED_CERTIFICATE" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("EXPIRED_CERTIFICATE", [])))
        recs.append(RecommendationItem(
            id="rec_expired_cert",
            priority="IMMEDIATE",
            title="Renew and Replace Expired Mail Server Certificates",
            finding="Expired X.509 Server Certificate",
            finding_category="EXPIRED_CERTIFICATE",
            recommended_action="Renew and deploy the certificate chain.",
            reason="Expired certificates trigger TLS handshake failure, reject mail routing in MTA-STS configurations, and expose clients to man-in-the-middle attacks.",
            description="One or more server certificates observed in the network capture have passed their expiration date.",
            remediation_steps=[
                "Issue a new valid certificate from a trusted public or corporate enterprise CA.",
                "Deploy automated renewal tooling (ACME / cert-manager) with 30-day proactive alert thresholds.",
                "Ensure intermediate CA certificates are properly bundled in the server handshake response.",
            ],
            compliance_standards=["RFC 5280", "CA/Browser Forum Baseline Requirements", "RFC 8461"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["EXPIRED_CERTIFICATE"],
        ))

    # 5. Weak Public Key (< 2048 bits)
    if "WEAK_PUBLIC_KEY" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("WEAK_PUBLIC_KEY", [])))
        recs.append(RecommendationItem(
            id="rec_weak_key",
            priority="HIGH",
            title="Upgrade Inadequate Public Key Lengths to Modern Standards",
            finding="Inadequate Public Key Length (< 2048-bit RSA)",
            finding_category="WEAK_PUBLIC_KEY",
            recommended_action="Replace with an appropriately sized modern key.",
            reason="RSA keys under 2048 bits fail to provide required security margins against factorization (NIST SP 800-52r2).",
            description="The server certificate observed in traffic uses an undersized RSA public key length.",
            remediation_steps=[
                "Re-issue certificate with at least 2048-bit RSA (recommended 3072-bit) or modern ECDSA (P-256 / P-384).",
                "Revoke and decommission keys smaller than 2048 bits across all mail infrastructure.",
            ],
            compliance_standards=["NIST SP 800-52r2 Section 3.1", "RFC 7525"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["WEAK_PUBLIC_KEY"],
        ))

    # 6. Plaintext Email / Credentials Transmission
    if "PLAINTEXT_CREDENTIALS" in category_counts or "UNENCRYPTED_TRAFFIC" in category_counts:
        cat_key = "PLAINTEXT_CREDENTIALS" if "PLAINTEXT_CREDENTIALS" in category_counts else "UNENCRYPTED_TRAFFIC"
        sess_ids = list(dict.fromkeys(category_sessions.get("PLAINTEXT_CREDENTIALS", []) + category_sessions.get("UNENCRYPTED_TRAFFIC", [])))
        recs.append(RecommendationItem(
            id="rec_auth_plain",
            priority="IMMEDIATE",
            title="Enforce Mandatory Transport Encryption for Email Authentication",
            finding="Plaintext Email Traffic & Authentication",
            finding_category=cat_key,
            recommended_action="Require TLS protection before authentication.",
            reason="RFC 8314 mandates that cleartext authentication MUST NOT be permitted over unencrypted channels, as credentials can be captured passively by any network eavesdropper.",
            description="Cleartext email transactions and authentication commands (AUTH PLAIN / LOGIN / USER) were observed without TLS.",
            remediation_steps=[
                "Configure MTA to reject AUTH commands unless TLS encryption is active (RFC 8314 Section 3).",
                "Migrate client configurations to implicit TLS ports (SMTPS: 465, IMAPS: 993, POP3S: 995).",
                "Rotate any credentials observed in cleartext sessions.",
            ],
            compliance_standards=["RFC 8314", "NIST SP 800-52r2", "PCI-DSS 4.0 Req 8.3"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or (category_counts.get("PLAINTEXT_CREDENTIALS", 0) + category_counts.get("UNENCRYPTED_TRAFFIC", 0)),
        ))

    # 7. STARTTLS Stripping Suspect / Upgrade Failure
    if "STARTTLS_STRIPPING_SUSPECT" in category_counts:
        sess_ids = list(dict.fromkeys(category_sessions.get("STARTTLS_STRIPPING_SUSPECT", [])))
        recs.append(RecommendationItem(
            id="rec_starttls_stripping",
            priority="HIGH",
            title="Mitigate STARTTLS Stripping via Strict MTA-STS and DANE Enforcement",
            finding="STARTTLS Stripping Suspect or Upgrade Failure",
            finding_category="STARTTLS_STRIPPING_SUSPECT",
            recommended_action="Review STARTTLS configuration and ensure successful TLS upgrade.",
            reason="Opportunistic STARTTLS is vulnerable to network adversaries who strip the 250 STARTTLS capability banner. Deploying MTA-STS (RFC 8461) mandates secure upgrade.",
            description="STARTTLS capability was advertised by the server or requested by the client, but the session continued in plaintext or failed to negotiate TLS.",
            remediation_steps=[
                "Publish an MTA-STS policy (`mode: enforce`) and implement DNS TLSRPT (RFC 8460).",
                "Deploy DANE TLSA records (RFC 7672) with DNSSEC for cryptographically bound MTA validation.",
                "Investigate firewall/middlebox TLS inspection devices that may be suppressing STARTTLS advertisements.",
            ],
            compliance_standards=["RFC 8461 (MTA-STS)", "RFC 7672 (DANE)", "RFC 8314"],
            affected_sessions=sess_ids,
            affected_sessions_count=len(sess_ids) or category_counts["STARTTLS_STRIPPING_SUSPECT"],
        ))

    immediate_count = sum(1 for r in recs if r.priority == "IMMEDIATE")

    return RecommendationResponse(
        analysis_id=analysis_id,
        recommendations=recs,
        total_recommendations=len(recs),
        immediate_actions_count=immediate_count,
    )


async def _gather_full_analysis_data(analysis_id: str, db: AsyncSession) -> dict:
    analysis = await db.get(Analysis, analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    find_stmt = select(SecurityFinding).where(SecurityFinding.analysis_id == analysis_id)
    findings = (await db.execute(find_stmt)).scalars().all()

    sess_stmt = select(EmailSession).where(EmailSession.analysis_id == analysis_id)
    sessions = (await db.execute(sess_stmt)).scalars().all()

    cert_stmt = select(X509Certificate).where(X509Certificate.analysis_id == analysis_id)
    certs = (await db.execute(cert_stmt)).scalars().all()

    rec_res = await get_analysis_recommendations(analysis_id, db)

    return {
        "analysis": {
            "id": analysis.id,
            "filename": analysis.filename,
            "file_size_bytes": analysis.file_size_bytes,
            "sha256_hash": analysis.sha256_hash,
            "status": analysis.status,
            "total_packets": analysis.total_packets,
            "email_packets": analysis.email_packets,
            "session_count": analysis.session_count,
            "finding_count": analysis.finding_count,
            "cert_count": analysis.cert_count,
            "security_score": analysis.security_score,
            "encryption_ratio": analysis.encryption_ratio,
            "duration_seconds": analysis.duration_seconds,
            "created_at": str(analysis.created_at),
            "completed_at": str(analysis.completed_at),
        },
        "findings": [f.__dict__ for f in findings],
        "sessions": [s.__dict__ for s in sessions],
        "certificates": [c.__dict__ for c in certs],
        "recommendations": [r.model_dump() for r in rec_res.recommendations],
    }


@router.get("/analysis/{analysis_id}/export/json")
async def export_analysis_json(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Export the comprehensive forensic analysis result as a structured JSON file."""
    data = await _gather_full_analysis_data(analysis_id, db)
    # Clean internal sqlalchemy state
    for k in ["findings", "sessions", "certificates"]:
        for item in data[k]:
            item.pop("_sa_instance_state", None)

    json_str = ReportGenerator.generate_json_report(data)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{analysis_id}.json"},
    )


@router.get("/analysis/{analysis_id}/export/html")
async def export_analysis_html(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Export the forensic analysis as a self-contained, enterprise SOC styled HTML report."""
    data = await _gather_full_analysis_data(analysis_id, db)
    html_content = ReportGenerator.generate_html_report(data)
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f"inline; filename=forensic_report_{analysis_id}.html"},
    )


@router.get("/analysis/{analysis_id}/export/pdf")
async def export_analysis_pdf(analysis_id: str, db: AsyncSession = Depends(get_db)):
    """Export the forensic analysis as an executive PDF compliance audit artifact."""
    data = await _gather_full_analysis_data(analysis_id, db)
    pdf_bytes = ReportGenerator.generate_pdf_report(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=forensic_report_{analysis_id}.pdf"},
    )
