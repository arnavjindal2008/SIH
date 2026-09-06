import datetime
import json
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.app.core.packet_parser import ParsedEmailSession
from backend.app.core.starttls_analyzer import StarttlsAnalyzer
from backend.app.core.tls_analyzer import TLSAnalyzer, DetailedTLSHandshake
from backend.app.core.cert_inspector import CertificateInspector
from backend.app.core.crypto_rules import CryptographicRulesEngine
from backend.app.core.ml_anomaly import SessionAnomalyDetector

# ---------------------------------------------------------------------------
# 1. STARTTLS / STLS State Machine Tests
# ---------------------------------------------------------------------------

def test_starttls_smtp_negotiation():
    lines = [
        "EHLO mail.client.local",
        "250-mail.server.local",
        "250-STARTTLS",
        "250 8BITMIME",
        "STARTTLS",
        "220 2.0.0 Ready to start TLS",
    ]
    res = StarttlsAnalyzer.analyze_stream(
        protocol="SMTP",
        payload_lines=lines,
        has_tls_records=True,
        first_payload_is_tls=False,
        src_port=49152,
        dst_port=25,
    )
    assert res.starttls_supported is True
    assert res.starttls_requested is True
    assert res.tls_upgrade_detected is True
    assert res.encryption_mode == "STARTTLS_UPGRADE"
    assert any("250-STARTTLS" in ev for ev in res.starttls_evidence)

def test_starttls_imap_negotiation():
    lines = [
        "* OK IMAP4rev1 Server Ready",
        "a001 CAPABILITY",
        "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED",
        "a001 OK CAPABILITY completed",
        "a002 STARTTLS",
        "a002 OK Begin TLS negotiation now",
    ]
    res = StarttlsAnalyzer.analyze_stream(
        protocol="IMAP",
        payload_lines=lines,
        has_tls_records=True,
        first_payload_is_tls=False,
        src_port=52111,
        dst_port=143,
    )
    assert res.starttls_supported is True
    assert res.starttls_requested is True
    assert res.tls_upgrade_detected is True
    assert res.encryption_mode == "STARTTLS_UPGRADE"

def test_starttls_pop3_negotiation():
    lines = [
        "+OK POP3 server ready",
        "CAPA",
        "+OK Capability list follows",
        "STLS",
        "USER",
        ".",
        "STLS",
        "+OK Begin TLS negotiation",
    ]
    res = StarttlsAnalyzer.analyze_stream(
        protocol="POP3",
        payload_lines=lines,
        has_tls_records=True,
        first_payload_is_tls=False,
        src_port=53222,
        dst_port=110,
    )
    assert res.starttls_supported is True
    assert res.starttls_requested is True
    assert res.tls_upgrade_detected is True
    assert res.encryption_mode == "STARTTLS_UPGRADE"

def test_starttls_stripping_evidence():
    lines = [
        "EHLO client.victim.local",
        "250-mail.server.local",
        "250-STARTTLS",
        "250 AUTH PLAIN",
        "AUTH PLAIN dXNlcgBwYXNz",
    ]
    res = StarttlsAnalyzer.analyze_stream(
        protocol="SMTP",
        payload_lines=lines,
        has_tls_records=False,
        first_payload_is_tls=False,
        src_port=54321,
        dst_port=25,
    )
    assert res.starttls_supported is True
    assert res.starttls_requested is False
    assert res.encryption_mode == "PLAINTEXT"
    assert any("Server advertised STARTTLS" in ev for ev in res.starttls_evidence)

# ---------------------------------------------------------------------------
# 2. TLS Handshake Dissection Tests
# ---------------------------------------------------------------------------

def test_tls_analyzer_tls12_client_server_hello():
    # Construct synthetic TLS 1.2 Client Hello (Handshake Type 1, 0x0303)
    client_hello = (
        b"\x16\x03\x01\x00\x31"  # Record Header: ContentType=22, Ver=0x0301, Len=49
        b"\x01\x00\x00\x2d"      # Handshake: Type=1, Length=45
        b"\x03\x03"              # Client Version TLS 1.2
        + (b"\xaa" * 32)         # Random (32 bytes)
        + b"\x00"                # Session ID len 0
        + b"\x00\x04\xc0\x2f\xc0\x30" # Cipher suites (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ...)
        + b"\x01\x00"            # Compression methods
    )
    
    parsed = TLSAnalyzer.parse_tls_records(client_hello)
    assert parsed.client_hello_seen is True
    assert parsed.tls_version == "TLS 1.2"
    assert "Incomplete" in parsed.handshake_status
    
    # Construct synthetic TLS 1.2 Server Hello (Handshake Type 2, 0x0303)
    server_hello = (
        b"\x16\x03\x03\x00\x2a"  # Record Header: ContentType=22, Ver=0x0303, Len=42
        b"\x02\x00\x00\x26"      # Handshake: Type=2, Length=38
        b"\x03\x03"              # Server Version TLS 1.2
        + (b"\xbb" * 32)         # Random (32 bytes)
        + b"\x00"                # Session ID len 0
        + b"\xc0\x2f"            # Selected cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        + b"\x00"                # Compression
    )
    
    parsed_server = TLSAnalyzer.parse_tls_records(server_hello, existing=parsed)
    assert parsed_server.server_hello_seen is True
    assert parsed_server.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert parsed_server.forward_secrecy is True
    assert parsed_server.key_exchange == "ECDHE"
    
    # Send ChangeCipherSpec record (ContentType=20) to complete the handshake
    ccs_record = b"\x14\x03\x03\x00\x01\x01"
    parsed_full = TLSAnalyzer.parse_tls_records(ccs_record, existing=parsed_server)
    assert parsed_full.change_cipher_spec_seen is True
    assert parsed_full.handshake_status == "Completed"

def test_tls_analyzer_alert_dissection():
    # ContentType=21 (Alert), Version=0x0303, Length=2
    # Alert: Level=2 (Fatal), Description=40 (handshake_failure)
    alert_record = b"\x15\x03\x03\x00\x02\x02\x28"
    parsed = TLSAnalyzer.parse_tls_records(alert_record)
    assert parsed.handshake_status == "Failed"
    assert len(parsed.tls_alerts) == 1
    assert "fatal" in parsed.tls_alerts[0].lower()
    assert "handshake_failure" in parsed.tls_alerts[0].lower()

# ---------------------------------------------------------------------------
# 3. X.509 Certificate Forensic Analysis Tests
# ---------------------------------------------------------------------------

def test_cert_inspector_forensics():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "smtp.corp.enterprise.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Global Enterprise Inc."),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Root CA G2"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Global Enterprise PKI"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(12345678901234567890)
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=335))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("smtp.corp.enterprise.com"),
                x509.DNSName("mail.corp.enterprise.com"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    
    der = cert.public_bytes(serialization.Encoding.DER)
    inspected = CertificateInspector.inspect_der(der, chain_index=0)
    
    assert inspected is not None
    assert inspected.subject_cn == "smtp.corp.enterprise.com"
    assert inspected.subject_dn is not None
    assert "Global Enterprise Inc." in inspected.subject_dn
    assert inspected.issuer_cn == "Enterprise Root CA G2"
    assert inspected.validity_status == "VALID"
    assert inspected.days_remaining is not None and inspected.days_remaining > 300
    assert inspected.key_size == 2048
    assert inspected.key_algorithm == "RSA"
    assert inspected.chain_index == 0
    assert inspected.chain_info == "Server / Leaf Certificate"
    assert inspected.observed_context == "Certificate observed in capture"
    assert inspected.raw_pem is not None
    assert "-----BEGIN CERTIFICATE-----" in inspected.raw_pem

def test_cert_inspector_weak_key_and_expired():
    # 1024-bit RSA key (Weak key violation NIST SP 800-52r2)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy.mail.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    # Expired 10 days ago
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(999999)
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    inspected = CertificateInspector.inspect_der(der, chain_index=1)
    
    assert inspected is not None
    assert inspected.is_expired is True
    assert inspected.validity_status == "EXPIRED"
    assert inspected.days_remaining is not None and inspected.days_remaining < 0
    assert inspected.is_self_signed is True
    assert inspected.key_size == 1024
    assert any("Weak RSA key length" in w for w in inspected.trust_warnings)
    assert any("expired" in w.lower() for w in inspected.trust_warnings)

# ---------------------------------------------------------------------------
# 4. Deterministic Rule Engine & Finding Verification Tests
# ---------------------------------------------------------------------------

def test_crypto_rules_mandatory_evidence():
    session = ParsedEmailSession(
        session_id="sess_rule_test_01",
        src_ip="192.168.10.15",
        src_port=54321,
        dst_ip="10.10.10.25",
        dst_port=25,
        protocol="SMTP",
        transport_protocol="TCP",
        tcp_stream_id=7,
        is_encrypted=False,
        has_auth_plain=True,
        plaintext_commands=["AUTH PLAIN dXNlcgBwYXNz"],
    )
    
    findings = CryptographicRulesEngine.evaluate_session(
        session=session,
        analysis_id="an_test_eval",
        cert_map={},
    )
    
    assert len(findings) >= 2
    for f in findings:
        assert f["evidence"], f"Finding {f['title']} is missing evidence field!"
        assert "TCP stream 7" in f["evidence"]
        assert f["recommendation"], f"Finding {f['title']} is missing recommendation field!"
        assert f["severity"] in ["Critical", "High", "Medium", "Low", "Informational"]
        assert f["category"] in [
            "PLAINTEXT_CREDENTIALS",
            "UNENCRYPTED_TRAFFIC",
            "DEPRECATED_TLS_VERSION",
            "WEAK_CIPHER_SUITE",
            "NO_FORWARD_SECRECY",
            "STARTTLS_STRIPPING_SUSPECT",
            "EXPIRED_CERTIFICATE",
            "SELF_SIGNED_CERTIFICATE",
            "WEAK_PUBLIC_KEY",
            "BROKEN_SIGNATURE_ALGORITHM",
            "TLS_ALERT_FAILURE",
            "INCOMPLETE_HANDSHAKE",
        ]

# ---------------------------------------------------------------------------
# 5. Security Posture Score (0-100) and Sub-scores Tests
# ---------------------------------------------------------------------------

def test_calculate_detailed_security_scores():
    # 1. Clean secure session
    clean_session = ParsedEmailSession(
        session_id="sess_clean",
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="10.0.0.2",
        dst_port=465,
        protocol="SMTPS",
        is_encrypted=True,
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        forward_secrecy=True,
        handshake_status="Completed",
    )
    clean_scores = CryptographicRulesEngine.calculate_detailed_security_scores(
        findings=[],
        total_sessions=1,
        encrypted_sessions=1,
        sessions=[clean_session],
    )
    assert clean_scores["overall_score"] == 100.0
    assert clean_scores["tls_score"] == 100.0
    assert clean_scores["certificate_score"] == 100.0
    assert clean_scores["cipher_score"] == 100.0
    assert clean_scores["protocol_score"] == 100.0
    assert clean_scores["starttls_score"] == 100.0
    assert clean_scores["score_label"] == "Excellent"
    assert "Score confidence high" in clean_scores["score_confidence_note"]

    # 2. Multi-vulnerability session
    bad_session = ParsedEmailSession(
        session_id="sess_bad",
        src_ip="10.0.0.1",
        src_port=50001,
        dst_ip="10.0.0.2",
        dst_port=25,
        protocol="SMTP",
        is_encrypted=False,
        handshake_status="Incomplete",
    )
    findings = [
        {"session_id": "sess_bad", "category": "PLAINTEXT_CREDENTIALS", "severity": "Critical"},
        {"session_id": "sess_bad", "category": "UNENCRYPTED_TRAFFIC", "severity": "High"},
        {"session_id": "sess_bad", "category": "DEPRECATED_TLS_VERSION", "severity": "High"},
        {"session_id": "sess_bad", "category": "WEAK_CIPHER_SUITE", "severity": "Medium"},
        {"session_id": "sess_bad", "category": "STARTTLS_STRIPPING_SUSPECT", "severity": "High"},
        {"session_id": "sess_bad", "category": "EXPIRED_CERTIFICATE", "severity": "High"},
    ]
    bad_scores = CryptographicRulesEngine.calculate_detailed_security_scores(
        findings=findings,
        total_sessions=1,
        encrypted_sessions=0,
        sessions=[bad_session],
    )
    assert bad_scores["overall_score"] < 70.0
    assert bad_scores["protocol_score"] <= 55.0
    assert bad_scores["tls_score"] <= 45.0
    assert bad_scores["cipher_score"] <= 80.0
    assert bad_scores["starttls_score"] <= 80.0
    assert bad_scores["certificate_score"] <= 80.0
    assert bad_scores["score_label"] in ["Moderate", "Poor", "Critical"]
    assert "Score confidence limited by incomplete capture." == bad_scores["score_confidence_note"]

# ---------------------------------------------------------------------------
# 6. AI Anomaly Detection (scikit-learn Isolation Forest) Tests
# ---------------------------------------------------------------------------

def test_ml_anomaly_detector():
    detector = SessionAnomalyDetector(contamination=0.2)
    assert detector.PROTOTYPE_NOTE == "AI anomaly detection is operating in prototype/baseline mode."
    
    # Normal modern TLS session
    normal_session = ParsedEmailSession(
        session_id="sess_ml_norm",
        src_ip="192.168.1.100",
        src_port=49888,
        dst_ip="10.0.0.5",
        dst_port=465,
        protocol="SMTPS",
        is_encrypted=True,
        encryption_mode="IMPLICIT_TLS",
        tls_version="TLS 1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        key_exchange="ECDHE",
        forward_secrecy=True,
        handshake_status="Completed",
        packet_count=45,
        byte_count=8500,
        duration_ms=450.0,
    )
    
    # Highly anomalous session: Cleartext SMTP with obsolete 3DES cipher name and incomplete handshake
    anom_session = ParsedEmailSession(
        session_id="sess_ml_anom",
        src_ip="192.168.1.200",
        src_port=12345,
        dst_ip="10.0.0.5",
        dst_port=25,
        protocol="SMTP",
        is_encrypted=False,
        encryption_mode="PLAINTEXT",
        tls_version="SSL 3.0",
        cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        key_exchange="None",
        forward_secrecy=False,
        handshake_status="Failed",
        packet_count=1,
        byte_count=40,
        duration_ms=5.0,
    )
    
    sessions = [normal_session, anom_session]
    detector.fit_and_score(sessions)
    
    # Verify annotations are populated
    for s in sessions:
        assert s.anomaly_score is not None
        assert s.anomaly_status in ["NORMAL", "ANOMALOUS", "BASELINE"]
        assert s.risk_priority in ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH"]
        assert s.anomaly_explanation is not None
    
    # Anomalous session explanation should flag unencrypted transport or legacy protocol
    assert "Unencrypted plaintext" in anom_session.anomaly_explanation or "legacy protocol" in anom_session.anomaly_explanation
