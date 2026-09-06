import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship, synonym
from backend.app.database import Base

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(64), primary_key=True, index=True)
    analysis_id = synonym("id")

    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, default=0)
    file_size_bytes = synonym("file_size")
    sha256_hash = Column(String(64), default="")
    status = Column(String(32), default="PENDING", index=True)  # PENDING, PROCESSING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
    
    packet_count = Column(Integer, default=0)
    total_packets = synonym("packet_count")
    ip_packet_count = Column(Integer, default=0)
    tcp_packet_count = Column(Integer, default=0)
    tcp_stream_count = Column(Integer, default=0)
    email_packets = Column(Integer, default=0)
    session_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    cert_count = Column(Integer, default=0)
    
    security_score = Column(Float, nullable=True)  # 0 to 100 overall
    overall_score = synonym("security_score")
    tls_score = Column(Float, default=100.0)
    certificate_score = Column(Float, default=100.0)
    cipher_score = Column(Float, default=100.0)
    protocol_score = Column(Float, default=100.0)
    starttls_score = Column(Float, default=100.0)
    score_label = Column(String(32), default="Good")
    score_confidence_note = Column(String(255), default="Score confidence high: verified complete forensic capture.")
    ai_mode_note = Column(String(255), default="AI anomaly detection is operating in prototype/baseline mode.")

    encryption_ratio = Column(Float, default=0.0)  # 0.0 to 1.0
    
    duration_seconds = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), index=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    sessions = relationship("EmailSession", back_populates="analysis", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="analysis", cascade="all, delete-orphan")
    certificates = relationship("X509Certificate", back_populates="analysis", cascade="all, delete-orphan")
    protocol_metrics = relationship("ProtocolMetric", back_populates="analysis", cascade="all, delete-orphan")


class EmailSession(Base):
    __tablename__ = "email_sessions"

    id = Column(String(64), primary_key=True, index=True)
    session_id = synonym("id")
    analysis_id = Column(String(64), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    session_index = Column(Integer, default=0)
    
    protocol = Column(String(32), default="UNKNOWN", index=True)  # SMTP, IMAP, POP3, UNKNOWN
    transport_protocol = Column(String(16), default="TCP")
    tcp_stream_id = Column(Integer, default=0, index=True)
    
    src_ip = Column(String(64), default="")
    source_ip = synonym("src_ip")
    src_port = Column(Integer, default=0)
    source_port = synonym("src_port")
    dst_ip = Column(String(64), default="")
    destination_ip = synonym("dst_ip")
    dst_port = Column(Integer, default=0)
    destination_port = synonym("dst_port")
    
    is_encrypted = Column(Boolean, default=False, index=True)
    encryption_mode = Column(String(32), default="UNKNOWN")  # IMPLICIT_TLS, STARTTLS_UPGRADE, FAILED_UPGRADE, PLAINTEXT, UNKNOWN
    
    tls_version = Column(String(32), nullable=True, index=True)  # "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "None"
    cipher_suite = Column(String(128), nullable=True)
    cipher_suite_code = Column(String(32), nullable=True)
    key_exchange = Column(String(64), nullable=True)
    forward_secrecy = Column(Boolean, default=False)
    elliptic_curve = Column(String(64), default="Not observed")
    signature_algorithm = Column(String(64), default="Not observed")
    handshake_status = Column(String(32), default="Not observed")
    tls_alerts = Column(Text, default="")
    session_resumption = Column(String(64), default="Not observed")
    
    starttls_supported = Column(Boolean, default=False)
    starttls_requested = Column(Boolean, default=False)
    starttls_accepted = Column(Boolean, default=False)
    tls_upgrade_detected = synonym("starttls_accepted")
    tls_handshake_detected = Column(Boolean, default=False)
    starttls_evidence = Column(Text, default="")
    
    sni = Column(String(255), nullable=True)
    alpn = Column(String(64), nullable=True)
    
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    duration_ms = Column(Float, default=0.0)
    
    client_hello_seen = Column(Boolean, default=False)
    server_hello_seen = Column(Boolean, default=False)
    certificate_seen = Column(Boolean, default=False)
    
    anomaly_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, default=False)
    anomaly_status = Column(String(32), default="NORMAL")
    risk_priority = Column(String(16), default="INFORMATIONAL")
    anomaly_explanation = Column(Text, default="")
    
    timestamp_first = Column(DateTime, nullable=True)
    first_seen = synonym("timestamp_first")
    timestamp_last = Column(DateTime, nullable=True)
    last_seen = synonym("timestamp_last")

    status = Column(String(32), default="UNKNOWN", index=True)  # ENCRYPTED, PLAINTEXT, ANOMALY, UNKNOWN
    protocol_evidence = Column(Text, default="")

    analysis = relationship("Analysis", back_populates="sessions")
    findings = relationship("SecurityFinding", back_populates="session")
    certificates = relationship("X509Certificate", back_populates="session")


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(String(64), primary_key=True, index=True)
    finding_id = synonym("id")
    analysis_id = Column(String(64), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    session_id = Column(String(64), ForeignKey("email_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    certificate_id = Column(String(64), nullable=True, index=True)
    
    severity = Column(String(16), default="INFO", index=True)  # Critical, High, Medium, Low, Informational
    category = Column(String(64), default="GENERAL", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, default="")
    technical_details = Column(Text, default="")
    affected_component = Column(String(128), default="")
    rfc_reference = Column(String(128), nullable=True)
    remediation = Column(Text, default="")
    recommendation = synonym("remediation")
    cve_reference = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    analysis = relationship("Analysis", back_populates="findings")
    session = relationship("EmailSession", back_populates="findings")


class X509Certificate(Base):
    __tablename__ = "x509_certificates"

    id = Column(String(64), primary_key=True, index=True)
    certificate_id = synonym("id")
    analysis_id = Column(String(64), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    session_id = Column(String(64), ForeignKey("email_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    
    fingerprint_sha256 = Column(String(64), index=True)
    subject_cn = Column(String(255), nullable=True)
    subject_org = Column(String(255), nullable=True)
    subject_dn = Column(String(512), nullable=True)
    issuer_cn = Column(String(255), nullable=True)
    issuer_org = Column(String(255), nullable=True)
    issuer_dn = Column(String(512), nullable=True)
    san_list = Column(Text, nullable=True)  # JSON string
    
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)
    is_expired = Column(Boolean, default=False)
    validity_status = Column(String(32), default="VALID")  # VALID, EXPIRED, NOT_YET_VALID
    days_remaining = Column(Integer, nullable=True)
    is_self_signed = Column(Boolean, default=False)
    
    key_algorithm = Column(String(32), nullable=True)
    key_size = Column(Integer, nullable=True)
    signature_algorithm = Column(String(64), nullable=True)
    serial_number = Column(String(128), nullable=True)
    trust_warnings = Column(Text, nullable=True)  # JSON array string
    raw_pem = Column(Text, nullable=True)
    chain_index = Column(Integer, default=0)
    chain_info = Column(String(128), default="Server / Leaf Certificate")
    observed_context = Column(String(255), default="Certificate observed in capture")

    analysis = relationship("Analysis", back_populates="certificates")
    session = relationship("EmailSession", back_populates="certificates")


class ProtocolMetric(Base):
    __tablename__ = "protocol_metrics"

    id = Column(String(64), primary_key=True, index=True)
    analysis_id = Column(String(64), ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    protocol = Column(String(32), nullable=False)
    
    session_count = Column(Integer, default=0)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    encrypted_sessions = Column(Integer, default=0)
    plaintext_sessions = Column(Integer, default=0)
    tls_versions_json = Column(Text, default="{}")
    ciphers_json = Column(Text, default="{}")

    analysis = relationship("Analysis", back_populates="protocol_metrics")
