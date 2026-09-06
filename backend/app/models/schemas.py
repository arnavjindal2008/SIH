from __future__ import annotations
import datetime
import json
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator

# Base & Health
class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    database: str = "connected"
    tshark_available: bool = False
    scikit_learn_available: bool = True
    cryptography_available: bool = True
    active_analyses: int = 0
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))

# Finding Schemas
class FindingBase(BaseModel):
    severity: str
    category: str
    title: str
    description: str
    evidence: str = ""
    technical_details: str = ""
    affected_component: str = ""
    rfc_reference: Optional[str] = None
    remediation: str = ""
    recommendation: Optional[str] = None
    cve_reference: Optional[str] = None
    certificate_id: Optional[str] = None
    protocol: Optional[str] = None
    tls_version: Optional[str] = None
    status: str = "DETECTED"
    risk: Optional[str] = None

    @model_validator(mode="after")
    def sync_recommendation(self) -> FindingBase:
        if not self.recommendation and self.remediation:
            self.recommendation = self.remediation
        elif self.recommendation and not self.remediation:
            self.remediation = self.recommendation
        return self

class FindingResponse(FindingBase):
    id: str
    finding_id: Optional[str] = None
    analysis_id: str
    session_id: Optional[str] = None
    created_at: datetime.datetime

    @model_validator(mode="after")
    def populate_finding_id(self) -> FindingResponse:
        if not self.finding_id:
            self.finding_id = self.id
        return self

    model_config = ConfigDict(from_attributes=True)

# Certificate Schemas
class CertificateBase(BaseModel):
    fingerprint_sha256: str
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    issuer_dn: Optional[str] = None
    san_list: list[str] = []
    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None
    is_expired: bool = False
    validity_status: str = "VALID"
    days_remaining: Optional[int] = None
    is_self_signed: bool = False
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    serial_number: Optional[str] = None
    trust_warnings: list[str] = []
    raw_pem: Optional[str] = None
    chain_index: int = 0
    chain_info: str = "Server / Leaf Certificate"
    observed_context: str = "Certificate observed in capture"

class CertificateResponse(CertificateBase):
    id: str
    certificate_id: Optional[str] = None
    analysis_id: str
    session_id: Optional[str] = None

    @model_validator(mode="after")
    def populate_certificate_id(self) -> CertificateResponse:
        if not self.certificate_id:
            self.certificate_id = self.id
        return self

    model_config = ConfigDict(from_attributes=True)

# Session Schemas
class SessionBase(BaseModel):
    session_index: int
    protocol: str
    transport_protocol: str = "TCP"
    tcp_stream_id: int = 0
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    
    is_encrypted: bool
    encryption_mode: str = "UNKNOWN"
    
    tls_version: Optional[str] = "Not observed"
    cipher_suite: Optional[str] = "Not observed"
    cipher_suite_code: Optional[str] = None
    key_exchange: Optional[str] = "Not observed"
    forward_secrecy: bool = False
    elliptic_curve: Optional[str] = "Not observed"
    signature_algorithm: Optional[str] = "Not observed"
    handshake_status: str = "Not observed"
    tls_alerts: Any = ""
    session_resumption: Optional[str] = "Not observed"
    
    starttls_supported: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    tls_upgrade_detected: bool = False
    tls_handshake_detected: bool = False
    starttls_evidence: Any = ""
    
    sni: Optional[str] = None
    alpn: Optional[str] = None
    packet_count: int = 0
    byte_count: int = 0
    duration_ms: float = 0.0
    client_hello_seen: bool = False
    server_hello_seen: bool = False
    certificate_seen: bool = False
    
    is_anomalous: bool = False
    anomaly_score: Optional[float] = None
    anomaly_status: str = "NORMAL"
    risk_priority: str = "INFORMATIONAL"
    anomaly_explanation: str = ""
    
    timestamp_first: Optional[datetime.datetime] = None
    timestamp_last: Optional[datetime.datetime] = None
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    status: str = "UNKNOWN"
    protocol_evidence: Optional[str] = ""

    @model_validator(mode="after")
    def populate_aliases(self) -> SessionBase:
        if not self.source_ip:
            self.source_ip = self.src_ip
        if self.source_port is None:
            self.source_port = self.src_port
        if not self.destination_ip:
            self.destination_ip = self.dst_ip
        if self.destination_port is None:
            self.destination_port = self.dst_port
        if not self.first_seen:
            self.first_seen = self.timestamp_first
        if not self.last_seen:
            self.last_seen = self.timestamp_last
        if not self.tls_upgrade_detected:
            self.tls_upgrade_detected = self.starttls_accepted
        return self

class SessionResponse(SessionBase):
    id: str
    session_id: Optional[str] = None
    analysis_id: str

    @model_validator(mode="after")
    def populate_session_id(self) -> SessionResponse:
        if not self.session_id:
            self.session_id = self.id
        return self

    model_config = ConfigDict(from_attributes=True)

# Protocol Metric Schemas
class ProtocolMetricResponse(BaseModel):
    protocol: str
    session_count: int
    packet_count: int
    byte_count: int
    encrypted_sessions: int
    plaintext_sessions: int
    encryption_rate: float
    tls_versions: dict[str, int] = {}
    ciphers: dict[str, int] = {}

    model_config = ConfigDict(from_attributes=True)

class ProtocolSummaryResponse(BaseModel):
    analysis_id: str
    protocols: list[ProtocolMetricResponse] = []
    total_sessions: int = 0
    encrypted_sessions: int = 0
    plaintext_sessions: int = 0
    overall_encryption_ratio: float = 0.0
    tls_version_distribution: dict[str, int] = {}
    cipher_suite_distribution: dict[str, int] = {}

# Security Recommendation Schemas
class RecommendationItem(BaseModel):
    id: str
    priority: str  # IMMEDIATE, HIGH, MEDIUM, LOW
    title: str
    finding: Optional[str] = None
    finding_category: str
    description: str
    recommended_action: Optional[str] = None
    reason: Optional[str] = None
    remediation_steps: list[str] = []
    compliance_standards: list[str] = []
    affected_sessions: list[str] = []
    affected_sessions_count: int = 0

    @model_validator(mode="after")
    def sync_fields(self) -> RecommendationItem:
        if not self.finding:
            self.finding = self.title
        if not self.recommended_action and self.remediation_steps:
            self.recommended_action = self.remediation_steps[0]
        if not self.reason:
            self.reason = self.description
        if not self.affected_sessions_count and self.affected_sessions:
            self.affected_sessions_count = len(self.affected_sessions)
        elif self.affected_sessions_count and not self.affected_sessions:
            self.affected_sessions = [f"Session #{i+1}" for i in range(self.affected_sessions_count)]
        return self

class RecommendationResponse(BaseModel):
    analysis_id: str
    recommendations: list[RecommendationItem] = []
    total_recommendations: int = 0
    immediate_actions_count: int = 0

# PCAP Validation Schemas
class PcapValidationResponse(BaseModel):
    is_valid: bool
    filename: str
    file_size: int
    format: Optional[str] = None
    error: Optional[str] = None
    tshark_available: bool = False
    engine_note: str = ""

# Analysis Schemas
class AnalysisSummary(BaseModel):
    id: str
    analysis_id: str
    filename: str
    file_size: int
    file_size_bytes: int
    sha256_hash: str
    status: str
    error_message: Optional[str] = None
    packet_count: int
    total_packets: int
    ip_packet_count: int = 0
    tcp_packet_count: int = 0
    tcp_stream_count: int = 0
    email_packets: int
    session_count: int
    finding_count: int
    cert_count: int
    
    security_score: Optional[float] = None
    overall_score: Optional[float] = None
    tls_score: float = 100.0
    certificate_score: float = 100.0
    cipher_score: float = 100.0
    protocol_score: float = 100.0
    starttls_score: float = 100.0
    score_label: str = "Good"
    score_confidence_note: str = "Score confidence high: complete forensic capture."
    ai_mode_note: str = "AI anomaly detection is operating in prototype/baseline mode."
    
    encryption_ratio: float
    duration_seconds: float
    created_at: datetime.datetime
    completed_at: Optional[datetime.datetime] = None

    @model_validator(mode="after")
    def sync_score(self) -> AnalysisSummary:
        if self.overall_score is None and self.security_score is not None:
            self.overall_score = self.security_score
        elif self.security_score is None and self.overall_score is not None:
            self.security_score = self.overall_score
        return self

    model_config = ConfigDict(from_attributes=True)

class AnalysisDetailResponse(AnalysisSummary):
    severity_breakdown: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    recent_findings: list[FindingResponse] = []
    recent_sessions: list[SessionResponse] = []
    certificates: list[CertificateResponse] = []

class AnalysisCreateRequest(BaseModel):
    notes: Optional[str] = None
