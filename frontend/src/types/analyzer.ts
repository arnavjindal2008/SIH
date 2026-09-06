export type AnalysisStatus = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface HealthResponse {
  status: string;
  version: string;
  database: string;
  tshark_available: boolean;
  scikit_learn_available: boolean;
  cryptography_available: boolean;
  active_analyses: number;
  timestamp: string;
}

export interface PcapValidationResponse {
  is_valid: boolean;
  filename: string;
  file_size: number;
  format?: string | null;
  error?: string | null;
  tshark_available: boolean;
  engine_note: string;
}

export interface AnalysisSummary {
  id: string;
  analysis_id?: string;
  filename: string;
  file_size?: number;
  file_size_bytes: number;
  sha256_hash: string;
  status: AnalysisStatus;
  error_message?: string | null;
  packet_count?: number;
  total_packets: number;
  ip_packet_count?: number;
  tcp_packet_count?: number;
  tcp_stream_count?: number;
  email_packets: number;
  session_count: number;
  finding_count: number;
  cert_count: number;
  security_score?: number | null;
  overall_score?: number | null;
  tls_score?: number;
  certificate_score?: number;
  cipher_score?: number;
  protocol_score?: number;
  starttls_score?: number;
  score_label?: string;
  score_confidence_note?: string;
  ai_mode_note?: string;
  encryption_ratio: number;
  duration_seconds: number;
  created_at: string;
  completed_at?: string | null;
}

export interface EmailSession {
  id: string;
  session_id?: string;
  analysis_id: string;
  session_index: number;
  protocol: string;
  transport_protocol?: string;
  tcp_stream_id?: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  is_encrypted: boolean;
  encryption_mode?: string;
  tls_version?: string | null;
  cipher_suite?: string | null;
  cipher_suite_code?: string | null;
  key_exchange?: string | null;
  forward_secrecy: boolean;
  elliptic_curve?: string | null;
  signature_algorithm?: string | null;
  handshake_status?: string;
  tls_alerts?: any;
  session_resumption?: string | null;
  starttls_supported?: boolean;
  starttls_requested: boolean;
  starttls_accepted: boolean;
  tls_upgrade_detected?: boolean;
  tls_handshake_detected?: boolean;
  starttls_evidence?: string | null;
  sni?: string | null;
  alpn?: string | null;
  packet_count: number;
  byte_count: number;
  duration_ms: number;
  client_hello_seen: boolean;
  server_hello_seen: boolean;
  certificate_seen: boolean;
  is_anomalous: boolean;
  anomaly_score?: number | null;
  anomaly_status?: string;
  risk_priority?: string;
  anomaly_explanation?: string;
  timestamp_first?: string | null;
  timestamp_last?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  status?: string;
  protocol_evidence?: string | string[] | null;
}

export interface SecurityFinding {
  id: string;
  finding_id?: string;
  analysis_id: string;
  session_id?: string | null;
  certificate_id?: string | null;
  severity: SeverityLevel;
  category: string;
  title: string;
  description: string;
  evidence?: string;
  technical_details: string;
  affected_component: string;
  rfc_reference?: string | null;
  remediation: string;
  recommendation?: string;
  cve_reference?: string | null;
  protocol?: string | null;
  tls_version?: string | null;
  risk?: string | null;
  status?: string;
  created_at: string;
}

export interface X509Certificate {
  id: string;
  certificate_id?: string;
  analysis_id: string;
  session_id?: string | null;
  fingerprint_sha256: string;
  subject_cn?: string | null;
  subject_org?: string | null;
  subject_dn?: string | null;
  issuer_cn?: string | null;
  issuer_org?: string | null;
  issuer_dn?: string | null;
  san_list: string[];
  valid_from?: string | null;
  valid_to?: string | null;
  is_expired: boolean;
  validity_status?: string;
  days_remaining?: number | null;
  is_self_signed: boolean;
  key_algorithm?: string | null;
  key_size?: number | null;
  signature_algorithm?: string | null;
  serial_number?: string | null;
  trust_warnings: string[];
  raw_pem?: string | null;
  chain_index?: number;
  chain_info?: string;
  observed_context?: string;
}

export interface ProtocolMetricResponse {
  protocol: string;
  session_count: number;
  packet_count: number;
  byte_count: number;
  encrypted_sessions: number;
  plaintext_sessions: number;
  encryption_rate: number;
  tls_versions: Record<string, number>;
  ciphers: Record<string, number>;
}

export interface ProtocolSummaryResponse {
  analysis_id: string;
  protocols: ProtocolMetricResponse[];
  total_sessions: number;
  encrypted_sessions: number;
  plaintext_sessions: number;
  overall_encryption_ratio: number;
  tls_version_distribution: Record<string, number>;
  cipher_suite_distribution: Record<string, number>;
}

export interface RecommendationItem {
  id: string;
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  finding_category: string;
  description: string;
  remediation_steps: string[];
  compliance_standards: string[];
  affected_sessions_count: number;
  finding?: string;
  recommended_action?: string;
  reason?: string;
  affected_sessions?: string[];
}

export interface RecommendationResponse {
  analysis_id: string;
  recommendations: RecommendationItem[];
  total_recommendations: number;
  immediate_actions_count: number;
}

export interface AnalysisDetailResponse extends AnalysisSummary {
  severity_breakdown: Record<SeverityLevel, number>;
  recent_findings: SecurityFinding[];
  recent_sessions: EmailSession[];
  certificates: X509Certificate[];
}
