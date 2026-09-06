import {
  HealthResponse,
  AnalysisSummary,
  AnalysisDetailResponse,
  EmailSession,
  SecurityFinding,
  X509Certificate,
  ProtocolSummaryResponse,
  RecommendationResponse,
  PcapValidationResponse,
} from '../types/analyzer';

const API_BASE = '/api';

export const api = {
  async getHealth(): Promise<HealthResponse> {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`);
    return res.json();
  },

  async validatePcap(file: File): Promise<PcapValidationResponse> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/pcap/validate`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'Failed to validate PCAP file');
    }
    return res.json();
  },

  async listAnalyses(): Promise<AnalysisSummary[]> {
    const res = await fetch(`${API_BASE}/analyses`);
    if (!res.ok) throw new Error(`Failed to list analyses: ${res.statusText}`);
    return res.json();
  },

  async uploadPcap(file: File): Promise<AnalysisSummary> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'Failed to analyze PCAP file');
    }
    return res.json();
  },

  async getAnalysisDetail(analysisId: string): Promise<AnalysisDetailResponse> {
    const res = await fetch(`${API_BASE}/analysis/${analysisId}`);
    if (!res.ok) throw new Error(`Failed to load analysis detail: ${res.statusText}`);
    return res.json();
  },

  async getSessions(
    analysisId: string,
    filters?: { protocol?: string; is_encrypted?: boolean; is_anomalous?: boolean }
  ): Promise<EmailSession[]> {
    const params = new URLSearchParams();
    if (filters?.protocol) params.set('protocol', filters.protocol);
    if (filters?.is_encrypted !== undefined) params.set('is_encrypted', String(filters.is_encrypted));
    if (filters?.is_anomalous !== undefined) params.set('is_anomalous', String(filters.is_anomalous));

    const url = `${API_BASE}/analysis/${analysisId}/sessions${params.toString() ? `?${params.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch sessions: ${res.statusText}`);
    return res.json();
  },

  async getFindings(
    analysisId: string,
    filters?: {
      severity?: string;
      category?: string;
      protocol?: string;
      tls_version?: string;
      session_id?: string;
      search?: string;
    }
  ): Promise<SecurityFinding[]> {
    const params = new URLSearchParams();
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.category) params.set('category', filters.category);
    if (filters?.protocol) params.set('protocol', filters.protocol);
    if (filters?.tls_version) params.set('tls_version', filters.tls_version);
    if (filters?.session_id) params.set('session_id', filters.session_id);
    if (filters?.search) params.set('search', filters.search);

    const url = `${API_BASE}/analysis/${analysisId}/findings${params.toString() ? `?${params.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
    return res.json();
  },

  async getCertificates(analysisId: string): Promise<X509Certificate[]> {
    const res = await fetch(`${API_BASE}/analysis/${analysisId}/certificates`);
    if (!res.ok) throw new Error(`Failed to fetch certificates: ${res.statusText}`);
    return res.json();
  },

  async getProtocols(analysisId: string): Promise<ProtocolSummaryResponse> {
    const res = await fetch(`${API_BASE}/analysis/${analysisId}/protocols`);
    if (!res.ok) throw new Error(`Failed to fetch protocol metrics: ${res.statusText}`);
    return res.json();
  },

  async getRecommendations(analysisId: string): Promise<RecommendationResponse> {
    const res = await fetch(`${API_BASE}/analysis/${analysisId}/recommendations`);
    if (!res.ok) throw new Error(`Failed to fetch recommendations: ${res.statusText}`);
    return res.json();
  },

  getExportJsonUrl(analysisId: string): string {
    return `${API_BASE}/analysis/${analysisId}/export/json`;
  },

  getExportHtmlUrl(analysisId: string): string {
    return `${API_BASE}/analysis/${analysisId}/export/html`;
  },

  getExportPdfUrl(analysisId: string): string {
    return `${API_BASE}/analysis/${analysisId}/export/pdf`;
  },
};
