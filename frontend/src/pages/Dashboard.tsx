import React, { useState, useEffect } from 'react';
import {
  AnalysisDetailResponse,
  AnalysisSummary,
  SecurityFinding,
  ProtocolSummaryResponse,
  EmailSession,
  X509Certificate,
  SeverityLevel,
} from '../types/analyzer';
import { api } from '../services/api';
import { MetricCard } from '../components/common/MetricCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { EmptyState } from '../components/common/EmptyState';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Lock,
  Unlock,
  FileSearch,
  AlertTriangle,
  ArrowRight,
  Clock,
  HardDrive,
  Server,
  FileCheck,
  Cpu,
  Activity,
  CheckCircle2,
  ExternalLink,
  Zap,
} from 'lucide-react';
import { PageId } from '../components/layout/Sidebar';

interface DashboardProps {
  analysisDetail: AnalysisDetailResponse | null;
  activeAnalysis: AnalysisSummary | null;
  onNavigate: (page: PageId) => void;
  onSelectFinding?: (finding: SecurityFinding) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  analysisDetail,
  activeAnalysis,
  onNavigate,
  onSelectFinding,
}) => {
  const [protocolData, setProtocolData] = useState<ProtocolSummaryResponse | null>(null);
  const [sessions, setSessions] = useState<EmailSession[]>([]);
  const [certificates, setCertificates] = useState<X509Certificate[]>([]);
  const [loadingExtras, setLoadingExtras] = useState(false);

  useEffect(() => {
    if (!activeAnalysis) return;
    loadDashboardExtras(activeAnalysis.id);
  }, [activeAnalysis?.id]);

  const loadDashboardExtras = async (analysisId: string) => {
    setLoadingExtras(true);
    try {
      const [protoRes, sessRes, certRes] = await Promise.allSettled([
        api.getProtocols(analysisId),
        api.getSessions(analysisId),
        api.getCertificates(analysisId),
      ]);

      if (protoRes.status === 'fulfilled') setProtocolData(protoRes.value);
      if (sessRes.status === 'fulfilled') setSessions(sessRes.value);
      if (certRes.status === 'fulfilled') setCertificates(certRes.value);
    } catch (err) {
      console.error('Failed to load dashboard extras:', err);
    } finally {
      setLoadingExtras(false);
    }
  };

  if (!activeAnalysis || !analysisDetail) {
    return (
      <div className="space-y-6">
        <EmptyState
          icon={FileSearch}
          title="No Active Forensic Analysis"
          description="Upload an enterprise network PCAP capture to passively inspect email streams, TLS handshakes, certificates, and cryptographic vulnerabilities."
          actionText="Ingest PCAP Capture"
          onAction={() => onNavigate('pcap-analysis')}
        />
      </div>
    );
  }

  // 1. Overall Security Score (0-100)
  const score = activeAnalysis.security_score ?? activeAnalysis.overall_score ?? 100;
  const scoreVariant =
    score >= 80 ? 'success' : score >= 50 ? 'warning' : 'critical';

  const encPercent = Math.round((activeAnalysis.encryption_ratio || 0) * 100);

  // 5. Severity distribution
  const sevBreakdown = analysisDetail.severity_breakdown || {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  const totalFindings =
    (sevBreakdown.CRITICAL || 0) +
    (sevBreakdown.HIGH || 0) +
    (sevBreakdown.MEDIUM || 0) +
    (sevBreakdown.LOW || 0) +
    (sevBreakdown.INFO || 0);

  // 3. Protocol distribution (SMTP, IMAP, POP3, Unknown)
  const protocolCounts = {
    SMTP: 0,
    IMAP: 0,
    POP3: 0,
    UNKNOWN: 0,
  };

  if (protocolData && protocolData.protocols) {
    for (const p of protocolData.protocols) {
      const protoUpper = p.protocol.toUpperCase();
      if (protoUpper.startsWith('SMTP')) protocolCounts.SMTP += p.session_count;
      else if (protoUpper.startsWith('IMAP')) protocolCounts.IMAP += p.session_count;
      else if (protoUpper.startsWith('POP3')) protocolCounts.POP3 += p.session_count;
      else protocolCounts.UNKNOWN += p.session_count;
    }
  } else if (sessions.length > 0) {
    for (const s of sessions) {
      const protoUpper = (s.protocol || '').toUpperCase();
      if (protoUpper.startsWith('SMTP')) protocolCounts.SMTP++;
      else if (protoUpper.startsWith('IMAP')) protocolCounts.IMAP++;
      else if (protoUpper.startsWith('POP3')) protocolCounts.POP3++;
      else protocolCounts.UNKNOWN++;
    }
  } else {
    // fallback to recent sessions if available
    for (const s of analysisDetail.recent_sessions) {
      const protoUpper = (s.protocol || '').toUpperCase();
      if (protoUpper.startsWith('SMTP')) protocolCounts.SMTP++;
      else if (protoUpper.startsWith('IMAP')) protocolCounts.IMAP++;
      else if (protoUpper.startsWith('POP3')) protocolCounts.POP3++;
      else protocolCounts.UNKNOWN++;
    }
  }
  const totalProtocolSessions =
    protocolCounts.SMTP + protocolCounts.IMAP + protocolCounts.POP3 + protocolCounts.UNKNOWN || 1;

  // 4. TLS version distribution
  const tlsCounts: Record<string, number> = {
    'TLS 1.3': 0,
    'TLS 1.2': 0,
    'TLS 1.1': 0,
    'TLS 1.0': 0,
    'Plaintext / None': 0,
  };

  if (protocolData && protocolData.tls_version_distribution) {
    for (const [ver, cnt] of Object.entries(protocolData.tls_version_distribution)) {
      if (ver.includes('1.3')) tlsCounts['TLS 1.3'] = (tlsCounts['TLS 1.3'] || 0) + cnt;
      else if (ver.includes('1.2')) tlsCounts['TLS 1.2'] = (tlsCounts['TLS 1.2'] || 0) + cnt;
      else if (ver.includes('1.1')) tlsCounts['TLS 1.1'] = (tlsCounts['TLS 1.1'] || 0) + cnt;
      else if (ver.includes('1.0')) tlsCounts['TLS 1.0'] = (tlsCounts['TLS 1.0'] || 0) + cnt;
      else tlsCounts['Plaintext / None'] = (tlsCounts['Plaintext / None'] || 0) + cnt;
    }
  } else {
    const sessionList = sessions.length > 0 ? sessions : analysisDetail.recent_sessions;
    for (const s of sessionList) {
      const ver = s.tls_version;
      if (!s.is_encrypted || !ver || ver === 'None') {
        tlsCounts['Plaintext / None']++;
      } else if (ver.includes('1.3')) {
        tlsCounts['TLS 1.3']++;
      } else if (ver.includes('1.2')) {
        tlsCounts['TLS 1.2']++;
      } else if (ver.includes('1.1')) {
        tlsCounts['TLS 1.1']++;
      } else if (ver.includes('1.0')) {
        tlsCounts['TLS 1.0']++;
      } else {
        tlsCounts['Plaintext / None']++;
      }
    }
  }
  const totalTlsSessions = Object.values(tlsCounts).reduce((a, b) => a + b, 0) || 1;

  // 7. Certificate status
  const certList = certificates.length > 0 ? certificates : (analysisDetail.certificates || []);
  const certStatus = {
    valid: 0,
    expired: 0,
    expiringSoon: 0,
    unknownOrSelfSigned: 0,
  };

  for (const c of certList) {
    if (c.is_expired || c.validity_status === 'EXPIRED') {
      certStatus.expired++;
    } else if (c.validity_status === 'EXPIRING_SOON') {
      certStatus.expiringSoon++;
    } else if (c.is_self_signed || c.validity_status === 'NOT_YET_VALID' || !c.validity_status) {
      certStatus.unknownOrSelfSigned++;
    } else {
      certStatus.valid++;
    }
  }
  const totalCerts = certList.length;

  // 8. STARTTLS status
  const sessionList = sessions.length > 0 ? sessions : analysisDetail.recent_sessions;
  const starttlsStatus = {
    implicitTls: 0,
    upgraded: 0,
    failedUpgrade: 0,
    plaintext: 0,
  };

  for (const s of sessionList) {
    if (s.encryption_mode === 'IMPLICIT_TLS' || (!s.starttls_requested && !s.starttls_supported && s.is_encrypted)) {
      starttlsStatus.implicitTls++;
    } else if (s.encryption_mode === 'STARTTLS_UPGRADE' || s.tls_upgrade_detected || (s.starttls_requested && s.is_encrypted)) {
      starttlsStatus.upgraded++;
    } else if (s.encryption_mode === 'FAILED_UPGRADE' || (s.starttls_requested && !s.is_encrypted)) {
      starttlsStatus.failedUpgrade++;
    } else {
      starttlsStatus.plaintext++;
    }
  }

  // 9. AI anomaly summary
  const anomalousSessions = sessionList.filter((s) => s.is_anomalous || s.anomaly_status === 'ANOMALOUS');
  const normalSessionsCount = sessionList.length - anomalousSessions.length;
  const highRiskAnomalies = sessionList.filter((s) => s.risk_priority === 'HIGH').length;
  const medRiskAnomalies = sessionList.filter((s) => s.risk_priority === 'MEDIUM').length;

  // 10. Recent sessions preview
  const recentSessionsPreview = (sessions.length > 0 ? sessions : analysisDetail.recent_sessions).slice(0, 5);

  // 6. Top security findings
  const topFindings = (analysisDetail.recent_findings || []).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* 1. Header Banner & Target Summary */}
      <div className="soc-card flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[#111827] to-[#121c2e] border-[#1e293b]">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 font-semibold uppercase">
              Forensic Target Analyzed
            </span>
            <span className="text-xs text-slate-400 font-mono">{activeAnalysis.id}</span>
          </div>
          <h2 className="text-xl font-bold text-white mt-1.5 font-mono">{activeAnalysis.filename}</h2>
          <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <HardDrive className="w-3.5 h-3.5 text-slate-500" />
              {(activeAnalysis.file_size_bytes / (1024 * 1024)).toFixed(2)} MB
            </span>
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              Execution: {activeAnalysis.duration_seconds}s
            </span>
            <span className="text-slate-500 truncate max-w-xs">SHA-256: {activeAnalysis.sha256_hash}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate('sessions')}
            className="px-3 py-2 rounded-md bg-[#1e293b] hover:bg-[#334155] text-slate-200 text-xs font-medium tracking-wide uppercase transition-colors"
          >
            Inspect Sessions
          </button>
          <button
            onClick={() => onNavigate('reports')}
            className="px-4 py-2 rounded-md bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium tracking-wide uppercase transition-colors flex items-center gap-2"
          >
            <span>Audit Report</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. Top Metric Cards (Overall Score + Core Counters) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Security Posture Score"
          value={`${score}/100`}
          subtitle={activeAnalysis.score_label || 'Compliance score'}
          icon={Shield}
          variant={scoreVariant}
        />
        <MetricCard
          title="Total Packets"
          value={activeAnalysis.total_packets.toLocaleString()}
          subtitle={`${activeAnalysis.email_packets.toLocaleString()} email pkts`}
          icon={Layers}
          variant="info"
        />
        <MetricCard
          title="Email Sessions"
          value={activeAnalysis.session_count}
          subtitle="Reconstructed streams"
          icon={Server}
          variant="default"
        />
        <MetricCard
          title="Security Findings"
          value={activeAnalysis.finding_count}
          subtitle={`${sevBreakdown.CRITICAL} Critical, ${sevBreakdown.HIGH} High`}
          icon={AlertTriangle}
          variant={activeAnalysis.finding_count > 0 ? 'critical' : 'success'}
        />
        <MetricCard
          title="Encryption Ratio"
          value={`${encPercent}%`}
          subtitle={encPercent >= 90 ? 'High transport security' : 'Cleartext exposure'}
          icon={Lock}
          variant={encPercent >= 80 ? 'success' : 'warning'}
        />
      </div>

      {/* 3. Granular Security Sub-Scores (TLS, Certs, Ciphers, Protocols, STARTTLS) */}
      <div className="soc-card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1e293b] pb-3">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white tracking-wide">
                Security Sub-Scores & Deductions (0–100)
              </h3>
              <span
                className={`px-2 py-0.5 text-[10px] font-mono rounded font-bold ${
                  score >= 80
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : score >= 50
                    ? 'bg-amber-950 text-amber-400 border border-amber-800'
                    : 'bg-rose-950 text-rose-400 border border-rose-800'
                }`}
              >
                {activeAnalysis.score_label || 'Evaluated'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic rule evaluation based on RFC 8314, RFC 8996, RFC 7525, and NIST SP 800-52r2.
            </p>
          </div>
          <div className="text-xs font-mono text-slate-400 bg-slate-900 px-2.5 py-1 rounded border border-slate-800 shrink-0">
            {activeAnalysis.score_confidence_note || 'Confidence: High (full passive reconstruction)'}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 pt-1">
          {[
            { label: 'TLS Protocol', score: activeAnalysis.tls_score ?? 100, weight: '25%' },
            { label: 'Certificates', score: activeAnalysis.certificate_score ?? 100, weight: '20%' },
            { label: 'Ciphers & PFS', score: activeAnalysis.cipher_score ?? 100, weight: '20%' },
            { label: 'Protocols & Auth', score: activeAnalysis.protocol_score ?? 100, weight: '20%' },
            { label: 'STARTTLS / STLS', score: activeAnalysis.starttls_score ?? 100, weight: '15%' },
          ].map((sub) => {
            const val = Math.round(sub.score);
            const colorClass =
              val >= 85
                ? 'text-emerald-400 bg-emerald-500'
                : val >= 60
                ? 'text-amber-400 bg-amber-500'
                : 'text-rose-400 bg-rose-500';
            return (
              <div key={sub.label} className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-300 font-medium">{sub.label}</span>
                  <span className="text-[10px] font-mono text-slate-500">{sub.weight}</span>
                </div>
                <div className="flex justify-between items-baseline">
                  <span className={`text-xl font-bold font-mono ${colorClass.split(' ')[0]}`}>{val}</span>
                  <span className="text-[10px] font-mono text-slate-500">/ 100</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${colorClass.split(' ')[1]}`}
                    style={{ width: `${Math.max(4, val)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. Multi-Distribution Grid: Protocols, TLS Versions, Severities */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Protocol Distribution */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Protocol Distribution
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              {totalProtocolSessions} sessions
            </span>
          </div>
          <div className="space-y-3">
            {[
              { label: 'SMTP', count: protocolCounts.SMTP, color: 'bg-sky-500', text: 'text-sky-400' },
              { label: 'IMAP', count: protocolCounts.IMAP, color: 'bg-emerald-500', text: 'text-emerald-400' },
              { label: 'POP3', count: protocolCounts.POP3, color: 'bg-amber-500', text: 'text-amber-400' },
              { label: 'Unknown', count: protocolCounts.UNKNOWN, color: 'bg-slate-500', text: 'text-slate-400' },
            ].map((p) => {
              const pct = Math.round((p.count / totalProtocolSessions) * 100);
              return (
                <div key={p.label} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className={p.text}>{p.label}</span>
                    <span className="text-slate-400">
                      {p.count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${p.color} rounded-full transition-all`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* TLS Version Distribution */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              TLS Version Distribution
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              {totalTlsSessions} analyzed
            </span>
          </div>
          <div className="space-y-3">
            {[
              { label: 'TLS 1.3', count: tlsCounts['TLS 1.3'], color: 'bg-emerald-500', text: 'text-emerald-400' },
              { label: 'TLS 1.2', count: tlsCounts['TLS 1.2'], color: 'bg-sky-500', text: 'text-sky-400' },
              { label: 'TLS 1.1', count: tlsCounts['TLS 1.1'], color: 'bg-amber-500', text: 'text-amber-400' },
              { label: 'TLS 1.0', count: tlsCounts['TLS 1.0'], color: 'bg-rose-500', text: 'text-rose-400' },
              { label: 'Plaintext / None', count: tlsCounts['Plaintext / None'], color: 'bg-slate-600', text: 'text-slate-400' },
            ].map((t) => {
              const pct = Math.round((t.count / totalTlsSessions) * 100);
              return (
                <div key={t.label} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className={t.text}>{t.label}</span>
                    <span className="text-slate-400">
                      {t.count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${t.color} rounded-full transition-all`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Severity Distribution
            </h3>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium"
            >
              View all ({totalFindings}) &rarr;
            </button>
          </div>
          <div className="space-y-3">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const).map((sev) => {
              const count = sevBreakdown[sev] || 0;
              const maxCount = Math.max(...Object.values(sevBreakdown), 1);
              const pct = Math.round((count / maxCount) * 100);

              const barColors: Record<string, string> = {
                CRITICAL: 'bg-rose-500',
                HIGH: 'bg-amber-500',
                MEDIUM: 'bg-yellow-500',
                LOW: 'bg-blue-500',
                INFO: 'bg-slate-500',
              };

              return (
                <div key={sev} className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <SeverityBadge severity={sev} size="sm" />
                    <span className="font-mono text-slate-300 font-semibold">{count}</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${barColors[sev]} rounded-full transition-all duration-500`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 5. Certificate Status & STARTTLS Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Certificate Status Breakdown */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
            <div className="flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-white tracking-wide">
                X.509 Certificate Status
              </h3>
            </div>
            <button
              onClick={() => onNavigate('certificates')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium"
            >
              View certificates ({totalCerts}) &rarr;
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Valid</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{certStatus.valid}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Expired</span>
              <div className={`text-xl font-bold font-mono mt-1 ${certStatus.expired > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                {certStatus.expired}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Expiring Soon</span>
              <div className={`text-xl font-bold font-mono mt-1 ${certStatus.expiringSoon > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                {certStatus.expiringSoon}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Self-Signed/Other</span>
              <div className={`text-xl font-bold font-mono mt-1 ${certStatus.unknownOrSelfSigned > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                {certStatus.unknownOrSelfSigned}
              </div>
            </div>
          </div>
        </div>

        {/* STARTTLS / STLS Upgrade Status */}
        <div className="soc-card space-y-4">
          <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white tracking-wide">
                STARTTLS / STLS Upgrade Posture
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">RFC 8314 & 7525</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Implicit TLS</span>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{starttlsStatus.implicitTls}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">STARTTLS Upgraded</span>
              <div className="text-xl font-bold font-mono text-sky-400 mt-1">{starttlsStatus.upgraded}</div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Plaintext Only</span>
              <div className={`text-xl font-bold font-mono mt-1 ${starttlsStatus.plaintext > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
                {starttlsStatus.plaintext}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] text-center">
              <span className="text-[11px] font-mono text-slate-400 block">Failed Upgrade</span>
              <div className={`text-xl font-bold font-mono mt-1 ${starttlsStatus.failedUpgrade > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
                {starttlsStatus.failedUpgrade}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 6. AI Anomaly Summary (Scikit-Learn IsolationForest) */}
      <div className="soc-card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1e293b] pb-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-white tracking-wide">
              AI-Assisted Anomaly Detection Summary (Scikit-Learn)
            </h3>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
            IsolationForest Model Active
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] space-y-1">
            <span className="text-[11px] font-mono text-slate-400">Total Analyzed</span>
            <div className="text-lg font-bold font-mono text-white">{sessionList.length} Sessions</div>
          </div>
          <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] space-y-1">
            <span className="text-[11px] font-mono text-slate-400">Anomalous Outliers</span>
            <div className={`text-lg font-bold font-mono ${anomalousSessions.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {anomalousSessions.length} Detected
            </div>
          </div>
          <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] space-y-1">
            <span className="text-[11px] font-mono text-slate-400">High Risk Priority</span>
            <div className={`text-lg font-bold font-mono ${highRiskAnomalies > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
              {highRiskAnomalies} Sessions
            </div>
          </div>
          <div className="p-3 rounded-lg bg-[#0b111e] border border-[#1e293b] space-y-1">
            <span className="text-[11px] font-mono text-slate-400">Medium Risk Priority</span>
            <div className={`text-lg font-bold font-mono ${medRiskAnomalies > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
              {medRiskAnomalies} Sessions
            </div>
          </div>
        </div>

        <div className="p-3 rounded bg-[#080d16] border border-[#1e293b] text-xs font-mono text-slate-400 flex items-center justify-between">
          <span>{activeAnalysis.ai_mode_note || 'AI anomaly detection is operating in prototype/baseline mode.'}</span>
          <span className="text-[11px] text-slate-500">Unsupervised Multi-Feature Heuristic</span>
        </div>
      </div>

      {/* 7. Top Security Findings Table */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">Top Security Findings</h3>
            <p className="text-xs text-slate-400">Prioritized vulnerabilities extracted directly from PCAP data</p>
          </div>
          <button
            onClick={() => onNavigate('findings')}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium"
          >
            View all {activeAnalysis.finding_count} findings &rarr;
          </button>
        </div>

        {topFindings.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs font-mono">
            No vulnerabilities or compliance violations detected in this capture.
          </div>
        ) : (
          <div className="divide-y divide-[#1e293b]">
            {topFindings.map((f) => (
              <div
                key={f.id}
                onClick={() => (onSelectFinding ? onSelectFinding(f) : onNavigate('findings'))}
                className="py-3 flex items-start justify-between gap-4 hover:bg-[#131c2e] px-2 rounded cursor-pointer transition-colors"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} size="sm" />
                    <span className="text-xs font-semibold text-slate-200 truncate">{f.title}</span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1">{f.description}</p>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-[11px] font-mono text-sky-400">{f.rfc_reference || 'RFC Rule'}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 8. Recent Reconstructed Sessions Table */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-2">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">Recent Reconstructed Sessions</h3>
            <p className="text-xs text-slate-400">Stream inspection preview from passive forensic capture</p>
          </div>
          <button
            onClick={() => onNavigate('sessions')}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium"
          >
            View all {activeAnalysis.session_count} sessions &rarr;
          </button>
        </div>

        {recentSessionsPreview.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs font-mono">
            No email sessions parsed in this capture.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-[#1e293b] text-[11px]">
                  <th className="pb-2 font-semibold">Stream</th>
                  <th className="pb-2 font-semibold">Protocol</th>
                  <th className="pb-2 font-semibold">Source</th>
                  <th className="pb-2 font-semibold">Destination</th>
                  <th className="pb-2 font-semibold">Security Mode</th>
                  <th className="pb-2 font-semibold">TLS Version</th>
                  <th className="pb-2 font-semibold text-right">Packets</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {recentSessionsPreview.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => onNavigate('sessions')}
                    className="hover:bg-[#131c2e] cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 text-sky-400 font-semibold">
                      #{s.tcp_stream_id ?? s.session_index}
                    </td>
                    <td className="py-2.5">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#1e293b] text-slate-200">
                        {s.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-300">
                      {s.source_ip || s.src_ip}:{s.source_port ?? s.src_port}
                    </td>
                    <td className="py-2.5 text-slate-300">
                      {s.destination_ip || s.dst_ip}:{s.destination_port ?? s.dst_port}
                    </td>
                    <td className="py-2.5">
                      {s.is_encrypted ? (
                        <span className="text-emerald-400 flex items-center gap-1">
                          <Lock className="w-3 h-3" /> Encrypted
                        </span>
                      ) : (
                        <span className="text-amber-400 flex items-center gap-1">
                          <Unlock className="w-3 h-3" /> Plaintext
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-slate-400">{s.tls_version || 'None'}</td>
                    <td className="py-2.5 text-right text-slate-300">{s.packet_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
