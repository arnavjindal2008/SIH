import React from 'react';
import { AnalysisSummary } from '../../types/analyzer';
import { StatusBadge } from '../common/StatusBadge';
import { FileUp, FileDown, ShieldCheck, Database } from 'lucide-react';
import { PageId } from './Sidebar';

interface HeaderProps {
  currentPage: PageId;
  activeAnalysis: AnalysisSummary | null;
  allAnalyses: AnalysisSummary[];
  onSelectAnalysis: (analysisId: string) => void;
  onNavigateToUpload: () => void;
  onNavigateToReports: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentPage,
  activeAnalysis,
  allAnalyses,
  onSelectAnalysis,
  onNavigateToUpload,
  onNavigateToReports,
}) => {
  const pageTitles: Record<PageId, { title: string; desc: string }> = {
    dashboard: { title: 'Security Posture Dashboard', desc: 'Forensic posture, risk score, and traffic encryption metrics' },
    'pcap-analysis': { title: 'PCAP Capture Ingestion', desc: 'Passive network packet capture parsing and deep inspection' },
    sessions: { title: 'Forensic Email Sessions', desc: 'Reconstructed TCP streams, TLS parameters, and port handshakes' },
    findings: { title: 'Cryptographic Security Findings', desc: 'RFC violations, deprecated protocols, and plaintext credential risks' },
    certificates: { title: 'X.509 Certificate Inspector', desc: 'Public key cryptography, expiration timeline, and trust chain validation' },
    protocols: { title: 'Protocol & Cipher Breakdown', desc: 'SMTP, IMAP, POP3, and STARTTLS cryptographic state distribution' },
    recommendations: { title: 'Remediation & Hardening', desc: 'Actionable NIST SP 800-52r2, RFC 8996, and MTA-STS compliance guidance' },
    reports: { title: 'Forensic Audit Reports', desc: 'Export forensic evidence in machine-readable JSON, HTML, and PDF formats' },
    settings: { title: 'Engine Configuration', desc: 'Analysis thresholds, port monitoring, and forensic detection rules' },
  };

  const currentMeta = pageTitles[currentPage] || { title: 'Console', desc: '' };

  return (
    <header className="h-16 bg-[#0c121e] border-b border-[#1e293b] px-6 flex items-center justify-between shrink-0">
      {/* Page Title & Breadcrumb */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">ECSA</span>
          <span className="text-xs text-slate-600">/</span>
          <h2 className="text-sm font-semibold text-white tracking-wide">{currentMeta.title}</h2>
        </div>
        <p className="text-[11px] text-slate-400 hidden sm:block">{currentMeta.desc}</p>
      </div>

      {/* Active PCAP Selector & Quick Actions */}
      <div className="flex items-center gap-3">
        {/* Active PCAP Dropdown */}
        <div className="flex items-center gap-2 bg-[#111a2d] border border-[#1e293b] px-3 py-1.5 rounded-md">
          <Database className="w-3.5 h-3.5 text-sky-400" />
          <span className="text-xs text-slate-400">Active PCAP:</span>
          <select
            value={activeAnalysis?.id || ''}
            onChange={(e) => onSelectAnalysis(e.target.value)}
            className="bg-transparent text-xs font-mono text-slate-200 outline-none cursor-pointer max-w-[160px] truncate"
          >
            {allAnalyses.length === 0 ? (
              <option value="" disabled>No PCAPs Analyzed</option>
            ) : (
              allAnalyses.map((a) => (
                <option key={a.id} value={a.id} className="bg-[#111a2d] text-slate-200">
                  {a.filename} ({a.session_count} sess)
                </option>
              ))
            )}
          </select>
        </div>

        {activeAnalysis && <StatusBadge status={activeAnalysis.status} />}

        {/* Quick Upload Button */}
        <button
          onClick={onNavigateToUpload}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium transition-colors"
        >
          <FileUp className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>

        {/* Quick Export Button */}
        {activeAnalysis && (
          <button
            onClick={onNavigateToReports}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#162238] hover:bg-[#1c2c48] border border-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            <FileDown className="w-3.5 h-3.5 text-slate-300" />
            <span>Reports</span>
          </button>
        )}
      </div>
    </header>
  );
};
