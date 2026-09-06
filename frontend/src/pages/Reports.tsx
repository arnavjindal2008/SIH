import React from 'react';
import { AnalysisSummary } from '../types/analyzer';
import { api } from '../services/api';
import { EmptyState } from '../components/common/EmptyState';
import {
  FileText,
  Download,
  Code,
  Globe,
  FileCheck,
  Shield,
  Layers,
  HardDrive,
  Clock,
  ExternalLink,
} from 'lucide-react';

interface ReportsProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Reports: React.FC<ReportsProps> = ({ activeAnalysis }) => {
  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={FileText}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to generate and export forensic audit reports."
      />
    );
  }

  const jsonUrl = api.getExportJsonUrl(activeAnalysis.id);
  const htmlUrl = api.getExportHtmlUrl(activeAnalysis.id);
  const pdfUrl = api.getExportPdfUrl(activeAnalysis.id);

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="soc-card flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide">Forensic Audit Export Center</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Export cryptographic forensic evidence, session reconstructions, and compliance audits
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span>Target:</span>
          <strong className="text-white">{activeAnalysis.filename}</strong>
        </div>
      </div>

      {/* 3 Export Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* JSON Export Card */}
        <div className="soc-card flex flex-col justify-between space-y-4 border-[#1e293b] hover:border-sky-500/50 transition-colors">
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-sky-950/80 border border-sky-800/60 flex items-center justify-center text-sky-400">
              <Code className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white tracking-wide">Machine-Readable JSON</h4>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Raw structured data export containing all session 5-tuples, raw handshake telemetry, RFC findings, and X.509 certificate metadata for SIEM/SOAR ingestion.
              </p>
            </div>
          </div>

          <div className="pt-4 border-t border-[#1e293b]">
            <a
              href={jsonUrl}
              download={`forensic_report_${activeAnalysis.id}.json`}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs tracking-wider uppercase transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Download JSON</span>
            </a>
          </div>
        </div>

        {/* HTML Export Card */}
        <div className="soc-card flex flex-col justify-between space-y-4 border-[#1e293b] hover:border-emerald-500/50 transition-colors">
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-950/80 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white tracking-wide">Interactive SOC HTML Report</h4>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Self-contained, styled HTML audit dossier complete with vulnerability breakdowns, session streams, and cryptographic scorecards for browser viewing.
              </p>
            </div>
          </div>

          <div className="pt-4 border-t border-[#1e293b] flex gap-2">
            <a
              href={htmlUrl}
              target="_blank"
              rel="noreferrer"
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-[#162238] hover:bg-[#1c2c48] border border-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Preview</span>
            </a>
            <a
              href={htmlUrl}
              download={`forensic_report_${activeAnalysis.id}.html`}
              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-medium uppercase tracking-wider transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download</span>
            </a>
          </div>
        </div>

        {/* PDF Export Card */}
        <div className="soc-card flex flex-col justify-between space-y-4 border-[#1e293b] hover:border-amber-500/50 transition-colors">
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-amber-950/80 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-white tracking-wide">Executive Compliance PDF</h4>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Formal forensic audit document generated with ReportLab. Designed for compliance auditors, CISO briefing, and forensic incident response filing.
              </p>
            </div>
          </div>

          <div className="pt-4 border-t border-[#1e293b]">
            <a
              href={pdfUrl}
              download={`forensic_report_${activeAnalysis.id}.pdf`}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs tracking-wider uppercase transition-colors"
            >
              <Download className="w-4 h-4" />
              <span>Download PDF</span>
            </a>
          </div>
        </div>
      </div>

      {/* Target File Summary Details */}
      <div className="soc-card space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Target Capture Cryptographic Integrity Metadata
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Analysis Reference</span>
            <div className="text-white font-bold mt-0.5">{activeAnalysis.id}</div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">File Integrity (SHA-256)</span>
            <div className="text-sky-400 font-bold mt-0.5 truncate" title={activeAnalysis.sha256_hash}>
              {activeAnalysis.sha256_hash}
            </div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Parse & Extraction Duration</span>
            <div className="text-white font-bold mt-0.5">{activeAnalysis.duration_seconds} seconds</div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Ingestion Timestamp</span>
            <div className="text-slate-300 font-bold mt-0.5">
              {new Date(activeAnalysis.created_at).toISOString().replace('T', ' ').slice(0, 19)} UTC
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
