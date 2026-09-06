import React, { useState } from 'react';
import { HealthResponse } from '../types/analyzer';
import {
  Settings as SettingsIcon,
  Shield,
  Cpu,
  Database,
  Sliders,
  CheckCircle2,
  AlertCircle,
  Terminal,
} from 'lucide-react';

interface SettingsProps {
  health: HealthResponse | null;
}

export const Settings: React.FC<SettingsProps> = ({ health }) => {
  const [contamination, setContamination] = useState('0.1');
  const [rfc8996Enabled, setRfc8996Enabled] = useState(true);
  const [rfc8314Enabled, setRfc8314Enabled] = useState(true);
  const [weakCiphersEnabled, setWeakCiphersEnabled] = useState(true);
  const [certValidationEnabled, setCertValidationEnabled] = useState(true);

  return (
    <div className="space-y-6">
      {/* Overview */}
      <div className="soc-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide">Forensic Engine Configuration</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic standards thresholds, monitored email ports, and ML anomaly detector parameters
          </p>
        </div>
        <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-sky-950 text-sky-400 border border-sky-800">
          PRODUCTION ENGINE V1.0.0
        </span>
      </div>

      {/* Grid: Monitored Ports & ML Settings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monitored Ports */}
        <div className="soc-card space-y-4">
          <div className="flex items-center gap-2 text-white font-semibold text-sm">
            <Sliders className="w-4 h-4 text-sky-400" />
            <span>Monitored Enterprise Email Ports</span>
          </div>
          <p className="text-xs text-slate-400">
            Network streams matching these destination or source ports are ingested and reassembled into email sessions.
          </p>

          <div className="space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 25</span>
                <span className="text-slate-400 ml-2">SMTP (MTA Relay / STARTTLS)</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 587</span>
                <span className="text-slate-400 ml-2">SMTP Submission (STARTTLS)</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 465</span>
                <span className="text-slate-400 ml-2">SMTPS (Implicit TLS - RFC 8314)</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 143</span>
                <span className="text-slate-400 ml-2">IMAP (Plaintext / STARTTLS)</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 993</span>
                <span className="text-slate-400 ml-2">IMAPS (Implicit TLS)</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded bg-[#0c121e] border border-[#1e293b]">
              <div>
                <span className="text-sky-400 font-bold">Port 110 & 995</span>
                <span className="text-slate-400 ml-2">POP3 & POP3S</span>
              </div>
              <span className="text-emerald-400 text-[11px] font-bold">ACTIVE</span>
            </div>
          </div>
        </div>

        {/* Machine Learning Pipeline */}
        <div className="soc-card space-y-4">
          <div className="flex items-center gap-2 text-white font-semibold text-sm">
            <Cpu className="w-4 h-4 text-sky-400" />
            <span>Passive ML Anomaly Detection (scikit-learn)</span>
          </div>
          <p className="text-xs text-slate-400">
            Unsupervised Isolation Forest model detecting statistical packet size, handshake latency, and command volume anomalies without active probing.
          </p>

          <div className="p-4 rounded-lg bg-[#0c121e] border border-[#1e293b] space-y-3 font-mono text-xs">
            <div className="flex justify-between py-1 border-b border-[#182338]">
              <span className="text-slate-400">Algorithm:</span>
              <span className="text-slate-200">IsolationForest (sklearn.ensemble)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#182338]">
              <span className="text-slate-400">N Estimators:</span>
              <span className="text-slate-200">100 Trees</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#182338]">
              <span className="text-slate-400">Contamination Ratio:</span>
              <span className="text-sky-400 font-bold">0.10 (10% anomaly bound)</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Extracted Features:</span>
              <span className="text-slate-300">Packet Count, Bytes, Duration, Auth Flag</span>
            </div>
          </div>

          <div className="p-3 rounded bg-emerald-950/20 border border-emerald-900/60 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>Scikit-Learn ML engine is loaded and initialized.</span>
          </div>
        </div>
      </div>

      {/* Standards & Forensic Evaluation Rules */}
      <div className="soc-card space-y-4">
        <div className="flex items-center gap-2 text-white font-semibold text-sm">
          <Shield className="w-4 h-4 text-sky-400" />
          <span>Active Cryptographic Standards & Rulesets</span>
        </div>
        <p className="text-xs text-slate-400">
          Evaluation rules enforced against passive packet streams during forensic analysis.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] flex items-center justify-between">
            <div>
              <span className="text-white font-bold">RFC 8996 (TLS 1.0 & 1.1 Deprecation)</span>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">Flags SSL 3.0, TLS 1.0, and TLS 1.1 handshakes as Critical/High vulnerabilities.</p>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold ml-4">
              ENFORCED
            </span>
          </div>

          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] flex items-center justify-between">
            <div>
              <span className="text-white font-bold">RFC 8314 (Cleartext Email Deprecation)</span>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">Flags unencrypted traffic and cleartext credentials (AUTH PLAIN, USER/PASS) as Critical.</p>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold ml-4">
              ENFORCED
            </span>
          </div>

          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] flex items-center justify-between">
            <div>
              <span className="text-white font-bold">RFC 7525 & RFC 7465 (Weak Ciphers)</span>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">Prohibits RC4, 3DES, DES, and CBC-mode ciphers without AEAD protection.</p>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold ml-4">
              ENFORCED
            </span>
          </div>

          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] flex items-center justify-between">
            <div>
              <span className="text-white font-bold">NIST SP 800-52r2 (Certificate Audit)</span>
              <p className="text-[11px] text-slate-400 font-sans mt-0.5">Enforces minimum RSA 2048-bit keys, validates expiration, and detects self-signed certs.</p>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold ml-4">
              ENFORCED
            </span>
          </div>
        </div>
      </div>

      {/* System Diagnostics */}
      <div className="soc-card space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Engine Runtime Diagnostics
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">FastAPI Framework</span>
            <div className="text-white font-bold mt-0.5">v1.0.0 (Uvicorn ASGI)</div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Database Engine</span>
            <div className="text-emerald-400 font-bold mt-0.5">SQLite + SQLAlchemy Async</div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Certificate Analyzer</span>
            <div className="text-emerald-400 font-bold mt-0.5">Python Cryptography 50.0.1</div>
          </div>
          <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500 text-[10px] uppercase">Packet Inspection Engine</span>
            <div className="text-sky-400 font-bold mt-0.5">Scapy 2.7.0 Libpcap</div>
          </div>
        </div>
      </div>
    </div>
  );
};
