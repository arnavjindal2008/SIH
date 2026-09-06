import React, { useState, useEffect } from 'react';
import { ProtocolSummaryResponse, AnalysisSummary } from '../types/analyzer';
import { api } from '../services/api';
import { EmptyState } from '../components/common/EmptyState';
import {
  Binary,
  Lock,
  Unlock,
  Layers,
  PieChart,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';

interface ProtocolsProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Protocols: React.FC<ProtocolsProps> = ({ activeAnalysis }) => {
  const [summary, setSummary] = useState<ProtocolSummaryResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!activeAnalysis) return;
    loadProtocols();
  }, [activeAnalysis]);

  const loadProtocols = async () => {
    if (!activeAnalysis) return;
    setLoading(true);
    try {
      const data = await api.getProtocols(activeAnalysis.id);
      setSummary(data);
    } catch (err) {
      console.error('Failed to load protocols:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={Binary}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to view protocol distributions and cryptographic state."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="soc-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide">Protocol & Cipher Breakdown</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic distribution across SMTP, IMAP, and POP3 email transport sessions
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="p-2 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500">Encrypted: </span>
            <strong className="text-emerald-400">{summary?.encrypted_sessions || 0}</strong>
          </div>
          <div className="p-2 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500">Plaintext: </span>
            <strong className="text-rose-400">{summary?.plaintext_sessions || 0}</strong>
          </div>
          <div className="p-2 rounded bg-[#0c121e] border border-[#1e293b]">
            <span className="text-slate-500">Ratio: </span>
            <strong className="text-sky-400">{Math.round((summary?.overall_encryption_ratio || 0) * 100)}%</strong>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="soc-card py-16 text-center text-xs text-slate-400 font-mono">
          Aggregating protocol metrics...
        </div>
      ) : !summary || summary.protocols.length === 0 ? (
        <div className="soc-card py-16 text-center text-xs text-slate-500 font-mono">
          No email protocols were identified in the analyzed capture.
        </div>
      ) : (
        <>
          {/* Protocol Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {summary.protocols.map((p) => {
              const encPct = Math.round(p.encryption_rate * 100);
              return (
                <div key={p.protocol} className="soc-card space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-sky-950 text-sky-400 border border-sky-800">
                        {p.protocol}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">{p.session_count} sessions</span>
                    </div>
                    <span className="text-xs font-mono text-slate-500">
                      {p.packet_count.toLocaleString()} pkts
                    </span>
                  </div>

                  {/* Encryption Progress Bar */}
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-400">Transport Security</span>
                      <span className={encPct >= 80 ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                        {encPct}% Encrypted
                      </span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden flex">
                      <div
                        className="h-full bg-emerald-500 transition-all duration-500"
                        style={{ width: `${encPct}%` }}
                      />
                      <div
                        className="h-full bg-rose-500 transition-all duration-500"
                        style={{ width: `${100 - encPct}%` }}
                      />
                    </div>
                  </div>

                  {/* Metrics Footer */}
                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#1e293b] text-xs font-mono">
                    <div className="p-2 rounded bg-[#0c121e]">
                      <span className="text-slate-500 text-[10px] uppercase">Encrypted</span>
                      <div className="text-emerald-400 font-bold mt-0.5">{p.encrypted_sessions}</div>
                    </div>
                    <div className="p-2 rounded bg-[#0c121e]">
                      <span className="text-slate-500 text-[10px] uppercase">Plaintext</span>
                      <div className="text-rose-400 font-bold mt-0.5">{p.plaintext_sessions}</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Two-Column Distributions: TLS Versions & Cipher Suites */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* TLS Version Distribution */}
            <div className="soc-card space-y-4">
              <h4 className="text-sm font-semibold text-white tracking-wide">TLS Protocol Version Distribution</h4>
              <div className="space-y-3 pt-1">
                {Object.entries(summary.tls_version_distribution).length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono py-4 text-center">No TLS handshakes recorded.</p>
                ) : (
                  Object.entries(summary.tls_version_distribution).map(([ver, count]) => {
                    const totalTls = Object.values(summary.tls_version_distribution).reduce((a, b) => a + b, 0);
                    const pct = Math.round((count / Math.max(totalTls, 1)) * 100);
                    const isLegacy = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1'].includes(ver);

                    return (
                      <div key={ver} className="space-y-1">
                        <div className="flex justify-between text-xs font-mono">
                          <span className={isLegacy ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                            {ver} {isLegacy ? '(Deprecated - RFC 8996)' : ''}
                          </span>
                          <span className="text-slate-400">{count} ({pct}%)</span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${isLegacy ? 'bg-rose-500' : 'bg-sky-500'} rounded-full`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Cipher Suite Distribution */}
            <div className="soc-card space-y-4">
              <h4 className="text-sm font-semibold text-white tracking-wide">Negotiated Cipher Suites</h4>
              <div className="space-y-3 pt-1">
                {Object.entries(summary.cipher_suite_distribution).length === 0 ? (
                  <p className="text-xs text-slate-500 font-mono py-4 text-center">No cipher suites negotiated.</p>
                ) : (
                  Object.entries(summary.cipher_suite_distribution).map(([cipher, count]) => {
                    const totalCiphers = Object.values(summary.cipher_suite_distribution).reduce((a, b) => a + b, 0);
                    const pct = Math.round((count / Math.max(totalCiphers, 1)) * 100);
                    const isWeak = cipher.includes('RC4') || cipher.includes('3DES') || cipher.includes('CBC');

                    return (
                      <div key={cipher} className="space-y-1">
                        <div className="flex justify-between text-xs font-mono">
                          <span className="text-slate-300 truncate max-w-xs" title={cipher}>
                            {cipher}
                          </span>
                          <span className="text-slate-400 shrink-0 ml-2">{count} ({pct}%)</span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${isWeak ? 'bg-amber-500' : 'bg-emerald-500'} rounded-full`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
