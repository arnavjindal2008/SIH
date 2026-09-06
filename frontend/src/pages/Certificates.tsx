import React, { useState, useEffect } from 'react';
import { X509Certificate, AnalysisSummary } from '../types/analyzer';
import { api } from '../services/api';
import { EmptyState } from '../components/common/EmptyState';
import {
  KeyRound,
  ShieldCheck,
  AlertTriangle,
  Calendar,
  Layers,
  Copy,
  Check,
} from 'lucide-react';

interface CertificatesProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Certificates: React.FC<CertificatesProps> = ({ activeAnalysis }) => {
  const [certs, setCerts] = useState<X509Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [copiedFp, setCopiedFp] = useState<string | null>(null);
  const [expandedPemId, setExpandedPemId] = useState<string | null>(null);

  useEffect(() => {
    if (!activeAnalysis) return;
    loadCerts();
  }, [activeAnalysis]);

  const loadCerts = async () => {
    if (!activeAnalysis) return;
    setLoading(true);
    try {
      const data = await api.getCertificates(activeAnalysis.id);
      setCerts(data);
    } catch (err) {
      console.error('Failed to load certificates:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedFp(text);
    setTimeout(() => setCopiedFp(null), 2000);
  };

  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={KeyRound}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to inspect TLS X.509 certificate chains."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Overview Card with Passive Disclaimer */}
      <div className="soc-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-white tracking-wide">Extracted X.509 Certificates</h3>
            <span className="px-2 py-0.5 text-[10px] font-mono rounded font-bold bg-sky-950 text-sky-400 border border-sky-800">
              Certificate observed in capture
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Public key certificates intercepted strictly from passive TLS handshake packets. No live server queries performed.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="px-3 py-1 rounded bg-[#0c121e] border border-[#1e293b] text-xs font-mono text-slate-300">
            Total Extracted: <strong className="text-white">{certs.length}</strong>
          </span>
        </div>
      </div>

      {loading ? (
        <div className="soc-card py-16 text-center text-xs text-slate-400 font-mono">
          Extracting certificate parameters...
        </div>
      ) : certs.length === 0 ? (
        <div className="soc-card py-16 text-center text-xs text-slate-500 font-mono">
          No X.509 certificates were captured in this PCAP analysis.
        </div>
      ) : (
        <div className="space-y-4">
          {certs.map((c) => (
            <div key={c.id} className="soc-card space-y-4">
              {/* Top Row: Subject CN, Chain Level & Badges */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded bg-sky-950/70 border border-sky-800/60 flex items-center justify-center text-sky-400 shrink-0">
                    <KeyRound className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-white font-mono">{c.subject_cn || 'Unknown Common Name'}</h4>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#131d2e] text-sky-300 border border-sky-800/60">
                        {c.chain_info || (c.chain_index === 0 ? 'Server / Leaf Certificate' : `Chain #${c.chain_index}`)}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5 truncate max-w-xl">
                      Subject DN: <span className="text-slate-300 font-mono text-[11px]">{c.subject_dn || c.subject_org || 'N/A'}</span>
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  {c.validity_status === 'EXPIRED' || c.is_expired ? (
                    <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800">
                      EXPIRED {c.days_remaining !== null && c.days_remaining !== undefined ? `(${Math.abs(c.days_remaining)}d ago)` : ''}
                    </span>
                  ) : c.validity_status === 'NOT_YET_VALID' ? (
                    <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">
                      NOT YET VALID
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                      VALID {c.days_remaining !== null && c.days_remaining !== undefined ? `(${c.days_remaining}d left)` : ''}
                    </span>
                  )}

                  {c.is_self_signed && (
                    <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">
                      SELF-SIGNED
                    </span>
                  )}

                  <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                    {c.key_algorithm} {c.key_size ? `(${c.key_size} bits)` : ''}
                  </span>
                </div>
              </div>

              {/* Grid: Issuer DN, Validity, Signature, SANs */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
                <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">Issuer Authority</span>
                  <div className="text-slate-200 font-bold truncate" title={c.issuer_cn || ''}>
                    {c.issuer_cn || 'Unknown Issuer'}
                  </div>
                  <div className="text-slate-400 text-[11px] truncate" title={c.issuer_dn || ''}>
                    {c.issuer_dn || c.issuer_org || 'No Issuer DN'}
                  </div>
                </div>

                <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">Validity Period</span>
                  <div className="text-slate-300 text-[11px]">
                    From: {c.valid_from ? new Date(c.valid_from).toISOString().split('T')[0] : 'N/A'}
                  </div>
                  <div className="text-slate-300 text-[11px]">
                    To: {c.valid_to ? new Date(c.valid_to).toISOString().split('T')[0] : 'N/A'}
                  </div>
                </div>

                <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">Signature & Serial</span>
                  <div className="text-slate-200 font-bold truncate" title={c.signature_algorithm || ''}>{c.signature_algorithm || 'N/A'}</div>
                  <div className="text-slate-400 text-[11px] truncate">Serial: {c.serial_number || 'N/A'}</div>
                </div>

                <div className="p-3 rounded bg-[#0c121e] border border-[#1e293b] space-y-1">
                  <span className="text-[10px] uppercase text-slate-500 font-semibold tracking-wider">Subject Alt Names (SAN)</span>
                  <div className="text-slate-300 text-[11px] truncate" title={c.san_list?.join(', ')}>
                    {c.san_list && c.san_list.length > 0 ? c.san_list.slice(0, 2).join(', ') : 'No SANs'}
                    {c.san_list && c.san_list.length > 2 ? ` (+${c.san_list.length - 2} more)` : ''}
                  </div>
                  <div className="text-slate-500 text-[10px]">Context: {c.observed_context || 'Observed in capture'}</div>
                </div>
              </div>

              {/* Warnings Row */}
              {c.trust_warnings && c.trust_warnings.length > 0 && (
                <div className="p-3 rounded bg-amber-950/20 border border-amber-900/60 space-y-1.5 text-xs">
                  <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Cryptographic & Forensic Trust Warnings:</span>
                  </div>
                  <ul className="list-disc list-inside space-y-0.5 text-amber-300/90 text-xs">
                    {c.trust_warnings.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* SHA-256 Fingerprint & PEM Viewer */}
              <div className="space-y-2">
                <div className="flex items-center justify-between p-2.5 rounded bg-[#090d16] border border-[#1e293b] text-xs font-mono">
                  <div className="flex items-center gap-2 truncate">
                    <span className="text-slate-500 text-[11px] uppercase">SHA-256 Fingerprint:</span>
                    <span className="text-sky-400 truncate font-bold">{c.fingerprint_sha256}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {c.raw_pem && (
                      <button
                        onClick={() => setExpandedPemId(expandedPemId === c.id ? null : c.id)}
                        className="px-2 py-0.5 rounded text-[11px] text-sky-400 hover:text-sky-300 bg-sky-950/60 border border-sky-800 transition-colors"
                      >
                        {expandedPemId === c.id ? 'Hide PEM' : 'View PEM'}
                      </button>
                    )}
                    <button
                      onClick={() => copyToClipboard(c.fingerprint_sha256)}
                      className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                      title="Copy SHA-256"
                    >
                      {copiedFp === c.fingerprint_sha256 ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {expandedPemId === c.id && c.raw_pem && (
                  <div className="p-3 rounded bg-[#05080f] border border-[#182338] text-[11px] font-mono text-slate-400 overflow-x-auto">
                    <pre className="whitespace-pre-wrap">{c.raw_pem}</pre>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
