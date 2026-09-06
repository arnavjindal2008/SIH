import React, { useState, useEffect } from 'react';
import { EmailSession, AnalysisSummary } from '../types/analyzer';
import { api } from '../services/api';
import { Drawer } from '../components/common/Drawer';
import { EmptyState } from '../components/common/EmptyState';
import { SessionTimeline } from '../components/sessions/SessionTimeline';
import {
  Network,
  Lock,
  Unlock,
  AlertTriangle,
  Search,
  Filter,
  ShieldCheck,
  Zap,
  ArrowRight,
  Clock,
  Layers,
  Terminal,
  Server,
  Activity,
} from 'lucide-react';

interface SessionsProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Sessions: React.FC<SessionsProps> = ({ activeAnalysis }) => {
  const [sessions, setSessions] = useState<EmailSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedSession, setSelectedSession] = useState<EmailSession | null>(null);

  // Filters
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [encFilter, setEncFilter] = useState<string>('ALL');
  const [anomalyFilter, setAnomalyFilter] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    if (!activeAnalysis) return;
    loadSessions();
  }, [activeAnalysis, protocolFilter, encFilter, anomalyFilter]);

  const loadSessions = async () => {
    if (!activeAnalysis) return;
    setLoading(true);
    try {
      const filters: any = {};
      if (protocolFilter !== 'ALL') filters.protocol = protocolFilter;
      if (encFilter === 'ENCRYPTED') filters.is_encrypted = true;
      if (encFilter === 'PLAINTEXT') filters.is_encrypted = false;
      if (anomalyFilter) filters.is_anomalous = true;

      const data = await api.getSessions(activeAnalysis.id, filters);
      setSessions(data);
    } catch (err) {
      console.error('Failed to load sessions:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (ts?: string | null) => {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      return d.toISOString().replace('T', ' ').replace('Z', '').slice(0, 19);
    } catch {
      return ts;
    }
  };

  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={Network}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to inspect reconstructed email sessions."
      />
    );
  }

  const filteredSessions = sessions.filter((s) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const src = `${s.source_ip || s.src_ip}:${s.source_port ?? s.src_port}`.toLowerCase();
    const dst = `${s.destination_ip || s.dst_ip}:${s.destination_port ?? s.dst_port}`.toLowerCase();
    const sessId = (s.session_id || s.id).toLowerCase();
    return (
      src.includes(q) ||
      dst.includes(q) ||
      sessId.includes(q) ||
      s.protocol.toLowerCase().includes(q) ||
      (s.cipher_suite && s.cipher_suite.toLowerCase().includes(q)) ||
      (s.tls_version && s.tls_version.toLowerCase().includes(q))
    );
  });

  // Calculate protocol counts for quick stats
  const countSmtp = sessions.filter((s) => s.protocol.toUpperCase().startsWith('SMTP')).length;
  const countImap = sessions.filter((s) => s.protocol.toUpperCase().startsWith('IMAP')).length;
  const countPop3 = sessions.filter((s) => s.protocol.toUpperCase().startsWith('POP3')).length;
  const countUnknown = sessions.filter((s) => s.protocol.toUpperCase() === 'UNKNOWN').length;

  const parseEvidence = (evidence?: string | string[] | null): string[] => {
    if (!evidence) return [];
    if (Array.isArray(evidence)) return evidence;
    try {
      const parsed = JSON.parse(evidence);
      if (Array.isArray(parsed)) return parsed;
      return [evidence];
    } catch {
      return [evidence];
    }
  };

  return (
    <div className="space-y-6">
      {/* Protocol Quick Filters & Search Bar */}
      <div className="soc-card flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Protocol Quick Filter Tabs */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setProtocolFilter('ALL')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all ${
              protocolFilter === 'ALL'
                ? 'bg-sky-600 text-white shadow-sm'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-slate-200'
            }`}
          >
            All Protocols ({sessions.length})
          </button>
          <button
            onClick={() => setProtocolFilter('SMTP')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
              protocolFilter === 'SMTP'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-blue-300'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-blue-400"></span>
            SMTP ({countSmtp})
          </button>
          <button
            onClick={() => setProtocolFilter('IMAP')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
              protocolFilter === 'IMAP'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-emerald-300'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            IMAP ({countImap})
          </button>
          <button
            onClick={() => setProtocolFilter('POP3')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
              protocolFilter === 'POP3'
                ? 'bg-purple-600 text-white shadow-sm'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-purple-300'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-purple-400"></span>
            POP3 ({countPop3})
          </button>
          <button
            onClick={() => setProtocolFilter('UNKNOWN')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-all flex items-center gap-1.5 ${
              protocolFilter === 'UNKNOWN'
                ? 'bg-slate-600 text-white shadow-sm'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-slate-300'
            }`}
          >
            <span className="w-2 h-2 rounded-full bg-slate-400"></span>
            Unknown ({countUnknown})
          </button>
        </div>

        {/* Search & Extra Filters */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IP, session, protocol..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-[#0c121e] border border-[#1e293b] rounded text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500 w-full md:w-60 font-mono"
            />
          </div>

          <button
            onClick={() => setAnomalyFilter(!anomalyFilter)}
            className={`px-2.5 py-1.5 rounded text-xs font-mono font-semibold transition-colors flex items-center gap-1.5 ${
              anomalyFilter
                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                : 'bg-[#0c121e] text-slate-400 border border-[#1e293b] hover:text-slate-200'
            }`}
            title="Filter ML Anomaly Sessions"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>ML Anomalies</span>
          </button>
        </div>
      </div>

      {/* Sessions Table */}
      <div className="soc-card p-0 overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1e293b] flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">Email & TCP Communication Sessions</h3>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Displaying {filteredSessions.length} sessions (derived from PCAP conversation streams)
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-[#0c121e] border border-[#1e293b] text-slate-400">
              <Layers className="w-3 h-3 text-sky-400" />
              Capture Streams: {activeAnalysis.tcp_stream_count || sessions.length}
            </span>
          </div>
        </div>

        {loading ? (
          <div className="py-16 text-center text-xs text-slate-400 font-mono">
            Extracting session metadata and protocol classifications...
          </div>
        ) : filteredSessions.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-500 font-mono">
            No sessions match the selected protocol filter or search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left soc-table">
              <thead>
                <tr>
                  <th>Session ID</th>
                  <th>Protocol</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Packets</th>
                  <th>Start Time</th>
                  <th>End Time</th>
                  <th>Status</th>
                  <th className="text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182338]">
                {filteredSessions.map((s) => {
                  const srcEndpoint = `${s.source_ip || s.src_ip}:${s.source_port ?? s.src_port}`;
                  const dstEndpoint = `${s.destination_ip || s.dst_ip}:${s.destination_port ?? s.dst_port}`;
                  const streamIndex = s.tcp_stream_id !== undefined ? s.tcp_stream_id : s.session_index;

                  return (
                    <tr
                      key={s.id}
                      onClick={() => setSelectedSession(s)}
                      className="hover:bg-[#121c2e] cursor-pointer transition-colors"
                    >
                      {/* Session ID */}
                      <td className="font-mono text-xs">
                        <div className="flex items-center gap-1.5">
                          <span className="text-sky-400 font-semibold">{s.session_id || s.id}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            Stream #{streamIndex}
                          </span>
                        </div>
                      </td>

                      {/* Protocol */}
                      <td>
                        {s.protocol.toUpperCase().startsWith('SMTP') ? (
                          <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/60">
                            {s.protocol}
                          </span>
                        ) : s.protocol.toUpperCase().startsWith('IMAP') ? (
                          <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                            {s.protocol}
                          </span>
                        ) : s.protocol.toUpperCase().startsWith('POP3') ? (
                          <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-purple-950/80 text-purple-400 border border-purple-800/60">
                            {s.protocol}
                          </span>
                        ) : (
                          <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            UNKNOWN
                          </span>
                        )}
                      </td>

                      {/* Source */}
                      <td className="font-mono text-xs text-slate-300">
                        {srcEndpoint}
                      </td>

                      {/* Destination */}
                      <td className="font-mono text-xs text-slate-300">
                        {dstEndpoint}
                      </td>

                      {/* Packets */}
                      <td className="font-mono text-xs text-slate-300">
                        {s.packet_count}
                      </td>

                      {/* Start Time */}
                      <td className="font-mono text-xs text-slate-400">
                        {formatTimestamp(s.first_seen || s.timestamp_first)}
                      </td>

                      {/* End Time */}
                      <td className="font-mono text-xs text-slate-400">
                        {formatTimestamp(s.last_seen || s.timestamp_last)}
                      </td>

                      {/* Status */}
                      <td>
                        {s.is_anomalous ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-400 font-semibold px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/60">
                            <Zap className="w-3 h-3" /> ANOMALOUS
                          </span>
                        ) : s.is_encrypted ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60">
                            <Lock className="w-3 h-3" /> ENCRYPTED
                          </span>
                        ) : s.protocol === 'UNKNOWN' ? (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-850 border border-slate-700">
                            <Network className="w-3 h-3" /> UNCLASSIFIED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-rose-400 font-semibold px-2 py-0.5 rounded bg-rose-950/60 border border-rose-800/60">
                            <Unlock className="w-3 h-3" /> PLAINTEXT
                          </span>
                        )}
                      </td>

                      {/* Inspect Action */}
                      <td className="text-right">
                        <button className="p-1 rounded hover:bg-slate-800 text-sky-400 transition-colors">
                          <ArrowRight className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Forensic Deep Inspection Drawer */}
      <Drawer
        isOpen={selectedSession !== null}
        onClose={() => setSelectedSession(null)}
        title={`Session Detail: ${selectedSession?.session_id || selectedSession?.id}`}
        subtitle={`${selectedSession?.protocol} • TCP Stream #${selectedSession?.tcp_stream_id ?? selectedSession?.session_index}`}
      >
        {selectedSession && (
          <div className="space-y-6">
            {/* Protocol Classification Banner */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  Protocol Classification
                </span>
                <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
                  {selectedSession.protocol}
                </span>
              </div>

              {/* Protocol Identification Evidence */}
              <div className="space-y-1.5 font-mono text-xs">
                <span className="text-slate-400 text-[11px]">Payload & Packet Evidence:</span>
                {parseEvidence(selectedSession.protocol_evidence).length > 0 ? (
                  <div className="space-y-1 mt-1">
                    {parseEvidence(selectedSession.protocol_evidence).map((ev, idx) => (
                      <div key={idx} className="p-2 rounded bg-[#080d16] border border-[#1a2333] text-slate-300 text-[11px] flex items-start gap-2">
                        <Terminal className="w-3.5 h-3.5 text-sky-400 mt-0.5 shrink-0" />
                        <span>{ev}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-2 rounded bg-[#080d16] text-slate-500 text-[11px]">
                    No payload evidence strings logged. Classification determined via TCP port correlation.
                  </div>
                )}
              </div>
            </div>

            {/* Stream 5-Tuple Box */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-3">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                TCP Conversation 5-Tuple & Transport
              </span>
              <div className="grid grid-cols-2 gap-4 font-mono text-xs">
                <div>
                  <span className="text-slate-500">Source (Client):</span>
                  <div className="text-slate-200 font-bold mt-0.5">
                    {selectedSession.source_ip || selectedSession.src_ip}:{selectedSession.source_port ?? selectedSession.src_port}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Destination (Server):</span>
                  <div className="text-slate-200 font-bold mt-0.5">
                    {selectedSession.destination_ip || selectedSession.dst_ip}:{selectedSession.destination_port ?? selectedSession.dst_port}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Transport Protocol:</span>
                  <div className="text-slate-200 font-bold mt-0.5">
                    {selectedSession.transport_protocol || 'TCP'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500">Wireshark Stream ID:</span>
                  <div className="text-sky-400 font-bold mt-0.5">
                    tcp.stream == {selectedSession.tcp_stream_id ?? selectedSession.session_index}
                  </div>
                </div>
              </div>
            </div>

            {/* Traffic Timestamps & Metrics */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-3">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Capture Timestamps & Volume
              </span>
              <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                <div>
                  <span className="text-slate-500">Start Time:</span>
                  <div className="text-slate-200 mt-0.5">{formatTimestamp(selectedSession.first_seen || selectedSession.timestamp_first)}</div>
                </div>
                <div>
                  <span className="text-slate-500">End Time:</span>
                  <div className="text-slate-200 mt-0.5">{formatTimestamp(selectedSession.last_seen || selectedSession.timestamp_last)}</div>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 font-mono text-center pt-2 border-t border-[#182338]">
                <div className="p-2 rounded bg-[#080d16]">
                  <div className="text-[11px] text-slate-500">Packets</div>
                  <div className="text-sm font-bold text-white mt-0.5">{selectedSession.packet_count}</div>
                </div>
                <div className="p-2 rounded bg-[#080d16]">
                  <div className="text-[11px] text-slate-500">Bytes</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {selectedSession.byte_count > 1024 ? `${(selectedSession.byte_count / 1024).toFixed(1)} KB` : `${selectedSession.byte_count} B`}
                  </div>
                </div>
                <div className="p-2 rounded bg-[#080d16]">
                  <div className="text-[11px] text-slate-500">Duration</div>
                  <div className="text-sm font-bold text-white mt-0.5">{selectedSession.duration_ms} ms</div>
                </div>
              </div>
            </div>

            {/* Event-Driven Sequence Timeline */}
            <SessionTimeline session={selectedSession} />

            {/* STARTTLS / STLS Negotiation Analysis (Phase 4) */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                STARTTLS / STLS Protocol Negotiation
              </h4>
              <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-2.5 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Encryption Mode:</span>
                  <span className={`font-bold px-2 py-0.5 rounded text-[11px] ${
                    selectedSession.encryption_mode === 'IMPLICIT_TLS'
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : selectedSession.encryption_mode === 'STARTTLS_UPGRADE'
                      ? 'bg-sky-950 text-sky-400 border border-sky-800'
                      : selectedSession.encryption_mode === 'FAILED_UPGRADE'
                      ? 'bg-rose-950 text-rose-400 border border-rose-800'
                      : 'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}>
                    {selectedSession.encryption_mode || (selectedSession.is_encrypted ? 'IMPLICIT_TLS' : 'PLAINTEXT')}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Server STARTTLS Advertised:</span>
                  <span className={selectedSession.starttls_supported ? 'text-emerald-400' : 'text-slate-400'}>
                    {selectedSession.starttls_supported ? 'Yes (Capability Announced)' : 'No / Not Observed'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Client STARTTLS Requested:</span>
                  <span className={selectedSession.starttls_requested ? 'text-sky-400' : 'text-slate-400'}>
                    {selectedSession.starttls_requested ? 'Yes (Command Sent)' : 'No'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">TLS Upgrade Accepted:</span>
                  <span className={(selectedSession.tls_upgrade_detected || selectedSession.starttls_accepted) ? 'text-emerald-400' : 'text-slate-400'}>
                    {(selectedSession.tls_upgrade_detected || selectedSession.starttls_accepted) ? 'Yes (Ready Response)' : 'No / Failed'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Handshake Followed Upgrade:</span>
                  <span className={selectedSession.tls_handshake_detected ? 'text-emerald-400' : 'text-slate-400'}>
                    {selectedSession.tls_handshake_detected ? 'Observed in Stream' : selectedSession.is_encrypted ? 'Implicit Handshake' : 'Not Observed'}
                  </span>
                </div>
                {selectedSession.starttls_evidence && (
                  <div className="pt-2 border-t border-[#182338]">
                    <span className="text-slate-400 text-[11px] block mb-1">Negotiation Evidence:</span>
                    <div className="p-2 rounded bg-[#080d16] text-sky-300 text-[11px] break-all border border-[#1a2333]">
                      {selectedSession.starttls_evidence}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Cryptographic Handshake Parameters (Phase 4) */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                TLS Handshake Dissection
              </h4>
              <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-2.5 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Handshake Status:</span>
                  <span className={`font-bold ${
                    selectedSession.handshake_status === 'Completed'
                      ? 'text-emerald-400'
                      : selectedSession.handshake_status === 'Incomplete'
                      ? 'text-amber-400'
                      : 'text-slate-400'
                  }`}>
                    {selectedSession.handshake_status || (selectedSession.is_encrypted ? 'Completed' : 'Not observed')}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">TLS Protocol Version:</span>
                  <span className="text-slate-200 font-bold">{selectedSession.tls_version || 'None'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Negotiated Cipher Suite:</span>
                  <span className="text-sky-300 truncate max-w-xs">{selectedSession.cipher_suite || 'None'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Key Exchange (Kx):</span>
                  <span className="text-slate-300">{selectedSession.key_exchange || 'None'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Elliptic Curve Group:</span>
                  <span className="text-slate-300">{selectedSession.elliptic_curve || 'Not observed'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Signature Algorithm:</span>
                  <span className="text-slate-300">{selectedSession.signature_algorithm || 'Not observed'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Perfect Forward Secrecy:</span>
                  <span className={selectedSession.forward_secrecy ? 'text-emerald-400' : 'text-amber-400'}>
                    {selectedSession.forward_secrecy ? 'Enforced (ECDHE / DHE)' : 'Not Enforced'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#182338]">
                  <span className="text-slate-400">Session Resumption:</span>
                  <span className="text-slate-300">{selectedSession.session_resumption || 'Not observed'}</span>
                </div>
                {selectedSession.tls_alerts && selectedSession.tls_alerts !== '[]' && selectedSession.tls_alerts !== '""' && (
                  <div className="pt-2 border-t border-[#182338]">
                    <span className="text-rose-400 text-[11px] block mb-1">TLS Alert Records:</span>
                    <div className="p-2 rounded bg-rose-950/40 text-rose-300 text-[11px] border border-rose-900/60 font-mono">
                      {typeof selectedSession.tls_alerts === 'string' ? selectedSession.tls_alerts : JSON.stringify(selectedSession.tls_alerts)}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* AI-Assisted Anomaly Assessment (Phase 5) */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-[#182338] pb-2">
                <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                  AI Anomaly Detection (IsolationForest)
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  selectedSession.is_anomalous || selectedSession.anomaly_status === 'ANOMALOUS'
                    ? 'bg-amber-950 text-amber-400 border border-amber-800'
                    : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                }`}>
                  {selectedSession.anomaly_status || (selectedSession.is_anomalous ? 'ANOMALOUS' : 'NORMAL')}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 py-1">
                <div>
                  <span className="text-slate-500 text-[11px]">Risk Priority:</span>
                  <div className={`font-bold mt-0.5 ${
                    selectedSession.risk_priority === 'HIGH'
                      ? 'text-rose-400'
                      : selectedSession.risk_priority === 'MEDIUM'
                      ? 'text-amber-400'
                      : 'text-slate-300'
                  }`}>
                    {selectedSession.risk_priority || 'INFORMATIONAL'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 text-[11px]">Anomaly Score:</span>
                  <div className="text-sky-400 font-bold mt-0.5">
                    {selectedSession.anomaly_score !== null && selectedSession.anomaly_score !== undefined
                      ? selectedSession.anomaly_score
                      : '0.00'}
                  </div>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-slate-500 text-[11px]">AI Model Explanation:</span>
                <div className="p-2.5 rounded bg-[#080d16] text-slate-300 text-[11px] leading-relaxed border border-[#1a2333]">
                  {selectedSession.anomaly_explanation || 'Parameters consistent with expected baseline.'}
                </div>
              </div>

              <div className="text-[10px] text-slate-500 italic">
                AI anomaly detection is operating in prototype/baseline mode.
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
