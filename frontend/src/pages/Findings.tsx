import React, { useState, useEffect } from 'react';
import { SecurityFinding, AnalysisSummary, SeverityLevel } from '../types/analyzer';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { EmptyState } from '../components/common/EmptyState';
import { Drawer } from '../components/common/Drawer';
import {
  ShieldAlert,
  Search,
  ExternalLink,
  BookOpen,
  Wrench,
  Layers,
  Filter,
  AlertTriangle,
  X,
  Radio,
  Server,
  Terminal,
  FileCheck,
} from 'lucide-react';

interface FindingsProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Findings: React.FC<FindingsProps> = ({ activeAnalysis }) => {
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);

  // Multi-dimensional filters
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [tlsFilter, setTlsFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [sessionFilter, setSessionFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    if (!activeAnalysis) return;
    loadFindings();
  }, [activeAnalysis?.id, severityFilter, protocolFilter, tlsFilter, categoryFilter, sessionFilter]);

  const loadFindings = async () => {
    if (!activeAnalysis) return;
    setLoading(true);
    try {
      const filters: any = {};
      if (severityFilter !== 'ALL') filters.severity = severityFilter;
      if (protocolFilter !== 'ALL') filters.protocol = protocolFilter;
      if (tlsFilter !== 'ALL') filters.tls_version = tlsFilter;
      if (categoryFilter !== 'ALL') filters.category = categoryFilter;
      if (sessionFilter.trim()) filters.session_id = sessionFilter.trim();
      if (searchQuery.trim()) filters.search = searchQuery.trim();

      const data = await api.getFindings(activeAnalysis.id, filters);
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadFindings();
  };

  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to view cryptographic vulnerabilities, protocol flaws, and compliance findings."
      />
    );
  }

  // Client-side quick filter in case search query is modified without form submit
  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q) ||
      (f.evidence && f.evidence.toLowerCase().includes(q)) ||
      (f.technical_details && f.technical_details.toLowerCase().includes(q)) ||
      (f.rfc_reference && f.rfc_reference.toLowerCase().includes(q)) ||
      (f.category && f.category.toLowerCase().includes(q)) ||
      (f.session_id && f.session_id.toLowerCase().includes(q)) ||
      (f.risk && f.risk.toLowerCase().includes(q))
    );
  });

  // Extract unique categories for category dropdown
  const uniqueCategories = Array.from(new Set(findings.map((f) => f.category))).filter(Boolean);

  const resetFilters = () => {
    setSeverityFilter('ALL');
    setProtocolFilter('ALL');
    setTlsFilter('ALL');
    setCategoryFilter('ALL');
    setSessionFilter('');
    setSearchQuery('');
  };

  const hasActiveFilters =
    severityFilter !== 'ALL' ||
    protocolFilter !== 'ALL' ||
    tlsFilter !== 'ALL' ||
    categoryFilter !== 'ALL' ||
    sessionFilter !== '' ||
    searchQuery !== '';

  return (
    <div className="space-y-6">
      {/* Filter Toolbar */}
      <div className="soc-card space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-sky-400" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Filter Security Findings
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              ({filteredFindings.length} of {findings.length} displayed)
            </span>
          </div>

          {hasActiveFilters && (
            <button
              onClick={resetFilters}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-medium transition-colors"
            >
              <X className="w-3.5 h-3.5" />
              Reset all filters
            </button>
          )}
        </div>

        {/* Filter Controls Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
          {/* Severity */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              Severity
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="INFO">Informational</option>
            </select>
          </div>

          {/* Protocol */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              Protocol
            </label>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
            >
              <option value="ALL">All Protocols</option>
              <option value="SMTP">SMTP</option>
              <option value="IMAP">IMAP</option>
              <option value="POP3">POP3</option>
              <option value="UNKNOWN">Unknown</option>
            </select>
          </div>

          {/* TLS Version */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              TLS Version
            </label>
            <select
              value={tlsFilter}
              onChange={(e) => setTlsFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
            >
              <option value="ALL">All Versions</option>
              <option value="TLS 1.3">TLS 1.3</option>
              <option value="TLS 1.2">TLS 1.2</option>
              <option value="TLS 1.1">TLS 1.1</option>
              <option value="TLS 1.0">TLS 1.0</option>
              <option value="NONE">Plaintext / None</option>
            </select>
          </div>

          {/* Finding Type / Category */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              Category
            </label>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
            >
              <option value="ALL">All Categories</option>
              {uniqueCategories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>

          {/* Session ID */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              Session
            </label>
            <input
              type="text"
              placeholder="Filter by session ID..."
              value={sessionFilter}
              onChange={(e) => setSessionFilter(e.target.value)}
              className="w-full px-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
            />
          </div>

          {/* Search */}
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
              Keyword Search
            </label>
            <form onSubmit={handleSearchSubmit} className="relative">
              <input
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-7 pr-2.5 py-1.5 bg-[#090e17] border border-[#1e293b] rounded text-xs text-slate-200 font-mono outline-none focus:border-sky-500"
              />
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-1/2 -translate-y-1/2" />
            </form>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="soc-card space-y-4">
        {loading ? (
          <div className="py-16 text-center text-xs text-slate-400 font-mono">
            Loading security findings...
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-500 font-mono">
            {findings.length === 0
              ? 'No security findings or cryptographic violations detected in this analysis.'
              : 'No findings match your active filter criteria.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="text-slate-500 border-b border-[#1e293b] text-[11px] uppercase tracking-wider">
                  <th className="pb-2.5 font-semibold">Severity</th>
                  <th className="pb-2.5 font-semibold">Finding</th>
                  <th className="pb-2.5 font-semibold">Protocol</th>
                  <th className="pb-2.5 font-semibold">Session</th>
                  <th className="pb-2.5 font-semibold">Evidence</th>
                  <th className="pb-2.5 font-semibold">Risk</th>
                  <th className="pb-2.5 font-semibold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {filteredFindings.map((f) => {
                  const evidenceSnippet = f.evidence || f.technical_details || 'N/A';
                  return (
                    <tr
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className="hover:bg-[#131c2e] cursor-pointer transition-colors group"
                    >
                      <td className="py-3 pr-3 whitespace-nowrap">
                        <SeverityBadge severity={f.severity} size="sm" />
                      </td>
                      <td className="py-3 pr-3 min-w-[200px]">
                        <div className="font-semibold text-slate-200 group-hover:text-sky-400 transition-colors">
                          {f.title}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5 flex items-center gap-1.5">
                          <span>{f.category}</span>
                          {f.rfc_reference && (
                            <>
                              <span>·</span>
                              <span className="text-sky-500 font-mono">{f.rfc_reference}</span>
                            </>
                          )}
                        </div>
                      </td>
                      <td className="py-3 pr-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-[#1e293b] text-slate-300">
                          {f.protocol ? f.protocol.toUpperCase() : 'N/A'}
                        </span>
                      </td>
                      <td className="py-3 pr-3 whitespace-nowrap">
                        {f.session_id ? (
                          <span className="text-sky-400 text-[11px]">{f.session_id}</span>
                        ) : (
                          <span className="text-slate-600">Capture-wide</span>
                        )}
                      </td>
                      <td className="py-3 pr-3 max-w-xs truncate text-slate-400 text-[11px]" title={evidenceSnippet}>
                        {evidenceSnippet}
                      </td>
                      <td className="py-3 pr-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            f.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : f.severity === 'HIGH'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : f.severity === 'MEDIUM'
                              ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                              : 'bg-slate-900 text-slate-400 border border-slate-800'
                          }`}
                        >
                          {f.risk || f.severity}
                        </span>
                      </td>
                      <td className="py-3 text-right whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/60 text-rose-300 border border-rose-800/80">
                          {f.status || 'DETECTED'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Drawer */}
      <Drawer
        isOpen={selectedFinding !== null}
        onClose={() => setSelectedFinding(null)}
        title={selectedFinding?.title || 'Security Finding Details'}
        subtitle={selectedFinding ? `Finding ID: ${selectedFinding.id}` : undefined}
      >
        {selectedFinding && (
          <div className="space-y-6">
            {/* Header / Severity Pill */}
            <div className="flex items-center justify-between pb-3 border-b border-[#1e293b]">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={selectedFinding.severity} />
                <span className="text-xs font-mono text-slate-400 uppercase">
                  {selectedFinding.category}
                </span>
              </div>
              <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800">
                {selectedFinding.status || 'DETECTED'}
              </span>
            </div>

            {/* 1. What was detected */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold block">
                What Was Detected
              </span>
              <h4 className="text-sm font-bold text-white">{selectedFinding.title}</h4>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedFinding.description}
              </p>
            </div>

            {/* 2. Why it matters (Risk & Impact) */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono uppercase tracking-wider text-amber-400 font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Why It Matters (Risk & Impact)
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  Risk Rating: {selectedFinding.risk || selectedFinding.severity}
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {selectedFinding.risk ||
                  `This vulnerability violates cryptographic best practices. Attackers performing passive network sniffing or active MITM manipulation may compromise email confidentiality, intercept authentication tokens, or force downgrade attacks.`}
              </p>
            </div>

            {/* 3. Evidence */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-sky-400 font-semibold flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                Observed Forensic Evidence
              </span>
              <div className="p-3 rounded bg-[#080d16] border border-[#1a2333] text-sky-300 text-xs font-mono break-all leading-relaxed">
                {selectedFinding.evidence || selectedFinding.technical_details || 'Observed directly in stream capture.'}
              </div>
            </div>

            {/* 4. Affected Session & Scope */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-3 font-mono text-xs">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">
                Affected Scope & Targets
              </span>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-slate-500 text-[11px]">Affected Session:</span>
                  <div className="text-slate-200 font-bold mt-0.5">
                    {selectedFinding.session_id || 'Capture-wide'}
                  </div>
                </div>
                <div>
                  <span className="text-slate-500 text-[11px]">Protocol:</span>
                  <div className="text-slate-200 font-bold mt-0.5">
                    {selectedFinding.protocol ? selectedFinding.protocol.toUpperCase() : 'N/A'}
                  </div>
                </div>
                {selectedFinding.tls_version && (
                  <div>
                    <span className="text-slate-500 text-[11px]">TLS Version:</span>
                    <div className="text-slate-200 font-bold mt-0.5">
                      {selectedFinding.tls_version}
                    </div>
                  </div>
                )}
                {selectedFinding.certificate_id && (
                  <div>
                    <span className="text-slate-500 text-[11px]">Certificate Ref:</span>
                    <div className="text-purple-400 font-bold mt-0.5 truncate">
                      {selectedFinding.certificate_id}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* 5. Recommendation & Remediation */}
            <div className="p-4 rounded-lg bg-[#0d1422] border border-emerald-900/60 space-y-3">
              <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-semibold flex items-center gap-1.5">
                <Wrench className="w-3.5 h-3.5" />
                Remediation & Recommendation
              </span>
              <p className="text-xs text-slate-200 leading-relaxed">
                {selectedFinding.recommendation || selectedFinding.remediation}
              </p>
              {(selectedFinding.rfc_reference || selectedFinding.cve_reference) && (
                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#182338] text-[11px] font-mono">
                  {selectedFinding.rfc_reference && (
                    <span className="px-2 py-0.5 rounded bg-[#080d16] text-sky-400 border border-sky-900">
                      Standard: {selectedFinding.rfc_reference}
                    </span>
                  )}
                  {selectedFinding.cve_reference && (
                    <span className="px-2 py-0.5 rounded bg-[#080d16] text-amber-400 border border-amber-900">
                      CVE: {selectedFinding.cve_reference}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
