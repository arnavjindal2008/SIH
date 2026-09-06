import React, { useState, useEffect } from 'react';
import { RecommendationResponse, AnalysisSummary } from '../types/analyzer';
import { api } from '../services/api';
import { EmptyState } from '../components/common/EmptyState';
import {
  Compass,
  AlertTriangle,
  CheckCircle,
  Wrench,
  ShieldAlert,
  ArrowRight,
  Terminal,
  Layers,
  HelpCircle,
} from 'lucide-react';

interface RecommendationsProps {
  activeAnalysis: AnalysisSummary | null;
}

export const Recommendations: React.FC<RecommendationsProps> = ({ activeAnalysis }) => {
  const [data, setData] = useState<RecommendationResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!activeAnalysis) return;
    loadRecs();
  }, [activeAnalysis?.id]);

  const loadRecs = async () => {
    if (!activeAnalysis) return;
    setLoading(true);
    try {
      const res = await api.getRecommendations(activeAnalysis.id);
      setData(res);
    } catch (err) {
      console.error('Failed to load recommendations:', err);
    } finally {
      setLoading(false);
    }
  };

  if (!activeAnalysis) {
    return (
      <EmptyState
        icon={Compass}
        title="No PCAP Analysis Selected"
        description="Select or upload a PCAP capture to generate prioritized cryptographic hardening recommendations."
      />
    );
  }

  const priorityStyles = {
    IMMEDIATE: 'bg-rose-950/80 text-rose-400 border-rose-800',
    HIGH: 'bg-amber-950/80 text-amber-400 border-amber-800',
    MEDIUM: 'bg-yellow-950/80 text-yellow-300 border-yellow-800',
    LOW: 'bg-blue-950/80 text-blue-400 border-blue-800',
  };

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="soc-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide">
            Prioritized Hardening Recommendations
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Actionable cryptographic directives generated exclusively from observed flaws in target PCAP traffic
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="px-3 py-1.5 rounded bg-rose-950/50 border border-rose-800 text-rose-300">
            Immediate Actions: <strong>{data?.immediate_actions_count || 0}</strong>
          </div>
          <div className="px-3 py-1.5 rounded bg-[#0c121e] border border-[#1e293b] text-slate-300">
            Total Directives: <strong>{data?.total_recommendations || 0}</strong>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="soc-card py-16 text-center text-xs text-slate-400 font-mono">
          Generating cryptographic hardening directives...
        </div>
      ) : !data || data.recommendations.length === 0 ? (
        <div className="soc-card py-16 text-center text-xs text-slate-500 font-mono">
          No vulnerabilities were observed in this capture. The analyzed email traffic adheres to security baselines.
        </div>
      ) : (
        <div className="space-y-6">
          {data.recommendations.map((rec) => (
            <div key={rec.id} className="soc-card space-y-4 border border-[#1e293b] hover:border-[#334155] transition-colors">
              {/* Header with Priority and Finding */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1e293b]">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${
                      priorityStyles[rec.priority] || priorityStyles.MEDIUM
                    }`}
                  >
                    {rec.priority} PRIORITY
                  </span>
                  <div>
                    <h4 className="text-sm font-bold text-white">{rec.finding || rec.title}</h4>
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                      {rec.finding_category}
                    </span>
                  </div>
                </div>
                <div className="text-xs font-mono text-slate-400 bg-[#090e17] px-2.5 py-1 rounded border border-[#1e293b]">
                  Affected Sessions: <strong className="text-sky-400">{rec.affected_sessions_count}</strong>
                </div>
              </div>

              {/* 1. Reason / Justification */}
              <div className="p-3.5 rounded-lg bg-[#0d1422] border border-[#1e293b] space-y-1 text-xs">
                <span className="text-[11px] font-mono uppercase tracking-wider text-amber-400 font-semibold flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5" />
                  Reason / Technical Justification
                </span>
                <p className="text-slate-300 leading-relaxed font-mono text-[11px]">
                  {rec.reason || rec.description}
                </p>
              </div>

              {/* 2. Recommended Action */}
              <div className="p-3.5 rounded-lg bg-[#0a1520] border border-sky-900/60 space-y-2 text-xs">
                <span className="text-[11px] font-mono uppercase tracking-wider text-sky-400 font-semibold flex items-center gap-1.5">
                  <Wrench className="w-3.5 h-3.5" />
                  Recommended Action
                </span>
                <p className="text-slate-200 leading-relaxed font-medium">
                  {rec.recommended_action || rec.description}
                </p>

                {rec.remediation_steps && rec.remediation_steps.length > 0 && (
                  <div className="pt-2 border-t border-sky-950/80 space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      Implementation Checklist:
                    </span>
                    <ul className="space-y-1">
                      {rec.remediation_steps.map((step, idx) => (
                        <li key={idx} className="text-[11px] text-slate-300 flex items-start gap-2 font-mono">
                          <CheckCircle className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* 3. Affected Sessions List */}
              {rec.affected_sessions && rec.affected_sessions.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] uppercase font-mono text-slate-400 font-semibold block">
                    Affected Stream Instances:
                  </span>
                  <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                    {rec.affected_sessions.map((sessId, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-[#080d16] text-slate-300 border border-[#1e293b]"
                      >
                        {sessId}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* 4. Compliance Mappings */}
              {rec.compliance_standards && rec.compliance_standards.length > 0 && (
                <div className="pt-2 border-t border-[#1e293b] flex flex-wrap items-center gap-2">
                  <span className="text-[10px] uppercase font-mono text-slate-500 font-semibold">
                    Compliance Standards:
                  </span>
                  {rec.compliance_standards.map((std, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#0c121e] text-sky-400 border border-sky-900/60"
                    >
                      {std}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
