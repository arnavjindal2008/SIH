import React from 'react';
import { AnalysisStatus } from '../../types/analyzer';
import { CheckCircle2, Clock, AlertTriangle, XCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: AnalysisStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const s = (status || 'PENDING').toUpperCase();

  if (s === 'COMPLETED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/80">
        <CheckCircle2 className="w-3.5 h-3.5" />
        Completed
      </span>
    );
  }

  if (s === 'PROCESSING') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider rounded bg-sky-950/60 text-sky-400 border border-sky-800/80 animate-pulse">
        <Clock className="w-3.5 h-3.5 animate-spin" />
        Analyzing
      </span>
    );
  }

  if (s === 'FAILED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider rounded bg-rose-950/60 text-rose-400 border border-rose-800/80">
        <XCircle className="w-3.5 h-3.5" />
        Failed
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold uppercase tracking-wider rounded bg-slate-900 text-slate-400 border border-slate-700">
      <AlertTriangle className="w-3.5 h-3.5" />
      {status}
    </span>
  );
};
