import React from 'react';
import { SeverityLevel } from '../../types/analyzer';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sev = (severity || 'INFO').toUpperCase();

  const styles: Record<string, string> = {
    CRITICAL: 'bg-rose-950/80 text-rose-400 border-rose-800/80 shadow-rose-950/50',
    HIGH: 'bg-amber-950/80 text-amber-400 border-amber-800/80 shadow-amber-950/50',
    MEDIUM: 'bg-yellow-950/70 text-yellow-300 border-yellow-800/70 shadow-yellow-950/40',
    LOW: 'bg-blue-950/70 text-blue-400 border-blue-800/70 shadow-blue-950/40',
    INFO: 'bg-slate-900 text-slate-400 border-slate-700 shadow-slate-950/30',
  };

  const currentStyle = styles[sev] || styles.INFO;
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-semibold tracking-wide uppercase border rounded ${padding} ${currentStyle}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current"></span>
      {sev}
    </span>
  );
};
