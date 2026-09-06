import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'default' | 'critical' | 'warning' | 'success' | 'info';
  badgeText?: string;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'default',
  badgeText,
}) => {
  const borderColors = {
    default: 'border-[#1e293b]',
    critical: 'border-rose-900/60 bg-rose-950/10',
    warning: 'border-amber-900/60 bg-amber-950/10',
    success: 'border-emerald-900/60 bg-emerald-950/10',
    info: 'border-sky-900/60 bg-sky-950/10',
  };

  const iconColors = {
    default: 'text-slate-400 bg-slate-800/60',
    critical: 'text-rose-400 bg-rose-950/80',
    warning: 'text-amber-400 bg-amber-950/80',
    success: 'text-emerald-400 bg-emerald-950/80',
    info: 'text-sky-400 bg-sky-950/80',
  };

  return (
    <div className={`soc-card ${borderColors[variant]} flex flex-col justify-between relative overflow-hidden`}>
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
          <div className="mt-2 text-2xl font-bold tracking-tight text-white font-mono">{value}</div>
        </div>
        <div className={`p-2.5 rounded-lg border border-[#1e293b] ${iconColors[variant]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      {(subtitle || badgeText) && (
        <div className="mt-3 pt-3 border-t border-[#1e293b]/70 flex items-center justify-between text-xs text-slate-400">
          {subtitle && <span>{subtitle}</span>}
          {badgeText && (
            <span className="px-1.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
              {badgeText}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
