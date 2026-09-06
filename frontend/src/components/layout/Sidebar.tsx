import React from 'react';
import {
  LayoutDashboard,
  FileSearch,
  Network,
  ShieldAlert,
  KeyRound,
  Binary,
  Compass,
  FileText,
  Settings,
  Shield,
  Activity,
} from 'lucide-react';
import { HealthResponse } from '../../types/analyzer';

export type PageId =
  | 'dashboard'
  | 'pcap-analysis'
  | 'sessions'
  | 'findings'
  | 'certificates'
  | 'protocols'
  | 'recommendations'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  health: HealthResponse | null;
  findingCount?: number;
  sessionCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onSelectPage,
  health,
  findingCount = 0,
  sessionCount = 0,
}) => {
  const navItems = [
    { id: 'dashboard' as PageId, label: 'Dashboard', icon: LayoutDashboard },
    { id: 'pcap-analysis' as PageId, label: 'PCAP Analysis', icon: FileSearch },
    { id: 'sessions' as PageId, label: 'Sessions', icon: Network, badge: sessionCount > 0 ? String(sessionCount) : undefined },
    { id: 'findings' as PageId, label: 'Findings', icon: ShieldAlert, badge: findingCount > 0 ? String(findingCount) : undefined, badgeCritical: findingCount > 0 },
    { id: 'certificates' as PageId, label: 'Certificates', icon: KeyRound },
    { id: 'protocols' as PageId, label: 'Protocols', icon: Binary },
    { id: 'recommendations' as PageId, label: 'Recommendations', icon: Compass },
    { id: 'reports' as PageId, label: 'Reports', icon: FileText },
    { id: 'settings' as PageId, label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0c121e] border-r border-[#1e293b] flex flex-col justify-between shrink-0 select-none">
      {/* Brand Header */}
      <div>
        <div className="p-5 border-b border-[#1e293b]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-sky-950/80 border border-sky-600/50 flex items-center justify-center text-sky-400 shadow-inner">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-wide leading-tight">ECSA Forensics</h1>
              <p className="text-[10px] uppercase font-mono text-sky-400 font-semibold tracking-wider">Passive PCAP Engine</p>
            </div>
          </div>
          <div className="mt-3 inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
            <span>SIH Enterprise Cyber Console</span>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectPage(item.id)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-md text-xs font-medium tracking-wide transition-colors ${
                  isActive
                    ? 'bg-sky-950/60 text-sky-300 border border-sky-800/60 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#131c2e]'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                      item.badgeCritical
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-slate-800 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Engine Health Status Footer */}
      <div className="p-4 border-t border-[#1e293b] bg-[#090d16]/70 text-xs">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Engine Status</span>
          <span className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            Online
          </span>
        </div>
        <div className="space-y-1 text-[11px] text-slate-400">
          <div className="flex justify-between">
            <span>FastAPI Backend:</span>
            <span className="text-slate-200 font-mono">{health?.status || 'Connecting...'}</span>
          </div>
          <div className="flex justify-between">
            <span>Cryptography:</span>
            <span className="text-emerald-400 font-mono">Active</span>
          </div>
          <div className="flex justify-between">
            <span>ML Anomaly:</span>
            <span className="text-emerald-400 font-mono">Scikit-Learn</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
