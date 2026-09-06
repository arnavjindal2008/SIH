import React from 'react';
import { Sidebar, PageId } from './Sidebar';
import { Header } from './Header';
import { AnalysisSummary, HealthResponse } from '../../types/analyzer';

interface AppLayoutProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
  health: HealthResponse | null;
  activeAnalysis: AnalysisSummary | null;
  allAnalyses: AnalysisSummary[];
  onSelectAnalysis: (analysisId: string) => void;
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  currentPage,
  onSelectPage,
  health,
  activeAnalysis,
  allAnalyses,
  onSelectAnalysis,
  children,
}) => {
  return (
    <div className="flex h-screen bg-[#090d16] text-slate-100 overflow-hidden font-sans">
      {/* Left Sidebar */}
      <Sidebar
        currentPage={currentPage}
        onSelectPage={onSelectPage}
        health={health}
        findingCount={activeAnalysis?.finding_count}
        sessionCount={activeAnalysis?.session_count}
      />

      {/* Main Workspace */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          currentPage={currentPage}
          activeAnalysis={activeAnalysis}
          allAnalyses={allAnalyses}
          onSelectAnalysis={onSelectAnalysis}
          onNavigateToUpload={() => onSelectPage('pcap-analysis')}
          onNavigateToReports={() => onSelectPage('reports')}
        />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#090d16]">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};
