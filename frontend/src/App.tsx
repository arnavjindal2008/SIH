import React, { useState, useEffect } from 'react';
import { PageId } from './components/layout/Sidebar';
import { AppLayout } from './components/layout/AppLayout';
import {
  AnalysisSummary,
  AnalysisDetailResponse,
  HealthResponse,
} from './types/analyzer';
import { api } from './services/api';

// Pages
import { Dashboard } from './pages/Dashboard';
import { PcapAnalysis } from './pages/PcapAnalysis';
import { Sessions } from './pages/Sessions';
import { Findings } from './pages/Findings';
import { Certificates } from './pages/Certificates';
import { Protocols } from './pages/Protocols';
import { Recommendations } from './pages/Recommendations';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';

export const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<PageId>('dashboard');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [allAnalyses, setAllAnalyses] = useState<AnalysisSummary[]>([]);
  const [activeAnalysis, setActiveAnalysis] = useState<AnalysisSummary | null>(null);
  const [analysisDetail, setAnalysisDetail] = useState<AnalysisDetailResponse | null>(null);
  const [isUploading, setIsUploading] = useState(false);

  // Initial load
  useEffect(() => {
    checkHealth();
    loadAnalyses();
  }, []);

  // When active analysis changes, fetch full detail
  useEffect(() => {
    if (activeAnalysis) {
      loadAnalysisDetail(activeAnalysis.id);
    } else {
      setAnalysisDetail(null);
    }
  }, [activeAnalysis]);

  const checkHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (err) {
      console.error('Health check failed:', err);
    }
  };

  const loadAnalyses = async () => {
    try {
      const list = await api.listAnalyses();
      setAllAnalyses(list);
      if (list.length > 0 && !activeAnalysis) {
        setActiveAnalysis(list[0]);
      }
    } catch (err) {
      console.error('Failed to load analyses:', err);
    }
  };

  const loadAnalysisDetail = async (analysisId: string) => {
    try {
      const detail = await api.getAnalysisDetail(analysisId);
      setAnalysisDetail(detail);
    } catch (err) {
      console.error('Failed to load analysis detail:', err);
    }
  };

  const handleSelectAnalysis = (analysisId: string) => {
    const selected = allAnalyses.find((a) => a.id === analysisId) || null;
    setActiveAnalysis(selected);
  };

  const handleUpload = async (file: File) => {
    setIsUploading(true);
    try {
      const newAnalysis = await api.uploadPcap(file);
      await loadAnalyses();
      setActiveAnalysis(newAnalysis);
      setCurrentPage('dashboard');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <AppLayout
      currentPage={currentPage}
      onSelectPage={setCurrentPage}
      health={health}
      activeAnalysis={activeAnalysis}
      allAnalyses={allAnalyses}
      onSelectAnalysis={handleSelectAnalysis}
    >
      {currentPage === 'dashboard' && (
        <Dashboard
          analysisDetail={analysisDetail}
          activeAnalysis={activeAnalysis}
          onNavigate={setCurrentPage}
        />
      )}

      {currentPage === 'pcap-analysis' && (
        <PcapAnalysis
          allAnalyses={allAnalyses}
          activeAnalysis={activeAnalysis}
          onSelectAnalysis={handleSelectAnalysis}
          onUpload={handleUpload}
          isUploading={isUploading}
        />
      )}

      {currentPage === 'sessions' && (
        <Sessions activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'findings' && (
        <Findings activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'certificates' && (
        <Certificates activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'protocols' && (
        <Protocols activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'recommendations' && (
        <Recommendations activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'reports' && (
        <Reports activeAnalysis={activeAnalysis} />
      )}

      {currentPage === 'settings' && (
        <Settings health={health} />
      )}
    </AppLayout>
  );
};

export default App;
