import React, { useState, useRef } from 'react';
import { AnalysisSummary, PcapValidationResponse } from '../types/analyzer';
import { StatusBadge } from '../components/common/StatusBadge';
import { api } from '../services/api';
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
  Clock,
  HardDrive,
  FileText,
  Shield,
  Layers,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Play,
  Terminal,
  Activity,
} from 'lucide-react';

interface PcapAnalysisProps {
  allAnalyses: AnalysisSummary[];
  activeAnalysis: AnalysisSummary | null;
  onSelectAnalysis: (analysisId: string) => void;
  onUpload: (file: File) => Promise<void>;
  isUploading: boolean;
}

export const PcapAnalysis: React.FC<PcapAnalysisProps> = ({
  allAnalyses,
  activeAnalysis,
  onSelectAnalysis,
  onUpload,
  isUploading,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<PcapValidationResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analysisStep, setAnalysisStep] = useState<number>(0);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleSelectFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleSelectFile(e.target.files[0]);
    }
  };

  const handleSelectFile = async (file: File) => {
    setErrorMessage(null);
    setValidationResult(null);
    setAnalysisStep(0);

    // 1. Validate file extension
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!['pcap', 'pcapng', 'cap'].includes(ext || '')) {
      setErrorMessage(
        `Unsupported format '.${ext}'. Only standard Libpcap (.pcap) and PCAP Next Generation (.pcapng) files are accepted.`
      );
      setSelectedFile(null);
      return;
    }

    // 2. Reject empty files immediately
    if (file.size === 0) {
      setErrorMessage('The selected file is empty (0 bytes). Please upload a valid packet capture.');
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);

    // 3. Pre-flight backend validation (binary magic and decode test)
    setIsValidating(true);
    try {
      const res = await api.validatePcap(file);
      setValidationResult(res);
      if (!res.is_valid) {
        setErrorMessage(res.error || 'Corrupted PCAP file: The capture could not be decoded.');
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Error occurred while verifying capture integrity.');
    } finally {
      setIsValidating(false);
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;
    setErrorMessage(null);

    // Step 1: Pre-flight validation
    setAnalysisStep(1);

    try {
      // Step 2: Stream ingestion & IP/TCP frame extraction
      const timer1 = setTimeout(() => setAnalysisStep(2), 600);
      const timer2 = setTimeout(() => setAnalysisStep(3), 1400);
      const timer3 = setTimeout(() => setAnalysisStep(4), 2200);

      await onUpload(selectedFile);

      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      setAnalysisStep(5);

      // Reset selection after successful run
      setTimeout(() => {
        setSelectedFile(null);
        setValidationResult(null);
        setAnalysisStep(0);
      }, 1500);
    } catch (err: any) {
      setAnalysisStep(0);
      setErrorMessage(err.message || 'PCAP analysis failed.');
    }
  };

  const handleClearSelection = () => {
    setSelectedFile(null);
    setValidationResult(null);
    setErrorMessage(null);
    setAnalysisStep(0);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const isAnalyzing = isUploading || analysisStep > 0;

  return (
    <div className="space-y-6">
      {/* Upload & Validation Workspace */}
      <div className="soc-card space-y-5">
        <div>
          <h3 className="text-sm font-semibold text-white tracking-wide">Ingest Packet Capture (PCAP / PCAPNG)</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Passive offline inspection of enterprise email protocols (SMTP, SMTPS, IMAP, IMAPS, POP3, POP3S)
          </p>
        </div>

        {/* Dropzone Area (Shown when no file is selected) */}
        {!selectedFile ? (
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-10 flex flex-col items-center justify-center cursor-pointer transition-all ${
              dragActive
                ? 'border-sky-500 bg-sky-950/20'
                : 'border-[#1e293b] hover:border-slate-700 bg-[#0c1322]'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="w-14 h-14 rounded-full bg-sky-950/80 border border-sky-600/40 flex items-center justify-center text-sky-400 mb-4 shadow-inner">
              <UploadCloud className="w-7 h-7" />
            </div>

            <h4 className="text-sm font-semibold text-slate-200">
              Drag and drop enterprise PCAP or PCAPNG file here
            </h4>
            <p className="text-xs text-slate-500 mt-1">
              Supports Libpcap classic (.pcap), PCAP Next Generation (.pcapng), and Wireshark captures (up to 100MB)
            </p>

            <button
              type="button"
              className="mt-5 px-4 py-2 rounded-md bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs tracking-wider uppercase transition-colors"
            >
              Browse Files On Disk
            </button>
          </div>
        ) : (
          /* Selected File Inspection & Action Box */
          <div className="p-5 rounded-lg bg-[#0c1322] border border-[#1e293b] space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#182338]">
              <div className="flex items-start gap-3.5">
                <div className="w-10 h-10 rounded-lg bg-sky-950/80 border border-sky-600/50 flex items-center justify-center text-sky-400 shrink-0">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white font-mono">{selectedFile.name}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-950 text-sky-400 border border-sky-800 uppercase">
                      {selectedFile.name.endsWith('.pcapng') ? 'PCAPNG' : 'LIBPCAP'}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-xs font-mono text-slate-400 mt-1">
                    <span>Size: <strong className="text-slate-200">{formatFileSize(selectedFile.size)}</strong></span>
                    <span>Type: {selectedFile.type || 'application/vnd.tcpdump.pcap'}</span>
                  </div>
                </div>
              </div>

              {/* Validation Status Badge */}
              <div className="flex items-center gap-2">
                {isValidating ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono bg-sky-950/60 text-sky-400 border border-sky-800 animate-pulse">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    Validating PCAP Header...
                  </span>
                ) : validationResult?.is_valid ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    PCAP Signature Validated
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-800">
                    <XCircle className="w-3.5 h-3.5" />
                    Validation Failed
                  </span>
                )}
              </div>
            </div>

            {/* Analysis Progress Stepper */}
            {isAnalyzing && (
              <div className="p-4 rounded bg-[#090d16] border border-[#1e293b] space-y-3">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-sky-400 font-semibold uppercase tracking-wider flex items-center gap-2">
                    <Activity className="w-4 h-4 animate-spin text-sky-400" />
                    Analysis Pipeline Running...
                  </span>
                  <span className="text-slate-400">Step {analysisStep} of 4</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className={`p-2.5 rounded border text-center ${analysisStep >= 1 ? 'bg-sky-950/60 border-sky-800 text-sky-300' : 'bg-slate-900 border-slate-800 text-slate-500'}`}>
                    1. Header Integrity
                  </div>
                  <div className={`p-2.5 rounded border text-center ${analysisStep >= 2 ? 'bg-sky-950/60 border-sky-800 text-sky-300' : 'bg-slate-900 border-slate-800 text-slate-500'}`}>
                    2. IP / TCP Frame Scan
                  </div>
                  <div className={`p-2.5 rounded border text-center ${analysisStep >= 3 ? 'bg-sky-950/60 border-sky-800 text-sky-300' : 'bg-slate-900 border-slate-800 text-slate-500'}`}>
                    3. Reassemble Streams
                  </div>
                  <div className={`p-2.5 rounded border text-center ${analysisStep >= 4 ? 'bg-sky-950/60 border-sky-800 text-sky-300' : 'bg-slate-900 border-slate-800 text-slate-500'}`}>
                    4. Crypto Rules & ML
                  </div>
                </div>
              </div>
            )}

            {/* Action Buttons Row */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <button
                type="button"
                onClick={handleClearSelection}
                disabled={isAnalyzing}
                className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors disabled:opacity-50"
              >
                Change File
              </button>

              <button
                type="button"
                onClick={handleStartAnalysis}
                disabled={isAnalyzing || !validationResult?.is_valid}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-md bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs tracking-wider uppercase transition-colors disabled:opacity-40 shadow-md shadow-sky-950"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{isAnalyzing ? 'Analyzing PCAP Traffic...' : 'Analyze PCAP'}</span>
              </button>
            </div>
          </div>
        )}

        {/* Error Alert Banner */}
        {errorMessage && (
          <div className="p-4 rounded-lg bg-rose-950/60 border border-rose-800 text-xs text-rose-300 flex items-start gap-3 shadow-inner">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <strong className="block font-semibold uppercase tracking-wider text-rose-300">PCAP Rejection Error</strong>
              <p className="leading-relaxed">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Diagnostic note when tshark is not installed */}
        {validationResult && !validationResult.tshark_available && (
          <div className="p-3 rounded bg-[#0e1628] border border-slate-800 text-xs text-slate-400 flex items-center justify-between font-mono">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-slate-500" />
              <span>Capture Engine: Scapy Native Libpcap (tshark CLI is not installed on host)</span>
            </div>
            <span className="text-[11px] text-sky-400">Standard Parsing Mode</span>
          </div>
        )}
      </div>

      {/* Historical Analyses Repository */}
      <div className="soc-card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-wide">Forensic Capture Repository</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified PCAP analyses with extracted TCP streams ({allAnalyses.length} total)
            </p>
          </div>
        </div>

        {allAnalyses.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs font-mono">
            No PCAP files have been ingested into the forensic repository yet.
          </div>
        ) : (
          <div className="overflow-x-auto border border-[#1e293b] rounded-lg">
            <table className="w-full text-left soc-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>Packets (Total)</th>
                  <th>IP Packets</th>
                  <th>TCP Packets</th>
                  <th>TCP Streams</th>
                  <th>Email Streams</th>
                  <th>Findings</th>
                  <th>Score</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182338]">
                {allAnalyses.map((a) => {
                  const isCurrent = activeAnalysis?.id === a.id;
                  const scoreColor =
                    a.security_score === null || a.security_score === undefined
                      ? 'text-slate-500'
                      : a.security_score >= 80
                      ? 'text-emerald-400'
                      : a.security_score >= 50
                      ? 'text-amber-400'
                      : 'text-rose-400';

                  const pktCount = a.packet_count ?? a.total_packets;
                  const fileSize = a.file_size ?? a.file_size_bytes;

                  return (
                    <tr
                      key={a.id}
                      className={`hover:bg-[#121c2e] transition-colors ${
                        isCurrent ? 'bg-[#142036]/60 border-l-2 border-l-sky-500' : ''
                      }`}
                    >
                      <td>
                        <StatusBadge status={a.status} />
                      </td>
                      <td className="font-mono text-xs font-semibold text-slate-200">
                        {a.filename}
                      </td>
                      <td className="text-xs text-slate-400 font-mono">
                        {formatFileSize(fileSize)}
                      </td>
                      <td className="text-xs font-mono text-slate-300 font-bold">
                        {pktCount.toLocaleString()}
                      </td>
                      <td className="text-xs font-mono text-slate-400">
                        {(a.ip_packet_count ?? 0).toLocaleString()}
                      </td>
                      <td className="text-xs font-mono text-slate-400">
                        {(a.tcp_packet_count ?? 0).toLocaleString()}
                      </td>
                      <td className="text-xs font-mono text-sky-400 font-bold">
                        {a.tcp_stream_count ?? 0}
                      </td>
                      <td className="text-xs font-mono text-slate-300">
                        {a.session_count}
                      </td>
                      <td className="text-xs font-mono">
                        <span className={a.finding_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                          {a.finding_count}
                        </span>
                      </td>
                      <td className={`text-xs font-mono font-bold ${scoreColor}`}>
                        {a.security_score !== null && a.security_score !== undefined
                          ? `${a.security_score}/100`
                          : 'N/A'}
                      </td>
                      <td className="text-right">
                        <button
                          onClick={() => onSelectAnalysis(a.id)}
                          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                            isCurrent
                              ? 'bg-sky-950 text-sky-400 border border-sky-800'
                              : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                          }`}
                        >
                          {isCurrent ? 'Active' : 'Load'}
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
    </div>
  );
};
