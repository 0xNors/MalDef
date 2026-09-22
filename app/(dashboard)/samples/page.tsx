"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Upload, FileSearch, Search, Zap, Eye, Clock } from "lucide-react";
import Link from "next/link";

export default function SamplesPage() {
  const [samples, setSamples] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [search, setSearch] = useState("");
  const [telemetryModal, setTelemetryModal] = useState<string | null>(null);
  const [telemetryData, setTelemetryData] = useState("");

  const fetchSamples = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/samples?search=${encodeURIComponent(search)}`);
      const data = await res.json();
      setSamples(Array.isArray(data) ? data : []);
    } catch {}
    setLoading(false);
  };

  useEffect(() => { fetchSamples(); }, []);

  const handleUpload = async (file: File) => {
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch("/api/samples/upload", { method: "POST", body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      // Redirect to analysis page for deep scanning like VirusTotal - takes time for most accurate
      window.location.href = `/analysis/${data.sample.id}`;
    } catch (e: any) {
      alert(e.message);
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleUpload(file);
  };

  const importTelemetry = async (sampleId: string) => {
    try {
      const events = JSON.parse(telemetryData);
      if (!Array.isArray(events)) throw new Error("Must be JSON array");
      
      const behaviorEvents = events.filter((e: any) => e.event_type);
      const networkEvents = events.filter((e: any) => e.destination_ip || e.destinationIp || e.destination_domain);
      
      if (behaviorEvents.length > 0) {
        await fetch("/api/telemetry/import", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sampleId, events: behaviorEvents, type: "behavior" })
        });
      }
      if (networkEvents.length > 0) {
        await fetch("/api/telemetry/import", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sampleId, events: networkEvents, type: "network" })
        });
      }
      
      await fetch(`/api/samples/${sampleId}/analyze`, { method: "POST" });
      setTelemetryModal(null);
      setTelemetryData("");
      fetchSamples();
    } catch (e: any) {
      alert("Import failed: " + e.message);
    }
  };

  return (
    <div className="p-4 lg:p-6 max-w-[1600px] mx-auto space-y-6">
      <div className="flex flex-col lg:flex-row justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-white flex items-center gap-3">
            <FileSearch className="w-6 h-6 text-[#ff3344]" />
            SAMPLE ANALYSIS
          </h1>
          <p className="text-[#71717a] text-sm font-mono mt-1">Enterprise file analysis • Real-time static analysis • No execution • Production grade</p>
        </div>
        <div className="flex gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525b]" />
            <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && fetchSamples()}
              placeholder="Search hash, filename, ID..." className="pl-10 pr-4 py-2.5 bg-[#181825] border border-[#27272a] rounded-xl text-white text-sm w-[260px] focus:border-[#ff3344]/50 outline-none" />
          </div>
          <button onClick={fetchSamples} className="px-4 py-2.5 bg-[#27272a] hover:bg-[#3f3f46] rounded-xl text-white text-sm">Search</button>
        </div>
      </div>

      <motion.div
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`relative glass rounded-2xl border-2 border-dashed p-8 text-center transition-all ${dragOver ? 'border-[#ff3344] bg-[#ff3344]/5' : 'border-[#27272a] hover:border-[#ff3344]/30'}`}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-[#ff3344]/5 to-transparent opacity-0 hover:opacity-100 transition-opacity rounded-2xl"></div>
        <div className="relative">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[#ff3344]/20 to-[#8b5cf6]/20 border border-[#ff3344]/20 flex items-center justify-center">
            <Upload className="w-8 h-8 text-[#ff3344]" />
          </div>
          <h3 className="text-white font-bold mb-2">Drop file here or click to browse</h3>
          <p className="text-[#71717a] text-xs font-mono mb-4">Max 20MB • SHA256/SHA1/MD5 • Entropy • PE Analysis • Real-time scoring</p>
          
          <input type="file" id="file-upload" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) handleUpload(f); }} />
          <label htmlFor="file-upload" className="inline-flex items-center gap-2 px-6 py-2.5 bg-white text-black rounded-xl font-bold text-sm hover:bg-[#e4e4e7] cursor-pointer transition-colors">
            <FileSearch className="w-4 h-4" />
            SELECT FILE
          </label>
          
          <div className="mt-4 flex justify-center gap-2 text-[10px] font-mono">
            <span className="px-2 py-1 rounded-full bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20">PRODUCTION SAFE</span>
            <span className="px-2 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] border border-[#ff3344]/20">STATIC ONLY</span>
            <span className="px-2 py-1 rounded-full bg-[#8b5cf6]/10 text-[#8b5cf6] border border-[#8b5cf6]/20">NO EXECUTION</span>
          </div>
        </div>
        {uploading && (
          <div className="absolute inset-0 bg-[#0a0a0f]/80 backdrop-blur-sm rounded-2xl flex items-center justify-center">
            <div className="text-center">
              <div className="w-8 h-8 border-2 border-[#ff3344] border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
              <p className="text-[#ff3344] font-mono text-xs">UPLOADING & ANALYZING...</p>
            </div>
          </div>
        )}
      </motion.div>

      {loading ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-40 glass rounded-xl animate-pulse"></div>)}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {samples.map((sample) => (
            <motion.div key={sample.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-2xl border border-white/5 p-5 hover:border-[#ff3344]/20 transition-colors group">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-[#181825] border border-white/5 flex items-center justify-center">
                    <FileSearch className="w-5 h-5 text-[#71717a] group-hover:text-[#ff3344] transition-colors" />
                  </div>
                  <div>
                    <p className="text-white font-medium text-sm truncate max-w-[200px]">{sample.originalFilename}</p>
                    <p className="text-[11px] font-mono text-[#52525b]">{sample.id} • {(sample.fileSize / 1024).toFixed(1)} KB • {sample.mimeType}</p>
                  </div>
                </div>
                <span className={`px-2 py-1 rounded-full text-[10px] font-mono font-bold border
                  ${sample.analysisStatus === 'COMPLETED' ? 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/20' : 
                    sample.analysisStatus === 'ANALYZING' ? 'bg-[#ffcc00]/10 text-[#ffcc00] border-[#ffcc00]/20' :
                    sample.analysisStatus === 'FAILED' ? 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20' : 'bg-[#27272a] text-[#71717a] border-white/5'}`}>
                  {sample.analysisStatus}
                </span>
              </div>

              <div className="space-y-2 mb-4">
                <div className="flex gap-2 text-[10px] font-mono">
                  <span className="text-[#52525b]">SHA256:</span>
                  <span className="text-[#a1a1aa] truncate">{sample.sha256.substring(0, 32)}...</span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="w-3 h-3 text-[#52525b]" />
                  <span className="text-[11px] font-mono text-[#71717a]">{new Date(sample.uploadTimestamp).toLocaleString()}</span>
                  {sample.analysis && (
                    <span className={`ml-auto px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border severity-${sample.analysis.severity.toLowerCase()}`}>
                      {sample.analysis.classification} • {sample.analysis.riskScore}/100
                    </span>
                  )}
                </div>
              </div>

              {sample.analysis && (
                <div className="mb-4">
                  <div className="h-1.5 w-full bg-[#1e1e2e] rounded-full overflow-hidden">
                    <div className="h-full transition-all" style={{ width: `${sample.analysis.riskScore}%`, background: sample.analysis.riskScore >= 80 ? '#ff3344' : sample.analysis.riskScore >= 60 ? '#ff6b35' : sample.analysis.riskScore >= 30 ? '#ffcc00' : '#00ff88' }}></div>
                  </div>
                  <div className="flex justify-between mt-1.5">
                    <span className="text-[10px] font-mono text-[#52525b]">RISK SCORE</span>
                    <span className="text-[10px] font-mono text-white">{sample.analysis.riskScore}/100 • {sample.analysis.confidence}% confidence</span>
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <Link href={`/analysis/${sample.id}`} className="flex-1 py-2 rounded-xl bg-white text-black text-xs font-bold text-center hover:bg-[#e4e4e7] transition-colors flex items-center justify-center gap-1.5">
                  <Eye className="w-3.5 h-3.5" /> VIEW ANALYSIS
                </Link>
                <button onClick={() => setTelemetryModal(sample.id)} className="px-3 py-2 rounded-xl bg-[#181825] border border-white/5 text-[#a1a1aa] hover:text-white hover:border-[#ff3344]/20 text-xs font-mono transition-colors flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5" /> TELEMETRY
                </button>
                <Link href={`/investigation/${sample.id}`} className="px-3 py-2 rounded-xl bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 text-[#8b5cf6] hover:bg-[#8b5cf6]/15 text-xs font-bold transition-colors">
                  INVESTIGATE
                </Link>
              </div>
            </motion.div>
          ))}
        </div>
      )}

      {samples.length === 0 && !loading && (
        <div className="glass rounded-2xl border border-white/5 p-12 text-center">
          <FileSearch className="w-12 h-12 text-[#27272a] mx-auto mb-3" />
          <p className="text-white font-medium">No samples analyzed yet</p>
          <p className="text-[#71717a] text-sm font-mono mt-1">Upload files to begin enterprise threat analysis</p>
        </div>
      )}

      {telemetryModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl glass-strong rounded-2xl border border-[#ff3344]/20 overflow-hidden">
            <div className="p-5 border-b border-white/5 flex items-center justify-between">
              <h3 className="font-bold text-white flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#ff3344]" />
                IMPORT REAL TELEMETRY (SIEM/EDR)
              </h3>
              <button onClick={() => setTelemetryModal(null)} className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">✕</button>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-[11px] font-mono text-[#71717a]">Import real behavioral and network telemetry from your SIEM, EDR, or sandbox. Supports JSON array format with event_type, process, registry, network connections. Data is correlated with static analysis for enhanced risk scoring.</p>
              <div className="glass rounded-xl p-3 border border-white/5 bg-[#181825]">
                <p className="text-[10px] font-mono text-[#52525b] mb-2">EXAMPLE FORMAT:</p>
                <pre className="text-[10px] font-mono text-[#71717a] overflow-x-auto">
{`[
  {
    "timestamp": "2024-01-01T10:00:00Z",
    "event_type": "process_creation",
    "process": "suspicious.exe",
    "parent_process": "explorer.exe"
  },
  {
    "timestamp": "2024-01-01T10:00:05Z",
    "source_process": "suspicious.exe",
    "destination_ip": "192.168.1.100",
    "port": 443,
    "protocol": "TCP"
  }
]`}
                </pre>
              </div>
              <textarea value={telemetryData} onChange={e => setTelemetryData(e.target.value)} placeholder='Paste JSON array of real telemetry events from your security tools...'
                className="w-full h-[240px] bg-[#0a0a0f] border border-[#27272a] rounded-xl p-3 text-xs font-mono text-white placeholder-[#52525b] focus:border-[#ff3344]/50 outline-none" />
              <div className="flex gap-2">
                <button onClick={() => importTelemetry(telemetryModal)} className="flex-1 py-2.5 bg-[#ff3344] text-black rounded-xl font-bold text-sm hover:bg-[#ff3344]/90 transition-colors">IMPORT & RE-ANALYZE</button>
                <button onClick={() => setTelemetryModal(null)} className="px-6 py-2.5 bg-[#27272a] text-white rounded-xl text-sm">Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
