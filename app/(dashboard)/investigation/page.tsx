"use client";
import { useEffect, useState } from "react";
import { Shield, SearchCheck, Clock, AlertTriangle, FileSearch, Target, Activity, Brain, Filter, Search } from "lucide-react";
import Link from "next/link";

export default function InvestigationListPage() {
  const [samples, setSamples] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  const fetchData = async () => {
    setLoading(true);
    try {
      const [sRes, aRes] = await Promise.all([fetch('/api/samples'), fetch('/api/alerts')]);
      const sData = await sRes.json();
      const aData = await aRes.json();
      const sampleArr = Array.isArray(sData.samples) ? sData.samples : Array.isArray(sData) ? sData : [];
      const alertArr = Array.isArray(aData) ? aData : [];
      setSamples(sampleArr);
      setAlerts(alertArr);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(()=>{fetchData();},[]);

  const filtered = samples.filter((s:any)=>{
    if (!search) return true;
    const low = search.toLowerCase();
    return s.originalFilename.toLowerCase().includes(low) || s.sha256.toLowerCase().includes(low) || s.id.toLowerCase().includes(low);
  });

  const getInvestigationStatus = (sampleId:string) => {
    const al = alerts.find((a:any)=>a.sampleId===sampleId);
    return al ? al.status : 'NO_ALERT';
  };

  return (
    <div className="p-4 lg:p-6 max-w-[1600px] mx-auto space-y-6">
      <div className="flex flex-col lg:flex-row justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#8b5cf6]/15 border border-[#8b5cf6]/20 flex items-center justify-center">
              <SearchCheck className="w-5 h-5 text-[#8b5cf6]" />
            </div>
            INVESTIGATION HUB
            <span className="px-2.5 py-1 rounded-full bg-[#8b5cf6]/15 text-[#a78bfa] border border-[#8b5cf6]/20 text-[12px] font-mono">{samples.length} cases • {alerts.length} alerts</span>
          </h1>
          <p className="text-[#71717a] text-[12px] font-mono mt-2">Incident response • Evidence collection • MITRE mapping • Workflow • All investigations from 29-engine deep scan</p>
        </div>
        <div className="flex gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525b]" />
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search investigations..." className="pl-10 pr-4 py-2.5 bg-[#181825] border border-[#27272a] rounded-xl text-white text-sm w-[260px]" />
          </div>
          <Link href="/alerts" className="px-4 py-2.5 bg-[#ff3344]/10 border border-[#ff3344]/20 rounded-xl text-[#ff5252] text-sm font-bold flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Alert Queue ({alerts.length})
          </Link>
          <Link href="/samples" className="px-4 py-2.5 bg-[#4f46e5] rounded-xl text-white text-sm font-bold">Samples</Link>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-4 rounded-2xl bg-[#12121a] border border-white/[0.06]"><p className="text-[11px] font-mono text-[#6b7280]">TOTAL INVESTIGATIONS</p><p className="text-[22px] font-bold text-white mt-1">{samples.length}</p><p className="text-[10px] text-[#52525b] mt-1">Samples uploaded</p></div>
        <div className="p-4 rounded-2xl bg-[#8b5cf6]/5 border border-[#8b5cf6]/20"><p className="text-[11px] font-mono text-[#a78bfa]">WITH ALERTS</p><p className="text-[22px] font-bold text-[#a78bfa] mt-1">{alerts.length}</p><p className="text-[10px] text-[#8b5cf6]/70 mt-1">Need investigation</p></div>
        <div className="p-4 rounded-2xl bg-[#ffab00]/5 border border-[#ffab00]/20"><p className="text-[11px] font-mono text-[#ffab00]">INVESTIGATING</p><p className="text-[22px] font-bold text-[#ffab00] mt-1">{alerts.filter((a:any)=>a.status==='INVESTIGATING').length}</p><p className="text-[10px] text-[#ffab00]/70 mt-1">Active</p></div>
        <div className="p-4 rounded-2xl bg-[#00c853]/5 border border-[#00c853]/20"><p className="text-[11px] font-mono text-[#00c853]">CLEAN / BENIGN</p><p className="text-[22px] font-bold text-[#00c853] mt-1">{samples.length - alerts.length}</p><p className="text-[10px] text-[#00c853]/70 mt-1">0/29 no alert</p></div>
      </div>

      <div className="glass rounded-2xl border border-white/5 overflow-hidden">
        <div className="px-6 py-4 border-b border-white/5 bg-[#16161f] flex items-center justify-between">
          <h3 className="text-[13px] font-bold tracking-wide text-white flex items-center gap-2"><FileSearch className="w-5 h-5 text-[#8b5cf6]" />ALL INVESTIGATIONS • Click to open incident response</h3>
          <span className="text-[11px] font-mono text-[#6b7280]">{filtered.length} cases</span>
        </div>
        <div className="divide-y divide-white/[0.04]">
          {filtered.map((s:any)=>{
            const status = getInvestigationStatus(s.id);
            const al = alerts.find((a:any)=>a.sampleId===s.id);
            return (
              <div key={s.id} className="p-5 hover:bg-white/[0.02] flex items-center gap-4 group">
                <div className="w-10 h-10 rounded-xl bg-[#181825] border border-white/10 flex items-center justify-center flex-shrink-0">
                  <FileSearch className="w-5 h-5 text-[#8b5cf6]" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-white font-bold text-[13px] truncate">{s.originalFilename}</p>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${status==='NEW'?'bg-[#ff3344]/15 text-[#ff3344] border-[#ff3344]/20':status==='INVESTIGATING'?'bg-[#ffab00]/15 text-[#ffab00] border-[#ffab00]/20':status==='NO_ALERT'?'bg-[#00c853]/15 text-[#00c853] border-[#00c853]/20':'bg-[#27272a] text-[#9ca3af] border-white/10'}`}>{status}</span>
                    {al && <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${al.severity==='CRITICAL'?'bg-[#d50000]/15 text-[#ff5252] border-[#d50000]/20':'bg-[#27272a] text-[#9ca3af] border-white/10'}`}>{al.severity} {al.riskScore}/100</span>}
                  </div>
                  <p className="text-[11px] font-mono text-[#6b7280] mt-1 flex items-center gap-2"><span>{s.id.substring(0,20)}...</span><span>•</span><span>{s.sha256.substring(0,16)}...</span><span>•</span><span>{(s.fileSize/1024).toFixed(1)} KB</span><span>•</span><span>{new Date(s.uploadTimestamp).toLocaleString()}</span></p>
                  {al && <p className="text-[11px] text-[#9ca3af] mt-1 truncate max-w-[600px]">{al.detectionReason}</p>}
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <Link href={`/investigation/${s.id}`} className="px-4 py-2 rounded-xl bg-white text-black text-[11px] font-bold hover:bg-[#e4e4e7] flex items-center gap-1.5">
                    <SearchCheck className="w-4 h-4" /> INVESTIGATE
                  </Link>
                  <Link href={`/analysis/${s.id}`} className="px-3 py-2 rounded-xl bg-[#181825] border border-white/10 text-white text-[11px] font-bold hover:bg-[#27272a] flex items-center gap-1">
                    <Target className="w-4 h-4" /> Analysis
                  </Link>
                </div>
              </div>
            );
          })}
          {filtered.length===0 && !loading && (
            <div className="p-12 text-center">
              <p className="text-white font-bold">No investigations yet</p>
              <p className="text-[#6b7280] text-[12px] mt-1">Upload files in Samples to create investigations. Malicious files auto-generate alerts.</p>
              <Link href="/samples" className="mt-4 inline-flex px-5 py-2.5 rounded-xl bg-[#4f46e5] text-white text-[12px] font-bold">Go to Samples</Link>
            </div>
          )}
          {loading && <div className="p-12 text-center"><div className="w-6 h-6 border-2 border-[#8b5cf6] border-t-transparent rounded-full animate-spin mx-auto"></div><p className="text-[11px] font-mono text-[#6b7280] mt-2">Loading investigations...</p></div>}
        </div>
      </div>
    </div>
  );
}
