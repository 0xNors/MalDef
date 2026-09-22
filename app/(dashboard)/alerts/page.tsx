"use client";
import { useEffect, useState } from "react";
import { AlertTriangle, Search, Filter, Eye, Clock, Shield, CheckCircle2, XCircle, AlertCircle, Brain, Target, Activity, Timer, SearchCheck, ShieldAlert, Workflow, BarChart3 } from "lucide-react";
import Link from "next/link";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [search, setSearch] = useState("");
  const [stats, setStats] = useState({ total: 0, new: 0, investigating: 0, resolved: 0, critical: 0 });

  const fetchAlerts = async () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (statusFilter) params.set("status", statusFilter);
    if (severityFilter) params.set("severity", severityFilter);
    if (search) params.set("search", search);
    try {
      const res = await fetch(`/api/alerts?${params}`);
      const data = await res.json();
      const arr = Array.isArray(data) ? data : [];
      setAlerts(arr);
      // calc stats
      setStats({
        total: arr.length,
        new: arr.filter((a:any)=>a.status==='NEW').length,
        investigating: arr.filter((a:any)=>a.status==='INVESTIGATING').length,
        resolved: arr.filter((a:any)=>a.status==='RESOLVED' || a.status==='CONTAINED').length,
        critical: arr.filter((a:any)=>a.severity==='CRITICAL').length,
      });
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchAlerts(); }, [statusFilter, severityFilter]);

  const getSeverityColor = (sev: string) => {
    switch(sev){
      case 'CRITICAL': return 'bg-[#d50000]/15 text-[#ff5252] border-[#d50000]/30';
      case 'HIGH': return 'bg-[#ff6b35]/15 text-[#ff6b35] border-[#ff6b35]/30';
      case 'MEDIUM': return 'bg-[#ffab00]/15 text-[#ffab00] border-[#ffab00]/30';
      default: return 'bg-[#6b7280]/15 text-[#9ca3af] border-white/10';
    }
  };

  const getStatusColor = (status: string) => {
    switch(status){
      case 'NEW': return 'bg-[#ff3344]/15 text-[#ff3344] border-[#ff3344]/20 animate-pulse';
      case 'INVESTIGATING': return 'bg-[#ffab00]/15 text-[#ffab00] border-[#ffab00]/20';
      case 'CONTAINED': return 'bg-[#8b5cf6]/15 text-[#a78bfa] border-[#8b5cf6]/20';
      case 'RESOLVED': return 'bg-[#00c853]/15 text-[#00c853] border-[#00c853]/20';
      case 'FALSE_POSITIVE': return 'bg-[#6b7280]/15 text-[#9ca3af] border-white/10';
      default: return 'bg-[#27272a] text-[#a1a1aa] border-white/5';
    }
  };

  return (
    <div className="p-4 lg:p-6 max-w-[1600px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#ff3344]/15 border border-[#ff3344]/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-[#ff3344]" />
            </div>
            ALERT QUEUE
            <span className="w-2.5 h-2.5 bg-[#ff3344] rounded-full animate-pulse shadow-[0_0_10px_#ff3344]"></span>
            <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/15 text-[#ff3344] border border-[#ff3344]/20 text-[12px] font-mono">{stats.total} total • {stats.new} NEW • {stats.critical} CRITICAL</span>
          </h1>
          <p className="text-[#71717a] text-[12px] font-mono mt-2 flex items-center gap-2">
            <Workflow className="w-3.5 h-3.5" /> SOC alert triage • Status workflow • Analyst assignment • Deep scan auto-generates alerts when risk ≥20 • Investigation hub integrated
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2.5 bg-[#181825] border border-[#27272a] rounded-xl text-white text-sm focus:border-[#ff3344]/30">
            <option value="">All Status</option>
            <option value="NEW">NEW</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
          </select>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className="px-3 py-2.5 bg-[#181825] border border-[#27272a] rounded-xl text-white text-sm focus:border-[#ff3344]/30">
            <option value="">All Severity</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525b]" />
            <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && fetchAlerts()} placeholder="Search alerts, sample, reason..." className="pl-10 pr-4 py-2.5 bg-[#181825] border border-[#27272a] rounded-xl text-white text-sm w-[260px] focus:border-[#4f46e5]/30" />
          </div>
          <button onClick={fetchAlerts} className="px-4 py-2.5 bg-[#4f46e5] hover:bg-[#4338ca] rounded-xl text-white text-sm font-bold shadow-[0_0_15px_rgba(79,70,229,0.2)] flex items-center gap-2">
            <Filter className="w-4 h-4" /> Filter
          </button>
          <Link href="/samples" className="px-4 py-2.5 bg-[#27272a] hover:bg-[#3f3f46] rounded-xl text-white text-sm font-bold flex items-center gap-2">
            <SearchCheck className="w-4 h-4" /> Investigate Samples
          </Link>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="p-4 rounded-2xl bg-[#12121a] border border-white/[0.06]">
          <p className="text-[11px] font-mono text-[#6b7280] flex items-center gap-2"><BarChart3 className="w-4 h-4" />TOTAL ALERTS</p>
          <p className="text-[24px] font-bold text-white mt-1">{stats.total}</p>
          <p className="text-[10px] text-[#52525b] mt-1">Auto from deep scan risk ≥20</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#ff3344]/5 border border-[#ff3344]/20">
          <p className="text-[11px] font-mono text-[#ff3344]">NEW • Needs Triage</p>
          <p className="text-[24px] font-bold text-[#ff5252] mt-1">{stats.new}</p>
          <p className="text-[10px] text-[#ff3344]/70 mt-1">Unassigned SOC queue</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#ffab00]/5 border border-[#ffab00]/20">
          <p className="text-[11px] font-mono text-[#ffab00]">INVESTIGATING</p>
          <p className="text-[24px] font-bold text-[#ffab00] mt-1">{stats.investigating}</p>
          <p className="text-[10px] text-[#ffab00]/70 mt-1">Active investigations</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#d50000]/5 border border-[#d50000]/20">
          <p className="text-[11px] font-mono text-[#ff5252]">CRITICAL</p>
          <p className="text-[24px] font-bold text-[#ff5252] mt-1">{stats.critical}</p>
          <p className="text-[10px] text-[#ff5252]/70 mt-1">Immediate response</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#00c853]/5 border border-[#00c853]/20">
          <p className="text-[11px] font-mono text-[#00c853]">RESOLVED/CONTAINED</p>
          <p className="text-[24px] font-bold text-[#00c853] mt-1">{stats.resolved}</p>
          <p className="text-[10px] text-[#00c853]/70 mt-1">Closed alerts</p>
        </div>
      </div>

      {/* Table */}
      <div className="glass rounded-2xl border border-white/5 overflow-hidden">
        <div className="px-6 py-4 border-b border-white/5 bg-[#16161f] flex items-center justify-between">
          <h3 className="text-[13px] font-bold tracking-wide text-white flex items-center gap-2"><ShieldAlert className="w-5 h-5 text-[#ff3344]" />SOC ALERTS • Real-time from 29-engine deep scan • Click INVESTIGATE for full incident response</h3>
          <span className="text-[11px] font-mono text-[#6b7280] px-3 py-1 rounded-full bg-[#1e1e2e] border border-white/10">{loading ? 'Loading...' : `${alerts.length} alerts`}</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-[10px] font-mono tracking-wide text-[#52525b] border-b border-white/5 bg-[#0f0f14]">
                <th className="text-left p-4">ALERT ID</th>
                <th className="text-left p-4">SAMPLE</th>
                <th className="text-left p-4">SEVERITY</th>
                <th className="text-left p-4">RISK</th>
                <th className="text-left p-4">REASON • 29 engines + MITRE + CrowdStrike</th>
                <th className="text-left p-4">STATUS</th>
                <th className="text-left p-4">ANALYST</th>
                <th className="text-left p-4">ACTION • Investigation</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id} className="border-b border-white/[0.03] hover:bg-white/[0.03] text-sm group transition-colors">
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-7 h-7 rounded-lg bg-[#ff3344]/10 border border-[#ff3344]/20 flex items-center justify-center"><AlertTriangle className="w-3.5 h-3.5 text-[#ff3344]" /></div>
                      <span className="font-mono text-[#ff3344] text-[11px] font-bold">{alert.id}</span>
                    </div>
                    <p className="text-[10px] font-mono text-[#52525b] mt-1 flex items-center gap-1"><Clock className="w-3 h-3" />{new Date(alert.timestamp).toLocaleString()}</p>
                  </td>
                  <td className="p-4">
                    <p className="text-white text-[12px] font-bold truncate max-w-[180px]">{alert.sampleFilename}</p>
                    <p className="text-[10px] font-mono text-[#6b7280] mt-1">{alert.sampleId?.substring(0,16)}...</p>
                    <div className="flex gap-1 mt-1.5">
                      {alert.mitreTechniques?.slice(0,3).map((t:string,i:number)=>(<span key={i} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[#8b5cf6]/15 text-[#a78bfa] border border-[#8b5cf6]/20">{t}</span>))}
                    </div>
                  </td>
                  <td className="p-4"><span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border flex items-center gap-1 w-fit ${getSeverityColor(alert.severity)}`}>{alert.severity==='CRITICAL'?<XCircle className="w-3 h-3" />:alert.severity==='HIGH'?<AlertTriangle className="w-3 h-3" />:<AlertCircle className="w-3 h-3" />}{alert.severity}</span></td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-[#1e1e2e] rounded-full overflow-hidden"><div className="h-full transition-all" style={{ width: `${alert.riskScore}%`, background: alert.riskScore >= 80 ? '#ff3344' : alert.riskScore >= 50 ? '#ff6b35' : '#ffab00' }}></div></div>
                      <span className="font-mono text-white text-xs font-bold">{alert.riskScore}</span>
                    </div>
                    <p className="text-[10px] text-[#52525b] mt-1">{alert.riskScore>=75?'CRITICAL':alert.riskScore>=50?'HIGH':'MEDIUM'}</p>
                  </td>
                  <td className="p-4 text-[#a1a1aa] text-[11px] max-w-[320px]">
                    <p className="leading-relaxed line-clamp-2">{alert.detectionReason}</p>
                    <p className="text-[10px] font-mono text-[#52525b] mt-1">Engines: 29 • MITRE {alert.mitreTechniques?.length||0} + CrowdStrike • Deep scan</p>
                  </td>
                  <td className="p-4"><span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${getStatusColor(alert.status)}`}>{alert.status}</span></td>
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-[#181825] border border-white/10 flex items-center justify-center text-[10px] font-bold text-[#ff3344]">{alert.analyst?.charAt(0) || 'U'}</div>
                      <span className="text-[#71717a] text-xs font-mono">{alert.analyst || 'Unassigned'}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <div className="flex gap-1.5">
                      <Link href={`/investigation/${alert.sampleId}`} className="px-3 py-1.5 rounded-lg bg-white text-black text-[11px] font-bold hover:bg-[#e4e4e7] flex items-center gap-1 shadow-[0_0_10px_rgba(255,255,255,0.1)] group-hover:shadow-[0_0_15px_rgba(255,255,255,0.2)]">
                        <SearchCheck className="w-3.5 h-3.5" /> INVESTIGATE
                      </Link>
                      <Link href={`/analysis/${alert.sampleId}`} className="px-2.5 py-1.5 rounded-lg bg-[#181825] border border-white/10 text-white text-[11px] font-bold hover:bg-[#27272a] flex items-center gap-1">
                        <Eye className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length === 0 && !loading && (
            <div className="p-16 text-center">
              <div className="w-16 h-16 rounded-2xl bg-[#181825] border border-white/5 flex items-center justify-center mx-auto mb-4">
                <Shield className="w-8 h-8 text-[#52525b]" />
              </div>
              <p className="text-white font-bold text-[14px]">No alerts yet • System ready for SOC triage</p>
              <p className="text-[#52525b] font-mono text-[12px] mt-2 max-w-[600px] mx-auto leading-relaxed">
                Alerts auto-generate when deep scan risk ≥20 (29 engines including MITRE {`201`} techniques + CrowdStrike 14 techniques). Upload a file via Samples → Upload → Deep Scan (29 engines, 15-20s) with malicious patterns (PE, suspicious strings, C2, YARA) to generate CRITICAL alerts. Benign PDFs remain 0/29 clean, no alert – no false positives. Investigation hub available in slider.
              </p>
              <div className="flex gap-2 justify-center mt-6">
                <Link href="/samples" className="px-5 py-2.5 rounded-xl bg-[#4f46e5] text-white text-[12px] font-bold hover:bg-[#4338ca]">Upload & Scan File (Generate Alert)</Link>
                <button onClick={fetchAlerts} className="px-5 py-2.5 rounded-xl bg-[#181825] border border-white/10 text-white text-[12px] font-bold">Refresh Alerts</button>
              </div>
            </div>
          )}
          {loading && (
            <div className="p-12 text-center">
              <div className="w-8 h-8 border-2 border-[#4f46e5] border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
              <p className="text-[#6b7280] font-mono text-xs">Loading SOC alerts from database...</p>
            </div>
          )}
        </div>
      </div>

      {/* Help */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-[#4f46e5]/5 border border-[#4f46e5]/20">
          <h4 className="text-[12px] font-bold text-[#818cf8] flex items-center gap-2"><Workflow className="w-4 h-4" />How Alerts Generate</h4>
          <p className="text-[11px] text-[#9ca3af] mt-2 leading-relaxed">1. Upload file → Samples page → 2. Deep Scan (29 engines 1-by-1, 15-20s) → 3. If riskScore ≥20 → Alert auto-created NEW with severity CRITICAL/HIGH/MEDIUM, detectionReason includes YARA + MITRE + CrowdStrike + Network + FileSystem, mitreTechniques list, sampleId link to investigation.</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#00c853]/5 border border-[#00c853]/20">
          <h4 className="text-[12px] font-bold text-[#00c853] flex items-center gap-2"><CheckCircle2 className="w-4 h-4" />No False Positives</h4>
          <p className="text-[11px] text-[#9ca3af] mt-2 leading-relaxed">Benign PDFs/DOCs/ZIPs (isDocument || isCompressed && !isPE) with 0 YARA, 0 C2, 0 MITRE, 0 CrowdStrike → risk 0 BENIGN → no alert, removed if existed. Document deep analysis shows why clean: no network, no file system ops.</p>
        </div>
        <div className="p-4 rounded-2xl bg-[#ff3344]/5 border border-[#ff3344]/20">
          <h4 className="text-[12px] font-bold text-[#ff5252] flex items-center gap-2"><SearchCheck className="w-4 h-4" />Investigation in Slider</h4>
          <p className="text-[11px] text-[#9ca3af] mt-2 leading-relaxed">Sidebar → Investigation (new) → lists all investigations (samples with analysis). Click any alert INVESTIGATE → incident response page with evidence overview, MITRE mapping, timeline, workflow status NEW→INVESTIGATING→CONTAINED→RESOLVED, analyst notes, recommendations.</p>
        </div>
      </div>
    </div>
  );
}
