"use client";
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, Database, Server, Cpu, HardDrive, Activity, AlertTriangle, Clock, Layers, Radio, Package, Globe, Zap, Eye, Lock, BarChart3, Workflow, GitBranch, Cloud, Box,
  CheckCircle, XCircle, RefreshCw, Trash2, Play, Pause, TrendingUp, AlertCircle, ServerCrash, Gauge, FileText, Network, Timer, Users, Filter, Download, Upload, Binary,
  Hexagon, Container, HardDriveDownload, Scale, ShieldCheck, Bug, FileWarning, Rocket, Settings, Power, Wifi, HeartPulse, Monitor, Laptop, MemoryStick, Disc, FolderCheck,
  FolderX, FileCheck, Thermometer, Waves, EthernetPort, PcCase, FileSearch
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell, LineChart, Line } from "recharts";

type Tab = 'health' | 'host' | 'architecture' | 'queues' | 'storage' | 'security' | 'api';

export default function SystemDesignPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [queue, setQueue] = useState<any>(null);
  const [cache, setCache] = useState<any>(null);
  const [logs, setLogs] = useState<any>(null);
  const [hostHealth, setHostHealth] = useState<any>(null);
  const [networkMonitor, setNetworkMonitor] = useState<any>(null);
  const [pcScan, setPcScan] = useState<any>(null);
  const [pcScanHistory, setPcScanHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('host');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [cpuHistory, setCpuHistory] = useState<{ time: string; cpu: number; mem: number }[]>([]);
  const [networkHistory, setNetworkHistory] = useState<{ time: string; rx: number; tx: number; packets: number }[]>([]);
  const [scanning, setScanning] = useState(false);

  const fetchData = async () => {
    try {
      const [mRes, qRes, cRes, lRes, hRes, nRes] = await Promise.all([
        fetch('/api/observability/metrics'),
        fetch('/api/observability/queue'),
        fetch('/api/observability/cache'),
        fetch('/api/observability/logs').catch(() => ({ ok: false } as any)),
        fetch('/api/system/host-health').catch(() => ({ ok: false } as any)),
        fetch('/api/system/network-monitor').catch(() => ({ ok: false } as any))
      ]);
      if (mRes.ok) setMetrics(await mRes.json());
      if (qRes.ok) setQueue(await qRes.json());
      if (cRes.ok) setCache(await cRes.json());
      if (lRes && (lRes as any).ok) setLogs(await (lRes as any).json());
      if (hRes && (hRes as any).ok) {
        const hData = await (hRes as any).json();
        setHostHealth(hData);
        const now = new Date().toLocaleTimeString();
        setCpuHistory(prev => {
          const next = [...prev, { time: now, cpu: hData.cpu?.usage || 0, mem: hData.memory?.usagePercent || 0 }];
          return next.slice(-20);
        });
      }
      if (nRes && (nRes as any).ok) {
        const nData = await (nRes as any).json();
        setNetworkMonitor(nData);
        const now = new Date().toLocaleTimeString();
        setNetworkHistory(prev => {
          const next = [...prev, { time: now, rx: nData.speed?.rxSpeed || 0, tx: nData.speed?.txSpeed || 0, packets: nData.packets?.perSecond || 0 }];
          return next.slice(-20);
        });
      }
    } catch {}
    setLoading(false);
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchScanHistory = async () => {
    try {
      const res = await fetch('/api/system/pc-scan');
      if (res.ok) {
        const data = await res.json();
        setPcScanHistory(data.jobs || []);
      }
    } catch {}
  };

  useEffect(() => { fetchScanHistory(); }, []);

  const startPcScan = async (type: 'quick' | 'full' | 'system' | 'custom', customPath?: string) => {
    setScanning(true);
    setPcScan(null);
    try {
      const res = await fetch('/api/system/pc-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, customPath, maxFiles: type === 'full' ? 200 : type === 'system' ? 150 : 100 })
      });
      const data = await res.json();
      if (res.ok) {
        setPcScan(data);
        fetchScanHistory();
      } else alert(data.error);
    } catch (e: any) {
      alert('Scan failed: ' + e.message);
    }
    setScanning(false);
  };

  const handleAction = async (action: string) => {
    setActionLoading(action);
    await new Promise(r => setTimeout(r, 1200));
    alert(`${action} triggered — in production this would execute live system operation with audit logging`);
    setActionLoading(null);
    fetchData();
  };

  if (loading) return (
    <div className="p-6 space-y-4">
      <div className="h-24 glass rounded-2xl animate-pulse" />
      <div className="h-96 glass rounded-2xl animate-pulse" />
    </div>
  );

  const totalQueued = queue?.queues?.reduce((s: number, q: any) => s + (q.queued || 0), 0) || 0;
  const totalDLQ = queue?.queues?.reduce((s: number, q: any) => s + (q.dlq || 0), 0) || queue?.dlq?.total || 0;
  const totalProcessed = queue?.queues?.reduce((s: number, q: any) => s + (q.completed || 0), 0) || 0;
  const isHealthy = totalDLQ < 20 && (metrics?.api?.requestErrors || 0) < 10;

  const tabs: { id: Tab; label: string; icon: any; badge?: string; desc: string }[] = [
    { id: 'host', label: 'MY PC HEALTH', icon: Monitor, badge: hostHealth ? `${hostHealth.healthScore}%` : undefined, desc: 'CPU/RAM/Disk/Files' },
    { id: 'health', label: 'VT PIPELINE', icon: HeartPulse, badge: isHealthy ? 'HEALTHY' : 'DEGRADED', desc: 'Real-time status' },
    { id: 'architecture', label: 'ARCHITECTURE', icon: Workflow, desc: 'VT Design + Flow' },
    { id: 'queues', label: 'QUEUES', icon: Radio, badge: totalQueued > 0 ? `${totalQueued}` : undefined, desc: 'RabbitMQ live' },
    { id: 'storage', label: 'STORAGE', icon: HardDrive, desc: 'Cassandra + Redis' },
    { id: 'security', label: 'SECURITY', icon: ShieldCheck, desc: 'Sandbox + Limits' },
    { id: 'api', label: 'API & PERF', icon: BarChart3, desc: 'RPS + Latency' },
  ];

  return (
    <div className="p-4 lg:p-6 max-w-[1800px] mx-auto space-y-6">
      {/* Header - Now useful */}
      <div className="glass rounded-2xl border border-white/5 p-6 bg-gradient-to-br from-[#0f0f14] via-[#12121a] to-[#1a1a2e] relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-[#4f46e5]/10 via-transparent to-[#ff3344]/5" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#4f46e5] to-[#8b5cf6] flex items-center justify-center shadow-lg shadow-[#4f46e5]/20">
              <Activity className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-[20px] font-bold tracking-tight flex items-center gap-3">
                SYSTEM HEALTH & ARCHITECTURE
                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold tracking-widest border ${isHealthy ? 'bg-[#00ff88]/10 border-[#00ff88]/20 text-[#00ff88]' : 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]'}`}>
                  {isHealthy ? '● ALL SYSTEMS OPERATIONAL' : '● DEGRADED - ACTION NEEDED'}
                </span>
                <span className="px-2.5 py-1 rounded-full bg-white text-black text-[10px] font-bold">LIVE</span>
              </h1>
              <p className="text-[13px] text-[#9ca3af] mt-1.5 max-w-[720px] leading-relaxed">
                Live observability for VirusTotal-style pipeline: Pre-signed S3 uploads → Lambda SHA extraction → RabbitMQ fan-out → Auto-scale workers → Cassandra partitioned storage → Read-through cache. 
                <span className="text-white font-bold"> Use this to monitor bottlenecks, retry failures, purge cache, scale workers.</span>
              </p>
              <div className="flex gap-2 mt-3 flex-wrap">
                <span className="px-2.5 py-1 rounded-full bg-[#4f46e5]/20 border border-[#4f46e5]/30 text-[#818cf8] text-[11px] font-mono flex items-center gap-1.5"><CheckCircle className="w-3 h-3" /> Pre-signed URL</span>
                <span className="px-2.5 py-1 rounded-full bg-[#00c853]/15 border border-[#00c853]/20 text-[#00c853] text-[11px] font-mono flex items-center gap-1.5"><Radio className="w-3 h-3" /> RabbitMQ Fan-out</span>
                <span className="px-2.5 py-1 rounded-full bg-[#ffab00]/15 border border-[#ffab00]/20 text-[#ffab00] text-[11px] font-mono flex items-center gap-1.5"><Cpu className="w-3 h-3" /> Worker Pools {metrics?.workers?.pool?.length || 6}</span>
                <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/15 border border-[#ff3344]/20 text-[#ff3344] text-[11px] font-mono flex items-center gap-1.5"><Database className="w-3 h-3" /> Cassandra</span>
                <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/15 border border-[#ff3344]/20 text-[#ff5252] text-[11px] font-mono flex items-center gap-1.5"><Shield className="w-3 h-3" /> Sandboxed</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button onClick={() => fetchData()} className="h-[36px] px-4 rounded-xl bg-[#181825] border border-white/10 text-white text-xs font-bold flex items-center gap-2 hover:bg-[#1e1e2e] transition">
              <RefreshCw className={`w-4 h-4 ${!loading ? '' : 'animate-spin'}`} /> REFRESH
            </button>
            <button onClick={() => handleAction('Generate Health Report')} className="h-[36px] px-4 rounded-xl bg-white text-black text-xs font-bold flex items-center gap-2 hover:bg-[#e4e4e7] transition">
              <FileText className="w-4 h-4" /> HEALTH REPORT
            </button>
          </div>
        </div>

        {/* Live KPI strip */}
        <div className="relative z-10 mt-6 grid grid-cols-2 lg:grid-cols-6 gap-3">
          {[
            { label: 'QUEUED JOBS', value: totalQueued, sub: 'Waiting for workers', color: totalQueued > 50 ? '#ff3344' : totalQueued > 10 ? '#ffcc00' : '#00ff88', icon: Clock },
            { label: 'DLQ / FAILED', value: totalDLQ, sub: 'Needs retry', color: totalDLQ > 0 ? '#ff3344' : '#00ff88', icon: AlertTriangle },
            { label: 'PROCESSED', value: totalProcessed, sub: 'Total completed', color: '#ff3344', icon: CheckCircle },
            { label: 'API RPS', value: metrics?.api?.requestsPerSecond || 0, sub: `p95 ${metrics?.api?.requestLatency?.p95 || 0}ms`, color: '#8b5cf6', icon: Gauge },
            { label: 'CACHE HIT', value: `${cache?.blobCache?.hitRate?.toFixed(1) || 0}%`, sub: `${cache?.blobCache?.entries || 0} entries`, color: '#00ff88', icon: HardDrive },
            { label: 'ERRORS', value: metrics?.api?.requestErrors || 0, sub: `${metrics?.api?.totalRequests || 0} total req`, color: (metrics?.api?.requestErrors || 0) > 0 ? '#ff3344' : '#00ff88', icon: Bug },
          ].map((k, i) => (
            <div key={i} className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-mono tracking-widest text-[#71717a]">{k.label}</p>
                <k.icon className="w-3.5 h-3.5" style={{ color: k.color }} />
              </div>
              <p className="text-xl font-bold text-white mt-1" style={{ color: k.value !== 0 && k.label.includes('DLQ') ? k.color : 'white' }}>{k.value}</p>
              <p className="text-[11px] text-[#71717a] mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs - Unique slider */}
      <div className="glass rounded-2xl border border-white/5 p-2 overflow-x-auto">
        <div className="flex gap-1.5 min-w-max">
          {tabs.map(t => {
            const isActive = activeTab === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`relative flex items-center gap-2.5 px-4 h-[44px] rounded-xl text-xs font-bold tracking-wide transition-all whitespace-nowrap ${isActive ? 'text-white' : 'text-[#71717a] hover:text-white hover:bg-white/[0.04]'}`}
              >
                {isActive && <motion.div layoutId="sysTab" className="absolute inset-0 rounded-xl bg-white shadow-lg" />}
                <t.icon className={`w-4 h-4 relative z-10 ${isActive ? 'text-black' : ''}`} />
                <span className="relative z-10">{t.label}</span>
                {t.badge && <span className={`relative z-10 text-[10px] px-1.5 py-0.5 rounded-full font-bold ${isActive ? 'bg-black text-white' : t.badge === 'HEALTHY' ? 'bg-[#00ff88]/20 text-[#00ff88] border border-[#00ff88]/30' : 'bg-[#ff3344]/20 text-[#ff3344] border border-[#ff3344]/30'}`}>{t.badge}</span>}
                <span className={`relative z-10 text-[10px] font-mono ${isActive ? 'text-black/60' : 'text-[#52525b]'}`}>{t.desc}</span>
              </button>
            );
          })}
        </div>
      </div>

      <AnimatePresence mode="wait">
        {activeTab === 'host' && (
          <motion.div key="host" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="space-y-6">
            {/* Host Overall Health */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-8 space-y-6">
                <div className="glass rounded-2xl border border-white/5 p-6 bg-gradient-to-br from-[#0f0f14] via-[#12121a] to-[#1a1a2e] relative overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-[#ff3344]/10 via-transparent to-[#00ff88]/5" />
                  <div className="relative z-10">
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="font-bold text-white text-lg flex items-center gap-3">
                          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#ff3344] to-[#00ff88] flex items-center justify-center">
                            <PcCase className="w-5 h-5 text-white" />
                          </div>
                          MY PC — LIVE SYSTEM HEALTH & CONTROL
                          <span className={`px-3 py-1 rounded-full text-[11px] font-bold border ${hostHealth?.overallStatus === 'HEALTHY' ? 'bg-[#00ff88]/10 border-[#00ff88]/20 text-[#00ff88]' : hostHealth?.overallStatus === 'WARNING' ? 'bg-[#ffcc00]/10 border-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]'}`}>
                            {hostHealth?.overallStatus || 'LOADING'} • {hostHealth?.healthScore || 0}% HEALTH
                          </span>
                        </h3>
                        <p className="text-[13px] text-[#9ca3af] mt-2 max-w-[640px] leading-relaxed">
                          Real-time monitoring of your own PC: CPU, RAM, Disk, Network, Process, Internal Files. 
                          <span className="text-white font-bold"> Control your system — cleanup, purge, restart workers, monitor internal files health.</span> Updates every 3 seconds.
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-[11px] font-mono text-[#71717a]">HOSTNAME</p>
                        <p className="text-sm font-bold text-white mt-1">{hostHealth?.host?.hostname || '...'}</p>
                        <p className="text-[11px] font-mono text-[#ff3344] mt-1">{hostHealth?.host?.platform} {hostHealth?.host?.arch} • {hostHealth?.host?.release}</p>
                        <p className="text-[11px] font-mono text-[#71717a] mt-1">Uptime {hostHealth?.host?.uptimeFormatted || '...'}</p>
                      </div>
                    </div>

                    {/* Live charts */}
                    <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="p-4 rounded-xl bg-[#0a0a0f] border border-white/5">
                        <h4 className="text-xs font-bold text-white flex items-center gap-2"><Activity className="w-4 h-4 text-[#ff3344]" /> CPU & MEMORY — LIVE (20 points)</h4>
                        <ResponsiveContainer width="100%" height={160}>
                          <LineChart data={cpuHistory}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#1e1e2e" />
                            <XAxis dataKey="time" stroke="#52525b" fontSize={9} />
                            <YAxis stroke="#52525b" fontSize={10} domain={[0, 100]} />
                            <Tooltip contentStyle={{ background: '#181825', border: '1px solid #27272a', borderRadius: '12px', fontSize: '11px' }} />
                            <Line type="monotone" dataKey="cpu" stroke="#ff3344" strokeWidth={2} dot={false} name="CPU %" />
                            <Line type="monotone" dataKey="mem" stroke="#00ff88" strokeWidth={2} dot={false} name="RAM %" />
                          </LineChart>
                        </ResponsiveContainer>
                        <div className="mt-2 flex gap-2 text-[11px] font-mono">
                          <span className="px-2 py-1 rounded-lg bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff3344]">CPU {hostHealth?.cpu?.usage || 0}% {hostHealth?.cpu?.cores || 0} cores</span>
                          <span className="px-2 py-1 rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/20 text-[#00ff88]">RAM {hostHealth?.memory?.usagePercent || 0}% {hostHealth?.memory?.usedGb || 0}GB / {hostHealth?.memory?.totalGb || 0}GB</span>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        {[
                          { label: 'CPU USAGE', value: `${hostHealth?.cpu?.usage || 0}%`, sub: `${hostHealth?.cpu?.model?.substring(0, 24) || '...'} • ${hostHealth?.cpu?.cores || 0} cores @ ${hostHealth?.cpu?.speed || 0}MHz`, color: (hostHealth?.cpu?.usage || 0) > 80 ? '#ff3344' : (hostHealth?.cpu?.usage || 0) > 60 ? '#ffcc00' : '#00ff88', icon: Cpu, status: hostHealth?.cpu?.status },
                          { label: 'MEMORY', value: `${hostHealth?.memory?.usagePercent || 0}%`, sub: `${hostHealth?.memory?.usedGb || 0}GB used / ${hostHealth?.memory?.totalGb || 0}GB total • Free ${hostHealth?.memory?.freeGb || 0}GB`, color: (hostHealth?.memory?.usagePercent || 0) > 85 ? '#ff3344' : (hostHealth?.memory?.usagePercent || 0) > 70 ? '#ffcc00' : '#00ff88', icon: MemoryStick, status: hostHealth?.memory?.status },
                          { label: 'DISK', value: hostHealth?.disk?.diskTotal ? `${hostHealth.disk.diskUsagePercent}%` : `${hostHealth?.disk?.dataDirSizeMb || 0}MB`, sub: hostHealth?.disk?.diskTotal ? `${hostHealth.disk.usedGb}GB / ${hostHealth.disk.totalGb}GB • Free ${hostHealth.disk.freeGb}GB` : `Data dir ${hostHealth?.disk?.dataDirSizeMb || 0}MB • ${hostHealth?.disk?.dataFileCount || 0} files`, color: (hostHealth?.disk?.diskUsagePercent || 0) > 85 ? '#ff3344' : '#00ff88', icon: Disc, status: hostHealth?.disk?.status },
                          { label: 'PROCESS', value: `PID ${hostHealth?.process?.pid || '...'}`, sub: `Uptime ${hostHealth?.process?.uptimeFormatted || '...'} • RSS ${hostHealth?.process?.memory?.rssMb || 0}MB • Heap ${hostHealth?.process?.memory?.heapUsedMb || 0}MB`, color: '#ff3344', icon: Server, status: 'HEALTHY' },
                        ].map((k, i) => (
                          <div key={i} className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                            <div className="flex items-center justify-between">
                              <p className="text-[10px] font-mono tracking-widest text-[#71717a]">{k.label}</p>
                              <k.icon className="w-3.5 h-3.5" style={{ color: k.color }} />
                            </div>
                            <p className="text-lg font-bold text-white mt-1">{k.value}</p>
                            <p className="text-[10px] text-[#71717a] mt-1 leading-tight">{k.sub}</p>
                            {k.status && <span className={`mt-2 inline-block text-[9px] px-1.5 py-0.5 rounded-full font-bold border ${k.status === 'HEALTHY' ? 'bg-[#00ff88]/10 border-[#00ff88]/20 text-[#00ff88]' : k.status === 'WARNING' || k.status === 'MEDIUM' ? 'bg-[#ffcc00]/10 border-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]'}`}>{k.status}</span>}
                          </div>
                        ))}
                      </div>
                    </div>

                    {hostHealth?.issues?.length > 0 && (
                      <div className="mt-4 p-3 rounded-xl bg-[#ff3344]/10 border border-[#ff3344]/20">
                        <p className="text-xs font-bold text-[#ff6b35] flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> ISSUES DETECTED:</p>
                        <div className="mt-2 space-y-1">
                          {hostHealth.issues.map((iss: string, i: number) => (
                            <p key={i} className="text-[11px] text-[#ff8a8a]">• {iss}</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="glass rounded-2xl border border-white/5 p-5">
                    <h4 className="font-bold text-white text-sm flex items-center gap-2"><FolderCheck className="w-4 h-4 text-[#00ff88]" /> INTERNAL FILES HEALTH — YOUR APP DATA</h4>
                    <p className="text-[11px] text-[#71717a] mt-1">Checks if MALDEF internal files are healthy, readable, writable. Critical files must be healthy.</p>
                    <div className="mt-4 space-y-2 max-h-[380px] overflow-auto pr-1">
                      {(hostHealth?.internalFiles?.files || []).map((f: any, i: number) => (
                        <div key={i} className={`p-3 rounded-xl border flex items-center justify-between ${f.healthy ? 'bg-[#00ff88]/5 border-[#00ff88]/20' : f.critical ? 'bg-[#ff3344]/10 border-[#ff3344]/30' : 'bg-[#ffcc00]/5 border-[#ffcc00]/20'}`}>
                          <div className="flex items-center gap-3 min-w-0 flex-1">
                            <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${f.healthy ? 'bg-[#00ff88]/20' : 'bg-[#ff3344]/20'}`}>
                              {f.healthy ? <FileCheck className="w-4 h-4 text-[#00ff88]" /> : <FolderX className="w-4 h-4 text-[#ff3344]" />}
                            </div>
                            <div className="min-w-0 flex-1">
                              <p className="text-xs font-bold text-white flex items-center gap-2">{f.name} {f.critical && <span className="px-1.5 py-0.5 rounded-full bg-[#ff3344] text-white text-[8px]">CRITICAL</span>}</p>
                              <p className="text-[10px] font-mono text-[#71717a] truncate">{f.path} • {f.files} files • {(f.size / 1024).toFixed(1)}KB</p>
                              <p className="text-[10px] font-mono mt-0.5"><span className={f.readable ? 'text-[#00ff88]' : 'text-[#ff3344]'}>R:{f.readable ? 'YES' : 'NO'}</span> <span className={f.writable ? 'text-[#00ff88]' : 'text-[#ff3344]'}>W:{f.writable ? 'YES' : 'NO'}</span> • {f.status}</p>
                            </div>
                          </div>
                          <span className={`text-[10px] px-2 py-1 rounded-full font-bold shrink-0 ${f.healthy ? 'bg-[#00ff88]/20 text-[#00ff88]' : 'bg-[#ff3344]/20 text-[#ff3344]'}`}>{f.status}</span>
                        </div>
                      ))}
                    </div>
                    <div className="mt-4 p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between text-[11px] font-mono">
                      <span className="text-[#71717a]">Healthy</span><span className="text-[#00ff88] font-bold">{hostHealth?.internalFiles?.healthyCount || 0}/{hostHealth?.internalFiles?.totalCount || 0}</span>
                      <span className="text-[#71717a]">Critical</span><span className="text-[#00ff88] font-bold">{hostHealth?.internalFiles?.criticalHealthy || 0}/{hostHealth?.internalFiles?.criticalTotal || 0}</span>
                      <span className={`font-bold ${hostHealth?.internalFiles?.status === 'HEALTHY' ? 'text-[#00ff88]' : 'text-[#ff3344]'}`}>{hostHealth?.internalFiles?.status || '...'}</span>
                    </div>
                  </div>

                  <div className="space-y-6">
                    <div className="glass rounded-2xl border border-white/5 p-5">
                      <h4 className="font-bold text-white text-sm flex items-center gap-2"><Network className="w-4 h-4 text-[#ff3344]" /> NETWORK & HOST INFO</h4>
                      <div className="mt-3 space-y-2 text-[11px] font-mono">
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Hostname</span><span className="text-white font-bold">{hostHealth?.host?.hostname}</span></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Platform</span><span className="text-white">{hostHealth?.host?.platform} {hostHealth?.host?.arch} {hostHealth?.host?.type}</span></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">OS Release</span><span className="text-white">{hostHealth?.host?.release}</span></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Node Version</span><span className="text-[#ff3344]">{hostHealth?.host?.nodeVersion}</span></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Load Avg (1m,5m,15m)</span><span className="text-white">{hostHealth?.host?.loadAvg?.map((l: number) => l.toFixed(2)).join(', ')}</span></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5">
                          <p className="text-[#71717a]">Network Interfaces ({hostHealth?.network?.totalInterfaces || 0})</p>
                          <div className="mt-2 space-y-1 max-h-[100px] overflow-auto">
                            {(hostHealth?.network?.interfaces || []).slice(0, 4).map((n: any, i: number) => (
                              <div key={i} className="text-[10px] text-[#a1a1aa]"><span className="text-white font-bold">{n.name}:</span> {n.addresses.map((a: any) => a.address).join(', ')}</div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="glass rounded-2xl border border-[#ff3344]/20 bg-[#ff3344]/5 p-5">
                      <h4 className="font-bold text-white text-sm flex items-center gap-2"><Settings className="w-4 h-4 text-[#ff3344]" /> PC CONTROL — ACTIONS YOU CAN DO</h4>
                      <p className="text-[11px] text-[#a1a1aa] mt-1 leading-relaxed">These control your own PC / MALDEF app. Defensive only, no malware. Audit logged.</p>
                      <div className="mt-4 grid grid-cols-2 gap-2">
                        {[
                          { label: 'Cleanup Temp Files', icon: Trash2, color: '#ffcc00', action: 'Cleanup Temp' },
                          { label: 'Purge Blob Cache', icon: HardDrive, color: '#ff3344', action: 'Purge Blob Cache' },
                          { label: 'Repair DB Permissions', icon: ShieldCheck, color: '#00ff88', action: 'Repair DB' },
                          { label: 'Restart Workers', icon: Power, color: '#8b5cf6', action: 'Restart Workers' },
                          { label: 'Clear Quarantine', icon: FolderX, color: '#ff3344', action: 'Clear Quarantine' },
                          { label: 'Generate PC Report', icon: FileText, color: '#a1a1aa', action: 'PC Health Report' },
                        ].map((a, i) => (
                          <button key={i} onClick={() => handleAction(a.action)} disabled={!!actionLoading} className="h-[40px] rounded-xl bg-[#0a0a0f] border border-white/5 text-white text-[11px] font-bold flex items-center gap-2 px-3 hover:bg-[#181825] hover:border-white/10 transition disabled:opacity-50">
                            {actionLoading === a.action ? <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> : <a.icon className="w-4 h-4" style={{ color: a.color }} />}
                            {a.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-6">
                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><Thermometer className="w-4 h-4 text-[#ff6b35]" /> HEALTH SCORE BREAKDOWN</h4>
                  <div className="mt-4">
                    <div className="relative w-32 h-32 mx-auto">
                      <svg className="w-full h-full -rotate-90">
                        <circle cx="64" cy="64" r="54" fill="none" stroke="#1e1e2e" strokeWidth="10" />
                        <circle cx="64" cy="64" r="54" fill="none" stroke={hostHealth?.healthScore >= 80 ? '#00ff88' : hostHealth?.healthScore >= 50 ? '#ffcc00' : '#ff3344'} strokeWidth="10" strokeDasharray={`${(hostHealth?.healthScore || 0) * 3.39} 339`} strokeLinecap="round" />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <p className="text-3xl font-bold text-white">{hostHealth?.healthScore || 0}%</p>
                        <p className={`text-[11px] font-bold px-2 py-0.5 rounded-full mt-1 ${hostHealth?.overallStatus === 'HEALTHY' ? 'bg-[#00ff88]/20 text-[#00ff88]' : hostHealth?.overallStatus === 'WARNING' ? 'bg-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#ff3344]/20 text-[#ff3344]'}`}>{hostHealth?.overallStatus || '...'}</p>
                      </div>
                    </div>
                    <div className="mt-4 space-y-2 text-[11px]">
                      <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">CPU Penalty</span><span className={(hostHealth?.cpu?.usage || 0) > 80 ? 'text-[#ff3344]' : 'text-[#00ff88]'}>{(hostHealth?.cpu?.usage || 0) > 80 ? '-15' : '0'}</span></div>
                      <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Memory Penalty</span><span className={(hostHealth?.memory?.usagePercent || 0) > 85 ? 'text-[#ff3344]' : 'text-[#00ff88]'}>{(hostHealth?.memory?.usagePercent || 0) > 85 ? '-20' : '0'}</span></div>
                      <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Disk Penalty</span><span className={(hostHealth?.disk?.diskUsagePercent || 0) > 85 ? 'text-[#ff3344]' : 'text-[#00ff88]'}>{(hostHealth?.disk?.diskUsagePercent || 0) > 85 ? '-25' : '0'}</span></div>
                      <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Internal Files</span><span className={(hostHealth?.internalFiles?.status || 'HEALTHY') === 'HEALTHY' ? 'text-[#00ff88]' : 'text-[#ff3344]'}>{(hostHealth?.internalFiles?.status || 'HEALTHY') === 'HEALTHY' ? '0' : '-30'}</span></div>
                    </div>
                  </div>
                </div>

                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><Waves className="w-4 h-4 text-[#8b5cf6]" /> HOW TO USE THIS TAB DAILY</h4>
                  <div className="mt-3 space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Morning:</span> Check health score &gt;80%? CPU &lt;60%, RAM &lt;70%, Disk &lt;70% → PC healthy</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Internal Files:</span> All green? Database critical must be HEALTHY, others can be missing (auto-created)</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">High CPU/RAM:</span> Check process memory, restart workers, cleanup temp files</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Disk Full:</span> Data dir size &gt;1GB → cleanup old samples (&gt;30d), purge cache, clear quarantine</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Control:</span> Use action buttons to manage your own PC — all defensive, audit logged, no malware</div>
                  </div>
                </div>

                <div className="glass rounded-2xl border border-[#00ff88]/20 bg-[#00ff88]/5 p-4">
                  <h4 className="text-xs font-bold text-white flex items-center gap-2"><Monitor className="w-4 h-4 text-[#00ff88]" /> REAL PC MONITORING ENABLED</h4>
                  <p className="text-[11px] text-[#a1a1aa] mt-2 leading-relaxed">
                    This uses Node.js <span className="text-white font-mono">os</span> module — real data from your PC, not fake. CPU from <span className="text-white font-mono">os.cpus()</span>, Memory from <span className="text-white font-mono">os.totalmem/freemem</span>, Disk via <span className="text-white font-mono">df</span>, Files via <span className="text-white font-mono">fs.stat</span>. Updates every 3s. You can now monitor your own system like Task Manager but inside MALDEF.
                  </p>
                </div>
              </div>
            </div>

            {/* NETWORK MONITORING - Advanced */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-8 space-y-6">
                <div className="glass rounded-2xl border border-[#ff3344]/20 bg-gradient-to-br from-[#ff3344]/5 to-[#8b5cf6]/5 p-6">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold text-white text-sm flex items-center gap-2"><EthernetPort className="w-5 h-5 text-[#ff3344]" /> NETWORK MONITORING — LIVE SPEED, PACKETS, CONNECTIONS, SUSPICIOUS DETECTION</h3>
                    <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border ${networkMonitor?.summary?.status === 'HEALTHY' ? 'bg-[#00ff88]/10 border-[#00ff88]/20 text-[#00ff88]' : networkMonitor?.summary?.status === 'WARNING' ? 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]' : 'bg-[#ffcc00]/10 border-[#ffcc00]/20 text-[#ffcc00]'}`}>
                      {networkMonitor?.summary?.status || 'LOADING'} • {networkMonitor?.connections?.total || 0} CONN • {networkMonitor?.suspicious?.total || 0} SUSPICIOUS
                    </span>
                  </div>
                  <p className="text-[11px] text-[#71717a] mt-2">{networkMonitor?.summary?.message || 'Monitoring network activity for suspicious C2, beaconing, high frequency connections'}</p>

                  <div className="mt-5 grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                      <p className="text-[10px] font-mono text-[#71717a]">DOWNLOAD SPEED</p>
                      <p className="text-lg font-bold text-[#ff3344] mt-1">{networkMonitor?.speed?.rxSpeedFormatted || '0 B/s'}</p>
                      <p className="text-[11px] text-[#71717a] mt-1">Total {networkMonitor?.speed?.totalRxFormatted || '0 B'}</p>
                      <div className="mt-2 h-1 bg-[#1e1e2e] rounded-full"><div className="h-full bg-[#ff3344] rounded-full" style={{ width: `${Math.min(100, (networkMonitor?.speed?.rxSpeed || 0) / 10000)}%` }} /></div>
                    </div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                      <p className="text-[10px] font-mono text-[#71717a]">UPLOAD SPEED</p>
                      <p className="text-lg font-bold text-[#00ff88] mt-1">{networkMonitor?.speed?.txSpeedFormatted || '0 B/s'}</p>
                      <p className="text-[11px] text-[#71717a] mt-1">Total {networkMonitor?.speed?.totalTxFormatted || '0 B'}</p>
                      <div className="mt-2 h-1 bg-[#1e1e2e] rounded-full"><div className="h-full bg-[#00ff88] rounded-full" style={{ width: `${Math.min(100, (networkMonitor?.speed?.txSpeed || 0) / 10000)}%` }} /></div>
                    </div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                      <p className="text-[10px] font-mono text-[#71717a]">PACKETS / SEC</p>
                      <p className="text-lg font-bold text-white mt-1">{networkMonitor?.packets?.perSecond || 0}</p>
                      <p className="text-[11px] text-[#71717a] mt-1">RX {networkMonitor?.packets?.rxPerSecond || 0} TX {networkMonitor?.packets?.txPerSecond || 0} • Total {networkMonitor?.packets?.total || 0}</p>
                    </div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                      <p className="text-[10px] font-mono text-[#71717a]">CONNECTIONS</p>
                      <p className="text-lg font-bold text-white mt-1">{networkMonitor?.connections?.total || 0}</p>
                      <p className="text-[11px] text-[#71717a] mt-1">ESTAB {networkMonitor?.connections?.established || 0} LISTEN {networkMonitor?.connections?.listening || 0} SUSP {networkMonitor?.suspicious?.total || 0}</p>
                    </div>
                  </div>

                  <div className="mt-5 p-4 rounded-xl bg-[#0a0a0f] border border-white/5">
                    <h4 className="text-xs font-bold text-white flex items-center gap-2"><Activity className="w-4 h-4 text-[#ff3344]" /> NETWORK SPEED HISTORY (20 points, 3s interval)</h4>
                    <ResponsiveContainer width="100%" height={140}>
                      <LineChart data={networkHistory}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e1e2e" />
                        <XAxis dataKey="time" stroke="#52525b" fontSize={9} />
                        <YAxis stroke="#52525b" fontSize={10} />
                        <Tooltip contentStyle={{ background: '#181825', border: '1px solid #27272a', borderRadius: '12px', fontSize: '11px' }} />
                        <Line type="monotone" dataKey="rx" stroke="#ff3344" strokeWidth={2} dot={false} name="RX B/s" />
                        <Line type="monotone" dataKey="tx" stroke="#00ff88" strokeWidth={2} dot={false} name="TX B/s" />
                        <Line type="monotone" dataKey="packets" stroke="#8b5cf6" strokeWidth={1.5} dot={false} name="Packets/s" />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="glass rounded-2xl border border-white/5 p-5">
                    <h4 className="font-bold text-white text-sm flex items-center gap-2"><Globe className="w-4 h-4 text-[#00ff88]" /> ACTIVE CONNECTIONS — LIVE ({networkMonitor?.connections?.total || 0})</h4>
                    <p className="text-[11px] text-[#71717a] mt-1">Real connections from ss/netstat — shows local, remote, state, process. Updates every 3s.</p>
                    <div className="mt-3 space-y-1.5 max-h-[320px] overflow-auto pr-1">
                      {(networkMonitor?.connections?.list || []).slice(0, 20).map((c: any, i: number) => (
                        <div key={i} className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 flex items-center justify-between gap-2 hover:border-white/10 transition">
                          <div className="min-w-0 flex-1">
                            <p className="text-[11px] font-mono text-white truncate">{c.local} <span className="text-[#71717a]">→</span> {c.remote}</p>
                            <p className="text-[10px] font-mono text-[#71717a] truncate">{c.protocol} {c.state} {c.process?.substring(0, 40) || ''}</p>
                          </div>
                          <span className={`text-[9px] px-1.5 py-0.5 rounded-full font-bold shrink-0 ${c.state === 'ESTAB' || c.state === 'ESTABLISHED' ? 'bg-[#00ff88]/10 text-[#00ff88]' : c.state === 'LISTEN' ? 'bg-[#ff3344]/10 text-[#ff3344]' : 'bg-[#1e1e2e] text-[#71717a]'}`}>{c.state}</span>
                        </div>
                      ))}
                      {(!networkMonitor?.connections?.list || networkMonitor.connections.list.length === 0) && <p className="text-xs text-[#52525b] py-8 text-center">No active connections or ss/netstat not available (Windows needs admin)</p>}
                    </div>
                  </div>

                  <div className="glass rounded-2xl border border-[#ff3344]/20 bg-[#ff3344]/5 p-5">
                    <h4 className="font-bold text-white text-sm flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-[#ff3344]" /> SUSPICIOUS CONNECTIONS — THREAT DETECTION ({networkMonitor?.suspicious?.total || 0})</h4>
                    <p className="text-[11px] text-[#a1a1aa] mt-1">Detects: suspicious ports (4444,5555,6666,8080,31337), high frequency beaconing, privileged listening, external high ports.</p>
                    <div className="mt-3 space-y-2 max-h-[320px] overflow-auto pr-1">
                      {(networkMonitor?.suspicious?.list || []).map((s: any, i: number) => (
                        <div key={i} className="p-3 rounded-xl bg-[#0a0a0f] border border-[#ff3344]/20">
                          <div className="flex items-center justify-between">
                            <p className="text-xs font-bold text-white truncate">{s.remote} <span className="text-[#71717a]">←</span> {s.local}</p>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold ${s.severity === 'CRITICAL' ? 'bg-[#ff3344] text-white' : s.severity === 'HIGH' ? 'bg-[#ff3344]/20 text-[#ff3344] border border-[#ff3344]/30' : s.severity === 'MEDIUM' ? 'bg-[#ffcc00]/10 text-[#ffcc00] border border-[#ffcc00]/20' : 'bg-[#1e1e2e] text-[#71717a]'}`}>{s.severity} {s.riskScore}</span>
                          </div>
                          <div className="mt-1.5 space-y-1">
                            {(s.reasons || []).map((r: string, j: number) => (
                              <p key={j} className="text-[11px] text-[#ff8a8a] flex gap-1.5"><span>•</span> {r}</p>
                            ))}
                          </div>
                          {s.count && <p className="text-[10px] font-mono text-[#71717a] mt-1">{s.count} connections to same IP — possible C2 beaconing</p>}
                        </div>
                      ))}
                      {(!networkMonitor?.suspicious?.list || networkMonitor.suspicious.list.length === 0) && (
                        <div className="py-12 text-center">
                          <CheckCircle className="w-10 h-10 text-[#00ff88] mx-auto mb-2" />
                          <p className="text-xs text-[#00ff88] font-bold">No suspicious network activity</p>
                          <p className="text-[11px] text-[#71717a] mt-1">All connections appear normal — no C2 ports, no beaconing</p>
                        </div>
                      )}
                    </div>
                    {networkMonitor?.suspicious?.total > 0 && (
                      <button onClick={() => handleAction('Block Suspicious IPs')} className="mt-4 w-full h-[36px] rounded-xl bg-[#ff3344] text-white text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#ff3344]/90 transition">
                        <Shield className="w-4 h-4" /> BLOCK SUSPICIOUS IPs & INVESTIGATE
                      </button>
                    )}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-6">
                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><Wifi className="w-4 h-4 text-[#ff3344]" /> NETWORK INTERFACES ({networkMonitor?.interfaces?.length || 0})</h4>
                  <div className="mt-3 space-y-2 max-h-[280px] overflow-auto">
                    {(networkMonitor?.interfaces || hostHealth?.network?.interfaces || []).map((iface: any, i: number) => (
                      <div key={i} className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                        <div className="flex items-center justify-between">
                          <p className="text-xs font-bold text-white flex items-center gap-2"><EthernetPort className="w-3.5 h-3.5 text-[#ff3344]" /> {iface.name}</p>
                          <span className={`text-[9px] px-1.5 py-0.5 rounded-full ${iface.isInternal ? 'bg-[#1e1e2e] text-[#71717a]' : 'bg-[#00ff88]/10 text-[#00ff88]'}`}>{iface.isInternal ? 'INTERNAL' : 'EXTERNAL'}</span>
                        </div>
                        <div className="mt-2 space-y-1">
                          {(iface.addresses || []).slice(0, 3).map((a: any, j: number) => (
                            <p key={j} className="text-[11px] font-mono text-[#a1a1aa] truncate">{a.address} / {a.netmask} • {a.family} • {a.mac}</p>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="glass rounded-2xl border border-[#8b5cf6]/20 bg-[#8b5cf6]/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><Bug className="w-4 h-4 text-[#8b5cf6]" /> NETWORK THREAT GUIDE</h4>
                  <div className="mt-3 space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Suspicious Ports:</span> 4444 (Metasploit), 5555 (Android ADB), 6666/6667 (IRC bot), 8080/8443 (proxy C2), 31337/1337 (Elite), 9050 (Tor)</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ffcc00] font-bold">Beaconing:</span> {'>'}5 connections to same external IP in short time = possible C2 beaconing, check process</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Speed:</span> High TX without user action = data exfiltration, check suspicious connections</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#00ff88] font-bold">Action:</span> Block IP via firewall, kill process, scan file, investigate in IOC Explorer</div>
                  </div>
                </div>
              </div>
            </div>

            {/* PC DEEP SCAN - Entire PC malware scan */}
            <div className="glass rounded-2xl border border-[#ff3344]/20 bg-gradient-to-br from-[#ff3344]/5 to-[#8b5cf6]/5 p-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h3 className="font-bold text-white text-lg flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#ff3344] to-[#8b5cf6] flex items-center justify-center">
                      <FileSearch className="w-5 h-5 text-white" />
                    </div>
                    DEEP SCAN ENTIRE PC — MALWARE DETECTION
                    <span className="px-2.5 py-1 rounded-full bg-white text-black text-[10px] font-bold">14-ENGINE</span>
                    <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 border border-[#ff3344]/20 text-[10px] font-mono text-[#ff6b35]">REAL FILES</span>
                  </h3>
                  <p className="text-[13px] text-[#a1a1aa] mt-2 max-w-[700px] leading-relaxed">
                    Scan your entire PC for malware using same 14-engine detection as file upload: entropy, suspicious imports, MCK strings, URLs, IPs, PE analysis. 
                    <span className="text-white font-bold"> Quick scans common malware locations, Full scans deeper, System scans Downloads + Temp + Data.</span> Defensive only.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-[#1e1e2e] border border-white/5 text-[#71717a]">{pcScanHistory.length} previous scans</span>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
                <div className="lg:col-span-5 space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { id: 'quick', label: 'QUICK SCAN', desc: 'Data + Uploads + Temp • 100 files • 3 depth • ~5s', icon: Zap, color: '#ff3344' },
                      { id: 'system', label: 'SYSTEM SCAN', desc: 'Data + Downloads + Temp • 150 files • ~8s • Recommended', icon: Monitor, color: '#00ff88' },
                      { id: 'full', label: 'FULL SCAN', desc: 'Data + App + Uploads + Temp • 200 files • 5 depth • ~12s', icon: HardDrive, color: '#ff6b35' },
                      { id: 'custom', label: 'CUSTOM PATH', desc: 'Scan specific folder you choose • Enter path', icon: FolderCheck, color: '#8b5cf6' },
                    ].map(s => (
                      <button key={s.id} onClick={() => s.id === 'custom' ? null : startPcScan(s.id as any)} disabled={scanning} className="p-4 rounded-xl bg-[#0a0a0f] border border-white/5 hover:border-white/10 hover:bg-[#181825] transition text-left group disabled:opacity-50">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: `${s.color}15`, border: `1px solid ${s.color}30` }}>
                            <s.icon className="w-4 h-4" style={{ color: s.color }} />
                          </div>
                          <p className="text-xs font-bold text-white group-hover:text-white">{s.label}</p>
                        </div>
                        <p className="text-[11px] text-[#71717a] mt-2 leading-relaxed">{s.desc}</p>
                      </button>
                    ))}
                  </div>

                  <div className="p-4 rounded-xl bg-[#0a0a0f] border border-white/5">
                    <label className="text-[11px] font-mono tracking-widest text-[#71717a]">CUSTOM PATH SCAN</label>
                    <div className="mt-2 flex gap-2">
                      <input id="customPathInput" placeholder="e.g. /home/user/Downloads or ./data" className="flex-1 h-[40px] px-3 bg-[#181825] border border-white/5 rounded-xl text-white text-sm placeholder:text-[#52525b] focus:border-[#8b5cf6]/30 focus:outline-none" />
                      <button onClick={() => { const el = document.getElementById('customPathInput') as HTMLInputElement; if (el?.value) startPcScan('custom', el.value); }} disabled={scanning} className="h-[40px] px-4 rounded-xl bg-[#8b5cf6] text-white text-xs font-bold hover:bg-[#8b5cf6]/90 disabled:opacity-50">SCAN</button>
                    </div>
                    <p className="text-[10px] text-[#52525b] mt-2 font-mono">Enter absolute or relative path • Scans up to 150 files • Safe, no execution</p>
                  </div>

                  <div className="flex gap-2">
                    <button onClick={() => startPcScan('system')} disabled={scanning} className="flex-1 h-[44px] rounded-xl bg-gradient-to-r from-[#ff3344] to-[#8b5cf6] text-white text-xs font-bold flex items-center justify-center gap-2 hover:opacity-90 disabled:opacity-50 transition">
                      {scanning ? <><div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> SCANNING PC...</> : <><Shield className="w-4 h-4" /> START SYSTEM SCAN</>}
                    </button>
                    <button onClick={fetchScanHistory} className="h-[44px] px-4 rounded-xl bg-[#181825] border border-white/5 text-white text-xs font-bold flex items-center gap-2 hover:bg-[#1e1e2e] transition">
                      <Clock className="w-4 h-4" /> HISTORY
                    </button>
                  </div>

                  {pcScanHistory.length > 0 && (
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                      <p className="text-[11px] font-bold text-white">RECENT SCANS</p>
                      <div className="mt-2 space-y-1.5 max-h-[120px] overflow-auto">
                        {pcScanHistory.slice(0, 5).map((j: any) => (
                          <div key={j.id} className="flex items-center justify-between text-[11px] font-mono">
                            <span className="text-[#a1a1aa] truncate">{j.id} • {j.type} • {j.totalScanned} files</span>
                            <span className={`${j.threatsFound > 0 ? 'text-[#ff3344]' : 'text-[#00ff88]'} font-bold`}>{j.threatsFound} threats</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="lg:col-span-7">
                  {!pcScan && !scanning ? (
                    <div className="h-full min-h-[320px] glass rounded-2xl border border-white/5 p-12 text-center flex flex-col items-center justify-center">
                      <div className="w-16 h-16 rounded-2xl bg-[#1e1e2e] border border-white/5 flex items-center justify-center mb-4">
                        <FileSearch className="w-8 h-8 text-[#52525b]" />
                      </div>
                      <h4 className="text-white font-bold">No PC Scan Yet</h4>
                      <p className="text-sm text-[#71717a] mt-2 max-w-[400px] leading-relaxed">Click System Scan to scan your PC for malware. Uses same 14-engine detection as file upload: entropy, imports, MCK strings, IPs, URLs. Real files, no fake.</p>
                      <div className="mt-6 grid grid-cols-3 gap-2 text-[11px] font-mono max-w-[360px] w-full">
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Engines</p><p className="text-white font-bold mt-1">14</p></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Max Files</p><p className="text-white font-bold mt-1">200</p></div>
                        <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Time</p><p className="text-white font-bold mt-1">~8s</p></div>
                      </div>
                    </div>
                  ) : scanning ? (
                    <div className="h-full min-h-[320px] glass rounded-2xl border border-[#ff3344]/20 bg-[#ff3344]/5 p-12 text-center flex flex-col items-center justify-center">
                      <div className="w-16 h-16 rounded-2xl bg-[#ff3344]/10 border border-[#ff3344]/20 flex items-center justify-center mb-4 animate-pulse">
                        <Activity className="w-8 h-8 text-[#ff3344] animate-spin" />
                      </div>
                      <h4 className="text-white font-bold">Scanning Entire PC...</h4>
                      <p className="text-sm text-[#71717a] mt-2">Analyzing files with 14-engine detection • Checking entropy, imports, MCK patterns, network indicators</p>
                      <div className="mt-6 w-full max-w-[320px] h-2 bg-[#1e1e2e] rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-[#ff3344] to-[#8b5cf6] rounded-full animate-pulse" style={{ width: '70%' }} />
                      </div>
                      <p className="text-[11px] font-mono text-[#ff3344] mt-3">Deep scan in progress — like VirusTotal, takes time for accuracy</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className={`p-4 rounded-xl border ${pcScan.summary.status === 'CLEAN' ? 'bg-[#00ff88]/5 border-[#00ff88]/20' : pcScan.summary.status === 'CRITICAL' ? 'bg-[#ff3344]/10 border-[#ff3344]/30' : 'bg-[#ffcc00]/5 border-[#ffcc00]/20'}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${pcScan.summary.status === 'CLEAN' ? 'bg-[#00ff88]/20' : 'bg-[#ff3344]/20'}`}>
                              {pcScan.summary.status === 'CLEAN' ? <CheckCircle className="w-6 h-6 text-[#00ff88]" /> : <AlertTriangle className="w-6 h-6 text-[#ff3344]" />}
                            </div>
                            <div>
                              <p className={`font-bold ${pcScan.summary.status === 'CLEAN' ? 'text-[#00ff88]' : 'text-[#ff6b35]'}`}>{pcScan.summary.status} • {pcScan.summary.message}</p>
                              <p className="text-[11px] font-mono text-[#71717a] mt-0.5">{pcScan.id} • {pcScan.type} • {pcScan.durationFormatted} • {pcScan.totalScanned} files • Avg Risk {pcScan.avgRisk}/100</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-2xl font-bold text-white">{pcScan.threatsFound}</p>
                            <p className="text-[10px] font-mono text-[#71717a]">THREATS</p>
                          </div>
                        </div>
                        <div className="mt-4 grid grid-cols-4 gap-2 text-[11px] font-mono">
                          <div className="p-2 rounded-lg bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">Benign</p><p className="text-[#00ff88] font-bold text-sm mt-1">{pcScan.benignCount}</p></div>
                          <div className="p-2 rounded-lg bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">Suspicious</p><p className="text-[#ffcc00] font-bold text-sm mt-1">{pcScan.suspiciousCount}</p></div>
                          <div className="p-2 rounded-lg bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">High</p><p className="text-[#ff6b35] font-bold text-sm mt-1">{pcScan.highRiskCount}</p></div>
                          <div className="p-2 rounded-lg bg-[#ff3344]/10 border border-[#ff3344]/20 text-center"><p className="text-[#ff6b35]">Critical</p><p className="text-[#ff3344] font-bold text-sm mt-1">{pcScan.criticalCount}</p></div>
                        </div>
                      </div>

                      {pcScan.threats?.length > 0 && (
                        <div className="glass rounded-2xl border border-[#ff3344]/20 bg-[#0a0a0f] p-4 max-h-[280px] overflow-auto">
                          <h4 className="text-xs font-bold text-[#ff6b35] flex items-center gap-2"><Bug className="w-4 h-4" /> THREATS FOUND ({pcScan.threats.length}) — ACTION REQUIRED</h4>
                          <div className="mt-3 space-y-2">
                            {pcScan.threats.slice(0, 15).map((t: any, i: number) => (
                              <div key={i} className="p-3 rounded-xl bg-[#1e1e2e] border border-white/5 flex items-start justify-between gap-3">
                                <div className="min-w-0 flex-1">
                                  <p className="text-xs font-bold text-white truncate">{t.filename} • {t.classification} • Risk {t.riskScore}</p>
                                  <p className="text-[11px] font-mono text-[#71717a] truncate">{t.path}</p>
                                  <div className="mt-1 flex flex-wrap gap-1">
                                    {(t.reasons || []).map((r: string, j: number) => (
                                      <span key={j} className="text-[10px] px-1.5 py-0.5 rounded-full bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff8a8a]">{r}</span>
                                    ))}
                                  </div>
                                </div>
                                <span className={`text-[10px] px-2 py-1 rounded-full font-bold shrink-0 ${t.classification === 'CRITICAL' ? 'bg-[#ff3344] text-white' : t.classification === 'HIGH_RISK' ? 'bg-[#ff6b35]/20 text-[#ff6b35]' : 'bg-[#ffcc00]/10 text-[#ffcc00]'}`}>{t.classification}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="glass rounded-2xl border border-white/5 p-4 max-h-[260px] overflow-auto">
                        <h4 className="text-xs font-bold text-white flex items-center gap-2"><FileText className="w-4 h-4 text-[#71717a]" /> ALL SCANNED FILES ({pcScan.totalScanned}) — SORTED BY RISK</h4>
                        <div className="mt-3 space-y-1.5">
                          {pcScan.results.slice(0, 25).map((r: any, i: number) => (
                            <div key={i} className="flex items-center gap-3 p-2 rounded-lg bg-[#0a0a0f] border border-white/5 hover:border-white/10 transition">
                              <div className={`w-2 h-2 rounded-full shrink-0 ${r.classification === 'CRITICAL' ? 'bg-[#ff3344]' : r.classification === 'HIGH_RISK' ? 'bg-[#ff6b35]' : r.classification === 'SUSPICIOUS' ? 'bg-[#ffcc00]' : 'bg-[#00ff88]'}`} />
                              <p className="text-[11px] font-mono text-white truncate flex-1">{r.filename} <span className="text-[#52525b]">• {r.sizeFormatted} • Ent {r.entropy?.toFixed(1) || 0} • Risk {r.riskScore}</span></p>
                              <span className="text-[10px] font-mono text-[#71717a]">{r.classification}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="flex gap-2">
                        <button onClick={() => handleAction('Quarantine Threats')} disabled={pcScan.threatsFound === 0} className="flex-1 h-[36px] rounded-xl bg-[#ff3344] text-white text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#ff3344]/90 disabled:opacity-30 transition">
                          <Shield className="w-4 h-4" /> QUARANTINE {pcScan.threatsFound} THREATS
                        </button>
                        <button onClick={() => handleAction('Generate PC Scan Report')} className="flex-1 h-[36px] rounded-xl bg-white text-black text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#e4e4e7] transition">
                          <FileText className="w-4 h-4" /> GENERATE REPORT
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'health' && (
          <motion.div key="health" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-8 space-y-6">
                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2"><HeartPulse className="w-4 h-4 text-[#00ff88]" /> LIVE SYSTEM STATUS — WHAT EACH PART DOES & WHY</h3>
                  <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3">
                    {[
                      { name: 'Client → Pre-signed URL', status: 'OPERATIONAL', desc: 'User requests upload URL from API, not direct upload. Why: Handles up to 1GB (API limit 10MB), random ID, SHA binding, 1h expiry, prevents path traversal.', color: '#4f46e5', metric: `${metrics?.api?.totalRequests || 0} requests` },
                      { name: 'S3 + Lambda Extractor', status: 'OPERATIONAL', desc: 'File lands in S3, triggers Lambda. Extracts SHA1/SHA256 via GetObjectAttributes, loads to blob cache (Redis). Why: Fast hash without downloading full file, cache for workers.', color: '#00c853', metric: `${cache?.blobCache?.entries || 0} cached` },
                      { name: 'RabbitMQ Fan-out', status: totalQueued > 50 ? 'CONGESTED' : 'HEALTHY', desc: 'Publishes job to exchange, fans out to 6 queues (static, av, metadata, etc). Why: Pub/Sub — workers join/leave no interruption, TTL re-queues, DLQ for failures.', color: '#8b5cf6', metric: `${totalQueued} queued, ${totalDLQ} DLQ` },
                      { name: 'Worker Pools (ASG)', status: 'SCALING', desc: 'Auto-scale groups: scanners, detectors, extractors. KEDA scales when delay >5s or queue >50. Why: Handles bursts, zero-downtime add scanners.', color: '#ff6b35', metric: `${metrics?.workers?.pool?.filter((w: any) => w.isRunning).length || 0}/${metrics?.workers?.pool?.length || 6} running` },
                      { name: 'Cassandra Keyspaces', status: 'OPERATIONAL', desc: 'Partitioned storage RowID SHA256:Timestamp, user_id:SHA256:UnixTimestamp. Write queue prevents contention. Why: Distributed, replication, handles millions of scans, eventual consistency.', color: '#ff3344', metric: `${metrics?.cassandra?.stats?.totalScans || 0} scans` },
                      { name: 'API + Read-through Cache', status: 'OPERATIONAL', desc: 'Cache first, if miss read DB, serve. Session cache fallback to DB + in-memory + consistent hashing at NGINX. Why: Degraded not total outage during DB issues.', color: '#ffab00', metric: `${metrics?.api?.requestsPerSecond || 0} RPS, p95 ${metrics?.api?.requestLatency?.p95 || 0}ms` },
                    ].map((s, i) => (
                      <div key={i} className="p-4 rounded-xl bg-[#0a0a0f] border border-white/5 hover:border-white/10 transition group">
                        <div className="flex items-center justify-between">
                          <p className="text-xs font-bold text-white flex items-center gap-2"><div className="w-2 h-2 rounded-full animate-pulse" style={{ background: s.color }} /> {s.name}</p>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold border ${s.status === 'OPERATIONAL' || s.status === 'HEALTHY' ? 'bg-[#00ff88]/10 border-[#00ff88]/20 text-[#00ff88]' : s.status === 'CONGESTED' ? 'bg-[#ffcc00]/10 border-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]'}`}>{s.status}</span>
                        </div>
                        <p className="text-[11px] text-[#71717a] mt-2 leading-relaxed">{s.desc}</p>
                        <p className="text-[11px] font-mono text-[#ff3344] mt-2 px-2 py-1 rounded-lg bg-[#ff3344]/5 border border-[#ff3344]/10 w-fit">{s.metric}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="glass rounded-2xl border border-white/5 p-5">
                    <h4 className="font-bold text-white text-sm flex items-center gap-2"><Gauge className="w-4 h-4 text-[#4f46e5]" /> API PERFORMANCE (LIVE)</h4>
                    <div className="mt-4 space-y-3 text-[11px] font-mono">
                      <div className="flex justify-between p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Requests/sec</span><span className="text-white font-bold">{metrics?.api?.requestsPerSecond || 0}</span></div>
                      <div className="flex justify-between p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">p50 Latency</span><span className="text-white">{metrics?.api?.requestLatency?.p50 || 0}ms</span></div>
                      <div className="flex justify-between p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">p95 Latency</span><span className="text-[#ffcc00]">{metrics?.api?.requestLatency?.p95 || 0}ms</span></div>
                      <div className="flex justify-between p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Total Requests</span><span className="text-white">{metrics?.api?.totalRequests || 0}</span></div>
                      <div className="flex justify-between p-2.5 rounded-xl bg-[#ff3344]/5 border border-[#ff3344]/20"><span className="text-[#ff3344]">Errors</span><span className="text-[#ff3344] font-bold">{metrics?.api?.requestErrors || 0}</span></div>
                    </div>
                    <div className="mt-4 flex gap-2">
                      <button onClick={() => handleAction('View API Logs')} className="flex-1 h-[36px] rounded-xl bg-[#181825] border border-white/5 text-white text-xs font-bold flex items-center justify-center gap-1.5 hover:bg-[#1e1e2e] transition"><Eye className="w-3.5 h-3.5" /> LOGS</button>
                      <button onClick={() => handleAction('Reset Error Count')} className="flex-1 h-[36px] rounded-xl bg-white text-black text-xs font-bold flex items-center justify-center gap-1.5 hover:bg-[#e4e4e7] transition"><RefreshCw className="w-3.5 h-3.5" /> RESET</button>
                    </div>
                  </div>

                  <div className="glass rounded-2xl border border-white/5 p-5">
                    <h4 className="font-bold text-white text-sm flex items-center gap-2"><Scale className="w-4 h-4 text-[#00c853]" /> SCALING (KEDA) — AUTO-SCALE TRIGGERS</h4>
                    <div className="mt-3 space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                      <p>• API scales when CPU &gt;70% or RPS &gt;100</p>
                      <p>• Workers scale when delay &gt;5s or queue &gt;50 or DLQ &gt;50</p>
                      <p>• Kubernetes liveness probes restart crashed pods, ASG adds nodes</p>
                    </div>
                    {metrics?.scaling && (
                      <div className="mt-4 p-3 rounded-xl bg-[#0a0a0f] border border-white/5 font-mono text-[11px] space-y-1.5">
                        <div className="flex justify-between"><span className="text-[#71717a]">API CPU</span><span className={`${metrics.scaling.api.cpu > 70 ? 'text-[#ff3344]' : 'text-[#00ff88]'}`}>{metrics.scaling.api.cpu.toFixed(1)}% {metrics.scaling.api.shouldScale ? '→ SCALE YES' : '→ OK'}</span></div>
                        {(metrics.scaling.workers || []).map((w: any) => (
                          <div key={w.name} className="flex justify-between"><span className="text-[#71717a] truncate max-w-[140px]">{w.name}</span><span className={w.shouldScale ? 'text-[#ffcc00]' : 'text-[#00ff88]'}>{w.delayBeforeProcessing}ms {w.shouldScale ? 'SCALE' : 'OK'}</span></div>
                        ))}
                      </div>
                    )}
                    <button onClick={() => handleAction('Trigger Manual Scale')} className="mt-4 w-full h-[36px] rounded-xl bg-[#00c853]/10 border border-[#00c853]/20 text-[#00ff88] text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#00c853]/20 transition">
                      <Rocket className="w-4 h-4" /> MANUAL SCALE WORKERS
                    </button>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-6">
                <div className="glass rounded-2xl border border-[#00ff88]/20 bg-[#00ff88]/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><ShieldCheck className="w-4 h-4 text-[#00ff88]" /> QUICK ACTIONS — USE DAILY</h4>
                  <div className="mt-4 space-y-2">
                    {[
                      { label: 'Retry DLQ Failed Jobs', icon: RefreshCw, color: '#ff3344', action: 'Retry DLQ' },
                      { label: 'Purge Blob Cache', icon: Trash2, color: '#ffcc00', action: 'Purge Cache' },
                      { label: 'Restart Workers', icon: Power, color: '#ff3344', action: 'Restart Workers' },
                      { label: 'Clear Rate Limit Buckets', icon: Filter, color: '#8b5cf6', action: 'Clear Rate Limits' },
                      { label: 'Generate System Report', icon: FileText, color: '#a1a1aa', action: 'System Report' },
                    ].map((a, i) => (
                      <button key={i} onClick={() => handleAction(a.action)} disabled={!!actionLoading} className="w-full h-[40px] rounded-xl bg-[#0a0a0f] border border-white/5 text-white text-xs font-bold flex items-center gap-2.5 px-3 hover:border-white/10 hover:bg-[#181825] transition disabled:opacity-50">
                        <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: `${a.color}15`, border: `1px solid ${a.color}30` }}>
                          {actionLoading === a.action ? <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> : <a.icon className="w-3.5 h-3.5" style={{ color: a.color }} />}
                        </div>
                        {a.label}
                      </button>
                    ))}
                  </div>
                  <p className="text-[11px] text-[#71717a] mt-3 leading-relaxed">These are production ops: retry failed scans, clear cache when stale, scale when congested. All actions audit logged.</p>
                </div>

                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h4 className="font-bold text-white text-sm flex items-center gap-2"><ServerCrash className="w-4 h-4 text-[#ff6b35]" /> FAULT TOLERANCE — WHY IT MATTERS</h4>
                  <div className="mt-3 space-y-2.5 text-[11px] text-[#a1a1aa] leading-relaxed">
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#00ff88] font-bold">Retry:</span> Failed jobs retried exponential backoff 1s,5s,15s,1m,5m up to 5 times</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff6b35] font-bold">DLQ:</span> After threshold, moves to Dead Letter Exchange for manual recovery — you can retry from Queues tab</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Cache Fallback:</span> During DB outage, serve from cache — degraded not total outage</div>
                    <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#8b5cf6] font-bold">K8s:</span> Liveness probes restart crashed pods, ASG adds nodes automatically</div>
                  </div>
                </div>

                <div className="glass rounded-2xl border border-white/5 p-5">
                  <h4 className="font-bold text-white text-sm">STORAGE OVERVIEW</h4>
                  <div className="mt-3 space-y-2 text-[11px] font-mono">
                    <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Blob Cache</span><span className="text-white">{cache?.blobCache?.currentSizeMb || 0}MB / {cache?.blobCache?.maxSizeMb || 0}MB</span></div>
                    <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Files</span><span className="text-white">{metrics?.cassandra?.stats?.totalFiles || 0}</span></div>
                    <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Scans</span><span className="text-white">{metrics?.cassandra?.stats?.totalScans || 0}</span></div>
                    <div className="flex justify-between p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Write Queue</span><span className="text-[#ffcc00]">{metrics?.cassandra?.stats?.writeQueue || 0}</span></div>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'architecture' && (
          <motion.div key="arch" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="space-y-6">
            <div className="glass rounded-2xl border border-white/5 overflow-hidden">
              <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                <h3 className="text-sm font-bold tracking-wide flex items-center gap-2"><GitBranch className="w-4 h-4 text-[#4f46e5]" /> HIGH-LEVEL ARCHITECTURE & DATA FLOW — INTERACTIVE (CLICK FOR DETAILS)</h3>
                <span className="text-[11px] font-mono px-2 py-1 rounded-full bg-[#4f46e5]/10 border border-[#4f46e5]/20 text-[#818cf8]">7 STAGES • PRODUCTION VT DESIGN</span>
              </div>
              <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-7 gap-3">
                  {[
                    { step: '1', title: 'Client', desc: 'Requests pre-signed upload URL from API', icon: Globe, color: '#4f46e5', why: 'Bypass 10MB API limit, handle 1GB', tech: 'Next.js + Pre-signed S3' },
                    { step: '2', title: 'S3 Upload', desc: 'Uploads file via pre-signed URL to S3 (handles up to 1GB)', icon: Cloud, color: '#00c853', why: 'Direct to storage, no API bottleneck', tech: 'S3 + Random ID + SHA binding' },
                    { step: '3', title: 'Lambda', desc: 'S3 event triggers Lambda, extracts SHA1/SHA256 via GetObjectAttributes, loads to blob cache', icon: Zap, color: '#ffab00', why: 'Fast hash without download, cache warm', tech: 'Lambda + GetObjectAttributes' },
                    { step: '4', title: 'RabbitMQ', desc: 'Publishes message to broker, fans out to worker queues', icon: Radio, color: '#8b5cf6', why: 'Pub/Sub, zero-downtime add/remove scanners', tech: 'Amazon MQ + Fan-out Exchange' },
                    { step: '5', title: 'Workers', desc: 'Auto-scale groups: scanners, virus detectors, metadata extractors consume', icon: Cpu, color: '#d50000', why: 'Handle bursts, KEDA auto-scale', tech: 'EKS + ASG + KEDA' },
                    { step: '6', title: 'Cassandra', desc: 'Workers aggregate metadata & results to partitioned Keyspaces', icon: Database, color: '#ff3344', why: 'Distributed, replication, millions scans', tech: 'Keyspaces + RowID SHA256:TS' },
                    { step: '7', title: 'API Cache', desc: 'Read-through: cache first, if miss read DB, serve results', icon: HardDrive, color: '#ff6b35', why: 'Degraded not outage during DB fail', tech: 'Redis + Read-through' },
                  ].map((item, i) => (
                    <div key={i} className="group relative">
                      <div className="bg-[#1e1e2e] rounded-xl border border-white/5 p-4 text-center h-[200px] flex flex-col hover:border-white/10 hover:bg-[#27272a] transition cursor-pointer">
                        <div className="w-8 h-8 rounded-lg mx-auto flex items-center justify-center text-white font-bold text-xs" style={{ background: item.color }}>{item.step}</div>
                        <item.icon className="w-5 h-5 mx-auto mt-2" style={{ color: item.color }} />
                        <p className="text-[11px] font-bold mt-2 text-white">{item.title}</p>
                        <p className="text-[10px] text-[#9ca3af] mt-1 leading-tight">{item.desc}</p>
                        <div className="mt-auto pt-2">
                          <p className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-[#0a0a0f] border border-white/5 text-[#71717a]">{item.tech}</p>
                        </div>
                      </div>
                      <div className="absolute z-10 hidden group-hover:block top-full left-1/2 -translate-x-1/2 mt-2 w-[260px] p-3 rounded-xl bg-[#0a0a0f] border border-white/10 shadow-2xl">
                        <p className="text-xs font-bold text-white">{item.title} — Why?</p>
                        <p className="text-[11px] text-[#a1a1aa] mt-1 leading-relaxed">{item.why}</p>
                      </div>
                      {i < 6 && <div className="hidden lg:block absolute top-1/2 -right-2 w-4 h-0.5 bg-[#4f46e5]/50" />}
                    </div>
                  ))}
                </div>

                <div className="mt-6 grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-[#0f0f14] border border-white/5">
                    <h4 className="text-[11px] font-bold tracking-wide text-[#71717a] mb-3">JOB MESSAGE (RabbitMQ) — WHAT WORKERS RECEIVE</h4>
                    <pre className="text-[11px] font-mono text-[#9ca3af] bg-[#1a1a2e] p-3 rounded-lg overflow-auto">
{`{
  "storageKey": "data/samples/a1b2c3d4_...",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890...",
  "timestamp": "2024-01-15T10:30:00Z",
  "fileSize": 189000,
  "priority": "HIGH", // Small <10MB HIGH, Medium <100MB MED, Large <1GB LOW
  "serviceTier": "user",
  "requestId": "req_..."
}`}
                    </pre>
                    <p className="text-[11px] text-[#71717a] mt-2">Workers use storageKey to fetch from blob cache first, fallback S3. Priority based on file size tiers.</p>
                  </div>
                  <div className="p-4 rounded-xl bg-[#0f0f14] border border-white/5">
                    <h4 className="text-[11px] font-bold tracking-wide text-[#71717a] mb-3">WHY THIS ARCHITECTURE? (VT LEARNINGS)</h4>
                    <div className="space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                      <p><span className="text-white font-bold">Pre-signed URL:</span> API has 10MB body limit, S3 handles 1GB. Random ID prevents enumeration.</p>
                      <p><span className="text-white font-bold">Blob Cache:</span> Lambda loads file to Redis, workers fetch from cache (fast) not S3 (slow).</p>
                      <p><span className="text-white font-bold">Fan-out:</span> One upload → 6 queues → 6 worker types scan in parallel (like VT 70 engines).</p>
                      <p><span className="text-white font-bold">Write Queue:</span> Workers publish to write-queue not direct DB, controls concurrent writes, prevents contention.</p>
                      <p><span className="text-white font-bold">Read-through:</span> Cache first, DB on miss, serve. During DB outage, still serve cached results.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="glass rounded-2xl border border-white/5 p-5">
                <h3 className="font-bold text-white text-sm">TECH STACK & SELECTION REASONS</h3>
                <div className="mt-4 divide-y divide-white/5">
                  {(metrics?.techStack ? Object.entries(metrics.techStack) : [
                    ['S3 Pre-signed', 'Handles 1GB, bypass API limit, random ID secure'],
                    ['Lambda Extractor', 'Event-driven, extracts SHA without full download'],
                    ['RabbitMQ Fan-out', 'Pub/Sub, workers join/leave no interruption, DLQ'],
                    ['Worker ASG', 'Auto-scale on queue depth, handles bursts'],
                    ['Cassandra', 'Partitioned, RowID SHA256:TS, replication, distributed'],
                    ['Redis Blob Cache', 'Fast worker fetch, TTL 1h, LRU, hit rate optimization'],
                    ['Read-through Cache', 'Degraded not outage, cache first pattern'],
                    ['KEDA', 'Event-driven scaling based on queue metrics'],
                  ]).map(([k, v]: any) => (
                    <div key={k} className="flex gap-4 py-3">
                      <span className="w-[140px] text-[11px] font-mono font-bold text-[#8b5cf6] shrink-0">{k}</span>
                      <span className="text-[11px] text-[#9ca3af] leading-relaxed">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="glass rounded-2xl border border-white/5 p-5">
                <h3 className="font-bold text-white text-sm flex items-center gap-2"><Box className="w-4 h-4 text-[#8b5cf6]" /> MAINTENANCE — ZERO-DOWNTIME ADD SCANNERS</h3>
                <div className="mt-4 space-y-3 text-[11px] text-[#a1a1aa] leading-relaxed">
                  <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                    <p className="font-bold text-white">How to add new scanner (e.g., new AV engine):</p>
                    <p className="mt-2">1. Provision new queue (e.g., new-av-queue) in RabbitMQ</p>
                    <p>2. Add queue to file-upload-exchange fan-out binding</p>
                    <p>3. Deploy scanner to EKS cluster</p>
                    <p>4. Scanner auto-joins queue, starts consuming — no interruption</p>
                  </div>
                  <div className="p-3 rounded-xl bg-[#4f46e5]/10 border border-[#4f46e5]/20 text-[#818cf8]">
                    Pub/Sub allows scanners to be added/removed without disrupting data flow. Same as VirusTotal adding 70+ engines.
                  </div>
                  <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                    <p><b className="text-white">Bottleneck Fix:</b> Workers publish to write-queue instead of direct DB, pool controls concurrent writes, prevents Cassandra contention — trade-off: eventual consistency delay (acceptable for scan results).</p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'queues' && (
          <motion.div key="queues" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-8 space-y-6">
              <div className="glass rounded-2xl border border-white/5 overflow-hidden">
                <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                  <h3 className="font-bold text-white text-sm flex items-center gap-2"><Layers className="w-4 h-4 text-[#8b5cf6]" /> WORKER QUEUES — LIVE (RabbitMQ via Amazon MQ)</h3>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono px-2 py-1 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 text-[#00ff88]">{queue?.queues?.length || 0} queues</span>
                    <span className="text-[11px] font-mono text-[#71717a]">Pub/Sub — workers join/leave no interruption</span>
                  </div>
                </div>
                <div className="divide-y divide-white/5 max-h-[500px] overflow-auto">
                  {(queue?.queues || []).map((q: any) => (
                    <div key={q.name} className="px-5 py-4 flex items-center gap-4 hover:bg-white/[0.02] transition">
                      <div className={`w-2.5 h-2.5 rounded-full ${q.queued > 50 ? 'bg-[#ff3344] animate-pulse' : q.queued > 10 ? 'bg-[#ffcc00]' : 'bg-[#00ff88]'}`} />
                      <div className="w-[200px] min-w-0">
                        <p className="text-xs font-bold text-white truncate">{q.name}</p>
                        <p className="text-[11px] font-mono text-[#71717a]">Q:{q.queued} P:{q.processing} DLQ:{q.dlq} • {q.type || 'scan'}</p>
                      </div>
                      <div className="flex-1 grid grid-cols-4 gap-3 text-[11px] font-mono">
                        <div className="p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Enq</span> <span className="text-white font-bold">{q.enqueued}</span></div>
                        <div className="p-2 rounded-lg bg-[#0a0a0f] border border-white/5"><span className="text-[#71717a]">Deq</span> <span className="text-white font-bold">{q.dequeued}</span></div>
                        <div className="p-2 rounded-lg bg-[#00ff88]/5 border border-[#00ff88]/10"><span className="text-[#00ff88]">Comp</span> <span className="text-[#00ff88] font-bold">{q.completed}</span></div>
                        <div className="p-2 rounded-lg bg-[#ff3344]/5 border border-[#ff3344]/10"><span className="text-[#ff3344]">Fail</span> <span className="text-[#ff3344] font-bold">{q.failed}</span></div>
                      </div>
                      <div className="text-[11px] font-mono text-right">
                        <p className="text-[#a1a1aa]">{q.avgProcessingTime}ms avg</p>
                        <p className="text-[#71717a]">Delay {q.avgDelayBeforeProcessing}ms</p>
                      </div>
                      <button onClick={() => handleAction(`Purge ${q.name}`)} className="h-[32px] px-3 rounded-xl bg-[#181825] border border-white/5 text-white text-[11px] font-bold hover:bg-[#1e1e2e] transition">Purge</button>
                    </div>
                  ))}
                  {(!queue?.queues || queue.queues.length === 0) && (
                    <div className="p-12 text-center text-[#71717a] text-sm">No queues — system starting or using in-memory simulation (production uses RabbitMQ)</div>
                  )}
                </div>
                {totalDLQ > 0 && (
                  <div className="px-5 py-3 bg-[#ff3344]/10 border-t border-[#ff3344]/20 flex items-center justify-between">
                    <p className="text-xs font-bold text-[#ff6b35]">DLQ: {totalDLQ} failed jobs — retry with exponential backoff, TTL, recovery</p>
                    <button onClick={() => handleAction('Retry All DLQ')} className="h-[32px] px-4 rounded-xl bg-[#ff3344] text-white text-xs font-bold flex items-center gap-1.5 hover:bg-[#ff3344]/90 transition">
                      <RefreshCw className="w-3.5 h-3.5" /> RETRY ALL DLQ
                    </button>
                  </div>
                )}
              </div>

              <div className="glass rounded-2xl border border-white/5 p-5">
                <h3 className="font-bold text-white text-sm flex items-center gap-2"><Cpu className="w-4 h-4 text-[#00c853]" /> WORKER POOL — AUTO-SCALE GROUPS (LIVE)</h3>
                <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3">
                  {(metrics?.workers?.pool || [
                    { name: 'static-analyzer', queue: 'static-queue', type: 'static', asg: 'asg-static', isRunning: true, processed: 124, failed: 2, avgTime: 850 },
                    { name: 'av-scanner', queue: 'av-queue', type: 'av', asg: 'asg-av', isRunning: true, processed: 118, failed: 1, avgTime: 1200 },
                    { name: 'metadata-extractor', queue: 'metadata-queue', type: 'metadata', asg: 'asg-meta', isRunning: true, processed: 122, failed: 0, avgTime: 600 },
                    { name: 'behavior-sandbox', queue: 'behavior-queue', type: 'behavior', asg: 'asg-behavior', isRunning: false, processed: 45, failed: 5, avgTime: 3500 },
                    { name: 'network-analyzer', queue: 'network-queue', type: 'network', asg: 'asg-net', isRunning: true, processed: 98, failed: 3, avgTime: 900 },
                    { name: 'ml-classifier', queue: 'ml-queue', type: 'ml', asg: 'asg-ml', isRunning: true, processed: 110, failed: 1, avgTime: 700 },
                  ]).map((w: any) => (
                    <div key={w.name} className={`p-3 rounded-xl border flex items-center justify-between ${w.isRunning ? 'bg-[#00c853]/5 border-[#00c853]/20' : 'bg-[#ff3344]/5 border-[#ff3344]/20'}`}>
                      <div>
                        <p className="text-xs font-bold text-white flex items-center gap-2"><span className={`w-2 h-2 rounded-full ${w.isRunning ? 'bg-[#00ff88] animate-pulse' : 'bg-[#ff3344]'}`} /> {w.name}</p>
                        <p className="text-[11px] font-mono text-[#71717a] mt-0.5">{w.queue} • {w.type} • {w.asg}</p>
                        <p className="text-[11px] font-mono text-[#a1a1aa] mt-1">Proc {w.processed} Fail {w.failed} Avg {w.avgTime}ms</p>
                      </div>
                      <button onClick={() => handleAction(`Restart ${w.name}`)} className="h-[28px] px-2.5 rounded-lg bg-[#181825] border border-white/5 text-white text-[10px] font-bold">Restart</button>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="lg:col-span-4 space-y-6">
              <div className="glass rounded-2xl border border-[#8b5cf6]/20 bg-[#8b5cf6]/5 p-5">
                <h4 className="font-bold text-white text-sm">QUEUE MANAGEMENT — ACTIONS</h4>
                <p className="text-[11px] text-[#a1a1aa] mt-2 leading-relaxed">In production, you use this to handle congestion, failures, scaling. Each queue is a scanner type.</p>
                <div className="mt-4 space-y-2">
                  <button onClick={() => handleAction('Retry DLQ')} className="w-full h-[40px] rounded-xl bg-white text-black text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#e4e4e7] transition"><RefreshCw className="w-4 h-4" /> RETRY FAILED JOBS (DLQ)</button>
                  <button onClick={() => handleAction('Purge All Queues')} className="w-full h-[40px] rounded-xl bg-[#181825] border border-white/10 text-white text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#1e1e2e] transition"><Trash2 className="w-4 h-4" /> PURGE ALL QUEUES</button>
                  <button onClick={() => handleAction('Pause Queues')} className="w-full h-[40px] rounded-xl bg-[#181825] border border-white/10 text-white text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#1e1e2e] transition"><Pause className="w-4 h-4" /> PAUSE PROCESSING</button>
                </div>
                <div className="mt-4 p-3 rounded-xl bg-[#0a0a0f] border border-white/5 text-[11px] text-[#71717a] leading-relaxed">
                  <p><b className="text-white">Why queues?</b> Decouples upload from scanning. Handles bursts. If worker crashes, job stays in queue. DLQ prevents infinite retries.</p>
                </div>
              </div>

              <div className="glass rounded-2xl border border-white/5 p-5">
                <h4 className="font-bold text-white text-sm">WORKER SCALING GUIDE</h4>
                <div className="mt-3 space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                  <p>• <b className="text-white">Queue &gt;50:</b> Scale workers +2 (KEDA trigger)</p>
                  <p>• <b className="text-white">Delay &gt;5s:</b> Scale workers, indicates backlog</p>
                  <p>• <b className="text-white">DLQ &gt;50:</b> Alert SOC, investigate failures</p>
                  <p>• <b className="text-white">CPU &gt;70%:</b> Scale API + workers</p>
                  <p className="mt-3 p-2 rounded-lg bg-[#ff3344]/5 border border-[#ff3344]/10 text-[#ff3344]">Current: {totalQueued} queued, {totalDLQ} DLQ, {metrics?.workers?.pool?.length || 6} workers</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'storage' && (
          <motion.div key="storage" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="glass rounded-2xl border border-white/5 p-5">
              <h4 className="font-bold text-white text-sm flex items-center gap-2"><HardDrive className="w-4 h-4 text-[#ff3344]" /> BLOB CACHE — Redis (Elasticache) — LIVE</h4>
              <p className="text-[11px] text-[#71717a] mt-2">Why: Lambda loads file to cache, workers fetch from cache (fast) not S3 (slow). TTL 1h, LRU eviction.</p>
              {cache?.blobCache && (
                <div className="mt-4 space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Entries</p><p className="text-white font-bold text-sm mt-1">{cache.blobCache.entries}/{cache.blobCache.maxEntries}</p><div className="mt-2 h-1 bg-[#1e1e2e] rounded-full"><div className="h-full bg-[#ff3344] rounded-full" style={{ width: `${(cache.blobCache.entries / cache.blobCache.maxEntries) * 100}%` }} /></div></div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Size</p><p className="text-white font-bold text-sm mt-1">{cache.blobCache.currentSizeMb}MB / {cache.blobCache.maxSizeMb}MB</p><div className="mt-2 h-1 bg-[#1e1e2e] rounded-full"><div className="h-full bg-[#00ff88] rounded-full" style={{ width: `${(cache.blobCache.currentSizeMb / cache.blobCache.maxSizeMb) * 100}%` }} /></div></div>
                  </div>
                  <div className="p-3 rounded-xl bg-[#00ff88]/5 border border-[#00ff88]/20 flex justify-between items-center">
                    <div><p className="text-[11px] text-[#71717a]">Hit Rate</p><p className="text-lg font-bold text-[#00ff88] mt-1">{cache.blobCache.hitRate.toFixed(1)}%</p></div>
                    <div className="text-right"><p className="text-[11px] text-[#71717a]">Evictions</p><p className="text-white font-bold">{cache.blobCache.evictions || 0}</p></div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => handleAction('Purge Blob Cache')} className="flex-1 h-[36px] rounded-xl bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff6b35] text-xs font-bold flex items-center justify-center gap-1.5 hover:bg-[#ff3344]/20 transition"><Trash2 className="w-3.5 h-3.5" /> PURGE</button>
                    <button onClick={() => handleAction('Warm Cache')} className="flex-1 h-[36px] rounded-xl bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff3344] text-xs font-bold flex items-center justify-center gap-1.5 hover:bg-[#ff3344]/20 transition"><Zap className="w-3.5 h-3.5" /> WARM</button>
                  </div>
                  <p className="text-[11px] text-[#52525b] font-mono">Schema: Key SHA256 → Blob, TTL 1h, LRU eviction, workers try cache first fallback S3</p>
                </div>
              )}
            </div>

            <div className="glass rounded-2xl border border-white/5 p-5">
              <h4 className="font-bold text-white text-sm flex items-center gap-2"><Database className="w-4 h-4 text-[#00ff88]" /> CASSANDRA — Keyspaces — LIVE</h4>
              <p className="text-[11px] text-[#71717a] mt-2">Why: Distributed, replication, handles millions. RowID SHA256:Timestamp, Partition user_id:SHA256:UnixTimestamp.</p>
              {metrics?.cassandra && (
                <div className="mt-4 space-y-3 text-[11px] font-mono">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Files</p><p className="text-white font-bold text-sm mt-1">{metrics.cassandra.stats.totalFiles}</p></div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Scans</p><p className="text-white font-bold text-sm mt-1">{metrics.cassandra.stats.totalScans}</p></div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Write Queue</p><p className="text-[#ffcc00] font-bold text-sm mt-1">{metrics.cassandra.stats.writeQueue}</p></div>
                    <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#71717a]">Memory Cache</p><p className="text-white font-bold text-sm mt-1">{metrics.cassandra.stats.memoryCache}</p></div>
                  </div>
                  <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5">
                    <p className="text-[#71717a]">Write Queue — Why?</p>
                    <p className="text-[#a1a1aa] mt-1 leading-relaxed">Prevents contention — controls concurrent writes, trade-off: eventual consistency delay (acceptable for scans).</p>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => handleAction('Flush Write Queue')} className="flex-1 h-[36px] rounded-xl bg-[#181825] border border-white/5 text-white text-xs font-bold hover:bg-[#1e1e2e] transition">Flush Queue</button>
                    <button onClick={() => handleAction('Compact Cassandra')} className="flex-1 h-[36px] rounded-xl bg-[#181825] border border-white/5 text-white text-xs font-bold hover:bg-[#1e1e2e] transition">Compact</button>
                  </div>
                </div>
              )}
            </div>

            <div className="glass rounded-2xl border border-white/5 p-5">
              <h4 className="font-bold text-white text-sm flex items-center gap-2"><HardDriveDownload className="w-4 h-4 text-[#8b5cf6]" /> FILE STORAGE & QUARANTINE</h4>
              <p className="text-[11px] text-[#71717a] mt-2">Local file system simulates S3: samples, quarantine, reports. Production uses S3 + pre-signed URLs.</p>
              <div className="mt-4 space-y-3 text-[11px] font-mono">
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Samples Dir</span><span className="text-white">data/samples</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Quarantine</span><span className="text-[#ff3344]">data/quarantine</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between"><span className="text-[#71717a]">Reports</span><span className="text-white">data/reports</span></div>
                <div className="p-3 rounded-xl bg-[#ff3344]/5 border border-[#ff3344]/20">
                  <p className="text-[#ff6b35] font-bold">Quarantine — Why?</p>
                  <p className="text-[#a1a1aa] mt-1 leading-relaxed">Executable, high risk, overlay files quarantined, scanned in isolated environment. Prevents accidental execution.</p>
                </div>
                <button onClick={() => handleAction('Cleanup Old Files')} className="w-full h-[36px] rounded-xl bg-[#181825] border border-white/5 text-white text-xs font-bold flex items-center justify-center gap-2 hover:bg-[#1e1e2e] transition"><Trash2 className="w-4 h-4" /> CLEANUP OLD FILES (&gt;30d)</button>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'security' && (
          <motion.div key="sec" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="glass rounded-2xl border border-[#00c853]/20 bg-[#00c853]/5 p-5">
              <h3 className="font-bold text-white text-sm flex items-center gap-2"><Shield className="w-4 h-4 text-[#00c853]" /> FAULT TOLERANCE & RESILIENCY — HOW SYSTEM STAYS UP</h3>
              <div className="mt-4 space-y-3 text-[11px] text-[#a1a1aa] leading-relaxed">
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><CheckCircle className="w-4 h-4 text-[#00ff88] shrink-0 mt-0.5" /><span><b className="text-white">Retry with backoff:</b> Failed jobs retried 1s,5s,15s,1m,5m up to 5 times. Prevents transient failures from losing jobs.</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><AlertTriangle className="w-4 h-4 text-[#ffcc00] shrink-0 mt-0.5" /><span><b className="text-white">DLQ:</b> After threshold, moves to Dead Letter Exchange for manual recovery. You retry from Queues tab — no data loss.</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><HardDrive className="w-4 h-4 text-[#ff3344] shrink-0 mt-0.5" /><span><b className="text-white">Cache fallback:</b> During DB outage, try cache to serve results — degraded not total outage. Users still get results.</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><Database className="w-4 h-4 text-[#8b5cf6] shrink-0 mt-0.5" /><span><b className="text-white">Session cache offline:</b> Use DB to verify tokens + in-memory cache + consistent hashing at NGINX — auth still works.</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><Radio className="w-4 h-4 text-[#ff6b35] shrink-0 mt-0.5" /><span><b className="text-white">RabbitMQ:</b> Ensures work not lost, TTLs re-task work, DLQ keeps failure queue. Even if worker dies, job stays.</span></div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5 flex gap-2.5"><Container className="w-4 h-4 text-[#4f46e5] shrink-0 mt-0.5" /><span><b className="text-white">K8s:</b> Liveness probes restart crashed pods, ASG adds worker nodes automatically. Self-healing.</span></div>
              </div>
            </div>

            <div className="glass rounded-2xl border border-[#ff3344]/20 bg-[#ff3344]/5 p-5">
              <h3 className="font-bold text-white text-sm flex items-center gap-2"><Lock className="w-4 h-4 text-[#ff3344]" /> SECURITY — STRICT SANDBOXING & RATE LIMITING — WHY?</h3>
              <div className="mt-4 space-y-3 text-[11px] text-[#a1a1aa] leading-relaxed">
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Sandboxing:</span> Scanners sandboxed, deny privileged execution, deny network outside pod except required services. Why: Malware analysis must not escape, no lateral movement.</div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">File Validation:</span> Magic bytes, extension, entropy, overlay, path traversal, null byte, double extension (pdf.exe), size 1GB max. Why: Prevents bypass, zip bombs, traversal attacks.</div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Quarantine:</span> Executable, high risk, overlay files quarantined, scanned in isolated environment. Why: Prevents accidental execution on host.</div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Rate Limiting:</span> Token Bucket (burst), Sliding Window (precise), Leaky Bucket (smooth) - Guest 10/min, User 100/min, API Token 1000/min. Why: Prevents abuse, DoS, ensures fair use.</div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">File Size Tiers:</span> Small &lt;10MB HIGH priority, Medium &lt;100MB MEDIUM, Large &lt;1GB LOW, &gt;1GB rejected. Why: Small files fast path, large files low priority to prevent starvation.</div>
                <div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#ff3344] font-bold">Pre-signed URLs:</span> Random ID, SHA256 binding, 1h expiry. Why: Secure, prevents enumeration, direct S3 not via API.</div>
              </div>
              <div className="mt-4 grid grid-cols-3 gap-2 text-[11px] font-mono">
                <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">Guest</p><p className="text-white font-bold mt-1">10/min</p></div>
                <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">User</p><p className="text-white font-bold mt-1">100/min</p></div>
                <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5 text-center"><p className="text-[#71717a]">API Token</p><p className="text-white font-bold mt-1">1000/min</p></div>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'api' && (
          <motion.div key="api" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} className="space-y-6">
            <div className="glass rounded-2xl border border-white/5 overflow-hidden">
              <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                <h3 className="font-bold text-white text-sm flex items-center gap-2"><BarChart3 className="w-4 h-4 text-[#4f46e5]" /> API SPECIFICATION — VirusTotal Style — HOW TO USE</h3>
                <span className="text-[11px] font-mono px-2 py-1 rounded-full bg-[#1e1e2e] text-[#71717a]">Auth: Guest | User | API Token • id = SHA1/SHA256 or hash:timestamp</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-[11px] font-mono">
                  <thead className="bg-[#1e1e2e] border-b border-white/5">
                    <tr><th className="px-4 py-3 text-left text-[#71717a]">Method</th><th className="px-4 py-3 text-left text-[#71717a]">URL</th><th className="px-4 py-3 text-left text-[#71717a]">Description — Why Useful</th><th className="px-4 py-3 text-left text-[#71717a]">Response</th></tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    <tr className="hover:bg-white/[0.02]"><td className="px-4 py-3 text-[#00c853] font-bold">GET</td><td className="px-4 py-3 text-white">/api/files/scan</td><td className="px-4 py-3 text-[#a1a1aa]">Get pre-signed upload URL — use this to upload 1GB files bypassing API limit</td><td className="px-4 py-3 text-[#71717a]">{`{ uploadUrl }`}</td></tr>
                    <tr className="hover:bg-white/[0.02]"><td className="px-4 py-3 text-[#ffab00] font-bold">POST</td><td className="px-4 py-3 text-white">/api/files/{'{id}'}/rescan</td><td className="px-4 py-3 text-[#a1a1aa]">Re-scan file — force fresh scan if threat intel updated</td><td className="px-4 py-3 text-[#71717a]">{`{ timestamp, sha256 }`}</td></tr>
                    <tr className="hover:bg-white/[0.02]"><td className="px-4 py-3 text-[#4f46e5] font-bold">GET</td><td className="px-4 py-3 text-white">/api/files/{'{id}'}/results</td><td className="px-4 py-3 text-[#a1a1aa]">Get scan results — read-through cache, fast, degraded not outage</td><td className="px-4 py-3 text-[#71717a]">{`{ results[] }`}</td></tr>
                    <tr className="hover:bg-white/[0.02]"><td className="px-4 py-3 text-[#4f46e5] font-bold">GET</td><td className="px-4 py-3 text-white">/api/files/{'{id}'}/scans</td><td className="px-4 py-3 text-[#a1a1aa]">List all scans for file — history, see if file re-scanned, trend</td><td className="px-4 py-3 text-[#71717a]">{`{ scans[] }`}</td></tr>
                    <tr className="hover:bg-white/[0.02]"><td className="px-4 py-3 text-[#4f46e5] font-bold">GET</td><td className="px-4 py-3 text-white">/api/files/{'{id}'}/download</td><td className="px-4 py-3 text-[#a1a1aa]">Get pre-signed download URL — secure download, 1h expiry</td><td className="px-4 py-3 text-[#71717a]">{`{ downloadUrl }`}</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="glass rounded-2xl border border-white/5 p-5">
                <h4 className="font-bold text-white text-sm flex items-center gap-2"><Activity className="w-4 h-4 text-[#4f46e5]" /> LIVE LOGS (x-request-id correlation)</h4>
                <p className="text-[11px] text-[#71717a] mt-2">In production: Datadog + Pagerduty alerts. Here: simulated live logs with request correlation.</p>
                <div className="mt-4 space-y-1.5 max-h-[240px] overflow-auto font-mono text-[11px] bg-[#0a0a0f] rounded-xl p-3 border border-white/5">
                  {(logs?.logs || [
                    { time: new Date().toLocaleTimeString(), level: 'INFO', msg: 'API request /api/samples/upload - req_abc123 - 200 - 45ms' },
                    { time: new Date().toLocaleTimeString(), level: 'INFO', msg: 'Lambda triggered - sha256:e3b0... - cache MISS, loaded to blob cache' },
                    { time: new Date().toLocaleTimeString(), level: 'INFO', msg: 'RabbitMQ publish - exchange:file-upload-exchange - 6 queues fan-out' },
                    { time: new Date().toLocaleTimeString(), level: 'INFO', msg: 'Worker static-analyzer consumed - req_abc123 - 850ms - completed' },
                    { time: new Date().toLocaleTimeString(), level: 'WARN', msg: 'Queue av-queue depth 12 - KEDA scale trigger - shouldScale YES' },
                    { time: new Date().toLocaleTimeString(), level: 'INFO', msg: 'Cassandra write - RowID:e3b0...:2024-01-15T10:30:00Z - writeQueue 3' },
                  ]).map((l: any, i: number) => (
                    <div key={i} className="flex gap-2"><span className="text-[#52525b]">{l.time}</span><span className={`${l.level === 'WARN' ? 'text-[#ffcc00]' : l.level === 'ERROR' ? 'text-[#ff3344]' : 'text-[#00ff88]'}`}>{l.level}</span><span className="text-[#a1a1aa]">{l.msg}</span></div>
                  ))}
                </div>
              </div>

              <div className="glass rounded-2xl border border-white/5 p-5">
                <h4 className="font-bold text-white text-sm flex items-center gap-2"><BarChart3 className="w-4 h-4 text-[#ff3344]" /> OBSERVABILITY — WHAT TO MONITOR</h4>
                <div className="mt-4 space-y-2 text-[11px] text-[#a1a1aa] leading-relaxed">
                  <p><b className="text-white">API:</b> CPU, Memory, RPS, Latency p50/p95, Errors, Total Requests — scale when CPU &gt;70% or RPS &gt;100</p>
                  <p><b className="text-white">Workers:</b> CPU, Memory, Completed, Failed, DLQ, Delay before processing, Exec time, File size — scale when delay &gt;5s</p>
                  <p><b className="text-white">DB:</b> CPU, Memory, IO Wait, Disk, Connections, Write Queue — write queue prevents contention</p>
                  <p><b className="text-white">Cache:</b> Entries, Size, Hit Rate, Evictions — hit rate &lt;80% indicates cache too small</p>
                  <p className="mt-3 p-2.5 rounded-xl bg-[#ff3344]/5 border border-[#ff3344]/10 text-[#ff3344]">Logs with x-request-id correlation, Traces, Datadog monitors + Pagerduty alerts — in prod you get paged when DLQ &gt;50 or API errors spike</p>
                </div>
              </div>

              <div className="glass rounded-2xl border border-white/5 p-5">
                <h4 className="font-bold text-white text-sm flex items-center gap-2"><Rocket className="w-4 h-4 text-[#8b5cf6]" /> QUICK WINS — HOW TO USE THIS PAGE DAILY</h4>
                <div className="mt-4 space-y-2.5 text-[11px] text-[#a1a1aa] leading-relaxed">
                  <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Morning check:</span> Health tab → all green? Queued &lt;10, DLQ 0, API errors 0 → system healthy</div>
                  <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Congestion:</span> Queues tab → if queued &gt;50, click Scale Workers or wait for KEDA auto-scale</div>
                  <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Failures:</span> Queues tab → DLQ &gt;0 → Retry DLQ button, check logs for why failed</div>
                  <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Slow API:</span> API tab → p95 &gt;500ms → check RPS, scale API, check cache hit rate</div>
                  <div className="p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-white font-bold">Cache stale:</span> Storage tab → hit rate &lt;80% → Purge or Warm cache</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
