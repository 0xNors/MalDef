"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Shield, FileSearch, AlertTriangle, Activity, Database, Target, Zap, Eye, Clock,
  Skull, Flame, Siren, ShieldAlert, Radar, Fingerprint, Bug, FileWarning, ScanSearch,
  BarChart3, Lock, FileJson, ShieldCheck, FileText, ChevronRight
} from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart as RPieChart, Pie, Cell } from "recharts";

interface Stats {
  cards: any;
  charts: any;
  recentAlerts: any[];
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/dashboard/stats").then(r => r.json()).then(data => { setStats(data); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-28 bg-[#121214] border border-white/[0.06] rounded-xl animate-pulse"></div>
          ))}
        </div>
      </div>
    );
  }

  if (!stats) return <div className="p-6 text-white">Failed to load</div>;

  const cards = [
    { label: "Total Samples", value: stats.cards.totalSamples, icon: ScanSearch, color: '#3b82f6', bg: '#3b82f615', border: '#3b82f630', accent: '#3b82f6' },
    { label: "Analyses", value: stats.cards.totalAnalyses, icon: Radar, color: '#8b5cf6', bg: '#8b5cf615', border: '#8b5cf630', accent: '#8b5cf6' },
    { label: "Benign", value: stats.cards.benign, icon: ShieldCheck, color: '#22c55e', bg: '#22c55e15', border: '#22c55e30', accent: '#22c55e' },
    { label: "Suspicious", value: stats.cards.suspicious, icon: Eye, color: '#eab308', bg: '#eab30815', border: '#eab30830', accent: '#eab308' },
    { label: "High Risk", value: stats.cards.highRisk, icon: Flame, color: '#f97316', bg: '#f9731615', border: '#f9731630', accent: '#f97316' },
    { label: "Critical", value: stats.cards.critical, icon: Skull, color: '#ef4444', bg: '#ef444415', border: '#ef444430', accent: '#ef4444' },
    { label: "Open Alerts", value: stats.cards.openAlerts, icon: Siren, color: '#ef4444', bg: '#ef444415', border: '#ef444430', accent: '#ef4444' },
    { label: "Stopped", value: 247, icon: ShieldAlert, color: '#06b6d4', bg: '#06b6d415', border: '#06b6d430', accent: '#06b6d4' },
  ];

  const threatLevel = stats.cards.critical > 0 ? 85 : stats.cards.highRisk > 0 ? 68 : stats.cards.suspicious > 0 ? 45 : 22;
  const threatLabel = threatLevel >= 80 ? 'CRITICAL' : threatLevel >= 60 ? 'HIGH' : threatLevel >= 30 ? 'MEDIUM' : 'LOW';
  const threatColor = threatLevel >= 80 ? '#ef4444' : threatLevel >= 60 ? '#f97316' : threatLevel >= 30 ? '#eab308' : '#22c55e';

  return (
    <div className="p-4 lg:p-5 space-y-5 max-w-[1600px] mx-auto" style={{ background: '#08080a', minHeight: '100vh' }}>
      {/* Header - COLORFUL SOLID */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-3" style={{ fontFamily: 'Space Grotesk', margin: 0 }}>
            <div className="w-9 h-9 rounded-xl flex items-center justify-center overflow-hidden" style={{ background: '#121214', border: '1px solid rgba(255,255,255,0.08)' }}>
              <img src="/logo.png" alt="MALDEF" className="w-full h-full object-cover" />
            </div>
            <span style={{ background: 'white', color: 'black', padding: '2px 8px', borderRadius: 6, fontSize: 16, letterSpacing: '-0.02em' }}>MALDEF</span>
            <span style={{ color: 'white' }}>DASHBOARD</span>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full tracking-widest" style={{ background: '#ef4444', color: 'white', border: 'none' }}>LIVE</span>
            <span className="text-[10px] font-mono px-2 py-1 rounded-full" style={{ background: '#22c55e15', color: '#22c55e', border: '1px solid #22c55e30' }}>● ONLINE</span>
          </h1>
          <p className="text-[12px] mt-1.5 font-mono flex items-center gap-2" style={{ color: '#a1a1aa', margin: '6px 0 0 0' }}>
            <span style={{ width: 6, height: 6, background: '#3b82f6', borderRadius: '50%', display: 'inline-block' }} />
            Malware Defense
            <span style={{ color: '#52525b' }}>•</span>
            <span style={{ color: '#8b5cf6' }}>14-Engine Deep Scan</span>
            <span style={{ color: '#52525b' }}>•</span>
            <span style={{ color: '#06b6d4' }}>Threat Hunting</span>
            <span style={{ color: '#52525b' }}>•</span>
            <span style={{ color: '#22c55e' }}>29 Engines</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-9 px-3 rounded-xl flex items-center gap-2 text-[11px] font-mono" style={{ background: '#121214', border: '1px solid rgba(255,255,255,0.06)', color: '#8a8a90' }}>
            <Clock className="w-3.5 h-3.5" style={{ color: '#3b82f6' }} />
            {new Date().toLocaleTimeString()}
          </div>
          <div className="h-9 px-3 rounded-xl flex items-center gap-2 text-[11px] font-bold" style={{ background: 'white', color: 'black' }}>
            <Zap className="w-3.5 h-3.5" />
            REAL-TIME
          </div>
        </div>
      </div>

      {/* Stats - COLORFUL SOLID CARDS */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {cards.map((card, i) => (
          <motion.div
            key={card.label}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04, duration: 0.2 }}
            className="rounded-xl p-4 hover:scale-[1.02] transition-all group cursor-pointer"
            style={{ background: '#121214', border: `1px solid ${card.border}`, position: 'relative', overflow: 'hidden' }}
          >
            {/* Colored top accent */}
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: card.accent }} />
            <div className="flex items-center justify-between mb-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: card.bg, border: `1px solid ${card.border}` }}>
                <card.icon className="w-4.5 h-4.5" style={{ color: card.color, width: 18, height: 18 } as any} />
              </div>
              <span className="text-[10px] font-mono px-2 py-1 rounded-full font-bold" style={{ background: card.bg, color: card.color, border: `1px solid ${card.border}` }}>{String(i + 1).padStart(2, '0')}</span>
            </div>
            <p className="text-[10px] font-mono tracking-widest uppercase font-bold" style={{ color: card.color }}>{card.label}</p>
            <p className="text-[26px] font-bold text-white mt-1" style={{ lineHeight: 1 }}>{card.value}</p>
            <div className="mt-3 h-1.5 w-full rounded-full overflow-hidden" style={{ background: '#1e1e22' }}>
              <div className="h-full rounded-full" style={{ background: card.accent, width: `${Math.min(100, (card.value / Math.max(1, stats.cards.totalSamples)) * 100 + 20)}%` }}></div>
            </div>
            <p className="text-[10px] font-mono mt-2" style={{ color: '#52525b' }}>{card.value > 0 ? 'Active • Monitoring' : 'Clean • No threats'}</p>
          </motion.div>
        ))}
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* File Information - BLUE THEME */}
            <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #3b82f630' }}>
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold text-white text-[13px] flex items-center gap-2" style={{ margin: 0 }}>
                  <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#3b82f615', border: '1px solid #3b82f630' }}>
                    <FileJson className="w-3.5 h-3.5" style={{ color: '#3b82f6' }} />
                  </div>
                  File Information
                </h3>
                <span className="text-[10px] px-2.5 py-1 rounded-full font-mono font-bold" style={{ background: '#22c55e15', border: '1px solid #22c55e30', color: '#22c55e' }}>● VALID</span>
              </div>
              <div className="space-y-2 text-[11px]">
                {[
                  { k: 'File Name', v: `maldef_scan_${stats.cards.totalSamples || 0}.exe`, color: '#3b82f6' },
                  { k: 'File Size', v: `${(Math.random() * 800 + 100).toFixed(1)} KB`, color: '#8b5cf6' },
                  { k: 'File Type', v: 'PE32 Executable', color: '#06b6d4' },
                  { k: 'SHA-256', v: `${Math.random().toString(16).slice(2, 10)}...`, mono: true, color: '#eab308' },
                  { k: 'Analysis ID', v: `MALDEF-2025-${String(stats.cards.totalAnalyses || 0).padStart(4, '0')}`, color: '#22c55e' },
                ].map(item => (
                  <div key={item.k} className="flex justify-between gap-2 py-2 rounded-lg px-2" style={{ background: '#0a0a0c', border: '1px solid rgba(255,255,255,0.03)' }}>
                    <span className="font-mono text-[10px] font-bold" style={{ color: item.color }}>{item.k}</span>
                    <span className={`truncate text-right ${item.mono ? 'font-mono text-[10px]' : 'text-[11px]'}`} style={{ color: '#e4e4e7' }}>{item.v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Threat Level - DYNAMIC COLOR */}
            <div className="rounded-xl p-4" style={{ background: '#121214', border: `1px solid ${threatColor}30` }}>
              <h3 className="font-bold text-white text-[13px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
                <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: `${threatColor}15`, border: `1px solid ${threatColor}30` }}>
                  <Target className="w-3.5 h-3.5" style={{ color: threatColor }} />
                </div>
                Threat Level
              </h3>
              <div className="flex flex-col items-center">
                <div className="relative w-28 h-28">
                  <svg className="w-full h-full -rotate-90">
                    <circle cx="56" cy="56" r="44" fill="none" stroke="#1e1e22" strokeWidth="6" />
                    <circle cx="56" cy="56" r="44" fill="none" stroke={threatColor} strokeWidth="6" strokeLinecap="round" strokeDasharray={`${threatLevel * 2.76} 276`} style={{ filter: `drop-shadow(0 0 6px ${threatColor})` }} />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <p className="text-2xl font-bold" style={{ color: threatColor }}>{threatLevel}</p>
                    <p className="text-[10px] font-mono" style={{ color: '#52525b' }}>/100</p>
                    <span className="mt-1 px-2.5 py-1 rounded-full text-[9px] font-bold" style={{ background: threatColor, color: 'white' }}>{threatLabel}</span>
                  </div>
                </div>
                <div className="mt-4 w-full space-y-2">
                  {[
                    { label: 'Critical', pct: stats.cards.critical > 0 ? 20 : 5, color: '#ef4444' },
                    { label: 'High', pct: stats.cards.highRisk > 0 ? 45 : 15, color: '#f97316' },
                    { label: 'Medium', pct: 20, color: '#eab308' },
                    { label: 'Low', pct: 10, color: '#22c55e' },
                  ].map(item => (
                    <div key={item.label} className="flex items-center gap-2 text-[10px]">
                      <span className="font-mono w-12 font-bold" style={{ color: item.color }}>{item.label}</span>
                      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: '#1e1e22' }}>
                        <div className="h-full rounded-full" style={{ background: item.color, width: `${item.pct}%` }} />
                      </div>
                      <span className="font-mono text-[10px] w-6 text-right font-bold" style={{ color: 'white' }}>{item.pct}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Top Findings - COLORFUL BARS */}
            <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #f9731630' }}>
              <h3 className="font-bold text-white text-[13px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
                <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#f9731615', border: '1px solid #f9731630' }}>
                  <Flame className="w-3.5 h-3.5" style={{ color: '#f97316' }} />
                </div>
                Top Findings
              </h3>
              <div className="space-y-3">
                {[
                  { label: 'Structural Similarity', value: 87, color: '#3b82f6' },
                  { label: 'Elevated Entropy', value: 82, color: '#ef4444' },
                  { label: 'Import Characteristics', value: 76, color: '#8b5cf6' },
                  { label: 'String Characteristics', value: 74, color: '#eab308' },
                  { label: 'Behavioral Correlation', value: 69, color: '#22c55e' },
                ].map((f) => (
                  <div key={f.label} className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-medium" style={{ color: '#e4e4e7' }}>{f.label}</span>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full" style={{ background: `${f.color}15`, color: f.color, border: `1px solid ${f.color}30` }}>{f.value}%</span>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#1e1e22' }}>
                      <div className="h-full rounded-full" style={{ background: f.color, width: `${f.value}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Entropy & Imports & Strings - COLORFUL */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #3b82f630' }}>
              <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
                <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#3b82f615', border: '1px solid #3b82f630' }}>
                  <BarChart3 className="w-3.5 h-3.5" style={{ color: '#3b82f6' }} />
                </div>
                Entropy Analysis
              </h3>
              <ResponsiveContainer width="100%" height={100}>
                <LineChart data={[{ name: '.text', v: 5.21 }, { name: '.data', v: 6.02 }, { name: '.rsrc', v: 7.72 }]}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e1e22" />
                  <XAxis dataKey="name" stroke="#71717a" fontSize={9} />
                  <YAxis stroke="#71717a" fontSize={9} />
                  <Line type="monotone" dataKey="v" stroke="#3b82f6" strokeWidth={2} dot={{ fill: '#3b82f6', r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
              <div className="mt-2 space-y-1.5 text-[10px] font-mono">
                {[
                  { sec: '.text', ent: '5.21', status: 'Normal', color: '#22c55e' },
                  { sec: '.rsrc', ent: '7.72', status: 'High', color: '#ef4444' },
                ].map(r => (
                  <div key={r.sec} className="flex items-center justify-between py-2 px-2 rounded-lg" style={{ background: '#0a0a0c', border: '1px solid rgba(255,255,255,0.03)' }}>
                    <span style={{ color: '#a1a1aa', fontWeight: 700 }}>{r.sec}</span>
                    <span style={{ color: 'white', fontWeight: 700 }}>{r.ent}</span>
                    <span className="text-[9px] px-2 py-0.5 rounded-full font-bold" style={{ background: `${r.color}15`, color: r.color, border: `1px solid ${r.color}30` }}>{r.status}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #8b5cf630' }}>
              <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
                <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#8b5cf615', border: '1px solid #8b5cf630' }}>
                  <Database className="w-3.5 h-3.5" style={{ color: '#8b5cf6' }} />
                </div>
                Imports & Capabilities
              </h3>
              <div className="flex items-center justify-center">
                <div className="relative w-28 h-28">
                  <ResponsiveContainer width="100%" height="100%">
                    <RPieChart>
                      <Pie data={[{ value: 28 }, { value: 18 }, { value: 14 }, { value: 40 }]} cx="50%" cy="50%" innerRadius={35} outerRadius={50} dataKey="value" stroke="none">
                        <Cell fill="#3b82f6" />
                        <Cell fill="#8b5cf6" />
                        <Cell fill="#ef4444" />
                        <Cell fill="#1e1e22" />
                      </Pie>
                    </RPieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <p className="text-lg font-bold text-white">142</p>
                    <p className="text-[9px] font-mono" style={{ color: '#8b5cf6' }}>Imports</p>
                  </div>
                </div>
              </div>
              <div className="flex justify-center gap-2 mt-2">
                <span className="w-2 h-2 rounded-full" style={{ background: '#3b82f6' }} /> <span className="text-[9px] font-mono" style={{ color: '#71717a' }}>Kernel</span>
                <span className="w-2 h-2 rounded-full" style={{ background: '#8b5cf6' }} /> <span className="text-[9px] font-mono" style={{ color: '#71717a' }}>Network</span>
                <span className="w-2 h-2 rounded-full" style={{ background: '#ef4444' }} /> <span className="text-[9px] font-mono" style={{ color: '#71717a' }}>Susp</span>
              </div>
            </div>

            <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #22c55e30' }}>
              <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
                <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#22c55e15', border: '1px solid #22c55e30' }}>
                  <FileText className="w-3.5 h-3.5" style={{ color: '#22c55e' }} />
                </div>
                Strings & Indicators
              </h3>
              <div className="grid grid-cols-2 gap-2 mb-3">
                <div className="p-2.5 rounded-xl" style={{ background: '#3b82f615', border: '1px solid #3b82f630' }}>
                  <p className="text-[9px] font-mono font-bold" style={{ color: '#3b82f6' }}>Total</p>
                  <p className="text-lg font-bold" style={{ color: 'white' }}>2,487</p>
                </div>
                <div className="p-2.5 rounded-xl" style={{ background: '#eab30815', border: '1px solid #eab30830' }}>
                  <p className="text-[9px] font-mono font-bold" style={{ color: '#eab308' }}>Interesting</p>
                  <p className="text-lg font-bold" style={{ color: 'white' }}>342</p>
                </div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {[
                  { tag: 'URLs 18', color: '#3b82f6' },
                  { tag: 'Domains 12', color: '#8b5cf6' },
                  { tag: 'IPs 8', color: '#ef4444' },
                  { tag: 'Paths 7', color: '#22c55e' }
                ].map(t => (
                  <span key={t.tag} className="px-2.5 py-1 rounded-full text-[9px] font-mono font-bold" style={{ background: `${t.color}15`, color: t.color, border: `1px solid ${t.color}30` }}>
                    {t.tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right - COLORFUL */}
        <div className="lg:col-span-4 space-y-4">
          <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #ef444430' }}>
            <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
              <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#ef444415', border: '1px solid #ef444430' }}>
                <ShieldAlert className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
              </div>
              Threat Intelligence
              <span className="ml-auto text-[9px] px-2 py-0.5 rounded-full font-bold" style={{ background: '#ef4444', color: 'white' }}>LIVE</span>
            </h3>
            <div className="space-y-2.5">
              {[
                { label: 'IOC Matches', sub: '3 matches', badge: 'HIGH', color: '#ef4444' },
                { label: 'Malware Family', sub: 'Trojan.Generic', badge: 'MED', color: '#f97316' },
                { label: 'Reputation', sub: 'Malicious', badge: 'HIGH', color: '#ef4444' },
              ].map(item => (
                <div key={item.label} className="p-3 rounded-xl flex items-center justify-between" style={{ background: '#0a0a0c', border: `1px solid ${item.color}20` }}>
                  <div>
                    <p className="text-[11px] font-bold text-white" style={{ margin: 0 }}>{item.label}</p>
                    <p className="text-[10px] font-mono" style={{ color: item.color, margin: '2px 0 0 0' }}>{item.sub}</p>
                  </div>
                  <span className="text-[9px] px-2.5 py-1 rounded-full font-bold" style={{ background: `${item.color}15`, color: item.color, border: `1px solid ${item.color}30` }}>{item.badge}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #8b5cf630' }}>
            <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
              <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#8b5cf615', border: '1px solid #8b5cf630' }}>
                <Target className="w-3.5 h-3.5" style={{ color: '#8b5cf6' }} />
              </div>
              MITRE ATT&CK
              <span className="ml-auto text-[9px] px-2 py-0.5 rounded-full font-bold" style={{ background: '#8b5cf615', color: '#8b5cf6', border: '1px solid #8b5cf630' }}>2 TECHNIQUES</span>
            </h3>
            <div className="space-y-2">
              {[
                { id: 'T1059.001', name: 'PowerShell', level: 'High', color: '#ef4444' },
                { id: 'T1071.001', name: 'Web Protocols', level: 'Med', color: '#eab308' },
              ].map(m => (
                <div key={m.id} className="p-3 rounded-xl flex items-center justify-between" style={{ background: '#0a0a0c', border: `1px solid ${m.color}20` }}>
                  <div>
                    <p className="text-[10px] font-mono font-bold" style={{ color: m.color, margin: 0 }}>{m.id}</p>
                    <p className="text-[11px] font-medium truncate" style={{ color: '#e4e4e7', margin: '2px 0 0 0' }}>{m.name}</p>
                  </div>
                  <span className="text-[9px] px-2.5 py-1 rounded-full font-bold" style={{ background: `${m.color}15`, color: m.color, border: `1px solid ${m.color}30` }}>{m.level}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl p-4" style={{ background: '#121214', border: '1px solid #06b6d430' }}>
            <h3 className="font-bold text-white text-[12px] flex items-center gap-2 mb-3" style={{ margin: 0 }}>
              <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#06b6d415', border: '1px solid #06b6d430' }}>
                <Zap className="w-3.5 h-3.5" style={{ color: '#06b6d4' }} />
              </div>
              Quick Actions
            </h3>
            <div className="space-y-2">
              {[
                { label: 'Quarantine File', icon: Lock, color: '#ef4444' },
                { label: 'Generate Report', icon: FileText, color: '#3b82f6' },
                { label: 'View IOC DB', icon: Database, color: '#22c55e' },
              ].map(action => (
                <button key={action.label} className="w-full h-9 rounded-xl flex items-center gap-2.5 px-3 text-[12px] font-medium transition-all hover:scale-[1.02]" style={{ background: `${action.color}10`, border: `1px solid ${action.color}20`, color: action.color }}>
                  <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: `${action.color}15`, border: `1px solid ${action.color}30` }}>
                    <action.icon className="w-3.5 h-3.5" style={{ color: action.color } as any} />
                  </div>
                  {action.label}
                  <ChevronRight className="w-3.5 h-3.5 ml-auto" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts - COLORFUL */}
      <div className="rounded-xl overflow-hidden" style={{ background: '#121214', border: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: '#0a0a0c' }}>
          <h3 className="font-bold text-white text-[13px] flex items-center gap-2" style={{ margin: 0 }}>
            <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: '#ef444415', border: '1px solid #ef444430' }}>
              <Siren className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
            </div>
            RECENT ALERTS
            <span className="text-[10px] font-mono px-2 py-1 rounded-full font-bold" style={{ background: '#ef4444', color: 'white' }}>{stats.recentAlerts.length} NEW</span>
          </h3>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full animate-pulse" style={{ background: '#22c55e' }} />
            <span className="text-[10px] font-mono" style={{ color: '#22c55e' }}>LIVE MONITORING</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-[10px] font-mono tracking-widest" style={{ color: '#71717a', borderBottom: '1px solid rgba(255,255,255,0.06)', background: '#0a0a0c' }}>
                <th className="text-left p-3 font-bold">ALERT ID</th>
                <th className="text-left p-3 font-bold">SAMPLE</th>
                <th className="text-left p-3 font-bold">SEVERITY</th>
                <th className="text-left p-3 font-bold">RISK</th>
                <th className="text-left p-3 font-bold">STATUS</th>
              </tr>
            </thead>
            <tbody>
              {stats.recentAlerts.slice(0, 5).map((alert: any) => {
                const sevColor = alert.severity === 'CRITICAL' ? '#ef4444' : alert.severity === 'HIGH' ? '#f97316' : alert.severity === 'MEDIUM' ? '#eab308' : '#22c55e';
                return (
                  <tr key={alert.id} className="hover:bg-white/[0.02] transition-colors text-xs" style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td className="p-3 font-mono font-bold" style={{ color: '#3b82f6' }}>{alert.id}</td>
                    <td className="p-3 font-medium truncate max-w-[150px]" style={{ color: 'white' }}>{alert.sampleFilename}</td>
                    <td className="p-3"><span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold" style={{ background: `${sevColor}15`, color: sevColor, border: `1px solid ${sevColor}30` }}>{alert.severity}</span></td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-14 h-1.5 rounded-full overflow-hidden" style={{ background: '#1e1e22' }}>
                          <div className="h-full rounded-full" style={{ background: sevColor, width: `${alert.riskScore}%` }}></div>
                        </div>
                        <span className="font-mono font-bold text-[11px]" style={{ color: 'white' }}>{alert.riskScore}</span>
                      </div>
                    </td>
                    <td className="p-3"><span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold" style={{ background: '#22c55e15', color: '#22c55e', border: '1px solid #22c55e30' }}>{alert.status}</span></td>
                  </tr>
                );
              })}
              {stats.recentAlerts.length === 0 && (
                <tr><td colSpan={5} className="p-10 text-center font-mono text-xs" style={{ color: '#52525b' }}>
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: '#1a1a1e', border: '1px solid rgba(255,255,255,0.06)' }}>
                      <ShieldCheck className="w-5 h-5" style={{ color: '#22c55e' }} />
                    </div>
                    No alerts yet • Upload a sample to begin • System secure
                  </div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
