"use client";
import { useEffect, useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Plus, Trash2, Shield, Globe, Hash, FileSearch, Copy, ExternalLink, Clock, Eye, Ban, CheckCircle, Zap, Tag, Database, Filter, Download, FileText, Link2, Target, Server, Info, X, BarChart3, Users, MapPin, Globe2, HardDrive, Network, Edit3, Save, User, History, Sparkles, Folder, FolderOpen, File, ChevronRight, Layers, Box } from "lucide-react";
import Link from "next/link";

interface IOC {
  id: string;
  value: string;
  type: string;
  severity: string;
  source: string;
  firstSeen: string;
  lastSeen: string;
  description: string;
  relatedAlerts: string[];
  tags: string[];
  confidence?: number;
  timesSeen?: number;
  relatedSamples?: string[];
  mitreTechniques?: string[];
  isWhitelisted?: boolean;
  isBlocked?: boolean;
  reputationScore?: number;
  threatIntel?: any;
  autoExtracted?: boolean;
  fileName?: string;
  enrichmentDetails?: any;
  notes?: string;
  threatActor?: string;
  campaign?: string;
  additionalInfo?: string;
  customFields?: { key: string; value: string }[];
  history?: any[];
  isImportant?: boolean;
  autoEnriched?: boolean;
}

export default function IOCPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [samples, setSamples] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [tagFilter, setTagFilter] = useState("");
  const [fileFilter, setFileFilter] = useState("");
  const [sortBy, setSortBy] = useState("lastSeen");
  const [showAdd, setShowAdd] = useState(false);
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null);
  const [newIOC, setNewIOC] = useState({ value: "", type: "IP", severity: "MEDIUM", description: "", tags: "" });
  const [viewMode, setViewMode] = useState<'flat'|'file'>('file');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [showFilters, setShowFilters] = useState(true);
  const [editMode, setEditMode] = useState(false);
  const [editData, setEditData] = useState({ notes: "", threatActor: "", campaign: "", additionalInfo: "", customKey: "", customValue: "" });
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(new Set());

  const fetchIOCs = async () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    if (typeFilter) params.set("type", typeFilter);
    if (severityFilter) params.set("severity", severityFilter);
    if (tagFilter) params.set("tag", tagFilter);
    if (fileFilter) params.set("source", fileFilter);
    if (sortBy) params.set("sort", sortBy);
    const res = await fetch(`/api/iocs?${params}`);
    const data = await res.json();
    if (data.iocs) {
      setIocs(data.iocs);
      setStats(data.stats);
    } else if (Array.isArray(data)) {
      setIocs(data);
    }
    setLoading(false);
  };

  const fetchSamples = async () => {
    try {
      const res = await fetch('/api/samples');
      const data = await res.json();
      setSamples(Array.isArray(data) ? data : []);
    } catch {}
  };

  useEffect(() => { fetchIOCs(); fetchSamples(); }, []);
  useEffect(() => { fetchIOCs(); }, [typeFilter, severityFilter, sortBy, tagFilter, fileFilter]);

  useEffect(() => {
    if (selectedIOC) {
      setEditData({
        notes: selectedIOC.notes || "",
        threatActor: selectedIOC.threatActor || "",
        campaign: selectedIOC.campaign || "",
        additionalInfo: selectedIOC.additionalInfo || "",
        customKey: "",
        customValue: ""
      });
      setEditMode(false);
    }
  }, [selectedIOC]);

  // Group IOCs by original file
  const fileGroups = useMemo(() => {
    const groups: Record<string, { fileName: string; source: string; iocs: IOC[]; sampleId?: string; fileInfo?: any }> = {};
    iocs.forEach(ioc => {
      const key = ioc.fileName || ioc.source || 'Unknown File';
      if (!groups[key]) {
        const relatedSample = samples.find(s => s.id === ioc.relatedSamples?.[0] || s.originalFilename === key);
        groups[key] = { fileName: key, source: ioc.source, iocs: [], sampleId: relatedSample?.id || ioc.relatedSamples?.[0], fileInfo: relatedSample };
      }
      groups[key].iocs.push(ioc);
    });
    return Object.values(groups).sort((a,b) => b.iocs.length - a.iocs.length);
  }, [iocs, samples]);

  const toggleFileExpand = (fileName: string) => {
    const newSet = new Set(expandedFiles);
    if (newSet.has(fileName)) newSet.delete(fileName);
    else newSet.add(fileName);
    setExpandedFiles(newSet);
  };

  const addIOC = async () => {
    const res = await fetch("/api/iocs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...newIOC, tags: newIOC.tags.split(",").map(t => t.trim()).filter(Boolean) }) });
    if (res.ok) { setShowAdd(false); setNewIOC({ value: "", type: "IP", severity: "MEDIUM", description: "", tags: "" }); fetchIOCs(); }
    else { const d = await res.json(); alert(d.error); }
  };

  const deleteIOC = async (id: string) => {
    if (!confirm("Delete IOC?")) return;
    await fetch(`/api/iocs/${id}`, { method: "DELETE" });
    fetchIOCs();
    setSelectedIOC(null);
  };

  const toggleBlock = async (ioc: IOC) => {
    await fetch(`/api/iocs/${ioc.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ isBlocked: !ioc.isBlocked, isWhitelisted: false }) });
    fetchIOCs();
    if (selectedIOC?.id === ioc.id) setSelectedIOC({ ...selectedIOC, isBlocked: !selectedIOC.isBlocked, isWhitelisted: false });
  };

  const toggleWhitelist = async (ioc: IOC) => {
    await fetch(`/api/iocs/${ioc.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ isWhitelisted: !ioc.isWhitelisted, isBlocked: false }) });
    fetchIOCs();
    if (selectedIOC?.id === ioc.id) setSelectedIOC({ ...selectedIOC, isWhitelisted: !selectedIOC.isWhitelisted, isBlocked: false });
  };

  const saveAdditionalInfo = async () => {
    if (!selectedIOC) return;
    const updatedCustomFields = [...(selectedIOC.customFields || [])];
    if (editData.customKey && editData.customValue) updatedCustomFields.push({ key: editData.customKey, value: editData.customValue });
    const res = await fetch(`/api/iocs/${selectedIOC.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        notes: editData.notes,
        threatActor: editData.threatActor,
        campaign: editData.campaign,
        additionalInfo: editData.additionalInfo,
        customFields: updatedCustomFields,
        lastUpdatedBy: "USER",
        history: [...(selectedIOC.history || []), { timestamp: new Date().toISOString(), user: "USER", action: "USER_ADDED_INFO", details: `Notes: ${editData.notes.substring(0,50)} | Actor: ${editData.threatActor}` }]
      })
    });
    if (res.ok) {
      const data = await res.json();
      setSelectedIOC(data.ioc);
      fetchIOCs();
      setEditMode(false);
      setEditData({ ...editData, customKey: "", customValue: "" });
    }
  };

  const copyToClipboard = (text: string) => { navigator.clipboard.writeText(text); };
  const exportCSV = () => {
    const toExport = selectedIds.size > 0 ? iocs.filter(i => selectedIds.has(i.id)) : iocs;
    const csv = ["fileName,type,value,severity,confidence,reputation,firstSeen,lastSeen,source,tags,threatActor,campaign"].concat(
      toExport.map(i => `"${(i.fileName||i.source).replace(/"/g,'""')}",${i.type},"${i.value.replace(/"/g,'""')}",${i.severity},${i.confidence||''},${i.reputationScore||''},${i.firstSeen},${i.lastSeen},"${i.source}","${(i.tags||[]).join(';')}","${(i.threatActor||'').replace(/"/g,'""')}","${(i.campaign||'').replace(/"/g,'""')}"`)
    ).join("\n");
    const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `maldef-iocs-by-file-${Date.now()}.csv`; a.click();
  };
  const exportSTIX = () => {
    const toExport = selectedIds.size > 0 ? iocs.filter(i => selectedIds.has(i.id)) : iocs;
    const stix = { type: "bundle", id: `bundle--${Date.now()}`, objects: toExport.map(ioc => ({ type: "indicator", id: `indicator--${ioc.id.toLowerCase()}`, created: ioc.firstSeen, modified: ioc.lastSeen, name: `${ioc.fileName||ioc.source} - ${ioc.type}: ${ioc.value.substring(0,50)}`, description: ioc.description, pattern: `[${ioc.type.toLowerCase()}:value = '${ioc.value}']`, labels: ioc.tags, custom: { fileName: ioc.fileName, threatActor: ioc.threatActor } })) };
    const blob = new Blob([JSON.stringify(stix, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `maldef-iocs-by-file-${Date.now()}.json`; a.click();
  };
  const getIcon = (type: string) => { switch(type) { case 'IP': return Server; case 'DOMAIN': return Globe; case 'URL': return Link2; case 'SHA256': case 'SHA1': case 'MD5': return Hash; case 'FILENAME': return FileText; default: return Hash; } };
  const getSeverityColor = (sev: string) => { switch(sev) { case 'CRITICAL': return 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20'; case 'HIGH': return 'bg-[#ff6b35]/10 text-[#ff6b35] border-[#ff6b35]/20'; case 'MEDIUM': return 'bg-[#ffcc00]/10 text-[#ffcc00] border-[#ffcc00]/20'; case 'LOW': return 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/20'; default: return 'bg-[#27272a] text-[#71717a] border-white/5'; } };
  const getTypeColor = (type: string) => { switch(type) { case 'IP': return 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20'; case 'DOMAIN': return 'bg-[#8b5cf6]/10 text-[#8b5cf6] border-[#8b5cf6]/20'; case 'URL': return 'bg-[#ff6b35]/10 text-[#ff6b35] border-[#ff6b35]/20'; case 'SHA256': return 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/20'; default: return 'bg-[#27272a] text-[#a1a1aa] border-white/5'; } };

  return (
    <div className="p-4 lg:p-6 max-w-[1800px] mx-auto space-y-6">
      <div className="flex flex-col lg:flex-row justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl lg:text-3xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#ffcc00] to-[#ff6b35] flex items-center justify-center"><Search className="w-5 h-5 text-white" /></div>
            IOC EXPLORER
            <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20">BY FILE</span>
          </h1>
          <p className="text-[#71717a] text-sm font-mono mt-2 max-w-4xl">Grouped by original file • See which IOC belongs to which file • Subfolders per file • Auto-fetched details + user notes</p>
          <div className="flex gap-2 mt-3 flex-wrap">
            <span className="px-2.5 py-1 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 text-[10px] font-mono text-[#00ff88] flex items-center gap-1.5"><Folder className="w-3 h-3" />Grouped by file</span>
            <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 border border-[#ff3344]/20 text-[10px] font-mono text-[#ff3344] flex items-center gap-1.5"><Box className="w-3 h-3" />Subfolders per file</span>
            <span className="px-2.5 py-1 rounded-full bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 text-[10px] font-mono text-[#8b5cf6] flex items-center gap-1.5"><Layers className="w-3 h-3" />Identify file source</span>
          </div>
        </div>
        <div className="flex gap-2.5 items-center">
          <button onClick={exportCSV} className="h-[44px] min-w-[100px] px-4 bg-[#181825] border border-white/10 rounded-xl text-white text-[13px] font-mono font-medium flex items-center justify-center gap-2 hover:bg-[#1e1e2e] hover:border-[#ff3344]/30 transition-all"><Download className="w-4 h-4" />CSV</button>
          <button onClick={exportSTIX} className="h-[44px] min-w-[100px] px-4 bg-[#181825] border border-white/10 rounded-xl text-white text-[13px] font-mono font-medium flex items-center justify-center gap-2 hover:bg-[#1e1e2e] hover:border-[#8b5cf6]/30 transition-all"><FileText className="w-4 h-4" />STIX</button>
          <button onClick={() => setShowAdd(true)} className="h-[44px] min-w-[120px] px-5 bg-white text-black rounded-xl font-bold text-[13px] flex items-center justify-center gap-2 hover:bg-[#e4e4e7] transition-colors shadow-lg"><Plus className="w-4 h-4" />ADD IOC</button>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-3">
          <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Total IOCs</p><p className="text-2xl font-bold text-white mt-1">{stats.total}</p><p className="text-[10px] font-mono text-[#00ff88] mt-1">{fileGroups.length} files</p></div>
          <div className="glass rounded-2xl p-4 border border-[#ff3344]/20 bg-[#ff3344]/5"><p className="text-[10px] font-mono text-[#ff3344] uppercase">Critical</p><p className="text-2xl font-bold text-[#ff3344] mt-1">{stats.bySeverity.CRITICAL}</p></div>
          <div className="glass rounded-2xl p-4 border border-[#ff3344]/20 bg-[#ff3344]/5"><p className="text-[10px] font-mono text-[#ff3344] uppercase">IPs</p><p className="text-2xl font-bold text-white mt-1">{stats.byType.IP}</p></div>
          <div className="glass rounded-2xl p-4 border border-[#8b5cf6]/20 bg-[#8b5cf6]/5"><p className="text-[10px] font-mono text-[#8b5cf6] uppercase">URLs</p><p className="text-2xl font-bold text-white mt-1">{stats.byType.URL}</p></div>
          <div className="glass rounded-2xl p-4 border border-[#00ff88]/20 bg-[#00ff88]/5"><p className="text-[10px] font-mono text-[#00ff88] uppercase">Hashes</p><p className="text-2xl font-bold text-white mt-1">{stats.byType.SHA256 + stats.byType.MD5 + stats.byType.SHA1}</p></div>
          <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Files</p><p className="text-2xl font-bold text-white mt-1">{fileGroups.length}</p><p className="text-[10px] font-mono text-[#52525b] mt-1">subfolders</p></div>
          <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Domains</p><p className="text-2xl font-bold text-white mt-1">{stats.byType.DOMAIN}</p></div>
          <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Tags</p><p className="text-2xl font-bold text-white mt-1">{stats.totalTags}</p></div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        <div className={`xl:col-span-1 space-y-4 ${showFilters ? 'block' : 'hidden xl:block'}`}>
          <div className="glass rounded-2xl border border-white/5 p-4">
            <h3 className="font-bold text-white text-sm mb-3 flex items-center gap-2"><Folder className="w-4 h-4 text-[#ffcc00]" />FILES (SUBFOLDERS)</h3>
            <div className="space-y-2 max-h-[400px] overflow-y-auto">
              {fileGroups.map(group => (
                <button key={group.fileName} onClick={() => setFileFilter(fileFilter === group.fileName ? '' : group.fileName)} className={`w-full text-left p-3 rounded-xl border transition-all ${fileFilter === group.fileName ? 'bg-[#ffcc00]/10 border-[#ffcc00]/20' : 'bg-[#181825] border-white/5 hover:border-white/10'}`}>
                  <div className="flex items-start gap-2">
                    <Folder className={`w-4 h-4 mt-0.5 flex-shrink-0 ${fileFilter === group.fileName ? 'text-[#ffcc00]' : 'text-[#71717a]'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-mono text-xs truncate">{group.fileName}</p>
                      <p className="text-[10px] font-mono text-[#71717a] mt-1">{group.iocs.length} IOCs • {group.iocs.filter(i=>i.type==='URL').length} URLs • {group.iocs.filter(i=>i.type==='IP').length} IPs • {group.iocs.filter(i=>i.type.includes('SHA')||i.type==='MD5').length} hashes</p>
                      <div className="flex gap-1 mt-1.5 flex-wrap">
                        {Array.from(new Set(group.iocs.map(i=>i.type))).slice(0,3).map(t => <span key={t} className="px-1.5 py-0.5 rounded bg-[#27272a] text-[9px] font-mono text-[#a1a1aa]">{t}</span>)}
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${fileFilter === group.fileName ? 'bg-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#27272a] text-[#71717a]'}`}>{group.iocs.length}</span>
                  </div>
                </button>
              ))}
              {fileGroups.length === 0 && <p className="text-[#71717a] text-xs font-mono text-center py-4">No files yet</p>}
            </div>

            <div className="mt-4 pt-4 border-t border-white/5">
              <p className="text-[11px] font-mono text-[#71717a] uppercase mb-2">View Mode</p>
              <div className="grid grid-cols-2 gap-2">
                <button onClick={() => setViewMode('file')} className={`h-[40px] px-3 rounded-xl text-xs font-mono font-bold border flex items-center justify-center gap-1.5 transition-all ${viewMode === 'file' ? 'bg-[#ffcc00]/10 border-[#ffcc00]/20 text-[#ffcc00]' : 'bg-[#181825] border-white/5 text-[#71717a] hover:border-white/10'}`}><Folder className="w-3.5 h-3.5" />By File</button>
                <button onClick={() => setViewMode('flat')} className={`h-[40px] px-3 rounded-xl text-xs font-mono font-bold border flex items-center justify-center gap-1.5 transition-all ${viewMode === 'flat' ? 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff3344]' : 'bg-[#181825] border-white/5 text-[#71717a] hover:border-white/10'}`}><Layers className="w-3.5 h-3.5" />Flat</button>
              </div>
            </div>

            <div className="mt-4 bg-[#0a0a0f] rounded-xl p-3 border border-white/5">
              <p className="text-[11px] font-mono text-[#a1a1aa] font-bold mb-1">How File Grouping Works</p>
              <p className="text-[10px] font-mono text-[#71717a] leading-relaxed">Each uploaded file creates a subfolder. All IOCs extracted from that file (hashes, C2 IPs, malicious URLs) are stored inside that folder. Click a file to filter, see which info belongs to which file. Like a file explorer for threat intel.</p>
            </div>
          </div>

          <div className="glass rounded-2xl border border-white/5 p-4">
            <h3 className="font-bold text-white text-sm mb-3 flex items-center gap-2"><Filter className="w-4 h-4 text-[#ff3344]" />FILTERS</h3>
            <div className="space-y-3">
              <div>
                <p className="text-[11px] font-mono text-[#71717a] uppercase mb-2">By Type</p>
                <div className="space-y-1.5">
                  {stats && Object.entries(stats.byType).map(([type, count]: any) => (
                    <button key={type} onClick={() => setTypeFilter(typeFilter === type ? '' : type)} className={`w-full flex justify-between items-center px-3 py-2 rounded-xl text-xs font-mono ${typeFilter === type ? 'bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff3344]' : 'bg-[#181825] border border-white/5 text-[#a1a1aa]'}`}>
                      <span>{type}</span><span className="px-1.5 py-0.5 rounded text-[10px] bg-[#27272a]">{count as number}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="xl:col-span-3 space-y-4">
          <div className="glass rounded-2xl border border-white/5 p-3 flex flex-wrap gap-2.5 items-center">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525b]" />
              <input value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && fetchIOCs()} placeholder="Search value, threat actor, campaign, notes, file name..." className="w-full h-[44px] pl-10 pr-4 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-[13px] outline-none focus:border-[#ff3344]/50 transition-colors" />
            </div>
            <select value={fileFilter} onChange={e => setFileFilter(e.target.value)} className="h-[44px] px-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-[13px] max-w-[200px] truncate outline-none focus:border-[#ff3344]/30">
              <option value="">All Files</option>
              {fileGroups.map(g => <option key={g.fileName} value={g.fileName}>{g.fileName} ({g.iocs.length})</option>)}
            </select>
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="h-[44px] px-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-[13px] outline-none focus:border-[#ff3344]/30"><option value="">All Types</option><option>SHA256</option><option>IP</option><option>DOMAIN</option><option>URL</option><option>FILENAME</option></select>
            <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="h-[44px] px-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-[13px] outline-none focus:border-[#ff3344]/30"><option value="lastSeen">Last Seen</option><option value="severity">Severity</option></select>
            <button onClick={fetchIOCs} className="h-[44px] min-w-[90px] px-5 bg-white text-black rounded-xl font-bold text-[13px] hover:bg-[#e4e4e7] transition-colors flex items-center justify-center">Search</button>
          </div>

          {fileFilter && (
            <div className="glass rounded-xl border border-[#ffcc00]/20 bg-[#ffcc00]/5 p-3 flex items-center gap-3">
              <FolderOpen className="w-5 h-5 text-[#ffcc00]" />
              <div><p className="text-white font-mono text-sm font-bold">{fileFilter}</p><p className="text-[11px] font-mono text-[#71717a]">Showing {iocs.length} IOCs from this file • <button onClick={() => setFileFilter('')} className="text-[#ffcc00] hover:underline">Clear filter</button></p></div>
              <button onClick={() => setFileFilter('')} className="ml-auto w-8 h-8 rounded-lg bg-[#0a0a0f] border border-white/10 flex items-center justify-center"><X className="w-4 h-4 text-white" /></button>
            </div>
          )}

          {loading ? (
            <div className="space-y-4">{[...Array(3)].map((_, i) => <div key={i} className="h-32 glass rounded-2xl animate-pulse"></div>)}</div>
          ) : viewMode === 'file' ? (
            <div className="space-y-6">
              {fileGroups.filter(g => !fileFilter || g.fileName === fileFilter).map(group => {
                const isExpanded = expandedFiles.has(group.fileName) || fileFilter === group.fileName || fileGroups.length === 1;
                return (
                  <motion.div key={group.fileName} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-2xl border border-white/5 overflow-hidden">
                    <button onClick={() => toggleFileExpand(group.fileName)} className="w-full p-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors text-left">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#ffcc00]/20 to-[#ff6b35]/20 border border-[#ffcc00]/20 flex items-center justify-center flex-shrink-0">
                          <File className="w-6 h-6 text-[#ffcc00]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-white font-bold font-mono text-sm flex items-center gap-2 truncate">
                            {group.fileName}
                            <span className="px-2 py-0.5 rounded-full bg-[#27272a] text-[10px] font-mono text-[#a1a1aa] border border-white/5">{group.iocs.length} IOCs</span>
                            {group.fileInfo && <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${group.fileInfo?.analysis?.riskScore >= 50 ? 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20' : 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/20'}`}>{group.fileInfo?.analysis?.classification || 'Unknown'}</span>}
                          </p>
                          <p className="text-[11px] font-mono text-[#71717a] mt-1 truncate">
                            {group.fileInfo ? `SHA256: ${group.fileInfo.sha256?.substring(0,16)}... • ${group.fileInfo.fileSize} bytes • ${new Date(group.fileInfo.uploadTimestamp).toLocaleDateString()}` : `Source: ${group.source} • First seen ${new Date(group.iocs[0]?.firstSeen).toLocaleDateString()}`}
                          </p>
                          <div className="flex gap-1.5 mt-2 flex-wrap">
                            <span className="px-2 py-0.5 rounded-full bg-[#00ff88]/10 text-[#00ff88] text-[10px] font-mono border border-[#00ff88]/10">{group.iocs.filter(i=>i.type.includes('SHA')||i.type==='MD5'||i.type==='SHA1').length} hashes</span>
                            <span className="px-2 py-0.5 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[10px] font-mono border border-[#ff3344]/10">{group.iocs.filter(i=>i.type==='IP').length} IPs</span>
                            <span className="px-2 py-0.5 rounded-full bg-[#8b5cf6]/10 text-[#8b5cf6] text-[10px] font-mono border border-[#8b5cf6]/10">{group.iocs.filter(i=>i.type==='DOMAIN').length} domains</span>
                            <span className="px-2 py-0.5 rounded-full bg-[#ff6b35]/10 text-[#ff6b35] text-[10px] font-mono border border-[#ff6b35]/10">{group.iocs.filter(i=>i.type==='URL').length} URLs</span>
                            <span className="px-2 py-0.5 rounded-full bg-[#ffcc00]/10 text-[#ffcc00] text-[10px] font-mono border border-[#ffcc00]/10">{group.iocs.filter(i=>i.type==='FILENAME').length} files</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 ml-3">
                        {group.sampleId && <Link href={`/investigation/${group.sampleId}`} onClick={e => e.stopPropagation()} className="h-8 px-3 rounded-xl bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 text-[#8b5cf6] text-xs font-mono font-medium hover:bg-[#8b5cf6]/20 flex items-center justify-center transition-colors">Investigate</Link>}
                        <div className={`w-8 h-8 rounded-xl bg-[#181825] border border-white/10 flex items-center justify-center transition-transform hover:border-white/20 ${isExpanded ? 'rotate-90' : ''}`}><ChevronRight className="w-4 h-4 text-[#71717a]" /></div>
                      </div>
                    </button>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="border-t border-white/5 bg-[#0a0a0f]/50">
                          <div className="p-4 grid grid-cols-1 lg:grid-cols-2 gap-3">
                            {group.iocs.map(ioc => {
                              const Icon = getIcon(ioc.type);
                              return (
                                <div key={ioc.id} className="bg-[#181825] rounded-xl border border-white/5 p-3 hover:border-[#ff3344]/20 transition-colors group">
                                  <div className="flex justify-between items-start mb-2">
                                    <div className="flex items-center gap-2">
                                      <div className="w-7 h-7 rounded-lg bg-[#0a0a0f] border border-white/5 flex items-center justify-center"><Icon className="w-3.5 h-3.5 text-[#71717a] group-hover:text-[#ff3344]" /></div>
                                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${getTypeColor(ioc.type)}`}>{ioc.type}</span>
                                      {ioc.autoExtracted && <span className="px-1.5 py-0.5 rounded-full bg-[#00ff88]/10 text-[#00ff88] text-[9px] font-mono border border-[#00ff88]/20">AUTO</span>}
                                    </div>
                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${getSeverityColor(ioc.severity)}`}>{ioc.severity}</span>
                                  </div>
                                  <div className="bg-[#0a0a0f] rounded-lg p-2.5 border border-white/5 mb-2">
                                    <p className="text-white font-mono text-[11px] break-all line-clamp-2">{ioc.value}</p>
                                  </div>
                                  <p className="text-[#71717a] text-[11px] line-clamp-2 mb-2">{ioc.description}</p>
                                  <div className="flex gap-1.5 flex-wrap mb-2">
                                    {(ioc.tags||[]).slice(0,3).map(t => <span key={t} className="px-1.5 py-0.5 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[9px] font-mono border border-[#ff3344]/10">{t}</span>)}
                                  </div>
                                  <div className="flex gap-2 items-center">
                                    <button onClick={() => setSelectedIOC(ioc)} className="flex-1 h-[36px] rounded-xl bg-white text-black text-[11px] font-bold flex items-center justify-center gap-1.5 hover:bg-[#e4e4e7] transition-colors"><Eye className="w-3.5 h-3.5" />Details + Add Info</button>
                                    <button onClick={() => copyToClipboard(ioc.value)} className="w-[36px] h-[36px] rounded-xl bg-[#0a0a0f] border border-white/10 flex items-center justify-center hover:border-[#ff3344]/20 hover:bg-[#181825] transition-all"><Copy className="w-3.5 h-3.5 text-[#71717a] hover:text-white" /></button>
                                    <button onClick={() => { const s = new Set(selectedIds); s.has(ioc.id) ? s.delete(ioc.id) : s.add(ioc.id); setSelectedIds(s); }} className="w-[36px] h-[36px] rounded-xl bg-[#0a0a0f] border border-white/10 flex items-center justify-center hover:border-white/20"><input type="checkbox" checked={selectedIds.has(ioc.id)} readOnly className="w-3.5 h-3.5 rounded" /></button>
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
              {fileGroups.length === 0 && (
                <div className="glass rounded-2xl border border-white/5 p-12 text-center">
                  <Folder className="w-12 h-12 text-[#27272a] mx-auto mb-3" />
                  <p className="text-white font-medium">No files with IOCs yet</p>
                  <p className="text-[#71717a] text-sm font-mono mt-1">Upload a file to see it as a subfolder with all its IOCs grouped inside</p>
                </div>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {iocs.map(ioc => {
                const Icon = getIcon(ioc.type);
                return (
                  <div key={ioc.id} className="glass rounded-2xl border border-white/5 p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Folder className="w-3 h-3 text-[#ffcc00]" />
                      <span className="text-[10px] font-mono text-[#ffcc00] truncate">{ioc.fileName||ioc.source}</span>
                    </div>
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2"><div className="w-8 h-8 rounded-lg bg-[#0a0a0f] border border-white/5 flex items-center justify-center"><Icon className="w-4 h-4 text-[#71717a]" /></div><span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${getTypeColor(ioc.type)}`}>{ioc.type}</span></div>
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${getSeverityColor(ioc.severity)}`}>{ioc.severity}</span>
                    </div>
                    <p className="text-white font-mono text-xs break-all bg-[#0a0a0f] p-2.5 rounded-xl border border-white/5 mb-2">{ioc.value.length > 80 ? ioc.value.substring(0,80)+'...' : ioc.value}</p>
                    <p className="text-[#71717a] text-xs mb-3">{ioc.description}</p>
                    <button onClick={() => setSelectedIOC(ioc)} className="w-full py-2 rounded-xl bg-white text-black text-xs font-bold flex items-center justify-center gap-1.5"><Eye className="w-3.5 h-3.5" />DETAILS + ADD INFO</button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Detail Modal */}
      <AnimatePresence>
        {selectedIOC && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/70 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto">
            <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }} className="w-full max-w-6xl glass-strong rounded-2xl border border-[#ff3344]/20 overflow-hidden my-8">
              <div className="p-5 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-[#181825] to-[#0a0a0f]">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="w-10 h-10 rounded-xl bg-[#0a0a0f] border border-white/10 flex items-center justify-center flex-shrink-0">{(() => { const I = getIcon(selectedIOC.type); return <I className="w-5 h-5 text-[#ff3344]" /> })()}</div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold text-white flex items-center gap-2 flex-wrap truncate">
                      <Folder className="w-4 h-4 text-[#ffcc00] flex-shrink-0" />
                      <span className="text-[#ffcc00] text-xs">{selectedIOC.fileName||selectedIOC.source}</span>
                      <span className="text-[#52525b]">/</span>
                      {selectedIOC.type} • {selectedIOC.value.substring(0,25)}...
                    </h3>
                    <p className="text-[11px] font-mono text-[#71717a]">File: {selectedIOC.fileName||selectedIOC.source} • First {new Date(selectedIOC.firstSeen).toLocaleDateString()} • {selectedIOC.timesSeen||1}x seen</p>
                  </div>
                </div>
                <button onClick={() => setSelectedIOC(null)} className="w-9 h-9 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-white ml-3 flex-shrink-0"><X className="w-4 h-4" /></button>
              </div>

              <div className="p-5 grid grid-cols-1 lg:grid-cols-5 gap-6 max-h-[80vh] overflow-y-auto">
                <div className="lg:col-span-3 space-y-5">
                  <div className="bg-[#ffcc00]/5 border border-[#ffcc00]/20 rounded-xl p-3">
                    <p className="text-[11px] font-mono text-[#ffcc00] uppercase font-bold flex items-center gap-2"><Folder className="w-4 h-4" />ORIGINAL FILE SUBFOLDER</p>
                    <p className="text-white font-mono text-sm mt-1">{selectedIOC.fileName||selectedIOC.source}</p>
                    <p className="text-[11px] font-mono text-[#71717a] mt-1">This IOC belongs to this file. All IOCs from same file are grouped together in file subfolder view. You can identify which info is from which file easily.</p>
                  </div>

                  <div>
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-2">Full IOC Value</p>
                    <div className="bg-[#0a0a0f] rounded-xl p-4 border border-white/5 relative"><p className="text-white font-mono text-sm break-all pr-10">{selectedIOC.value}</p><button onClick={() => copyToClipboard(selectedIOC.value)} className="absolute top-3 right-3 w-8 h-8 rounded-lg bg-[#181825] border border-white/10 flex items-center justify-center"><Copy className="w-4 h-4 text-[#71717a]" /></button></div>
                  </div>

                  {selectedIOC.enrichmentDetails && (
                    <div className="bg-[#ff3344]/5 border border-[#ff3344]/20 rounded-2xl p-4">
                      <p className="text-[11px] font-mono text-[#ff3344] uppercase mb-3 font-bold flex items-center gap-2"><Sparkles className="w-4 h-4" />AUTO-FETCHED DETAILS</p>
                      {selectedIOC.enrichmentDetails.geo && <div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5 mb-2"><p className="text-[10px] font-mono text-[#71717a] uppercase mb-2 flex items-center gap-1"><MapPin className="w-3 h-3" />Geo</p><p className="text-white text-xs font-mono">{selectedIOC.enrichmentDetails.geo.country} {selectedIOC.enrichmentDetails.geo.city} • {selectedIOC.enrichmentDetails.geo.asn}</p></div>}
                      {selectedIOC.enrichmentDetails.fileDetails && <div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase mb-1">File Details</p><p className="text-white text-xs font-mono">Size {selectedIOC.enrichmentDetails.fileDetails.fileSize} • Entropy {selectedIOC.enrichmentDetails.fileDetails.entropy} • {selectedIOC.enrichmentDetails.fileDetails.mimeType}</p></div>}
                    </div>
                  )}

                  <div className="bg-[#8b5cf6]/5 border border-[#8b5cf6]/20 rounded-2xl p-4">
                    <div className="flex justify-between items-center mb-3">
                      <p className="text-[11px] font-mono text-[#8b5cf6] uppercase font-bold flex items-center gap-2"><Edit3 className="w-4 h-4" />USER ADDITIONAL INFO FOR FUTURE</p>
                      <button onClick={() => setEditMode(!editMode)} className={`px-3 py-1.5 rounded-lg text-xs font-mono ${editMode ? 'bg-[#27272a] text-white' : 'bg-[#8b5cf6]/10 text-[#8b5cf6] border border-[#8b5cf6]/20'}`}>{editMode ? 'Cancel' : 'Edit/Add'}</button>
                    </div>
                    {!editMode ? (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-2"><div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Threat Actor</p><p className="text-white text-sm mt-1">{selectedIOC.threatActor || <span className="text-[#52525b]">Not set</span>}</p></div><div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Campaign</p><p className="text-white text-sm mt-1">{selectedIOC.campaign || <span className="text-[#52525b]">Not set</span>}</p></div></div>
                        <div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Notes</p><p className="text-[#a1a1aa] text-sm mt-1">{selectedIOC.notes || 'No notes'}</p></div>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-2"><input value={editData.threatActor} onChange={e => setEditData({ ...editData, threatActor: e.target.value })} placeholder="Threat Actor e.g., APT29" className="p-2.5 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm" /><input value={editData.campaign} onChange={e => setEditData({ ...editData, campaign: e.target.value })} placeholder="Campaign e.g., SolarWinds" className="p-2.5 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm" /></div>
                        <textarea value={editData.notes} onChange={e => setEditData({ ...editData, notes: e.target.value })} placeholder="Notes for future hunting" className="w-full p-2.5 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm h-[80px]" />
                        <button onClick={saveAdditionalInfo} className="w-full py-3 bg-[#8b5cf6] text-white rounded-xl font-bold text-sm flex items-center justify-center gap-2"><Save className="w-4 h-4" />Save for Future</button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="bg-[#0a0a0f] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3">Threat Intel (Auto)</p>
                    <div className="space-y-2">
                      <div className="p-3 rounded-xl bg-[#181825] border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">VirusTotal</p><p className="text-white font-bold text-sm mt-1">{selectedIOC.threatIntel?.virusTotal?.ratio || '0/29'}</p></div>
                      {selectedIOC.type === 'IP' && selectedIOC.threatIntel?.abuseIPDB && <div className="p-3 rounded-xl bg-[#181825] border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">AbuseIPDB</p><p className="text-white font-bold text-sm mt-1">Score {selectedIOC.threatIntel.abuseIPDB.score}/100 • {selectedIOC.threatIntel.abuseIPDB.reports} reports</p></div>}
                    </div>
                  </div>

                  <div className="bg-[#181825] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3">Actions</p>
                    <div className="space-y-2">
                      <button onClick={() => toggleBlock(selectedIOC)} className={`w-full py-2.5 rounded-xl font-bold text-sm flex items-center justify-center gap-2 ${selectedIOC.isBlocked ? 'bg-[#ff3344] text-white' : 'bg-white text-black'}`}><Ban className="w-4 h-4" />{selectedIOC.isBlocked ? 'Unblock' : 'Block'}</button>
                      <Link href={`/samples?search=${encodeURIComponent(selectedIOC.fileName||selectedIOC.source)}`} className="w-full py-2.5 rounded-xl bg-[#ffcc00]/10 border border-[#ffcc00]/20 text-[#ffcc00] font-bold text-sm flex items-center justify-center gap-2"><Folder className="w-4 h-4" />View File Folder</Link>
                      <button onClick={() => deleteIOC(selectedIOC.id)} className="w-full py-2.5 rounded-xl bg-[#ff3344]/10 border border-[#ff3344]/20 text-[#ff3344] font-bold text-sm flex items-center justify-center gap-2"><Trash2 className="w-4 h-4" />Delete</button>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {showAdd && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-md glass-strong rounded-2xl border border-[#ff3344]/20 p-5">
            <h3 className="font-bold text-white mb-4">Add New IOC</h3>
            <div className="space-y-3">
              <input value={newIOC.value} onChange={e => setNewIOC({ ...newIOC, value: e.target.value })} placeholder="IOC Value" className="w-full p-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm" />
              <div className="grid grid-cols-2 gap-2"><select value={newIOC.type} onChange={e => setNewIOC({ ...newIOC, type: e.target.value })} className="p-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm"><option>SHA256</option><option>IP</option><option>DOMAIN</option><option>URL</option><option>FILENAME</option></select><select value={newIOC.severity} onChange={e => setNewIOC({ ...newIOC, severity: e.target.value })} className="p-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>
              <input value={newIOC.description} onChange={e => setNewIOC({ ...newIOC, description: e.target.value })} placeholder="Description" className="w-full p-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm" />
              <input value={newIOC.tags} onChange={e => setNewIOC({ ...newIOC, tags: e.target.value })} placeholder="Tags comma separated" className="w-full p-3 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-sm" />
              <div className="flex gap-2"><button onClick={addIOC} className="flex-1 py-3 bg-white text-black rounded-xl font-bold text-sm">Add IOC</button><button onClick={() => setShowAdd(false)} className="px-6 py-3 bg-[#27272a] text-white rounded-xl text-sm">Cancel</button></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
