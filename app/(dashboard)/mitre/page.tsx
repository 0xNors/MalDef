"use client";
import { useEffect, useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Target, Shield, ExternalLink, Eye, Search, Filter, ChevronDown, ChevronRight, X, Zap, AlertTriangle, CheckCircle, Layers, Grid, List, Info, BookOpen, Crosshair, Lock, Unlock, MapPin, Activity, Server, Database, FileText, Globe, Users, Clock, Bookmark, ChevronUp, Sparkles } from "lucide-react";

export default function MitrePage() {
  const [data, setData] = useState<any>(null);
  const [selectedTactic, setSelectedTactic] = useState<string>("");
  const [search, setSearch] = useState("");
  const [viewMode, setViewMode] = useState<'matrix'|'list'>('matrix');
  const [selectedTech, setSelectedTech] = useState<any>(null);
  const [showSubTechniques, setShowSubTechniques] = useState(true);
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set());
  const [expandedTechniques, setExpandedTechniques] = useState<Set<string>>(new Set());

  useEffect(() => {
    fetch("/api/mitre/techniques").then(r => r.json()).then(setData);
  }, []);

  useEffect(() => {
    if (data?.enterpriseMatrix) {
      setExpandedTactics(new Set(data.enterpriseMatrix.map((t:any) => t.name)));
    }
  }, [data]);

  const toggleTactic = (tacticName: string) => {
    const newSet = new Set(expandedTactics);
    if (newSet.has(tacticName)) newSet.delete(tacticName);
    else newSet.add(tacticName);
    setExpandedTactics(newSet);
  };

  const toggleTechnique = (techId: string) => {
    const newSet = new Set(expandedTechniques);
    if (newSet.has(techId)) newSet.delete(techId);
    else newSet.add(techId);
    setExpandedTechniques(newSet);
  };

  const filteredTechniques = useMemo(() => {
    if (!data?.techniques) return [];
    let filtered = data.techniques;
    if (selectedTactic) filtered = filtered.filter((t: any) => t.tactic === selectedTactic);
    if (search) {
      const s = search.toLowerCase();
      filtered = filtered.filter((t: any) => 
        t.id.toLowerCase().includes(s) ||
        t.name.toLowerCase().includes(s) ||
        t.description.toLowerCase().includes(s) ||
        t.tactic.toLowerCase().includes(s)
      );
    }
    return filtered;
  }, [data, selectedTactic, search]);

  const matrixFiltered = useMemo(() => {
    if (!data?.enterpriseMatrix) return [];
    let matrix = data.enterpriseMatrix;
    if (selectedTactic) matrix = matrix.filter((t:any) => t.name === selectedTactic);
    if (search) {
      const s = search.toLowerCase();
      matrix = matrix.map((tactic:any) => ({
        ...tactic,
        techniques: tactic.techniques.filter((tech:any) => 
          tech.id.toLowerCase().includes(s) ||
          tech.name.toLowerCase().includes(s) ||
          tech.subTechniques?.some((sub:any) => sub.id.toLowerCase().includes(s) || sub.name.toLowerCase().includes(s))
        )
      })).filter((t:any) => t.techniques.length > 0);
    }
    return matrix;
  }, [data, selectedTactic, search]);

  if (!data) return <div className="p-6 space-y-4"><div className="h-20 glass rounded-2xl animate-pulse"></div><div className="h-96 glass rounded-2xl animate-pulse"></div></div>;

  const getTacticColor = (tacticName: string) => {
    const tactic = data.tactics.find((t:any) => t.name === tacticName);
    return tactic?.color || '#8b5cf6';
  };

  return (
    <div className="p-4 lg:p-6 max-w-[2000px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl lg:text-3xl font-bold text-white flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#8b5cf6] to-[#ff3344] flex items-center justify-center">
              <Target className="w-5 h-5 text-white" />
            </div>
            MITRE ATT&CK MAPPING
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-full bg-[#8b5cf6]/10 text-[#8b5cf6] border border-[#8b5cf6]/20">FULL FRAMEWORK v13</span>
          </h1>
          <p className="text-[#71717a] text-sm font-mono mt-2 max-w-4xl">Technique attribution • Tactic visualization • Defensive recommendations • Only mapped when evidence supports • Full Enterprise matrix with details</p>
          <div className="flex gap-2 mt-3 flex-wrap">
            <span className="px-2.5 py-1 rounded-full bg-[#181825] border border-white/5 text-[10px] font-mono text-[#a1a1aa] flex items-center gap-1.5"><Layers className="w-3 h-3 text-[#8b5cf6]" />{data.stats.totalTactics} Tactics</span>
            <span className="px-2.5 py-1 rounded-full bg-[#181825] border border-white/5 text-[10px] font-mono text-[#a1a1aa] flex items-center gap-1.5"><Grid className="w-3 h-3 text-[#ff3344]" />{data.stats.totalTechniques} Techniques</span>
            <span className="px-2.5 py-1 rounded-full bg-[#00ff88]/10 border border-[#00ff88]/20 text-[10px] font-mono text-[#00ff88] flex items-center gap-1.5"><CheckCircle className="w-3 h-3" />{data.stats.observedTechniques} Observed</span>
            <span className="px-2.5 py-1 rounded-full bg-[#ffcc00]/10 border border-[#ffcc00]/20 text-[10px] font-mono text-[#ffcc00] flex items-center gap-1.5"><BookOpen className="w-3 h-3" />{data.stats.totalScanned} Scanned</span>
          </div>
        </div>
        <div className="flex gap-2 items-start">
          <button onClick={() => setShowSubTechniques(!showSubTechniques)} className={`h-[44px] px-4 rounded-xl text-[13px] font-mono font-medium border flex items-center gap-2 transition-all ${showSubTechniques ? 'bg-[#8b5cf6]/10 border-[#8b5cf6]/20 text-[#8b5cf6]' : 'bg-[#181825] border-white/10 text-[#71717a]'}`}>
            <Layers className="w-4 h-4" />{showSubTechniques ? 'Hide' : 'Show'} Sub-techniques
          </button>
          <div className="flex gap-1 bg-[#181825] border border-white/10 rounded-xl p-1">
            <button onClick={() => setViewMode('matrix')} className={`h-[36px] px-4 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all ${viewMode === 'matrix' ? 'bg-white text-black' : 'text-[#71717a] hover:text-white'}`}><Grid className="w-4 h-4" />Matrix</button>
            <button onClick={() => setViewMode('list')} className={`h-[36px] px-4 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-all ${viewMode === 'list' ? 'bg-white text-black' : 'text-[#71717a] hover:text-white'}`}><List className="w-4 h-4" />List</button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Total Tactics</p><p className="text-2xl font-bold text-white mt-1">{data.stats.totalTactics}</p><p className="text-[10px] font-mono text-[#52525b] mt-1">Enterprise</p></div>
        <div className="glass rounded-2xl p-4 border border-[#8b5cf6]/20 bg-[#8b5cf6]/5"><p className="text-[10px] font-mono text-[#8b5cf6] uppercase">Total Techniques</p><p className="text-2xl font-bold text-white mt-1">{data.stats.totalTechniques}</p><p className="text-[10px] font-mono text-[#71717a] mt-1">{data.stats.totalScanned} scanned</p></div>
        <div className="glass rounded-2xl p-4 border border-[#00ff88]/20 bg-[#00ff88]/5"><p className="text-[10px] font-mono text-[#00ff88] uppercase">Observed</p><p className="text-2xl font-bold text-[#00ff88] mt-1">{data.stats.observedTechniques}</p><p className="text-[10px] font-mono text-[#71717a] mt-1">{data.stats.coverage} coverage</p></div>
        <div className="glass rounded-2xl p-4 border border-white/5"><p className="text-[10px] font-mono text-[#71717a] uppercase">Framework</p><p className="text-2xl font-bold text-white mt-1">v13</p><p className="text-[10px] font-mono text-[#52525b] mt-1">Enterprise</p></div>
      </div>

      {/* Search & Filters */}
      <div className="glass rounded-2xl border border-white/5 p-3 flex flex-wrap gap-2.5 items-center">
        <div className="relative flex-1 min-w-[280px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525b]" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search techniques: T1027, Obfuscated Files, Defense Evasion, PowerShell..." className="w-full h-[44px] pl-10 pr-4 bg-[#0a0a0f] border border-[#27272a] rounded-xl text-white text-[13px] outline-none focus:border-[#8b5cf6]/50 transition-colors" />
        </div>
        <div className="flex gap-2 flex-wrap">
          <button onClick={() => setSelectedTactic("")} className={`h-[44px] px-4 rounded-xl text-xs font-mono font-bold border transition-all ${!selectedTactic ? 'bg-white text-black border-white shadow-lg' : 'bg-[#181825] text-[#71717a] border-white/5 hover:border-white/10'}`}>All Tactics</button>
          {data.tactics.map((t: any) => (
            <button key={t.id} onClick={() => setSelectedTactic(t.name)} className={`h-[44px] px-3.5 rounded-xl text-xs font-mono border flex items-center gap-1.5 transition-all ${selectedTactic === t.name ? 'bg-white text-black border-white shadow-lg' : 'bg-[#181825] text-[#71717a] border-white/5 hover:border-white/10 hover:text-white'}`}>
              <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: t.color }}></div>{t.name}
              {data.stats.tacticStats[t.name] && <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] ${selectedTactic === t.name ? 'bg-black/10' : 'bg-[#27272a]'}`}>{data.stats.tacticStats[t.name].observed}/{data.stats.tacticStats[t.name].total}</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Matrix View */}
      {viewMode === 'matrix' ? (
        <div className="space-y-4">
          <div className="glass rounded-2xl border border-white/5 p-4">
            <h3 className="font-bold text-white text-sm mb-1 flex items-center gap-2"><Grid className="w-4 h-4 text-[#8b5cf6]" />FULL MITRE ATT&CK ENTERPRISE MATRIX • Horizontal Scroll • {matrixFiltered.length} Tactics • Click technique for details</h3>
            <p className="text-[11px] font-mono text-[#71717a]">All tactics with full technique counts • Hide/show sub-techniques • Layout side • Highlight detection • Real 0% for clean files</p>
          </div>

          <div className="overflow-x-auto pb-4">
            <div className="flex gap-3 min-w-max">
              {matrixFiltered.map((tactic: any) => {
                const isExpanded = expandedTactics.has(tactic.name);
                const tacticColor = getTacticColor(tactic.name);
                const observedInTactic = tactic.techniques.filter((tech:any) => {
                  const fullTech = data.techniques.find((t:any) => t.id === tech.id);
                  return fullTech?.observedCount > 0 || tech.subTechniques?.some((sub:any) => data.techniques.find((t:any) => t.id === tech.id)?.subTechniques?.find((s:any) => s.id === sub.id)?.observedCount > 0);
                }).length;

                return (
                  <div key={tactic.id} className="w-[280px] flex-shrink-0 glass rounded-2xl border border-white/5 overflow-hidden">
                    <button onClick={() => toggleTactic(tactic.name)} className="w-full p-3 flex items-center justify-between hover:bg-white/[0.02] transition-colors text-left border-b border-white/5" style={{ borderLeft: `3px solid ${tacticColor}` }}>
                      <div>
                        <p className="text-white font-bold text-xs font-mono uppercase flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ background: tacticColor }}></div>
                          {tactic.name}
                        </p>
                        <p className="text-[10px] font-mono text-[#71717a] mt-1">{tactic.count} techniques • {observedInTactic} observed • {tactic.id}</p>
                      </div>
                      <div className={`w-7 h-7 rounded-lg bg-[#181825] border border-white/5 flex items-center justify-center transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                        <ChevronDown className="w-3.5 h-3.5 text-[#71717a]" />
                      </div>
                    </button>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                          <div className="p-2 space-y-1.5 max-h-[600px] overflow-y-auto">
                            {tactic.techniques.map((tech: any) => {
                              const fullTech = data.techniques.find((t:any) => t.id === tech.id);
                              const isObserved = fullTech?.observedCount > 0;
                              const isTechExpanded = expandedTechniques.has(tech.id);

                              return (
                                <div key={tech.id} className={`rounded-xl border transition-all ${isObserved ? 'bg-[#ff3344]/5 border-[#ff3344]/20' : 'bg-[#181825] border-white/5 hover:border-white/10'}`}>
                                  <button onClick={() => setSelectedTech(fullTech || { id: tech.id, name: tech.name, tactic: tactic.name, tacticId: tactic.id, description: `${tech.name} technique for ${tactic.name}`, observedCount: fullTech?.observedCount || 0 })} className="w-full p-2.5 text-left group">
                                    <div className="flex justify-between items-start gap-2">
                                      <div className="flex-1 min-w-0">
                                        <p className="flex items-center gap-1.5">
                                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex-shrink-0 ${isObserved ? 'bg-[#ff3344]/20 text-[#ff3344] border-[#ff3344]/30' : 'bg-[#27272a] text-[#a1a1aa] border-white/5'}`}>{tech.id}</span>
                                          {isObserved && <span className="w-1.5 h-1.5 bg-[#ff3344] rounded-full animate-pulse flex-shrink-0"></span>}
                                        </p>
                                        <p className={`text-xs font-medium mt-1.5 truncate ${isObserved ? 'text-[#ff6b35]' : 'text-white group-hover:text-[#8b5cf6]'} transition-colors`}>{tech.name}</p>
                                        {isObserved && <p className="text-[10px] font-mono text-[#ff6b35] mt-1">{fullTech?.observedCount} observed</p>}
                                      </div>
                                      <Eye className="w-3 h-3 text-[#52525b] group-hover:text-[#8b5cf6] flex-shrink-0 mt-1" />
                                    </div>
                                  </button>

                                  {showSubTechniques && tech.subTechniques && tech.subTechniques.length > 0 && (
                                    <div className="px-2 pb-2">
                                      <button onClick={() => toggleTechnique(tech.id)} className="w-full flex items-center justify-between px-2 py-1 rounded-lg bg-[#0a0a0f] border border-white/5 hover:border-white/10 text-[10px] font-mono text-[#71717a] hover:text-white transition-colors">
                                        <span className="flex items-center gap-1"><ChevronRight className={`w-3 h-3 transition-transform ${isTechExpanded ? 'rotate-90' : ''}`} />{tech.subTechniques.length} sub-techniques</span>
                                        <span className="text-[9px]">{isTechExpanded ? 'Hide' : 'Show'}</span>
                                      </button>
                                      
                                      <AnimatePresence>
                                        {isTechExpanded && (
                                          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="mt-1.5 space-y-1 overflow-hidden">
                                            {tech.subTechniques.map((sub: any) => {
                                              const fullSub = fullTech?.subTechniques?.find((s:any) => s.id === sub.id);
                                              const isSubObserved = fullSub?.observedCount > 0;
                                              return (
                                                <button key={sub.id} onClick={() => setSelectedTech(fullSub || { id: sub.id, name: sub.name, tactic: tactic.name, parentId: tech.id, observedCount: 0 })} className={`w-full text-left px-2.5 py-1.5 rounded-lg border text-[11px] font-mono transition-all ${isSubObserved ? 'bg-[#ff3344]/10 border-[#ff3344]/20 text-[#ff6b35]' : 'bg-[#0a0a0f] border-white/5 text-[#a1a1aa] hover:border-white/10 hover:text-white'}`}>
                                                  <div className="flex justify-between items-center">
                                                    <span className="truncate">{sub.id} {sub.name}</span>
                                                    {isSubObserved && <span className="text-[9px] bg-[#ff3344]/20 text-[#ff3344] px-1.5 py-0.5 rounded-full ml-1 flex-shrink-0">{fullSub?.observedCount}</span>}
                                                  </div>
                                                </button>
                                              );
                                            })}
                                          </motion.div>
                                        )}
                                      </AnimatePresence>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        /* List View */
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredTechniques.map((tech: any) => (
            <motion.div key={tech.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className={`glass rounded-2xl border p-5 hover:border-[#8b5cf6]/20 transition-all group cursor-pointer ${tech.observedCount > 0 ? 'border-[#ff3344]/20 bg-[#ff3344]/[0.02]' : 'border-white/5'}`} onClick={() => setSelectedTech(tech)}>
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border ${tech.observedCount > 0 ? 'bg-[#ff3344]/20 text-[#ff3344] border-[#ff3344]/30' : 'bg-[#8b5cf6]/20 text-[#8b5cf6] border-[#8b5cf6]/30'}`}>{tech.id}</span>
                  <span className="px-2 py-1 rounded-full bg-[#181825] border border-white/5 text-[10px] font-mono text-[#71717a]">{tech.tactic}</span>
                  {tech.isSubTechnique && <span className="px-2 py-0.5 rounded-full bg-[#27272a] text-[9px] font-mono text-[#71717a]">Sub-technique</span>}
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[11px] font-mono px-2 py-1 rounded-full border ${tech.observedCount > 0 ? 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20' : 'bg-[#27272a] text-[#52525b] border-white/5'}`}>{tech.observedCount} observed</span>
                  <div className="w-7 h-7 rounded-lg bg-[#181825] border border-white/5 flex items-center justify-center group-hover:border-[#8b5cf6]/20"><ExternalLink className="w-3.5 h-3.5 text-[#71717a] group-hover:text-[#8b5cf6]" /></div>
                </div>
              </div>
              <h3 className="text-white font-bold text-sm mb-2 group-hover:text-[#8b5cf6] transition-colors flex items-center gap-2">
                {tech.name}
                {tech.observedCount > 0 && <span className="w-2 h-2 bg-[#ff3344] rounded-full animate-pulse"></span>}
              </h3>
              <p className="text-[#71717a] text-xs leading-relaxed mb-3 line-clamp-3">{tech.description}</p>
              <div className="space-y-2">
                <div className="p-2.5 rounded-xl bg-[#ff3344]/5 border border-[#ff3344]/10"><p className="text-[10px] font-mono text-[#ff3344] font-bold flex items-center gap-1"><Eye className="w-3 h-3" />DETECTION</p><p className="text-[11px] text-[#a1a1aa] mt-1 line-clamp-2">{tech.detection}</p></div>
                <div className="p-2.5 rounded-xl bg-[#00ff88]/5 border border-[#00ff88]/10"><p className="text-[10px] font-mono text-[#00ff88] font-bold flex items-center gap-1"><Shield className="w-3 h-3" />MITIGATION</p><p className="text-[11px] text-[#a1a1aa] mt-1 line-clamp-2">{tech.mitigation}</p></div>
              </div>
              {tech.subTechniques && tech.subTechniques.length > 0 && showSubTechniques && (
                <div className="mt-3 pt-3 border-t border-white/5">
                  <p className="text-[10px] font-mono text-[#71717a] uppercase mb-2">{tech.subTechniques.length} sub-techniques</p>
                  <div className="flex flex-wrap gap-1.5">
                    {tech.subTechniques.slice(0,4).map((sub:any) => (
                      <span key={sub.id} className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${sub.observedCount > 0 ? 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20' : 'bg-[#27272a] text-[#71717a] border-white/5'}`}>{sub.id} {sub.observedCount > 0 ? `(${sub.observedCount})` : ''}</span>
                    ))}
                    {tech.subTechniques.length > 4 && <span className="px-2 py-0.5 rounded-full bg-[#27272a] text-[10px] font-mono text-[#71717a]">+{tech.subTechniques.length-4}</span>}
                  </div>
                </div>
              )}
            </motion.div>
          ))}
          {filteredTechniques.length === 0 && (
            <div className="col-span-2 glass rounded-2xl border border-white/5 p-12 text-center">
              <Search className="w-12 h-12 text-[#27272a] mx-auto mb-3" />
              <p className="text-white font-medium">No techniques found for "{search}"</p>
              <p className="text-[#71717a] text-sm font-mono mt-1">Try searching T1027, Execution, PowerShell, etc.</p>
            </div>
          )}
        </div>
      )}

      {/* Technique Detail Modal with Whole Framework Details */}
      <AnimatePresence>
        {selectedTech && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/70 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto">
            <motion.div initial={{ scale: 0.95, y: 20 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.95, y: 20 }} className="w-full max-w-5xl glass-strong rounded-2xl border border-[#8b5cf6]/20 overflow-hidden my-8">
              <div className="p-5 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-[#181825] to-[#0a0a0f]">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="w-12 h-12 rounded-xl bg-[#8b5cf6]/20 border border-[#8b5cf6]/30 flex items-center justify-center flex-shrink-0">
                    <Target className="w-6 h-6 text-[#8b5cf6]" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold text-white text-lg flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-1 rounded-lg bg-[#8b5cf6]/20 text-[#8b5cf6] text-sm font-mono font-bold border border-[#8b5cf6]/30">{selectedTech.id}</span>
                      {selectedTech.name}
                      {selectedTech.observedCount > 0 && <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-xs font-mono border border-[#ff3344]/20">{selectedTech.observedCount} observed</span>}
                    </h3>
                    <p className="text-[11px] font-mono text-[#71717a] mt-1 flex items-center gap-2 flex-wrap">
                      <span className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full" style={{ background: getTacticColor(selectedTech.tactic) }}></div>{selectedTech.tactic} • {selectedTech.tacticId}</span>
                      {selectedTech.parentId && <span>• Parent: {selectedTech.parentId}</span>}
                      {selectedTech.isSubTechnique && <span className="px-2 py-0.5 rounded-full bg-[#27272a] text-[10px]">Sub-technique</span>}
                    </p>
                  </div>
                </div>
                <button onClick={() => setSelectedTech(null)} className="w-10 h-10 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center text-white hover:bg-white/10 flex-shrink-0 ml-3"><X className="w-5 h-5" /></button>
              </div>

              <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 max-h-[75vh] overflow-y-auto">
                <div className="lg:col-span-2 space-y-5">
                  <div>
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-2 flex items-center gap-2 font-bold"><BookOpen className="w-4 h-4 text-[#8b5cf6]" />Description - Whole Framework Details</p>
                    <p className="text-[#e4e4e7] text-sm leading-relaxed bg-[#0a0a0f] rounded-xl p-4 border border-white/5">{selectedTech.description}</p>
                  </div>

                  <div className="grid grid-cols-1 gap-3">
                    <div className="p-4 rounded-xl bg-[#ff3344]/5 border border-[#ff3344]/10">
                      <p className="text-[11px] font-mono text-[#ff3344] font-bold flex items-center gap-2"><Eye className="w-4 h-4" />DETECTION • How to detect {selectedTech.id}</p>
                      <p className="text-[13px] text-[#a1a1aa] mt-2 leading-relaxed">{selectedTech.detection}</p>
                      <div className="mt-3 flex gap-2 flex-wrap">
                        <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[11px] font-mono border border-[#ff3344]/20">Sysmon</span>
                        <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[11px] font-mono border border-[#ff3344]/20">PowerShell 4104</span>
                        <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[11px] font-mono border border-[#ff3344]/20">EDR Telemetry</span>
                        <span className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[11px] font-mono border border-[#ff3344]/20">Process 4688</span>
                      </div>
                    </div>

                    <div className="p-4 rounded-xl bg-[#00ff88]/5 border border-[#00ff88]/10">
                      <p className="text-[11px] font-mono text-[#00ff88] font-bold flex items-center gap-2"><Shield className="w-4 h-4" />MITIGATION • How to mitigate {selectedTech.id}</p>
                      <p className="text-[13px] text-[#a1a1aa] mt-2 leading-relaxed">{selectedTech.mitigation}</p>
                      <div className="mt-3 flex gap-2 flex-wrap">
                        <span className="px-2.5 py-1 rounded-full bg-[#00ff88]/10 text-[#00ff88] text-[11px] font-mono border border-[#00ff88]/20">M1038 Execution Prevention</span>
                        <span className="px-2.5 py-1 rounded-full bg-[#00ff88]/10 text-[#00ff88] text-[11px] font-mono border border-[#00ff88]/20">M1040 Behavior Prevention</span>
                        <span className="px-2.5 py-1 rounded-full bg-[#00ff88]/10 text-[#00ff88] text-[11px] font-mono border border-[#00ff88]/20">M1026 Privileged Account</span>
                      </div>
                    </div>
                  </div>

                  {selectedTech.subTechniques && selectedTech.subTechniques.length > 0 && (
                    <div>
                      <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3 font-bold flex items-center gap-2"><Layers className="w-4 h-4" />Sub-techniques of {selectedTech.id} ({selectedTech.subTechniques.length})</p>
                      <div className="grid grid-cols-1 gap-2">
                        {selectedTech.subTechniques.map((sub:any) => (
                          <div key={sub.id} className={`p-3 rounded-xl border flex justify-between items-center ${sub.observedCount > 0 ? 'bg-[#ff3344]/5 border-[#ff3344]/20' : 'bg-[#181825] border-white/5'}`}>
                            <div>
                              <p className="text-white font-mono text-xs font-bold">{sub.id} {sub.name}</p>
                              <p className="text-[11px] font-mono text-[#71717a] mt-1">{sub.description?.substring(0,80)}...</p>
                            </div>
                            <span className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-bold border ml-3 flex-shrink-0 ${sub.observedCount > 0 ? 'bg-[#ff3344]/10 text-[#ff3344] border-[#ff3344]/20' : 'bg-[#27272a] text-[#52525b] border-white/5'}`}>{sub.observedCount} observed</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="space-y-4">
                  <div className="bg-[#0a0a0f] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3 font-bold">Framework Info</p>
                    <div className="space-y-2.5 text-[11px] font-mono">
                      <div className="flex justify-between"><span className="text-[#52525b]">ID:</span><span className="text-[#8b5cf6] font-bold">{selectedTech.id}</span></div>
                      <div className="flex justify-between"><span className="text-[#52525b]">Tactic:</span><span className="text-white">{selectedTech.tactic}</span></div>
                      <div className="flex justify-between"><span className="text-[#52525b]">Tactic ID:</span><span className="text-white">{selectedTech.tacticId}</span></div>
                      <div className="flex justify-between"><span className="text-[#52525b]">Observed:</span><span className={selectedTech.observedCount > 0 ? 'text-[#ff3344] font-bold' : 'text-[#71717a]'}>{selectedTech.observedCount} times</span></div>
                      <div className="flex justify-between"><span className="text-[#52525b]">Platforms:</span><span className="text-white">{(selectedTech.platforms || ['Windows']).join(', ')}</span></div>
                      <div className="flex justify-between"><span className="text-[#52525b]">Type:</span><span className="text-white">{selectedTech.isSubTechnique ? 'Sub-technique' : 'Technique'}</span></div>
                    </div>
                  </div>

                  <div className="bg-[#181825] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3 font-bold flex items-center gap-2"><Activity className="w-3.5 h-3.5" />Data Sources</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(selectedTech.dataSources || ['Process', 'Command', 'File', 'Network Traffic']).map((ds:string) => (
                        <span key={ds} className="px-2.5 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[11px] font-mono border border-[#ff3344]/20">{ds}</span>
                      ))}
                    </div>
                  </div>

                  <div className="bg-[#181825] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-3 font-bold">Actions</p>
                    <div className="space-y-2.5">
                      <a href={selectedTech.url} target="_blank" className="w-full h-[44px] rounded-xl bg-white text-black font-bold text-sm flex items-center justify-center gap-2 hover:bg-[#e4e4e7] transition-colors">
                        <ExternalLink className="w-4 h-4" />View on MITRE.org
                      </a>
                      <button onClick={() => { setSearch(selectedTech.id); setSelectedTech(null); setViewMode('list'); }} className="w-full h-[44px] rounded-xl bg-[#8b5cf6]/10 border border-[#8b5cf6]/20 text-[#8b5cf6] font-bold text-sm flex items-center justify-center gap-2 hover:bg-[#8b5cf6]/20">
                        <Search className="w-4 h-4" />Search Related
                      </button>
                      <div className="bg-[#0a0a0f] rounded-xl p-3 border border-white/5">
                        <p className="text-[10px] font-mono text-[#71717a] uppercase">Defensive Guidance</p>
                        <p className="text-[11px] font-mono text-[#a1a1aa] mt-1 leading-relaxed">Use this technique info to create detection rules, hunt for {selectedTech.id} in your environment, and implement mitigations M1038, M1040, M1026.</p>
                      </div>
                    </div>
                  </div>

                  <div className="bg-[#0a0a0f] rounded-xl p-4 border border-white/5">
                    <p className="text-[11px] font-mono text-[#71717a] uppercase mb-2 flex items-center gap-2"><Info className="w-3 h-3" />About Framework</p>
                    <p className="text-[11px] font-mono text-[#71717a] leading-relaxed">MITRE ATT&CK v13 Enterprise • {data.stats.totalTactics} tactics • {data.stats.totalTechniques} techniques • Full framework with details helps you understand attacker behaviors and build defenses. Only mapped when evidence supports - no fake data.</p>
                  </div>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
