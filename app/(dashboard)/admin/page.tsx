"use client";
import { useEffect, useState } from "react";
import { Users, Shield, Database, Activity, Settings, AlertTriangle, FileText } from "lucide-react";

export default function AdminPage() {
  const [activeTab, setActiveTab] = useState("users");
  const [users, setUsers] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  useEffect(() => {
    // Fetch users via dashboard? We'll fetch from a custom endpoint or use DB via API - for MVP use static + fetch dashboard
    fetch("/api/dashboard/stats").then(() => {
      // Since no users API, we'll mock from local - but we have DB, let's create quick inline fetch for admin data via custom
      // For now, fetch audit logs via a new endpoint we will create? Let's just fetch via /api/auth/me and assume admin can see all
      // Workaround: fetch users from a new admin API we need to create
    });
    fetchAdminData();
  }, []);

  const fetchAdminData = async () => {
    try {
      const res = await fetch("/api/admin/data");
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
        setRules(data.rules || []);
        setAuditLogs(data.auditLogs || []);
      }
    } catch {}
  };

  return (
    <div className="p-4 lg:p-6 max-w-[1600px] mx-auto space-y-6">
      <div>
        <h1 className="font-display text-2xl font-bold text-white flex items-center gap-3"><Shield className="w-6 h-6 text-[#ff006a]" /> ADMIN PANEL</h1>
        <p className="text-[#71717a] text-sm font-mono mt-1">User management • Detection rules • Audit logs • System configuration • RBAC</p>
      </div>

      <div className="flex gap-2">
        {[
          { id: "users", label: "Users", icon: Users },
          { id: "rules", label: "Detection Rules", icon: Activity },
          { id: "audit", label: "Audit Logs", icon: FileText },
          { id: "system", label: "System", icon: Settings },
        ].map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium ${activeTab === tab.id ? 'bg-white text-black' : 'bg-[#181825] border border-white/5 text-[#71717a] hover:text-white'}`}><tab.icon className="w-4 h-4" />{tab.label}</button>
        ))}
      </div>

      {activeTab === "users" && (
        <div className="glass rounded-2xl border border-white/5 overflow-hidden">
          <div className="p-5 border-b border-white/5"><h3 className="font-bold text-white text-sm">USER MANAGEMENT (RBAC)</h3></div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-[10px] font-mono text-[#52525b] border-b border-white/5"><th className="text-left p-3">USER</th><th className="text-left p-3">EMAIL</th><th className="text-left p-3">ROLE</th><th className="text-left p-3">CREATED</th><th className="text-left p-3">STATUS</th></tr></thead>
              <tbody>
                {users.map((u: any) => (
                  <tr key={u.id} className="border-b border-white/[0.03]"><td className="p-3 text-white">{u.name}</td><td className="p-3 font-mono text-[#71717a] text-xs">{u.email}</td><td className="p-3"><span className="px-2 py-1 rounded-full bg-[#ff3344]/10 text-[#ff3344] text-[10px] font-mono border border-[#ff3344]/20">{u.role}</span></td><td className="p-3 text-[#71717a] text-xs font-mono">{new Date(u.createdAt).toLocaleDateString()}</td><td className="p-3"><span className="w-2 h-2 bg-[#00ff88] rounded-full inline-block"></span><span className="text-[#00ff88] text-[11px] font-mono ml-1">ACTIVE</span></td></tr>
                ))}
                {users.length === 0 && <tr><td colSpan={5} className="p-8 text-center text-[#52525b] font-mono text-xs">Loading users... If not loading, ensure ADMIN role and check /api/admin/data</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "rules" && (
        <div className="glass rounded-2xl border border-white/5 overflow-hidden">
          <div className="p-5 border-b border-white/5"><h3 className="font-bold text-white text-sm">DETECTION RULES ENGINE</h3><p className="text-[11px] font-mono text-[#52525b] mt-1">Modular rule engine • Stored separately from logic • MITRE mapping • Enable/disable</p></div>
          <div className="p-4 space-y-2">
            {rules.map((r: any) => (
              <div key={r.id} className="p-4 rounded-xl bg-[#0a0a0f] border border-white/5 flex justify-between items-start">
                <div><p className="text-white text-sm font-medium flex items-center gap-2"><span className="px-2 py-0.5 rounded bg-[#27272a] text-[10px] font-mono">{r.id}</span>{r.name}<span className={`px-2 py-0.5 rounded-full text-[10px] font-mono border severity-${r.severity.toLowerCase()}`}>{r.severity}</span></p><p className="text-xs text-[#71717a] mt-1">{r.description}</p><p className="text-[11px] font-mono text-[#52525b] mt-1">Condition: {r.condition} • Score: {r.score} • Category: {r.category} • MITRE: {r.mitreTechnique || 'N/A'}</p></div>
                <span className={`px-2 py-1 rounded-full text-[10px] font-mono ${r.enabled ? 'bg-[#00ff88]/10 text-[#00ff88] border border-[#00ff88]/20' : 'bg-[#27272a] text-[#71717a]'}`}>{r.enabled ? 'ENABLED' : 'DISABLED'}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "audit" && (
        <div className="glass rounded-2xl border border-white/5 overflow-hidden">
          <div className="p-5 border-b border-white/5"><h3 className="font-bold text-white text-sm">AUDIT LOGS • SECURITY HARDENING</h3></div>
          <div className="max-h-[500px] overflow-y-auto">
            {auditLogs.slice(0, 100).map((log: any) => (
              <div key={log.id} className="p-3 border-b border-white/[0.03] flex gap-3 text-xs"><span className="font-mono text-[#52525b]">{new Date(log.timestamp).toLocaleString()}</span><span className="px-1.5 py-0.5 rounded bg-[#27272a] text-[#a1a1aa] text-[10px] font-mono">{log.action}</span><span className="text-[#71717a]">{log.details}</span><span className="ml-auto font-mono text-[#52525b] text-[10px]">{log.userId.substring(0, 8)}</span></div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "system" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="glass rounded-2xl border border-white/5 p-5"><h3 className="font-bold text-white text-sm mb-3">SECURITY HARDENING STATUS</h3><div className="space-y-2 text-xs">{[
            { label: "JWT Authentication", status: "ENABLED", color: "#00ff88" },
            { label: "Password Hashing (bcrypt 12)", status: "ENABLED", color: "#00ff88" },
            { label: "RBAC (ADMIN/ANALYST/MANAGER)", status: "ENABLED", color: "#00ff88" },
            { label: "Rate Limiting", status: "ENABLED", color: "#00ff88" },
            { label: "File Validation & Safe Names", status: "ENABLED", color: "#00ff88" },
            { label: "No Execution Policy", status: "ENFORCED", color: "#ff3344" },
            { label: "Security Headers", status: "ENABLED", color: "#00ff88" },
            { label: "Audit Logging", status: "ENABLED", color: "#00ff88" },
          ].map(s => <div key={s.label} className="flex justify-between p-2.5 rounded-xl bg-[#0a0a0f] border border-white/5"><span className="text-[#a1a1aa]">{s.label}</span><span className="font-mono font-bold" style={{ color: s.color }}>{s.status}</span></div>)}</div></div>
          <div className="glass rounded-2xl border border-white/5 p-5"><h3 className="font-bold text-white text-sm mb-3">SYSTEM CONFIGURATION</h3><div className="space-y-3 text-xs font-mono"><div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#52525b]">DATABASE</p><p className="text-white mt-1">PostgreSQL (mck_guard) with SQLite fallback • JSON file persistence for demo</p></div><div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#52525b]">STORAGE</p><p className="text-white mt-1">data/samples/ • Safe random filenames • 20MB limit</p></div><div className="p-3 rounded-xl bg-[#0a0a0f] border border-white/5"><p className="text-[#52525b]">DEFENSIVE ONLY</p><p className="text-[#00ff88] mt-1">No malware generation • No execution • No C2 • Static analysis only • Synthetic telemetry</p></div></div></div>
        </div>
      )}
    </div>
  );
}
