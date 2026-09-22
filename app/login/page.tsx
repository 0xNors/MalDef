"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Lock, Mail, Eye, EyeOff, AlertTriangle, Fingerprint, Building2, Users, Crown, UserCheck, Check } from "lucide-react";

const ROLES = [
  { value: "ANALYST", label: "SOC Analyst", desc: "Upload, analyze, investigate", icon: UserCheck },
  { value: "MANAGER", label: "Security Manager", desc: "Dashboard, reports, trends", icon: Users },
  { value: "ADMIN", label: "Administrator", desc: "Full system access", icon: Crown },
];

export default function LoginPage() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [formData, setFormData] = useState({ name: "", email: "", password: "", confirmPassword: "", organization: "", role: "ANALYST" });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      if (!isLogin) {
        if (formData.password !== formData.confirmPassword) throw new Error("Passwords do not match");
        const res = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: formData.name, email: formData.email, password: formData.password, organization: formData.organization, role: formData.role }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Registration failed");
        setIsLogin(true);
        alert(`Account created as ${data.user.role}! Please login.`);
        setFormData({ name: "", email: "", password: "", confirmPassword: "", organization: "", role: data.user.role });
      } else {
        const res = await fetch("/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: formData.email, password: formData.password, role: formData.role }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Login failed");
        router.push("/dashboard");
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", width: "100%", background: "#08080a", color: "white", position: "relative", fontFamily: "Inter, sans-serif" }}>
      <div className="login-outer" style={{ position: "relative", zIndex: 10, minHeight: "100vh", display: "flex", flexDirection: "column" }}>
        {/* LEFT */}
        <div className="left-panel" style={{ width: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between", padding: 24, borderBottom: "1px solid rgba(255,255,255,0.06)", background: "#0a0a0c", boxSizing: "border-box" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: "#121214", border: '1px solid rgba(255,255,255,0.08)', display: "flex", alignItems: "center", justifyContent: "center", overflow: 'hidden' }}>
              <img src="/logo.png" alt="MALDEF" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, letterSpacing: "-0.02em", lineHeight: 1 }}>MALDEF</div>
              <div style={{ fontSize: 9, fontFamily: "monospace", letterSpacing: "0.12em", color: "#71717a", marginTop: 2 }}>ENTERPRISE SECURITY</div>
            </div>
          </div>

          <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center", maxWidth: 520, width: "100%", margin: "0 auto", padding: "32px 0", boxSizing: "border-box" }}>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 10px", borderRadius: 9999, background: "#121214", border: "1px solid rgba(255,255,255,0.06)", color: "#8a8a90", fontSize: 10, fontFamily: "monospace", letterSpacing: "0.05em", width: "fit-content" }}>
              <span style={{ width: 6, height: 6, background: "#22c55e", borderRadius: "50%", display: "inline-block" }} />
              ROLE SELECTION • RBAC • PRODUCTION
            </div>

            <h1 style={{ marginTop: 20, fontSize: 36, fontWeight: 700, lineHeight: 1.1, letterSpacing: "-0.02em", margin: "20px 0 0 0", fontFamily: "Space Grotesk" }}>
              <span style={{ display: "block", color: "white" }}>CHOOSE YOUR</span>
              <span style={{ display: "block", color: "white" }}>ROLE & ACCESS</span>
              <span style={{ display: "block", color: "#71717a" }}>SECURELY</span>
            </h1>

            <p style={{ marginTop: 12, fontSize: 13, lineHeight: 1.5, color: "#8a8a90", maxWidth: 440 }}>
              Select your role during registration and login. ADMIN, ANALYST, or MANAGER – each with specific permissions.
            </p>

            <div style={{ marginTop: 28, display: "flex", flexDirection: "column", gap: 8, width: "100%" }}>
              {ROLES.map((role) => {
                const isSelected = formData.role === role.value;
                return (
                  <button
                    key={role.value}
                    type="button"
                    onClick={() => setFormData({ ...formData, role: role.value })}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      borderRadius: 10,
                      padding: 12,
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      border: `1px solid ${isSelected ? "rgba(255,255,255,0.15)" : "rgba(255,255,255,0.06)"}`,
                      background: isSelected ? "#151518" : "#121214",
                      cursor: "pointer",
                      boxSizing: "border-box"
                    }}
                  >
                    <div style={{
                      width: 36, height: 36, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center",
                      flexShrink: 0,
                      background: isSelected ? "#1e1e22" : "#121214",
                      border: "1px solid rgba(255,255,255,0.06)",
                      color: isSelected ? "white" : "#71717a"
                    }}>
                      <role.icon style={{ width: 16, height: 16 }} />
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <span style={{ fontSize: 13, fontWeight: 600, color: "white" }}>{role.label}</span>
                        <span style={{ fontSize: 9, fontFamily: "monospace", padding: "2px 6px", borderRadius: 4, background: "#1e1e22", color: "#8a8a90", border: "1px solid rgba(255,255,255,0.06)" }}>{role.value}</span>
                        {isSelected && <span style={{ fontSize: 9, fontFamily: "monospace", padding: "2px 6px", borderRadius: 4, background: "white", color: "black", fontWeight: 700 }}>SELECTED</span>}
                      </div>
                      <p style={{ fontSize: 11, color: "#71717a", margin: "2px 0 0 0" }}>{role.desc}</p>
                    </div>
                    <div style={{ width: 20, height: 20, borderRadius: "50%", border: `1.5px solid ${isSelected ? "white" : "#27272a"}`, background: isSelected ? "white" : "transparent", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      {isSelected && <Check style={{ width: 12, height: 12, color: "black" }} />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* RIGHT */}
        <div className="right-panel" style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "center", padding: 24, background: "#08080a", boxSizing: "border-box" }}>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} style={{ width: "100%", maxWidth: 360 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
              <div style={{ width: 56, height: 56, borderRadius: 12, background: "#121214", border: "1px solid rgba(255,255,255,0.06)", display: "flex", alignItems: "center", justifyContent: "center", overflow: 'hidden' }}>
                <img src="/logo.png" alt="MALDEF" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
              </div>
              <h2 style={{ marginTop: 16, fontSize: 16, fontWeight: 700, letterSpacing: "-0.01em", margin: "16px 0 0 0", fontFamily: "Space Grotesk" }}>{isLogin ? "SECURE ACCESS" : "CREATE ACCOUNT"}</h2>
              <p style={{ marginTop: 4, fontSize: 12, color: "#71717a", margin: "4px 0 0 0" }}>{isLogin ? "Select role and authenticate" : "Choose your role"}</p>
            </div>

            <div style={{ marginTop: 24, position: "relative", background: "#121214", borderRadius: 9999, padding: 3, border: "1px solid rgba(255,255,255,0.06)", display: "flex" }}>
              <motion.div layout style={{ position: "absolute", top: 3, bottom: 3, width: "calc(50% - 3px)", background: "white", borderRadius: 9999 }} animate={{ x: isLogin ? 3 : "calc(100% + 3px)" }} transition={{ type: "spring", stiffness: 400, damping: 30 }} />
              <button onClick={() => { setIsLogin(true); setError(""); }} style={{ position: "relative", zIndex: 10, flex: 1, padding: "9px 0", borderRadius: 9999, fontSize: 12, fontWeight: 600, border: "none", cursor: "pointer", background: "transparent", color: isLogin ? "black" : "#71717a" }}>LOGIN</button>
              <button onClick={() => { setIsLogin(false); setError(""); }} style={{ position: "relative", zIndex: 10, flex: 1, padding: "9px 0", borderRadius: 9999, fontSize: 12, fontWeight: 600, border: "none", cursor: "pointer", background: "transparent", color: !isLogin ? "black" : "#71717a" }}>REGISTER</button>
            </div>

            <form onSubmit={handleSubmit} style={{ marginTop: 20, display: "flex", flexDirection: "column", gap: 12 }}>
              <AnimatePresence mode="wait">
                {!isLogin && (
                  <motion.div key="name" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} style={{ overflow: "hidden" }}>
                    <div style={{ position: "relative" }}>
                      <Fingerprint style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", width: 14, height: 14, color: "#52525b" }} />
                      <input type="text" placeholder="Full Name" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} style={{ width: "100%", padding: "12px 12px 12px 36px", background: "#121214", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, color: "white", outline: "none", fontSize: 13, boxSizing: "border-box" }} required={!isLogin} />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <label style={{ fontSize: 10, fontFamily: "monospace", letterSpacing: "0.08em", color: "#52525b", textTransform: "uppercase" }}>Select Role • {isLogin ? "Login As" : "Register As"}</label>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
                  {ROLES.map((role) => {
                    const selected = formData.role === role.value;
                    return (
                      <button key={role.value} type="button" onClick={() => setFormData({ ...formData, role: role.value })} style={{
                        padding: 10,
                        borderRadius: 8,
                        border: `1px solid ${selected ? "white" : "rgba(255,255,255,0.06)"}`,
                        textAlign: "center",
                        background: selected ? "white" : "#121214",
                        color: selected ? "black" : "#71717a",
                        cursor: "pointer",
                        boxSizing: "border-box"
                      }}>
                        <role.icon style={{ width: 16, height: 16, margin: "0 auto", display: "block" }} />
                        <p style={{ marginTop: 4, fontSize: 10, fontWeight: 700, fontFamily: "monospace", margin: "4px 0 0 0" }}>{role.value}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div style={{ position: "relative" }}>
                <Mail style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", width: 14, height: 14, color: "#52525b" }} />
                <input type="email" placeholder="work@company.com" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} style={{ width: "100%", padding: "12px 12px 12px 36px", background: "#121214", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, color: "white", outline: "none", fontSize: 13, boxSizing: "border-box" }} required />
              </div>

              <div style={{ position: "relative" }}>
                <Lock style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", width: 14, height: 14, color: "#52525b" }} />
                <input type={showPassword ? "text" : "password"} placeholder="••••••••" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} style={{ width: "100%", padding: "12px 36px 12px 36px", background: "#121214", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, color: "white", outline: "none", fontSize: 13, boxSizing: "border-box" }} required />
                <button type="button" onClick={() => setShowPassword(!showPassword)} style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "transparent", border: "none", color: "#71717a", cursor: "pointer" }}>{showPassword ? <EyeOff style={{ width: 14, height: 14 }} /> : <Eye style={{ width: 14, height: 14 }} />}</button>
              </div>

              <AnimatePresence>
                {!isLogin && (
                  <motion.div key="extra" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} style={{ display: "flex", flexDirection: "column", gap: 12, overflow: "hidden" }}>
                    <div style={{ position: "relative" }}>
                      <Lock style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", width: 14, height: 14, color: "#52525b" }} />
                      <input type={showPassword ? "text" : "password"} placeholder="Confirm Password" value={formData.confirmPassword} onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })} style={{ width: "100%", padding: "12px 12px 12px 36px", background: "#121214", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, color: "white", outline: "none", fontSize: 13, boxSizing: "border-box" }} required={!isLogin} />
                    </div>
                    <div style={{ position: "relative" }}>
                      <Building2 style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", width: 14, height: 14, color: "#52525b" }} />
                      <input type="text" placeholder="Organization (Optional)" value={formData.organization} onChange={(e) => setFormData({ ...formData, organization: e.target.value })} style={{ width: "100%", padding: "12px 12px 12px 36px", background: "#121214", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, color: "white", outline: "none", fontSize: 13, boxSizing: "border-box" }} />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {error && (
                <div style={{ borderRadius: 8, padding: 10, border: "1px solid rgba(239,68,68,0.20)", background: "rgba(239,68,68,0.08)", display: "flex", gap: 8 }}>
                  <AlertTriangle style={{ width: 14, height: 14, color: "#ef4444", marginTop: 2, flexShrink: 0 }} />
                  <p style={{ fontSize: 11, color: "#fca5a5", lineHeight: 1.4, margin: 0 }}>{error}</p>
                </div>
              )}

              <button type="submit" disabled={loading} className="btn-44" style={{ width: "100%", background: "white", color: "black", fontWeight: 600, borderRadius: 8, border: "none", cursor: "pointer", opacity: loading ? 0.6 : 1 }}>
                {loading ? "PROCESSING..." : `${isLogin ? `LOGIN AS ${formData.role}` : `REGISTER AS ${formData.role}`}`}
              </button>
            </form>
          </motion.div>
        </div>
      </div>

      <style>{`
        @media (min-width: 1024px) {
          .login-outer { flex-direction: row !important; }
          .left-panel { width: 52% !important; border-bottom: none !important; border-right: 1px solid rgba(255,255,255,0.06) !important; padding: 32px !important; }
          .right-panel { width: 48% !important; padding: 32px !important; }
        }
        @media (max-width: 640px) {
          .left-panel, .right-panel { padding: 20px !important; }
        }
      `}</style>
    </div>
  );
}
