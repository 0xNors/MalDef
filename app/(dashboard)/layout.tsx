"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Sidebar from "@/components/layout/Sidebar";
import TopNav from "@/components/layout/TopNav";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const res = await fetch("/api/auth/me");
        if (!res.ok) {
          router.push("/login");
          return;
        }
        const data = await res.json();
        setUser(data.user);
      } catch {
        router.push("/login");
      } finally {
        setLoading(false);
      }
    };
    checkAuth();
  }, [router]);

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#08080a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: 40, height: 40, border: '2px solid rgba(255,255,255,0.08)', borderTopColor: 'white', borderRadius: '10px', animation: 'spin 0.8s linear infinite', margin: '0 auto 12px auto' }}></div>
          <p style={{ color: 'white', fontFamily: 'Space Grotesk', fontSize: 12, letterSpacing: '0.05em', fontWeight: 600 }}>MALDEF</p>
          <p style={{ color: '#52525b', fontFamily: 'JetBrains Mono', fontSize: 10, letterSpacing: '0.1em', marginTop: 4 }}>LOADING...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#08080a', display: 'block' }}>
      <Sidebar user={user} collapsed={collapsed} setCollapsed={setCollapsed} mobileOpen={mobileOpen} setMobileOpen={setMobileOpen} />
      <TopNav onMenuClick={() => setMobileOpen(true)} collapsed={collapsed} />
      <main
        style={{
          paddingTop: 64,
          paddingLeft: collapsed ? 72 : 260,
          transition: 'padding-left 0.2s ease',
          minHeight: '100vh',
          background: '#08080a',
          display: 'block',
        } as any}
        className="max-lg:!pl-0"
      >
        <div style={{ minHeight: 'calc(100vh - 64px)', width: '100%', display: 'block' }}>
          {children}
        </div>
      </main>
      <style>{`
        @media (max-width: 1024px) {
          main { padding-left: 0 !important; }
          header { left: 0 !important; }
        }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .scrollbar-thin::-webkit-scrollbar { width: 6px; height: 6px; }
        .scrollbar-thin::-webkit-scrollbar-track { background: #0a0a0c; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: #27272a; border-radius: 3px; }
        .glass { background: #121214; border: 1px solid rgba(255,255,255,0.06); }
        .glass-strong { background: #0f0f12; border: 1px solid rgba(255,255,255,0.08); }
        .glass-red { background: #121214; border: 1px solid rgba(255,255,255,0.06); }
        .maldef-text { font-family: 'Space Grotesk', sans-serif; }
      `}</style>
    </div>
  );
}
