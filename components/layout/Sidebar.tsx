"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, LayoutDashboard, FileSearch, AlertTriangle, Search, Network, Brain, FileText, Users,
  LogOut, ChevronLeft, ChevronRight, Activity, Zap, Target, Database, Command, X, Workflow,
  HardDrive, Radio, SearchCheck, Bug, Fingerprint, Crosshair, Radar, FileWarning, ScanSearch,
  ShieldAlert, Eye, Lock, BarChart3, Settings, Skull, Flame, Bomb, Siren, ShieldCheck, Globe
} from "lucide-react";

interface SidebarProps {
  user: any;
  collapsed: boolean;
  setCollapsed: (v: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (v: boolean) => void;
}

// CLEAN NAV - NO DUPLICATES, solid colors, minimal
const navItems = [
  { icon: LayoutDashboard, label: "Dashboard", href: "/dashboard", badge: null },
  { icon: Radar, label: "Threat Intelligence", href: "/iocs", badge: "LIVE" },
  { icon: ShieldAlert, label: "Malware Analysis", href: "/samples", badge: "HOT" },
  { icon: Activity, label: "Behavior Analysis", href: "/investigation", badge: null },
  { icon: HardDrive, label: "System Health", href: "/system", badge: null },
  { icon: Fingerprint, label: "MALDEF Fingerprint", href: "/ml", badge: "AI" },
  { icon: FileText, label: "Reports", href: "/reports", badge: "PRO" },
  { icon: Target, label: "Threat Hunting", href: "/mitre", badge: null },
];

const adminItems = [
  { icon: Users, label: "Admin Panel", href: "/admin", badge: "ADMIN" },
];

export default function Sidebar({ user, collapsed, setCollapsed, mobileOpen, setMobileOpen }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [commandOpen, setCommandOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandOpen(!commandOpen);
      }
      if (e.key === 'Escape') setCommandOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [commandOpen]);

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/login");
  };

  const isAdmin = user?.role === 'ADMIN';

  return (
    <>
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.7)',
              zIndex: 40,
            } as any}
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      <aside
        style={{
          position: 'fixed',
          left: 0,
          top: 0,
          height: '100vh',
          width: collapsed ? 72 : 260,
          zIndex: 50,
          display: 'flex',
          flexDirection: 'column',
          background: '#0a0a0c',
          borderRight: '1px solid rgba(255,255,255,0.06)',
          transition: 'width 0.2s ease, transform 0.2s ease',
          overflow: 'hidden',
        } as any}
        className={`${mobileOpen ? '' : '-translate-x-full lg:translate-x-0'} lg:!translate-x-0`}
      >
        {/* Header - 64px solid */}
        <div
          style={{
            height: 64,
            minHeight: 64,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 14px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: 1 }}>
            <div
              style={{
                width: 36,
                height: 36,
                minWidth: 36,
                borderRadius: 10,
                background: '#121214',
                border: '1px solid rgba(255,255,255,0.08)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                overflow: 'hidden',
              }}
            >
              <img src="/logo.png" alt="MALDEF" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            </div>
            {!collapsed && (
              <div style={{ minWidth: 0, flex: 1 }}>
                <h1 style={{ fontWeight: 700, color: 'white', fontSize: 14, letterSpacing: '-0.02em', lineHeight: '1.1', margin: 0, fontFamily: 'Space Grotesk' }}>MALDEF</h1>
                <p style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: '#71717a', letterSpacing: '0.08em', margin: '2px 0 0 0', fontWeight: 500 }}>v2.1 DEFENSE</p>
              </div>
            )}
          </div>

          <button
            onClick={() => setCollapsed(!collapsed)}
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.06)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#71717a',
              cursor: 'pointer',
            } as any}
            className="hidden lg:flex hover:!bg-white/[0.06] hover:!text-white transition-colors"
          >
            {collapsed ? <ChevronRight style={{ width: 14, height: 14 }} /> : <ChevronLeft style={{ width: 14, height: 14 }} />}
          </button>
          <button
            onClick={() => setMobileOpen(false)}
            style={{
              width: 28,
              height: 28,
              borderRadius: 8,
              background: 'rgba(255,255,255,0.04)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'white',
              cursor: 'pointer',
            } as any}
            className="lg:!hidden"
          >
            <X style={{ width: 14, height: 14 }} />
          </button>
        </div>

        {/* User - minimal solid */}
        {!collapsed && (
          <div style={{ padding: 12, flexShrink: 0, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
            <div
              style={{
                background: '#121214',
                borderRadius: 10,
                padding: 10,
                border: '1px solid rgba(255,255,255,0.06)',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <div
                style={{
                  width: 32,
                  height: 32,
                  minWidth: 32,
                  borderRadius: 8,
                  background: '#1e1e22',
                  border: '1px solid rgba(255,255,255,0.06)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 12,
                  fontWeight: 700,
                  color: 'white',
                  flexShrink: 0,
                }}
              >
                {user?.name?.charAt(0) || 'A'}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ color: 'white', fontSize: 12, fontWeight: 600, margin: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user?.name || user?.email?.split('@')[0] || 'Admin'}</p>
                <p style={{ fontSize: 10, color: '#71717a', margin: '2px 0 0 0', fontFamily: 'JetBrains Mono' }}>{user?.role || 'ADMIN'} • ONLINE</p>
              </div>
            </div>
          </div>
        )}

        {/* Navigation - clean, no duplicates */}
        <div
          style={{
            flex: 1,
            overflowY: 'auto',
            overflowX: 'hidden',
            padding: '12px 10px',
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          } as any}
          className="scrollbar-thin"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {!collapsed && <p style={{ fontSize: 10, fontFamily: 'JetBrains Mono', letterSpacing: '0.12em', color: '#52525b', margin: '0 0 8px 8px', fontWeight: 600 }}>NAVIGATION</p>}
            {navItems.map((item) => {
              const isActive =
                (item.href === '/dashboard' && pathname === '/dashboard') ||
                (item.href === '/iocs' && pathname === '/iocs') ||
                (item.href === '/samples' && (pathname === '/samples' || pathname.startsWith('/analysis') || pathname.startsWith('/samples'))) ||
                (item.href === '/investigation' && pathname.startsWith('/investigation')) ||
                (item.href === '/system' && pathname === '/system') ||
                (item.href === '/ml' && pathname === '/ml') ||
                (item.href === '/reports' && pathname === '/reports') ||
                (item.href === '/mitre' && pathname === '/mitre');

              return (
                <Link
                  key={item.label}
                  href={item.href}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '10px 10px',
                    borderRadius: 8,
                    fontSize: 13,
                    fontWeight: isActive ? 600 : 450,
                    textDecoration: 'none',
                    background: isActive ? '#1a1a1e' : 'transparent',
                    color: isActive ? 'white' : '#8a8a90',
                    border: isActive ? '1px solid rgba(255,255,255,0.06)' : '1px solid transparent',
                    justifyContent: collapsed ? 'center' : 'flex-start',
                    minHeight: 38,
                    whiteSpace: 'nowrap',
                    transition: 'all 0.15s ease',
                  } as any}
                  className="hover:!bg-[#151518] hover:!text-white"
                >
                  <item.icon
                    style={{
                      width: 16,
                      height: 16,
                      minWidth: 16,
                      flexShrink: 0,
                      color: isActive ? 'white' : '#5a5a60',
                    } as any}
                  />
                  {!collapsed && (
                    <>
                      <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.label}</span>
                      {item.badge && (
                        <span
                          style={{
                            fontSize: 9,
                            fontFamily: 'JetBrains Mono',
                            padding: '2px 6px',
                            borderRadius: 5,
                            fontWeight: 700,
                            background: item.badge === 'LIVE' ? '#ef4444' : item.badge === 'HOT' ? '#ef4444' : item.badge === 'AI' ? '#1e1e22' : '#1e1e22',
                            color: item.badge === 'LIVE' || item.badge === 'HOT' ? 'white' : '#8a8a90',
                            border: item.badge === 'AI' || item.badge === 'PRO' ? '1px solid rgba(255,255,255,0.08)' : 'none',
                          }}
                        >
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </Link>
              );
            })}
          </div>

          {isAdmin && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {!collapsed && <p style={{ fontSize: 10, fontFamily: 'JetBrains Mono', letterSpacing: '0.12em', color: '#52525b', margin: '0 0 8px 8px', fontWeight: 600 }}>ADMIN</p>}
              {adminItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.label}
                    href={item.href}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '10px 10px',
                      borderRadius: 8,
                      fontSize: 13,
                      fontWeight: isActive ? 600 : 450,
                      textDecoration: 'none',
                      background: isActive ? '#1a1a1e' : 'transparent',
                      color: isActive ? 'white' : '#8a8a90',
                      border: isActive ? '1px solid rgba(255,255,255,0.06)' : '1px solid transparent',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      minHeight: 38,
                      whiteSpace: 'nowrap',
                    } as any}
                    className="hover:!bg-[#151518] hover:!text-white"
                  >
                    <item.icon style={{ width: 16, height: 16, minWidth: 16, flexShrink: 0, color: isActive ? 'white' : '#5a5a60' } as any} />
                    {!collapsed && <span style={{ flex: 1 }}>{item.label}</span>}
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer - minimal */}
        <div style={{ padding: 10, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0 }}>
          {!collapsed && (
            <div
              style={{
                background: '#121214',
                borderRadius: 8,
                padding: 10,
                border: '1px solid rgba(255,255,255,0.06)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <Flame style={{ width: 14, height: 14, color: '#ef4444', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 10, fontWeight: 600, color: '#a1a1aa', margin: 0, fontFamily: 'JetBrains Mono', letterSpacing: '0.05em' }}>THREAT LEVEL</p>
                <p style={{ fontSize: 10, color: '#52525b', margin: '2px 0 0 0', fontFamily: 'JetBrains Mono' }}>CRITICAL • 247 stopped</p>
              </div>
              <div style={{ display: 'flex', gap: 2 }}>
                <div style={{ width: 3, height: 12, background: '#ef4444', borderRadius: 2 }}></div>
                <div style={{ width: 3, height: 12, background: '#ef4444', borderRadius: 2, opacity: 0.8 }}></div>
                <div style={{ width: 3, height: 12, background: '#27272a', borderRadius: 2 }}></div>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 6 }}>
            <button
              onClick={() => setCommandOpen(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                padding: '10px',
                borderRadius: 8,
                background: '#121214',
                border: '1px solid rgba(255,255,255,0.06)',
                color: '#71717a',
                fontSize: 11,
                fontFamily: 'JetBrains Mono',
                cursor: 'pointer',
                flex: collapsed ? undefined : 1,
                width: collapsed ? '100%' : undefined,
                minHeight: 36,
              } as any}
              className="hover:!bg-[#1a1a1e] hover:!text-white transition-colors"
            >
              <Command style={{ width: 14, height: 14 }} />
              {!collapsed && <span>⌘K</span>}
            </button>

            <button
              onClick={handleLogout}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                padding: '10px',
                borderRadius: 8,
                background: '#121214',
                border: '1px solid rgba(255,255,255,0.06)',
                color: '#8a8a90',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                flex: collapsed ? undefined : 1,
                width: collapsed ? '100%' : undefined,
                minHeight: 36,
                whiteSpace: 'nowrap',
              } as any}
              className="hover:!bg-[#1a1a1e] hover:!text-white transition-colors"
            >
              <LogOut style={{ width: 14, height: 14 }} />
              {!collapsed && <span>LOGOUT</span>}
            </button>
          </div>
        </div>
      </aside>

      {/* Command palette - solid, minimal */}
      <AnimatePresence>
        {commandOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.75)',
              backdropFilter: 'blur(12px)',
              zIndex: 100,
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'center',
              paddingTop: '20vh',
              padding: '20vh 16px 16px 16px',
            } as any}
            onClick={() => setCommandOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              onClick={e => e.stopPropagation()}
              style={{
                width: '100%',
                maxWidth: 520,
                background: '#0f0f10',
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.08)',
                boxShadow: '0 20px 60px rgba(0,0,0,0.8)',
                overflow: 'hidden',
              } as any}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 14, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <Search style={{ width: 18, height: 18, color: '#71717a', flexShrink: 0 }} />
                <input
                  autoFocus
                  placeholder="Search MALDEF — hash, file, IOC..."
                  style={{
                    flex: 1,
                    background: 'transparent',
                    color: 'white',
                    outline: 'none',
                    border: 'none',
                    fontSize: 13,
                  } as any}
                />
                <kbd style={{ padding: '4px 8px', borderRadius: 6, background: '#1a1a1e', border: '1px solid rgba(255,255,255,0.06)', fontSize: 10, color: '#71717a' }}>ESC</kbd>
              </div>
              <div style={{ padding: 8, maxHeight: 300, overflowY: 'auto' as any }}>
                {[
                  { icon: LayoutDashboard, label: "Dashboard", action: "/dashboard" },
                  { icon: ShieldAlert, label: "Malware Analysis", action: "/samples" },
                  { icon: Search, label: "IOC Explorer", action: "/iocs" },
                  { icon: Target, label: "Threat Hunting", action: "/mitre" },
                ].map((item) => (
                  <button
                    key={item.label}
                    onClick={() => { router.push(item.action); setCommandOpen(false); }}
                    style={{
                      width: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 12,
                      padding: '10px 12px',
                      borderRadius: 8,
                      background: 'transparent',
                      border: 'none',
                      color: '#8a8a90',
                      fontSize: 13,
                      textAlign: 'left' as any,
                      cursor: 'pointer',
                    } as any}
                    className="hover:!bg-[#1a1a1e] hover:!text-white"
                  >
                    <item.icon style={{ width: 16, height: 16 }} />
                    <span>{item.label}</span>
                  </button>
                ))}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
