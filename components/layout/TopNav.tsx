"use client";
import { useState, useEffect } from "react";
import { Search, Bell, Shield, Activity, Clock, Menu } from "lucide-react";

interface TopNavProps {
  onMenuClick: () => void;
  collapsed: boolean;
}

export default function TopNav({ onMenuClick, collapsed }: TopNavProps) {
  const [time, setTime] = useState(new Date());
  const [alertCount, setAlertCount] = useState(0);
  const [iocCount, setIocCount] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    fetch("/api/alerts").then(r => r.json()).then(d => setAlertCount(Array.isArray(d) ? d.filter((a: any) => a.status === 'NEW').length : 0)).catch(()=>{});
    fetch("/api/iocs").then(r => r.json()).then(d => setIocCount(Array.isArray(d) ? d.length : 0)).catch(()=>{});
    return () => clearInterval(interval);
  }, []);

  return (
    <header
      style={{
        position: 'fixed',
        top: 0,
        right: 0,
        left: collapsed ? 72 : 260,
        height: 64,
        minHeight: 64,
        background: '#0a0a0c',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        zIndex: 30,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        transition: 'left 0.2s ease',
      } as any}
      className="lg:px-6 max-lg:!left-0"
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
        <button
          onClick={onMenuClick}
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: '#121214',
            border: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'white',
            cursor: 'pointer',
          } as any}
          className="lg:!hidden"
        >
          <Menu style={{ width: 18, height: 18 }} />
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }} className="hidden md:flex">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', borderRadius: 20, background: '#121214', border: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ width: 6, height: 6, background: '#22c55e', borderRadius: '50%' }}></div>
            <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: '#a1a1aa', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>ONLINE</span>
          </div>
          <div style={{ height: 14, width: 1, background: 'rgba(255,255,255,0.08)' }}></div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'JetBrains Mono', color: '#52525b', whiteSpace: 'nowrap' }}>
            <Clock style={{ width: 12, height: 12, flexShrink: 0 }} />
            <span style={{ color: '#8a8a90' }}>{time.toLocaleTimeString()}</span>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '8px 12px',
            borderRadius: 8,
            background: '#121214',
            border: '1px solid rgba(255,255,255,0.06)',
            color: '#52525b',
            cursor: 'pointer',
            minWidth: 0,
          } as any}
          className="hidden lg:flex hover:!border-white/10 hover:!bg-[#151518] transition-colors"
        >
          <Search style={{ width: 14, height: 14, flexShrink: 0 }} />
          <span style={{ fontSize: 12, whiteSpace: 'nowrap' }}>Search hash, file, IOC...</span>
          <div style={{ marginLeft: 8, display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
            <kbd style={{ padding: '2px 6px', borderRadius: 4, background: '#1e1e22', border: '1px solid rgba(255,255,255,0.06)', fontSize: 10 }}>⌘</kbd>
            <kbd style={{ padding: '2px 6px', borderRadius: 4, background: '#1e1e22', border: '1px solid rgba(255,255,255,0.06)', fontSize: 10 }}>K</kbd>
          </div>
        </div>

        <button
          style={{
            position: 'relative',
            width: 36,
            height: 36,
            borderRadius: 8,
            background: '#121214',
            border: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#71717a',
            cursor: 'pointer',
          } as any}
          className="hover:!bg-[#151518] hover:!text-white transition-colors"
        >
          <Bell style={{ width: 16, height: 16 }} />
          {alertCount > 0 && (
            <span style={{ position: 'absolute', top: -4, right: -4, width: 18, height: 18, background: '#ef4444', borderRadius: '50%', fontSize: 10, fontWeight: 700, color: 'white', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '2px solid #0a0a0c' }}>
              {alertCount}
            </span>
          )}
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderRadius: 8, background: '#121214', border: '1px solid rgba(255,255,255,0.06)' }} className="hidden md:flex">
          <Activity style={{ width: 14, height: 14, color: '#71717a', flexShrink: 0 }} />
          <div style={{ textAlign: 'left', minWidth: 0 }}>
            <p style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: 'white', lineHeight: 1, margin: 0, whiteSpace: 'nowrap' }}>THREAT INTEL</p>
            <p style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#71717a', margin: '2px 0 0 0', whiteSpace: 'nowrap' }}>{iocCount} IOCs</p>
          </div>
        </div>

        <div style={{ width: 1, height: 20, background: 'rgba(255,255,255,0.06)', flexShrink: 0 }} className="hidden lg:block"></div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: '#1e1e22', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Shield style={{ width: 16, height: 16, color: '#a1a1aa' }} />
          </div>
          <div style={{ textAlign: 'left', minWidth: 0 }} className="hidden lg:block">
            <p style={{ fontSize: 12, fontWeight: 500, color: 'white', lineHeight: 1, margin: 0, whiteSpace: 'nowrap' }}>Admin</p>
            <p style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#71717a', margin: '2px 0 0 0', whiteSpace: 'nowrap' }}>Security Analyst</p>
          </div>
        </div>
      </div>
    </header>
  );
}
