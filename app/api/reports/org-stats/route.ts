export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const analyses = db.analyses || [];
  const samples = db.samples || [];
  const reports = db.reports || [];
  const iocs = db.iocs || [];
  const detections = db.detections || [];

  const now = new Date();
  const last30 = analyses.filter((a: any) => {
    const d = new Date(a.timestamp);
    const diff = (now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24);
    return diff <= 30;
  });

  // Risk distribution
  const riskBuckets = [
    { label: '0-20', count: analyses.filter((a: any) => a.riskScore < 20).length },
    { label: '20-40', count: analyses.filter((a: any) => a.riskScore >= 20 && a.riskScore < 40).length },
    { label: '40-60', count: analyses.filter((a: any) => a.riskScore >= 40 && a.riskScore < 60).length },
    { label: '60-80', count: analyses.filter((a: any) => a.riskScore >= 60 && a.riskScore < 80).length },
    { label: '80-100', count: analyses.filter((a: any) => a.riskScore >= 80).length },
  ];

  // Classification
  const classDist = {
    BENIGN: analyses.filter((a: any) => a.classification === 'BENIGN').length,
    SUSPICIOUS: analyses.filter((a: any) => a.classification === 'SUSPICIOUS').length,
    HIGH_RISK: analyses.filter((a: any) => a.classification === 'HIGH_RISK').length,
    CRITICAL: analyses.filter((a: any) => a.classification === 'CRITICAL').length,
  };

  // Timeline last 14 days
  const timelineMap = new Map<string, { date: string; total: number; critical: number; high: number; avgRisk: number; risks: number[] }>();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().split('T')[0];
    timelineMap.set(key, { date: key, total: 0, critical: 0, high: 0, avgRisk: 0, risks: [] });
  }
  analyses.forEach((a: any) => {
    const day = (a.timestamp || '').split('T')[0];
    if (timelineMap.has(day)) {
      const e = timelineMap.get(day)!;
      e.total++;
      e.risks.push(a.riskScore || 0);
      if (a.classification === 'CRITICAL') e.critical++;
      if (a.classification === 'HIGH_RISK') e.high++;
    }
  });
  const timeline = Array.from(timelineMap.values()).map(e => ({
    date: e.date.slice(5),
    fullDate: e.date,
    total: e.total,
    critical: e.critical,
    high: e.high,
    avgRisk: e.risks.length ? Math.round(e.risks.reduce((s, v) => s + v, 0) / e.risks.length) : 0,
  }));

  // Top MITRE
  const mitreMap = new Map<string, number>();
  analyses.forEach((a: any) => {
    (a.mitreMappings || []).forEach((m: any) => {
      const id = m.techniqueId || m.technique || 'Unknown';
      mitreMap.set(id, (mitreMap.get(id) || 0) + 1);
    });
  });
  const topMitre = Array.from(mitreMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([id, count]) => ({ id, count }));

  // Top IOCs types
  const iocTypes = {
    IP: iocs.filter((i: any) => i.type === 'IP').length,
    DOMAIN: iocs.filter((i: any) => i.type === 'DOMAIN').length,
    URL: iocs.filter((i: any) => i.type === 'URL').length,
    HASH: iocs.filter((i: any) => ['SHA256', 'SHA1', 'MD5'].includes(i.type)).length,
  };

  return NextResponse.json({
    totalSamples: samples.length,
    totalAnalyses: analyses.length,
    totalReports: reports.length,
    totalIOCs: iocs.length,
    last30Count: last30.length,
    avgRisk: analyses.length ? Math.round(analyses.reduce((s: number, a: any) => s + (a.riskScore || 0), 0) / analyses.length) : 0,
    avgConfidence: analyses.length ? Math.round(analyses.reduce((s: number, a: any) => s + (a.confidence || 0), 0) / analyses.length) : 0,
    criticalCount: classDist.CRITICAL,
    highCount: classDist.HIGH_RISK,
    riskBuckets,
    classDist,
    timeline,
    topMitre,
    iocTypes,
    recentReports: reports.slice(0, 5),
  });
}
