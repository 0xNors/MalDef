export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();

  const totalSamples = db.samples.length;
  const totalAnalyses = db.analyses.length;
  
  const benign = db.analyses.filter(a => a.classification === 'BENIGN').length;
  const suspicious = db.analyses.filter(a => a.classification === 'SUSPICIOUS').length;
  const highRisk = db.analyses.filter(a => a.classification === 'HIGH_RISK').length;
  const critical = db.analyses.filter(a => a.classification === 'CRITICAL').length;

  const openAlerts = db.alerts.filter(a => ['NEW', 'INVESTIGATING'].includes(a.status)).length;
  const resolvedAlerts = db.alerts.filter(a => ['RESOLVED', 'CONTAINED', 'FALSE_POSITIVE'].includes(a.status)).length;

  // Severity distribution
  const severityDist = [
    { name: 'LOW', value: db.analyses.filter(a => a.severity === 'LOW').length, color: '#00ff88' },
    { name: 'MEDIUM', value: db.analyses.filter(a => a.severity === 'MEDIUM').length, color: '#ffcc00' },
    { name: 'HIGH', value: db.analyses.filter(a => a.severity === 'HIGH').length, color: '#ff6b35' },
    { name: 'CRITICAL', value: db.analyses.filter(a => a.severity === 'CRITICAL').length, color: '#ff3344' },
  ];

  // Risk score distribution
  const riskDist = [
    { range: '0-29', count: db.analyses.filter(a => a.riskScore < 30).length },
    { range: '30-59', count: db.analyses.filter(a => a.riskScore >= 30 && a.riskScore < 60).length },
    { range: '60-79', count: db.analyses.filter(a => a.riskScore >= 60 && a.riskScore < 80).length },
    { range: '80-100', count: db.analyses.filter(a => a.riskScore >= 80).length },
  ];

  // Timeline - last 7 days
  const timeline = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    const count = db.analyses.filter(a => a.timestamp.split('T')[0] === dateStr).length;
    timeline.push({ date: dateStr.slice(5), count, benign: db.analyses.filter(a => a.timestamp.split('T')[0] === dateStr && a.classification === 'BENIGN').length });
  }

  // Detection categories
  const categoryCount: Record<string, number> = {};
  db.detections.forEach(d => {
    categoryCount[d.category] = (categoryCount[d.category] || 0) + 1;
  });
  const detectionCategories = Object.entries(categoryCount).map(([name, value]) => ({ name, value }));

  // Top IOCs
  const topIOCs = db.iocs
    .sort((a, b) => b.relatedAlerts.length - a.relatedAlerts.length)
    .slice(0, 5)
    .map(ioc => ({ value: ioc.value, type: ioc.type, count: ioc.relatedAlerts.length, severity: ioc.severity }));

  // ATT&CK tactics
  const tacticCount: Record<string, number> = {};
  db.analyses.forEach(a => {
    a.mitreMappings?.forEach((m: any) => {
      tacticCount[m.tactic] = (tacticCount[m.tactic] || 0) + 1;
    });
  });
  const attackTactics = Object.entries(tacticCount).map(([name, value]) => ({ name, value }));

  // Alert status
  const alertStatus = [
    { name: 'NEW', value: db.alerts.filter(a => a.status === 'NEW').length, color: '#ff3344' },
    { name: 'INVESTIGATING', value: db.alerts.filter(a => a.status === 'INVESTIGATING').length, color: '#ffcc00' },
    { name: 'CONTAINED', value: db.alerts.filter(a => a.status === 'CONTAINED').length, color: '#00d9ff' },
    { name: 'RESOLVED', value: db.alerts.filter(a => a.status === 'RESOLVED').length, color: '#00ff88' },
    { name: 'FALSE_POSITIVE', value: db.alerts.filter(a => a.status === 'FALSE_POSITIVE').length, color: '#71717a' },
  ];

  const recentAlerts = db.alerts.slice(0, 10).map(a => ({
    ...a,
    analyst: a.assignedAnalyst ? db.users.find(u => u.id === a.assignedAnalyst)?.name : 'Unassigned'
  }));

  return NextResponse.json({
    cards: { totalSamples, totalAnalyses, benign, suspicious, highRisk, critical, openAlerts, resolvedAlerts },
    charts: { severityDist, riskDist, timeline, detectionCategories, topIOCs, attackTactics, alertStatus },
    recentAlerts,
  });
}
