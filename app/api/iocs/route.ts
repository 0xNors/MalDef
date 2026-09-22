export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB, saveDB, generateId } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const { searchParams } = new URL(req.url);
  const type = searchParams.get('type');
  const severity = searchParams.get('severity');
  const search = searchParams.get('search')?.toLowerCase() || '';
  const tag = searchParams.get('tag')?.toLowerCase() || '';
  const sort = searchParams.get('sort') || 'lastSeen';
  const source = searchParams.get('source');

  let iocs = [...db.iocs];

  if (type) iocs = iocs.filter(i => i.type === type);
  if (severity) iocs = iocs.filter(i => i.severity === severity);
  if (source) iocs = iocs.filter(i => i.source?.toLowerCase().includes(source.toLowerCase()));
  if (tag) iocs = iocs.filter(i => i.tags?.some(t => t.toLowerCase().includes(tag)));
  if (search) {
    iocs = iocs.filter(i => 
      i.value.toLowerCase().includes(search) ||
      i.description.toLowerCase().includes(search) ||
      i.tags?.some(t => t.toLowerCase().includes(search)) ||
      i.source?.toLowerCase().includes(search)
    );
  }

  // Sorting
  iocs.sort((a,b) => {
    if (sort === 'lastSeen') return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
    if (sort === 'firstSeen') return new Date(b.firstSeen).getTime() - new Date(a.firstSeen).getTime();
    if (sort === 'severity') {
      const order: any = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };
      return (order[b.severity]||0) - (order[a.severity]||0);
    }
    if (sort === 'timesSeen') return (b.timesSeen||0) - (a.timesSeen||0);
    if (sort === 'reputation') return (b.reputationScore||0) - (a.reputationScore||0);
    return 0;
  });

  // Stats
  const stats = {
    total: db.iocs.length,
    byType: {
      SHA256: db.iocs.filter(i=>i.type==='SHA256').length,
      SHA1: db.iocs.filter(i=>i.type==='SHA1').length,
      MD5: db.iocs.filter(i=>i.type==='MD5').length,
      IP: db.iocs.filter(i=>i.type==='IP').length,
      DOMAIN: db.iocs.filter(i=>i.type==='DOMAIN').length,
      URL: db.iocs.filter(i=>i.type==='URL').length,
      FILENAME: db.iocs.filter(i=>i.type==='FILENAME').length,
    },
    bySeverity: {
      CRITICAL: db.iocs.filter(i=>i.severity==='CRITICAL').length,
      HIGH: db.iocs.filter(i=>i.severity==='HIGH').length,
      MEDIUM: db.iocs.filter(i=>i.severity==='MEDIUM').length,
      LOW: db.iocs.filter(i=>i.severity==='LOW').length,
    },
    blocked: db.iocs.filter(i=>i.isBlocked).length,
    whitelisted: db.iocs.filter(i=>i.isWhitelisted).length,
    autoExtracted: db.iocs.filter(i=>i.autoExtracted).length,
    totalTags: Array.from(new Set(db.iocs.flatMap(i=>i.tags||[]))).length,
    topTags: Array.from(
      db.iocs.flatMap(i=>i.tags||[]).reduce((acc: Map<string,number>, tag) => {
        acc.set(tag, (acc.get(tag)||0)+1);
        return acc;
      }, new Map<string,number>()).entries()
    ).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([tag,count])=>({tag,count})),
    recent: db.iocs.slice(0,5)
  };

  return NextResponse.json({ iocs, stats });
}

export async function POST(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (user.role !== 'ADMIN' && user.role !== 'ANALYST') return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const body = await req.json();
  const { value, type, severity, description, tags } = body;

  if (!value || !type || !severity) return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });

  const validTypes = ['SHA256', 'SHA1', 'MD5', 'IP', 'DOMAIN', 'URL', 'FILENAME'];
  if (!validTypes.includes(type)) return NextResponse.json({ error: 'Invalid IOC type' }, { status: 400 });

  const db = loadDB();
  
  if (db.iocs.find(i => i.value.toLowerCase() === value.toLowerCase() && i.type === type)) {
    return NextResponse.json({ error: 'IOC already exists' }, { status: 409 });
  }

  const now = new Date().toISOString();
  const ioc = {
    id: generateId('IOC-'),
    value,
    type,
    severity,
    source: user.email,
    firstSeen: now,
    lastSeen: now,
    description: description || '',
    relatedAlerts: [],
    tags: tags || [],
    confidence: 85,
    timesSeen: 1,
    relatedSamples: [],
    mitreTechniques: [],
    isWhitelisted: false,
    isBlocked: severity === 'CRITICAL' || severity === 'HIGH',
    reputationScore: severity === 'CRITICAL' ? 90 : severity === 'HIGH' ? 75 : 50,
    threatIntel: {
      virusTotal: { detections: 0, total: 29, ratio: '0/29' },
      otx: { pulses: 0, tags: tags || [] }
    },
    lastEnriched: now,
    autoExtracted: false,
  };

  db.iocs.unshift(ioc as any);
  db.auditLogs.unshift({
    id: generateId('AUDIT-'),
    timestamp: now,
    userId: user.userId,
    action: 'IOC_CREATE',
    resource: 'iocs',
    details: `Created IOC ${type}:${value}`,
  });
  saveDB(db);

  return NextResponse.json({ message: 'IOC created', ioc });
}
