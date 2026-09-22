export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const { searchParams } = new URL(req.url);
  const status = searchParams.get('status');
  const severity = searchParams.get('severity');
  const search = searchParams.get('search')?.toLowerCase() || '';

  let alerts = db.alerts.map(a => ({
    ...a,
    analyst: a.assignedAnalyst ? db.users.find(u => u.id === a.assignedAnalyst)?.name : 'Unassigned',
    sample: db.samples.find(s => s.id === a.sampleId)
  }));

  if (status) alerts = alerts.filter(a => a.status === status);
  if (severity) alerts = alerts.filter(a => a.severity === severity);
  if (search) {
    alerts = alerts.filter(a => 
      a.id.toLowerCase().includes(search) ||
      a.sampleFilename.toLowerCase().includes(search) ||
      a.detectionReason.toLowerCase().includes(search) ||
      a.sampleId.toLowerCase().includes(search)
    );
  }

  // Sort newest first
  alerts.sort((a,b)=> new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return NextResponse.json(alerts);
}
