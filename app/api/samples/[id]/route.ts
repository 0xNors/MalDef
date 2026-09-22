export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const sample = db.samples.find(s => s.id === params.id);
  if (!sample) return NextResponse.json({ error: 'Sample not found' }, { status: 404 });

  const analysis = db.analyses.find(a => a.sampleId === sample.id);
  const staticFindings = db.staticFindings.filter(f => f.sampleId === sample.id);
  const behaviorEvents = db.behaviorEvents.filter(e => e.sampleId === sample.id);
  const networkEvents = db.networkEvents.filter(e => e.sampleId === sample.id);
  const detections = db.detections.filter(d => d.sampleId === sample.id);
  const alerts = db.alerts.filter(a => a.sampleId === sample.id);

  return NextResponse.json({ sample, analysis, staticFindings, behaviorEvents, networkEvents, detections, alerts });
}
