export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB, saveDB, generateId } from '@/lib/db';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const alert = db.alerts.find(a => a.id === params.id);
  if (!alert) return NextResponse.json({ error: 'Alert not found' }, { status: 404 });

  const sample = db.samples.find(s => s.id === alert.sampleId);
  const analysis = db.analyses.find(a => a.id === alert.analysisId);
  const detections = db.detections.filter(d => d.sampleId === alert.sampleId);
  const staticFindings = db.staticFindings.filter(f => f.sampleId === alert.sampleId);
  const behaviorEvents = db.behaviorEvents.filter(e => e.sampleId === alert.sampleId);
  const networkEvents = db.networkEvents.filter(e => e.sampleId === alert.sampleId);
  const notes = db.analystNotes.filter(n => n.alertId === alert.id);

  return NextResponse.json({ alert, sample, analysis, detections, staticFindings, behaviorEvents, networkEvents, notes });
}

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const alert = db.alerts.find(a => a.id === params.id);
  if (!alert) return NextResponse.json({ error: 'Alert not found' }, { status: 404 });

  const body = await req.json();
  const { status, assignedAnalyst, note } = body;

  if (status) {
    const validStatuses = ['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];
    if (!validStatuses.includes(status)) return NextResponse.json({ error: 'Invalid status' }, { status: 400 });
    alert.status = status;
    if (status === 'INVESTIGATING' && !alert.assignedAnalyst) {
      alert.assignedAnalyst = user.userId;
    }
  }

  if (assignedAnalyst !== undefined) {
    alert.assignedAnalyst = assignedAnalyst;
  }

  if (note) {
    db.analystNotes.unshift({
      id: generateId('NOTE-'),
      alertId: alert.id,
      sampleId: alert.sampleId,
      author: user.userId,
      content: note,
      timestamp: new Date().toISOString(),
    });
  }

  db.auditLogs.unshift({
    id: generateId('AUDIT-'),
    timestamp: new Date().toISOString(),
    userId: user.userId,
    action: 'ALERT_UPDATE',
    resource: 'alerts',
    details: `Alert ${alert.id} updated to ${status || alert.status}`,
  });

  saveDB(db);

  return NextResponse.json({ message: 'Alert updated', alert });
}
