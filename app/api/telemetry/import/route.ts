export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB, saveDB, generateId } from '@/lib/db';

export async function POST(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    const body = await req.json();
    const { sampleId, events, type } = body;

    if (!sampleId || !events || !Array.isArray(events)) {
      return NextResponse.json({ error: 'sampleId and events array required' }, { status: 400 });
    }

    const db = loadDB();
    const sample = db.samples.find(s => s.id === sampleId);
    if (!sample) return NextResponse.json({ error: 'Sample not found' }, { status: 404 });

    let imported = 0;

    if (type === 'behavior' || !type) {
      events.forEach((ev: any) => {
        if (ev.event_type) {
          db.behaviorEvents.push({
            id: generateId('BEV-'),
            sampleId,
            timestamp: ev.timestamp || new Date().toISOString(),
            eventType: ev.event_type,
            process: ev.process || ev.source_process || 'unknown',
            parentProcess: ev.parent_process || ev.parentProcess,
            details: ev,
            severity: ev.severity || (['registry_change', 'scheduled_task_event', 'service_event'].includes(ev.event_type) ? 'HIGH' : 'MEDIUM'),
          });
          imported++;
        }
      });
    }

    if (type === 'network' || !type) {
      events.forEach((ev: any) => {
        if (ev.destination_ip || ev.destinationIp) {
          db.networkEvents.push({
            id: generateId('NEV-'),
            sampleId,
            timestamp: ev.timestamp || new Date().toISOString(),
            sourceProcess: ev.source_process || ev.sourceProcess || ev.process || 'unknown',
            destinationIp: ev.destination_ip || ev.destinationIp,
            destinationDomain: ev.destination_domain || ev.destinationDomain,
            port: ev.port || 80,
            protocol: ev.protocol || 'TCP',
            frequency: ev.frequency || 1,
            severity: ev.severity || 'MEDIUM',
            isAnomalous: ev.isAnomalous || ev.port === 4444 || ev.port === 6666 || false,
          });
          imported++;
        }
      });
    }

    // If generic, try to auto-detect
    if (!type) {
      // Already handled both, but dedupe if needed
    }

    db.auditLogs.unshift({
      id: generateId('AUDIT-'),
      timestamp: new Date().toISOString(),
      userId: user.userId,
      action: 'TELEMETRY_IMPORT',
      resource: 'telemetry',
      details: `Imported ${imported} events for sample ${sampleId}`,
    });

    saveDB(db);

    return NextResponse.json({ message: `Imported ${imported} events`, imported });
  } catch (e) {
    console.error('Telemetry import error', e);
    return NextResponse.json({ error: 'Import failed' }, { status: 500 });
  }
}
