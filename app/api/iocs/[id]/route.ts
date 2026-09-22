export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB, saveDB, generateId } from '@/lib/db';

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (user.role !== 'ADMIN' && user.role !== 'ANALYST') return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const db = loadDB();
  const ioc = db.iocs.find(i => i.id === params.id);
  if (!ioc) return NextResponse.json({ error: 'IOC not found' }, { status: 404 });

  const body = await req.json();
  Object.assign(ioc, body, { lastSeen: new Date().toISOString() });

  db.auditLogs.unshift({
    id: generateId('AUDIT-'),
    timestamp: new Date().toISOString(),
    userId: user.userId,
    action: 'IOC_UPDATE',
    resource: 'iocs',
    details: `Updated IOC ${ioc.type}:${ioc.value}`,
  });
  saveDB(db);

  return NextResponse.json({ message: 'IOC updated', ioc });
}

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (user.role !== 'ADMIN') return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const db = loadDB();
  const idx = db.iocs.findIndex(i => i.id === params.id);
  if (idx === -1) return NextResponse.json({ error: 'IOC not found' }, { status: 404 });

  const ioc = db.iocs[idx];
  db.iocs.splice(idx, 1);

  db.auditLogs.unshift({
    id: generateId('AUDIT-'),
    timestamp: new Date().toISOString(),
    userId: user.userId,
    action: 'IOC_DELETE',
    resource: 'iocs',
    details: `Deleted IOC ${ioc.type}:${ioc.value}`,
  });
  saveDB(db);

  return NextResponse.json({ message: 'IOC deleted' });
}
