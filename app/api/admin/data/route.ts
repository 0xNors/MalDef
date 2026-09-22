export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (user.role !== 'ADMIN') return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const db = loadDB();
  return NextResponse.json({
    users: db.users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt, lastLogin: u.lastLogin })),
    rules: db.detectionRules,
    auditLogs: db.auditLogs.slice(0, 200),
    stats: { totalUsers: db.users.length, totalRules: db.detectionRules.length, totalLogs: db.auditLogs.length }
  });
}
