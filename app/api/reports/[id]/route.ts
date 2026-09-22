export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const report = db.reports.find(r => r.id === params.id);
  if (!report) return NextResponse.json({ error: 'Report not found' }, { status: 404 });

  return NextResponse.json(report);
}
