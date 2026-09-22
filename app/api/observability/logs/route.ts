export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/observability/logger';
import { getCurrentUserFromRequest } from '@/lib/auth';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const level = req.nextUrl.searchParams.get('level') as any;
  const service = req.nextUrl.searchParams.get('service') || undefined;
  const requestId = req.nextUrl.searchParams.get('requestId') || undefined;
  const limit = parseInt(req.nextUrl.searchParams.get('limit') || '100');

  const logs = logger.getLogs({ level, service, requestId, limit });

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    total: logs.length,
    logs,
    services: [...new Set(logs.map(l => l.service))],
    levels: [...new Set(logs.map(l => l.level))]
  });
}
