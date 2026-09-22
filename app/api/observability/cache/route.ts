export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { blobCache } from '@/lib/storage/blobCache';
import { getCurrentUserFromRequest } from '@/lib/auth';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const action = req.nextUrl.searchParams.get('action');
  
  if (action === 'clear') {
    blobCache.clear();
    return NextResponse.json({ message: 'Cache cleared' });
  }

  const stats = blobCache.getStats();

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    blobCache: stats,
    redis: {
      sessionCache: { key: 'Auth Token', value: { user_id: '...', secret: '...' } },
      fileCache: { key: 'SHA256 Hash', value: 'Blob', ttl: '1 hour' }
    },
    readThrough: {
      description: 'API uses read-through caching - first tries cache, if miss reads from DB (Cassandra)',
      flow: [
        'Client requests GET /files/{id}/results',
        'API checks Redis cache (Elasticache) for results',
        'If HIT: return cached results immediately',
        'If MISS: read from Cassandra (Keyspaces), write to cache, return results',
        'During DB outage: serve from cache (degraded but not total outage)',
        'Session cache offline: use DB to verify tokens + in-memory cache on app server + consistent hashing at NGINX'
      ]
    }
  });
}
