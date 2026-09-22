export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitHeaders } from '@/lib/security/rateLimiter';
import { generateRequestId, logger } from '@/lib/observability/logger';
import { cassandraStore } from '@/lib/storage/cassandra';
import { loadDB } from '@/lib/db';

/**
 * GET /files/{id}/scans - Returns list of scans for a file (VirusTotal System Design)
 */

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const requestId = req.headers.get('x-request-id') || generateRequestId();
  const id = params.id;

  const rateLimit = checkRateLimit(req, 'tokenBucket');
  if (!rateLimit.allowed) {
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429, headers: createRateLimitHeaders(rateLimit) });
  }

  try {
    const scans = cassandraStore.getFileScansBySha256(id);
    
    const db = loadDB();
    const sample = db.samples.find(s => s.sha256 === id || s.sha1 === id || s.id === id);
    const analyses = sample ? db.analyses.filter(a => a.sampleId === sample.id) : [];

    if (scans.length === 0 && analyses.length === 0) {
      return NextResponse.json({ error: 'No scans found' }, { status: 404, headers: { 'X-Request-Id': requestId } });
    }

    const allScans = [
      ...scans.map(s => ({
        timestamp: s.timestamp,
        md5: s.fileMetadata.md5,
        sha1: s.fileMetadata.sha1,
        sha256: s.sha256,
        size: s.fileMetadata.fileSize,
        filename: s.fileMetadata.fileNames[0],
        rowId: s.rowId,
        partitionKey: s.partitionKey,
        analysisCount: s.history.analysisCount,
        firstSubmission: s.history.firstSubmission,
        lastSubmission: s.history.lastSubmission,
        aggregated: s.aggregated,
        source: 'cassandra'
      })),
      ...analyses.map(a => ({
        timestamp: a.timestamp,
        md5: sample?.md5,
        sha1: sample?.sha1,
        sha256: sample?.sha256,
        size: sample?.fileSize,
        filename: sample?.originalFilename,
        rowId: a.id,
        partitionKey: `${sample?.id}:${a.id}`,
        analysisCount: 1,
        firstSubmission: a.timestamp,
        lastSubmission: a.timestamp,
        aggregated: {
          riskScore: a.riskScore,
          severity: a.severity,
          classification: a.classification,
          ratio: (a as any).comprehensiveReport?.virusTotal?.ratio || '0/12'
        },
        source: 'legacy'
      }))
    ].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    logger.info(requestId, 'api/files/scans', `Retrieved ${allScans.length} scans for ${id.substring(0, 16)}`, { count: allScans.length });

    return NextResponse.json({
      sha256: id,
      totalScans: allScans.length,
      scans: allScans.slice(0, 20), // Last 20 scans
      history: scans.length > 0 ? scans[0].history : null,
      cassandraStats: cassandraStore.getStats()
    }, { headers: { 'X-Request-Id': requestId, ...createRateLimitHeaders(rateLimit) } });

  } catch (e) {
    logger.error(requestId, 'api/files/scans', 'Failed to get scans', e as Error);
    return NextResponse.json({ error: 'Failed to get scans' }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}
