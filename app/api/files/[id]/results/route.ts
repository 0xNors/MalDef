export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitHeaders } from '@/lib/security/rateLimiter';
import { generateRequestId, logger } from '@/lib/observability/logger';
import { metricsCollector } from '@/lib/observability/metrics';
import { loadDB } from '@/lib/db';
import { cassandraStore } from '@/lib/storage/cassandra';

/**
 * GET /files/{id}/results - Retrieves scan results (VirusTotal System Design)
 * Read-through caching: API first tries cache, if miss reads from DB (Cassandra)
 * id can be SHA1 or SHA256 or hash:timestamp
 */

const resultsCache = new Map<string, { data: any; expires: number }>();
const CACHE_TTL = 300000; // 5 minutes

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const startTime = Date.now();
  const requestId = req.headers.get('x-request-id') || generateRequestId();
  const id = params.id;
  
  const rateLimit = checkRateLimit(req, 'tokenBucket');
  if (!rateLimit.allowed) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429, headers: createRateLimitHeaders(rateLimit) });
  }

  try {
    // Parse id: could be hash or hash:timestamp
    let sha256 = id;
    let timestamp: string | undefined;
    if (id.includes(':')) {
      const parts = id.split(':');
      sha256 = parts[0];
      timestamp = parts[1];
    }

    // Read-through caching strategy
    const cacheKey = `results:${sha256}:${timestamp || 'latest'}`;
    const cached = resultsCache.get(cacheKey);
    
    if (cached && Date.now() < cached.expires) {
      logger.debug(requestId, 'api/files/results', `Cache HIT for ${sha256.substring(0, 16)}`, { cacheHit: true, sha256: sha256.substring(0, 16) });
      metricsCollector.recordRequest(Date.now() - startTime, false);
      return NextResponse.json(
        { ...cached.data, cached: true, cacheHit: true },
        { headers: { 'X-Request-Id': requestId, 'X-Cache': 'HIT', ...createRateLimitHeaders(rateLimit) } }
      );
    }

    logger.debug(requestId, 'api/files/results', `Cache MISS for ${sha256.substring(0, 16)} - reading from Cassandra`, { cacheHit: false });

    // Try Cassandra (Keyspaces) first
    let cassandraScans = cassandraStore.getFileScansBySha256(sha256);
    let latestScan = timestamp ? cassandraScans.find(s => s.timestamp === timestamp || s.rowId.includes(timestamp)) || null : cassandraStore.getLatestScan(sha256);

    // Fallback to legacy DB
    const db = loadDB();
    const sample = db.samples.find(s => s.sha256 === sha256 || s.sha1 === sha256 || s.id === sha256);
    
    if (!sample && !latestScan) {
      metricsCollector.recordRequest(Date.now() - startTime, true);
      return NextResponse.json({ error: 'File not found - no scans' }, { status: 404, headers: { 'X-Request-Id': requestId } });
    }

    const analysis = sample ? db.analyses.find(a => a.sampleId === sample.id) : null;
    const comprehensive = (analysis as any)?.comprehensiveReport;

    // Aggregate results like VirusTotal
    const results: any[] = [];
    
    if (comprehensive?.aToZ) {
      for (const [letter, info] of Object.entries(comprehensive.aToZ as any)) {
        results.push({
          engine: (info as any).title,
          version: '1.0',
          result: (info as any).status === 'clean' ? 'Clean' : (info as any).status === 'suspicious' ? 'Suspicious' : 'Malicious',
          category: letter,
          method: (info as any).title,
          update: analysis?.timestamp || new Date().toISOString(),
          details: (info as any).details,
          risk: (info as any).risk
        });
      }
    }

    if (comprehensive?.yara?.matches) {
      for (const match of comprehensive.yara.matches) {
        results.push({
          engine: 'YARA',
          version: '4.3',
          result: match.family,
          category: 'YARA',
          method: match.rule,
          update: analysis?.timestamp,
          details: match.description,
          mitre: match.mitre
        });
      }
    }

    const responseData = {
      timestamp: latestScan?.timestamp || analysis?.timestamp || new Date().toISOString(),
      sha1: sample?.sha1 || latestScan?.fileMetadata.sha1 || '',
      sha256: sample?.sha256 || latestScan?.sha256 || sha256,
      md5: sample?.md5 || latestScan?.fileMetadata.md5 || '',
      size: sample?.fileSize || latestScan?.fileMetadata.fileSize || 0,
      fileType: sample?.mimeType || latestScan?.fileMetadata.fileType || 'unknown',
      firstSubmission: latestScan?.history.firstSubmission || sample?.uploadTimestamp,
      lastSubmission: latestScan?.history.lastSubmission || analysis?.timestamp,
      timesSubmitted: latestScan?.history.analysisCount || 1,
      results,
      aggregated: {
        totalEngines: comprehensive?.virusTotal?.engines || results.length || 12,
        detections: comprehensive?.virusTotal?.detections || results.filter(r => r.result !== 'Clean').length,
        ratio: comprehensive?.virusTotal?.ratio || `${results.filter(r => r.result !== 'Clean').length}/${results.length || 12}`,
        verdict: comprehensive?.virusTotal?.verdict || (results.filter(r => r.result !== 'Clean').length === 0 ? 'Clean' : 'Malicious'),
        riskScore: analysis?.riskScore || latestScan?.aggregated.riskScore || 0,
        severity: analysis?.severity || latestScan?.aggregated.severity || 'LOW',
        classification: analysis?.classification || latestScan?.aggregated.classification || 'BENIGN',
        threatCategories: comprehensive?.riskAssessment?.threatCategories || latestScan?.aggregated.threatCategories || [],
        mitreTechniques: comprehensive?.mitre?.techniques?.map((t: any) => t.id) || latestScan?.aggregated.mitreTechniques || [],
        iocs: comprehensive?.iocs?.all || latestScan?.aggregated.iocs || []
      },
      fileMetadata: {
        fileNames: latestScan?.fileMetadata.fileNames || [sample?.originalFilename],
        fileType: latestScan?.fileMetadata.fileType || sample?.mimeType,
        fileSize: latestScan?.fileMetadata.fileSize || sample?.fileSize,
        md5: latestScan?.fileMetadata.md5 || sample?.md5,
        sha1: latestScan?.fileMetadata.sha1 || sample?.sha1,
        sha256: latestScan?.fileMetadata.sha256 || sample?.sha256,
        imphash: latestScan?.fileMetadata.imphash || (comprehensive?.fileIntelligence?.hashes?.imphash),
        magic: latestScan?.fileMetadata.magic || comprehensive?.fileIntelligence?.basic?.magic,
        entropy: latestScan?.fileMetadata.entropy || comprehensive?.fileIntelligence?.entropy?.overall,
        isPE: latestScan?.fileMetadata.isPE || comprehensive?.fileIntelligence?.fileType?.isPE
      },
      cassandra: {
        rowId: latestScan?.rowId,
        partitionKey: latestScan?.partitionKey,
        history: latestScan?.history
      },
      cached: false,
      cacheHit: false
    };

    // Write to cache (read-through)
    resultsCache.set(cacheKey, { data: responseData, expires: Date.now() + CACHE_TTL });

    // Cleanup old cache entries
    if (resultsCache.size > 1000) {
      const oldest = Array.from(resultsCache.entries()).sort((a, b) => a[1].expires - b[1].expires)[0];
      if (oldest) resultsCache.delete(oldest[0]);
    }

    metricsCollector.recordRequest(Date.now() - startTime, false);
    logger.info(requestId, 'api/files/results', `Retrieved results for ${sha256.substring(0, 16)} - ${responseData.aggregated.ratio} detections`, { sha256: sha256.substring(0, 16), detections: responseData.aggregated.detections });

    return NextResponse.json(responseData, {
      headers: { 'X-Request-Id': requestId, 'X-Cache': 'MISS', ...createRateLimitHeaders(rateLimit) }
    });

  } catch (e) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.error(requestId, 'api/files/results', 'Failed to get results', e as Error);
    return NextResponse.json({ error: 'Failed to retrieve results', details: String(e) }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}
