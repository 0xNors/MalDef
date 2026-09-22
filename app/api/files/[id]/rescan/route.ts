export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitHeaders } from '@/lib/security/rateLimiter';
import { generateRequestId, logger } from '@/lib/observability/logger';
import { metricsCollector } from '@/lib/observability/metrics';
import { loadDB } from '@/lib/db';
import { cassandraStore } from '@/lib/storage/cassandra';
import { broker, createJobMessage } from '@/lib/queue/broker';
import { blobCache } from '@/lib/storage/blobCache';
import fs from 'fs';

/**
 * POST /files/{id}/rescan - Initiates re-scan of a file (VirusTotal System Design)
 */

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const startTime = Date.now();
  const requestId = req.headers.get('x-request-id') || generateRequestId();
  const id = params.id;

  const rateLimit = checkRateLimit(req, 'slidingWindow');
  if (!rateLimit.allowed) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    return NextResponse.json({ error: 'Rate limit exceeded - rescan limited' }, { status: 429, headers: createRateLimitHeaders(rateLimit) });
  }

  try {
    const db = loadDB();
    const sample = db.samples.find(s => s.sha256 === id || s.sha1 === id || s.id === id);

    if (!sample) {
      // Try Cassandra
      const scans = cassandraStore.getFileScansBySha256(id);
      if (scans.length === 0) {
        return NextResponse.json({ error: 'File not found' }, { status: 404, headers: { 'X-Request-Id': requestId } });
      }
      // Use latest scan info
      const latest = scans[0];
      const filePath = latest.history.submissions[0] ? `data/samples/${latest.fileMetadata.fileNames[0]}` : '';
      
      // Create job for rescan
      const jobMessage = createJobMessage({
        storageKey: filePath,
        sha256: latest.sha256,
        sha1: latest.fileMetadata.sha1,
        md5: latest.fileMetadata.md5,
        fileSize: latest.fileMetadata.fileSize,
        originalFilename: latest.fileMetadata.fileNames[0] || 'unknown',
        mimeType: latest.fileMetadata.fileType,
        priority: 'HIGH',
        requestId
      });

      const published = broker.publish('file-upload-exchange', jobMessage);

      logger.info(requestId, 'api/files/rescan', `Rescan initiated for ${id.substring(0, 16)} from Cassandra`, { sha256: id.substring(0, 16), queues: published.queues });

      return NextResponse.json({
        message: 'Rescan initiated',
        timestamp: new Date().toISOString(),
        sha256: latest.sha256,
        sha1: latest.fileMetadata.sha1,
        md5: latest.fileMetadata.md5,
        size: latest.fileMetadata.fileSize,
        job: { storageKey: filePath, queues: published.queues, requestId, priority: 'HIGH' }
      }, { headers: { 'X-Request-Id': requestId, ...createRateLimitHeaders(rateLimit) } });
    }

    if (!fs.existsSync(sample.filePath)) {
      return NextResponse.json({ error: 'File not found on disk' }, { status: 404, headers: { 'X-Request-Id': requestId } });
    }

    // Load into blob cache for faster worker access
    const buffer = fs.readFileSync(sample.filePath);
    blobCache.set(sample.sha256, buffer);

    const jobMessage = createJobMessage({
      storageKey: sample.filePath,
      sha256: sample.sha256,
      sha1: sample.sha1,
      md5: sample.md5,
      fileSize: sample.fileSize,
      originalFilename: sample.originalFilename,
      mimeType: sample.mimeType,
      priority: 'HIGH',
      requestId
    });

    const published = broker.publish('file-upload-exchange', jobMessage);

    logger.info(requestId, 'api/files/rescan', `Rescan initiated for ${sample.originalFilename} - ${sample.sha256.substring(0, 16)}`, { filename: sample.originalFilename, queues: published.queues });

    metricsCollector.recordRequest(Date.now() - startTime, false);

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      md5: sample.md5,
      sha1: sample.sha1,
      sha256: sample.sha256,
      size: sample.fileSize,
      filename: sample.originalFilename,
      job: {
        storageKey: sample.filePath,
        queues: published.queues,
        published: published.published,
        requestId,
        priority: 'HIGH'
      },
      message: 'Re-scan initiated - file queued to all worker queues via RabbitMQ fan-out'
    }, { headers: { 'X-Request-Id': requestId, ...createRateLimitHeaders(rateLimit) } });

  } catch (e) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.error(requestId, 'api/files/rescan', 'Rescan failed', e as Error);
    return NextResponse.json({ error: 'Rescan failed', details: String(e) }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}
