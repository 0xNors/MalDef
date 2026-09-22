export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, createRateLimitHeaders } from '@/lib/security/rateLimiter';
import { generateRequestId, logger } from '@/lib/observability/logger';
import { metricsCollector } from '@/lib/observability/metrics';
import { loadDB } from '@/lib/db';
import { cassandraStore } from '@/lib/storage/cassandra';
import { blobCache } from '@/lib/storage/blobCache';
import crypto from 'crypto';
import fs from 'fs';

/**
 * GET /files/{id}/download - Returns pre-signed download URL (VirusTotal System Design)
 */

const DOWNLOAD_TOKENS = new Map<string, { sha256: string; expires: number; requestId: string }>();

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const startTime = Date.now();
  const requestId = req.headers.get('x-request-id') || generateRequestId();
  const id = params.id;
  const token = req.nextUrl.searchParams.get('token');

  const rateLimit = checkRateLimit(req, 'tokenBucket');
  if (!rateLimit.allowed) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429, headers: createRateLimitHeaders(rateLimit) });
  }

  try {
    // If token provided, serve file directly (pre-signed URL flow)
    if (token) {
      const tokenData = DOWNLOAD_TOKENS.get(token);
      if (!tokenData || Date.now() > tokenData.expires) {
        return NextResponse.json({ error: 'Invalid or expired download token' }, { status: 403, headers: { 'X-Request-Id': requestId } });
      }

      if (tokenData.sha256 !== id) {
        return NextResponse.json({ error: 'Token mismatch' }, { status: 403, headers: { 'X-Request-Id': requestId } });
      }

      const db = loadDB();
      const sample = db.samples.find(s => s.sha256 === id || s.sha1 === id);

      if (!sample || !fs.existsSync(sample.filePath)) {
        // Try blob cache
        const cached = blobCache.get(id);
        if (cached) {
          logger.info(requestId, 'api/files/download', `Serving ${id.substring(0, 16)} from blob cache`, { cacheHit: true });
          return new NextResponse(new Uint8Array(cached), {
            headers: {
              'Content-Type': 'application/octet-stream',
              'Content-Disposition': `attachment; filename="${sample?.originalFilename || id}"`,
              'X-Request-Id': requestId,
              'X-Cache': 'HIT',
              ...createRateLimitHeaders(rateLimit)
            }
          });
        }
        return NextResponse.json({ error: 'File not found' }, { status: 404, headers: { 'X-Request-Id': requestId } });
      }

      const buffer = fs.readFileSync(sample.filePath);
      DOWNLOAD_TOKENS.delete(token);

      logger.info(requestId, 'api/files/download', `Download served for ${id.substring(0, 16)} via token ${token.substring(0, 8)}`, { sha256: id.substring(0, 16) });
      metricsCollector.recordRequest(Date.now() - startTime, false);

      return new NextResponse(new Uint8Array(buffer), {
        headers: {
          'Content-Type': sample.mimeType || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${sample.originalFilename}"`,
          'X-Request-Id': requestId,
          ...createRateLimitHeaders(rateLimit)
        }
      });
    }

    // Otherwise, generate pre-signed download URL
    const db = loadDB();
    const sample = db.samples.find(s => s.sha256 === id || s.sha1 === id || s.id === id);
    const cassandraScans = cassandraStore.getFileScansBySha256(id);

    if (!sample && cassandraScans.length === 0) {
      return NextResponse.json({ error: 'File not found' }, { status: 404, headers: { 'X-Request-Id': requestId } });
    }

    const downloadToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 3600000; // 1 hour

    DOWNLOAD_TOKENS.set(downloadToken, {
      sha256: id,
      expires: expiresAt,
      requestId
    });

    // Cleanup expired
    for (const [key, data] of DOWNLOAD_TOKENS) {
      if (Date.now() > data.expires) DOWNLOAD_TOKENS.delete(key);
    }

    const downloadUrl = `/api/files/${id}/download?token=${downloadToken}&requestId=${requestId}`;

    logger.info(requestId, 'api/files/download', `Generated pre-signed download URL for ${id.substring(0, 16)}`, { sha256: id.substring(0, 16) });
    metricsCollector.recordRequest(Date.now() - startTime, false);

    return NextResponse.json({
      downloadUrl,
      token: downloadToken,
      expiresAt: new Date(expiresAt).toISOString(),
      sha256: id,
      filename: sample?.originalFilename || cassandraScans[0]?.fileMetadata.fileNames[0] || id,
      size: sample?.fileSize || cassandraScans[0]?.fileMetadata.fileSize || 0,
      message: 'Use downloadUrl to download file content - pre-signed URL valid for 1 hour'
    }, { headers: { 'X-Request-Id': requestId, ...createRateLimitHeaders(rateLimit) } });

  } catch (e) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.error(requestId, 'api/files/download', 'Download failed', e as Error);
    return NextResponse.json({ error: 'Download failed' }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}
