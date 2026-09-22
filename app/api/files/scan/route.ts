export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { checkRateLimit, checkFileUploadLimit, createRateLimitHeaders, getClientTier } from '@/lib/security/rateLimiter';
import { validateUploadRequest } from '@/lib/security/sandbox';
import { generateRequestId, logger } from '@/lib/observability/logger';
import { metricsCollector } from '@/lib/observability/metrics';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';

/**
 * GET /files/scan - Returns pre-signed upload URL to S3 (VirusTotal System Design)
 * VirusTotal: To upload a file for scanning, client must first request a pre-signed upload URL from API
 * Client will then use this pre-signed URL to upload file to S3 object storage
 * Reason: API Gateway and Lambda have low request body limits (~10MB), we want to handle up to 1GB
 */

const UPLOAD_TOKENS = new Map<string, { sha256?: string; expires: number; userId: string; tier: string; requestId: string }>();

export async function GET(req: NextRequest) {
  const startTime = Date.now();
  const requestId = req.headers.get('x-request-id') || generateRequestId();
  
  // Rate limiting - token bucket
  const rateLimit = checkRateLimit(req, 'tokenBucket');
  if (!rateLimit.allowed) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.warn(requestId, 'api/files/scan', 'Rate limit exceeded', { tier: rateLimit.tier, ip: req.headers.get('x-forwarded-for') });
    return NextResponse.json(
      { error: 'Rate limit exceeded', retryAfter: rateLimit.resetMs },
      { status: 429, headers: createRateLimitHeaders(rateLimit) }
    );
  }

  try {
    const user = await getCurrentUserFromRequest(req);
    const tier = getClientTier(req);
    const userId = user?.userId || `guest_${requestId}`;

    // Generate pre-signed upload URL (simulated S3)
    const uploadId = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 3600000; // 1 hour expiry

    // Store upload token
    UPLOAD_TOKENS.set(uploadId, {
      expires: expiresAt,
      userId,
      tier,
      requestId
    });

    // Cleanup expired tokens
    for (const [key, token] of UPLOAD_TOKENS) {
      if (Date.now() > token.expires) UPLOAD_TOKENS.delete(key);
    }

    const uploadUrl = `/api/files/upload?token=${uploadId}&requestId=${requestId}`;
    const downloadUrlTemplate = `/api/files/{id}/download`;

    logger.info(requestId, 'api/files/scan', `Generated pre-signed URL for ${userId} tier ${tier}`, { uploadId: uploadId.substring(0, 16), tier });

    metricsCollector.recordRequest(Date.now() - startTime, false);

    return NextResponse.json(
      {
        uploadUrl,
        uploadId,
        expiresAt: new Date(expiresAt).toISOString(),
        maxSize: 1024 * 1024 * 1024, // 1GB
        allowedTypes: ['*/*'],
        message: 'Use pre-signed URL to upload file directly to storage. After upload, S3 event triggers Lambda which publishes to RabbitMQ.',
        instructions: {
          step1: 'POST file to uploadUrl with multipart/form-data',
          step2: 'S3 event notification triggers Lambda',
          step3: 'Lambda extracts SHA1/SHA256 via GetObjectAttributes and publishes to RabbitMQ broker',
          step4: 'RabbitMQ fans out to worker queues (scanner, virus-detector, metadata-extractor)',
          step5: 'Workers consume and write results to Cassandra (Keyspaces)',
          step6: 'Retrieve results via GET /files/{id}/results with read-through cache'
        },
        security: {
          sandboxing: 'Files quarantined and scanned in isolated environment, no privileged execution',
          rateLimiting: `${tier} tier: ${rateLimit.limit} req/min, remaining ${rateLimit.remaining}`,
          fileValidation: 'Magic bytes, entropy, overlay, path traversal, null byte checks'
        }
      },
      { headers: { ...createRateLimitHeaders(rateLimit), 'X-Request-Id': requestId } }
    );

  } catch (e) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.error(requestId, 'api/files/scan', 'Failed to generate upload URL', e as Error);
    return NextResponse.json({ error: 'Failed to generate upload URL' }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  const requestId = req.headers.get('x-request-id') || generateRequestId();

  const rateLimit = checkRateLimit(req, 'slidingWindow');
  if (!rateLimit.allowed) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    return NextResponse.json({ error: 'Rate limit exceeded' }, { status: 429, headers: createRateLimitHeaders(rateLimit) });
  }

  try {
    const user = await getCurrentUserFromRequest(req);
    const formData = await req.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json({ error: 'File required' }, { status: 400, headers: { 'X-Request-Id': requestId } });
    }

    // File size check per VirusTotal design - skip scanning if exceeds threshold
    const fileSizeCheck = checkFileUploadLimit(req, file.size);
    if (!fileSizeCheck.allowed) {
      logger.warn(requestId, 'api/files/scan', `File upload rejected: ${fileSizeCheck.reason}`, { size: file.size, tier: fileSizeCheck.tier });
      return NextResponse.json({ error: fileSizeCheck.reason, tier: fileSizeCheck.tier }, { status: 413, headers: { 'X-Request-Id': requestId } });
    }

    const validation = validateUploadRequest(file.name, file.size, file.type);
    if (!validation.valid) {
      return NextResponse.json({ error: validation.reason }, { status: 400, headers: { 'X-Request-Id': requestId } });
    }

    // Forward to upload handler
    const uploadDir = path.join(process.cwd(), 'data', 'samples');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

    const buffer = Buffer.from(await file.arrayBuffer());
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
    const safeFilename = `${crypto.randomBytes(16).toString('hex')}_${sha256.substring(0, 8)}_${file.name.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    const filePath = path.join(uploadDir, safeFilename);

    fs.writeFileSync(filePath, buffer);

    logger.info(requestId, 'api/files/scan', `File uploaded via direct POST: ${file.name} -> ${safeFilename}, size ${file.size}, SHA256 ${sha256.substring(0, 16)}`, { fileSize: file.size, sha256: sha256.substring(0, 16) });

    metricsCollector.recordRequest(Date.now() - startTime, false);

    // Simulate S3 event -> Lambda -> RabbitMQ flow
    const { broker, createJobMessage } = await import('@/lib/queue/broker');
    const { blobCache } = await import('@/lib/storage/blobCache');

    // Lambda: extract SHA1/SHA256 via GetObjectAttributes and load into blob cache
    blobCache.set(sha256, buffer);

    const jobMessage = createJobMessage({
      storageKey: filePath,
      sha256,
      sha1,
      fileSize: file.size,
      originalFilename: file.name,
      mimeType: file.type || 'application/octet-stream',
      serviceTier: (user ? 'user' : 'guest') as any,
      priority: file.size < 10 * 1024 * 1024 ? 'HIGH' : 'MEDIUM',
      requestId
    });

    // Publish to RabbitMQ broker which fans out to worker queues
    const published = broker.publish('file-upload-exchange', jobMessage);

    return NextResponse.json(
      {
        message: 'File uploaded successfully - S3 event triggered Lambda, published to RabbitMQ',
        id: sha256,
        sha256,
        sha1,
        md5: crypto.createHash('md5').update(buffer).digest('hex'),
        size: file.size,
        filename: file.name,
        safeFilename,
        uploadId: safeFilename,
        timestamp: new Date().toISOString(),
        job: {
          storageKey: filePath,
          queues: published.queues,
          published: published.published,
          requestId,
          priority: jobMessage.priority
        },
        nextSteps: {
          results: `/api/files/${sha256}/results`,
          scans: `/api/files/${sha256}/scans`,
          download: `/api/files/${sha256}/download`
        }
      },
      { headers: { 'X-Request-Id': requestId, ...createRateLimitHeaders(rateLimit) } }
    );

  } catch (e) {
    metricsCollector.recordRequest(Date.now() - startTime, true);
    logger.error(requestId, 'api/files/scan', 'Upload failed', e as Error);
    return NextResponse.json({ error: 'Upload failed', details: String(e) }, { status: 500, headers: { 'X-Request-Id': requestId } });
  }
}
