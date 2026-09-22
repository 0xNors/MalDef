/**
 * MCK-Guard Strict Rate Limiting - VirusTotal System Design
 * Implements: Token Bucket, Leaky Bucket, Sliding Window
 * Tiers: Guest, User, API Token, Service Tier based on file size
 */

export interface RateLimitConfig {
  guest: { requests: number; windowMs: number; bucketSize: number };
  user: { requests: number; windowMs: number; bucketSize: number };
  apiToken: { requests: number; windowMs: number; bucketSize: number };
  fileSize: { small: number; medium: number; large: number; maxSize: number }; // bytes
}

const DEFAULT_CONFIG: RateLimitConfig = {
  guest: { requests: 10, windowMs: 60000, bucketSize: 20 }, // 10 req/min
  user: { requests: 100, windowMs: 60000, bucketSize: 200 }, // 100 req/min
  apiToken: { requests: 1000, windowMs: 60000, bucketSize: 2000 }, // 1000 req/min
  fileSize: { small: 10 * 1024 * 1024, medium: 100 * 1024 * 1024, large: 1024 * 1024 * 1024, maxSize: 1024 * 1024 * 1024 } // 1GB max
};

interface TokenBucket {
  tokens: number;
  lastRefill: number;
  capacity: number;
  refillRate: number; // tokens per ms
}

interface SlidingWindowLog {
  timestamps: number[];
  windowMs: number;
  maxRequests: number;
}

interface LeakyBucket {
  queue: number[];
  leakRate: number; // requests per ms
  capacity: number;
  lastLeak: number;
}

class RateLimiterStore {
  private tokenBuckets = new Map<string, TokenBucket>();
  private slidingWindows = new Map<string, SlidingWindowLog>();
  private leakyBuckets = new Map<string, LeakyBucket>();
  private fileSizeBuckets = new Map<string, { count: number; totalSize: number; windowStart: number }>();

  // Token Bucket: burst + sustained rate
  checkTokenBucket(key: string, config: { requests: number; windowMs: number; bucketSize: number }): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    let bucket = this.tokenBuckets.get(key);
    
    if (!bucket) {
      bucket = {
        tokens: config.bucketSize,
        lastRefill: now,
        capacity: config.bucketSize,
        refillRate: config.requests / config.windowMs
      };
      this.tokenBuckets.set(key, bucket);
    }

    // Refill tokens
    const elapsed = now - bucket.lastRefill;
    const refill = elapsed * bucket.refillRate;
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + refill);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, remaining: Math.floor(bucket.tokens), resetMs: Math.ceil((1 - bucket.tokens) / bucket.refillRate) };
    }

    const needed = 1 - bucket.tokens;
    const waitMs = Math.ceil(needed / bucket.refillRate);
    return { allowed: false, remaining: 0, resetMs: waitMs };
  }

  // Sliding Window: precise rate limiting
  checkSlidingWindow(key: string, config: { requests: number; windowMs: number }): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    let window = this.slidingWindows.get(key);

    if (!window) {
      window = { timestamps: [], windowMs: config.windowMs, maxRequests: config.requests };
      this.slidingWindows.set(key, window);
    }

    // Remove old entries
    window.timestamps = window.timestamps.filter(t => now - t < window.windowMs);

    if (window.timestamps.length < window.maxRequests) {
      window.timestamps.push(now);
      return { allowed: true, remaining: window.maxRequests - window.timestamps.length, resetMs: window.windowMs };
    }

    const oldest = window.timestamps[0];
    const resetMs = window.windowMs - (now - oldest);
    return { allowed: false, remaining: 0, resetMs: Math.max(0, resetMs) };
  }

  // Leaky Bucket: smooth out bursts
  checkLeakyBucket(key: string, config: { requests: number; windowMs: number; bucketSize: number }): { allowed: boolean; remaining: number; resetMs: number } {
    const now = Date.now();
    let bucket = this.leakyBuckets.get(key);

    if (!bucket) {
      bucket = {
        queue: [],
        leakRate: config.requests / config.windowMs,
        capacity: config.bucketSize,
        lastLeak: now
      };
      this.leakyBuckets.set(key, bucket);
    }

    // Leak
    const elapsed = now - bucket.lastLeak;
    const leaks = Math.floor(elapsed * bucket.leakRate);
    if (leaks > 0) {
      bucket.queue = bucket.queue.slice(leaks);
      bucket.lastLeak = now;
    }

    if (bucket.queue.length < bucket.capacity) {
      bucket.queue.push(now);
      return { allowed: true, remaining: bucket.capacity - bucket.queue.length, resetMs: Math.ceil(bucket.queue.length / bucket.leakRate) };
    }

    return { allowed: false, remaining: 0, resetMs: Math.ceil(bucket.capacity / bucket.leakRate) };
  }

  // File size tier + count limiting
  checkFileUpload(key: string, fileSize: number): { allowed: boolean; reason?: string; tier: string } {
    const now = Date.now();
    const windowMs = 3600000; // 1 hour
    let bucket = this.fileSizeBuckets.get(key);

    if (!bucket) {
      bucket = { count: 0, totalSize: 0, windowStart: now };
      this.fileSizeBuckets.set(key, bucket);
    }

    if (now - bucket.windowStart > windowMs) {
      bucket.count = 0;
      bucket.totalSize = 0;
      bucket.windowStart = now;
    }

    if (fileSize > DEFAULT_CONFIG.fileSize.maxSize) {
      return { allowed: false, reason: `File size ${fileSize} exceeds max ${DEFAULT_CONFIG.fileSize.maxSize} (1GB)`, tier: 'rejected' };
    }

    const tier = fileSize < DEFAULT_CONFIG.fileSize.small ? 'small' : fileSize < DEFAULT_CONFIG.fileSize.medium ? 'medium' : 'large';
    
    // Tier-based limits per hour
    const tierLimits = {
      guest: { count: 10, totalSize: 100 * 1024 * 1024 },
      user: { count: 100, totalSize: 10 * 1024 * 1024 * 1024 },
      apiToken: { count: 1000, totalSize: 100 * 1024 * 1024 * 1024 }
    };

    const userTier = key.startsWith('guest') ? 'guest' : key.startsWith('api') ? 'apiToken' : 'user';
    const limits = tierLimits[userTier as keyof typeof tierLimits];

    if (bucket.count >= limits.count) {
      return { allowed: false, reason: `Upload count limit ${limits.count}/hour exceeded`, tier };
    }

    if (bucket.totalSize + fileSize > limits.totalSize) {
      return { allowed: false, reason: `Total size limit ${limits.totalSize} exceeded`, tier };
    }

    bucket.count++;
    bucket.totalSize += fileSize;

    return { allowed: true, tier };
  }

  // Cleanup old entries
  cleanup() {
    const now = Date.now();
    const maxAge = 3600000; // 1 hour
    for (const [key, bucket] of this.tokenBuckets) {
      if (now - bucket.lastRefill > maxAge) this.tokenBuckets.delete(key);
    }
    for (const [key, window] of this.slidingWindows) {
      window.timestamps = window.timestamps.filter(t => now - t < window.windowMs);
      if (window.timestamps.length === 0 && now - (window.timestamps[window.timestamps.length - 1] || 0) > maxAge) {
        this.slidingWindows.delete(key);
      }
    }
  }
}

const store = new RateLimiterStore();

// Cleanup every 5 minutes
if (typeof setInterval !== 'undefined') {
  setInterval(() => store.cleanup(), 300000);
}

export function getClientTier(req: any): 'guest' | 'user' | 'apiToken' {
  const auth = req.headers.get?.('authorization') || req.headers?.authorization || '';
  if (auth.startsWith('Bearer ') && auth.length > 50) return 'apiToken'; // API token longer
  if (auth) return 'user';
  return 'guest';
}

export function getClientKey(req: any): string {
  const ip = req.headers.get?.('x-forwarded-for') || req.headers?.['x-forwarded-for'] || req.ip || 'unknown';
  const tier = getClientTier(req);
  const userId = req.headers.get?.('x-user-id') || 'anon';
  return `${tier}:${ip}:${userId}`;
}

export function checkRateLimit(req: any, strategy: 'tokenBucket' | 'slidingWindow' | 'leakyBucket' = 'tokenBucket'): { allowed: boolean; remaining: number; resetMs: number; tier: string; limit: number } {
  const key = getClientKey(req);
  const tier = getClientTier(req);
  const config = DEFAULT_CONFIG[tier];

  let result: { allowed: boolean; remaining: number; resetMs: number };

  switch (strategy) {
    case 'slidingWindow':
      result = store.checkSlidingWindow(key, config);
      break;
    case 'leakyBucket':
      result = store.checkLeakyBucket(key, config);
      break;
    case 'tokenBucket':
    default:
      result = store.checkTokenBucket(key, config);
      break;
  }

  return { ...result, tier, limit: config.requests };
}

export function checkFileUploadLimit(req: any, fileSize: number): { allowed: boolean; reason?: string; tier: string } {
  const key = getClientKey(req);
  return store.checkFileUpload(key, fileSize);
}

export function createRateLimitHeaders(result: { allowed: boolean; remaining: number; resetMs: number; tier: string; limit: number }): Record<string, string> {
  return {
    'X-RateLimit-Limit': result.limit.toString(),
    'X-RateLimit-Remaining': result.remaining.toString(),
    'X-RateLimit-Reset': Math.ceil(Date.now() / 1000 + result.resetMs / 1000).toString(),
    'X-RateLimit-Tier': result.tier,
    'Retry-After': result.allowed ? '0' : Math.ceil(result.resetMs / 1000).toString()
  };
}
