/**
 * MCK-Guard File Blob Cache - VirusTotal System Design
 * AWS Elasticache (Redis) simulation: in-memory blob store for faster file download by workers
 * Lambda loads file content into blob store for faster worker access
 */

interface CacheEntry {
  data: Buffer;
  sha256: string;
  size: number;
  createdAt: number;
  lastAccess: number;
  accessCount: number;
  ttl: number; // ms
}

class BlobCache {
  private cache = new Map<string, CacheEntry>();
  private maxSize: number; // bytes
  private currentSize = 0;
  private maxEntries: number;
  private defaultTtl: number;

  constructor(maxSizeMb = 500, maxEntries = 1000, defaultTtlMs = 3600000) {
    this.maxSize = maxSizeMb * 1024 * 1024;
    this.maxEntries = maxEntries;
    this.defaultTtl = defaultTtlMs;

    // Cleanup expired entries every minute
    if (typeof setInterval !== 'undefined') {
      setInterval(() => this.cleanup(), 60000);
    }
  }

  // Get file content from cache (fast path for workers)
  get(sha256: string): Buffer | null {
    const entry = this.cache.get(sha256);
    if (!entry) return null;

    const now = Date.now();
    if (now - entry.createdAt > entry.ttl) {
      this.delete(sha256);
      return null;
    }

    entry.lastAccess = now;
    entry.accessCount++;
    return entry.data;
  }

  // Set file content (Lambda loads file into cache after S3 upload)
  set(sha256: string, data: Buffer, ttlMs?: number): boolean {
    const size = data.length;
    
    // Don't cache if too large (>100MB)
    if (size > 100 * 1024 * 1024) return false;

    // Evict if needed
    while (this.currentSize + size > this.maxSize || this.cache.size >= this.maxEntries) {
      if (!this.evictLRU()) break;
    }

    if (this.currentSize + size > this.maxSize) return false;

    const existing = this.cache.get(sha256);
    if (existing) {
      this.currentSize -= existing.size;
    }

    this.cache.set(sha256, {
      data,
      sha256,
      size,
      createdAt: Date.now(),
      lastAccess: Date.now(),
      accessCount: 0,
      ttl: ttlMs || this.defaultTtl
    });

    this.currentSize += size;
    return true;
  }

  delete(sha256: string): boolean {
    const entry = this.cache.get(sha256);
    if (!entry) return false;
    this.currentSize -= entry.size;
    this.cache.delete(sha256);
    return true;
  }

  has(sha256: string): boolean {
    const entry = this.cache.get(sha256);
    if (!entry) return false;
    if (Date.now() - entry.createdAt > entry.ttl) {
      this.delete(sha256);
      return false;
    }
    return true;
  }

  private evictLRU(): boolean {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.lastAccess < oldestTime) {
        oldestTime = entry.lastAccess;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.delete(oldestKey);
      return true;
    }
    return false;
  }

  private cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (now - entry.createdAt > entry.ttl) {
        this.delete(key);
      }
    }
  }

  getStats() {
    return {
      entries: this.cache.size,
      currentSize: this.currentSize,
      currentSizeMb: Math.round(this.currentSize / 1024 / 1024 * 100) / 100,
      maxSizeMb: this.maxSize / 1024 / 1024,
      maxEntries: this.maxEntries,
      hitRate: this.cache.size > 0 ? Array.from(this.cache.values()).reduce((sum, e) => sum + e.accessCount, 0) / this.cache.size : 0,
      entriesDetail: Array.from(this.cache.values()).map(e => ({
        sha256: e.sha256.substring(0, 16) + '...',
        size: e.size,
        ageMs: Date.now() - e.createdAt,
        accessCount: e.accessCount
      }))
    };
  }

  clear() {
    this.cache.clear();
    this.currentSize = 0;
  }
}

// Singleton - Redis compliant cache
export const blobCache = new BlobCache(500, 1000, 3600000);

// File cache schema per VirusTotal design
export const fileCacheSchema = {
  key: 'SHA256 Hash',
  value: 'Blob',
  ttl: '1 hour',
  maxSize: '500MB',
  eviction: 'LRU'
};
