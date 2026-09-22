/**
 * MCK-Guard Observability Metrics - VirusTotal System Design
 * Datadog APM style metrics for API, workers, DB
 */

export interface APIMetrics {
  cpu: number;
  memory: number;
  requestsPerSecond: number;
  requestLatency: { p50: number; p95: number; p99: number; avg: number };
  requestErrors: number;
  totalRequests: number;
  timestamp: string;
}

export interface WorkerMetrics {
  name: string;
  cpu: number;
  memory: number;
  completedScans: number;
  failedScans: number;
  dlqSize: number;
  delayBeforeScanning: number; // ms - for KEDA scaling
  executionTime: { avg: number; p95: number; max: number };
  scannedFileSize: { avg: number; total: number };
  timestamp: string;
}

export interface DBMetrics {
  cpu: number;
  memory: number;
  ioWait: number;
  diskUtilization: number;
  connections: number;
  readLatency: number;
  writeLatency: number;
  timestamp: string;
}

class MetricsCollector {
  private apiMetrics: APIMetrics[] = [];
  private workerMetrics = new Map<string, WorkerMetrics[]>();
  private dbMetrics: DBMetrics[] = [];
  private requestLatencies: number[] = [];
  private requestCount = 0;
  private errorCount = 0;
  private startTime = Date.now();

  // API Server Metrics
  recordRequest(latencyMs: number, isError: boolean = false) {
    this.requestCount++;
    this.requestLatencies.push(latencyMs);
    if (this.requestLatencies.length > 1000) {
      this.requestLatencies = this.requestLatencies.slice(-1000);
    }
    if (isError) this.errorCount++;

    // Calculate metrics every 100 requests
    if (this.requestCount % 100 === 0) {
      this.calculateAPIMetrics();
    }
  }

  private calculateAPIMetrics() {
    const sorted = [...this.requestLatencies].sort((a, b) => a - b);
    const avg = sorted.reduce((a, b) => a + b, 0) / sorted.length || 0;
    const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
    const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
    const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;

    const elapsedSec = (Date.now() - this.startTime) / 1000;
    const rps = this.requestCount / elapsedSec;

    const metric: APIMetrics = {
      cpu: Math.random() * 30 + 10, // Simulated - in real would use os.cpus()
      memory: Math.random() * 20 + 40,
      requestsPerSecond: Math.round(rps * 100) / 100,
      requestLatency: { p50: Math.round(p50), p95: Math.round(p95), p99: Math.round(p99), avg: Math.round(avg) },
      requestErrors: this.errorCount,
      totalRequests: this.requestCount,
      timestamp: new Date().toISOString()
    };

    this.apiMetrics.push(metric);
    if (this.apiMetrics.length > 100) this.apiMetrics = this.apiMetrics.slice(-100);
  }

  getAPIMetrics(): APIMetrics | null {
    if (this.apiMetrics.length === 0) this.calculateAPIMetrics();
    return this.apiMetrics[this.apiMetrics.length - 1] || null;
  }

  // Worker Metrics
  recordWorkerCompletion(workerName: string, executionTimeMs: number, fileSize: number, success: boolean) {
    if (!this.workerMetrics.has(workerName)) {
      this.workerMetrics.set(workerName, []);
    }

    const metrics = this.workerMetrics.get(workerName)!;
    const last = metrics[metrics.length - 1];

    const newMetric: WorkerMetrics = {
      name: workerName,
      cpu: Math.random() * 40 + 20,
      memory: Math.random() * 30 + 30,
      completedScans: (last?.completedScans || 0) + (success ? 1 : 0),
      failedScans: (last?.failedScans || 0) + (success ? 0 : 1),
      dlqSize: last?.dlqSize || 0,
      delayBeforeScanning: Math.random() * 5000, // Simulated queue delay
      executionTime: {
        avg: last ? Math.round((last.executionTime.avg * last.completedScans + executionTimeMs) / (last.completedScans + 1)) : executionTimeMs,
        p95: Math.max(last?.executionTime.p95 || 0, executionTimeMs),
        max: Math.max(last?.executionTime.max || 0, executionTimeMs)
      },
      scannedFileSize: {
        avg: last ? Math.round((last.scannedFileSize.avg * last.completedScans + fileSize) / (last.completedScans + 1)) : fileSize,
        total: (last?.scannedFileSize.total || 0) + fileSize
      },
      timestamp: new Date().toISOString()
    };

    metrics.push(newMetric);
    if (metrics.length > 100) metrics.splice(0, metrics.length - 100);
  }

  updateWorkerDLQ(workerName: string, dlqSize: number) {
    const metrics = this.workerMetrics.get(workerName);
    if (metrics && metrics.length > 0) {
      metrics[metrics.length - 1].dlqSize = dlqSize;
    }
  }

  updateWorkerDelay(workerName: string, delayMs: number) {
    const metrics = this.workerMetrics.get(workerName);
    if (metrics && metrics.length > 0) {
      metrics[metrics.length - 1].delayBeforeScanning = delayMs;
    }
  }

  getWorkerMetrics(workerName?: string): WorkerMetrics[] | WorkerMetrics | null {
    if (workerName) {
      const m = this.workerMetrics.get(workerName);
      return m ? m[m.length - 1] : null;
    }
    const all: WorkerMetrics[] = [];
    for (const [, metrics] of this.workerMetrics) {
      if (metrics.length > 0) all.push(metrics[metrics.length - 1]);
    }
    return all;
  }

  // DB Metrics
  recordDBMetrics(metrics: Partial<DBMetrics>) {
    const dbMetric: DBMetrics = {
      cpu: metrics.cpu || Math.random() * 20 + 10,
      memory: metrics.memory || Math.random() * 20 + 50,
      ioWait: metrics.ioWait || Math.random() * 10,
      diskUtilization: metrics.diskUtilization || Math.random() * 30 + 20,
      connections: metrics.connections || Math.floor(Math.random() * 50 + 10),
      readLatency: metrics.readLatency || Math.random() * 20 + 5,
      writeLatency: metrics.writeLatency || Math.random() * 30 + 10,
      timestamp: new Date().toISOString()
    };
    this.dbMetrics.push(dbMetric);
    if (this.dbMetrics.length > 100) this.dbMetrics = this.dbMetrics.slice(-100);
  }

  getDBMetrics(): DBMetrics | null {
    return this.dbMetrics[this.dbMetrics.length - 1] || null;
  }

  getAllMetrics() {
    return {
      api: this.getAPIMetrics(),
      workers: this.getWorkerMetrics() as WorkerMetrics[],
      db: this.getDBMetrics(),
      summary: {
        totalRequests: this.requestCount,
        totalErrors: this.errorCount,
        errorRate: this.requestCount > 0 ? (this.errorCount / this.requestCount * 100).toFixed(2) + '%' : '0%',
        uptime: Math.floor((Date.now() - this.startTime) / 1000) + 's',
        avgLatency: this.requestLatencies.length > 0 ? Math.round(this.requestLatencies.reduce((a, b) => a + b, 0) / this.requestLatencies.length) + 'ms' : '0ms'
      }
    };
  }

  // KEDA scaling triggers
  getScalingMetrics() {
    const workers = this.getWorkerMetrics() as WorkerMetrics[];
    const api = this.getAPIMetrics();

    return {
      api: {
        cpu: api?.cpu || 0,
        shouldScale: (api?.cpu || 0) > 70 || (api?.requestsPerSecond || 0) > 100
      },
      workers: workers.map(w => ({
        name: w.name,
        delayBeforeProcessing: w.delayBeforeScanning,
        shouldScale: w.delayBeforeScanning > 5000 || w.dlqSize > 50,
        queueLength: w.dlqSize + w.completedScans
      }))
    };
  }
}

export const metricsCollector = new MetricsCollector();
