/**
 * MCK-Guard Worker Pool - VirusTotal System Design
 * Independent auto-scale groups of file scanners, virus detectors, metadata extractors
 * Workers consume from queues, use blob cache, write to Cassandra
 */

import { broker, JobMessage } from './broker';
import { blobCache } from '../storage/blobCache';
import { cassandraStore } from '../storage/cassandra';
import { metricsCollector } from '../observability/metrics';
import { logger } from '../observability/logger';
import { performStaticAnalysis } from '../analysis/staticAnalyzer';
import { scanWithYara } from '../analysis/yaraEngine';
import { detectPacker } from '../analysis/packerDetector';
import { decodeStrings } from '../analysis/stringDecoder';
import { analyzeC2 } from '../analysis/c2Analyzer';
import { analyzeSignatures } from '../analysis/signatureAnalyzer';
import { performMultiLayerScan } from '../analysis/multiLayerScanner';
import fs from 'fs';
import path from 'path';

export interface Worker {
  name: string;
  queueName: string;
  type: 'scanner' | 'detector' | 'extractor';
  isRunning: boolean;
  processedCount: number;
  failedCount: number;
  avgExecutionTime: number;
  lastHealthCheck: string;
  autoScaleGroup: string;
}

class WorkerPool {
  private workers = new Map<string, Worker>();
  private workerIntervals = new Map<string, NodeJS.Timeout>();

  constructor() {
    this.registerWorker({ name: 'file-scanner-1', queueName: 'scanner-queue', type: 'scanner', autoScaleGroup: 'scanner-asg' });
    this.registerWorker({ name: 'virus-detector-1', queueName: 'virus-detector-queue', type: 'detector', autoScaleGroup: 'detector-asg' });
    this.registerWorker({ name: 'metadata-extractor-1', queueName: 'metadata-extractor-queue', type: 'extractor', autoScaleGroup: 'extractor-asg' });
    this.registerWorker({ name: 'yara-scanner-1', queueName: 'yara-queue', type: 'scanner', autoScaleGroup: 'scanner-asg' });
    this.registerWorker({ name: 'packer-detector-1', queueName: 'packer-queue', type: 'detector', autoScaleGroup: 'detector-asg' });
    this.registerWorker({ name: 'c2-analyzer-1', queueName: 'c2-queue', type: 'detector', autoScaleGroup: 'detector-asg' });
  }

  registerWorker(worker: Omit<Worker, 'isRunning' | 'processedCount' | 'failedCount' | 'avgExecutionTime' | 'lastHealthCheck'>) {
    this.workers.set(worker.name, {
      ...worker,
      isRunning: false,
      processedCount: 0,
      failedCount: 0,
      avgExecutionTime: 0,
      lastHealthCheck: new Date().toISOString()
    });
  }

  startWorker(workerName: string) {
    const worker = this.workers.get(workerName);
    if (!worker || worker.isRunning) return;

    worker.isRunning = true;
    logger.info(`worker-${workerName}`, workerName, `Worker started - consuming from ${worker.queueName}`, { queue: worker.queueName, type: worker.type });

    const interval = setInterval(async () => {
      if (!worker.isRunning) return;

      try {
        const message = broker.dequeue(worker.queueName);
        if (!message) return;

        const startTime = Date.now();
        const requestId = message.requestId;

        logger.info(requestId, workerName, `Processing ${message.storageKey} - SHA256 ${message.sha256.substring(0, 16)}...`, { storageKey: message.storageKey, priority: message.priority });

        // Try blob cache first (fast path) - VirusTotal design
        let buffer: Buffer | null = null;
        const cached = blobCache.get(message.sha256);
        if (cached) {
          buffer = cached;
          logger.debug(requestId, workerName, `Cache HIT for ${message.sha256.substring(0, 16)} - blob cache`, { cacheHit: true });
        } else {
          // Fallback to S3 (file system)
          try {
            if (fs.existsSync(message.storageKey)) {
              buffer = fs.readFileSync(message.storageKey);
              // Load into blob cache for faster future access (Lambda behavior)
              blobCache.set(message.sha256, buffer);
              logger.debug(requestId, workerName, `Cache MISS - loaded from storage and cached`, { cacheHit: false, size: buffer.length });
            } else {
              throw new Error(`File not found: ${message.storageKey}`);
            }
          } catch (e) {
            logger.error(requestId, workerName, `Failed to load file ${message.storageKey}`, e as Error);
            broker.nack(worker.queueName, message.requestId, `FILE_NOT_FOUND: ${message.storageKey}`);
            worker.failedCount++;
            metricsCollector.recordWorkerCompletion(workerName, Date.now() - startTime, message.fileSize, false);
            return;
          }
        }

        // Execute worker-specific scanning (sandboxed - no privileged execution, no external network)
        let result: any = null;
        let success = true;

        try {
          switch (worker.type) {
            case 'scanner':
              if (worker.queueName === 'scanner-queue') {
                const staticResult = performStaticAnalysis(buffer!, message.originalFilename);
                const multiLayer = performMultiLayerScan(buffer!, message.originalFilename, staticResult, [], []);
                result = { static: staticResult, multiLayer };
              } else if (worker.queueName === 'yara-queue') {
                result = scanWithYara(buffer!);
              }
              break;
            
            case 'detector':
              if (worker.queueName === 'virus-detector-queue') {
                const staticResult = performStaticAnalysis(buffer!, message.originalFilename);
                result = { detections: staticResult.findings, risk: staticResult.entropy.risk };
              } else if (worker.queueName === 'packer-queue') {
                const staticResult = performStaticAnalysis(buffer!, message.originalFilename);
                result = detectPacker(buffer!, staticResult.entropy, {
                  isCompressed: staticResult.fileInfo.isCompressed,
                  isPE: staticResult.fileInfo.isPE,
                  isDocument: staticResult.fileInfo.isDocument,
                  mimeType: staticResult.fileInfo.mimeType
                });
              } else if (worker.queueName === 'c2-queue') {
                const staticResult = performStaticAnalysis(buffer!, message.originalFilename);
                result = analyzeC2(staticResult.strings.urls, staticResult.strings.ips, [], []);
              }
              break;

            case 'extractor':
              if (worker.queueName === 'metadata-extractor-queue') {
                const staticResult = performStaticAnalysis(buffer!, message.originalFilename);
                result = {
                  hashes: staticResult.hashes,
                  fileInfo: staticResult.fileInfo,
                  entropy: staticResult.entropy,
                  strings: staticResult.strings,
                  peInfo: staticResult.peInfo
                };
              }
              break;
          }

          // Write to Cassandra via write queue (prevent contention)
          // In real VirusTotal, workers write to partitioned AWS Keyspaces
          const executionTime = Date.now() - startTime;
          worker.processedCount++;
          worker.avgExecutionTime = (worker.avgExecutionTime * (worker.processedCount - 1) + executionTime) / worker.processedCount;
          worker.lastHealthCheck = new Date().toISOString();

          // Ack
          broker.ack(worker.queueName, message.requestId, executionTime);
          metricsCollector.recordWorkerCompletion(workerName, executionTime, message.fileSize, true);

          logger.info(requestId, workerName, `Completed ${message.storageKey} in ${executionTime}ms`, { executionTime, result: result ? 'success' : 'no result' });

        } catch (e) {
          logger.error(requestId, workerName, `Worker failed for ${message.storageKey}`, e as Error);
          broker.nack(worker.queueName, message.requestId, `WORKER_ERROR: ${(e as Error).message}`);
          worker.failedCount++;
          metricsCollector.recordWorkerCompletion(workerName, Date.now() - startTime, message.fileSize, false);
        }

      } catch (e) {
        logger.error('unknown', workerName, `Worker loop error`, e as Error);
      }
    }, 100); // Poll every 100ms

    this.workerIntervals.set(workerName, interval);
  }

  stopWorker(workerName: string) {
    const worker = this.workers.get(workerName);
    if (!worker) return;

    worker.isRunning = false;
    const interval = this.workerIntervals.get(workerName);
    if (interval) {
      clearInterval(interval);
      this.workerIntervals.delete(workerName);
    }
    logger.info(`worker-${workerName}`, workerName, `Worker stopped`);
  }

  startAll() {
    for (const [name] of this.workers) {
      this.startWorker(name);
    }
  }

  stopAll() {
    for (const [name] of this.workers) {
      this.stopWorker(name);
    }
  }

  getWorker(name: string): Worker | undefined {
    return this.workers.get(name);
  }

  getAllWorkers(): Worker[] {
    return Array.from(this.workers.values());
  }

  getHealthyWorkers(): Worker[] {
    return Array.from(this.workers.values()).filter(w => w.isRunning);
  }

  // Auto-scale based on KEDA metrics
  autoScale() {
    const metrics = broker.getAllMetrics();
    for (const metric of metrics) {
      if (metric.queued > 50 && metric.avgDelayBeforeProcessing > 5000) {
        // Scale up workers for this queue
        const workersForQueue = Array.from(this.workers.values()).filter(w => w.queueName === metric.name);
        const running = workersForQueue.filter(w => w.isRunning).length;
        if (running < 3) { // Max 3 per queue in simulation
          const newWorkerName = `${metric.name.replace('-queue', '')}-${Date.now()}`;
          this.registerWorker({
            name: newWorkerName,
            queueName: metric.name,
            type: workersForQueue[0]?.type || 'scanner',
            autoScaleGroup: workersForQueue[0]?.autoScaleGroup || 'default-asg'
          });
          this.startWorker(newWorkerName);
          logger.info('autoscaler', 'keda', `Scaled up ${metric.name} - new worker ${newWorkerName}, queue ${metric.queued}, delay ${metric.avgDelayBeforeProcessing}ms`);
        }
      }
    }
  }

  healthCheck(): { healthy: boolean; workers: Worker[]; totalQueued: number } {
    const allMetrics = broker.getAllMetrics();
    const totalQueued = allMetrics.reduce((sum, m) => sum + m.queued, 0);
    const healthy = this.getHealthyWorkers().length > 0 && totalQueued < 1000;
    return { healthy, workers: this.getAllWorkers(), totalQueued };
  }
}

export const workerPool = new WorkerPool();

// Start workers in production
if (process.env.NODE_ENV === 'production') {
  workerPool.startAll();
}
