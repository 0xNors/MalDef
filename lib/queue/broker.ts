/**
 * MCK-Guard Message Queue Broker - VirusTotal System Design
 * RabbitMQ via Amazon MQ simulation: fan-out, worker queues, TTL, DLQ, retry with exponential backoff, priority
 */

export interface JobMessage {
  storageKey: string;
  sha256: string;
  sha1: string;
  md5?: string;
  timestamp: string;
  fileSize: number;
  originalFilename: string;
  mimeType: string;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; // priority queue support
  retryCount: number;
  maxRetries: number;
  userAgent?: string;
  serviceTier?: 'guest' | 'user' | 'premium';
  requestId: string;
}

export interface QueueConfig {
  name: string;
  durable: boolean;
  maxLength?: number;
  messageTtl?: number; // ms
  deadLetterExchange?: string;
  priority: boolean;
}

export interface WorkerQueue {
  config: QueueConfig;
  messages: JobMessage[];
  processing: Map<string, { message: JobMessage; startTime: number; attempts: number }>;
  dlq: JobMessage[]; // Dead Letter Queue
  metrics: {
    enqueued: number;
    dequeued: number;
    completed: number;
    failed: number;
    dlqCount: number;
    avgProcessingTime: number;
    delayBeforeProcessing: number[]; // for scaling metric
  };
}

class MessageBroker {
  private queues = new Map<string, WorkerQueue>();
  private exchanges = new Map<string, Set<string>>(); // exchange -> queue names (fan-out)
  private retryDelays = [1000, 5000, 15000, 60000, 300000]; // exponential backoff: 1s, 5s, 15s, 1m, 5m

  constructor() {
    // Initialize exchanges and queues per VirusTotal design
    this.createExchange('file-upload-exchange', ['scanner-queue', 'virus-detector-queue', 'metadata-extractor-queue', 'yara-queue', 'packer-queue', 'c2-queue']);
    
    // Worker queues - independent auto-scale groups
    this.createQueue({ name: 'scanner-queue', durable: true, messageTtl: 300000, deadLetterExchange: 'dlq-exchange', priority: true });
    this.createQueue({ name: 'virus-detector-queue', durable: true, messageTtl: 300000, deadLetterExchange: 'dlq-exchange', priority: true });
    this.createQueue({ name: 'metadata-extractor-queue', durable: true, messageTtl: 120000, deadLetterExchange: 'dlq-exchange', priority: false });
    this.createQueue({ name: 'yara-queue', durable: true, messageTtl: 300000, deadLetterExchange: 'dlq-exchange', priority: true });
    this.createQueue({ name: 'packer-queue', durable: true, messageTtl: 120000, deadLetterExchange: 'dlq-exchange', priority: false });
    this.createQueue({ name: 'c2-queue', durable: true, messageTtl: 300000, deadLetterExchange: 'dlq-exchange', priority: true });
    this.createQueue({ name: 'write-queue', durable: true, messageTtl: 60000, deadLetterExchange: 'dlq-exchange', priority: false }); // For DB write contention fix
    this.createQueue({ name: 'dlq-queue', durable: true, priority: false }); // Dead Letter Queue
  }

  createExchange(name: string, queueNames: string[]) {
    this.exchanges.set(name, new Set(queueNames));
  }

  createQueue(config: QueueConfig) {
    this.queues.set(config.name, {
      config,
      messages: [],
      processing: new Map(),
      dlq: [],
      metrics: {
        enqueued: 0,
        dequeued: 0,
        completed: 0,
        failed: 0,
        dlqCount: 0,
        avgProcessingTime: 0,
        delayBeforeProcessing: []
      }
    });
  }

  // Publish to exchange - fan-out to all queues (VirusTotal design)
  publish(exchangeName: string, message: JobMessage): { published: number; queues: string[] } {
    const queueNames = this.exchanges.get(exchangeName);
    if (!queueNames) {
      // Direct to queue if exchange not found
      if (this.queues.has(exchangeName)) {
        this.enqueue(exchangeName, message);
        return { published: 1, queues: [exchangeName] };
      }
      throw new Error(`Exchange ${exchangeName} not found`);
    }

    let count = 0;
    const publishedQueues: string[] = [];
    
    for (const queueName of queueNames) {
      if (this.queues.has(queueName)) {
        // Clone message for each queue with same storageKey but different processing
        const cloned: JobMessage = { ...message, timestamp: new Date().toISOString() };
        this.enqueue(queueName, cloned);
        count++;
        publishedQueues.push(queueName);
      }
    }

    return { published: count, queues: publishedQueues };
  }

  // Enqueue with priority and TTL
  enqueue(queueName: string, message: JobMessage) {
    const queue = this.queues.get(queueName);
    if (!queue) throw new Error(`Queue ${queueName} not found`);

    // Check max length
    if (queue.config.maxLength && queue.messages.length >= queue.config.maxLength) {
      // Move oldest to DLQ if TTL exceeded or queue full
      const oldest = queue.messages.shift();
      if (oldest) {
        queue.dlq.push(oldest);
        queue.metrics.dlqCount++;
      }
    }

    // Priority insertion: CRITICAL first, then HIGH, MEDIUM, LOW
    if (queue.config.priority) {
      const priorityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const insertIndex = queue.messages.findIndex(m => priorityOrder[m.priority] < priorityOrder[message.priority]);
      if (insertIndex === -1) {
        queue.messages.push(message);
      } else {
        queue.messages.splice(insertIndex, 0, message);
      }
    } else {
      queue.messages.push(message);
    }

    queue.metrics.enqueued++;

    // Message TTL handling - auto move to DLQ if expired (simulate)
    if (queue.config.messageTtl) {
      setTimeout(() => {
        const idx = queue.messages.findIndex(m => m.storageKey === message.storageKey && m.requestId === message.requestId);
        if (idx !== -1) {
          const expired = queue.messages.splice(idx, 1)[0];
          if (queue.config.deadLetterExchange) {
            this.moveToDLQ(queueName, expired, 'TTL_EXPIRED');
          }
        }
      }, queue.config.messageTtl);
    }
  }

  // Dequeue for worker consumption (Pub/Sub - workers join/leave with no interruptions)
  dequeue(queueName: string): JobMessage | null {
    const queue = this.queues.get(queueName);
    if (!queue || queue.messages.length === 0) return null;

    const message = queue.messages.shift()!;
    const processingId = `${message.storageKey}:${message.requestId}:${Date.now()}`;
    
    queue.processing.set(processingId, {
      message,
      startTime: Date.now(),
      attempts: message.retryCount
    });

    queue.metrics.dequeued++;
    
    // Track delay before processing (for KEDA scaling metric)
    const delay = Date.now() - new Date(message.timestamp).getTime();
    queue.metrics.delayBeforeProcessing.push(delay);
    if (queue.metrics.delayBeforeProcessing.length > 100) {
      queue.metrics.delayBeforeProcessing = queue.metrics.delayBeforeProcessing.slice(-100);
    }

    // Simulate processing timeout - if not acked, requeue
    setTimeout(() => {
      if (queue.processing.has(processingId)) {
        const proc = queue.processing.get(processingId)!;
        this.handleFailure(queueName, processingId, 'PROCESSING_TIMEOUT');
      }
    }, 120000); // 2 min timeout

    return { ...message, requestId: processingId }; // Use processingId as ack token
  }

  // Ack - successful processing
  ack(queueName: string, processingId: string, processingTimeMs: number) {
    const queue = this.queues.get(queueName);
    if (!queue) return;

    const proc = queue.processing.get(processingId);
    if (proc) {
      queue.processing.delete(processingId);
      queue.metrics.completed++;
      
      // Update avg processing time
      const currentAvg = queue.metrics.avgProcessingTime;
      const completed = queue.metrics.completed;
      queue.metrics.avgProcessingTime = (currentAvg * (completed - 1) + processingTimeMs) / completed;
    }
  }

  // Nack with retry - exponential backoff
  nack(queueName: string, processingId: string, reason: string) {
    this.handleFailure(queueName, processingId, reason);
  }

  private handleFailure(queueName: string, processingId: string, reason: string) {
    const queue = this.queues.get(queueName);
    if (!queue) return;

    const proc = queue.processing.get(processingId);
    if (!proc) return;

    queue.processing.delete(processingId);
    queue.metrics.failed++;

    const message = proc.message;
    
    if (message.retryCount < message.maxRetries) {
      // Retry with exponential backoff
      const delay = this.retryDelays[Math.min(message.retryCount, this.retryDelays.length - 1)];
      const retryMessage: JobMessage = {
        ...message,
        retryCount: message.retryCount + 1,
        timestamp: new Date().toISOString()
      };

      setTimeout(() => {
        this.enqueue(queueName, retryMessage);
      }, delay);

      console.log(`[Broker] Retrying ${message.storageKey} in ${delay}ms (attempt ${retryMessage.retryCount}/${message.maxRetries}) - reason: ${reason}`);
    } else {
      // Move to DLQ after max retries
      this.moveToDLQ(queueName, message, reason);
    }
  }

  private moveToDLQ(queueName: string, message: JobMessage, reason: string) {
    const queue = this.queues.get(queueName);
    if (!queue) return;

    const dlqQueue = this.queues.get('dlq-queue');
    if (dlqQueue) {
      dlqQueue.messages.push({ ...message, timestamp: new Date().toISOString() });
      dlqQueue.metrics.enqueued++;
      dlqQueue.metrics.dlqCount++;
    }

    queue.dlq.push(message);
    queue.metrics.dlqCount++;

    console.log(`[Broker] Moved ${message.storageKey} to DLQ from ${queueName} - reason: ${reason}, retries: ${message.retryCount}`);
  }

  // Metrics for observability and KEDA scaling
  getQueueMetrics(queueName: string) {
    const queue = this.queues.get(queueName);
    if (!queue) return null;

    const avgDelay = queue.metrics.delayBeforeProcessing.length > 0
      ? queue.metrics.delayBeforeProcessing.reduce((a, b) => a + b, 0) / queue.metrics.delayBeforeProcessing.length
      : 0;

    return {
      name: queueName,
      queued: queue.messages.length,
      processing: queue.processing.size,
      dlq: queue.dlq.length,
      enqueued: queue.metrics.enqueued,
      dequeued: queue.metrics.dequeued,
      completed: queue.metrics.completed,
      failed: queue.metrics.failed,
      dlqCount: queue.metrics.dlqCount,
      avgProcessingTime: Math.round(queue.metrics.avgProcessingTime),
      avgDelayBeforeProcessing: Math.round(avgDelay),
      isHealthy: queue.messages.length < 1000 && queue.dlq.length < 100
    };
  }

  getAllMetrics() {
    const metrics: any[] = [];
    for (const [name] of this.queues) {
      const m = this.getQueueMetrics(name);
      if (m) metrics.push(m);
    }
    return metrics;
  }

  // For testing and recovery
  getDLQMessages(queueName: string = 'dlq-queue'): JobMessage[] {
    const queue = this.queues.get(queueName);
    return queue ? [...queue.dlq, ...queue.messages] : [];
  }

  requeueDLQ(storageKey: string): boolean {
    const dlq = this.queues.get('dlq-queue');
    if (!dlq) return false;

    const idx = dlq.messages.findIndex(m => m.storageKey === storageKey);
    if (idx === -1) {
      const dlqIdx = dlq.dlq.findIndex(m => m.storageKey === storageKey);
      if (dlqIdx === -1) return false;
      const msg = dlq.dlq.splice(dlqIdx, 1)[0];
      msg.retryCount = 0;
      this.publish('file-upload-exchange', msg);
      return true;
    }

    const msg = dlq.messages.splice(idx, 1)[0];
    msg.retryCount = 0;
    this.publish('file-upload-exchange', msg);
    return true;
  }

  purgeQueue(queueName: string) {
    const queue = this.queues.get(queueName);
    if (queue) {
      queue.messages = [];
      queue.processing.clear();
    }
  }
}

// Singleton broker (managed RabbitMQ via Amazon MQ simulation)
export const broker = new MessageBroker();

export function createJobMessage(params: {
  storageKey: string;
  sha256: string;
  sha1: string;
  md5?: string;
  fileSize: number;
  originalFilename: string;
  mimeType: string;
  userAgent?: string;
  serviceTier?: 'guest' | 'user' | 'premium';
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  requestId?: string;
}): JobMessage {
  // Priority based on service tier and file size (VirusTotal design)
  let priority: JobMessage['priority'] = params.priority || 'MEDIUM';
  if (!params.priority) {
    if (params.serviceTier === 'premium') priority = 'CRITICAL';
    else if (params.fileSize < 10 * 1024 * 1024) priority = 'HIGH'; // Small files first
    else if (params.fileSize > 100 * 1024 * 1024) priority = 'LOW'; // Large files lower priority
  }

  return {
    storageKey: params.storageKey,
    sha256: params.sha256,
    sha1: params.sha1,
    md5: params.md5,
    timestamp: new Date().toISOString(),
    fileSize: params.fileSize,
    originalFilename: params.originalFilename,
    mimeType: params.mimeType,
    priority,
    retryCount: 0,
    maxRetries: 5,
    userAgent: params.userAgent,
    serviceTier: params.serviceTier || 'user',
    requestId: params.requestId || `req_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`
  };
}
