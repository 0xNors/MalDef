export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { metricsCollector } from '@/lib/observability/metrics';
import { broker } from '@/lib/queue/broker';
import { blobCache } from '@/lib/storage/blobCache';
import { cassandraStore } from '@/lib/storage/cassandra';
import { workerPool } from '@/lib/queue/workers';
import { getCurrentUserFromRequest } from '@/lib/auth';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const allMetrics = metricsCollector.getAllMetrics();
  const queueMetrics = broker.getAllMetrics();
  const cacheStats = blobCache.getStats();
  const cassandraStats = cassandraStore.getStats();
  const scalingMetrics = metricsCollector.getScalingMetrics();
  const workerHealth = workerPool.healthCheck();

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    api: allMetrics.api,
    workers: {
      list: allMetrics.workers,
      health: workerHealth,
      pool: workerPool.getAllWorkers().map(w => ({
        name: w.name,
        queue: w.queueName,
        type: w.type,
        isRunning: w.isRunning,
        processed: w.processedCount,
        failed: w.failedCount,
        avgTime: Math.round(w.avgExecutionTime),
        asg: w.autoScaleGroup,
        lastCheck: w.lastHealthCheck
      }))
    },
    queues: queueMetrics,
    cache: {
      blob: cacheStats,
      schema: { key: 'SHA256 Hash', value: 'Blob', ttl: '1 hour', maxSize: '500MB', eviction: 'LRU' }
    },
    cassandra: {
      stats: cassandraStats,
      schema: {
        fileScansTable: { rowId: 'SHA256:Timestamp', partitionKey: 'user_id:SHA256:UnixTimestamp' },
        writeQueue: 'Batched to prevent contention - trade-off: eventual consistency'
      }
    },
    scaling: scalingMetrics,
    summary: allMetrics.summary,
    observability: {
      logging: 'Structured logs with x-request-id correlation for Datadog',
      metrics: 'API, Worker, DB metrics for monitors and auto-scale',
      tracing: 'x-request-id header for distributed tracing',
      alerting: 'Datadog monitors + Pagerduty integration'
    },
    techStack: {
      apiGateway: 'Amazon API Gateway - managed',
      apiServer: 'Golang (Next.js simulation) - simple, fast, web/cloud',
      loadBalancing: 'NGINX - consistent hashing',
      messageQueue: 'RabbitMQ via Amazon MQ - clustering, HA, priority queues, routing',
      compute: 'Kubernetes via Amazon EKS - managed K8s, horizontal scaling',
      storage: 'Cassandra via Amazon Keyspaces - distributed, scalable, replication',
      cache: 'AWS Elasticache (Redis) - fast key-value',
      observability: 'Datadog APM + Pagerduty',
      blobStorage: 'Amazon S3 - object storage',
      autoscaling: 'KEDA - event-driven autoscaler'
    }
  });
}
