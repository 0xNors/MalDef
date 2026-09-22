export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { broker } from '@/lib/queue/broker';
import { getCurrentUserFromRequest } from '@/lib/auth';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const action = req.nextUrl.searchParams.get('action');
  const storageKey = req.nextUrl.searchParams.get('storageKey');

  if (action === 'dlq' && storageKey) {
    const success = broker.requeueDLQ(storageKey);
    return NextResponse.json({ message: success ? 'Requeued from DLQ' : 'Not found in DLQ', storageKey, success });
  }

  if (action === 'purge') {
    const queueName = req.nextUrl.searchParams.get('queue');
    if (queueName) {
      broker.purgeQueue(queueName);
      return NextResponse.json({ message: `Purged ${queueName}` });
    }
  }

  const metrics = broker.getAllMetrics();
  const dlqMessages = broker.getDLQMessages();

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    queues: metrics,
    dlq: {
      total: dlqMessages.length,
      messages: dlqMessages.slice(0, 20).map(m => ({
        storageKey: m.storageKey,
        sha256: m.sha256.substring(0, 16) + '...',
        retryCount: m.retryCount,
        maxRetries: m.maxRetries,
        priority: m.priority,
        timestamp: m.timestamp,
        fileSize: m.fileSize,
        originalFilename: m.originalFilename
      }))
    },
    design: {
      queueingModel: 'Pub/Sub worker pool - workers consume work from queues, join/leave with no interruptions',
      jobMessage: { storageKey: '...', sha256: '...', sha1: '...', timestamp: '...' },
      worker: 'AV scanner, static analyzer, external API job, etc.',
      faultTolerance: [
        'Failed jobs retried with exponential backoff up to threshold',
        'If retry threshold exceeded, job moves to Dead Letter Exchange',
        'RabbitMQ queues ensure work not lost due to failed scanners',
        'Message TTLs re-task work, DLQ keeps failure queue for recovery',
        'Kubernetes restarts crashed pods via liveness probes',
        'Auto Scale Group adds worker nodes when needed'
      ]
    }
  });
}
