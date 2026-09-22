export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';
import { extractFeatures, predict } from '@/lib/ml/model';
import fs from 'fs';
import { performStaticAnalysis } from '@/lib/analysis/staticAnalyzer';
import { calculateCorrelationScore } from '@/lib/analysis/detectionEngine';

export async function POST(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { sampleId } = await req.json();
  if (!sampleId) return NextResponse.json({ error: 'sampleId required' }, { status: 400 });

  const db = loadDB();
  const sample = db.samples.find(s => s.id === sampleId);
  if (!sample) return NextResponse.json({ error: 'Sample not found' }, { status: 404 });

  const behaviorEvents = db.behaviorEvents.filter(e => e.sampleId === sampleId);
  const networkEvents = db.networkEvents.filter(e => e.sampleId === sampleId);

  let staticResult: any = null;
  if (fs.existsSync(sample.filePath)) {
    const buffer = fs.readFileSync(sample.filePath);
    staticResult = performStaticAnalysis(buffer, sample.originalFilename);
  } else {
    const analysis = db.analyses.find(a => a.sampleId === sampleId);
    staticResult = analysis ? { entropy: analysis.entropy, fileInfo: analysis.fileInfo, peInfo: { sections: 4, imports: [], suspiciousImports: [] }, strings: { suspicious: [], urls: [], ips: [] } } : null;
  }

  if (!staticResult) return NextResponse.json({ error: 'No static analysis available' }, { status: 400 });

  const correlationScore = calculateCorrelationScore(
    behaviorEvents.map(e => ({ timestamp: e.timestamp, event_type: e.eventType, process: e.process, parent_process: e.parentProcess })),
    networkEvents.map(e => ({ timestamp: e.timestamp, source_process: e.sourceProcess, destination_ip: e.destinationIp, destination_domain: e.destinationDomain, port: e.port, protocol: e.protocol })),
    staticResult
  );

  const features = extractFeatures(staticResult, behaviorEvents, networkEvents, correlationScore, sample.fileSize);
  const prediction = predict(features);

  return NextResponse.json({ features, prediction });
}
