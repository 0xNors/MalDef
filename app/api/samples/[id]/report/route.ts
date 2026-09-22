export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

/**
 * A-to-Z Comprehensive Report API
 * Returns full malware analysis from A to Z
 */
export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const sample = db.samples.find(s => s.id === params.id);
  if (!sample) return NextResponse.json({ error: 'Sample not found' }, { status: 404 });

  const analysis = db.analyses.find(a => a.sampleId === sample.id);
  if (!analysis) return NextResponse.json({ error: 'No analysis found' }, { status: 404 });

  const comprehensiveReport = (analysis as any).comprehensiveReport;
  const multiLayer = (analysis as any).multiLayer;
  const yara = (analysis as any).yara;
  const packer = (analysis as any).packer;
  const c2 = (analysis as any).c2;
  const attackChain = (analysis as any).attackChain;

  if (!comprehensiveReport) {
    return NextResponse.json({ 
      error: 'No comprehensive report - re-analyze for A-to-Z',
      hasAnalysis: true,
      hasMultiLayer: !!multiLayer,
      suggestion: 'Run POST /api/samples/[id]/analyze to generate advanced A-to-Z report'
    }, { status: 404 });
  }

  return NextResponse.json({
    sample: {
      id: sample.id,
      filename: sample.originalFilename,
      size: sample.fileSize,
      mimeType: sample.mimeType,
      sha256: sample.sha256,
      sha1: sample.sha1,
      md5: sample.md5,
      uploadTimestamp: sample.uploadTimestamp
    },
    analysis: {
      id: analysis.id,
      timestamp: analysis.timestamp,
      riskScore: analysis.riskScore,
      severity: analysis.severity,
      classification: analysis.classification,
      confidence: analysis.confidence,
      reasons: analysis.reasons,
      recommendations: analysis.recommendations
    },
    comprehensiveReport,
    summary: {
      riskScore: comprehensiveReport.riskAssessment.riskScore,
      severity: comprehensiveReport.riskAssessment.severity,
      classification: comprehensiveReport.riskAssessment.classification,
      confidence: comprehensiveReport.riskAssessment.confidence,
      threatCategories: comprehensiveReport.riskAssessment.threatCategories,
      families: comprehensiveReport.yara.families,
      packer: comprehensiveReport.fileIntelligence.basic.packer,
      isC2: comprehensiveReport.c2Analysis.isC2,
      killChain: comprehensiveReport.attackChain.killChain,
      completeness: comprehensiveReport.attackChain.completeness,
      iocs: comprehensiveReport.iocs.total,
      totalFindings: Object.values(comprehensiveReport.aToZ).filter((v: any) => v.status !== 'clean').length
    },
    aToZ: comprehensiveReport.aToZ
  });
}
