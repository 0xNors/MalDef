export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import { loadDB } from '@/lib/db';

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const db = loadDB();
  const { searchParams } = new URL(req.url);
  const search = searchParams.get('search')?.toLowerCase() || '';
  
  let samples = db.samples;

  if (search) {
    samples = samples.filter(s => 
      s.originalFilename.toLowerCase().includes(search) ||
      s.sha256.toLowerCase().includes(search) ||
      s.sha1.toLowerCase().includes(search) ||
      s.md5.toLowerCase().includes(search) ||
      s.id.toLowerCase().includes(search)
    );
  }

  // Enrich with analysis
  const enriched = samples.map(s => {
    const analysis = db.analyses.find(a => a.sampleId === s.id);
    return { ...s, analysis };
  });

  return NextResponse.json(enriched.slice(0, 100));
}
