export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import fs from 'fs';
import path from 'path';
import { performStaticAnalysis } from '@/lib/analysis/staticAnalyzer';
import { loadDB } from '@/lib/db';

// In-memory scan jobs
const scanJobs = new Map<string, any>();

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function scanDirectory(dir: string, maxFiles = 200, maxDepth = 4, currentDepth = 0, results: any[] = [], scannedPaths = new Set<string>()): any[] {
  if (currentDepth > maxDepth || results.length >= maxFiles) return results;
  if (scannedPaths.has(dir)) return results;
  scannedPaths.add(dir);

  try {
    const items = fs.readdirSync(dir);
    for (const item of items) {
      if (results.length >= maxFiles) break;
      if (item.startsWith('.') && item !== '.env.example') continue;
      if (['node_modules', '.next', '.git', '__pycache__', 'dist', 'build'].includes(item)) continue;

      const fullPath = path.join(dir, item);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          scanDirectory(fullPath, maxFiles, maxDepth, currentDepth + 1, results, scannedPaths);
        } else if (stat.isFile()) {
          if (stat.size > 100 * 1024 * 1024) continue; // skip >100MB
          if (stat.size < 10) continue;
          
          // Only scan interesting file types
          const ext = path.extname(item).toLowerCase();
          const interestingExts = ['.exe', '.dll', '.js', '.ps1', '.bat', '.vbs', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.7z', '.bin', '.dat', '.tmp'];
          const isInteresting = interestingExts.includes(ext) || stat.size < 5 * 1024 * 1024;
          
          if (isInteresting || Math.random() < 0.1) { // sample 10% of other files
            try {
              const buffer = fs.readFileSync(fullPath);
              const analysis = performStaticAnalysis(buffer, item);
              
              const riskScore = Math.round(
                (analysis.entropy.overall * 8) +
                ((analysis.peInfo as any)?.suspiciousImports?.length || 0 * 12) +
                (analysis.strings.suspicious.length * 10) +
                (analysis.strings.urls.length * 5) +
                (analysis.strings.ips.length * 8)
              );
              
              let classification: 'BENIGN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL' = 'BENIGN';
              if (riskScore >= 75) classification = 'CRITICAL';
              else if (riskScore >= 45) classification = 'HIGH_RISK';
              else if (riskScore >= 20) classification = 'SUSPICIOUS';
              
              const isThreat = classification !== 'BENIGN';
              
              results.push({
                path: fullPath.replace(process.cwd(), '.'),
                fullPath,
                filename: item,
                size: stat.size,
                sizeFormatted: formatBytes(stat.size),
                extension: ext,
                entropy: analysis.entropy.overall,
                suspiciousImports: (analysis.peInfo as any)?.suspiciousImports?.length || 0,
                suspiciousStrings: analysis.strings.suspicious.length,
                urls: analysis.strings.urls.length,
                ips: analysis.strings.ips.length,
                riskScore,
                classification,
                isThreat,
                reasons: [
                  ...(analysis.entropy.overall > 7.2 ? [`High entropy ${analysis.entropy.overall.toFixed(2)} (packed)`] : []),
                  ...((analysis.peInfo as any)?.suspiciousImports?.length > 0 ? [`Suspicious imports: ${(analysis.peInfo as any).suspiciousImports.slice(0, 3).join(', ')}`] : []),
                  ...(analysis.strings.suspicious.length > 0 ? [`MCK patterns: ${analysis.strings.suspicious.length}`] : []),
                  ...(analysis.strings.ips.length > 0 ? [`IPs found: ${analysis.strings.ips.length}`] : []),
                  ...(analysis.strings.urls.length > 0 ? [`URLs found: ${analysis.strings.urls.length}`] : []),
                ].slice(0, 3),
                scannedAt: new Date().toISOString(),
              });
            } catch (e: any) {
              results.push({
                path: fullPath.replace(process.cwd(), '.'),
                filename: item,
                size: stat.size,
                sizeFormatted: formatBytes(stat.size),
                error: e.message,
                classification: 'BENIGN',
                isThreat: false,
                riskScore: 0,
              });
            }
          }
        }
      } catch {}
    }
  } catch {}
  return results;
}

export async function POST(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { type = 'quick', customPath, maxFiles = 150 } = await req.json();

  const jobId = `SCAN-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
  const startTime = Date.now();

  scanJobs.set(jobId, { id: jobId, status: 'SCANNING', progress: 0, type, startedAt: new Date().toISOString(), results: [] });

  // Determine scan paths based on type
  let scanPaths: string[] = [];
  const dataDir = path.join(process.cwd(), 'data');
  
  if (type === 'quick') {
    scanPaths = [
      dataDir,
      path.join(process.cwd(), 'uploads'),
      osTmpDir(),
    ].filter(p => fs.existsSync(p));
  } else if (type === 'full') {
    scanPaths = [
      dataDir,
      path.join(process.cwd(), 'uploads'),
      path.join(process.cwd(), 'app'),
      osTmpDir(),
    ].filter(p => fs.existsSync(p));
  } else if (type === 'custom' && customPath) {
    const resolved = path.resolve(customPath);
    if (fs.existsSync(resolved)) scanPaths = [resolved];
    else return NextResponse.json({ error: 'Custom path does not exist' }, { status: 400 });
  } else if (type === 'system') {
    // System critical areas (safe to scan)
    scanPaths = [
      dataDir,
      path.join(process.cwd(), 'uploads'),
      osTmpDir(),
      path.join(os.homedir(), 'Downloads'),
    ].filter(p => fs.existsSync(p));
  }

  // Perform scan synchronously for MVP (with limits)
  let allResults: any[] = [];
  for (const scanPath of scanPaths) {
    const results = scanDirectory(scanPath, Math.floor(maxFiles / scanPaths.length), type === 'full' ? 5 : 3);
    allResults = allResults.concat(results);
    if (allResults.length >= maxFiles) break;
  }

  const threats = allResults.filter(r => r.isThreat);
  const duration = Date.now() - startTime;

  const job = {
    id: jobId,
    status: 'COMPLETED',
    progress: 100,
    type,
    scanPaths,
    startedAt: new Date(scanJobs.get(jobId).startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: duration,
    durationFormatted: `${(duration / 1000).toFixed(1)}s`,
    totalScanned: allResults.length,
    threatsFound: threats.length,
    benignCount: allResults.filter(r => r.classification === 'BENIGN').length,
    suspiciousCount: allResults.filter(r => r.classification === 'SUSPICIOUS').length,
    highRiskCount: allResults.filter(r => r.classification === 'HIGH_RISK').length,
    criticalCount: allResults.filter(r => r.classification === 'CRITICAL').length,
    avgRisk: allResults.length ? Math.round(allResults.reduce((s, r) => s + (r.riskScore || 0), 0) / allResults.length) : 0,
    results: allResults.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)),
    threats: threats.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0)),
    summary: {
      status: threats.length === 0 ? 'CLEAN' : threats.some(t => t.classification === 'CRITICAL') ? 'CRITICAL' : 'INFECTED',
      message: threats.length === 0 ? `PC Clean - ${allResults.length} files scanned, no threats` : `${threats.length} threats found in ${allResults.length} files - ${threats.filter(t => t.classification === 'CRITICAL').length} critical`,
    }
  };

  scanJobs.set(jobId, job);

  // Keep only last 10 jobs
  if (scanJobs.size > 10) {
    const oldest = Array.from(scanJobs.keys())[0];
    scanJobs.delete(oldest);
  }

  return NextResponse.json(job);
}

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const url = new URL(req.url);
  const jobId = url.searchParams.get('jobId');

  if (jobId) {
    const job = scanJobs.get(jobId);
    if (!job) return NextResponse.json({ error: 'Job not found' }, { status: 404 });
    return NextResponse.json(job);
  }

  // List all jobs
  const jobs = Array.from(scanJobs.values()).sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  return NextResponse.json({ jobs, total: jobs.length });
}

function osTmpDir() {
  try {
    return require('os').tmpdir();
  } catch {
    return '/tmp';
  }
}

import os from 'os';
