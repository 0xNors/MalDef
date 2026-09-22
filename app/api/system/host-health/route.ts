export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

function getCpuUsage() {
  const cpus = os.cpus();
  let totalIdle = 0, totalTick = 0;
  cpus.forEach(cpu => {
    for (const type in cpu.times) {
      totalTick += (cpu.times as any)[type];
    }
    totalIdle += cpu.times.idle;
  });
  const idle = totalIdle / cpus.length;
  const total = totalTick / cpus.length;
  return { idle, total, usage: Math.round(100 - (100 * idle / total)), cores: cpus.length, model: cpus[0]?.model || 'Unknown', speed: cpus[0]?.speed || 0 };
}

function getDiskUsage() {
  try {
    const dataDir = path.join(process.cwd(), 'data');
    let totalSize = 0, fileCount = 0;
    const getDirSize = (dir: string): number => {
      try {
        let size = 0;
        const files = fs.readdirSync(dir);
        for (const f of files) {
          try {
            const fp = path.join(dir, f);
            const stat = fs.statSync(fp);
            if (stat.isDirectory()) size += getDirSize(fp);
            else { size += stat.size; fileCount++; }
          } catch {}
        }
        return size;
      } catch { return 0; }
    };
    if (fs.existsSync(dataDir)) totalSize = getDirSize(dataDir);

    // Try to get real disk usage via df (linux) or wmic (win)
    let diskTotal = 0, diskFree = 0, diskUsed = 0;
    try {
      if (os.platform() !== 'win32') {
        const out = execSync('df -k / 2>/dev/null | tail -1', { encoding: 'utf8' });
        const parts = out.trim().split(/\s+/);
        if (parts.length >= 4) {
          diskTotal = parseInt(parts[1]) * 1024;
          diskUsed = parseInt(parts[2]) * 1024;
          diskFree = parseInt(parts[3]) * 1024;
        }
      }
    } catch {}

    return { dataDirSize: totalSize, dataFileCount: fileCount, diskTotal, diskFree, diskUsed, diskUsagePercent: diskTotal ? Math.round((diskUsed / diskTotal) * 100) : 0 };
  } catch {
    return { dataDirSize: 0, dataFileCount: 0, diskTotal: 0, diskFree: 0, diskUsed: 0, diskUsagePercent: 0 };
  }
}

function getInternalFilesHealth() {
  const base = path.join(process.cwd(), 'data');
  const checks = [
    { name: 'Database', path: path.join(base, 'database.json'), critical: true },
    { name: 'Samples Storage', path: path.join(base, 'samples'), critical: false },
    { name: 'Quarantine', path: path.join(base, 'quarantine'), critical: false },
    { name: 'Reports', path: path.join(base, 'reports'), critical: false },
    { name: 'Telemetry', path: path.join(base, 'telemetry'), critical: false },
    { name: 'Datasets', path: path.join(base, 'datasets'), critical: false },
    { name: 'Cassandra Cache', path: path.join(base, 'cassandra'), critical: false },
    { name: 'MITRE Cache', path: path.join(base, 'mitre'), critical: false },
  ];

  return checks.map(c => {
    try {
      const exists = fs.existsSync(c.path);
      let size = 0, files = 0, readable = false, writable = false;
      if (exists) {
        const stat = fs.statSync(c.path);
        if (stat.isDirectory()) {
          const items = fs.readdirSync(c.path);
          files = items.length;
          size = items.reduce((s, f) => {
            try { return s + fs.statSync(path.join(c.path, f)).size; } catch { return s; }
          }, 0);
        } else {
          size = stat.size;
          files = 1;
        }
        try { fs.accessSync(c.path, fs.constants.R_OK); readable = true; } catch {}
        try { fs.accessSync(c.path, fs.constants.W_OK); writable = true; } catch {}
      }
      const healthy = exists && readable && writable;
      return {
        name: c.name,
        path: c.path.replace(process.cwd(), '.'),
        exists,
        healthy,
        critical: c.critical,
        size,
        files,
        readable,
        writable,
        status: !exists ? 'MISSING' : !healthy ? 'DEGRADED' : 'HEALTHY',
      };
    } catch (e: any) {
      return { name: c.name, path: c.path, exists: false, healthy: false, critical: c.critical, size: 0, files: 0, readable: false, writable: false, status: 'ERROR', error: e.message };
    }
  });
}

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const cpu = getCpuUsage();
  const memTotal = os.totalmem();
  const memFree = os.freemem();
  const memUsed = memTotal - memFree;
  const memUsage = Math.round((memUsed / memTotal) * 100);

  const disk = getDiskUsage();
  const internalFiles = getInternalFilesHealth();

  const uptime = os.uptime();
  const uptimeHours = Math.floor(uptime / 3600);
  const uptimeDays = Math.floor(uptimeHours / 24);

  const loadAvg = os.loadavg();
  const network = Object.entries(os.networkInterfaces()).map(([name, addrs]) => ({
    name,
    addresses: (addrs || []).map(a => ({ address: a.address, family: a.family, mac: a.mac, internal: a.internal })),
  })).filter(n => n.addresses.length > 0);

  const processMem = process.memoryUsage();
  const processUptime = process.uptime();

  // Health score
  let healthScore = 100;
  const issues: string[] = [];
  if (memUsage > 85) { healthScore -= 20; issues.push(`High memory usage ${memUsage}%`); }
  if (cpu.usage > 80) { healthScore -= 15; issues.push(`High CPU usage ${cpu.usage}%`); }
  if (disk.diskUsagePercent > 85) { healthScore -= 25; issues.push(`Low disk space ${disk.diskUsagePercent}% used`); }
  const unhealthyCritical = internalFiles.filter(f => f.critical && !f.healthy);
  if (unhealthyCritical.length > 0) { healthScore -= 30; issues.push(`Critical internal files unhealthy: ${unhealthyCritical.map(f => f.name).join(', ')}`); }
  if (healthScore < 0) healthScore = 0;

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    host: {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      release: os.release(),
      type: os.type(),
      uptime,
      uptimeFormatted: `${uptimeDays}d ${uptimeHours % 24}h ${Math.floor((uptime % 3600) / 60)}m`,
      loadAvg,
      nodeVersion: process.version,
      user: os.userInfo().username,
    },
    cpu: {
      ...cpu,
      loadAvg,
      status: cpu.usage > 80 ? 'HIGH' : cpu.usage > 60 ? 'MEDIUM' : 'HEALTHY',
    },
    memory: {
      total: memTotal,
      free: memFree,
      used: memUsed,
      usagePercent: memUsage,
      totalGb: (memTotal / 1024 / 1024 / 1024).toFixed(2),
      freeGb: (memFree / 1024 / 1024 / 1024).toFixed(2),
      usedGb: (memUsed / 1024 / 1024 / 1024).toFixed(2),
      status: memUsage > 85 ? 'CRITICAL' : memUsage > 70 ? 'WARNING' : 'HEALTHY',
    },
    disk: {
      ...disk,
      totalGb: disk.diskTotal ? (disk.diskTotal / 1024 / 1024 / 1024).toFixed(2) : 'N/A',
      freeGb: disk.diskFree ? (disk.diskFree / 1024 / 1024 / 1024).toFixed(2) : 'N/A',
      usedGb: disk.diskUsed ? (disk.diskUsed / 1024 / 1024 / 1024).toFixed(2) : 'N/A',
      dataDirSizeMb: (disk.dataDirSize / 1024 / 1024).toFixed(2),
      status: disk.diskUsagePercent > 85 ? 'CRITICAL' : disk.diskUsagePercent > 70 ? 'WARNING' : 'HEALTHY',
    },
    network: {
      interfaces: network,
      totalInterfaces: network.length,
    },
    process: {
      pid: process.pid,
      uptime: processUptime,
      uptimeFormatted: `${Math.floor(processUptime / 3600)}h ${Math.floor((processUptime % 3600) / 60)}m`,
      memory: {
        rss: processMem.rss,
        heapTotal: processMem.heapTotal,
        heapUsed: processMem.heapUsed,
        external: processMem.external,
        rssMb: (processMem.rss / 1024 / 1024).toFixed(2),
        heapUsedMb: (processMem.heapUsed / 1024 / 1024).toFixed(2),
      },
      versions: process.versions,
    },
    internalFiles: {
      files: internalFiles,
      healthyCount: internalFiles.filter(f => f.healthy).length,
      totalCount: internalFiles.length,
      criticalHealthy: internalFiles.filter(f => f.critical && f.healthy).length,
      criticalTotal: internalFiles.filter(f => f.critical).length,
      status: unhealthyCritical.length > 0 ? 'CRITICAL' : internalFiles.some(f => !f.healthy) ? 'WARNING' : 'HEALTHY',
    },
    healthScore,
    issues,
    overallStatus: healthScore >= 80 ? 'HEALTHY' : healthScore >= 50 ? 'WARNING' : 'CRITICAL',
  });
}
