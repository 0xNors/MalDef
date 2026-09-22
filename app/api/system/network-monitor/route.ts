export const dynamic = 'force-dynamic';
import { NextRequest, NextResponse } from 'next/server';
import { getCurrentUserFromRequest } from '@/lib/auth';
import os from 'os';
import fs from 'fs';
import { execSync } from 'child_process';

let prevNetworkStats: { rx: number; tx: number; time: number } | null = null;

function getNetworkSpeed() {
  try {
    if (os.platform() !== 'win32' && fs.existsSync('/proc/net/dev')) {
      const data = fs.readFileSync('/proc/net/dev', 'utf8');
      const lines = data.split('\n').slice(2);
      let totalRx = 0, totalTx = 0;
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 10) {
          const iface = parts[0].replace(':', '');
          if (iface !== 'lo') {
            totalRx += parseInt(parts[1]) || 0;
            totalTx += parseInt(parts[9]) || 0;
          }
        }
      }
      const now = Date.now();
      let rxSpeed = 0, txSpeed = 0;
      if (prevNetworkStats) {
        const timeDiff = (now - prevNetworkStats.time) / 1000;
        if (timeDiff > 0) {
          rxSpeed = Math.round((totalRx - prevNetworkStats.rx) / timeDiff);
          txSpeed = Math.round((totalTx - prevNetworkStats.tx) / timeDiff);
        }
      }
      prevNetworkStats = { rx: totalRx, tx: totalTx, time: now };
      return {
        totalRx, totalTx,
        rxSpeed, txSpeed,
        rxSpeedFormatted: formatBytes(rxSpeed) + '/s',
        txSpeedFormatted: formatBytes(txSpeed) + '/s',
        totalRxFormatted: formatBytes(totalRx),
        totalTxFormatted: formatBytes(totalTx),
      };
    }
  } catch {}
  return { totalRx: 0, totalTx: 0, rxSpeed: 0, txSpeed: 0, rxSpeedFormatted: 'N/A', txSpeedFormatted: 'N/A', totalRxFormatted: 'N/A', totalTxFormatted: 'N/A' };
}

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getActiveConnections() {
  const connections: any[] = [];
  try {
    if (os.platform() !== 'win32') {
      try {
        const out = execSync('ss -tunap 2>/dev/null | head -n 100', { encoding: 'utf8', timeout: 3000 });
        const lines = out.split('\n').slice(1);
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 5) {
            const state = parts[0];
            const recvQ = parts[1];
            const sendQ = parts[2];
            const local = parts[3];
            const peer = parts[4];
            const proc = parts.slice(5).join(' ');
            connections.push({ state, recvQ, sendQ, local, remote: peer, process: proc, protocol: line.includes('tcp') ? 'TCP' : 'UDP' });
          }
        }
      } catch {
        try {
          const out = execSync('netstat -tunap 2>/dev/null | head -n 100', { encoding: 'utf8', timeout: 3000 });
          const lines = out.split('\n').slice(2);
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 4) {
              connections.push({ protocol: parts[0], recvQ: parts[1], sendQ: parts[2], local: parts[3], remote: parts[4], state: parts[5] || 'UNKNOWN', process: parts.slice(6).join(' ') });
            }
          }
        } catch {}
      }
    }
  } catch {}
  return connections.slice(0, 50);
}

function detectSuspiciousConnections(connections: any[]) {
  const suspiciousPorts = [4444, 5555, 6666, 6667, 8080, 8443, 9001, 9050, 31337, 1337, 1234];
  const suspicious: any[] = [];
  
  for (const conn of connections) {
    const remote = conn.remote || '';
    const local = conn.local || '';
    const remotePort = parseInt(remote.split(':').pop() || '0');
    const localPort = parseInt(local.split(':').pop() || '0');
    
    let reasons: string[] = [];
    let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW' as any;
    
    if (suspiciousPorts.includes(remotePort) || suspiciousPorts.includes(localPort)) {
      reasons.push(`Suspicious port ${remotePort || localPort} (common C2/malware)`);
      severity = 'HIGH';
    }
    if (remote.includes(':') && !remote.startsWith('127.') && !remote.startsWith('10.') && !remote.startsWith('192.168.') && !remote.startsWith('::1') && !remote.startsWith('0.0.0.0')) {
      const ip = remote.split(':')[0];
      if (ip && !ip.startsWith('127.') && conn.state === 'ESTAB') {
        // External connection
        if (remotePort === 443 || remotePort === 80) {
          // Normal web, low
        } else if (remotePort > 1024) {
          reasons.push(`External connection to high port ${remotePort}`);
          if (severity === 'LOW') severity = 'MEDIUM';
        }
      }
    }
    if (conn.state === 'LISTEN' && (localPort < 1024 && localPort !== 80 && localPort !== 443 && localPort !== 22)) {
      reasons.push(`Suspicious listening on privileged port ${localPort}`);
      if (severity === 'LOW') severity = 'MEDIUM';
    }
    
    if (reasons.length > 0) {
      suspicious.push({ ...conn, reasons, severity, riskScore: severity === 'CRITICAL' ? 90 : severity === 'HIGH' ? 70 : severity === 'MEDIUM' ? 40 : 20 });
    }
  }
  
  // Group by remote IP to detect high frequency
  const ipCount = new Map<string, number>();
  for (const c of connections) {
    const ip = (c.remote || '').split(':')[0];
    if (ip) ipCount.set(ip, (ipCount.get(ip) || 0) + 1);
  }
  for (const [ip, count] of ipCount.entries()) {
    if (count > 5 && !ip.startsWith('127.') && !ip.startsWith('10.') && !ip.startsWith('192.168.')) {
      suspicious.push({
        remote: ip,
        local: 'Multiple',
        state: 'MULTIPLE',
        protocol: 'TCP',
        reasons: [`High frequency: ${count} connections to ${ip} (possible C2/beaconing)`],
        severity: 'HIGH' as const,
        riskScore: 75,
        count,
      });
    }
  }
  
  return suspicious;
}

export async function GET(req: NextRequest) {
  const user = await getCurrentUserFromRequest(req);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const speed = getNetworkSpeed();
  const connections = getActiveConnections();
  const suspicious = detectSuspiciousConnections(connections);
  
  const interfaces = Object.entries(os.networkInterfaces()).map(([name, addrs]) => ({
    name,
    addresses: (addrs || []).map(a => ({
      address: a.address,
      netmask: a.netmask,
      family: a.family,
      mac: a.mac,
      internal: a.internal,
      cidr: (a as any).cidr,
    })),
    isInternal: (addrs || []).every(a => a.internal),
    isUp: true,
  }));

  // Packet stats simulation based on speed
  const packetsPerSec = Math.round((speed.rxSpeed + speed.txSpeed) / 1500); // avg packet 1500 bytes
  const totalPackets = Math.round((speed.totalRx + speed.totalTx) / 1500);

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    speed,
    interfaces,
    connections: {
      total: connections.length,
      established: connections.filter(c => c.state === 'ESTAB' || c.state === 'ESTABLISHED').length,
      listening: connections.filter(c => c.state === 'LISTEN').length,
      list: connections,
    },
    suspicious: {
      total: suspicious.length,
      critical: suspicious.filter(s => s.severity === 'CRITICAL').length,
      high: suspicious.filter(s => s.severity === 'HIGH').length,
      medium: suspicious.filter(s => s.severity === 'MEDIUM').length,
      list: suspicious,
    },
    packets: {
      perSecond: packetsPerSec,
      total: totalPackets,
      rxPerSecond: Math.round(speed.rxSpeed / 1500),
      txPerSecond: Math.round(speed.txSpeed / 1500),
    },
    summary: {
      status: suspicious.length > 0 ? (suspicious.some(s => s.severity === 'HIGH' || s.severity === 'CRITICAL') ? 'WARNING' : 'CAUTION') : 'HEALTHY',
      message: suspicious.length === 0 ? 'No suspicious network activity detected' : `${suspicious.length} suspicious connections detected - review required`,
      totalConnections: connections.length,
      suspiciousCount: suspicious.length,
    }
  });
}
