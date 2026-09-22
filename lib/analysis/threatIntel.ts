/**
 * MCK-Guard Threat Intel - Stronger detection
 */

export interface ThreatIntelResult {
  reputation: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  riskScore: number;
  findings: any[];
}

export function aggregateThreatIntelSync(urls: string[], ips: string[], hashes: any, suspicious: string[]): ThreatIntelResult {
  const findings: any[] = [];
  let riskScore = 0;
  let reputation: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' = 'BENIGN';

  // Check suspicious strings for threat intel
  if (suspicious.length >= 3) {
    riskScore += Math.min(suspicious.length * 8, 40);
    reputation = suspicious.length >= 5 ? 'MALICIOUS' : 'SUSPICIOUS';
    findings.push({
      category: 'Threat Intel',
      severity: reputation === 'MALICIOUS' ? 'HIGH' : 'MEDIUM',
      title: `Suspicious Patterns: ${suspicious.length}`,
      description: `${suspicious.length} suspicious patterns indicate malicious reputation`,
      evidence: suspicious.slice(0, 2).join(' | ').substring(0, 200),
      score: Math.min(suspicious.length * 8, 40)
    });
  }

  // Check URLs
  if (urls.length > 0) {
    const suspiciousUrls = urls.filter(u => {
      const lower = u.toLowerCase();
      return lower.includes('.tk') || lower.includes('.ml') || /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u) || lower.includes('.exe');
    });
    
    if (suspiciousUrls.length > 0) {
      riskScore += suspiciousUrls.length * 15;
      reputation = 'MALICIOUS';
      findings.push({
        category: 'URL Reputation',
        severity: 'HIGH',
        title: `Malicious URLs: ${suspiciousUrls.length}`,
        description: `${suspiciousUrls.length} URLs with malicious indicators`,
        evidence: suspiciousUrls.slice(0, 2).join(', '),
        score: suspiciousUrls.length * 15
      });
    }
  }

  // Check IPs
  if (ips.length > 0) {
    const externalIps = ips.filter(ip => !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('127.'));
    if (externalIps.length > 0) {
      riskScore += externalIps.length * 10;
      if (reputation === 'BENIGN') reputation = 'SUSPICIOUS';
      findings.push({
        category: 'IP Reputation',
        severity: 'MEDIUM',
        title: `External IPs: ${externalIps.length}`,
        description: `${externalIps.length} external IP addresses`,
        evidence: externalIps.join(', '),
        score: externalIps.length * 10
      });
    }
  }

  return {
    reputation,
    riskScore: Math.min(riskScore, 100),
    findings
  };
}
