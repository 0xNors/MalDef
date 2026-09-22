/**
 * MCK-Guard URL Analyzer - Stronger detection, encoded
 */

export interface UrlAnalysisResult {
  totalUrls: number;
  riskScore: number;
  threatCategories: string[];
  urls: {
    url: string;
    risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    reasons: string[];
    category: string;
    score: number;
  }[];
  findings: {
    category: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    description: string;
    evidence: string;
    score: number;
  }[];
  reputation: {
    malicious: number;
    suspicious: number;
    benign: number;
  };
}

export function analyzeUrls(urls: string[]): UrlAnalysisResult {
  if (!urls || urls.length === 0) {
    return {
      totalUrls: 0,
      riskScore: 0,
      threatCategories: [],
      urls: [],
      findings: [],
      reputation: { malicious: 0, suspicious: 0, benign: 0 }
    };
  }

  const analyzed: UrlAnalysisResult['urls'] = [];
  const findings: UrlAnalysisResult['findings'] = [];
  let riskScore = 0;
  const threatCategories: string[] = [];

  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.work', '.click'];
  const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'paypal'];

  urls.forEach(url => {
    const lower = url.toLowerCase();
    const reasons: string[] = [];
    let risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let score = 0;
    let category = 'Benign';

    // Check for IP URL
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      reasons.push('IP address URL - possible C2');
      risk = 'HIGH';
      score = 25;
      category = 'C2';
      threatCategories.push('C2');
    }

    // Suspicious TLD
    if (suspiciousTlds.some(t => lower.includes(t))) {
      reasons.push(`Suspicious TLD ${suspiciousTlds.find(t => lower.includes(t))}`);
      risk = risk === 'LOW' ? 'MEDIUM' : risk;
      score = Math.max(score, 15);
      category = 'Suspicious TLD';
      threatCategories.push('Phishing');
    }

    // Long URL
    if (url.length > 100) {
      reasons.push('Long URL - possible obfuscation');
      score = Math.max(score, 10);
      if (risk === 'LOW') risk = 'MEDIUM';
    }

    // Executable in URL
    if (lower.includes('.exe') || lower.includes('.dll') || lower.includes('.ps1') || lower.includes('.bat')) {
      reasons.push('Executable file in URL - possible payload');
      risk = 'CRITICAL';
      score = Math.max(score, 35);
      category = 'Payload Delivery';
      threatCategories.push('Malware');
    }

    // Phishing keywords with login
    if (suspiciousKeywords.some(k => lower.includes(k)) && (lower.includes('login') || lower.includes('verify'))) {
      reasons.push('Phishing pattern - login/verify keywords');
      risk = risk === 'LOW' ? 'MEDIUM' : risk;
      score = Math.max(score, 20);
      category = 'Phishing';
      threatCategories.push('Phishing');
    }

    // URL shortener
    if (lower.includes('bit.ly') || lower.includes('tinyurl') || lower.includes('t.me')) {
      reasons.push('URL shortener - possible obfuscation');
      score = Math.max(score, 10);
      if (risk === 'LOW') risk = 'MEDIUM';
    }

    // If no reasons, benign
    if (reasons.length === 0) {
      reasons.push('Clean URL');
      category = 'Benign';
    }

    analyzed.push({ url, risk, reasons, category, score });
    riskScore += score;

    if (risk === 'HIGH' || risk === 'CRITICAL') {
      findings.push({
        category: 'URL Reputation',
        severity: risk,
        title: `Malicious URL: ${category}`,
        description: `${reasons.join(', ')} - ${url.substring(0, 80)}`,
        evidence: url,
        score
      });
    }
  });

  const malicious = analyzed.filter(u => u.risk === 'CRITICAL' || u.risk === 'HIGH').length;
  const suspicious = analyzed.filter(u => u.risk === 'MEDIUM').length;
  const benign = analyzed.filter(u => u.risk === 'LOW').length;

  return {
    totalUrls: urls.length,
    riskScore: Math.min(riskScore, 100),
    threatCategories: Array.from(new Set(threatCategories)),
    urls: analyzed,
    findings,
    reputation: { malicious, suspicious, benign }
  };
}

export function extractUrlsFromBuffer(buffer: Buffer): string[] {
  const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 1024 * 1024));
  const urlRegex = /https?:\/\/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s"'<>]*)?/gi;
  const matches = text.match(urlRegex) || [];
  const benignDomains = ['github.com', 'microsoft.com', 'google.com', 'w3.org', 'example.com'];
  return Array.from(new Set(matches))
    .filter(url => !benignDomains.some(d => url.includes(d)) && url.length > 10 && url.length < 500)
    .slice(0, 20);
}
