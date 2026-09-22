/**
 * MCK-Guard String Decoder - Stronger detection
 */

export interface StringDecoderResult {
  decoded: any[];
  iocs: any[];
  riskScore: number;
  findings: any[];
}

export function decodeStrings(buffer: Buffer, strings: string[]): StringDecoderResult {
  const decoded: any[] = [];
  const iocs: any[] = [];
  const findings: any[] = [];
  let riskScore = 0;

  const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 1024 * 1024));

  // Base64 pattern
  const base64Regex = /(?:[A-Za-z0-9+\/]{20,}={0,2})/g;
  const base64Matches = text.match(base64Regex) || [];
  
  base64Matches.slice(0, 20).forEach((b64, idx) => {
    try {
      if (b64.length < 20 || b64.length > 500) return;
      // Skip if not valid base64
      if (!/^[A-Za-z0-9+\/]+={0,2}$/.test(b64)) return;
      const decodedStr = Buffer.from(b64, 'base64').toString('utf-8');
      // Check if decoded looks meaningful
      if (decodedStr.length < 10 || decodedStr.length > 500) return;
      if (!/^[\x20-\x7E\s]{10,}/.test(decodedStr)) return;
      
      const lower = decodedStr.toLowerCase();
      const hasIoc = lower.includes('http') || lower.includes('.exe') || lower.includes('powershell') || lower.includes('cmd');
      
      if (hasIoc || decodedStr.length > 30) {
        decoded.push({
          type: 'Base64',
          original: b64.substring(0, 80),
          decoded: decodedStr.substring(0, 200),
          risk: hasIoc ? 'HIGH' : 'MEDIUM',
          offset: text.indexOf(b64)
        });
        
        if (hasIoc) {
          iocs.push({ type: 'decoded_url', value: decodedStr.substring(0, 100), source: 'base64' });
          riskScore += 15;
        }
      }
    } catch {}
  });

  // PowerShell -enc detection
  const psEncRegex = /-e(?:nc|ncodedCommand)\s+([A-Za-z0-9+\/]{20,}={0,2})/gi;
  let m;
  while ((m = psEncRegex.exec(text)) !== null) {
    try {
      const b64 = m[1];
      const decodedStr = Buffer.from(b64, 'base64').toString('utf-16le').substring(0, 500);
      decoded.push({
        type: 'PowerShell EncodedCommand',
        original: m[0].substring(0, 100),
        decoded: decodedStr.substring(0, 200),
        risk: 'CRITICAL',
        offset: m.index
      });
      findings.push({
        category: 'Obfuscation',
        severity: 'CRITICAL',
        title: 'PowerShell EncodedCommand',
        description: 'PowerShell -EncodedCommand detected - highly obfuscated',
        evidence: m[0].substring(0, 100),
        score: 35
      });
      riskScore += 35;
    } catch {}
  }

  // Hex decoding
  const hexRegex = /(?:\\x[0-9a-fA-F]{2}){10,}/g;
  const hexMatches = text.match(hexRegex) || [];
  hexMatches.slice(0, 10).forEach(hexStr => {
    try {
      const cleaned = hexStr.replace(/\\x/g, '');
      const buf = Buffer.from(cleaned, 'hex');
      const decodedStr = buf.toString('utf-8').substring(0, 200);
      if (decodedStr.length > 10 && /^[\x20-\x7E]{10,}/.test(decodedStr)) {
        decoded.push({
          type: 'Hex',
          original: hexStr.substring(0, 80),
          decoded: decodedStr,
          risk: 'MEDIUM',
          offset: 0
        });
        riskScore += 10;
      }
    } catch {}
  });

  // FromBase64String pattern
  if (text.toLowerCase().includes('frombase64string') || text.toLowerCase().includes('frombase64')) {
    findings.push({
      category: 'Obfuscation',
      severity: 'HIGH',
      title: 'Base64 Decoding API',
      description: 'FromBase64String API detected - possible obfuscated payload',
      evidence: 'FromBase64String found in file',
      score: 20
    });
    riskScore += 20;
  }

  if (decoded.length > 0) {
    findings.push({
      category: 'Deobfuscation',
      severity: decoded.some((d:any)=>d.risk==='CRITICAL') ? 'CRITICAL' : 'MEDIUM',
      title: `Decoded ${decoded.length} hidden strings`,
      description: `${decoded.length} obfuscated strings decoded, ${iocs.length} IOCs extracted`,
      evidence: decoded.map((d:any)=>d.decoded.substring(0,50)).join(' | ').substring(0, 200),
      score: Math.min(decoded.length * 10, 40)
    });
  }

  return {
    decoded,
    iocs,
    riskScore: Math.min(riskScore, 100),
    findings
  };
}
