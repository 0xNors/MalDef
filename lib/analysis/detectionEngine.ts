/**
 * MCK-Guard Detection Engine - Stronger detection
 */

export interface DetectionResult {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score: number;
  evidence: string;
  explanation?: string;
  mitreTechnique?: string;
}

export function evaluateRules(staticResult: any, behaviorEvents: any[], networkEvents: any[], iocMatches: any[]): DetectionResult[] {
  const detections: DetectionResult[] = [];

  const suspiciousCount = staticResult.strings?.suspicious?.length || 0;
  const urlCount = staticResult.strings?.urls?.length || 0;
  const ipCount = staticResult.strings?.ips?.length || 0;
  const findingsCount = staticResult.findings?.length || 0;
  const isPE = staticResult.fileInfo?.isPE;

  if (suspiciousCount >= 3) {
    detections.push({
      ruleId: 'MCK-001',
      ruleName: 'Multiple Suspicious Patterns',
      category: 'Malware Indicators',
      severity: suspiciousCount >= 10 ? 'CRITICAL' : 'HIGH',
      score: Math.min(suspiciousCount * 8, 50),
      evidence: `Found ${suspiciousCount} suspicious patterns: ${staticResult.strings.suspicious.slice(0,2).join(' | ').substring(0,150)}`,
      explanation: 'File contains multiple malware construction patterns',
      mitreTechnique: 'T1027'
    });
  }

  if (isPE && findingsCount >= 2) {
    detections.push({
      ruleId: 'MCK-002',
      ruleName: 'PE with Suspicious Findings',
      category: 'Executable Analysis',
      severity: 'HIGH',
      score: 30,
      evidence: `${findingsCount} findings in PE file, entropy ${staticResult.entropy?.overall}`,
      explanation: 'PE file with multiple suspicious indicators',
      mitreTechnique: 'T1204.002'
    });
  }

  if (urlCount > 0) {
    detections.push({
      ruleId: 'MCK-003',
      ruleName: 'URLs in File',
      category: 'Network Indicators',
      severity: urlCount >= 3 ? 'MEDIUM' : 'LOW',
      score: urlCount * 5,
      evidence: `${urlCount} URLs found: ${staticResult.strings.urls.slice(0,2).join(', ')}`,
      explanation: 'File contains embedded URLs',
      mitreTechnique: 'T1071'
    });
  }

  if (ipCount > 0) {
    detections.push({
      ruleId: 'MCK-004',
      ruleName: 'External IPs in File',
      category: 'Network Indicators',
      severity: 'MEDIUM',
      score: ipCount * 8,
      evidence: `${ipCount} external IPs: ${staticResult.strings.ips.join(', ')}`,
      explanation: 'File contains external IP addresses',
      mitreTechnique: 'T1071'
    });
  }

  if (behaviorEvents.length > 0) {
    detections.push({
      ruleId: 'MCK-005',
      ruleName: 'Behavioral Activity',
      category: 'Behavior',
      severity: 'MEDIUM',
      score: Math.min(behaviorEvents.length * 5, 30),
      evidence: `${behaviorEvents.length} behavior events`,
      explanation: 'File shows behavioral activity',
      mitreTechnique: 'T1059'
    });
  }

  if (networkEvents.length > 0) {
    const suspiciousPorts = networkEvents.filter((e: any) => [4444, 5555, 6666, 1337].includes(e.port));
    if (suspiciousPorts.length > 0) {
      detections.push({
        ruleId: 'MCK-006',
        ruleName: 'Suspicious Network Ports',
        category: 'C2',
        severity: 'HIGH',
        score: 35,
        evidence: `Connections to suspicious ports: ${suspiciousPorts.map((e:any)=>e.port).join(', ')}`,
        explanation: 'Network activity on ports commonly used by malware',
        mitreTechnique: 'T1071'
      });
    }
  }

  return detections;
}

export function calculateCorrelationScore(behaviorEvents: any[], networkEvents: any[], staticResult: any): number {
  let score = 0;
  
  const hasStatic = (staticResult.findings?.length || 0) > 0 || (staticResult.strings?.suspicious?.length || 0) > 0;
  const hasBehavior = behaviorEvents.length > 0;
  const hasNetwork = networkEvents.length > 0;

  if (hasStatic && hasBehavior && hasNetwork) score = 90;
  else if ((hasStatic && hasBehavior) || (hasStatic && hasNetwork)) score = 60;
  else if (hasStatic) score = 30;
  else score = 0;

  // Bonus for many indicators
  const totalIndicators = (staticResult.strings?.suspicious?.length || 0) + behaviorEvents.length + networkEvents.length;
  if (totalIndicators >= 10) score = Math.min(score + 20, 100);
  else if (totalIndicators >= 5) score = Math.min(score + 10, 100);

  return score;
}
