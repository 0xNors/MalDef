/**
 * MCK-Guard Behavior Analyzer - Stronger detection with encoded patterns
 */

const __d = (b: string) => Buffer.from(b, 'base64').toString('utf-8');

export interface BehaviorAnalysisResult {
  findings: {
    category: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    description: string;
    evidence: string;
    score: number;
  }[];
  patterns: any[];
  threatCategories: string[];
  riskScore: number;
}

export interface BehaviorResult extends BehaviorAnalysisResult {}

export function analyzeBehaviors(
  behaviorEvents: any[],
  networkEvents: any[],
  suspiciousStrings: string[],
  suspiciousImports: string[]
): BehaviorAnalysisResult {
  const findings: BehaviorAnalysisResult['findings'] = [];
  const patterns: any[] = [];
  const threatCategories: string[] = [];
  let riskScore = 0;

  const hasProcessCreation = behaviorEvents.some(e => e.event_type === 'process_creation' || e.eventType === 'process_creation');
  const hasFileMod = behaviorEvents.some(e => e.event_type?.includes('file_') || e.eventType?.includes('file_'));
  const hasRegistry = behaviorEvents.some(e => e.event_type === 'registry_change' || e.eventType === 'registry_change');
  const hasNetwork = networkEvents.length > 0;

  // Check suspicious strings for behavior patterns
  const suspiciousLower = suspiciousStrings.map(s => s.toLowerCase());
  
  const credTools = [__d('bWltaWthdHo='), 'sekurlsa', 'lsass', 'sam', 'ntds'];
  const hasCredDump = suspiciousLower.some(s => credTools.some(t => s.includes(t.toLowerCase())));
  
  const injectionApis = [__d('VmlydHVhbEFsbG9j'), __d('V3JpdGVQcm9jZXNzTWVtb3J5'), __d('Q3JlYXRlUmVtb3RlVGhyZWFk')].map(s => s.toLowerCase());
  const hasInjection = suspiciousImports.some(i => injectionApis.includes(i.toLowerCase())) || suspiciousLower.some(s => injectionApis.some(api => s.includes(api)));

  const persistencePatterns = ['registry', 'run key', 'scheduled task', 'service', 'startup'];
  const hasPersistence = hasRegistry || suspiciousLower.some(s => persistencePatterns.some(p => s.includes(p)));

  const c2Patterns = ['http', 'tcp', 'beacon', 'c2', 'callback'];
  const hasC2Pattern = suspiciousLower.some(s => c2Patterns.some(p => s.includes(p))) || hasNetwork;

  if (hasCredDump) {
    findings.push({
      category: 'Credential Access',
      severity: 'CRITICAL',
      title: 'Credential Dumping Behavior',
      description: 'Detected credential dumping patterns - possible LSASS/SAM access',
      evidence: suspiciousStrings.filter(s => credTools.some(t => s.toLowerCase().includes(t.toLowerCase()))).join(' | ').substring(0, 200),
      score: 40
    });
    patterns.push({ type: 'credential_access', confidence: 90 });
    threatCategories.push('Credential Access');
    riskScore += 40;
  }

  if (hasInjection) {
    findings.push({
      category: 'Defense Evasion',
      severity: 'CRITICAL',
      title: 'Process Injection Behavior',
      description: 'Detected process injection APIs - possible process hollowing',
      evidence: suspiciousImports.join(', ') + ' | ' + suspiciousStrings.filter(s => s.toLowerCase().includes('virtualalloc') || s.toLowerCase().includes('writeprocess')).join(' | ').substring(0, 200),
      score: 35
    });
    patterns.push({ type: 'process_injection', confidence: 85 });
    threatCategories.push('Defense Evasion', 'Privilege Escalation');
    riskScore += 35;
  }

  if (hasPersistence) {
    findings.push({
      category: 'Persistence',
      severity: 'HIGH',
      title: 'Persistence Mechanism',
      description: 'Detected persistence via registry, scheduled tasks, or services',
      evidence: hasRegistry ? 'Registry change events detected' : 'Persistence patterns in strings',
      score: 25
    });
    patterns.push({ type: 'persistence', confidence: 75 });
    threatCategories.push('Persistence');
    riskScore += 25;
  }

  if (hasC2Pattern && (suspiciousStrings.length > 0 || hasNetwork)) {
    findings.push({
      category: 'Command and Control',
      severity: hasNetwork ? 'HIGH' : 'MEDIUM',
      title: 'C2 Communication Pattern',
      description: `Detected C2 patterns with ${networkEvents.length} network events`,
      evidence: `Network events: ${networkEvents.length}, C2 patterns in strings: ${suspiciousLower.filter(s => c2Patterns.some(p => s.includes(p))).length}`,
      score: hasNetwork ? 30 : 15
    });
    patterns.push({ type: 'c2', confidence: hasNetwork ? 80 : 60 });
    threatCategories.push('Command and Control');
    riskScore += hasNetwork ? 30 : 15;
  }

  if (hasProcessCreation && hasFileMod) {
    findings.push({
      category: 'Execution',
      severity: 'MEDIUM',
      title: 'Process and File Activity',
      description: 'Process creation combined with file modifications',
      evidence: `Process creation: ${hasProcessCreation}, File mods: ${hasFileMod}`,
      score: 20
    });
    patterns.push({ type: 'execution', confidence: 70 });
    threatCategories.push('Execution');
    riskScore += 20;
  }

  // If many suspicious strings, add generic finding
  if (suspiciousStrings.length >= 5) {
    findings.push({
      category: 'Malware Indicators',
      severity: suspiciousStrings.length >= 10 ? 'CRITICAL' : 'HIGH',
      title: `Multiple Suspicious Patterns: ${suspiciousStrings.length}`,
      description: `File contains ${suspiciousStrings.length} suspicious patterns indicating malware construction`,
      evidence: suspiciousStrings.slice(0, 3).join(' | ').substring(0, 250),
      score: Math.min(suspiciousStrings.length * 5, 40)
    });
    riskScore += Math.min(suspiciousStrings.length * 3, 30);
  }

  return {
    findings,
    patterns,
    threatCategories: Array.from(new Set(threatCategories)),
    riskScore: Math.min(riskScore, 100)
  };
}
