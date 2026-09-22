import { DetectionResult } from './detectionEngine';
import { StaticAnalysisResult } from './staticAnalyzer';

export interface RiskScoreResult {
  riskScore: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';
  reasons: string[];
  breakdown: { category: string; score: number; maxScore: number; details: string }[];
}

export function calculateRiskScore(
  staticResult: StaticAnalysisResult,
  detections: DetectionResult[],
  correlationScore: number,
  behaviorCount: number,
  networkCount: number
): RiskScoreResult {
  let totalScore = 0;
  const breakdown: RiskScoreResult['breakdown'] = [];
  const reasons: string[] = [];
  
  const isCompressed = staticResult.fileInfo.isCompressed;
  const isPE = staticResult.fileInfo.isPE;
  const isDocument = staticResult.fileInfo.isDocument;
  
  // === STATIC ANALYSIS (max 40) - FIXED FOR FALSE POSITIVES ===
  let staticScore = 0;
  
  // Entropy scoring - different for compressed vs PE vs text
  let entropyScore = 0;
  if (isCompressed) {
    // Compressed files: high entropy is NORMAL
    if (staticResult.entropy.overall > 7.95) entropyScore = 5;
    else entropyScore = 0;
    if (entropyScore > 0) reasons.push(`+${entropyScore} High entropy in compressed file (${staticResult.entropy.overall}) - possible encryption`);
  } else if (isPE) {
    // PE files: high entropy is suspicious (packing)
    if (staticResult.entropy.overall > 7.6) entropyScore = 25;
    else if (staticResult.entropy.overall > 7.2) entropyScore = 15;
    else if (staticResult.entropy.overall > 6.8) entropyScore = 5;
    if (entropyScore > 0) reasons.push(`+${entropyScore} Elevated entropy in executable (${staticResult.entropy.overall}) - possible MCK packing`);
  } else {
    // Other files
    if (staticResult.entropy.overall > 7.8) entropyScore = 20;
    else if (staticResult.entropy.overall > 7.2) entropyScore = 10;
    else if (staticResult.entropy.overall > 6.5) entropyScore = 3;
    if (entropyScore > 0) reasons.push(`+${entropyScore} Elevated entropy (${staticResult.entropy.overall})`);
  }
  staticScore += entropyScore;
  
  // Suspicious strings - MCK patterns are strong indicators
  let suspiciousStringScore = 0;
  if (staticResult.strings.suspicious.length > 0) {
    // MCK patterns are weighted heavily
    suspiciousStringScore = Math.min(staticResult.strings.suspicious.length * 8, 30);
    staticScore += suspiciousStringScore;
    reasons.push(`+${suspiciousStringScore} MCK malware patterns detected (${staticResult.strings.suspicious.length}) - strong indicator`);
  }
  
  // URLs and IPs - only if not benign
  if (staticResult.strings.urls.length > 0) {
    const urlScore = Math.min(staticResult.strings.urls.length * 2, 8);
    staticScore += urlScore;
    if (urlScore > 0) reasons.push(`+${urlScore} URLs embedded (${staticResult.strings.urls.length})`);
  }
  
  if (staticResult.strings.ips.length > 0) {
    const ipScore = staticResult.strings.ips.length * 5;
    staticScore += ipScore;
    reasons.push(`+${ipScore} External IPs found (${staticResult.strings.ips.length}) - potential C2`);
  }
  
  // Suspicious imports - strong MCK indicator
  let importScore = 0;
  const suspImports = staticResult.peInfo?.suspiciousImports.length || 0;
  if (suspImports >= 3) {
    importScore = suspImports * 7; // Heavy weight for MCK pattern
    reasons.push(`+${Math.min(importScore, 25)} MCK API pattern: ${suspImports} suspicious imports (injection, persistence, C2)`);
  } else if (suspImports > 0) {
    importScore = suspImports * 3;
    reasons.push(`+${importScore} Suspicious imports (${suspImports})`);
  }
  staticScore += Math.min(importScore, 25);
  
  staticScore = Math.min(staticScore, 40);
  breakdown.push({
    category: 'Static Analysis',
    score: staticScore,
    maxScore: 40,
    details: `Entropy: ${staticResult.entropy.overall} (${isCompressed ? 'compressed' : isPE ? 'PE' : 'other'}), MCK patterns: ${staticResult.strings.suspicious.length}, Suspicious imports: ${suspImports}`
  });
  totalScore += staticScore;
  
  // === DETECTION RULES (max 35) ===
  let detectionScore = 0;
  detections.forEach(d => {
    // Weight MCK-specific detections higher
    if (d.ruleName.includes('MCK') || d.severity === 'CRITICAL') {
      detectionScore += d.score * 0.8;
    } else {
      detectionScore += d.score * 0.4;
    }
  });
  detectionScore = Math.min(Math.round(detectionScore), 35);
  if (detectionScore > 0) {
    reasons.push(`+${detectionScore} Detection rules triggered (${detections.length}) - ${detections.filter(d => d.severity === 'CRITICAL').length} critical`);
  }
  breakdown.push({
    category: 'Detection Rules',
    score: detectionScore,
    maxScore: 35,
    details: `${detections.length} rules, ${detections.filter(d => d.severity === 'CRITICAL').length} critical`
  });
  totalScore += detectionScore;
  
  // === BEHAVIORAL (max 15) ===
  let behaviorScore = 0;
  if (behaviorCount > 0) {
    // More weight if multiple types (persistence, injection, etc)
    behaviorScore = Math.min(behaviorCount * 2, 15);
    reasons.push(`+${behaviorScore} Behavioral telemetry (${behaviorCount} events) - real execution data`);
  }
  breakdown.push({
    category: 'Behavioral',
    score: behaviorScore,
    maxScore: 15,
    details: `${behaviorCount} behavior events`
  });
  totalScore += behaviorScore;
  
  // === NETWORK (max 15) ===
  let networkScore = 0;
  if (networkCount > 0) {
    networkScore = Math.min(networkCount * 3, 15);
    reasons.push(`+${networkScore} Network anomalies (${networkCount} connections)`);
  }
  breakdown.push({
    category: 'Network',
    score: networkScore,
    maxScore: 15,
    details: `${networkCount} network events`
  });
  totalScore += networkScore;
  
  // === CORRELATION BONUS (max 15) - stronger for real MCK ===
  let correlationBonus = 0;
  if (correlationScore > 80) correlationBonus = 15;
  else if (correlationScore > 60) correlationBonus = 10;
  else if (correlationScore > 40) correlationBonus = 5;
  else if (correlationScore > 20) correlationBonus = 2;
  
  if (correlationBonus > 0) {
    reasons.push(`+${correlationBonus} Correlated MCK pattern (score ${correlationScore}) - multiple indicators together`);
  }
  breakdown.push({
    category: 'Correlation',
    score: correlationBonus,
    maxScore: 15,
    details: `Correlation score: ${correlationScore}`
  });
  totalScore += correlationBonus;
  
  totalScore = Math.min(Math.round(totalScore), 100);
  
  // === CLASSIFICATION - STRICTER THRESHOLDS TO AVOID FALSE POSITIVES ===
  let severity: RiskScoreResult['severity'];
  let classification: RiskScoreResult['classification'];
  
  // For compressed files, require higher score to be suspicious
  if (isCompressed && !isPE) {
    if (totalScore >= 85) {
      severity = 'CRITICAL';
      classification = 'CRITICAL';
    } else if (totalScore >= 65) {
      severity = 'HIGH';
      classification = 'HIGH_RISK';
    } else if (totalScore >= 40) {
      severity = 'MEDIUM';
      classification = 'SUSPICIOUS';
    } else {
      severity = 'LOW';
      classification = 'BENIGN';
    }
  } else {
    // PE and other files - standard thresholds but stricter
    if (totalScore >= 75) {
      severity = 'CRITICAL';
      classification = 'CRITICAL';
    } else if (totalScore >= 50) {
      severity = 'HIGH';
      classification = 'HIGH_RISK';
    } else if (totalScore >= 25) {
      severity = 'MEDIUM';
      classification = 'SUSPICIOUS';
    } else {
      severity = 'LOW';
      classification = 'BENIGN';
    }
  }
  
  // Confidence based on evidence diversity and file type
  const evidenceTypes = [
    staticScore > 5,
    detectionScore > 0,
    behaviorScore > 0,
    networkScore > 0,
    correlationBonus > 0
  ].filter(Boolean).length;
  
  let confidence = 0;
  if (classification === 'BENIGN') {
    // High confidence for benign if no strong indicators
    if (totalScore < 10) confidence = 90 + Math.random() * 8;
    else if (totalScore < 20) confidence = 80 + Math.random() * 10;
    else confidence = 70 + Math.random() * 10;
  } else {
    confidence = 60 + evidenceTypes * 8 + Math.min(detections.length * 4, 20) + Math.min(totalScore * 0.2, 15);
    if (totalScore > 75 && evidenceTypes >= 3) confidence = 88 + Math.random() * 10;
  }
  confidence = Math.min(Math.round(confidence), 99);
  
  if (reasons.length === 0) {
    if (isCompressed) {
      reasons.push('File is compressed archive (ZIP, PDF, DOCX) - high entropy is normal for this type');
      reasons.push('No MCK malware construction kit patterns detected');
      reasons.push('No suspicious APIs or C2 indicators');
      reasons.push('File appears benign - compressed files naturally have high entropy');
    } else {
      reasons.push('No significant suspicious indicators detected');
      reasons.push('No MCK malware patterns found');
      reasons.push('File appears benign based on static analysis');
    }
  }
  
  return {
    riskScore: totalScore,
    severity,
    confidence,
    classification,
    reasons,
    breakdown,
  };
}

export function getRecommendations(
  riskResult: RiskScoreResult,
  detections: DetectionResult[],
  staticResult: StaticAnalysisResult
): string[] {
  const recs: string[] = [];
  
  if (riskResult.classification === 'BENIGN') {
    if (staticResult.fileInfo.isCompressed) {
      recs.push('File is compressed archive - high entropy is expected and normal');
      recs.push('No MCK malware indicators detected - file appears safe');
    } else {
      recs.push('File appears benign - no MCK malware indicators');
    }
    recs.push('Maintain standard endpoint protection');
    recs.push('No further action required');
    return recs;
  }
  
  if (riskResult.riskScore >= 25) {
    recs.push('Review file in isolated sandbox environment');
    recs.push('Preserve evidence for further analysis');
  }
  
  if (detections.some(d => d.category.includes('Behavioral'))) {
    recs.push('Review process activity and parent-child relationships');
    recs.push('Investigate persistence indicators (registry, scheduled tasks, services)');
  }
  
  if (detections.some(d => d.category.includes('Network'))) {
    recs.push('Review network connections and DNS queries for C2');
    recs.push('Check firewall logs for suspicious IPs/domains');
    recs.push('Search related IOCs across SIEM');
  }
  
  if (staticResult.entropy.overall > 7.2 && staticResult.fileInfo.isPE) {
    recs.push('PE file is packed - unpack in sandbox (UPX, MPRESS) for deeper analysis');
    recs.push('Packed executables are common in MCK-generated malware');
  }
  
  if (riskResult.riskScore >= 50) {
    recs.push('Perform full endpoint scan with updated definitions');
    recs.push('Monitor related systems for similar IOCs');
    recs.push('Review authentication logs for lateral movement');
    recs.push('Hunt for related MCK TTPs using MITRE ATT&CK mapping');
  }
  
  if (riskResult.riskScore >= 75) {
    recs.push('Escalate to incident response team - potential MCK malware');
    recs.push('Initiate containment per IR playbook');
    recs.push('Collect forensic evidence with chain of custody');
    recs.push('Block IOCs at perimeter and search enterprise-wide');
  }
  
  recs.push('Update detection rules with new MCK patterns if confirmed');
  recs.push('Document findings for threat intelligence');
  
  return recs;
}
