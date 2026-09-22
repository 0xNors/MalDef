/**
 * MCK-Guard Multi-Layer Scanner
 * Implements detection flow from reference repo: 
 * 1. Initial Content Analysis -> 2. External API Verification -> 3. Dynamic Behavior Analysis
 * Improved for MCK-Guard file analysis
 */

import { StaticAnalysisResult } from './staticAnalyzer';
import { analyzeHtmlContent, HtmlAnalysisResult } from './htmlAnalyzer';
import { analyzeJsContent, JsAnalysisResult } from './jsAnalyzer';
import { analyzeUrls, UrlAnalysisResult } from './urlAnalyzer';
import { aggregateThreatIntelSync, ThreatIntelResult } from './threatIntel';
import { analyzeBehaviors, BehaviorAnalysisResult } from './behaviorAnalyzer';
const __dec = (b: string) => Buffer.from(b, 'base64').toString('utf-8');


export interface MultiLayerResult {
  layers: {
    static: { risk: number; findings: number; categories: string[] };
    html: HtmlAnalysisResult;
    javascript: JsAnalysisResult;
    url: UrlAnalysisResult;
    threatIntel: ThreatIntelResult;
    behavior: BehaviorAnalysisResult;
  };
  aggregated: {
    riskScore: number;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    classification: string;
    confidence: number;
    threatCategories: string[];
    totalFindings: number;
  };
  findings: {
    category: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    description: string;
    evidence: string;
    score: number;
    layer: string;
  }[];
  recommendations: string[];
}

export function performMultiLayerScan(
  buffer: Buffer,
  filename: string,
  staticResult: StaticAnalysisResult,
  behaviorEvents: any[],
  networkEvents: any[]
): MultiLayerResult {
  // Layer 1: Initial Content Analysis (like reference repo's static + JS + HTML)
  const htmlResult = analyzeHtmlContent(buffer, filename);
  const jsResult = analyzeJsContent(buffer, filename);
  const urlResult = analyzeUrls(staticResult.strings.urls);

  // Layer 2: External API Verification (threat intel)
  const threatIntelResult = aggregateThreatIntelSync(
    staticResult.strings.urls,
    staticResult.strings.ips,
    staticResult.hashes,
    staticResult.strings.suspicious
  );

  // Layer 3: Dynamic Behavior Analysis
  const behaviorResult = analyzeBehaviors(
    behaviorEvents,
    networkEvents,
    staticResult.strings.suspicious,
    staticResult.peInfo?.suspiciousImports || []
  );

  // Aggregate all findings
  const allFindings: MultiLayerResult['findings'] = [];

  // Add HTML findings
  htmlResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'HTML Analysis' });
  });

  // Add JS findings
  jsResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'JavaScript Analysis' });
  });

  // Add URL findings
  urlResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'URL Analysis' });
  });

  // Add Threat Intel findings
  threatIntelResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'Threat Intelligence' });
  });

  // Add Behavior findings
  behaviorResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'Behavior Analysis' });
  });

  // Add static findings
  staticResult.findings.forEach(f => {
    allFindings.push({ ...f, layer: 'Static Analysis' } as any);
  });

  // Calculate aggregated risk (weighted)
  // Weights inspired by reference repo's risk assessment: indicators count, severity per threat, etc.
  const staticWeight = 0.30;
  const htmlWeight = htmlResult.isHtml ? 0.15 : 0;
  const jsWeight = jsResult.isJs ? 0.15 : 0;
  const urlWeight = urlResult.totalUrls > 0 ? 0.15 : 0.05;
  const threatIntelWeight = 0.10;
  const behaviorWeight = (behaviorEvents.length > 0 || networkEvents.length > 0) ? 0.25 : 0.10;

  const totalWeight = staticWeight + htmlWeight + jsWeight + urlWeight + threatIntelWeight + behaviorWeight;

  const weightedRisk = (
    (staticResult.entropy.risk.score + staticResult.findings.reduce((s, f) => s + f.score, 0)) * staticWeight +
    htmlResult.riskScore * htmlWeight +
    jsResult.riskScore * jsWeight +
    urlResult.riskScore * urlWeight +
    threatIntelResult.riskScore * threatIntelWeight +
    behaviorResult.riskScore * behaviorWeight
  ) / totalWeight;

  // Normalize to 0-100 with correlation bonus
  let aggregatedRisk = Math.min(Math.round(weightedRisk * 1.2), 100);

  // Correlation bonuses (multi-layer detection is stronger)
  const layersTriggered = [
    staticResult.findings.length > 0,
    htmlResult.findings.length > 0,
    jsResult.findings.length > 0,
    urlResult.findings.length > 0,
    threatIntelResult.findings.length > 0,
    behaviorResult.findings.length > 0
  ].filter(Boolean).length;

  if (layersTriggered >= 4) aggregatedRisk = Math.min(aggregatedRisk + 15, 100);
  else if (layersTriggered >= 3) aggregatedRisk = Math.min(aggregatedRisk + 10, 100);
  else if (layersTriggered >= 2) aggregatedRisk = Math.min(aggregatedRisk + 5, 100);

  // Determine severity and classification
  let severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  let classification = 'BENIGN';
  
  if (aggregatedRisk >= 75) {
    severity = 'CRITICAL';
    classification = 'CRITICAL';
  } else if (aggregatedRisk >= 50) {
    severity = 'HIGH';
    classification = 'HIGH_RISK';
  } else if (aggregatedRisk >= 25) {
    severity = 'MEDIUM';
    classification = 'SUSPICIOUS';
  } else if (aggregatedRisk >= 10) {
    severity = 'LOW';
    classification = 'LOW_RISK';
  } else {
    severity = 'LOW';
    classification = 'BENIGN';
  }

  // For compressed files with no real threats, ensure BENIGN
  if (staticResult.fileInfo.isCompressed && !staticResult.fileInfo.isPE && 
      htmlResult.findings.length === 0 && jsResult.findings.length === 0 && 
      urlResult.reputation.malicious === 0 && behaviorResult.findings.length === 0) {
    aggregatedRisk = Math.min(aggregatedRisk, 5);
    severity = 'LOW';
    classification = 'BENIGN';
  }

  // Confidence based on layers
  const confidence = Math.min(50 + layersTriggered * 10 + Math.min(allFindings.length * 3, 30), 98);

  // Aggregate threat categories
  const allCategories = [
    ...htmlResult.threatCategories,
    ...jsResult.threatCategories,
    ...urlResult.threatCategories,
    ...behaviorResult.threatCategories,
    ...staticResult.findings.map(f => f.category)
  ];
  const threatCategories = Array.from(new Set(allCategories));

  // Recommendations based on multi-layer
  const recommendations: string[] = [];
  
  if (classification === 'BENIGN') {
    recommendations.push('File appears benign across all detection layers - no action required');
    if (staticResult.fileInfo.isCompressed) {
      recommendations.push('Compressed file - high entropy is normal, no MCK indicators');
    }
  } else {
    if (htmlResult.findings.length > 0) recommendations.push(`Review HTML layer: ${htmlResult.findings.length} findings including ${htmlResult.threatCategories.join(', ')}`);
    if (jsResult.findings.length > 0) recommendations.push(`Review JavaScript layer: ${jsResult.threatCategories.join(', ')} - check for obfuscation`);
    if (urlResult.reputation.malicious > 0) recommendations.push(`Block malicious URLs: ${urlResult.urls.filter(u => u.risk === 'CRITICAL' || u.risk === 'HIGH').length} high-risk URLs detected`);
    if (behaviorResult.threatCategories.length > 0) recommendations.push(`Behavioral analysis shows: ${behaviorResult.threatCategories.join(', ')} - investigate in sandbox`);
    if (threatIntelResult.reputation === 'MALICIOUS') recommendations.push('Threat intelligence confirms malicious reputation - escalate');
    
    if (severity === 'CRITICAL' || severity === 'HIGH') {
      recommendations.push('Isolate sample and perform full forensic analysis');
      recommendations.push('Check for lateral movement and persistence mechanisms');
      recommendations.push('Update detection rules with new IOCs');
    }
  }

  recommendations.push('Maintain endpoint protection and monitor for related IOCs');

  return {
    layers: {
      static: { 
        risk: staticResult.entropy.risk.score + staticResult.findings.reduce((s, f) => s + f.score, 0), 
        findings: staticResult.findings.length, 
        categories: staticResult.findings.map(f => f.category) 
      },
      html: htmlResult,
      javascript: jsResult,
      url: urlResult,
      threatIntel: threatIntelResult,
      behavior: behaviorResult
    },
    aggregated: {
      riskScore: aggregatedRisk,
      severity,
      classification,
      confidence,
      threatCategories,
      totalFindings: allFindings.length
    },
    findings: allFindings,
    recommendations
  };
}
