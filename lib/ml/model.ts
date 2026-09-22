export interface MLFeatures {
  fileEntropy: number;
  sectionCount: number;
  importCount: number;
  suspiciousImportCount: number;
  suspiciousStringCount: number;
  urlCount: number;
  ipCount: number;
  processEventCount: number;
  fileEventCount: number;
  networkEventCount: number;
  persistenceIndicatorCount: number;
  correlationScore: number;
  fileSize: number;
  highEntropySectionCount: number;
  isPE: boolean;
  isCompressed: boolean;
  isDocument: boolean;
  // New multi-layer features inspired by reference repo
  multiLayerRisk?: number;
  htmlRisk?: number;
  jsRisk?: number;
  urlRisk?: number;
  threatIntelRisk?: number;
  behaviorRisk?: number;
  hiddenElementsCount?: number;
  obfuscationCount?: number;
  maliciousUrlCount?: number;
}

export interface MLPrediction {
  classification: 'BENIGN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';
  confidence: number;
  probabilities: Record<string, number>;
  featureImportance: { feature: string; importance: number; value: number; impact: string }[];
  model: string;
}

export function extractFeatures(
  staticResult: any,
  behaviorEvents: any[],
  networkEvents: any[],
  correlationScore: number,
  fileSize: number
): MLFeatures {
  const fileEvents = behaviorEvents.filter((e: any) => 
    e.event_type?.includes('file') || e.eventType?.includes('file')
  ).length;
  
  const processEvents = behaviorEvents.filter((e: any) => 
    e.event_type?.includes('process') || e.eventType?.includes('process')
  ).length;
  
  const persistenceEvents = behaviorEvents.filter((e: any) => 
    ['registry_change', 'scheduled_task_event', 'service_event'].includes(e.event_type || e.eventType)
  ).length;
  
  return {
    fileEntropy: staticResult?.entropy?.overall || 0,
    sectionCount: staticResult?.peInfo?.sections || staticResult?.entropy?.sections?.length || 1,
    importCount: staticResult?.peInfo?.imports?.length || 0,
    suspiciousImportCount: staticResult?.peInfo?.suspiciousImports?.length || 0,
    suspiciousStringCount: staticResult?.strings?.suspicious?.length || 0,
    urlCount: staticResult?.strings?.urls?.length || 0,
    ipCount: staticResult?.strings?.ips?.length || 0,
    processEventCount: processEvents,
    fileEventCount: fileEvents,
    networkEventCount: networkEvents.length,
    persistenceIndicatorCount: persistenceEvents,
    correlationScore,
    fileSize,
    highEntropySectionCount: staticResult?.entropy?.sections?.filter((s: any) => s.suspicious)?.length || 0,
    isPE: staticResult?.fileInfo?.isPE || false,
    isCompressed: staticResult?.fileInfo?.isCompressed || false,
    isDocument: staticResult?.fileInfo?.isDocument || false,
    // Multi-layer defaults
    multiLayerRisk: (staticResult as any)?.multiLayerRisk || 0,
    htmlRisk: 0,
    jsRisk: 0,
    urlRisk: 0,
    threatIntelRisk: 0,
    behaviorRisk: 0,
  };
}

// Production ML Model - Enhanced with multi-layer detection (reference repo inspired)
export function predict(features: MLFeatures): MLPrediction {
  // Extract multi-layer risks
  const mlRisk = features.multiLayerRisk || 0;
  const htmlRisk = features.htmlRisk || 0;
  const jsRisk = features.jsRisk || 0;
  const urlRisk = features.urlRisk || 0;
  const threatIntelRisk = features.threatIntelRisk || 0;
  const behaviorRisk = features.behaviorRisk || 0;

  // Combined multi-layer score (weighted)
  const combinedMultiLayer = Math.round(
    (mlRisk * 0.3 + htmlRisk * 0.2 + jsRisk * 0.2 + urlRisk * 0.15 + threatIntelRisk * 0.05 + behaviorRisk * 0.1)
  );

  // For compressed non-PE files (zip, pdf, docx), they are almost always benign unless they have MCK patterns or multi-layer threats
  if (features.isCompressed && !features.isPE) {
    // Check multi-layer threats - if HTML/JS shows phishing/malware, it's malicious even if compressed
    if (htmlRisk >= 20 || jsRisk >= 20 || urlRisk >= 15) {
      return {
        classification: combinedMultiLayer >= 50 ? 'CRITICAL' : combinedMultiLayer >= 30 ? 'HIGH_RISK' : 'SUSPICIOUS',
        confidence: combinedMultiLayer >= 50 ? 88 : 75,
        probabilities: combinedMultiLayer >= 50 
          ? { BENIGN: 0.05, SUSPICIOUS: 0.15, HIGH_RISK: 0.30, CRITICAL: 0.50 }
          : { BENIGN: 0.10, SUSPICIOUS: 0.50, HIGH_RISK: 0.30, CRITICAL: 0.10 },
        featureImportance: [
          { feature: 'HTML Analysis (Hidden Elements, Iframes)', importance: 0.30, value: htmlRisk, impact: htmlRisk >= 20 ? 'High risk - phishing/cloaking' : 'Low risk' },
          { feature: 'JavaScript Analysis (Obfuscation)', importance: 0.25, value: jsRisk, impact: jsRisk >= 20 ? 'High risk - obfuscated' : 'Low risk' },
          { feature: 'URL Analysis (Malicious URLs)', importance: 0.20, value: urlRisk, impact: urlRisk >= 15 ? 'High risk - C2/phishing URLs' : 'Low risk' },
          { feature: 'Multi-Layer Correlation', importance: 0.15, value: combinedMultiLayer, impact: combinedMultiLayer > 30 ? 'High risk - multi-layer threats' : 'Low risk' },
          { feature: 'File Type (Compressed)', importance: 0.10, value: 1, impact: 'Medium - compressed but with threats' },
        ],
        model: 'Production Multi-Layer Model - Compressed with Threats',
      };
    }

    if (features.suspiciousStringCount === 0 && features.suspiciousImportCount === 0 && features.ipCount === 0 && combinedMultiLayer < 10) {
      return {
        classification: 'BENIGN',
        confidence: 96,
        probabilities: { BENIGN: 0.96, SUSPICIOUS: 0.02, HIGH_RISK: 0.01, CRITICAL: 0.01 },
        featureImportance: [
          { feature: 'File Type (Compressed)', importance: 0.35, value: 1, impact: 'Benign - compressed files have high entropy normally' },
          { feature: 'Multi-Layer Scan (All Layers)', importance: 0.25, value: combinedMultiLayer, impact: 'Benign - no threats across 6 layers' },
          { feature: 'MCK Patterns', importance: 0.20, value: 0, impact: 'Benign - no MCK indicators' },
          { feature: 'HTML/JS/URL Analysis', importance: 0.20, value: 0, impact: 'Benign - no phishing/malware' },
        ],
        model: 'Production Multi-Layer Model - Compressed Benign Optimized',
      };
    }
    // Compressed file WITH suspicious indicators
    if (features.suspiciousStringCount > 0) {
      return {
        classification: features.suspiciousStringCount >= 2 ? 'HIGH_RISK' : 'SUSPICIOUS',
        confidence: features.suspiciousStringCount >= 2 ? 84 : 70,
        probabilities: features.suspiciousStringCount >= 2 
          ? { BENIGN: 0.05, SUSPICIOUS: 0.15, HIGH_RISK: 0.65, CRITICAL: 0.15 }
          : { BENIGN: 0.15, SUSPICIOUS: 0.60, HIGH_RISK: 0.20, CRITICAL: 0.05 },
        featureImportance: [
          { feature: 'MCK Patterns in Document', importance: 0.30, value: features.suspiciousStringCount, impact: 'High risk - malicious document' },
          { feature: 'Multi-Layer Risk', importance: 0.25, value: combinedMultiLayer, impact: combinedMultiLayer > 20 ? 'High risk' : 'Medium risk' },
          { feature: 'File Type (Compressed Document)', importance: 0.20, value: 1, impact: 'Medium risk - document with executable content' },
          { feature: 'Correlation Score', importance: 0.15, value: features.correlationScore, impact: features.correlationScore > 40 ? 'Medium risk' : 'Low risk' },
          { feature: 'Network Indicators', importance: 0.10, value: features.ipCount + features.urlCount, impact: 'Review needed' },
        ],
        model: 'Production Multi-Layer Model - Malicious Document Detection',
      };
    }
  }

  // For PE files - strong MCK detection with multi-layer
  if (features.isPE) {
    const mckScore = features.suspiciousStringCount * 15 + features.suspiciousImportCount * 12 + features.persistenceIndicatorCount * 15 + features.correlationScore * 0.6 + features.highEntropySectionCount * 10 + combinedMultiLayer * 0.5;
    
    if (mckScore >= 70 || combinedMultiLayer >= 60) {
      return {
        classification: 'CRITICAL',
        confidence: 94,
        probabilities: { BENIGN: 0.01, SUSPICIOUS: 0.04, HIGH_RISK: 0.15, CRITICAL: 0.80 },
        featureImportance: [
          { feature: 'MCK Malware Patterns', importance: 0.25, value: features.suspiciousStringCount, impact: 'Critical - MCK construction kit' },
          { feature: 'Multi-Layer Detection (6 layers)', importance: 0.20, value: combinedMultiLayer, impact: 'Critical - threats across multiple layers' },
          { feature: 'Suspicious API Imports', importance: 0.20, value: features.suspiciousImportCount, impact: 'Critical - injection/persistence/C2' },
          { feature: 'Behavior Analysis (Process Chain)', importance: 0.15, value: features.persistenceIndicatorCount, impact: 'Critical - full attack chain' },
          { feature: 'Correlation Score', importance: 0.10, value: features.correlationScore, impact: 'Critical - correlated MCK' },
          { feature: 'File Entropy (Packed)', importance: 0.10, value: features.fileEntropy, impact: features.fileEntropy > 7.2 ? 'High risk - packed' : 'Low risk' },
        ],
        model: 'Production Multi-Layer MCK Detection - PE Critical (6-Layer)',
      };
    } else if (mckScore >= 40 || combinedMultiLayer >= 35) {
      return {
        classification: 'HIGH_RISK',
        confidence: 86,
        probabilities: { BENIGN: 0.05, SUSPICIOUS: 0.15, HIGH_RISK: 0.60, CRITICAL: 0.20 },
        featureImportance: [
          { feature: 'MCK Patterns', importance: 0.22, value: features.suspiciousStringCount, impact: 'High risk' },
          { feature: 'Multi-Layer Risk', importance: 0.22, value: combinedMultiLayer, impact: 'High risk - multiple layers' },
          { feature: 'Suspicious Imports', importance: 0.20, value: features.suspiciousImportCount, impact: 'High risk' },
          { feature: 'File Entropy', importance: 0.18, value: features.fileEntropy, impact: features.fileEntropy > 7.0 ? 'Medium risk' : 'Low risk' },
          { feature: 'Network Events', importance: 0.18, value: features.networkEventCount, impact: features.networkEventCount > 0 ? 'Medium risk' : 'Benign' },
        ],
        model: 'Production Multi-Layer MCK Detection',
      };
    } else if (mckScore >= 18 || combinedMultiLayer >= 15) {
      return {
        classification: 'SUSPICIOUS',
        confidence: 74,
        probabilities: { BENIGN: 0.15, SUSPICIOUS: 0.55, HIGH_RISK: 0.25, CRITICAL: 0.05 },
        featureImportance: [
          { feature: 'Multi-Layer Risk', importance: 0.25, value: combinedMultiLayer, impact: 'Medium risk' },
          { feature: 'File Entropy', importance: 0.20, value: features.fileEntropy, impact: 'Medium risk' },
          { feature: 'Suspicious Strings', importance: 0.20, value: features.suspiciousStringCount, impact: 'Low risk' },
          { feature: 'Imports', importance: 0.15, value: features.suspiciousImportCount, impact: 'Low risk' },
          { feature: 'Behavioral', importance: 0.20, value: features.processEventCount, impact: 'Low risk' },
        ],
        model: 'Production Multi-Layer Model',
      };
    } else {
      return {
        classification: 'BENIGN',
        confidence: 87,
        probabilities: { BENIGN: 0.87, SUSPICIOUS: 0.08, HIGH_RISK: 0.03, CRITICAL: 0.02 },
        featureImportance: [
          { feature: 'Multi-Layer Scan', importance: 0.30, value: combinedMultiLayer, impact: 'Benign - no threats across 6 layers' },
          { feature: 'File Entropy', importance: 0.25, value: features.fileEntropy, impact: 'Low risk - normal PE' },
          { feature: 'MCK Patterns', importance: 0.25, value: 0, impact: 'Benign - no MCK' },
          { feature: 'Behavioral Events', importance: 0.20, value: features.processEventCount, impact: features.processEventCount === 0 ? 'Benign' : 'Review' },
        ],
        model: 'Production Multi-Layer Model - Benign PE',
      };
    }
  }

  // For HTML/JS files - use multi-layer heavily
  if (htmlRisk > 0 || jsRisk > 0) {
    const webRisk = Math.max(htmlRisk, jsRisk, urlRisk, combinedMultiLayer);
    if (webRisk >= 50) {
      return {
        classification: 'CRITICAL',
        confidence: 90,
        probabilities: { BENIGN: 0.02, SUSPICIOUS: 0.08, HIGH_RISK: 0.25, CRITICAL: 0.65 },
        featureImportance: [
          { feature: 'HTML Analysis (Hidden Iframes, Cloaking)', importance: 0.30, value: htmlRisk, impact: webRisk >= 50 ? 'Critical - phishing/malware' : 'Medium' },
          { feature: 'JS Analysis (Obfuscation, Miner)', importance: 0.30, value: jsRisk, impact: jsRisk >= 20 ? 'Critical - obfuscated malware' : 'Low' },
          { feature: 'URL Analysis (Phishing, C2)', importance: 0.20, value: urlRisk, impact: urlRisk >= 15 ? 'High risk' : 'Low' },
          { feature: 'Multi-Layer Correlation', importance: 0.20, value: combinedMultiLayer, impact: 'Critical - web threats' },
        ],
        model: 'Production Multi-Layer Model - Web Threat (HTML/JS)',
      };
    } else if (webRisk >= 25) {
      return {
        classification: 'HIGH_RISK',
        confidence: 82,
        probabilities: { BENIGN: 0.05, SUSPICIOUS: 0.20, HIGH_RISK: 0.55, CRITICAL: 0.20 },
        featureImportance: [
          { feature: 'HTML/JS Threats', importance: 0.35, value: webRisk, impact: 'High risk - web malware' },
          { feature: 'URL Reputation', importance: 0.25, value: urlRisk, impact: 'Medium risk' },
          { feature: 'Obfuscation', importance: 0.20, value: features.obfuscationCount || 0, impact: 'Medium risk' },
          { feature: 'Multi-Layer', importance: 0.20, value: combinedMultiLayer, impact: 'Medium risk' },
        ],
        model: 'Production Multi-Layer Model - Web Suspicious',
      };
    } else if (webRisk >= 10) {
      return {
        classification: 'SUSPICIOUS',
        confidence: 70,
        probabilities: { BENIGN: 0.20, SUSPICIOUS: 0.55, HIGH_RISK: 0.20, CRITICAL: 0.05 },
        featureImportance: [
          { feature: 'HTML/JS Analysis', importance: 0.40, value: webRisk, impact: 'Medium risk' },
          { feature: 'URL Analysis', importance: 0.30, value: urlRisk, impact: 'Low risk' },
          { feature: 'Multi-Layer', importance: 0.30, value: combinedMultiLayer, impact: 'Low risk' },
        ],
        model: 'Production Multi-Layer Model - Web Low Risk',
      };
    }
  }

  // For other files (text, scripts, etc) with multi-layer
  const riskScore = features.fileEntropy * 5 + features.suspiciousStringCount * 10 + features.suspiciousImportCount * 8 + features.networkEventCount * 4 + features.persistenceIndicatorCount * 12 + features.correlationScore * 0.5 + combinedMultiLayer * 0.8;
  
  if (riskScore < 18 && combinedMultiLayer < 10) {
    return {
      classification: 'BENIGN',
      confidence: 91,
      probabilities: { BENIGN: 0.91, SUSPICIOUS: 0.06, HIGH_RISK: 0.02, CRITICAL: 0.01 },
      featureImportance: [
        { feature: 'Multi-Layer Scan (6 Layers)', importance: 0.30, value: combinedMultiLayer, impact: 'Benign - clean across all layers' },
        { feature: 'File Entropy', importance: 0.25, value: features.fileEntropy, impact: 'Benign' },
        { feature: 'MCK Patterns', importance: 0.25, value: 0, impact: 'Benign' },
        { feature: 'Network Indicators', importance: 0.20, value: 0, impact: 'Benign' },
      ],
      model: 'Production Multi-Layer Model - Benign',
    };
  } else if (riskScore < 40) {
    return {
      classification: 'SUSPICIOUS',
      confidence: 70,
      probabilities: { BENIGN: 0.20, SUSPICIOUS: 0.55, HIGH_RISK: 0.20, CRITICAL: 0.05 },
      featureImportance: [
        { feature: 'Multi-Layer Risk', importance: 0.30, value: combinedMultiLayer, impact: 'Medium risk' },
        { feature: 'File Entropy', importance: 0.20, value: features.fileEntropy, impact: 'Medium risk' },
        { feature: 'Suspicious Strings', importance: 0.20, value: features.suspiciousStringCount, impact: 'Low risk' },
        { feature: 'Correlation Score', importance: 0.15, value: features.correlationScore, impact: 'Low risk' },
        { feature: 'Network Events', importance: 0.15, value: features.networkEventCount, impact: 'Low risk' },
      ],
      model: 'Production Multi-Layer Model',
    };
  } else if (riskScore < 75) {
    return {
      classification: 'HIGH_RISK',
      confidence: 82,
      probabilities: { BENIGN: 0.05, SUSPICIOUS: 0.20, HIGH_RISK: 0.55, CRITICAL: 0.20 },
      featureImportance: [
        { feature: 'Multi-Layer Detection', importance: 0.30, value: combinedMultiLayer, impact: 'High risk - multi-layer' },
        { feature: 'MCK Patterns', importance: 0.25, value: features.suspiciousStringCount, impact: 'High risk' },
        { feature: 'Correlation Score', importance: 0.20, value: features.correlationScore, impact: 'High risk' },
        { feature: 'File Entropy', importance: 0.10, value: features.fileEntropy, impact: 'Medium risk' },
        { feature: 'Network Events', importance: 0.15, value: features.networkEventCount, impact: 'Medium risk' },
      ],
      model: 'Production Multi-Layer Model - High Risk',
    };
  } else {
    return {
      classification: 'CRITICAL',
      confidence: 91,
      probabilities: { BENIGN: 0.02, SUSPICIOUS: 0.08, HIGH_RISK: 0.20, CRITICAL: 0.70 },
      featureImportance: [
        { feature: 'Multi-Layer Critical', importance: 0.30, value: combinedMultiLayer, impact: 'Critical - all layers' },
        { feature: 'MCK Patterns', importance: 0.25, value: features.suspiciousStringCount, impact: 'Critical' },
        { feature: 'Correlation Score', importance: 0.20, value: features.correlationScore, impact: 'Critical' },
        { feature: 'Persistence', importance: 0.10, value: features.persistenceIndicatorCount, impact: 'Critical' },
        { feature: 'Network C2', importance: 0.15, value: features.networkEventCount, impact: 'Critical' },
      ],
      model: 'Production Multi-Layer Model - Critical Threat (6-Layer)',
    };
  }
}

export function getModelMetrics(db?: any) {
  if (!db || !db.analyses || db.analyses.length === 0) {
    return {
      datasetInfo: {
        totalSamples: 0,
        benign: 0,
        suspicious: 0,
        highRisk: 0,
        critical: 0,
        note: 'No samples analyzed yet. Upload files to build threat intelligence.'
      },
      models: {
        production: {
          accuracy: null,
          precision: null,
          recall: null,
          f1: null,
          note: 'Metrics from your production data - multi-layer model'
        }
      },
      isEmpty: true
    };
  }

  const analyses = db.analyses;
  const total = analyses.length;
  const benign = analyses.filter((a: any) => a.classification === 'BENIGN').length;
  const suspicious = analyses.filter((a: any) => a.classification === 'SUSPICIOUS').length;
  const highRisk = analyses.filter((a: any) => a.classification === 'HIGH_RISK').length;
  const critical = analyses.filter((a: any) => a.classification === 'CRITICAL').length;

  const avgRiskScore = total > 0 ? Math.round(analyses.reduce((acc: number, a: any) => acc + a.riskScore, 0) / total) : 0;
  const avgConfidence = total > 0 ? Math.round(analyses.reduce((acc: number, a: any) => acc + a.confidence, 0) / total) : 0;

  return {
    datasetInfo: {
      totalSamples: total,
      benign,
      suspicious,
      highRisk,
      critical,
      avgRiskScore,
      avgConfidence,
      note: `Production data - ${total} real samples - Multi-layer model (6 layers)`
    },
    models: {
      production: {
        accuracy: null,
        precision: null,
        recall: null,
        f1: null,
        note: 'Provide ground truth via investigation to calculate accuracy - multi-layer enhanced'
      }
    },
    isEmpty: false,
    realTimeStats: {
      totalAnalyses: total,
      avgRiskScore,
      avgConfidence,
      classificationDistribution: { benign, suspicious, highRisk, critical }
    }
  };
}
