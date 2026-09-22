/**
 * MCK-Guard File System Analyzer - Stronger detection
 */

export interface FileSystemResult {
  usesFileSystem: boolean;
  fileSystemType: 'NONE' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  riskScore: number;
  summary: string;
  structure: any;
  fileOperations: any[];
  fileSystemFlow: any[];
  locationAnalysis: any;
  spreadAnalysis: any;
  dependencyAnalysis: any;
  persistenceDeep: any;
  executionContext: any;
  systemImpact: any;
  forensicTimeline: any[];
  artifactDetails: any;
  documentDetails: any;
  findings: any[];
}

export function analyzeFileSystem(
  staticResult: any,
  behaviorEvents: any[],
  packerResult: any
): FileSystemResult {
  const suspiciousStrings = staticResult.strings?.suspicious || [];
  const isPE = staticResult.fileInfo?.isPE;
  const isDocument = staticResult.fileInfo?.isDocument;

  const hasFileCreation = behaviorEvents.some((e: any) => e.event_type === 'file_creation' || e.eventType === 'file_creation');
  const hasFileMod = behaviorEvents.some((e: any) => e.event_type?.includes('file_') || e.eventType?.includes('file_'));
  const hasRegistry = behaviorEvents.some((e: any) => e.event_type === 'registry_change' || e.eventType === 'registry_change');

  const fileOperations: any[] = [];
  const findings: any[] = [];

  // Check for file operations in suspicious strings
  const fileOpPatterns = ['createfile', 'writefile', 'deletefile', 'copyfile', 'movefile'];
  const hasFileOpsInStrings = suspiciousStrings.some((s: string) => fileOpPatterns.some(p => s.toLowerCase().includes(p)));

  if (hasFileCreation) {
    fileOperations.push({ type: 'File Creation', path: 'Unknown', risk: 'MEDIUM' });
  }
  if (hasFileMod) {
    fileOperations.push({ type: 'File Modification', path: 'Unknown', risk: 'MEDIUM' });
  }
  if (hasRegistry) {
    fileOperations.push({ type: 'Registry Modification', path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', risk: 'HIGH' });
  }

  let fileSystemType: 'NONE' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' = 'NONE';
  let riskScore = 0;
  let summary = 'File system not used - clean file';
  let usesFileSystem = false;

  if (fileOperations.length > 0 || hasFileOpsInStrings) {
    fileSystemType = hasRegistry ? 'MALICIOUS' : 'SUSPICIOUS';
    riskScore = hasRegistry ? 60 : 30;
    summary = `File system activity: ${fileOperations.length} operations, registry ${hasRegistry ? 'Yes' : 'No'} - file uses file system`;
    usesFileSystem = true;
    findings.push({
      category: 'File System',
      severity: fileSystemType === 'MALICIOUS' ? 'HIGH' : 'MEDIUM',
      title: `File System ${fileSystemType}`,
      description: summary,
      evidence: fileOperations.map((f: any) => f.type).join(', '),
      score: riskScore
    });
  } else if (isPE && suspiciousStrings.length >= 5) {
    fileSystemType = 'SUSPICIOUS';
    riskScore = 25;
    summary = `PE file with ${suspiciousStrings.length} suspicious patterns - possible file system operations (dropper)`;
    usesFileSystem = true;
    findings.push({
      category: 'File System',
      severity: 'MEDIUM',
      title: 'Possible Dropper',
      description: `PE with ${suspiciousStrings.length} suspicious patterns indicates possible file dropper`,
      evidence: suspiciousStrings.slice(0, 2).join(' | ').substring(0, 200),
      score: 25
    });
  } else {
    fileSystemType = 'NONE';
    riskScore = 0;
    summary = 'File system NOT going using this file - clean file, no file operations';
    usesFileSystem = false;
  }

  // For documents, always NONE/BENIGN
  if (isDocument && !isPE) {
    fileSystemType = 'NONE';
    riskScore = 0;
    summary = 'Document file - file system NOT used, clean';
    usesFileSystem = false;
  }

  return {
    usesFileSystem,
    fileSystemType,
    riskScore,
    summary,
    structure: {
      totalFileEvents: behaviorEvents.filter((e: any) => e.event_type?.includes('file_')).length,
      totalRegistryEvents: behaviorEvents.filter((e: any) => e.event_type === 'registry_change').length,
      hasFileCreation,
      hasFileModification: hasFileMod,
      hasFileDeletion: false,
      hasRegistryChange: hasRegistry,
      hasPersistence: hasRegistry,
      hasAutomaticScripts: false,
      hasDownloadCradle: false,
      hasC2: false,
      hasBeaconing: false,
      hasDGA: false,
      hasUrls: false,
      hasIps: false,
      hasDomains: false,
      hasSuspiciousPorts: false,
      hasHttpRequests: false,
      hasDnsQueries: false,
      protocols: [],
      ports: [],
      externalConnections: 0,
      internalConnections: 0,
      totalUrlsRaw: 0,
      totalIpsRaw: 0,
      filteredUrls: [],
      filteredIps: [],
      benignUrls: [],
      benignIps: [],
      allUrls: [],
      allIps: []
    },
    fileOperations,
    fileSystemFlow: fileSystemType === 'NONE' ? [{
      step: 1,
      action: 'No File System Activity',
      description: 'Clean file - no file system operations, file system NOT used',
      target: 'None',
      risk: 'NONE',
      evidence: 'No file creation, modification, registry - clean'
    }] : fileOperations.map((op: any, idx: number) => ({
      step: idx + 1,
      action: op.type,
      description: `File system operation: ${op.type} at ${op.path}`,
      target: op.path,
      risk: op.risk,
      evidence: op.type
    })),
    locationAnalysis: {
      currentObservedPath: '/tmp/sandbox/upload',
      fileOrigin: 'User upload',
      isSystemLocation: false,
      isTempLocation: true,
      isUserLocation: false,
      locationRisk: fileSystemType === 'NONE' ? 'NONE' : 'MEDIUM',
      fullPathAnalysis: fileSystemType === 'NONE' ? 'File in sandbox temp - clean, no system locations' : 'File shows file system activity',
      typicalMalwareDropLocations: [],
      persistenceLocations: [],
      systemCriticalLocations: [],
      userDataLocations: [],
      locationDetails: [summary]
    },
    spreadAnalysis: {
      canSpread: false,
      selfReplication: false,
      usbSpread: false,
      networkShareSpread: false,
      spreadMethods: [],
      spreadDetails: [],
      spreadSummary: fileSystemType === 'NONE' ? 'No spread - clean file' : 'Possible spread via file operations',
      spreadRisk: 'NONE'
    },
    dependencyAnalysis: {
      demandsFiles: false,
      demandLevel: 'NONE',
      createdFiles: [],
      modifiedFiles: [],
      deletedFiles: [],
      accessedFiles: [],
      requiredSystemFiles: [],
      details: [summary],
      fullDependencyAnalysis: summary,
      dependencyRisk: riskScore
    },
    persistenceDeep: {
      hasPersistence: hasRegistry,
      totalPersistencePoints: hasRegistry ? 1 : 0,
      mechanisms: hasRegistry ? [{ type: 'Registry Run Key', location: 'HKCU\\Run', risk: 'HIGH' }] : [],
      autostartLocations: [],
      persistenceSummary: hasRegistry ? 'Persistence detected via registry' : 'No persistence - clean'
    },
    executionContext: {
      privilegesRequired: 'NONE',
      executionRisk: fileSystemType === 'NONE' ? 'NONE' : 'MEDIUM',
      executionSummary: summary,
      processTree: [],
      processInjection: { detected: false, techniques: [], targets: [] }
    },
    systemImpact: {
      impactLevel: fileSystemType,
      impactSummary: summary,
      impactedAreas: [],
      systemStability: 'Stable',
      recoveryComplexity: 'None'
    },
    forensicTimeline: [],
    artifactDetails: {
      totalArtifacts: fileOperations.length,
      fileArtifacts: [],
      registryArtifacts: [],
      processArtifacts: []
    },
    documentDetails: {
      details: [summary],
      fullAnalysis: summary
    },
    findings
  };
}
