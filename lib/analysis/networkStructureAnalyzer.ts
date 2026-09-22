/**
 * MCK-Guard Network Structure Analyzer - Stronger detection
 */

export interface NetworkStructureResult {
  usesNetwork: boolean;
  networkType: 'NONE' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'C2';
  riskScore: number;
  summary: string;
  structure: {
    hasUrls: boolean;
    hasIps: boolean;
    hasDomains: boolean;
    hasSuspiciousPorts: boolean;
    hasHttpRequests: boolean;
    hasDnsQueries: boolean;
    hasAutomaticScripts: boolean;
    hasDownloadCradle: boolean;
    hasC2: boolean;
    hasBeaconing: boolean;
    hasDGA: boolean;
    protocols: string[];
    ports: number[];
    externalConnections: number;
    internalConnections: number;
    totalUrlsRaw: number;
    totalIpsRaw: number;
    filteredUrls: string[];
    filteredIps: string[];
    benignUrls: string[];
    benignIps: string[];
    allUrls: string[];
    allIps: string[];
  };
  automaticScripts: any[];
  networkFlow: any[];
  fileSystemBypass: any;
  documentDetails: any;
  findings: any[];
}

export function analyzeNetworkStructure(
  staticResult: any,
  networkEvents: any[],
  decodedIocs: any[],
  c2Result?: any
): NetworkStructureResult {
  const urlsRaw = staticResult.strings?.urls || [];
  const ipsRaw = staticResult.strings?.ips || [];
  const suspiciousStrings = staticResult.strings?.suspicious || [];
  const isPE = staticResult.fileInfo?.isPE;

  const benignUrlPatterns = ['w3.org', 'microsoft.com', 'adobe.com', 'w3schools.com', 'github.com', 'google.com', 'example.com', 'schemas.openxmlformats', 'purl.org'];
  const benignIpPatterns = ['192.168.', '10.', '127.', '8.8.8.8', '1.1.1.1'];

  const filteredUrls = urlsRaw.filter((url: string) => !benignUrlPatterns.some((b: string) => url.includes(b)));
  const filteredIps = ipsRaw.filter((ip: string) => !benignIpPatterns.some((b: string) => ip.startsWith(b)));

  const benignUrls = urlsRaw.filter((url: string) => benignUrlPatterns.some((b: string) => url.includes(b)));
  const benignIps = ipsRaw.filter((ip: string) => benignIpPatterns.some((b: string) => ip.startsWith(b)));

  const hasUrls = filteredUrls.length > 0;
  const hasIps = filteredIps.length > 0;
  const hasSuspiciousPorts = networkEvents.some((e: any) => [4444, 5555, 6666, 1337, 8080].includes(e.port));
  const hasHttpRequests = filteredUrls.some((u: string) => u.startsWith('http'));
  const hasDnsQueries = networkEvents.some((e: any) => e.port === 53) || filteredUrls.length > 0;

  // Automatic scripts detection
  const automaticScripts: any[] = [];
  const text = JSON.stringify(suspiciousStrings).toLowerCase();
  
  if (text.includes('downloadstring') || text.includes('downloadfile') || text.includes('webclient')) {
    automaticScripts.push({
      type: 'PowerShell Download Cradle',
      description: 'PowerShell download cradle detected',
      evidence: suspiciousStrings.find((s: string) => s.toLowerCase().includes('downloadstring')) || 'DownloadString pattern',
      severity: 'CRITICAL',
      worksInNetwork: true,
      networkActivity: 'Downloads payload from remote C2'
    });
  }
  if (text.includes('frombase64string') && text.includes('invoke-expression')) {
    automaticScripts.push({
      type: 'PowerShell Base64 Execution',
      description: 'Base64 encoded PowerShell execution',
      evidence: 'FromBase64String + Invoke-Expression',
      severity: 'HIGH',
      worksInNetwork: true,
      networkActivity: 'Executes decoded payload'
    });
  }
  if (text.includes('wscript.shell') || text.includes('shell.run')) {
    automaticScripts.push({
      type: 'WScript.Shell Execution',
      description: 'WScript.Shell automatic execution',
      evidence: 'WScript.Shell pattern',
      severity: 'HIGH',
      worksInNetwork: false,
      networkActivity: 'Local execution'
    });
  }
  if (text.includes('rundll32') && text.includes('javascript:')) {
    automaticScripts.push({
      type: 'LOLBIN Rundll32 JS',
      description: 'Rundll32 JavaScript execution - LOLBIN',
      evidence: 'rundll32.*javascript: pattern',
      severity: 'CRITICAL',
      worksInNetwork: true,
      networkActivity: 'Executes remote JS payload'
    });
  }

  const hasAutomaticScripts = automaticScripts.length > 0;
  const hasDownloadCradle = automaticScripts.some((s: any) => s.type.includes('Download Cradle'));
  const hasC2 = c2Result?.isC2 || filteredUrls.length > 0 || filteredIps.length > 0;
  const hasBeaconing = c2Result?.beaconing?.detected || false;
  const hasDGA = c2Result?.dga?.detected || false;

  const protocols = Array.from(new Set([
    ...(hasHttpRequests ? ['http', 'https'] : []),
    ...(hasDnsQueries ? ['dns'] : []),
    ...(hasIps ? ['tcp'] : [])
  ])) as string[];

  const ports = Array.from(new Set([
    ...networkEvents.map((e: any) => e.port).filter(Boolean),
    ...(hasHttpRequests ? [80, 443] : [])
  ])) as number[];

  let networkType: 'NONE' | 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS' | 'C2' = 'NONE';
  let riskScore = 0;
  let summary = 'No network activity - clean file';
  let usesNetwork = false;

  if (hasC2 || hasAutomaticScripts || hasSuspiciousPorts) {
    if (c2Result?.isC2 || hasAutomaticScripts) {
      networkType = 'C2';
      riskScore = 80;
      summary = `C2 network detected: ${filteredUrls.length} URLs, ${filteredIps.length} external IPs, ${automaticScripts.length} automatic scripts - file WORKS in network as malware`;
      usesNetwork = true;
    } else if (hasUrls || hasIps) {
      networkType = 'MALICIOUS';
      riskScore = 60;
      summary = `Malicious network activity: ${filteredUrls.length} suspicious URLs, ${filteredIps.length} external IPs`;
      usesNetwork = true;
    }
  } else if (filteredUrls.length > 0 || filteredIps.length > 0) {
    networkType = 'SUSPICIOUS';
    riskScore = 30;
    summary = `Suspicious network indicators: ${filteredUrls.length} URLs, ${filteredIps.length} IPs`;
    usesNetwork = true;
  } else if (urlsRaw.length > 0 || ipsRaw.length > 0) {
    networkType = 'BENIGN';
    riskScore = 0;
    summary = `Benign network indicators only: ${benignUrls.length} benign URLs filtered (w3.org, microsoft.com), ${benignIps.length} private IPs - file does NOT work in network`;
    usesNetwork = false;
  } else {
    networkType = 'NONE';
    riskScore = 0;
    summary = 'No network activity - file does NOT work in network, clean';
    usesNetwork = false;
  }

  // For PE files with many suspicious patterns, increase risk
  if (isPE && suspiciousStrings.length >= 5) {
    if (networkType === 'NONE' || networkType === 'BENIGN') {
      networkType = 'SUSPICIOUS';
      riskScore = Math.max(riskScore, 25);
      summary = `PE file with ${suspiciousStrings.length} suspicious patterns - possible network capability even though no URLs found in static`;
      usesNetwork = true;
    }
  }

  const networkFlow = [];
  if (networkType === 'NONE') {
    networkFlow.push({
      step: 1,
      action: 'No Network Activity',
      description: 'Clean file - no network activity, does NOT work in network',
      protocol: 'None',
      destination: 'None',
      risk: 'NONE',
      evidence: 'No URLs, IPs, or network events - clean verified deeply'
    });
  } else {
    networkFlow.push({
      step: 1,
      action: 'Network Indicators Found',
      description: `${filteredUrls.length} filtered URLs, ${filteredIps.length} external IPs after benign filtering`,
      protocol: protocols.join(', ') || 'http',
      destination: filteredUrls[0] || filteredIps[0] || 'Unknown',
      risk: networkType === 'C2' ? 'CRITICAL' : networkType === 'MALICIOUS' ? 'HIGH' : 'MEDIUM',
      evidence: `Raw ${urlsRaw.length} URLs → ${filteredUrls.length} filtered, Raw ${ipsRaw.length} IPs → ${filteredIps.length} external`
    });
    if (hasAutomaticScripts) {
      networkFlow.push({
        step: 2,
        action: 'Automatic Scripts Detected',
        description: `${automaticScripts.length} automatic scripts that work in network`,
        protocol: 'PowerShell/JS',
        destination: 'C2 Server',
        risk: 'CRITICAL',
        evidence: automaticScripts.map((s: any) => s.type).join(', ')
      });
    }
  }

  return {
    usesNetwork,
    networkType,
    riskScore,
    summary,
    structure: {
      hasUrls,
      hasIps,
      hasDomains: false,
      hasSuspiciousPorts,
      hasHttpRequests,
      hasDnsQueries,
      hasAutomaticScripts,
      hasDownloadCradle,
      hasC2,
      hasBeaconing,
      hasDGA,
      protocols,
      ports,
      externalConnections: filteredIps.length,
      internalConnections: benignIps.length,
      totalUrlsRaw: urlsRaw.length,
      totalIpsRaw: ipsRaw.length,
      filteredUrls,
      filteredIps,
      benignUrls,
      benignIps,
      allUrls: urlsRaw,
      allIps: ipsRaw
    },
    automaticScripts,
    networkFlow,
    fileSystemBypass: {
      triesToBypass: hasAutomaticScripts,
      usesDirectNetwork: hasC2,
      noFileSystem: false,
      explanation: hasAutomaticScripts ? 'File tries to bypass file system via direct network download (fileless)' : 'No file system bypass'
    },
    documentDetails: {
      hasContent: urlsRaw.length > 0 || ipsRaw.length > 0,
      contentType: staticResult.fileInfo?.mimeType || 'unknown',
      details: [
        `Raw URLs: ${urlsRaw.length}, Filtered: ${filteredUrls.length}, Benign: ${benignUrls.length}`,
        `Raw IPs: ${ipsRaw.length}, Filtered: ${filteredIps.length}, Benign: ${benignIps.length}`,
        `Automatic Scripts: ${automaticScripts.length}`,
        `Network Type: ${networkType}, Uses Network: ${usesNetwork}`,
        `Summary: ${summary}`
      ],
      fullAnalysis: summary
    },
    findings: automaticScripts.map((s: any) => ({
      category: 'Network',
      severity: s.severity,
      title: s.type,
      description: s.description,
      evidence: s.evidence,
      score: s.severity === 'CRITICAL' ? 30 : 20
    }))
  };
}
