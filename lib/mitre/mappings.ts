export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  description: string;
  detection: string;
  mitigation: string;
  url: string;
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  'T1027': {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.',
    detection: 'Monitor for high entropy files, packed executables, and obfuscation patterns in static analysis',
    mitigation: 'Use anti-malware with unpacking capabilities, enable behavior-based detection',
    url: 'https://attack.mitre.org/techniques/T1027/'
  },
  'T1106': {
    id: 'T1106',
    name: 'Native API',
    tactic: 'Execution',
    tacticId: 'TA0002',
    description: 'Adversaries may directly interact with Windows API to execute behaviors difficult to detect.',
    detection: 'Monitor for suspicious API imports like memory operation APIs',
    mitigation: 'Enable API monitoring, use EDR with user-mode hooking detection',
    url: 'https://attack.mitre.org/techniques/T1106/'
  },
  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversaries may communicate using application layer protocols to avoid detection.',
    detection: 'Monitor for unusual HTTP/S connections, rare domains, and anomalous network patterns',
    mitigation: 'Network segmentation, proxy filtering, TLS inspection',
    url: 'https://attack.mitre.org/techniques/T1071/'
  },
  'T1055': {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    description: 'Adversaries may inject code into processes to evade detection and gain access.',
    detection: 'Correlate process creation with file modifications and memory anomalies',
    mitigation: 'Enable exploit protection, monitor process memory operations',
    url: 'https://attack.mitre.org/techniques/T1055/'
  },
  'T1053': {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may abuse task scheduling to facilitate initial or recurring execution.',
    detection: 'Monitor scheduled task creation combined with registry modifications',
    mitigation: 'Restrict task creation permissions, audit scheduled tasks',
    url: 'https://attack.mitre.org/techniques/T1053/'
  },
  'T1105': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    description: 'Adversaries may transfer tools or files from external system into compromised environment.',
    detection: 'IOC matching, monitor file downloads from rare destinations',
    mitigation: 'Block file transfers from untrusted sources, network filtering',
    url: 'https://attack.mitre.org/techniques/T1105/'
  },
  'T1082': {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    description: 'Adversaries may attempt to get detailed information about operating system and hardware.',
    detection: 'Multiple discovery commands correlated with network activity',
    mitigation: 'Limit system information access, monitor discovery tools',
    url: 'https://attack.mitre.org/techniques/T1082/'
  },
  'T1547': {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    description: 'Adversaries may configure system settings to automatically execute program on boot or logon.',
    detection: 'Registry run keys, startup folder modifications, service installations',
    mitigation: 'Monitor autostart locations, restrict registry permissions',
    url: 'https://attack.mitre.org/techniques/T1547/'
  },
  'T1003': {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
    detection: 'Monitor LSASS access, credential dumping tools, suspicious process memory reads',
    mitigation: 'Enable Credential Guard, restrict debug privileges, monitor LSASS',
    url: 'https://attack.mitre.org/techniques/T1003/'
  },
  'T1041': {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    description: 'Adversaries may steal data by exfiltrating it over existing C2 channel.',
    detection: 'Large outbound transfers over C2 protocols, anomalous data volumes',
    mitigation: 'Data loss prevention, network traffic analysis, egress filtering',
    url: 'https://attack.mitre.org/techniques/T1041/'
  }
};

export const TACTICS = [
  { id: 'TA0001', name: 'Initial Access', color: '#ff3344' },
  { id: 'TA0002', name: 'Execution', color: '#ff6b35' },
  { id: 'TA0003', name: 'Persistence', color: '#ffcc00' },
  { id: 'TA0004', name: 'Privilege Escalation', color: '#00d9ff' },
  { id: 'TA0005', name: 'Defense Evasion', color: '#8b5cf6' },
  { id: 'TA0006', name: 'Credential Access', color: '#ff006a' },
  { id: 'TA0007', name: 'Discovery', color: '#00ff88' },
  { id: 'TA0008', name: 'Lateral Movement', color: '#00d9ff' },
  { id: 'TA0009', name: 'Collection', color: '#ffcc00' },
  { id: 'TA0010', name: 'Exfiltration', color: '#ff3344' },
  { id: 'TA0011', name: 'Command and Control', color: '#8b5cf6' },
  { id: 'TA0040', name: 'Impact', color: '#ff006a' },
];

export function mapDetectionsToMitre(detections: { mitreTechnique?: string; evidence: string; ruleName: string }[]) {
  return detections
    .filter(d => d.mitreTechnique && MITRE_TECHNIQUES[d.mitreTechnique])
    .map(d => {
      const technique = MITRE_TECHNIQUES[d.mitreTechnique!];
      return {
        ...technique,
        evidence: d.evidence,
        detectionLogic: d.ruleName,
        confidence: d.mitreTechnique ? 85 : 50,
      };
    });
}

export function getMitreStats(analyses: any[]) {
  const tacticCount: Record<string, number> = {};
  analyses.forEach(a => {
    a.mitreMappings?.forEach((m: any) => {
      tacticCount[m.tactic] = (tacticCount[m.tactic] || 0) + 1;
    });
  });
  return tacticCount;
}
