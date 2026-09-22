/**
 * MITRE ATT&CK Mitigations - Defensive mapping for Incident Investigation
 * Each technique maps to enterprise mitigations MXXXX
 */

export interface Mitigation {
  id: string;
  name: string;
  description: string;
  type: 'prevent' | 'detect' | 'contain' | 'eradicate' | 'recover';
  implementation: string[];
  tools: string[];
}

export const mitigationCatalog: Record<string, Mitigation> = {
  'M1038': { id: 'M1038', name: 'Execution Prevention', description: 'Block execution of code on a system through application control, script blocking, etc.', type: 'prevent', implementation: ['Enable Windows Defender Application Control (WDAC)', 'AppLocker rules for exe/dll/ps1', 'Block unsigned scripts'], tools: ['WDAC', 'AppLocker', 'Carbon Black'] },
  'M1026': { id: 'M1026', name: 'Privileged Account Management', description: 'Manage privileged accounts and limit admin rights', type: 'prevent', implementation: ['Credential Guard, LSA protection', 'Remove local admin, use PAM', 'Audit privileged groups'], tools: ['LAPS', 'CyberArk', 'Credential Guard'] },
  'M1018': { id: 'M1018', name: 'User Account Management', description: 'Manage user accounts, permissions, and lifecycle', type: 'prevent', implementation: ['Disable inactive accounts', 'Least privilege, no admin for daily use', 'MFA for all'], tools: ['AD, Azure AD, MFA'] },
  'M1028': { id: 'M1028', name: 'Operating System Configuration', description: 'Harden OS settings and reduce attack surface', type: 'prevent', implementation: ['Disable WScript, MSHTA, Rundll32 javascript if not needed', 'PowerShell Constrained Language Mode', 'Block LOLBINs via WDAC'], tools: ['GPO, Intune, WDAC'] },
  'M1040': { id: 'M1040', name: 'Behavior Prevention on Endpoint', description: 'Use behavioral analysis to block suspicious actions', type: 'prevent', implementation: ['Enable EDR behavioral blocking', 'AMSI for PowerShell', 'Block process injection APIs'], tools: ['CrowdStrike, Defender for Endpoint, SentinelOne'] },
  'M1050': { id: 'M1050', name: 'Exploit Protection', description: 'Protect against exploitation of vulnerabilities', type: 'prevent', implementation: ['Enable DEP, ASLR, CFG', 'EMET/Exploit Guard', 'Patch management'], tools: ['Windows Exploit Guard, EMET'] },
  'M1022': { id: 'M1022', name: 'Restrict File and Directory Permissions', description: 'Restrict access to sensitive files', type: 'prevent', implementation: ['Remove write to startup folders', 'Protect SAM, LSASS, registry run keys', 'ACL hardening'], tools: ['ICACLS, GPO'] },
  'M1013': { id: 'M1013', name: 'Application Developer Guidance', description: 'Secure coding to prevent abuse', type: 'prevent', implementation: ['Validate input, no eval(atob)', 'Code signing'], tools: ['SAST, CodeQL'] },
  'M1051': { id: 'M1051', name: 'Update Software', description: 'Patch and update to close vulnerabilities', type: 'prevent', implementation: ['Auto-update OS, browser, Office', 'Vuln scanning'], tools: ['WSUS, SCCM'] },
  'M1047': { id: 'M1047', name: 'Audit', description: 'Enable logging and auditing for detection', type: 'detect', implementation: ['Enable PowerShell Script Block Logging 4104', 'Process creation 4688, Sysmon', 'Registry auditing'], tools: ['Sysmon, SIEM, Splunk'] },
  'M1049': { id: 'M1049', name: 'Antivirus/Antimalware', description: 'Use AV signatures and heuristics', type: 'detect', implementation: ['Update AV definitions', 'Enable cloud protection', 'YARA rules for CredTool, C2, Loader'], tools: ['Defender, CrowdStrike, YARA'] },
  'M1011': { id: 'M1011', name: 'User Training', description: 'Train users to recognize phishing, social engineering', type: 'prevent', implementation: ['Phishing simulations', 'Report suspicious .exe.pdf.exe'], tools: ['KnowBe4'] },
  'M1056': { id: 'M1056', name: 'Pre-compromise', description: 'Prevent initial access', type: 'prevent', implementation: ['Email filtering for .exe, .js, double extensions', 'Block malicious domains at DNS'], tools: ['Proofpoint, Quad9'] },
  'M1031': { id: 'M1031', name: 'Network Intrusion Prevention', description: 'Block malicious network traffic', type: 'contain', implementation: ['IDS/IPS for C2 ports 4444,5555,6666,1337', 'Block IPs 185.234.218.123, 45.33.32.156', 'DNS filtering for DGA'], tools: ['Suricata, Snort, Firewall'] },
  'M1021': { id: 'M1021', name: 'Restrict Web-Based Content', description: 'Block malicious web content', type: 'prevent', implementation: ['Block javascript: in rundll32/mshta', 'Browser isolation'], tools: ['Proxy, Zscaler'] },
  'M1057': { id: 'M1057', name: 'Data Loss Prevention', description: 'Prevent exfiltration', type: 'contain', implementation: ['DLP for sensitive docs', 'Block exfil over C2 T1041'], tools: ['DLP, CASB'] },
  'M1027': { id: 'M1027', name: 'Password Policies', description: 'Strong password and credential hygiene', type: 'prevent', implementation: ['14+ chars, no reuse, MFA', 'Block credential dumping'], tools: ['MFA, Password manager'] },
  'M1025': { id: 'M1025', name: 'Privileged Process Integrity', description: 'Protect LSASS, SAM, credentials', type: 'prevent', implementation: ['RunAsPPL for LSASS, Credential Guard', 'Block Mimikatz, sekurlsa::logonpasswords'], tools: ['Credential Guard, LSA Protection'] },
  'M1041': { id: 'M1041', name: 'Encrypt Sensitive Information', description: 'Encrypt to reduce impact of exfil', type: 'recover', implementation: ['BitLocker, EFS', 'Encrypt backups'], tools: ['BitLocker'] },
  'M1053': { id: 'M1053', name: 'Data Backup', description: 'Backup to recover from ransomware', type: 'recover', implementation: ['3-2-1 backups, offline immutable', 'Test restores, no deletion by vssadmin'], tools: ['Veeam, offline backup'] },
  'M1015': { id: 'M1015', name: 'Active Directory Configuration', description: 'Harden AD against lateral movement', type: 'prevent', implementation: ['Tiered admin, no lateral with SMB', 'Block T1021.002'], tools: ['AD Hardening'] },
  'M1030': { id: 'M1030', name: 'Network Segmentation', description: 'Segment to contain breach', type: 'contain', implementation: ['Isolate infected host, block C2', 'VLAN, firewall rules'], tools: ['Firewall, NAC'] },
};

export const techniqueToMitigations: Record<string, string[]> = {
  'T1059.001': ['M1038', 'M1028', 'M1049', 'M1047'],
  'T1059.007': ['M1038', 'M1021', 'M1049'],
  'T1106': ['M1038', 'M1040', 'M1050'],
  'T1547.001': ['M1022', 'M1018', 'M1047', 'M1040'],
  'T1053.005': ['M1018', 'M1047', 'M1028'],
  'T1543.003': ['M1018', 'M1047', 'M1028'],
  'T1055': ['M1040', 'M1026', 'M1050', 'M1049'],
  'T1055.001': ['M1040', 'M1026', 'M1050'],
  'T1055.012': ['M1040', 'M1050'],
  'T1027': ['M1049', 'M1038', 'M1047'],
  'T1027.001': ['M1049', 'M1038'],
  'T1140': ['M1049', 'M1047'],
  'T1036': ['M1011', 'M1056', 'M1047'],
  'T1497': ['M1040', 'M1047'],
  'T1497.001': ['M1040', 'M1047'],
  'T1003.001': ['M1025', 'M1026', 'M1027', 'M1040'],
  'T1003': ['M1025', 'M1026'],
  'T1110': ['M1027', 'M1018', 'M1032'],
  'T1082': ['M1047'],
  'T1083': ['M1047'],
  'T1057': ['M1047'],
  'T1021.002': ['M1015', 'M1030', 'M1026'],
  'T1021': ['M1015', 'M1030'],
  'T1005': ['M1057', 'M1018'],
  'T1113': ['M1057', 'M1040'],
  'T1056.001': ['M1040', 'M1057'],
  'T1071.001': ['M1031', 'M1030', 'M1047'],
  'T1071': ['M1031', 'M1030'],
  'T1105': ['M1031', 'M1030'],
  'T1573': ['M1031'],
  'T1090': ['M1031'],
  'T1041': ['M1057', 'M1031'],
  'T1486': ['M1053', 'M1040', 'M1030'],
  'T1490': ['M1053', 'M1022', 'M1018'],
  'T1496': ['M1040', 'M1030', 'M1050'],
  'T1218': ['M1038', 'M1028', 'M1047'],
  'T1218.005': ['M1038', 'M1028'],
  'T1218.011': ['M1038', 'M1028'],
  'T1566': ['M1011', 'M1056', 'M1031'],
  'T1190': ['M1051', 'M1030'],
};

export function getMitigationsForTechnique(techId: string): Mitigation[] {
  const baseId = techId.split('.')[0]; // T1055 from T1055.001
  const ids = techniqueToMitigations[techId] || techniqueToMitigations[baseId] || ['M1040', 'M1047', 'M1038'];
  return ids.map(id => mitigationCatalog[id]).filter(Boolean);
}
