// MITRE ATT&CK v13 Enterprise - Full Framework Matrix
// Based on https://attack.mitre.org/ - All tactics and techniques
export interface MitreTechnique {
  id: string;
  name: string;
  subTechniques?: MitreTechnique[];
}

export interface MitreTactic {
  id: string;
  name: string;
  count: number;
  techniques: MitreTechnique[];
}

export const enterpriseMatrix: MitreTactic[] = [
  {
    id: 'TA0043',
    name: 'Reconnaissance',
    count: 10,
    techniques: [
      { id: 'T1595', name: 'Active Scanning', subTechniques: [{ id: 'T1595.001', name: 'Scanning IP Blocks' }, { id: 'T1595.002', name: 'Vulnerability Scanning' }, { id: 'T1595.003', name: 'Wordlist Scanning' }] },
      { id: 'T1592', name: 'Gather Victim Host Information', subTechniques: [{ id: 'T1592.001', name: 'Hardware' }, { id: 'T1592.002', name: 'Software' }, { id: 'T1592.003', name: 'Firmware' }, { id: 'T1592.004', name: 'Client Configurations' }] },
      { id: 'T1589', name: 'Gather Victim Identity Information', subTechniques: [{ id: 'T1589.001', name: 'Credentials' }, { id: 'T1589.002', name: 'Email Addresses' }, { id: 'T1589.003', name: 'Employee Names' }] },
      { id: 'T1590', name: 'Gather Victim Network Information', subTechniques: [{ id: 'T1590.001', name: 'Domain Properties' }, { id: 'T1590.002', name: 'DNS' }, { id: 'T1590.003', name: 'Network Trust Dependencies' }, { id: 'T1590.004', name: 'Network Topology' }, { id: 'T1590.005', name: 'IP Addresses' }, { id: 'T1590.006', name: 'Network Security Appliances' }] },
      { id: 'T1591', name: 'Gather Victim Org Information', subTechniques: [{ id: 'T1591.001', name: 'Determine Physical Locations' }, { id: 'T1591.002', name: 'Business Relationships' }, { id: 'T1591.003', name: 'Identify Business Tempo' }, { id: 'T1591.004', name: 'Identify Roles' }] },
      { id: 'T1598', name: 'Phishing for Information', subTechniques: [{ id: 'T1598.001', name: 'Spearphishing Service' }, { id: 'T1598.002', name: 'Spearphishing Attachment' }, { id: 'T1598.003', name: 'Spearphishing Link' }] },
      { id: 'T1593', name: 'Search Open Websites/Domains', subTechniques: [{ id: 'T1593.001', name: 'Social Media' }, { id: 'T1593.002', name: 'Search Engines' }] },
      { id: 'T1594', name: 'Search Victim-Owned Websites' },
      { id: 'T1596', name: 'Search Open Technical Databases', subTechniques: [{ id: 'T1596.001', name: 'DNS/Passive DNS' }, { id: 'T1596.002', name: 'WHOIS' }, { id: 'T1596.003', name: 'Digital Certificates' }, { id: 'T1596.004', name: 'CDNs' }, { id: 'T1596.005', name: 'Scan Databases' }] },
      { id: 'T1597', name: 'Search Closed Sources', subTechniques: [{ id: 'T1597.001', name: 'Threat Intel Vendors' }, { id: 'T1597.002', name: 'Purchase Technical Data' }] },
    ]
  },
  {
    id: 'TA0042',
    name: 'Resource Development',
    count: 8,
    techniques: [
      { id: 'T1583', name: 'Acquire Infrastructure', subTechniques: [{ id: 'T1583.001', name: 'Domains' }, { id: 'T1583.002', name: 'DNS Server' }, { id: 'T1583.003', name: 'Virtual Private Server' }, { id: 'T1583.004', name: 'Server' }, { id: 'T1583.005', name: 'Botnet' }, { id: 'T1583.006', name: 'Web Services' }] },
      { id: 'T1584', name: 'Compromise Infrastructure', subTechniques: [{ id: 'T1584.001', name: 'Domains' }, { id: 'T1584.002', name: 'DNS Server' }, { id: 'T1584.003', name: 'Virtual Private Server' }, { id: 'T1584.004', name: 'Server' }, { id: 'T1584.005', name: 'Botnet' }, { id: 'T1584.006', name: 'Web Services' }] },
      { id: 'T1585', name: 'Establish Accounts', subTechniques: [{ id: 'T1585.001', name: 'Social Media Accounts' }, { id: 'T1585.002', name: 'Email Accounts' }, { id: 'T1585.003', name: 'Cloud Accounts' }] },
      { id: 'T1586', name: 'Compromise Accounts', subTechniques: [{ id: 'T1586.001', name: 'Social Media Accounts' }, { id: 'T1586.002', name: 'Email Accounts' }, { id: 'T1586.003', name: 'Cloud Accounts' }] },
      { id: 'T1587', name: 'Develop Capabilities', subTechniques: [{ id: 'T1587.001', name: 'Malware' }, { id: 'T1587.002', name: 'Code Signing Certificates' }, { id: 'T1587.003', name: 'Digital Certificates' }, { id: 'T1587.004', name: 'Exploits' }] },
      { id: 'T1588', name: 'Obtain Capabilities', subTechniques: [{ id: 'T1588.001', name: 'Malware' }, { id: 'T1588.002', name: 'Tool' }, { id: 'T1588.003', name: 'Code Signing Certificates' }, { id: 'T1588.004', name: 'Digital Certificates' }, { id: 'T1588.005', name: 'Exploits' }, { id: 'T1588.006', name: 'Vulnerabilities' }] },
      { id: 'T1608', name: 'Stage Capabilities', subTechniques: [{ id: 'T1608.001', name: 'Upload Malware' }, { id: 'T1608.002', name: 'Upload Tool' }, { id: 'T1608.003', name: 'Install Digital Certificate' }, { id: 'T1608.004', name: 'Drive-by Target' }, { id: 'T1608.005', name: 'Link Target' }] },
      { id: 'T1599', name: 'Network Boundary Bridging', subTechniques: [{ id: 'T1599.001', name: 'Network Address Translation Traversal' }] },
    ]
  },
  {
    id: 'TA0001',
    name: 'Initial Access',
    count: 9,
    techniques: [
      { id: 'T1189', name: 'Drive-by Compromise' },
      { id: 'T1190', name: 'Exploit Public-Facing Application' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1200', name: 'Hardware Additions' },
      { id: 'T1566', name: 'Phishing', subTechniques: [{ id: 'T1566.001', name: 'Spearphishing Attachment' }, { id: 'T1566.002', name: 'Spearphishing Link' }, { id: 'T1566.003', name: 'Spearphishing via Service' }] },
      { id: 'T1091', name: 'Replication Through Removable Media' },
      { id: 'T1195', name: 'Supply Chain Compromise', subTechniques: [{ id: 'T1195.001', name: 'Compromise Software Dependencies' }, { id: 'T1195.002', name: 'Compromise Software Supply Chain' }, { id: 'T1195.003', name: 'Compromise Hardware Supply Chain' }] },
      { id: 'T1199', name: 'Trusted Relationship' },
      { id: 'T1078', name: 'Valid Accounts', subTechniques: [{ id: 'T1078.001', name: 'Default Accounts' }, { id: 'T1078.002', name: 'Domain Accounts' }, { id: 'T1078.003', name: 'Local Accounts' }, { id: 'T1078.004', name: 'Cloud Accounts' }] },
    ]
  },
  {
    id: 'TA0002',
    name: 'Execution',
    count: 14,
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interpreter', subTechniques: [{ id: 'T1059.001', name: 'PowerShell' }, { id: 'T1059.002', name: 'AppleScript' }, { id: 'T1059.003', name: 'Windows Command Shell' }, { id: 'T1059.004', name: 'Unix Shell' }, { id: 'T1059.005', name: 'Visual Basic' }, { id: 'T1059.006', name: 'Python' }, { id: 'T1059.007', name: 'JavaScript' }, { id: 'T1059.008', name: 'Network Device CLI' }] },
      { id: 'T1609', name: 'Container Administration Command' },
      { id: 'T1610', name: 'Deploy Container' },
      { id: 'T1106', name: 'Native API' },
      { id: 'T1053', name: 'Scheduled Task/Job', subTechniques: [{ id: 'T1053.002', name: 'At' }, { id: 'T1053.003', name: 'Cron' }, { id: 'T1053.005', name: 'Scheduled Task' }, { id: 'T1053.006', name: 'Systemd Timers' }, { id: 'T1053.007', name: 'Container Orchestration Job' }] },
      { id: 'T1129', name: 'Shared Modules' },
      { id: 'T1072', name: 'Software Deployment Tools' },
      { id: 'T1569', name: 'System Services', subTechniques: [{ id: 'T1569.001', name: 'Launchctl' }, { id: 'T1569.002', name: 'Service Execution' }] },
      { id: 'T1204', name: 'User Execution', subTechniques: [{ id: 'T1204.001', name: 'Malicious Link' }, { id: 'T1204.002', name: 'Malicious File' }, { id: 'T1204.003', name: 'Malicious Image' }] },
      { id: 'T1047', name: 'Windows Management Instrumentation' },
      { id: 'T1559', name: 'Inter-Process Communication', subTechniques: [{ id: 'T1559.001', name: 'Component Object Model' }, { id: 'T1559.002', name: 'Dynamic Data Exchange' }] },
      { id: 'T1106', name: 'Native API' },
      { id: 'T1129', name: 'Shared Modules' },
      { id: 'T1204', name: 'User Execution' },
    ]
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    count: 19,
    techniques: [
      { id: 'T1543', name: 'Create or Modify System Process', subTechniques: [{ id: 'T1543.001', name: 'Launch Agent' }, { id: 'T1543.002', name: 'Systemd Service' }, { id: 'T1543.003', name: 'Windows Service' }, { id: 'T1543.004', name: 'Launch Daemon' }] },
      { id: 'T1547', name: 'Boot or Logon Autostart Execution', subTechniques: [{ id: 'T1547.001', name: 'Registry Run Keys' }, { id: 'T1547.002', name: 'Authentication Package' }, { id: 'T1547.003', name: 'Time Providers' }, { id: 'T1547.004', name: 'Winlogon Helper DLL' }, { id: 'T1547.005', name: 'Security Support Provider' }, { id: 'T1547.006', name: 'Kernel Modules and Extensions' }, { id: 'T1547.007', name: 'Re-opened Applications' }, { id: 'T1547.008', name: 'LSASS Driver' }, { id: 'T1547.009', name: 'Shortcut Modification' }, { id: 'T1547.010', name: 'Port Monitors' }, { id: 'T1547.012', name: 'Print Processors' }, { id: 'T1547.013', name: 'XDG Autostart Entries' }, { id: 'T1547.014', name: 'Active Setup' }] },
      { id: 'T1037', name: 'Boot or Logon Initialization Scripts', subTechniques: [{ id: 'T1037.001', name: 'Logon Script' }, { id: 'T1037.002', name: 'Login Hook' }, { id: 'T1037.003', name: 'Network Logon Script' }, { id: 'T1037.004', name: 'RC Scripts' }, { id: 'T1037.005', name: 'Startup Items' }] },
      { id: 'T1546', name: 'Event Triggered Execution', subTechniques: [{ id: 'T1546.001', name: 'Change Default File Association' }, { id: 'T1546.002', name: 'Screensaver' }, { id: 'T1546.003', name: 'Windows Management Instrumentation Event Subscription' }, { id: 'T1546.008', name: 'Accessibility Features' }, { id: 'T1546.012', name: 'Image File Execution Options Injection' }] },
      { id: 'T1136', name: 'Create Account', subTechniques: [{ id: 'T1136.001', name: 'Local Account' }, { id: 'T1136.002', name: 'Domain Account' }, { id: 'T1136.003', name: 'Cloud Account' }] },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1574', name: 'Hijack Execution Flow', subTechniques: [{ id: 'T1574.001', name: 'DLL Search Order Hijacking' }, { id: 'T1574.002', name: 'DLL Side-Loading' }, { id: 'T1574.006', name: 'Dynamic Linker Hijacking' }] },
      { id: 'T1554', name: 'Compromise Client Software Binary' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1505', name: 'Server Software Component', subTechniques: [{ id: 'T1505.001', name: 'SQL Stored Procedures' }, { id: 'T1505.002', name: 'Transport Agent' }, { id: 'T1505.003', name: 'Web Shell' }] },
      { id: 'T1205', name: 'Traffic Signaling', subTechniques: [{ id: 'T1205.001', name: 'Port Knocking' }] },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1137', name: 'Office Application Startup', subTechniques: [{ id: 'T1137.001', name: 'Office Template Macros' }, { id: 'T1137.002', name: 'Office Test' }] },
      { id: 'T1542', name: 'Pre-OS Boot', subTechniques: [{ id: 'T1542.001', name: 'System Firmware' }, { id: 'T1542.002', name: 'Component Firmware' }, { id: 'T1542.003', name: 'Bootkit' }] },
      { id: 'T1546', name: 'Event Triggered Execution' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1554', name: 'Compromise Client Software Binary' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1137', name: 'Office Application Startup' },
    ]
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    count: 13,
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism', subTechniques: [{ id: 'T1548.001', name: 'Setuid and Setgid' }, { id: 'T1548.002', name: 'Bypass User Account Control' }, { id: 'T1548.003', name: 'Sudo and Sudo Caching' }, { id: 'T1548.004', name: 'Elevated Execution with Prompt' }] },
      { id: 'T1134', name: 'Access Token Manipulation', subTechniques: [{ id: 'T1134.001', name: 'Token Impersonation/Theft' }, { id: 'T1134.002', name: 'Create Process with Token' }, { id: 'T1134.003', name: 'Make and Impersonate Token' }, { id: 'T1134.004', name: 'Parent PID Spoofing' }, { id: 'T1134.005', name: 'SID-History Injection' }] },
      { id: 'T1547', name: 'Boot or Logon Autostart Execution' },
      { id: 'T1037', name: 'Boot or Logon Initialization Scripts' },
      { id: 'T1543', name: 'Create or Modify System Process' },
      { id: 'T1484', name: 'Domain Policy Modification', subTechniques: [{ id: 'T1484.001', name: 'Group Policy Modification' }, { id: 'T1484.002', name: 'Domain Trust Modification' }] },
      { id: 'T1546', name: 'Event Triggered Execution' },
      { id: 'T1068', name: 'Exploitation for Privilege Escalation' },
      { id: 'T1574', name: 'Hijack Execution Flow' },
      { id: 'T1055', name: 'Process Injection', subTechniques: [{ id: 'T1055.001', name: 'Dynamic-link Library Injection' }, { id: 'T1055.002', name: 'Portable Executable Injection' }, { id: 'T1055.003', name: 'Thread Execution Hijacking' }, { id: 'T1055.004', name: 'Asynchronous Procedure Call' }, { id: 'T1055.008', name: 'Ptrace System Calls' }, { id: 'T1055.011', name: 'Extra Window Memory Injection' }, { id: 'T1055.012', name: 'Process Hollowing' }] },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
    ]
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    count: 42,
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control Mechanism' },
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1006', name: 'Direct Volume Access' },
      { id: 'T1480', name: 'Execution Guardrails', subTechniques: [{ id: 'T1480.001', name: 'Environmental Keying' }] },
      { id: 'T1211', name: 'Exploitation for Defense Evasion' },
      { id: 'T1140', name: 'Deobfuscate/Decode Files or Information' },
      { id: 'T1222', name: 'File and Directory Permissions Modification', subTechniques: [{ id: 'T1222.001', name: 'Windows File and Directory Permissions' }, { id: 'T1222.002', name: 'Linux and Mac File and Directory Permissions' }] },
      { id: 'T1564', name: 'Hide Artifacts', subTechniques: [{ id: 'T1564.001', name: 'Hidden Files and Directories' }, { id: 'T1564.002', name: 'Hidden Users' }, { id: 'T1564.003', name: 'Hidden Window' }, { id: 'T1564.004', name: 'NTFS File Attributes' }, { id: 'T1564.006', name: 'Run Virtual Instance' }] },
      { id: 'T1574', name: 'Hijack Execution Flow' },
      { id: 'T1562', name: 'Impair Defenses', subTechniques: [{ id: 'T1562.001', name: 'Disable or Modify Tools' }, { id: 'T1562.002', name: 'Disable Windows Event Logging' }, { id: 'T1562.004', name: 'Disable or Modify System Firewall' }, { id: 'T1562.006', name: 'Indicator Blocking' }] },
      { id: 'T1070', name: 'Indicator Removal', subTechniques: [{ id: 'T1070.001', name: 'Clear Windows Event Logs' }, { id: 'T1070.002', name: 'Clear Linux or Mac System Logs' }, { id: 'T1070.004', name: 'File Deletion' }, { id: 'T1070.006', name: 'Timestomp' }] },
      { id: 'T1027', name: 'Obfuscated Files or Information', subTechniques: [{ id: 'T1027.001', name: 'Binary Padding' }, { id: 'T1027.002', name: 'Software Packing' }, { id: 'T1027.003', name: 'Steganography' }, { id: 'T1027.004', name: 'Compile After Delivery' }, { id: 'T1027.005', name: 'Indicator Removal from Tools' }, { id: 'T1027.006', name: 'HTML Smuggling' }] },
      { id: 'T1014', name: 'Rootkit' },
      { id: 'T1497', name: 'Virtualization/Sandbox Evasion', subTechniques: [{ id: 'T1497.001', name: 'System Checks' }, { id: 'T1497.002', name: 'User Activity Based Checks' }, { id: 'T1497.003', name: 'Time Based Evasion' }] },
      { id: 'T1221', name: 'Template Injection' },
      { id: 'T1207', name: 'Rogue Domain Controller' },
      { id: 'T1036', name: 'Masquerading', subTechniques: [{ id: 'T1036.001', name: 'Invalid Code Signature' }, { id: 'T1036.002', name: 'Right-to-Left Override' }, { id: 'T1036.003', name: 'Rename System Utilities' }, { id: 'T1036.004', name: 'Masquerade Task or Service' }, { id: 'T1036.005', name: 'Match Legitimate Name or Location' }] },
      { id: 'T1112', name: 'Modify Registry' },
      { id: 'T1027', name: 'Obfuscated Files or Information' },
      { id: 'T1055', name: 'Process Injection' },
      { id: 'T1497', name: 'Virtualization/Sandbox Evasion' },
      { id: 'T1202', name: 'Indirect Command Execution' },
      { id: 'T1550', name: 'Use Alternate Authentication Material' },
      { id: 'T1553', name: 'Subvert Trust Controls', subTechniques: [{ id: 'T1553.001', name: 'Gatekeeper Bypass' }, { id: 'T1553.002', name: 'Code Signing' }, { id: 'T1553.004', name: 'Install Root Certificate' }] },
      { id: 'T1218', name: 'System Binary Proxy Execution', subTechniques: [{ id: 'T1218.001', name: 'Compiled HTML File' }, { id: 'T1218.011', name: 'Rundll32' }] },
      { id: 'T1216', name: 'System Script Proxy Execution' },
      { id: 'T1045', name: 'Software Packing' },
      { id: 'T1497', name: 'Virtualization/Sandbox Evasion' },
      { id: 'T1027', name: 'Obfuscated Files or Information' },
      { id: 'T1218', name: 'System Binary Proxy Execution' },
      { id: 'T1553', name: 'Subvert Trust Controls' },
      { id: 'T1036', name: 'Masquerading' },
      { id: 'T1211', name: 'Exploitation for Defense Evasion' },
      { id: 'T1222', name: 'File and Directory Permissions Modification' },
      { id: 'T1564', name: 'Hide Artifacts' },
      { id: 'T1574', name: 'Hijack Execution Flow' },
      { id: 'T1562', name: 'Impair Defenses' },
      { id: 'T1070', name: 'Indicator Removal' },
      { id: 'T1014', name: 'Rootkit' },
      { id: 'T1221', name: 'Template Injection' },
      { id: 'T1207', name: 'Rogue Domain Controller' },
      { id: 'T1036', name: 'Masquerading' },
      { id: 'T1112', name: 'Modify Registry' },
    ]
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    count: 17,
    techniques: [
      { id: 'T1003', name: 'OS Credential Dumping', subTechniques: [{ id: 'T1003.001', name: 'LSASS Memory' }, { id: 'T1003.002', name: 'Security Account Manager' }, { id: 'T1003.003', name: 'NTDS' }, { id: 'T1003.004', name: 'LSA Secrets' }, { id: 'T1003.005', name: 'Cached Domain Credentials' }, { id: 'T1003.006', name: 'DCSync' }] },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1110', name: 'Brute Force', subTechniques: [{ id: 'T1110.001', name: 'Password Guessing' }, { id: 'T1110.002', name: 'Password Cracking' }, { id: 'T1110.003', name: 'Password Spraying' }, { id: 'T1110.004', name: 'Credential Stuffing' }] },
      { id: 'T1555', name: 'Credentials from Password Stores', subTechniques: [{ id: 'T1555.001', name: 'Keychain' }, { id: 'T1555.002', name: 'Securityd Memory' }, { id: 'T1555.003', name: 'Credentials from Web Browsers' }, { id: 'T1555.004', name: 'Windows Credential Manager' }] },
      { id: 'T1212', name: 'Exploitation for Credential Access' },
      { id: 'T1056', name: 'Input Capture', subTechniques: [{ id: 'T1056.001', name: 'Keylogging' }, { id: 'T1056.002', name: 'GUI Input Capture' }, { id: 'T1056.003', name: 'Web Portal Capture' }, { id: 'T1056.004', name: 'Credential API Hooking' }] },
      { id: 'T1557', name: 'Adversary-in-the-Middle', subTechniques: [{ id: 'T1557.001', name: 'LLMNR/NBT-NS Poisoning' }, { id: 'T1557.002', name: 'ARP Cache Poisoning' }, { id: 'T1557.003', name: 'DHCP Spoofing' }] },
      { id: 'T1552', name: 'Unsecured Credentials', subTechniques: [{ id: 'T1552.001', name: 'Credentials In Files' }, { id: 'T1552.002', name: 'Credentials in Registry' }, { id: 'T1552.004', name: 'Private Keys' }] },
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1555', name: 'Credentials from Password Stores' },
      { id: 'T1212', name: 'Exploitation for Credential Access' },
      { id: 'T1056', name: 'Input Capture' },
      { id: 'T1557', name: 'Adversary-in-the-Middle' },
      { id: 'T1552', name: 'Unsecured Credentials' },
      { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', subTechniques: [{ id: 'T1558.001', name: 'Golden Ticket' }, { id: 'T1558.002', name: 'Silver Ticket' }, { id: 'T1558.003', name: 'Kerberoasting' }] },
      { id: 'T1539', name: 'Steal Web Session Cookie' },
    ]
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    count: 31,
    techniques: [
      { id: 'T1087', name: 'Account Discovery', subTechniques: [{ id: 'T1087.001', name: 'Local Account' }, { id: 'T1087.002', name: 'Domain Account' }, { id: 'T1087.003', name: 'Email Account' }, { id: 'T1087.004', name: 'Cloud Account' }] },
      { id: 'T1010', name: 'Application Window Discovery' },
      { id: 'T1217', name: 'Browser Information Discovery' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
      { id: 'T1538', name: 'Cloud Service Dashboard' },
      { id: 'T1482', name: 'Domain Trust Discovery' },
      { id: 'T1083', name: 'File and Directory Discovery' },
      { id: 'T1046', name: 'Network Service Discovery' },
      { id: 'T1135', name: 'Network Share Discovery' },
      { id: 'T1040', name: 'Network Sniffing' },
      { id: 'T1201', name: 'Password Policy Discovery' },
      { id: 'T1120', name: 'Peripheral Device Discovery' },
      { id: 'T1069', name: 'Permission Groups Discovery', subTechniques: [{ id: 'T1069.001', name: 'Local Groups' }, { id: 'T1069.002', name: 'Domain Groups' }, { id: 'T1069.003', name: 'Cloud Groups' }] },
      { id: 'T1057', name: 'Process Discovery' },
      { id: 'T1012', name: 'Query Registry' },
      { id: 'T1018', name: 'Remote System Discovery' },
      { id: 'T1016', name: 'System Network Configuration Discovery', subTechniques: [{ id: 'T1016.001', name: 'Internet Connection Discovery' }] },
      { id: 'T1007', name: 'System Service Discovery' },
      { id: 'T1082', name: 'System Information Discovery' },
      { id: 'T1016', name: 'System Network Configuration Discovery' },
      { id: 'T1049', name: 'System Network Connections Discovery' },
      { id: 'T1033', name: 'System Owner/User Discovery' },
      { id: 'T1007', name: 'System Service Discovery' },
      { id: 'T1124', name: 'System Time Discovery' },
      { id: 'T1496', name: 'Virtualization/Sandbox Evasion' },
      { id: 'T1087', name: 'Account Discovery' },
      { id: 'T1010', name: 'Application Window Discovery' },
      { id: 'T1217', name: 'Browser Information Discovery' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
      { id: 'T1538', name: 'Cloud Service Dashboard' },
      { id: 'T1482', name: 'Domain Trust Discovery' },
    ]
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    count: 9,
    techniques: [
      { id: 'T1021', name: 'Remote Services', subTechniques: [{ id: 'T1021.001', name: 'Remote Desktop Protocol' }, { id: 'T1021.002', name: 'SMB/Windows Admin Shares' }, { id: 'T1021.003', name: 'Distributed Component Object Model' }, { id: 'T1021.004', name: 'SSH' }, { id: 'T1021.005', name: 'VNC' }, { id: 'T1021.006', name: 'Windows Remote Management' }] },
      { id: 'T1091', name: 'Replication Through Removable Media' },
      { id: 'T1570', name: 'Lateral Tool Transfer' },
      { id: 'T1563', name: 'Remote Service Session Hijacking', subTechniques: [{ id: 'T1563.001', name: 'SSH Hijacking' }, { id: 'T1563.002', name: 'RDP Hijacking' }] },
      { id: 'T1210', name: 'Exploitation of Remote Services' },
      { id: 'T1080', name: 'Taint Shared Content' },
      { id: 'T1563', name: 'Remote Service Session Hijacking' },
      { id: 'T1021', name: 'Remote Services' },
      { id: 'T1091', name: 'Replication Through Removable Media' },
    ]
  },
  {
    id: 'TA0009',
    name: 'Collection',
    count: 17,
    techniques: [
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1039', name: 'Data from Network Shared Drive' },
      { id: 'T1025', name: 'Data from Removable Media' },
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1074', name: 'Data Staged', subTechniques: [{ id: 'T1074.001', name: 'Local Data Staging' }, { id: 'T1074.002', name: 'Remote Data Staging' }] },
      { id: 'T1113', name: 'Screen Capture' },
      { id: 'T1115', name: 'Clipboard Data' },
      { id: 'T1056', name: 'Input Capture' },
      { id: 'T1114', name: 'Email Collection', subTechniques: [{ id: 'T1114.001', name: 'Local Email Collection' }, { id: 'T1114.002', name: 'Remote Email Collection' }, { id: 'T1114.003', name: 'Email Forwarding Rule' }] },
      { id: 'T1213', name: 'Data from Information Repositories', subTechniques: [{ id: 'T1213.001', name: 'Confluence' }, { id: 'T1213.002', name: 'Sharepoint' }, { id: 'T1213.003', name: 'Code Repositories' }] },
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1039', name: 'Data from Network Shared Drive' },
      { id: 'T1025', name: 'Data from Removable Media' },
      { id: 'T1074', name: 'Data Staged' },
      { id: 'T1113', name: 'Screen Capture' },
      { id: 'T1115', name: 'Clipboard Data' },
      { id: 'T1056', name: 'Input Capture' },
    ]
  },
  {
    id: 'TA0011',
    name: 'Command and Control',
    count: 16,
    techniques: [
      { id: 'T1071', name: 'Application Layer Protocol', subTechniques: [{ id: 'T1071.001', name: 'Web Protocols' }, { id: 'T1071.002', name: 'File Transfer Protocols' }, { id: 'T1071.003', name: 'Mail Protocols' }, { id: 'T1071.004', name: 'DNS' }] },
      { id: 'T1092', name: 'Communication Through Removable Media' },
      { id: 'T1132', name: 'Data Encoding', subTechniques: [{ id: 'T1132.001', name: 'Standard Encoding' }, { id: 'T1132.002', name: 'Non-Standard Encoding' }] },
      { id: 'T1008', name: 'Fallback Channels' },
      { id: 'T1105', name: 'Ingress Tool Transfer' },
      { id: 'T1104', name: 'Multi-Stage Channels' },
      { id: 'T1095', name: 'Non-Application Layer Protocol' },
      { id: 'T1571', name: 'Non-Standard Port' },
      { id: 'T1572', name: 'Protocol Tunneling' },
      { id: 'T1090', name: 'Proxy', subTechniques: [{ id: 'T1090.001', name: 'Internal Proxy' }, { id: 'T1090.002', name: 'External Proxy' }, { id: 'T1090.003', name: 'Multi-hop Proxy' }] },
      { id: 'T1219', name: 'Remote Access Tools' },
      { id: 'T1205', name: 'Traffic Signaling', subTechniques: [{ id: 'T1205.001', name: 'Port Knocking' }] },
      { id: 'T1102', name: 'Web Service', subTechniques: [{ id: 'T1102.001', name: 'Dead Drop Resolver' }, { id: 'T1102.002', name: 'Bidirectional Communication' }, { id: 'T1102.003', name: 'One-Way Communication' }] },
      { id: 'T1071', name: 'Application Layer Protocol' },
      { id: 'T1092', name: 'Communication Through Removable Media' },
      { id: 'T1132', name: 'Data Encoding' },
    ]
  },
  {
    id: 'TA0010',
    name: 'Exfiltration',
    count: 9,
    techniques: [
      { id: 'T1020', name: 'Automated Exfiltration', subTechniques: [{ id: 'T1020.001', name: 'Traffic Duplication' }] },
      { id: 'T1030', name: 'Data Transfer Size Limits' },
      { id: 'T1027', name: 'Obfuscated Files or Information' },
      { id: 'T1011', name: 'Exfiltration Over Other Network Medium', subTechniques: [{ id: 'T1011.001', name: 'Exfiltration Over Bluetooth' }] },
      { id: 'T1052', name: 'Exfiltration Over Physical Medium', subTechniques: [{ id: 'T1052.001', name: 'Exfiltration over USB' }] },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'T1011', name: 'Exfiltration Over Other Network Medium' },
      { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', subTechniques: [{ id: 'T1048.001', name: 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol' }, { id: 'T1048.002', name: 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol' }, { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol' }] },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    ]
  },
  {
    id: 'TA0040',
    name: 'Impact',
    count: 13,
    techniques: [
      { id: 'T1485', name: 'Data Destruction' },
      { id: 'T1486', name: 'Data Encrypted for Impact' },
      { id: 'T1491', name: 'Defacement', subTechniques: [{ id: 'T1491.001', name: 'Internal Defacement' }, { id: 'T1491.002', name: 'External Defacement' }] },
      { id: 'T1561', name: 'Disk Wipe', subTechniques: [{ id: 'T1561.001', name: 'Disk Content Wipe' }, { id: 'T1561.002', name: 'Disk Structure Wipe' }] },
      { id: 'T1499', name: 'Endpoint Denial of Service', subTechniques: [{ id: 'T1499.001', name: 'OS Exhaustion Flood' }, { id: 'T1499.002', name: 'Service Exhaustion Flood' }, { id: 'T1499.003', name: 'Application Exhaustion Flood' }, { id: 'T1499.004', name: 'Application or System Exploitation' }] },
      { id: 'T1495', name: 'Firmware Corruption' },
      { id: 'T1490', name: 'Inhibit System Recovery' },
      { id: 'T1489', name: 'Service Stop' },
      { id: 'T1529', name: 'System Shutdown/Reboot' },
      { id: 'T1496', name: 'Resource Hijacking' },
      { id: 'T1498', name: 'Network Denial of Service', subTechniques: [{ id: 'T1498.001', name: 'Direct Network Flood' }, { id: 'T1498.002', name: 'Reflection Amplification' }] },
      { id: 'T1485', name: 'Data Destruction' },
      { id: 'T1486', name: 'Data Encrypted for Impact' },
    ]
  },
];

export const getAllTechniques = () => {
  const all: { tacticId: string; tacticName: string; id: string; name: string; isSub: boolean; parentId?: string }[] = [];
  enterpriseMatrix.forEach(tactic => {
    tactic.techniques.forEach(tech => {
      all.push({ tacticId: tactic.id, tacticName: tactic.name, id: tech.id, name: tech.name, isSub: false });
      if (tech.subTechniques) {
        tech.subTechniques.forEach(sub => {
          all.push({ tacticId: tactic.id, tacticName: tactic.name, id: sub.id, name: sub.name, isSub: true, parentId: tech.id });
        });
      }
    });
  });
  return all;
};

export const totalTechniquesCount = getAllTechniques().length;
