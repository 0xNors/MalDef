import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';

const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'database.json');

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  role: 'ADMIN' | 'ANALYST' | 'MANAGER';
  createdAt: string;
  lastLogin?: string;
  isActive: boolean;
}

export interface Sample {
  id: string;
  originalFilename: string;
  safeFilename: string;
  fileSize: number;
  mimeType: string;
  sha256: string;
  sha1: string;
  md5: string;
  uploadTimestamp: string;
  uploadedBy: string;
  analysisStatus: 'PENDING' | 'ANALYZING' | 'COMPLETED' | 'FAILED';
  filePath: string;
}

export interface StaticFinding {
  id: string;
  sampleId: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  evidence: string;
  score: number;
}

export interface BehaviorEvent {
  id: string;
  sampleId: string;
  timestamp: string;
  eventType: string;
  process?: string;
  parentProcess?: string;
  details: any;
  severity: string;
}

export interface NetworkEvent {
  id: string;
  sampleId: string;
  timestamp: string;
  sourceProcess: string;
  destinationIp: string;
  destinationDomain?: string;
  port: number;
  protocol: string;
  frequency: number;
  severity: string;
  isAnomalous: boolean;
}

export interface IOC {
  id: string;
  value: string;
  type: 'SHA256' | 'SHA1' | 'MD5' | 'IP' | 'DOMAIN' | 'URL' | 'FILENAME';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source: string;
  firstSeen: string;
  lastSeen: string;
  description: string;
  relatedAlerts: string[];
  tags: string[];
  // Advanced fields
  confidence?: number;
  timesSeen?: number;
  relatedSamples?: string[];
  mitreTechniques?: string[];
  isWhitelisted?: boolean;
  isBlocked?: boolean;
  reputationScore?: number;
  threatIntel?: {
    abuseIPDB?: { score: number; reports: number; isWhitelisted: boolean };
    virusTotal?: { detections: number; total: number; ratio: string };
    otx?: { pulses: number; tags: string[] };
  };
  lastEnriched?: string;
  autoExtracted?: boolean;
  fileName?: string;
  // Automated important details + user additional info
  enrichmentDetails?: {
    geo?: { country: string; city: string; countryCode: string; lat: number; lon: number; asn: string; isp: string; org: string };
    whois?: { registrar: string; created: string; expires: string; updated: string; nameServers: string[]; status: string };
    fileDetails?: { fileSize: number; mimeType: string; magic: string; entropy: number; imphash?: string; compileTime?: string };
    networkDetails?: { openPorts: number[]; protocols: string[]; reverseDns?: string; firstSeenInWild?: string };
    relatedThreats?: string[];
  };
  // User additional info for future
  notes?: string;
  threatActor?: string;
  campaign?: string;
  additionalInfo?: string;
  customFields?: { key: string; value: string }[];
  lastUpdatedBy?: string;
  history?: { timestamp: string; user: string; action: string; details: string }[];
  isImportant?: boolean;
  autoEnriched?: boolean;
}

export interface Detection {
  id: string;
  sampleId: string;
  ruleId: string;
  ruleName: string;
  category: string;
  severity: string;
  score: number;
  explanation: string;
  evidence: string;
  timestamp: string;
}

export interface Alert {
  id: string;
  sampleId: string;
  sampleFilename: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  detectionReason: string;
  status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  assignedAnalyst?: string;
  mitreTechniques: string[];
  analysisId?: string;
}

export interface Analysis {
  id: string;
  sampleId: string;
  timestamp: string;
  riskScore: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  classification: 'BENIGN' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';
  reasons: string[];
  staticFindings: string[];
  detections: string[];
  mlPrediction?: string;
  mitreMappings: any[];
  recommendations: string[];
  entropy: { overall: number; sections: { name: string; entropy: number; size: number }[] };
  fileInfo: any;
  timeline: any[];
}

export interface AnalystNote {
  id: string;
  alertId?: string;
  sampleId?: string;
  author: string;
  content: string;
  timestamp: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  condition: string;
  score: number;
  enabled: boolean;
  mitreTechnique?: string;
  createdAt: string;
}

export interface Report {
  id: string;
  sampleId: string;
  analysisId: string;
  generatedBy: string;
  timestamp: string;
  reportData: any;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  userId: string;
  action: string;
  resource: string;
  details: string;
  ip?: string;
}

export interface DB {
  users: User[];
  samples: Sample[];
  analyses: Analysis[];
  staticFindings: StaticFinding[];
  behaviorEvents: BehaviorEvent[];
  networkEvents: NetworkEvent[];
  iocs: IOC[];
  detections: Detection[];
  alerts: Alert[];
  analystNotes: AnalystNote[];
  detectionRules: DetectionRule[];
  reports: Report[];
  auditLogs: AuditLog[];
}

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const subdirs = ['samples', 'telemetry', 'datasets', 'mitre', 'reports'];
    subdirs.forEach(d => {
      const p = path.join(DATA_DIR, d);
      if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    });
  } catch (e) {
    console.error('ensureDataDir error', e);
  }
}

function getDefaultDB(): DB {
  return {
    users: [],
    samples: [],
    analyses: [],
    staticFindings: [],
    behaviorEvents: [],
    networkEvents: [],
    iocs: [],
    detections: [],
    alerts: [],
    analystNotes: [],
    detectionRules: [
      { id: 'RULE-001', name: 'High Entropy Section', description: 'Detects sections with entropy > 7.2 indicating possible packing or encryption', category: 'Static indicator', severity: 'MEDIUM', condition: 'section_entropy > 7.2', score: 20, enabled: true, mitreTechnique: 'T1027', createdAt: new Date().toISOString() },
      { id: 'RULE-002', name: 'Suspicious Imports', description: 'Executable imports suspicious API combinations (suspicious API combinations)', category: 'Static indicator', severity: 'HIGH', condition: 'suspicious_imports >= 3', score: 25, enabled: true, mitreTechnique: 'T1106', createdAt: new Date().toISOString() },
      { id: 'RULE-003', name: 'Suspicious String Patterns', description: 'Detects URLs, IPs, PowerShell, and obfuscation patterns in strings', category: 'Static indicator', severity: 'MEDIUM', condition: 'suspicious_strings >= 5', score: 15, enabled: true, mitreTechnique: 'T1071', createdAt: new Date().toISOString() },
      { id: 'RULE-004', name: 'Process Injection Pattern', description: 'Behavioral correlation: process creation combined with file modification', category: 'Behavioral indicator', severity: 'HIGH', condition: 'process_creation AND file_modification within 60s', score: 30, enabled: true, mitreTechnique: 'T1055', createdAt: new Date().toISOString() },
      { id: 'RULE-005', name: 'Persistence Mechanism', description: 'Registry modification combined with scheduled task or service creation', category: 'Behavioral indicator', severity: 'CRITICAL', condition: 'registry_change AND (scheduled_task_event OR service_event)', score: 35, enabled: true, mitreTechnique: 'T1053', createdAt: new Date().toISOString() },
      { id: 'RULE-006', name: 'Anomalous Network Connection', description: 'Unusual outbound connection on suspicious port or to rare destination', category: 'Network indicator', severity: 'HIGH', condition: 'rare_destination OR suspicious_port', score: 25, enabled: true, mitreTechnique: 'T1071', createdAt: new Date().toISOString() },
      { id: 'RULE-007', name: 'IOC Match', description: 'File hash or network indicator matches known IOC from threat intelligence', category: 'IOC match', severity: 'CRITICAL', condition: 'ioc_match', score: 40, enabled: true, mitreTechnique: 'T1105', createdAt: new Date().toISOString() },
      { id: 'RULE-008', name: 'Correlated Threat Pattern', description: 'Multiple independent suspicious indicators correlated across static, behavior, and network', category: 'Correlation', severity: 'HIGH', condition: 'correlation_score > 60', score: 20, enabled: true, mitreTechnique: 'T1082', createdAt: new Date().toISOString() },
    ],
    reports: [],
    auditLogs: [],
  };
}

export function loadDB(): DB {
  ensureDataDir();
  
  if (!fs.existsSync(DB_FILE)) {
    const defaultDB = getDefaultDB();
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(defaultDB, null, 2));
    } catch (e) {
      console.error('Failed to create DB file', e);
    }
    return defaultDB;
  }
  
  try {
    const data = fs.readFileSync(DB_FILE, 'utf-8');
    if (!data || data.trim().length === 0) {
      console.warn('DB file empty, returning default');
      return getDefaultDB();
    }
    const parsed = JSON.parse(data) as DB;
    // Ensure arrays exist
    if (!parsed.detectionRules || parsed.detectionRules.length === 0) {
      parsed.detectionRules = getDefaultDB().detectionRules;
    }
    if (!parsed.users) parsed.users = [];
    if (!parsed.iocs) parsed.iocs = [];
    if (!parsed.auditLogs) parsed.auditLogs = [];
    if (!parsed.samples) parsed.samples = [];
    if (!parsed.analyses) parsed.analyses = [];
    if (!parsed.staticFindings) parsed.staticFindings = [];
    if (!parsed.behaviorEvents) parsed.behaviorEvents = [];
    if (!parsed.networkEvents) parsed.networkEvents = [];
    if (!parsed.detections) parsed.detections = [];
    if (!parsed.alerts) parsed.alerts = [];
    if (!parsed.analystNotes) parsed.analystNotes = [];
    if (!parsed.reports) parsed.reports = [];
    
    return parsed;
  } catch (e) {
    console.error('DB load error, returning default without overwriting:', e);
    return getDefaultDB();
  }
}

export function saveDB(db: DB) {
  ensureDataDir();
  try {
    // Direct atomic write
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error('Failed to save DB', e);
    throw e;
  }
}

export function generateId(prefix: string = ''): string {
  return `${prefix}${randomUUID().slice(0, 8).toUpperCase()}`;
}
