/**
 * MCK-Guard Strict Sandboxing - VirusTotal System Design
 * Security: file validation, magic bytes, quarantine, no privileged execution, network isolation
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export interface SandboxingResult {
  safe: boolean;
  quarantined: boolean;
  checks: { name: string; passed: boolean; severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; details: string }[];
  riskScore: number;
  action: 'ALLOW' | 'QUARANTINE' | 'REJECT';
  reason: string;
  fileInfo: {
    magic: string;
    mimeType: string;
    extension: string;
    size: number;
    sha256: string;
    entropy: number;
    isExecutable: boolean;
    isArchive: boolean;
    hasOverlay: boolean;
  };
}

const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB VirusTotal limit
const QUARANTINE_DIR = path.join(process.cwd(), 'data', 'quarantine');

// Dangerous extensions that require extra sandboxing
const DANGEROUS_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.apk', '.com', '.pif', '.msi'];

// Magic bytes validation
const MAGIC_BYTES: Record<string, { mime: string; ext: string[]; executable: boolean }> = {
  '4D5A': { mime: 'application/x-msdownload', ext: ['.exe', '.dll'], executable: true },
  '7F454C46': { mime: 'application/x-executable', ext: ['.elf'], executable: true },
  '504B0304': { mime: 'application/zip', ext: ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk'], executable: false },
  '25504446': { mime: 'application/pdf', ext: ['.pdf'], executable: false },
  '1F8B': { mime: 'application/gzip', ext: ['.gz'], executable: false },
  '52617221': { mime: 'application/x-rar-compressed', ext: ['.rar'], executable: false },
  '89504E47': { mime: 'image/png', ext: ['.png'], executable: false },
  'FFD8FF': { mime: 'image/jpeg', ext: ['.jpg', '.jpeg'], executable: false },
  '47494638': { mime: 'image/gif', ext: ['.gif'], executable: false },
  '23212F': { mime: 'text/x-script', ext: ['.sh', '.py', '.js'], executable: false },
};

function ensureQuarantineDir() {
  if (!fs.existsSync(QUARANTINE_DIR)) {
    fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
  }
}

function calculateEntropy(buffer: Buffer): number {
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) freq[buffer[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / buffer.length;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

function detectOverlay(buffer: Buffer): boolean {
  try {
    if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
      const e_lfanew = buffer.readUInt32LE(0x3C);
      if (e_lfanew < buffer.length - 6) {
        // Check if file is much larger than PE headers indicate
        return buffer.length > 1024 * 1024 && buffer.length > e_lfanew * 10;
      }
    }
  } catch {}
  return false;
}

export function validateFileSecurity(buffer: Buffer, filename: string): SandboxingResult {
  ensureQuarantineDir();
  
  const checks: SandboxingResult['checks'] = [];
  let riskScore = 0;
  
  const size = buffer.length;
  const ext = path.extname(filename).toLowerCase();
  const magic = buffer.subarray(0, 8).toString('hex').toUpperCase();
  const magicShort = magic.substring(0, 8);
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = calculateEntropy(buffer.subarray(0, Math.min(buffer.length, 1024 * 1024)));
  const hasOverlay = detectOverlay(buffer);
  
  let mimeType = 'application/octet-stream';
  let isExecutable = false;
  let isArchive = false;
  
  // Check magic bytes
  for (const [sig, info] of Object.entries(MAGIC_BYTES)) {
    if (magic.startsWith(sig)) {
      mimeType = info.mime;
      isExecutable = info.executable;
      isArchive = info.mime.includes('zip') || info.mime.includes('rar') || info.mime.includes('gzip');
      break;
    }
  }

  // 1. File size check
  if (size > MAX_FILE_SIZE) {
    checks.push({ name: 'File Size', passed: false, severity: 'CRITICAL', details: `File size ${size} exceeds max ${MAX_FILE_SIZE} (1GB) - reject per VirusTotal design` });
    riskScore += 100;
  } else if (size > 100 * 1024 * 1024) {
    checks.push({ name: 'File Size', passed: true, severity: 'MEDIUM', details: `Large file ${size} bytes - requires extra sandboxing` });
    riskScore += 15;
  } else {
    checks.push({ name: 'File Size', passed: true, severity: 'LOW', details: `File size ${size} within limits` });
  }

  // 2. Extension validation
  if (DANGEROUS_EXTENSIONS.includes(ext)) {
    checks.push({ name: 'Dangerous Extension', passed: true, severity: 'HIGH', details: `Extension ${ext} is executable/script - requires sandboxing, no privileged execution` });
    riskScore += 20;
    isExecutable = true;
  } else {
    checks.push({ name: 'Extension Check', passed: true, severity: 'LOW', details: `Extension ${ext} - ${DANGEROUS_EXTENSIONS.includes(ext) ? 'dangerous' : 'safe'}` });
  }

  // 3. Magic byte validation (masquerading detection)
  const expectedExts = Object.values(MAGIC_BYTES).find(v => magic.startsWith(Object.keys(MAGIC_BYTES).find(k => MAGIC_BYTES[k].mime === v.mime) || ''))?.ext;
  const magicValid = !expectedExts || expectedExts.includes(ext) || ext === '' || isArchive;
  
  if (ext === '.exe' && !isExecutable && magicShort !== '4D5A') {
    checks.push({ name: 'Magic Byte Mismatch', passed: false, severity: 'CRITICAL', details: `File has .exe extension but magic ${magicShort} is not PE (MZ) - masquerading attack!` });
    riskScore += 50;
  } else if (!magicValid && size > 100) {
    checks.push({ name: 'Magic Byte Check', passed: false, severity: 'MEDIUM', details: `Magic ${magicShort} does not match extension ${ext} - possible masquerading` });
    riskScore += 15;
  } else {
    checks.push({ name: 'Magic Byte Check', passed: true, severity: 'LOW', details: `Magic ${magicShort} valid for ${mimeType}` });
  }

  // 4. Entropy check for obfuscation
  if (entropy > 7.8 && !isArchive && mimeType !== 'application/pdf' && mimeType !== 'image/png' && mimeType !== 'image/jpeg') {
    checks.push({ name: 'High Entropy', passed: true, severity: 'HIGH', details: `High entropy ${entropy} - possible packing/encryption, sandbox required` });
    riskScore += 25;
  } else if (entropy > 7.5 && isExecutable) {
    checks.push({ name: 'Entropy Check', passed: true, severity: 'MEDIUM', details: `Entropy ${entropy} elevated for executable - possible packing` });
    riskScore += 10;
  } else {
    checks.push({ name: 'Entropy Check', passed: true, severity: 'LOW', details: `Entropy ${entropy} normal for ${mimeType}` });
  }

  // 5. Overlay detection
  if (hasOverlay) {
    checks.push({ name: 'Overlay Data', passed: true, severity: 'HIGH', details: 'File has overlay data appended - common in MCK droppers, sandbox required' });
    riskScore += 20;
  } else {
    checks.push({ name: 'Overlay Check', passed: true, severity: 'LOW', details: 'No overlay data' });
  }

  // 6. Path traversal check
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    checks.push({ name: 'Path Traversal', passed: false, severity: 'CRITICAL', details: `Filename ${filename} contains path traversal - reject` });
    riskScore += 100;
  } else {
    checks.push({ name: 'Path Traversal', passed: true, severity: 'LOW', details: 'Filename safe' });
  }

  // 7. Null byte injection
  if (filename.includes('\0')) {
    checks.push({ name: 'Null Byte', passed: false, severity: 'CRITICAL', details: 'Filename contains null byte - injection attack' });
    riskScore += 100;
  } else {
    checks.push({ name: 'Null Byte Check', passed: true, severity: 'LOW', details: 'No null bytes' });
  }

  // 8. Double extension (e.g., document.pdf.exe)
  const parts = filename.split('.');
  if (parts.length > 2 && DANGEROUS_EXTENSIONS.includes('.' + parts[parts.length - 1].toLowerCase())) {
    const secondExt = '.' + parts[parts.length - 2].toLowerCase();
    if (['.pdf', '.doc', '.docx', '.jpg', '.png', '.txt'].includes(secondExt)) {
      checks.push({ name: 'Double Extension', passed: false, severity: 'HIGH', details: `Double extension ${filename} - ${secondExt}${ext} masquerading as document/image` });
      riskScore += 30;
    }
  }

  // Determine action
  let action: SandboxingResult['action'] = 'ALLOW';
  let reason = 'File passed all security checks';
  let quarantined = false;
  let safe = true;

  if (riskScore >= 100 || checks.some(c => !c.passed && c.severity === 'CRITICAL')) {
    action = 'REJECT';
    reason = 'Critical security violation - file rejected per VirusTotal strict security';
    safe = false;
  } else if (riskScore >= 30 || isExecutable || hasOverlay || DANGEROUS_EXTENSIONS.includes(ext)) {
    action = 'QUARANTINE';
    reason = `File requires sandboxing: risk ${riskScore}, executable ${isExecutable}, overlay ${hasOverlay} - quarantine and scan in isolated environment`;
    quarantined = true;
    safe = true; // Safe after quarantine
  }

  return {
    safe,
    quarantined,
    checks,
    riskScore: Math.min(riskScore, 100),
    action,
    reason,
    fileInfo: {
      magic: magicShort,
      mimeType,
      extension: ext,
      size,
      sha256,
      entropy,
      isExecutable,
      isArchive,
      hasOverlay
    }
  };
}

export function quarantineFile(buffer: Buffer, filename: string, sha256: string): string {
  ensureQuarantineDir();
  const quarantinePath = path.join(QUARANTINE_DIR, `${sha256}_${Date.now()}_${filename.replace(/[^a-zA-Z0-9.-]/g, '_')}`);
  fs.writeFileSync(quarantinePath, buffer);
  return quarantinePath;
}

export function createSecureFilename(original: string, sha256: string): string {
  const ext = path.extname(original).toLowerCase();
  const safeBase = original.replace(/[^a-zA-Z0-9.-]/g, '_').substring(0, 50);
  // Random ID like VirusTotal: randomly generated ID
  const randomId = crypto.randomBytes(16).toString('hex');
  return `${randomId}_${sha256.substring(0, 8)}_${safeBase}`;
}

export function validateUploadRequest(filename: string, size: number, mimeType?: string): { valid: boolean; reason?: string } {
  if (!filename || filename.length === 0) return { valid: false, reason: 'Filename required' };
  if (filename.length > 255) return { valid: false, reason: 'Filename too long' };
  if (size === 0) return { valid: false, reason: 'Empty file' };
  if (size > MAX_FILE_SIZE) return { valid: false, reason: `File size ${size} exceeds 1GB limit` };
  
  // Block dangerous paths
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return { valid: false, reason: 'Invalid filename - path traversal' };
  }

  return { valid: true };
}
