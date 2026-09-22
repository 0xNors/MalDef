/**
 * MCK-Guard Cassandra-like Partitioned Storage - VirusTotal System Design
 * AWS Keyspaces (Cassandra) simulation: distributed, scalable, partitioned
 * RowID: SHA256:Timestamp, File Metadata, Analysis results aggregated
 */

import fs from 'fs';
import path from 'path';

const CASSANDRA_DIR = path.join(process.cwd(), 'data', 'cassandra');

interface FileScanRow {
  rowId: string; // SHA256:Timestamp
  sha256: string;
  timestamp: string;
  partitionKey: string; // user_id:SHA256:UnixTimestamp per design
  history: {
    createDate: string;
    firstSubmission: string;
    lastSubmission: string;
    analysisCount: number;
    submissions: { timestamp: string; userId: string; filename: string; size: number }[];
  };
  fileMetadata: {
    attributes: string[];
    fileNames: string[];
    fileType: string;
    fileSize: number;
    md5: string;
    sha1: string;
    sha256: string;
    vhash?: string;
    authentihash?: string;
    imphash?: string;
    richPEHeader?: string;
    ssdeep?: string;
    tlsh?: string;
    magic: string;
    trID?: string;
    entropy: number;
    isPE: boolean;
    isCompressed: boolean;
  };
  analysis: {
    [key: string]: { // Key: AntiVirus:Version, Value: Result:Date
      result: string;
      date: string;
      version: string;
      engine: string;
      category: string;
      method: string;
      confidence: number;
      details: any;
    }
  };
  aggregated: {
    totalEngines: number;
    detections: number;
    ratio: string;
    verdict: string;
    riskScore: number;
    severity: string;
    classification: string;
    threatCategories: string[];
    mitreTechniques: string[];
    iocs: { type: string; value: string }[];
  };
}

interface UserRow {
  rowId: string; // Username
  info: {
    username: string;
    email: string;
    passwordHash: string;
    createdAt: string;
    lastLogin: string;
    role: string;
  };
}

interface TokenRow {
  rowId: string; // Public JWT
  info: {
    secret: string;
    username: string;
    enabled: boolean;
    createdAt: string;
    expiresAt: string;
    tier: string;
  };
}

class CassandraStore {
  private memoryCache = new Map<string, FileScanRow>();
  private writeQueue: FileScanRow[] = [];
  private isWriting = false;

  constructor() {
    this.ensureDir();
    // Process write queue to prevent DB contention (VirusTotal trade-off consideration)
    if (typeof setInterval !== 'undefined') {
      setInterval(() => this.processWriteQueue(), 1000); // Batch writes every second
    }
  }

  private ensureDir() {
    if (!fs.existsSync(CASSANDRA_DIR)) {
      fs.mkdirSync(CASSANDRA_DIR, { recursive: true });
    }
    const partitions = ['file_scans', 'users', 'tokens', 'sessions'];
    partitions.forEach(p => {
      const dir = path.join(CASSANDRA_DIR, p);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    });
  }

  // Write with queue to prevent contention (VirusTotal potential bottleneck fix)
  async writeFileScan(row: FileScanRow): Promise<void> {
    // Add to write queue instead of direct write
    this.writeQueue.push(row);
    this.memoryCache.set(row.rowId, row);
    
    // Also update partition for fast lookup by SHA256
    const partitionFile = path.join(CASSANDRA_DIR, 'file_scans', `${row.sha256}.json`);
    let existing: FileScanRow[] = [];
    if (fs.existsSync(partitionFile)) {
      try {
        existing = JSON.parse(fs.readFileSync(partitionFile, 'utf-8'));
      } catch {}
    }
    
    const idx = existing.findIndex(r => r.rowId === row.rowId);
    if (idx !== -1) existing[idx] = row;
    else existing.push(row);
    
    // Keep only last 10 scans per file (like VirusTotal scans list)
    if (existing.length > 10) {
      existing = existing.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).slice(0, 10);
    }

    fs.writeFileSync(partitionFile, JSON.stringify(existing, null, 2));
  }

  private async processWriteQueue() {
    if (this.isWriting || this.writeQueue.length === 0) return;
    this.isWriting = true;

    const batch = this.writeQueue.splice(0, 10); // Batch of 10
    for (const row of batch) {
      try {
        const filePath = path.join(CASSANDRA_DIR, 'file_scans', `row_${row.rowId.replace(/[:/]/g, '_')}.json`);
        fs.writeFileSync(filePath, JSON.stringify(row, null, 2));
      } catch (e) {
        console.error('[Cassandra] Write error', e);
        // Re-queue on failure
        this.writeQueue.push(row);
      }
    }

    this.isWriting = false;
  }

  // Read with partitioning
  getFileScansBySha256(sha256: string): FileScanRow[] {
    // Try memory cache first
    const cached = Array.from(this.memoryCache.values()).filter(r => r.sha256 === sha256);
    if (cached.length > 0) return cached.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    const partitionFile = path.join(CASSANDRA_DIR, 'file_scans', `${sha256}.json`);
    if (!fs.existsSync(partitionFile)) return [];
    
    try {
      const data = JSON.parse(fs.readFileSync(partitionFile, 'utf-8'));
      return data.sort((a: FileScanRow, b: FileScanRow) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } catch {
      return [];
    }
  }

  getFileScanByRowId(rowId: string): FileScanRow | null {
    if (this.memoryCache.has(rowId)) return this.memoryCache.get(rowId)!;

    const filePath = path.join(CASSANDRA_DIR, 'file_scans', `row_${rowId.replace(/[:/]/g, '_')}.json`);
    if (!fs.existsSync(filePath)) return null;

    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    } catch {
      return null;
    }
  }

  getLatestScan(sha256: string): FileScanRow | null {
    const scans = this.getFileScansBySha256(sha256);
    return scans.length > 0 ? scans[0] : null;
  }

  // Create new scan row from analysis
  createScanRow(params: {
    sha256: string;
    sha1: string;
    md5: string;
    filename: string;
    fileSize: number;
    fileType: string;
    magic: string;
    entropy: number;
    isPE: boolean;
    isCompressed: boolean;
    imphash?: string;
    userId: string;
    analysisResults: any;
    comprehensiveReport: any;
  }): FileScanRow {
    const timestamp = new Date().toISOString();
    const unixTs = Math.floor(Date.now() / 1000);
    const rowId = `${params.sha256}:${timestamp}`;
    const partitionKey = `${params.userId}:${params.sha256}:${unixTs}`;

    const existing = this.getFileScansBySha256(params.sha256);
    const firstSubmission = existing.length > 0 ? existing[existing.length - 1].history.firstSubmission : timestamp;

    const row: FileScanRow = {
      rowId,
      sha256: params.sha256,
      timestamp,
      partitionKey,
      history: {
        createDate: timestamp,
        firstSubmission,
        lastSubmission: timestamp,
        analysisCount: existing.length + 1,
        submissions: [
          ...existing.flatMap(e => e.history.submissions),
          { timestamp, userId: params.userId, filename: params.filename, size: params.fileSize }
        ].slice(-20)
      },
      fileMetadata: {
        attributes: [],
        fileNames: [...new Set([...existing.flatMap(e => e.fileMetadata.fileNames), params.filename])].slice(-10),
        fileType: params.fileType,
        fileSize: params.fileSize,
        md5: params.md5,
        sha1: params.sha1,
        sha256: params.sha256,
        imphash: params.imphash,
        magic: params.magic,
        entropy: params.entropy,
        isPE: params.isPE,
        isCompressed: params.isCompressed
      },
      analysis: {},
      aggregated: {
        totalEngines: params.comprehensiveReport?.virusTotal?.engines || 12,
        detections: params.comprehensiveReport?.virusTotal?.detections || 0,
        ratio: params.comprehensiveReport?.virusTotal?.ratio || '0/12',
        verdict: params.comprehensiveReport?.virusTotal?.verdict || 'Clean',
        riskScore: params.analysisResults?.riskScore || 0,
        severity: params.analysisResults?.severity || 'LOW',
        classification: params.analysisResults?.classification || 'BENIGN',
        threatCategories: params.comprehensiveReport?.riskAssessment?.threatCategories || [],
        mitreTechniques: params.comprehensiveReport?.mitre?.techniques?.map((t: any) => t.id) || [],
        iocs: params.comprehensiveReport?.iocs?.all?.map((i: any) => ({ type: i.type, value: i.value })) || []
      }
    };

    // Populate analysis column family: Key AntiVirus:Version, Value Result:Date
    if (params.comprehensiveReport?.aToZ) {
      for (const [letter, info] of Object.entries(params.comprehensiveReport.aToZ as any)) {
        const infoAny = info as any;
        const key = `MCK-Guard-${letter}:${infoAny.title}:1.0`;
        row.analysis[key] = {
          result: infoAny.status,
          date: timestamp,
          version: '1.0',
          engine: infoAny.title,
          category: letter,
          method: infoAny.title,
          confidence: params.analysisResults?.confidence || 0,
          details: info
        };
      }
    }

    if (params.comprehensiveReport?.yara?.matches) {
      for (const match of params.comprehensiveReport.yara.matches) {
        const key = `YARA:${match.rule}:1.0`;
        row.analysis[key] = {
          result: 'Malicious',
          date: timestamp,
          version: '1.0',
          engine: 'YARA',
          category: 'YARA',
          method: match.rule,
          confidence: 90,
          details: match
        };
      }
    }

    return row;
  }

  // Metrics
  getStats() {
    const files = fs.readdirSync(path.join(CASSANDRA_DIR, 'file_scans')).filter(f => f.endsWith('.json'));
    let totalScans = 0;
    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(CASSANDRA_DIR, 'file_scans', file), 'utf-8'));
        if (Array.isArray(data)) totalScans += data.length;
        else totalScans += 1;
      } catch {}
    }

    return {
      totalFiles: files.length,
      totalScans,
      writeQueue: this.writeQueue.length,
      memoryCache: this.memoryCache.size,
      partitions: files.length
    };
  }
}

export const cassandraStore = new CassandraStore();

// Schema documentation per VirusTotal design
export const cassandraSchema = {
  fileScansTable: {
    rowId: 'SHA256:Timestamp',
    description: 'File scan metadata, retrieved by user_id:SHA256:UnixTimestamp',
    columns: {
      history: ['Create Date', 'First Submission', 'Last Submission', 'Analysis'],
      fileMetadata: ['Attributes', 'File Name(s)', 'File Type', 'File Size', 'MD5', 'SHA-1', 'SHA-256', 'Vhash', 'Authentihash', 'Imphash', 'Rich PE header', 'SSDEEP', 'TLSH', 'Magic', 'TrID'],
      analysis: 'Key: AntiVirus:Version, Value: Result:Date'
    }
  },
  usersTable: {
    rowId: 'Username',
    columns: ['Username', 'Email', 'PasswordHash', 'CreatedAt', 'LastLogin']
  },
  tokensTable: {
    rowId: 'Public JWT',
    columns: ['Secret', 'Username', 'Enabled']
  }
};
