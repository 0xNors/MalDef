/**
 * MCK-Guard Structured Logging - VirusTotal System Design
 * Logs with request ID correlation for Datadog
 */

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  requestId: string;
  service: string;
  message: string;
  data?: any;
  error?: string;
  stack?: string;
  userId?: string;
  ip?: string;
  latencyMs?: number;
  traceId?: string;
  spanId?: string;
}

class Logger {
  private logs: LogEntry[] = [];
  private maxLogs = 10000;

  private createEntry(level: LogLevel, requestId: string, service: string, message: string, data?: any, error?: Error): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      requestId,
      service,
      message,
      data,
      error: error?.message,
      stack: error?.stack,
      traceId: requestId.split('-')[0] || requestId
    };
  }

  log(level: LogLevel, requestId: string, service: string, message: string, data?: any) {
    const entry = this.createEntry(level, requestId, service, message, data);
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // Console output with colors for dev
    const colors: Record<LogLevel, string> = {
      DEBUG: '\x1b[36m',
      INFO: '\x1b[32m',
      WARN: '\x1b[33m',
      ERROR: '\x1b[31m',
      CRITICAL: '\x1b[35m'
    };
    const reset = '\x1b[0m';
    console.log(`${colors[level]}[${level}]${reset} [${requestId}] [${service}] ${message}`, data ? JSON.stringify(data).substring(0, 200) : '');
  }

  debug(requestId: string, service: string, message: string, data?: any) {
    this.log('DEBUG', requestId, service, message, data);
  }

  info(requestId: string, service: string, message: string, data?: any) {
    this.log('INFO', requestId, service, message, data);
  }

  warn(requestId: string, service: string, message: string, data?: any) {
    this.log('WARN', requestId, service, message, data);
  }

  error(requestId: string, service: string, message: string, error?: Error, data?: any) {
    const entry = this.createEntry('ERROR', requestId, service, message, data, error);
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) this.logs = this.logs.slice(-this.maxLogs);
    console.error(`[ERROR] [${requestId}] [${service}] ${message}`, error?.message, data ? JSON.stringify(data).substring(0, 200) : '');
  }

  critical(requestId: string, service: string, message: string, error?: Error, data?: any) {
    const entry = this.createEntry('CRITICAL', requestId, service, message, data, error);
    this.logs.push(entry);
    console.error(`[CRITICAL] [${requestId}] [${service}] ${message}`, error?.message);
  }

  getLogs(filter?: { level?: LogLevel; service?: string; requestId?: string; limit?: number }): LogEntry[] {
    let filtered = this.logs;
    if (filter?.level) filtered = filtered.filter(l => l.level === filter.level);
    if (filter?.service) filtered = filtered.filter(l => l.service === filter.service);
    if (filter?.requestId) filtered = filtered.filter(l => l.requestId === filter.requestId);
    if (filter?.limit) filtered = filtered.slice(-filter.limit);
    return filtered.reverse();
  }

  getLogsByRequestId(requestId: string): LogEntry[] {
    return this.logs.filter(l => l.requestId === requestId || l.traceId === requestId.split('-')[0]);
  }

  clear() {
    this.logs = [];
  }
}

export const logger = new Logger();

export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 10)}_${Math.random().toString(36).substring(2, 6)}`;
}

export function getRequestIdFromHeaders(headers: any): string {
  return headers.get?.('x-request-id') || headers['x-request-id'] || headers.get?.('x-correlation-id') || generateRequestId();
}
