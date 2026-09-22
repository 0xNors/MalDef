import bcrypt from 'bcryptjs';
import * as jose from 'jose';
import { cookies } from 'next/headers';
import { NextRequest } from 'next/server';

const DEFAULT_SECRET = 'mck-guard-production-secret-key-32-chars-minimum-change-me!';

function getJwtSecret(): Uint8Array {
  const secret = process.env.JWT_SECRET || DEFAULT_SECRET;
  
  if (!process.env.JWT_SECRET) {
    console.warn('⚠️  JWT_SECRET not set, using built-in default. For production, set JWT_SECRET in .env.local (32+ chars)');
  }
  
  if (secret.length < 32) {
    console.warn('⚠️  JWT_SECRET too short, using default. Must be 32+ chars');
    return new TextEncoder().encode(DEFAULT_SECRET);
  }
  
  return new TextEncoder().encode(secret);
}

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  name: string;
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function createToken(payload: JWTPayload): Promise<string> {
  const secret = getJwtSecret();
  return await new jose.SignJWT(payload as any)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('24h')
    .sign(secret);
}

export async function verifyToken(token: string): Promise<JWTPayload | null> {
  try {
    const secret = getJwtSecret();
    const { payload } = await jose.jwtVerify(token, secret);
    return payload as unknown as JWTPayload;
  } catch (e) {
    console.error('Token verify failed:', e);
    return null;
  }
}

export async function getCurrentUserFromRequest(req: NextRequest): Promise<JWTPayload | null> {
  try {
    const token = req.cookies.get('mck_token')?.value;
    if (!token) {
      const authHeader = req.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        const bearerToken = authHeader.substring(7);
        return verifyToken(bearerToken);
      }
      return null;
    }
    return verifyToken(token);
  } catch {
    return null;
  }
}

export async function getCurrentUser(): Promise<JWTPayload | null> {
  try {
    const cookieStore = cookies();
    const token = cookieStore.get('mck_token')?.value;
    if (!token) return null;
    return verifyToken(token);
  } catch {
    return null;
  }
}

export function validatePasswordStrength(password: string): { valid: boolean; message: string } {
  if (password.length < 8) return { valid: false, message: 'Password must be at least 8 characters' };
  if (!/[A-Z]/.test(password)) return { valid: false, message: 'Password must contain uppercase letter' };
  if (!/[a-z]/.test(password)) return { valid: false, message: 'Password must contain lowercase letter' };
  if (!/[0-9]/.test(password)) return { valid: false, message: 'Password must contain number' };
  if (!/[!@#$%^&*]/.test(password)) return { valid: false, message: 'Password must contain special character (!@#$%^&*)' };
  return { valid: true, message: 'Strong password' };
}

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

export function checkRateLimit(identifier: string, maxRequests = 20, windowMs = 15 * 60 * 1000): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(identifier);
  
  if (!record || now > record.resetTime) {
    rateLimitMap.set(identifier, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  if (record.count >= maxRequests) {
    return false;
  }
  
  record.count++;
  return true;
}

// Cleanup in production - only run on server
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitMap.entries()) {
      if (now > record.resetTime) {
        rateLimitMap.delete(key);
      }
    }
  }, 60 * 1000);
}
