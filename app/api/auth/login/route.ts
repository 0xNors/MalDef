export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { loadDB, saveDB, generateId } from '@/lib/db';
import { verifyPassword, createToken, checkRateLimit } from '@/lib/auth';

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get('x-forwarded-for') || 'unknown';
    if (!checkRateLimit(`login:${ip}`, 20, 15 * 60 * 1000)) {
      return NextResponse.json({ error: 'Too many login attempts. Try again later.' }, { status: 429 });
    }

    const { email, password, role } = await req.json();

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password required' }, { status: 400 });
    }

    const db = loadDB();
    const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.isActive);

    if (!user) {
      return NextResponse.json({ error: 'Invalid credentials - user not found' }, { status: 401 });
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      db.auditLogs.unshift({
        id: generateId('AUDIT-'),
        timestamp: new Date().toISOString(),
        userId: user.id,
        action: 'LOGIN_FAILED',
        resource: 'auth',
        details: `Failed login attempt for ${email} from ${ip}`,
      });
      saveDB(db);
      return NextResponse.json({ error: 'Invalid credentials - wrong password' }, { status: 401 });
    }

    // Role validation - if role selected during login, must match user's actual role
    if (role) {
      const requestedRole = role.toUpperCase();
      if (requestedRole !== user.role) {
        db.auditLogs.unshift({
          id: generateId('AUDIT-'),
          timestamp: new Date().toISOString(),
          userId: user.id,
          action: 'LOGIN_FAILED_ROLE_MISMATCH',
          resource: 'auth',
          details: `Role mismatch for ${email}: requested ${requestedRole}, actual ${user.role}`,
        });
        saveDB(db);
        return NextResponse.json({ 
          error: `Role mismatch: Your account is ${user.role}, but you selected ${requestedRole}. Please select correct role.` 
        }, { status: 403 });
      }
    }

    const token = await createToken({
      userId: user.id,
      email: user.email,
      role: user.role,
      name: user.name,
    });

    user.lastLogin = new Date().toISOString();
    db.auditLogs.unshift({
      id: generateId('AUDIT-'),
      timestamp: new Date().toISOString(),
      userId: user.id,
      action: 'LOGIN_SUCCESS',
      resource: 'auth',
      details: `User ${email} (${user.role}) logged in from ${ip}${role ? ` as ${role}` : ''}`,
    });
    saveDB(db);

    const response = NextResponse.json({
      message: `Login successful as ${user.role}`,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });

    response.cookies.set('mck_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24,
      path: '/',
    });

    return response;
  } catch (e) {
    console.error('Login error', e);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
