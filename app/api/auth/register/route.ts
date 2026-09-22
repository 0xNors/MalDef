export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import { loadDB, saveDB, generateId } from '@/lib/db';
import { hashPassword, validatePasswordStrength, checkRateLimit } from '@/lib/auth';

const VALID_ROLES = ['ADMIN', 'ANALYST', 'MANAGER'];

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get('x-forwarded-for') || 'unknown';
    if (!checkRateLimit(`register:${ip}`, 20, 15 * 60 * 1000)) {
      return NextResponse.json({ error: 'Too many registration attempts. Try again later.' }, { status: 429 });
    }

    const { name, email, password, organization, role } = await req.json();

    if (!name || !email || !password) {
      return NextResponse.json({ error: 'Name, email and password required' }, { status: 400 });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json({ error: 'Invalid email format' }, { status: 400 });
    }

    const pwdCheck = validatePasswordStrength(password);
    if (!pwdCheck.valid) {
      return NextResponse.json({ error: pwdCheck.message }, { status: 400 });
    }

    // Validate role - respect user's selection always
    let requestedRole = role?.toUpperCase() || 'ANALYST';
    if (!VALID_ROLES.includes(requestedRole)) {
      requestedRole = 'ANALYST';
    }

    const db = loadDB();
    
    if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return NextResponse.json({ error: 'Email already registered' }, { status: 409 });
    }

    const passwordHash = await hashPassword(password);
    
    // Market ready: Respect role selection always - no forced ADMIN
    const finalRole = requestedRole;
    
    const newUser = {
      id: generateId('user-'),
      email: email.toLowerCase(),
      passwordHash,
      name: name.trim(),
      role: finalRole,
      createdAt: new Date().toISOString(),
      isActive: true,
    } as any;

    db.users.push(newUser);
    db.auditLogs.unshift({
      id: generateId('AUDIT-'),
      timestamp: new Date().toISOString(),
      userId: newUser.id,
      action: 'USER_REGISTER',
      resource: 'users',
      details: `New ${finalRole} registered: ${email}${organization ? ` (${organization})` : ''} [Role selected: ${requestedRole}]`,
    });

    saveDB(db);

    return NextResponse.json({ 
      message: `Account created as ${finalRole}`, 
      user: { id: newUser.id, email: newUser.email, name: newUser.name, role: newUser.role },
      selectedRole: requestedRole,
      finalRole
    });
  } catch (e) {
    console.error('Register error', e);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
