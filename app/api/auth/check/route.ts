export const dynamic = 'force-dynamic';

import { NextResponse } from 'next/server';
import { loadDB } from '@/lib/db';

export async function GET() {
  try {
    const db = loadDB();
    return NextResponse.json({
      isFirstUser: db.users.length === 0,
      totalUsers: db.users.length
    });
  } catch (e: any) {
    console.error('Check error', e);
    return NextResponse.json({ isFirstUser: true, totalUsers: 0, error: e.message });
  }
}
