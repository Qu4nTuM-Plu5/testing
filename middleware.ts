/**
 * Bloom Security Shield — Next.js middleware.
 *
 * This wraps every request:
 *  1. Extracts IP, session (JWT cookie), user-agent, body
 *  2. Calls Bloom /api/sdk/evaluate → BLOCK if rule matches
 *  3. Tracks the event async to Bloom /api/sdk/ingest
 *
 * Env vars (set in Vercel):
 *  BLOOM_API_URL=https://your-bloom.vercel.app
 *  BLOOM_PROJECT_ID=proj_xxx
 *  BLOOM_API_KEY=bloom_xxx
 *
 * To DISABLE Bloom (e.g. for local dev), simply don't set BLOOM_API_URL.
 * The middleware will skip the network call and pass through.
 */

import { NextRequest, NextResponse } from 'next/server';
import { bloomEvaluate, bloomTrack, sanitizeInput } from './lib/bloom-shield';

export async function middleware(req: NextRequest) {
  const startTime = Date.now();
  const url = req.nextUrl;

  // Skip static assets
  if (url.pathname.match(/\.(ico|png|jpg|jpeg|gif|svg|css|js|woff|woff2|ttf|map|webp)$/)) {
    return NextResponse.next();
  }

  // Skip Next.js internals
  if (url.pathname.startsWith('/_next/')) {
    return NextResponse.next();
  }

  // Extract real client IP (Vercel sets x-forwarded-for)
  const forwardedFor = req.headers.get('x-forwarded-for') || '';
  const realIp = forwardedFor.split(',')[0]?.trim() ||
                 req.headers.get('x-real-ip') ||
                 '0.0.0.0';

  // Extract session ID from JWT cookie or Authorization header
  const sessionId =
    req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').slice(0, 64) ||
    req.cookies.get('session')?.value?.slice(0, 64) ||
    req.cookies.get('token')?.value?.slice(0, 64);

  // For POST/PUT/PATCH — read body, sanitize, then pass through
  let inputSnippet: string | undefined;
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    try {
      const body = await req.text();
      if (body) {
        inputSnippet = sanitizeInput(body);
      }
    } catch {
      // Skip if body can't be read
    }
  }

  // Capture X-Bloom-Verify header if present (used by Test button to verify middleware is installed)
  const verifyHeader = req.headers.get('x-bloom-verify');
  const userAgentRaw = req.headers.get('user-agent') || '';
  const userAgentFinal = verifyHeader ? `${userAgentRaw} [Bloom-Verify: ${verifyHeader}]` : userAgentRaw;

  const event = {
    method: req.method,
    path: url.pathname,
    host: url.host,
    ip: realIp,
    userAgent: userAgentFinal || undefined,
    sessionId,
    inputSnippet,
    statusCode: 200,
    responseTime: Date.now() - startTime,
  };

  // Threat evaluation — Bloom returns BLOCK if a rule matches
  const decision = await bloomEvaluate(event);
  if (decision.action === 'BLOCK') {
    // Use waitUntil to keep the fire-and-forget bloomTrack alive
    // (Vercel Edge runtime may abort pending fetches once we return)
    try {
      // @ts-ignore — waitUntil is available on NextRequest in Edge runtime
      if (req.waitUntil) {
        // @ts-ignore
        req.waitUntil(bloomTrack({ ...event, statusCode: 403 }));
      } else {
        bloomTrack({ ...event, statusCode: 403 });
      }
    } catch {
      bloomTrack({ ...event, statusCode: 403 });
    }
    return NextResponse.json(
      { error: 'Access Denied by Bloom SIEM', rule: decision.rule, reason: decision.reason },
      { status: 403 }
    );
  }

  // Track the event (fire-and-forget, with waitUntil to keep it alive)
  try {
    // @ts-ignore
    if (req.waitUntil) {
      // @ts-ignore
      req.waitUntil(bloomTrack(event));
    } else {
      bloomTrack(event);
    }
  } catch {
    bloomTrack(event);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
