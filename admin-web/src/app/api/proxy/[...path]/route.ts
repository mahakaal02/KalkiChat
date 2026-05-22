import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

/**
 * Server-side reverse proxy to the backend.
 *
 * We never expose the JWT/session to JavaScript. The browser calls
 * /api/proxy/admin/users → this route → backend with the admin_session cookie
 * attached.  Response Set-Cookie headers are forwarded back, so the backend
 * controls cookie lifecycle.
 */

const INTERNAL = process.env.API_INTERNAL_BASE ?? 'http://localhost:8080';

async function relay(req: NextRequest, params: { path: string[] }) {
  // Map /api/proxy/<rest> -> <INTERNAL>/v1/<rest>. The backend mounts every
  // route under /v1 (see backend/internal/api/router.go), and the browser-side
  // code stays version-agnostic by calling /api/proxy/... directly.
  const upstreamPath = '/v1/' + params.path.join('/');
  const url = new URL(upstreamPath, INTERNAL);
  url.search = req.nextUrl.search;

  const fwdHeaders = new Headers();
  for (const [k, v] of req.headers.entries()) {
    if (/^host$|^connection$|^content-length$/i.test(k)) continue;
    fwdHeaders.set(k, v);
  }
  const session = cookies().get('admin_session')?.value;
  const pre2fa = cookies().get('admin_pre2fa')?.value;
  const cookieHeader = [
    session ? `admin_session=${session}` : '',
    pre2fa ? `admin_pre2fa=${pre2fa}` : '',
  ].filter(Boolean).join('; ');
  if (cookieHeader) fwdHeaders.set('Cookie', cookieHeader);

  const init: RequestInit = {
    method: req.method,
    headers: fwdHeaders,
    redirect: 'manual',
  };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = await req.text();
  }

  const upstream = await fetch(url.toString(), init);

  const respHeaders = new Headers();
  for (const [k, v] of upstream.headers.entries()) {
    if (/^transfer-encoding$|^connection$|^content-encoding$|^set-cookie$/i.test(k)) continue;
    respHeaders.append(k, v);
  }
  // The backend scopes its Set-Cookie Path to /v1/admin/... but the browser
  // talks to /api/proxy/admin/... — without rewriting the Path the browser
  // would store a cookie it never sends back to us. Use getSetCookie() so
  // multiple Set-Cookie headers don't get comma-joined.
  for (const sc of upstream.headers.getSetCookie()) {
    const rewritten = sc.replace(/(\bPath=)\/v1\//i, '$1/api/proxy/');
    respHeaders.append('Set-Cookie', rewritten);
  }
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } })    { return relay(req, ctx.params); }
export async function POST(req: NextRequest, ctx: { params: { path: string[] } })   { return relay(req, ctx.params); }
export async function PUT(req: NextRequest, ctx: { params: { path: string[] } })    { return relay(req, ctx.params); }
export async function DELETE(req: NextRequest, ctx: { params: { path: string[] } }) { return relay(req, ctx.params); }
