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
  const path = '/' + params.path.join('/');
  const url = new URL(req.nextUrl.pathname.replace('/api/proxy', ''), INTERNAL);
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
    if (/^transfer-encoding$|^connection$|^content-encoding$/i.test(k)) continue;
    respHeaders.append(k, v);
  }
  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: respHeaders,
  });
  void path; // suppress unused warning
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } })    { return relay(req, ctx.params); }
export async function POST(req: NextRequest, ctx: { params: { path: string[] } })   { return relay(req, ctx.params); }
export async function PUT(req: NextRequest, ctx: { params: { path: string[] } })    { return relay(req, ctx.params); }
export async function DELETE(req: NextRequest, ctx: { params: { path: string[] } }) { return relay(req, ctx.params); }
