/**
 * Server-side fetch helper. The browser never sees a Bearer token; the admin
 * session is an HttpOnly cookie set by the backend, and we relay it through.
 */

const PUBLIC_API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? 'http://localhost:8080';
const INTERNAL_API_BASE = process.env.API_INTERNAL_BASE ?? PUBLIC_API_BASE;

import { cookies } from 'next/headers';

export type ApiError = { code: string; message: string };

async function rawFetch<T>(
  path: string,
  init: RequestInit & { internal?: boolean } = {},
): Promise<{ ok: true; data: T } | { ok: false; error: ApiError; status: number }> {
  const base = init.internal ? INTERNAL_API_BASE : PUBLIC_API_BASE;
  const headers = new Headers(init.headers);

  if (init.internal) {
    // Forward the admin session cookie to the backend.
    const c = cookies().get('admin_session');
    if (c) headers.set('Cookie', `admin_session=${c.value}`);
  }
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(`${base}${path}`, {
    ...init,
    headers,
    cache: 'no-store',
  });

  const text = await res.text();
  if (!res.ok) {
    let parsed: { error?: ApiError } = {};
    try { parsed = JSON.parse(text); } catch { /* noop */ }
    return {
      ok: false,
      status: res.status,
      error: parsed.error ?? { code: 'HTTP_' + res.status, message: text },
    };
  }
  if (text === '') return { ok: true, data: undefined as unknown as T };
  return { ok: true, data: JSON.parse(text) as T };
}

export const api = {
  /** Server-component-side call. Forwards admin cookie automatically. */
  internal<T>(path: string, init?: RequestInit) {
    return rawFetch<T>(path, { ...init, internal: true });
  },
  /** Browser-side relay through Next.js route handlers in /api/proxy/[...]. */
  public<T>(path: string, init?: RequestInit) {
    return rawFetch<T>(path, { ...init, internal: false });
  },
};
