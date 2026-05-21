import { NextResponse, type NextRequest } from 'next/server';

/**
 * Edge middleware: guards /admin/* routes by presence of admin_session cookie.
 * Real authorization is performed server-side by the backend on every call.
 */
export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (pathname.startsWith('/login') || pathname.startsWith('/api/proxy/admin/auth')) {
    return NextResponse.next();
  }
  if (pathname === '/' || pathname.startsWith('/admin')) {
    const has = req.cookies.get('admin_session')?.value;
    if (!has) {
      const url = req.nextUrl.clone();
      url.pathname = '/login';
      url.searchParams.set('next', pathname);
      return NextResponse.redirect(url);
    }
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
