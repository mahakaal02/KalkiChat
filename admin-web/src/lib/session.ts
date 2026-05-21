import { cookies } from 'next/headers';

/** Returns true if the admin session cookie is present. Validation is the
 *  backend's job — every backend endpoint checks the JWT signature again. */
export function hasAdminSession(): boolean {
  return Boolean(cookies().get('admin_session')?.value);
}

/** Returns true if the user is mid-2FA (pre-2fa cookie set). */
export function hasPre2FA(): boolean {
  return Boolean(cookies().get('admin_pre2fa')?.value);
}
