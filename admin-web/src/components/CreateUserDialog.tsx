'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';

type CreateUserOk = {
  id: string;
  login: string;
  status: string;
  must_change_password: boolean;
  initial_password?: string;
};

/**
 * Admin -> Users -> "+ Create user" button mounts this dialog.
 *
 * UX flow:
 *   1. Admin types a login (3-32 chars, lowercase alnum + ._-).
 *   2. Admin chooses "Auto-generate password" (default) OR enters their own.
 *   3. On submit, POST /api/proxy/admin/users.
 *   4. On 201, swap into a "share these credentials" panel that displays the
 *      cleartext password ONCE alongside a Copy button. We deliberately don't
 *      fetch the password again — the backend only includes it in the create
 *      response, so the admin must capture it now.
 *   5. After Done, refresh the users list so the new row appears.
 *
 * The created user has must_change_password=TRUE, so the mobile app will
 * force them through the change-password screen on first login.
 */
export function CreateUserDialog({ onClose }: { onClose: () => void }) {
  const [login, setLogin] = useState('');
  const [autoGenerate, setAutoGenerate] = useState(true);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CreateUserOk | null>(null);
  const [busy, startTransition] = useTransition();
  const router = useRouter();

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(login.trim().toLowerCase())) {
      setError('Login must be 3–32 chars, lowercase letters/digits/._- only.');
      return;
    }
    if (!autoGenerate) {
      if (password.length < 10) {
        setError('Password must be at least 10 characters.');
        return;
      }
      if (password !== confirm) {
        setError('Password and confirmation do not match.');
        return;
      }
    }
    startTransition(async () => {
      const body: { login: string; initial_password?: string } = {
        login: login.trim().toLowerCase(),
      };
      if (!autoGenerate) body.initial_password = password;
      const r = await fetch('/api/proxy/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include',
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) {
        setError(j?.error?.message || j?.error?.code || `HTTP ${r.status}`);
        return;
      }
      setResult(j as CreateUserOk);
    });
  }

  function done() {
    onClose();
    router.refresh();
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 bg-black/60 flex items-center justify-center px-4 z-50"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="card w-full max-w-md space-y-4">
        {result ? <Shared result={result} onDone={done} /> : (
          <form onSubmit={submit} className="space-y-4" autoComplete="off">
            <header>
              <h2 className="text-lg font-semibold">Create user</h2>
              <p className="text-xs text-gray-400 mt-1">
                The new user must change this password on their first login.
              </p>
            </header>

            <div>
              <label className="label">User ID (permanent)</label>
              <input
                value={login}
                onChange={(e) => setLogin(e.target.value)}
                placeholder="alice"
                required
                autoFocus
                className="input font-mono"
              />
              <p className="text-xs text-gray-500 mt-1">
                Lowercase. 3–32 chars. Letters, digits, dot/underscore/hyphen.
              </p>
            </div>

            <div className="space-y-2">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={autoGenerate}
                  onChange={(e) => setAutoGenerate(e.target.checked)}
                />
                Auto-generate initial password
              </label>
              {!autoGenerate && (
                <div className="space-y-2">
                  <div>
                    <label className="label">Initial password</label>
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      minLength={10}
                      required={!autoGenerate}
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="label">Confirm</label>
                    <input
                      type="password"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      minLength={10}
                      required={!autoGenerate}
                      className="input"
                    />
                  </div>
                </div>
              )}
            </div>

            {error && <p className="text-danger text-sm">{error}</p>}

            <div className="flex justify-end gap-2 pt-2">
              <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
              <button className="btn-primary" disabled={busy}>
                {busy ? 'Creating…' : 'Create user'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

function Shared({ result, onDone }: { result: CreateUserOk; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (!result.initial_password) return;
    try {
      await navigator.clipboard.writeText(
        `login: ${result.login}\npassword: ${result.initial_password}`,
      );
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked — fall through, admin can select manually */
    }
  }
  return (
    <div className="space-y-4">
      <header>
        <h2 className="text-lg font-semibold text-accent">User created</h2>
        <p className="text-xs text-gray-400 mt-1">
          Share these credentials with the user over a secure channel.
          {' '}
          <strong className="text-danger">
            This password will not be shown again.
          </strong>
        </p>
      </header>

      <div className="border border-line/40 rounded-lg p-4 bg-bg/40 space-y-3">
        <Row label="User ID" value={result.login} mono />
        {result.initial_password ? (
          <Row label="Password" value={result.initial_password} mono />
        ) : (
          <p className="text-xs text-gray-500">
            (You supplied the password yourself, so it&apos;s not echoed back here.)
          </p>
        )}
      </div>

      <div className="flex justify-between items-center">
        {result.initial_password && (
          <button type="button" className="btn-ghost" onClick={copy}>
            {copied ? 'Copied ✓' : 'Copy credentials'}
          </button>
        )}
        <button type="button" className="btn-primary ml-auto" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-gray-400">{label}</div>
      <div className={mono ? 'font-mono text-sm select-all' : 'text-sm select-all'}>
        {value}
      </div>
    </div>
  );
}
