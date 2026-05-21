'use client';

import { useState, useTransition } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

export default function LoginPage() {
  const [stage, setStage] = useState<'password' | 'totp'>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();
  const router = useRouter();
  const params = useSearchParams();
  const nextPath = params.get('next') ?? '/';

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const r = await fetch('/api/proxy/admin/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        credentials: 'include',
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        setError(j?.error?.code ?? 'login failed');
        return;
      }
      setStage('totp');
    });
  }

  async function submitTOTP(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const r = await fetch('/api/proxy/admin/auth/totp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: totp }),
        credentials: 'include',
      });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        setError(j?.error?.code ?? 'totp failed');
        return;
      }
      router.replace(nextPath);
    });
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4">
      <div className="card w-full max-w-sm space-y-5">
        <header className="text-center">
          <div className="text-xs uppercase tracking-widest text-gray-400">KalkiChat</div>
          <h1 className="text-2xl font-semibold mt-1">Admin sign-in</h1>
        </header>
        {stage === 'password' ? (
          <form onSubmit={submitPassword} className="space-y-3" autoComplete="off">
            <div>
              <label className="label">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoFocus
                className="input"
              />
            </div>
            <div>
              <label className="label">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="input"
              />
            </div>
            {error && <p className="text-danger text-sm">{error}</p>}
            <button className="btn-primary w-full" disabled={busy}>
              {busy ? 'Signing in…' : 'Continue'}
            </button>
          </form>
        ) : (
          <form onSubmit={submitTOTP} className="space-y-3" autoComplete="off">
            <div>
              <label className="label">6-digit code</label>
              <input
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totp}
                onChange={(e) => setTotp(e.target.value.replace(/\D/g, ''))}
                required
                autoFocus
                className="input tracking-[0.5em] text-center text-xl"
              />
            </div>
            {error && <p className="text-danger text-sm">{error}</p>}
            <button className="btn-primary w-full" disabled={busy}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
            <button
              type="button"
              className="btn-ghost w-full"
              onClick={() => setStage('password')}
            >
              Back
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
