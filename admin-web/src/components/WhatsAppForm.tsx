'use client';

import { useState, useTransition } from 'react';

type Cfg = { phone_e164: string; message_template: string };

export function WhatsAppForm({ initial }: { initial: Cfg }) {
  const [phone, setPhone] = useState(initial.phone_e164);
  const [msg, setMsg] = useState(initial.message_template);
  const [status, setStatus] = useState<'idle' | 'ok' | 'err'>('idle');
  const [busy, startTransition] = useTransition();

  const preview = `https://wa.me/${phone.replace(/[^\d]/g, '')}?text=${encodeURIComponent(msg)}`;

  function save(e: React.FormEvent) {
    e.preventDefault();
    setStatus('idle');
    startTransition(async () => {
      const r = await fetch('/api/proxy/admin/config/whatsapp', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone_e164: phone, message_template: msg }),
      });
      setStatus(r.ok ? 'ok' : 'err');
    });
  }

  return (
    <form onSubmit={save} className="card space-y-4 max-w-2xl">
      <div>
        <label className="label">Phone (E.164, e.g. +14155551234)</label>
        <input
          className="input font-mono"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          required
          pattern="^\+\d{7,15}$"
        />
      </div>
      <div>
        <label className="label">Message template</label>
        <textarea
          className="input min-h-[120px]"
          value={msg}
          maxLength={1000}
          onChange={(e) => setMsg(e.target.value)}
        />
        <p className="text-xs text-gray-500 mt-1">
          Placeholder <code>{'{user_id}'}</code> is preserved verbatim — clients
          do not interpolate it (avoids leaking IDs back).
        </p>
      </div>
      <div>
        <label className="label">Preview link</label>
        <a
          href={preview}
          target="_blank"
          rel="noopener noreferrer"
          className="block break-all text-sm font-mono text-accent underline">
          {preview}
        </a>
      </div>
      <div className="flex gap-3 items-center">
        <button className="btn-primary" disabled={busy}>
          {busy ? 'Saving…' : 'Save'}
        </button>
        {status === 'ok' && <span className="text-accent text-sm">Saved.</span>}
        {status === 'err' && <span className="text-danger text-sm">Failed.</span>}
      </div>
    </form>
  );
}
