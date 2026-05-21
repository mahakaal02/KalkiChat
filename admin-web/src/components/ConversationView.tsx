'use client';

import { useState, useTransition } from 'react';

type Message = {
  id: string; sender_device_id: string;
  envelope: string; signature: string;
  media_id: string | null; created_at: string;
};

export function ConversationView({
  userId,
  messages,
}: { userId: string; messages: Message[] }) {
  const [text, setText] = useState('');
  const [busy, startTransition] = useTransition();

  function send() {
    if (!text.trim()) return;
    startTransition(async () => {
      // In a real implementation: the admin's local crypto module (running
      // in a Web Worker) seals the plaintext to each user device, signs the
      // envelope, and POSTs to /v1/admin/users/:id/messages with
      // X-Admin-Device-Id set. For now we placeholder.
      await fetch(`/api/proxy/admin/users/${userId}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Admin-Device-Id': 'admin-web-placeholder',
        },
        body: JSON.stringify({
          client_id: crypto.randomUUID(),
          recipient_device_id: 'pick-from-prekeys',
          envelope: btoa(text), // PLACEHOLDER — real impl seals to user's device
          signature: '',
        }),
      });
      setText('');
    });
  }

  return (
    <div className="flex-1 flex flex-col gap-3">
      <div className="flex-1 overflow-y-auto space-y-2">
        {messages.length === 0 && (
          <p className="text-sm text-gray-500">No messages yet.</p>
        )}
        {messages.map((m) => (
          <div key={m.id} className="border border-line/30 rounded-lg p-3 text-sm">
            <div className="text-xs text-gray-500 flex justify-between">
              <span className="font-mono">{m.sender_device_id}</span>
              <time>{new Date(m.created_at).toLocaleString()}</time>
            </div>
            <p className="font-mono text-xs text-gray-400 mt-1 break-all">
              [ciphertext · {m.envelope.length} chars b64]
            </p>
          </div>
        ))}
      </div>
      <div className="border-t border-line/30 pt-3 flex gap-2">
        <input
          className="input flex-1"
          placeholder="Reply"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') send(); }}
        />
        <button className="btn-primary" disabled={busy} onClick={send}>
          {busy ? 'Sending…' : 'Send'}
        </button>
      </div>
    </div>
  );
}
