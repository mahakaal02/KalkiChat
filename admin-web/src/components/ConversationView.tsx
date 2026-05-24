'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Per-row shape returned by /v1/admin/users/:id/conversation after the
 * admin-sync work landed. `plaintext` and `direction` are nullable
 * because admin-mobile relays plaintext asynchronously — until it does,
 * the row carries only ciphertext metadata and we render a "decrypting…"
 * placeholder.
 */
type Message = {
  id: string;
  sender_device_id: string;
  envelope: string;
  signature: string;
  media_id: string | null;
  created_at: string;
  plaintext: string | null;
  direction: 'inbound' | 'outbound' | null;
};

/**
 * Outbound queue row, surfaced so the UI can show "sending…" indicators
 * for replies admin-mobile hasn't drained yet, plus a clear error
 * message when admin-mobile fails to wrap (e.g. no session with user).
 */
type Outbound = {
  id: string;
  body: string;
  status: 'pending' | 'sent' | 'failed';
  last_error: string | null;
  created_at: string;
  sent_at: string | null;
  server_message_id: string | null;
};

type ConversationPayload = {
  conversation_id: string;
  messages: Message[];
  outbound_queue: Outbound[];
};

export function ConversationView({
  userId,
  initial,
}: {
  userId: string;
  /** Server-rendered initial payload so first paint isn't blocking. */
  initial: ConversationPayload;
}) {
  const [convo, setConvo] = useState<ConversationPayload>(initial);
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [sendErr, setSendErr] = useState<string | null>(null);
  const scrollerRef = useRef<HTMLDivElement | null>(null);

  // Auto-poll every 5s. The conversation view is short-lived (the admin
  // navigates between users frequently), and the payload is small, so a
  // 5s tick is the simple right answer — no need for SSE or WS plumbing.
  // Cleanup on unmount + when userId changes (admin switches users).
  const reload = useCallback(async () => {
    try {
      const res = await fetch(
        `/api/proxy/admin/users/${userId}/conversation`,
        { cache: 'no-store' },
      );
      if (!res.ok) return;
      const data = (await res.json()) as ConversationPayload;
      setConvo(data);
    } catch {
      // Transient; next tick retries.
    }
  }, [userId]);

  useEffect(() => {
    const t = setInterval(reload, 5000);
    return () => clearInterval(t);
  }, [reload]);

  // Auto-scroll to the bottom whenever the message count grows. We use a
  // ref + the scrollHeight rather than scrollIntoView() so a user
  // scrolling up to read history isn't yanked back to the bottom on the
  // next 5s tick — only NEW totals scroll.
  const prevCount = useRef(convo.messages.length + convo.outbound_queue.length);
  useEffect(() => {
    const total = convo.messages.length + convo.outbound_queue.length;
    if (total !== prevCount.current && scrollerRef.current) {
      scrollerRef.current.scrollTop = scrollerRef.current.scrollHeight;
    }
    prevCount.current = total;
  }, [convo]);

  async function send() {
    const body = text.trim();
    if (!body || sending) return;
    setSending(true);
    setSendErr(null);
    try {
      const res = await fetch('/api/proxy/admin-sync/outbound', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, body }),
      });
      if (!res.ok) {
        const t = await res.text().catch(() => '');
        setSendErr(`send failed (${res.status}): ${t.slice(0, 200)}`);
        return;
      }
      setText('');
      // Refresh immediately so the new "sending…" indicator appears
      // without waiting for the 5s tick.
      reload();
    } catch (e) {
      setSendErr(e instanceof Error ? e.message : 'send failed');
    } finally {
      setSending(false);
    }
  }

  // Merge messages + still-pending outbound queue into a single
  // chronologically-sorted display list. Sent rows in the queue are
  // also rendered (briefly) so the operator sees confirmation; once
  // they age out of the 24h window the server stops returning them and
  // the corresponding admin_plaintext row carries the message on.
  const display = [
    ...convo.messages.map((m) => ({
      kind: 'msg' as const,
      key: m.id,
      time: new Date(m.created_at).getTime(),
      ...m,
    })),
    ...convo.outbound_queue.map((q) => ({
      kind: 'queue' as const,
      key: q.id,
      time: new Date(q.created_at).getTime(),
      ...q,
    })),
  ].sort((a, b) => a.time - b.time);

  return (
    <div className="flex-1 flex flex-col gap-3 min-h-0">
      <div
        ref={scrollerRef}
        className="flex-1 overflow-y-auto space-y-2 pr-1"
      >
        {display.length === 0 && (
          <p className="text-sm text-gray-500">No messages yet.</p>
        )}
        {display.map((row) => {
          if (row.kind === 'msg') {
            const outgoing = row.direction === 'outbound';
            const decrypting = row.plaintext === null;
            return (
              <div
                key={row.key}
                className={
                  outgoing
                    ? 'ml-12 border border-emerald-900/40 bg-emerald-950/30 rounded-lg p-3 text-sm'
                    : 'mr-12 border border-line/30 rounded-lg p-3 text-sm'
                }
              >
                <div className="text-xs text-gray-500 flex justify-between gap-2">
                  <span>{outgoing ? 'You' : 'User'}</span>
                  <time>{new Date(row.created_at).toLocaleString()}</time>
                </div>
                {decrypting ? (
                  <p className="text-xs text-gray-400 italic mt-1">
                    decrypting on admin device…
                  </p>
                ) : (
                  <p className="whitespace-pre-wrap mt-1">{row.plaintext}</p>
                )}
              </div>
            );
          }
          // Pending / failed / sent queue row
          const cls =
            row.status === 'failed'
              ? 'ml-12 border border-red-900/40 bg-red-950/30 rounded-lg p-3 text-sm'
              : 'ml-12 border border-emerald-900/40 bg-emerald-950/30 rounded-lg p-3 text-sm opacity-70';
          return (
            <div key={row.key} className={cls}>
              <div className="text-xs text-gray-500 flex justify-between gap-2">
                <span>
                  You ·{' '}
                  {row.status === 'pending'
                    ? 'sending…'
                    : row.status === 'failed'
                      ? 'failed'
                      : 'sent'}
                </span>
                <time>{new Date(row.created_at).toLocaleString()}</time>
              </div>
              <p className="whitespace-pre-wrap mt-1">{row.body}</p>
              {row.last_error && (
                <p className="text-xs text-red-300 mt-1">
                  {row.last_error}
                </p>
              )}
            </div>
          );
        })}
      </div>
      {sendErr && (
        <p className="text-xs text-red-400 px-1">{sendErr}</p>
      )}
      <div className="border-t border-line/30 pt-3 flex gap-2">
        <input
          className="input flex-1"
          placeholder="Reply"
          value={text}
          disabled={sending}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        <button
          className="btn-primary"
          disabled={sending || !text.trim()}
          onClick={send}
        >
          {sending ? 'Sending…' : 'Send'}
        </button>
      </div>
    </div>
  );
}
