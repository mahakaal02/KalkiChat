'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';

export type ChatRow = {
  user_id: string;
  login: string;
  status: string;
  conversation_id: string;
  last_message_at: string | null;
  message_count: number;
  preview_size: number;
};

/**
 * The WhatsApp-style left rail. Each row shows the user's permanent ID
 * (which we surface "in place of contact name" per the admin spec), a
 * relative timestamp of the last message, and an encrypted-preview badge
 * since admin-side decryption is not yet provisioned.
 */
export function ChatList({ rows }: { rows: ChatRow[] }) {
  const params = useParams() as { userId?: string };
  const activeId = params.userId;

  if (rows.length === 0) {
    return (
      <p className="p-4 text-sm text-gray-500">
        No conversations yet. Create a user first.
      </p>
    );
  }

  return (
    <ul className="divide-y divide-line/20">
      {rows.map((c) => {
        const active = c.user_id === activeId;
        return (
          <li key={c.user_id}>
            <Link
              href={`/messages/${c.user_id}`}
              className={[
                'flex flex-col gap-1 px-4 py-3 transition-colors',
                active ? 'bg-line/40' : 'hover:bg-line/20',
              ].join(' ')}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm truncate">{c.login}</span>
                <time className="text-[10px] uppercase tracking-wider text-gray-500 shrink-0">
                  {relativeTime(c.last_message_at)}
                </time>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-500 truncate">
                  {c.message_count === 0
                    ? 'No messages yet'
                    : c.preview_size > 0
                      ? `🔒 encrypted · ${c.message_count} message${c.message_count === 1 ? '' : 's'}`
                      : `${c.message_count} message${c.message_count === 1 ? '' : 's'}`}
                </span>
                {c.status !== 'active' && (
                  <span className="text-[10px] uppercase tracking-wider text-danger">
                    {c.status}
                  </span>
                )}
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function relativeTime(iso: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  const m = Math.round(ms / 60_000);
  if (m < 1) return 'now';
  if (m < 60) return `${m}m`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.round(h / 24);
  if (d < 7) return `${d}d`;
  return new Date(iso).toLocaleDateString();
}
