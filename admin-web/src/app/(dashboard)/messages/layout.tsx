import { api } from '@/lib/api';
import { ChatList, type ChatRow } from '@/components/ChatList';

/**
 * Two-pane WhatsApp/Telegram-style layout shared by /messages and
 * /messages/[userId]. The left pane lists every user's conversation sorted
 * by most-recent activity; the right pane is whatever the child route
 * renders (empty state for /messages, the conversation pane for
 * /messages/[userId]).
 */
export default async function MessagesLayout({
  children,
}: { children: React.ReactNode }) {
  const r = await api.internal<{ conversations: ChatRow[] }>('/v1/admin/conversations');
  const rows: ChatRow[] = r.ok ? r.data.conversations : [];
  return (
    <section className="h-[calc(100vh-3rem)] -m-6 grid grid-cols-1 md:grid-cols-[20rem_1fr]">
      <aside className="border-r border-line/30 overflow-y-auto bg-surface/40">
        <header className="px-4 py-3 border-b border-line/30 sticky top-0 bg-surface/95 backdrop-blur">
          <h1 className="text-lg font-semibold">Messages</h1>
          <p className="text-xs text-gray-500">
            {rows.length} {rows.length === 1 ? 'conversation' : 'conversations'}
          </p>
        </header>
        <ChatList rows={rows} />
      </aside>
      <main className="overflow-y-auto">{children}</main>
    </section>
  );
}
