import Link from 'next/link';
import { api } from '@/lib/api';
import { ConversationView } from '@/components/ConversationView';

type Message = {
  id: string;
  sender_device_id: string;
  envelope: string;
  signature: string;
  media_id: string | null;
  created_at: string;
};
type UserDetail = {
  id: string;
  login: string;
  status: string;
  must_change_password: boolean;
};

export default async function MessagesUserPage({
  params,
}: { params: { userId: string } }) {
  const [userR, convoR] = await Promise.all([
    api.internal<UserDetail>(`/v1/admin/users/${params.userId}`),
    api.internal<{ conversation_id: string; messages: Message[] }>(
      `/v1/admin/users/${params.userId}/conversation`,
    ),
  ]);
  if (!userR.ok) {
    return (
      <div className="p-6 text-danger">
        Failed to load user: {userR.error.message}
      </div>
    );
  }
  const u = userR.data;
  const convo = convoR.ok ? convoR.data : { conversation_id: '', messages: [] };

  return (
    <div className="h-full flex flex-col">
      <header className="px-6 py-3 border-b border-line/30 flex items-center justify-between gap-3 sticky top-0 bg-bg/95 backdrop-blur z-10">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold font-mono truncate">{u.login}</h2>
            {u.must_change_password && (
              <span
                className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-300"
                title="Must change password on first login"
              >
                PW RESET
              </span>
            )}
            <span className={
              u.status === 'active'
                ? 'text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/30 text-emerald-300'
                : 'text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-300'
            }>
              {u.status}
            </span>
          </div>
          <p className="text-xs text-gray-500 font-mono truncate">{u.id}</p>
        </div>
        <Link href={`/users/${u.id}`} className="btn-ghost text-xs">
          Open user details
        </Link>
      </header>

      <div className="px-6 py-2 bg-amber-900/10 border-b border-amber-900/20 text-xs text-amber-200">
        🔒 End-to-end encrypted. Message bodies are sealed to user devices;
        decryption requires provisioning an admin device key (not yet wired).
        The list below shows metadata only.
      </div>

      <div className="flex-1 px-6 py-4 overflow-hidden">
        <ConversationView userId={u.id} messages={convo.messages} />
      </div>
    </div>
  );
}
