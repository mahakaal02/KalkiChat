import { api } from '@/lib/api';
import { ConversationView } from '@/components/ConversationView';

type Device = {
  id: string; name: string; platform: string;
  created_at: string; last_seen_at: string; revoked_at: string | null;
};
type UserDetail = { id: string; login: string; status: string; devices: Device[] };
type Message = {
  id: string; sender_device_id: string;
  envelope: string; signature: string;
  media_id: string | null; created_at: string;
};

export default async function UserDetailPage({
  params,
}: { params: { id: string } }) {
  const [userR, convoR] = await Promise.all([
    api.internal<UserDetail>(`/v1/admin/users/${params.id}`),
    api.internal<{ conversation_id: string; messages: Message[] }>(
      `/v1/admin/users/${params.id}/conversation`,
    ),
  ]);
  if (!userR.ok) {
    return <div className="text-danger">Failed: {userR.error.message}</div>;
  }
  const u = userR.data;
  const convo = convoR.ok ? convoR.data : { conversation_id: '', messages: [] };
  return (
    <section className="space-y-5">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold font-mono">{u.login}</h1>
          <p className="text-xs text-gray-400">{u.id} · {u.status}</p>
        </div>
        <div className="flex gap-2">
          <form action={`/api/proxy/admin/users/${u.id}/revoke-sessions`} method="POST">
            <button className="btn-ghost">Sign out all devices</button>
          </form>
          <form
            action={`/api/proxy/admin/users/${u.id}/${u.status === 'suspended' ? 'unsuspend' : 'suspend'}`}
            method="POST">
            <button className={u.status === 'suspended' ? 'btn-primary' : 'btn-danger'}>
              {u.status === 'suspended' ? 'Unsuspend' : 'Suspend'}
            </button>
          </form>
        </div>
      </header>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="card lg:col-span-2 h-[70vh] flex flex-col">
          <h2 className="text-sm uppercase tracking-wider text-gray-400 mb-2">Conversation</h2>
          <ConversationView userId={u.id} messages={convo.messages} />
        </div>
        <div className="card h-[70vh] overflow-y-auto">
          <h2 className="text-sm uppercase tracking-wider text-gray-400 mb-2">Devices</h2>
          <ul className="space-y-2">
            {u.devices.map((d) => (
              <li key={d.id} className="border border-line/30 rounded-lg p-3 text-sm">
                <div className="flex justify-between">
                  <span>{d.name}</span>
                  <span className={d.revoked_at ? 'text-danger' : 'text-accent'}>
                    {d.revoked_at ? 'revoked' : 'active'}
                  </span>
                </div>
                <div className="text-xs text-gray-500 mt-1 font-mono">{d.id}</div>
                <div className="text-xs text-gray-500">{d.platform}</div>
                {!d.revoked_at && (
                  <form action={`/api/proxy/admin/devices/${d.id}/revoke`} method="POST" className="mt-2">
                    <button className="btn-danger w-full text-xs py-1">Revoke</button>
                  </form>
                )}
              </li>
            ))}
            {u.devices.length === 0 && (
              <li className="text-gray-500 text-sm">No devices.</li>
            )}
          </ul>
        </div>
      </div>
    </section>
  );
}
