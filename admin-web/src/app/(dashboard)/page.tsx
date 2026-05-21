import { api } from '@/lib/api';

type Analytics = {
  users_total: number;
  users_active: number;
  messages_24h: number;
  messages_7d: number;
};

export default async function OverviewPage() {
  const r = await api.internal<Analytics>('/v1/admin/analytics');
  const a: Analytics = r.ok
    ? r.data
    : { users_total: 0, users_active: 0, messages_24h: 0, messages_7d: 0 };
  return (
    <section className="space-y-6">
      <h1 className="text-2xl font-semibold">Overview</h1>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card label="Users (total)" value={a.users_total} />
        <Card label="Users (active)" value={a.users_active} />
        <Card label="Messages 24h" value={a.messages_24h} />
        <Card label="Messages 7d" value={a.messages_7d} />
      </div>
      <div className="card">
        <h2 className="text-sm uppercase tracking-wider text-gray-400 mb-2">
          Security posture
        </h2>
        <ul className="text-sm space-y-1">
          <li>· Messages auto-delete after 30 days (crypto-erased).</li>
          <li>· Plaintext is never stored on the server.</li>
          <li>· Admin actions are audit-logged. Message bodies are not.</li>
        </ul>
      </div>
    </section>
  );
}

function Card({ label, value }: { label: string; value: number }) {
  return (
    <div className="card">
      <div className="label">{label}</div>
      <div className="text-3xl font-semibold">{value.toLocaleString()}</div>
    </div>
  );
}
