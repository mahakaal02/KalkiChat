import { api } from '@/lib/api';

type AuditEvent = {
  id: number;
  actor_kind: string; actor_id: string;
  action: string;
  target_kind: string | null; target_id: string | null;
  ip: string | null; user_agent: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
};

export default async function AuditPage() {
  const r = await api.internal<{ events: AuditEvent[] }>('/v1/admin/audit');
  const events: AuditEvent[] = r.ok ? r.data.events : [];
  return (
    <section className="space-y-5">
      <header className="flex justify-between items-center">
        <h1 className="text-2xl font-semibold">Audit log</h1>
        <a href="/api/proxy/admin/audit.csv" className="btn-ghost" download>
          Export CSV
        </a>
      </header>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 uppercase text-xs tracking-wider">
              <th className="py-2">When</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-t border-line/30 align-top">
                <td className="py-2 text-gray-400">
                  {new Date(e.created_at).toLocaleString()}
                </td>
                <td className="font-mono text-xs">
                  <div>{e.actor_kind}</div>
                  <div className="text-gray-500">{e.actor_id}</div>
                </td>
                <td>{e.action}</td>
                <td className="font-mono text-xs">
                  {e.target_kind && <div>{e.target_kind}</div>}
                  {e.target_id && <div className="text-gray-500">{e.target_id}</div>}
                </td>
                <td className="text-gray-400 font-mono text-xs">{e.ip ?? '—'}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr><td colSpan={5} className="py-4 text-center text-gray-500">No events.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-gray-500 max-w-2xl">
        Audit records are append-only at the database layer. They include who
        did what and against whom — they <strong>never</strong> include
        message bodies.
      </p>
    </section>
  );
}
