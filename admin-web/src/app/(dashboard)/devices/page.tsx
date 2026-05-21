import { api } from '@/lib/api';

type Device = {
  id: string; owner_kind: string; owner_id: string;
  name: string; platform: string;
  last_seen_at: string; revoked_at: string | null;
  online: boolean;
};

export default async function DevicesPage() {
  const r = await api.internal<{ devices: Device[] }>('/v1/admin/devices');
  const devices: Device[] = r.ok ? r.data.devices : [];
  return (
    <section className="space-y-5">
      <h1 className="text-2xl font-semibold">Active devices</h1>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 uppercase text-xs tracking-wider">
              <th className="py-2">Device</th>
              <th>Owner</th>
              <th>Platform</th>
              <th>Status</th>
              <th>Last seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} className="border-t border-line/30">
                <td className="py-2">
                  <div>{d.name}</div>
                  <div className="text-xs text-gray-500 font-mono">{d.id}</div>
                </td>
                <td className="text-xs font-mono">
                  <div>{d.owner_kind}</div>
                  <div className="text-gray-500">{d.owner_id}</div>
                </td>
                <td>{d.platform}</td>
                <td>
                  {d.revoked_at ? (
                    <span className="text-danger">revoked</span>
                  ) : d.online ? (
                    <span className="text-accent">online</span>
                  ) : (
                    <span className="text-gray-400">offline</span>
                  )}
                </td>
                <td className="text-gray-400 text-xs">
                  {new Date(d.last_seen_at).toLocaleString()}
                </td>
                <td>
                  {!d.revoked_at && (
                    <form action={`/api/proxy/admin/devices/${d.id}/revoke`} method="POST">
                      <button className="btn-danger text-xs">Revoke</button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
            {devices.length === 0 && (
              <tr><td colSpan={6} className="py-4 text-center text-gray-500">No devices.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
