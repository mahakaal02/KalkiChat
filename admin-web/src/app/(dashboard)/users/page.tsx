import Link from 'next/link';
import { api } from '@/lib/api';

type User = { id: string; login: string; status: string; created_at: string; last_login: string | null };

export default async function UsersPage({
  searchParams,
}: { searchParams: { q?: string } }) {
  const q = searchParams.q ?? '';
  const r = await api.internal<{ users: User[] }>(
    `/v1/admin/users${q ? `?q=${encodeURIComponent(q)}` : ''}`,
  );
  const users: User[] = r.ok ? r.data.users : [];
  return (
    <section className="space-y-5">
      <h1 className="text-2xl font-semibold">Users</h1>
      <form className="flex gap-2">
        <input
          name="q"
          defaultValue={q}
          placeholder="search by login"
          className="input max-w-sm"
        />
        <button className="btn-primary">Search</button>
      </form>
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 uppercase text-xs tracking-wider">
              <th className="py-2">Login</th>
              <th>Status</th>
              <th>Last login</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-line/30">
                <td className="py-2 font-mono">{u.login}</td>
                <td>
                  <span className={u.status === 'active' ? 'text-accent' : 'text-danger'}>
                    {u.status}
                  </span>
                </td>
                <td className="text-gray-400">
                  {u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                </td>
                <td>
                  <Link href={`/users/${u.id}`} className="btn-ghost">Open</Link>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr><td colSpan={4} className="py-4 text-center text-gray-500">No users.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
