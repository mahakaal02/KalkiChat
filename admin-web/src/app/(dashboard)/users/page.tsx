import Link from 'next/link';
import { api } from '@/lib/api';
import { UsersToolbar } from './UsersToolbar';

type User = {
  id: string;
  login: string;
  status: string;
  created_at: string;
  last_login: string | null;
  must_change_password: boolean;
};

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
      <UsersToolbar initialQuery={q} />
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-gray-400 uppercase text-xs tracking-wider">
              <th className="py-2">User ID</th>
              <th>Status</th>
              <th>Last login</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t border-line/30">
                <td className="py-2 font-mono">
                  {u.login}
                  {u.must_change_password && (
                    <span
                      className="ml-2 inline-block text-[10px] px-1.5 py-0.5 rounded
                                 bg-amber-900/40 text-amber-300 align-middle"
                      title="Must change password on first login"
                    >
                      PW RESET
                    </span>
                  )}
                </td>
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
