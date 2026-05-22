import Link from 'next/link';
import { redirect } from 'next/navigation';
import { hasAdminSession } from '@/lib/session';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  if (!hasAdminSession()) redirect('/login');
  return (
    <div className="min-h-screen flex">
      <aside className="w-60 bg-surface border-r border-line/30 flex flex-col">
        <div className="px-5 py-5 border-b border-line/30">
          <div className="text-xs uppercase tracking-widest text-gray-400">KalkiChat</div>
          <div className="font-semibold mt-1">Admin</div>
        </div>
        <nav className="flex-1 p-3 space-y-1 text-sm">
          <NavLink href="/">Overview</NavLink>
          <NavLink href="/messages">Messages</NavLink>
          <NavLink href="/users">Users</NavLink>
          <NavLink href="/devices">Devices</NavLink>
          <NavLink href="/config/whatsapp">WhatsApp Config</NavLink>
          <NavLink href="/audit">Audit log</NavLink>
        </nav>
        <form action="/api/proxy/admin/auth/logout" method="POST" className="p-3">
          <button className="btn-ghost w-full">Sign out</button>
        </form>
      </aside>
      <main className="flex-1 p-6 overflow-auto">{children}</main>
    </div>
  );
}

function NavLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="block px-3 py-2 rounded-lg hover:bg-line/40 transition">
      {children}
    </Link>
  );
}
