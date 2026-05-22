'use client';

import { useState } from 'react';
import { CreateUserDialog } from '@/components/CreateUserDialog';

/**
 * Header strip for /users: a title, the search form (kept as a plain GET form
 * so users-page server-component re-renders with new searchParams), and the
 * "+ Create user" button which mounts a client-side dialog.
 */
export function UsersToolbar({ initialQuery }: { initialQuery: string }) {
  const [creating, setCreating] = useState(false);

  return (
    <header className="flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-2xl font-semibold">Users</h1>
      <div className="flex items-center gap-2">
        <form className="flex gap-2">
          <input
            name="q"
            defaultValue={initialQuery}
            placeholder="search by user ID"
            className="input max-w-sm"
          />
          <button className="btn-ghost">Search</button>
        </form>
        <button className="btn-primary" onClick={() => setCreating(true)}>
          + Create user
        </button>
      </div>
      {creating && <CreateUserDialog onClose={() => setCreating(false)} />}
    </header>
  );
}
