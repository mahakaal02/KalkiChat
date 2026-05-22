/**
 * /messages — the empty state shown in the right pane when no specific
 * conversation has been selected yet. The chat list itself lives in the
 * shared layout.tsx, so it stays visible.
 */
export default function MessagesIndex() {
  return (
    <div className="h-full flex items-center justify-center p-8 text-center">
      <div className="max-w-sm space-y-3 text-gray-400">
        <div className="text-5xl">💬</div>
        <h2 className="text-lg text-gray-200">Select a conversation</h2>
        <p className="text-sm">
          Pick any user from the list on the left to view their chat history
          with the admin.
        </p>
      </div>
    </div>
  );
}
