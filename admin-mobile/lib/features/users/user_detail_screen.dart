import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';
import '../../data/local_db.dart';
import '../chat/admin_chat_controller.dart';

/// Per-user conversation screen for the admin companion device.
///
/// What you see here is plaintext that THIS device decrypted from
/// envelopes coming over /v1/ws (handled by [AdminChatController]).
/// We do NOT fetch ciphertext over HTTP and try to decode it after
/// the fact — that path doesn't have the ratchet state.
///
/// The list is sourced from the local SQLCipher DB (the `messages`
/// table, filtered by user_id). It auto-refreshes whenever the chat
/// controller signals a new message arrived (via `lastMessageAt`).
class UserDetailScreen extends ConsumerStatefulWidget {
  const UserDetailScreen({super.key, required this.userId});
  final String userId;

  @override
  ConsumerState<UserDetailScreen> createState() => _State();
}

class _State extends ConsumerState<UserDetailScreen> {
  Map<String, dynamic>? _user;
  List<Map<String, Object?>> _msgs = <Map<String, Object?>>[];
  final TextEditingController _reply = TextEditingController();
  bool _busy = false;
  String? _err;
  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _load();
    // HTTP backfill safety net: any message the WS missed (registered
    // device race, transient disconnect, app cold-started after the user
    // had already sent) gets fetched as ciphertext, decrypted locally,
    // and relayed to /admin-sync/inbound. Fires on open AND every 5s so
    // a one-time fetch failure self-heals.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref
          .read(adminChatControllerProvider.notifier)
          .backfillFromServer(widget.userId)
          .then((_) {
        if (mounted) _load();
      });
    });
    _poll = Timer.periodic(const Duration(seconds: 5), (_) async {
      if (!mounted) return;
      await ref
          .read(adminChatControllerProvider.notifier)
          .backfillFromServer(widget.userId);
      if (mounted) unawaited(_load());
    });
  }

  @override
  void dispose() {
    _poll?.cancel();
    _reply.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final api = ref.read(adminApiProvider);
    final AdminLocalDb db = await AdminLocalDb.open();
    final results = await Future.wait<dynamic>(<Future<dynamic>>[
      api.get('/v1/admin/users/${widget.userId}'),
      db.messagesForUser(widget.userId),
    ]);
    if (!mounted) return;
    setState(() {
      _user = (results[0].data as Map).cast<String, dynamic>();
      _msgs = results[1] as List<Map<String, Object?>>;
    });
  }

  Future<void> _send() async {
    final String text = _reply.text.trim();
    if (text.isEmpty) return;
    setState(() {
      _busy = true;
      _err = null;
    });
    try {
      // Find a peer device id from the most-recent inbound message —
      // that's the user device we're already in session with. If we've
      // never received from this user, admin-mobile can't initiate
      // (that's a v2 feature); surface a friendly note.
      final Map<String, Object?> lastIn = _msgs.lastWhere(
        (Map<String, Object?> m) => m['direction'] == 'in',
        orElse: () => <String, Object?>{},
      );
      if (lastIn.isEmpty) {
        setState(() => _err =
            'No active session with this user yet — wait for them to message first.');
        return;
      }
      final String peer = lastIn['peer_device_id']! as String;
      final bool ok =
          await ref.read(adminChatControllerProvider.notifier).sendReply(
                peerDeviceId: peer,
                userId: widget.userId,
                text: text,
              );
      if (ok) {
        _reply.clear();
        await _load();
      } else {
        final String? lastError =
            ref.read(adminChatControllerProvider).lastError;
        setState(() => _err = lastError ?? 'send failed');
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    // Listen to chat controller state — when a new message arrives,
    // re-load the local DB to pick up the row.
    ref.listen<AdminChatState>(adminChatControllerProvider, (prev, next) {
      if (prev?.lastMessageAt != next.lastMessageAt) {
        _load();
      }
    });

    if (_user == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    final Map<String, dynamic> u = _user!;
    final AdminChatState chat = ref.watch(adminChatControllerProvider);

    return Scaffold(
      appBar: AppBar(
        // We navigate here via context.go('/users/<id>') which REPLACES
        // the route rather than pushing onto a stack, so Flutter's
        // automatic back button doesn't appear. An explicit leading
        // IconButton always routes back to the chat list — matches
        // the affordance every common chat app has.
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          tooltip: 'Back to chat list',
          onPressed: () => context.go('/users'),
        ),
        title: Text(u['login'] as String),
        actions: <Widget>[
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Icon(
              chat.connected ? Icons.cloud_done : Icons.cloud_off,
              size: 18,
              color: chat.connected ? Colors.greenAccent : Colors.redAccent,
            ),
          ),
        ],
      ),
      body: Column(
        children: <Widget>[
          if (chat.lastError != null)
            Container(
              width: double.infinity,
              color: const Color(0x33FFAA00),
              padding: const EdgeInsets.all(8),
              child: Text(chat.lastError!,
                  style: const TextStyle(fontSize: 12, color: Colors.amberAccent)),
            ),
          Expanded(
            child: _msgs.isEmpty
                ? const Center(
                    child: Text(
                      'No messages yet.\n'
                      'When this user sends a support message,\n'
                      'it will appear here decrypted on this device.',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.white54),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.all(12),
                    itemCount: _msgs.length,
                    itemBuilder: (BuildContext c, int i) {
                      final Map<String, Object?> m = _msgs[i];
                      final bool outgoing = m['direction'] == 'out';
                      final String text =
                          (m['plaintext'] as String?) ?? '(decryption pending)';
                      final DateTime at = DateTime.fromMillisecondsSinceEpoch(
                          m['created_at']! as int);
                      return Align(
                        alignment: outgoing
                            ? Alignment.centerRight
                            : Alignment.centerLeft,
                        child: Container(
                          margin: const EdgeInsets.symmetric(vertical: 3),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 12, vertical: 8),
                          constraints: const BoxConstraints(maxWidth: 300),
                          decoration: BoxDecoration(
                            color: outgoing
                                ? const Color(0xFF1F4D44)
                                : const Color(0xFF202733),
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: <Widget>[
                              Text(text,
                                  style: const TextStyle(fontSize: 14)),
                              const SizedBox(height: 2),
                              Text(
                                _timeFmt(at),
                                style: const TextStyle(
                                    fontSize: 10, color: Colors.white54),
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
          if (_err != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Text(_err!,
                  style: const TextStyle(color: Colors.redAccent, fontSize: 12)),
            ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
              child: Row(
                children: <Widget>[
                  Expanded(
                    child: TextField(
                      controller: _reply,
                      decoration: const InputDecoration(hintText: 'Reply'),
                      enableInteractiveSelection: false,
                    ),
                  ),
                  IconButton.filled(
                    onPressed: _busy ? null : _send,
                    icon: const Icon(Icons.send),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

String _timeFmt(DateTime t) {
  String two(int v) => v < 10 ? '0$v' : '$v';
  return '${two(t.hour)}:${two(t.minute)}';
}
