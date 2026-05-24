import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';
import '../chat/admin_chat_controller.dart';

final usersProvider = FutureProvider.family<List<Map<String, dynamic>>, String>(
    (ref, q) async {
  final api = ref.read(adminApiProvider);
  final r = await api.get('/v1/admin/users', q.isEmpty ? null : <String, dynamic>{'q': q});
  if (r.statusCode != 200) return <Map<String, dynamic>>[];
  final List<dynamic> raw = (r.data as Map)['users'] as List<dynamic>;
  return raw.cast<Map<String, dynamic>>();
});

class UsersScreen extends ConsumerStatefulWidget {
  const UsersScreen({super.key});

  @override
  ConsumerState<UsersScreen> createState() => _State();
}

class _State extends ConsumerState<UsersScreen> {
  String _q = '';

  @override
  void initState() {
    super.initState();
    // Bring up the WS + DB + prekey-upload pipeline now that we know the
    // user is signed in. Idempotent — safe to call across navigations.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(adminChatControllerProvider.notifier).start();
    });
  }

  @override
  Widget build(BuildContext context) {
    final AsyncValue<List<Map<String, dynamic>>> users = ref.watch(usersProvider(_q));
    final AdminChatState chat = ref.watch(adminChatControllerProvider);
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: <Widget>[
            const Text('Users'),
            const SizedBox(width: 8),
            // Status pill: green = WS connected, red = disconnected. Lives
            // in the appbar so the admin sees it across navigations and
            // immediately knows if "messages aren't arriving" is a
            // connectivity issue vs. a real "no messages" state.
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: chat.connected
                    ? const Color(0x4400AA66)
                    : const Color(0x44CC3333),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                chat.connected ? 'online' : 'offline',
                style: const TextStyle(fontSize: 11),
              ),
            ),
          ],
        ),
        actions: <Widget>[
          IconButton(
            icon: const Icon(Icons.history),
            onPressed: () => context.go('/audit'),
            tooltip: 'Audit',
          ),
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () => context.go('/config/whatsapp'),
            tooltip: 'WhatsApp config',
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
              child: Text(
                'Chat: ${chat.lastError!}',
                style: const TextStyle(
                    fontSize: 12, color: Colors.amberAccent),
              ),
            ),
          Padding(
            padding: const EdgeInsets.all(12),
            child: TextField(
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search), hintText: 'Search login',
              ),
              onSubmitted: (String v) => setState(() => _q = v),
            ),
          ),
          Expanded(
            child: users.when(
              loading: () => const Center(child: CircularProgressIndicator()),
              error: (Object e, _) => Center(child: Text('$e')),
              data: (List<Map<String, dynamic>> list) => ListView.separated(
                itemBuilder: (_, int i) {
                  final Map<String, dynamic> u = list[i];
                  return ListTile(
                    title: Text(u['login'] as String,
                        style: const TextStyle(fontFamily: 'monospace')),
                    subtitle: Text(u['status'] as String),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => context.go('/users/${u['id']}'),
                  );
                },
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemCount: list.length,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
