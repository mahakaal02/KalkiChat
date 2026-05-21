import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';

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
  Widget build(BuildContext context) {
    final AsyncValue<List<Map<String, dynamic>>> users = ref.watch(usersProvider(_q));
    return Scaffold(
      appBar: AppBar(
        title: const Text('Users'),
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
