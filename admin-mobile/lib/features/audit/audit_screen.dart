import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api.dart';

final auditProvider = FutureProvider<List<Map<String, dynamic>>>((ref) async {
  final r = await ref.read(adminApiProvider).get('/v1/admin/audit');
  if (r.statusCode != 200) return <Map<String, dynamic>>[];
  return ((r.data as Map)['events'] as List<dynamic>).cast<Map<String, dynamic>>();
});

class AuditScreen extends ConsumerWidget {
  const AuditScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final events = ref.watch(auditProvider);
    return Scaffold(
      appBar: AppBar(title: const Text('Audit log')),
      body: events.when(
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (Object e, _) => Center(child: Text('$e')),
        data: (List<Map<String, dynamic>> list) => ListView.separated(
          itemBuilder: (_, int i) {
            final Map<String, dynamic> e = list[i];
            return ListTile(
              dense: true,
              title: Text(e['action'] as String),
              subtitle: Text(
                '${e['actor_kind']} ${e['actor_id']} → '
                '${e['target_kind'] ?? '—'} ${e['target_id'] ?? ''}\n'
                '${e['created_at']}',
              ),
              isThreeLine: true,
            );
          },
          separatorBuilder: (_, __) => const Divider(height: 1),
          itemCount: list.length,
        ),
      ),
    );
  }
}
