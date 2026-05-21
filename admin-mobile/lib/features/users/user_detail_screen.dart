import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api.dart';

class UserDetailScreen extends ConsumerStatefulWidget {
  const UserDetailScreen({super.key, required this.userId});
  final String userId;

  @override
  ConsumerState<UserDetailScreen> createState() => _State();
}

class _State extends ConsumerState<UserDetailScreen> {
  Map<String, dynamic>? _u;
  List<dynamic> _msgs = <dynamic>[];
  final TextEditingController _reply = TextEditingController();
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final api = ref.read(adminApiProvider);
    final results = await Future.wait<dynamic>(<Future<dynamic>>[
      api.get('/v1/admin/users/${widget.userId}'),
      api.get('/v1/admin/users/${widget.userId}/conversation'),
    ]);
    if (!mounted) return;
    setState(() {
      _u = (results[0].data as Map).cast<String, dynamic>();
      _msgs = ((results[1].data as Map?)?['messages'] as List<dynamic>?) ?? <dynamic>[];
    });
  }

  Future<void> _send() async {
    final String text = _reply.text.trim();
    if (text.isEmpty) return;
    setState(() => _busy = true);
    try {
      // Real impl: seal with admin's per-device key. Placeholder shown.
      await ref.read(adminApiProvider).post(
            '/v1/admin/users/${widget.userId}/messages',
            <String, dynamic>{
              'client_id': DateTime.now().millisecondsSinceEpoch.toString(),
              'recipient_device_id': 'pick-from-prekeys',
              'envelope': '',
              'signature': '',
            },
          );
      _reply.clear();
      await _load();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_u == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    final Map<String, dynamic> u = _u!;
    return Scaffold(
      appBar: AppBar(title: Text(u['login'] as String)),
      body: Column(
        children: <Widget>[
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(12),
              reverse: true,
              itemCount: _msgs.length,
              itemBuilder: (BuildContext c, int i) {
                final Map<String, dynamic> m = (_msgs[_msgs.length - 1 - i] as Map).cast<String, dynamic>();
                return Card(
                  child: Padding(
                    padding: const EdgeInsets.all(8),
                    child: Text(
                      '[ciphertext ${(m['envelope'] as String).length}b · '
                      'from ${(m['sender_device_id'] as String).substring(0, 8)}…]',
                      style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                    ),
                  ),
                );
              },
            ),
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
