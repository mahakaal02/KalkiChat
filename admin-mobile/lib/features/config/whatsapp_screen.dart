import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api.dart';

class WhatsAppScreen extends ConsumerStatefulWidget {
  const WhatsAppScreen({super.key});

  @override
  ConsumerState<WhatsAppScreen> createState() => _State();
}

class _State extends ConsumerState<WhatsAppScreen> {
  final TextEditingController _phone = TextEditingController();
  final TextEditingController _msg = TextEditingController();
  String _status = '';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final r = await ref.read(adminApiProvider).get('/v1/admin/config/whatsapp');
    if (r.statusCode == 200) {
      final Map<String, dynamic> j = (r.data as Map).cast<String, dynamic>();
      _phone.text = j['phone_e164'] as String? ?? '';
      _msg.text = j['message_template'] as String? ?? '';
      if (mounted) setState(() {});
    }
  }

  Future<void> _save() async {
    setState(() { _busy = true; _status = ''; });
    try {
      final r = await ref.read(adminApiProvider).put('/v1/admin/config/whatsapp', <String, String>{
        'phone_e164': _phone.text.trim(),
        'message_template': _msg.text,
      });
      setState(() => _status = r.statusCode == 200 ? 'Saved.' : 'Failed: ${r.statusCode}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('WhatsApp onboarding')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            const Text('Number and message used by new users when they tap '
                '"Request Login". Applies instantly.'),
            const SizedBox(height: 12),
            TextField(
              controller: _phone,
              decoration: const InputDecoration(labelText: 'Phone (E.164, e.g. +14155551234)'),
              keyboardType: TextInputType.phone,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _msg,
              decoration: const InputDecoration(labelText: 'Message template'),
              maxLines: 5,
              maxLength: 1000,
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: _busy ? null : _save,
              child: Text(_busy ? '…' : 'Save'),
            ),
            if (_status.isNotEmpty) ...<Widget>[
              const SizedBox(height: 12),
              Text(_status),
            ],
          ],
        ),
      ),
    );
  }
}
