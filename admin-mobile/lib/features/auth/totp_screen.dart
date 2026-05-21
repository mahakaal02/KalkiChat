import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';

class AdminTotpScreen extends ConsumerStatefulWidget {
  const AdminTotpScreen({super.key});

  @override
  ConsumerState<AdminTotpScreen> createState() => _State();
}

class _State extends ConsumerState<AdminTotpScreen> {
  final TextEditingController _code = TextEditingController();
  bool _busy = false;
  String? _err;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Two-factor')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            const Text('Enter the 6-digit code from your authenticator app.'),
            const SizedBox(height: 16),
            TextField(
              controller: _code,
              keyboardType: TextInputType.number,
              inputFormatters: <TextInputFormatter>[
                FilteringTextInputFormatter.digitsOnly,
                LengthLimitingTextInputFormatter(6),
              ],
              decoration: const InputDecoration(labelText: 'Code'),
              style: const TextStyle(fontSize: 22, letterSpacing: 8),
              textAlign: TextAlign.center,
              autofocus: true,
            ),
            if (_err != null) ...<Widget>[
              const SizedBox(height: 12),
              Text(_err!, style: const TextStyle(color: Colors.redAccent)),
            ],
            const SizedBox(height: 24),
            FilledButton(onPressed: _busy ? null : _go, child: const Text('Verify')),
          ],
        ),
      ),
    );
  }

  Future<void> _go() async {
    setState(() { _busy = true; _err = null; });
    try {
      final api = ref.read(adminApiProvider);
      final r = await api.post('/v1/admin/auth/totp', <String, String>{'code': _code.text});
      if (r.statusCode != 200) {
        setState(() => _err = 'Bad code');
        return;
      }
      await api.saveSessionFromHeaders(r.headers);
      if (!mounted) return;
      context.go('/users');
    } catch (e) {
      setState(() => _err = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
}
