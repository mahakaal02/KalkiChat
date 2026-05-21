import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api.dart';

class AdminLoginScreen extends ConsumerStatefulWidget {
  const AdminLoginScreen({super.key});

  @override
  ConsumerState<AdminLoginScreen> createState() => _State();
}

class _State extends ConsumerState<AdminLoginScreen> {
  final TextEditingController _email = TextEditingController();
  final TextEditingController _pw = TextEditingController();
  bool _busy = false;
  String? _err;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              const SizedBox(height: 32),
              const Text('KalkiChat Admin',
                  style: TextStyle(fontSize: 26, fontWeight: FontWeight.w700)),
              const SizedBox(height: 24),
              TextField(controller: _email, decoration: const InputDecoration(labelText: 'Email')),
              const SizedBox(height: 12),
              TextField(controller: _pw, obscureText: true,
                  decoration: const InputDecoration(labelText: 'Password')),
              if (_err != null) ...<Widget>[
                const SizedBox(height: 12),
                Text(_err!, style: const TextStyle(color: Colors.redAccent)),
              ],
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _busy ? null : _go,
                child: Text(_busy ? '…' : 'Continue'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _go() async {
    setState(() { _busy = true; _err = null; });
    try {
      final api = ref.read(adminApiProvider);
      final r = await api.post('/v1/admin/auth/login', <String, String>{
        'email': _email.text.trim(),
        'password': _pw.text,
      });
      if (r.statusCode != 200) {
        setState(() => _err = 'Sign-in failed (${r.statusCode})');
        return;
      }
      if (!mounted) return;
      context.go('/totp');
    } catch (e) {
      setState(() => _err = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }
}
