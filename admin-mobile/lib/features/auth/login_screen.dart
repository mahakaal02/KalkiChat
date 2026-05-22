import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'auth_state.dart';

/// Email + password collection screen. Doesn't talk to the backend
/// itself any more — credentials are stashed in [pendingAdminAuthProvider]
/// and the TOTP screen does the actual /v1/admin/devices/register call
/// once the TOTP code is in hand.
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
              const SizedBox(height: 8),
              const Text(
                'Companion-device sign-in',
                style: TextStyle(color: Colors.white54),
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _email,
                decoration: const InputDecoration(labelText: 'Email'),
                autocorrect: false,
                enableSuggestions: false,
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _pw,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Password'),
                autocorrect: false,
                enableSuggestions: false,
              ),
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
    setState(() {
      _busy = true;
      _err = null;
    });
    final String email = _email.text.trim();
    final String password = _pw.text;
    if (email.isEmpty || password.isEmpty) {
      setState(() {
        _err = 'Email and password are required.';
        _busy = false;
      });
      return;
    }
    // No server round-trip here — we collect creds and let the TOTP
    // screen do the single-shot /v1/admin/devices/register. This lets
    // us return informative errors (BAD_CREDENTIALS, BAD_TOTP, etc.)
    // from one endpoint instead of two.
    ref.read(pendingAdminAuthProvider.notifier).state =
        PendingAdminAuth(email: email, password: password);
    if (!mounted) return;
    setState(() => _busy = false);
    context.go('/totp');
  }
}
