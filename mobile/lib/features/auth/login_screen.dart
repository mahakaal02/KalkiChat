import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../onboarding/whatsapp_onboarding.dart';
import 'login_controller.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final TextEditingController _userIdCtrl = TextEditingController();
  final TextEditingController _passCtrl = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _userIdCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final LoginResult res =
          await ref.read(loginControllerProvider.notifier).login(
                userId: _userIdCtrl.text.trim(),
                password: _passCtrl.text,
              );
      if (!mounted) return;
      if (res.mustChangePassword) {
        // Admin-provisioned account on first login — gate the user behind a
        // forced change-password screen. The current password is the one
        // they just typed; pass it through to save them retyping.
        context.go('/change-password',
            extra: <String, String>{'current': _passCtrl.text});
      } else {
        context.go('/chat');
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _openWhatsApp() async {
    try {
      await WhatsAppOnboarding.open(ref);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not open WhatsApp: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              const SizedBox(height: 48),
              const Text(
                'Welcome back',
                style: TextStyle(fontSize: 28, fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 8),
              const Text('Sign in to KalkiChat',
                  style: TextStyle(color: Colors.white54)),
              const SizedBox(height: 32),
              TextField(
                controller: _userIdCtrl,
                textInputAction: TextInputAction.next,
                autocorrect: false,
                enableSuggestions: false,
                decoration: const InputDecoration(labelText: 'User ID'),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _passCtrl,
                obscureText: true,
                enableInteractiveSelection: false, // disables copy/paste menu
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.done,
                onSubmitted: (_) => _submit(),
                decoration: const InputDecoration(labelText: 'Password'),
              ),
              if (_error != null) ...<Widget>[
                const SizedBox(height: 12),
                Text(_error!, style: const TextStyle(color: Colors.redAccent)),
              ],
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _busy ? null : _submit,
                child: _busy
                    ? const SizedBox(
                        width: 22,
                        height: 22,
                        child: CircularProgressIndicator(
                          strokeWidth: 2, color: Color(0xFF062A24)))
                    : const Text('Sign in'),
              ),
              const SizedBox(height: 32),
              Center(
                child: TextButton(
                  onPressed: _openWhatsApp,
                  child: const Text(
                    'New User? Request Login',
                    style: TextStyle(
                      decoration: TextDecoration.underline,
                      color: Color(0xFF7AE2CF),
                    ),
                  ),
                ),
              ),
              const Spacer(),
              const Padding(
                padding: EdgeInsets.only(bottom: 12),
                child: Text(
                  'Your messages are end-to-end encrypted.\nKalkiChat cannot read them.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white38, fontSize: 12),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
