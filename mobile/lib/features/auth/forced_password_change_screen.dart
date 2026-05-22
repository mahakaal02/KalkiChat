import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'login_controller.dart';

/// Shown after an admin-provisioned first-login. The backend returned
/// `must_change_password=true` on the login response; this screen MUST be
/// completed before /chat is reachable. We don't expose a "skip" — closing
/// the app and re-logging-in just returns here.
///
/// Routed at `/change-password`. The previous screen passes the just-typed
/// current password via `extra` so we can pre-fill the current-password
/// field instead of asking the user to retype it.
class ForcedPasswordChangeScreen extends ConsumerStatefulWidget {
  const ForcedPasswordChangeScreen({super.key, this.initialCurrentPassword});

  final String? initialCurrentPassword;

  @override
  ConsumerState<ForcedPasswordChangeScreen> createState() =>
      _ForcedPasswordChangeScreenState();
}

class _ForcedPasswordChangeScreenState
    extends ConsumerState<ForcedPasswordChangeScreen> {
  late final TextEditingController _currentCtrl;
  final TextEditingController _newCtrl = TextEditingController();
  final TextEditingController _confirmCtrl = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _currentCtrl =
        TextEditingController(text: widget.initialCurrentPassword ?? '');
  }

  @override
  void dispose() {
    _currentCtrl.dispose();
    _newCtrl.dispose();
    _confirmCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;
    final String current = _currentCtrl.text;
    final String next = _newCtrl.text;
    final String confirm = _confirmCtrl.text;
    if (current.isEmpty) {
      setState(() => _error = 'Enter your current (temporary) password.');
      return;
    }
    if (next.length < 10) {
      setState(() => _error = 'New password must be at least 10 characters.');
      return;
    }
    if (next == current) {
      setState(() => _error = 'New password must differ from the current one.');
      return;
    }
    if (next != confirm) {
      setState(() => _error = 'New password and confirmation do not match.');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(loginControllerProvider.notifier).changePassword(
            currentPassword: current,
            newPassword: next,
          );
      if (!mounted) return;
      context.go('/chat');
    } catch (e) {
      // The controller throws Exception("<CODE>"). Render just the code.
      setState(() => _error = e.toString().replaceFirst('Exception: ', ''));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      // No back button — this is a gate, not an optional screen.
      appBar: AppBar(
        title: const Text('Set a new password'),
        automaticallyImplyLeading: false,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              const SizedBox(height: 24),
              const Text(
                'Your account was created by an admin. Please choose your own '
                'password before continuing.',
                style: TextStyle(color: Colors.white70),
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _currentCtrl,
                obscureText: true,
                enableInteractiveSelection: false,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.next,
                decoration:
                    const InputDecoration(labelText: 'Current (temporary) password'),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _newCtrl,
                obscureText: true,
                enableInteractiveSelection: false,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.next,
                decoration: const InputDecoration(
                  labelText: 'New password (min 10 chars)',
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _confirmCtrl,
                obscureText: true,
                enableInteractiveSelection: false,
                autocorrect: false,
                enableSuggestions: false,
                textInputAction: TextInputAction.done,
                onSubmitted: (_) => _submit(),
                decoration: const InputDecoration(labelText: 'Confirm new password'),
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
                    : const Text('Set password and continue'),
              ),
              const Spacer(),
              const Padding(
                padding: EdgeInsets.only(bottom: 12),
                child: Text(
                  'Choose a password only you know. KalkiChat staff will '
                  'never ask for it.',
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
