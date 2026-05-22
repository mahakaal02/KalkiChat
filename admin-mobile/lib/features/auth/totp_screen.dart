import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:kalki_crypto/kalki_crypto.dart';

import '../../core/api.dart';
import '../../core/security/keystore.dart';
import 'auth_state.dart';

/// Final step of admin companion-device sign-in.
///
/// The user has already entered email + password on the login screen.
/// We pick those up from [pendingAdminAuthProvider], collect the
/// 6-digit TOTP code, generate Ed25519 + X25519 identity keys (lazily,
/// via [IdentityKeys.initOrLoad] backed by [AdminHardwareKeystore]), and
/// hit POST /v1/admin/devices/register with everything at once.
///
/// On success: the response carries `access_token` + `refresh_token` +
/// `device_id` + `admin_id`. All four are written to the hardware
/// keystore so the rest of the app can use them transparently
/// (the API client attaches the Bearer token automatically; the WS
/// client will read it on connect).
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
    final PendingAdminAuth? pending = ref.watch(pendingAdminAuthProvider);
    if (pending == null) {
      // Defensive: somebody landed on /totp without going through /login
      // first. Bounce them back to start the flow.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) context.go('/login');
      });
      return const Scaffold(body: SizedBox.shrink());
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Two-factor')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('Signing in as ${pending.email}',
                style: const TextStyle(color: Colors.white54)),
            const SizedBox(height: 16),
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
            FilledButton(
              onPressed: _busy ? null : () => _register(pending),
              child: Text(_busy ? '…' : 'Verify and register device'),
            ),
            const SizedBox(height: 16),
            const Text(
              'This device will be registered as a cryptographic '
              'participant in support conversations. Messages are '
              'decrypted locally on this device, never on the server.',
              style: TextStyle(color: Colors.white54, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _register(PendingAdminAuth pending) async {
    if (_code.text.length != 6) {
      setState(() => _err = 'Enter the 6-digit code.');
      return;
    }
    setState(() {
      _busy = true;
      _err = null;
    });
    try {
      // 1. Generate (or load existing) Ed25519 + X25519 identity keys.
      //    On first launch this generates fresh keys and stashes them in
      //    the hardware keystore; on re-sign-in it reuses the same pair
      //    so the device's identity is stable.
      final IdentityKeys keys =
          await IdentityKeys.initOrLoad(AdminHardwareKeystore.I);

      // 2. POST /v1/admin/devices/register with everything in one shot.
      final api = ref.read(adminApiProvider);
      final r = await api.post('/v1/admin/devices/register', <String, dynamic>{
        'email': pending.email,
        'password': pending.password,
        'totp_code': _code.text,
        'device': <String, dynamic>{
          'name': _deviceName(),
          'platform': _platform(),
          'identity_ed25519': base64Encode(keys.edPubBytes),
          'identity_x25519': base64Encode(keys.xPubBytes),
        },
      });
      if (r.statusCode != 200) {
        setState(() => _err = _errorFrom(r));
        return;
      }
      final Map<String, dynamic> body =
          (r.data as Map).cast<String, dynamic>();

      // 3. Persist the Bearer credentials. The API client picks these up
      //    on every subsequent request automatically.
      await AdminHardwareKeystore.I
          .writeString('access_token', body['access_token'] as String);
      await AdminHardwareKeystore.I
          .writeString('refresh_token', body['refresh_token'] as String);
      await AdminHardwareKeystore.I
          .writeString('device_id', body['device_id'] as String);
      await AdminHardwareKeystore.I
          .writeString('admin_id', body['admin_id'] as String);

      // 4. Clear the in-memory pending creds so they don't linger.
      ref.read(pendingAdminAuthProvider.notifier).state = null;

      if (!mounted) return;
      context.go('/users');
    } catch (e) {
      setState(() => _err = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _platform() {
    if (kIsWeb) return 'web';
    try {
      if (Platform.isAndroid) return 'android';
      if (Platform.isIOS) return 'ios';
    } catch (_) {/* dart:io not available, fall through */}
    return 'android';
  }

  String _deviceName() {
    if (kIsWeb) return 'KalkiChat Admin (web)';
    return 'KalkiChat Admin (${_platform()})';
  }

  String _errorFrom(dynamic resp) {
    try {
      final Map<String, dynamic> data =
          ((resp.data as Map?)?.cast<String, dynamic>()) ?? <String, dynamic>{};
      final Object? err = data['error'];
      if (err is Map) {
        final String code = (err['code'] as String?) ?? 'ERR';
        switch (code) {
          case 'BAD_CREDENTIALS':
            return 'Email or password is incorrect. Try signing in again.';
          case 'BAD_TOTP':
            return 'Code did not match. Wait for the next 30-second window.';
          case 'MISSING_FIELDS':
            return 'Server rejected the request — missing fields.';
          default:
            return 'Sign-in failed: $code';
        }
      }
    } catch (_) {/* fall through */}
    return 'Sign-in failed (HTTP ${resp.statusCode}).';
  }
}
