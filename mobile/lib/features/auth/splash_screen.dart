import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/security/keystore.dart';
import '../../core/security/security_gate.dart';

class SplashScreen extends ConsumerStatefulWidget {
  const SplashScreen({super.key});

  @override
  ConsumerState<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends ConsumerState<SplashScreen> {
  @override
  void initState() {
    super.initState();
    unawaited(_route());
  }

  Future<void> _route() async {
    // Brief splash for UX continuity.
    await Future<void>.delayed(const Duration(milliseconds: 600));
    if (!mounted) return;
    if (SecurityGate.isCompromised) {
      context.go('/blocked');
      return;
    }
    final String? token = await HardwareKeystore.I.readString('access_token');
    if (!mounted) return;
    context.go(token == null ? '/login' : '/chat');
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Icon(Icons.lock_outline, size: 64, color: Color(0xFF7AE2CF)),
            SizedBox(height: 16),
            Text(
              'KalkiChat',
              style: TextStyle(
                fontSize: 28,
                fontWeight: FontWeight.w700,
                letterSpacing: 1.5,
              ),
            ),
            SizedBox(height: 8),
            Text('secure messaging',
                style: TextStyle(color: Colors.white54, fontSize: 12, letterSpacing: 2)),
          ],
        ),
      ),
    );
  }
}

void unawaited(Future<void> _) {}
