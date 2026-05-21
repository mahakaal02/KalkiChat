import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app/app.dart';
import 'core/security/security_gate.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // FLAG_SECURE on Android; iOS handled per-screen.
  await SecurityGate.applyGlobalProtections();

  // Lock orientation portrait for chat screens — predictable UX + a11y.
  await SystemChrome.setPreferredOrientations(<DeviceOrientation>[
    DeviceOrientation.portraitUp,
  ]);

  runApp(const ProviderScope(child: KalkiApp()));
}
