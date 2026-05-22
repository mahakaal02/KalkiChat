import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:screen_protector/screen_protector.dart';

import 'app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // FLAG_SECURE on Android (blocks screenshots + screen-recording surfaces);
  // background-blur on iOS. Same protection mobile/lib/main.dart uses.
  await ScreenProtector.preventScreenshotOn();
  await ScreenProtector.protectDataLeakageWithBlur();
  await SystemChrome.setPreferredOrientations(<DeviceOrientation>[
    DeviceOrientation.portraitUp,
  ]);
  runApp(const ProviderScope(child: KalkiAdminApp()));
}
