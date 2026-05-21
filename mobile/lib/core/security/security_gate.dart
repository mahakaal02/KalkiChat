import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';
import 'package:flutter_windowmanager/flutter_windowmanager.dart';
import 'package:screen_protector/screen_protector.dart';

/// Single source of truth for runtime security policy:
///
/// 1. FLAG_SECURE on Android — blocks screenshots, screen recording,
///    and removes the chat from the recents preview.
/// 2. iOS background-blur + capture detection.
/// 3. Root / jailbreak detection: any positive signal sends the user to a
///    "blocked" screen and refuses to read or display messages.
///
/// This is *defence in depth*. The server still enforces everything.
class SecurityGate {
  static bool _initialised = false;
  static bool _compromised = false;

  static bool get isCompromised => _compromised;

  /// Call once during `main()` — before any UI is shown.
  static Future<void> applyGlobalProtections() async {
    if (_initialised) return;
    _initialised = true;

    if (Platform.isAndroid) {
      // Block screenshots / screen recording / recents preview.
      await FlutterWindowManager.addFlags(FlutterWindowManager.FLAG_SECURE);
    }
    if (Platform.isIOS) {
      // Show a blank screen when backgrounded (prevents recents-preview leak).
      await ScreenProtector.protectDataLeakageWithBlur();
      // Notify app if screen recording is started, so we can blank chat.
      await ScreenProtector.preventScreenshotOn();
    }

    await recheck();
  }

  /// Re-run jailbreak/root checks. Called on app resume.
  static Future<void> recheck() async {
    if (kDebugMode) return; // Debug builds run on emulators / test devices.

    try {
      final bool isJB = await FlutterJailbreakDetection.jailbroken;
      final bool isDev = await FlutterJailbreakDetection.developerMode;
      _compromised = isJB || (Platform.isAndroid && isDev);
    } on PlatformException {
      // If the detection plugin itself fails, be safe and lock down.
      _compromised = true;
    }
  }
}
