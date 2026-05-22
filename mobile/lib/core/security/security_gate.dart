import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:safe_device/safe_device.dart';
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
      // Sets FLAG_SECURE on the host activity: blocks screenshots, screen
      // recording, and removes the app from the recents preview.
      await ScreenProtector.protectDataLeakageOn();
      await ScreenProtector.preventScreenshotOn();
    }
    if (Platform.isIOS) {
      // Show a blur view when backgrounded (prevents recents-preview leak)
      // and prevent capture / detect screen recording.
      await ScreenProtector.protectDataLeakageWithBlur();
      await ScreenProtector.preventScreenshotOn();
    }

    await recheck();
  }

  /// Re-run jailbreak/root checks. Called on app resume.
  static Future<void> recheck() async {
    if (kDebugMode) return; // Debug builds run on emulators / test devices.

    try {
      final bool isJB = await SafeDevice.isJailBroken;
      final bool isDev =
          Platform.isAndroid ? await SafeDevice.isDevelopmentModeEnable : false;
      _compromised = isJB || isDev;
    } on PlatformException {
      // If the detection plugin itself fails, be safe and lock down.
      _compromised = true;
    }
  }
}
