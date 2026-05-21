import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Wraps `flutter_secure_storage`, which backs onto:
///
///   * Android — `EncryptedSharedPreferences` keyed in the Android Keystore
///     (StrongBox if available).
///   * iOS    — Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
///
/// The wrapped key set never leaves hardware-isolated storage.
class HardwareKeystore {
  HardwareKeystore._();
  static final HardwareKeystore I = HardwareKeystore._();

  static const FlutterSecureStorage _ss = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      synchronizable: false,
    ),
  );

  /// Read raw bytes; returns null if absent.
  Future<List<int>?> readBytes(String key) async {
    final String? v = await _ss.read(key: key);
    if (v == null) return null;
    return base64Decode(v);
  }

  Future<void> writeBytes(String key, List<int> value) async {
    await _ss.write(key: key, value: base64Encode(value));
  }

  Future<String?> readString(String key) => _ss.read(key: key);
  Future<void> writeString(String key, String value) =>
      _ss.write(key: key, value: value);

  Future<void> delete(String key) => _ss.delete(key: key);

  Future<void> wipe() => _ss.deleteAll();
}
