import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:kalki_crypto/kalki_crypto.dart';

/// Hardware-backed secret storage for the admin companion device.
///
/// Backs onto:
///   * Android — `EncryptedSharedPreferences` keyed in the Android Keystore
///     (StrongBox where available).
///   * iOS    — Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
///
/// Mirrors `mobile/lib/core/security/keystore.dart` and `implements`
/// `KeyStorage` from the shared `kalki_crypto` package, so the X3DH +
/// DoubleRatchet stack can persist identity keys here without taking a
/// hard dep on `flutter_secure_storage`.
///
/// Keys stored under this keystore:
///   * `ed25519_priv` / `ed25519_pub` / `x25519_priv` / `x25519_pub`
///     — the admin device's long-term identity (managed by IdentityKeys).
///   * `access_token` / `refresh_token` / `device_id` / `admin_id`
///     — the Bearer credentials returned by /v1/admin/devices/register.
///   * `sqlcipher_pass` — the 256-bit passphrase that unlocks the local DB.
///   * `peer_ed25519_{deviceId}` — per-peer identity pubkeys cached at
///     bootstrap time so we can verify subsequent steady-state envelopes.
class AdminHardwareKeystore implements KeyStorage {
  AdminHardwareKeystore._();
  static final AdminHardwareKeystore I = AdminHardwareKeystore._();

  static const FlutterSecureStorage _ss = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
      synchronizable: false,
    ),
  );

  @override
  Future<List<int>?> readBytes(String key) async {
    final String? v = await _ss.read(key: key);
    if (v == null) return null;
    return base64Decode(v);
  }

  @override
  Future<void> writeBytes(String key, List<int> value) async {
    await _ss.write(key: key, value: base64Encode(value));
  }

  Future<String?> readString(String key) => _ss.read(key: key);
  Future<void> writeString(String key, String value) =>
      _ss.write(key: key, value: value);

  Future<void> delete(String key) => _ss.delete(key: key);
  Future<void> wipe() => _ss.deleteAll();
}
