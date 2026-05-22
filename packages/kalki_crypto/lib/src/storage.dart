/// Storage abstraction the crypto package uses to persist long-term key
/// material (Ed25519 + X25519 private keys, ratchet state) on the device.
///
/// The crypto package deliberately doesn't pick a backend — the user mobile
/// app and the admin companion-device app each inject their own
/// implementation (today both wrap `flutter_secure_storage` via the
/// `HardwareKeystore` class). Keeping the dependency injected means:
///
///   * the crypto package stays pure Dart and trivially unit-testable,
///   * different consumers can swap in different secure-storage backends
///     (hardware keystore on mobile, an encrypted file on a hypothetical
///     desktop client, an in-memory store in tests),
///   * we don't leak Flutter-only types like `FlutterSecureStorage` into
///     a package that's supposed to be the cryptographic source of truth.
abstract class KeyStorage {
  /// Returns the raw bytes previously written under [key], or null if
  /// nothing is stored for that key.
  Future<List<int>?> readBytes(String key);

  /// Persist [value] under [key]. Implementations MUST hard-fail rather
  /// than silently truncating if the backend can't accept the payload.
  Future<void> writeBytes(String key, List<int> value);
}
