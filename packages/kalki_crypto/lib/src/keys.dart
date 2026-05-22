import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'storage.dart';

/// Holds the device's long-term identity material.
///
/// Private halves live in [KeyStorage] — typically a hardware-backed
/// secure-storage area like Android Keystore or iOS Keychain via
/// `flutter_secure_storage`. The public halves are cached in memory for
/// fast use; private halves are fetched on demand when signing or doing
/// key exchange and not kept in process memory beyond a single call.
///
/// **Construction**: call [initOrLoad] with the same [KeyStorage]
/// instance throughout the app's lifetime. The factory:
///
///   * returns the cached instance on second-and-later calls;
///   * reuses persisted keys if they already exist in the store;
///   * otherwise generates a fresh Ed25519 + X25519 keypair and persists
///     both before returning.
class IdentityKeys {
  IdentityKeys._(
    this._storage,
    this.deviceEd25519Public,
    this.deviceX25519Public,
  );

  final KeyStorage _storage;
  final SimplePublicKey deviceEd25519Public;
  final SimplePublicKey deviceX25519Public;

  static const String _kEdPriv = 'ed25519_priv';
  static const String _kEdPub = 'ed25519_pub';
  static const String _kXPriv = 'x25519_priv';
  static const String _kXPub = 'x25519_pub';

  // Module-level cache so callers don't have to thread a singleton.
  // Keyed by storage identity so two storages (e.g. test vs prod) don't
  // collide.
  static final Map<KeyStorage, IdentityKeys> _cache =
      <KeyStorage, IdentityKeys>{};

  /// Initialise on first launch. Idempotent for a given [storage].
  static Future<IdentityKeys> initOrLoad(KeyStorage storage) async {
    final IdentityKeys? hit = _cache[storage];
    if (hit != null) return hit;

    final List<int>? edPubBytes = await storage.readBytes(_kEdPub);
    final List<int>? xPubBytes = await storage.readBytes(_kXPub);

    if (edPubBytes != null && xPubBytes != null) {
      final IdentityKeys k = IdentityKeys._(
        storage,
        SimplePublicKey(edPubBytes, type: KeyPairType.ed25519),
        SimplePublicKey(xPubBytes, type: KeyPairType.x25519),
      );
      _cache[storage] = k;
      return k;
    }

    final Ed25519 ed = Ed25519();
    final X25519 x = X25519();

    final SimpleKeyPair edKp = await ed.newKeyPair();
    final SimpleKeyPair xKp = await x.newKeyPair();

    final SimpleKeyPairData edData = await edKp.extract();
    final SimpleKeyPairData xData = await xKp.extract();
    final SimplePublicKey edPub = await edKp.extractPublicKey();
    final SimplePublicKey xPub = await xKp.extractPublicKey();

    await storage.writeBytes(_kEdPriv, edData.bytes);
    await storage.writeBytes(_kEdPub, edPub.bytes);
    await storage.writeBytes(_kXPriv, xData.bytes);
    await storage.writeBytes(_kXPub, xPub.bytes);

    final IdentityKeys k = IdentityKeys._(storage, edPub, xPub);
    _cache[storage] = k;
    return k;
  }

  /// Sign `message` with the device Ed25519 private key.
  Future<List<int>> sign(List<int> message) async {
    final List<int>? priv = await _storage.readBytes(_kEdPriv);
    if (priv == null) throw StateError('Ed25519 private key missing');
    final SimpleKeyPairData kp = SimpleKeyPairData(
      priv,
      publicKey: deviceEd25519Public,
      type: KeyPairType.ed25519,
    );
    final Signature sig = await Ed25519().sign(message, keyPair: kp);
    return sig.bytes;
  }

  /// Compute X25519 shared secret with `peerPub`.
  Future<List<int>> dh(SimplePublicKey peerPub) async {
    final List<int>? priv = await _storage.readBytes(_kXPriv);
    if (priv == null) throw StateError('X25519 private key missing');
    final SimpleKeyPairData kp = SimpleKeyPairData(
      priv,
      publicKey: deviceX25519Public,
      type: KeyPairType.x25519,
    );
    final SecretKey s = await X25519().sharedSecretKey(
      keyPair: kp,
      remotePublicKey: peerPub,
    );
    return s.extractBytes();
  }

  Uint8List get edPubBytes => Uint8List.fromList(deviceEd25519Public.bytes);
  Uint8List get xPubBytes => Uint8List.fromList(deviceX25519Public.bytes);
}
