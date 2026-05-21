import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../security/keystore.dart';

/// Holds the device's long-term identity material. Keys live in the
/// hardware-backed keystore via [HardwareKeystore]; we cache the *public*
/// halves in memory for fast use, and only fetch the private halves when
/// signing or doing key exchange.
class IdentityKeys {
  IdentityKeys._(this.deviceEd25519Public, this.deviceX25519Public);

  final SimplePublicKey deviceEd25519Public;
  final SimplePublicKey deviceX25519Public;

  static const String _kEdPriv = 'ed25519_priv';
  static const String _kEdPub = 'ed25519_pub';
  static const String _kXPriv = 'x25519_priv';
  static const String _kXPub = 'x25519_pub';

  static IdentityKeys? _cached;

  /// Initialise on first launch. Idempotent.
  static Future<IdentityKeys> initOrLoad() async {
    if (_cached != null) return _cached!;

    final HardwareKeystore ks = HardwareKeystore.I;
    final List<int>? edPubBytes = await ks.readBytes(_kEdPub);
    final List<int>? xPubBytes = await ks.readBytes(_kXPub);

    if (edPubBytes != null && xPubBytes != null) {
      _cached = IdentityKeys._(
        SimplePublicKey(edPubBytes, type: KeyPairType.ed25519),
        SimplePublicKey(xPubBytes, type: KeyPairType.x25519),
      );
      return _cached!;
    }

    final Ed25519 ed = Ed25519();
    final X25519 x = X25519();

    final SimpleKeyPair edKp = await ed.newKeyPair();
    final SimpleKeyPair xKp = await x.newKeyPair();

    final SimpleKeyPairData edData = await edKp.extract();
    final SimpleKeyPairData xData = await xKp.extract();
    final SimplePublicKey edPub = await edKp.extractPublicKey();
    final SimplePublicKey xPub = await xKp.extractPublicKey();

    await ks.writeBytes(_kEdPriv, edData.bytes);
    await ks.writeBytes(_kEdPub, edPub.bytes);
    await ks.writeBytes(_kXPriv, xData.bytes);
    await ks.writeBytes(_kXPub, xPub.bytes);

    _cached = IdentityKeys._(edPub, xPub);
    return _cached!;
  }

  /// Sign `message` with the device Ed25519 private key.
  Future<List<int>> sign(List<int> message) async {
    final List<int>? priv = await HardwareKeystore.I.readBytes(_kEdPriv);
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
    final List<int>? priv = await HardwareKeystore.I.readBytes(_kXPriv);
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
    return await s.extractBytes();
  }

  Uint8List get edPubBytes => Uint8List.fromList(deviceEd25519Public.bytes);
  Uint8List get xPubBytes => Uint8List.fromList(deviceX25519Public.bytes);
}
