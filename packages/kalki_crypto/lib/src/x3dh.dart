import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Signal X3DH (Extended Triple Diffie-Hellman) key agreement.
///
/// X3DH lets a sender (Alice) start a secure session with a recipient (Bob)
/// who is offline: Bob has uploaded a long-lived identity key plus a signed
/// prekey and (optionally) a batch of one-time prekeys; Alice fetches those,
/// mixes in her own keypair plus a per-session ephemeral, and derives a
/// shared secret SK that Bob can re-derive when he later sees Alice's
/// bootstrap envelope.
///
/// The KDF is HKDF-SHA256 with:
///   * salt   = 32 zero bytes
///   * info   = "KalkiChat-X3DH-v1" (versioned so future protocol revs can
///              be domain-separated cleanly)
///   * IKM    = DH1 || DH2 || DH3 [|| DH4]
///
/// Where:
///   * DH1 = X25519(IK_A_priv, SPK_B_pub)   – binds Alice's identity to Bob's signed prekey
///   * DH2 = X25519(EK_A_priv, IK_B_pub)    – binds Alice's ephemeral to Bob's identity
///   * DH3 = X25519(EK_A_priv, SPK_B_pub)   – binds both ephemera together
///   * DH4 = X25519(EK_A_priv, OPK_B_pub)   – one-time-prekey contribution (if present)
///
/// Including DH4 when OPK is available provides forward secrecy against
/// compromise of Bob's long-term signed-prekey private. The OPK MUST be
/// deleted by Bob after exactly one use.
///
/// **Security note for reviewers:** this implementation has not been
/// independently reviewed by a cryptographer. It follows the Signal X3DH
/// spec (rev 1, 2016) by construction but should be exercised against
/// published test vectors before any deployment to users facing serious
/// adversaries.

/// HKDF info string — bytes of "KalkiChat-X3DH-v1".
const List<int> _hkdfInfo = <int>[
  0x4B, 0x61, 0x6C, 0x6B, 0x69, 0x43, 0x68, 0x61, 0x74,
  0x2D, 0x58, 0x33, 0x44, 0x48, 0x2D, 0x76, 0x31,
];

/// Result of an X3DH initiator run.
class X3DHInitiateResult {
  X3DHInitiateResult({
    required this.sharedSecret,
    required this.ephemeralX25519Pub,
    required this.ephemeralX25519Priv,
  });

  /// 32-byte shared secret. Feed into [DoubleRatchet.initiator] as rootKey.
  final Uint8List sharedSecret;

  /// The ephemeral public key the initiator generated. Must be transmitted
  /// in the bootstrap envelope so the responder can re-derive the secret.
  final Uint8List ephemeralX25519Pub;

  /// The ephemeral private key. Kept locally for the duration of the
  /// initiate call only; the [DoubleRatchet] doesn't need it after this
  /// point, so callers should not persist it.
  final Uint8List ephemeralX25519Priv;
}

/// X3DH initiator side. Call when starting a new session with a peer whose
/// prekey bundle you've just fetched.
///
/// `ourIdentityX25519Priv` is the initiator's long-term X25519 identity
/// private key (32 bytes). The corresponding public key is implied; this
/// function never needs it.
///
/// All `peer...` arguments come from the prekey bundle returned by
/// `GET /v1/prekeys/{device_id}`. The caller MUST have verified
/// `peerSignedPrekeySignature` against `peerIdentityEd25519` before
/// calling — see [verifySignedPrekey].
///
/// `peerOneTimePrekeyPub` is optional. Pass null only if the bundle did not
/// include one (the server's prekey pool was exhausted for that device).
/// Passing null reduces forward secrecy, so callers should ensure their
/// prekey-replenishment loop keeps the pool primed.
Future<X3DHInitiateResult> x3dhInitiate({
  required Uint8List ourIdentityX25519Priv,
  required Uint8List ourIdentityX25519Pub,
  required Uint8List peerIdentityX25519Pub,
  required Uint8List peerSignedPrekeyPub,
  Uint8List? peerOneTimePrekeyPub,
}) async {
  if (ourIdentityX25519Priv.length != 32 ||
      ourIdentityX25519Pub.length != 32 ||
      peerIdentityX25519Pub.length != 32 ||
      peerSignedPrekeyPub.length != 32) {
    throw ArgumentError('all X25519 key halves must be 32 bytes');
  }
  if (peerOneTimePrekeyPub != null && peerOneTimePrekeyPub.length != 32) {
    throw ArgumentError('peerOneTimePrekeyPub must be 32 bytes when present');
  }

  final X25519 x = X25519();

  // Generate per-session ephemeral.
  final SimpleKeyPair ephKp = await x.newKeyPair();
  final SimpleKeyPairData ephData = await ephKp.extract();
  final SimplePublicKey ephPub = await ephKp.extractPublicKey();

  final SimpleKeyPairData ourId = SimpleKeyPairData(
    ourIdentityX25519Priv,
    publicKey:
        SimplePublicKey(ourIdentityX25519Pub, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );

  final SimplePublicKey peerIdK =
      SimplePublicKey(peerIdentityX25519Pub, type: KeyPairType.x25519);
  final SimplePublicKey peerSpk =
      SimplePublicKey(peerSignedPrekeyPub, type: KeyPairType.x25519);

  // DH1 = X25519(IK_A_priv, SPK_B_pub)
  final SecretKey dh1 =
      await x.sharedSecretKey(keyPair: ourId, remotePublicKey: peerSpk);
  // DH2 = X25519(EK_A_priv, IK_B_pub)
  final SecretKey dh2 =
      await x.sharedSecretKey(keyPair: ephKp, remotePublicKey: peerIdK);
  // DH3 = X25519(EK_A_priv, SPK_B_pub)
  final SecretKey dh3 =
      await x.sharedSecretKey(keyPair: ephKp, remotePublicKey: peerSpk);

  final List<int> dh1B = await dh1.extractBytes();
  final List<int> dh2B = await dh2.extractBytes();
  final List<int> dh3B = await dh3.extractBytes();

  List<int> ikm = <int>[...dh1B, ...dh2B, ...dh3B];

  if (peerOneTimePrekeyPub != null) {
    final SimplePublicKey peerOpk =
        SimplePublicKey(peerOneTimePrekeyPub, type: KeyPairType.x25519);
    // DH4 = X25519(EK_A_priv, OPK_B_pub)
    final SecretKey dh4 =
        await x.sharedSecretKey(keyPair: ephKp, remotePublicKey: peerOpk);
    final List<int> dh4B = await dh4.extractBytes();
    ikm = <int>[...ikm, ...dh4B];
  }

  final Uint8List sk = await _hkdf32(ikm);

  return X3DHInitiateResult(
    sharedSecret: sk,
    ephemeralX25519Pub: Uint8List.fromList(ephPub.bytes),
    ephemeralX25519Priv: Uint8List.fromList(ephData.bytes),
  );
}

/// X3DH responder side. Call when a bootstrap envelope arrives.
///
/// `ourSignedPrekeyPriv` is the local 32-byte private key for the SPK the
/// initiator referenced in their bootstrap header (`bootstrap.signedPrekeyId`).
///
/// `ourOneTimePrekeyPriv` is the local private key for the OPK the initiator
/// consumed (`bootstrap.oneTimePrekeyId`). Pass null only when the initiator
/// reported `oneTimePrekeyId == 0`, meaning they couldn't get an OPK from
/// the pool. After this call returns, the caller MUST delete the OPK from
/// local storage so it is never reused.
Future<Uint8List> x3dhResponder({
  required Uint8List ourIdentityX25519Priv,
  required Uint8List ourIdentityX25519Pub,
  required Uint8List ourSignedPrekeyPriv,
  required Uint8List ourSignedPrekeyPub,
  required Uint8List peerIdentityX25519Pub,
  required Uint8List peerEphemeralX25519Pub,
  Uint8List? ourOneTimePrekeyPriv,
  Uint8List? ourOneTimePrekeyPub,
}) async {
  if (ourIdentityX25519Priv.length != 32 ||
      ourIdentityX25519Pub.length != 32 ||
      ourSignedPrekeyPriv.length != 32 ||
      ourSignedPrekeyPub.length != 32 ||
      peerIdentityX25519Pub.length != 32 ||
      peerEphemeralX25519Pub.length != 32) {
    throw ArgumentError('all X25519 key halves must be 32 bytes');
  }
  if ((ourOneTimePrekeyPriv == null) != (ourOneTimePrekeyPub == null)) {
    throw ArgumentError(
        'ourOneTimePrekey priv/pub must both be present or both absent');
  }

  final X25519 x = X25519();

  final SimpleKeyPairData ourId = SimpleKeyPairData(
    ourIdentityX25519Priv,
    publicKey:
        SimplePublicKey(ourIdentityX25519Pub, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );
  final SimpleKeyPairData ourSpk = SimpleKeyPairData(
    ourSignedPrekeyPriv,
    publicKey: SimplePublicKey(ourSignedPrekeyPub, type: KeyPairType.x25519),
    type: KeyPairType.x25519,
  );

  final SimplePublicKey peerIdK =
      SimplePublicKey(peerIdentityX25519Pub, type: KeyPairType.x25519);
  final SimplePublicKey peerEph =
      SimplePublicKey(peerEphemeralX25519Pub, type: KeyPairType.x25519);

  // DH1 = X25519(SPK_B_priv, IK_A_pub) == X25519(IK_A_priv, SPK_B_pub)
  final SecretKey dh1 =
      await x.sharedSecretKey(keyPair: ourSpk, remotePublicKey: peerIdK);
  // DH2 = X25519(IK_B_priv, EK_A_pub) == X25519(EK_A_priv, IK_B_pub)
  final SecretKey dh2 =
      await x.sharedSecretKey(keyPair: ourId, remotePublicKey: peerEph);
  // DH3 = X25519(SPK_B_priv, EK_A_pub) == X25519(EK_A_priv, SPK_B_pub)
  final SecretKey dh3 =
      await x.sharedSecretKey(keyPair: ourSpk, remotePublicKey: peerEph);

  final List<int> dh1B = await dh1.extractBytes();
  final List<int> dh2B = await dh2.extractBytes();
  final List<int> dh3B = await dh3.extractBytes();

  List<int> ikm = <int>[...dh1B, ...dh2B, ...dh3B];

  if (ourOneTimePrekeyPriv != null) {
    final SimpleKeyPairData ourOpk = SimpleKeyPairData(
      ourOneTimePrekeyPriv,
      publicKey:
          SimplePublicKey(ourOneTimePrekeyPub!, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    // DH4 = X25519(OPK_B_priv, EK_A_pub) == X25519(EK_A_priv, OPK_B_pub)
    final SecretKey dh4 =
        await x.sharedSecretKey(keyPair: ourOpk, remotePublicKey: peerEph);
    final List<int> dh4B = await dh4.extractBytes();
    ikm = <int>[...ikm, ...dh4B];
  }

  return _hkdf32(ikm);
}

/// Verify that a signed-prekey public was signed by the claimed identity's
/// Ed25519 key. Callers MUST run this before [x3dhInitiate] — otherwise an
/// attacker who can serve prekey bundles can substitute their own keys.
///
/// `signature` and `identityEd25519Pub` are 64 bytes and 32 bytes respectively.
Future<bool> verifySignedPrekey({
  required Uint8List signedPrekeyPub,
  required Uint8List signature,
  required Uint8List identityEd25519Pub,
}) async {
  return Ed25519().verify(
    signedPrekeyPub,
    signature: Signature(
      signature,
      publicKey:
          SimplePublicKey(identityEd25519Pub, type: KeyPairType.ed25519),
    ),
  );
}

Future<Uint8List> _hkdf32(List<int> ikm) async {
  final Hkdf kdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final SecretKey out = await kdf.deriveKey(
    secretKey: SecretKey(ikm),
    nonce: List<int>.filled(32, 0), // salt = 32 zero bytes
    info: _hkdfInfo,
  );
  return Uint8List.fromList(await out.extractBytes());
}
