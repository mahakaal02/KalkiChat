import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// On-the-wire ciphertext envelope.
///
/// Two layouts share the same prefix; the `type` byte selects between them:
///
/// **Type 0 — chat (steady-state):**
/// ```
///   ver(1) | type=0(1) | senderDev(16) | recipientDev(16)
///   ratchetPub(32) | prevChainLen(varint) | msgNumber(varint)
///   nonce(12) | ciphertext(N) | tag(16)
/// ```
///
/// **Type 1 — bootstrap (initiator's first message in a new session):**
/// ```
///   ver(1) | type=1(1) | senderDev(16) | recipientDev(16)
///   ratchetPub(32) | prevChainLen(varint=0) | msgNumber(varint=0)
///   identityEd25519(32) | identityX25519(32) | ephemeralX25519(32)
///   spkId(varint) | opkId(varint, 0 = none used)
///   nonce(12) | ciphertext(N) | tag(16)
/// ```
///
/// The `ratchetPub` in a bootstrap message is the sender's freshly-generated
/// initial-ratchet DH sending public key (NOT the X3DH ephemeral, which is
/// carried separately in the bootstrap header). The recipient feeds this into
/// `DoubleRatchet.ratchetReceive` after running X3DH to seed matching state.
///
/// The Ed25519 signature is computed over the **full envelope bytes** and
/// transmitted alongside; for bootstrap envelopes the signature is
/// transitively verified against the `identityEd25519` field declared in the
/// envelope itself (the signer proves possession of the identity private key
/// they're claiming).
class Envelope {
  Envelope({
    required this.senderDevId,
    required this.recipientDevId,
    required this.ratchetPub,
    required this.msgNumber,
    required this.nonce,
    required this.ciphertext,
    this.prevChainLen = 0,
    this.bootstrap,
  });

  final Uint8List senderDevId; // 16 bytes
  final Uint8List recipientDevId; // 16 bytes
  final Uint8List ratchetPub; // 32 bytes — sender's DH sending pubkey
  final Uint8List nonce; // 12 bytes
  final Uint8List ciphertext; // includes 16-byte GCM tag at end
  final int msgNumber;
  final int prevChainLen;

  /// Present only on the first message of a new session (X3DH bootstrap).
  /// Null for steady-state chat messages.
  final BootstrapHeader? bootstrap;

  bool get isBootstrap => bootstrap != null;

  Uint8List toBytes() {
    final BytesBuilder b = BytesBuilder();
    b.addByte(1); // version
    b.addByte(bootstrap == null ? 0 : 1); // type
    b.add(senderDevId);
    b.add(recipientDevId);
    b.add(ratchetPub);
    _writeVarint(b, prevChainLen);
    _writeVarint(b, msgNumber);
    if (bootstrap != null) {
      b.add(bootstrap!.identityEd25519);
      b.add(bootstrap!.identityX25519);
      b.add(bootstrap!.ephemeralX25519);
      _writeVarint(b, bootstrap!.signedPrekeyId);
      _writeVarint(b, bootstrap!.oneTimePrekeyId);
    }
    b.add(nonce);
    b.add(ciphertext);
    return b.toBytes();
  }

  static Envelope fromBytes(Uint8List raw) {
    int off = 0;
    if (raw[off++] != 1) throw const FormatException('bad version');
    final int type = raw[off++];
    if (type != 0 && type != 1) {
      throw FormatException('unknown envelope type: $type');
    }
    final Uint8List s = raw.sublist(off, off + 16);
    off += 16;
    final Uint8List r = raw.sublist(off, off + 16);
    off += 16;
    final Uint8List rp = raw.sublist(off, off + 32);
    off += 32;
    final (int prev, int o1) = _readVarint(raw, off);
    off = o1;
    final (int msg, int o2) = _readVarint(raw, off);
    off = o2;

    BootstrapHeader? boot;
    if (type == 1) {
      final Uint8List idEd = raw.sublist(off, off + 32);
      off += 32;
      final Uint8List idX = raw.sublist(off, off + 32);
      off += 32;
      final Uint8List eph = raw.sublist(off, off + 32);
      off += 32;
      final (int spkId, int o3) = _readVarint(raw, off);
      off = o3;
      final (int opkId, int o4) = _readVarint(raw, off);
      off = o4;
      boot = BootstrapHeader(
        identityEd25519: idEd,
        identityX25519: idX,
        ephemeralX25519: eph,
        signedPrekeyId: spkId,
        oneTimePrekeyId: opkId,
      );
    }

    final Uint8List n = raw.sublist(off, off + 12);
    off += 12;
    final Uint8List ct = raw.sublist(off);
    return Envelope(
      senderDevId: s,
      recipientDevId: r,
      ratchetPub: rp,
      msgNumber: msg,
      nonce: n,
      ciphertext: ct,
      prevChainLen: prev,
      bootstrap: boot,
    );
  }

  /// Encrypt a plaintext message with `messageKey` (32 bytes), then ask the
  /// caller to sign the resulting envelope bytes with whatever Ed25519
  /// signer they have on hand. Returning the signature alongside the
  /// envelope means the wire transport can carry both without `Envelope`
  /// having to know anything about the keystore.
  ///
  /// `sign` is invoked exactly once with the canonical envelope bytes;
  /// `IdentityKeys.sign` from this same package satisfies the signature.
  static Future<({Envelope envelope, List<int> signature})> seal({
    required Uint8List senderDevId,
    required Uint8List recipientDevId,
    required Uint8List ratchetPub,
    required int msgNumber,
    required int prevChainLen,
    required List<int> messageKey,
    required List<int> plaintext,
    required Future<List<int>> Function(List<int>) sign,
    BootstrapHeader? bootstrap,
  }) async {
    final AesGcm gcm = AesGcm.with256bits();
    final SecretKey k = SecretKey(messageKey);
    final List<int> nonce = gcm.newNonce();
    final SecretBox box = await gcm.encrypt(
      plaintext,
      secretKey: k,
      nonce: nonce,
      aad: _aad(senderDevId, recipientDevId, msgNumber),
    );
    final Envelope env = Envelope(
      senderDevId: senderDevId,
      recipientDevId: recipientDevId,
      ratchetPub: ratchetPub,
      msgNumber: msgNumber,
      nonce: Uint8List.fromList(nonce),
      ciphertext: Uint8List.fromList(<int>[...box.cipherText, ...box.mac.bytes]),
      prevChainLen: prevChainLen,
      bootstrap: bootstrap,
    );
    final List<int> sig = await sign(env.toBytes());
    return (envelope: env, signature: sig);
  }

  /// Decrypt — assumes signature already verified by the caller.
  static Future<List<int>> open({
    required Envelope envelope,
    required List<int> messageKey,
  }) async {
    final AesGcm gcm = AesGcm.with256bits();
    final SecretKey k = SecretKey(messageKey);
    final int ctLen = envelope.ciphertext.length - 16;
    final SecretBox box = SecretBox(
      envelope.ciphertext.sublist(0, ctLen),
      nonce: envelope.nonce,
      mac: Mac(envelope.ciphertext.sublist(ctLen)),
    );
    return gcm.decrypt(
      box,
      secretKey: k,
      aad: _aad(envelope.senderDevId, envelope.recipientDevId, envelope.msgNumber),
    );
  }

  /// Verify the Ed25519 signature on an envelope's bytes against the supplied
  /// public key. Returns true if valid. Use this for steady-state envelopes;
  /// for bootstrap envelopes, the public key is the `identityEd25519` field
  /// inside the envelope itself (we don't trust it yet — we trust the X3DH
  /// shared secret, which is bound to it).
  static Future<bool> verify({
    required Envelope envelope,
    required List<int> signature,
    required Uint8List signerIdentityEd25519Pub,
  }) async {
    return Ed25519().verify(
      envelope.toBytes(),
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(
          signerIdentityEd25519Pub,
          type: KeyPairType.ed25519,
        ),
      ),
    );
  }

  static List<int> _aad(Uint8List s, Uint8List r, int n) {
    final BytesBuilder b = BytesBuilder()
      ..add(s)
      ..add(r);
    _writeVarint(b, n);
    return b.toBytes();
  }

  static void _writeVarint(BytesBuilder b, int v) {
    while (v >= 0x80) {
      b.addByte((v & 0x7F) | 0x80);
      v >>= 7;
    }
    b.addByte(v & 0x7F);
  }

  static (int value, int newOffset) _readVarint(Uint8List buf, int off) {
    int shift = 0;
    int result = 0;
    while (true) {
      final int byte = buf[off++];
      result |= (byte & 0x7F) << shift;
      if ((byte & 0x80) == 0) return (result, off);
      shift += 7;
    }
  }

  String toBase64() => base64.encode(toBytes());
  static Envelope fromBase64(String s) => fromBytes(base64.decode(s));
}

/// Extra fields present on the **first** message of a new session
/// (X3DH bootstrap). The recipient uses these to re-derive the same shared
/// secret the sender produced, then bootstraps a matching Double Ratchet.
class BootstrapHeader {
  const BootstrapHeader({
    required this.identityEd25519,
    required this.identityX25519,
    required this.ephemeralX25519,
    required this.signedPrekeyId,
    required this.oneTimePrekeyId,
  });

  /// Sender's long-term Ed25519 public key. Used to verify the envelope
  /// signature. Bound into the X3DH shared secret so a forger would have to
  /// also collide the resulting symmetric key.
  final Uint8List identityEd25519;

  /// Sender's long-term X25519 public key. Used in X3DH DH1.
  final Uint8List identityX25519;

  /// Sender's per-session ephemeral X25519 public key. Used in DH2/3/4.
  final Uint8List ephemeralX25519;

  /// Which signed prekey of the recipient's was consumed. Recipient looks
  /// up the matching private key.
  final int signedPrekeyId;

  /// Which one-time prekey of the recipient's was consumed; 0 = none used.
  /// One-time prekeys MUST be deleted after exactly one consumption to
  /// preserve forward secrecy.
  final int oneTimePrekeyId;
}
