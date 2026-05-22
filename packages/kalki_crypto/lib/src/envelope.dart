import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'keys.dart';

/// On-the-wire ciphertext envelope.
///
/// Layout (binary):
///
///   ver(1) | type(1) | senderDev(16) | recipientDev(16)
///   ratchetPub(32) | prevChainLen(varint) | msgNumber(varint)
///   nonce(12) | ciphertext(N) | tag(16)
///
/// The Ed25519 signature is computed over the full envelope and sent
/// alongside it.
class Envelope {
  Envelope({
    required this.senderDevId,
    required this.recipientDevId,
    required this.ratchetPub,
    required this.msgNumber,
    required this.nonce,
    required this.ciphertext,
    this.prevChainLen = 0,
  });

  final Uint8List senderDevId; // 16-byte ULID-as-bytes (or short hash)
  final Uint8List recipientDevId;
  final Uint8List ratchetPub; // 32
  final Uint8List nonce; // 12
  final Uint8List ciphertext; // includes 16-byte GCM tag at end
  final int msgNumber;
  final int prevChainLen;

  Uint8List toBytes() {
    final BytesBuilder b = BytesBuilder();
    b.addByte(1); // version
    b.addByte(0); // message type (chat)
    b.add(senderDevId);
    b.add(recipientDevId);
    b.add(ratchetPub);
    _writeVarint(b, prevChainLen);
    _writeVarint(b, msgNumber);
    b.add(nonce);
    b.add(ciphertext);
    return b.toBytes();
  }

  static Envelope fromBytes(Uint8List raw) {
    int off = 0;
    if (raw[off++] != 1) throw const FormatException('bad version');
    final int type = raw[off++];
    if (type != 0) throw const FormatException('unknown type');
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
    );
  }

  /// Encrypt a plaintext message with `messageKey` (32 bytes).
  /// Returns the envelope and an Ed25519 signature over its bytes.
  static Future<({Envelope envelope, List<int> signature})> seal({
    required IdentityKeys identity,
    required Uint8List senderDevId,
    required Uint8List recipientDevId,
    required Uint8List ratchetPub,
    required int msgNumber,
    required int prevChainLen,
    required List<int> messageKey,
    required List<int> plaintext,
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
    );
    final List<int> sig = await identity.sign(env.toBytes());
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
