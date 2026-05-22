import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:kalki_crypto/kalki_crypto.dart';

import '../../core/api.dart';
import '../../data/local_db.dart';

/// Generates this admin device's prekey bundle and uploads the public
/// halves to `POST /v1/prekeys`. Private halves stay on-device in the
/// SQLCipher DB so the X3DH responder can use them later when a user
/// initiates a session.
///
/// Why prekeys exist at all: X3DH lets a sender start a session with an
/// offline recipient by mixing in the recipient's pre-published keys.
/// Without prekeys uploaded, no user can start a support conversation
/// with this admin device — they'd get a 404 from /v1/prekeys/{device_id}.
///
/// Replenishment policy: when the local OPK pool drops below
/// `lowWaterMark`, we top it back up to `targetPool`. For dev/pilot scope
/// the values below are fine; in production you'd watch the pool size
/// in metrics and tune.
class AdminPrekeyManager {
  AdminPrekeyManager(this._api, this._db);
  final AdminApi _api;
  final AdminLocalDb _db;

  static const int lowWaterMark = 5;
  static const int targetPool = 20;

  /// Provision a fresh bundle on first sign-in OR top up if pool is low.
  /// Idempotent — safe to call on every app launch.
  Future<void> ensureProvisioned(IdentityKeys identity) async {
    // Signed prekey: keep one. If none yet, generate + sign + upload.
    final ({Uint8List xPriv, Uint8List xPub, Uint8List signature, int id})
        spk = await _generateAndStoreSignedPrekey(identity);

    final int existingOpks = await _db.oneTimePrekeyCount();
    final int shortfall = targetPool - existingOpks;
    final List<({int id, Uint8List xPriv, Uint8List xPub})> freshOpks =
        existingOpks < lowWaterMark
            ? await _generateOneTimePrekeys(shortfall)
            : <({int id, Uint8List xPriv, Uint8List xPub})>[];
    if (freshOpks.isNotEmpty) {
      await _db.insertOneTimePrekeys(freshOpks);
    }

    // Upload: signed prekey is always uploaded (cheap, just replaces).
    // OPKs only when we actually generated new ones.
    final Map<String, dynamic> body = <String, dynamic>{
      'signed_prekey': <String, dynamic>{
        'id': spk.id,
        'pubkey_x25519': base64Encode(spk.xPub),
        'signature_ed25519': base64Encode(spk.signature),
      },
      if (freshOpks.isNotEmpty)
        'one_time_prekeys': freshOpks
            .map((o) => <String, dynamic>{
                  'id': o.id,
                  'pubkey_x25519': base64Encode(o.xPub),
                })
            .toList(growable: false),
    };
    final r = await _api.post('/v1/prekeys', body);
    if (r.statusCode != 200) {
      throw StateError('prekey upload failed: HTTP ${r.statusCode}');
    }
  }

  Future<
      ({
        Uint8List xPriv,
        Uint8List xPub,
        Uint8List signature,
        int id,
      })> _generateAndStoreSignedPrekey(IdentityKeys identity) async {
    // For simplicity we use prekey_id=1 — the schema's single-row
    // constraint via upsertSignedPrekey replaces on rotation. Multi-id
    // rotation can land later.
    const int id = 1;
    final X25519 x = X25519();
    final SimpleKeyPair kp = await x.newKeyPair();
    final SimpleKeyPairData data = await kp.extract();
    final SimplePublicKey pub = await kp.extractPublicKey();
    final Uint8List xPub = Uint8List.fromList(pub.bytes);
    final Uint8List xPriv = Uint8List.fromList(data.bytes);
    final List<int> sigBytes = await identity.sign(xPub);
    final Uint8List signature = Uint8List.fromList(sigBytes);
    await _db.upsertSignedPrekey(
        id: id, xPriv: xPriv, xPub: xPub, signature: signature);
    return (
      xPriv: xPriv,
      xPub: xPub,
      signature: signature,
      id: id,
    );
  }

  Future<List<({int id, Uint8List xPriv, Uint8List xPub})>>
      _generateOneTimePrekeys(int count) async {
    final List<({int id, Uint8List xPriv, Uint8List xPub})> out =
        <({int id, Uint8List xPriv, Uint8List xPub})>[];
    final X25519 x = X25519();
    // Use millis as the high-bits of the id so multiple runs don't
    // collide. The backend treats (device_id, prekey_id) as the PK.
    final int base =
        DateTime.now().millisecondsSinceEpoch & 0x7FFFFFFF;
    for (int i = 0; i < count; i++) {
      final SimpleKeyPair kp = await x.newKeyPair();
      final SimpleKeyPairData data = await kp.extract();
      final SimplePublicKey pub = await kp.extractPublicKey();
      out.add((
        id: base + i + 1,
        xPriv: Uint8List.fromList(data.bytes),
        xPub: Uint8List.fromList(pub.bytes),
      ));
    }
    return out;
  }
}
