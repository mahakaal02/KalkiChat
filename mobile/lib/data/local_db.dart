import 'dart:async';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite_sqlcipher/sqflite.dart';

import 'package:kalki_crypto/kalki_crypto.dart';

import '../core/security/keystore.dart';

/// Encrypted SQLite (sqlcipher) — backs:
///   * Locally cached ciphertext envelopes + decrypted plaintext (UI cache).
///   * The Double Ratchet state per peer.
///   * The outgoing queue (offline send buffer).
///
/// The passphrase is a 256-bit random value generated at first launch and
/// stored in the hardware keystore.
class LocalDb {
  LocalDb._(this._db);
  final Database _db;

  static LocalDb? _instance;

  static Future<LocalDb> open() async {
    if (_instance != null) return _instance!;
    final HardwareKeystore ks = HardwareKeystore.I;
    String? pass = await ks.readString('sqlcipher_pass');
    if (pass == null) {
      final List<int> rnd = List<int>.generate(32, (_) =>
          DateTime.now().microsecondsSinceEpoch ^ (_random() & 0xFF) & 0xFF);
      pass = _toHex(Uint8List.fromList(rnd));
      await ks.writeString('sqlcipher_pass', pass);
    }
    final String dir = (await getApplicationDocumentsDirectory()).path;
    final String path = p.join(dir, 'kalki.db');
    final Database db = await openDatabase(
      path,
      password: pass,
      version: 1,
      onCreate: (Database d, int v) async {
        await d.execute('''
          CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            peer_device_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            envelope BLOB NOT NULL,
            plaintext TEXT,
            media_id TEXT,
            created_at INTEGER NOT NULL,
            status TEXT NOT NULL
          )
        ''');
        await d.execute('CREATE INDEX messages_created_idx ON messages(created_at)');
        await d.execute('CREATE INDEX messages_status_idx ON messages(status)');

        await d.execute('''
          CREATE TABLE ratchet_state (
            peer_device_id TEXT PRIMARY KEY,
            blob BLOB NOT NULL,
            updated_at INTEGER NOT NULL
          )
        ''');

        await d.execute('''
          CREATE TABLE outbox (
            client_id TEXT PRIMARY KEY,
            recipient_device_id TEXT NOT NULL,
            envelope BLOB NOT NULL,
            signature BLOB NOT NULL,
            media_id TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
          )
        ''');
      },
    );
    _instance = LocalDb._(db);
    return _instance!;
  }

  Database get raw => _db;

  Future<void> insertOutgoing({
    required String id,
    required String peerDeviceId,
    required Uint8List envelope,
    required String plaintext,
    String? mediaId,
  }) async {
    await _db.insert('messages', <String, Object?>{
      'id': id,
      'peer_device_id': peerDeviceId,
      'direction': 'out',
      'envelope': envelope,
      'plaintext': plaintext,
      'media_id': mediaId,
      'created_at': DateTime.now().millisecondsSinceEpoch,
      'status': 'pending',
    });
  }

  Future<void> insertIncoming({
    required String id,
    required String peerDeviceId,
    required Uint8List envelope,
    required String plaintext,
    String? mediaId,
  }) async {
    await _db.insert('messages', <String, Object?>{
      'id': id,
      'peer_device_id': peerDeviceId,
      'direction': 'in',
      'envelope': envelope,
      'plaintext': plaintext,
      'media_id': mediaId,
      'created_at': DateTime.now().millisecondsSinceEpoch,
      'status': 'delivered',
    });
  }

  Future<void> markStatus(String id, String status) async {
    await _db.update('messages', <String, Object?>{'status': status},
        where: 'id = ?', whereArgs: <Object?>[id]);
  }

  Future<List<Map<String, Object?>>> recentMessages({int limit = 50}) async {
    return _db.query(
      'messages',
      orderBy: 'created_at DESC',
      limit: limit,
    );
  }

  Future<void> saveRatchet(String peerDeviceId, DoubleRatchet r) async {
    final Uint8List blob = _encodeRatchet(r);
    await _db.insert(
      'ratchet_state',
      <String, Object?>{
        'peer_device_id': peerDeviceId,
        'blob': blob,
        'updated_at': DateTime.now().millisecondsSinceEpoch,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<DoubleRatchet?> loadRatchet(String peerDeviceId) async {
    final List<Map<String, Object?>> rows = await _db.query(
      'ratchet_state',
      where: 'peer_device_id = ?',
      whereArgs: <Object?>[peerDeviceId],
      limit: 1,
    );
    if (rows.isEmpty) return null;
    return _decodeRatchet(rows.first['blob']! as Uint8List);
  }

  /// Forget the ratchet for [peerDeviceId]. Used when the admin operator
  /// has re-registered their device — the old peer id will never accept
  /// our steady-state envelopes again, so the next send must X3DH-
  /// bootstrap to whatever the new peer device is.
  Future<void> deleteRatchet(String peerDeviceId) async {
    await _db.delete(
      'ratchet_state',
      where: 'peer_device_id = ?',
      whereArgs: <Object?>[peerDeviceId],
    );
  }

  /// Outbox: persist outbound while offline.
  Future<void> enqueueOutbox({
    required String clientId,
    required String recipientDeviceId,
    required Uint8List envelope,
    required Uint8List signature,
    String? mediaId,
  }) async {
    await _db.insert('outbox', <String, Object?>{
      'client_id': clientId,
      'recipient_device_id': recipientDeviceId,
      'envelope': envelope,
      'signature': signature,
      'media_id': mediaId,
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<List<Map<String, Object?>>> outboxPending() =>
      _db.query('outbox', orderBy: 'created_at ASC');

  Future<void> outboxDelete(String clientId) async {
    await _db.delete('outbox',
        where: 'client_id = ?', whereArgs: <Object?>[clientId]);
  }

  /// Hard-delete everything older than [ttl] and run a VACUUM so the pages are
  /// rewritten (sqlcipher overwrites raw bytes on VACUUM).
  Future<void> purgeOlderThan(Duration ttl) async {
    final int cutoff =
        DateTime.now().subtract(ttl).millisecondsSinceEpoch;
    await _db.delete('messages', where: 'created_at < ?', whereArgs: <Object?>[cutoff]);
    await _db.execute('VACUUM');
  }

  static Uint8List _encodeRatchet(DoubleRatchet r) {
    final Map<String, dynamic> m = r.toMap();
    final BytesBuilder b = BytesBuilder();
    void put(String k) {
      final List<int> v = (m[k] as List<int>);
      b.addByte(v.length);
      b.add(v);
    }
    put('rk');
    put('cks');
    put('ckr');
    put('dhsP');
    put('dhsB');
    put('dhrB');
    final ByteData bd = ByteData(12);
    bd.setUint32(0, m['ns'] as int);
    bd.setUint32(4, m['nr'] as int);
    bd.setUint32(8, m['pn'] as int);
    b.add(bd.buffer.asUint8List());
    return b.toBytes();
  }

  static DoubleRatchet _decodeRatchet(Uint8List buf) {
    int off = 0;
    Uint8List take() {
      final int n = buf[off++];
      final Uint8List v = buf.sublist(off, off + n);
      off += n;
      return Uint8List.fromList(v);
    }
    final Uint8List rk = take();
    final Uint8List cks = take();
    final Uint8List ckr = take();
    final Uint8List dhsP = take();
    final Uint8List dhsB = take();
    final Uint8List dhrB = take();
    final ByteData bd =
        ByteData.sublistView(buf.sublist(off, off + 12));
    return DoubleRatchet(
      rootKey: rk,
      sendChainKey: cks,
      recvChainKey: ckr,
      dhSendPriv: dhsP,
      dhSendPub: dhsB,
      dhRecvPub: dhrB,
      nSend: bd.getUint32(0),
      nRecv: bd.getUint32(4),
      pn: bd.getUint32(8),
    );
  }

  static int _seed = DateTime.now().microsecondsSinceEpoch;
  static int _random() {
    _seed = (_seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return _seed;
  }

  static String _toHex(Uint8List b) {
    const String hex = '0123456789abcdef';
    final StringBuffer sb = StringBuffer();
    for (final int v in b) {
      sb
        ..write(hex[(v >> 4) & 0xF])
        ..write(hex[v & 0xF]);
    }
    return sb.toString();
  }
}
