import 'dart:async';
import 'dart:typed_data';

import 'package:kalki_crypto/kalki_crypto.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite_sqlcipher/sqflite.dart';

import '../core/security/keystore.dart';

/// Encrypted SQLite (SQLCipher) for the admin companion device.
///
/// Stores three kinds of data, all of which MUST live only on the device
/// (never on the server):
///
///   * `ratchet_state` — per-peer Double Ratchet state. One row per
///     user we're in a session with.
///   * `signed_prekey` / `one_time_prekeys` — the *private* halves of the
///     prekey bundle we've uploaded to /v1/prekeys. Identity is in the
///     hardware keystore; prekey privates are in the DB because there can
///     be many (one per OTP) and they rotate.
///   * `messages` — decrypted plaintext + the original envelope + the
///     direction. This is the UI's source of truth for the chat list.
///
/// The DB passphrase is a 32-byte random value generated on first launch
/// and stashed in [AdminHardwareKeystore]. Without the keystore the DB
/// is unreadable (SQLCipher AES-256-GCM page encryption).
class AdminLocalDb {
  AdminLocalDb._(this._db);
  final Database _db;

  static AdminLocalDb? _instance;

  static Future<AdminLocalDb> open() async {
    if (_instance != null) return _instance!;
    final AdminHardwareKeystore ks = AdminHardwareKeystore.I;
    String? pass = await ks.readString('sqlcipher_pass');
    if (pass == null) {
      final Uint8List rnd = _entropy(32);
      pass = _hex(rnd);
      await ks.writeString('sqlcipher_pass', pass);
    }
    final String dir = (await getApplicationDocumentsDirectory()).path;
    final String path = p.join(dir, 'kalki_admin.db');
    final Database db = await openDatabase(
      path,
      password: pass,
      version: 1,
      onCreate: (Database d, int v) async {
        await d.execute('''
          CREATE TABLE ratchet_state (
            peer_device_id TEXT PRIMARY KEY,
            blob BLOB NOT NULL,
            updated_at INTEGER NOT NULL
          )
        ''');

        // One signed prekey at a time; INSERT OR REPLACE on rotation.
        await d.execute('''
          CREATE TABLE signed_prekey (
            prekey_id INTEGER PRIMARY KEY,
            x_priv BLOB NOT NULL,
            x_pub  BLOB NOT NULL,
            signature BLOB NOT NULL,
            created_at INTEGER NOT NULL
          )
        ''');

        // Many one-time prekeys; rows are deleted on consume so the
        // forward-secrecy guarantee holds.
        await d.execute('''
          CREATE TABLE one_time_prekeys (
            prekey_id INTEGER PRIMARY KEY,
            x_priv BLOB NOT NULL,
            x_pub  BLOB NOT NULL,
            created_at INTEGER NOT NULL
          )
        ''');

        await d.execute('''
          CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            peer_device_id TEXT NOT NULL,
            user_id TEXT,
            direction TEXT NOT NULL,
            envelope BLOB NOT NULL,
            plaintext TEXT,
            created_at INTEGER NOT NULL
          )
        ''');
        await d.execute(
            'CREATE INDEX messages_peer_idx ON messages(peer_device_id, created_at)');
        await d.execute(
            'CREATE INDEX messages_user_idx ON messages(user_id, created_at)');
      },
    );
    _instance = AdminLocalDb._(db);
    return _instance!;
  }

  Database get raw => _db;

  // ---- Ratchet state ------------------------------------------------------

  Future<void> saveRatchet(String peerDeviceId, DoubleRatchet r) async {
    await _db.insert(
      'ratchet_state',
      <String, Object?>{
        'peer_device_id': peerDeviceId,
        'blob': _encodeRatchet(r),
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

  // ---- Prekey storage -----------------------------------------------------

  Future<void> upsertSignedPrekey({
    required int id,
    required Uint8List xPriv,
    required Uint8List xPub,
    required Uint8List signature,
  }) async {
    // The schema has prekey_id as the primary key and one row per rotation.
    // We delete the previous row(s) before inserting so the most-recent SPK
    // is the only one held.
    await _db.delete('signed_prekey');
    await _db.insert('signed_prekey', <String, Object?>{
      'prekey_id': id,
      'x_priv': xPriv,
      'x_pub': xPub,
      'signature': signature,
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  Future<Map<String, Object?>?> loadSignedPrekeyById(int id) async {
    final List<Map<String, Object?>> rows = await _db.query(
      'signed_prekey',
      where: 'prekey_id = ?',
      whereArgs: <Object?>[id],
      limit: 1,
    );
    return rows.isEmpty ? null : rows.first;
  }

  Future<void> insertOneTimePrekeys(
      List<({int id, Uint8List xPriv, Uint8List xPub})> opks) async {
    final Batch b = _db.batch();
    final int now = DateTime.now().millisecondsSinceEpoch;
    for (final ({int id, Uint8List xPriv, Uint8List xPub}) o in opks) {
      b.insert('one_time_prekeys', <String, Object?>{
        'prekey_id': o.id,
        'x_priv': o.xPriv,
        'x_pub': o.xPub,
        'created_at': now,
      }, conflictAlgorithm: ConflictAlgorithm.ignore);
    }
    await b.commit(noResult: true);
  }

  /// Consume (remove) the one-time prekey row with the given id. Called
  /// after a successful X3DH responder run so the same OPK never serves
  /// two bootstraps — that's the property forward-secrecy depends on.
  Future<({Uint8List xPriv, Uint8List xPub})?> consumeOneTimePrekey(
      int id) async {
    final List<Map<String, Object?>> rows = await _db.query(
      'one_time_prekeys',
      where: 'prekey_id = ?',
      whereArgs: <Object?>[id],
      limit: 1,
    );
    if (rows.isEmpty) return null;
    final Map<String, Object?> row = rows.first;
    await _db.delete('one_time_prekeys',
        where: 'prekey_id = ?', whereArgs: <Object?>[id]);
    return (
      xPriv: row['x_priv']! as Uint8List,
      xPub: row['x_pub']! as Uint8List,
    );
  }

  Future<int> oneTimePrekeyCount() async {
    final List<Map<String, Object?>> r =
        await _db.rawQuery('SELECT COUNT(*) AS c FROM one_time_prekeys');
    return (r.first['c']! as int);
  }

  // ---- Message persistence ------------------------------------------------

  Future<void> insertMessage({
    required String id,
    required String peerDeviceId,
    String? userId,
    required String direction, // 'in' or 'out'
    required Uint8List envelope,
    String? plaintext,
  }) async {
    await _db.insert('messages', <String, Object?>{
      'id': id,
      'peer_device_id': peerDeviceId,
      'user_id': userId,
      'direction': direction,
      'envelope': envelope,
      'plaintext': plaintext,
      'created_at': DateTime.now().millisecondsSinceEpoch,
    });
  }

  /// Return messages exchanged with any device belonging to [userId].
  /// Sorted oldest-first so the UI can render top-down without reversing.
  Future<List<Map<String, Object?>>> messagesForUser(String userId) async {
    return _db.query(
      'messages',
      where: 'user_id = ?',
      whereArgs: <Object?>[userId],
      orderBy: 'created_at ASC',
    );
  }

  Future<List<Map<String, Object?>>> messagesForPeerDevice(
      String peerDeviceId) async {
    return _db.query(
      'messages',
      where: 'peer_device_id = ?',
      whereArgs: <Object?>[peerDeviceId],
      orderBy: 'created_at ASC',
    );
  }

  // ---- Serialization for DoubleRatchet ------------------------------------
  // Mirrors mobile/lib/data/local_db.dart so both apps speak the same blob
  // format. (Future move: extract into kalki_crypto.)

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
    final ByteData bd = ByteData.sublistView(buf.sublist(off, off + 12));
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

  // ---- Misc helpers -------------------------------------------------------

  static int _seed = DateTime.now().microsecondsSinceEpoch;
  static int _rnd() {
    _seed = (_seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return _seed;
  }

  static Uint8List _entropy(int n) {
    final Uint8List out = Uint8List(n);
    for (int i = 0; i < n; i++) {
      out[i] =
          (DateTime.now().microsecond ^ _rnd() ^ DateTime.now().millisecond) &
              0xFF;
    }
    return out;
  }

  static String _hex(Uint8List b) {
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
