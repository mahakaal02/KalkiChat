import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:kalki_crypto/kalki_crypto.dart';
import 'package:uuid/uuid.dart';

import '../../core/api.dart';
import '../../core/net/ws_client.dart';
import '../../core/security/keystore.dart';
import '../../data/local_db.dart';
import 'prekey_manager.dart';

/// State broadcast to the UI. `lastError` carries decrypt / signature
/// failures so the user_detail_screen can surface them without crashing.
/// `lastMessageAt` is bumped on every successful incoming message —
/// screens watching this controller can refresh their plaintext lists.
class AdminChatState {
  const AdminChatState({
    this.connected = false,
    this.lastError,
    this.lastMessageAt,
  });
  final bool connected;
  final String? lastError;
  final DateTime? lastMessageAt;

  AdminChatState copyWith({
    bool? connected,
    String? lastError,
    DateTime? lastMessageAt,
  }) =>
      AdminChatState(
        connected: connected ?? this.connected,
        lastError: lastError,
        lastMessageAt: lastMessageAt ?? this.lastMessageAt,
      );
}

final adminChatControllerProvider =
    StateNotifierProvider<AdminChatController, AdminChatState>((ref) {
  return AdminChatController(ref.read(adminApiProvider));
});

/// Owns the WebSocket connection to /v1/ws, the local DB, the prekey
/// manager, and the X3DH responder path. Spun up once after sign-in
/// (see admin-mobile's app shell calling [start]) and lives for the
/// whole session.
///
/// Responsibilities:
///   * Connect WS, reconnect on drop.
///   * On incoming `message.recv`:
///       - parse the envelope
///       - if bootstrap (type=1): run X3DH responder, init
///         DoubleRatchet.responder, advance via ratchetReceive, decrypt
///       - if steady-state (type=0): verify signature against cached
///         peer identity, advance ratchet if peer rotated, decrypt
///       - persist plaintext to messages table keyed by sender device
///         + the user_id we map the device to (so the UI can group
///         conversations by user).
///       - **relay plaintext to /v1/admin-sync/inbound** so admin-web
///         can display it; ack the WS so the backend marks delivered
///         and won't re-replay on next reconnect.
///   * On outgoing reply (called from user_detail_screen): seal with
///     the existing ratchet's nextSendKey, ship via WS.
///   * Poll /v1/admin-sync/outbound/pending every 5s; for each queued
///     reply admin-web has composed, look up the right peer device,
///     call sendReply, then POST /sent so the backend mirrors the
///     plaintext for the web display and stops handing the item out.
class AdminChatController extends StateNotifier<AdminChatState> {
  AdminChatController(this._api) : super(const AdminChatState());

  final AdminApi _api;
  AdminLocalDb? _db;
  AdminWsClient? _ws;
  AdminPrekeyManager? _prekeys;
  Timer? _outboundPoll;
  bool _outboundBusy = false;

  /// Called once after sign-in completes. Idempotent: safe to call
  /// repeatedly on app resume.
  Future<void> start() async {
    _db ??= await AdminLocalDb.open();
    _prekeys ??= AdminPrekeyManager(_api, _db!);
    final IdentityKeys keys =
        await IdentityKeys.initOrLoad(AdminHardwareKeystore.I);
    try {
      await _prekeys!.ensureProvisioned(keys);
    } catch (e) {
      state = state.copyWith(lastError: 'prekey upload failed: $e');
    }
    if (_ws == null) {
      _ws = AdminWsClient(url: Uri.parse(AdminEnv.wsUrl));
      await _ws!.connect(_handleEvent);
      state = state.copyWith(connected: true);
    }
    _outboundPoll ??= Timer.periodic(
      const Duration(seconds: 5),
      (_) => unawaited(_drainOutbound()),
    );
    // Drain immediately so the very first reply admin-web sends
    // doesn't have to wait up to 5s for its first poll tick.
    unawaited(_drainOutbound());
  }

  Future<void> stop() async {
    _outboundPoll?.cancel();
    _outboundPoll = null;
    await _ws?.close();
    _ws = null;
    state = state.copyWith(connected: false);
  }

  /// Send an admin reply within an EXISTING session. The session must
  /// already have been bootstrapped by an incoming user message —
  /// admin-mobile is responder-only for now (admin-initiated
  /// conversations land in a future phase).
  Future<bool> sendReply({
    required String peerDeviceId,
    required String userId,
    required String text,
  }) async {
    final AdminLocalDb db = _db!;
    final DoubleRatchet? ratchet = await db.loadRatchet(peerDeviceId);
    if (ratchet == null) {
      state = state.copyWith(
          lastError: 'no session with $peerDeviceId — wait for user message');
      return false;
    }
    final IdentityKeys keys =
        await IdentityKeys.initOrLoad(AdminHardwareKeystore.I);
    final String? ourDeviceId =
        await AdminHardwareKeystore.I.readString('device_id');
    if (ourDeviceId == null) {
      state = state.copyWith(lastError: 'not signed in');
      return false;
    }
    final Uint8List senderDev = _toDevBytes(ourDeviceId);
    final Uint8List recipDev = _toDevBytes(peerDeviceId);
    final Uint8List mk = await ratchet.nextSendKey();
    final ({Envelope envelope, List<int> signature}) sealed =
        await Envelope.seal(
      sign: keys.sign,
      senderDevId: senderDev,
      recipientDevId: recipDev,
      ratchetPub: ratchet.dhSendPub,
      msgNumber: ratchet.nSend - 1,
      prevChainLen: ratchet.pn,
      messageKey: mk,
      plaintext: utf8.encode(text),
    );
    await db.saveRatchet(peerDeviceId, ratchet);
    final Uint8List envBytes = sealed.envelope.toBytes();
    final String clientId = const Uuid().v4();
    await db.insertMessage(
      id: clientId,
      peerDeviceId: peerDeviceId,
      userId: userId,
      direction: 'out',
      envelope: envBytes,
      plaintext: text,
    );
    // Stash plaintext so the message.persisted handler can relay it to
    // /admin-sync/inbound (with the now-known server_id) for the
    // admin-web display mirror. Cleared in _handlePersisted.
    _pendingOutboundPlaintext[clientId] = text;
    // The admin-mobile WS hub speaks the same `message.send` schema as
    // user-mobile — see backend/internal/api/ws.go handleSend.
    _ws?.send(<String, dynamic>{
      'type': 'message.send',
      'id': clientId,
      'data': <String, dynamic>{
        'client_id': clientId,
        'recipient_device_id': peerDeviceId,
        'envelope': base64Encode(envBytes),
        'signature': base64Encode(sealed.signature),
      },
    });
    state = state.copyWith(lastMessageAt: DateTime.now());
    return true;
  }

  // ----- Inbound path -----------------------------------------------------

  /// Pending outbound sends keyed by client_id. When message.persisted
  /// arrives we look up the pending entry, relay the plaintext through
  /// /admin-sync/inbound (server computes direction='outbound' from the
  /// messages row), and clear. Bounded by the WS flush rate; entries
  /// that never get a persisted reply leak but the map is small.
  final Map<String, String> _pendingOutboundPlaintext = <String, String>{};

  Future<void> _handleEvent(Map<String, dynamic> ev) async {
    final String type = ev['type'] as String? ?? '';
    try {
      switch (type) {
        case 'message.recv':
          await _handleIncoming(ev);
          break;
        case 'message.persisted':
          await _handlePersisted(ev);
          break;
      }
    } catch (e) {
      state = state.copyWith(lastError: '$type failed: $e');
    }
  }

  Future<void> _handlePersisted(Map<String, dynamic> ev) async {
    final Map<String, dynamic> d =
        (ev['data'] as Map).cast<String, dynamic>();
    final String clientId = d['client_id'] as String? ?? '';
    final String serverId = d['server_id'] as String? ?? '';
    if (clientId.isEmpty || serverId.isEmpty) return;
    final String? plaintext = _pendingOutboundPlaintext.remove(clientId);
    if (plaintext == null) return;
    // direction is derived server-side; this just needs the body + id.
    await _relayInbound(serverId, plaintext);
  }

  Future<void> _handleIncoming(Map<String, dynamic> ev) async {
    final Map<String, dynamic> d =
        (ev['data'] as Map).cast<String, dynamic>();
    final String envB64 = d['envelope'] as String;
    final String sigB64 = d['signature'] as String? ?? '';
    final String senderDeviceId = d['sender_device_id'] as String? ?? '';
    final String serverMessageId = d['server_id'] as String? ?? '';

    final Uint8List envBytes = Uint8List.fromList(base64.decode(envB64));
    final Envelope env = Envelope.fromBytes(envBytes);
    final Uint8List signature =
        Uint8List.fromList(base64.decode(sigB64));

    if (env.isBootstrap) {
      await _handleBootstrap(
          env, signature, envBytes, senderDeviceId, serverMessageId);
    } else {
      await _handleSteadyState(
          env, signature, envBytes, senderDeviceId, serverMessageId);
    }
  }

  Future<void> _handleBootstrap(
    Envelope env,
    Uint8List signature,
    Uint8List envBytes,
    String senderDeviceId,
    String serverMessageId,
  ) async {
    final BootstrapHeader hdr = env.bootstrap!;
    // 1. Verify the signature against the identity the bootstrap claims.
    //    Trust is established here by the X3DH binding: an attacker who
    //    forges this header would still need the matching X25519 priv
    //    to produce a DH that matches what we'll derive below.
    if (!await Envelope.verify(
      envelope: env,
      signature: signature,
      signerIdentityEd25519Pub: hdr.identityEd25519,
    )) {
      state = state.copyWith(
          lastError:
              'bootstrap from $senderDeviceId — signature invalid, discarding');
      return;
    }

    // 2. Look up our own prekey privates that were consumed.
    final AdminLocalDb db = _db!;
    final Map<String, Object?>? spkRow =
        await db.loadSignedPrekeyById(hdr.signedPrekeyId);
    if (spkRow == null) {
      state = state.copyWith(
          lastError:
              'bootstrap referenced unknown signed_prekey id ${hdr.signedPrekeyId}');
      return;
    }
    ({Uint8List xPriv, Uint8List xPub})? opk;
    if (hdr.oneTimePrekeyId != 0) {
      opk = await db.consumeOneTimePrekey(hdr.oneTimePrekeyId);
      if (opk == null) {
        state = state.copyWith(
            lastError:
                'bootstrap referenced unknown OPK id ${hdr.oneTimePrekeyId}');
        return;
      }
    }

    // 3. Read our identity X25519 priv from the keystore. Same narrow
    //    leakage policy as in user-mobile's chat_controller.
    final List<int>? ourXPriv =
        await AdminHardwareKeystore.I.readBytes('x25519_priv');
    final IdentityKeys keys =
        await IdentityKeys.initOrLoad(AdminHardwareKeystore.I);
    if (ourXPriv == null) {
      state = state.copyWith(lastError: 'admin identity X25519 not loaded');
      return;
    }

    // 4. X3DH responder.
    final Uint8List sk = await x3dhResponder(
      ourIdentityX25519Priv: Uint8List.fromList(ourXPriv),
      ourIdentityX25519Pub: keys.xPubBytes,
      ourSignedPrekeyPriv: spkRow['x_priv']! as Uint8List,
      ourSignedPrekeyPub: spkRow['x_pub']! as Uint8List,
      peerIdentityX25519Pub: hdr.identityX25519,
      peerEphemeralX25519Pub: hdr.ephemeralX25519,
      ourOneTimePrekeyPriv: opk?.xPriv,
      ourOneTimePrekeyPub: opk?.xPub,
    );

    // 5. Initialise the responder-side ratchet, advance via
    //    ratchetReceive(env.ratchetPub) to derive matching recvChain.
    final DoubleRatchet ratchet = DoubleRatchet.responder(
      sharedSecret: sk,
      signedPrekeyPriv: spkRow['x_priv']! as Uint8List,
      signedPrekeyPub: spkRow['x_pub']! as Uint8List,
    );
    await ratchet.ratchetReceive(env.ratchetPub);
    final Uint8List mk = await ratchet.nextRecvKey();
    final List<int> pt =
        await Envelope.open(envelope: env, messageKey: mk);
    await db.saveRatchet(senderDeviceId, ratchet);

    // Cache the peer's identity Ed25519 so we can verify subsequent
    // type-0 envelopes from them without re-receiving a bootstrap.
    await AdminHardwareKeystore.I.writeBytes(
        'peer_ed25519_$senderDeviceId', hdr.identityEd25519);

    final String userId =
        await _resolveUserIdForDevice(senderDeviceId) ?? '';
    final String plaintext = utf8.decode(pt);
    await db.insertMessage(
      id: const Uuid().v4(),
      peerDeviceId: senderDeviceId,
      userId: userId,
      direction: 'in',
      envelope: envBytes,
      plaintext: plaintext,
    );
    await _relayInbound(serverMessageId, plaintext);
    _ackServer(serverMessageId);
    state = state.copyWith(lastMessageAt: DateTime.now(), lastError: null);
  }

  Future<void> _handleSteadyState(
    Envelope env,
    Uint8List signature,
    Uint8List envBytes,
    String senderDeviceId,
    String serverMessageId,
  ) async {
    final AdminLocalDb db = _db!;
    final DoubleRatchet? ratchet = await db.loadRatchet(senderDeviceId);
    if (ratchet == null) {
      state = state.copyWith(
          lastError:
              'received from $senderDeviceId without an existing session — discarding');
      return;
    }
    final List<int>? peerEd = await AdminHardwareKeystore.I
        .readBytes('peer_ed25519_$senderDeviceId');
    if (peerEd == null) {
      state = state.copyWith(
          lastError: 'missing peer identity for $senderDeviceId');
      return;
    }
    if (!await Envelope.verify(
      envelope: env,
      signature: signature,
      signerIdentityEd25519Pub: Uint8List.fromList(peerEd),
    )) {
      state = state.copyWith(
          lastError: 'signature invalid from $senderDeviceId — discarded');
      return;
    }
    if (!_bytesEqual(env.ratchetPub, ratchet.dhRecvPub)) {
      await ratchet.ratchetReceive(env.ratchetPub);
    }
    final Uint8List mk = await ratchet.nextRecvKey();
    final List<int> pt =
        await Envelope.open(envelope: env, messageKey: mk);
    await db.saveRatchet(senderDeviceId, ratchet);

    final String userId =
        await _resolveUserIdForDevice(senderDeviceId) ?? '';
    final String plaintext = utf8.decode(pt);
    await db.insertMessage(
      id: const Uuid().v4(),
      peerDeviceId: senderDeviceId,
      userId: userId,
      direction: 'in',
      envelope: envBytes,
      plaintext: plaintext,
    );
    await _relayInbound(serverMessageId, plaintext);
    _ackServer(serverMessageId);
    state = state.copyWith(lastMessageAt: DateTime.now(), lastError: null);
  }

  /// We need to group messages from a device under that device's owning
  /// user for the UI. The mapping isn't carried in the envelope (which
  /// is per-device), so we look it up through the admin-only endpoint
  /// /v1/admin/devices. Cached after first hit per session.
  final Map<String, String> _deviceToUser = <String, String>{};
  Future<String?> _resolveUserIdForDevice(String deviceId) async {
    final String? hit = _deviceToUser[deviceId];
    if (hit != null) return hit;
    try {
      final r = await _api.get('/v1/admin/devices');
      if (r.statusCode != 200) return null;
      final List<dynamic> list =
          ((r.data as Map?)?['devices'] as List<dynamic>?) ?? const <dynamic>[];
      for (final dynamic e in list) {
        final Map<String, dynamic> row = (e as Map).cast<String, dynamic>();
        final String id = row['id'] as String? ?? '';
        final String owner = row['owner_id'] as String? ?? '';
        if (id.isNotEmpty && owner.isNotEmpty) {
          _deviceToUser[id] = owner;
        }
      }
      return _deviceToUser[deviceId];
    } catch (_) {
      return null;
    }
  }

  // ----- admin-sync bridge -----------------------------------------------

  /// Push the freshly-decrypted plaintext to /v1/admin-sync/inbound so
  /// admin-web can render it. Server gates on "caller is on at least one
  /// end of this message" and dedupes via the admin_plaintext PK, so
  /// best-effort + retry-friendly: a failure here just means admin-web
  /// will keep showing "decrypting…" until the next time we replay.
  Future<void> _relayInbound(String serverMessageId, String plaintext) async {
    if (serverMessageId.isEmpty) return;
    try {
      await _api.post('/v1/admin-sync/inbound', <String, dynamic>{
        'message_id': serverMessageId,
        'body': plaintext,
      });
    } catch (e) {
      // Don't surface in state.lastError — the user's read of the
      // message succeeded; admin-web will catch up on the next replay
      // (next WS reconnect triggers backend backfill of undelivered
      // rows, which re-fires _handleIncoming, which re-relays).
    }
  }

  /// Tell the backend "I've processed this message_id" so it stops
  /// re-delivering on every reconnect via the WS backfill path.
  void _ackServer(String serverMessageId) {
    if (serverMessageId.isEmpty) return;
    _ws?.send(<String, dynamic>{
      'type': 'message.ack',
      'data': <String, dynamic>{'server_id': serverMessageId},
    });
  }

  /// Poll /v1/admin-sync/outbound/pending; for each queued reply from
  /// admin-web, look up the peer device, encrypt + send via the
  /// existing WS path, then POST /sent so the queue row transitions and
  /// the plaintext mirror is populated for the web display.
  Future<void> _drainOutbound() async {
    if (_db == null) return;
    if (_outboundBusy) return; // overlapping ticks are a no-op
    _outboundBusy = true;
    try {
      final r = await _api.get('/v1/admin-sync/outbound/pending');
      if (r.statusCode != 200) return;
      final List<dynamic> items = ((r.data as Map?)?['items'] as List<dynamic>?) ??
          const <dynamic>[];
      for (final dynamic it in items) {
        final Map<String, dynamic> row = (it as Map).cast<String, dynamic>();
        final String id = row['id'] as String? ?? '';
        final String userId = row['user_id'] as String? ?? '';
        final String body = row['body'] as String? ?? '';
        if (id.isEmpty || userId.isEmpty || body.isEmpty) continue;
        await _processOutbound(id, userId, body);
      }
    } catch (e) {
      // Transient — next poll tick retries. Don't poison state.
    } finally {
      _outboundBusy = false;
    }
  }

  Future<void> _processOutbound(
      String queueId, String userId, String body) async {
    final String? peerDeviceId = await _db!.peerDeviceForUser(userId);
    if (peerDeviceId == null) {
      // No session yet with this user; can't encrypt. Tell the backend
      // it failed so admin-web can show a clear "user hasn't messaged
      // us yet — they need to start the conversation" message instead
      // of leaving the reply stuck in 'pending' forever.
      await _markOutboundFailed(queueId,
          'no session with user yet (they must send first)');
      return;
    }
    // Reuse the existing sendReply path so encryption / signing /
    // ratchet bookkeeping all stays in one place.
    final bool ok = await sendReply(
      peerDeviceId: peerDeviceId,
      userId: userId,
      text: body,
    );
    if (!ok) {
      await _markOutboundFailed(queueId,
          state.lastError ?? 'sendReply returned false');
      return;
    }
    // sendReply persisted the message locally with a client UUID, but
    // the SERVER message id only comes back via the message.persisted
    // WS event — which is async. For the queue row we use the WS
    // message id we just sent (clientId); the backend's
    // /admin-sync/outbound/{id}/sent handler is forgiving about
    // not-yet-arrived server ids (it stores what we give it; the web
    // UI's correlation is best-effort anyway).
    //
    // To do this cleanly we'd need to wait for message.persisted then
    // resolve server_id. The pragmatic shortcut: re-fetch the most-
    // recent outgoing message from local DB and use its envelope hash
    // as a stable correlation key. Simplest of all: just send the
    // queue id back as a stand-in until we wire the persisted-event
    // correlator. For the immediate UX the important thing is the row
    // transitions to 'sent' so admin-web stops showing "sending…".
    //
    // We pass an empty server_message_id; the server's atomic
    // /sent handler will mark the row sent and skip the plaintext
    // mirror insert (it requires a real msg_id). The plaintext for
    // outbound messages is also kept locally by sendReply — admin-web
    // will see it on the next conversation fetch via the LEFT JOIN to
    // admin_plaintext + outbound_queue.body fallback.
    await _markOutboundSent(queueId);
  }

  Future<void> _markOutboundSent(String queueId) async {
    try {
      await _api.post(
        '/v1/admin-sync/outbound/$queueId/sent',
        <String, dynamic>{'server_message_id': ''},
      );
    } catch (_) {/* next poll tick retries */}
  }

  Future<void> _markOutboundFailed(String queueId, String err) async {
    try {
      await _api.post(
        '/v1/admin-sync/outbound/$queueId/sent',
        <String, dynamic>{'error': err},
      );
    } catch (_) {/* next poll tick retries */}
  }

  static Uint8List _toDevBytes(String id) {
    final Uint8List out = Uint8List(16);
    final List<int> bytes = utf8.encode(id);
    for (int i = 0; i < 16 && i < bytes.length; i++) {
      out[i] = bytes[i];
    }
    return out;
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
