import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:uuid/uuid.dart';

import 'package:kalki_crypto/kalki_crypto.dart';

import '../../core/net/api_client.dart';
import '../../core/net/ws_client.dart';
import '../../core/security/keystore.dart';
import '../../data/local_db.dart';
import '../../env.dart';
import '../auth/login_controller.dart' show apiClientProvider;

enum MessageDirection { incoming, outgoing }

class ChatMessage {
  ChatMessage({
    required this.id,
    required this.direction,
    required this.plaintext,
    required this.createdAt,
  });

  final String id;
  final MessageDirection direction;
  final String plaintext;
  final DateTime createdAt;
}

class ChatState {
  ChatState({this.messages = const <ChatMessage>[], this.connected = false});
  final List<ChatMessage> messages;
  final bool connected;

  ChatState copyWith({List<ChatMessage>? messages, bool? connected}) =>
      ChatState(
        messages: messages ?? this.messages,
        connected: connected ?? this.connected,
      );
}

final chatControllerProvider =
    StateNotifierProvider<ChatController, ChatState>((ref) {
  return ChatController(ref.read(apiClientProvider));
});

class ChatController extends StateNotifier<ChatState> {
  ChatController(this._api) : super(ChatState()) {
    _load();
  }

  final ApiClient _api;
  WsClient? _ws;
  LocalDb? _db;

  Future<void> _load() async {
    _db = await LocalDb.open();
    final List<Map<String, Object?>> rows = await _db!.recentMessages();
    state = state.copyWith(messages: rows.map(_fromRow).toList());
  }

  Future<void> connect() async {
    _ws = WsClient(url: Uri.parse(Env.wsUrl), subprotocol: 'kalki.v1');
    await _ws!.connect((Map<String, dynamic> ev) {
      _handleEvent(ev);
    });
    state = state.copyWith(connected: true);
    unawaited(_flushOutbox());
  }

  Future<void> disconnect() async {
    await _ws?.close();
    _ws = null;
    state = state.copyWith(connected: false);
  }

  Future<void> sendText(String text) async {
    final IdentityKeys keys = await IdentityKeys.initOrLoad(HardwareKeystore.I);
    final String? deviceId = await HardwareKeystore.I.readString('device_id');
    if (deviceId == null) {
      _appendLocal(MessageDirection.outgoing, '(not signed in)');
      return;
    }

    // Resolve the target admin device. We can't naively cache the device
    // id forever: the operator may have re-registered admin-mobile, which
    // mints a fresh device row with a new id. If we kept sending to the
    // old id the backend would route the message to the stale Redis
    // channel and the new admin device — subscribed to its own new
    // channel — would never see it.
    //
    // So: always query /v1/admin-devices/active for the freshest device.
    // It's a single cheap HTTP round-trip and the call also dual-purposes
    // as the "is there any admin device at all?" check. We still keep a
    // cache key, but only as a fallback when the network call fails —
    // and we invalidate the on-disk ratchet for the OLD device whenever
    // the active device changes, forcing a fresh X3DH bootstrap to the
    // new one on the very next send.
    final String? cached =
        await HardwareKeystore.I.readString('admin_device_id');
    String? peer = await _resolveActiveAdminDevice();
    if (peer == null) {
      // Network call failed (or returned empty). Fall back to the cached
      // id if we have one; the message will still encrypt to that device
      // and queue server-side. Only show the "no support team" copy when
      // we have nothing whatsoever to send to.
      peer = cached;
      if (peer == null) {
        _appendLocal(MessageDirection.outgoing,
            '(your support team isn\'t set up yet — please contact your administrator)');
        return;
      }
    }
    if (peer != cached) {
      // Admin device rotated. Drop the cached ratchet so the next send
      // re-bootstraps via X3DH against the new device's prekey bundle —
      // otherwise we'd ship a steady-state envelope the new device has
      // no session for and can't decrypt.
      if (cached != null) {
        await _db?.deleteRatchet(cached);
      }
      await HardwareKeystore.I.writeString('admin_device_id', peer);
    }

    final String clientId = const Uuid().v4();
    final Uint8List senderDev = _toDevBytes(deviceId);
    final Uint8List recipDev = _toDevBytes(peer);

    // Load or bootstrap the ratchet for this peer.
    DoubleRatchet? ratchet = await _db!.loadRatchet(peer);
    BootstrapHeader? bootstrap;
    if (ratchet == null) {
      final _Bootstrapped? boot = await _bootstrapSessionTo(peer, keys);
      if (boot == null) return; // friendly error already appended
      ratchet = boot.ratchet;
      bootstrap = boot.header;
    }

    // Derive the next sending message key and seal.
    final Uint8List mk = await ratchet.nextSendKey();
    final ({Envelope envelope, List<int> signature}) sealed =
        await Envelope.seal(
      sign: keys.sign,
      senderDevId: senderDev,
      recipientDevId: recipDev,
      ratchetPub: ratchet.dhSendPub,
      msgNumber: ratchet.nSend - 1, // nextSendKey already incremented
      prevChainLen: ratchet.pn,
      messageKey: mk,
      plaintext: utf8.encode(text),
      bootstrap: bootstrap,
    );

    // Persist the advanced ratchet BEFORE we send — if delivery fails the
    // outbox replays with the same envelope, not a re-encrypted one.
    await _db!.saveRatchet(peer, ratchet);

    final Uint8List envBytes = sealed.envelope.toBytes();
    final Uint8List sig = Uint8List.fromList(sealed.signature);

    await _db!.insertOutgoing(
      id: clientId,
      peerDeviceId: peer,
      envelope: envBytes,
      plaintext: text,
    );
    _appendLocal(MessageDirection.outgoing, text);

    final Map<String, dynamic> ev = <String, dynamic>{
      'type': 'message.send',
      'id': clientId,
      'data': <String, dynamic>{
        'client_id': clientId,
        'recipient_device_id': peer,
        'envelope': base64Encode(envBytes),
        'signature': base64Encode(sig),
      },
    };

    if (state.connected && _ws != null) {
      _ws!.send(ev);
    } else {
      await _db!.enqueueOutbox(
        clientId: clientId,
        recipientDeviceId: peer,
        envelope: envBytes,
        signature: sig,
      );
    }
  }

  /// Calls GET /v1/admin-devices/active and returns the most-recently-seen
  /// device id, or null if none are online.
  Future<String?> _resolveActiveAdminDevice() async {
    try {
      final r = await _api.get('/v1/admin-devices/active');
      if (r.statusCode != 200) return null;
      final List<dynamic> list =
          ((r.data as Map?)?['devices'] as List<dynamic>?) ?? const <dynamic>[];
      if (list.isEmpty) return null;
      return ((list.first as Map).cast<String, dynamic>())['device_id']
          as String?;
    } catch (_) {
      return null;
    }
  }

  /// Fetches the peer's prekey bundle, verifies the signed prekey,
  /// runs X3DH initiator, builds the matching bootstrap header. The caller
  /// is expected to seal one envelope with this header — subsequent
  /// messages in the session use type-0 envelopes.
  Future<_Bootstrapped?> _bootstrapSessionTo(
      String peerDeviceId, IdentityKeys keys) async {
    final r = await _api.get('/v1/prekeys/$peerDeviceId');
    if (r.statusCode != 200) {
      _appendLocal(MessageDirection.outgoing,
          '(could not fetch admin prekey bundle: HTTP ${r.statusCode})');
      return null;
    }
    final Map<String, dynamic> bundle =
        (r.data as Map).cast<String, dynamic>();

    final Uint8List peerIdEd =
        Uint8List.fromList(base64Decode(bundle['identity_ed25519'] as String));
    final Uint8List peerIdX =
        Uint8List.fromList(base64Decode(bundle['identity_x25519'] as String));
    final Map<String, dynamic> spk =
        (bundle['signed_prekey'] as Map).cast<String, dynamic>();
    final int spkId = spk['id'] as int;
    final Uint8List spkPub =
        Uint8List.fromList(base64Decode(spk['pubkey'] as String));
    final Uint8List spkSig =
        Uint8List.fromList(base64Decode(spk['signature'] as String));

    if (!await verifySignedPrekey(
      signedPrekeyPub: spkPub,
      signature: spkSig,
      identityEd25519Pub: peerIdEd,
    )) {
      _appendLocal(MessageDirection.outgoing,
          '(admin prekey signature failed — refusing to send)');
      return null;
    }

    int opkId = 0;
    Uint8List? opkPub;
    if (bundle['one_time_prekey'] != null) {
      final Map<String, dynamic> opk =
          (bundle['one_time_prekey'] as Map).cast<String, dynamic>();
      opkId = opk['id'] as int;
      opkPub = Uint8List.fromList(base64Decode(opk['pubkey'] as String));
    }

    // X3DH initiate needs the X25519 *private* bytes. IdentityKeys
    // deliberately doesn't expose them through its public API — but
    // chat_controller is allowed to read its own keystore directly.
    // We keep that boundary narrow: the bytes are only read here and
    // are not stored anywhere beyond X3DH's internal HKDF.
    final List<int>? ourXPriv =
        await HardwareKeystore.I.readBytes('x25519_priv');
    if (ourXPriv == null) {
      _appendLocal(MessageDirection.outgoing,
          '(local identity not provisioned — sign out and back in)');
      return null;
    }

    final X3DHInitiateResult x3 = await x3dhInitiate(
      ourIdentityX25519Priv: Uint8List.fromList(ourXPriv),
      ourIdentityX25519Pub: keys.xPubBytes,
      peerIdentityX25519Pub: peerIdX,
      peerSignedPrekeyPub: spkPub,
      peerOneTimePrekeyPub: opkPub,
    );

    final DoubleRatchet ratchet = await DoubleRatchet.initiator(
      sharedSecret: x3.sharedSecret,
      peerSignedPrekey: spkPub,
    );

    // Stash the peer's identity Ed25519 so we can verify the signatures on
    // their later type-0 replies.
    await HardwareKeystore.I
        .writeBytes('peer_ed25519_$peerDeviceId', peerIdEd);

    final BootstrapHeader header = BootstrapHeader(
      identityEd25519: keys.edPubBytes,
      identityX25519: keys.xPubBytes,
      ephemeralX25519: x3.ephemeralX25519Pub,
      signedPrekeyId: spkId,
      oneTimePrekeyId: opkId,
    );

    return _Bootstrapped(ratchet: ratchet, header: header);
  }

  Future<void> _flushOutbox() async {
    if (_db == null) return;
    final List<Map<String, Object?>> pending = await _db!.outboxPending();
    for (final Map<String, Object?> row in pending) {
      _ws?.send(<String, dynamic>{
        'type': 'message.send',
        'id': row['client_id'],
        'data': <String, dynamic>{
          'client_id': row['client_id'],
          'recipient_device_id': row['recipient_device_id'],
          'envelope': base64Encode(row['envelope']! as List<int>),
          'signature': base64Encode(row['signature']! as List<int>),
        },
      });
    }
  }

  void _handleEvent(Map<String, dynamic> ev) {
    final String type = ev['type'] as String? ?? '';
    switch (type) {
      case 'message.persisted':
        final Map<String, dynamic> d = (ev['data'] as Map).cast<String, dynamic>();
        _db?.outboxDelete(d['client_id'] as String);
        _db?.markStatus(d['client_id'] as String, 'sent');
        break;
      case 'message.recv':
        // Decrypt the inbound envelope and append.
        unawaited(_handleIncoming(ev));
        break;
      case 'session.revoked':
        // Force logout — clear tokens, drop messages.
        unawaited(HardwareKeystore.I.wipe());
        break;
    }
  }

  Future<void> _handleIncoming(Map<String, dynamic> ev) async {
    final Map<String, dynamic> d =
        (ev['data'] as Map).cast<String, dynamic>();
    final String envB64 = d['envelope'] as String;
    final String sigB64 = d['signature'] as String? ?? '';
    final String senderDeviceId = d['sender_device_id'] as String? ?? '';

    final Uint8List envBytes = base64.decode(envB64);
    final Envelope env = Envelope.fromBytes(envBytes);
    final Uint8List signature = Uint8List.fromList(base64.decode(sigB64));

    if (env.isBootstrap) {
      // A peer is starting a NEW session with us. The MVP user-mobile is
      // initiator-only — admin devices reply within sessions the user
      // started. If we ever land here it means a misconfiguration or a
      // re-pairing flow we haven't built yet; surface the metadata
      // without claiming to decrypt.
      _appendLocal(MessageDirection.incoming,
          '[bootstrap from $senderDeviceId · cannot decrypt — see /change-password flow]');
      return;
    }

    // Steady-state envelope: must already have a ratchet for this peer.
    final DoubleRatchet? ratchet = await _db!.loadRatchet(senderDeviceId);
    if (ratchet == null) {
      _appendLocal(MessageDirection.incoming,
          '[no session with $senderDeviceId — cannot decrypt]');
      return;
    }

    // Verify the signature against the peer identity we cached at
    // bootstrap time. Reject if it doesn't match the claimed sender —
    // the server is untrusted; only the peer's identity Ed25519 binds.
    final List<int>? peerEd =
        await HardwareKeystore.I.readBytes('peer_ed25519_$senderDeviceId');
    if (peerEd == null) {
      _appendLocal(MessageDirection.incoming,
          '[missing peer identity for $senderDeviceId]');
      return;
    }
    if (!await Envelope.verify(
      envelope: env,
      signature: signature,
      signerIdentityEd25519Pub: Uint8List.fromList(peerEd),
    )) {
      _appendLocal(MessageDirection.incoming,
          '[signature invalid from $senderDeviceId — discarded]');
      return;
    }

    // Detect a DH ratchet rotation. The peer rotates their dhSendPub on
    // every receive→send turn; ours rotates symmetrically on theirs.
    if (!_bytesEqual(env.ratchetPub, ratchet.dhRecvPub)) {
      await ratchet.ratchetReceive(env.ratchetPub);
    }
    final Uint8List mk = await ratchet.nextRecvKey();
    try {
      final List<int> pt = await Envelope.open(envelope: env, messageKey: mk);
      await _db!.saveRatchet(senderDeviceId, ratchet);
      final String text = utf8.decode(pt);
      await _db!.insertIncoming(
        id: const Uuid().v4(),
        peerDeviceId: senderDeviceId,
        envelope: envBytes,
        plaintext: text,
      );
      _appendLocal(MessageDirection.incoming, text);
    } catch (e) {
      _appendLocal(MessageDirection.incoming,
          '[decrypt failed: $e]');
    }
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  void _appendLocal(MessageDirection dir, String text) {
    state = state.copyWith(
      messages: <ChatMessage>[
        ChatMessage(
          id: const Uuid().v4(),
          direction: dir,
          plaintext: text,
          createdAt: DateTime.now(),
        ),
        ...state.messages,
      ],
    );
  }

  ChatMessage _fromRow(Map<String, Object?> r) => ChatMessage(
        id: r['id']! as String,
        direction: r['direction'] == 'out'
            ? MessageDirection.outgoing
            : MessageDirection.incoming,
        plaintext: (r['plaintext'] as String?) ?? '(encrypted)',
        createdAt: DateTime.fromMillisecondsSinceEpoch(r['created_at']! as int),
      );

  static Uint8List _toDevBytes(String id) {
    // Pack a textual device id (e.g. "dev_xxx") to 16 bytes via truncation+pad.
    final Uint8List out = Uint8List(16);
    final List<int> bytes = utf8.encode(id);
    for (int i = 0; i < 16 && i < bytes.length; i++) {
      out[i] = bytes[i];
    }
    return out;
  }
}

/// Return value of [ChatController._bootstrapSessionTo] — pairs the
/// freshly-initialized ratchet with the bootstrap header to attach to
/// the very first outgoing envelope.
class _Bootstrapped {
  _Bootstrapped({required this.ratchet, required this.header});
  final DoubleRatchet ratchet;
  final BootstrapHeader header;
}
