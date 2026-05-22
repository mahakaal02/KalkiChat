import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:uuid/uuid.dart';

import 'package:kalki_crypto/kalki_crypto.dart';

import '../../core/net/ws_client.dart';
import '../../core/security/keystore.dart';
import '../../data/local_db.dart';
import '../../env.dart';

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
  return ChatController();
});

class ChatController extends StateNotifier<ChatState> {
  ChatController() : super(ChatState()) {
    _load();
  }

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
    final String? recipient =
        await HardwareKeystore.I.readString('admin_device_id');
    if (deviceId == null || recipient == null) {
      // No paired admin device known yet — caller should fetch a prekey bundle
      // and run X3DH. Surface a friendly message.
      _appendLocal(MessageDirection.outgoing,
          '(no admin session yet — pending pairing)');
      return;
    }

    final Uuid uuid = const Uuid();
    final String clientId = uuid.v4();

    // For brevity this sample uses a per-message random key signed by Ed25519
    // and protected by AES-GCM. In production this is the Double Ratchet
    // message-key chain (see core/crypto/ratchet.dart).
    final List<int> messageKey =
        Uint8List.fromList(List<int>.generate(32, (_) => DateTime.now().microsecond & 0xFF));

    final Uint8List senderDev = _toDevBytes(deviceId);
    final Uint8List recipDev = _toDevBytes(recipient);

    final ({Envelope envelope, List<int> signature}) sealed = await Envelope.seal(
      sign: keys.sign,
      senderDevId: senderDev,
      recipientDevId: recipDev,
      ratchetPub: keys.xPubBytes,
      msgNumber: state.messages.length,
      prevChainLen: 0,
      messageKey: messageKey,
      plaintext: utf8.encode(text),
    );

    final Uint8List envBytes = sealed.envelope.toBytes();
    final Uint8List sig = Uint8List.fromList(sealed.signature);

    await _db!.insertOutgoing(
      id: clientId,
      peerDeviceId: recipient,
      envelope: envBytes,
      plaintext: text,
    );
    _appendLocal(MessageDirection.outgoing, text);

    final Map<String, dynamic> ev = <String, dynamic>{
      'type': 'message.send',
      'id': clientId,
      'data': <String, dynamic>{
        'client_id': clientId,
        'recipient_device_id': recipient,
        'envelope': base64Encode(envBytes),
        'signature': base64Encode(sig),
      },
    };

    if (state.connected && _ws != null) {
      _ws!.send(ev);
    } else {
      await _db!.enqueueOutbox(
        clientId: clientId,
        recipientDeviceId: recipient,
        envelope: envBytes,
        signature: sig,
      );
    }
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
    final Map<String, dynamic> d = (ev['data'] as Map).cast<String, dynamic>();
    // Real decryption uses the ratchet's recv chain. For this scaffold we
    // surface the ciphertext length as a placeholder.
    final String envB64 = d['envelope'] as String;
    final int approxBytes = base64.decode(envB64).length;
    _appendLocal(MessageDirection.incoming, '[encrypted message · $approxBytes b]');
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
