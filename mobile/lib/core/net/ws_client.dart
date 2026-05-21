import 'dart:async';
import 'dart:convert';

import 'package:logger/logger.dart';
import 'package:web_socket_channel/io.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../security/keystore.dart';

typedef WsEventHandler = void Function(Map<String, dynamic> ev);

/// Reconnecting, JWT-authenticated WebSocket client.
class WsClient {
  WsClient({required this.url, required this.subprotocol});

  final Uri url;
  final String subprotocol;
  final Logger _log = Logger();

  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _sub;
  Timer? _reconnect;
  int _backoffMs = 1000;
  bool _closedByUser = false;
  WsEventHandler? _onEvent;

  Future<void> connect(WsEventHandler onEvent) async {
    _onEvent = onEvent;
    _closedByUser = false;
    await _open();
  }

  Future<void> _open() async {
    final String? token = await HardwareKeystore.I.readString('access_token');
    if (token == null) {
      _log.w('ws: no access token; aborting');
      return;
    }
    try {
      final IOWebSocketChannel ch = IOWebSocketChannel.connect(
        url,
        protocols: <String>[subprotocol],
        headers: <String, String>{'Authorization': 'Bearer $token'},
        pingInterval: const Duration(seconds: 25),
      );
      _channel = ch;
      _sub = ch.stream.listen(
        (dynamic data) {
          try {
            final Map<String, dynamic> j =
                (jsonDecode(data as String) as Map).cast<String, dynamic>();
            _onEvent?.call(j);
          } catch (e) {
            _log.w('ws: bad frame: $e');
          }
        },
        onError: (Object e) {
          _log.w('ws error: $e');
          _scheduleReconnect();
        },
        onDone: () {
          _log.i('ws closed');
          _scheduleReconnect();
        },
        cancelOnError: true,
      );
      _backoffMs = 1000;
      _log.i('ws connected');
    } catch (e) {
      _log.w('ws open failed: $e');
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    if (_closedByUser) return;
    _reconnect?.cancel();
    final int delay = _backoffMs;
    _backoffMs = (_backoffMs * 2).clamp(1000, 30000);
    _reconnect = Timer(Duration(milliseconds: delay), _open);
  }

  void send(Map<String, dynamic> event) {
    final WebSocketChannel? ch = _channel;
    if (ch == null) {
      _log.w('ws: cannot send, no channel');
      return;
    }
    ch.sink.add(jsonEncode(event));
  }

  Future<void> close() async {
    _closedByUser = true;
    _reconnect?.cancel();
    await _sub?.cancel();
    await _channel?.sink.close();
    _channel = null;
  }
}
