import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../security/keystore.dart';

/// Thin WebSocket wrapper for the admin companion device. Mirrors the
/// shape of `mobile/lib/core/net/ws_client.dart` so the two apps speak
/// the same protocol: the `kalki.v1` sub-protocol, line-delimited JSON,
/// each frame `{type, id?, data}`.
///
/// Auth: the backend's `/v1/ws` route is gated by `authMiddleware` which
/// expects a Bearer JWT. We read it from [AdminHardwareKeystore] on
/// `connect()` and append it as a `?token=...` query param — the WS
/// handshake doesn't carry `Authorization` headers cleanly across
/// browsers / proxies, so token-in-URL is the established pattern in
/// this codebase. The token is short-lived (15 min) so this is OK.
///
/// Reconnect policy: simple exponential backoff capped at 30s. Consumers
/// subscribe via [onEvent]; we don't expose the underlying stream so
/// reconnect can replace it transparently.
class AdminWsClient {
  AdminWsClient({required this.url, this.subprotocol = 'kalki.v1'});

  final Uri url;
  final String subprotocol;

  WebSocketChannel? _ch;
  StreamSubscription<dynamic>? _sub;
  bool _connected = false;
  bool _wantOpen = false;
  void Function(Map<String, dynamic>)? _onEvent;
  Duration _backoff = const Duration(seconds: 1);

  bool get isConnected => _connected;

  Future<void> connect(void Function(Map<String, dynamic>) onEvent) async {
    _wantOpen = true;
    _onEvent = onEvent;
    await _openOnce();
  }

  Future<void> _openOnce() async {
    final String? tok =
        await AdminHardwareKeystore.I.readString('access_token');
    if (tok == null || tok.isEmpty) {
      throw StateError('not signed in: no access_token in keystore');
    }
    final Uri authed =
        url.replace(queryParameters: <String, String>{...url.queryParameters, 'token': tok});
    try {
      _ch = WebSocketChannel.connect(authed, protocols: <String>[subprotocol]);
      _connected = true;
      _backoff = const Duration(seconds: 1);
      _sub = _ch!.stream.listen(
        (dynamic raw) {
          try {
            final Map<String, dynamic> ev =
                (json.decode(raw as String) as Map<String, dynamic>);
            _onEvent?.call(ev);
          } catch (_) {/* unparseable frame; drop */}
        },
        onError: (Object _) => _scheduleReconnect(),
        onDone: _scheduleReconnect,
        cancelOnError: true,
      );
    } catch (_) {
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    _connected = false;
    if (!_wantOpen) return;
    final Duration delay = _backoff;
    _backoff = _backoff * 2;
    if (_backoff > const Duration(seconds: 30)) {
      _backoff = const Duration(seconds: 30);
    }
    Future<void>.delayed(delay, _openOnce);
  }

  void send(Map<String, dynamic> ev) {
    if (!_connected || _ch == null) return;
    _ch!.sink.add(json.encode(ev));
  }

  Future<void> close() async {
    _wantOpen = false;
    await _sub?.cancel();
    await _ch?.sink.close();
    _connected = false;
  }
}
