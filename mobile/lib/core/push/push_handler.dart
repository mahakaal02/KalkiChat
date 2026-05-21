import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:logger/logger.dart';

import '../net/api_client.dart';

/// FCM wake-up handler. Push payloads contain NO message content; they only
/// instruct the device "something arrived; come fetch it over TLS+JWT".
class PushHandler {
  PushHandler(this._api);
  final ApiClient _api;
  final Logger _log = Logger();

  Future<void> initialize() async {
    final FirebaseMessaging fm = FirebaseMessaging.instance;
    final NotificationSettings settings = await fm.requestPermission(
      alert: true, badge: true, sound: false, // no preview sound
    );
    _log.i('push perm: ${settings.authorizationStatus}');
    final String? token = await fm.getToken();
    if (token != null) {
      // POST the token to /v1/devices/me/push (omitted from this scaffold).
      _log.i('push token registered');
    }
    FirebaseMessaging.onMessage.listen((RemoteMessage m) async {
      // We don't display the FCM payload; we fetch the real envelope.
      final String? msgID = m.data['msg_id'] as String?;
      if (msgID == null) return;
      await _api.get('/v1/conversation/me', query: <String, dynamic>{'after': msgID});
    });
  }
}
