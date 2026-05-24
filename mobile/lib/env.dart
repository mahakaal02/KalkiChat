/// Build-time environment configuration.
///
/// **Defaults** are the production endpoints + cert pins so a plain
/// `flutter build apk --debug` produces an APK that talks to prod out
/// of the box (useful for tester APKs). Override any of these via
/// `--dart-define=KEY=VALUE` for local dev or staging:
///
///   flutter run \
///     --dart-define=API_BASE=http://10.0.2.2:8080 \
///     --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws \
///     --dart-define=DEV_ALLOW_HTTP=true
///
/// SPKI pin notes:
///   * PRIMARY is the LE R13 intermediate — stable for ~years.
///   * BACKUP is the current leaf — rotates every ~90 days when LE renews.
///   * If TLS handshakes start failing in the field, refresh both:
///       openssl s_client -connect kalki-chat-backend.cloud.podstack.ai:443 \
///         -servername kalki-chat-backend.cloud.podstack.ai -showcerts </dev/null \
///       (then SPKI sha256 extraction — see helm/schat/README.md)
class Env {
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE',
    defaultValue: 'https://kalki-chat-backend.cloud.podstack.ai',
  );

  static const String wsUrl = String.fromEnvironment(
    'WS_URL',
    defaultValue: 'wss://kalki-chat-backend.cloud.podstack.ai/v1/ws',
  );

  static const List<String> spkiPins = <String>[
    // PRIMARY — LE R13 intermediate SPKI (sha256, base64). Stable.
    String.fromEnvironment(
      'SPKI_PIN_PRIMARY',
      defaultValue: 'AlSQhgtJirc8ahLyekmtX+Iw+v46yPYRLJt9Cq1GlB0=',
    ),
    // BACKUP — current leaf SPKI for cloud.podstack.ai (rotates ~90d).
    String.fromEnvironment(
      'SPKI_PIN_BACKUP',
      defaultValue: 'TyR2l7eGIMRhcXuPTJTDCobMvwvlSR26TJHAm5ckR+s=',
    ),
  ];
}
