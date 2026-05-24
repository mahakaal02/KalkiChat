/// Build-time environment configuration.
///
/// **Defaults** are the production endpoints + cert pins so a plain
/// `flutter build apk --release` produces an APK that talks to prod out
/// of the box (useful for tester APKs). Override any of these via
/// `--dart-define=KEY=VALUE` for local dev or staging:
///
///   flutter run \
///     --dart-define=API_BASE=http://10.0.2.2:8080 \
///     --dart-define=WS_URL=ws://10.0.2.2:8080/v1/ws \
///     --dart-define=DEV_ALLOW_HTTP=true
///
/// SPKI cert pinning
/// -----------------
/// The pin values are SHA-256 of cert SubjectPublicKeyInfo, base64.
/// The custom [SchatCertPinning] plugin (see packages/schat_cert_pinning/)
/// walks the **full TLS chain** on every connection and accepts iff *any*
/// cert's SPKI matches *any* allowed pin.
///
/// PRIMARY pins to the Let's Encrypt R13 INTERMEDIATE keypair, which is
/// stable for years. Leaf rotation (every ~60-90 days when certbot/Traefik
/// renews) doesn't affect us because the intermediate stays put.
///
/// BACKUP is the current leaf — pure belt-and-suspenders. If LE ever
/// rotates intermediates (rare, announced years in advance), the leaf
/// pin is the safety net until the APK is rebuilt with the new
/// intermediate pin.
///
/// To refresh pins after an intermediate rotation:
///   openssl s_client -connect kalki-chat-backend.cloud.podstack.ai:443 \
///     -servername kalki-chat-backend.cloud.podstack.ai -showcerts </dev/null \
///   | (extract each cert and compute SPKI sha256 — full pipeline in
///      packages/schat_cert_pinning/lib/schat_cert_pinning.dart docstring)
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
    // PRIMARY — LE R13 intermediate SPKI. STABLE FOR YEARS.
    String.fromEnvironment(
      'SPKI_PIN_PRIMARY',
      defaultValue: 'AlSQhgtJirc8ahLyekmtX+Iw+v46yPYRLJt9Cq1GlB0=',
    ),
    // BACKUP — current leaf SPKI for cloud.podstack.ai. Rotates every
    // ~90 days but the primary intermediate pin covers us through every
    // rotation, so this is a safety net not a hard requirement.
    String.fromEnvironment(
      'SPKI_PIN_BACKUP',
      defaultValue: 'G+NL1xCWI8JwTcCg6ze1z3a7jjHjblqPf0yYb1IOxuA=',
    ),
  ];
}
