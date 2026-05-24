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
/// **About the cert pins — important misnomer:**
///   The `spkiPins` name dates from when this code was intended to pin
///   to the SubjectPublicKeyInfo (the rotation-stable part of the cert
///   chain). The Dio interceptor we actually use — `http_certificate_pinning`
///   — does NOT do SPKI pinning. It hashes the **whole DER-encoded leaf
///   certificate** (`serverCertificates[0].encoded`) with SHA-256 and
///   formats it as **uppercase hex with no separators** (`%02X` per byte).
///   The library only ever checks the LEAF cert; intermediate hashes
///   would be ignored.
///
///   Net effect: these values must be regenerated on every Let's Encrypt
///   leaf rotation (currently set to expire **2026-07-31**, so plan an
///   APK rebuild before then). The "BACKUP" slot below is a forward-
///   compat placeholder — populate it with the *next* leaf hash if you
///   know it in advance (e.g. force-renew via certbot then capture).
///
///   To regenerate after a rotation:
///       openssl s_client -connect kalki-chat-backend.cloud.podstack.ai:443 \
///         -servername kalki-chat-backend.cloud.podstack.ai </dev/null 2>/dev/null \
///       | openssl x509 -outform DER 2>/dev/null \
///       | openssl dgst -sha256 -hex \
///       | awk '{print toupper($NF)}' | tr -d ':'
///
///   Tracking this misnamed variable is on the v2 todo list — switch to a
///   library that does real SPKI pinning (so we don't break every 90d).
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
    // PRIMARY — SHA-256 of the current LEAF cert (CN=cloud.podstack.ai),
    // uppercase hex, no separators. Expires 2026-07-31. Refresh before then.
    String.fromEnvironment(
      'SPKI_PIN_PRIMARY',
      defaultValue:
          'E5037E4421C077493BB270D3C635B26E066F4A16B5AEEEF1027CC20C19DAB613',
    ),
    // BACKUP — placeholder. Library only checks index 0 (leaf), so any
    // value here is effectively dead weight today. Reserved for when we
    // pre-stage the next leaf hash ahead of LE renewal.
    String.fromEnvironment(
      'SPKI_PIN_BACKUP',
      defaultValue:
          'E5037E4421C077493BB270D3C635B26E066F4A16B5AEEEF1027CC20C19DAB613',
    ),
  ];
}
