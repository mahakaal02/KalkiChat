/// Build-time environment configuration. Pass via `--dart-define`:
///
///   flutter run \
///     --dart-define=API_BASE=https://api.kalkichat.example \
///     --dart-define=SPKI_PIN_PRIMARY=AAAA... \
///     --dart-define=SPKI_PIN_BACKUP=BBBB... \
///     --dart-define=WS_URL=wss://api.kalkichat.example/v1/ws
class Env {
  static const String apiBaseUrl = String.fromEnvironment(
    'API_BASE',
    defaultValue: 'https://api.kalkichat.example',
  );

  static const String wsUrl = String.fromEnvironment(
    'WS_URL',
    defaultValue: 'wss://api.kalkichat.example/v1/ws',
  );

  static const List<String> spkiPins = <String>[
    String.fromEnvironment('SPKI_PIN_PRIMARY'),
    String.fromEnvironment('SPKI_PIN_BACKUP'),
  ];
}
