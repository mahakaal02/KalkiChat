import 'dart:async';

import 'package:flutter/services.dart';

/// SPKI (SubjectPublicKeyInfo) certificate pinning that walks the full
/// TLS chain on every connection.
///
/// Unlike `http_certificate_pinning` (which only checks the leaf cert),
/// this plugin lets a connection pass when **any** cert in the chain —
/// leaf, any intermediate, or root — matches **any** of the allowed
/// SPKI fingerprints. That means you can pin to a stable intermediate
/// (e.g. Let's Encrypt R13's public key) and the APK survives every
/// leaf rotation without a rebuild.
///
/// Pin format: SHA-256 of the cert's DER-encoded `SubjectPublicKeyInfo`,
/// base64 encoded. Generate with:
///
/// ```bash
/// openssl s_client -connect <host>:443 -servername <host> -showcerts \
///   </dev/null 2>/dev/null \
/// | awk '/-----BEGIN CERTIFICATE-----/{p=1} p; /-----END CERTIFICATE-----/{p=0; print "---"}' \
/// | while IFS= read -r line; do printf '%s\n' "$line"; done \
/// | csplit -z -s -f /tmp/cert- -b '%02d.pem' - '/---/+1' '{*}'
/// for f in /tmp/cert-*.pem; do
///   echo "subject: $(openssl x509 -in "$f" -noout -subject)"
///   echo "  spki:  $(openssl x509 -in "$f" -pubkey -noout \
///                   | openssl pkey -pubin -outform DER \
///                   | openssl dgst -sha256 -binary | base64)"
/// done
/// ```
class SchatCertPinning {
  SchatCertPinning._();

  static const MethodChannel _channel = MethodChannel('io.schat/cert_pinning');

  /// Performs a TLS handshake to [serverURL], walks the resulting cert
  /// chain, and returns iff at least one cert's SPKI sha256 (base64)
  /// appears in [allowedSpkiSha256Base64].
  ///
  /// Throws a [PlatformException] otherwise. Specific error codes:
  ///   * `NO_INTERNET` — DNS / connect / handshake failed before chain
  ///     could be retrieved
  ///   * `PIN_MISMATCH` — handshake completed but no cert in the chain
  ///     matched any allowed pin. Message includes the actual chain
  ///     SPKI fingerprints so an operator can refresh pins.
  ///
  /// [timeoutSeconds] caps connect + handshake time (default 10 s). On
  /// timeout the call throws `NO_INTERNET` with a "timeout" message.
  static Future<void> check({
    required String serverURL,
    required List<String> allowedSpkiSha256Base64,
    int timeoutSeconds = 10,
  }) async {
    if (allowedSpkiSha256Base64.isEmpty) {
      throw ArgumentError('allowedSpkiSha256Base64 must not be empty');
    }
    await _channel.invokeMethod<void>('check', <String, Object?>{
      'url': serverURL,
      'pins': allowedSpkiSha256Base64,
      'timeoutSeconds': timeoutSeconds,
    });
  }
}
