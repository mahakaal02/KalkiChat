import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:schat_cert_pinning/schat_cert_pinning.dart';

import 'security/keystore.dart';

/// Build with:
/// `flutter run --dart-define=API_BASE=https://api.kalkichat.example`
class AdminEnv {
  // Production endpoints by default — a plain `flutter build apk --debug`
  // produces an APK that talks to prod. Override via --dart-define for
  // local dev (e.g. API_BASE=http://10.0.2.2:8080 + DEV_ALLOW_HTTP=true).
  static const String apiBase = String.fromEnvironment(
    'API_BASE',
    defaultValue: 'https://kalki-chat-backend.cloud.podstack.ai',
  );
  static const String wsUrl = String.fromEnvironment(
    'WS_URL',
    defaultValue: 'wss://kalki-chat-backend.cloud.podstack.ai/v1/ws',
  );
  // SPKI cert pins — SHA-256(SubjectPublicKeyInfo), base64.
  // The schat_cert_pinning plugin walks the full TLS chain and accepts
  // if any cert matches any pin, so pinning to the LE R13 intermediate
  // (stable for years) means leaf rotations don't break the APK. See
  // mobile/lib/env.dart for the full explanation.
  static const List<String> spkiPins = <String>[
    // PRIMARY — LE R13 intermediate. Stable for years.
    String.fromEnvironment(
      'SPKI_PIN_PRIMARY',
      defaultValue: 'AlSQhgtJirc8ahLyekmtX+Iw+v46yPYRLJt9Cq1GlB0=',
    ),
    // BACKUP — current leaf SPKI. Safety net only.
    String.fromEnvironment(
      'SPKI_PIN_BACKUP',
      defaultValue: 'G+NL1xCWI8JwTcCg6ze1z3a7jjHjblqPf0yYb1IOxuA=',
    ),
  ];

  /// Dev escape hatch matching the mobile app's DEV_ALLOW_HTTP. When set,
  /// disables SSL pinning so emulators can hit http://10.0.2.2:8080.
  /// MUST remain false in production builds.
  static const bool devAllowHttp =
      bool.fromEnvironment('DEV_ALLOW_HTTP', defaultValue: false);
}

final adminApiProvider = Provider<AdminApi>((_) => AdminApi());

/// HTTPS client for the admin companion-device app. Two authentication
/// modes coexist:
///
///   * Bearer JWT — what `/v1/admin/devices/register` returns. Used for
///     everything after first sign-in. Persisted in [AdminHardwareKeystore]
///     under `access_token`.
///   * `admin_session` cookie — legacy path used by the web admin
///     dashboard. Forwarded if present, so the same client can talk to
///     the web admin's cookie-gated routes during local development.
///
/// On every request: pin SHA-256, attach whichever credential is present.
class AdminApi {
  AdminApi()
      : _dio = Dio(BaseOptions(
          baseUrl: AdminEnv.apiBase,
          connectTimeout: const Duration(seconds: 10),
          receiveTimeout: const Duration(seconds: 20),
          headers: <String, String>{'Content-Type': 'application/json'},
          validateStatus: (int? s) => s != null && s < 500,
        )) {
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (RequestOptions opts, RequestInterceptorHandler h) async {
        if (!AdminEnv.devAllowHttp) {
          // Chain-walking SPKI pin check. See
          // packages/schat_cert_pinning/lib/schat_cert_pinning.dart.
          try {
            await SchatCertPinning.check(
              serverURL: opts.uri.toString(),
              allowedSpkiSha256Base64: AdminEnv.spkiPins,
              timeoutSeconds: 10,
            );
          } catch (e) {
            return h.reject(DioException(
              requestOptions: opts,
              type: DioExceptionType.badCertificate,
              message: 'pin: $e',
            ));
          }
        }
        // Prefer bearer (companion-device flow); fall back to cookie.
        final String? tok =
            await AdminHardwareKeystore.I.readString('access_token');
        if (tok != null && tok.isNotEmpty) {
          opts.headers['Authorization'] = 'Bearer $tok';
        } else {
          final String? cookie =
              await AdminHardwareKeystore.I.readString('admin_session');
          if (cookie != null) {
            opts.headers['Cookie'] = 'admin_session=$cookie';
          }
        }
        return h.next(opts);
      },
    ));
  }

  final Dio _dio;

  Future<Response<dynamic>> get(String path, [Map<String, dynamic>? q]) =>
      _dio.get<dynamic>(path, queryParameters: q);
  Future<Response<dynamic>> post(String path, Object? body) =>
      _dio.post<dynamic>(path, data: body);
  Future<Response<dynamic>> put(String path, Object? body) =>
      _dio.put<dynamic>(path, data: body);

  /// Persist the admin_session cookie returned by /admin/auth/totp. Only
  /// used by the legacy cookie-based flow; new sign-ins go through
  /// /v1/admin/devices/register and write `access_token` directly.
  Future<void> saveSessionFromHeaders(Headers h) async {
    for (final String s in h['set-cookie'] ?? <String>[]) {
      final RegExpMatch? m = RegExp(r'admin_session=([^;]+)').firstMatch(s);
      if (m != null && m.group(1) != null) {
        await AdminHardwareKeystore.I
            .writeString('admin_session', m.group(1)!);
      }
    }
  }

  Future<void> clearSession() async {
    await AdminHardwareKeystore.I.delete('admin_session');
    await AdminHardwareKeystore.I.delete('access_token');
    await AdminHardwareKeystore.I.delete('refresh_token');
    await AdminHardwareKeystore.I.delete('device_id');
    await AdminHardwareKeystore.I.delete('admin_id');
  }
}
