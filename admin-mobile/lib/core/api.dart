import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

/// Build with:
/// `flutter run --dart-define=API_BASE=https://api.kalkichat.example`
class AdminEnv {
  static const String apiBase = String.fromEnvironment(
    'API_BASE',
    defaultValue: 'https://api.kalkichat.example',
  );
  static const List<String> spkiPins = <String>[
    String.fromEnvironment('SPKI_PIN_PRIMARY'),
    String.fromEnvironment('SPKI_PIN_BACKUP'),
  ];
}

final adminApiProvider = Provider<AdminApi>((_) => AdminApi());

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
        try {
          await HttpCertificatePinning.check(
            serverURL: opts.uri.toString(),
            sha: SHA.SHA256,
            allowedSHAFingerprints: AdminEnv.spkiPins,
            timeout: 10,
          );
        } catch (e) {
          return h.reject(DioException(
            requestOptions: opts,
            type: DioExceptionType.badCertificate,
            message: 'pin: $e',
          ));
        }
        final String? cookie = await _ss.read(key: 'admin_session');
        if (cookie != null) opts.headers['Cookie'] = 'admin_session=$cookie';
        return h.next(opts);
      },
    ));
  }

  final Dio _dio;
  static const FlutterSecureStorage _ss = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  Future<Response<dynamic>> get(String path, [Map<String, dynamic>? q]) =>
      _dio.get<dynamic>(path, queryParameters: q);
  Future<Response<dynamic>> post(String path, Object? body) =>
      _dio.post<dynamic>(path, data: body);
  Future<Response<dynamic>> put(String path, Object? body) =>
      _dio.put<dynamic>(path, data: body);

  /// Persist the admin_session cookie returned by /admin/auth/totp.
  Future<void> saveSessionFromHeaders(Headers h) async {
    for (final String s in h['set-cookie'] ?? <String>[]) {
      final RegExpMatch? m = RegExp(r'admin_session=([^;]+)').firstMatch(s);
      if (m != null) {
        await _ss.write(key: 'admin_session', value: m.group(1));
      }
    }
  }

  Future<void> clearSession() => _ss.delete(key: 'admin_session');
}
