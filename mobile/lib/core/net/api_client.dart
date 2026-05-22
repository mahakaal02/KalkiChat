import 'dart:async';

import 'package:dio/dio.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

import '../security/keystore.dart';

/// HTTPS client with SSL pinning and JWT injection.
///
/// Pins are SPKI-SHA256 hashes embedded at build time. Two pins are required
/// so we can rotate the leaf without bricking installed apps. If neither pin
/// matches, the request is hard-failed — no soft fallback to system trust.
class ApiClient {
  ApiClient({
    required this.baseUrl,
    required this.spkiPins,
  }) : _dio = Dio(BaseOptions(
          baseUrl: baseUrl,
          connectTimeout: const Duration(seconds: 10),
          receiveTimeout: const Duration(seconds: 20),
          sendTimeout: const Duration(seconds: 20),
          headers: <String, String>{
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          validateStatus: (int? s) => s != null && s < 500,
        )) {
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (RequestOptions opts, RequestInterceptorHandler h) async {
        // Dev shortcut: plain HTTP has no TLS cert to pin. Guarded by an
        // explicit --dart-define=DEV_ALLOW_HTTP=true; defaults to off.
        const bool devAllowHttp = bool.fromEnvironment('DEV_ALLOW_HTTP');
        final bool isHttp = opts.uri.scheme == 'http';
        if (isHttp && !devAllowHttp) {
          return h.reject(DioException(
            requestOptions: opts,
            type: DioExceptionType.badCertificate,
            message: 'plain HTTP refused; pass --dart-define=DEV_ALLOW_HTTP=true for dev',
          ));
        }
        if (!isHttp) {
          // SSL pin check first (cheap, fail-fast).
          try {
            await HttpCertificatePinning.check(
              serverURL: opts.uri.toString(),
              sha: SHA.SHA256,
              allowedSHAFingerprints: spkiPins,
              timeout: 10,
            );
          } catch (e) {
            return h.reject(DioException(
              requestOptions: opts,
              type: DioExceptionType.badCertificate,
              message: 'SSL pin failure: $e',
            ));
          }
        }
        final String? token = await HardwareKeystore.I.readString('access_token');
        if (token != null && !opts.headers.containsKey('Authorization')) {
          opts.headers['Authorization'] = 'Bearer $token';
        }
        return h.next(opts);
      },
      onError: (DioException e, ErrorInterceptorHandler h) async {
        // 401 → try refresh once, replay.
        if (e.response?.statusCode == 401 &&
            e.requestOptions.extra['retried'] != true) {
          final bool refreshed = await _tryRefresh();
          if (refreshed) {
            e.requestOptions.extra['retried'] = true;
            try {
              final Response<dynamic> r = await _dio.fetch<dynamic>(e.requestOptions);
              return h.resolve(r);
            } catch (_) {}
          }
        }
        return h.next(e);
      },
    ));
  }

  final Dio _dio;
  final String baseUrl;
  final List<String> spkiPins;

  Future<Response<dynamic>> get(String path,
          {Map<String, dynamic>? query}) =>
      _dio.get<dynamic>(path, queryParameters: query);

  Future<Response<dynamic>> post(String path, {Object? body}) =>
      _dio.post<dynamic>(path, data: body);

  Future<Response<dynamic>> put(String path, {Object? body}) =>
      _dio.put<dynamic>(path, data: body);

  Future<bool> _tryRefresh() async {
    final String? rt = await HardwareKeystore.I.readString('refresh_token');
    if (rt == null) return false;
    try {
      final Response<dynamic> r = await _dio.post<dynamic>(
        '/v1/auth/refresh',
        data: <String, String>{'refresh_token': rt},
        options: Options(headers: <String, String>{'Authorization': ''}),
      );
      if (r.statusCode == 200 && r.data is Map) {
        final Map<String, dynamic> j = (r.data as Map).cast<String, dynamic>();
        await HardwareKeystore.I.writeString('access_token', j['access_token'] as String);
        await HardwareKeystore.I.writeString('refresh_token', j['refresh_token'] as String);
        return true;
      }
    } catch (_) {}
    return false;
  }
}
