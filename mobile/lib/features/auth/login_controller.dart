import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/crypto/keys.dart';
import '../../core/net/api_client.dart';
import '../../core/security/keystore.dart';
import '../../env.dart';

final apiClientProvider = Provider<ApiClient>((_) {
  return ApiClient(baseUrl: Env.apiBaseUrl, spkiPins: Env.spkiPins);
});

final loginControllerProvider =
    StateNotifierProvider<LoginController, AsyncValue<void>>((ref) {
  return LoginController(ref.read(apiClientProvider));
});

class LoginController extends StateNotifier<AsyncValue<void>> {
  LoginController(this._api) : super(const AsyncData<void>(null));

  final ApiClient _api;

  Future<void> login({required String userId, required String password}) async {
    state = const AsyncLoading<void>();
    try {
      final IdentityKeys keys = await IdentityKeys.initOrLoad();

      final Map<String, dynamic> body = <String, dynamic>{
        'user_id': userId,
        'password': password,
        'device': <String, dynamic>{
          'name': await _deviceName(),
          'platform': _platform(),
          'identity_ed25519': base64Encode(keys.edPubBytes),
          'identity_x25519': base64Encode(keys.xPubBytes),
        },
      };

      final r = await _api.post('/v1/auth/login', body: body);
      if (r.statusCode != 200) {
        final Map<String, dynamic> err =
            ((r.data as Map?) ?? <String, dynamic>{}).cast<String, dynamic>();
        throw Exception(err['error']?.toString() ?? 'login failed');
      }
      final Map<String, dynamic> j = (r.data as Map).cast<String, dynamic>();
      await HardwareKeystore.I.writeString('access_token', j['access_token'] as String);
      await HardwareKeystore.I.writeString('refresh_token', j['refresh_token'] as String);
      await HardwareKeystore.I.writeString('device_id', j['device_id'] as String);
      state = const AsyncData<void>(null);
    } catch (e, s) {
      state = AsyncError<void>(e, s);
      rethrow;
    }
  }

  Future<String> _deviceName() async => 'KalkiChat ${_platform()}';
  String _platform() {
    // Avoid `dart:io` in a way that fails on web — but mobile always has it.
    return const String.fromEnvironment('PLATFORM', defaultValue: 'android');
  }
}
