import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../auth/login_controller.dart';

/// Opens WhatsApp via the `wa.me` deep-link, with prefilled admin number
/// and message. The link is fetched fresh from the backend each time, so
/// when an admin updates the config it takes effect for *every* future
/// click — Android, iOS, or web.
///
/// We never call the WhatsApp Business API.
class WhatsAppOnboarding {
  static Future<void> open(WidgetRef ref) async {
    final api = ref.read(apiClientProvider);
    final r = await api.get('/v1/onboarding/whatsapp-link');
    if (r.statusCode != 200) {
      throw Exception('Failed to load onboarding link');
    }
    final Map<String, dynamic> j = (r.data as Map).cast<String, dynamic>();
    final String waMeUrl = j['wa_me_url'] as String;
    final Uri uri = Uri.parse(waMeUrl);
    final bool ok = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!ok) {
      throw Exception('WhatsApp not installed?');
    }
  }
}
