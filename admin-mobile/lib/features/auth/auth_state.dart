import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Ephemeral state carried between the login screen (email + password) and
/// the TOTP screen (TOTP code + device registration). The values live in
/// memory only and are cleared as soon as `/v1/admin/devices/register`
/// returns successfully or the user navigates away.
///
/// Why hold the password in memory across two screens?
///
/// `/v1/admin/devices/register` is a single-round-trip call that takes
/// email + password + TOTP code + device keys all together. Asking the
/// admin to retype the password on the TOTP screen would be hostile;
/// keeping a short-lived in-memory copy is the standard pattern.
class PendingAdminAuth {
  const PendingAdminAuth({required this.email, required this.password});
  final String email;
  final String password;
}

/// `null` means the login screen hasn't run yet (or its credentials were
/// cleared by a successful register or a sign-out).
final pendingAdminAuthProvider =
    StateProvider<PendingAdminAuth?>((_) => null);
