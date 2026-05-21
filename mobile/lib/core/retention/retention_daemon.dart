import 'dart:async';

import '../../data/local_db.dart';

/// Background task that deletes locally-cached ciphertext + plaintext older
/// than 30 days, then `VACUUM`s the sqlcipher DB so the pages are rewritten.
///
/// Runs at:
///   * App cold start (after splash).
///   * Every 6 hours while the process is alive (foreground or background).
class RetentionDaemon {
  RetentionDaemon._();
  static final RetentionDaemon I = RetentionDaemon._();

  static const Duration retention = Duration(days: 30);
  Timer? _timer;
  bool _running = false;

  Future<void> start() async {
    if (_running) return;
    _running = true;
    await _sweep();
    _timer = Timer.periodic(const Duration(hours: 6), (_) => _sweep());
  }

  Future<void> _sweep() async {
    final LocalDb db = await LocalDb.open();
    await db.purgeOlderThan(retention);
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
    _running = false;
  }
}
