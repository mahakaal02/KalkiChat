/// Public surface of the KalkiChat E2E crypto package.
///
/// Two apps consume this: the user mobile app (every chat) and the admin
/// companion-device app (support conversations). Keeping a single
/// implementation here avoids divergence in the most security-critical
/// code in the repo. Anything not exported below is internal to the
/// package and should not be imported across the boundary.
library kalki_crypto;

export 'src/envelope.dart' show Envelope;
export 'src/keys.dart' show IdentityKeys;
export 'src/ratchet.dart' show DoubleRatchet;
export 'src/storage.dart' show KeyStorage;
