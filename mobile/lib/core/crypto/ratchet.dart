import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// A minimal Signal-style Double Ratchet. Per chat-peer.
///
/// State is `(rk, ckSend, ckRecv, dhSend, dhRecvPub, nSend, nRecv, pn)`.
/// Each message key is derived via HKDF over the chain key, then the chain
/// advances. A DH ratchet step happens on receiving a message whose
/// `ratchetPub` differs from the cached `dhRecvPub`.
///
/// Persistence: callers serialize/deserialize via [toMap]/[fromMap].
class DoubleRatchet {
  DoubleRatchet({
    required this.rootKey,
    required this.sendChainKey,
    required this.recvChainKey,
    required this.dhSendPriv,
    required this.dhSendPub,
    required this.dhRecvPub,
    this.nSend = 0,
    this.nRecv = 0,
    this.pn = 0,
  });

  Uint8List rootKey;
  Uint8List sendChainKey;
  Uint8List recvChainKey;
  Uint8List dhSendPriv;
  Uint8List dhSendPub;
  Uint8List dhRecvPub;
  int nSend;
  int nRecv;
  int pn;

  /// Derive next sending message key & advance chain.
  Future<Uint8List> nextSendKey() async {
    final List<int> mk = await _kdfChain(sendChainKey, _msgInfo);
    sendChainKey = Uint8List.fromList(await _kdfChain(sendChainKey, _chainInfo));
    nSend++;
    return Uint8List.fromList(mk);
  }

  /// Derive next receiving message key & advance chain.
  Future<Uint8List> nextRecvKey() async {
    final List<int> mk = await _kdfChain(recvChainKey, _msgInfo);
    recvChainKey = Uint8List.fromList(await _kdfChain(recvChainKey, _chainInfo));
    nRecv++;
    return Uint8List.fromList(mk);
  }

  /// Perform a DH ratchet step on receiving a message with a new peer pub.
  Future<void> ratchetReceive(Uint8List newPeerPub) async {
    final X25519 x = X25519();
    final SimpleKeyPairData kp = SimpleKeyPairData(
      dhSendPriv,
      publicKey: SimplePublicKey(dhSendPub, type: KeyPairType.x25519),
      type: KeyPairType.x25519,
    );
    final SecretKey dh1 = await x.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(newPeerPub, type: KeyPairType.x25519),
    );
    final List<int> dh1Bytes = await dh1.extractBytes();
    final (Uint8List rk1, Uint8List ckRecv) =
        await _rootKdf(rootKey, dh1Bytes);

    // Generate new sending DH and second root step.
    final SimpleKeyPair newKp = await x.newKeyPair();
    final SimpleKeyPairData newData = await newKp.extract();
    final SimplePublicKey newPub = await newKp.extractPublicKey();
    final SecretKey dh2 = await x.sharedSecretKey(
      keyPair: newKp,
      remotePublicKey: SimplePublicKey(newPeerPub, type: KeyPairType.x25519),
    );
    final List<int> dh2Bytes = await dh2.extractBytes();
    final (Uint8List rk2, Uint8List ckSend) =
        await _rootKdf(rk1, dh2Bytes);

    pn = nSend;
    nSend = 0;
    nRecv = 0;
    rootKey = rk2;
    recvChainKey = ckRecv;
    sendChainKey = ckSend;
    dhSendPriv = Uint8List.fromList(newData.bytes);
    dhSendPub = Uint8List.fromList(newPub.bytes);
    dhRecvPub = newPeerPub;
  }

  Map<String, dynamic> toMap() => <String, dynamic>{
        'rk': rootKey,
        'cks': sendChainKey,
        'ckr': recvChainKey,
        'dhsP': dhSendPriv,
        'dhsB': dhSendPub,
        'dhrB': dhRecvPub,
        'ns': nSend,
        'nr': nRecv,
        'pn': pn,
      };

  static DoubleRatchet fromMap(Map<String, dynamic> m) => DoubleRatchet(
        rootKey: Uint8List.fromList(m['rk'] as List<int>),
        sendChainKey: Uint8List.fromList(m['cks'] as List<int>),
        recvChainKey: Uint8List.fromList(m['ckr'] as List<int>),
        dhSendPriv: Uint8List.fromList(m['dhsP'] as List<int>),
        dhSendPub: Uint8List.fromList(m['dhsB'] as List<int>),
        dhRecvPub: Uint8List.fromList(m['dhrB'] as List<int>),
        nSend: m['ns'] as int,
        nRecv: m['nr'] as int,
        pn: m['pn'] as int,
      );
}

const List<int> _msgInfo = <int>[0x01];
const List<int> _chainInfo = <int>[0x02];

Future<List<int>> _kdfChain(List<int> ck, List<int> info) async {
  final Hmac hmac = Hmac.sha256();
  final Mac mac = await hmac.calculateMac(info, secretKey: SecretKey(ck));
  return mac.bytes;
}

Future<(Uint8List, Uint8List)> _rootKdf(List<int> rk, List<int> dh) async {
  final Hkdf kdf = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
  final SecretKey out = await kdf.deriveKey(
    secretKey: SecretKey(dh),
    nonce: rk,
    info: const <int>[0x6B, 0x61, 0x6C, 0x6B, 0x69, 0x2D, 0x72, 0x6F, 0x6F, 0x74], // "kalki-root"
  );
  final List<int> bytes = await out.extractBytes();
  return (
    Uint8List.fromList(bytes.sublist(0, 32)),
    Uint8List.fromList(bytes.sublist(32)),
  );
}
