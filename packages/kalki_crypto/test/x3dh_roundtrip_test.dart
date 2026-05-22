import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:kalki_crypto/kalki_crypto.dart';
import 'package:test/test.dart';

/// End-to-end protocol test.
///
/// Alice (initiator) and Bob (responder) each generate identity keypairs.
/// Bob also publishes a signed prekey + one one-time prekey. Alice fetches
/// the bundle, runs X3DH, builds a bootstrap envelope, sends. Bob receives,
/// runs X3DH responder, derives matching state, decrypts. They then
/// alternate replies — each rebuild and ratchet-advance — verifying that
/// the Double Ratchet stays in sync over many turns.
///
/// If this passes, the cryptographic core works end-to-end. The remaining
/// work in phase 2 is wiring this into the app message-send/receive paths.
void main() {
  test('seal/open round-trips a single message with a known key', () async {
    final _Party alice = await _Party.generate('alice');
    final Uint8List mk =
        Uint8List.fromList(List<int>.generate(32, (i) => i * 7 & 0xFF));
    final ({Envelope envelope, List<int> signature}) sealed =
        await Envelope.seal(
      sign: alice.sign,
      senderDevId: _padDev('a'),
      recipientDevId: _padDev('b'),
      ratchetPub: Uint8List.fromList(List<int>.generate(32, (i) => i)),
      msgNumber: 0,
      prevChainLen: 0,
      messageKey: mk,
      plaintext: utf8.encode('round-trip me'),
    );
    final List<int> got =
        await Envelope.open(envelope: sealed.envelope, messageKey: mk);
    expect(utf8.decode(got), 'round-trip me');
  });

  group('X3DH + Double Ratchet end-to-end', () {
    test(
        'bootstrap, alternating replies, message keys advance correctly with OPK',
        () async {
      final _Party alice = await _Party.generate('alice');
      final _Party bob = await _Party.generate('bob');

      final _SignedPrekey bobSpk = await bob.generateSignedPrekey(id: 1);
      final _OneTimePrekey bobOpk = await bob.generateOneTimePrekey(id: 17);

      // ---- 1. Alice verifies Bob's signed prekey ---------------------
      expect(
        await verifySignedPrekey(
          signedPrekeyPub: bobSpk.x25519Pub,
          signature: bobSpk.signature,
          identityEd25519Pub: bob.identityEd25519Pub,
        ),
        isTrue,
        reason: 'signed prekey verification must succeed before X3DH',
      );

      // ---- 2. Alice runs X3DH initiator -----------------------------
      final X3DHInitiateResult aliceX3dh = await x3dhInitiate(
        ourIdentityX25519Priv: alice.identityX25519Priv,
        ourIdentityX25519Pub: alice.identityX25519Pub,
        peerIdentityX25519Pub: bob.identityX25519Pub,
        peerSignedPrekeyPub: bobSpk.x25519Pub,
        peerOneTimePrekeyPub: bobOpk.x25519Pub,
      );

      // ---- 3. Bob runs X3DH responder, must derive identical SK -----
      final Uint8List bobSk = await x3dhResponder(
        ourIdentityX25519Priv: bob.identityX25519Priv,
        ourIdentityX25519Pub: bob.identityX25519Pub,
        ourSignedPrekeyPriv: bobSpk.x25519Priv,
        ourSignedPrekeyPub: bobSpk.x25519Pub,
        peerIdentityX25519Pub: alice.identityX25519Pub,
        peerEphemeralX25519Pub: aliceX3dh.ephemeralX25519Pub,
        ourOneTimePrekeyPriv: bobOpk.x25519Priv,
        ourOneTimePrekeyPub: bobOpk.x25519Pub,
      );
      expect(bobSk, equals(aliceX3dh.sharedSecret),
          reason: 'X3DH responder must derive the same shared secret');

      // ---- 4. Initialize ratchets -----------------------------------
      final DoubleRatchet aliceRatchet = await DoubleRatchet.initiator(
        sharedSecret: aliceX3dh.sharedSecret,
        peerSignedPrekey: bobSpk.x25519Pub,
      );
      final DoubleRatchet bobRatchet = DoubleRatchet.responder(
        sharedSecret: bobSk,
        signedPrekeyPriv: bobSpk.x25519Priv,
        signedPrekeyPub: bobSpk.x25519Pub,
      );

      // Sanity: Bob has not received yet, so his recvChain is still zero.
      // After ratchetReceive(alice.dhSendPub), Bob's recvChain should equal
      // the chain Alice already has in sendChain. We check that here so a
      // failure points exactly at the DH/HKDF arithmetic instead of the
      // surrounding GCM machinery.
      final DoubleRatchet bobPeek = DoubleRatchet.fromMap(bobRatchet.toMap());
      await bobPeek.ratchetReceive(aliceRatchet.dhSendPub);
      expect(bobPeek.recvChainKey, equals(aliceRatchet.sendChainKey),
          reason:
              'Bob.recvChainKey after first ratchetReceive must equal '
              'Alice.sendChainKey from her initiator() step');

      // ---- 5. Alice sends a bootstrap message -----------------------
      final Uint8List aliceDevId = _padDev('alice-device');
      final Uint8List bobDevId = _padDev('bob-device');

      final Uint8List firstMk = await aliceRatchet.nextSendKey();
      final ({Envelope envelope, List<int> signature}) sealed = await Envelope.seal(
        sign: alice.sign,
        senderDevId: aliceDevId,
        recipientDevId: bobDevId,
        ratchetPub: aliceRatchet.dhSendPub,
        msgNumber: 0,
        prevChainLen: 0,
        messageKey: firstMk,
        plaintext: utf8.encode('hello support, this is my first message'),
        bootstrap: BootstrapHeader(
          identityEd25519: alice.identityEd25519Pub,
          identityX25519: alice.identityX25519Pub,
          ephemeralX25519: aliceX3dh.ephemeralX25519Pub,
          signedPrekeyId: bobSpk.id,
          oneTimePrekeyId: bobOpk.id,
        ),
      );

      // Verify Alice's signature against the identity she claims (must be
      // her actual identity Ed25519 — anyone with the bundle could attempt
      // to send, but only the real Alice can sign).
      expect(
        await Envelope.verify(
          envelope: sealed.envelope,
          signature: sealed.signature,
          signerIdentityEd25519Pub: sealed.envelope.bootstrap!.identityEd25519,
        ),
        isTrue,
        reason: 'envelope signature must verify against the embedded identity',
      );

      // ---- 6. Bob processes the bootstrap, advances ratchet, decrypts
      // Bob's first incoming triggers a DH ratchet step with Alice's
      // freshly-generated dhSendPub, which derives the matching recv key.
      await bobRatchet.ratchetReceive(sealed.envelope.ratchetPub);
      final Uint8List bobRecvMk0 = await bobRatchet.nextRecvKey();
      // Diagnostic: the message keys themselves must match.
      expect(_hex(bobRecvMk0), equals(_hex(firstMk)),
          reason: 'Bob.nextRecvKey() must equal Alice.nextSendKey() for the first message');
      final List<int> decrypted = await Envelope.open(
        envelope: sealed.envelope,
        messageKey: bobRecvMk0,
      );
      expect(utf8.decode(decrypted),
          equals('hello support, this is my first message'));

      // ---- 7. Bob replies — type-0 (no bootstrap header) ------------
      final Uint8List bobMk0 = await bobRatchet.nextSendKey();
      final ({Envelope envelope, List<int> signature}) bobReply =
          await Envelope.seal(
        sign: bob.sign,
        senderDevId: bobDevId,
        recipientDevId: aliceDevId,
        ratchetPub: bobRatchet.dhSendPub,
        msgNumber: 0,
        prevChainLen: 0,
        messageKey: bobMk0,
        plaintext: utf8.encode('hi alice, support here'),
      );
      expect(bobReply.envelope.isBootstrap, isFalse);

      // ---- 8. Alice processes the reply -----------------------------
      // The ratchetPub on Bob's reply is new from Alice's POV (Bob's
      // ratchetReceive in step 6 rotated his sending DH), so Alice must
      // also rotate before decrypting.
      await aliceRatchet.ratchetReceive(bobReply.envelope.ratchetPub);
      final Uint8List aliceRecvMk = await aliceRatchet.nextRecvKey();
      final List<int> aliceGot = await Envelope.open(
        envelope: bobReply.envelope,
        messageKey: aliceRecvMk,
      );
      expect(utf8.decode(aliceGot), equals('hi alice, support here'));

      // ---- 9. Multiple turns, no extra DH rotations -----------------
      // Within a chain (one party sending consecutively), the chain key
      // advances per message and message keys MUST be unique.
      final Set<String> seenKeys = <String>{};
      seenKeys.add(_hex(firstMk));
      seenKeys.add(_hex(bobMk0));

      for (int i = 1; i <= 3; i++) {
        // Alice sends another message in her current sending chain.
        final Uint8List mk = await aliceRatchet.nextSendKey();
        expect(seenKeys.add(_hex(mk)), isTrue,
            reason: 'message keys must never repeat (turn $i, alice)');
        final ({Envelope envelope, List<int> signature}) e =
            await Envelope.seal(
          sign: alice.sign,
          senderDevId: aliceDevId,
          recipientDevId: bobDevId,
          ratchetPub: aliceRatchet.dhSendPub,
          msgNumber: i,
          prevChainLen: 1,
          messageKey: mk,
          plaintext: utf8.encode('alice msg $i'),
        );
        // Bob's receive path must detect a new ratchetPub and run a DH
        // ratchet step before pulling the message key. This is the
        // behaviour the Session class will encapsulate; in this hand-rolled
        // test we do it explicitly. On turn 1, Alice has rotated since
        // Bob's last receive (her own ratchetReceive on Bob's reply created
        // a fresh send DH); turns 2 and 3 stay within that same chain.
        if (!_bytesEqual(e.envelope.ratchetPub, bobRatchet.dhRecvPub)) {
          await bobRatchet.ratchetReceive(e.envelope.ratchetPub);
        }
        final Uint8List bobMk = await bobRatchet.nextRecvKey();
        final List<int> got =
            await Envelope.open(envelope: e.envelope, messageKey: bobMk);
        expect(utf8.decode(got), equals('alice msg $i'));
      }
    });

    test('X3DH without OPK still yields matching shared secret', () async {
      final _Party alice = await _Party.generate('alice');
      final _Party bob = await _Party.generate('bob');
      final _SignedPrekey bobSpk = await bob.generateSignedPrekey(id: 1);

      final X3DHInitiateResult aliceX3dh = await x3dhInitiate(
        ourIdentityX25519Priv: alice.identityX25519Priv,
        ourIdentityX25519Pub: alice.identityX25519Pub,
        peerIdentityX25519Pub: bob.identityX25519Pub,
        peerSignedPrekeyPub: bobSpk.x25519Pub,
      );
      final Uint8List bobSk = await x3dhResponder(
        ourIdentityX25519Priv: bob.identityX25519Priv,
        ourIdentityX25519Pub: bob.identityX25519Pub,
        ourSignedPrekeyPriv: bobSpk.x25519Priv,
        ourSignedPrekeyPub: bobSpk.x25519Pub,
        peerIdentityX25519Pub: alice.identityX25519Pub,
        peerEphemeralX25519Pub: aliceX3dh.ephemeralX25519Pub,
      );
      expect(bobSk, equals(aliceX3dh.sharedSecret));
    });

    test('verifySignedPrekey rejects forged signature', () async {
      final _Party real = await _Party.generate('real');
      final _Party attacker = await _Party.generate('attacker');
      final _SignedPrekey spk = await real.generateSignedPrekey(id: 1);

      // Sig is valid against real.identity, but if we hand verifier the
      // attacker's identity, it must reject.
      expect(
        await verifySignedPrekey(
          signedPrekeyPub: spk.x25519Pub,
          signature: spk.signature,
          identityEd25519Pub: attacker.identityEd25519Pub,
        ),
        isFalse,
      );
    });

    test('Envelope.verify rejects tampered ciphertext', () async {
      final _Party alice = await _Party.generate('alice');
      final ({Envelope envelope, List<int> signature}) sealed =
          await Envelope.seal(
        sign: alice.sign,
        senderDevId: _padDev('a'),
        recipientDevId: _padDev('b'),
        ratchetPub: Uint8List.fromList(List<int>.generate(32, (i) => i)),
        msgNumber: 0,
        prevChainLen: 0,
        messageKey: Uint8List.fromList(List<int>.generate(32, (_) => 7)),
        plaintext: utf8.encode('hello'),
      );

      // Flip a ciphertext byte — signature should no longer verify.
      final Uint8List tampered = Uint8List.fromList(sealed.envelope.ciphertext);
      tampered[0] ^= 0xFF;
      final Envelope evil = Envelope(
        senderDevId: sealed.envelope.senderDevId,
        recipientDevId: sealed.envelope.recipientDevId,
        ratchetPub: sealed.envelope.ratchetPub,
        msgNumber: sealed.envelope.msgNumber,
        prevChainLen: sealed.envelope.prevChainLen,
        nonce: sealed.envelope.nonce,
        ciphertext: tampered,
      );
      expect(
        await Envelope.verify(
          envelope: evil,
          signature: sealed.signature,
          signerIdentityEd25519Pub: alice.identityEd25519Pub,
        ),
        isFalse,
      );
    });
  });
}

// ============================================================================
// Helpers
// ============================================================================

class _Party {
  _Party._(
    this.name,
    this.identityEd25519Pub,
    this.identityEd25519Priv,
    this.identityX25519Pub,
    this.identityX25519Priv,
  );

  final String name;
  final Uint8List identityEd25519Pub;
  final Uint8List identityEd25519Priv;
  final Uint8List identityX25519Pub;
  final Uint8List identityX25519Priv;

  static Future<_Party> generate(String name) async {
    final SimpleKeyPair ed = await Ed25519().newKeyPair();
    final SimpleKeyPair x = await X25519().newKeyPair();
    final SimpleKeyPairData edData = await ed.extract();
    final SimpleKeyPairData xData = await x.extract();
    final SimplePublicKey edPub = await ed.extractPublicKey();
    final SimplePublicKey xPub = await x.extractPublicKey();
    return _Party._(
      name,
      Uint8List.fromList(edPub.bytes),
      Uint8List.fromList(edData.bytes),
      Uint8List.fromList(xPub.bytes),
      Uint8List.fromList(xData.bytes),
    );
  }

  Future<_SignedPrekey> generateSignedPrekey({required int id}) async {
    final SimpleKeyPair x = await X25519().newKeyPair();
    final SimpleKeyPairData data = await x.extract();
    final SimplePublicKey pub = await x.extractPublicKey();
    final Signature sig = await Ed25519().sign(
      pub.bytes,
      keyPair: SimpleKeyPairData(
        identityEd25519Priv,
        publicKey:
            SimplePublicKey(identityEd25519Pub, type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      ),
    );
    return _SignedPrekey(
      id: id,
      x25519Pub: Uint8List.fromList(pub.bytes),
      x25519Priv: Uint8List.fromList(data.bytes),
      signature: Uint8List.fromList(sig.bytes),
    );
  }

  Future<_OneTimePrekey> generateOneTimePrekey({required int id}) async {
    final SimpleKeyPair x = await X25519().newKeyPair();
    final SimpleKeyPairData data = await x.extract();
    final SimplePublicKey pub = await x.extractPublicKey();
    return _OneTimePrekey(
      id: id,
      x25519Pub: Uint8List.fromList(pub.bytes),
      x25519Priv: Uint8List.fromList(data.bytes),
    );
  }

  Future<List<int>> sign(List<int> message) async {
    final Signature s = await Ed25519().sign(
      message,
      keyPair: SimpleKeyPairData(
        identityEd25519Priv,
        publicKey:
            SimplePublicKey(identityEd25519Pub, type: KeyPairType.ed25519),
        type: KeyPairType.ed25519,
      ),
    );
    return s.bytes;
  }
}

class _SignedPrekey {
  _SignedPrekey({
    required this.id,
    required this.x25519Pub,
    required this.x25519Priv,
    required this.signature,
  });
  final int id;
  final Uint8List x25519Pub;
  final Uint8List x25519Priv;
  final Uint8List signature;
}

class _OneTimePrekey {
  _OneTimePrekey({
    required this.id,
    required this.x25519Pub,
    required this.x25519Priv,
  });
  final int id;
  final Uint8List x25519Pub;
  final Uint8List x25519Priv;
}

Uint8List _padDev(String s) {
  final Uint8List out = Uint8List(16);
  final List<int> bytes = utf8.encode(s);
  for (int i = 0; i < 16 && i < bytes.length; i++) {
    out[i] = bytes[i];
  }
  return out;
}

String _hex(List<int> b) =>
    b.map((int v) => v.toRadixString(16).padLeft(2, '0')).join();

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
