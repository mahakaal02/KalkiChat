import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:kalki_chat/core/crypto/envelope.dart';

void main() {
  test('envelope round-trips through binary form', () async {
    final Uint8List sender = Uint8List.fromList(List<int>.generate(16, (i) => i));
    final Uint8List recip = Uint8List.fromList(List<int>.generate(16, (i) => 16 + i));
    final Uint8List ratchet = Uint8List.fromList(List<int>.generate(32, (i) => i + 100));

    final env = Envelope(
      senderDevId: sender,
      recipientDevId: recip,
      ratchetPub: ratchet,
      msgNumber: 42,
      prevChainLen: 3,
      nonce: Uint8List.fromList(List<int>.generate(12, (i) => i)),
      ciphertext: Uint8List.fromList(List<int>.generate(48, (i) => i)),
    );

    final Uint8List bytes = env.toBytes();
    final Envelope back = Envelope.fromBytes(bytes);
    expect(back.msgNumber, 42);
    expect(back.prevChainLen, 3);
    expect(back.senderDevId, sender);
    expect(back.recipientDevId, recip);
    expect(back.ratchetPub, ratchet);
  });
}
