// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The self-signed certificate's serial number is a minimal, positive DER INTEGER. Clearing only the
// top bit of 16 random bytes left a non-minimal leading zero whenever the first byte came out 0x00
// and the second below 0x80 (X.690 8.3.2), and OpenSSL refused that certificate ("illegal padding")
// about one time in 256.

import assert from 'node:assert/strict';
import { randomBytes, X509Certificate } from 'node:crypto';
import { describe, it } from 'node:test';
import { certificateSerial, selfSignedKeyPair } from '../src/x509.ts';

/** The serial INTEGER's content octets, read from the certificate's DER. */
function encodedSerial(der: Buffer): Buffer {
  // Certificate SEQUENCE, then tbsCertificate SEQUENCE, each with a long-form length.
  let at = 0;
  for (let i = 0; i < 2; i += 1) {
    assert.equal(der[at], 0x30);
    const first = der[at + 1]!;
    at += 2 + (first < 0x80 ? 0 : first & 0x7f);
  }
  // version [0] EXPLICIT INTEGER 2, then the serial INTEGER.
  assert.deepEqual(der.subarray(at, at + 5), Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]));
  at += 5;
  assert.equal(der[at], 0x02);
  const length = der[at + 1]!;
  return der.subarray(at + 2, at + 2 + length);
}

/** A DER INTEGER that is positive and minimal (X.690 8.3.2, RFC 5280 4.1.2.2). */
function assertMinimalPositive(serial: Buffer): void {
  assert.ok(serial.length >= 1 && serial.length <= 20, `serial is 1 to 20 octets, not ${serial.length}`);
  assert.equal(serial[0]! & 0x80, 0, 'serial is positive');
  if (serial.length > 1) {
    assert.ok(!(serial[0] === 0x00 && serial[1]! < 0x80), 'serial has no superfluous leading zero');
  }
  assert.ok(serial.some((b) => b !== 0), 'serial is not zero');
}

describe('the certificate serial number', () => {
  it('is a minimal positive INTEGER whatever the first two random bytes are', () => {
    for (let a = 0; a < 256; a += 1) {
      for (let b = 0; b < 256; b += 1) {
        const random = Buffer.alloc(16, 0);
        random[0] = a;
        random[1] = b;
        const serial = certificateSerial(random);
        assert.equal(serial.length, 16);
        assertMinimalPositive(serial);
      }
    }
  });

  it('makes a certificate OpenSSL parses when the random bytes start 0x00 then below 0x80', () => {
    const forced = (size: number) => {
      const bytes = Buffer.alloc(size, 0x11);
      bytes[0] = 0x00;
      bytes[1] = 0x05;
      return bytes;
    };
    const pair = selfSignedKeyPair({ commonName: 'serial', bits: 2048 }, forced);
    const parsed = new X509Certificate(pair.certificatePem);
    assert.ok(parsed.verify(parsed.publicKey));
    assertMinimalPositive(encodedSerial(parsed.raw));
    assert.equal(parsed.serialNumber.length, 32);
  });

  it('makes 2000 certificates that all parse, every first random byte among them', () => {
    for (let i = 0; i < 2000; i += 1) {
      // Every first byte about eight times, the rest random: a serial that started 0x00 then below
      // 0x80 used to fail here every run rather than one run in 256.
      const random = (size: number) => {
        const bytes = randomBytes(size);
        bytes[0] = i & 0xff;
        return bytes;
      };
      // A small key keeps 2000 key generations quick; the serial does not depend on it.
      const pair = selfSignedKeyPair({ commonName: `serial ${i}`, bits: 512 }, random);
      const parsed = new X509Certificate(pair.certificatePem);
      assertMinimalPositive(encodedSerial(parsed.raw));
    }
  });
});
