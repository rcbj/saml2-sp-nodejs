// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A self-signed certificate for a service provider's signing key, made with node:crypto alone (node can
// make keys but not certificates, and needing openssl on every machine would be a dependency). SAML uses
// the certificate only as a container for the public key, exchanged in metadata, so self-signed is the
// norm: nobody validates its chain. The DER is written by hand below; it is small.

import { generateKeyPairSync, randomBytes, sign, X509Certificate } from 'node:crypto';

function length(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const tlv = (tag: number, ...content: Buffer[]) => {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), length(body.length), body]);
};
const seq = (...c: Buffer[]) => tlv(0x30, ...c);
const set = (...c: Buffer[]) => tlv(0x31, ...c);

function oid(dotted: string): Buffer {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [a! * 40 + b!];
  for (const n of rest) {
    const chunk: number[] = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function time(d: Date): Buffer {
  // UTCTime up to 2049, GeneralizedTime from 2050 (RFC 5280 4.1.2.5).
  const iso = d.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
  return d.getUTCFullYear() < 2050 ? tlv(0x17, Buffer.from(iso.slice(2), 'ascii')) : tlv(0x18, Buffer.from(iso, 'ascii'));
}

const name = (cn: string) => seq(set(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(cn, 'utf8')))));
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));

export interface KeyPairOptions {
  /** The certificate's subject (and issuer) common name. */
  commonName: string;
  /** How long the certificate is valid for, in days. Default 1095 (three years). */
  days?: number;
  /** The RSA modulus length. Default 3072. */
  bits?: number;
}

export interface KeyPair {
  /** The private key, PKCS#8 PEM. */
  privateKeyPem: string;
  /** The self-signed certificate, PEM. */
  certificatePem: string;
  certificate: X509Certificate;
}

/** A new RSA key and a self-signed certificate for it, with the key usages SAML signing and encryption need. */
export function createSelfSignedKeyPair(options: KeyPairOptions): KeyPair {
  const days = options.days ?? 1095;
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: options.bits ?? 3072 });
  const serial = randomBytes(16);
  serial[0] = serial[0]! & 0x7f;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore.getTime() + days * 86_400_000);
  const extensions = tlv(0xa3, seq(
    // basicConstraints, critical: not a CA.
    seq(oid('2.5.29.19'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, seq())),
    // keyUsage, critical: digitalSignature and keyEncipherment.
    seq(oid('2.5.29.15'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, tlv(0x03, Buffer.from([0x05, 0xa0])))),
  ));
  const tbs = seq(
    tlv(0xa0, tlv(0x02, Buffer.from([0x02]))),
    tlv(0x02, serial),
    SHA256_RSA,
    name(options.commonName),
    seq(time(notBefore), time(notAfter)),
    name(options.commonName),
    publicKey.export({ type: 'spki', format: 'der' }),
    extensions,
  );
  const signature = sign('sha256', tbs, privateKey);
  const der = seq(tbs, SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const certificatePem = `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
  const certificate = new X509Certificate(certificatePem);
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string, certificatePem, certificate };
}
