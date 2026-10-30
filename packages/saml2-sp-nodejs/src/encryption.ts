// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Decrypting an <saml:EncryptedAssertion> or <saml:EncryptedID> (XML Encryption 1.1) with node:crypto
// alone. The content key is RSA-OAEP wrapped to this service provider's certificate; the content is
// AES-GCM or AES-CBC. RSA PKCS#1 v1.5 key transport is refused (it is the padding oracle XML Encryption
// was broken with), and so is an OAEP whose MGF1 hash differs from its digest, which node cannot do.

import { createDecipheriv, constants, privateDecrypt, type KeyObject } from 'node:crypto';
import { SamlError } from './errors.ts';
import { NS, attr, child, descendants, text } from './xml.ts';

const CIPHERS: Record<string, { name: string; gcm: boolean; keyLength: number }> = {
  'http://www.w3.org/2009/xmlenc11#aes128-gcm': { name: 'aes-128-gcm', gcm: true, keyLength: 16 },
  'http://www.w3.org/2009/xmlenc11#aes192-gcm': { name: 'aes-192-gcm', gcm: true, keyLength: 24 },
  'http://www.w3.org/2009/xmlenc11#aes256-gcm': { name: 'aes-256-gcm', gcm: true, keyLength: 32 },
  'http://www.w3.org/2001/04/xmlenc#aes128-cbc': { name: 'aes-128-cbc', gcm: false, keyLength: 16 },
  'http://www.w3.org/2001/04/xmlenc#aes192-cbc': { name: 'aes-192-cbc', gcm: false, keyLength: 24 },
  'http://www.w3.org/2001/04/xmlenc#aes256-cbc': { name: 'aes-256-cbc', gcm: false, keyLength: 32 },
};

const OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
const OAEP = 'http://www.w3.org/2009/xmlenc11#rsa-oaep';
const DIGESTS: Record<string, string> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 'sha1',
  'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
  'http://www.w3.org/2001/04/xmldsig-more#sha384': 'sha384',
  'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
};
const MGFS: Record<string, string> = {
  'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'sha1',
  'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'sha256',
  'http://www.w3.org/2009/xmlenc11#mgf1sha384': 'sha384',
  'http://www.w3.org/2009/xmlenc11#mgf1sha512': 'sha512',
};

function fail(message: string, cause?: unknown): never {
  throw new SamlError('decryption', message, cause === undefined ? {} : { cause });
}

function unwrapKey(encryptedKey: Element, key: KeyObject): Buffer {
  const method = child(encryptedKey, NS.xenc, 'EncryptionMethod');
  const alg = method ? attr(method, 'Algorithm') ?? '' : '';
  if (alg !== OAEP_MGF1P && alg !== OAEP) fail(`the content key is wrapped with ${alg || '(none)'}; only RSA-OAEP is accepted`);
  const digestMethod = method ? child(method, NS.ds, 'DigestMethod') : undefined;
  const digestAlg = digestMethod ? attr(digestMethod, 'Algorithm') : undefined;
  const digest = digestAlg ? DIGESTS[digestAlg] : 'sha1';
  if (!digest) fail(`the OAEP digest ${digestAlg} is not supported`);
  let mgf = 'sha1';
  if (alg === OAEP && method) {
    const mgfEl = child(method, NS.xenc11, 'MGF');
    const mgfAlg = mgfEl ? attr(mgfEl, 'Algorithm') : undefined;
    if (mgfAlg) mgf = MGFS[mgfAlg] ?? fail(`the OAEP mask generation function ${mgfAlg} is not supported`);
  }
  if (mgf !== digest) fail(`OAEP with digest ${digest} and MGF1 ${mgf} is not supported; node:crypto uses one hash for both`);
  const cipherValue = descendants(encryptedKey, NS.xenc, 'CipherValue')[0];
  try {
    return privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: digest }, Buffer.from(text(cipherValue), 'base64'));
  } catch (err) {
    return fail('the content key could not be unwrapped with this service provider\'s key', err);
  }
}

/**
 * Decrypts the `<xenc:EncryptedData>` inside `encrypted` (an EncryptedAssertion or EncryptedID) and
 * returns the plaintext XML. The wrapped content key is looked for inside the EncryptedData's KeyInfo
 * and, as many identity providers place it, beside the EncryptedData.
 */
export function decryptElement(encrypted: Element, key: KeyObject): string {
  const data = child(encrypted, NS.xenc, 'EncryptedData');
  if (!data) fail(`<${encrypted.localName}> has no EncryptedData`);
  const method = child(data, NS.xenc, 'EncryptionMethod');
  const cipher = CIPHERS[method ? attr(method, 'Algorithm') ?? '' : ''];
  if (!cipher) fail(`the content is encrypted with ${method ? attr(method, 'Algorithm') : '(none)'}, which is not supported`);
  const encryptedKey = descendants(encrypted, NS.xenc, 'EncryptedKey')[0];
  if (!encryptedKey) fail(`<${encrypted.localName}> carries no EncryptedKey`);
  const contentKey = unwrapKey(encryptedKey, key);
  if (contentKey.length !== cipher.keyLength) fail(`the content key is ${contentKey.length} bytes; ${cipher.name} needs ${cipher.keyLength}`);

  const cipherData = child(data, NS.xenc, 'CipherData');
  const bytes = Buffer.from(text(cipherData ? child(cipherData, NS.xenc, 'CipherValue') : undefined), 'base64');
  try {
    if (cipher.gcm) {
      if (bytes.length < 12 + 16) fail('the ciphertext is too short');
      const decipher = createDecipheriv(cipher.name, contentKey, bytes.subarray(0, 12)) as ReturnType<typeof createDecipheriv> & { setAuthTag(t: Buffer): void };
      decipher.setAuthTag(bytes.subarray(bytes.length - 16));
      return Buffer.concat([decipher.update(bytes.subarray(12, bytes.length - 16)), decipher.final()]).toString('utf8');
    }
    if (bytes.length < 32 || bytes.length % 16) fail('the ciphertext is not a whole number of blocks');
    const decipher = createDecipheriv(cipher.name, contentKey, bytes.subarray(0, 16));
    decipher.setAutoPadding(false);
    const plain = Buffer.concat([decipher.update(bytes.subarray(16)), decipher.final()]);
    // XML Encryption's padding: the last byte is the pad length; the pad bytes themselves are arbitrary.
    const pad = plain[plain.length - 1] ?? 0;
    if (pad < 1 || pad > 16) fail('the decrypted content is not padded as XML Encryption pads it');
    return plain.subarray(0, plain.length - pad).toString('utf8');
  } catch (err) {
    if (err instanceof SamlError) throw err;
    return fail('the content could not be decrypted', err);
  }
}
