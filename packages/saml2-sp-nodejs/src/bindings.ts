// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The two front-channel bindings' encodings (SAML 2.0 Bindings, sections 3.4 and 3.5):
//
//   HTTP-Redirect  the message DEFLATEd, base64'd and put in the query; the signature, when there is one,
//                  is over the query string itself (SAMLRequest|SAMLResponse, RelayState, SigAlg), as
//                  the sender encoded it. That is why the receiving side needs the raw query string.
//   HTTP-POST      the message base64'd in a form field, posted by the browser; any signature is inside
//                  the XML.

import { sign, verify, type KeyObject, type X509Certificate } from 'node:crypto';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { SamlError } from './errors.ts';
import { RSA_SHA256, SIGNATURE_ALGORITHMS } from './signature.ts';
import { escapeXml } from './xml.ts';

const MAX_INFLATED = 1024 * 1024;

/** The query string for a message sent on HTTP-Redirect, signed with the service provider's key. */
export function redirectQuery(param: 'SAMLRequest' | 'SAMLResponse', xml: string, relayState: string | undefined, key: KeyObject): string {
  const parts = [`${param}=${encodeURIComponent(deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64'))}`];
  if (relayState !== undefined) parts.push(`RelayState=${encodeURIComponent(relayState)}`);
  parts.push(`SigAlg=${encodeURIComponent(RSA_SHA256)}`);
  const signed = parts.join('&');
  const signature = sign('sha256', Buffer.from(signed, 'utf8'), key).toString('base64');
  return `${signed}&Signature=${encodeURIComponent(signature)}`;
}

function decodeComponent(raw: string): string {
  try {
    return decodeURIComponent(raw.replace(/\+/g, '%20'));
  } catch (err) {
    throw new SamlError('binding', 'the query string is not validly percent-encoded', { cause: err });
  }
}

export interface RedirectMessage {
  xml: string;
  relayState: string | undefined;
  /** Whether the query carried a signature, which then verified. */
  signed: boolean;
}

/**
 * Reads a message received on HTTP-Redirect. A query signature, when present, is verified against
 * `certs`; one that does not verify is refused. Whether an unsigned message is acceptable is the
 * caller's decision.
 */
export function readRedirect(rawQuery: string, param: 'SAMLRequest' | 'SAMLResponse', certs: readonly X509Certificate[]): RedirectMessage {
  const raw = new Map<string, string>();
  for (const pair of rawQuery.replace(/^\?/, '').split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const name = decodeComponent(eq < 0 ? pair : pair.slice(0, eq));
    if (raw.has(name)) throw new SamlError('binding', `the query string carries ${name} twice`);
    raw.set(name, eq < 0 ? '' : pair.slice(eq + 1));
  }
  const message = raw.get(param);
  if (!message) throw new SamlError('binding', `the query string carries no ${param}`);
  let xml: string;
  try {
    xml = inflateRawSync(Buffer.from(decodeComponent(message), 'base64'), { maxOutputLength: MAX_INFLATED }).toString('utf8');
  } catch (err) {
    throw new SamlError('binding', `${param} is not a DEFLATE-encoded message`, { cause: err });
  }
  const relayState = raw.has('RelayState') ? decodeComponent(raw.get('RelayState')!) : undefined;

  const signature = raw.get('Signature');
  if (signature === undefined) return { xml, relayState, signed: false };
  const sigAlg = decodeComponent(raw.get('SigAlg') ?? '');
  const hash = SIGNATURE_ALGORITHMS[sigAlg];
  if (!hash) throw new SamlError('signature', `the query is signed with ${sigAlg || '(no SigAlg)'}, which is refused`);
  // The signed string is built from the values AS THEY ARRIVED, not re-encoded (Bindings 3.4.4.1).
  const signedParts = [`${param}=${message}`];
  if (raw.has('RelayState')) signedParts.push(`RelayState=${raw.get('RelayState')}`);
  signedParts.push(`SigAlg=${raw.get('SigAlg')}`);
  const data = Buffer.from(signedParts.join('&'), 'utf8');
  const sigBytes = Buffer.from(decodeComponent(signature), 'base64');
  for (const cert of certs) {
    if (verify(hash, data, cert.publicKey, sigBytes)) {
      return { xml, relayState, signed: true };
    }
  }
  throw new SamlError('signature', 'the query string signature does not verify against the identity provider\'s certificate');
}

/** Reads a base64 message received on HTTP-POST. */
export function readPost(value: string, param: string): string {
  const compact = value.replace(/\s+/g, '');
  if (!compact || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) throw new SamlError('binding', `${param} is not base64`);
  return Buffer.from(compact, 'base64').toString('utf8');
}

/**
 * The page that sends a message on HTTP-POST: a form the browser posts to `action`. It has a real
 * submit button, so it works with scripting off; with a `nonce` it also carries a one-line script, for
 * a Content-Security-Policy that allows that nonce, that submits it at once.
 */
export function postFormHtml(action: string, fields: Record<string, string>, options: { nonce?: string; title?: string } = {}): string {
  const inputs = Object.entries(fields)
    .map(([name, value]) => `<input type="hidden" name="${escapeXml(name)}" value="${escapeXml(value)}">`)
    .join('\n      ');
  const script = options.nonce
    ? `\n    <script nonce="${escapeXml(options.nonce)}">document.forms[0].submit();</script>`
    : '';
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>${escapeXml(options.title ?? 'Signing in')}</title></head>
  <body>
    <form method="post" action="${escapeXml(action)}">
      ${inputs}
      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>
      <button type="submit">Continue</button>
    </form>${script}
  </body>
</html>
`;
}
