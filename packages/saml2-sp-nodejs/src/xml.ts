// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The XML this module reads and writes. Every message is parsed here, and a document with a DOCTYPE is
// refused before the parser sees it: SAML never needs one, and a DTD is how entity expansion and
// external entities get in. Lookups are by namespace and local name, never by prefix, because the
// prefix is the sender's choice.

import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { SamlError } from './errors.ts';

export const NS = {
  samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  xenc11: 'http://www.w3.org/2009/xmlenc11#',
  soap: 'http://schemas.xmlsoap.org/soap/envelope/',
} as const;

export const BINDING = {
  redirect: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
  post: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
  artifact: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
  soap: 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
} as const;

export const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
export const CM_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

/** Parses a SAML message or metadata document. Throws `xml` on anything malformed or carrying a DTD. */
export function parseXml(text: string, what = 'the message'): Document {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    throw new SamlError('xml', `${what} carries a DOCTYPE or an entity declaration, which SAML never needs`);
  }
  const problems: string[] = [];
  const parser = new DOMParser({
    locator: {},
    errorHandler: {
      warning: () => {},
      error: (msg: string) => { problems.push(msg); },
      fatalError: (msg: string) => { problems.push(msg); },
    },
  });
  let doc: Document;
  try {
    doc = parser.parseFromString(text, 'application/xml') as unknown as Document;
  } catch (err) {
    throw new SamlError('xml', `${what} is not well-formed XML: ${(err as Error).message}`, { cause: err });
  }
  if (problems.length || !doc || !doc.documentElement) {
    throw new SamlError('xml', `${what} is not well-formed XML: ${problems[0] ?? 'no document element'}`);
  }
  return doc;
}

export function serialize(node: Node): string {
  return new XMLSerializer().serializeToString(node as never);
}

/** The element children of `el` with this namespace and local name. */
export function children(el: Element | Document, ns: string, local: string): Element[] {
  const out: Element[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1 && (n as Element).namespaceURI === ns && (n as Element).localName === local) out.push(n as Element);
  }
  return out;
}

/** The one child with this name, or undefined. More than one is refused: SAML never repeats these. */
export function child(el: Element, ns: string, local: string): Element | undefined {
  const found = children(el, ns, local);
  if (found.length > 1) throw new SamlError('validation', `<${el.localName}> has more than one <${local}>`);
  return found[0];
}

/** Every element below `el` (at any depth) with this namespace and local name. */
export function descendants(el: Element | Document, ns: string, local: string): Element[] {
  return Array.from(el.getElementsByTagNameNS(ns, local) as unknown as ArrayLike<Element>);
}

export function text(el: Element | undefined): string {
  return (el?.textContent ?? '').trim();
}

export function attr(el: Element, name: string): string | undefined {
  return el.hasAttribute(name) ? el.getAttribute(name) ?? undefined : undefined;
}

/** Refuses a document in which two elements share an ID: that is how a signature is made to point elsewhere. */
export function assertUniqueIds(doc: Document): void {
  const seen = new Set<string>();
  const all = doc.getElementsByTagName('*') as unknown as ArrayLike<Element>;
  for (let i = 0; i < all.length; i += 1) {
    const el = all[i]!;
    for (const name of ['ID', 'Id', 'id']) {
      const v = el.getAttribute(name);
      if (!v) continue;
      if (seen.has(v)) throw new SamlError('signature', `two elements carry the ID ${v}`);
      seen.add(v);
    }
  }
}

export function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/** A SAML ID: an NCName, so it starts with a letter or underscore. 160 random bits, as the core spec asks. */
export function newId(randomHex: string): string {
  return `_${randomHex}`;
}

/** The PEM body of a certificate as one base64 line, the form metadata and KeyInfo carry. */
export function pemBody(pem: string): string {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
}

/** A base64 certificate (as metadata carries it) as a PEM. */
export function toPem(base64: string): string {
  const body = base64.replace(/\s+/g, '');
  return `-----BEGIN CERTIFICATE-----\n${body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
}
