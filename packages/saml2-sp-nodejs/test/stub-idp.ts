// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A stub SAML identity provider for the tests: it writes Responses the way an identity provider does,
// signs them with its own key, encrypts assertions, signs Redirect-binding query strings, and runs an
// artifact resolution service over plain HTTP that checks the service provider's signed ArtifactResolve.
// It shares no code with the library except xml-crypto, the signing engine.

import { createCipheriv, createHash, createPublicKey, publicEncrypt, randomBytes, sign, constants, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { deflateRawSync } from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
export const SP_KEY = fixture('sp.key');
export const SP_CERT = fixture('sp.crt');
export const IDP_KEY = fixture('idp.key');
export const IDP_CERT = fixture('idp.crt');

export const IDP_ENTITY = 'https://idp.test/saml2';
export const SP_ENTITY = 'https://sp.test/saml/metadata';
export const ACS = 'https://sp.test/saml/acs';

const body = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s+/g, '');
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
const id = () => `_${randomBytes(16).toString('hex')}`;

export function idpMetadata(arsUrl = 'https://idp.test/saml2/ars'): string {
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body(IDP_CERT)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="${arsUrl}" index="0" isDefault="true"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/saml2/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.test/saml2/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

export interface AssertionOptions {
  inResponseTo?: string | undefined;
  audience?: string;
  recipient?: string;
  notOnOrAfterMs?: number;
  issuer?: string;
  nameId?: string;
  /** Extra AttributeStatement content (e.g. an EncryptedAttribute). */
  extraAttributes?: string;
}

export function assertionXml(o: AssertionOptions = {}): { xml: string; id: string } {
  const aid = id();
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : '';
  const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${aid}" Version="2.0" IssueInstant="${iso(0)}">`
    + `<saml:Issuer>${o.issuer ?? IDP_ENTITY}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${o.nameId ?? 'alice-1234'}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${o.recipient ?? ACS}" NotOnOrAfter="${iso(o.notOnOrAfterMs ?? 300_000)}"${irt}/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(-5000)}" NotOnOrAfter="${iso(o.notOnOrAfterMs ?? 300_000)}"><saml:AudienceRestriction><saml:Audience>${o.audience ?? SP_ENTITY}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(-1000)}" SessionIndex="_session1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + `<saml:AttributeStatement><saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>`
    + `<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>${o.extraAttributes ?? ''}</saml:AttributeStatement>`
    + '</saml:Assertion>';
  return { xml, id: aid };
}

/** Signs the element with this ID, enveloped, right after its Issuer. */
export function signXml(xml: string, elementId: string, key = IDP_KEY, cert = IDP_CERT): string {
  const sig = new SignedXml({ privateKey: key, publicCert: cert, signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#' });
  sig.addReference({ xpath: `//*[@ID='${elementId}']`, transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'], digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
  sig.computeSignature(xml, { prefix: 'ds', location: { reference: `//*[@ID='${elementId}']/*[local-name(.)='Issuer']`, action: 'after' } });
  return sig.getSignedXml();
}

export function signedAssertion(o: AssertionOptions = {}): { xml: string; id: string } {
  const a = assertionXml(o);
  return { xml: signXml(a.xml, a.id), id: a.id };
}

/** Encrypts an assertion to the service provider's certificate, as EncryptedAssertion. */
export function encryptAssertion(assertion: string, cipher: 'aes-256-gcm' | 'aes-128-cbc' = 'aes-256-gcm', transport: 'mgf1p' | 'oaep256' = 'mgf1p', wrapper = 'EncryptedAssertion'): string {
  const key = randomBytes(cipher === 'aes-256-gcm' ? 32 : 16);
  let value: Buffer;
  let alg: string;
  if (cipher === 'aes-256-gcm') {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(assertion, 'utf8'), c.final()]);
    value = Buffer.concat([iv, ct, c.getAuthTag()]);
    alg = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
  } else {
    const iv = randomBytes(16);
    const c = createCipheriv('aes-128-cbc', key, iv);
    value = Buffer.concat([iv, c.update(assertion, 'utf8'), c.final()]);
    alg = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
  }
  const wrapped = publicEncrypt({ key: createPublicKey(new X509Certificate(SP_CERT).publicKey.export({ type: 'spki', format: 'pem' })), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: transport === 'mgf1p' ? 'sha1' : 'sha256' }, key);
  const keyMethod = transport === 'mgf1p'
    ? '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>'
    : '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></xenc:EncryptionMethod>';
  return `<saml:${wrapper} xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`
    + '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">'
    + `<xenc:EncryptionMethod Algorithm="${alg}"/>`
    + `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>${keyMethod}`
    + `<xenc:CipherData><xenc:CipherValue>${wrapped.toString('base64')}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>`
    + `<xenc:CipherData><xenc:CipherValue>${value.toString('base64')}</xenc:CipherValue></xenc:CipherData>`
    + `</xenc:EncryptedData></saml:${wrapper}>`;
}

export interface ResponseOptions {
  inResponseTo?: string | undefined;
  destination?: string | null;
  status?: string;
  sign?: boolean;
  assertion?: string;
  issuer?: string;
}

export function responseXml(o: ResponseOptions = {}): string {
  const rid = id();
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : '';
  const dest = o.destination === null ? '' : ` Destination="${o.destination ?? ACS}"`;
  const status = o.status ?? 'urn:oasis:names:tc:SAML:2.0:status:Success';
  const assertion = o.assertion ?? (status.endsWith('Success') ? signedAssertion({ inResponseTo: o.inResponseTo }).xml : '');
  const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${rid}" Version="2.0" IssueInstant="${iso(0)}"${dest}${irt}>`
    + `<saml:Issuer>${o.issuer ?? IDP_ENTITY}</saml:Issuer>`
    + `<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>`
    + assertion
    + '</samlp:Response>';
  return o.sign ? signXml(xml, rid) : xml;
}

/** The query string of a Response sent on HTTP-Redirect, signed with the identity provider's key. */
export function redirectResponseQuery(xml: string, relayState?: string, key = IDP_KEY): string {
  const parts = [`SAMLResponse=${encodeURIComponent(deflateRawSync(Buffer.from(xml)).toString('base64'))}`];
  if (relayState) parts.push(`RelayState=${encodeURIComponent(relayState)}`);
  parts.push(`SigAlg=${encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')}`);
  const signature = sign('sha256', Buffer.from(parts.join('&')), key).toString('base64');
  return `${parts.join('&')}&Signature=${encodeURIComponent(signature)}`;
}

/** A type 0x0004 artifact for this identity provider. */
export function artifactFor(entityId = IDP_ENTITY): string {
  const out = Buffer.alloc(44);
  out.writeUInt16BE(4, 0);
  out.writeUInt16BE(0, 2);
  createHash('sha1').update(entityId).digest().copy(out, 4);
  randomBytes(20).copy(out, 24);
  return out.toString('base64');
}

/**
 * An artifact resolution service on 127.0.0.1. Each artifact resolves once to the Response stored for
 * it. The ArtifactResolve must be signed by the service provider's key, or the answer is empty.
 */
export async function startArs(): Promise<{ url: string; put(artifact: string, response: string): void; resolved: string[]; close(): Promise<void> }> {
  const store = new Map<string, string>();
  const resolved: string[] = [];
  const server = http.createServer((req, res) => {
    let text = '';
    req.on('data', (c) => { text += c; });
    req.on('end', () => {
      const doc = new DOMParser().parseFromString(text, 'text/xml');
      const resolve = doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'ArtifactResolve')[0]!;
      const sigNode = resolve.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
      let ok = false;
      if (sigNode) {
        const sig = new SignedXml({ publicCert: SP_CERT, getCertFromKeyInfo: () => null });
        sig.loadSignature(sigNode as never);
        try {
          ok = sig.checkSignature(text);
        } catch {
          ok = false;
        }
      }
      const artifact = resolve.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'Artifact')[0]?.textContent ?? '';
      const message = ok ? store.get(artifact) : undefined;
      store.delete(artifact);
      if (message) resolved.push(artifact);
      const answer = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>`
        + `<samlp:ArtifactResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id()}" Version="2.0" IssueInstant="${iso(0)}" InResponseTo="${resolve.getAttribute('ID')}">`
        + `<saml:Issuer>${IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
        + (message ?? '')
        + '</samlp:ArtifactResponse></soap:Body></soap:Envelope>';
      res.writeHead(200, { 'content-type': 'text/xml' });
      res.end(answer);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/ars`,
    put: (artifact, response) => { store.set(artifact, response); },
    resolved,
    close: () => new Promise((r) => server.close(() => r())),
  };
}
