// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The service provider against the stub identity provider (test/stub-idp.ts), on every binding, and
// against the ways a Response is forged, replayed or misdirected.

import assert from 'node:assert/strict';
import { createPublicKey, verify, X509Certificate } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { inflateRawSync } from 'node:zlib';
import { DOMParser } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { SamlError, ServiceProvider, type SamlConfig } from '../src/index.ts';
import {
  ACS, IDP_ENTITY, SP_CERT, SP_ENTITY, SP_KEY, artifactFor, assertionXml, encryptAssertion, idpMetadata,
  redirectResponseQuery, responseXml, signXml, signedAssertion, startArs,
} from './stub-idp.ts';

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

function config(extra: Partial<SamlConfig> = {}, arsUrl?: string): SamlConfig {
  return { entityId: SP_ENTITY, acsUrl: ACS, privateKey: SP_KEY, certificate: SP_CERT, idpMetadata: idpMetadata(arsUrl), ...extra };
}

async function post(sp: ServiceProvider, xml: string, requestId: string | undefined, relayState?: string) {
  const body: Record<string, string> = { SAMLResponse: b64(xml) };
  if (relayState) body.RelayState = relayState;
  return sp.acs({ method: 'POST', url: '/saml/acs', body }, { requestId });
}

async function rejects(p: Promise<unknown>, code: string, pattern?: RegExp) {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof SamlError, `expected a SamlError, got ${String(err)}`);
    assert.equal(err.code, code, err.message);
    if (pattern) assert.match(err.message, pattern);
    return true;
  });
}

describe('configuration', () => {
  it('refuses a configuration without a key, or with a certificate for another key', async () => {
    await rejects(ServiceProvider.create({ ...config(), privateKey: undefined as never }), 'config', /privateKey/);
    const { readFileSync } = await import('node:fs');
    const otherCert = readFileSync(new URL('./fixtures/idp.crt', import.meta.url), 'utf8');
    await rejects(ServiceProvider.create(config({ certificate: otherCert })), 'config', /not for the private key/);
  });

  it('reads the identity provider from its metadata', async () => {
    const sp = await ServiceProvider.create(config());
    assert.equal(sp.idp.entityId, IDP_ENTITY);
    assert.equal(sp.idp.ssoUrls.redirect, 'https://idp.test/saml2/sso');
    assert.equal(sp.idp.signingCertificates.length, 1);
  });

  it('writes metadata with a signed-requests key and the ACS on all three bindings', async () => {
    const sp = await ServiceProvider.create(config());
    const doc = new DOMParser().parseFromString(sp.metadata(), 'text/xml');
    const acs = Array.from(doc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'AssertionConsumerService') as unknown as ArrayLike<Element>);
    assert.deepEqual(acs.map((e) => e.getAttribute('Binding')!.split(':').pop()), ['HTTP-POST', 'HTTP-Redirect', 'HTTP-Artifact']);
    assert.ok(acs.every((e) => e.getAttribute('Location') === ACS));
    assert.match(sp.metadata(), /AuthnRequestsSigned="true"/);
    assert.match(sp.metadata(), /<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*<\/md:KeyDescriptor>/);
  });
});

describe('the AuthnRequest', () => {
  it('on HTTP-Redirect: deflated, with a query signature that verifies with the SP certificate', async () => {
    const sp = await ServiceProvider.create(config());
    const req = sp.login({ relayState: '/home' });
    assert.equal(req.binding, 'redirect');
    const url = new URL(req.url);
    assert.equal(url.origin + url.pathname, 'https://idp.test/saml2/sso');
    const raw = url.search.slice(1);
    const [signedPart, sigPart] = raw.split('&Signature=');
    const ok = verify('sha256', Buffer.from(signedPart!), createPublicKey(new X509Certificate(SP_CERT).publicKey.export({ type: 'spki', format: 'pem' })), Buffer.from(decodeURIComponent(sigPart!), 'base64'));
    assert.ok(ok, 'the query signature verifies');
    const xml = inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest')!, 'base64')).toString();
    assert.match(xml, new RegExp(`ID="${req.id}"`));
    assert.match(xml, /ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/);
    assert.match(xml, /Destination="https:\/\/idp.test\/saml2\/sso"/);
    assert.equal(url.searchParams.get('RelayState'), '/home');
  });

  it('on HTTP-POST: an enveloped signature after the Issuer, in an auto-posting form', async () => {
    const sp = await ServiceProvider.create(config({ requestBinding: 'post' }));
    const req = sp.login({ responseBinding: 'artifact', nonce: 'abc' });
    assert.equal(req.binding, 'post');
    if (req.binding !== 'post') return;
    const xml = Buffer.from(req.fields.SAMLRequest!, 'base64').toString();
    assert.match(xml, /<saml:Issuer>[^<]+<\/saml:Issuer><ds:Signature/);
    assert.match(xml, /HTTP-Artifact/);
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const sig = new SignedXml({ publicCert: SP_CERT, getCertFromKeyInfo: () => null });
    sig.loadSignature(doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0] as never);
    assert.ok(sig.checkSignature(xml));
    assert.match(req.html, /<script nonce="abc">/);
    assert.match(req.html, /<button type="submit">/);
  });

  it('refuses a RelayState over 80 bytes', async () => {
    const sp = await ServiceProvider.create(config());
    assert.throws(() => sp.login({ relayState: 'x'.repeat(81) }), /80 bytes/);
  });
});

describe('a Response on HTTP-POST', () => {
  it('signed Response and signed assertion: who signed in, with attributes', async () => {
    const sp = await ServiceProvider.create(config());
    const who = await post(sp, responseXml({ inResponseTo: '_req1', sign: true }), '_req1', '/home');
    assert.equal(who.nameId, 'alice-1234');
    assert.equal(who.nameIdFormat, 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
    assert.equal(who.sessionIndex, '_session1');
    assert.equal(who.relayState, '/home');
    assert.equal(who.binding, 'post');
    assert.deepEqual(who.attributes.groups, ['staff', 'admins']);
    assert.deepEqual(who.attributes['urn:oid:0.9.2342.19200300.100.1.3'], ['alice@example.com']);
    assert.equal(who.attributeFriendlyNames['urn:oid:0.9.2342.19200300.100.1.3'], 'mail');
    assert.equal(who.authnContextClassRef, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport');
  });

  it('accepts a signed assertion in an unsigned Response', async () => {
    const sp = await ServiceProvider.create(config());
    const who = await post(sp, responseXml({ inResponseTo: '_req1' }), '_req1');
    assert.equal(who.nameId, 'alice-1234');
  });

  it('refuses an unsigned assertion, even in a signed Response, by default', async () => {
    const sp = await ServiceProvider.create(config());
    const xml = responseXml({ inResponseTo: '_r', sign: true, assertion: assertionXml({ inResponseTo: '_r' }).xml });
    await rejects(post(sp, xml, '_r'), 'validation', /not signed/);
    const lax = await ServiceProvider.create(config({ wantAssertionsSigned: false }));
    assert.equal((await post(lax, xml, '_r')).nameId, 'alice-1234');
  });

  it('refuses a Response with nothing signed', async () => {
    const sp = await ServiceProvider.create(config({ wantAssertionsSigned: false }));
    const xml = responseXml({ inResponseTo: '_r', assertion: assertionXml({ inResponseTo: '_r' }).xml });
    await rejects(post(sp, xml, '_r'), 'validation', /neither/);
  });

  it('refuses an assertion altered after it was signed', async () => {
    const sp = await ServiceProvider.create(config());
    const xml = responseXml({ inResponseTo: '_r' }).replace('alice-1234', 'mallory');
    await rejects(post(sp, xml, '_r'), 'signature');
  });

  it('refuses a signature by another key', async () => {
    const sp = await ServiceProvider.create(config());
    const a = assertionXml({ inResponseTo: '_r' });
    const xml = responseXml({ inResponseTo: '_r', assertion: signXml(a.xml, a.id, SP_KEY, SP_CERT) });
    await rejects(post(sp, xml, '_r'), 'signature', /does not verify/);
  });

  it('is not fooled by signature wrapping: a forged assertion beside, or with the ID of, the signed one', async () => {
    const sp = await ServiceProvider.create(config());
    const signed = signedAssertion({ inResponseTo: '_r' });
    const forged = assertionXml({ inResponseTo: '_r', nameId: 'mallory' }).xml;
    // Two assertions: refused outright.
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: forged + signed.xml }), '_r'), 'validation', /exactly one/);
    // The forged one carrying the signed one's ID, the signed one hidden inside it.
    const hidden = forged.replace(/ID="[^"]+"/, `ID="${signed.id}"`).replace('</saml:Assertion>', `<saml:Advice>${signed.xml}</saml:Advice></saml:Assertion>`);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: hidden }), '_r'), 'signature', /two elements/);
    // The signature moved onto the forged assertion: its reference points at another ID.
    const sigXml = /<ds:Signature[\s\S]*<\/ds:Signature>/.exec(signed.xml)![0];
    const moved = forged.replace(/(<\/saml:Issuer>)/, `$1${sigXml}`);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: moved }), '_r'), 'signature', /refers to/);
  });

  it('refuses a Response for another audience, another ACS, or that has expired', async () => {
    const sp = await ServiceProvider.create(config());
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: signedAssertion({ inResponseTo: '_r', audience: 'https://other.test' }).xml }), '_r'), 'validation', /not for/);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: signedAssertion({ inResponseTo: '_r', recipient: 'https://other.test/acs' }).xml }), '_r'), 'validation', /Recipient/);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: signedAssertion({ inResponseTo: '_r', notOnOrAfterMs: -120_000 }).xml }), '_r'), 'validation', /expired/);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', destination: 'https://other.test/acs' }), '_r'), 'validation', /addressed to/);
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: signedAssertion({ inResponseTo: '_r', issuer: 'https://evil.test' }).xml }), '_r'), 'validation', /issued by/);
  });

  it('refuses an answer to a request this browser did not make, and an unsolicited one unless allowed', async () => {
    const sp = await ServiceProvider.create(config());
    await rejects(post(sp, responseXml({ inResponseTo: '_r' }), '_other'), 'validation', /not a request this browser/);
    await rejects(post(sp, responseXml({ inResponseTo: '_r' }), undefined), 'validation', /not a request this browser/);
    await rejects(post(sp, responseXml({}), undefined), 'validation', /unsolicited/);
    const open = await ServiceProvider.create(config({ allowUnsolicited: true }));
    assert.equal((await post(open, responseXml({}), undefined)).inResponseTo, undefined);
  });

  it('refuses the same assertion twice', async () => {
    const sp = await ServiceProvider.create(config());
    const xml = responseXml({ inResponseTo: '_r', sign: true });
    await post(sp, xml, '_r');
    await rejects(post(sp, xml, '_r'), 'replay');
  });

  it('reports the identity provider\'s non-success status', async () => {
    const sp = await ServiceProvider.create(config());
    await assert.rejects(post(sp, responseXml({ inResponseTo: '_r', status: 'urn:oasis:names:tc:SAML:2.0:status:Responder' }), '_r'), (err: unknown) => {
      assert.ok(err instanceof SamlError && err.code === 'status');
      assert.equal(err.status?.code, 'urn:oasis:names:tc:SAML:2.0:status:Responder');
      return true;
    });
  });

  it('refuses a DOCTYPE', async () => {
    const sp = await ServiceProvider.create(config());
    const xml = `<!DOCTYPE x [<!ENTITY e "x">]>${responseXml({ inResponseTo: '_r' })}`;
    await rejects(post(sp, xml, '_r'), 'xml', /DOCTYPE/);
  });

  it('decrypts an encrypted assertion (AES-GCM and AES-CBC, RSA-OAEP)', async () => {
    const sp = await ServiceProvider.create(config());
    for (const cipher of ['aes-256-gcm', 'aes-128-cbc'] as const) {
      const a = signedAssertion({ inResponseTo: '_r' });
      const who = await post(sp, responseXml({ inResponseTo: '_r', sign: true, assertion: encryptAssertion(a.xml, cipher) }), '_r');
      assert.equal(who.nameId, 'alice-1234', cipher);
      assert.equal(who.encrypted, true);
    }
    // RSA-OAEP with SHA-256 and MGF1-SHA-256 (XML Encryption 1.1), what the demo asks iya-sts for.
    const a = signedAssertion({ inResponseTo: '_r' });
    assert.equal((await post(sp, responseXml({ inResponseTo: '_r', assertion: encryptAssertion(a.xml, 'aes-256-gcm', 'oaep256') }), '_r')).nameId, 'alice-1234');
  });

  it('refuses a plaintext assertion when wantAssertionsEncrypted is on', async () => {
    const sp = await ServiceProvider.create(config({ wantAssertionsEncrypted: true }));
    await rejects(post(sp, responseXml({ inResponseTo: '_r', sign: true }), '_r'), 'validation', /not encrypted/);
    const a = signedAssertion({ inResponseTo: '_r' });
    assert.equal((await post(sp, responseXml({ inResponseTo: '_r', assertion: encryptAssertion(a.xml) }), '_r')).encrypted, true);
  });

  it('refuses an encrypted assertion whose ciphertext was altered', async () => {
    const sp = await ServiceProvider.create(config());
    const enc = encryptAssertion(signedAssertion({ inResponseTo: '_r' }).xml);
    const values = [...enc.matchAll(/<xenc:CipherValue>([^<]+)<\/xenc:CipherValue>/g)];
    const last = values[values.length - 1]![1]!;
    const bytes = Buffer.from(last, 'base64');
    bytes[20] = bytes[20]! ^ 1;
    await rejects(post(sp, responseXml({ inResponseTo: '_r', assertion: enc.replace(last, bytes.toString('base64')) }), '_r'), 'decryption');
  });

  it('decrypts an EncryptedAttribute', async () => {
    const sp = await ServiceProvider.create(config());
    const secret = encryptAssertion('<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>', 'aes-256-gcm', 'oaep256', 'EncryptedAttribute');
    const a = assertionXml({ inResponseTo: '_r', extraAttributes: secret });
    const who = await post(sp, responseXml({ inResponseTo: '_r', assertion: signXml(a.xml, a.id) }), '_r');
    assert.deepEqual(who.attributes.employeeNumber, ['E-42']);
  });
});

describe('a Response on HTTP-Redirect', () => {
  it('verifies the query signature and reads the Response', async () => {
    const sp = await ServiceProvider.create(config());
    const query = redirectResponseQuery(responseXml({ inResponseTo: '_r' }), '/there');
    const who = await sp.acs({ method: 'GET', url: `/saml/acs?${query}` }, { requestId: '_r' });
    assert.equal(who.binding, 'redirect');
    assert.equal(who.relayState, '/there');
  });

  it('refuses a query signature by another key, and a changed RelayState', async () => {
    const sp = await ServiceProvider.create(config());
    const forged = redirectResponseQuery(responseXml({ inResponseTo: '_r' }), '/x', SP_KEY);
    await rejects(sp.acs({ method: 'GET', url: `/saml/acs?${forged}` }, { requestId: '_r' }), 'signature');
    const changed = redirectResponseQuery(responseXml({ inResponseTo: '_r' }), '/x').replace('RelayState=%2Fx', 'RelayState=%2Fy');
    await rejects(sp.acs({ method: 'GET', url: `/saml/acs?${changed}` }, { requestId: '_r' }), 'signature');
  });
});

describe('a Response on HTTP-Artifact', () => {
  let ars: Awaited<ReturnType<typeof startArs>>;
  before(async () => { ars = await startArs(); });
  after(async () => { await ars.close(); });

  it('resolves the artifact with a signed ArtifactResolve, and validates the Response', async () => {
    const sp = await ServiceProvider.create(config({ responseBinding: 'artifact' }, ars.url));
    const req = sp.login();
    assert.match(req.xml, /HTTP-Artifact/);
    const artifact = artifactFor();
    ars.put(artifact, responseXml({ inResponseTo: req.id }));
    const who = await sp.acs({ method: 'GET', url: `/saml/acs?SAMLart=${encodeURIComponent(artifact)}&RelayState=%2Fa` }, { requestId: req.id });
    assert.equal(who.binding, 'artifact');
    assert.equal(who.relayState, '/a');
    assert.equal(who.nameId, 'alice-1234');
    assert.deepEqual(ars.resolved, [artifact]);
  });

  it('accepts the artifact on a POST too, and fails clearly on one already used', async () => {
    const sp = await ServiceProvider.create(config({}, ars.url));
    const artifact = artifactFor();
    ars.put(artifact, responseXml({ inResponseTo: '_r' }));
    assert.equal((await sp.acs({ method: 'POST', url: '/saml/acs', body: `SAMLart=${encodeURIComponent(artifact)}` }, { requestId: '_r' })).binding, 'artifact');
    await rejects(sp.acs({ method: 'POST', url: '/saml/acs', body: { SAMLart: artifact } }, { requestId: '_r' }), 'artifact', /did not resolve/);
  });

  it('refuses an artifact from another identity provider without dialing anybody', async () => {
    const sp = await ServiceProvider.create(config({}, ars.url));
    await rejects(sp.acs({ method: 'GET', url: `/saml/acs?SAMLart=${encodeURIComponent(artifactFor('https://evil.test'))}` }, { requestId: '_r' }), 'artifact', /not issued by/);
  });
});

describe('the ACS request', () => {
  it('refuses a request with no SAML message', async () => {
    const sp = await ServiceProvider.create(config());
    await rejects(sp.acs({ method: 'GET', url: '/saml/acs' }), 'binding');
  });
});
