// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The Shared Signals receiver against a stub transmitter: discovery, a poll stream created once and
// found again, SETs verified and routed to the right local sessions, acknowledgements, and refusals.
// The stub signs with its own key through node:crypto, independently of the receiver's verifier.

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { EVENT, MemorySessionIndex, SamlError, SignalsReceiver, subjectOf, type SamlLogin, type SignalEvent } from '../src/index.ts';
import { verifyCompactJws } from '../src/ssf/jws.ts';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };

function jws(payload: object, key = privateKey, header: object = { alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' }): string {
  const h = Buffer.from(JSON.stringify(header)).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${h}.${p}.${sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
}

interface Stub { url: string; queue: Map<string, string>; acked: string[]; errs: Record<string, unknown>; created: number; close(): Promise<void> }

async function startTransmitter(): Promise<Stub> {
  const queue = new Map<string, string>();
  const acked: string[] = [];
  const errs: Record<string, unknown> = {};
  const streams: Record<string, unknown>[] = [];
  let created = 0;
  let base = '';
  const server = http.createServer((req, res) => {
    let text = '';
    req.on('data', (c) => { text += c; });
    req.on('end', () => {
      const out = (status: number, body?: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(body === undefined ? '' : JSON.stringify(body));
      };
      const url = new URL(req.url ?? '/', base);
      if (url.pathname === '/.well-known/ssf-configuration') {
        return out(200, { issuer: base, jwks_uri: `${base}/jwks`, configuration_endpoint: `${base}/ssf/stream`, verification_endpoint: `${base}/ssf/verify`, delivery_methods_supported: ['urn:ietf:rfc:8936'] });
      }
      if (url.pathname === '/jwks') return out(200, { keys: [jwk] });
      if (url.pathname === '/ssf/stream' && req.method === 'GET') return out(200, streams);
      if (url.pathname === '/ssf/stream' && req.method === 'POST') {
        const body = JSON.parse(text);
        created += 1;
        const s = { stream_id: `s${created}`, iss: base, aud: 'my-app', delivery: { method: body.delivery.method, endpoint_url: `${base}/ssf/poll/s${created}` }, events_requested: body.events_requested, events_delivered: body.events_requested };
        streams.push(s);
        return out(201, s);
      }
      if (url.pathname.startsWith('/ssf/poll/')) {
        const body = JSON.parse(text || '{}');
        for (const jti of body.ack ?? []) { acked.push(jti); queue.delete(jti); }
        Object.assign(errs, body.setErrs ?? {});
        for (const jti of Object.keys(body.setErrs ?? {})) queue.delete(jti);
        return out(200, { sets: Object.fromEntries(queue), moreAvailable: false });
      }
      return out(404, { err: 'not found' });
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url: base, queue, acked, errs, get created() { return created; }, close: () => new Promise((r) => server.close(() => r())) } as Stub;
}

function set(stub: Stub, type: string, subId: object, extra: object = {}, opts: { key?: typeof privateKey; aud?: string; iss?: string } = {}): string {
  const jti = randomUUID();
  stub.queue.set(jti, jws({ iss: opts.iss ?? stub.url, aud: opts.aud ?? 'my-app', jti, iat: Math.floor(Date.now() / 1000), sub_id: subId, events: { [type]: { event_timestamp: 1, ...extra } } }, opts.key));
  return jti;
}

const login = (person: string, sessionIndex: string): SamlLogin => ({
  nameId: person, authnInstant: new Date(), issuer: 'x', binding: 'post', encrypted: true, responseId: 'r', assertionId: randomUUID(),
  attributes: { 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': [`urn:uuid:${person}`], 'urn:oid:0.9.2342.19200300.100.1.3': [`${person}@example.com`] },
  attributeFriendlyNames: {}, sessionIndex,
});

describe('the Shared Signals receiver', () => {
  let stub: Stub;
  before(async () => { stub = await startTransmitter(); });
  after(async () => { await stub.close(); });

  it('verifies a SET against the JWKS, and refuses another key, a missing kid and none', () => {
    const token = jws({ a: 1 });
    assert.deepEqual(verifyCompactJws(token, [jwk]).payload, { a: 1 });
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, other.privateKey), [jwk]), /does not verify/);
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, privateKey, { alg: 'RS256', kid: 'nope' }), [jwk]), /no RSA signing key with kid nope/);
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, privateKey, { alg: 'none' }), [jwk]), /does not verify/);
    assert.throws(() => verifyCompactJws(jws({ a: 1 }, privateKey, { alg: 'HS256', kid: 'k1' }), [jwk]), /does not verify/);
  });

  it('reads complex, iss_sub and email subjects', () => {
    assert.deepEqual(subjectOf({ format: 'complex', user: { format: 'iss_sub', iss: 'https://i', sub: 'urn:uuid:a' }, session: { format: 'opaque', id: 'S1' } }, 'https://i'), { person: 'urn:uuid:a', idpSession: 'S1' });
    assert.deepEqual(subjectOf({ format: 'iss_sub', iss: 'https://other', sub: 'urn:uuid:a' }, 'https://i'), {}, 'another issuer names nobody here');
    assert.deepEqual(subjectOf({ format: 'email', email: 'A@x.com' }, 'https://i'), { email: 'A@x.com' });
  });

  it('creates its poll stream once, ends exactly the sessions an event names, and acknowledges', async () => {
    const ended: string[][] = [];
    const seen: SignalEvent[] = [];
    const r = new SignalsReceiver({ transmitter: stub.url, onEndSessions: (ids) => { ended.push(ids); }, pollIntervalMs: 60_000, log: { info() {}, warn() {}, error() {} } });
    r.on('*', (e) => { seen.push(e); });
    await r.start();
    r.stop();
    assert.equal(stub.created, 1);
    assert.equal(r.stream?.stream_id, 's1');

    // alice has two local sessions from two IdP sessions; bob one.
    await r.track('L-a1', login('alice', 'IDP-A1'));
    await r.track('L-a2', login('alice', 'IDP-A2'));
    await r.track('L-b1', login('bob', 'IDP-B1'));

    // CAEP session-revoked naming alice's first IdP session ends only L-a1.
    const j1 = set(stub, EVENT.sessionRevoked, { format: 'complex', user: { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:alice' }, session: { format: 'opaque', id: 'IDP-A1' } });
    // CAEP credential-change about bob ends nothing; it is handed to the handler.
    const j2 = set(stub, EVENT.credentialChange, { format: 'complex', user: { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:bob' } }, { credential_type: 'password', change_type: 'update' });
    await r.pollOnce();
    assert.deepEqual(ended, [['L-a1']]);
    assert.equal(seen.find((e) => e.jti === j2)?.ended, false);
    assert.deepEqual(seen.find((e) => e.jti === j2)?.sessions, ['L-b1']);

    // RISC account-disabled about alice (iss_sub) ends her remaining session; the earlier two are acknowledged.
    const j3 = set(stub, EVENT.accountDisabled, { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:alice' });
    await r.pollOnce();
    assert.deepEqual(ended, [['L-a1'], ['L-a2']]);
    assert.ok([j1, j2].every((j) => stub.acked.includes(j)));

    // A RISC event by email reaches bob.
    set(stub, EVENT.credentialCompromise, { format: 'email', email: 'BOB@example.com' }, { credential_type: 'password' });
    await r.pollOnce();
    assert.deepEqual(ended[2], ['L-b1']);
    await r.pollOnce();
    assert.ok(stub.acked.includes(j3));

    // A second receiver finds the stream rather than creating another.
    const again = new SignalsReceiver({ transmitter: stub.url, onEndSessions: () => {}, log: { info() {}, warn() {}, error() {} } });
    await again.start();
    again.stop();
    assert.equal(stub.created, 1);
    assert.equal(again.stream?.stream_id, 's1');
  });

  it('refuses a forged, misaddressed or foreign SET without acting on it, and reports it in setErrs', async () => {
    const ended: string[][] = [];
    const index = new MemorySessionIndex();
    const r = new SignalsReceiver({ transmitter: stub.url, sessionIndex: index, onEndSessions: (ids) => { ended.push(ids); }, log: { info() {}, warn() {}, error() {} } });
    await r.start();
    r.stop();
    await r.track('L-c1', login('carol', 'IDP-C1'));
    const subject = { format: 'complex', user: { format: 'iss_sub', iss: stub.url, sub: 'urn:uuid:carol' }, session: { format: 'opaque', id: 'IDP-C1' } };
    const forged = set(stub, EVENT.sessionRevoked, subject, {}, { key: other.privateKey });
    const misaddressed = set(stub, EVENT.sessionRevoked, subject, {}, { aud: 'someone-else' });
    const foreign = set(stub, EVENT.sessionRevoked, subject, {}, { iss: 'https://evil.example' });
    await r.pollOnce();
    assert.deepEqual(ended, []);
    assert.deepEqual(index.byPerson('urn:uuid:carol'), ['L-c1']);
    await r.pollOnce();
    for (const j of [forged, misaddressed, foreign]) assert.ok(j in stub.errs, `${j} reported`);
  });

  it('refuses a transmitter without poll delivery', async () => {
    const r = new SignalsReceiver({ transmitter: 'http://127.0.0.1:1', onEndSessions: () => {}, log: { info() {}, warn() {}, error() {} } });
    await assert.rejects(r.start(), (e: unknown) => e instanceof SamlError && e.code === 'ssf');
  });
});
