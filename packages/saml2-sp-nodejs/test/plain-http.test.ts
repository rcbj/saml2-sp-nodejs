// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Plain http is refused for every fetch (metadata, ArtifactResolve, the Shared Signals transmitter)
// unless the host is loopback, before any connection. `http://0.0.0.0:<port>` reaches a 127.0.0.1
// listener on Linux, so a listener that sees no connection proves the refusal comes first.

import assert from 'node:assert/strict';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { SamlError, ServiceProvider, SignalsReceiver, type SamlConfig } from '../src/index.ts';
import { isLoopbackHost } from '../src/http.ts';
import { ACS, IDP_ENTITY, SP_CERT, SP_ENTITY, SP_KEY, artifactFor, idpMetadata, responseXml, startArs } from './stub-idp.ts';

const REFUSED = /is refused: plain http is allowed only to a loopback host/;
const quiet = { info() {}, warn() {}, error() {} };

function config(idpMetadataSource: string): SamlConfig {
  return { entityId: SP_ENTITY, acsUrl: ACS, privateKey: SP_KEY, certificate: SP_CERT, idpMetadata: idpMetadataSource };
}

async function refused(p: Promise<unknown>, code: string, shown: string, secret?: string) {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof SamlError, `expected a SamlError, got ${String(err)}`);
    assert.equal(err.code, code, err.message);
    assert.match(err.message, REFUSED);
    assert.ok(err.message.startsWith(`http://${shown} is refused`), err.message);
    if (secret) assert.ok(!err.message.includes(secret), 'the error carries the password');
    assert.ok(!err.message.includes('/md') && !err.message.includes('?'), 'the error carries the path or query');
    return true;
  });
}

const metadataOf = (url: string) => ServiceProvider.create(config(url));

async function artifactAt(arsUrl: string) {
  const sp = await ServiceProvider.create(config(idpMetadata(arsUrl)));
  return sp.acs({ method: 'GET', url: `/saml/acs?SAMLart=${encodeURIComponent(artifactFor())}` }, { requestId: '_r' });
}

const transmitterAt = (url: string) => new SignalsReceiver({ transmitter: url, onEndSessions: () => {}, log: quiet }).start();

describe('plain http off loopback', () => {
  let tripwire: net.Server;
  let connections = 0;
  let port = 0;
  before(async () => {
    tripwire = net.createServer((socket) => {
      connections += 1;
      socket.destroy();
    });
    await new Promise<void>((r) => tripwire.listen(0, '127.0.0.1', r));
    port = (tripwire.address() as AddressInfo).port;
  });
  after(async () => { await new Promise((r) => tripwire.close(() => r(undefined))); });

  it('knows a loopback host', () => {
    for (const h of ['localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '127.255.255.255', '[::1]']) assert.equal(isLoopbackHost(h), true, h);
    for (const h of ['example.com', '0.0.0.0', '128.0.0.1', '10.0.0.1', 'localhost.example.com', '[::ffff:127.0.0.1]', '[::]']) {
      assert.equal(isLoopbackHost(h), false, h);
    }
  });

  it('refuses metadata, ArtifactResolve and the transmitter on http://example.com', async () => {
    await refused(metadataOf('http://example.com/md?x=1'), 'metadata', 'example.com');
    await refused(artifactAt('http://example.com/md'), 'artifact', 'example.com');
    await refused(transmitterAt('http://example.com:8080'), 'ssf', 'example.com:8080');
  });

  it('refuses http://0.0.0.0 before connecting to a listener it would reach', async () => {
    // The tripwire is reachable this way: without the refusal, these would connect to it.
    await refused(metadataOf(`http://0.0.0.0:${port}/md`), 'metadata', `0.0.0.0:${port}`);
    await refused(artifactAt(`http://0.0.0.0:${port}/md`), 'artifact', `0.0.0.0:${port}`);
    await refused(transmitterAt(`http://0.0.0.0:${port}`), 'ssf', `0.0.0.0:${port}`);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(connections, 0);
  });

  it('never counts a URL with userinfo as loopback, and keeps the password out of the error', async () => {
    await refused(metadataOf(`http://localhost:${port}@example.com/md`), 'metadata', 'example.com');
    await refused(metadataOf(`http://user:s3cret-pw@localhost:${port}/md`), 'metadata', `localhost:${port}`, 's3cret-pw');
    await refused(transmitterAt(`http://user:s3cret-pw@127.0.0.1:${port}`), 'ssf', `127.0.0.1:${port}`, 's3cret-pw');
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(connections, 0);
  });
});

describe('plain http on loopback, and https', () => {
  let server: http.Server;
  let ars: Awaited<ReturnType<typeof startArs>>;
  let port = 0;
  before(async () => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/samlmetadata+xml' });
      res.end(idpMetadata());
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as AddressInfo).port;
    ars = await startArs();
  });
  after(async () => {
    await new Promise((r) => server.close(() => r(undefined)));
    await ars.close();
  });

  it('reads metadata from http://127.0.0.1 and http://localhost', async () => {
    assert.equal((await metadataOf(`http://127.0.0.1:${port}/md`)).idp.entityId, IDP_ENTITY);
    assert.equal((await metadataOf(`http://localhost:${port}/md`)).idp.entityId, IDP_ENTITY);
  });

  it('resolves an artifact at http://localhost', async () => {
    const arsPort = new URL(ars.url).port;
    const sp = await ServiceProvider.create(config(idpMetadata(`http://localhost:${arsPort}/ars`)));
    const artifact = artifactFor();
    ars.put(artifact, responseXml({ inResponseTo: '_r' }));
    const who = await sp.acs({ method: 'GET', url: `/saml/acs?SAMLart=${encodeURIComponent(artifact)}` }, { requestId: '_r' });
    assert.equal(who.binding, 'artifact');
  });

  it('fails https to an unreachable host as a connection error, not as the refusal', async () => {
    await assert.rejects(metadataOf('https://127.0.0.1:1/md'), (err: unknown) => {
      assert.ok(err instanceof SamlError);
      assert.equal(err.code, 'metadata');
      assert.doesNotMatch(err.message, REFUSED);
      assert.match(err.message, /ECONNREFUSED/);
      return true;
    });
  });
});
