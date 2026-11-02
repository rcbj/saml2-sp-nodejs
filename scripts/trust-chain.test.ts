// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// idpCa end to end, offline: the install script's saveTrustChain writes iya-sts's whole listener CA
// trust chain (leaf, TLS Issuing CA, Intermediate, Root) to the file demo/saml.json's idpCa names,
// and the library reads the identity provider's metadata over HTTPS through that file as it is, and
// still checks the host name.
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readConfigFile, ServiceProvider } from '../packages/saml2-sp-nodejs/src/index.ts';
import { IDP_ENTITY, idpMetadata } from '../packages/saml2-sp-nodejs/test/stub-idp.ts';
import { acceptFirstUse, saveTrustChain, trustPath } from './trust-chain.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = join(repoRoot, 'packages/saml2-sp-nodejs/test/fixtures');
const BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** A four-certificate chain shaped like iya-sts's: Root, Intermediate, TLS Issuing CA, leaf. */
function makeChain(work: string) {
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  const ext = join(work, 'ext.cnf');
  writeFileSync(ext, [
    '[ca]',
    'basicConstraints = critical, CA:TRUE',
    'keyUsage = critical, keyCertSign, cRLSign',
    '[leaf]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = IP:127.0.0.1, DNS:localhost',
    '[elsewhere]',
    'basicConstraints = critical, CA:FALSE',
    'keyUsage = critical, digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = DNS:elsewhere.example',
    '',
  ].join('\n'));
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=sts Root CA',
    '-keyout', join(work, 'root.key'), '-out', join(work, 'root.pem'));
  let serial = Date.now();
  const issue = (name: string, subject: string, issuer: string, section: string) => {
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', subject,
      '-keyout', join(work, `${name}.key`), '-out', join(work, `${name}.csr`));
    openssl('x509', '-req', '-in', join(work, `${name}.csr`), '-days', '1', '-set_serial', String(serial += 1),
      '-CA', join(work, `${issuer}.pem`), '-CAkey', join(work, `${issuer}.key`),
      '-extfile', ext, '-extensions', section, '-out', join(work, `${name}.pem`));
  };
  issue('intermediate', '/CN=sts Intermediate CA', 'root', 'ca');
  issue('issuing', '/CN=sts TLS Issuing CA', 'intermediate', 'ca');
  issue('leaf', '/CN=localhost', 'issuing', 'leaf');
  // The same chain, a leaf for another name: the trust file must not be enough on its own.
  issue('elsewhere', '/CN=elsewhere.example', 'issuing', 'elsewhere');
  const pem = (name: string) => readFileSync(join(work, `${name}.pem`), 'utf8').trim();
  return {
    key: readFileSync(join(work, 'leaf.key')),
    elsewhereKey: readFileSync(join(work, 'elsewhere.key')),
    elsewhere: `${pem('elsewhere')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    presented: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n`,
    published: `${pem('leaf')}\n${pem('issuing')}\n${pem('intermediate')}\n${pem('root')}\n`,
    root: new X509Certificate(pem('root')),
  };
}

describe('the iya-sts trust chain in idpCa', () => {
  const work = mkdtempSync(join(tmpdir(), 'saml-idpca-'));
  const chain = makeChain(work);
  let server: https.Server;
  let elsewhere: https.Server;
  let port = 0;
  let elsewherePort = 0;

  const handler: https.RequestListener = (req, res) => {
    if (req.url === '/tls/server-certificate') {
      res.setHeader('content-type', 'text/plain');
      res.end(chain.published);
      return;
    }
    if (req.url === '/saml2/metadata') {
      res.setHeader('content-type', 'application/samlmetadata+xml');
      res.end(idpMetadata());
      return;
    }
    res.statusCode = 404;
    res.end();
  };

  before(async () => {
    server = https.createServer({ key: chain.key, cert: chain.presented }, handler);
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
    port = (server.address() as AddressInfo).port;
    elsewhere = https.createServer({ key: chain.elsewhereKey, cert: chain.elsewhere }, handler);
    await new Promise<void>((done) => elsewhere.listen(0, '127.0.0.1', () => done()));
    elsewherePort = (elsewhere.address() as AddressInfo).port;
  });

  after(async () => {
    await new Promise<void>((done) => server.close(() => done()));
    await new Promise<void>((done) => elsewhere.close(() => done()));
  });

  // demo/saml.json as shipped, in a scratch demo directory, so idpCa resolves as it does in the image.
  const demo = join(work, 'demo');
  const config = join(demo, 'saml.json');
  const metadataAt = (host: string, p: number) => ({ idpMetadata: `https://${host}:${p}/saml2/metadata` });

  it('the install script writes the whole chain to the file idpCa names', async () => {
    mkdirSync(join(demo, 'generated'), { recursive: true });
    copyFileSync(join(repoRoot, 'demo/saml.json'), config);
    copyFileSync(join(fixtures, 'sp.key'), join(demo, 'generated/sp.key'));
    copyFileSync(join(fixtures, 'sp.crt'), join(demo, 'generated/sp.crt'));
    const raw = JSON.parse(readFileSync(config, 'utf8')) as { idpCa: string };
    assert.equal(raw.idpCa, 'generated/idp-ca.pem');
    const dest = trustPath(raw.idpCa, demo);
    assert.equal(dest, join(demo, 'generated/idp-ca.pem'));
    // A single certificate, as the old script left it, is replaced by the whole chain. It is this
    // chain's root, so the fetch is verified against it.
    writeFileSync(dest!, `${chain.root.toString().trim()}\n`);
    const saved = await saveTrustChain(`https://127.0.0.1:${port}`, dest);
    assert.equal(saved.verified, true);
    assert.equal(saved.count, 4);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    const written = readFileSync(dest!, 'utf8').match(BLOCK) ?? [];
    const expected = chain.published.match(BLOCK) ?? [];
    assert.equal(written.length, 4);
    assert.deepEqual(
      written.map((pem) => new X509Certificate(pem).fingerprint256),
      expected.map((pem) => new X509Certificate(pem).fingerprint256),
    );
    assert.equal(new X509Certificate(written[3]!).subject, 'CN=sts Root CA');
  });

  it('with no file yet, the chain is taken on first use', async () => {
    const saved = await saveTrustChain(`https://127.0.0.1:${port}`, join(work, 'fresh.pem'));
    assert.equal(saved.verified, false);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
  });

  it('a later refresh verifies the server against the chain the file already holds', async () => {
    const dest = join(demo, 'generated/idp-ca.pem');
    const saved = await saveTrustChain(`https://127.0.0.1:${port}`, dest);
    assert.equal(saved.verified, true);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
  });

  it('a held chain that verifies the server is not given up for a host name the leaf does not carry', async () => {
    const dest = join(work, 'held-elsewhere.pem');
    copyFileSync(join(demo, 'generated/idp-ca.pem'), dest);
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, dest), /altnames|Hostname/);
    assert.equal(readFileSync(dest, 'utf8'), readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
  });

  it('a held chain from another CA (a restarted development iya-sts) is replaced on first use', async () => {
    const other = mkdtempSync(join(tmpdir(), 'idpca-other-'));
    const stale = makeChain(other);
    const dest = join(work, 'stale.pem');
    writeFileSync(dest, stale.published);
    const saved = await saveTrustChain(`https://127.0.0.1:${port}`, dest);
    assert.equal(saved.verified, false);
    assert.equal(saved.anchor.fingerprint256, chain.root.fingerprint256);
    assert.notEqual(saved.anchor.fingerprint256, stale.root.fingerprint256);
  });

  it('first use checks the host name, the presented leaf, and every link of the chain', async () => {
    const certs = (chain.published.match(BLOCK) ?? []).map((pem) => new X509Certificate(pem));
    const [leaf, issuing, intermediate, root] = certs as [X509Certificate, X509Certificate, X509Certificate, X509Certificate];
    acceptFirstUse('127.0.0.1', { certs, leaf });
    assert.throws(() => acceptFirstUse('elsewhere.example', { certs, leaf }), /altnames|Hostname/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs, leaf: issuing }), /handshake presented/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [leaf, intermediate, root], leaf }), /not signed/);
    assert.throws(() => acceptFirstUse('127.0.0.1', { certs: [], leaf }), /no certificates/);
    // Without a held chain, a server whose leaf does not name the host is refused too.
    await assert.rejects(saveTrustChain(`https://127.0.0.1:${elsewherePort}`, join(work, 'none.pem')));
  });

  it('the library reads the metadata through that file, and not without it', async () => {
    const resolved = readConfigFile(config, metadataAt('127.0.0.1', port));
    assert.equal(resolved.idpCa, readFileSync(join(demo, 'generated/idp-ca.pem'), 'utf8'));
    const sp = await ServiceProvider.fromFile(config, metadataAt('127.0.0.1', port));
    assert.equal(sp.idp.entityId, IDP_ENTITY);
    // Without idpCa, node's own store does not know this root.
    const raw = JSON.parse(readFileSync(config, 'utf8')) as Record<string, unknown>;
    delete raw.idpCa;
    const bare = join(demo, 'bare.json');
    writeFileSync(bare, JSON.stringify(raw));
    await assert.rejects(ServiceProvider.fromFile(bare, metadataAt('127.0.0.1', port)));
  });

  it('the library checks the host name as well as the chain', async () => {
    // The right leaf, by its IP address SAN and by its DNS SAN.
    assert.equal((await ServiceProvider.fromFile(config, metadataAt('127.0.0.1', port))).idp.entityId, IDP_ENTITY);
    assert.equal((await ServiceProvider.fromFile(config, metadataAt('localhost', port))).idp.entityId, IDP_ENTITY);
    // The same trusted chain, a leaf for another name: refused.
    await assert.rejects(ServiceProvider.fromFile(config, metadataAt('127.0.0.1', elsewherePort)), /altnames/);
  });
});
