// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The setup script's plan, offline: what it registers, and where.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ENCRYPTION, MULTIPLE_ACCOUNTS, filesOf, metadataFor, ssfCalls, idpMetadataUrl, parseArgs, planFor, realmOf } from './configure-iya-sts.ts';
import { demoPort, endpointsFor, onPort } from './redirects.mjs';

describe('configure-iya-sts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'saml-setup-'));
  const config = join(dir, 'saml.json');
  writeFileSync(config, JSON.stringify({
    entityId: 'http://localhost:3000/saml/metadata', acsUrl: 'http://localhost:3000/saml/acs',
    privateKey: 'generated/sp.key', certificate: 'generated/sp.crt',
    idpMetadata: 'generated/idp-metadata.xml', idpCa: 'generated/idp-ca.pem',
  }));

  it('resolves the configuration\'s files next to it', () => {
    const files = filesOf(config);
    assert.equal(files.key, join(dir, 'generated/sp.key'));
    assert.equal(files.spMetadata, join(dir, 'generated/sp-metadata.xml'));
    assert.equal(files.idpCa, join(dir, 'generated/idp-ca.pem'));
  });

  it('registers from the metadata document, pins encryption, and fetches the per-SP IdP metadata', () => {
    const files = filesOf(config);
    const plan = planFor(files, 'https://localhost:8081', 'saml-demo-user', '<md:EntityDescriptor/>');
    const create = plan[0]!;
    assert.match(create.path, /\/admin-api\/applications\/create$/);
    assert.deepEqual(create.body, {
      identifier: 'http://localhost:3000/saml/metadata', name: 'saml2-sp-nodejs demo', protocols: ['saml2'],
      fields: { samlSpMetadata: '<md:EntityDescriptor/>' },
    });
    assert.match(plan[1]!.path, /\/admin-api\/saml2\/upload-metadata$/);
    const sets = plan.filter((c) => c.path.endsWith('/applications/set')).map((c) => c.body as { attribute: string; value: string });
    assert.deepEqual(Object.fromEntries(sets.map((s) => [s.attribute, s.value])), ENCRYPTION);
    assert.ok(plan.some((c) => c.path === 'https://localhost:8081/saml2/metadata/http%3A%2F%2Flocalhost%3A3000%2Fsaml%2Fmetadata'));
    assert.deepEqual(plan.find((c) => c.path.endsWith('/admin-api/config/set'))?.body, MULTIPLE_ACCOUNTS);
    assert.match(plan[plan.length - 1]!.path, /\/users\/create$/);
    assert.equal(planFor(files, 'https://localhost:8081', '', 'x').some((c) => c.path.endsWith('/users/create')), false);
  });

  it('with an ssf block, gives the application Shared Signals access by its own certificate', () => {
    const withSsf = join(dir, 'saml-ssf.json');
    writeFileSync(withSsf, JSON.stringify({ ...JSON.parse(readFileSync(config, 'utf8')), ssf: { transmitter: 'https://localhost:8081' } }));
    const files = filesOf(withSsf);
    assert.equal(files.ssfTransmitter, 'https://localhost:8081');
    const calls = ssfCalls(files, 'https://localhost:8081', 'PEM');
    assert.deepEqual(calls.map((c) => c.path.replace('https://localhost:8081/admin-api', '')),
      ['/applications/add', '/roles/add-member', '/tls/trust/add', '/applications/add-certificate']);
    assert.deepEqual(calls[0]!.body, { application: 'http://localhost:3000/saml/metadata', attribute: 'oauthAllowedScope', value: 'ssf.manage' });
    assert.deepEqual(calls[1]!.body, { role: 'SSF_MANAGE', kind: 'application', member: 'http://localhost:3000/saml/metadata' });
    assert.ok(planFor(files, 'https://localhost:8081', '', 'x').some((c) => c.path.endsWith('/applications/add-certificate')));
    assert.ok(!planFor(filesOf(config), 'https://localhost:8081', '', 'x').some((c) => c.path.endsWith('/applications/add-certificate')), 'no ssf block, no access');
  });

  it('keeps a realm\'s base and refuses any other path', () => {
    assert.deepEqual(realmOf('https://idp.test/realm/acme'), { origin: 'https://idp.test', base: 'https://idp.test/realm/acme' });
    assert.throws(() => realmOf('https://idp.test/saml2'), /realm/);
    assert.equal(idpMetadataUrl('https://idp.test/realm/acme', 'urn:x'), 'https://idp.test/realm/acme/saml2/metadata/urn%3Ax');
  });

  it('takes its options, and refuses plain http', () => {
    const a = parseArgs(['--idp', 'https://idp.test/', '--public-url', 'http://app.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(a.idp, 'https://idp.test');
    assert.equal(a.publicUrl, 'http://app.test');
    assert.equal(a.publicUrlGiven, true);
    assert.equal(parseArgs([], {}).publicUrlGiven, false);
    assert.equal(parseArgs([], { PUBLIC_URL: 'http://demo.test' }).publicUrlGiven, true);
    assert.equal(a.testUser, '');
    assert.equal(a.dryRun, true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--public-url', ''], {}), /empty/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });

  it('registers a loopback entityID and ACS on the port the demo listens on', () => {
    const file = { entityId: 'http://localhost:3000/saml/metadata', acsUrl: 'http://localhost:3000/saml/acs' };
    const moved = endpointsFor(file.entityId, file.acsUrl, { publicUrlGiven: false, port: 3001 });
    assert.equal(moved.entityId, 'http://localhost:3001/saml/metadata');
    assert.equal(moved.acsUrl, 'http://localhost:3001/saml/acs');
    assert.equal(onPort('http://127.0.0.1:3000/saml/acs', 3001), 'http://127.0.0.1:3001/saml/acs');
    assert.equal(onPort('http://[::1]:3000/saml/acs', 3001), 'http://[::1]:3001/saml/acs');
    const published = endpointsFor('https://app.example/saml/metadata', 'https://app.example/saml/acs', { publicUrlGiven: false, port: 3001 });
    assert.equal(published.entityId, 'https://app.example/saml/metadata');
    assert.equal(published.acsUrl, 'https://app.example/saml/acs');
    const explicit = endpointsFor(file.entityId, file.acsUrl, { publicUrl: 'http://app.test:9', publicUrlGiven: true, port: 3001 });
    assert.equal(explicit.entityId, 'http://app.test:9/saml/metadata');
    assert.equal(explicit.acsUrl, 'http://app.test:9/saml/acs');
    assert.equal(demoPort('3000', '3001'), 3001);
    assert.equal(demoPort('3001', ''), 3001);
    assert.equal(demoPort('3000', 'nope'), 3000);
    assert.equal(demoPort('', undefined), undefined);
    assert.equal(demoPort('nope', undefined), undefined);

    const files = filesOf(config);
    const endpoints = endpointsFor(files.entityId, files.acsUrl, { publicUrlGiven: false, port: 3001 });
    files.entityId = endpoints.entityId;
    files.acsUrl = endpoints.acsUrl;
    const plan = planFor(files, 'https://localhost:8081', '', '<md:EntityDescriptor/>');
    assert.equal((plan[0]!.body as { identifier: string }).identifier, 'http://localhost:3001/saml/metadata');
    assert.ok(plan.some((c) => c.path === idpMetadataUrl('https://localhost:8081', endpoints.entityId)));

    const fixtures = join(dirname(fileURLToPath(import.meta.url)), '../packages/saml2-sp-nodejs/test/fixtures');
    const metaConfig = join(dir, 'saml-port.json');
    writeFileSync(metaConfig, JSON.stringify({
      entityId: file.entityId, acsUrl: file.acsUrl,
      privateKey: join(fixtures, 'sp.key'), certificate: join(fixtures, 'sp.crt'),
      idpMetadata: 'https://idp.example/metadata',
      ssf: { transmitter: 'https://localhost:8081', pollIntervalMs: 3000 },
    }));
    const xml = metadataFor(metaConfig, endpoints.entityId, endpoints.acsUrl);
    assert.match(xml, /entityID="http:\/\/localhost:3001\/saml\/metadata"/);
    assert.match(xml, /Location="http:\/\/localhost:3001\/saml\/acs"/);
    assert.doesNotMatch(xml, /localhost:3000/);
    const registered = planFor(files, 'https://localhost:8081', '', xml)[0]!.body as { fields: { samlSpMetadata: string } };
    assert.equal(registered.fields.samlSpMetadata, xml);
    assert.equal(JSON.parse(readFileSync(metaConfig, 'utf8')).ssf.pollIntervalMs, 3000);
  });
});
