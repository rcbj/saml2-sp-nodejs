// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The setup script's plan, offline: what it registers, and where.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { ENCRYPTION, MULTIPLE_ACCOUNTS, filesOf, ssfCalls, idpMetadataUrl, parseArgs, planFor, realmOf } from './configure-iya-sts.ts';

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
    const a = parseArgs(['--idp', 'https://idp.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(a.idp, 'https://idp.test');
    assert.equal(a.testUser, '');
    assert.equal(a.dryRun, true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });
});
