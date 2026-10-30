#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * Sets up the demo against a running iya-sts, with the two metadata documents doing all the work:
 *
 *   1. the service provider's key pair, if the files the configuration names do not exist yet
 *      (the same as `npm run generate-keys`);
 *   2. the identity provider's TLS root, if the configuration's `idpCa` file does not exist yet: taken
 *      from the TLS handshake (trust on first use) and its fingerprint printed, for you to compare with
 *      iya-sts's Server configuration → PKI page;
 *   3. this service provider's METADATA (the same as `npm run generate-metadata`), written to
 *      demo/generated/sp-metadata.xml and REGISTERED on iya-sts from that document: the application is
 *      created with it in `samlSpMetadata`, which iya-sts consumes on create, or — when it exists
 *      already — the document is consumed again with `saml2/upload-metadata`. Its ACS endpoints and
 *      bindings, its signing and encryption certificate and AuthnRequestsSigned all come from it;
 *      Then the application's assertion encryption is pinned: `saml2EncryptAssertion` TRUE with
 *      AES-256-GCM and RSA-OAEP (SHA-256). The encryption key in the metadata already makes iya-sts
 *      encrypt; these name the algorithms rather than leaving them to the realm's defaults;
 *   4. iya-sts's IdP METADATA for this service provider (`/saml2/metadata/<entityID>`), checked with the
 *      library's own reader and written where the configuration's `idpMetadata` points, so the library
 *      learns the IdP (entityID, SSO and artifact resolution endpoints, signing certificate) from it;
 *   5. a test user to sign in as.
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/configure-iya-sts.ts
 *   node scripts/configure-iya-sts.ts --idp https://localhost:8081 --config demo/saml.json
 *   node scripts/configure-iya-sts.ts --dry-run          # print the plan, send nothing
 *
 * The management API token is minted as iya-sts's seeded client `sts-api-client` (client_credentials,
 * HTTP Basic), audienced to `<idp>/admin-api`, scope `admin:read admin:write`. The secret is
 * ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET; iya-sts's docs/management-api.md says where
 * a compose stack keeps it.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { connect, type PeerCertificate } from 'node:tls';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { main as cli } from '../packages/saml2-sp-nodejs/src/cli.ts';
import { send } from '../packages/saml2-sp-nodejs/src/http.ts';
import { readIdpMetadata } from '../packages/saml2-sp-nodejs/src/metadata.ts';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function usage(): string {
  return `Usage: node scripts/configure-iya-sts.ts [--config path] [--idp url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's SAML configuration (default: demo/saml.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --test-user     The test user to create (default: saml-demo-user). Its password is
                  $SAML_DEMO_USER_PASSWORD, or one is generated and printed once. With
                  $SAML_DEMO_USER_PASSWORD set, an existing user's password is replaced.
  --no-test-user  Do not create a test user.
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET.`;
}

export interface Args {
  config: string;
  idp: string;
  testUser: string;
  dryRun: boolean;
  help: boolean;
}

export function parseArgs(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): Args {
  const out: Args = {
    config: resolve(repoRoot, 'demo/saml.json'),
    idp: (env.IYA_STS_URL || 'https://localhost:8081').replace(/\/+$/, ''),
    testUser: 'saml-demo-user',
    dryRun: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    const value = () => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${arg} needs a value\n${usage()}`);
      return v;
    };
    if (arg === '--help' || arg === '-h') out.help = true;
    else if (arg === '--config') out.config = resolve(value());
    else if (arg === '--idp') out.idp = value().replace(/\/+$/, '');
    else if (arg === '--test-user') out.testUser = value().trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else if (arg === '--dry-run') out.dryRun = true;
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  const u = new URL(out.idp);
  if (u.protocol !== 'https:') throw new Error(`--idp must be https, not ${out.idp}`);
  return out;
}

/** The files the configuration names, resolved against it. */
export interface DemoFiles {
  entityId: string;
  key: string;
  cert: string;
  idpMetadata: string;
  idpCa: string | undefined;
  spMetadata: string;
}

export function filesOf(configPath: string): DemoFiles {
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as Record<string, string | undefined>;
  const base = dirname(configPath);
  const at = (p: string | undefined, what: string) => {
    if (!p || p.includes('-----BEGIN') || /^https?:/.test(p) || p.startsWith('<')) {
      throw new Error(`${configPath}'s ${what} must be a file path for this script to write`);
    }
    return isAbsolute(p) ? p : resolve(base, p);
  };
  if (!raw.entityId) throw new Error(`${configPath} has no entityId`);
  const key = at(raw.privateKey, 'privateKey');
  return {
    entityId: raw.entityId,
    key,
    cert: at(raw.certificate, 'certificate'),
    idpMetadata: at(raw.idpMetadata, 'idpMetadata'),
    idpCa: raw.idpCa ? at(raw.idpCa, 'idpCa') : undefined,
    spMetadata: resolve(dirname(key), 'sp-metadata.xml'),
  };
}

/** The realm's base and the origin a token is minted at: `/realm/<id>` is kept, anything else refused. */
export function realmOf(idp: string): { origin: string; base: string } {
  const u = new URL(idp);
  const path = u.pathname.replace(/\/+$/, '');
  if (path && !/^\/realm\/[^/]+$/.test(path)) throw new Error(`--idp must be iya-sts's base URL or a realm's (/realm/<id>), not ${idp}`);
  return { origin: u.origin, base: `${u.origin}${path}` };
}

/** iya-sts's metadata for one service provider: its SSO, SLO and artifact resolution endpoints for it. */
export const idpMetadataUrl = (base: string, entityId: string) => `${base}/saml2/metadata/${encodeURIComponent(entityId)}`;

/** The application's assertion encryption, pinned (iya-sts saml/CLAUDE.md, the per-application settings). */
export const ENCRYPTION: Record<string, string> = {
  saml2EncryptAssertion: 'TRUE',
  saml2EncryptionAlgorithm: 'aes256-gcm',
  saml2KeyTransportAlgorithm: 'rsa-oaep',
};

/** The management API calls, in order, as `{ method, path, body, why }`. Pure, for --dry-run and the tests. */
export function planFor(files: DemoFiles, base: string, testUser: string, spMetadataXml: string) {
  const calls: Array<{ method: string; path: string; body: unknown; why: string }> = [
    {
      method: 'POST', path: `${base}/admin-api/applications/create`, why: `register ${files.entityId} from its metadata`,
      body: { identifier: files.entityId, name: 'saml2-sp-nodejs demo', protocols: ['saml2'], fields: { samlSpMetadata: spMetadataXml } },
    },
    {
      method: 'POST', path: `${base}/admin-api/saml2/upload-metadata`, why: '(only if it already exists) consume the metadata again',
      body: { sp: files.entityId, family: 'saml2', document: spMetadataXml },
    },
    { method: 'GET', path: idpMetadataUrl(base, files.entityId), body: undefined, why: `fetch the IdP metadata into ${files.idpMetadata}` },
  ];
  for (const [attribute, value] of Object.entries(ENCRYPTION)) {
    calls.splice(2, 0, { method: 'POST', path: `${base}/admin-api/applications/set`, why: `encrypt the assertion: ${attribute}`, body: { application: files.entityId, attribute, value } });
  }
  if (testUser) calls.push({ method: 'POST', path: `${base}/admin-api/users/create`, why: `create the test user ${testUser}`, body: { username: testUser } });
  return calls;
}

/** The root of the chain the server presents, taken from the handshake without verifying it. */
function fetchTlsRoot(origin: string): Promise<X509Certificate> {
  const u = new URL(origin);
  return new Promise((resolvePromise, reject) => {
    const socket = connect({ host: u.hostname, port: Number(u.port || 443), servername: u.hostname, rejectUnauthorized: false }, () => {
      let cert = socket.getPeerCertificate(true) as PeerCertificate & { issuerCertificate?: PeerCertificate };
      while (cert.issuerCertificate && cert.issuerCertificate !== cert && cert.issuerCertificate.raw) cert = cert.issuerCertificate;
      socket.end();
      resolvePromise(new X509Certificate(cert.raw));
    });
    socket.on('error', reject);
  });
}

async function json(url: string, ca: string | undefined, init: { method?: string; headers?: Record<string, string>; body?: string }) {
  const tls = ca ? { ca } : {};
  const answer = await send(url, init, tls, 'config');
  let body: Record<string, unknown> = {};
  try {
    body = answer.body ? JSON.parse(answer.body) : {};
  } catch {
    throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status} with non-JSON: ${answer.body.slice(0, 300)}`);
  }
  if (answer.status === 401 || answer.status === 403) throw new Error(`${init.method ?? 'GET'} ${url} answered ${answer.status}: ${JSON.stringify(body).slice(0, 300)}`);
  return { status: answer.status, body };
}

const errorsOf = (body: Record<string, unknown>) => ([] as unknown[]).concat(body.errors ?? []).map(String);

async function mintAdminToken(origin: string, base: string, ca: string | undefined, secret: string): Promise<string> {
  const form = new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read admin:write', resource: `${base}/admin-api` });
  const reply = await json(`${base}/oauth2/token`, ca, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}` },
    body: form.toString(),
  });
  if (reply.status !== 200 || typeof reply.body.access_token !== 'string') {
    throw new Error(`the token endpoint at ${origin} answered ${reply.status} ${JSON.stringify(reply.body).slice(0, 300)}`);
  }
  return reply.body.access_token;
}

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  const files = filesOf(args.config);
  const { origin, base } = realmOf(args.idp);

  if (args.dryRun) {
    const xml = existsSync(files.cert) ? '<the SP metadata from the configuration>' : '<the SP metadata, once the key pair exists>';
    if (!existsSync(files.key)) console.log(`# would generate the key pair ${files.key}, ${files.cert}`);
    if (files.idpCa && !existsSync(files.idpCa)) console.log(`# would save ${origin}'s TLS root to ${files.idpCa}`);
    console.log(`# would write ${files.spMetadata}`);
    for (const c of planFor(files, base, args.testUser, xml)) {
      console.log(`${c.method} ${c.path}  # ${c.why}${c.body ? `\n${JSON.stringify(c.body, null, 2)}` : ''}`);
    }
    return;
  }

  // 1. The key pair.
  if (!existsSync(files.key) && !existsSync(files.cert)) {
    console.log('No key pair yet; generating one.');
    await cli(['generate-keys', '--config', args.config]);
  }

  // 2. The IdP's TLS root, trusted on first use.
  let ca: string | undefined;
  if (files.idpCa) {
    if (!existsSync(files.idpCa)) {
      const root = await fetchTlsRoot(origin);
      mkdirSync(dirname(files.idpCa), { recursive: true });
      writeFileSync(files.idpCa, root.toString());
      console.log(`Saved ${origin}'s TLS root to ${files.idpCa} (trusted on first use):`);
      console.log(`  ${root.subject.replace(/\n/g, ', ')}\n  sha256 ${root.fingerprint256}`);
      console.log('  Compare it with the Root CA on iya-sts\'s Server configuration → PKI page.');
    }
    ca = readFileSync(files.idpCa, 'utf8');
  }

  // 3. The SP metadata, and the application registered from it.
  await cli(['metadata', '--config', args.config, '--out', files.spMetadata]);
  const spMetadataXml = readFileSync(files.spMetadata, 'utf8');
  const secret = process.env.ADMIN_API_CLIENT_SECRET || process.env.STS_ADMIN_API_CLIENT_SECRET || '';
  if (!secret) throw new Error('neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.');
  const token = await mintAdminToken(origin, base, ca, secret);
  const api = (path: string, body: unknown) => json(`${base}/admin-api${path}`, ca, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  const [create, upload] = planFor(files, base, args.testUser, spMetadataXml);
  const created = await api('/applications/create', create!.body);
  if (created.body.ok) {
    console.log(`Registered ${files.entityId} from its metadata.`);
    if (typeof created.body.message === 'string' && /NOT consumed/.test(created.body.message)) {
      throw new Error(`iya-sts created the application but refused its metadata: ${created.body.message}`);
    }
  } else if (errorsOf(created.body).some((e) => /already in this registry/i.test(e))) {
    const consumed = await api('/saml2/upload-metadata', upload!.body);
    if (!consumed.body.ok) throw new Error(`iya-sts refused the metadata: ${JSON.stringify(consumed.body).slice(0, 500)}`);
    console.log(`${files.entityId} was registered already; its metadata was consumed again.`);
  } else {
    throw new Error(`iya-sts refused to create ${files.entityId}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }

  for (const [attribute, value] of Object.entries(ENCRYPTION)) {
    const set = await api('/applications/set', { application: files.entityId, attribute, value });
    if (!set.body.ok) throw new Error(`setting ${attribute}=${value} was refused: ${JSON.stringify(set.body).slice(0, 300)}`);
  }
  console.log('Assertions to it are encrypted: AES-256-GCM, the key wrapped with RSA-OAEP (SHA-256).');

  // 4. The IdP metadata, for the library.
  const url = idpMetadataUrl(base, files.entityId);
  const fetched = await send(url, { headers: { accept: 'application/samlmetadata+xml' } }, ca ? { ca } : {}, 'metadata');
  if (fetched.status !== 200) throw new Error(`${url} answered ${fetched.status}`);
  const idp = readIdpMetadata(fetched.body);
  mkdirSync(dirname(files.idpMetadata), { recursive: true });
  writeFileSync(files.idpMetadata, fetched.body);
  console.log(`Saved the IdP metadata to ${files.idpMetadata}:`);
  console.log(`  entityID   ${idp.entityId}`);
  console.log(`  SSO        ${idp.ssoUrls.redirect ?? idp.ssoUrls.post}`);
  console.log(`  artifacts  ${[...idp.artifactResolutionServices.values()].join(', ') || '(none)'}`);

  // 5. The test user.
  if (args.testUser) {
    const found = await json(`${base}/admin-api/users?user=${encodeURIComponent(args.testUser)}`, ca, { headers: { accept: 'application/json', authorization: `Bearer ${token}` } });
    const password = process.env.SAML_DEMO_USER_PASSWORD || '';
    if (found.body.known === true && password) {
      const set = await api('/users/set-password', { user: args.testUser, password, passwordConfirm: password });
      if (!set.body.ok) throw new Error(`setting ${args.testUser}'s password was refused: ${JSON.stringify(set.body).slice(0, 300)}`);
      console.log(`User ${args.testUser} already exists; its password is now SAML_DEMO_USER_PASSWORD.`);
    } else if (found.body.known === true) {
      console.log(`User ${args.testUser} already exists; its password is unchanged (set SAML_DEMO_USER_PASSWORD to replace it).`);
    } else {
      const attributes = { cn: `SAML Demo ${args.testUser}`, givenName: 'SAML', sn: 'Demo', displayName: `SAML Demo ${args.testUser}`, mail: `${args.testUser}@saml-demo.test` };
      const body = password
        ? { username: args.testUser, invent: false, credential: 'password', password, passwordConfirm: password, attributes }
        : { username: args.testUser, invent: false, credential: 'generate', attributes };
      const made = await api('/users/create', body);
      if (!made.body.ok) throw new Error(`creating ${args.testUser} was refused: ${JSON.stringify(made.body).slice(0, 300)}`);
      console.log(`Created user ${args.testUser}.`);
      if (made.body.password) console.log(`Generated password for ${args.testUser} (shown once): ${String(made.body.password)}`);
    }
  }
  console.log('Done. Start the demo with: docker compose up --build');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err: Error) => {
    console.error(err.message);
    process.exit(1);
  });
}
