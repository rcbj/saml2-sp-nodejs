#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// saml2-sp-nodejs's command line: the two things a service provider needs before its first sign-in.
//
//   saml2-sp-nodejs generate-keys --config saml.json [--cn name] [--days n] [--bits n] [--force]
//   saml2-sp-nodejs generate-keys --key sp.key --cert sp.crt --cn name
//   saml2-sp-nodejs metadata --config saml.json [--out sp-metadata.xml]

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { resolveConfig, type SamlConfig } from './config.ts';
import { ServiceProvider } from './service-provider.ts';
import { createSelfSignedKeyPair } from './x509.ts';

export const USAGE = `Usage:
  saml2-sp-nodejs generate-keys --config <saml.json> [--cn <name>] [--days <n>] [--bits <n>] [--force]
  saml2-sp-nodejs generate-keys --key <file> --cert <file> [--cn <name>] [--days <n>] [--bits <n>] [--force]
      A new RSA key and a self-signed certificate, written where the configuration's privateKey and
      certificate point (or to --key and --cert). Refuses to replace existing files without --force.
      The common name defaults to the host of the configuration's entityId.

  saml2-sp-nodejs metadata --config <saml.json> [--out <file>]
      This service provider's SAML metadata, from the configuration and its certificate: give it to the
      identity provider. Written to --out, or to standard output.`;

type Args = Record<string, string | true>;

export function parseArgs(argv: readonly string[]): { command: string | undefined; args: Args } {
  const [command, ...rest] = argv;
  const args: Args = {};
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i]!;
    if (!a.startsWith('--')) throw new Error(`unexpected argument ${a}\n\n${USAGE}`);
    const key = a.slice(2);
    if (key === 'force' || key === 'help') {
      args[key] = true;
    } else {
      const v = rest[i + 1];
      if (v === undefined || v.startsWith('--')) throw new Error(`--${key} needs a value\n\n${USAGE}`);
      args[key] = v;
      i += 1;
    }
  }
  return { command, args };
}

const str = (v: string | true | undefined) => (typeof v === 'string' ? v : undefined);

/** Where generate-keys writes, from --key/--cert or from the configuration file's own paths. */
export function keyPaths(args: Args): { key: string; cert: string; commonName: string } {
  const configPath = str(args.config);
  let key = str(args.key);
  let cert = str(args.cert);
  let commonName = str(args.cn);
  if (configPath) {
    const raw = JSON.parse(readFileSync(configPath, 'utf8')) as Partial<SamlConfig>;
    const base = dirname(resolve(configPath));
    const at = (p: string | undefined, what: string) => {
      if (!p || p.includes('-----BEGIN ')) throw new Error(`${configPath}'s ${what} must be a file path for generate-keys to write to`);
      return isAbsolute(p) ? p : resolve(base, p);
    };
    key ??= at(raw.privateKey, 'privateKey');
    cert ??= at(raw.certificate, 'certificate');
    if (!commonName && raw.entityId) {
      try {
        commonName = new URL(raw.entityId).host;
      } catch {
        commonName = raw.entityId;
      }
    }
  }
  if (!key || !cert) throw new Error(`generate-keys needs --config, or --key and --cert\n\n${USAGE}`);
  return { key: resolve(key), cert: resolve(cert), commonName: commonName ?? 'saml2-sp-nodejs service provider' };
}

export async function main(argv: readonly string[] = process.argv.slice(2), out: (s: string) => void = (s) => process.stdout.write(s)): Promise<void> {
  const { command, args } = parseArgs(argv);
  if (!command || args.help || command === 'help') {
    out(`${USAGE}\n`);
    return;
  }
  if (command === 'generate-keys') {
    const { key, cert, commonName } = keyPaths(args);
    if (!args.force && (existsSync(key) || existsSync(cert))) {
      throw new Error(`${existsSync(key) ? key : cert} already exists; pass --force to replace the key pair.\n`
        + 'Replacing it means giving the identity provider the new metadata before the next sign-in.');
    }
    const days = str(args.days) ? Number(args.days) : undefined;
    const bits = str(args.bits) ? Number(args.bits) : undefined;
    if (days !== undefined && !(Number.isInteger(days) && days > 0)) throw new Error('--days must be a positive whole number');
    if (bits !== undefined && ![2048, 3072, 4096].includes(bits)) throw new Error('--bits must be 2048, 3072 or 4096');
    const pair = createSelfSignedKeyPair({ commonName, ...(days ? { days } : {}), ...(bits ? { bits } : {}) });
    mkdirSync(dirname(key), { recursive: true });
    mkdirSync(dirname(cert), { recursive: true });
    writeFileSync(key, pair.privateKeyPem, { mode: 0o600 });
    writeFileSync(cert, pair.certificatePem, { mode: 0o644 });
    out(`Wrote the private key  ${key} (mode 600)\n`);
    out(`Wrote the certificate  ${cert}\n`);
    out(`  subject   CN=${commonName}\n  valid to  ${pair.certificate.validTo}\n  sha256    ${pair.certificate.fingerprint256}\n`);
    return;
  }
  if (command === 'metadata') {
    const configPath = str(args.config);
    if (!configPath) throw new Error(`metadata needs --config\n\n${USAGE}`);
    // The metadata needs only this service provider's half of the configuration: the identity
    // provider's metadata and TLS root are neither read nor fetched, so this runs before they exist.
    const raw = JSON.parse(readFileSync(configPath, 'utf8')) as SamlConfig;
    delete raw.idpCa;
    const xml = new ServiceProvider(resolveConfig(raw, dirname(resolve(configPath))), undefined).metadata();
    const target = str(args.out);
    if (target) {
      mkdirSync(dirname(resolve(target)), { recursive: true });
      writeFileSync(target, xml);
      out(`Wrote the service provider metadata to ${resolve(target)}\n`);
    } else {
      out(xml);
    }
    return;
  }
  throw new Error(`unknown command ${command}\n\n${USAGE}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err: Error) => {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  });
}
