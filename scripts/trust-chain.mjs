// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// Fetches the identity provider's listener CA trust chain and writes the file the configuration's
// idpCa names. iya-sts publishes that bundle at GET /tls/server-certificate: the listener
// certificate, the TLS Issuing CA, the Intermediate, and the Root. The first fetch does not verify
// TLS; there is nothing to verify it against until this file exists. If that document is missing,
// the handshake's own chain is used.
//
//   node scripts/trust-chain.mjs --config demo/saml.json --idp https://localhost:8081
//
// scripts/configure-iya-sts.ts, the install script, calls saveTrustChain on every run and reports a
// failure. Run this by hand to refresh the file after iya-sts made a new CA (a development iya-sts
// does when it restarts), then rebuild the demo image, which carries the file from build time.

import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { isIP } from 'node:net';
import { dirname, isAbsolute, resolve } from 'node:path';
import { connect } from 'node:tls';
import { pathToFileURL } from 'node:url';

const TIMEOUT_MS = 10_000;

/** SNI is a hostname. An IP address literal is not one, and Node refuses it. */
function servernameOf(hostname) {
  return isIP(hostname) ? undefined : hostname;
}

/** A path or `file:` path. PEM and `env:` are the configuration's own value, and are not a file to write. */
export function trustPath(raw, baseDir) {
  if (typeof raw !== 'string') return undefined;
  const value = raw.trim();
  if (!value || value.includes('-----BEGIN') || value.startsWith('env:')) return undefined;
  const path = value.startsWith('file:') ? value.slice(5) : value;
  if (!path) return undefined;
  return isAbsolute(path) ? path : resolve(baseDir, path);
}

function certificatesOf(pem) {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((block) => new X509Certificate(block));
}

function bundleOf(certs) {
  if (!certs.length) throw new Error('the trust chain has no certificates');
  const anchor = [...certs].reverse().find((cert) => cert.subject === cert.issuer) ?? certs[certs.length - 1];
  return {
    pem: `${certs.map((cert) => cert.toString().trim()).join('\n')}\n`,
    anchor,
    count: certs.length,
  };
}

/** `GET /tls/server-certificate`. Verification is off: this fetch is what makes the next one possible. */
function fetchPublished(origin) {
  const target = new URL('/tls/server-certificate', origin);
  return new Promise((resolvePromise, reject) => {
    const servername = servernameOf(target.hostname);
    const req = https.request({
      host: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: 'GET',
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      timeout: TIMEOUT_MS,
      ...(servername ? { servername } : {}),
      headers: { accept: 'text/plain' },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        if ((res.statusCode ?? 0) !== 200) {
          reject(new Error(`${target.href} answered ${res.statusCode}`));
          return;
        }
        try {
          resolvePromise(bundleOf(certificatesOf(Buffer.concat(chunks).toString('utf8'))));
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${target.href} did not answer within ${TIMEOUT_MS / 1000} s`)));
    req.on('error', reject);
    req.end();
  });
}

/** Every certificate the handshake presented, leaf first, including the root when the server sends it. */
function fetchHandshake(origin) {
  const target = new URL(origin);
  return new Promise((resolvePromise, reject) => {
    const servername = servernameOf(target.hostname);
    const socket = connect({
      host: target.hostname,
      port: Number(target.port || 443),
      ...(servername ? { servername } : {}),
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    }, () => {
      const certs = [];
      const seen = new Set();
      let current = socket.getPeerCertificate(true);
      while (current?.raw && current.fingerprint256 && !seen.has(current.fingerprint256)) {
        seen.add(current.fingerprint256);
        certs.push(new X509Certificate(current.raw));
        const next = current.issuerCertificate;
        if (!next || next === current || !next.raw) break;
        current = next;
      }
      socket.end();
      try {
        resolvePromise(bundleOf(certs));
      } catch (err) {
        reject(err);
      }
    });
    socket.setTimeout(TIMEOUT_MS, () => {
      socket.destroy();
      reject(new Error(`${origin} did not complete a TLS handshake`));
    });
    socket.on('error', reject);
  });
}

/** The published trust chain, or the handshake's chain when that document is not served. */
export async function fetchTrustChain(origin) {
  try {
    return await fetchPublished(origin);
  } catch {
    return fetchHandshake(origin);
  }
}

/** Writes the chain to `dest`, replacing whatever was there. */
export async function saveTrustChain(origin, dest) {
  const chain = await fetchTrustChain(origin);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, chain.pem);
  return { ...chain, path: dest, origin };
}

function argsOf(argv) {
  let config = process.env.SAML_CONFIG || '';
  let idp = process.env.IYA_STS_URL || '';
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--config' || argv[i] === '--idp') {
      const value = argv[i + 1] ?? '';
      if (!value) throw new Error(`${argv[i]} needs a value`);
      if (argv[i] === '--config') config = value;
      else idp = value;
      i += 1;
    }
  }
  if (!config) throw new Error('trust-chain needs --config <file> or SAML_CONFIG');
  return { config: resolve(config), idp: idp || 'https://localhost:8081' };
}

async function main() {
  const args = argsOf(process.argv.slice(2));
  const raw = JSON.parse(readFileSync(args.config, 'utf8'));
  const dest = trustPath(raw.idpCa, dirname(args.config));
  if (!dest) throw new Error(`${args.config} idpCa is not a file this process can update`);
  const saved = await saveTrustChain(new URL(args.idp).origin, dest);
  console.log(`Saved ${saved.origin}'s listener CA trust chain (${saved.count} certificate(s)) to ${saved.path}`);
  console.log(`  trust anchor ${saved.anchor.subject.replaceAll('\n', ', ')}`);
  console.log(`  sha256 ${saved.anchor.fingerprint256}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(`idpCa: not updated: ${err.message}`);
    process.exit(1);
  });
}
