// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The back channel: fetching the identity provider's metadata and resolving an artifact. node:http(s)
// only. TLS is always verified; `ca` adds the certificates to trust beyond node's own store (an identity
// provider whose listener certificate chains to a private root). Answers are capped in size and time.

import http from 'node:http';
import https from 'node:https';
import { rootCertificates } from 'node:tls';
import { SamlError, type SamlErrorCode } from './errors.ts';

const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 15_000;

export interface BackChannelOptions {
  /** PEM certificates to trust for TLS, in addition to node's own store. */
  ca?: string;
  /** A client certificate and key to present (mutual TLS), PEM. */
  cert?: string;
  key?: string;
}

export interface HttpAnswer {
  status: number;
  contentType: string;
  body: string;
}

export function send(url: string, init: { method?: string; headers?: Record<string, string>; body?: string },
  tls: BackChannelOptions, code: SamlErrorCode): Promise<HttpAnswer> {
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return Promise.reject(new SamlError(code, `${url} is not an http(s) URL`));
  }
  const payload = init.body === undefined ? undefined : Buffer.from(init.body, 'utf8');
  const options: https.RequestOptions = {
    method: init.method ?? 'GET',
    headers: { ...(init.headers ?? {}), ...(payload ? { 'content-length': String(payload.length) } : {}) },
    timeout: TIMEOUT_MS,
  };
  if (target.protocol === 'https:') {
    // Naming a private root adds it to node's own store rather than replacing the store.
    if (tls.ca) options.ca = [tls.ca, ...rootCertificates];
    if (tls.cert && tls.key) {
      options.cert = tls.cert;
      options.key = tls.key;
    }
  }
  const lib = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(target, options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          req.destroy(new SamlError(code, `${url} answered more than ${MAX_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        contentType: String(res.headers['content-type'] ?? ''),
        body: Buffer.concat(chunks).toString('utf8'),
      }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new SamlError(code, `${url} did not answer within ${TIMEOUT_MS / 1000} s`)));
    req.on('error', (err) => reject(err instanceof SamlError ? err : new SamlError(code, `${url}: ${err.message}`, { cause: err })));
    if (payload) req.write(payload);
    req.end();
  });
}

