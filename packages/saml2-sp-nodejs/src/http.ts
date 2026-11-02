// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The back channel: fetching the identity provider's metadata and resolving an artifact. node:http(s)
// only. TLS is always verified; `ca` adds the certificates to trust beyond node's own store (an identity
// provider whose listener certificate chains to a private root). Answers are capped in size and time.
// Plain http is refused unless the host is loopback (see plainHttpRefusal), and a URL holding whitespace
// or a control character is refused outright (see hasWhitespaceOrControl). node:http(s) never follows a
// redirect, and nothing here does either: a 3xx is returned to the caller as the answer.

import http from 'node:http';
import https from 'node:https';
import { isIPv4 } from 'node:net';
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

/** A loopback host: 127.0.0.0/8, ::1 or the name localhost. `host` is a WHATWG URL hostname. */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === 'localhost') return true;
  if (isIPv4(h)) return h.split('.')[0] === '127';
  // The WHATWG parser writes IPv6 bracketed and in its shortest form, so ::1 is always "[::1]".
  return h === '[::1]';
}

/**
 * The refusal of a plain http URL, unless it names a loopback host, where the bytes never leave the machine.
 * Userinfo is never loopback, so `http://localhost:80@host/` cannot pass as localhost. The message
 * names the scheme and host[:port] only: never userinfo, path or query.
 */
function plainHttpRefusal(target: URL, code: SamlErrorCode): SamlError | undefined {
  if (target.username === '' && target.password === '' && isLoopbackHost(target.hostname)) return undefined;
  return new SamlError(code, `http://${target.host} is refused: plain http is allowed only to a loopback host `
    + '(127.0.0.0/8, ::1, localhost); use https');
}

/**
 * Whether a URL holds whitespace (any Unicode White_Space, U+00A0 included) or a control character
 * (C0, DEL, C1). The WHATWG parser silently drops tabs and newlines and trims leading and trailing
 * spaces and C0 controls, so such a URL can name one host to a reader and dial another; none is ever
 * a valid URL.
 */
export function hasWhitespaceOrControl(url: string): boolean {
  return /[\s\p{Cc}]/u.test(url);
}

export function send(url: string, init: { method?: string; headers?: Record<string, string>; body?: string },
  tls: BackChannelOptions, code: SamlErrorCode): Promise<HttpAnswer> {
  // Before parsing: the parser would quietly remove what the check below must see. The message never
  // repeats the URL.
  if (hasWhitespaceOrControl(url)) {
    return Promise.reject(new SamlError(code, 'the URL is refused: it holds whitespace or a control character'));
  }
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return Promise.reject(new SamlError(code, `${url} is not an http(s) URL`));
  }
  // Every fetch this library makes goes through here: the identity provider's metadata (its signing
  // keys), the ArtifactResolve (the signed request out, the assertion back) and the Shared Signals
  // transmitter (SETs and the bearer token). None of them may travel in the clear off this machine, so
  // plain http is refused before any lookup or connection unless the host is loopback.
  const refusal = target.protocol === 'http:' ? plainHttpRefusal(target, code) : undefined;
  if (refusal) return Promise.reject(refusal);
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

