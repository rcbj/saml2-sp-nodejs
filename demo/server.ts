// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The demo: a traditional server-rendered web application that signs people in with SAML 2.0 through
// saml2-sp-nodejs. node:http and nothing else; Node runs this TypeScript file as it is.
//
//   GET  /                the home page: who is signed in, or the sign-in buttons
//   GET  /login           a signed AuthnRequest; ?binding=post|redirect|artifact picks the RESPONSE binding
//   GET  /saml/acs        the assertion consumer service, for HTTP-Redirect and HTTP-Artifact
//   POST /saml/acs        the assertion consumer service, for HTTP-POST (and an artifact posted)
//   GET  /saml/metadata   this service provider's metadata (its entityID)
//   POST /logout          ends the local session
//   GET  /events          Server-Sent Events for the signed-in tab: a Shared Signals event ended its session
//   GET  /healthz         for the container's health check
//
// SHARED SIGNALS: with an `ssf` block in the configuration file the demo is also a CAEP and RISC receiver
// (the library's SignalsReceiver): one poll stream at the identity provider, authenticated by mutual TLS
// with the service provider's own key pair. An event that revokes a session, or disables, purges or
// compromises an account, ENDS the matching local sessions here, and their open tabs are told at once.
//
// Two cookies. `saml_pending` holds the outstanding AuthnRequest ids, HMAC-signed, scoped to the ACS,
// and SameSite=None: the identity provider's HTTP-POST binding brings the browser back with a CROSS-SITE
// POST, on which a Lax cookie is not sent. `sid` is the session, SameSite=Lax, set after the ACS.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EVENT, SamlError, ServiceProvider, SignalsReceiver, type ResponseBinding, type SamlLogin, type SignalEvent } from 'saml2-sp-nodejs';

const here = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const CONFIG = resolve(process.env.SAML_CONFIG || resolve(here, 'saml.json'));
const SECRET = process.env.SESSION_SECRET ? Buffer.from(process.env.SESSION_SECRET) : randomBytes(32);
const SESSION_MS = 8 * 3600_000;
const MAX_SESSIONS = 10_000;
const MAX_BODY = 512 * 1024;
const STYLES = readFileSync(resolve(here, 'public/styles.css'));
const APP_JS = readFileSync(resolve(here, 'public/app.js'));
const SSF = (() => {
  try {
    const raw = JSON.parse(readFileSync(CONFIG, 'utf8')) as { ssf?: { transmitter?: string; pollIntervalMs?: number } };
    return raw.ssf?.transmitter ? raw.ssf : undefined;
  } catch {
    return undefined;
  }
})();

// The service provider is built on first use and again after a failure, so the demo starts (and is
// healthy) before the identity provider is reachable or the setup script has been run.
let spPromise: Promise<ServiceProvider> | undefined;
function serviceProvider(): Promise<ServiceProvider> {
  spPromise ??= ServiceProvider.fromFile(CONFIG).then((sp) => {
    startReceiver(sp);
    return sp;
  }, (err: unknown) => {
    spPromise = undefined;
    throw err;
  });
  return spPromise;
}

interface Session {
  login: SamlLogin;
  expires: number;
  /** Shared Signals events about this session or its person, newest first. */
  signals: Array<{ at: string; type: string; ended: boolean; detail: string }>;
}
const sessions = new Map<string, Session>();
// The open /events streams of each session, told when a signal arrives or ends it.
const listeners = new Map<string, Set<ServerResponse>>();

function tell(sid: string, event: string, data: unknown): void {
  for (const res of listeners.get(sid) ?? []) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (event === 'signed-out') res.end();
  }
  if (event === 'signed-out') listeners.delete(sid);
}

const shortType = (uri: string) => uri.replace(/^.*\/event-type\//, '');

// THE RECEIVER, started once the service provider is loaded. Its state is shown on the home page.
let receiver: SignalsReceiver | undefined;
let receiverState = SSF ? 'starting' : 'not configured (no ssf block in the configuration file)';
function startReceiver(sp: ServiceProvider): void {
  if (!SSF || receiver) return;
  const r = new SignalsReceiver({
    transmitter: SSF.transmitter!,
    // Mutual TLS with the service provider's own key pair: no secret, nothing to rotate but the key.
    tls: {
      ...(sp.config.idpCa ? { ca: sp.config.idpCa } : {}),
      cert: sp.config.certificate.toString(),
      key: sp.config.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    },
    description: `saml2-sp-nodejs demo (${sp.config.entityId})`,
    ...(SSF.pollIntervalMs ? { pollIntervalMs: SSF.pollIntervalMs } : {}),
    onEndSessions: (ids: string[], event: SignalEvent) => {
      for (const sid of ids) {
        sessions.delete(sid);
        tell(sid, 'signed-out', { type: shortType(event.type), reason: event.payload.reason_user ?? event.payload.reason_admin ?? event.payload.reason ?? null });
      }
      console.log(`ssf: ${shortType(event.type)} ended ${ids.length} local session(s)`);
    },
  });
  r.on('*', (event: SignalEvent) => {
    const detail = [event.subject.person, event.subject.email, event.subject.idpSession && `IdP session ${event.subject.idpSession}`]
      .filter(Boolean).join(', ');
    for (const sid of event.sessions) {
      const s = sessions.get(sid);
      s?.signals.unshift({ at: new Date().toISOString(), type: shortType(event.type), ended: event.ended, detail });
      if (s) s.signals.length = Math.min(s.signals.length, 20);
      if (!event.ended) tell(sid, 'signal', { type: shortType(event.type) });
    }
    if (event.type === EVENT.verification) console.log('ssf: verification event received');
  });
  receiver = r;
  r.start().then(() => {
    receiverState = `polling stream ${r.stream?.stream_id} at ${SSF.transmitter}`;
  }, (err: Error) => {
    receiverState = `not running: ${err.message}`;
    receiver = undefined;
    console.warn(`ssf: the receiver did not start: ${err.message}`);
  });
}

const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const mac = (value: string) => createHmac('sha256', SECRET).update(value).digest('base64url');

function sealed(value: unknown): string {
  const body = Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${body}.${mac(body)}`;
}

function unseal<T>(token: string | undefined): T | undefined {
  if (!token) return undefined;
  const [body, tag] = token.split('.');
  if (!body || !tag) return undefined;
  const want = Buffer.from(mac(body));
  const got = Buffer.from(tag);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return undefined;
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString()) as T;
  } catch {
    return undefined;
  }
}

function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

// Secure on an https deployment and on localhost, which browsers treat as a secure context; SameSite=None
// needs Secure, so the HTTP-POST binding needs one or the other.
let secureCookies = true;

function cookie(name: string, value: string, opts: { path?: string; maxAge?: number; sameSite?: 'Lax' | 'None' }): string {
  return [`${name}=${encodeURIComponent(value)}`, `Path=${opts.path ?? '/'}`, 'HttpOnly', `SameSite=${opts.sameSite ?? 'Lax'}`,
    ...(secureCookies ? ['Secure'] : []), ...(opts.maxAge !== undefined ? [`Max-Age=${opts.maxAge}`] : [])].join('; ');
}

function currentSession(req: IncomingMessage): Session | undefined {
  const sid = cookies(req).sid;
  const s = sid ? sessions.get(sid) : undefined;
  if (!s) return undefined;
  if (s.expires <= Date.now()) {
    sessions.delete(sid!);
    return undefined;
  }
  return s;
}

function send(res: ServerResponse, status: number, body: string | Buffer, headers: Record<string, string | string[]> = {}): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ...headers,
  });
  res.end(body);
}

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><link rel="stylesheet" href="/styles.css"></head>
<body><header><a href="/">saml2-sp-nodejs demo</a></header><main>
${body}
</main><footer>A traditional web application signing in with SAML 2.0 through <a href="https://www.npmjs.com/package/saml2-sp-nodejs">saml2-sp-nodejs</a>.</footer></body>
</html>
`;
}

const BINDINGS: ResponseBinding[] = ['post', 'redirect', 'artifact'];
const BINDING_LABEL: Record<ResponseBinding, string> = { post: 'HTTP-POST', redirect: 'HTTP-Redirect', artifact: 'HTTP-Artifact' };

function home(session: Session | undefined, sp: ServiceProvider | undefined, problem?: string): string {
  if (session) {
    const l = session.login;
    const rows = Object.entries(l.attributes).map(([name, values]) =>
      `<tr><th>${esc(l.attributeFriendlyNames[name] ?? name)}${l.attributeFriendlyNames[name] ? `<br><small>${esc(name)}</small>` : ''}</th><td>${values.map(esc).join('<br>')}</td></tr>`).join('');
    return page('Signed in', `<h1>Signed in as ${esc(l.nameId)}</h1>
<table class="facts">
<tr><th>NameID</th><td>${esc(l.nameId)}<br><small>${esc(l.nameIdFormat)}</small></td></tr>
<tr><th>Identity provider</th><td>${esc(l.issuer)}</td></tr>
<tr><th>Response binding</th><td>${esc(BINDING_LABEL[l.binding])}</td></tr>
<tr><th>Authenticated</th><td>${esc(l.authnInstant.toISOString?.() ?? l.authnInstant)}<br><small>${esc(l.authnContextClassRef)}</small></td></tr>
<tr><th>Session index</th><td>${esc(l.sessionIndex)}</td></tr>
<tr><th>Assertion</th><td>${esc(l.assertionId)}<br><small>${l.encrypted ? 'arrived encrypted (EncryptedAssertion), decrypted with this service provider\'s key' : 'arrived in clear'}; signature verified</small></td></tr>
</table>
<h2>Attributes</h2>
${rows ? `<table class="facts">${rows}</table>` : '<p>The identity provider released no attributes.</p>'}
<h2>Shared Signals</h2>
<p><small>Receiver: ${esc(receiverState)}</small></p>
${session.signals.length ? `<table class="facts"><tr><th>When</th><th>Event</th></tr>${session.signals.map((e) => `<tr><td>${esc(e.at)}</td><td>${esc(e.type)}${e.ended ? ' — ended this session' : ''}<br><small>${esc(e.detail)}</small></td></tr>`).join('')}</table>` : '<p>No CAEP or RISC event about this session yet. Sign this person out at the identity provider, disable them, or change their password, and watch this tab.</p>'}
<p id="signal-banner" class="problem" hidden></p>
<form method="post" action="/logout"><button type="submit">Sign out of this application</button></form>
<script src="/app.js"></script>`);
  }
  const requestBinding = sp ? (sp.config.requestBinding === 'post' ? 'HTTP-POST' : 'HTTP-Redirect') : '(configuration not loaded)';
  const buttons = BINDINGS.map((b) => `<a class="button${b === sp?.config.responseBinding ? ' primary' : ''}" href="/login?binding=${b}">Sign in — response by ${BINDING_LABEL[b]}</a>`).join('\n');
  return page('Sign in', `<h1>Sign in with SAML 2.0</h1>
${problem ? `<p class="problem">${esc(problem)}</p>` : ''}
<p>Service provider-initiated single sign-on: this application sends a <strong>signed</strong> AuthnRequest on
<strong>${esc(requestBinding)}</strong> to ${esc(sp?.idp.entityId ?? 'the identity provider')}, and asks for the Response on the binding you pick.</p>
<p class="buttons">${buttons}</p>
<p><a href="/saml/metadata">This service provider's metadata</a></p>`);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolveBody, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('the request body is too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

interface Pending {
  ids: string[];
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://demo.invalid');
  const method = req.method ?? 'GET';

  if (url.pathname === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain' });
  if (url.pathname === '/styles.css') return send(res, 200, STYLES, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'max-age=300' });
  if (url.pathname === '/app.js') return send(res, 200, APP_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'max-age=300' });

  if (url.pathname === '/events' && method === 'GET') {
    const sid = cookies(req).sid;
    if (!sid || !currentSession(req)) return send(res, 204, '');
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
    res.write(': listening\n\n');
    const set = listeners.get(sid) ?? new Set<ServerResponse>();
    set.add(res);
    listeners.set(sid, set);
    req.on('close', () => {
      set.delete(res);
      if (!set.size) listeners.delete(sid);
    });
    return;
  }

  if (url.pathname === '/' && method === 'GET') {
    const session = currentSession(req);
    let sp: ServiceProvider | undefined;
    let problem: string | undefined;
    try {
      sp = await serviceProvider();
    } catch (err) {
      problem = `The service provider is not configured yet: ${(err as Error).message}. Run the setup script (npm run configure-iya-sts).`;
    }
    return send(res, 200, home(session, sp, problem), session ? {
      'content-security-policy': "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    } : {});
  }

  if (url.pathname === '/saml/metadata' && method === 'GET') {
    const sp = await serviceProvider();
    return send(res, 200, sp.metadata(), { 'content-type': 'application/samlmetadata+xml' });
  }

  if (url.pathname === '/login' && method === 'GET') {
    const sp = await serviceProvider();
    const asked = url.searchParams.get('binding');
    const responseBinding = BINDINGS.includes(asked as ResponseBinding) ? asked as ResponseBinding : undefined;
    const nonce = randomBytes(16).toString('base64');
    const request = sp.login({ relayState: '/', nonce, ...(responseBinding ? { responseBinding } : {}) });
    // Keep the last few outstanding ids, so two tabs signing in at once both succeed.
    const before = unseal<Pending>(cookies(req).saml_pending)?.ids ?? [];
    const pending = cookie('saml_pending', sealed({ ids: [request.id, ...before].slice(0, 3) }), { path: new URL(sp.config.acsUrl).pathname, maxAge: 600, sameSite: 'None' });
    if (request.binding === 'redirect') {
      res.writeHead(302, { location: request.url, 'set-cookie': pending, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
      res.end();
      return;
    }
    // The POST binding: a form that posts to the identity provider, submitted by a script this one nonce allows.
    return send(res, 200, request.html, {
      'set-cookie': pending,
      'content-security-policy': `default-src 'none'; script-src 'nonce-${nonce}'; form-action ${new URL(request.url).origin}; frame-ancestors 'none'; base-uri 'none'`,
    });
  }

  if (url.pathname === '/saml/acs' && (method === 'GET' || method === 'POST')) {
    const sp = await serviceProvider();
    const body = method === 'POST' ? await readBody(req) : undefined;
    const pending = unseal<Pending>(cookies(req).saml_pending);
    const clearPending = cookie('saml_pending', '', { path: new URL(sp.config.acsUrl).pathname, maxAge: 0, sameSite: 'None' });
    try {
      const login = await sp.acs({ method, url: req.url ?? '/', body }, { requestId: pending?.ids });
      if (sessions.size >= MAX_SESSIONS) {
        for (const [k, s] of sessions) if (s.expires <= Date.now()) sessions.delete(k);
      }
      if (sessions.size >= MAX_SESSIONS) throw new Error('too many sessions');
      const sid = randomBytes(32).toString('base64url');
      const until = Math.min(Date.now() + SESSION_MS, login.sessionNotOnOrAfter?.getTime() ?? Infinity);
      sessions.set(sid, { login, expires: until, signals: [] });
      await receiver?.track(sid, login, new Date(until));
      console.log(`signed in ${login.nameId} by ${login.binding} (assertion ${login.assertionId})`);
      const target = login.relayState?.startsWith('/') && !login.relayState.startsWith('//') ? login.relayState : '/';
      res.writeHead(303, { location: target, 'set-cookie': [clearPending, cookie('sid', sid, { maxAge: Math.floor((until - Date.now()) / 1000) })], 'cache-control': 'no-store' });
      res.end();
    } catch (err) {
      const what = err instanceof SamlError ? `${err.code}: ${err.message}` : (err as Error).message;
      console.warn(`sign-in refused: ${what}`);
      // A demo shows the reason; a production application logs it and shows only that sign-in failed.
      send(res, 400, page('Sign-in failed', `<h1>Sign-in failed</h1><p class="problem">${esc(what)}</p><p><a href="/">Start again</a></p>`), { 'set-cookie': clearPending });
    }
    return;
  }

  if (url.pathname === '/logout' && method === 'POST') {
    const sid = cookies(req).sid;
    if (sid) {
      sessions.delete(sid);
      await receiver?.untrack(sid);
    }
    res.writeHead(303, { location: '/', 'set-cookie': cookie('sid', '', { maxAge: 0 }), 'cache-control': 'no-store' });
    res.end();
    return;
  }

  send(res, 404, page('Not found', '<h1>Not found</h1>'));
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err: Error) => {
    console.error(err);
    if (!res.headersSent) send(res, 500, page('Error', `<h1>Something went wrong</h1><p class="problem">${esc(err.message)}</p><p><a href="/">Home</a></p>`));
    else res.end();
  });
});

try {
  const config = JSON.parse(readFileSync(CONFIG, 'utf8')) as { acsUrl?: string };
  const acs = new URL(config.acsUrl ?? 'http://localhost/');
  secureCookies = acs.protocol === 'https:' || acs.hostname === 'localhost' || acs.hostname === '127.0.0.1';
} catch (err) {
  console.warn(`cannot read ${CONFIG}: ${(err as Error).message}`);
}

server.listen(PORT, () => console.log(`saml2-sp-nodejs demo on port ${PORT}, configuration ${CONFIG}`));
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => server.close(() => process.exit(0)));
