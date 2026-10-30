// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The demo: a traditional server-rendered web application that signs people in with SAML 2.0 through
// saml2-sp-nodejs. node:http and nothing else; Node runs this TypeScript file as it is.
//
// SEVERAL PEOPLE IN ONE BROWSER. The browser holds one cookie, `aset`, naming an ACCOUNT SET: the people
// signed in to it, each a session of their own (their own SAML login, events and live channel). Which one
// a tab shows is in its URL, `/u/<account>/`, an id stable for as long as that person stays signed in, so
// two tabs can show two people at once and an account that ends never makes another tab show someone else.
//
//   GET  /                to the first account's page, or the sign-in buttons when nobody is signed in
//   GET  /u/<a>/          that account's page; ?tab=events shows its CAEP and RISC events and the stream
//   GET  /login           a signed AuthnRequest; ?binding=post|redirect|artifact picks the RESPONSE binding;
//                         ?add=1 adds another person (ForceAuthn); ?account=<a> signs that person in again
//                         (ForceAuthn, with their NameID as the Subject hint)
//   GET  /login           a signed AuthnRequest; ?binding=post|redirect|artifact picks the RESPONSE binding
//   GET  /saml/acs        the assertion consumer service, for HTTP-Redirect and HTTP-Artifact
//   POST /saml/acs        the assertion consumer service, for HTTP-POST (and an artifact posted)
//   GET  /saml/metadata   this service provider's metadata (its entityID)
//   GET  /u/<a>/events    Server-Sent Events for that account's tab: each event about THAT account's session
//                         or person, as JSON, the moment the receiver has it (and the ones a reconnecting
//                         tab missed, from Last-Event-ID); the stream's status; and that the session ended
//   GET  /u/<a>/api/signals  the same events as JSON (?after=<id>), for a tab without a working event stream
//   POST /u/<a>/signals/verify  asks the identity provider for a verification event, for that account
//   POST /u/<a>/signals/clear  empties that account's event log
//   POST /u/<a>/logout    signs that account out of this application; the others stay
//   POST /logout          signs every account in this browser out of this application
//   GET  /healthz         for the container's health check
//
// SHARED SIGNALS: with an `ssf` block in the configuration file the demo is also a CAEP and RISC receiver
// (the library's SignalsReceiver): one poll stream at the identity provider, authenticated by mutual TLS
// with the service provider's own key pair. An event that revokes a session, or disables, purges or
// compromises an account, ENDS the matching local sessions here, and their open tabs are told at once.
//
// Two cookies. `saml_pending` holds the outstanding AuthnRequest ids, HMAC-signed, scoped to the ACS,
// and SameSite=None: the identity provider's HTTP-POST binding brings the browser back with a CROSS-SITE
// POST, on which a Lax cookie is not sent. `aset` is the account set, SameSite=Lax, set after the ACS.

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

/** One received event, as the events tab draws it and the browser receives it. */
interface LoggedEvent {
  /** This process's sequence number: the SSE event id, and what ?after= counts from. */
  id: number;
  at: string;
  /** The event type URI. */
  type: string;
  family: 'CAEP' | 'RISC' | 'SSF';
  /** Whether it ended this session (for a stream event: never). */
  ended: boolean;
  /** `session`: about this session or its person. `stream`: the verification this session asked for. */
  about: 'session' | 'stream';
  /** Who and what the event names: person, email, IdP session. */
  subject: string;
  /** The event's own members: initiating_entity, reason_admin, credential_type, state, ... */
  members: Record<string, unknown>;
  jti: string;
}

interface Session {
  login: SamlLogin;
  expires: number;
  /** The account set it is in, and its account id there (the `/u/<a>/` in its URLs). */
  setId: string;
  account: string;
  /** Shared Signals events about this session or its person, newest first. */
  signals: LoggedEvent[];
}
const sessions = new Map<string, Session>();
// Account sets: the browser's `aset` cookie names one; it lists the sessions of the people signed in there.
const accountSets = new Map<string, string[]>();

/** Ends a local session wherever it was: the session, its place in its account set, its tabs. */
function endSession(sid: string): void {
  const s = sessions.get(sid);
  sessions.delete(sid);
  if (!s) return;
  const set = accountSets.get(s.setId);
  if (set) {
    const left = set.filter((x) => x !== sid);
    if (left.length) accountSets.set(s.setId, left);
    else accountSets.delete(s.setId);
  }
}
// The open /events streams of each session, told when a signal arrives or ends it.
const listeners = new Map<string, Set<ServerResponse>>();

function tell(sid: string, event: string, data: unknown, id?: number): void {
  for (const res of listeners.get(sid) ?? []) {
    res.write(`${id !== undefined ? `id: ${id}\n` : ''}event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    if (event === 'signed-out') res.end();
  }
  if (event === 'signed-out') listeners.delete(sid);
}

const shortType = (uri: string) => uri.replace(/^.*\/event-type\//, '');
const familyOf = (uri: string): LoggedEvent['family'] => (/\/caep\//.test(uri) ? 'CAEP' : /\/risc\//.test(uri) ? 'RISC' : 'SSF');

// WHO SEES WHAT. A session's log holds only events the receiver matched to that session or its person,
// and only that session's /events and /api/signals read it: user A never receives an event about user B.
// The stream's own two events name nobody: a verification goes only to the session that asked for it
// (by the `state` it sent), and stream-updated changes the stream's status, which carries no person.
const LOG_SIZE = 25;
let sequence = 0;
const verificationsAsked = new Map<string, string>(); // state -> the session that asked
let streamStatus: { status: string; reason?: unknown; at: string } | undefined;

function logFor(sid: string, entry: LoggedEvent): void {
  const s = sessions.get(sid);
  if (!s) return;
  s.signals.unshift(entry);
  s.signals.length = Math.min(s.signals.length, LOG_SIZE);
  tell(sid, 'signal', entry, entry.id);
}

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
        endSession(sid);
        tell(sid, 'signed-out', { type: shortType(event.type), reason: event.payload.reason_user ?? event.payload.reason_admin ?? event.payload.reason ?? null });
      }
      console.log(`ssf: ${shortType(event.type)} ended ${ids.length} local session(s)`);
    },
  });
  r.on('*', (event: SignalEvent) => {
    const entry: LoggedEvent = {
      id: ++sequence,
      at: new Date().toISOString(),
      type: event.type,
      family: familyOf(event.type),
      ended: event.ended,
      about: 'session',
      subject: [event.subject.person, event.subject.email, event.subject.idpSession && `IdP session ${event.subject.idpSession}`]
        .filter(Boolean).join(', '),
      members: event.payload,
      jti: event.jti,
    };
    if (event.type === EVENT.verification) {
      const asker = verificationsAsked.get(String(event.payload.state ?? ''));
      verificationsAsked.delete(String(event.payload.state ?? ''));
      if (asker) logFor(asker, { ...entry, about: 'stream' });
      console.log(`ssf: verification received${asker ? '' : ' (asked by no session here)'}`);
      return;
    }
    if (event.type === EVENT.streamUpdated) {
      streamStatus = { status: String(event.payload.status ?? ''), reason: event.payload.reason, at: entry.at };
      for (const sid of listeners.keys()) tell(sid, 'stream', streamStatus);
      return;
    }
    // An event that ended a session is not logged there: the session is gone, and its tab was told.
    if (!event.ended) for (const sid of event.sessions) logFor(sid, entry);
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

/** The accounts signed in to this browser, in the order they were added, expired ones dropped. */
function accountsOf(req: IncomingMessage): Array<{ sid: string; session: Session }> {
  return accountsOfSet(cookies(req).aset);
}

function accountsOfSet(setId: string | undefined): Array<{ sid: string; session: Session }> {
  const out: Array<{ sid: string; session: Session }> = [];
  for (const sid of (setId && accountSets.get(setId)) || []) {
    const session = sessions.get(sid);
    if (!session) continue;
    if (session.expires <= Date.now()) {
      endSession(sid);
      void receiver?.untrack(sid);
      continue;
    }
    out.push({ sid, session });
  }
  return out;
}

/** The account a `/u/<a>/` URL names, if it is signed in to THIS browser's account set; else nothing. */
function accountOf(req: IncomingMessage, account: string): { sid: string; session: Session } | undefined {
  return accountsOf(req).find((x) => x.session.account === account);
}

const samePerson = (a: SamlLogin, b: SamlLogin) =>
  a.issuer === b.issuer && a.nameId === b.nameId && (a.nameIdFormat ?? '') === (b.nameIdFormat ?? '');

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

type Tab = 'identity' | 'events';

function tabs(base: string, active: Tab, count = 0): string {
  const tab = (id: Tab, label: string) =>
    `<a class="page-tab" role="tab" href="${base}/?tab=${id}" aria-selected="${id === active}"${id === active ? ' aria-current="page"' : ''}>${label}</a>`;
  return `<nav class="page-tabs" role="tablist" aria-label="Sections">${tab('identity', 'Identity')}${tab('events', `CAEP &amp; RISC events <span class="count" id="signal-count">${count || ''}</span>`)}</nav>`;
}

function member(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    // A language map (reason_admin: { en: "..." }) reads best as its first value; anything else as JSON.
    const values = Object.values(value as Record<string, unknown>);
    if (values.length && values.every((v) => typeof v === 'string')) return values.join(' / ');
    return JSON.stringify(value);
  }
  return String(value);
}

function logItem(e: LoggedEvent): string {
  const members = Object.entries(e.members)
    .filter(([k]) => k !== 'subject')
    .map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(member(v))}</td></tr>`).join('');
  const outcome = e.about === 'stream' ? 'about the stream: the verification this session asked for' : e.ended ? 'ended this session' : 'recorded; this session continues';
  return `<li class="log-item" data-id="${e.id}">
  <div class="log-top"><span class="badge ${e.family.toLowerCase()}">${e.family}</span> <strong>${esc(shortType(e.type))}</strong> <time>${esc(e.at)}</time></div>
  <p class="log-outcome${e.ended ? ' ended' : ''}">${esc(outcome)}</p>
  ${e.subject ? `<p><small>Subject: ${esc(e.subject)}</small></p>` : ''}
  ${members ? `<table class="facts members">${members}</table>` : ''}
  <p><small>jti ${esc(e.jti)}</small></p>
</li>`;
}

function eventsPanel(base: string, session: Session, notice?: string): string {
  const stream = receiver?.stream;
  const delivered = (stream?.events_delivered ?? []) as string[];
  const lastId = session.signals[0]?.id ?? 0;
  return `<section class="card">
<h2>Shared Signals stream</h2>
${notice ? `<p class="notice">${esc(notice)}</p>` : ''}
<table class="facts">
<tr><th>Receiver</th><td>${esc(receiverState)}</td></tr>
<tr><th>Stream status</th><td id="stream-status">${esc(streamStatus ? `${streamStatus.status} (${streamStatus.at})` : 'enabled')}</td></tr>
${stream ? `<tr><th>Stream</th><td>${esc(stream.stream_id)}<br><small>poll delivery (RFC 8936) at ${esc(stream.delivery?.endpoint_url)}</small></td></tr>
<tr><th>Authentication</th><td>mutual TLS with this service provider's own certificate</td></tr>
<tr><th>Delivers</th><td>${delivered.map((t) => `<span class="badge ${familyOf(t).toLowerCase()}">${familyOf(t)}</span> ${esc(shortType(t))}`).join('<br>') || '(nothing yet)'}</td></tr>` : ''}
<tr><th>Ends this session on</th><td>session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked</td></tr>
</table>
${stream ? `<form method="post" action="${base}/signals/verify" class="inline" id="verify-form"><button type="submit">Request verification event</button></form>` : ''}
</section>
<section class="card">
<h2>Event log</h2>
<p><small>The CAEP and RISC events about this session or its person, newest first, and the verification events this session asked for. Each appears here within moments of the receiver getting it: <span id="live-state">connecting…</span></small></p>
<ol class="log" id="log" data-last-id="${lastId}">${session.signals.map((e) => logItem(e)).join('')}</ol>
<p class="empty" id="log-empty"${session.signals.length ? ' hidden' : ''}>No CAEP or RISC event about this session yet. At the identity provider, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>
<form method="post" action="${base}/signals/clear" class="inline"><button type="submit" class="secondary">Clear this session's log</button></form>
</section>`;
}

/** The browser's accounts: switch between them, add another, sign one or all out. */
function accountBar(accounts: Array<{ session: Session }>, current: Session): string {
  const items = accounts.map(({ session: a }) => a === current
    ? `<li aria-current="true"><strong>${esc(a.login.nameId)}</strong></li>`
    : `<li><a href="/u/${esc(a.account)}/">${esc(a.login.nameId)}</a></li>`).join('');
  return `<nav class="accounts" aria-label="Accounts in this browser">
<span class="accounts-label">Signed in here:</span> <ul>${items}</ul>
<a class="button small" href="/login?add=1">Add another account</a>
${accounts.length > 1 ? '<form method="post" action="/logout" class="inline"><button type="submit" class="secondary small">Sign out of all accounts</button></form>' : ''}
</nav>`;
}

function home(session: Session | undefined, sp: ServiceProvider | undefined, problem?: string, tab: Tab = 'identity', notice?: string,
  accounts: Array<{ session: Session }> = [], gone?: string): string {
  if (session) {
    const base = `/u/${session.account}`;
    const l = session.login;
    const rows = Object.entries(l.attributes).map(([name, values]) =>
      `<tr><th>${esc(l.attributeFriendlyNames[name] ?? name)}${l.attributeFriendlyNames[name] ? `<br><small>${esc(name)}</small>` : ''}</th><td>${values.map(esc).join('<br>')}</td></tr>`).join('');
    const identity = `<table class="facts">
<tr><th>NameID</th><td>${esc(l.nameId)}<br><small>${esc(l.nameIdFormat)}</small></td></tr>
<tr><th>Identity provider</th><td>${esc(l.issuer)}</td></tr>
<tr><th>Response binding</th><td>${esc(BINDING_LABEL[l.binding])}</td></tr>
<tr><th>Authenticated</th><td>${esc(l.authnInstant.toISOString?.() ?? l.authnInstant)}<br><small>${esc(l.authnContextClassRef)}</small></td></tr>
<tr><th>Session index</th><td>${esc(l.sessionIndex)}</td></tr>
<tr><th>Assertion</th><td>${esc(l.assertionId)}<br><small>${l.encrypted ? 'arrived encrypted (EncryptedAssertion), decrypted with this service provider\'s key' : 'arrived in clear'}; signature verified</small></td></tr>
</table>
<h2>Attributes</h2>
${rows ? `<table class="facts">${rows}</table>` : '<p>The identity provider released no attributes.</p>'}`;
    const count = session.signals.length;
    return page('Signed in', `<h1>Signed in as ${esc(l.nameId)}</h1>
${accountBar(accounts, session)}
${gone ? `<p class="notice">${esc(gone)}</p>` : ''}
${tabs(base, tab, count)}
<p id="signal-banner" class="problem" hidden></p>
<p id="signal-toast" class="notice" hidden></p>
<div role="tabpanel" id="panel" data-base="${base}" data-tab="${tab}" data-last-id="${session.signals[0]?.id ?? 0}">${tab === 'events' ? eventsPanel(base, session, notice) : identity}</div>
<form method="post" action="${base}/logout" class="inline"><button type="submit">Sign out of this account</button></form>
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
  /**
   * The browser's account set when the sign-in began. The ACS cannot read the `aset` cookie itself: the
   * HTTP-POST binding brings the browser back with a CROSS-SITE POST, on which a SameSite=Lax cookie is not
   * sent. This cookie is SameSite=None, scoped to the ACS, and sealed, so it carries the set across.
   */
  set?: string;
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://demo.invalid');
  const method = req.method ?? 'GET';

  if (url.pathname === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain' });
  if (url.pathname === '/styles.css') return send(res, 200, STYLES, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'max-age=300' });
  if (url.pathname === '/app.js') return send(res, 200, APP_JS, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'max-age=300' });

  // An account's own paths. `here` is that account in THIS browser's set, or nothing (signed out, or an
  // account id from another browser), and every one of them answers only about it.
  const scoped = /^\/u\/([A-Za-z0-9_-]{6,32})(\/.*)?$/.exec(url.pathname);
  const here = scoped ? accountOf(req, scoped[1]!) : undefined;
  const sub = scoped ? (scoped[2] ?? '/') : undefined;

  if (scoped && !here) {
    if (sub === '/api/signals') return send(res, 401, JSON.stringify({ signedIn: false }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    if (sub === '/events') return send(res, 204, '');
    // Never another account's page under this one's URL: back to the start, which says why.
    res.writeHead(303, { location: '/?gone=1', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (here && sub === '/events' && method === 'GET') {
    const sid = here.sid;
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
    // A reconnecting EventSource sends the last id it saw; the first connection says ?after=. Either way it
    // is sent what it missed of THIS session's log, oldest first, before anything new.
    const after = Number(req.headers['last-event-id'] ?? url.searchParams.get('after') ?? 0) || 0;
    res.write('retry: 2000\n\n');
    for (const e of [...here.session.signals].reverse()) if (e.id > after) res.write(`id: ${e.id}\nevent: signal\ndata: ${JSON.stringify(e)}\n\n`);
    if (streamStatus) res.write(`event: stream\ndata: ${JSON.stringify(streamStatus)}\n\n`);
    const set = listeners.get(sid) ?? new Set<ServerResponse>();
    set.add(res);
    listeners.set(sid, set);
    // A comment now and then keeps an idle connection open through proxies, and lets the server notice a
    // tab that went away.
    const keepAlive = setInterval(() => res.write(': keep-alive\n\n'), 20_000);
    req.on('close', () => {
      clearInterval(keepAlive);
      set.delete(res);
      if (!set.size) listeners.delete(sid);
    });
    return;
  }

  if (here && sub === '/api/signals' && method === 'GET') {
    const session = here.session;
    const json = { 'content-type': 'application/json', 'cache-control': 'no-store' };
    const after = Number(url.searchParams.get('after') ?? 0) || 0;
    const events = [...session.signals].reverse().filter((e) => e.id > after);
    return send(res, 200, JSON.stringify({ signedIn: true, events, lastId: session.signals[0]?.id ?? after, streamStatus: streamStatus ?? null }), json);
  }

  if (url.pathname === '/' && method === 'GET') {
    const first = accountsOf(req)[0];
    if (first) {
      res.writeHead(303, { location: `/u/${first.session.account}/${url.searchParams.get('gone') ? '?gone=1' : ''}`, 'cache-control': 'no-store' });
      res.end();
      return;
    }
  }

  if ((url.pathname === '/' || (here && sub === '/')) && method === 'GET') {
    const session = here?.session;
    let sp: ServiceProvider | undefined;
    let problem: string | undefined;
    try {
      sp = await serviceProvider();
    } catch (err) {
      problem = `The service provider is not configured yet: ${(err as Error).message}. Run the setup script (npm run configure-iya-sts).`;
    }
    const tab = url.searchParams.get('tab') === 'events' ? 'events' : 'identity';
    const notice = url.searchParams.get('verify') === 'sent'
      ? 'Verification event requested; it shows in the log within a few seconds.'
      : url.searchParams.get('verify') === 'failed' ? 'The identity provider refused the verification request; see the demo\'s log.' : undefined;
    const gone = url.searchParams.get('gone') ? 'The account you opened is no longer signed in here.' : undefined;
    return send(res, 200, home(session, sp, gone && !session ? gone : problem, tab, notice, accountsOf(req), gone), session ? {
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
    // Adding a person: ForceAuthn, so the identity provider authenticates someone rather than signing the
    // current person in again by single sign-on. Signing one account in again: ForceAuthn, and their
    // NameID as the Subject hint, which tells the identity provider which of its accounts this is for.
    const again = url.searchParams.get('account') ? accountOf(req, url.searchParams.get('account')!) : undefined;
    const add = url.searchParams.get('add') === '1';
    const request = sp.login({
      relayState: '/', nonce,
      ...(responseBinding ? { responseBinding } : {}),
      ...(add || again ? { forceAuthn: true } : {}),
      ...(again ? { subjectHint: again.session.login.nameId, ...(again.session.login.nameIdFormat ? { subjectHintFormat: again.session.login.nameIdFormat } : {}) } : {}),
    });
    // Keep the last few outstanding ids, so two tabs signing in at once both succeed.
    const before = unseal<Pending>(cookies(req).saml_pending)?.ids ?? [];
    const setNow = cookies(req).aset;
    const pending = cookie('saml_pending', sealed({ ids: [request.id, ...before].slice(0, 3), ...(setNow && accountSets.has(setNow) ? { set: setNow } : {}) }), { path: new URL(sp.config.acsUrl).pathname, maxAge: 600, sameSite: 'None' });
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
      // Into this browser's account set. A person already in it is signed in again in their own place
      // (same account id, so their tabs keep their URL); anyone else is added. The set gets a NEW id at
      // every sign-in, so a set id seen before a sign-in names nothing after it.
      const oldSetId = pending?.set ?? cookies(req).aset;
      const accounts = accountsOfSet(oldSetId);
      const existing = accounts.find((a) => samePerson(a.session.login, login));
      const account = existing?.session.account ?? randomBytes(9).toString('base64url');
      if (existing) {
        endSession(existing.sid);
        await receiver?.untrack(existing.sid);
        tell(existing.sid, 'replaced', {});
      }
      const setId = randomBytes(32).toString('base64url');
      const order = accounts.map((a) => (a.sid === existing?.sid ? sid : a.sid));
      if (!existing) order.push(sid);
      if (oldSetId) accountSets.delete(oldSetId);
      accountSets.set(setId, order);
      for (const x of order) {
        const s = x === sid ? undefined : sessions.get(x);
        if (s) s.setId = setId;
      }
      sessions.set(sid, { login, expires: until, signals: [], setId, account });
      await receiver?.track(sid, login, new Date(until));
      console.log(`signed in ${login.nameId} by ${login.binding} (assertion ${login.assertionId}); ${order.length} account(s) in this browser`);
      const longest = Math.max(...order.map((x) => sessions.get(x)?.expires ?? 0));
      res.writeHead(303, { location: `/u/${account}/`, 'set-cookie': [clearPending, cookie('aset', setId, { maxAge: Math.floor((longest - Date.now()) / 1000) })], 'cache-control': 'no-store' });
      res.end();
    } catch (err) {
      const what = err instanceof SamlError ? `${err.code}: ${err.message}` : (err as Error).message;
      console.warn(`sign-in refused: ${what}`);
      // A demo shows the reason; a production application logs it and shows only that sign-in failed.
      send(res, 400, page('Sign-in failed', `<h1>Sign-in failed</h1><p class="problem">${esc(what)}</p><p><a href="/">Start again</a></p>`), { 'set-cookie': clearPending });
    }
    return;
  }

  if (here && sub === '/signals/verify' && method === 'POST') {
    let outcome = 'failed';
    const sid = here.sid;
    if (receiver?.stream) {
      try {
        const state = randomBytes(12).toString('base64url');
        verificationsAsked.set(state, sid);
        if (verificationsAsked.size > 1000) verificationsAsked.delete(verificationsAsked.keys().next().value!);
        await receiver.verify(state);
        outcome = 'sent';
      } catch (err) {
        console.warn(`ssf: verification request refused: ${(err as Error).message}`);
      }
    }
    if (String(req.headers.accept ?? '').includes('application/json')) {
      return send(res, outcome === 'sent' ? 202 : 502, JSON.stringify({ outcome }), { 'content-type': 'application/json', 'cache-control': 'no-store' });
    }
    res.writeHead(303, { location: `/u/${here.session.account}/?tab=events&verify=${outcome}`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (here && sub === '/signals/clear' && method === 'POST') {
    here.session.signals = [];
    res.writeHead(303, { location: `/u/${here.session.account}/?tab=events`, 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (here && sub === '/logout' && method === 'POST') {
    endSession(here.sid);
    await receiver?.untrack(here.sid);
    tell(here.sid, 'signed-out', {});
    res.writeHead(303, { location: '/', 'cache-control': 'no-store' });
    res.end();
    return;
  }

  if (url.pathname === '/logout' && method === 'POST') {
    for (const { sid } of accountsOf(req)) {
      endSession(sid);
      await receiver?.untrack(sid);
      tell(sid, 'signed-out', {});
    }
    res.writeHead(303, { location: '/', 'set-cookie': cookie('aset', '', { maxAge: 0 }), 'cache-control': 'no-store' });
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
