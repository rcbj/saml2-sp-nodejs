// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A Shared Signals receiver for a server-side application (OpenID SSF 1.0, RFC 8936 poll delivery):
// the application's ONE stream at the transmitter carries CAEP and RISC events about every person who
// uses it, and each event is turned into the application's own sessions to end.
//
//   start()       finds the transmitter (/.well-known/ssf-configuration), finds the application's stream
//                 or creates it (poll delivery), and polls it;
//   track()       after a sign-in: this local session belongs to this person and this IdP session;
//   untrack()     after a sign-out;
//   onEndSessions the application's callback: these local sessions must end now;
//   on(type)      the application's handler for an event type, for everything else.
//
// AUTHENTICATION is the application's choice of headers or TLS client certificate (`auth`); with the
// service provider's own key pair as a TLS client certificate no secret is needed at all. Every SET is
// verified — signature against the transmitter's JWKS, `iss`, `aud`, `typ` — before anything acts on
// it, and acknowledged only once it has been handled.
//
// The poll loop is this module's own timer: it is the receiver, and polling is what an RFC 8936
// receiver does. stop() ends it.

import { SamlError } from '../errors.ts';
import { send, type BackChannelOptions } from '../http.ts';
import type { SamlLogin } from '../response.ts';
import { DEFAULT_ENDING_EVENTS, DEFAULT_EVENTS_REQUESTED, EVENT, subjectOf, type SubjectRef } from './events.ts';
import { verifyCompactJws, type Jwk } from './jws.ts';
import { MemorySessionIndex, trackedFrom, type SessionIndex } from './session-index.ts';

const POLL_METHOD = 'urn:ietf:rfc:8936';

/** One verified event, as handed to the application. */
export interface SignalEvent {
  /** The event type URI. */
  type: string;
  /** The event's own members (`initiating_entity`, `reason_admin`, `credential_type`, ...). */
  payload: Record<string, unknown>;
  /** Who and what it is about. */
  subject: SubjectRef;
  /** The SET's `jti`, `iat`, `txn`. */
  jti: string;
  iat?: number | undefined;
  txn?: string | undefined;
  /** The local sessions it names, whether or not they were ended. */
  sessions: string[];
  /** Whether the receiver ended them (the type is in `endOn`). */
  ended: boolean;
}

export interface SignalsReceiverOptions {
  /** The transmitter's issuer, e.g. `https://idp.example.com`; its configuration is read from `/.well-known/ssf-configuration` there. */
  transmitter: string;
  /** TLS for every call to the transmitter: `ca` to trust, and `cert` + `key` to present (mutual TLS). */
  tls?: BackChannelOptions;
  /** Extra headers for every call (e.g. an `authorization` header), for a transmitter that wants one. */
  headers?: () => Record<string, string> | Promise<Record<string, string>>;
  /** The event types to ask for. Default: CAEP's session and credential events and RISC's account events. */
  eventsRequested?: readonly string[];
  /** The event types that END the matching local sessions. Default: session-revoked, account-disabled, account-purged, credential-compromise, sessions-revoked. */
  endOn?: readonly string[];
  /** Called with the local sessions an event ends. End them in the application's session store. */
  onEndSessions: (localIds: string[], event: SignalEvent) => void | Promise<void>;
  /** The session index; default one process's memory. */
  sessionIndex?: SessionIndex;
  /** The SAML attribute holding the person's subject. Default iya-sts's (and AD FS's) `nameidentifier` claim. */
  subjectAttribute?: string;
  /** A description of the stream, shown at the transmitter. */
  description?: string;
  /** How long to wait between polls when nothing was waiting, in milliseconds. Default 5000. */
  pollIntervalMs?: number;
  /** At most this many SETs per poll. Default 50. */
  maxEvents?: number;
  /** Where the receiver logs. Default console. */
  log?: Pick<Console, 'info' | 'warn' | 'error'>;
}

interface Configuration {
  issuer: string;
  jwks_uri: string;
  configuration_endpoint: string;
  delivery_methods_supported?: string[];
  [k: string]: unknown;
}

interface StreamConfig {
  stream_id: string;
  aud?: string | string[];
  delivery?: { method?: string; endpoint_url?: string };
  events_delivered?: string[];
  events_requested?: string[];
  [k: string]: unknown;
}

export class SignalsReceiver {
  readonly #o: Required<Omit<SignalsReceiverOptions, 'headers' | 'tls' | 'subjectAttribute' | 'description'>> & SignalsReceiverOptions;
  readonly #index: SessionIndex;
  #config: Configuration | undefined;
  #stream: StreamConfig | undefined;
  #keys: Jwk[] = [];
  #keysAt = 0;
  #timer: NodeJS.Timeout | undefined;
  #running = false;
  #ack: string[] = [];
  #errs: Record<string, { err: string; description: string }> = {};
  readonly #handlers = new Map<string, Array<(e: SignalEvent) => void | Promise<void>>>();

  constructor(options: SignalsReceiverOptions) {
    if (!options || typeof options.onEndSessions !== 'function') throw new SamlError('config', 'onEndSessions is required');
    if (!/^https?:\/\//.test(options.transmitter ?? '')) throw new SamlError('config', 'transmitter must be an http(s) URL');
    this.#o = {
      eventsRequested: DEFAULT_EVENTS_REQUESTED,
      endOn: DEFAULT_ENDING_EVENTS,
      sessionIndex: options.sessionIndex ?? new MemorySessionIndex(),
      pollIntervalMs: 5000,
      maxEvents: 50,
      log: console,
      ...options,
      transmitter: options.transmitter.replace(/\/+$/, ''),
    } as never;
    this.#index = this.#o.sessionIndex;
  }

  /** The stream the receiver is polling, once started. */
  get stream(): Readonly<StreamConfig> | undefined {
    return this.#stream;
  }

  /** Remembers a local session's person and identity provider session, after a sign-in. */
  async track(localId: string, login: SamlLogin, expiresAt?: Date): Promise<void> {
    await this.#index.add(trackedFrom(localId, login, {
      ...(this.#o.subjectAttribute ? { subjectAttribute: this.#o.subjectAttribute } : {}),
      ...(expiresAt ? { expiresAt } : {}),
    }));
  }

  /** Forgets a local session, after a sign-out. */
  async untrack(localId: string): Promise<void> {
    await this.#index.remove(localId);
  }

  /** Adds a handler for one event type (`EVENT.*`), or `*` for every event. */
  on(type: string, handler: (event: SignalEvent) => void | Promise<void>): this {
    const list = this.#handlers.get(type) ?? [];
    list.push(handler);
    this.#handlers.set(type, list);
    return this;
  }

  async #call(method: string, url: string, body?: unknown): Promise<{ status: number; json: unknown }> {
    const headers: Record<string, string> = { accept: 'application/json', ...(await this.#o.headers?.()) };
    if (body !== undefined) headers['content-type'] = 'application/json';
    const answer = await send(url, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }, this.#o.tls ?? {}, 'ssf');
    let json: unknown = undefined;
    if (answer.body) {
      try {
        json = JSON.parse(answer.body);
      } catch {
        json = answer.body;
      }
    }
    return { status: answer.status, json };
  }

  async #discover(): Promise<Configuration> {
    const url = `${this.#o.transmitter}/.well-known/ssf-configuration`;
    const r = await this.#call('GET', url);
    const c = r.json as Configuration;
    if (r.status !== 200 || !c || typeof c !== 'object' || !c.configuration_endpoint || !c.jwks_uri) {
      throw new SamlError('ssf', `${url} answered ${r.status} without a usable transmitter configuration`);
    }
    if (c.delivery_methods_supported && !c.delivery_methods_supported.includes(POLL_METHOD)) {
      throw new SamlError('ssf', 'the transmitter does not offer poll delivery (RFC 8936)');
    }
    return c;
  }

  async #jwks(force = false): Promise<Jwk[]> {
    if (!force && this.#keys.length && Date.now() - this.#keysAt < 3600_000) return this.#keys;
    const r = await this.#call('GET', this.#config!.jwks_uri);
    const keys = (r.json as { keys?: Jwk[] })?.keys;
    if (r.status !== 200 || !Array.isArray(keys)) throw new SamlError('ssf', `the transmitter's JWKS answered ${r.status}`);
    this.#keys = keys;
    this.#keysAt = Date.now();
    return keys;
  }

  /** Finds this receiver's poll stream at the transmitter, or creates it. */
  async #ensureStream(): Promise<StreamConfig> {
    const endpoint = this.#config!.configuration_endpoint;
    const listed = await this.#call('GET', endpoint);
    if (listed.status === 200) {
      const all = Array.isArray(listed.json) ? listed.json as StreamConfig[] : listed.json ? [listed.json as StreamConfig] : [];
      const mine = all.find((s) => s?.delivery?.method === POLL_METHOD && s.stream_id);
      if (mine) return mine;
    } else if (listed.status !== 404) {
      throw new SamlError('ssf', `listing the streams at ${endpoint} answered ${listed.status}: ${JSON.stringify(listed.json).slice(0, 300)}`);
    }
    const created = await this.#call('POST', endpoint, {
      delivery: { method: POLL_METHOD },
      events_requested: this.#o.eventsRequested,
      ...(this.#o.description ? { description: this.#o.description } : {}),
    });
    const s = created.json as StreamConfig;
    if (created.status !== 200 && created.status !== 201 || !s?.stream_id) {
      throw new SamlError('ssf', `creating a stream at ${endpoint} answered ${created.status}: ${JSON.stringify(created.json).slice(0, 300)}`);
    }
    return s;
  }

  /** Finds the transmitter and the stream, then polls until stop(). */
  async start(): Promise<void> {
    if (this.#running) return;
    this.#config = await this.#discover();
    await this.#jwks(true);
    this.#stream = await this.#ensureStream();
    if (!this.#stream.delivery?.endpoint_url) throw new SamlError('ssf', 'the stream has no poll endpoint_url');
    this.#running = true;
    this.#o.log.info(`ssf: polling stream ${this.#stream.stream_id} at ${this.#stream.delivery.endpoint_url}, delivering ${(this.#stream.events_delivered ?? []).length} event type(s)`);
    void this.#loop();
  }

  /** Stops polling. Acknowledgements not yet sent are sent by the next start's first poll. */
  stop(): void {
    this.#running = false;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
  }

  async #loop(): Promise<void> {
    if (!this.#running) return;
    let delay = this.#o.pollIntervalMs;
    try {
      const more = await this.pollOnce();
      if (more) delay = 0;
    } catch (err) {
      this.#o.log.warn(`ssf: poll failed: ${(err as Error).message}`);
      delay = Math.min(this.#o.pollIntervalMs * 4, 60_000);
    }
    if (this.#running) this.#timer = setTimeout(() => void this.#loop(), delay);
  }

  #inflight: Promise<boolean> | undefined;

  /**
   * One poll: acknowledges what was handled since the last, handles what arrives. Answers whether more
   * is waiting. A call while a poll is in flight joins it rather than starting a second one: two
   * overlapping polls are both handed every SET not yet acknowledged, and would handle each twice.
   */
  pollOnce(): Promise<boolean> {
    this.#inflight ??= this.#pollNow().finally(() => {
      this.#inflight = undefined;
    });
    return this.#inflight;
  }

  async #pollNow(): Promise<boolean> {
    const url = this.#stream!.delivery!.endpoint_url!;
    const ack = this.#ack.splice(0);
    const setErrs = this.#errs;
    this.#errs = {};
    const r = await this.#call('POST', url, {
      maxEvents: this.#o.maxEvents,
      returnImmediately: true,
      ...(ack.length ? { ack } : {}),
      ...(Object.keys(setErrs).length ? { setErrs } : {}),
    });
    if (r.status !== 200) {
      this.#ack.unshift(...ack);
      Object.assign(this.#errs, setErrs);
      throw new SamlError('ssf', `the poll answered ${r.status}: ${JSON.stringify(r.json).slice(0, 300)}`);
    }
    const body = (r.json ?? {}) as { sets?: Record<string, string>; moreAvailable?: boolean };
    for (const [jti, token] of Object.entries(body.sets ?? {})) {
      try {
        await this.#handle(jti, token);
        this.#ack.push(jti);
      } catch (err) {
        // RFC 8936 section 2.4: a SET the receiver could not accept is reported, not acknowledged.
        const description = (err as Error).message;
        this.#o.log.warn(`ssf: SET ${jti} refused: ${description}`);
        this.#errs[jti] = { err: err instanceof SamlError && err.code === 'signature' ? 'invalid_key' : 'invalid_request', description };
      }
    }
    return !!body.moreAvailable;
  }

  async #handle(jti: string, token: string): Promise<void> {
    let verified;
    try {
      verified = verifyCompactJws(token, await this.#jwks());
    } catch (err) {
      // A key the receiver has not seen yet: read the JWKS again, once, and retry.
      if (!(err instanceof SamlError) || !/publishes no|does not verify/.test(err.message)) throw err;
      verified = verifyCompactJws(token, await this.#jwks(true));
    }
    const { header, payload } = verified;
    if (header.typ !== undefined && String(header.typ).toLowerCase() !== 'secevent+jwt') throw new SamlError('validation', `the SET's typ is ${String(header.typ)}`);
    if (payload.iss !== this.#config!.issuer) throw new SamlError('validation', `the SET was issued by ${String(payload.iss)}, not ${this.#config!.issuer}`);
    const want = ([] as string[]).concat(this.#stream!.aud ?? []);
    const aud = ([] as unknown[]).concat(payload.aud ?? []).map(String);
    if (want.length && !aud.some((a) => want.includes(a))) throw new SamlError('validation', `the SET is for ${aud.join(', ')}, not this stream`);
    if (payload.jti !== undefined && payload.jti !== jti) throw new SamlError('validation', 'the SET\'s jti is not the one it was delivered under');
    const events = payload.events as Record<string, Record<string, unknown>> | undefined;
    if (!events || typeof events !== 'object' || !Object.keys(events).length) throw new SamlError('validation', 'the SET carries no events');

    for (const [type, body] of Object.entries(events)) {
      const subject = subjectOf(payload.sub_id ?? (body as Record<string, unknown>)?.subject, this.#config!.issuer);
      const sessions = await this.#sessionsFor(type, subject);
      const ends = this.#o.endOn.includes(type) && sessions.length > 0;
      const event: SignalEvent = {
        type, payload: body ?? {}, subject, jti, sessions, ended: ends,
        iat: typeof payload.iat === 'number' ? payload.iat : undefined,
        txn: typeof payload.txn === 'string' ? payload.txn : undefined,
      };
      if (ends) {
        try {
          await this.#o.onEndSessions(sessions, event);
        } catch (err) {
          // The SET was valid; the application failed to end its sessions. Logged loudly and still
          // acknowledged, for the reason above, and the sessions stay in the index so a later account
          // event can still find them.
          this.#o.log.error(`ssf: onEndSessions threw for ${type} (SET ${jti} is still acknowledged): ${(err as Error).message}`);
          event.ended = false;
        }
        if (event.ended) for (const id of sessions) await this.#index.remove(id);
      }
      // A handler's failure is the APPLICATION's, not the SET's: it is logged, the other handlers still
      // run, and the SET is still acknowledged. Reporting it in setErrs would tell the transmitter a valid
      // SET was invalid, and the transmitter drops what it is told is invalid.
      for (const h of [...(this.#handlers.get(type) ?? []), ...(this.#handlers.get('*') ?? [])]) {
        try {
          await h(event);
        } catch (err) {
          this.#o.log.error(`ssf: a handler for ${type} threw (SET ${jti} is still acknowledged): ${(err as Error).message}`);
        }
      }
    }
  }

  /**
   * The local sessions an event names. A session event with an IdP session names only the local
   * sessions started from it; otherwise every local session of the person (by subject, then email).
   */
  async #sessionsFor(type: string, subject: SubjectRef): Promise<string[]> {
    if (type === EVENT.verification || type === EVENT.streamUpdated) return [];
    if (subject.idpSession) {
      const found = await this.#index.byIdpSession(subject.idpSession);
      if (found.length || type === EVENT.sessionRevoked) return found;
    }
    if (subject.person) return this.#index.byPerson(subject.person);
    if (subject.email) return this.#index.byEmail(subject.email);
    return [];
  }

  /** Asks the transmitter to send a verification event (SSF 1.0 section 8.1.4.2), to prove the stream end to end. */
  async verify(state?: string): Promise<void> {
    const endpoint = this.#config?.verification_endpoint;
    if (typeof endpoint !== 'string') throw new SamlError('ssf', 'the transmitter publishes no verification_endpoint');
    const r = await this.#call('POST', endpoint, { stream_id: this.#stream!.stream_id, ...(state ? { state } : {}) });
    if (r.status !== 200 && r.status !== 204) throw new SamlError('ssf', `verification answered ${r.status}`);
  }
}
