// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Which of the application's own sessions belong to which person, and to which identity provider
// session. A Shared Signals event names the identity provider's view of things — a person by their
// subject, a session by the identity provider's session id (SAML's SessionIndex) — and this is the
// table that turns that into the application's sessions to end.

import type { SamlLogin } from '../response.ts';

/** What one of the application's sessions is known by, read from the SAML login that started it. */
export interface TrackedSession {
  /** The application's own session id (its cookie's session, its database row). */
  localId: string;
  /** The person's subject at the identity provider (e.g. `urn:uuid:…`), or undefined if the assertion did not carry it. */
  person?: string | undefined;
  /** The person's email address, for events whose subject is an `email`. Compared without case. */
  email?: string | undefined;
  /** The identity provider's session id: the assertion's SessionIndex. */
  idpSession?: string | undefined;
  /** When the application's session ends anyway; the index forgets it then. */
  expiresAt?: Date | undefined;
}

/**
 * Where the receiver looks up sessions. The default is one process's memory; an application that runs
 * several processes gives every one of them the same index (a database table, Redis), so that an event
 * one process receives ends a session another process created.
 */
export interface SessionIndex {
  add(session: TrackedSession): void | Promise<void>;
  remove(localId: string): void | Promise<void>;
  byPerson(person: string): string[] | Promise<string[]>;
  byEmail(email: string): string[] | Promise<string[]>;
  byIdpSession(idpSession: string): string[] | Promise<string[]>;
}

/** One process's memory, bounded: expired sessions go first, then the oldest. */
export class MemorySessionIndex implements SessionIndex {
  readonly #sessions = new Map<string, TrackedSession>();
  readonly #max: number;

  constructor(max = 100_000) {
    this.#max = max;
  }

  add(session: TrackedSession): void {
    if (this.#sessions.size >= this.#max && !this.#sessions.has(session.localId)) {
      const now = Date.now();
      for (const [k, v] of this.#sessions) if (v.expiresAt && v.expiresAt.getTime() <= now) this.#sessions.delete(k);
      while (this.#sessions.size >= this.#max) this.#sessions.delete(this.#sessions.keys().next().value!);
    }
    this.#sessions.set(session.localId, { ...session, email: session.email?.toLowerCase() });
  }

  remove(localId: string): void {
    this.#sessions.delete(localId);
  }

  #find(match: (s: TrackedSession) => boolean): string[] {
    const now = Date.now();
    const out: string[] = [];
    for (const [k, v] of this.#sessions) {
      if (v.expiresAt && v.expiresAt.getTime() <= now) {
        this.#sessions.delete(k);
        continue;
      }
      if (match(v)) out.push(k);
    }
    return out;
  }

  byPerson(person: string): string[] {
    return this.#find((s) => s.person === person);
  }

  byEmail(email: string): string[] {
    const e = email.toLowerCase();
    return this.#find((s) => s.email === e);
  }

  byIdpSession(idpSession: string): string[] {
    return this.#find((s) => s.idpSession === idpSession);
  }
}

/** The attribute iya-sts (and AD FS) carry the person's subject in by default. */
export const DEFAULT_SUBJECT_ATTRIBUTE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
const MAIL_ATTRIBUTES = ['urn:oid:0.9.2342.19200300.100.1.3', 'mail', 'email', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'];

/** What a SAML login says about the session, for the index. */
export function trackedFrom(localId: string, login: SamlLogin, options: { subjectAttribute?: string; expiresAt?: Date } = {}): TrackedSession {
  const attr = options.subjectAttribute ?? DEFAULT_SUBJECT_ATTRIBUTE;
  const person = login.attributes[attr]?.[0];
  const email = MAIL_ATTRIBUTES.map((n) => login.attributes[n]?.[0]).find(Boolean)
    ?? (login.nameIdFormat === 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' ? login.nameId : undefined);
  return {
    localId,
    person,
    email,
    idpSession: login.sessionIndex,
    expiresAt: options.expiresAt ?? login.sessionNotOnOrAfter,
  };
}
