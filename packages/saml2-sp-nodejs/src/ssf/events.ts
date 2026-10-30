// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The event types this receiver asks for, and what an event's subject names. CAEP (OpenID CAEP 1.0)
// is about SESSIONS; RISC (OpenID RISC 1.0) is about ACCOUNTS. Subject identifiers are RFC 9493's,
// and SSF 1.0 section 3's complex subject (`user`, `session`, `device`, ...).

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';

export const EVENT = {
  sessionRevoked: `${CAEP}session-revoked`,
  credentialChange: `${CAEP}credential-change`,
  assuranceLevelChange: `${CAEP}assurance-level-change`,
  tokenClaimsChange: `${CAEP}token-claims-change`,
  accountDisabled: `${RISC}account-disabled`,
  accountEnabled: `${RISC}account-enabled`,
  accountPurged: `${RISC}account-purged`,
  credentialCompromise: `${RISC}credential-compromise`,
  sessionsRevoked: `${RISC}sessions-revoked`,
  accountCredentialChangeRequired: `${RISC}account-credential-change-required`,
  verification: `${SSF}verification`,
  streamUpdated: `${SSF}stream-updated`,
} as const;

/** What the receiver asks the transmitter for by default. */
export const DEFAULT_EVENTS_REQUESTED: readonly string[] = [
  EVENT.sessionRevoked, EVENT.credentialChange, EVENT.assuranceLevelChange, EVENT.tokenClaimsChange,
  EVENT.accountDisabled, EVENT.accountEnabled, EVENT.accountPurged, EVENT.credentialCompromise,
  EVENT.sessionsRevoked, EVENT.accountCredentialChangeRequired,
];

/**
 * The events that end the matching local sessions by default: the session itself was revoked, or the
 * account behind it was disabled, deleted, compromised or had every session revoked. The others are
 * handed to the application's handlers and end nothing unless it says so.
 */
export const DEFAULT_ENDING_EVENTS: readonly string[] = [
  EVENT.sessionRevoked, EVENT.accountDisabled, EVENT.accountPurged, EVENT.credentialCompromise, EVENT.sessionsRevoked,
];

/** Who and what an event's subject names, in the terms the session index is searched by. */
export interface SubjectRef {
  /** The person: an `iss_sub`'s `sub` (when its `iss` is the transmitter's issuer). */
  person?: string;
  /** An `email` subject's address. */
  email?: string;
  /** The identity provider session: a complex subject's `session` (`opaque` id, or an `iss_sub`'s `sub`). */
  idpSession?: string;
}

function simple(id: Record<string, unknown> | undefined, issuer: string): { sub?: string; email?: string; opaque?: string } {
  if (!id || typeof id !== 'object') return {};
  const format = String(id.format ?? id.subject_type ?? '');
  if (format === 'iss_sub' && typeof id.sub === 'string' && (id.iss === undefined || id.iss === issuer)) return { sub: id.sub };
  if (format === 'email' && typeof id.email === 'string') return { email: id.email };
  if (format === 'opaque' && typeof id.id === 'string') return { opaque: id.id };
  if (format === 'aliases' && Array.isArray(id.identifiers)) {
    return Object.assign({}, ...id.identifiers.map((x: unknown) => simple(x as Record<string, unknown>, issuer)));
  }
  return {};
}

/**
 * Reads an event's subject: SSF 1.0's `sub_id` claim, or (deprecated) a `subject` member of the event
 * itself. A complex subject's `user` names the person and its `session` the identity provider session.
 */
export function subjectOf(subId: unknown, issuer: string): SubjectRef {
  if (!subId || typeof subId !== 'object') return {};
  const id = subId as Record<string, unknown>;
  const format = String(id.format ?? id.subject_type ?? '');
  const out: SubjectRef = {};
  if (format === 'complex' || (!format && (id.user || id.session))) {
    const user = simple(id.user as Record<string, unknown>, issuer);
    const session = simple(id.session as Record<string, unknown>, issuer);
    if (user.sub) out.person = user.sub;
    if (user.email) out.email = user.email;
    const s = session.opaque ?? session.sub;
    if (s) out.idpSession = s;
    return out;
  }
  const one = simple(id, issuer);
  if (one.sub) out.person = one.sub;
  if (one.email) out.email = one.email;
  return out;
}
