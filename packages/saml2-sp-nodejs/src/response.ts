// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Validating a <samlp:Response> under the Web Browser SSO profile (SAML Profiles 4.1.4.3), whichever
// binding brought it. The order matters:
//
//   1. the Response's own signature, or the binding's (a verified query signature, the artifact back
//      channel); from here on the Response is read from what was signed;
//   2. the Response: issuer, destination, InResponseTo, status;
//   3. exactly one assertion, decrypted if it is encrypted, and its own signature (required by default);
//      from here on the assertion is read from what was signed;
//   4. the assertion: issuer, a bearer confirmation for this ACS and this request, the time window, this
//      service provider in the audience, an authentication statement;
//   5. the assertion has not been accepted before.

import type { KeyObject, X509Certificate } from 'node:crypto';
import { decryptElement } from './encryption.ts';
import { SamlError, type SamlStatus } from './errors.ts';
import type { ReplayCache } from './replay.ts';
import { verifySigned } from './signature.ts';
import { CM_BEARER, NS, STATUS_SUCCESS, assertUniqueIds, attr, child, children, parseXml, text } from './xml.ts';
import type { ResponseBinding } from './config.ts';

/** Who signed in, as the identity provider asserted it. */
export interface SamlLogin {
  /** The subject's NameID value. */
  nameId: string;
  /** Its Format, e.g. `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`. */
  nameIdFormat?: string;
  nameQualifier?: string;
  spNameQualifier?: string;
  /** The identity provider's session, for logout: the AuthnStatement's SessionIndex. */
  sessionIndex?: string;
  /** When the identity provider says this session must end, if it says. */
  sessionNotOnOrAfter?: Date;
  /** When the person authenticated. */
  authnInstant: Date;
  /** How, e.g. `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`. */
  authnContextClassRef?: string;
  /** Every attribute, by its Name, with all its values. */
  attributes: Record<string, string[]>;
  /** The FriendlyName of each attribute that has one, by Name. */
  attributeFriendlyNames: Record<string, string>;
  /** The identity provider's entityID. */
  issuer: string;
  /** The ID of the AuthnRequest this answers; absent for an unsolicited Response. */
  inResponseTo?: string;
  /** The RelayState that came back with the Response. */
  relayState?: string;
  /** The binding the Response arrived on. */
  binding: ResponseBinding;
  /** Whether the assertion arrived encrypted (an EncryptedAssertion). */
  encrypted: boolean;
  responseId: string;
  assertionId: string;
}

export interface ValidationContext {
  entityId: string;
  acsUrl: string;
  idpEntityId: string;
  idpCertificates: readonly X509Certificate[];
  decryptionKey: KeyObject;
  clockSkewMs: number;
  wantAssertionsSigned: boolean;
  wantAssertionsEncrypted: boolean;
  allowUnsolicited: boolean;
  replayCache: ReplayCache;
  /** The AuthnRequest IDs this browser has outstanding. Empty: only an unsolicited Response can match. */
  expectedRequestIds: readonly string[];
  now?: Date;
}

export interface ReceivedResponse {
  /** The document holding the Response, as text. */
  xml: string;
  /** The Response element inside it. */
  response: Element;
  binding: ResponseBinding;
  relayState?: string | undefined;
  /** The binding already authenticated the Response (a verified query signature, or the TLS back channel). */
  authenticatedByBinding: boolean;
}

const invalid = (message: string): never => {
  throw new SamlError('validation', message);
};

function instant(value: string | undefined, what: string): Date | undefined {
  if (value === undefined) return undefined;
  // xs:dateTime as SAML uses it: UTC, with a Z.
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(value)) return invalid(`${what} is not a UTC dateTime: ${value}`);
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? invalid(`${what} is not a dateTime: ${value}`) : d;
}

function issuerOf(el: Element, required: boolean, expected: string, what: string): void {
  const issuer = child(el, NS.saml, 'Issuer');
  if (!issuer) {
    if (required) invalid(`${what} has no Issuer`);
    return;
  }
  const format = attr(issuer, 'Format');
  if (format && format !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity') invalid(`${what}'s Issuer has the Format ${format}`);
  if (text(issuer) !== expected) invalid(`${what} was issued by ${text(issuer)}, not by ${expected}`);
}

function statusOf(response: Element): SamlStatus {
  const status = child(response, NS.samlp, 'Status');
  if (!status) return invalid('the Response has no Status');
  const top = child(status, NS.samlp, 'StatusCode');
  if (!top) return invalid('the Response has no StatusCode');
  const sub = child(top, NS.samlp, 'StatusCode');
  const out: SamlStatus = { code: attr(top, 'Value') ?? '' };
  if (sub && attr(sub, 'Value')) out.subCode = attr(sub, 'Value')!;
  const message = text(child(status, NS.samlp, 'StatusMessage'));
  if (message) out.message = message;
  return out;
}

/** Validates a received Response and returns who signed in. Throws a {@link SamlError} otherwise. */
export async function validateResponse(received: ReceivedResponse, ctx: ValidationContext): Promise<SamlLogin> {
  const now = (ctx.now ?? new Date()).getTime();
  const skew = ctx.clockSkewMs;

  // 1. The Response's signature, and from here on the Response as signed.
  assertUniqueIds(received.response.ownerDocument);
  if (received.response.namespaceURI !== NS.samlp || received.response.localName !== 'Response') {
    invalid(`the message is a <${received.response.localName}>, not a Response`);
  }
  let response = received.response;
  let responseXml = received.xml;
  const signedResponse = verifySigned(received.xml, received.response, ctx.idpCertificates, 'the Response');
  if (signedResponse !== undefined) {
    responseXml = signedResponse;
    response = parseXml(signedResponse, 'the signed Response').documentElement;
  }
  const responseAuthenticated = signedResponse !== undefined || received.authenticatedByBinding;

  // 2. The Response.
  if (attr(response, 'Version') !== '2.0') invalid(`the Response is version ${attr(response, 'Version') ?? '(none)'}, not 2.0`);
  const responseId = attr(response, 'ID') ?? invalid('the Response has no ID');
  issuerOf(response, false, ctx.idpEntityId, 'the Response');
  const destination = attr(response, 'Destination');
  if (destination !== undefined && destination !== ctx.acsUrl) invalid(`the Response is addressed to ${destination}, not to ${ctx.acsUrl}`);
  if (destination === undefined && responseAuthenticated && received.binding !== 'artifact') {
    // Bindings 3.4.5.2 and 3.5.5.2: a signed message on the front channel MUST carry its Destination.
    invalid('the Response is signed but has no Destination');
  }
  const inResponseTo = attr(response, 'InResponseTo');
  if (inResponseTo !== undefined) {
    if (!ctx.expectedRequestIds.includes(inResponseTo)) invalid(`the Response answers ${inResponseTo}, which is not a request this browser has outstanding`);
  } else if (!ctx.allowUnsolicited) {
    invalid('the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted');
  }
  const status = statusOf(response);
  if (status.code !== STATUS_SUCCESS) {
    throw new SamlError('status', `the identity provider answered ${status.subCode ?? status.code}${status.message ? `: ${status.message}` : ''}`, { status });
  }

  // 3. The assertion, decrypted, and its signature.
  const plain = children(response, NS.saml, 'Assertion');
  const encrypted = children(response, NS.saml, 'EncryptedAssertion');
  if (plain.length + encrypted.length !== 1) invalid(`the Response holds ${plain.length + encrypted.length} assertions; exactly one is accepted`);
  let assertion: Element;
  let assertionXml: string;
  if (encrypted.length) {
    assertionXml = decryptElement(encrypted[0]!, ctx.decryptionKey);
    const doc = parseXml(assertionXml, 'the decrypted assertion');
    assertUniqueIds(doc);
    assertion = doc.documentElement;
    if (assertion.namespaceURI !== NS.saml || assertion.localName !== 'Assertion') invalid('the EncryptedAssertion does not hold an Assertion');
  } else {
    if (ctx.wantAssertionsEncrypted) invalid('the assertion is not encrypted, and wantAssertionsEncrypted is on');
    assertion = plain[0]!;
    assertionXml = responseXml;
  }
  const signedAssertion = verifySigned(assertionXml, assertion, ctx.idpCertificates, 'the assertion');
  if (signedAssertion !== undefined) {
    assertion = parseXml(signedAssertion, 'the signed assertion').documentElement;
  } else if (ctx.wantAssertionsSigned) {
    invalid('the assertion is not signed, and wantAssertionsSigned is on');
  } else if (!responseAuthenticated) {
    invalid('neither the Response nor its assertion is signed');
  }

  // 4. The assertion.
  if (attr(assertion, 'Version') !== '2.0') invalid('the assertion is not version 2.0');
  const assertionId = attr(assertion, 'ID') ?? invalid('the assertion has no ID');
  issuerOf(assertion, true, ctx.idpEntityId, 'the assertion');

  const subject = child(assertion, NS.saml, 'Subject') ?? invalid('the assertion has no Subject');
  let nameIdEl = child(subject, NS.saml, 'NameID');
  const encryptedId = child(subject, NS.saml, 'EncryptedID');
  if (!nameIdEl && encryptedId) {
    const doc = parseXml(decryptElement(encryptedId, ctx.decryptionKey), 'the decrypted NameID');
    nameIdEl = doc.documentElement;
    if (nameIdEl.namespaceURI !== NS.saml || nameIdEl.localName !== 'NameID') invalid('the EncryptedID does not hold a NameID');
  }
  if (!nameIdEl || !text(nameIdEl)) invalid('the assertion\'s Subject has no NameID');

  // Profiles 4.1.4.2: at least one bearer SubjectConfirmation for this ACS, unexpired, answering this request.
  const reasons: string[] = [];
  let confirmedUntil: Date | undefined;
  for (const sc of children(subject, NS.saml, 'SubjectConfirmation')) {
    if (attr(sc, 'Method') !== CM_BEARER) {
      reasons.push(`method ${attr(sc, 'Method')}`);
      continue;
    }
    const data = child(sc, NS.saml, 'SubjectConfirmationData');
    if (!data) {
      reasons.push('no SubjectConfirmationData');
      continue;
    }
    const recipient = attr(data, 'Recipient');
    const notOnOrAfter = instant(attr(data, 'NotOnOrAfter'), 'SubjectConfirmationData NotOnOrAfter');
    const notBefore = attr(data, 'NotBefore');
    const scInResponseTo = attr(data, 'InResponseTo');
    if (recipient !== ctx.acsUrl) reasons.push(`Recipient ${recipient ?? '(none)'}`);
    else if (!notOnOrAfter) reasons.push('no NotOnOrAfter');
    else if (notOnOrAfter.getTime() <= now - skew) reasons.push(`expired at ${notOnOrAfter.toISOString()}`);
    else if (notBefore !== undefined) reasons.push('a NotBefore, which a bearer confirmation must not have');
    else if (scInResponseTo !== inResponseTo) reasons.push(`InResponseTo ${scInResponseTo ?? '(none)'}`);
    else {
      confirmedUntil = notOnOrAfter;
      break;
    }
  }
  if (!confirmedUntil) invalid(`no bearer SubjectConfirmation of the assertion fits: ${reasons.join('; ') || 'there is none'}`);

  const conditions = child(assertion, NS.saml, 'Conditions');
  if (!conditions) invalid('the assertion has no Conditions, so it names no audience');
  const notBefore = instant(attr(conditions!, 'NotBefore'), 'Conditions NotBefore');
  const notOnOrAfter = instant(attr(conditions!, 'NotOnOrAfter'), 'Conditions NotOnOrAfter');
  if (notBefore && notBefore.getTime() > now + skew) invalid(`the assertion is not valid before ${notBefore.toISOString()}`);
  if (notOnOrAfter && notOnOrAfter.getTime() <= now - skew) invalid(`the assertion expired at ${notOnOrAfter.toISOString()}`);
  const restrictions = children(conditions!, NS.saml, 'AudienceRestriction');
  if (!restrictions.length) invalid('the assertion has no AudienceRestriction');
  // Every AudienceRestriction must name this service provider (Core 2.5.1.4).
  for (const r of restrictions) {
    if (!children(r, NS.saml, 'Audience').some((a) => text(a) === ctx.entityId)) invalid(`the assertion is not for ${ctx.entityId}`);
  }

  const authn = children(assertion, NS.saml, 'AuthnStatement')[0] ?? invalid('the assertion has no AuthnStatement');
  const authnInstant = instant(attr(authn, 'AuthnInstant'), 'AuthnInstant') ?? invalid('the AuthnStatement has no AuthnInstant');
  const sessionNotOnOrAfter = instant(attr(authn, 'SessionNotOnOrAfter'), 'SessionNotOnOrAfter');
  if (sessionNotOnOrAfter && sessionNotOnOrAfter.getTime() <= now - skew) invalid('the identity provider\'s session has already ended');
  const contextEl = child(authn, NS.saml, 'AuthnContext');
  const classRef = contextEl ? text(child(contextEl, NS.saml, 'AuthnContextClassRef')) : '';

  const attributes: Record<string, string[]> = {};
  const attributeFriendlyNames: Record<string, string> = {};
  for (const statement of children(assertion, NS.saml, 'AttributeStatement')) {
    // An EncryptedAttribute (Core 2.7.3.2) is decrypted to the Attribute it holds; the assertion's
    // signature covers its ciphertext, so it was verified above like everything else.
    const decrypted = children(statement, NS.saml, 'EncryptedAttribute').map((e) => {
      const el = parseXml(decryptElement(e, ctx.decryptionKey), 'the decrypted attribute').documentElement;
      if (el.namespaceURI !== NS.saml || el.localName !== 'Attribute') invalid('an EncryptedAttribute does not hold an Attribute');
      return el;
    });
    for (const a of [...children(statement, NS.saml, 'Attribute'), ...decrypted]) {
      const name = attr(a, 'Name');
      if (!name) continue;
      const values = children(a, NS.saml, 'AttributeValue').map((v) => v.textContent ?? '');
      (attributes[name] ??= []).push(...values);
      const friendly = attr(a, 'FriendlyName');
      if (friendly) attributeFriendlyNames[name] = friendly;
    }
  }

  // 5. Once only. Remembered for as long as the assertion could be presented.
  const keepUntil = new Date(Math.max(confirmedUntil!.getTime(), notOnOrAfter?.getTime() ?? 0) + skew);
  if (await ctx.replayCache.checkAndRecord(`${ctx.idpEntityId} ${assertionId}`, keepUntil)) {
    throw new SamlError('replay', `the assertion ${assertionId} has been accepted before`);
  }

  const login: SamlLogin = {
    nameId: text(nameIdEl),
    authnInstant,
    attributes,
    attributeFriendlyNames,
    issuer: ctx.idpEntityId,
    binding: received.binding,
    encrypted: encrypted.length > 0,
    responseId,
    assertionId,
  };
  const optional: Partial<SamlLogin> = {
    nameIdFormat: attr(nameIdEl!, 'Format'),
    nameQualifier: attr(nameIdEl!, 'NameQualifier'),
    spNameQualifier: attr(nameIdEl!, 'SPNameQualifier'),
    sessionIndex: attr(authn, 'SessionIndex'),
    sessionNotOnOrAfter,
    authnContextClassRef: classRef || undefined,
    inResponseTo,
    relayState: received.relayState,
  };
  for (const [k, v] of Object.entries(optional)) if (v !== undefined) (login as unknown as Record<string, unknown>)[k] = v;
  return login;
}
