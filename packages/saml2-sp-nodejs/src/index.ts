// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * saml2-sp-nodejs: a server-side SAML 2.0 service provider.
 *
 * ```ts
 * import { ServiceProvider } from 'saml2-sp-nodejs';
 *
 * const sp = await ServiceProvider.fromFile('saml.json');
 * const request = sp.login({ relayState: '/' });     // keep request.id with the browser, then redirect
 * const who = await sp.acs({ method, url, body }, { requestId });   // at the ACS
 * ```
 *
 * @packageDocumentation
 */

export { ServiceProvider } from './service-provider.ts';
export type { AcsOptions, AcsRequest, LoginOptions, LoginRequest, ServiceProviderOptions } from './service-provider.ts';
export { readConfigFile, resolveConfig } from './config.ts';
export type { RequestBinding, ResolvedConfig, ResponseBinding, SamlConfig } from './config.ts';
export type { SamlLogin } from './response.ts';
export type { IdpMetadata } from './metadata.ts';
export { MemoryReplayCache } from './replay.ts';
export type { ReplayCache } from './replay.ts';
export { SamlError } from './errors.ts';
export type { SamlErrorCode, SamlStatus } from './errors.ts';
export { postFormHtml } from './bindings.ts';
export { createSelfSignedKeyPair } from './x509.ts';
export type { KeyPair, KeyPairOptions } from './x509.ts';
export { SignalsReceiver } from './ssf/receiver.ts';
export type { SignalEvent, SignalsReceiverOptions } from './ssf/receiver.ts';
export { MemorySessionIndex, trackedFrom, DEFAULT_SUBJECT_ATTRIBUTE } from './ssf/session-index.ts';
export type { SessionIndex, TrackedSession } from './ssf/session-index.ts';
export { EVENT, DEFAULT_EVENTS_REQUESTED, DEFAULT_ENDING_EVENTS, subjectOf } from './ssf/events.ts';
export type { SubjectRef } from './ssf/events.ts';
