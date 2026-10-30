// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

/**
 * What kind of failure a {@link SamlError} is. An application usually answers every one of them the
 * same way (the sign-in failed, start again), and logs the code and message for the operator.
 *
 * - `config`: the configuration is incomplete or contradictory.
 * - `metadata`: the identity provider's metadata could not be fetched or does not describe what is needed.
 * - `binding`: the request at the assertion consumer service does not carry a SAML message in a binding
 *   this service provider accepts.
 * - `xml`: the message is not well-formed XML, or carries a DOCTYPE.
 * - `signature`: a signature is missing, uses an algorithm that is refused, or does not verify.
 * - `status`: the identity provider answered with a non-success status. {@link SamlError.status} has it.
 * - `validation`: the message verified but a check on its content failed (audience, recipient, time
 *   window, `InResponseTo`, issuer, ...).
 * - `replay`: the assertion has been accepted before.
 * - `artifact`: the artifact could not be resolved.
 * - `decryption`: an encrypted assertion or NameID could not be decrypted.
 */
export type SamlErrorCode =
  | 'config'
  | 'metadata'
  | 'binding'
  | 'xml'
  | 'signature'
  | 'status'
  | 'validation'
  | 'replay'
  | 'artifact'
  | 'decryption';

/** The status an identity provider answered with, when it was not `Success`. */
export interface SamlStatus {
  /** The top-level `StatusCode`, e.g. `urn:oasis:names:tc:SAML:2.0:status:Responder`. */
  code: string;
  /** The second-level `StatusCode`, e.g. `urn:oasis:names:tc:SAML:2.0:status:AuthnFailed`. */
  subCode?: string;
  /** The `StatusMessage`, if there was one. It is the identity provider's text; do not show it as yours. */
  message?: string;
}

/** Every failure this module reports is one of these. */
export class SamlError extends Error {
  /** What kind of failure it is. */
  readonly code: SamlErrorCode;
  /** For `code === 'status'`: the status the identity provider answered with. */
  readonly status?: SamlStatus;

  constructor(code: SamlErrorCode, message: string, options: { cause?: unknown; status?: SamlStatus } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'SamlError';
    this.code = code;
    if (options.status) this.status = options.status;
  }
}
