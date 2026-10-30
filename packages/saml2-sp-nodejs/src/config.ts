// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The configuration: seven settings, four of them with defaults. Everything else this service provider
// needs is in the identity provider's metadata, which the configuration names.

import { createPrivateKey, X509Certificate, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { SamlError } from './errors.ts';

export type RequestBinding = 'redirect' | 'post';
export type ResponseBinding = 'post' | 'redirect' | 'artifact';

/**
 * The configuration, as a JSON file holds it. File paths are relative to the file.
 *
 * ```json
 * {
 *   "entityId": "https://app.example.com/saml/metadata",
 *   "acsUrl": "https://app.example.com/saml/acs",
 *   "privateKey": "keys/sp.key",
 *   "certificate": "keys/sp.crt",
 *   "idpMetadata": "https://idp.example.com/saml2/metadata"
 * }
 * ```
 */
export interface SamlConfig {
  /** This service provider's entityID. Its metadata URL is the usual choice. */
  entityId: string;
  /** The assertion consumer service: where the identity provider sends the browser back. */
  acsUrl: string;
  /** The RSA private key every request is signed with (and encrypted assertions decrypted with): a PEM file path, or the PEM. */
  privateKey: string;
  /** The certificate for that key: a PEM file path, or the PEM. */
  certificate: string;
  /** The identity provider's metadata: an http(s) URL, a file path, or the XML itself. */
  idpMetadata: string;
  /** The binding the AuthnRequest is sent on. Default `redirect`. */
  requestBinding?: RequestBinding;
  /** The binding the identity provider is asked to send the Response on. Default `post`. */
  responseBinding?: ResponseBinding;

  /** PEM certificate(s) to trust for TLS to the identity provider (metadata URL, artifact resolution), beyond node's own store: a file path or the PEM. */
  idpCa?: string;
  /** For metadata that is an aggregate: the identity provider's entityID. */
  idpEntityId?: string;
  /** The `NameIDPolicy` Format to ask for. Default: none, the identity provider decides. */
  nameIdFormat?: string;
  /** How far the two clocks may disagree, in seconds. Default 60. */
  clockSkewSeconds?: number;
  /** Refuse a Response whose assertion is not signed itself, even when the Response is. Default true. */
  wantAssertionsSigned?: boolean;
  /** Refuse a Response whose assertion is not encrypted (an EncryptedAssertion) to this service provider's key. Default false. */
  wantAssertionsEncrypted?: boolean;
  /** Accept a Response nobody asked for (identity-provider-initiated sign-in). Default false. */
  allowUnsolicited?: boolean;
}

/** The configuration with its files read and its defaults filled in. */
export interface ResolvedConfig {
  entityId: string;
  acsUrl: string;
  privateKey: KeyObject;
  certificate: X509Certificate;
  idpMetadata: string;
  requestBinding: RequestBinding;
  responseBinding: ResponseBinding;
  idpCa?: string;
  idpEntityId?: string;
  nameIdFormat?: string;
  clockSkewMs: number;
  wantAssertionsSigned: boolean;
  wantAssertionsEncrypted: boolean;
  allowUnsolicited: boolean;
}

const looksLikePem = (v: string) => v.includes('-----BEGIN ');

function material(value: string, baseDir: string, what: string): string {
  if (looksLikePem(value)) return value;
  const path = isAbsolute(value) ? value : resolve(baseDir, value);
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    throw new SamlError('config', `${what} is neither a PEM nor a readable file (${path})`, { cause: err });
  }
}

function absoluteUrl(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new SamlError('config', `${what} is required`);
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('not http(s)');
  } catch {
    throw new SamlError('config', `${what} must be an absolute http(s) URL, not ${value}`);
  }
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], dflt: T, what: string): T {
  if (value === undefined || value === null || value === '') return dflt;
  if (!allowed.includes(value as T)) throw new SamlError('config', `${what} must be one of ${allowed.join(', ')}, not ${String(value)}`);
  return value as T;
}

/** Checks a configuration and reads its key, certificate and CA files, relative to `baseDir`. */
export function resolveConfig(config: SamlConfig, baseDir = process.cwd()): ResolvedConfig {
  if (!config || typeof config !== 'object') throw new SamlError('config', 'the configuration must be an object');
  const entityId = config.entityId;
  if (typeof entityId !== 'string' || !entityId.trim()) throw new SamlError('config', 'entityId is required');
  const acsUrl = absoluteUrl(config.acsUrl, 'acsUrl');
  if (typeof config.privateKey !== 'string' || typeof config.certificate !== 'string') {
    throw new SamlError('config', 'privateKey and certificate are required: every AuthnRequest is signed');
  }
  let privateKey: KeyObject;
  let certificate: X509Certificate;
  try {
    privateKey = createPrivateKey(material(config.privateKey, baseDir, 'privateKey'));
    certificate = new X509Certificate(material(config.certificate, baseDir, 'certificate'));
  } catch (err) {
    if (err instanceof SamlError) throw err;
    throw new SamlError('config', `the private key or certificate cannot be read: ${(err as Error).message}`, { cause: err });
  }
  if (privateKey.asymmetricKeyType !== 'rsa') throw new SamlError('config', `the private key is ${privateKey.asymmetricKeyType}; an RSA key is required`);
  if (!certificate.checkPrivateKey(privateKey)) throw new SamlError('config', 'the certificate is not for the private key');
  if (typeof config.idpMetadata !== 'string' || !config.idpMetadata.trim()) throw new SamlError('config', 'idpMetadata is required');
  let idpMetadata = config.idpMetadata.trim();
  if (!/^https?:\/\//.test(idpMetadata) && !idpMetadata.startsWith('<')) {
    idpMetadata = isAbsolute(idpMetadata) ? idpMetadata : resolve(baseDir, idpMetadata);
  }
  const skew = config.clockSkewSeconds ?? 60;
  if (typeof skew !== 'number' || !Number.isFinite(skew) || skew < 0 || skew > 600) {
    throw new SamlError('config', 'clockSkewSeconds must be a number from 0 to 600');
  }
  const out: ResolvedConfig = {
    entityId,
    acsUrl,
    privateKey,
    certificate,
    idpMetadata,
    requestBinding: oneOf(config.requestBinding, ['redirect', 'post'] as const, 'redirect', 'requestBinding'),
    responseBinding: oneOf(config.responseBinding, ['post', 'redirect', 'artifact'] as const, 'post', 'responseBinding'),
    clockSkewMs: skew * 1000,
    wantAssertionsSigned: config.wantAssertionsSigned ?? true,
    wantAssertionsEncrypted: config.wantAssertionsEncrypted ?? false,
    allowUnsolicited: config.allowUnsolicited ?? false,
  };
  if (config.idpCa) out.idpCa = material(config.idpCa, baseDir, 'idpCa');
  if (config.idpEntityId) out.idpEntityId = config.idpEntityId;
  if (config.nameIdFormat) out.nameIdFormat = config.nameIdFormat;
  return out;
}

/** Reads a configuration file (JSON). Paths in it are relative to the file. `overrides` win over the file. */
export function readConfigFile(path: string, overrides: Partial<SamlConfig> = {}): ResolvedConfig {
  let parsed: SamlConfig;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as SamlConfig;
  } catch (err) {
    throw new SamlError('config', `${path} cannot be read as JSON: ${(err as Error).message}`, { cause: err });
  }
  const defined = Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined));
  return resolveConfig({ ...parsed, ...defined }, dirname(resolve(path)));
}
