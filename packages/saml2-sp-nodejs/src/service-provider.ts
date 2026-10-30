// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The service provider: what an application calls. Three calls make a sign-in:
//
//   login()     builds a signed AuthnRequest and says how to send the browser to the identity provider;
//               the application keeps the request's id with the browser (a cookie) until it comes back;
//   acs()       reads the Response at the assertion consumer service, whichever binding brought it,
//               validates it against the ids that browser has outstanding, and returns who signed in;
//   metadata()  this service provider's metadata, for the identity provider.
//
// It speaks no web framework: acs() takes the method, the URL and the parsed or raw form body, which
// every framework (and node:http) has.

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolveArtifact } from './artifact.ts';
import { postFormHtml, readPost, readRedirect, redirectQuery } from './bindings.ts';
import { readConfigFile, resolveConfig, type RequestBinding, type ResolvedConfig, type ResponseBinding, type SamlConfig } from './config.ts';
import { SamlError } from './errors.ts';
import { send, type BackChannelOptions } from './http.ts';
import { readIdpMetadata, writeSpMetadata, type IdpMetadata } from './metadata.ts';
import { MemoryReplayCache, type ReplayCache } from './replay.ts';
import { validateResponse, type SamlLogin } from './response.ts';
import { signEnveloped } from './signature.ts';
import { BINDING, NS, escapeXml, newId, parseXml } from './xml.ts';

/** Options that are code rather than configuration. */
export interface ServiceProviderOptions {
  /** Where accepted assertion IDs are remembered. Default: this process's memory. */
  replayCache?: ReplayCache;
}

/** Per sign-in choices; each defaults to the configuration. */
export interface LoginOptions {
  /** Opaque state the identity provider returns unchanged (at most 80 bytes, Bindings 3.4.3). Typically where to go after sign-in. */
  relayState?: string;
  /** Ask the identity provider to authenticate the person again even if it has a session. */
  forceAuthn?: boolean;
  /** Ask the identity provider not to interact with the person. */
  isPassive?: boolean;
  requestBinding?: RequestBinding;
  responseBinding?: ResponseBinding;
  /** For `requestBinding: 'post'`: a CSP nonce for the auto-submit script on the form page. */
  nonce?: string;
}

/** How to send the browser to the identity provider. Keep `id` with the browser until it returns. */
export type LoginRequest =
  | { id: string; binding: 'redirect'; responseBinding: ResponseBinding; url: string; xml: string }
  | { id: string; binding: 'post'; responseBinding: ResponseBinding; url: string; fields: Record<string, string>; html: string; xml: string };

/** The parts of an HTTP request at the assertion consumer service that this module reads. */
export interface AcsRequest {
  /** `GET` or `POST`. */
  method: string;
  /** The request URL: the path and query as received (`req.url`, `req.originalUrl`), or an absolute URL. */
  url: string;
  /** For POST: the form body, raw (`application/x-www-form-urlencoded` text) or already parsed. */
  body?: string | Record<string, unknown> | undefined;
}

export interface AcsOptions {
  /** The AuthnRequest id(s) this browser has outstanding, as kept from {@link ServiceProvider.login}. */
  requestId?: string | readonly string[] | undefined;
}

const BINDING_URI: Record<ResponseBinding, string> = {
  post: BINDING.post,
  redirect: BINDING.redirect,
  artifact: BINDING.artifact,
};

export class ServiceProvider {
  readonly config: ResolvedConfig;
  #idp: IdpMetadata | undefined;
  readonly #replayCache: ReplayCache;

  constructor(config: ResolvedConfig, idp: IdpMetadata | undefined, options: ServiceProviderOptions = {}) {
    this.config = config;
    this.#idp = idp;
    this.#replayCache = options.replayCache ?? new MemoryReplayCache();
  }

  /** Builds a service provider from a configuration object and loads the identity provider's metadata. */
  static async create(config: SamlConfig, options: ServiceProviderOptions & { baseDir?: string } = {}): Promise<ServiceProvider> {
    const sp = new ServiceProvider(resolveConfig(config, options.baseDir), undefined, options);
    await sp.refreshMetadata();
    return sp;
  }

  /** Builds a service provider from a JSON configuration file and loads the identity provider's metadata. */
  static async fromFile(path: string, overrides: Partial<SamlConfig> = {}, options: ServiceProviderOptions = {}): Promise<ServiceProvider> {
    const sp = new ServiceProvider(readConfigFile(path, overrides), undefined, options);
    await sp.refreshMetadata();
    return sp;
  }

  /** The identity provider, as its metadata describes it. */
  get idp(): IdpMetadata {
    if (!this.#idp) throw new SamlError('metadata', 'the identity provider\'s metadata has not been loaded');
    return this.#idp;
  }

  get #tls(): BackChannelOptions {
    return this.config.idpCa ? { ca: this.config.idpCa } : {};
  }

  /** (Re)reads the identity provider's metadata from where the configuration says it is. Call it to pick up a key rollover. */
  async refreshMetadata(): Promise<IdpMetadata> {
    const source = this.config.idpMetadata;
    let xml: string;
    if (source.startsWith('<')) {
      xml = source;
    } else if (/^https?:\/\//.test(source)) {
      const answer = await send(source, { headers: { accept: 'application/samlmetadata+xml, application/xml, text/xml' } }, this.#tls, 'metadata');
      if (answer.status !== 200) throw new SamlError('metadata', `${source} answered HTTP ${answer.status}`);
      xml = answer.body;
    } else {
      try {
        xml = readFileSync(source, 'utf8');
      } catch (err) {
        throw new SamlError('metadata', `the identity provider metadata file ${source} cannot be read`, { cause: err });
      }
    }
    this.#idp = readIdpMetadata(xml, this.config.idpEntityId);
    return this.#idp;
  }

  /** This service provider's metadata. Serve it at the entityID, or give it to the identity provider. */
  metadata(): string {
    return writeSpMetadata({
      entityId: this.config.entityId,
      acsUrl: this.config.acsUrl,
      certificate: this.config.certificate,
      wantAssertionsSigned: this.config.wantAssertionsSigned,
      ...(this.config.nameIdFormat ? { nameIdFormat: this.config.nameIdFormat } : {}),
    });
  }

  /** Builds a signed AuthnRequest. Send the browser where the answer says, and keep `id` with that browser. */
  login(options: LoginOptions = {}): LoginRequest {
    const binding = options.requestBinding ?? this.config.requestBinding;
    const responseBinding = options.responseBinding ?? this.config.responseBinding;
    if (responseBinding === 'artifact' && !this.idp.artifactResolutionServices.size) {
      throw new SamlError('config', 'the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact');
    }
    const destination = this.idp.ssoUrls[binding];
    if (!destination) throw new SamlError('config', `the identity provider has no SingleSignOnService on HTTP-${binding === 'post' ? 'POST' : 'Redirect'}`);
    if (options.relayState !== undefined && Buffer.byteLength(options.relayState) > 80) {
      throw new SamlError('config', 'relayState is longer than the 80 bytes the bindings allow');
    }
    const id = newId(randomBytes(20).toString('hex'));
    const forceAuthn = options.forceAuthn ? ' ForceAuthn="true"' : '';
    const isPassive = options.isPassive ? ' IsPassive="true"' : '';
    const policy = this.config.nameIdFormat
      ? `<samlp:NameIDPolicy Format="${escapeXml(this.config.nameIdFormat)}" AllowCreate="true"/>`
      : '<samlp:NameIDPolicy AllowCreate="true"/>';
    const xml = `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${id}" Version="2.0"`
      + ` IssueInstant="${new Date().toISOString()}" Destination="${escapeXml(destination)}"`
      + ` AssertionConsumerServiceURL="${escapeXml(this.config.acsUrl)}" ProtocolBinding="${BINDING_URI[responseBinding]}"${forceAuthn}${isPassive}>`
      + `<saml:Issuer>${escapeXml(this.config.entityId)}</saml:Issuer>`
      + policy
      + '</samlp:AuthnRequest>';

    if (binding === 'redirect') {
      const query = redirectQuery('SAMLRequest', xml, options.relayState, this.config.privateKey);
      const url = `${destination}${destination.includes('?') ? '&' : '?'}${query}`;
      return { id, binding, responseBinding, url, xml };
    }
    const signed = signEnveloped(xml, id, this.config.privateKey, this.config.certificate);
    const fields: Record<string, string> = { SAMLRequest: Buffer.from(signed, 'utf8').toString('base64') };
    if (options.relayState !== undefined) fields.RelayState = options.relayState;
    const html = postFormHtml(destination, fields, options.nonce ? { nonce: options.nonce } : {});
    return { id, binding, responseBinding, url: destination, fields, html, xml: signed };
  }

  /**
   * Reads and validates the Response at the assertion consumer service, on whichever binding it came:
   * a POSTed `SAMLResponse`, a `SAMLResponse` in the query (HTTP-Redirect), or a `SAMLart` in the query
   * or the form (HTTP-Artifact, resolved here over SOAP). Returns who signed in; throws a
   * {@link SamlError} otherwise.
   */
  async acs(request: AcsRequest, options: AcsOptions = {}): Promise<SamlLogin> {
    const idp = this.idp;
    const method = request.method.toUpperCase();
    const rawQuery = request.url.includes('?') ? request.url.slice(request.url.indexOf('?') + 1).split('#')[0]! : '';
    const query = new URLSearchParams(rawQuery);
    const form = method === 'POST' ? formOf(request.body) : new URLSearchParams();
    const expectedRequestIds = options.requestId === undefined ? [] : ([] as string[]).concat(options.requestId);
    const ctx = {
      entityId: this.config.entityId,
      acsUrl: this.config.acsUrl,
      idpEntityId: idp.entityId,
      idpCertificates: idp.signingCertificates,
      decryptionKey: this.config.privateKey,
      clockSkewMs: this.config.clockSkewMs,
      wantAssertionsSigned: this.config.wantAssertionsSigned,
      wantAssertionsEncrypted: this.config.wantAssertionsEncrypted,
      allowUnsolicited: this.config.allowUnsolicited,
      replayCache: this.#replayCache,
      expectedRequestIds,
    };

    const samlArt = form.get('SAMLart') ?? query.get('SAMLart');
    if (samlArt) {
      const resolved = await resolveArtifact({
        artifact: samlArt,
        entityId: this.config.entityId,
        idpEntityId: idp.entityId,
        artifactResolutionServices: idp.artifactResolutionServices,
        idpCertificates: idp.signingCertificates,
        key: this.config.privateKey,
        certificate: this.config.certificate,
        tls: this.#tls,
      });
      const relayState = form.get('SAMLart') ? form.get('RelayState') : query.get('RelayState');
      return validateResponse({ ...resolved, binding: 'artifact', relayState: relayState ?? undefined, authenticatedByBinding: true }, ctx);
    }
    if (method === 'POST' && form.get('SAMLResponse')) {
      const xml = readPost(form.get('SAMLResponse')!, 'SAMLResponse');
      const doc = parseXml(xml, 'the Response');
      return validateResponse({ xml, response: doc.documentElement, binding: 'post', relayState: form.get('RelayState') ?? undefined, authenticatedByBinding: false }, ctx);
    }
    if (query.get('SAMLResponse')) {
      const message = readRedirect(rawQuery, 'SAMLResponse', idp.signingCertificates);
      const doc = parseXml(message.xml, 'the Response');
      return validateResponse({ xml: message.xml, response: doc.documentElement, binding: 'redirect', relayState: message.relayState, authenticatedByBinding: message.signed }, ctx);
    }
    throw new SamlError('binding', 'the request carries no SAMLResponse or SAMLart');
  }
}

function formOf(body: AcsRequest['body']): URLSearchParams {
  if (body === undefined || body === null) return new URLSearchParams();
  if (typeof body === 'string') return new URLSearchParams(body);
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) if (typeof v === 'string') out.set(k, v);
  return out;
}
