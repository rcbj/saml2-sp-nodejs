// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The HTTP-Artifact binding (SAML 2.0 Bindings, section 3.6), as the receiving side of a Response. The
// browser brings back only a reference, the SAMLart; this service provider sends a SIGNED
// <samlp:ArtifactResolve> over SOAP to the identity provider's ArtifactResolutionService and gets the
// Response in the <samlp:ArtifactResponse>. The Response never passes through the browser.
//
// The back channel is TLS to an address from the identity provider's own metadata, verified, so a
// Response that arrives this way is authenticated by the channel (Bindings 3.6.5.2); a signature on the
// ArtifactResponse, when there is one, is verified as well.

import { createHash, randomBytes, type KeyObject, type X509Certificate } from 'node:crypto';
import { SamlError } from './errors.ts';
import { send, type BackChannelOptions } from './http.ts';
import { signEnveloped, verifySigned } from './signature.ts';
import { NS, STATUS_SUCCESS, assertUniqueIds, attr, child, children, escapeXml, newId, parseXml, text } from './xml.ts';

export interface ParsedArtifact {
  endpointIndex: number;
  sourceId: Buffer;
}

/** Reads a type 0x0004 artifact: type code, endpoint index, SourceID (SHA-1 of the issuer's entityID), handle. */
export function parseArtifact(samlArt: string): ParsedArtifact {
  const bytes = Buffer.from(samlArt.replace(/\s+/g, ''), 'base64');
  if (bytes.length !== 44 || bytes.readUInt16BE(0) !== 0x0004) {
    throw new SamlError('artifact', 'SAMLart is not a SAML 2.0 type 0x0004 artifact');
  }
  return { endpointIndex: bytes.readUInt16BE(2), sourceId: bytes.subarray(4, 24) };
}

export interface ResolveInput {
  artifact: string;
  entityId: string;
  idpEntityId: string;
  artifactResolutionServices: ReadonlyMap<number, string>;
  idpCertificates: readonly X509Certificate[];
  key: KeyObject;
  certificate: X509Certificate;
  tls: BackChannelOptions;
}

export interface ResolvedArtifact {
  /** The ArtifactResponse document, as text (or, when it was signed, what was signed). */
  xml: string;
  /** The samlp:Response it carried. */
  response: Element;
}

/** Resolves an artifact at the identity provider and returns the Response it stood for. */
export async function resolveArtifact(input: ResolveInput): Promise<ResolvedArtifact> {
  const parsed = parseArtifact(input.artifact);
  const expectedSource = createHash('sha1').update(input.idpEntityId, 'utf8').digest();
  if (!parsed.sourceId.equals(expectedSource)) {
    throw new SamlError('artifact', `the artifact was not issued by ${input.idpEntityId}`);
  }
  const location = input.artifactResolutionServices.get(parsed.endpointIndex)
    ?? (parsed.endpointIndex === 0 ? input.artifactResolutionServices.values().next().value : undefined);
  if (!location) throw new SamlError('artifact', `the identity provider's metadata has no SOAP ArtifactResolutionService with index ${parsed.endpointIndex}`);

  const id = newId(randomBytes(20).toString('hex'));
  const unsigned = `<samlp:ArtifactResolve xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${escapeXml(location)}">`
    + `<saml:Issuer>${escapeXml(input.entityId)}</saml:Issuer>`
    + `<samlp:Artifact>${escapeXml(input.artifact)}</samlp:Artifact>`
    + '</samlp:ArtifactResolve>';
  const signed = signEnveloped(unsigned, id, input.key, input.certificate);
  const envelope = `<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="${NS.soap}"><soap:Body>${signed}</soap:Body></soap:Envelope>`;

  const answer = await send(location, {
    method: 'POST',
    headers: { 'content-type': 'text/xml; charset=utf-8', soapaction: '"http://www.oasis-open.org/committees/security"', accept: 'text/xml' },
    body: envelope,
  }, input.tls, 'artifact');
  if (answer.status !== 200) throw new SamlError('artifact', `the artifact resolution service answered HTTP ${answer.status}`);

  const doc = parseXml(answer.body, 'the ArtifactResponse');
  assertUniqueIds(doc);
  const body = doc.documentElement.namespaceURI === NS.soap ? child(doc.documentElement, NS.soap, 'Body') : undefined;
  let artifactResponse = body ? child(body, NS.samlp, 'ArtifactResponse') : undefined;
  if (!artifactResponse) throw new SamlError('artifact', 'the artifact resolution service did not answer with a SOAP ArtifactResponse');
  let xml = answer.body;
  const signedResponse = verifySigned(answer.body, artifactResponse, input.idpCertificates, 'the ArtifactResponse');
  if (signedResponse !== undefined) {
    xml = signedResponse;
    artifactResponse = parseXml(signedResponse, 'the signed ArtifactResponse').documentElement;
  }
  if (attr(artifactResponse, 'InResponseTo') !== id) throw new SamlError('artifact', 'the ArtifactResponse does not answer this ArtifactResolve');
  const issuer = child(artifactResponse, NS.saml, 'Issuer');
  if (issuer && text(issuer) !== input.idpEntityId) throw new SamlError('artifact', `the ArtifactResponse was issued by ${text(issuer)}`);
  const status = child(artifactResponse, NS.samlp, 'Status');
  const code = status ? attr(child(status, NS.samlp, 'StatusCode') ?? status, 'Value') : undefined;
  if (code !== STATUS_SUCCESS) throw new SamlError('artifact', `the artifact resolution failed: ${code ?? 'no status'}`);
  // An artifact that is unknown, expired or already used is answered with Success and no message.
  const response = children(artifactResponse, NS.samlp, 'Response')[0];
  if (!response) throw new SamlError('artifact', 'the identity provider did not resolve the artifact (unknown, expired, or already used)');
  return { xml, response };
}
