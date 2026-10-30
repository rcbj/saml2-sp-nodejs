// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// Metadata, both ways: reading the identity provider's (its entityID, where its single sign-on and
// artifact resolution services are, and the certificates it signs with), and writing this service
// provider's own, which is how the identity provider learns everything about it in one document.

import { X509Certificate } from 'node:crypto';
import { SamlError } from './errors.ts';
import { BINDING, NS, attr, children, descendants, escapeXml, parseXml, pemBody, text, toPem } from './xml.ts';

/** What this module needs to know about the identity provider. */
export interface IdpMetadata {
  entityId: string;
  /** The SingleSignOnService location for each binding the identity provider offers it on. */
  ssoUrls: { redirect?: string; post?: string };
  /** The SOAP ArtifactResolutionService locations, by index. */
  artifactResolutionServices: Map<number, string>;
  /** The certificates its signatures are verified against. */
  signingCertificates: X509Certificate[];
  /** `WantAuthnRequestsSigned`; this module signs every request whatever it says. */
  wantAuthnRequestsSigned: boolean;
}

function certificatesOf(role: Element, use: 'signing' | 'encryption'): X509Certificate[] {
  const out: X509Certificate[] = [];
  for (const kd of children(role, NS.md, 'KeyDescriptor')) {
    const u = attr(kd, 'use');
    if (u && u !== use) continue;
    // The first certificate of each X509Data is the key's own; any after it are its chain.
    for (const data of descendants(kd, NS.ds, 'X509Data')) {
      const first = children(data, NS.ds, 'X509Certificate')[0];
      if (!first) continue;
      try {
        out.push(new X509Certificate(toPem(text(first))));
      } catch (err) {
        throw new SamlError('metadata', `a ${use} certificate in the identity provider's metadata cannot be read`, { cause: err });
      }
    }
  }
  return out;
}

/**
 * Reads identity provider metadata: an EntityDescriptor, or an EntitiesDescriptor holding the one named
 * `entityId`.
 */
export function readIdpMetadata(xml: string, entityId?: string): IdpMetadata {
  const doc = parseXml(xml, 'the identity provider metadata');
  const root = doc.documentElement;
  let entity: Element | undefined;
  if (root.namespaceURI === NS.md && root.localName === 'EntityDescriptor') {
    entity = root;
  } else if (root.namespaceURI === NS.md && root.localName === 'EntitiesDescriptor') {
    const all = descendants(root, NS.md, 'EntityDescriptor').filter((e) => descendants(e, NS.md, 'IDPSSODescriptor').length);
    entity = entityId ? all.find((e) => attr(e, 'entityID') === entityId) : all.length === 1 ? all[0] : undefined;
    if (!entity) {
      throw new SamlError('metadata', entityId
        ? `the metadata aggregate has no identity provider ${entityId}`
        : `the metadata aggregate holds ${all.length} identity providers; name one with idpEntityId`);
    }
  } else {
    throw new SamlError('metadata', 'the identity provider metadata is not an EntityDescriptor');
  }
  const id = attr(entity, 'entityID');
  if (!id) throw new SamlError('metadata', 'the identity provider metadata has no entityID');
  if (entityId && id !== entityId) throw new SamlError('metadata', `the metadata describes ${id}, not ${entityId}`);
  const role = children(entity, NS.md, 'IDPSSODescriptor')[0];
  if (!role) throw new SamlError('metadata', `${id}'s metadata has no IDPSSODescriptor`);

  const ssoUrls: IdpMetadata['ssoUrls'] = {};
  for (const sso of children(role, NS.md, 'SingleSignOnService')) {
    const binding = attr(sso, 'Binding');
    const location = attr(sso, 'Location');
    if (!location) continue;
    if (binding === BINDING.redirect && !ssoUrls.redirect) ssoUrls.redirect = location;
    if (binding === BINDING.post && !ssoUrls.post) ssoUrls.post = location;
  }
  const artifactResolutionServices = new Map<number, string>();
  for (const ars of children(role, NS.md, 'ArtifactResolutionService')) {
    const location = attr(ars, 'Location');
    if (attr(ars, 'Binding') === BINDING.soap && location) artifactResolutionServices.set(Number(attr(ars, 'index') ?? 0), location);
  }
  const signingCertificates = certificatesOf(role, 'signing');
  if (!signingCertificates.length) throw new SamlError('metadata', `${id}'s metadata names no signing certificate`);
  if (!ssoUrls.redirect && !ssoUrls.post) throw new SamlError('metadata', `${id}'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService`);
  return {
    entityId: id,
    ssoUrls,
    artifactResolutionServices,
    signingCertificates,
    wantAuthnRequestsSigned: attr(role, 'WantAuthnRequestsSigned') === 'true',
  };
}

const ENCRYPTION_METHODS = [
  'http://www.w3.org/2009/xmlenc11#aes256-gcm',
  'http://www.w3.org/2009/xmlenc11#aes128-gcm',
  'http://www.w3.org/2009/xmlenc11#rsa-oaep',
  'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
];

/** What goes into this service provider's metadata. */
export interface SpMetadataInput {
  entityId: string;
  acsUrl: string;
  certificate: X509Certificate;
  nameIdFormat?: string;
  wantAssertionsSigned: boolean;
}

/**
 * This service provider's metadata: one signing-and-encryption key, and the assertion consumer service
 * on all three response bindings at the same URL (index 0 POST, the default; 1 Redirect; 2 Artifact).
 */
export function writeSpMetadata(input: SpMetadataInput): string {
  const cert = pemBody(input.certificate.toString());
  const keyInfo = `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`;
  // The encryption key names what this service provider decrypts, strongest first (Metadata 2.4.1.1):
  // an identity provider that reads them picks from these, and never PKCS#1 v1.5.
  const methods = ENCRYPTION_METHODS.map((m) => `\n      <md:EncryptionMethod Algorithm="${m}"/>`).join('');
  const key = (use: string) => `    <md:KeyDescriptor use="${use}">
      ${keyInfo}${use === 'encryption' ? methods : ''}
    </md:KeyDescriptor>`;
  const acs = escapeXml(input.acsUrl);
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}" entityID="${escapeXml(input.entityId)}">
  <md:SPSSODescriptor protocolSupportEnumeration="${NS.samlp}" AuthnRequestsSigned="true" WantAssertionsSigned="${input.wantAssertionsSigned}">
${key('signing')}
${key('encryption')}${input.nameIdFormat ? `\n    <md:NameIDFormat>${escapeXml(input.nameIdFormat)}</md:NameIDFormat>` : ''}
    <md:AssertionConsumerService Binding="${BINDING.post}" Location="${acs}" index="0" isDefault="true"/>
    <md:AssertionConsumerService Binding="${BINDING.redirect}" Location="${acs}" index="1"/>
    <md:AssertionConsumerService Binding="${BINDING.artifact}" Location="${acs}" index="2"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`;
}
