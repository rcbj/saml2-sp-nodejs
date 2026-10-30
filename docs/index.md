---
title: saml2-sp-nodejs
---

# saml2-sp-nodejs

A **SAML 2.0 service provider** for **server-side** Node.js applications: the traditional web application that renders its pages on the server and keeps its session there. It covers:

- **Signed AuthnRequests**, always: on HTTP-Redirect (a query-string signature) or HTTP-POST (an enveloped signature).
- **Responses on all three bindings**: HTTP-POST, HTTP-Artifact (the artifact resolved with a signed `ArtifactResolve` over SOAP, so the Response never passes through the browser), and HTTP-Redirect.
- **Strict validation**: signatures only against the identity provider's own metadata certificates, read from what was signed (no signature wrapping), audience, recipient, time window, `InResponseTo`, and each assertion accepted once.
- **Encryption**: `EncryptedAssertion`, `EncryptedID` and `EncryptedAttribute` decrypted with `node:crypto` (AES-GCM/CBC, RSA-OAEP; PKCS#1 v1.5 refused), and an option that refuses a plaintext assertion.
- **Metadata both ways**: this service provider's written from its configuration, the identity provider's read from a file or a URL.

It is TypeScript and works from JavaScript, needs no web framework, and depends on [`xml-crypto`](https://github.com/node-saml/xml-crypto) and [`@xmldom/xmldom`](https://github.com/xmldom/xmldom) only. It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/saml2-sso.html)'s SAML 2.0 identity provider.

## Install

```sh
npm install saml2-sp-nodejs
```

## Where to read

- **[Server-side guide](guide.md):** keys, metadata, the login route, the assertion consumer service and the session, step by step.
- **[Handling CAEP and RISC events](signals.md):** every CAEP and RISC event type, what it carries, what the receiver does by default, and a handler for each.
- **[Configuration and API reference](reference.md):** every setting, what is checked, the bindings, encryption, errors and the API.
- **[TypeScript API](api/)** (TypeDoc), generated from the source.
- **[Setting up iya-sts](configure.md):** registering the application from its metadata, and reading iya-sts's metadata into the library.
- **[Running the demo](demo.md):** a complete application in one container.
- **[Development and releases](development.md):** tests, CI, branches and versions.

## Quick look

```ts
import { ServiceProvider } from 'saml2-sp-nodejs';

const sp = await ServiceProvider.fromFile('saml.json');

// /login
const request = sp.login({ relayState: '/' });       // keep request.id with the browser
// redirect to request.url, or send request.html for the POST binding

// /saml/acs (GET and POST)
const who = await sp.acs({ method, url, body }, { requestId });
console.log(who.nameId, who.attributes, who.encrypted);
```

The configuration is five lines:

```json
{
  "entityId": "https://app.example.com/saml/metadata",
  "acsUrl": "https://app.example.com/saml/acs",
  "privateKey": "keys/sp.key",
  "certificate": "keys/sp.crt",
  "idpMetadata": "keys/idp-metadata.xml"
}
```

Two commands make the rest:

```sh
npx saml2-sp-nodejs generate-keys --config saml.json    # the signing and encryption key pair
npx saml2-sp-nodejs metadata --config saml.json --out sp-metadata.xml   # for the identity provider
```
