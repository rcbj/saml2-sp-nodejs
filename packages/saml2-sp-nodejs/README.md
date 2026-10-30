# saml2-sp-nodejs

A **SAML 2.0 service provider** for server-side Node.js applications: signed AuthnRequests, and Responses received on **HTTP-POST**, **HTTP-Redirect** or **HTTP-Artifact**, validated strictly, with encrypted assertions decrypted. Written in TypeScript, usable from JavaScript (ESM, or `require()` on Node 22.12+). Two runtime dependencies: [`xml-crypto`](https://github.com/node-saml/xml-crypto) and [`@xmldom/xmldom`](https://github.com/xmldom/xmldom). Everything else is `node:crypto`, `node:zlib` and `node:https`.

**Documentation:** <https://rcbj.github.io/saml2-sp-nodejs/> (guide, Shared Signals handlers, API reference)

```sh
npm install saml2-sp-nodejs
```

It speaks no web framework. The three calls take and return plain values, so it fits Express, Fastify, Koa or `node:http` alike. See the [server-side guide](docs/guide.md) for a walkthrough.

## Quick look

```ts
import { ServiceProvider, SamlError } from 'saml2-sp-nodejs';

const sp = await ServiceProvider.fromFile('saml.json');

// GET /login: a signed AuthnRequest. Keep request.id with the browser until it comes back.
const request = sp.login({ relayState: '/' });
// request.binding === 'redirect' → redirect to request.url
// request.binding === 'post'     → send request.html (a form that posts itself)

// GET|POST /saml/acs: whichever binding the Response came on.
try {
  const who = await sp.acs({ method: req.method, url: req.url, body }, { requestId });
  // who.nameId, who.attributes, who.sessionIndex, who.encrypted, ...
} catch (err) {
  if (err instanceof SamlError) console.warn(err.code, err.message);
}

// GET /saml/metadata: this service provider's metadata, for the identity provider.
res.end(sp.metadata());
```

From JavaScript it is the same without the types:

```js
const { ServiceProvider } = await import('saml2-sp-nodejs');   // or require('saml2-sp-nodejs') on Node 22.12+
```

## The configuration

```json
{
  "entityId": "https://app.example.com/saml/metadata",
  "acsUrl": "https://app.example.com/saml/acs",
  "privateKey": "keys/sp.key",
  "certificate": "keys/sp.crt",
  "idpMetadata": "keys/idp-metadata.xml"
}
```

| Setting | Default | |
|---|---|---|
| `entityId` | required | This service provider's entityID. |
| `acsUrl` | required | The assertion consumer service, where the browser comes back. |
| `privateKey`, `certificate` | required | The RSA key every request is signed with (and encrypted assertions decrypted with), and its certificate. A file path, relative to the configuration file, or the PEM itself. |
| `idpMetadata` | required | The identity provider's metadata: a file path, an `https` URL, or the XML. Its entityID, endpoints and signing certificates are read from it. |
| `requestBinding` | `redirect` | The AuthnRequest's binding: `redirect` (query-string signature) or `post` (enveloped signature). |
| `responseBinding` | `post` | The binding the Response is asked for on: `post`, `artifact` or `redirect`. |
| `wantAssertionsSigned` | `true` | Refuse an assertion that is not signed itself, even inside a signed Response. |
| `wantAssertionsEncrypted` | `false` | Refuse an assertion that is not an `EncryptedAssertion`. |
| `idpCa` | — | PEM certificate(s) to trust for TLS to the identity provider (the metadata URL, artifact resolution), in addition to node's own store. |
| `idpEntityId` | — | For metadata that is an aggregate: which identity provider. |
| `nameIdFormat` | — | The `NameIDPolicy` Format to ask for. |
| `clockSkewSeconds` | `60` | How far the two clocks may disagree. |
| `allowUnsolicited` | `false` | Accept a Response no request asked for (identity-provider-initiated sign-in). |

`ServiceProvider.create(config, { baseDir })` takes the same members as an object.

## What it checks

Every Response, whichever binding brought it:

- **No DOCTYPE**, and no two elements sharing an ID, which is how a signature is made to point at the wrong element.
- **Signatures against the identity provider's own certificates, from its metadata**, never against a certificate the message carries. RSA-SHA256/384/512 only; SHA-1 is refused. A signature must be an enveloped signature of its own parent: one reference, to the parent's ID, with only the enveloped and canonicalization transforms.
- **What was signed is what is read.** Once a signature verifies, the element is parsed from the XML that was signed, never from the document it arrived in, so a forged element placed beside the signed one is not seen.
- **The Response**: Version 2.0, the identity provider as Issuer, `Destination` equal to the ACS (required when the Response is signed), `InResponseTo` one of the requests this browser has outstanding, status `Success` (otherwise a `status` error with the codes).
- **Exactly one assertion**, decrypted if it is encrypted, signed by default.
- **The assertion**: the identity provider as Issuer; a bearer `SubjectConfirmation` whose `Recipient` is the ACS, whose `InResponseTo` matches, which has not expired and has no `NotBefore`; `Conditions` in their time window; this service provider in every `AudienceRestriction`; an `AuthnStatement`, with its `SessionNotOnOrAfter` not passed.
- **Once only**: the assertion's ID is remembered until it could no longer be presented. The default `MemoryReplayCache` is one process's. Give `ServiceProvider` a shared `replayCache` when the application runs several.

## The three response bindings

| Binding | What happens at the ACS |
|---|---|
| **HTTP-POST** | The Response arrives in the `SAMLResponse` form field; its signature is inside the XML. |
| **HTTP-Artifact** | The browser brings a `SAMLart`; `acs()` sends a **signed** `ArtifactResolve` over SOAP to the identity provider's `ArtifactResolutionService` (TLS, verified) and validates the Response it gets back. The Response never passes through the browser. |
| **HTTP-Redirect** | The Response arrives DEFLATEd in the query. A query signature is verified over the parameters exactly as they arrived. **The SAML Web Browser SSO profile (Profiles 4.1.2) forbids an identity provider to send a Response this way**, because a signed Response rarely fits in a URL. It is accepted for the identity providers that do; prefer POST or Artifact. |

The AuthnRequest goes on HTTP-Redirect or HTTP-POST. SAML has no artifact binding an identity provider accepts a request on in practice, and **no encrypted AuthnRequest**: a request is signed, and TLS keeps it confidential.

## Encryption

`EncryptedAssertion`, `EncryptedID` and `EncryptedAttribute` are decrypted with `node:crypto`: AES-GCM or AES-CBC content, the key wrapped with RSA-OAEP (`rsa-oaep-mgf1p`, or XML Encryption 1.1 `rsa-oaep` with one hash for digest and MGF1). **RSA PKCS#1 v1.5 key transport is refused** (it is the padding oracle XML Encryption was broken with). The metadata publishes the encryption key and the algorithms accepted. Set `wantAssertionsEncrypted` to refuse a plaintext assertion.

## Shared Signals: CAEP and RISC

`SignalsReceiver` makes the application a Shared Signals receiver (OpenID SSF 1.0, poll delivery per RFC 8936). It has **one stream** at the identity provider, carrying CAEP session events and RISC account events about **every person** who uses the application. Each event is turned into the application's own sessions to end.

```ts
import { EVENT, ServiceProvider, SignalsReceiver } from 'saml2-sp-nodejs';

const sp = await ServiceProvider.fromFile('saml.json');
const signals = new SignalsReceiver({
  transmitter: 'https://idp.example.com',
  // Mutual TLS with the SP's own key pair: no token, no secret.
  tls: { ca: sp.config.idpCa, cert: sp.config.certificate.toString(),
         key: sp.config.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string },
  onEndSessions: (localIds, event) => { for (const id of localIds) sessionStore.destroy(id); },
});
signals.on(EVENT.credentialChange, (event) => console.log('credential changed:', event.payload.credential_type));
signals.on('*', (event) => console.log(event.type, event.subject));
await signals.start();

// at the ACS, after the session is created:
await signals.track(session.id, who);
// at sign-out:
await signals.untrack(session.id);
```

- **One stream, found or created.** `start()` reads `/.well-known/ssf-configuration`. It reuses the application's poll stream (`GET` on the configuration endpoint lists the caller's streams) or creates one, then polls.
- **Every SET is verified before anything acts on it**: the signature against the transmitter's JWKS (RS, PS, ES, EdDSA; the key chosen by `kid`, never from the token), `iss`, `aud` (the stream's), `typ` and `jti`. A SET is acknowledged only once handled. One it refuses is reported in `setErrs` and changes nothing.
- **Matching events to sessions.** `track()` records three things from the SAML login:
  - the person's subject, read from `subjectAttribute`, which defaults to iya-sts's (and AD FS's) `nameidentifier` claim and holds `urn:uuid:…`;
  - their email address;
  - the IdP session, the assertion's `SessionIndex`, which is the session id a CAEP event names.

  A `session-revoked` naming an IdP session ends only the local sessions started from it. An account event (`account-disabled`, `account-purged`, `credential-compromise`, `sessions-revoked`) ends all of the person's local sessions. `endOn` changes which types end sessions; every event also goes to the `on(type)` handlers.
- **Handlers, one per event type.** `on(EVENT.x, handler)` for any of CAEP's eight and RISC's fourteen types (`EVENT`, `CAEP_EVENTS`, `RISC_EVENTS`), or `'*'` for all. Handlers run after the SET is verified and before it is acknowledged. One that throws is logged, and the SET is still acknowledged. **[Handling CAEP and RISC events](docs/signals.md)** lists every type, its members, its default and a handler for each.
- **Several processes.** The default `MemorySessionIndex` is one process's memory. Give every process the same `sessionIndex` (a table, Redis), and run the receiver in one of them, so an event ends sessions wherever they were created.
- **Authentication.** Use `tls.cert`/`tls.key` (mutual TLS), or `headers()` to supply an `authorization` header for a transmitter that wants a token.

## Errors

Every failure is a `SamlError` with a `code`: `config`, `metadata`, `binding`, `xml`, `signature`, `status`, `validation`, `replay`, `artifact`, `decryption` or `ssf` (the Shared Signals transmitter or stream). A `status` error carries the identity provider's `status` (`code`, `subCode`, `message`). Log the message; tell the person only that sign-in failed.

## The command line

```sh
npx saml2-sp-nodejs generate-keys --config saml.json   # a new RSA key and a self-signed certificate
npx saml2-sp-nodejs metadata --config saml.json --out sp-metadata.xml
```

`generate-keys` writes where the configuration's `privateKey` and `certificate` point (or `--key`/`--cert`), refuses to replace them without `--force`, and takes `--cn`, `--days` (1095) and `--bits` (3072). The certificate only carries the public key in metadata, so self-signed is the norm. After a new key, give the identity provider the new metadata.

## API

| | |
|---|---|
| `ServiceProvider.fromFile(path, overrides?, options?)` | Read a JSON configuration (paths relative to it) and load the IdP metadata. |
| `ServiceProvider.create(config, { baseDir?, replayCache? })` | The same from an object. |
| `sp.login({ relayState?, forceAuthn?, isPassive?, subjectHint?, subjectHintFormat?, requestBinding?, responseBinding?, nonce? })` | A signed AuthnRequest: `{ id, binding, responseBinding, url, xml }`, plus `fields` and `html` for POST. `nonce` puts a CSP nonce on the auto-submit script. |
| `sp.acs({ method, url, body? }, { requestId? })` | Validate the Response; resolves to a `SamlLogin`. `body` is the raw form text or a parsed object. |
| `sp.metadata()` | This service provider's metadata. |
| `sp.refreshMetadata()` | Read the IdP metadata again (a key rollover). |
| `sp.idp`, `sp.config` | What was read. |
| `MemoryReplayCache`, `ReplayCache` | The default replay cache, and the interface for a shared one (`checkAndRecord(id, expiresAt)`). |
| `postFormHtml(action, fields, { nonce? })` | The auto-posting form page. |
| `SamlError` | Every failure. |

`SamlLogin`: `nameId`, `nameIdFormat`, `nameQualifier`, `spNameQualifier`, `sessionIndex`, `sessionNotOnOrAfter`, `authnInstant`, `authnContextClassRef`, `attributes` (Name → values), `attributeFriendlyNames`, `issuer`, `inResponseTo`, `relayState`, `binding`, `encrypted`, `responseId`, `assertionId`.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
