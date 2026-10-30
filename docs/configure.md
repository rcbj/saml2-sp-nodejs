---
title: Setting up iya-sts
---

# Setting up iya-sts

Two metadata documents do all the work. This service provider's metadata, made from its configuration, is what iya-sts registers the application from. iya-sts's metadata, fetched for that application, is what the library reads to know the identity provider. Nothing is typed into either side by hand.

## The script

```sh
npm install
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
```

[`scripts/configure-iya-sts.ts`](https://github.com/rcbj/saml2-sp-nodejs/blob/main/scripts/configure-iya-sts.ts) reads [`demo/saml.json`](https://github.com/rcbj/saml2-sp-nodejs/blob/main/demo/saml.json) and:

1. **Makes the key pair** if the files `privateKey` and `certificate` name do not exist yet (the same as `npm run generate-keys`).
2. **Saves iya-sts's TLS root** to the `idpCa` file if it does not exist yet. It is taken from the TLS handshake (trust on first use) and its SHA-256 fingerprint is printed: compare it with the Root CA on iya-sts's **Server configuration → PKI** page.
3. **Writes this service provider's metadata** to `demo/generated/sp-metadata.xml` (the same as `npm run generate-metadata`) and **registers the application from it**: `POST /admin-api/applications/create` with the document in `samlSpMetadata`, which iya-sts consumes on create, or, when the application exists, `POST /admin-api/saml2/upload-metadata`. The assertion consumer service on its three bindings, the signing and encryption certificate and `AuthnRequestsSigned` all come from the document.
4. **Pins assertion encryption** on the application: `saml2EncryptAssertion` TRUE, `saml2EncryptionAlgorithm` `aes256-gcm`, `saml2KeyTransportAlgorithm` `rsa-oaep`. (iya-sts already encrypts to a service provider whose metadata publishes an encryption key; these name the algorithms.)
5. **Turns on `authn.multipleAccounts` for the realm** (`POST /admin-api/config/set`), so one browser may hold several signed-in people. The demo signs several people in to one browser. With the setting off, iya-sts ends the first person's session when the second signs in there, and sends CAEP `session-revoked` for it, which ends that person's account in the demo too.
6. **With an `ssf` block in the configuration, gives the application Shared Signals access by its own certificate** (mutual TLS: no token, no secret):
   - `POST /admin-api/applications/add`: `oauthAllowedScope` `ssf.manage` (which includes read; iya-sts reads a certificate's scopes as declared);
   - `POST /admin-api/roles/add-member`: the application in `SSF_MANAGE`, the role that authorizes the scope;
   - `POST /admin-api/tls/trust/add`: the SP certificate as a client trust anchor, so the TLS handshake accepts it (process-wide; at most 32 anchors);
   - `POST /admin-api/applications/add-certificate` (iya-sts #1227): the certificate stored on the application entry, which makes a handshake presenting it this application at `/ssf/*`.
7. **Fetches iya-sts's metadata for this application**, `/saml2/metadata/<entityID>`, checks it with the library's own reader, and saves it where `idpMetadata` points. Its entityID, the SSO and artifact resolution endpoints and the signing certificate come from it.
8. **Creates a test user**, `saml-demo-user`. Its password is `SAML_DEMO_USER_PASSWORD`, or one is generated and printed once. With `SAML_DEMO_USER_PASSWORD` set, an existing user's password is replaced.

Every step can be run again: an existing application has its metadata consumed again, and an existing key pair, CA file and user are kept.

| Option | Use |
|---|---|
| `--idp url` | iya-sts is not at `https://localhost:8081` (or `$IYA_STS_URL`). A trust realm's base, `https://host/realm/<id>`, registers in that realm. |
| `--config path` | Another configuration file. |
| `--test-user name`, `--no-test-user` | Another test user, or none. |
| `--dry-run` | Print the plan and send nothing. |

### The management API secret

The script mints a token as iya-sts's seeded client `sts-api-client` (`client_credentials`, HTTP Basic, audience `<idp>/admin-api`, scope `admin:read admin:write`). The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. On iya-sts's compose stack it is kept in OpenBao; [iya-sts's management API page](https://rcbj.github.io/iya-sts/management-api.html) says how to read it.

## What iya-sts checks, in product mode

iya-sts in product mode accepts this service provider only because the metadata registered it:

- **The SP must be registered.** An AuthnRequest from an unknown issuer is refused before anything else.
- **Requests must be signed**, verified against the certificate in the consumed metadata, never against one the request carries.
- **The ACS must be one the metadata registered**, matched exactly.
- **Assertions are always signed.** Encrypting them is per application.

## Doing it by hand

On iya-sts's console: **Protocols → SAML → SAML 2.0 IdP**, register the entityID, open it, paste `sp-metadata.xml` into **Its metadata** and press **Consume it**, then copy the **Metadata** URL and save that document where `idpMetadata` points. Turn on **Encrypt the assertion** on the application's **Configuration → SAML 2.0** tab. See [Configuring SAML 2.0](https://rcbj.github.io/iya-sts/configure-saml.html).

## Another identity provider

The library needs nothing iya-sts-specific. Give any SAML 2.0 identity provider `sp-metadata.xml`, and save its metadata where `idpMetadata` points (or set `idpMetadata` to its metadata URL, with `idpCa` if its TLS certificate chains to a private root).
