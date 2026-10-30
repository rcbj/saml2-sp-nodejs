# Adding SAML 2.0 sign-in to a server-side web application

This walks through what a traditional, server-rendered application needs: the keys and metadata, the two routes, the cookie that carries the request id, and the session. The [demo](../../../demo/server.ts) is all of it in one file with `node:http`; the same steps in Express are below.

## 1. A key pair, and the configuration

```sh
npx saml2-sp-nodejs generate-keys --config saml.json
```

```json
{
  "entityId": "https://app.example.com/saml/metadata",
  "acsUrl": "https://app.example.com/saml/acs",
  "privateKey": "keys/sp.key",
  "certificate": "keys/sp.crt",
  "idpMetadata": "keys/idp-metadata.xml",
  "wantAssertionsEncrypted": true
}
```

Keep the private key out of the image and out of version control: mount it, or read it from your secret store and pass the PEM in `privateKey`.

## 2. Exchange metadata with the identity provider

```sh
npx saml2-sp-nodejs metadata --config saml.json --out sp-metadata.xml
```

Give `sp-metadata.xml` to the identity provider. It registers the assertion consumer service on all three bindings, the signing and encryption key, and `AuthnRequestsSigned="true"`. Save the identity provider's metadata where `idpMetadata` points, or point `idpMetadata` at its URL. For iya-sts, [`scripts/configure-iya-sts.ts`](../../../scripts/configure-iya-sts.ts) does both through its management API.

## 3. The login route

```ts
import express from 'express';
import { ServiceProvider } from 'saml2-sp-nodejs';

const sp = await ServiceProvider.fromFile('saml.json');
const app = express();

app.get('/login', (req, res) => {
  const request = sp.login({ relayState: '/' });
  // The request id goes with THIS browser, so the Response can be matched to it. SameSite=None:
  // the HTTP-POST binding brings the browser back with a cross-site POST, which drops a Lax cookie.
  res.cookie('saml_pending', sign(request.id), {
    httpOnly: true, secure: true, sameSite: 'none', path: '/saml/acs', maxAge: 600_000,
  });
  if (request.binding === 'redirect') return res.redirect(request.url);
  res.type('html').send(request.html);
});
```

`sign()` is your application's cookie signing (`cookie-parser` with a secret, or an HMAC). The id is not a secret, but a cookie the browser could replace would let it choose which request a Response answers.

## 4. The assertion consumer service

```ts
app.post('/saml/acs', express.urlencoded({ extended: false, limit: '512kb' }), acs);
app.get('/saml/acs', acs);   // HTTP-Artifact (and HTTP-Redirect)

async function acs(req, res) {
  try {
    const who = await sp.acs(
      { method: req.method, url: req.originalUrl, body: req.body },
      { requestId: unsign(req.cookies.saml_pending) },
    );
    res.clearCookie('saml_pending', { path: '/saml/acs' });
    req.session.regenerate(() => {          // a new session id at sign-in
      req.session.user = { nameId: who.nameId, attributes: who.attributes, sessionIndex: who.sessionIndex };
      res.redirect(303, safeLocal(who.relayState) ?? '/');
    });
  } catch (err) {
    console.warn('SAML sign-in refused', err.code, err.message);
    res.status(400).send('Sign-in failed.');
  }
}
```

- **Pass `req.originalUrl`**, the URL as received: the HTTP-Redirect binding's signature is over the query string exactly as it arrived.
- **`relayState` came through the browser.** Only follow it to a path on your own site (`safeLocal`), never to an absolute URL.
- **Regenerate the session** at sign-in, and set its lifetime no longer than `who.sessionNotOnOrAfter`.

## 5. Metadata at the entityID

```ts
app.get('/saml/metadata', (req, res) => res.type('application/samlmetadata+xml').send(sp.metadata()));
```

## 6. Signed out by the identity provider: Shared Signals

A session at the application outlives a sign-out at the identity provider unless something tells it. `SignalsReceiver` is that something: it receives the identity provider's CAEP and RISC events and ends the matching sessions (see the [reference](../README.md#shared-signals-caep-and-risc)).

```ts
const signals = new SignalsReceiver({
  transmitter: 'https://idp.example.com',
  tls: { ca: sp.config.idpCa, cert: sp.config.certificate.toString(),
         key: sp.config.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string },
  onEndSessions: (ids) => ids.forEach((id) => req.sessionStore.destroy(id, () => {})),
});
await signals.start();
```

React to each event type with your own handler, `signals.on(EVENT.credentialChange, …)`: [Handling CAEP and RISC events](signals.md) has one for every CAEP and RISC type.

In the ACS, after `req.session.regenerate()`, call `await signals.track(req.sessionID, who)`; at sign-out, `await signals.untrack(req.sessionID)`. Ending the session in the store is what matters: the browser's next request finds no session. Telling an open tab at once (Server-Sent Events, a WebSocket) is a courtesy on top; the demo does it.

## 7. Several people in one browser

The library is per sign-in, so several people in one browser is the application's session design. A pattern that fits a server-rendered application, and that the [demo](../../../demo/server.ts) implements:

- **One cookie names an account set** held on the server: the people signed in to this browser, each with their own session.
- **The URL says which person a tab is for**, as a stable per-account id (`/u/<account>/…`), not a position. A cookie is shared by every tab, so it can't say that.
- **Adding a person:** `sp.login({ forceAuthn: true })`, so the identity provider authenticates someone instead of signing the current person in again.
- **Signing a known person in again:** `sp.login({ forceAuthn: true, subjectHint: who.nameId, subjectHintFormat: who.nameIdFormat })`. The hint becomes the AuthnRequest's `<saml:Subject>`, which tells an identity provider holding several accounts which one to use.

The trap: **the ACS cannot read a `SameSite=Lax` cookie when the Response arrives by HTTP-POST.** It's a cross-site POST, so the browser leaves such cookies off. Note the account set in the cookie that carries the request id: it's scoped to the ACS, `SameSite=None` and signed. Otherwise every POST-binding sign-in starts a new set and the browser forgets everyone else.

The identity provider must also let one browser hold several sessions. Otherwise a second sign-in ends the first person's IdP session, and its CAEP `session-revoked` then ends their session here too.

## 8. Several processes

The replay cache remembers accepted assertion IDs in one process's memory, and the Shared Signals session index likewise. Behind a load balancer, give every process one shared replay cache (and one shared `sessionIndex`, with the receiver running in a single process): anything with an atomic set-if-absent and an expiry.

```ts
const sp = await ServiceProvider.fromFile('saml.json', {}, {
  replayCache: {
    async checkAndRecord(id, expiresAt) {
      const ok = await redis.set(`saml:${id}`, '1', { NX: true, PXAT: expiresAt.getTime() });
      return ok === null;   // true = seen before
    },
  },
});
```

## 9. Key rollover

Generate a new pair (`generate-keys --force`), publish the new metadata to the identity provider, then restart. For the identity provider's own rollover, call `sp.refreshMetadata()` (or restart) after its metadata changes.
