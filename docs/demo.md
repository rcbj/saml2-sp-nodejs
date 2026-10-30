---
title: Running the demo
---

# Running the demo

The demo is a traditional server-rendered web application, [`demo/server.ts`](https://github.com/rcbj/saml2-sp-nodejs/blob/main/demo/server.ts): `node:http`, no framework, run by Node as TypeScript. It signs people in with SP-initiated SAML 2.0 single sign-on through `saml2-sp-nodejs`, against iya-sts.

## 1. Set it up on iya-sts

```sh
npm install
ADMIN_API_CLIENT_SECRET=… SAML_DEMO_USER_PASSWORD=… npm run configure-iya-sts
```

This makes the key pair and both metadata documents in `demo/generated/` and registers the application. See [Setting up iya-sts](configure.md).

## 2. Start it

```sh
docker compose up --build
```

Open <http://localhost:3000> and pick a response binding:

- **HTTP-POST** (the default): iya-sts posts the signed Response, with the assertion encrypted, back through the browser.
- **HTTP-Artifact**: the browser brings back only a reference. The demo's server resolves it with a signed `ArtifactResolve` to iya-sts's artifact resolution service.
- **HTTP-Redirect**: the Response in the query string. The SAML Web SSO profile forbids this for a Response because a signed one rarely fits in a URL. With encryption on, iya-sts's Response is about 20 KB and does not reach the browser. It is there to show that.

The AuthnRequest goes on HTTP-Redirect (`requestBinding` in `demo/saml.json`), signed. Sign in as `saml-demo-user`. The page shows the NameID, the binding, the session index, whether the assertion arrived encrypted, and every attribute iya-sts released.

## Shared Signals: signed out by the identity provider

`demo/saml.json`'s `ssf` block makes the demo a CAEP and RISC receiver. It keeps one poll stream at iya-sts, polls it every three seconds, and authenticates with mutual TLS using the SP's own key pair.

Once you're signed in, the page has two tabs. **Identity** shows what the SAML assertion said. **CAEP & RISC events** shows two things:

- **The Shared Signals stream:** the receiver's state, the stream and its poll endpoint, how it authenticates, every event type it delivers (marked CAEP or RISC), and which of them end the session. A **Request verification event** button asks iya-sts to send the stream's verification event.
- **The event log:** every CAEP and RISC event about this session or its person, plus the verification events this session asked for, newest first. Each entry shows its family, what the demo did ("ended this session", or "recorded; this session continues"), the subject (the person's `urn:uuid:` subject, the IdP session), every member the event carried (`initiating_entity`, `reason_admin`, `credential_type`, …) and its `jti`.

### Events reach the browser within seconds, and only the right browser

The page doesn't reload. Each event is drawn as it arrives: an entry in the log on the events tab, a count on the tab's label, and a notice on the Identity tab. On 8081 an event typically shows within about 3–4 seconds of the change at iya-sts: up to one poll interval (3 s), plus delivery.

- **`GET /events`** is a Server-Sent Events stream. The server sends each event to the session's open tabs as JSON as soon as the receiver has it. Each event carries an `id`; a tab that reconnects (the browser does that by itself) is replayed what it missed.
- **`GET /api/signals?after=<id>`** returns the same events as JSON. The page polls it every 3 seconds if the event stream can't be kept open. A 401 means the session has ended.
- **Isolation:** both read only the requesting session's own log. A session's log holds only the events the receiver matched to that session or its person (by the IdP session or the `urn:uuid:` subject), so one person never receives another person's events. A `verification` event goes only to the session that asked for it, matched by the `state` value the request carried. `stream-updated` changes the stream's status shown on the card, which names nobody.
- **Rendering:** everything an event carries comes from the identity provider, so the page draws it as text, never as HTML. The page's Content-Security-Policy allows only its own script (`/app.js`) and connections back to its own origin.

Verified with two people signed in, in two browsers: a password change for one shows only on that person's page and in their `/api/signals`. A verification request reaches only the page that made it, and ending one person's session at iya-sts signs out only their tab.

Sign in, then do one of these at iya-sts and watch the demo's tab:

- **Sign out** of iya-sts, or end the session on **Monitoring → Sessions**: CAEP `session-revoked` names that IdP session, and the demo session started from it ends.
- **Disable** the user on their **Directory → Users** page: RISC `account-disabled` ends every demo session of that person.
- **Change the user's password**: CAEP `credential-change` is listed on the page, and ends nothing (`endOn` decides which events end sessions).

**Needs iya-sts with #1227 and #1230** (develop 02de0743f or later): #1227 lets an application hold a stored certificate, and #1230 keeps it there when iya-sts writes the application entry (a stream created, a sign-in recorded).

When a session ends, its open tab is told at once over Server-Sent Events (`/events`, read by the static `/app.js`) and goes back to the sign-in page. The session itself is already gone on the server, so a closed tab finds it gone on the next request.

## The container

`demo/generated/` is mounted read-only at `/app/demo/generated`: the key, the certificate, both metadata documents and iya-sts's TLS root. None of them is in the image.

The container uses the **host's network**, so that `https://localhost:8081`, which the demo's server dials to resolve an artifact, is the same address inside it as in the browser. On Docker Desktop, turn on host networking (**Settings → Resources → Network**).

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | The port the demo listens on. It must match `acsUrl` and `entityId` in `demo/saml.json`. |
| `SAML_CONFIG` | `demo/saml.json` | Another configuration file. |
| `SESSION_SECRET` | random per start | Signs the pending-request cookie. Set it to keep sign-ins in flight across a restart. |

To run it without a container: `npm run build && npm start`.

## How it handles the browser

- **`/events` and `/api/signals`** answer only for the session in the `sid` cookie (see above).
- **`saml_pending`** holds the outstanding AuthnRequest ids (the last three, so two tabs can sign in at once), HMAC-signed, scoped to `/saml/acs`, for ten minutes. It is `SameSite=None; Secure`, because the HTTP-POST binding brings the browser back with a **cross-site POST**, on which a `Lax` cookie is not sent. Browsers treat `http://localhost` as secure, so this works locally. A deployment needs HTTPS.
- **`sid`** is the session, `SameSite=Lax; HttpOnly`, set after the Response is accepted, and ending no later than the identity provider's `SessionNotOnOrAfter`.
- The pages send a strict Content-Security-Policy. The POST-binding page is the one with a script, the auto-submit, allowed by a per-request nonce, and its `form-action` names only the identity provider. It also has a real submit button.
- A refused sign-in shows the `SamlError` code and message. That is for the demo: a production application logs it and tells the person only that sign-in failed.
