# saml2-sp-nodejs

A SAML 2.0 service provider for a traditional Node.js application, and a CAEP and RISC receiver. It sends a signed AuthnRequest, accepts the response on HTTP-POST, HTTP-Redirect, and HTTP-Artifact, validates the assertion strictly, and decrypts it when it is encrypted. It is TypeScript, usable from JavaScript. Runtime dependencies are `xml-crypto` and `@xmldom/xmldom`.

[wsfed-caep-nodejs](https://github.com/rcbj/wsfed-caep-nodejs) follows this layout, with WS-Federation in place of these HTTP bindings.

Documentation: <https://rcbj.github.io/saml2-sp-nodejs/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 22.18 or later. The package engines field says `>=22.18.0`. Continuous integration runs the suite on 22.18.0 and 24.22.1. The published JavaScript runs on Node 22.12 or later.

## Layout

| Path | What it is |
|---|---|
| `packages/saml2-sp-nodejs` | The library published to npm as `saml2-sp-nodejs`. Source is `src/` (`service-provider.ts`, `bindings.ts`, `response.ts`, `metadata.ts`, `signature.ts`, `encryption.ts`, `artifact.ts`, `ssf/`). Tests and the stub identity provider are `test/`. `npm run build` writes `dist/`. |
| `demo` | The server-rendered demo. `demo/server.ts` and `demo/public/`. Config is `demo/saml.json`. |
| `scripts` | `configure-iya-sts.ts`, the install script, registers the service provider on iya-sts and writes the listener CA trust chain to the file `idpCa` names. Metadata is posted for the entityID and assertion consumer URL that run registers. It is Node and runs inside the demo image, not with node or npm on the host. `live_iya_sts.py` is host Python: it signs the demo in to a fresh iya-sts and checks `GET /live-status`. `trust-chain.mjs` holds `saveTrustChain()`. `trust-chain.test.ts`: the chain is written whole to `idpCa`'s path, and the library reads metadata through it and still checks the host name. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc. It is outside the npm workspace. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

The root `package.json` is a private workspace. Committed manifests stay at `M.N.0` from the root `VERSION` file.

## Usage

```sh
npm install saml2-sp-nodejs
```

```ts
import { ServiceProvider, SamlError } from 'saml2-sp-nodejs';

const sp = await ServiceProvider.fromFile('saml.json');
const request = sp.login({ relayState: '/' });
// redirect binding: redirect to request.url
// POST binding: send request.html
const who = await sp.acs({ method: req.method, url: req.url, body }, { requestId });
```

Keep `request.id` with the browser until it returns. The package README and `packages/saml2-sp-nodejs/docs/guide.md` are the reference.

## Tests

```sh
npm ci
npm test
npm run build
npm run version:check
```

`npm test` runs `node:test` on the TypeScript sources in `packages/saml2-sp-nodejs/test` and on `scripts/*.test.ts`. The library tests use the stub identity provider in `test/stub-idp.ts`, which signs responses, encrypts assertions, and resolves artifacts. `version:check` fails unless every manifest is `M.N.0`.

The container unit suite is `docker build --target test .`. The test stage runs `npm test` and is a sibling of the demo stage, so `docker build .` and `docker compose build` do not run it.

`.github/workflows/tests.yml` also builds the demo image and checks that `/login` returns a signed Redirect AuthnRequest. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container. Do not change that workflow for the live sign-in.

`.github/workflows/nightly.yml` runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 06:11 UTC (`11 6 * * *`), and on `workflow_dispatch`. GitHub runs the schedule only from the default branch. The live script never binds host port 3000, 8081, or 18481 to 18495.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… SAML_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `saml-demo-user`. Unless `SAML_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/saml-demo-user.password` (created mode 0600) and prints only that path, never the password.

A loopback entityID and assertion consumer URL follow `PORT` in the running server and in `scripts/configure-iya-sts.ts`. The metadata posted to iya-sts is built from those rewritten values. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. A different port is a different entityID, so run `configure-iya-sts` again after changing `PORT`. The previous `:3000` registration stays on iya-sts. `pollIntervalMs` is a millisecond pause, not a port.

The shipped `demo/saml.json` has an `ssf` block, so the demo receives CAEP and RISC events. `"signals": false` turns that off: SAML sign-in is unchanged, the demo does not start `SignalsReceiver`, and `configure-iya-sts` does not register the SSF role or scope or require a transmitter. The default is on. `ServiceProvider` does not start a receiver; constructing `SignalsReceiver` opts in. Assertion encryption is left as the shipped file has it.

`GET /live-status` returns JSON and does not look at the browser cookie. `signedIn` is true when any local account session exists. `subject` is that session's NameID, or null. `receiver` is the receiver's state. `events` is the accepted events as `type` and `jti` only. No tokens. `session-revoked` ends the matching local session, so `signedIn` is false afterwards. The session index treats the assertion `SessionIndex` as the CAEP session id. When a `session-revoked` event names some other id, the receiver matches nobody; if this demo has one account session, the event handler ends it and logs that the SessionIndex is not the CAEP session id.

`scripts/live_iya_sts.py` is the live half. Host Python and Docker only. Configuring the client is `node scripts/configure-iya-sts.ts` inside the demo image (`SAML` image built from this Dockerfile). Do not run node or npm on the host for it. The script starts iya-sts from `IYA_STS_IMAGE`, or builds origin/main, in memory mode with persistence and clustering off and no request workers, unless `IYA_STS_URL` is already set. It does not stop a container it did not start, and it never removes `iya-sts-live-main`, `iya-sts-live-probe`, or a name that starts with `sts`. Its own containers are `iya-sts-live-saml2-sp-nodejs` and `saml2-sp-nodejs-live-demo`. It copies this checkout to a scratch build context, builds the demo image there, and runs the install script `node scripts/configure-iya-sts.ts` in it, which writes the key pair, the IdP metadata and the `idpCa` chain into the context's `demo/generated`. Then it builds the demo image again, checks it carries that chain (and nothing else from `demo/generated`), and runs it on `LIVE_DEMO_PORT` (default 18654) with host networking and only the key, the certificate and the IdP metadata mounted, one file each. It never rewrites `idpCa` or fetches the CA for the demo. iya-sts is published on `127.0.0.1:LIVE_STS_PORT` (default 18554). Use a fresh iya-sts for every run. Its Driver logs no request URL or status: CodeQL treats anything after the password POST as derived from the password. Secrets reach docker as `-e NAME`, never `-e NAME=value`. Every `ssl` context it makes has a TLS 1.2 minimum.

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/saml.json` names the iya-sts TLS listener CA trust chain the library trusts when it reads the identity provider's metadata over HTTPS, resolves an artifact, and calls the Shared Signals transmitter. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be the PEM itself. The library trusts every certificate in it, in addition to Node's own store, and still checks the host name against the listener certificate's subjectAltName.

`scripts/configure-iya-sts.ts`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer (`scripts/trust-chain.mjs`). It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts (a development iya-sts makes a new CA when it restarts). `.dockerignore` admits only that file from `demo/generated`; the key pair and both metadata documents stay out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The container does not refresh the chain at start. `node scripts/trust-chain.mjs --config demo/saml.json --idp https://localhost:8081` refreshes the file by hand. Compose mounts `demo/generated` (for the key, the certificate and the IdP metadata), which hides the image's copy behind the host's file.

**Plain http (#17).** `send()` in `packages/saml2-sp-nodejs/src/http.ts` is the one place every fetch goes through (metadata URL, `ArtifactResolve`, SSF configuration, JWKS, stream and poll). It refuses plain `http://` to a host that is not loopback (`127.0.0.0/8`, `[::1]`, `localhost`, by `isLoopbackHost()` on the WHATWG hostname) before any lookup or connection, keeping the fetch's `SamlError` code and naming only `http://host[:port]`; userinfo is never loopback. A URL holding whitespace (U+00A0 included) or a control character is refused first, before `new URL()` (`hasWhitespaceOrControl()`, #19): the WHATWG parser drops tabs and newlines and trims spaces, so it could otherwise dial a host a reader does not see. `node:http(s)` follows no redirect and nothing here follows a `Location`, so a 3xx is the answer. No opt-out. `test/plain-http.test.ts` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so its tripwire listener proves no connection is opened.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
