# saml2-sp-nodejs

A **SAML 2.0 service provider** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a demo app built on it. It signs every AuthnRequest, receives the Response on **HTTP-POST**, **HTTP-Artifact** or **HTTP-Redirect**, validates it strictly, and decrypts encrypted assertions. It depends on `xml-crypto` and `@xmldom/xmldom` only.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/saml2-sso.html)'s SAML 2.0 identity provider, and follows [`gnap-caep-js`](https://github.com/rcbj/gnap-caep-js)'s layout.

**Documentation:** <https://rcbj.github.io/saml2-sp-nodejs/>

| Path | |
|---|---|
| [`packages/saml2-sp-nodejs`](packages/saml2-sp-nodejs) | The library, published to npm as [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs). |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | The install script. Registers the demo on a running iya-sts from its metadata, writes the iya-sts listener CA trust chain to the file `idpCa` names, and reads iya-sts's metadata back. Run it inside the demo image, not with node on the host. |
| [`scripts/live_iya_sts.py`](scripts/live_iya_sts.py) | Host Python. Signs the demo in to a fresh iya-sts and checks `GET /live-status`. |

## Install

```sh
npm install saml2-sp-nodejs
```

See the [package README](packages/saml2-sp-nodejs/README.md) for the reference and the [server-side guide](packages/saml2-sp-nodejs/docs/guide.md) for a walkthrough.

## Run the demo

```sh
npm install
npm run generate-keys                  # the SP's signing and encryption key pair
npm run generate-metadata              # demo/generated/sp-metadata.xml, for the identity provider
ADMIN_API_CLIENT_SECRET=… SAML_DEMO_USER_PASSWORD=… npm run configure-iya-sts   # both of the above, then register on iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `saml-demo-user`. Unless `SAML_DEMO_USER_PASSWORD` sets its password, iya-sts generates one, and the install script writes it to `demo/generated/saml-demo-user.password` (created mode 0600) and prints only that path, never the password. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## Develop

```sh
npm install
npm test
npm run build
```

Branch from `develop`. See [Development and releases](docs/development.md).

The container unit suite is `docker build --target test .`. That stage is not the demo image, so `docker build .` does not run it. Push and pull-request CI stays [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## The iya-sts trust chain (`idpCa`)

`idpCa` in `demo/saml.json` names the iya-sts TLS listener CA trust chain the library trusts when it reads the identity provider's metadata over HTTPS, resolves an artifact, and calls the Shared Signals transmitter. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be the PEM itself. The library trusts every certificate in it, in addition to Node's own store, and still checks the host name against the listener certificate's subjectAltName.

`scripts/configure-iya-sts.ts`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer (`scripts/trust-chain.mjs`). When the file already holds a chain, the fetch is verified against it; only when that chain cannot verify the server (no file yet, or a new CA) is the chain taken on first use, after checking that the leaf names the host and is the one the handshake presented, and that each certificate is signed by the next. It prints whether it verified, the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts (a development iya-sts makes a new CA when it restarts). `.dockerignore` admits only that file from `demo/generated`; the key pair and both metadata documents stay out of the image. A build with no chain file yet (a fresh clone, CI's `--target test`) still succeeds; the image then has no `idpCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing path and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both. The container does not refresh the chain at start. `node scripts/trust-chain.mjs --config demo/saml.json --idp https://localhost:8081` refreshes the file by hand. Compose mounts `demo/generated` (for the key, the certificate and the IdP metadata), which hides the image's copy behind the host's file.

**Plain http (#17).** Identity-provider metadata from a URL, artifact resolution and every Shared Signals transmitter call (configuration, stream and poll) use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys, an `ArtifactResolve` returns the assertion, and Shared Signals carry SETs and the bearer token. A URL with userinfo is never loopback, and a URL holding whitespace or a control character is refused outright, so no two parsers can disagree about its host. Node's `https.request` follows no redirect, so there is no second hop to check. The `SamlError` keeps the fetch's code (`metadata`, `artifact`, `ssf`) and names the scheme and host only. There is no opt-out. The service provider's own entityID and ACS URL may stay http; they are never fetched.

## Live sign-in

[`scripts/live_iya_sts.py`](scripts/live_iya_sts.py) uses the host's Python and Docker. It starts a fresh iya-sts in memory mode unless `IYA_STS_URL` is already set, (`IYA_STS_IMAGE` names an iya-sts image to start instead of building `main`). It copies this checkout to a scratch build context, builds the demo image there and runs the install script `node scripts/configure-iya-sts.ts` inside it, which writes the key pair, the IdP metadata and the `idpCa` chain into the context's `demo/generated`. Then it builds the demo image again, checks the image carries the chain and nothing else from `demo/generated`, and starts it with only the key, the certificate and the IdP metadata mounted, one file each. It never rewrites `idpCa` or fetches the CA for the demo. `LIVE_STS_PORT` (default 18554) and `LIVE_DEMO_PORT` (default 18654) choose the ports. It signs in, and requires `GET /live-status` to show a credential-change while signed in and then a session-revoked with `signedIn` false. Do not run node or npm on the host for that registration. It never binds host port 3000, 8081, or 18481 to 18495. Assertion encryption is left as `demo/saml.json` has it.

`GET /live-status` is JSON: `signedIn` (true when any local account session exists), `subject`, `receiver`, and `events` of `type` and `jti` only. No tokens. If the assertion `SessionIndex` is not the CAEP session id, the event handler ends this demo's one session and says so.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 06:11 UTC, and on `workflow_dispatch`.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
