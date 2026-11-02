# saml2-sp-nodejs

A **SAML 2.0 service provider** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a demo app built on it. It signs every AuthnRequest, receives the Response on **HTTP-POST**, **HTTP-Artifact** or **HTTP-Redirect**, validates it strictly, and decrypts encrypted assertions. It depends on `xml-crypto` and `@xmldom/xmldom` only.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/saml2-sso.html)'s SAML 2.0 identity provider, and follows [`gnap-caep-js`](https://github.com/rcbj/gnap-caep-js)'s layout.

**Documentation:** <https://rcbj.github.io/saml2-sp-nodejs/>

| Path | |
|---|---|
| [`packages/saml2-sp-nodejs`](packages/saml2-sp-nodejs) | The library, published to npm as [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs). |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | Registers the demo on a running iya-sts from its metadata, and reads iya-sts's metadata back. Run it inside the demo image, not with node on the host. |
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

Open <http://localhost:3000> and sign in as `saml-demo-user`. See [Running the demo](docs/demo.md) and [Setting up iya-sts](docs/configure.md).

## Develop

```sh
npm install
npm test
npm run build
```

Branch from `develop`. See [Development and releases](docs/development.md).

The container unit suite is `docker build --target test .`. That stage is not the demo image, so `docker build .` does not run it. Push and pull-request CI stays [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

## Live sign-in

[`scripts/live_iya_sts.py`](scripts/live_iya_sts.py) uses the host's Python and Docker. It starts a fresh iya-sts in memory mode unless `IYA_STS_URL` is already set, registers the demo by running `node scripts/configure-iya-sts.ts` inside the demo image, signs in, and requires `GET /live-status` to show a credential-change while signed in and then a session-revoked with `signedIn` false. Do not run node or npm on the host for that registration. Do not bind host ports 3000 or 8081. Assertion encryption is left as `demo/saml.json` has it.

`GET /live-status` is JSON: `signedIn` (true when any local account session exists), `subject`, `receiver`, and `events` of `type` and `jti` only. No tokens. If the assertion `SessionIndex` is not the CAEP session id, the event handler ends this demo's one session and says so.

[`.github/workflows/nightly.yml`](.github/workflows/nightly.yml) runs `docker build --target test .` and then `python3 scripts/live_iya_sts.py` at 06:11 UTC, and on `workflow_dispatch`.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
