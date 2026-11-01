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
| `scripts` | `configure-iya-sts.ts` registers the service provider on iya-sts. Metadata is posted for the entityID and assertion consumer URL that run registers. `redirects.mjs` rewrites a loopback URL onto `PORT`. `version.mjs` stamps the published version. |
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

`.github/workflows/tests.yml` also builds the demo image and checks that `/login` returns a signed Redirect AuthnRequest. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… SAML_DEMO_USER_PASSWORD=… npm run configure-iya-sts
docker compose up --build
```

Open <http://localhost:3000> and sign in as `saml-demo-user`.

A loopback entityID and assertion consumer URL follow `PORT` in the running server and in `scripts/configure-iya-sts.ts`. The metadata posted to iya-sts is built from those rewritten values. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. A different port is a different entityID, so run `configure-iya-sts` again after changing `PORT`. The previous `:3000` registration stays on iya-sts. `pollIntervalMs` is a millisecond pause, not a port.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
