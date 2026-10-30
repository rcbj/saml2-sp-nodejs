---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
npm run build
```

The library's tests run with `node:test` on the TypeScript sources directly, against a stub identity provider (`packages/saml2-sp-nodejs/test/stub-idp.ts`) that writes and signs Responses with its own key, encrypts assertions, signs Redirect-binding query strings and runs an artifact resolution service that checks the signed `ArtifactResolve`. They cover:

- the configuration, the IdP metadata, and this service provider's metadata;
- the AuthnRequest on both bindings, with its signature verified independently;
- the Response on HTTP-POST: signed Response, signed assertion, neither, an altered assertion, another key, three signature-wrapping attacks, audience, recipient, expiry, destination, issuer, `InResponseTo`, unsolicited, replay, a non-success status, a DOCTYPE;
- encryption: AES-GCM and AES-CBC, RSA-OAEP with SHA-1 and SHA-256, an altered ciphertext, `EncryptedAttribute`, and `wantAssertionsEncrypted`;
- HTTP-Redirect: the query signature, another key, a changed RelayState;
- HTTP-Artifact: resolution on GET and POST, an artifact already used, an artifact from another identity provider;
- the setup script's plan, offline.

`npm run build` compiles `src/*.ts` to `dist/*.js` and `dist/*.d.ts` with TypeScript 7, strict.

Node.js 22.18 or later is required for the TypeScript sources to run as they are; the published package is JavaScript and runs on Node 22.12 or later.

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| `tests.yml` | every push and pull request | `npm test`, the build, the manifests check, then builds the demo image and checks its pages, headers and metadata |
| `npm-publish.yml` | pushes to `main` and `develop` that change the package | tests, stamps the version, packs and publishes to npm with provenance |
| `pages.yml` | pushes to `main` that change the docs or the source | builds this site and the TypeDoc reference |

## Branches

- **`develop`** is where work comes together: branch from it and merge back into it.
- **`main`** is what is released.

## Versions and releases

`M.N` is in the `VERSION` file; the patch number is worked out at build time from what is on npm (`scripts/version.mjs`). `main` publishes `M.N.P` under `latest`; `develop` publishes `M.N.P-next.R` under `next`. After bumping `VERSION`, run `npm run version:sync`.

## One-time setup on GitHub and npm

**GitHub Pages** (`pages.yml`). Pages must exist and build from GitHub Actions. Someone with admin rights on the repository does it once:

```sh
gh api -X POST repos/rcbj/saml2-sp-nodejs/pages -f build_type=workflow
```

or **Settings → Pages → Source: GitHub Actions**. The site is then published at <https://rcbj.github.io/saml2-sp-nodejs/>.

**npm** (`npm-publish.yml`). The package is published as [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs), with provenance.

1. Create the repository environment **`npm`** (**Settings → Environments**). Add required reviewers to it to hold every publish for approval.
2. For the **first** publish, add the repository secret **`NPM_TOKEN`**: an npm granular access token with publish rights. A trusted publisher can only be configured for a package that already exists.
3. After the first publish, configure **trusted publishing** on npmjs.com (the package's **Settings → Trusted publishing**): repository `rcbj/saml2-sp-nodejs`, workflow `npm-publish.yml`, environment `npm`. Then delete `NPM_TOKEN`.
