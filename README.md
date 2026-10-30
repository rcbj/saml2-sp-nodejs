# saml2-sp-nodejs

A **SAML 2.0 service provider** for server-side Node.js applications, written in TypeScript and usable from JavaScript, and a demo app built on it. It signs every AuthnRequest, receives the Response on **HTTP-POST**, **HTTP-Artifact** or **HTTP-Redirect**, validates it strictly, and decrypts encrypted assertions. It depends on `xml-crypto` and `@xmldom/xmldom` only.

It is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/saml2-sso.html)'s SAML 2.0 identity provider, and follows [`gnap-caep-js`](https://github.com/rcbj/gnap-caep-js)'s layout.

**Documentation:** <https://rcbj.github.io/saml2-sp-nodejs/>

| Path | |
|---|---|
| [`packages/saml2-sp-nodejs`](packages/saml2-sp-nodejs) | The library, published to npm as [`saml2-sp-nodejs`](https://www.npmjs.com/package/saml2-sp-nodejs). |
| [`demo`](demo) | A traditional server-rendered web application, run in one container. |
| [`scripts/configure-iya-sts.ts`](scripts/configure-iya-sts.ts) | Registers the demo on a running iya-sts from its metadata, and reads iya-sts's metadata back. |

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

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
