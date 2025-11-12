# Tauri Plugin: p256-signer

Sign messages from a Tauri app using platform passkeys (WebAuthn). This plugin exposes a small JS API
that serializes WebAuthn requests to be handled by the native layer and returns a parsed
PublicKeyCredential which can be used to build viem/web3-style accounts (for example a webauthn-p256
owner for account abstraction / 4337 flows).

This repository contains:

- Rust plugin code for Tauri (the native implementation).
- JS bindings (lightweight helpers) in `guest-js/` and a distributable bundle in `dist-js/`.

Key notes

- The plugin does not bypass the platform security model: you must configure the consuming Android/iOS
 application to allow WebAuthn/passkey use. On Android this normally means adding an assetlinks JSON
 entry hosted at your domain and verifying your package name / signing certificate. On iOS you need
 properly configured Associated Domains and, where relevant, App Clip/entitlements.

Use this plugin when you want to let a Tauri desktop/mobile app create and use WebAuthn passkeys
and surface the resulting signatures/public keys to a JS layer (for example to construct viem accounts).

## Quick install

This project publishes JS bindings as the package `@metasig/tauri-plugin-p256-signer-api` (see
`package.json`). To use the JS helpers in your Tauri app, install the package (npm / pnpm / yarn):

```bash
# from your app's frontend
pnpm add @metasig/tauri-plugin-p256-signer-api
```

The native plugin is a standard Tauri plugin. Include it in your Tauri Rust plugin list and enable
the plugin during build. See "Build & develop" below for local build instructions.

## Usage (JS example)

The JS bindings expose two high-level helpers: `createCredential` and `getCredential`.
They serialize WebAuthn options into a JSON-friendly form, invoke the native plugin and return
a parsed `PublicKeyCredential` object that behaves like the browser API.

Example (browser/guest code):

```ts
import { createCredential, getCredential } from '@metasig/tauri-plugin-p256-signer-api';

// Create a credential from PublicKeyCredentialCreationOptions
const created = await createCredential(creationOptions);

// Request an assertion
const asserted = await getCredential({ publicKey: requestOptions });

// Use asserted.response.signature and asserted.rawId in your app (for example to register a
// viem webauthn-p256 account or to verify a signature server-side).
```

For more advanced usage and the exact serialization/parsing behavior, see `guest-js/index.ts` in
this repository.

## Build & develop

From the repository root you can build both the JS bundle and the Rust plugin.

- Build JS bundle:

```bash
pnpm build
```

- Build Rust plugin (requires Rust >= 1.77.2):

```bash
cargo build --release
```

## License

This repository is licensed under Apache-2.0 (see `package.json`).
