# BloomConnect License Generator

A static, mobile-first owner tool: **Device ID → authorize → generate → copy / WhatsApp**. License duration is fixed at **365 days**. No customer accounts, database, paid API, signing server, or laptop kept running.

## Run and deploy

Node.js 22.14 or newer (Node 24 LTS recommended):

```sh
npm ci
npm test
npm run build
npm run dev
```

Cloudflare Pages: build `npm run build`, output `dist`. No secrets or environment variables are required. Use HTTPS (or localhost for development). See [deployment instructions](docs/DEPLOYMENT.md).

## One-time owner setup

1. Open the final HTTPS website. With an empty vault, **Create New Signing Key** is selected. Enter and confirm a strong passphrase, then choose **Create and save key**.
2. Choose **Download encrypted backup**, **Download public-key.json**, and **Download Desktop Integration Package** from **Owner setup**. Keep the .bloomkey.json file and its passphrase safe. The public JWK and integration ZIP can go to the Desktop maintainer.
3. To move an existing key to another browser, use **Restore Existing Signing Key**, select the backup and enter its original passphrase.
4. Optionally enable device unlock using a PRF-capable passkey. If it is unavailable, use the passphrase to authorize signing.
5. Return to the generator. The encrypted vault persists on this browser and origin.

## Daily use

1. Paste the desktop app's exact **Device ID**.
2. Tap **Generate License Key**.
3. Approve device verification if PRF unlock is enabled. Otherwise enter your original owner passphrase in the one-field inline prompt and tap Generate again. A passphrase fallback is also available explicitly if a configured passkey is unavailable.
4. The signed license appears directly on the same screen, with large **Copy License** and **Share via WhatsApp** buttons.

Every license needs fresh authorization. No unlocked signing session is retained. Changing the Device ID or starting another request clears the previous result. Wrong passwords, cancelled passkeys, missing PRF output, invalid assertions, and decryption failures produce no license.

The signed payload retains all BC1 fields and adds the signed signing-key ID (kid). With the customer form removed, `customer` is the nonblank string `BloomConnect` and `phone` is empty. Product remains exactly `BloomConnect`; timestamps are UTC milliseconds. Issue time is 00:00 UTC today, expiry is exactly 365 × 86,400,000 milliseconds later. Device matching stays case-sensitive, trimming only leading/trailing whitespace as before.

## Encrypted local vault

- Original backup: unchanged PBKDF2-HMAC-SHA-256 (600,000 iterations), random 256-bit salt, AES-256-GCM, random 96-bit IV and 128-bit tag, encrypted PKCS#8.
- Optional device envelope: WebAuthn PRF produces a credential-bound 256-bit secret. HKDF-SHA-256 derives a non-extractable AES-256-GCM wrapping key using a random salt and the context `BloomConnect-owner-passkey/v1`. That context is also AES-GCM additional authenticated data. A fresh random 96-bit IV encrypts the **same** private key.
- LocalStorage contains only encrypted key material and public metadata (JWK, fingerprint, credential ID, authenticator public SPKI, salts, IVs, RP ID). No plaintext private key, passphrase, PRF output, unwrapped signing key, or wrapping key is persisted. Unexpected fields in imported backup JSON are stripped before saving.
- Every device unlock uses a fresh random challenge and requires WebAuthn user verification. The app validates the challenge, origin, RP ID hash, credential ID, user-presence/user-verification flags, and authenticator signature before using PRF output to decrypt.
- An ordinary biometric prompt is never used to gate an unencrypted locally saved key. The PRF secret is required cryptographically. Missing support never silently downgrades to unprotected signing.
- Working signing keys are imported non-extractable, held in a single request, and never assigned to React state or a reusable session. Temporary PKCS#8/PRF buffers are cleared. JavaScript cannot guarantee immediate erasure of garbage-collected memory.
- There is no public signing endpoint. Anyone can view the static source, but cannot sign with your identity without the encrypted key plus its passphrase or usable passkey.

Keep the original encrypted backup and passphrase separately and safely. Device setup is not a replacement for backup. Clearing browser/site data removes local setup. A moved domain or another phone requires importing the same backup again; passkey setup is scoped to the website origin. Passkeys may synchronize through the platform's provider; that does **not** synchronize this app's local encrypted vault or history. Browser private mode and restrictive storage settings may prevent persistence.

Only open trusted deployments. A compromised hosting/GitHub account, malicious same-origin code, or a compromised browser can capture secrets during owner authorization. Protect deployment access. Offline desktop checks still depend on a trustworthy local clock and stable device ID; this app adds no online revocation.

The WebAuthn design follows the [MDN PRF extension documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions) and [W3C PRF explainer](https://github.com/w3c/webauthn/blob/main/explainers/prf-extension.md). Passkey/PRF support varies across browsers and authenticators, so physical phone testing remains necessary.

## History

A small footer link opens session history, with search, verified record import, export, and license download. History clears on refresh/close; export before leaving. Saved records include customer/device information. Maximum imported file: 4 MB, 500 records. Encrypted owner setup persists independently. There is no automatic synchronization between phones.

## Desktop integration

The BC1 signing algorithm and wire encoding are unchanged. Current licenses add kid, which is checked against the trusted public key. Earlier BC1 licenses can still be verified against pinned keys.

Download the integration ZIP from **Owner setup**. It includes the production public key, the wire specification and integration guide, and examples signed by a disposable test key. Add the production JWK to the array in the separate Desktop project's packages/licensing/website-public-keys.json and rebuild Desktop. Preserve older trusted public keys for licenses still in use. Verify a license for the actual Desktop Device ID before distributing the updated installer. See [Desktop verification](docs/DESKTOP.md).

## Tests

```sh
npm test
npm run test:ui
npm run build
```

`npm test`: Node's built-in runner, original crypto suite plus encrypted vault/authorization tests. `npm run test:ui`: Playwright with installed Google Chrome, desktop and phone-sized viewports, including actual Chrome virtual authenticator PRF support. Tests use disposable in-memory keys, not the owner's production private key. Test artifacts are ignored by Git and are never part of the Pages upload.

## Project layout

- `src/App.tsx`: device-only main screen, separate one-time setup, session history.
- `src/vault.ts`: encrypted local persistence, key identity checks, WebAuthn/PRF protection.
- `shared/license.ts`: BC1 signing, verification, key IDs, and backup helpers.
- `desktop/verify-license.mjs`: native Node/Electron verifier.
- `tests/`: crypto, vault, desktop compatibility, and browser workflows.
- `public/_headers`: Cloudflare security headers.
- `docs/`: deployment, desktop integration, and test results.