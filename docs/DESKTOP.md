# BloomConnect Desktop verification and migration

## Configure BloomConnect Desktop

Download the ZIP from **Owner setup** and add its production public JWK from public-key.json to the Desktop project's packages/licensing/website-public-keys.json array. Preserve existing trusted entries for earlier licenses. Run npm run installer in the Desktop checkout and test activation with a license issued for the Device ID shown by that build.

The example and vectors in the package use a separate fixture key and historical dates. The production public key is the trust anchor for licenses issued from your owner vault.

## TypeScript / Web Crypto desktop

Copy `shared/license.ts` into your desktop source or consume it from a shared local package. Embed the **public** JSON exported by the owner. Do not load a replacement public key from a customer-editable file or license input.

```ts
import { importPublicKey, verifyLicense } from './shared/license';
import embeddedPublicJwk from './BloomConnect-public-key.json';

const verificationKey = await importPublicKey(embeddedPublicJwk);
// Obtain this from your existing stable device-ID implementation.
const localDeviceId = getBloomConnectDeviceId();
try {
  const entitlement = await verifyLicense(
    pastedLicense.trim(), verificationKey, localDeviceId, Date.now()
  );
  enableBloomConnect(entitlement.expires);
} catch {
  disableProtectedFeatures();
  showLicenseRequired();
}
```

The application functions in the example are integration points, not included application APIs. Enforce verification at startup and periodically while running, including at expiry. Saving an earlier “valid=true” result must not bypass a fresh check. Keep protected operation checks in a trusted process, not only a UI toggle.

## Node / Electron main process

Use the independent native-crypto verifier in `desktop/verify-license.mjs`:

```js
import { verifyDesktopLicense } from './desktop/verify-license.mjs';
// Bundle this exported JWK as application-owned, immutable configuration.
const embeddedPublicJwk = { kty: 'EC', crv: 'P-256', x: 'YOUR_X', y: 'YOUR_Y' };

function checkActivation(licenseText, localDeviceId) {
  return verifyDesktopLicense(licenseText.trim(), embeddedPublicJwk, localDeviceId);
}
```

Replace the placeholder with your real exported public key before use. Never include an encrypted backup, passphrase, `d` coordinate, PKCS#8 key, or any private signing material in an installer. Do not expose signing functionality through Electron IPC. A customer may submit a license; they must not supply the authoritative device ID or verification key.

Run `npm test` to check native Node verification of Web Crypto signatures and the reverse direction. Add application-level tests using your actual device-ID provider, installer, OS clock behavior, and protected features.

## BC1 wire format

```text
BC1.<base64url(UTF-8 JSON payload)>.<base64url(signature)>
```

Base64url has no padding. Verify the exact ASCII bytes `BC1.<payload-segment>`; do **not** deserialize and reserialize before signature verification. ECDSA signatures are 64-byte IEEE P1363, `r[32] || s[32]`, SHA-256, NIST P-256 / secp256r1. Many libraries default to DER signatures: explicitly choose P1363 or convert safely. JSON uses these fields:

| Field | Meaning |
| --- | --- |
| `v` | Integer `1` |
| `id` | 16 random bytes, 22-character base64url |
| `customer` | Nonblank customer name, at most 160 UTF-16 code units |
| `phone` | Optional phone represented by a string; empty if absent, at most 50 code units |
| `device` | Trimmed, nonblank device ID, at most 256 code units |
| `product` | Exact string `BloomConnect` |
| `issued` | UTC Unix timestamp in **milliseconds**, inclusive |
| `expires` | UTC Unix timestamp in **milliseconds**, exclusive |
| `kid` | Base64url SHA-256 of UTF-8 compact JSON containing crv, kty, x, y in that order. Checked against the trusted signing key. May be absent on older BC1 licenses. |

The issue date is midnight UTC. Expiry is issue time + days × 86,400,000, independent of local daylight-saving changes. Reject `now < issued` and `now >= expires`. Device IDs are compared case-sensitively after trimming leading/trailing whitespace from the locally obtained ID. Do not invent a new hardware-ID scheme if the app already has one; copy its display value exactly into the generator.

Validate types, product, version, lengths, timestamp ranges, signature encoding, and integer timestamps. Reject malformed payloads, invalid signatures, the wrong device, and expired/not-yet-active licenses. Cap license input at 8,192 characters. Do not automatically infer entitlements from an unverified decoded payload.

For .NET, the equivalent core API is `ECDsa.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)`, importing JWK `x` and `y` into `ECParameters` with `ECCurve.NamedCurves.nistP256`. Use Unix milliseconds and all the same validation rules. BloomConnect Desktop uses the Node/Electron verification path.

## Backup format (owner tool only)

The JSON contains `format=BloomConnect-encrypted-key`, `version=1`, `kdf=PBKDF2-SHA256`, `iterations=600000`, base64url `salt`, `cipher=AES-256-GCM`, base64url `iv`, and base64url `ciphertext` (Web Crypto ciphertext with the 16-byte tag appended). Password UTF-8 bytes are used as entered; do not trim or Unicode-normalize them. AES-GCM additional authenticated data is the UTF-8 string `BloomConnect-encrypted-key/v1`. Plaintext is PKCS#8 DER. This format is for the owner website, never the desktop customer flow.

## Preserve existing licenses

1. Inventory the current desktop format, algorithm, device-ID provider, expiry behavior, and key storage. Back up source and existing verification tests. Do not assume BC1 works in existing releases.
2. Preserve the existing verifier. Add an explicitly routed BC1 verifier with the new embedded public key. If a token starts with `BC1.`, verify it only with the BC1 verifier; failure must not fall through to a weaker legacy path.
3. Retain the legacy verifier only for licenses it already supports. Test known valid legacy fixtures and tampered/expired fixtures. Never “migrate” a license just by trusting its unsigned decoded fields.
4. Ship a desktop release that accepts BC1 alongside the preserved legacy format. Only then issue BC1 licenses. Existing customers can retain their existing entitlements until a documented replacement or expiry policy applies.
5. If rotating keys, ship an explicit allowlist of trusted old and new public keys first. Resolve signed key IDs only against the bundled allowlist. For older BC1 tokens, verify against that same allowlist. Preserve the old public key for licenses you still intend to honor. Import the original encrypted backup to continue issuing with the same identity.
6. Remove legacy support only in a deliberate, announced later release after all affected customers have migrated. Offline revocation is not part of this application.
