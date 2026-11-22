import { strToU8, zipSync } from 'fflate';
import { base64url, createPayload, createSigningKey, keyId, publicKeyJson, signLicense } from '../shared/license';

export async function desktopPackage(ownerPublicKey: JsonWebKey): Promise<Uint8Array> {
  const ownerKeyId = await keyId(ownerPublicKey);
  const fixture = await createSigningKey();
  const testPublicKey = await publicKeyJson(fixture.publicKey);
  const testKeyId = await keyId(testPublicKey);
  const device = 'BC1-INTEGRATION-TEST';
  const payload = createPayload({ customer: 'BloomConnect', device, issueDate: '2020-01-01', days: 365, kid: testKeyId });
  const license = await signLicense(payload, fixture.privateKey);
  const changedBody = base64url(strToU8(JSON.stringify({ ...payload, expires: payload.expires + 1 })));
  const tampered = `BC1.${changedBody}.${license.split('.')[2]}`;
  const now = payload.issued + 1;
  const vectors = {
    fixturePublicKey: testPublicKey, fixtureKeyId: testKeyId, payload,
    cases: [
      { name: 'valid', license, device, now, valid: true },
      { name: 'modified expiry', license: tampered, device, now, valid: false },
      { name: 'wrong device', license, device: 'BC1-OTHER-DEVICE', now, valid: false },
      { name: 'expired', license, device, now: payload.expires, valid: false },
      { name: 'future', license, device, now: payload.issued - 1, valid: false },
    ],
  };
  return zipSync({
    'public-key.json': strToU8(JSON.stringify(ownerPublicKey, null, 2)),
    'license-example.txt': strToU8(`${license}\n`),
    'license-test-vectors.json': strToU8(JSON.stringify(vectors, null, 2)),
    'license-format.md': strToU8(`# BloomConnect BC1 license format

The production key ID for this package is \`${ownerKeyId}\`.

- Public key format is an EC P-256 JWK. The \`x\` and \`y\` coordinates are unsigned 32-byte big-endian integers encoded as unpadded base64url. The JWK contains no private \`d\` member.
- Derive the key ID as unpadded base64url of SHA-256 over UTF-8 compact JSON with fields in this order: \`crv\`, \`kty\`, \`x\`, \`y\`. Ignore other JWK fields when deriving the ID.
- Wire format is \`BC1.<body>.<signature>\`. Sign the exact ASCII bytes of \`BC1.<body>\` using ECDSA P-256 with SHA-256. Encode the signature as unpadded base64url of 64-byte IEEE P1363 \`r || s\` (32 bytes each).
- The body is unpadded base64url of UTF-8 compact JSON using ECMAScript JSON.stringify escaping, no whitespace outside strings, and fields in this order.

| Field | Type and meaning |
| --- | --- |
| v | Integer format version, 1 |
| id | Unpadded base64url of 16 random bytes |
| customer | Nonblank string, max 160 UTF-16 code units. Website emits BloomConnect |
| phone | String, max 50 UTF-16 code units. Website emits an empty string |
| device | Case-sensitive desktop device ID, trimmed, nonempty, max 256 UTF-16 code units |
| product | Exact string BloomConnect |
| issued | Nonnegative safe integer Unix milliseconds, UTC midnight on the issue date |
| expires | Safe integer Unix milliseconds, greater than issued and at most 8640000000000000. Website emits issued + 31536000000 |
| kid | Key ID of the signing key. Legacy BC1 licenses may omit this field |
`),
    'desktop-integration-guide.md': strToU8(`# BloomConnect Desktop integration

1. Add the trusted JWK from \`public-key.json\` to the array in \`packages/licensing/website-public-keys.json\` in the BloomConnect Desktop source, then rebuild the installer. Its key ID is \`${ownerKeyId}\`. Select verification keys only from trusted build configuration. Retain earlier trusted website keys when licenses issued with them still need to work.
2. Split the token into exactly three segments and require BC1. Require canonical unpadded base64url and exactly 64 signature bytes. Verify the original ASCII prefix and body with ECDSA P-256/SHA-256. In Node use \`crypto.verify\` with \`dsaEncoding: 'ieee-p1363'\`. Check the signature before trusting the payload and verify the original wire bytes directly.
3. Decode the payload as strict UTF-8 and validate the schema in license-format.md. Require the expected product and format version. For new licenses require kid to match the trusted public key. If maintaining legacy BC1 support, accept absent kid only after verifying against a separately pinned trusted key.
4. Compare device with the trimmed local device ID, preserving case. Require issued <= current UTC Unix milliseconds < expires. Recheck these conditions when using a stored license.
5. Run the test vectors with fixturePublicKey and each case's device and now. The example uses that test key and the historical timestamps. Keep the fixture public key out of production trust configuration.
6. Build BloomConnect Desktop with the production public key, get its Device ID, generate a real license for that ID, and activate it in Desktop to confirm integration.
`),
  });
}
