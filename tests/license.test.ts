import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, sign } from 'node:crypto';
import { createSigningKey, createPayload, DAY, signLicense, verifyLicense, exportBackup, restoreBackup, importPublicKey, publicKeyJson, base64url, decodeLicense, parseBackup } from '../shared/license.ts';
import { verifyDesktopLicense } from '../desktop/verify-license.mjs';

const pair = await createSigningKey();
const jwk = await publicKeyJson(pair.publicKey);
const payload = createPayload({ customer: 'Alex Morgan', phone: '+94 77 123 4567', device: 'BC-WIN-1234', issueDate: '2026-01-01', days: 365 });
const license = await signLicense(payload, pair.privateKey);
const now = payload.issued + DAY;
const passphrase = 'four long words safely stored';
const backup = await exportBackup(pair.privateKey, passphrase);

test('signing and verification preserve all customer details', async () => {
  assert.deepEqual(await verifyLicense(license, pair.publicKey, payload.device, now), payload);
});
test('default 365-day duration uses exact UTC milliseconds across a leap year', () => {
  assert.equal(payload.expires - payload.issued, 365 * DAY);
  const leap = createPayload({ customer: 'Leap', device: 'A', issueDate: '2024-01-01', days: 365 });
  assert.equal(new Date(leap.expires).toISOString(), '2024-12-31T00:00:00.000Z');
});
test('all supported durations and custom days calculate UTC expiry', () => {
  for (const days of [30, 90, 180, 365, 42]) {
    const p = createPayload({ customer: 'A', device: 'D', issueDate: '2026-01-01', days });
    assert.equal(p.expires, p.issued + days * DAY);
  }
});
test('device binding rejects other devices and preserves case', async () => {
  await assert.rejects(verifyLicense(license, pair.publicKey, 'other', now), /another device/);
  assert.throws(() => verifyDesktopLicense(license, jwk, 'bc-win-1234', now), /another device/);
});
test('wrong owner passphrase cannot restore key', async () => {
  await assert.rejects(restoreBackup(backup, 'incorrect owner passphrase'), /Could not unlock/);
});
test('every security-sensitive field is covered by the signature', async () => {
  for (const mutation of [{ device: 'OTHER' }, { expires: payload.expires + DAY }, { customer: 'Modified' }, { phone: 'other' }, { product: 'Other' }, { issued: payload.issued + DAY }, { id: 'AAAAAAAAAAAAAAAAAAAAAA' }]) {
    const body = base64url(new TextEncoder().encode(JSON.stringify({ ...payload, ...mutation })));
    const modified = `BC1.${body}.${license.split('.')[2]}`;
    await assert.rejects(verifyLicense(modified, pair.publicKey, 'OTHER', now));
    assert.throws(() => verifyDesktopLicense(modified, jwk, 'OTHER', now));
  }
});
test('expired license and exclusive expiry boundary are rejected', async () => {
  for (const time of [payload.expires, payload.expires + 1]) {
    await assert.rejects(verifyLicense(license, pair.publicKey, payload.device, time), /expired/);
    assert.throws(() => verifyDesktopLicense(license, jwk, payload.device, time), /expired/);
  }
  assert.deepEqual(await verifyLicense(license, pair.publicKey, payload.device, payload.expires - 1), payload);
});
test('future license is rejected until UTC issue time', async () => {
  await assert.rejects(verifyLicense(license, pair.publicKey, payload.device, payload.issued - 1), /not active/);
  assert.throws(() => verifyDesktopLicense(license, jwk, payload.device, payload.issued - 1), /not active/);
});
test('invalid public keys and a different valid key are rejected', async () => {
  await assert.rejects(importPublicKey({ kty: 'RSA' }));
  await assert.rejects(importPublicKey({ ...jwk, x: 'bad' }));
  await assert.rejects(importPublicKey({ ...jwk, d: 'private' }));
  const other = await createSigningKey();
  await assert.rejects(verifyLicense(license, other.publicKey, payload.device, now), /signature/);
  assert.throws(() => verifyDesktopLicense(license, { kty: 'RSA' }, payload.device, now));
  assert.throws(() => verifyDesktopLicense(license, { ...jwk, x: 'bad' }, payload.device, now));
});
test('encrypted backup exports and restores the same signing identity', async () => {
  const restored = await restoreBackup(JSON.parse(JSON.stringify(backup)), passphrase);
  assert.equal(restored.privateKey.extractable, false);
  assert.deepEqual(await publicKeyJson(restored.publicKey), { ...jwk, ext: true });
  const signed = await signLicense(payload, restored.privateKey);
  assert.deepEqual(await verifyLicense(signed, pair.publicKey, payload.device, now), payload);
  assert.deepEqual(verifyDesktopLicense(signed, jwk, payload.device, now), payload);
});
test('backup uses fresh salt, IV, and authenticated ciphertext; contains no raw key', async () => {
  const second = await exportBackup(pair.privateKey, passphrase);
  assert.notEqual(backup.salt, second.salt); assert.notEqual(backup.iv, second.iv); assert.notEqual(backup.ciphertext, second.ciphertext);
  const tampered = { ...backup, ciphertext: (backup.ciphertext[0] === 'A' ? 'B' : 'A') + backup.ciphertext.slice(1) };
  await assert.rejects(restoreBackup(tampered, passphrase));
  assert.equal('privateKey' in backup, false);
  assert.throws(() => parseBackup({ ...backup, iterations: 1 }));
  assert.throws(() => parseBackup({ ...backup, iterations: 999999999 }));
  await assert.rejects(exportBackup(pair.privateKey, 'short'));
});
test('desktop compatibility: Web Crypto signatures verify with independent Node native crypto', () => {
  assert.deepEqual(verifyDesktopLicense(license, jwk, payload.device, now), payload);
});
test('desktop compatibility: native Node signatures verify with Web Crypto', async () => {
  const privateJwk = await publicKeyJson(pair.privateKey);
  const key = createPrivateKey({ key: { ...privateJwk }, format: 'jwk' });
  const message = license.split('.').slice(0, 2).join('.');
  const sig = sign('sha256', Buffer.from(message), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  assert.deepEqual(await verifyLicense(`${message}.${sig}`, pair.publicKey, payload.device, now), payload);
});
test('malformed license, signature, version, and noncanonical encoding are rejected', async () => {
  for (const bad of ['', 'BC2.a.b', license + '.extra', license.slice(0, -20), 'BC1.!!!.!!!', 'x'.repeat(9000)]) {
    await assert.rejects(verifyLicense(bad, pair.publicKey, payload.device, now));
    assert.throws(() => verifyDesktopLicense(bad, jwk, payload.device, now));
  }
  const parts = license.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  await assert.rejects(verifyLicense(parts.join('.'), pair.publicKey, payload.device, now), /signature/);
});
test('invalid fields, invalid calendar dates, and invalid durations are rejected', () => {
  for (const days of [0, -1, 1.5, 36501, NaN]) assert.throws(() => createPayload({ customer: 'A', device: 'B', issueDate: '2026-01-01', days }));
  assert.throws(() => createPayload({ customer: 'A', device: 'B', issueDate: '2026-02-30', days: 365 }));
  assert.throws(() => createPayload({ customer: ' ', device: 'B', issueDate: '2026-01-01', days: 365 }));
});
test('license identifiers use secure random 128-bit IDs', () => {
  const ids = new Set(Array.from({ length: 100 }, () => createPayload({ customer: 'A', device: 'B', issueDate: '2026-01-01', days: 365 }).id));
  assert.equal(ids.size, 100); assert.equal(decodeLicense(license).id.length, 22);
});
test('no unlocked key means no signing capability', async () => {
  await assert.rejects(signLicense(payload, undefined as unknown as CryptoKey));
});
