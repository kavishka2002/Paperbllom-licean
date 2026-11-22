import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, sign } from 'node:crypto';
import { createSigningKey, exportBackup, createPayload, signLicense, publicKeyJson, base64url, DAY } from '../shared/license.ts';
import { prepareVault, saveVault, readVault, unlockWithPassphrase, enableDeviceUnlock, unlockWithDevice, deriveDeviceWrappingKey, VAULT_STORAGE_KEY, type PasskeyEnvelope } from '../src/vault.ts';
import { verifyDesktopLicense } from '../desktop/verify-license.mjs';

const signingPair = await createSigningKey();
const password = 'existing owner backup passphrase';
const backup = await exportBackup(signingPair.privateKey, password);
const vault = await prepareVault(backup, password);
const payload = createPayload({ customer: 'BloomConnect', device: 'EXISTING-DESKTOP-ID', issueDate: '2026-11-21', days: 365 });

test('one-time setup preserves the original public key and rejects a different backup', async () => {
  assert.deepEqual(vault.publicKey, await publicKeyJson(signingPair.publicKey));
  assert.deepEqual(vault.backup, backup);
  const other = await createSigningKey();
  await assert.rejects(prepareVault(await exportBackup(other.privateKey, password), password, vault), /different signing key/);
});
test('only encrypted material and public metadata survive local persistence', () => {
  const values = new Map<string, string>();
  const store = { getItem: (k: string) => values.get(k) ?? null, setItem: (k: string, value: string) => { values.set(k, value); } };
  saveVault(vault, store);
  assert.deepEqual(readVault(store), vault);
  const saved = values.get(VAULT_STORAGE_KEY)!;
  assert.equal(saved.includes(password), false);
  assert.equal(saved.includes('privateKey'), false);
  assert.equal(saved.includes('"d":'), false);
  assert.equal(readVault({ getItem: () => null }), null);
  assert.throws(() => readVault({ getItem: () => '{"version":3}' }));
});
test('unexpected plaintext backup fields are stripped before persistence', async () => {
  const prepared = await prepareVault({ ...backup, passphrase: password, privateKey: 'DO NOT STORE', d: 'DO NOT STORE' }, password);
  const saved = JSON.stringify(prepared);
  assert.equal(saved.includes(password), false); assert.equal(saved.includes('DO NOT STORE'), false);
});
test('fallback requires the original passphrase and keeps desktop identity/365-day format', async () => {
  await assert.rejects(unlockWithPassphrase(vault, 'wrong passphrase'));
  const unlocked = await unlockWithPassphrase(vault, password);
  assert.equal(unlocked.privateKey.extractable, false);
  const license = await signLicense(payload, unlocked.privateKey);
  assert.deepEqual(verifyDesktopLicense(license, vault.publicKey, payload.device, payload.issued + DAY), payload);
  assert.equal(payload.expires - payload.issued, 365 * DAY);
  const changed = { ...vault, fingerprint: 'another-key' };
  await assert.rejects(unlockWithPassphrase(changed, password), /identity mismatch/);
});
test('PRF-derived wrapping keys require a full 256-bit secret and are not exportable', async () => {
  await assert.rejects(deriveDeviceWrappingKey(new Uint8Array(0), new Uint8Array(32)));
  assert.equal((await deriveDeviceWrappingKey(new Uint8Array(32), new Uint8Array(32))).extractable, false);
});

test('passkey PRF encrypts the original key; authorization cannot be skipped, replayed, or downgraded', async () => {
  const authenticator = await createSigningKey();
  const privateJwk = await publicKeyJson(authenticator.privateKey);
  const nodePrivate = createPrivateKey({ key: { ...privateJwk }, format: 'jwk' });
  const spki = await crypto.subtle.exportKey('spki', authenticator.publicKey);
  const id = crypto.getRandomValues(new Uint8Array(32));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  let mode = 'valid'; let count = 0;
  const createCredential = () => ({ rawId: id.buffer, id: base64url(id), response: { getPublicKey: () => spki, getPublicKeyAlgorithm: () => -7 }, getClientExtensionResults: () => ({ prf: { enabled: true } }) });
  const getCredential = async (options: CredentialRequestOptions) => {
    count++;
    if (mode === 'cancel') throw new DOMException('Cancelled', 'NotAllowedError');
    const request = options.publicKey!;
    assert.equal(request.userVerification, 'required');
    const clientDataJSON = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.get', origin: mode === 'origin' ? 'https://evil.example' : 'https://owner.example', challenge: mode === 'replay' ? 'old-challenge' : base64url(new Uint8Array(request.challenge as ArrayBuffer)), crossOrigin: false }));
    const auth = new Uint8Array(37);
    auth.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(mode === 'rp' ? 'evil.example' : 'owner.example'))));
    auth[32] = mode === 'no-uv' ? 1 : 5;
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));
    const signed = new Uint8Array(auth.length + hash.length); signed.set(auth); signed.set(hash, auth.length);
    const signature = sign('sha256', signed, nodePrivate);
    if (mode === 'signature') signature[signature.length - 1] ^= 1;
    return { id: base64url(id), rawId: id.buffer, response: { clientDataJSON: clientDataJSON.buffer, authenticatorData: auth.buffer, signature }, getClientExtensionResults: () => mode === 'no-prf' ? {} : { prf: { results: { first: mode === 'wrong-prf' ? new Uint8Array(32).buffer : secret.slice().buffer } } } };
  };
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const install = (name: string, value: unknown) => { originals.set(name, Object.getOwnPropertyDescriptor(globalThis, name)); Object.defineProperty(globalThis, name, { configurable: true, value }); };
  install('isSecureContext', true); install('PublicKeyCredential', class {}); install('location', { hostname: 'owner.example', origin: 'https://owner.example' });
  install('navigator', { credentials: { create: createCredential, get: getCredential } });
  try {
    const protectedVault = await enableDeviceUnlock(vault, password);
    assert.equal(protectedVault.fingerprint, vault.fingerprint);
    assert.equal(protectedVault.passkey?.rpId, 'owner.example');
    const unlocked = await unlockWithDevice(protectedVault);
    assert.equal(unlocked.privateKey.extractable, false);
    assert.deepEqual(verifyDesktopLicense(await signLicense(payload, unlocked.privateKey), vault.publicKey, payload.device, payload.issued + DAY), payload);
    assert.equal(count, 2); // Setup test assertion plus one fresh per-license assertion.
    for (mode of ['cancel', 'no-uv', 'origin', 'rp', 'replay', 'signature', 'no-prf', 'wrong-prf']) {
      await assert.rejects(unlockWithDevice(protectedVault), `must reject ${mode}`);
    }
    mode = 'valid';
    const tampered = structuredClone(protectedVault);
    const envelope = tampered.passkey as PasskeyEnvelope;
    envelope.ciphertext = (envelope.ciphertext[0] === 'A' ? 'B' : 'A') + envelope.ciphertext.slice(1);
    await assert.rejects(unlockWithDevice(tampered));
    // The encrypted passphrase backup remains independently recoverable after PRF failure.
    assert.deepEqual(await publicKeyJson((await unlockWithPassphrase(protectedVault, password)).publicKey), vault.publicKey);
  } finally {
    for (const [name, descriptor] of originals) { if (descriptor) Object.defineProperty(globalThis, name, descriptor); else Reflect.deleteProperty(globalThis, name); }
  }
});
