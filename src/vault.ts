import { base64url, unbase64url, parseBackup, restoreBackup, publicKeyJson, decryptBackupMaterial, importSigningMaterial, keyId as fingerprint, type KeyBackup } from '../shared/license.ts';

export const VAULT_STORAGE_KEY = 'bloomconnect-owner-vault-v1';
const enc = new TextEncoder();
const context = enc.encode('BloomConnect-owner-passkey/v1');
export interface PasskeyEnvelope {
  credentialId: string; publicSpki: string; rpId: string; prfSalt: string;
  hkdfSalt: string; iv: string; ciphertext: string;
}
export interface OwnerVault {
  format: 'BloomConnect-owner-vault'; version: 1; backup: KeyBackup;
  publicKey: JsonWebKey; fingerprint: string; passkey?: PasskeyEnvelope;
}
type PrfExtensions = AuthenticationExtensionsClientInputs & { prf: { eval: { first: Uint8Array } } };
type PrfOutput = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first: ArrayBuffer } } };
export { fingerprint };
export function readVault(storage: Pick<Storage, 'getItem'> = localStorage): OwnerVault | null {
  const value = storage.getItem(VAULT_STORAGE_KEY);
  if (!value) return null;
  if (value.length > 20000) throw new Error('Saved owner data is invalid. Restore your original encrypted backup in Owner setup.');
  const v = JSON.parse(value) as OwnerVault;
  if (v.format !== 'BloomConnect-owner-vault' || v.version !== 1 || !v.publicKey || v.publicKey.d || v.publicKey.kty !== 'EC' || v.publicKey.crv !== 'P-256' || !v.publicKey.x || !v.publicKey.y || typeof v.fingerprint !== 'string') throw new Error('Saved owner data is invalid. Restore your original encrypted backup.');
  parseBackup(v.backup);
  if (v.passkey) {
    for (const field of ['credentialId', 'publicSpki', 'rpId', 'prfSalt', 'hkdfSalt', 'iv', 'ciphertext'] as const) {
      if (typeof v.passkey[field] !== 'string' || !v.passkey[field] || v.passkey[field].length > 4096) throw new Error('Saved device unlock data is invalid.');
    }
    if (unbase64url(v.passkey.prfSalt).length !== 32 || unbase64url(v.passkey.hkdfSalt).length !== 32 || unbase64url(v.passkey.iv).length !== 12) throw new Error('Saved device unlock data is invalid.');
  }
  return v;
}
export function saveVault(vault: OwnerVault, storage: Pick<Storage, 'setItem'> = localStorage) {
  // Only encrypted PKCS#8 and public metadata are persisted. No CryptoKey or password.
  storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(vault));
}
export async function prepareVault(backup: unknown, passphrase: string, existing?: OwnerVault | null): Promise<OwnerVault> {
  const parsed = parseBackup(backup);
  const unlocked = await restoreBackup(parsed, passphrase);
  const publicKey = await publicKeyJson(unlocked.publicKey);
  const identity = await fingerprint(publicKey);
  if (existing && identity !== existing.fingerprint) throw new Error('This backup uses a different signing key. Use the original backup that matches your desktop app.');
  return { format: 'BloomConnect-owner-vault', version: 1, backup: parsed, publicKey, fingerprint: identity, ...(existing?.passkey ? { passkey: existing.passkey } : {}) };
}
export async function assertIdentity(v: OwnerVault, publicKey: CryptoKey) {
  const identity = await fingerprint(await publicKeyJson(publicKey));
  if (identity !== v.fingerprint || identity !== await fingerprint(v.publicKey)) throw new Error('Signing identity mismatch. Restore the original owner backup.');
}
export async function unlockWithPassphrase(v: OwnerVault, passphrase: string) {
  const unlocked = await restoreBackup(v.backup, passphrase);
  await assertIdentity(v, unlocked.publicKey); return unlocked;
}
export function canUsePasskeys(): boolean {
  return globalThis.isSecureContext && typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials;
}
export async function deriveDeviceWrappingKey(prf: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  if (prf.length !== 32 || salt.length !== 32) throw new Error('Device unlock did not provide a secure encryption secret.');
  const material = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: context }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
function prfBytes(credential: PublicKeyCredential): Uint8Array {
  const first = (credential.getClientExtensionResults() as PrfOutput).prf?.results?.first;
  if (!first || first.byteLength !== 32) throw new Error('This passkey does not support encrypted device unlock (PRF). Use your backup passphrase.');
  return new Uint8Array(first);
}
/** WebAuthn ES256 signatures use DER; Web Crypto expects fixed-width P1363. */
export function derToP1363(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error('Invalid authenticator signature.');
  let pos = 2; const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (der[pos++] !== 2) throw new Error('Invalid authenticator signature.');
    const length = der[pos++];
    if (!length || length > 33 || pos + length > der.length || der[pos] & 0x80) throw new Error('Invalid authenticator signature.');
    let integer = der.slice(pos, pos + length); pos += length;
    if (integer.length > 1 && integer[0] === 0) {
      if (!(integer[1] & 0x80)) throw new Error('Invalid authenticator signature.');
      integer = integer.slice(1);
    }
    if (integer.length > 32) throw new Error('Invalid authenticator signature.');
    out.set(integer, part * 32 + 32 - integer.length);
  }
  if (pos !== der.length) throw new Error('Invalid authenticator signature.');
  return out;
}
export async function validateAssertion(credential: PublicKeyCredential, envelope: PasskeyEnvelope, challenge: Uint8Array, expectedOrigin: string) {
  if (credential.id !== envelope.credentialId || base64url(new Uint8Array(credential.rawId)) !== envelope.credentialId) throw new Error('Unexpected owner passkey.');
  const response = credential.response as AuthenticatorAssertionResponse;
  const clientBytes = new Uint8Array(response.clientDataJSON);
  const client = JSON.parse(new TextDecoder().decode(clientBytes));
  if (client.type !== 'webauthn.get' || client.challenge !== base64url(challenge) || client.origin !== expectedOrigin || client.crossOrigin === true) throw new Error('Device authorization does not match this request.');
  const auth = new Uint8Array(response.authenticatorData);
  const expectedRp = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(envelope.rpId)));
  if (auth.length < 37 || auth.slice(0, 32).some((b, i) => b !== expectedRp[i]) || (auth[32] & 5) !== 5) throw new Error('Owner presence and device verification are required.');
  const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientBytes));
  const signed = new Uint8Array(auth.length + clientHash.length); signed.set(auth); signed.set(clientHash, auth.length);
  const publicKey = await crypto.subtle.importKey('spki', unbase64url(envelope.publicSpki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, derToP1363(new Uint8Array(response.signature)), signed)) throw new Error('Invalid device authorization signature.');
}
async function getDeviceKey(envelope: PasskeyEnvelope): Promise<CryptoKey> {
  if (!canUsePasskeys() || envelope.rpId !== location.hostname) throw new Error('Device unlock is unavailable on this address. Use your backup passphrase.');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.get({ publicKey: {
    challenge, rpId: envelope.rpId, allowCredentials: [{ type: 'public-key', id: unbase64url(envelope.credentialId) }],
    userVerification: 'required', timeout: 60000,
    extensions: { prf: { eval: { first: unbase64url(envelope.prfSalt) } } } as PrfExtensions,
  } }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Device authorization was cancelled.');
  await validateAssertion(credential, envelope, challenge, location.origin);
  const secret = prfBytes(credential);
  try { return await deriveDeviceWrappingKey(secret, unbase64url(envelope.hkdfSalt)); }
  finally { secret.fill(0); }
}
export async function enableDeviceUnlock(v: OwnerVault, passphrase: string): Promise<OwnerVault> {
  // Verify the existing signing identity before creating a credential. No new signing key.
  await unlockWithPassphrase(v, passphrase);
  if (!canUsePasskeys()) throw new Error('Passkeys are not supported here. Use your backup passphrase for each license.');
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({ publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: 'BloomConnect Owner', id: location.hostname },
    user: { id: crypto.getRandomValues(new Uint8Array(32)), name: 'bloomconnect-owner', displayName: 'BloomConnect Owner' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
    attestation: 'none', timeout: 60000, extensions: { prf: { eval: { first: salt } } } as PrfExtensions,
  } }) as PublicKeyCredential | null;
  if (!credential) throw new Error('Device unlock setup was cancelled. Your encrypted backup is unchanged.');
  const response = credential.response as AuthenticatorAttestationResponse;
  const spki = response.getPublicKey?.();
  if (!spki || response.getPublicKeyAlgorithm?.() !== -7 || !(credential.getClientExtensionResults() as PrfOutput).prf?.enabled) throw new Error('This device or passkey does not support PRF encryption. Use your backup passphrase.');
  const envelope: PasskeyEnvelope = { credentialId: base64url(new Uint8Array(credential.rawId)), publicSpki: base64url(new Uint8Array(spki)),
    rpId: location.hostname, prfSalt: base64url(salt), hkdfSalt: base64url(crypto.getRandomValues(new Uint8Array(32))), iv: '', ciphertext: '' };
  // Test an actual assertion rather than trusting capability detection or registration alone.
  const key = await getDeviceKey(envelope);
  const raw = await decryptBackupMaterial(v.backup, passphrase);
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    envelope.iv = base64url(iv);
    envelope.ciphertext = base64url(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: context }, key, raw)));
    return { ...v, passkey: envelope };
  } finally { raw.fill(0); }
}
export async function unlockWithDevice(v: OwnerVault) {
  if (!v.passkey) throw new Error('Device unlock is not configured. Use your backup passphrase.');
  const key = await getDeviceKey(v.passkey);
  let raw: Uint8Array;
  try { raw = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64url(v.passkey.iv), additionalData: context }, key, unbase64url(v.passkey.ciphertext))); }
  catch { throw new Error('Could not decrypt the owner key with this passkey. Use your backup passphrase.'); }
  try { const unlocked = await importSigningMaterial(raw); await assertIdentity(v, unlocked.publicKey); return unlocked; }
  finally { raw.fill(0); }
}
