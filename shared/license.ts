/** BloomConnect v1 protocol. This module has no React or Node dependency. */
export const PRODUCT = 'BloomConnect' as const;
export const DAY = 86_400_000;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
export interface LicensePayload {
  v: 1; id: string; customer: string; phone: string; device: string;
  product: typeof PRODUCT; issued: number; expires: number; kid?: string;
}
export interface LicenseRecord { key: string; payload: LicensePayload }
export interface KeyBackup {
  format: 'BloomConnect-encrypted-key'; version: 1;
  kdf: 'PBKDF2-SHA256'; iterations: number; salt: string;
  cipher: 'AES-256-GCM'; iv: string; ciphertext: string;
}
const AAD = enc.encode('BloomConnect-encrypted-key/v1');
export function base64url(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unbase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new Error('Invalid encoding.');
  const bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
  if (base64url(bytes) !== value) throw new Error('Non-canonical encoding.');
  return bytes;
}
export function validatePayload(p: unknown): asserts p is LicensePayload {
  if (!p || typeof p !== 'object') throw new Error('Invalid license payload.');
  const a = p as LicensePayload;
  if (a.v !== 1 || a.product !== PRODUCT || typeof a.id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(a.id)
    || (a.kid !== undefined && (typeof a.kid !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(a.kid)))
    || typeof a.customer !== 'string' || !a.customer.trim() || a.customer.length > 160
    || typeof a.phone !== 'string' || a.phone.length > 50
    || typeof a.device !== 'string' || !a.device.trim() || a.device.length > 256
    || a.device !== a.device.trim() || !Number.isSafeInteger(a.issued) || !Number.isSafeInteger(a.expires)
    || a.issued < 0 || a.expires <= a.issued || a.expires > 8_640_000_000_000_000) throw new Error('Invalid license payload.');
}
export function normalizeDeviceId(value: string): string {
  const device = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(device)) throw new Error('Paste a valid Device ID from BloomConnect Desktop.');
  return device;
}
export function createPayload(input: { customer: string; phone?: string; device: string; issueDate: string; days: number; kid?: string }): LicensePayload {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(input.issueDate) || !Number.isInteger(input.days) || input.days < 1 || input.days > 36500) throw new Error('Choose a valid issue date and 1–36,500 days.');
  const issued = Date.parse(`${input.issueDate}T00:00:00.000Z`);
  if (!Number.isFinite(issued) || new Date(issued).toISOString().slice(0, 10) !== input.issueDate) throw new Error('Invalid issue date.');
  const payload: LicensePayload = { v: 1, id: base64url(crypto.getRandomValues(new Uint8Array(16))),
    customer: input.customer.trim(), phone: input.phone?.trim() ?? '', device: input.device.trim(),
    product: PRODUCT, issued, expires: issued + input.days * DAY, ...(input.kid === undefined ? {} : { kid: input.kid }) };
  validatePayload(payload); return payload;
}
export async function createSigningKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
}
export async function publicKeyJson(key: CryptoKey): Promise<JsonWebKey> { return crypto.subtle.exportKey('jwk', key); }
export async function keyId(jwk: JsonWebKey): Promise<string> {
  const { crv, kty, x, y } = jwk;
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(JSON.stringify({ crv, kty, x, y })));
  return base64url(new Uint8Array(digest));
}
export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d || !jwk.x || !jwk.y) throw new Error('Expected a public ECDSA P-256 key.');
  return crypto.subtle.importKey('jwk', jwk, algorithm, true, ['verify']);
}
export async function signLicense(payload: LicensePayload, privateKey: CryptoKey): Promise<string> {
  validatePayload(payload);
  const { v, id, customer, phone, device, product, issued, expires, kid } = payload;
  const body = base64url(enc.encode(JSON.stringify({ v, id, customer, phone, device, product, issued, expires, kid })));
  const message = `BC1.${body}`;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, enc.encode(message));
  return `${message}.${base64url(new Uint8Array(signature))}`;
}
export function decodeLicense(key: string): LicensePayload {
  if (key.length > 8192) throw new Error('License is too large.');
  const parts = key.split('.');
  if (parts.length !== 3 || parts[0] !== 'BC1' || unbase64url(parts[2]).length !== 64) throw new Error('Unsupported license format.');
  const payload: unknown = JSON.parse(dec.decode(unbase64url(parts[1])));
  validatePayload(payload); return payload;
}
export async function verifyLicense(key: string, publicKey: CryptoKey, device: string, now = Date.now()): Promise<LicensePayload> {
  const payload = decodeLicense(key);
  const [prefix, body, sig] = key.split('.');
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, unbase64url(sig), enc.encode(`${prefix}.${body}`))) throw new Error('Invalid license signature.');
  if (payload.kid !== undefined && payload.kid !== await keyId(await publicKeyJson(publicKey))) throw new Error('License key ID does not match the trusted public key.');
  if (payload.device !== device.trim()) throw new Error('This license belongs to another device.');
  if (now < payload.issued) throw new Error('This license is not active yet.');
  if (now >= payload.expires) throw new Error('This license has expired.');
  return payload;
}
async function derive(passphrase: string, salt: Uint8Array, iterations: number, usage: KeyUsage): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, { name: 'AES-GCM', length: 256 }, false, [usage]);
}
export async function exportBackup(privateKey: CryptoKey, passphrase: string): Promise<KeyBackup> {
  if (passphrase.length < 12) throw new Error('Use a passphrase of at least 12 characters.');
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 600_000;
  const key = await derive(passphrase, salt, iterations, 'encrypt');
  const raw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 }, key, raw);
    return { format: 'BloomConnect-encrypted-key', version: 1, kdf: 'PBKDF2-SHA256', iterations, salt: base64url(salt), cipher: 'AES-256-GCM', iv: base64url(iv), ciphertext: base64url(new Uint8Array(ciphertext)) };
  } finally { raw.fill(0); }
}
export function parseBackup(input: unknown): KeyBackup {
  if (!input || typeof input !== 'object') throw new Error('Invalid encrypted backup.');
  const b = input as KeyBackup;
  if (b.format !== 'BloomConnect-encrypted-key' || b.version !== 1 || b.kdf !== 'PBKDF2-SHA256'
    || b.cipher !== 'AES-256-GCM' || !Number.isInteger(b.iterations) || b.iterations < 600_000 || b.iterations > 2_000_000
    || typeof b.salt !== 'string' || typeof b.iv !== 'string' || typeof b.ciphertext !== 'string'
    || b.ciphertext.length > 4096 || unbase64url(b.salt).length !== 32 || unbase64url(b.iv).length !== 12) throw new Error('Invalid or unsupported encrypted backup.');
  return { format: b.format, version: b.version, kdf: b.kdf, iterations: b.iterations, salt: b.salt, cipher: b.cipher, iv: b.iv, ciphertext: b.ciphertext };
}
export async function restoreBackup(input: unknown, passphrase: string): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const raw = await decryptBackupMaterial(input, passphrase);
  try { return await importSigningMaterial(raw); } finally { raw.fill(0); }
}
/** Owner-authorized reprotection only. Callers must zero this temporary buffer. */
export async function decryptBackupMaterial(input: unknown, passphrase: string): Promise<Uint8Array> {
  const b = parseBackup(input);
  const key = await derive(passphrase, unbase64url(b.salt), b.iterations, 'decrypt');
  try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64url(b.iv), additionalData: AAD, tagLength: 128 }, key, unbase64url(b.ciphertext))); }
  catch { throw new Error('Could not unlock. Check your passphrase and backup file.'); }
}
export async function importSigningMaterial(raw: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: CryptoKey }> {
  const exportable = await crypto.subtle.importKey('pkcs8', raw, algorithm, true, ['sign']);
  const jwk = await publicKeyJson(exportable);
  delete jwk.d; delete jwk.key_ops;
  const publicKey = await importPublicKey(jwk);
  const privateKey = await crypto.subtle.importKey('pkcs8', raw, algorithm, false, ['sign']);
  return { privateKey, publicKey };
}
