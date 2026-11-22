/** Node 22+ / Electron main-process verifier. Embed only your public JWK. */
import { createHash, createPublicKey, verify } from 'node:crypto';

function decode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid license encoding.');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value) throw new Error('Invalid license encoding.');
  return bytes;
}

export function verifyDesktopLicense(license, publicJwk, localDeviceId, now = Date.now()) {
  if (typeof license !== 'string' || license.length > 8192) throw new Error('Invalid license.');
  const parts = license.split('.');
  if (parts.length !== 3 || parts[0] !== 'BC1') throw new Error('Unsupported license format.');
  const [prefix, body, signature] = parts;
  const sig = decode(signature);
  if (sig.length !== 64) throw new Error('Invalid signature length.');
  if (!publicJwk || publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-256' || publicJwk.d || !publicJwk.x || !publicJwk.y) throw new Error('Invalid public key.');
  const key = createPublicKey({ key: publicJwk, format: 'jwk' });
  if (!verify('sha256', Buffer.from(`${prefix}.${body}`, 'ascii'), { key, dsaEncoding: 'ieee-p1363' }, sig)) throw new Error('Invalid license signature.');
  const p = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(decode(body)));
  if (!p || p.v !== 1 || p.product !== 'BloomConnect' || typeof p.id !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(p.id)
    || typeof p.customer !== 'string' || !p.customer.trim() || p.customer.length > 160
    || typeof p.phone !== 'string' || p.phone.length > 50
    || typeof p.device !== 'string' || !p.device.trim() || p.device.length > 256 || p.device !== p.device.trim()
    || !Number.isSafeInteger(p.issued) || p.issued < 0 || !Number.isSafeInteger(p.expires)
    || p.expires <= p.issued || p.expires > 8_640_000_000_000_000) throw new Error('Invalid license payload.');
  const { crv, kty, x, y } = publicJwk;
  if (p.kid !== undefined && p.kid !== createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url')) throw new Error('License key ID does not match the trusted public key.');
  if (p.device !== localDeviceId.trim()) throw new Error('This license belongs to another device.');
  if (now < p.issued) throw new Error('This license is not active yet.');
  if (now >= p.expires) throw new Error('This license has expired.');
  return Object.freeze(p);
}
