import type { LicensePayload } from '../shared/license';
export function verifyDesktopLicense(license: string, publicJwk: JsonWebKey, localDeviceId: string, now?: number): Readonly<LicensePayload>;
