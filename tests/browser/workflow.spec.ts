import { readFile } from 'node:fs/promises';
import { strFromU8, unzipSync } from 'fflate';
import { test, expect, type Page } from '@playwright/test';
import { createSigningKey, exportBackup, publicKeyJson, keyId, DAY } from '../../shared/license';
import { verifyDesktopLicense } from '../../desktop/verify-license.mjs';
import { VAULT_STORAGE_KEY } from '../../src/vault';

const pair = await createSigningKey();
const password = 'existing owner passphrase for tests';
const backup = await exportBackup(pair.privateKey, password);
const publicKey = await publicKeyJson(pair.publicKey);
const target = 'BC1-EXISTING-WINDOWS-DEVICE-ID';

async function setup(page: Page, deviceUnlock = false) {
  await page.getByRole('button', { name: 'Restore Existing Signing Key', exact: true }).click();
  await page.getByLabel('Encrypted signing backup').setInputFiles({ name: 'existing.bloomkey.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(backup)) });
  await page.getByLabel('Owner passphrase', { exact: true }).fill(password);
  if (deviceUnlock) await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Save encrypted key' }).click();
  await expect(page.getByLabel('Device ID', { exact: true })).toBeVisible();
}
function checkDesktop(key: string) {
  const p = verifyDesktopLicense(key, publicKey, target);
  expect(p.product).toBe('BloomConnect'); expect(p.customer).toBe('BloomConnect'); expect(p.phone).toBe('');
  expect(p.expires - p.issued).toBe(365 * DAY);
  expect(p.kid).toBeTruthy();
  expect(() => verifyDesktopLicense(key, publicKey, 'OTHER-DEVICE')).toThrow();
}

test('device-only fallback authorizes every license; encrypted setup survives reload', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await setup(page);
  const saved = await page.evaluate(key => localStorage.getItem(key)!, VAULT_STORAGE_KEY);
  expect(saved).not.toContain(password); expect(saved).not.toContain('"d":');
  expect(JSON.parse(saved).publicKey).toEqual(publicKey);
  await page.reload();
  await page.getByLabel('Device ID', { exact: true }).fill(target);
  await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
  await expect(page.getByLabel('Owner passphrase')).toBeVisible();
  await page.getByLabel('Owner passphrase').fill('wrong password');
  await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Could not unlock');
  await expect(page.getByRole('heading', { name: 'Your license is ready' })).toHaveCount(0);
  await page.getByLabel('Owner passphrase').fill(password);
  await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your license is ready' })).toBeVisible();
  const key = await page.getByLabel('Generated License Key').inputValue(); checkDesktop(key);
  await expect(page.getByLabel('Owner passphrase')).toHaveCount(0);
  await page.getByRole('button', { name: 'Copy License', exact: true }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(key);
  await expect(page.getByRole('button', { name: 'Copied!', exact: true })).toBeVisible();
  await page.evaluate(() => { (window as unknown as { sharedUrl: string }).sharedUrl = ''; window.open = url => { (window as unknown as { sharedUrl: string }).sharedUrl = String(url); return null; }; });
  await page.getByRole('button', { name: 'Share via WhatsApp' }).click();
  const url = await page.evaluate(() => (window as unknown as { sharedUrl: string }).sharedUrl);
  expect(url).toContain('https://wa.me/?text='); expect(decodeURIComponent(url)).toContain(key);
  await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
  await expect(page.getByLabel('Owner passphrase')).toBeVisible();
  await page.getByLabel('Owner passphrase').fill(password);
  await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your license is ready' })).toBeVisible();
  expect(await page.getByLabel('Generated License Key').inputValue()).not.toBe(key);
  await page.getByRole('button', { name: /History \(/ }).click();
  await expect(page.locator('.record')).toHaveCount(2);
  await page.reload();
  expect(await page.evaluate(key => localStorage.getItem(key), VAULT_STORAGE_KEY)).toBe(saved);
  await page.getByRole('button', { name: /History \(/ }).click();
  await expect(page.getByText('No licenses in this session yet.')).toBeVisible();
  expect(errors).toEqual([]);
});

test('real virtual-authenticator PRF unlock preserves original desktop key', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
  } });
  try {
    await page.goto('/'); await setup(page, true);
    await expect(page.getByRole('status')).toContainText('Device unlock enabled');
    const saved = await page.evaluate(key => localStorage.getItem(key)!, VAULT_STORAGE_KEY);
    expect(JSON.parse(saved).passkey.ciphertext.length).toBeGreaterThan(50);
    await page.reload();
    await page.getByLabel('Device ID', { exact: true }).fill(target);
    await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Your license is ready' })).toBeVisible();
    checkDesktop(await page.getByLabel('Generated License Key').inputValue());
    await expect(page.getByLabel('Owner passphrase')).toHaveCount(0);
    // A missing authenticator cannot authorize signing, and fallback is explicit.
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await page.getByRole('button', { name: 'Use passphrase instead' }).click();
    await page.getByLabel('Owner passphrase').fill('wrong password');
    await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('Could not unlock');
    await expect(page.getByRole('heading', { name: 'Your license is ready' })).toHaveCount(0);
    await page.getByLabel('Owner passphrase').fill(password);
    await page.getByRole('button', { name: 'Generate License Key', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Your license is ready' })).toBeVisible();
    checkDesktop(await page.getByLabel('Generated License Key').inputValue());
  } finally { await cdp.detach(); }
});

test('unsupported PRF reports fallback and never saves an unprotected key', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page); await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: false } });
  try {
    await page.goto('/'); await setup(page, true);
    await expect(page.getByRole('status')).toContainText('Device unlock was not enabled');
    const saved = JSON.parse(await page.evaluate(key => localStorage.getItem(key)!, VAULT_STORAGE_KEY));
    expect(saved.passkey).toBeUndefined(); expect(saved.backup.format).toBe('BloomConnect-encrypted-key');
    await page.getByLabel('Device ID').fill(target);
    await page.getByRole('button', { name: 'Generate License Key' }).click();
    await expect(page.getByLabel('Owner passphrase')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Your license is ready' })).toHaveCount(0);
  } finally { await cdp.detach(); }
});

test('simple screen fits phones and supports dark mode', async ({ page }, testInfo) => {
  await page.goto('/');
  for (const width of [320, 390, 768, 1024, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await page.setViewportSize({ width: testInfo.project.name === 'desktop-chrome' ? 1440 : 390, height: 900 });
  await page.screenshot({ path: testInfo.outputPath('generator-light.png'), fullPage: true });
  await page.getByRole('button', { name: 'Switch to dark mode' }).click();
  await expect(page.locator('html')).toHaveClass('dark');
  await page.screenshot({ path: testInfo.outputPath('generator-dark.png'), fullPage: true });
});
test('create a new key, export public integration files and restore the backup', async ({ page, browser }) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Create New Signing Key' })).toHaveAttribute('aria-pressed', 'true');
  const create = async (pw: string, confirmation = pw) => {
    await page.getByLabel('Owner passphrase', { exact: true }).fill(pw);
    await page.getByLabel('Confirm passphrase').fill(confirmation);
    await page.getByRole('button', { name: 'Create and save key' }).click();
  };
  await create('1234567890123456');
  await expect(page.getByRole('alert')).toContainText('Use at least 16 characters');
  await create(password, 'different confirmation');
  await expect(page.getByRole('alert')).toContainText('do not match');
  await create(password);
  await expect(page.getByRole('heading', { name: 'Owner key saved' })).toBeVisible();

  const getFile = async (name: string) => {
    const [file] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name, exact: true }).click()]);
    return readFile((await file.path())!);
  };
  const backupFile = await getFile('Download encrypted backup');
  const ownerPublic = JSON.parse((await getFile('Download public-key.json')).toString());
  expect(JSON.parse(backupFile.toString()).ciphertext).toBeTruthy();
  expect(backupFile.toString()).not.toContain(password);
  expect(ownerPublic.d).toBeUndefined();

  const zip = unzipSync(await getFile('Download Desktop Integration Package'));
  expect(Object.keys(zip).sort()).toEqual(['desktop-integration-guide.md', 'license-example.txt', 'license-format.md', 'license-test-vectors.json', 'public-key.json']);
  expect(JSON.parse(strFromU8(zip['public-key.json']))).toEqual(ownerPublic);
  const vectors = JSON.parse(strFromU8(zip['license-test-vectors.json']));
  expect(strFromU8(zip['license-example.txt']).trim()).toBe(vectors.cases[0].license);
  expect(vectors.fixturePublicKey.d).toBeUndefined();
  expect(vectors.fixtureKeyId).not.toBe(await keyId(ownerPublic));
  for (const vector of vectors.cases) {
    const verify = () => verifyDesktopLicense(vector.license, vectors.fixturePublicKey, vector.device, vector.now);
    if (vector.valid) expect(verify()).toEqual(vectors.payload);
    else expect(verify).toThrow();
  }
  const restored = await browser.newContext();
  try {
    const other = await restored.newPage();
    await other.goto(page.url());
    await other.getByRole('button', { name: 'Restore Existing Signing Key' }).click();
    await other.getByLabel('Encrypted signing backup').setInputFiles({ name: 'new.bloomkey.json', mimeType: 'application/json', buffer: backupFile });
    await other.getByLabel('Owner passphrase').fill(password);
    await other.getByRole('button', { name: 'Save encrypted key' }).click();
    await other.getByLabel('Device ID', { exact: true }).fill('bad device');
    await other.getByRole('button', { name: 'Generate License Key' }).click();
    await expect(other.getByRole('alert')).toContainText('valid Device ID');
    await expect(other.getByLabel('Owner passphrase')).toHaveCount(0);
    await other.getByLabel('Device ID', { exact: true }).fill(target);
    await other.getByRole('button', { name: 'Generate License Key' }).click();
    await other.getByLabel('Owner passphrase').fill(password);
    await other.getByRole('button', { name: 'Generate License Key' }).click();
    const code = await other.getByLabel('Generated License Key').inputValue();
    await other.setViewportSize({ width: 320, height: 844 });
    expect(await other.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const payload = verifyDesktopLicense(code, ownerPublic, target);
    expect(payload.kid).toBe(await keyId(ownerPublic));
    expect(payload.expires - payload.issued).toBe(365 * DAY);
    await other.getByRole('button', { name: 'Generate Another License' }).click();
    await expect(other.getByLabel('Device ID', { exact: true })).toHaveValue('');
  } finally {
    await restored.close();
  }
});
