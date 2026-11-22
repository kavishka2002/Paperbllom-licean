import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Flower2, KeyRound, Copy, Check, MessageCircle, Fingerprint, Moon, Sun, ShieldCheck, Upload, Download, ChevronLeft, AlertCircle } from 'lucide-react';
import { createPayload, createSigningKey, exportBackup, normalizeDeviceId, signLicense, verifyLicense, decodeLicense, importPublicKey, type LicenseRecord } from '../shared/license';
import { desktopPackage } from './integration';
import { readVault, saveVault, prepareVault, canUsePasskeys, enableDeviceUnlock, unlockWithDevice, unlockWithPassphrase, VAULT_STORAGE_KEY, type OwnerVault } from './vault';

type Page = 'generator' | 'setup' | 'history';
const date = (ms: number) => new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(ms);
function download(name: string, value: BlobPart, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}
async function readFile(file: File): Promise<unknown> {
  if (file.size > 4_000_000) throw new Error('Choose a file smaller than 4 MB.');
  return JSON.parse(await file.text());
}
export default function App() {
  const [loaded] = useState(() => { try { return { vault: readVault(), error: '' }; } catch { return { vault: null, error: 'Could not read the saved owner key. Restore your encrypted backup in Owner setup.' }; } });
  const [vault, setVault] = useState<OwnerVault | null>(loaded.vault);
  const [page, setPage] = useState<Page>(loaded.vault ? 'generator' : 'setup');
  const [setupMode, setSetupMode] = useState<'create' | 'restore' | 'manage'>(loaded.vault ? 'manage' : 'create');
  const [device, setDevice] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [error, setError] = useState(loaded.error);
  const [notice, setNotice] = useState('');
  const [result, setResult] = useState<LicenseRecord | null>(null);
  const [copied, setCopied] = useState(false);
  const [records, setRecords] = useState<LicenseRecord[]>([]);
  const [query, setQuery] = useState('');
  const [backupFile, setBackupFile] = useState<File | null>(null);
  const [enablePasskey, setEnablePasskey] = useState(false);
  const [dark, setDark] = useState(() => { try { return localStorage.getItem('bloom-theme') === 'dark'; } catch { return false; } });
  const deviceInput = useRef<HTMLInputElement>(null);
  const passwordInput = useRef<HTMLInputElement>(null);
  useEffect(() => { document.documentElement.classList.toggle('dark', dark); try { localStorage.setItem('bloom-theme', dark ? 'dark' : 'light'); } catch { /* Theme preference is optional. */ } }, [dark]);
  useEffect(() => { if (needsPassword) passwordInput.current?.focus(); }, [needsPassword]);
  useEffect(() => {
    const changed = (event: StorageEvent) => {
      if (event.key !== VAULT_STORAGE_KEY && event.key !== null) return;
      setPassphrase(''); setResult(null); setNeedsPassword(false);
      try { setVault(readVault()); } catch { setVault(null); setError('Owner key changed in another tab. Restore your encrypted backup.'); }
    };
    addEventListener('storage', changed); return () => removeEventListener('storage', changed);
  }, []);
  function selectSetup(mode: typeof setupMode) {
    setSetupMode(mode); setBackupFile(null); setPassphrase(''); setConfirmation(''); setError(''); setEnablePasskey(false);
  }
  function navigate(next: Page) {
    if (busyRef.current) return;
    setPage(next === 'generator' && !vault ? 'setup' : next);
    if (next === 'setup') selectSetup(vault ? 'manage' : 'create');
    setError(''); setNotice(''); setPassphrase(''); setConfirmation(''); setNeedsPassword(false);
  }
  async function generate(e: FormEvent) {
    e.preventDefault(); if (busyRef.current) return;
    setError(''); setNotice(''); setCopied(false); setResult(null);
    if (!vault) { navigate('setup'); return; }
    let targetDevice: string;
    try { targetDevice = normalizeDeviceId(device); }
    catch (e) { setError((e as Error).message); return; }
    if ((!vault.passkey || needsPassword) && !passphrase) { setNeedsPassword(true); return; }
    const active = vault;
    const password = passphrase;
    setPassphrase(''); setResult(null); busyRef.current = true; setBusy(true);
    try {
      const snapshot = localStorage.getItem(VAULT_STORAGE_KEY);
      if (snapshot !== JSON.stringify(active)) throw new Error('Owner key changed. Reload and authorize signing again.');
      const unlocked = needsPassword || !active.passkey
        ? await unlockWithPassphrase(active, password)
        : await unlockWithDevice(active);
      if (localStorage.getItem(VAULT_STORAGE_KEY) !== snapshot) throw new Error('Owner key changed. Authorize signing again.');
      // Keep the BC1 schema intact: no customer form is needed for device-only issuance.
      const payload = createPayload({ customer: 'BloomConnect', phone: '', device: targetDevice, issueDate: new Date().toISOString().slice(0, 10), days: 365, kid: active.fingerprint });
      const key = await signLicense(payload, unlocked.privateKey);
      await verifyLicense(key, unlocked.publicKey, targetDevice);
      if (localStorage.getItem(VAULT_STORAGE_KEY) !== snapshot) throw new Error('Owner key changed. Authorize signing again.');
      const record = { key, payload }; setResult(record); setRecords(old => [record, ...old]); setNeedsPassword(false);
      setNotice('License ready. Copy it or share on WhatsApp.');
      // No unlocked key is assigned to state, storage, or a reusable session.
    } catch (e) { setError(e instanceof DOMException && e.name === 'NotAllowedError' ? 'Device authorization was cancelled or unavailable. No license was generated. Try again or use your passphrase.' : (e as Error).message); }
    finally { busyRef.current = false; setBusy(false); }
  }
  async function setup(e: FormEvent) {
    e.preventDefault(); if (busyRef.current) return;
    busyRef.current = true; setBusy(true); setError(''); setNotice('');
    const password = passphrase; setPassphrase(''); setConfirmation('');
    try {
      const snapshot = localStorage.getItem(VAULT_STORAGE_KEY);
      let backup: unknown;
      if (setupMode === 'create') {
        if (vault) throw new Error('An owner key is already configured.');
        if (password.trim().length < 16 || /^[\d\s]+$/.test(password) || /^(.)\1+$/.test(password)) throw new Error('Use at least 16 characters. Choose a unique passphrase with several unrelated words.');
        if (password !== confirmation) throw new Error('The passphrases do not match.');
        const pair = await createSigningKey();
        backup = await exportBackup(pair.privateKey, password);
      } else if (setupMode === 'manage') {
        backup = vault?.backup;
      } else if (backupFile) {
        backup = await readFile(backupFile);
      }
      if (!backup) throw new Error('Choose your existing encrypted signing backup.');
      let updated = await prepareVault(backup, password, vault);
      let deviceMessage = '';
      if (enablePasskey) {
        try { updated = await enableDeviceUnlock(updated, password); deviceMessage = ' Device unlock enabled.'; }
        catch (e) { deviceMessage = ` Device unlock was not enabled: ${(e as Error).message} Your passphrase is still required for every license.`; }
      }
      if (localStorage.getItem(VAULT_STORAGE_KEY) !== snapshot) throw new Error('Owner key changed in another tab. Try again.');
      saveVault(updated); setVault(updated); selectSetup('manage');
      setPage(setupMode === 'create' ? 'setup' : 'generator'); setNeedsPassword(false);
      setNotice(`Encrypted owner key saved on this browser.${deviceMessage}`);
    } catch (e) { setError((e as Error).message); }
    finally { busyRef.current = false; setBusy(false); }
  }
  async function downloadIntegration() {
    if (!vault || busyRef.current) return;
    busyRef.current = true; setBusy(true); setError('');
    try {
      const archive = await desktopPackage(vault.publicKey);
      download('BloomConnect-desktop-integration.zip', new Uint8Array(archive), 'application/zip');
    } catch (e) { setError((e as Error).message); }
    finally { busyRef.current = false; setBusy(false); }
  }
  async function copy() {
    if (!result) return;
    try { await navigator.clipboard.writeText(result.key); setCopied(true); setNotice('License copied.'); }
    catch { setError('Copy was blocked by the browser. Tap the key text to select it and copy manually.'); }
  }
  function share() {
    if (!result) return;
    const p = result.payload;
    window.open(`https://wa.me/?text=${encodeURIComponent(`BloomConnect license\nDevice: ${p.device}\nExpires: ${date(p.expires)} UTC\n\n${result.key}`)}`, '_blank', 'noopener,noreferrer');
  }
  async function importRecords(file: File) {
    try {
      if (!vault) throw new Error('Set up the owner key first so imported signatures can be verified.');
      const data = await readFile(file) as { format: string; version: number; records: LicenseRecord[] };
      if (data.format !== 'BloomConnect-records' || data.version !== 1 || !Array.isArray(data.records) || data.records.length > 500) throw new Error('Choose a BloomConnect record export, with at most 500 records.');
      const publicKey = await importPublicKey(vault.publicKey);
      const checked: LicenseRecord[] = [];
      for (const record of data.records) {
        const p = decodeLicense(record.key);
        checked.push({ key: record.key, payload: await verifyLicense(record.key, publicKey, p.device, p.issued) });
      }
      setRecords(old => [...new Map([...checked, ...old].map(r => [r.key, r])).values()]); setNotice(`${checked.length} verified records imported.`);
    } catch (e) { setError((e as Error).message); }
  }
  return <div className="phone-app">
    <header className="app-header"><a href="#" className="brand" onClick={e => { e.preventDefault(); navigate('generator'); }}><span className="brand-icon"><Flower2 size={25} /></span><span>BloomConnect<small>LICENSE GENERATOR</small></span></a><button disabled={busy} type="button" className="icon-button" onClick={() => setDark(!dark)} aria-label={dark ? 'Switch to light mode' : 'Switch to dark mode'}>{dark ? <Sun size={21} /> : <Moon size={21} />}</button></header>
    <main>
      {page !== 'generator' && vault && <button type="button" disabled={busy} className="back-button" onClick={() => navigate('generator')}><ChevronLeft size={18} />Back to generator</button>}
      <div className="intro"><h1>{page === 'history' ? 'Session history' : 'BloomConnect License Generator'}</h1>{page === 'history' && <p>Export records before closing this page.</p>}</div>
      {!globalThis.isSecureContext && <div className="message error" role="alert">Open this website over HTTPS or localhost. Secure signing is unavailable over ordinary HTTP.</div>}
      {error && <div className="message error" role="alert"><AlertCircle size={19} /><span>{error}</span></div>}
      {notice && <div className="message notice" role="status">{notice}</div>}
      {page === 'generator' && <>
        <section className="card"><form onSubmit={generate}>
          <label className="field">Device ID<input ref={deviceInput} disabled={busy} required maxLength={256} autoCapitalize="off" autoCorrect="off" spellCheck={false} value={device} onChange={e => { setDevice(e.target.value); setResult(null); setCopied(false); }} placeholder="Paste your Device ID" /></label>
          <div className="duration"><span>License duration</span><strong>365 days</strong></div>
          {needsPassword && <div className="unlock-inline"><label className="field">Owner passphrase<input ref={passwordInput} disabled={busy} required type="password" autoComplete="current-password" value={passphrase} onChange={e => setPassphrase(e.target.value)} placeholder="Unlock to generate this license" /></label><p>Your passphrase is cleared after this request.</p></div>}
          <button type="submit" className="button primary full" disabled={busy || !globalThis.isSecureContext}>{busy ? <Fingerprint size={22} /> : <KeyRound size={22} />}{busy ? 'Authorizing…' : 'Generate License Key'}</button>
          <p className="security-note"><ShieldCheck size={15} />{vault?.passkey && !needsPassword ? 'Device authorization required each time' : 'Owner authorization required each time'}</p>
          {vault?.passkey && !needsPassword && <button type="button" className="text-button full" disabled={busy} onClick={() => { setNeedsPassword(true); setError(''); }}>Use passphrase instead</button>}
        </form></section>
        {result && <section className="card result-card" aria-labelledby="result-title"><div className="result-title"><span><Check size={21} /></span><h2 id="result-title">Your license is ready</h2></div><dl className="license-details">
          <div><dt>Device ID</dt><dd>{result.payload.device}</dd></div>
          <div><dt>Issue Date</dt><dd>{date(result.payload.issued)} UTC</dd></div>
          <div><dt>Expiry Date</dt><dd>{date(result.payload.expires)} UTC</dd></div>
        </dl><label className="field">Generated License Key<textarea readOnly rows={5} value={result.key} onFocus={e => e.target.select()} /></label><button type="button" className="button primary full copy-button" onClick={() => void copy()}>{copied ? <Check size={23} /> : <Copy size={23} />}{copied ? 'Copied!' : 'Copy License'}</button><button type="button" className="button whatsapp full" onClick={share}><MessageCircle size={21} />Share via WhatsApp</button><button type="button" className="button secondary full next-license" onClick={() => { setDevice(''); setResult(null); setCopied(false); setNotice(''); setError(''); deviceInput.current?.focus(); }}>Generate Another License</button></section>}
      </>}
      {page === 'setup' && <section className="card setup-card">
        <h2>{vault ? 'Owner key saved' : 'Set up your signing key'}</h2>
        <p className="body-copy">{vault ? 'Download your recovery backup and the public key for your Desktop build.' : 'Create a signing key on this device or restore an encrypted backup.'}</p>
        {!vault && <div className="setup-options" role="group" aria-label="Setup method">
          <button type="button" className={`button ${setupMode === 'create' ? 'primary' : 'secondary'}`} aria-pressed={setupMode === 'create'} disabled={busy} onClick={() => selectSetup('create')}>Create New Signing Key</button>
          <button type="button" className={`button ${setupMode === 'restore' ? 'primary' : 'secondary'}`} aria-pressed={setupMode === 'restore'} disabled={busy} onClick={() => selectSetup('restore')}>Restore Existing Signing Key</button>
        </div>}
        {vault && <div className="setup-options">
          <button disabled={busy} type="button" className="button secondary" onClick={() => download('BloomConnect-signing-key.bloomkey.json', JSON.stringify(vault.backup, null, 2))}><Download size={17} />Download encrypted backup</button>
          <button disabled={busy} type="button" className="button secondary" onClick={() => download('public-key.json', JSON.stringify(vault.publicKey, null, 2))}><Download size={17} />Download public-key.json</button>
          <button disabled={busy} type="button" className="button secondary" onClick={() => void downloadIntegration()}><Download size={17} />Download Desktop Integration Package</button>
          <button disabled={busy} type="button" className="text-button" onClick={() => selectSetup(setupMode === 'restore' ? 'manage' : 'restore')}>{setupMode === 'restore' ? 'Use saved key' : 'Restore Existing Signing Key'}</button>
        </div>}
        {(setupMode !== 'manage' || (canUsePasskeys() && !vault?.passkey)) && <form onSubmit={setup}>
          {setupMode === 'restore' && <label className="upload-zone"><Upload size={24} /><strong>{backupFile?.name || 'Choose encrypted backup'}</strong><small>Your existing .bloomkey.json file</small><input disabled={busy} aria-label="Encrypted signing backup" type="file" accept=".json,application/json" onChange={e => { setBackupFile(e.target.files?.[0] ?? null); setError(''); }} /></label>}
          {setupMode === 'create' && <p className="body-copy">Use a unique passphrase with several unrelated words and at least 16 characters.</p>}
          <label className="field">Owner passphrase<input required disabled={busy} type="password" autoComplete={setupMode === 'create' ? 'new-password' : 'current-password'} value={passphrase} onChange={e => setPassphrase(e.target.value)} /></label>
          {setupMode === 'create' && <label className="field">Confirm passphrase<input required disabled={busy} type="password" autoComplete="new-password" value={confirmation} onChange={e => setConfirmation(e.target.value)} /></label>}
          {!vault?.passkey && canUsePasskeys() && <label className="checkbox"><input disabled={busy} type="checkbox" checked={enablePasskey} onChange={e => setEnablePasskey(e.target.checked)} /><span>Use device unlock when supported<small>A compatible passkey must support PRF to decrypt your key. You can always use your passphrase.</small></span></label>}
          <button disabled={busy || !globalThis.isSecureContext || (setupMode === 'manage' && !enablePasskey) || (setupMode === 'restore' && !backupFile)} className="button primary full" type="submit"><ShieldCheck size={20} />{busy ? 'Working…' : setupMode === 'create' ? 'Create and save key' : setupMode === 'restore' ? 'Save encrypted key' : 'Enable device unlock'}</button>
        </form>}
        {vault?.passkey && <p className="body-copy">Device unlock is enabled. Your backup passphrase remains available.</p>}
        <p className="setup-footnote">Keep your encrypted backup and passphrase safe. Clearing browser data removes this device’s setup.</p>
      </section>}
      {page === 'history' && <section className="card"><label className="field">Search records<input value={query} onChange={e => setQuery(e.target.value)} placeholder="Customer name or Device ID" /></label><div className="record-tools"><button className="button secondary" disabled={!records.length} onClick={() => download('license-records-export.json', JSON.stringify({ format: 'BloomConnect-records', version: 1, records }, null, 2))}><Download size={17} />Export records</button><label className="button secondary file-label"><Upload size={17} />Import records<input aria-label="Import records" type="file" accept=".json" onChange={e => { const f = e.target.files?.[0]; if (f) void importRecords(f); e.target.value = ''; }} /></label></div>{records.filter(r => `${r.payload.customer} ${r.payload.device}`.toLowerCase().includes(query.toLowerCase())).map(record => <article className="record" key={record.key}><strong>{record.payload.device}</strong><p>{record.payload.customer} · Expires {date(record.payload.expires)}</p><button className="text-button" onClick={() => download(`BloomConnect-${record.payload.id}.license`, record.key)}>Download license</button></article>)}{!records.length && <p className="body-copy empty">No licenses in this session yet.</p>}</section>}
    </main>
    {vault && <footer><span><ShieldCheck size={14} />Signed on your device</span><div><button disabled={busy} className="text-button" onClick={() => navigate('history')}>History ({records.length})</button><button disabled={busy} className="text-button" onClick={() => navigate('setup')}>Owner setup</button></div></footer>}
  </div>;
}
