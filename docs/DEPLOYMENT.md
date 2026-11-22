# Free Cloudflare Pages deployment

This is a Vite static app. The build needs no secrets, API tokens, database, or environment variables. Generated owner keys must **never** be committed to GitHub or placed in `public/` or `dist/`.

## GitHub-connected deployment

1. Create a GitHub repository and upload this project's source, including `package-lock.json`, `public/_headers`, and the documentation. Exclude `node_modules/`, `dist/`, owner backups, licenses, and exported customer records. The included `.gitignore` covers their standard filenames. Review files before committing; custom backup filenames may need additional exclusions.
2. In Cloudflare's dashboard open **Workers & Pages → Create application → Pages → Connect to Git** (the labels may change). Choose your repository.
3. Set:

   | Setting | Value |
   | --- | --- |
   | Framework preset | Vite (or None) |
   | Production branch | `main` (or your chosen branch) |
   | Root directory | Repository root |
   | Build command | `npm run build` |
   | Build output directory | `dist` |
   | Build environment variable | `NODE_VERSION=24` |

4. Deploy. Cloudflare installs dependencies and serves `dist/` over HTTPS on a free `*.pages.dev` address. Open that address from Android Chrome or iPhone Safari.
5. Later pushes to the production branch rebuild the app. Preview branches can be used for review before changing production.

Use the **Pages** static hosting flow, not a Worker requiring an application server. There are no Pages Functions. A custom domain is optional; the supplied Pages domain is sufficient and requires no purchased domain. Cloudflare's free plan is subject to its current published usage limits.

## Direct upload without connecting GitHub

Run locally:

```sh
npm ci
npm test
npm run build
```

In Cloudflare Pages choose **Direct Upload**, create a project, and upload the contents of `dist/` (or a ZIP containing those contents at its root). Include `index.html`, assets, favicon, and `_headers`. Direct-upload projects and Git-integrated projects have different update workflows; choose the workflow you want when creating the project.

After uploading, verify the returned HTTPS address. Create a new signing key there or restore your existing encrypted owner backup. The laptop is only needed for development or manual uploads, never to keep the deployed site running. Git-connected updates can run entirely in Cloudflare.

## Deployment smoke check

1. In a fresh browser profile, confirm **Create New Signing Key** is selected and **Restore Existing Signing Key** is available.
2. Create or restore your signing key. Download the encrypted backup and Desktop integration package in **Owner setup**.
3. Optionally enable device unlock on the final production HTTPS domain. Confirm a device verification request actually occurs. If PRF is unsupported, the screen must report the passphrase fallback rather than claim that biometrics protect the key.
4. Reload the page. Generate a license with device authorization or the inline passphrase fallback; no backup re-import should be required.
5. Generate another license and confirm a fresh authorization is required. Cancel authorization or use a wrong passphrase and confirm that no license appears.
6. Test clipboard copy and WhatsApp on a real phone. Export/import history before refreshing if records are needed.
7. Verify the generated license in the actual BloomConnect Desktop build with the matching embedded public key. Reject modified signatures, wrong devices, and expired licenses.
8. Confirm HTTPS and `_headers` delivery. Test backups before relying on browser-local storage.

Passkeys are origin-scoped. Set them up on the final domain, not a temporary preview address. Browser data does not synchronize between phones; a passkey provider may synchronize a credential but not this app's local vault. The original encrypted backup remains your recovery method.

## Development and troubleshooting

- `npm run dev` prints the preview URL. HTTP localhost is a secure context; plain HTTP over a LAN IP generally is not.
- Clipboard access can be denied by browser permissions. The license text is selectable as a manual-copy fallback; history supports file download.
- iPhone Safari may preview a downloaded JSON/text file; use its Share → Save to Files action. Test saving and restoring your backup before relying on it.
- File import uses the phone's file picker. Browser profiles and devices do not share session history.
- A wrong passphrase cannot be reset. Recover using the original passphrase and an intact backup.
- The app is deploy-ready, but no Cloudflare account or repository was connected during development. No hosted URL has been created by this project alone.
