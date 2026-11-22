# BloomConnect validation

The website production build passes TypeScript checking and Vite compilation. The Cloudflare upload ZIP contains the static output with its security headers.

## Website tests

- The 23 Node tests passed. They cover BC1 signing, UTC duration, tampering, device binding, backup encryption and restoration, wrong passphrases, and passkey PRF authorization.
- All 10 desktop and mobile Chrome tests passed. They exercise new setup and restoration, encrypted backup download, public JWK and integration ZIP downloads, positive and negative vectors, fixed-duration generation, clipboard and WhatsApp URL construction, history, and narrow layouts. Chrome's virtual authenticator exercises actual PRF decryption and the fallback when PRF is unavailable.
- Both iPhone-sized WebKit tests passed, covering layout and new key setup, downloads, restore, and license generation. To rerun, install the Playwright browser with npx playwright install webkit, set BLOOMCONNECT_TEST_WEBKIT=1, then run npx playwright test --project iphone-webkit.

## Desktop activation

The separate BloomConnect Desktop checkout builds successfully. All 10 offline licensing tests pass. In the latest full Desktop suite, 82 of 83 tests passed. The WhatsApp Web workspace test timed out during engine setup. Its Windows Electron integration harness accepted a BC1 license signed by the website implementation with a disposable signing key and the actual local Device ID. The harness checked rejection of a signed token with a mismatched key ID, reopening the DPAPI-protected activation, and renewal.

An installer that trusts the owner's new public key still needs to be built and activated with an owner-issued license. Browser runs use emulation and virtual authenticators. Physical Android and iPhone hardware, WhatsApp delivery, and a live Cloudflare deployment have yet to be verified.
