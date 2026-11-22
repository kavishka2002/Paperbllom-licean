import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser',
  timeout: 45_000,
  fullyParallel: false,
  use: { baseURL: 'http://localhost:5173', colorScheme: 'light', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop-chrome', use: { channel: 'chrome', permissions: ['clipboard-read', 'clipboard-write'], viewport: { width: 1440, height: 1000 } } },
    { name: 'phone-chrome', use: { channel: 'chrome', permissions: ['clipboard-read', 'clipboard-write'], viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
    ...(process.env.BLOOMCONNECT_TEST_WEBKIT ? [{
      name: 'iphone-webkit',
      grep: /simple screen|create a new key/,
      use: { ...devices['iPhone 13'] },
    }] : []),
  ],
  webServer: { command: 'npm run dev', url: 'http://localhost:5173', reuseExistingServer: !process.env.CI },
});
