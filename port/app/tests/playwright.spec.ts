import { test, expect } from '@playwright/test';

const locales = ['en', 'en-PSEUDO', 'ar-PSEUDO'];

for (const locale of locales) {
  test(`screenshots in ${locale}`, async ({ page }) => {
    // Navigate with locale param
    await page.goto(`http://localhost:1420/?lang=${locale}`);

    // Monitor tab
    await page.waitForSelector('.sidebar');
    await page.screenshot({ path: `screenshots/monitor_${locale}.png`, fullPage: true });

    // Rules tab
    await page.click('button[id="tab-btn-rules"]');
    await page.waitForSelector('.rules-table');
    await page.screenshot({ path: `screenshots/rules_${locale}.png`, fullPage: true });

    // Settings tab
    await page.click('button[id="tab-btn-settings"]');
    await page.waitForSelector('.settings-section');
    await page.screenshot({ path: `screenshots/settings_${locale}.png`, fullPage: true });

    // Alert window
    await page.goto(`http://localhost:1420/src/alert.html?lang=${locale}`);
    await page.waitForSelector('.alert-container');
    await page.screenshot({ path: `screenshots/alert_${locale}.png`, fullPage: true });
  });
}
