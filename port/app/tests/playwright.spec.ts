import { test, expect } from '@playwright/test';

test('has title', async ({ page }) => {
  await page.goto('http://localhost:1420');
  await expect(page).toHaveTitle(/Rat/);
});

test('screenshots', async ({ page }) => {
  await page.goto('http://localhost:1420');

  // Monitor tab
  await page.waitForSelector('h3:has-text("Apps (by Service)")');
  await page.screenshot({ path: 'screenshots/monitor.png', fullPage: true });

  // Rules tab
  await page.click('button:has-text("Rules")');
  await page.waitForSelector('h3:has-text("Rules Table")');
  await page.screenshot({ path: 'screenshots/rules.png', fullPage: true });

  // Settings tab
  await page.click('button:has-text("Settings")');
  await page.waitForSelector('h4:has-text("GeoIP Databases")');
  await page.screenshot({ path: 'screenshots/settings.png', fullPage: true });

  // Alert window
  await page.goto('http://localhost:1420/src/alert.html');
  await page.waitForSelector('h2:has-text("Connection Attempt Blocked")');
  await page.screenshot({ path: 'screenshots/alert.png', fullPage: true });
});
