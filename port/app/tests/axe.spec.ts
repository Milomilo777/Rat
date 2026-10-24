import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import fs from 'fs';

const results: any[] = [];

test.afterAll(() => {
  fs.writeFileSync('../reports/axe-results.json', JSON.stringify(results, null, 2));
});

test('accessibility checks - light mode', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });

  // Monitor tab
  await page.goto('http://localhost:1420');
  await page.waitForSelector('.sidebar');
  let v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Monitor - Light', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Rules tab
  await page.click('button[id="tab-btn-rules"]');
  await page.waitForSelector('.rules-table');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Rules - Light', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Settings tab
  await page.click('button[id="tab-btn-settings"]');
  await page.waitForSelector('.settings-section');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Settings - Light', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Alert window
  await page.goto('http://localhost:1420/src/alert.html');
  await page.waitForSelector('.alert-container');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Alert - Light', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);
});

test('accessibility checks - dark mode', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });

  // Monitor tab
  await page.goto('http://localhost:1420');
  await page.waitForSelector('.sidebar');
  let v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Monitor - Dark', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Rules tab
  await page.click('button[id="tab-btn-rules"]');
  await page.waitForSelector('.rules-table');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Rules - Dark', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Settings tab
  await page.click('button[id="tab-btn-settings"]');
  await page.waitForSelector('.settings-section');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Settings - Dark', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);

  // Alert window
  await page.goto('http://localhost:1420/src/alert.html');
  await page.waitForSelector('.alert-container');
  v = await new AxeBuilder({ page }).analyze();
  results.push({ context: 'Alert - Dark', violations: v.violations });
  expect(v.violations.filter(v => ['critical', 'serious'].includes(v.impact!)).length).toBe(0);
});
