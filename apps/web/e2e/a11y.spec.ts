import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

async function audit(page: Page, path: string) {
  await page.goto(path);
  await page.waitForLoadState('networkidle');
  await expect(page.locator('h1').first()).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  expect(results.passes.length).toBeGreaterThan(10); // axe actually ran
  const serious = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  expect(serious.map((v) => `${path}: ${v.id} — ${v.help} (${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(', ')})`)).toEqual([]);
}

test('no serious or critical WCAG 2.1 AA violations on major screens', async ({ page }, info) => {
  for (const p of ['/', '/login', '/register', '/privacy', '/contact', '/forgot-password']) await audit(page, p);
  await page.goto('/register');
  await page.getByLabel('Email').fill(`a11y-${info.project.name}-${Date.now()}@e2e.example`);
  await page.getByLabel('Password').fill('a11y-correct-horse-42');
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page).toHaveURL(/dashboard/);
  await audit(page, '/dashboard'); // empty state
  await page.goto('/connections');
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Use development fixture mailbox' }).click();
  await expect(page.getByText(/Last scan: Completed/)).toBeVisible({ timeout: 20_000 });
  for (const p of ['/dashboard', '/accounts', '/remediation', '/alerts', '/reports', '/check', '/extension', '/plan', '/settings', '/connections', '/dasi-method']) {
    await audit(page, p);
  }
  await page.goto('/accounts');
  await page.getByRole('link', { name: 'Fixtureshop' }).click();
  await expect(page.getByRole('heading', { name: 'Fixtureshop', level: 1 })).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => v.id)).toEqual([]);
});
