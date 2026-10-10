import { expect, test, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const PASSWORD = 'e2e-correct-horse-42';

async function register(page: Page, email: string) {
  await page.goto('/register');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
}

const unique = (name: string, project: string) => `${name}-${project}-${Date.now()}@e2e.example`;

test('signed-out users are redirected and see honest auth errors', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Email').fill('nobody@e2e.example');
  await page.getByLabel('Password').fill('wrong-password-123');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toHaveText('Invalid email or password');
  await page.goto('/register');
  await page.getByLabel('Email').fill('short@e2e.example');
  await page.getByLabel('Password').fill('short');
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Use at least 12 characters')).toBeVisible();
});

test('Free user: discovery, DASI, corrections, remediation, report, site check, contact, settings', async ({ page }, info) => {
  const email = unique('free', info.project.name);
  await register(page, email);
  await expect(page.getByText('Not enough information yet')).toBeVisible();

  // Mailbox consent is explicit; buttons stay disabled until the user authorises.
  await page.goto('/connections');
  const fixtureBtn = page.getByRole('button', { name: 'Use development fixture mailbox' });
  await expect(fixtureBtn).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Connect Gmail' })).toBeDisabled();
  await expect(page.getByText('Not configured on this server').first()).toBeVisible();
  await page.getByRole('checkbox').check();
  await fixtureBtn.click();
  await expect(page.getByText(/Last scan: Completed/)).toBeVisible({ timeout: 20_000 });

  await page.goto('/dashboard');
  await expect(page.getByRole('img', { name: /DASI \d+ out of 100/ })).toBeVisible();
  await expect(page.getByText('Development fixture data.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Highest-priority findings' })).toBeVisible();
  const scoreBefore = await page.getByRole('img', { name: /DASI \d+ out of 100/ }).getAttribute('aria-label');

  // Correct a false positive.
  await page.goto('/accounts');
  await page.getByRole('link', { name: 'Spotify' }).click();
  await page.getByRole('button', { name: 'Not mine' }).click();
  await expect(page.getByText('Saved. Your risk score was updated.')).toBeVisible();
  await expect(page.getByText('You marked this as not yours')).toBeVisible();

  // Remediation: user-reported completion updates the score without a page reload.
  await page.goto('/remediation');
  const first = page.locator('.list > li').first();
  const title = await first.locator('strong').first().innerText();
  await first.getByRole('button', { name: 'I’ve done this' }).click();
  await page.getByRole('button', { name: /^Done/ }).click();
  await expect(page.locator('.list > li', { hasText: title }).getByText('Done (you reported)')).toBeVisible();
  await page.goto('/dashboard');
  const scoreAfter = await page.getByRole('img', { name: /DASI \d+ out of 100/ }).getAttribute('aria-label');
  expect(scoreAfter).not.toBe(scoreBefore);

  // Excel report: a real .xlsx (zip) file is downloaded.
  await page.goto('/reports');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /Download security report/ }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^footprintx-report-\d{4}-\d{2}-\d{2}\.xlsx$/);
  const buf = await readFile((await dl.path())!);
  expect(buf.subarray(0, 2).toString()).toBe('PK');
  await expect(page.getByText('Security report downloaded.')).toBeVisible();

  // Manual site check with controlled fixtures (no real malicious sites).
  await page.goto('/check');
  await page.getByLabel('Website or link').fill('malicious.fixture.test');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByRole('heading', { name: 'Known malicious site' })).toBeVisible();
  await page.getByLabel('Website or link').fill('localhost');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByText('Local and private network addresses are not checked.')).toBeVisible();

  // Extension protection is Premium.
  await page.goto('/extension');
  await expect(page.getByText('Protection requires Premium.')).toBeVisible();

  // Notifications need separate consent.
  await page.goto('/settings');
  await page.getByLabel('Important new security findings').check();
  await page.getByRole('button', { name: 'Save preferences' }).click();
  await expect(page.getByText(/Confirm that FootprintX may email/)).toBeVisible();
  await page.getByLabel(/I agree that FootprintX may email/).check();
  await page.getByRole('button', { name: 'Save preferences' }).click();
  await expect(page.getByText('Notification preferences saved.')).toBeVisible();

  // Data export.
  const [exp] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: /Download all my data/ }).click()]);
  expect((await readFile((await exp.path())!)).subarray(0, 2).toString()).toBe('PK');

  // Contact form, development outbox mode is labelled honestly.
  await page.goto('/contact');
  await page.waitForTimeout(1600);
  await page.getByLabel('Name').fill('E2E Tester');
  await page.getByLabel('Subject').fill('Hello from e2e');
  await page.getByLabel('Message').fill('This is an automated end-to-end test message.');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.getByText(/It was not emailed/)).toBeVisible();

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('link', { name: 'Sign in' }).first()).toBeVisible();
});

test('Premium (development entitlement): extension linking, security events, account deletion', async ({ page }, info) => {
  const email = unique('premium', info.project.name);
  await register(page, email);
  await page.goto('/plan');
  await expect(page.getByText('Online payments are not available yet.')).toBeVisible();
  await page.getByRole('button', { name: 'Enable Premium for development' }).click();
  await expect(page.getByText('Development entitlement — no payment')).toBeVisible();

  await page.goto('/extension');
  await page.getByRole('button', { name: 'Create link code' }).click();
  await expect(page.getByLabel('Link code')).toHaveText(/^[A-Z0-9]{5}-[A-Z0-9]{5}$/);
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  await page.getByLabel('Sync warning events from my linked browsers').check();
  await expect(page.getByLabel('Sync warning events from my linked browsers')).toBeChecked();

  await page.goto('/settings');
  await page.getByText('Delete my account').click();
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Type DELETE to confirm').fill('DELETE');
  await page.getByRole('button', { name: 'Permanently delete account' }).click();
  await expect(page).toHaveURL(/\/\?deleted=1$/);
  await expect(page.getByText('Your account and all its data were permanently deleted.')).toBeVisible();
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toHaveText('Invalid email or password');
});

test('navigation is keyboard and small-screen accessible', async ({ page }, info) => {
  await register(page, unique('nav', info.project.name));
  if (info.project.name === 'mobile') {
    const toggle = page.getByRole('button', { name: 'Menu' });
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await toggle.click();
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Accounts' }).click();
  } else {
    await expect(page.getByRole('button', { name: 'Menu' })).toBeHidden();
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Accounts' }).click();
  }
  await expect(page.getByRole('heading', { name: 'Accounts', level: 1 })).toBeVisible();
  // No horizontal page scroll.
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Accounts', level: 1 })).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
});
