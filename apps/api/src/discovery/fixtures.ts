/**
 * DEVELOPMENT FIXTURES — NOT REAL DATA.
 *
 * A synthetic mailbox used to demonstrate and test discovery when no OAuth
 * credentials are configured. Everything derived from it is stored with
 * is_fixture = true and labelled "Development fixture" in the UI and reports.
 * Fictional services use the reserved ".example" TLD (RFC 2606).
 */
import type { MessageMeta } from './classifier.js';

export const FIXTURE_MAILBOX_ADDRESS = 'fixture-mailbox@footprintx-dev-fixture.example';

const daysAgo = (now: Date, d: number) => new Date(now.getTime() - d * 86400_000).toISOString();

export function fixtureMessages(now: Date): MessageMeta[] {
  const m = (id: string, from: string, subject: string, days: number): MessageMeta => ({ id: `fixture-${id}`, from, subject, date: daysAgo(now, days) });
  return [
    m('01', 'FixtureShop <no-reply@fixtureshop.example>', 'Welcome to FixtureShop!', 6 * 365),
    m('02', 'FixtureShop <orders@fixtureshop.example>', 'Your order confirmation #10042', 200),
    m('03', 'FixtureSocial <hello@fixturesocial.example>', 'Confirm your email address', 2 * 365),
    m('04', 'FixtureSocial <security@fixturesocial.example>', 'New sign-in from Firefox on Windows', 12),
    m('05', 'FixtureForum <noreply@fixtureforum.example>', 'Welcome to FixtureForum', 5 * 365),
    m('06', 'FixtureBank <alerts@fixturebank.example>', 'Your monthly account statement is ready', 15),
    m('07', 'FixtureBank <security@fixturebank.example>', 'Suspicious sign-in attempt blocked', 5),
    m('08', 'GitHub <noreply@github.com>', 'Welcome to GitHub', 4 * 365),
    m('09', 'GitHub <noreply@github.com>', '[GitHub] A new sign-in from Chrome on Linux', 30),
    m('10', 'Spotify <no-reply@spotify.com>', 'Your receipt from Spotify', 40),
    m('11', 'Google <no-reply@accounts.google.com>', 'Security alert', 20),
    m('12', 'A Friend <friend.person@gmail.com>', 'Welcome to my birthday party', 3),
    m('13', 'Random News <news@randomnews.example>', "This week's top stories", 2),
    m('14', 'FixtureShop <no-reply@fixtureshop.example>', 'Reset your password', 300),
  ];
}

/** DEVELOPMENT FIXTURE breach catalogue (fictional services only). */
export const FIXTURE_BREACHES = [
  {
    id: 'FixtureShop', title: 'FixtureShop (development fixture)', domain: 'fixtureshop.example', breachDate: isoYearsAgo(3),
    dataClasses: ['Email addresses', 'Passwords', 'Names'], pwnCount: 120000,
  },
  {
    id: 'FixtureSocial', title: 'FixtureSocial (development fixture)', domain: 'fixturesocial.example', breachDate: isoYearsAgo(5),
    dataClasses: ['Email addresses', 'Usernames'], pwnCount: 50000,
  },
  {
    id: 'FixtureForum', title: 'FixtureForum (development fixture)', domain: 'fixtureforum.example', breachDate: isoYearsAgo(4),
    dataClasses: ['Email addresses', 'Passwords', 'IP addresses'], pwnCount: 9000,
  },
];

function isoYearsAgo(years: number): string {
  const d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() - years);
  return d.toISOString().slice(0, 10);
}
