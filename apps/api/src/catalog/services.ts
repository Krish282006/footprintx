/**
 * Curated catalogue of well-known services and their official account-security pages.
 *
 * Links were curated from each vendor's own account settings / help documentation.
 * They are labelled "curated_official" in the product. Vendors move pages; run
 * `npm run links:verify -w apps/api` from a network that can reach the vendors to
 * re-check reachability (the build environment could not reach most vendor sites,
 * see BUILD_STATUS.md). Unknown services fall back to the W3C
 * "/.well-known/change-password" convention, which is labelled as unverified.
 */
export type ServiceCategory = 'email_identity' | 'financial' | 'social' | 'shopping' | 'developer' | 'productivity' | 'entertainment' | 'travel' | 'other';

export type CatalogService = {
  domain: string; // registrable domain used as the account key
  name: string;
  category: ServiceCategory;
  senderDomains?: string[]; // other registrable domains this service sends mail from
  securityUrl: string; // where password and two-step settings live
  passwordUrl?: string;
  mfaUrl?: string;
  activityUrl?: string;
  deleteUrl?: string;
};

export const SERVICE_CATALOG: CatalogService[] = [
  {
    domain: 'google.com', name: 'Google', category: 'email_identity', senderDomains: ['youtube.com'],
    securityUrl: 'https://myaccount.google.com/security',
    passwordUrl: 'https://myaccount.google.com/signinoptions/password',
    mfaUrl: 'https://myaccount.google.com/signinoptions/two-step-verification',
    activityUrl: 'https://myaccount.google.com/device-activity',
    deleteUrl: 'https://myaccount.google.com/delete-services-or-account',
  },
  {
    domain: 'microsoft.com', name: 'Microsoft', category: 'email_identity',
    senderDomains: ['microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'xbox.com'],
    securityUrl: 'https://account.microsoft.com/security',
    passwordUrl: 'https://account.live.com/password/change',
    activityUrl: 'https://account.live.com/activity',
    deleteUrl: 'https://account.live.com/closeaccount.aspx',
  },
  {
    domain: 'apple.com', name: 'Apple Account', category: 'email_identity', senderDomains: ['icloud.com'],
    securityUrl: 'https://account.apple.com/account/manage',
    deleteUrl: 'https://privacy.apple.com/',
  },
  {
    domain: 'yahoo.com', name: 'Yahoo', category: 'email_identity',
    securityUrl: 'https://login.yahoo.com/account/security',
  },
  {
    domain: 'facebook.com', name: 'Facebook', category: 'social', senderDomains: ['facebookmail.com'],
    securityUrl: 'https://accountscenter.facebook.com/password_and_security',
    activityUrl: 'https://www.facebook.com/settings?tab=security',
  },
  {
    domain: 'instagram.com', name: 'Instagram', category: 'social',
    securityUrl: 'https://accountscenter.instagram.com/password_and_security/',
  },
  {
    domain: 'x.com', name: 'X (Twitter)', category: 'social', senderDomains: ['twitter.com'],
    securityUrl: 'https://x.com/settings/security',
    passwordUrl: 'https://x.com/settings/password',
    mfaUrl: 'https://x.com/settings/account/login_verification',
    deleteUrl: 'https://x.com/settings/deactivate',
  },
  {
    domain: 'linkedin.com', name: 'LinkedIn', category: 'social',
    securityUrl: 'https://www.linkedin.com/mypreferences/d/categories/sign-in-and-security',
    passwordUrl: 'https://www.linkedin.com/mypreferences/d/change-password',
    mfaUrl: 'https://www.linkedin.com/mypreferences/d/two-step-verification',
    deleteUrl: 'https://www.linkedin.com/mypreferences/d/close-account',
  },
  {
    domain: 'reddit.com', name: 'Reddit', category: 'social', senderDomains: ['redditmail.com'],
    securityUrl: 'https://www.reddit.com/settings/account',
  },
  {
    domain: 'pinterest.com', name: 'Pinterest', category: 'social',
    securityUrl: 'https://www.pinterest.com/settings/security',
  },
  {
    domain: 'github.com', name: 'GitHub', category: 'developer',
    securityUrl: 'https://github.com/settings/security',
    activityUrl: 'https://github.com/settings/security-log',
    deleteUrl: 'https://github.com/settings/admin',
  },
  {
    domain: 'gitlab.com', name: 'GitLab', category: 'developer',
    securityUrl: 'https://gitlab.com/-/profile/account',
    passwordUrl: 'https://gitlab.com/-/user_settings/password/edit',
  },
  {
    domain: 'paypal.com', name: 'PayPal', category: 'financial',
    securityUrl: 'https://www.paypal.com/myaccount/security/',
  },
  {
    domain: 'amazon.com', name: 'Amazon', category: 'shopping',
    securityUrl: 'https://www.amazon.com/your-account',
    mfaUrl: 'https://www.amazon.com/a/settings/approval',
  },
  {
    domain: 'ebay.com', name: 'eBay', category: 'shopping',
    securityUrl: 'https://accountsettings.ebay.com/uas',
  },
  {
    domain: 'netflix.com', name: 'Netflix', category: 'entertainment',
    securityUrl: 'https://www.netflix.com/account',
  },
  {
    domain: 'spotify.com', name: 'Spotify', category: 'entertainment',
    securityUrl: 'https://www.spotify.com/account/overview/',
    passwordUrl: 'https://www.spotify.com/account/change-password/',
  },
  {
    domain: 'twitch.tv', name: 'Twitch', category: 'entertainment',
    securityUrl: 'https://www.twitch.tv/settings/security',
  },
  {
    domain: 'dropbox.com', name: 'Dropbox', category: 'productivity', senderDomains: ['dropboxmail.com'],
    securityUrl: 'https://www.dropbox.com/account/security',
  },
  {
    domain: 'adobe.com', name: 'Adobe', category: 'productivity',
    securityUrl: 'https://account.adobe.com/security',
  },
  {
    domain: 'canva.com', name: 'Canva', category: 'productivity',
    securityUrl: 'https://www.canva.com/settings/login-and-security',
  },
  {
    domain: 'slack.com', name: 'Slack', category: 'productivity',
    securityUrl: 'https://slack.com/account/settings',
  },
  {
    domain: 'zoom.us', name: 'Zoom', category: 'productivity',
    securityUrl: 'https://zoom.us/profile',
  },
  {
    domain: 'airbnb.com', name: 'Airbnb', category: 'travel',
    securityUrl: 'https://www.airbnb.com/account-settings/login-and-security',
  },
  {
    domain: 'uber.com', name: 'Uber', category: 'travel',
    securityUrl: 'https://account.uber.com/security',
  },
];

const byDomain = new Map<string, CatalogService>();
for (const s of SERVICE_CATALOG) {
  byDomain.set(s.domain, s);
  for (const d of s.senderDomains ?? []) byDomain.set(d, s);
}

export function lookupService(registrableDomain: string): CatalogService | undefined {
  return byDomain.get(registrableDomain);
}

/** Display name for a service we have no catalogue entry for, e.g. "shop-example.co.uk" -> "Shop-example". */
export function fallbackServiceName(domain: string): string {
  const label = domain.split('.')[0] ?? domain;
  return label.charAt(0).toUpperCase() + label.slice(1);
}

export type SecurityLink = { url: string; kind: 'curated_official' | 'well_known_standard' };

export function securityLink(domain: string, action: 'password' | 'mfa' | 'activity' | 'delete' | 'security'): SecurityLink | null {
  const s = lookupService(domain);
  if (s) {
    const url =
      (action === 'password' && s.passwordUrl) ||
      (action === 'mfa' && s.mfaUrl) ||
      (action === 'activity' && s.activityUrl) ||
      (action === 'delete' && s.deleteUrl) ||
      (action === 'delete' ? null : s.securityUrl);
    return url ? { url, kind: 'curated_official' } : null;
  }
  if (action === 'password') {
    return { url: `https://${domain}/.well-known/change-password`, kind: 'well_known_standard' };
  }
  return null;
}

/** Brand labels used by the look-alike heuristic (second-level labels of catalogue domains). */
export const BRAND_LABELS = Array.from(new Set(SERVICE_CATALOG.flatMap((s) => [s.domain, ...(s.senderDomains ?? [])]).map((d) => d.split('.')[0]))).filter(
  (l) => l.length >= 4,
);
export const BRAND_DOMAINS = new Set(SERVICE_CATALOG.flatMap((s) => [s.domain, ...(s.senderDomains ?? [])]));
