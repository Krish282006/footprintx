import { lookupService, fallbackServiceName, type ServiceCategory } from '../catalog/services.js';
import { registrableDomainOf } from '../lib/domain.js';

/** Metadata FootprintX reads from a message. No bodies, no attachments. */
export type MessageMeta = {
  id: string;
  from: string; // raw From header, e.g. "GitHub <noreply@github.com>"
  subject: string;
  date: string; // ISO timestamp
};

export type EvidenceType = 'account_creation' | 'security_notification' | 'password_reset' | 'transactional' | 'marketing';

export type Classification = {
  serviceDomain: string;
  serviceName: string;
  category: ServiceCategory;
  senderDomain: string;
  evidenceType: EvidenceType;
  signal: string;
  confidence: number;
  observedAt: string;
};

type Rule = { type: EvidenceType; signal: string; confidence: number; pattern: RegExp };

// Ordered: the first matching rule wins. Security rules come first because e.g.
// "Your password was changed" must not be read as a reset request.
const RULES: Rule[] = [
  { type: 'security_notification', signal: 'account_closed', confidence: 0.9, pattern: /\b(your account (has been|was) (deleted|closed)|account (deletion|closure) (confirmed|complete)|we('ve| have) (deleted|closed) your account)\b/i },
  { type: 'security_notification', signal: 'password_changed', confidence: 0.9, pattern: /\b(your password (was|has been) (changed|updated|reset)|password (changed|updated) successfully|password change confirmation)\b/i },
  { type: 'security_notification', signal: 'mfa_enabled', confidence: 0.9, pattern: /\b((two|2)[- ]?(step|factor)( verification| authentication)?|2fa|mfa) (is (now )?|has been |was )?(turned on|enabled|activated|set up)\b/i },
  { type: 'security_notification', signal: 'suspicious_activity', confidence: 0.85, pattern: /\b(suspicious|unusual) (activity|sign[- ]?in|login|log[- ]?in attempt)|someone (may have )?(tried|accessed)|unauthori[sz]ed (access|login)/i },
  { type: 'security_notification', signal: 'new_signin', confidence: 0.85, pattern: /\b(new (sign[- ]?in|login|log[- ]?in|device)|sign[- ]?in (from|on) (a )?new|login (from|on) (a )?new|new browser)\b/i },
  { type: 'security_notification', signal: 'security_alert_generic', confidence: 0.8, pattern: /\bsecurity (alert|notice|notification)\b/i },
  { type: 'security_notification', signal: 'verification_code', confidence: 0.75, pattern: /\b(verification|security|login|sign[- ]?in|one[- ]?time) (code|pin)\b/i },
  { type: 'account_creation', signal: 'account_created', confidence: 0.9, pattern: /\b(welcome to|thanks? (you )?for (signing up|joining|registering|creating)|your (new )?account (has been|is|was) (created|ready|set up)|account created)\b/i },
  { type: 'account_creation', signal: 'confirm_email', confidence: 0.85, pattern: /\b(confirm|verify|activate) (your )?(e-?mail( address)?|account|registration|sign[- ]?up)\b|complete your (registration|sign[- ]?up)/i },
  { type: 'password_reset', signal: 'password_reset_request', confidence: 0.7, pattern: /\b(reset (your )?password|password reset|forgot (your )?password|recover your account)\b/i },
  { type: 'transactional', signal: 'receipt_or_order', confidence: 0.6, pattern: /\b(receipt|invoice|order (confirmation|#|number|confirmed)|your order|payment (received|confirmation|successful)|subscription (confirmed|renewal|renewed)|billing)\b/i },
  { type: 'transactional', signal: 'account_notice', confidence: 0.55, pattern: /\b(your account|account (update|statement|summary|settings)|terms of service|privacy policy update)\b/i },
];

// Free-mail domains: messages from people at these domains are not service evidence,
// unless the local part is clearly an automated account mailbox.
const FREEMAIL = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'icloud.com',
  'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com',
]);
const SYSTEM_LOCAL = /^(no-?reply|do-?not-?reply|account(s)?|security|alerts?|notifications?|info|support|verify|team|hello)([-+._].*)?$/i;

export function parseFrom(from: string): { local: string; domain: string } | null {
  const match = /<([^>]+)>/.exec(from);
  const addr = (match ? match[1] : from).trim().toLowerCase();
  const at = addr.lastIndexOf('@');
  if (at < 1 || at === addr.length - 1) return null;
  const domain = addr.slice(at + 1).replace(/[^a-z0-9.-]/g, '');
  if (!domain.includes('.')) return null;
  return { local: addr.slice(0, at), domain };
}

/**
 * Classifies one message's metadata as account evidence, or returns null when the
 * message is not evidence of an account (personal mail, unknown newsletters, ...).
 */
export function classifyMessage(msg: MessageMeta): Classification | null {
  const sender = parseFrom(msg.from);
  if (!sender) return null;
  const registrable = registrableDomainOf(sender.domain);
  if (!registrable) return null;
  const date = new Date(msg.date);
  if (Number.isNaN(date.getTime())) return null;

  const service = lookupService(registrable);
  if (FREEMAIL.has(registrable) && !service) {
    if (!SYSTEM_LOCAL.test(sender.local)) return null;
  }
  if (FREEMAIL.has(registrable) && service && !SYSTEM_LOCAL.test(sender.local)) {
    // e.g. a friend writing from outlook.com is not evidence of a Microsoft account.
    return null;
  }

  const subject = (msg.subject ?? '').slice(0, 500);
  const rule = RULES.find((r) => r.pattern.test(subject));
  let evidenceType: EvidenceType;
  let signal: string;
  let confidence: number;
  if (rule) {
    ({ type: evidenceType, signal, confidence } = rule);
  } else if (service && SYSTEM_LOCAL.test(sender.local)) {
    // Generic mail from a known service's system mailbox: weak evidence (could be a newsletter).
    evidenceType = 'marketing';
    signal = 'known_service_mail';
    confidence = 0.25;
  } else {
    return null;
  }

  const serviceDomain = service?.domain ?? registrable;
  return {
    serviceDomain,
    serviceName: service?.name ?? fallbackServiceName(serviceDomain),
    category: service?.category ?? 'other',
    senderDomain: sender.domain,
    evidenceType,
    signal,
    confidence,
    observedAt: date.toISOString(),
  };
}

/**
 * Account-existence confidence from all evidence: the strongest item, plus a small
 * bonus for each additional independent evidence type, capped at 0.99.
 */
export function accountConfidence(items: { evidenceType: string; confidence: number }[]): number {
  if (!items.length) return 0;
  const max = Math.max(...items.map((i) => i.confidence));
  const types = new Set(items.map((i) => i.evidenceType));
  return Math.min(0.99, Math.round((max + 0.05 * (types.size - 1)) * 1000) / 1000);
}
