import nodemailer from 'nodemailer';
import type { Config } from '../config.js';
import type { Db } from '../db/pool.js';
import { logger } from '../lib/logger.js';

export type MailMessage = { to: string; subject: string; text: string; replyTo?: string };
export type DeliveryStatus = 'sent' | 'failed' | 'not_configured' | 'dev_logged';
export type DeliveryResult = { status: DeliveryStatus; error?: string };

export interface Mailer {
  readonly mode: 'none' | 'smtp' | 'devlog';
  isConfigured(): boolean;
  send(msg: MailMessage): Promise<DeliveryResult>;
}

/** Strips anything that looks like credentials from provider error text before storing it. */
function sanitizeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.replace(/(pass(word)?|auth|user)[=:]\S+/gi, '$1=[REDACTED]').slice(0, 300);
}

export function createMailer(config: Config, db: Db): Mailer {
  if (config.EMAIL_PROVIDER === 'smtp') {
    const configured = Boolean(config.SMTP_HOST);
    const transport = configured
      ? nodemailer.createTransport({
          host: config.SMTP_HOST,
          port: config.SMTP_PORT,
          secure: config.SMTP_SECURE,
          auth: config.SMTP_USER ? { user: config.SMTP_USER, pass: config.SMTP_PASS } : undefined,
          connectionTimeout: 10_000,
          greetingTimeout: 10_000,
          socketTimeout: 15_000,
          // Allow self-signed only for local test servers; never in production.
          tls: config.NODE_ENV === 'production' ? undefined : { rejectUnauthorized: false },
        })
      : null;
    return {
      mode: 'smtp',
      isConfigured: () => configured,
      async send(msg) {
        if (!transport) return { status: 'not_configured', error: 'SMTP_HOST is not set' };
        try {
          await transport.sendMail({ from: config.EMAIL_FROM, to: msg.to, subject: msg.subject, text: msg.text, replyTo: msg.replyTo });
          return { status: 'sent' };
        } catch (err) {
          const error = sanitizeError(err);
          logger.warn({ error }, 'email delivery failed');
          return { status: 'failed', error };
        }
      },
    };
  }
  if (config.EMAIL_PROVIDER === 'devlog') {
    return {
      mode: 'devlog',
      isConfigured: () => true,
      async send(msg) {
        // DEVELOPMENT ONLY: record the message locally; nothing is delivered.
        try {
          await db.query('INSERT INTO dev_outbox (to_address, subject, body) VALUES ($1, $2, $3)', [msg.to, msg.subject, msg.text]);
          logger.info({ to: msg.to, subject: msg.subject }, '[devlog] email recorded in dev_outbox (not delivered)');
          return { status: 'dev_logged' };
        } catch (err) {
          return { status: 'failed', error: sanitizeError(err) };
        }
      },
    };
  }
  return {
    mode: 'none',
    isConfigured: () => false,
    async send() {
      return { status: 'not_configured', error: 'Email delivery is not configured' };
    },
  };
}
