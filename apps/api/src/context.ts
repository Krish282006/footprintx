import type { Config } from './config.js';
import type { Db } from './db/pool.js';
import type { Mailer } from './email/mailer.js';
import type { FetchLike } from './lib/http.js';
import type { MailboxProvider, ProviderId } from './discovery/providers.js';
import type { ReputationService } from './threat/service.js';

export type AppContext = {
  config: Config;
  db: Db;
  mailer: Mailer;
  fetchImpl: FetchLike;
  providers: Record<ProviderId, MailboxProvider>;
  reputation: ReputationService;
  /** Multiplies rate-limit allowances (tests use a large value except in rate-limit tests). */
  rateLimitScale: number;
  /** Background work started by requests (scans); tests await these. */
  background: Set<Promise<unknown>>;
};

export function track(ctx: AppContext, p: Promise<unknown>) {
  ctx.background.add(p);
  p.finally(() => ctx.background.delete(p));
}
