import { useEffect, type ReactNode } from 'react';
import { ApiError, type Level, type Severity } from '../api';

export function useTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · FootprintX`;
  }, [title]);
}

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  useTitle(title);
  return (
    <div className="page-header">
      <h1>{title}</h1>
      {children && <p>{children}</p>}
    </div>
  );
}

export const formatDate = (v: string | null | undefined, withTime = false) =>
  v ? new Date(v).toLocaleString(undefined, withTime ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' }) : 'Unknown';

const LEVEL_TEXT: Record<string, string> = { low: 'Low', moderate: 'Moderate', high: 'High', critical: 'Critical', unknown: 'Unknown', medium: 'Medium', info: 'Info' };

export function LevelBadge({ level }: { level: Level | Severity | null | undefined }) {
  const l = level ?? 'unknown';
  return <span className={`badge badge-${l}`}>{LEVEL_TEXT[l] ?? l}</span>;
}

const REP_TEXT = { green: 'No known threat', red: 'Known malicious', amber: 'Suspicious', grey: 'Not checked' } as const;
const REP_ICON = { green: '✓', red: '✕', amber: '!', grey: '?' } as const;
export function ReputationBadge({ status }: { status: keyof typeof REP_TEXT }) {
  return (
    <span className={`badge badge-${status}`}>
      <span aria-hidden="true">{REP_ICON[status]}</span> {REP_TEXT[status]}
    </span>
  );
}

export function FixtureBadge({ show = true }: { show?: boolean }) {
  if (!show) return null;
  return (
    <span className="badge badge-fixture" title="Synthetic development data, not a real discovery">
      Development fixture
    </span>
  );
}

export function Notice({ kind = 'info', children, title }: { kind?: 'info' | 'success' | 'warning' | 'error'; children: ReactNode; title?: string }) {
  return (
    <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      {title && <strong>{title} </strong>}
      {children}
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="state" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" /> <span>{label}</span>
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const message = error instanceof ApiError ? error.message : 'Something went wrong.';
  return (
    <div className="notice notice-error" role="alert">
      <p>{message}</p>
      {retry && (
        <button className="btn btn-small" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state">
      <h2>{title}</h2>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function errorText(err: unknown): string {
  return err instanceof ApiError ? err.message : err ? 'Something went wrong. Please try again.' : '';
}

export function fieldErrors(err: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (err instanceof ApiError) for (const i of err.issues) out[i.path] ??= i.message;
  return out;
}

/** Semi-circular DASI gauge. Colour is never the only signal: the number and level are shown too. */
export function DasiGauge({ score, level }: { score: number | null; level: Level }) {
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score)) / 100;
  const r = 70;
  const len = Math.PI * r;
  return (
    <svg className="gauge" viewBox="0 0 168 104" role="img" aria-label={score === null ? 'DASI not yet calculated' : `DASI ${score} out of 100, ${LEVEL_TEXT[level]} risk`}>
      <path className="track" d="M14 90 A70 70 0 0 1 154 90" fill="none" strokeWidth="14" strokeLinecap="round" />
      <path className={`lvl-${level}`} d="M14 90 A70 70 0 0 1 154 90" fill="none" strokeWidth="14" strokeLinecap="round" strokeDasharray={`${len * pct} ${len}`} />
      <text x="84" y="80" textAnchor="middle" fontSize="34" fontWeight="700">{score ?? '—'}</text>
      <text x="84" y="100" textAnchor="middle" fontSize="11">of 100</text>
    </svg>
  );
}

export const STATUS_LABEL: Record<string, string> = {
  recommended: 'Recommended',
  in_progress: 'In progress',
  user_reported_complete: 'Done (you reported)',
  verification_pending: 'Verification pending',
  verified_complete: 'Verified complete',
  unable_to_verify: 'Unable to verify',
  dismissed: 'Dismissed',
};

export const OWNERSHIP_LABEL: Record<string, string> = {
  discovered: 'Found in email',
  user_confirmed: 'Confirmed by you',
  user_added: 'Added by you',
  false_positive: 'Marked not mine',
};

export const MFA_LABEL: Record<string, string> = {
  unknown: 'Unknown',
  user_reported_enabled: 'On (you reported)',
  user_reported_disabled: 'Off (you reported)',
  evidence_enabled: 'On (confirmation email found)',
};

export function LinkKind({ kind }: { kind: string | null }) {
  if (kind === 'curated_official') return <small className="muted">Official page (curated)</small>;
  if (kind === 'well_known_standard') return <small className="muted">Standard change-password address — this site may not support it</small>;
  return null;
}
