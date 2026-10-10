import { useState } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type RemediationItem, type RemediationStatus } from '../api';
import { Empty, ErrorState, FixtureBadge, LevelBadge, LinkKind, Loading, Notice, PageHeader, STATUS_LABEL, errorText } from '../components/ui';

function useInvalidateRisk() {
  const qc = useQueryClient();
  return () => {
    for (const k of ['remediation', 'dashboard', 'accounts', 'account', 'alerts']) void qc.invalidateQueries({ queryKey: [k] });
  };
}

/** Status controls for one recommendation. Only valid transitions are offered. */
export function StatusActions({ item, compact = false }: { item: RemediationItem; compact?: boolean }) {
  const invalidate = useInvalidateRisk();
  const [msg, setMsg] = useState<{ kind: 'error' | 'info'; text: string } | null>(null);
  const change = useMutation({
    mutationFn: (status: RemediationStatus) => api(`/api/remediation/${item.id}`, { method: 'PATCH', body: { status } }),
    onSuccess: () => {
      setMsg(null);
      invalidate();
    },
    onError: (e) => setMsg({ kind: 'error', text: errorText(e) }),
  });
  const verify = useMutation({
    mutationFn: () => api<{ status: RemediationStatus }>(`/api/remediation/${item.id}/verify`, { method: 'POST' }),
    onSuccess: (r) => {
      setMsg({ kind: 'info', text: `Verification result: ${STATUS_LABEL[r.status]}.` });
      invalidate();
    },
    onError: (e) => setMsg({ kind: 'error', text: errorText(e) }),
  });
  const busy = change.isPending || verify.isPending;
  const s = item.status;
  return (
    <div>
      <div className="row">
        {item.official_url && (
          <a className="btn btn-small btn-primary" href={item.official_url} target="_blank" rel="noopener noreferrer">
            Open {item.service_name} settings <span className="visually-hidden">(opens in a new tab)</span>
          </a>
        )}
        {s === 'recommended' && (
          <button className="btn btn-small" disabled={busy} onClick={() => change.mutate('in_progress')}>
            Start
          </button>
        )}
        {(s === 'recommended' || s === 'in_progress' || s === 'unable_to_verify') && (
          <button className="btn btn-small" disabled={busy} onClick={() => change.mutate('user_reported_complete')}>
            I’ve done this
          </button>
        )}
        {(s === 'user_reported_complete' || s === 'unable_to_verify') && item.verifiable && (
          <button className="btn btn-small" disabled={busy} onClick={() => verify.mutate()}>
            Check for confirmation
          </button>
        )}
        {(s === 'recommended' || s === 'in_progress') && !compact && (
          <button className="btn btn-small" disabled={busy} onClick={() => change.mutate('dismissed')}>
            Dismiss
          </button>
        )}
        {(s === 'dismissed' || s === 'verified_complete' || s === 'user_reported_complete' || s === 'unable_to_verify' || s === 'verification_pending') && !compact && (
          <button className="btn btn-small" disabled={busy} onClick={() => change.mutate('recommended')}>
            Reopen
          </button>
        )}
        <span className={`badge ${s === 'verified_complete' ? 'badge-green' : s === 'dismissed' ? 'badge-grey' : 'badge-plain'}`}>{STATUS_LABEL[s]}</span>
      </div>
      {item.official_url && <LinkKind kind={item.url_kind} />}
      {!item.official_url && <small className="muted">No verified link for this service — use its account settings.</small>}
      {item.status_note && <p className="hint">{item.status_note}</p>}
      {s === 'user_reported_complete' && <p className="hint">Recorded as reported by you. FootprintX cannot see changes on other websites{item.verifiable ? ' unless the service emails you a confirmation' : ''}.</p>}
      {msg && <Notice kind={msg.kind}>{msg.text}</Notice>}
    </div>
  );
}

const FILTERS: { key: string; label: string; match: (s: RemediationStatus) => boolean }[] = [
  { key: 'open', label: 'To do', match: (s) => s === 'recommended' || s === 'in_progress' },
  { key: 'done', label: 'Done', match: (s) => ['user_reported_complete', 'verification_pending', 'verified_complete', 'unable_to_verify'].includes(s) },
  { key: 'dismissed', label: 'Dismissed', match: (s) => s === 'dismissed' },
  { key: 'all', label: 'All', match: () => true },
];

export function Remediation() {
  const [filter, setFilter] = useState('open');
  const q = useQuery({ queryKey: ['remediation'], queryFn: () => api<{ items: RemediationItem[] }>('/api/remediation') });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const f = FILTERS.find((x) => x.key === filter)!;
  const items = q.data.items.filter((i) => f.match(i.status));
  return (
    <div>
      <PageHeader title="Remediation">Highest-impact actions first. Links open each service’s own security page — FootprintX never asks for your passwords.</PageHeader>
      <div className="tabs" role="group" aria-label="Filter recommendations">
        {FILTERS.map((x) => (
          <button key={x.key} className="btn btn-small" aria-pressed={filter === x.key} onClick={() => setFilter(x.key)}>
            {x.label} ({q.data.items.filter((i) => x.match(i.status)).length})
          </button>
        ))}
      </div>
      <section className="card">
        {items.length === 0 ? (
          <Empty title={filter === 'open' ? 'No open actions' : 'Nothing here'}>
            {q.data.items.length === 0 ? (
              <>Recommendations appear after accounts are discovered. <Link to="/connections">Connect a mailbox</Link>.</>
            ) : null}
          </Empty>
        ) : (
          <ul className="list">
            {items.map((i) => (
              <li key={i.id}>
                <div className="row">
                  {i.severity && <LevelBadge level={i.severity} />}
                  <strong>{i.title}</strong>
                  <FixtureBadge show={Boolean(i.is_fixture)} />
                </div>
                <p className="muted">{i.description}</p>
                <StatusActions item={i} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
