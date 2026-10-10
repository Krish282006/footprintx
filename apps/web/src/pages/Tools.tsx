import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, download, type Reputation } from '../api';
import { useAuth } from '../auth';
import { Empty, ErrorState, formatDate, LevelBadge, Loading, Notice, PageHeader, ReputationBadge, errorText, fieldErrors } from '../components/ui';

// ---- Reports & history ---------------------------------------------------------------------
export function Reports() {
  const [state, setState] = useState<{ kind: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const history = useQuery({
    queryKey: ['dasi-history'],
    queryFn: () => api<{ history: { id: string; score: number | null; level: string; coverage: string; reason: string; created_at: string; changes: { serviceName: string; from: number | null; to: number | null; reason: string }[] }[] }>('/api/dasi/history'),
  });

  async function get(path: string, name: string, label: string) {
    setBusy(path);
    setState({ kind: 'info', text: `Preparing ${label}…` });
    try {
      await download(path, name);
      setState({ kind: 'success', text: `${label} downloaded.` });
    } catch (err) {
      setState({ kind: 'error', text: `${label} could not be generated: ${errorText(err)}` });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="stack">
      <PageHeader title="Reports">Excel workbooks generated from your saved data. Development fixture rows are labelled in the file.</PageHeader>
      {state && <Notice kind={state.kind}>{state.text}</Notice>}
      <section className="card">
        <h2>Security report</h2>
        <p className="muted">Summary, accounts, risk findings, recommendations, DASI history and scans{' '}(plus security activity on Premium).</p>
        <button className="btn btn-primary" disabled={Boolean(busy)} onClick={() => get('/api/reports/security.xlsx', 'footprintx-report.xlsx', 'Security report')}>
          {busy === '/api/reports/security.xlsx' ? 'Generating…' : 'Download security report (.xlsx)'}
        </button>
      </section>
      <section className="card">
        <h2>DASI history</h2>
        {history.isPending ? (
          <Loading />
        ) : history.isError ? (
          <ErrorState error={history.error} retry={() => history.refetch()} />
        ) : history.data.history.length === 0 ? (
          <p className="muted">No score history yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Date</th><th className="num">DASI</th><th>Level</th><th>Reason</th></tr></thead>
              <tbody>
                {history.data.history.map((h) => (
                  <tr key={h.id}>
                    <td>{formatDate(h.created_at, true)}</td>
                    <td className="num">{h.score ?? '—'}</td>
                    <td><LevelBadge level={h.level as 'low'} /></td>
                    <td>
                      {h.reason}
                      {h.changes.length > 0 && (
                        <details>
                          <summary>{h.changes.length} change(s)</summary>
                          <ul>{h.changes.map((c, i) => <li key={i}>{c.serviceName}: {c.from ?? '—'} → {c.to ?? '—'} — {c.reason}</li>)}</ul>
                        </details>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

// ---- Manual domain check (Free) ---------------------------------------------------------------
export function ReputationResult({ r }: { r: Reputation }) {
  return (
    <section className={`card rep rep-${r.status}`} aria-live="polite">
      <div className="row">
        <ReputationBadge status={r.status} />
        <strong>{r.displayDomain ?? r.domain}</strong>
      </div>
      <h2>{r.summary}</h2>
      <ul>{r.reasons.map((x) => <li key={x}>{x}</li>)}</ul>
      {r.nextSteps.length > 0 && (
        <>
          <h3>What to do</h3>
          <ul>{r.nextSteps.map((x) => <li key={x}>{x}</li>)}</ul>
        </>
      )}
      <details>
        <summary>Sources checked</summary>
        <ul>
          {r.providers.map((p) => (
            <li key={p.provider}>
              {p.provider}: {p.outcome === 'error' ? `unavailable (${p.error})` : p.outcome.replace('_', ' ')}
            </li>
          ))}
        </ul>
        {r.checkedAt && <p className="hint">Checked {formatDate(r.checkedAt, true)}{r.fromCache ? ' (cached)' : ''}.</p>}
      </details>
      {r.limitations && <p className="hint">{r.limitations}</p>}
    </section>
  );
}

export function DomainCheck() {
  const check = useMutation({ mutationFn: (domain: string) => api<{ result: Reputation }>('/api/domain-check', { method: 'POST', body: { domain } }) });
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    check.mutate(String(new FormData(e.currentTarget).get('domain') ?? ''));
  }
  return (
    <div className="stack">
      <PageHeader title="Check a site">Look up a website against FootprintX’s configured threat sources. Only the hostname is checked.</PageHeader>
      <section className="card">
        <form onSubmit={submit} className="row" noValidate>
          <div className="grow">
            <label htmlFor="domain">Website or link</label>
            <input id="domain" name="domain" type="text" placeholder="example.com" required />
          </div>
          <button className="btn btn-primary" disabled={check.isPending}>{check.isPending ? 'Checking…' : 'Check'}</button>
        </form>
      </section>
      {check.isError && <Notice kind="error">{errorText(check.error)}</Notice>}
      {check.data && <ReputationResult r={check.data.result} />}
    </div>
  );
}

// ---- Contact --------------------------------------------------------------------------------
export function Contact() {
  const { user } = useAuth();
  const opened = useRef(Date.now());
  const send = useMutation({
    mutationFn: (body: Record<string, unknown>) => api<{ status: string; message: string }>('/api/contact', { method: 'POST', body }),
  });
  const fe = fieldErrors(send.error);
  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    send.mutate({
      name: f.get('name'), email: f.get('email'), subject: f.get('subject'), message: f.get('message'),
      website: f.get('website') || undefined, elapsedMs: Date.now() - opened.current,
    });
  }
  return (
    <div className="stack">
      <PageHeader title="Contact us">Questions, feedback or a privacy request? Send us an email. Please don’t include passwords or codes.</PageHeader>
      <section className="card">
        {send.isSuccess ? (
          <Notice kind={send.data.status === 'sent' ? 'success' : 'info'}>{send.data.message}</Notice>
        ) : (
          <form onSubmit={submit} noValidate>
            {send.isError && !Object.keys(fe).length && <Notice kind="error">{errorText(send.error)}</Notice>}
            <div className="grid grid-2">
              <div className="field">
                <label htmlFor="c-name">Name</label>
                <input id="c-name" name="name" type="text" autoComplete="name" defaultValue={user?.displayName ?? ''} required aria-invalid={Boolean(fe.name)} />
                {fe.name && <div className="field-error">{fe.name}</div>}
              </div>
              <div className="field">
                <label htmlFor="c-email">Your email</label>
                <input id="c-email" name="email" type="email" autoComplete="email" defaultValue={user?.email ?? ''} required aria-invalid={Boolean(fe.email)} />
                {fe.email && <div className="field-error">{fe.email}</div>}
              </div>
            </div>
            <div className="field">
              <label htmlFor="c-subject">Subject</label>
              <input id="c-subject" name="subject" type="text" required aria-invalid={Boolean(fe.subject)} />
              {fe.subject && <div className="field-error">{fe.subject}</div>}
            </div>
            <div className="field">
              <label htmlFor="c-message">Message</label>
              <textarea id="c-message" name="message" required aria-invalid={Boolean(fe.message)} />
              {fe.message && <div className="field-error">{fe.message}</div>}
            </div>
            <div className="hp" aria-hidden="true">
              <label htmlFor="c-website">Leave this empty</label>
              <input id="c-website" name="website" type="text" tabIndex={-1} autoComplete="off" />
            </div>
            <button className="btn btn-primary" disabled={send.isPending}>{send.isPending ? 'Sending…' : 'Send message'}</button>
          </form>
        )}
      </section>
    </div>
  );
}

// ---- Plans ------------------------------------------------------------------------------------
type PlanInfo = { plan: 'free' | 'premium'; planSource: string; features: { free: string[]; premium: string[] }; billing: { configured: boolean; message: string }; devEntitlementsEnabled: boolean };

export function Plan() {
  const { refresh } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['plan'], queryFn: () => api<PlanInfo>('/api/plan') });
  const setPlan = useMutation({
    mutationFn: (plan: 'free' | 'premium') => api('/api/dev/plan', { method: 'POST', body: { plan } }),
    onSuccess: async () => {
      await refresh();
      await qc.invalidateQueries();
    },
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const p = q.data;
  return (
    <div className="stack">
      <PageHeader title="Plans">Every Free feature is fully available — there are no account or scan limits to push you to upgrade.</PageHeader>
      <p>
        Your plan: <strong>{p.plan === 'premium' ? 'Premium' : 'Free'}</strong>
        {p.planSource === 'development' && <span className="badge badge-fixture">Development entitlement — no payment</span>}
      </p>
      <div className="grid grid-2">
        <section className="card">
          <h2>Free</h2>
          <ul>{p.features.free.map((f) => <li key={f}>{f}</li>)}</ul>
        </section>
        <section className="card">
          <h2>Premium</h2>
          <ul>{p.features.premium.map((f) => <li key={f}>{f}</li>)}</ul>
          <Notice kind="info">{p.billing.message}</Notice>
        </section>
      </div>
      {p.devEntitlementsEnabled && (
        <section className="card">
          <h2>Development entitlement</h2>
          <p className="muted">This server allows switching plans for local testing. It is not a purchase and is disabled in production.</p>
          {setPlan.isError && <Notice kind="error">{errorText(setPlan.error)}</Notice>}
          <button className="btn" disabled={setPlan.isPending} onClick={() => setPlan.mutate(p.plan === 'premium' ? 'free' : 'premium')}>
            {p.plan === 'premium' ? 'Switch back to Free' : 'Enable Premium for development'}
          </button>
        </section>
      )}
    </div>
  );
}

// ---- Extension -----------------------------------------------------------------------------------
type SecurityEvent = { id: string; domain: string; status: 'red' | 'amber'; reasons: string[]; action: string; occurred_at: string };

export function Extension() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const premium = user?.plan === 'premium';
  const tokens = useQuery({ queryKey: ['ext-tokens'], queryFn: () => api<{ tokens: { id: string; label: string; created_at: string; last_used_at: string | null }[] }>('/api/extension/tokens') });
  const events = useQuery({ queryKey: ['security-events'], queryFn: () => api<{ events: SecurityEvent[]; syncEnabled: boolean }>('/api/security-events'), enabled: premium });
  const code = useMutation({ mutationFn: () => api<{ code: string; expiresAt: string }>('/api/extension/link-code', { method: 'POST' }) });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/api/extension/tokens/${id}`, { method: 'DELETE' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['ext-tokens'] }) });
  const sync = useMutation({
    mutationFn: (enabled: boolean) => api<{ enabled: boolean }>('/api/security-events/sync', { method: 'PUT', body: { enabled } }),
    onSuccess: (r) => qc.setQueryData<{ events: SecurityEvent[]; syncEnabled: boolean }>(['security-events'], (old) => (old ? { ...old, syncEnabled: r.enabled } : old)),
  });
  const [syncOn, setSyncOn] = useState(false);
  useEffect(() => {
    if (events.data) setSyncOn(events.data.syncEnabled);
  }, [events.data]);
  const clear = useMutation({ mutationFn: () => api('/api/security-events', { method: 'DELETE' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['security-events'] }) });

  return (
    <div className="stack">
      <PageHeader title="Browser extension">
        Premium protection: the extension checks the sites you visit against FootprintX’s threat sources and warns you about known-malicious or suspicious sites.
      </PageHeader>
      {!premium && (
        <Notice kind="info">
          Protection requires Premium. You can link the extension now; it will show “Premium required” until your plan includes protection. <Link to="/plan">See plans</Link>
        </Notice>
      )}
      <section className="card">
        <h2>1. Install</h2>
        <p>Build and load the extension as described in the README (<code>npm run build -w apps/extension</code>, then load <code>apps/extension/dist</code> as an unpacked extension in Chrome or Edge).</p>
        <h2>2. Link it to your account</h2>
        <p className="muted">Create a one-time code and enter it in the extension popup. Codes expire after 10 minutes.</p>
        {code.data ? (
          <p>
            <span className="code-box" aria-label="Link code">{code.data.code}</span>
            <span className="hint"> Expires {formatDate(code.data.expiresAt, true)}</span>
          </p>
        ) : null}
        {code.isError && <Notice kind="error">{errorText(code.error)}</Notice>}
        <button className="btn btn-primary" onClick={() => code.mutate()} disabled={code.isPending}>{code.data ? 'Create a new code' : 'Create link code'}</button>
      </section>
      <section className="card">
        <h2>Linked browsers</h2>
        {tokens.isPending ? <Loading /> : tokens.isError ? <ErrorState error={tokens.error} /> : tokens.data.tokens.length === 0 ? (
          <p className="muted">No browsers linked.</p>
        ) : (
          <ul className="list">
            {tokens.data.tokens.map((t) => (
              <li key={t.id} className="row spread">
                <span><strong>{t.label}</strong> <span className="hint">linked {formatDate(t.created_at)} · last used {t.last_used_at ? formatDate(t.last_used_at, true) : 'never'}</span></span>
                <button className="btn btn-small btn-danger" onClick={() => revoke.mutate(t.id)} disabled={revoke.isPending}>Unlink</button>
              </li>
            ))}
          </ul>
        )}
      </section>
      {premium && (
        <section className="card">
          <h2>Security events</h2>
          <p className="muted">
            When sync is on, the extension sends only warnings (known-malicious or suspicious sites): the hostname, the reason and what you did.
            Normal browsing is never sent.
          </p>
          {events.isPending ? <Loading /> : events.isError ? <ErrorState error={events.error} /> : (
            <>
              <label className="checkbox">
                <input type="checkbox" checked={syncOn}
                  onChange={(e) => {
                    const v = e.target.checked;
                    setSyncOn(v);
                    sync.mutate(v, { onError: () => setSyncOn(!v) });
                  }} disabled={sync.isPending} />
                <span>Sync warning events from my linked browsers</span>
              </label>
              {sync.isError && <Notice kind="error">{errorText(sync.error)}</Notice>}
              {events.data.events.length === 0 ? (
                <Empty title="No security events" />
              ) : (
                <>
                  <div className="table-wrap">
                    <table>
                      <thead><tr><th>When</th><th>Site</th><th>Status</th><th>Action</th></tr></thead>
                      <tbody>
                        {events.data.events.map((e) => (
                          <tr key={e.id}>
                            <td>{formatDate(e.occurred_at, true)}</td>
                            <td>{e.domain}<div className="hint">{e.reasons.join(' ')}</div></td>
                            <td><ReputationBadge status={e.status} /></td>
                            <td>{e.action.replace('_', ' ')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <button className="btn btn-small btn-danger" onClick={() => clear.mutate()} disabled={clear.isPending}>Delete event history</button>
                </>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}
