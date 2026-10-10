import { useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type Account, type Finding, type RemediationItem } from '../api';
import { Empty, ErrorState, FixtureBadge, formatDate, LevelBadge, Loading, MFA_LABEL, Notice, OWNERSHIP_LABEL, PageHeader, errorText, useTitle } from '../components/ui';
import { StatusActions } from './Remediation';

function useInvalidate() {
  const qc = useQueryClient();
  return () => {
    for (const k of ['accounts', 'account', 'dashboard', 'remediation', 'alerts']) void qc.invalidateQueries({ queryKey: [k] });
  };
}

const confidenceText = (c: number) => (c >= 0.8 ? 'High' : c >= 0.5 ? 'Medium' : 'Low');

export function Accounts() {
  const [search, setSearch] = useState('');
  const [showHidden, setShowHidden] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const invalidate = useInvalidate();
  const q = useQuery({ queryKey: ['accounts'], queryFn: () => api<{ accounts: Account[] }>('/api/accounts') });
  const add = useMutation({
    mutationFn: (domain: string) => api('/api/accounts', { method: 'POST', body: { domain } }),
    onSuccess: () => {
      setMsg({ kind: 'success', text: 'Account added to your inventory.' });
      invalidate();
    },
    onError: (e) => setMsg({ kind: 'error', text: errorText(e) }),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const term = search.trim().toLowerCase();
  const all = q.data.accounts;
  const hiddenCount = all.filter((a) => a.ownership === 'false_positive').length;
  const list = all.filter((a) => (showHidden || a.ownership !== 'false_positive') && (!term || a.service_name.toLowerCase().includes(term) || a.service_domain.includes(term)));

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const domain = String(new FormData(form).get('domain') ?? '');
    add.mutate(domain, { onSuccess: () => form.reset() });
  }

  return (
    <div>
      <PageHeader title="Accounts">
        Accounts found from email evidence or added by you. Discovery can miss accounts and can be wrong — correct anything that isn’t yours.
      </PageHeader>
      {msg && <Notice kind={msg.kind}>{msg.text}</Notice>}
      <section className="card">
        <div className="row spread">
          <div className="grow">
            <label htmlFor="acct-search" className="visually-hidden">Search accounts</label>
            <input id="acct-search" type="search" placeholder="Search accounts" value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>
          {hiddenCount > 0 && (
            <label className="checkbox">
              <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} /> Show {hiddenCount} marked “not mine”
            </label>
          )}
        </div>
        {all.length === 0 ? (
          <Empty title="No accounts yet" action={<Link className="btn btn-primary" to="/connections">Connect a mailbox</Link>}>
            Connect a mailbox to discover accounts, or add one you know about below.
          </Empty>
        ) : list.length === 0 ? (
          <p className="muted">No accounts match your search.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Risk</th>
                  <th>Source</th>
                  <th>Confidence</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {list.map((a) => (
                  <tr key={a.id}>
                    <td>
                      <Link to={`/accounts/${a.id}`}><strong>{a.service_name}</strong></Link>
                      <div className="hint">{a.service_domain}</div>
                      <FixtureBadge show={a.is_fixture} />
                    </td>
                    <td>
                      {a.risk_score === null ? <span className="muted">Excluded</span> : <><LevelBadge level={a.risk_level} /> <span className="muted">{a.risk_score}</span></>}
                    </td>
                    <td>{OWNERSHIP_LABEL[a.ownership]}</td>
                    <td>{a.ownership === 'discovered' ? confidenceText(Number(a.confidence)) : '—'}</td>
                    <td>{formatDate(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="card">
        <h2>Add an account manually</h2>
        <form onSubmit={submit} className="row" noValidate>
          <div className="grow">
            <label htmlFor="domain">Website domain</label>
            <input id="domain" name="domain" type="text" placeholder="example.com" required />
          </div>
          <button className="btn btn-primary" disabled={add.isPending}>
            Add account
          </button>
        </form>
      </section>
    </div>
  );
}

type AccountDetailData = {
  account: Account & { mfa_status: string };
  identities: string[];
  evidence: { id: string; source: string; evidence_type: string; signal: string; confidence: number; sender_domain: string | null; identity_email: string | null; observed_at: string; is_fixture: boolean }[];
  findings: (Finding & { details: Record<string, unknown> })[];
  remediation: (RemediationItem & { finding_id: string })[];
  catalog: { name: string; securityUrl: string } | null;
};

const EVIDENCE_TEXT: Record<string, string> = {
  account_creation: 'Account creation or verification email',
  security_notification: 'Security notification',
  password_reset: 'Password reset email',
  transactional: 'Receipt, order or account notice',
  marketing: 'Other email from the service (weak evidence)',
  user_reported: 'Added by you',
  breach_record: 'Email address found in a breach',
};

export function AccountDetail() {
  const { id = '' } = useParams();
  const invalidate = useInvalidate();
  const [msg, setMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const q = useQuery({ queryKey: ['account', id], queryFn: () => api<AccountDetailData>(`/api/accounts/${id}`) });
  useTitle(q.data?.account.service_name ?? 'Account');
  const update = useMutation({
    mutationFn: (body: Record<string, string>) => api(`/api/accounts/${id}`, { method: 'PATCH', body }),
    onSuccess: () => {
      setMsg({ kind: 'success', text: 'Saved. Your risk score was updated.' });
      invalidate();
    },
    onError: (e) => setMsg({ kind: 'error', text: errorText(e) }),
  });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const { account: a, findings, remediation, evidence, identities } = q.data;
  const active = findings.filter((f) => f.state !== 'inactive');
  const inactive = findings.filter((f) => f.state === 'inactive');

  return (
    <div className="stack">
      <p><Link to="/accounts">← All accounts</Link></p>
      <div className="page-header">
        <h1>{a.service_name}</h1>
        <div className="row">
          <span className="muted">{a.service_domain}</span>
          <span className="badge badge-plain">{OWNERSHIP_LABEL[a.ownership]}</span>
          <FixtureBadge show={a.is_fixture} />
          {a.risk_score !== null && <><LevelBadge level={a.risk_level} /> <span className="muted">Account risk {a.risk_score}/100</span></>}
        </div>
      </div>
      {msg && <Notice kind={msg.kind}>{msg.text}</Notice>}

      <section className="card">
        <h2>Is this your account?</h2>
        <p className="muted">
          {a.ownership === 'discovered' && `Found from ${evidence.length} email evidence item(s) — confidence ${confidenceText(Number(a.confidence)).toLowerCase()}.`}
          {a.ownership === 'false_positive' && 'You marked this as not yours. It is excluded from your score and future scans will skip it.'}
          {a.ownership === 'user_confirmed' && 'You confirmed this account is yours.'}
          {a.ownership === 'user_added' && 'You added this account yourself.'}
          {identities.length > 0 && ` Linked email: ${identities.join(', ')}.`}
        </p>
        <div className="row">
          {a.ownership === 'discovered' && (
            <button className="btn btn-small" disabled={update.isPending} onClick={() => update.mutate({ ownership: 'user_confirmed' })}>Yes, it’s mine</button>
          )}
          {(a.ownership === 'discovered' || a.ownership === 'user_confirmed') && (
            <button className="btn btn-small" disabled={update.isPending} onClick={() => update.mutate({ ownership: 'false_positive' })}>Not mine</button>
          )}
          {a.ownership === 'false_positive' && (
            <button className="btn btn-small" disabled={update.isPending} onClick={() => update.mutate({ ownership: 'discovered' })}>Restore</button>
          )}
        </div>
      </section>

      {a.ownership !== 'false_positive' && (
        <section className="card">
          <h2>Two-step verification</h2>
          <p className="muted">FootprintX cannot see this setting. Tell us what you know; it is recorded as user-reported.</p>
          <div className="field narrow">
            <label htmlFor="mfa">Status</label>
            {a.mfa_status === 'evidence_enabled' ? (
              <p id="mfa">{MFA_LABEL[a.mfa_status]}</p>
            ) : (
              <select id="mfa" value={a.mfa_status} disabled={update.isPending} onChange={(e) => update.mutate({ mfaStatus: e.target.value })}>
                <option value="unknown">Unknown</option>
                <option value="user_reported_enabled">On</option>
                <option value="user_reported_disabled">Off</option>
              </select>
            )}
          </div>
        </section>
      )}

      <section className="card">
        <h2>Findings</h2>
        {active.length === 0 ? (
          <p className="muted">No active findings.</p>
        ) : (
          <ul className="list">
            {active.map((f) => (
              <li key={f.id}>
                <div className="row">
                  <LevelBadge level={f.severity} />
                  <strong>{f.title}</strong>
                  {f.state !== 'open' && <span className="badge badge-plain">{f.state === 'mitigated_verified' ? 'Mitigated (verified)' : 'Mitigated (you reported)'}</span>}
                </div>
                <p>{f.explanation}</p>
                <details>
                  <summary>Score details ({f.contribution} points)</summary>
                  <pre className="table-wrap">{JSON.stringify(f.details, null, 2)}</pre>
                </details>
              </li>
            ))}
          </ul>
        )}
        {inactive.length > 0 && (
          <details>
            <summary>{inactive.length} past finding(s) no longer applicable</summary>
            <ul>{inactive.map((f) => <li key={f.id}>{f.title}</li>)}</ul>
          </details>
        )}
      </section>

      {a.ownership !== 'false_positive' && remediation.length > 0 && (
        <section className="card">
          <h2>Recommended actions</h2>
          <ul className="list">
            {remediation.map((r) => (
              <li key={r.id}>
                <strong>{r.title}</strong>
                <p className="muted">{r.description}</p>
                <StatusActions item={{ ...r, service_name: a.service_name }} />
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="card">
        <details>
          <summary>Evidence ({evidence.length})</summary>
          {evidence.length === 0 ? (
            <p className="muted">No email evidence.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Date</th><th>Type</th><th>From domain</th><th>Source</th></tr></thead>
                <tbody>
                  {evidence.map((e) => (
                    <tr key={e.id}>
                      <td>{formatDate(e.observed_at)}</td>
                      <td>{EVIDENCE_TEXT[e.evidence_type] ?? e.evidence_type}</td>
                      <td>{e.sender_domain ?? '—'}</td>
                      <td>{e.is_fixture ? 'Development fixture' : e.source === 'google' ? 'Gmail' : e.source === 'microsoft' ? 'Outlook' : e.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="hint">Only the sender domain, evidence type and date are stored — never subjects or message content.</p>
        </details>
      </section>
    </div>
  );
}
