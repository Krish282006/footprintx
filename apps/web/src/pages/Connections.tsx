import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api';
import { Empty, ErrorState, FixtureBadge, formatDate, Loading, Notice, PageHeader, errorText } from '../components/ui';

type Provider = { id: string; label: string; scopes: string[]; configured: boolean; isFixture: boolean };
type Consent = Record<'version' | 'accessed' | 'why' | 'stored' | 'limits' | 'disconnect' | 'notEmailNotifications', string>;
type Scan = { id: string; status: string; messages_examined: number; evidence_found: number; accounts_new: number; error_code: string | null; error_message: string | null; started_at: string; finished_at: string | null; is_fixture: boolean };
type Connection = { id: string; provider: string; email_address: string; status: string; last_scan_at: string | null; latest_scan: Scan | null };

const CALLBACK_MSG: Record<string, string> = {
  access_denied: 'You declined access, so no mailbox was connected.',
  invalid_state: 'The sign-in link expired or was already used. Please try again.',
  connection_failed: 'The provider could not complete the connection. Please try again later.',
  provider_error: 'The provider returned an error. Please try again.',
  invalid_callback: 'The sign-in response was invalid. Please try again.',
};

const SCAN_TEXT: Record<string, string> = {
  running: 'Scanning…',
  completed: 'Completed',
  partial: 'Partially completed',
  failed: 'Failed',
};

export function Connections() {
  const qc = useQueryClient();
  const [params] = useSearchParams();
  const [consent, setConsent] = useState(false);
  const [message, setMessage] = useState<{ kind: 'success' | 'error' | 'info'; text: string } | null>(null);
  const providers = useQuery({ queryKey: ['providers'], queryFn: () => api<{ providers: Provider[]; consent: Consent }>('/api/connections/providers') });
  const conns = useQuery({
    queryKey: ['connections'],
    queryFn: () => api<{ connections: Connection[] }>('/api/connections'),
    refetchInterval: (q) => (q.state.data?.connections.some((c) => c.latest_scan?.status === 'running') ? 2000 : false),
  });
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['connections'] });
    void qc.invalidateQueries({ queryKey: ['dashboard'] });
    void qc.invalidateQueries({ queryKey: ['accounts'] });
  };
  const body = { consent: true, consentVersion: providers.data?.consent.version };

  const connect = useMutation({
    mutationFn: async (p: Provider) => {
      if (p.isFixture) return api('/api/connections/devfixture', { method: 'POST', body });
      const r = await api<{ authorizationUrl: string }>(`/api/connections/oauth/${p.id}/start`, { method: 'POST', body });
      window.location.assign(r.authorizationUrl);
      return null;
    },
    onSuccess: (r) => {
      if (r) setMessage({ kind: 'info', text: 'Development fixture mailbox connected. Scanning synthetic messages…' });
      invalidate();
    },
    onError: (e) => setMessage({ kind: 'error', text: errorText(e) }),
  });
  const rescan = useMutation({
    mutationFn: (id: string) => api(`/api/connections/${id}/scan`, { method: 'POST' }),
    onSuccess: () => {
      setMessage({ kind: 'info', text: 'Scan started.' });
      invalidate();
    },
    onError: (e) => setMessage({ kind: 'error', text: errorText(e) }),
  });
  const disconnect = useMutation({
    mutationFn: ({ id, purge }: { id: string; purge: boolean }) => api<{ revocation: string; purgedAccounts: number; note?: string }>(`/api/connections/${id}?purge=${purge}`, { method: 'DELETE' }),
    onSuccess: (r) => {
      setMessage({ kind: 'success', text: `Mailbox disconnected.${r.purgedAccounts ? ` Removed ${r.purgedAccounts} account(s) that had no other evidence.` : ''}${r.note ? ` ${r.note}` : ''}` });
      invalidate();
    },
    onError: (e) => setMessage({ kind: 'error', text: errorText(e) }),
  });

  if (providers.isPending || conns.isPending) return <Loading />;
  if (providers.isError) return <ErrorState error={providers.error} retry={() => providers.refetch()} />;
  if (conns.isError) return <ErrorState error={conns.error} retry={() => conns.refetch()} />;
  const c = providers.data.consent;
  const cbError = params.get('error');
  const connected = params.get('connected');

  return (
    <div className="stack">
      <PageHeader title="Connected mailboxes">Connect one or more mailboxes so FootprintX can find evidence of your online accounts.</PageHeader>
      {connected && <Notice kind="success">Mailbox connected. The first scan has started.</Notice>}
      {cbError && <Notice kind="error">{CALLBACK_MSG[cbError] ?? 'The connection did not complete.'}</Notice>}
      {message && <Notice kind={message.kind}>{message.text}</Notice>}

      <section className="card">
        <h2>Your mailboxes</h2>
        {conns.data.connections.length === 0 ? (
          <Empty title="No mailbox connected">Connect a mailbox below to start discovering accounts.</Empty>
        ) : (
          <ul className="list">
            {conns.data.connections.map((conn) => {
              const s = conn.latest_scan;
              return (
                <li key={conn.id}>
                  <div className="row spread">
                    <div>
                      <strong>{conn.email_address}</strong> {conn.provider !== 'devfixture' && <span className="badge badge-plain">{conn.provider === 'google' ? 'Gmail' : 'Outlook'}</span>}{' '}
                      <FixtureBadge show={conn.provider === 'devfixture'} />
                      {conn.status === 'reauth_required' && <span className="badge badge-amber">Reconnect needed</span>}
                    </div>
                    <div className="row">
                      <button className="btn btn-small" disabled={s?.status === 'running' || rescan.isPending} onClick={() => rescan.mutate(conn.id)}>
                        Scan again
                      </button>
                      <button
                        className="btn btn-small btn-danger"
                        disabled={disconnect.isPending}
                        onClick={() => {
                          if (window.confirm('Disconnect this mailbox? FootprintX will revoke access where possible and delete the evidence gathered from it.')) {
                            disconnect.mutate({ id: conn.id, purge: true });
                          }
                        }}
                      >
                        Disconnect
                      </button>
                    </div>
                  </div>
                  {s ? (
                    <p className="hint">
                      Last scan: <strong>{SCAN_TEXT[s.status] ?? s.status}</strong> · {formatDate(s.started_at, true)} · {s.messages_examined} messages examined ·{' '}
                      {s.evidence_found} new evidence · {s.accounts_new} new accounts
                      {s.status === 'partial' && ' — some messages could not be read, so results are incomplete.'}
                      {s.status === 'failed' && ` — ${s.error_code === 'reauth_required' ? 'access expired; disconnect and connect again.' : 'the provider could not be reached.'}`}
                    </p>
                  ) : (
                    <p className="hint">Not scanned yet.</p>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="card" aria-labelledby="consent-h">
        <h2 id="consent-h">Connect a mailbox</h2>
        <dl>
          <dt><strong>What is accessed</strong></dt>
          <dd>{c.accessed}</dd>
          <dt><strong>Why</strong></dt>
          <dd>{c.why}</dd>
          <dt><strong>What is stored</strong></dt>
          <dd>{c.stored}</dd>
          <dt><strong>Limits</strong></dt>
          <dd>{c.limits}</dd>
          <dt><strong>Disconnecting</strong></dt>
          <dd>{c.disconnect}</dd>
        </dl>
        <p className="muted">{c.notEmailNotifications}</p>
        <label className="checkbox">
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>I authorise FootprintX to read message metadata (sender, subject, date) from the mailbox I choose, as described above.</span>
        </label>
        <div className="row" role="group" aria-label="Mailbox providers">
          {providers.data.providers.map((p) => (
            <div key={p.id}>
              <button className={`btn ${p.isFixture ? '' : 'btn-primary'}`} disabled={!consent || !p.configured || connect.isPending} onClick={() => connect.mutate(p)}>
                {p.isFixture ? 'Use development fixture mailbox' : `Connect ${p.label}`}
              </button>
              {!p.configured && <div className="hint">Not configured on this server</div>}
              {p.isFixture && <div className="hint">Synthetic messages for local testing — not your mailbox</div>}
            </div>
          ))}
        </div>
        {!consent && <p className="hint">Tick the authorisation box to enable the connect buttons.</p>}
      </section>
      <p>
        <Link to="/accounts">View discovered accounts</Link>
      </p>
    </div>
  );
}
