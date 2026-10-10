import { Link } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { api, type Change, type Dasi, type Finding, type RemediationItem } from '../api';
import { DasiGauge, Empty, ErrorState, FixtureBadge, formatDate, LevelBadge, Loading, Notice, PageHeader } from '../components/ui';
import { StatusActions } from './Remediation';

type DashboardData = {
  dasi: Dasi;
  topFindings: Finding[];
  nextActions: RemediationItem[];
  recentChanges: { score: number | null; level: string; changes: Change[]; reason: string; created_at: string }[];
  counts: { accounts: number; fixture_accounts: number; open_actions: number; unread_alerts: number; connections: number; running_scans: number };
  breachData: { available: boolean; lastSuccess: string | null; lastError: string | null };
};

const MEANING: Record<string, string> = {
  low: 'Little observed risk right now. Keep two-step verification on and re-scan occasionally.',
  moderate: 'Some exposure worth fixing. Start with the actions below.',
  high: 'Significant exposure. The actions below will reduce it the most.',
  critical: 'Serious exposure. Act on the critical findings first.',
  unknown: 'No score yet — FootprintX needs evidence before it can measure your exposure.',
};

export function Dashboard() {
  const q = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => api<DashboardData>('/api/dashboard'),
    // While a scan runs, refresh every 2 seconds so results appear without reloading.
    refetchInterval: (query) => ((query.state.data?.counts.running_scans ?? 0) > 0 ? 2000 : false),
  });

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const d = q.data;
  const { dasi } = d;

  return (
    <div>
      <PageHeader title="Dashboard" />
      {d.counts.fixture_accounts > 0 && (
        <Notice kind="info" title="Development fixture data.">
          Some accounts come from the development fixture mailbox. They are synthetic test data, not real discoveries.
        </Notice>
      )}
      {d.counts.running_scans > 0 && (
        <Notice kind="info">
          <span className="spinner" aria-hidden="true" /> A mailbox scan is running. Results will appear here automatically.
        </Notice>
      )}
      {!d.breachData.available && (
        <Notice kind="warning" title="Breach data unavailable.">
          The breach catalogue could not be loaded{d.breachData.lastError ? ` (${d.breachData.lastError})` : ''}, so breach exposure is not checked. Your score includes an uncertainty allowance for this.
        </Notice>
      )}

      <div className="grid grid-dash">
        <section className="card" aria-labelledby="dasi-h">
          <h2 id="dasi-h">Digital Attack Surface Index</h2>
          <div className="dasi">
            <DasiGauge score={dasi.score} level={dasi.level} />
            <div className="score-meaning">
              <p>
                <LevelBadge level={dasi.level} /> <span className="muted">Higher means more observed risk.</span>
              </p>
              <p>{MEANING[dasi.level]}</p>
              {dasi.coverage !== 'complete' && dasi.score !== null && (
                <p className="muted">Discovery is {dasi.coverage === 'none' ? 'not complete' : 'partial'}, so some accounts may be missing.</p>
              )}
            </div>
          </div>
          {dasi.notes.map((n) => (
            <p key={n} className="muted">{n}</p>
          ))}
          {dasi.components.length > 0 && (
            <details>
              <summary>Why this score?</summary>
              <table>
                <thead>
                  <tr><th>Factor</th><th className="num">Points</th></tr>
                </thead>
                <tbody>
                  {dasi.components.map((c) => (
                    <tr key={c.key}>
                      <td>
                        {c.label}
                        <div className="hint">{c.explanation}</div>
                      </td>
                      <td className="num">{c.points}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="hint">
                Model {dasi.modelVersion}. <Link to="/dasi-method">How DASI works</Link>
              </p>
            </details>
          )}
          <p className="hint">
            <Link to="/connections">Manage mailboxes</Link> · <Link to="/check">Check a site</Link>
          </p>
          {d.counts.connections === 0 && (
            <p>
              <Link to="/connections" className="btn btn-primary">Connect a mailbox to discover accounts</Link>
            </p>
          )}
        </section>

        <section className="card" aria-labelledby="actions-h">
          <div className="row spread">
            <h2 id="actions-h">Recommended next actions</h2>
            {d.counts.open_actions > 3 && <Link to="/remediation">All {d.counts.open_actions} actions</Link>}
          </div>
          {d.nextActions.length === 0 ? (
            <Empty title="Nothing to do right now">{d.counts.accounts ? 'You have no open recommendations.' : 'Recommendations appear once accounts are discovered.'}</Empty>
          ) : (
            <ul className="list">
              {d.nextActions.map((a) => (
                <li key={a.id}>
                  <strong>{a.title}</strong>
                  <p className="muted">{a.description}</p>
                  <StatusActions item={a} compact />
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card" aria-labelledby="findings-h">
        <div className="row spread">
          <h2 id="findings-h">Highest-priority findings</h2>
          {dasi.criticalFindingCount > 0 && <span className="badge badge-critical">{dasi.criticalFindingCount} critical</span>}
        </div>
        {d.topFindings.length === 0 ? (
          <Empty title="No unresolved high-priority findings" />
        ) : (
          <ul className="list">
            {d.topFindings.map((f) => (
              <li key={f.id}>
                <div className="row">
                  <LevelBadge level={f.severity} />
                  <Link to={`/accounts/${f.account_id}`}><strong>{f.title}</strong></Link>
                  <FixtureBadge show={Boolean(f.is_fixture)} />
                </div>
                <details>
                  <summary>Explanation</summary>
                  <p>{f.explanation}</p>
                </details>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card" aria-labelledby="changes-h">
        <h2 id="changes-h">Recent changes</h2>
        {d.recentChanges.length === 0 ? (
          <p className="muted">No score changes yet.</p>
        ) : (
          <ul className="list">
            {d.recentChanges.map((s) => (
              <li key={s.created_at}>
                <div className="row spread">
                  <strong>{s.reason}</strong>
                  <small>{formatDate(s.created_at, true)} · DASI {s.score ?? '—'}</small>
                </div>
                <ul>
                  {s.changes.slice(0, 4).map((c, i) => (
                    <li key={i}>
                      {c.serviceName}: {c.from === null && c.to === null ? c.reason : `${c.from ?? '—'} → ${c.to ?? '—'}`}
                    </li>
                  ))}
                  {s.changes.length > 4 && <li className="muted">and {s.changes.length - 4} more</li>}
                </ul>
              </li>
            ))}
          </ul>
        )}
        <p>
          <Link to="/reports">Full score history</Link>
        </p>
      </section>
    </div>
  );
}
