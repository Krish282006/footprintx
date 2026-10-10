import { Link } from 'react-router';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type Severity } from '../api';
import { Empty, ErrorState, formatDate, LevelBadge, Loading, PageHeader } from '../components/ui';

type Alert = { id: string; kind: string; severity: Severity; title: string; body: string; account_id: string | null; read_at: string | null; created_at: string };

export function Alerts() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['alerts'], queryFn: () => api<{ alerts: Alert[] }>('/api/alerts') });
  const read = useMutation({ mutationFn: (id: string) => api(`/api/alerts/${id}/read`, { method: 'POST' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) });
  const readAll = useMutation({ mutationFn: () => api('/api/alerts/read-all', { method: 'POST' }), onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const unread = q.data.alerts.filter((a) => !a.read_at).length;
  return (
    <div>
      <PageHeader title="Alerts">New important findings. In-app alerts are always on; email alerts are optional in <Link to="/settings#notifications">Settings</Link>.</PageHeader>
      <section className="card">
        {unread > 0 && (
          <p><button className="btn btn-small" onClick={() => readAll.mutate()} disabled={readAll.isPending}>Mark all as read</button></p>
        )}
        {q.data.alerts.length === 0 ? (
          <Empty title="No alerts">You will see new critical or high findings here.</Empty>
        ) : (
          <ul className="list">
            {q.data.alerts.map((a) => (
              <li key={a.id}>
                <div className="row spread">
                  <div className="row">
                    <LevelBadge level={a.severity} />
                    {a.account_id ? <Link to={`/accounts/${a.account_id}`}><strong>{a.title}</strong></Link> : <strong>{a.title}</strong>}
                    {!a.read_at && <span className="badge badge-plain">New</span>}
                  </div>
                  <small>{formatDate(a.created_at, true)}</small>
                </div>
                <p className="muted">{a.body}</p>
                {!a.read_at && <button className="btn btn-small" onClick={() => read.mutate(a.id)}>Mark as read</button>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
