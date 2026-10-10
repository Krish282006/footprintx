import { useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, download } from '../api';
import { useAuth } from '../auth';
import { ErrorState, Loading, Notice, PageHeader, errorText } from '../components/ui';

type Prefs = {
  preferences: { emailSecurityAlerts: boolean; emailRemediationReminders: boolean; emailPeriodicSummary: boolean; emailConsentAt: string | null };
  emailDelivery: { configured: boolean; mode: string };
};

function Notifications() {
  const { user } = useAuth();
  const q = useQuery({ queryKey: ['prefs'], queryFn: () => api<Prefs>('/api/notifications/preferences') });
  const [form, setForm] = useState({ emailSecurityAlerts: false, emailRemediationReminders: false, emailPeriodicSummary: false, emailConsent: false });
  const save = useMutation({ mutationFn: () => api('/api/notifications/preferences', { method: 'PUT', body: form }), onSuccess: () => q.refetch() });
  useEffect(() => {
    if (q.data) setForm({ ...q.data.preferences, emailConsent: Boolean(q.data.preferences.emailConsentAt) });
  }, [q.data]);
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorState error={q.error} />;
  const anyOn = form.emailSecurityAlerts || form.emailRemediationReminders || form.emailPeriodicSummary;
  const toggle = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.checked }));
  return (
    <section className="card" id="notifications" aria-labelledby="notif-h">
      <h2 id="notif-h">Email notifications</h2>
      <p className="muted">Optional and off by default. In-app alerts and extension warnings work either way. Unchanged findings are never re-sent, and there is no email after every scan.</p>
      {!q.data.emailDelivery.configured && <Notice kind="warning">Email delivery is not configured on this server, so no emails will be sent even if you opt in.</Notice>}
      {q.data.emailDelivery.mode === 'devlog' && <Notice kind="info">Development mode: emails are written to the local development outbox, not delivered.</Notice>}
      <form
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <label className="checkbox"><input type="checkbox" checked={form.emailSecurityAlerts} onChange={toggle('emailSecurityAlerts')} /> Important new security findings</label>
        <label className="checkbox"><input type="checkbox" checked={form.emailRemediationReminders} onChange={toggle('emailRemediationReminders')} /> Weekly reminders for high-priority actions still open</label>
        <label className="checkbox"><input type="checkbox" checked={form.emailPeriodicSummary} onChange={toggle('emailPeriodicSummary')} /> Weekly summary (only when something changed)</label>
        {anyOn && !q.data.preferences.emailConsentAt && (
          <label className="checkbox"><input type="checkbox" checked={form.emailConsent} onChange={toggle('emailConsent')} /> I agree that FootprintX may email {user?.email} about my security.</label>
        )}
        {save.isError && <Notice kind="error">{errorText(save.error)}</Notice>}
        {save.isSuccess && <Notice kind="success">Notification preferences saved.</Notice>}
        <button className="btn btn-primary" disabled={save.isPending}>Save preferences</button>
      </form>
    </section>
  );
}

function ChangePassword() {
  const m = useMutation({ mutationFn: (body: Record<string, FormDataEntryValue | null>) => api<{ message: string }>('/api/auth/change-password', { method: 'POST', body }) });
  return (
    <section className="card" aria-labelledby="pw-h">
      <h2 id="pw-h">Change password</h2>
      {m.isSuccess && <Notice kind="success">{m.data.message}</Notice>}
      {m.isError && <Notice kind="error">{errorText(m.error)}</Notice>}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          m.mutate({ currentPassword: f.get('currentPassword'), newPassword: f.get('newPassword') }, { onSuccess: () => (e.target as HTMLFormElement).reset() });
        }}
      >
        <div className="grid grid-2">
          <div className="field"><label htmlFor="cur">Current password</label><input id="cur" name="currentPassword" type="password" autoComplete="current-password" required /></div>
          <div className="field"><label htmlFor="new">New password</label><input id="new" name="newPassword" type="password" autoComplete="new-password" minLength={12} required /></div>
        </div>
        <button className="btn" disabled={m.isPending}>Change password</button>
      </form>
    </section>
  );
}

function PrivacyControls() {
  const { clearSession } = useAuth();
  const [exportMsg, setExportMsg] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const [exporting, setExporting] = useState(false);
  const del = useMutation({
    mutationFn: (body: Record<string, FormDataEntryValue | null>) => api<{ revocations: { provider: string; result: string }[] }>('/api/privacy/delete-account', { method: 'POST', body }),
    onSuccess: () => {
      clearSession();
      // Full reload: the server session no longer exists, so start from a clean state.
      window.location.replace('/?deleted=1');
    },
  });
  return (
    <section className="card" aria-labelledby="privacy-h">
      <h2 id="privacy-h">Your data</h2>
      <p className="muted">
        See the <Link to="/privacy">privacy notice</Link>. Manage mailbox access in <Link to="/connections">Connected mailboxes</Link>.
      </p>
      {exportMsg && <Notice kind={exportMsg.kind}>{exportMsg.text}</Notice>}
      <button
        className="btn"
        disabled={exporting}
        onClick={async () => {
          setExporting(true);
          try {
            await download('/api/privacy/export.xlsx', 'footprintx-data-export.xlsx');
            setExportMsg({ kind: 'success', text: 'Your data export was downloaded.' });
          } catch (err) {
            setExportMsg({ kind: 'error', text: `Export failed: ${errorText(err)}` });
          } finally {
            setExporting(false);
          }
        }}
      >
        {exporting ? 'Preparing…' : 'Download all my data (.xlsx)'}
      </button>
      <details>
        <summary>Delete my account</summary>
        <p>This permanently deletes your FootprintX account and all data: accounts, evidence, findings, history, alerts and extension links. Mailbox access is revoked where the provider supports it.</p>
        {del.isError && <Notice kind="error">{errorText(del.error)}</Notice>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            del.mutate({ password: f.get('password'), confirm: f.get('confirm') });
          }}
        >
          <div className="grid grid-2">
            <div className="field"><label htmlFor="del-pw">Password</label><input id="del-pw" name="password" type="password" autoComplete="current-password" required /></div>
            <div className="field"><label htmlFor="del-confirm">Type DELETE to confirm</label><input id="del-confirm" name="confirm" type="text" autoComplete="off" required /></div>
          </div>
          <button className="btn btn-danger" disabled={del.isPending}>Permanently delete account</button>
        </form>
      </details>
    </section>
  );
}

export function Settings() {
  const { user } = useAuth();
  return (
    <div className="stack">
      <PageHeader title="Settings" />
      <section className="card">
        <h2>Account</h2>
        <p>Signed in as <strong>{user?.email}</strong> · Plan: <Link to="/plan">{user?.plan === 'premium' ? 'Premium' : 'Free'}</Link></p>
        <p><Link to="/connections">Connected mailboxes</Link> · <Link to="/extension">Browser extension</Link></p>
      </section>
      <Notifications />
      <ChangePassword />
      <PrivacyControls />
    </div>
  );
}
