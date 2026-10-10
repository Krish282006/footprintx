import { useState, type FormEvent } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { api, type User } from '../api';
import { useAuth } from '../auth';
import { errorText, fieldErrors, Notice, PageHeader, useTitle } from '../components/ui';

export function Landing() {
  useTitle('Secure your digital past');
  const { user } = useAuth();
  const location = useLocation();
  if (user) return <Navigate to="/dashboard" replace />;
  const deleted = new URLSearchParams(location.search).get('deleted') === '1';
  return (
    <div>
      {deleted && <Notice kind="success">Your account and all its data were permanently deleted.</Notice>}
      <section className="hero">
        <h1>Secure your digital past. Protect your online future.</h1>
        <p className="tagline">
          FootprintX finds the online accounts your inbox shows you have, checks them against known breaches, scores your exposure with an
          explainable Digital Attack Surface Index (DASI), and tells you what to fix first.
        </p>
        <div className="row">
          <Link to="/register" className="btn btn-primary">
            Create a free account
          </Link>
          <Link to="/login" className="btn">
            Sign in
          </Link>
        </div>
      </section>
      <div className="grid grid-2">
        <section className="card">
          <h2>What FootprintX does</h2>
          <ul>
            <li>Builds an account inventory from email evidence you explicitly authorise (sender, subject and date only).</li>
            <li>Matches your services against public breach data and explains what it means for you.</li>
            <li>Calculates a 0–100 DASI score with every factor shown.</li>
            <li>Prioritises actions with links to each service’s official security page, and tracks your progress.</li>
            <li>Premium: a browser extension that warns about known-malicious and suspicious sites.</li>
          </ul>
        </section>
        <section className="card">
          <h2>What it does not claim</h2>
          <ul>
            <li>It cannot find every account you have — only those with evidence it can see.</li>
            <li>A breached service does not prove your own account was exposed.</li>
            <li>It cannot see your passwords or two-step settings, so changes you report are labelled “user-reported”.</li>
            <li>“No known threat” is not a guarantee that a website is safe. FootprintX is not antivirus software.</li>
          </ul>
          <p>
            <Link to="/privacy">Read how your data is handled</Link>
          </p>
        </section>
      </div>
    </div>
  );
}

export function Login() {
  useTitle('Sign in');
  const { user, setSession } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to="/dashboard" replace />;
  const from = (location.state as { from?: string } | null)?.from ?? '/dashboard';

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ user: User; csrfToken: string }>('/api/auth/login', { method: 'POST', body: { email: f.get('email'), password: f.get('password') } });
      setSession(res.user, res.csrfToken);
      navigate(from.startsWith('/') && !from.startsWith('//') ? from : '/dashboard', { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card auth-card">
      <h1>Sign in</h1>
      {error ? <Notice kind="error">{errorText(error)}</Notice> : null}
      <form onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="email" required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="current-password" required />
        </div>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p className="hint">
        <Link to="/forgot-password">Forgot your password?</Link> · <Link to="/register">Create an account</Link>
      </p>
    </div>
  );
}

export function Register() {
  useTitle('Create account');
  const { user, setSession } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  if (user) return <Navigate to="/dashboard" replace />;
  const fe = fieldErrors(error);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ user: User; csrfToken: string }>('/api/auth/register', {
        method: 'POST',
        body: { email: f.get('email'), password: f.get('password'), displayName: f.get('displayName') || undefined, acceptPrivacy: f.get('acceptPrivacy') === 'on' },
      });
      setSession(res.user, res.csrfToken);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card auth-card">
      <h1>Create your account</h1>
      <p className="muted">Free includes discovery, breach checks, DASI, remediation tracking and Excel reports.</p>
      {error && !Object.keys(fe).length ? <Notice kind="error">{errorText(error)}</Notice> : null}
      <form onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="email" required aria-invalid={Boolean(fe.email)} aria-describedby={fe.email ? 'email-err' : undefined} />
          {fe.email && <div id="email-err" className="field-error">{fe.email}</div>}
        </div>
        <div className="field">
          <label htmlFor="displayName">Name (optional)</label>
          <input id="displayName" name="displayName" type="text" autoComplete="name" />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="new-password" required minLength={12} aria-invalid={Boolean(fe.password)} aria-describedby="pw-hint" />
          <div id="pw-hint" className={fe.password ? 'field-error' : 'hint'}>{fe.password ?? 'At least 12 characters. A passphrase is easiest to remember.'}</div>
        </div>
        <div className="field">
          <label className="checkbox">
            <input type="checkbox" name="acceptPrivacy" aria-invalid={Boolean(fe.acceptPrivacy)} />
            <span>
              I have read the <Link to="/privacy" target="_blank">privacy notice</Link> and agree to FootprintX storing my account data as described.
            </span>
          </label>
          {fe.acceptPrivacy && <div className="field-error">{fe.acceptPrivacy}</div>}
        </div>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Creating account…' : 'Create account'}
        </button>
      </form>
      <p className="hint">
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}

export function ForgotPassword() {
  useTitle('Reset password');
  const [result, setResult] = useState<{ kind: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setResult(null);
    try {
      const res = await api<{ message: string; devMode: boolean }>('/api/auth/forgot-password', { method: 'POST', body: { email: f.get('email') } });
      setResult({ kind: res.devMode ? 'info' : 'success', text: res.message });
    } catch (err) {
      setResult({ kind: 'error', text: errorText(err) });
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="card auth-card">
      <h1>Reset your password</h1>
      {result && <Notice kind={result.kind}>{result.text}</Notice>}
      <form onSubmit={submit} noValidate>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="email" required />
        </div>
        <button className="btn btn-primary" disabled={busy}>
          {busy ? 'Sending…' : 'Send reset link'}
        </button>
      </form>
      <p className="hint">
        <Link to="/login">Back to sign in</Link>
      </p>
    </div>
  );
}

export function ResetPassword() {
  useTitle('Choose a new password');
  const token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? '';
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await api('/api/auth/reset-password', { method: 'POST', body: { token, password: f.get('password') } });
      setDone(true);
      history.replaceState(null, '', '/reset-password');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }
  if (!token && !done) {
    return (
      <div className="card auth-card">
        <h1>Reset link missing</h1>
        <p>Open the link from your reset email, or <Link to="/forgot-password">request a new one</Link>.</p>
      </div>
    );
  }
  return (
    <div className="card auth-card">
      <h1>Choose a new password</h1>
      {done ? (
        <Notice kind="success">
          Password updated. <Link to="/login">Sign in</Link>
        </Notice>
      ) : (
        <form onSubmit={submit} noValidate>
          {error ? <Notice kind="error">{errorText(error)}</Notice> : null}
          <div className="field">
            <label htmlFor="password">New password</label>
            <input id="password" name="password" type="password" autoComplete="new-password" minLength={12} required />
            <div className="hint">At least 12 characters. All other sessions will be signed out.</div>
          </div>
          <button className="btn btn-primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save new password'}
          </button>
        </form>
      )}
    </div>
  );
}

export function Privacy() {
  return (
    <div className="stack">
      <PageHeader title="Privacy notice">Version 2026-10-01. Plain-language summary of what FootprintX collects and why.</PageHeader>
      <section className="card">
        <h2>What we collect</h2>
        <ul>
          <li><strong>Your FootprintX account:</strong> email, optional name, a one-way (Argon2id) password hash, plan, and consent records.</li>
          <li><strong>Mailbox metadata, only if you connect a mailbox:</strong> sender, subject and date of messages are read to find account evidence. We store only the conclusion (service domain, evidence type, date) and a one-way hash of the message ID. Subjects and message bodies are not stored. We never request access to message bodies.</li>
          <li><strong>Your corrections and progress:</strong> accounts you confirm, add or mark “not mine”, and remediation statuses you set.</li>
          <li><strong>Premium extension:</strong> the extension sends only the hostname of the site you visit (not the path, page content, forms, cookies or credentials) for reputation checks. Results are cached without your identity. Warning events are synced only if you turn on sync.</li>
        </ul>
      </section>
      <section className="card">
        <h2>What we never collect</h2>
        <p>Passwords for other websites, one-time codes, two-step secrets, recovery codes, cookies, password-manager contents, or your browsing history.</p>
      </section>
      <section className="card">
        <h2>Consent and choices</h2>
        <ul>
          <li>Connecting a mailbox and receiving email notifications are separate choices; each has its own consent.</li>
          <li>Disconnect a mailbox at any time. We revoke access where the provider supports it and delete the evidence from that mailbox.</li>
          <li>Download all your data as an Excel workbook, or delete your account (which deletes all your data) from Settings.</li>
        </ul>
      </section>
      <section className="card">
        <h2>Retention</h2>
        <ul>
          <li>Account data: until you delete your account. Sessions expire after 7 days. Reset links expire after 1 hour.</li>
          <li>Mailbox tokens and evidence: until you disconnect the mailbox or delete your account.</li>
          <li>Domain-reputation cache: up to 12 hours, not linked to any user.</li>
          <li>Contact messages: kept to answer you; ask us to delete them at any time.</li>
        </ul>
        <p>
          Breach data comes from the public Have I Been Pwned breach list (CC BY 4.0). Questions? <Link to="/contact">Contact us</Link>.
        </p>
      </section>
    </div>
  );
}

export function DasiMethod() {
  const model = useQuery({ queryKey: ['dasi-model'], queryFn: () => api<Record<string, unknown>>('/api/dasi/model'), retry: false });
  return (
    <div className="stack">
      <PageHeader title="How DASI works">
        The Digital Attack Surface Index is a 0–100 score where higher means more observed risk. Every factor is shown on your dashboard.
      </PageHeader>
      <section className="card">
        <h2>For each account</h2>
        <ul>
          <li><strong>Breaches:</strong> points by the most sensitive data exposed (passwords 45, security answers/tokens 40, financial or ID data 35, contact data 15), multiplied by how strongly evidence ties your account to the breach, how recent it is, and how confident we are the account exists.</li>
          <li><strong>Recent security emails</strong> (new sign-ins, suspicious activity) in the last 90 days.</li>
          <li><strong>Two-step verification:</strong> unknown counts as risk. Reporting it on lowers, but does not remove, that risk.</li>
          <li><strong>Dormant accounts:</strong> no activity for two years adds a small amount.</li>
          <li>High-impact accounts (email, financial) weigh more.</li>
        </ul>
      </section>
      <section className="card">
        <h2>Overall score</h2>
        <p>DASI = 0.6 × your riskiest account + 0.4 × combined exposure across accounts + uncertainty (incomplete discovery or unavailable breach data).</p>
        <p>Levels: 0–24 low, 25–49 moderate, 50–74 high, 75–100 critical. With no evidence at all the score is “unknown”, not zero.</p>
        <p>Critical findings are always listed separately, even when the overall score is moderate.</p>
      </section>
      <section className="card">
        <h2>What your actions do</h2>
        <p>
          If you report changing a password after a breach, that breach’s points are halved and labelled “user-reported”. If a later mailbox
          scan finds a “your password was changed” email from that service, it is marked verified. Historical breach findings are never deleted.
        </p>
        {model.data ? (
          <details>
            <summary>Model constants ({String(model.data.version)})</summary>
            <pre className="table-wrap">{JSON.stringify(model.data, null, 2)}</pre>
          </details>
        ) : (
          <p className="muted">Sign in to view the exact model constants used by the server.</p>
        )}
      </section>
    </div>
  );
}
