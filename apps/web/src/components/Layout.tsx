import { useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { api } from '../api';
import { useAuth } from '../auth';

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/accounts', label: 'Accounts' },
  { to: '/remediation', label: 'Remediation' },
  { to: '/reports', label: 'Reports' },
  { to: '/extension', label: 'Extension' },
  { to: '/settings', label: 'Settings' },
];

export function Layout() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const alerts = useQuery({
    queryKey: ['alerts'],
    queryFn: () => api<{ alerts: { read_at: string | null }[] }>('/api/alerts'),
    enabled: Boolean(user),
  });
  const unread = alerts.data?.alerts.filter((a) => !a.read_at).length ?? 0;

  return (
    <>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <header className="app-header">
        <div className="header-inner">
          <Link to={user ? '/dashboard' : '/'} className="brand">
            <img src="/favicon.svg" alt="" /> FootprintX
          </Link>
          {user && (
            <>
              <button className="btn btn-small menu-toggle" aria-expanded={open} aria-controls="main-nav" onClick={() => setOpen((o) => !o)}>
                Menu
              </button>
              <nav id="main-nav" aria-label="Main" className={`nav${open ? ' open' : ''}`} onClick={() => setOpen(false)}>
                {NAV.map((n) => (
                  <NavLink key={n.to} to={n.to} className={({ isActive }) => (isActive ? 'active' : undefined)}>
                    {n.label}
                  </NavLink>
                ))}
              </nav>
              <div className="header-tools">
                <Link to="/alerts" className="btn btn-small" aria-label={`Alerts, ${unread} unread`}>
                  Alerts{unread > 0 && <span className="badge badge-critical">{unread}</span>}
                </Link>
                <Link to="/plan" className="badge badge-plain plan-chip" title="Your plan">
                  {user.plan === 'premium' ? 'Premium' : 'Free'}
                </Link>
                <button className="btn btn-small" onClick={() => void logout()}>
                  Sign out
                </button>
              </div>
            </>
          )}
          {!user && (
            <div className="header-tools push">
              {location.pathname !== '/login' && (
                <Link to="/login" className="btn btn-small">
                  Sign in
                </Link>
              )}
              {location.pathname !== '/register' && (
                <Link to="/register" className="btn btn-small btn-primary">
                  Create account
                </Link>
              )}
            </div>
          )}
        </div>
      </header>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <footer className="app-footer">
        <nav aria-label="Footer">
          <Link to="/privacy">Privacy</Link>
          <Link to="/dasi-method">How DASI works</Link>
          <Link to="/contact">Contact us</Link>
          {user && <Link to="/check">Check a site</Link>}
          {user && <Link to="/connections">Mailboxes</Link>}
          {user && <Link to="/plan">Plans</Link>}
        </nav>
        <div>FootprintX — Secure Your Digital Past. Protect Your Online Future.</div>
      </footer>
    </>
  );
}
