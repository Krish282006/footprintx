import { StrictMode, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError } from './api';
import { AuthProvider, useAuth } from './auth';
import { Layout } from './components/Layout';
import { Loading, PageHeader } from './components/ui';
import { DasiMethod, ForgotPassword, Landing, Login, Privacy, Register, ResetPassword } from './pages/Public';
import { Dashboard } from './pages/Dashboard';
import { Connections } from './pages/Connections';
import { AccountDetail, Accounts } from './pages/Accounts';
import { Remediation } from './pages/Remediation';
import { Alerts } from './pages/Alerts';
import { Contact, DomainCheck, Extension, Plan, Reports } from './pages/Tools';
import { Settings } from './pages/Settings';
import './styles.css';

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Loading />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function NotFound() {
  return <PageHeader title="Page not found">The page you asked for does not exist.</PageHeader>;
}

export function AppRoutes() {
  const { loading } = useAuth();
  if (loading) return <Loading />;
  const p = (el: ReactNode) => <RequireAuth>{el}</RequireAuth>;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Landing />} />
        <Route path="login" element={<Login />} />
        <Route path="register" element={<Register />} />
        <Route path="forgot-password" element={<ForgotPassword />} />
        <Route path="reset-password" element={<ResetPassword />} />
        <Route path="privacy" element={<Privacy />} />
        <Route path="dasi-method" element={<DasiMethod />} />
        <Route path="contact" element={<Contact />} />
        <Route path="dashboard" element={p(<Dashboard />)} />
        <Route path="connections" element={p(<Connections />)} />
        <Route path="accounts" element={p(<Accounts />)} />
        <Route path="accounts/:id" element={p(<AccountDetail />)} />
        <Route path="remediation" element={p(<Remediation />)} />
        <Route path="alerts" element={p(<Alerts />)} />
        <Route path="reports" element={p(<Reports />)} />
        <Route path="check" element={p(<DomainCheck />)} />
        <Route path="extension" element={p(<Extension />)} />
        <Route path="plan" element={p(<Plan />)} />
        <Route path="settings" element={p(<Settings />)} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
        refetchOnWindowFocus: true,
        staleTime: 5_000,
      },
    },
  });
}

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={makeQueryClient()}>
        <BrowserRouter>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </StrictMode>,
  );
}
