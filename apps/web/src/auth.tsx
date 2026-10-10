import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api, setCsrf, type User } from './api';

type AuthState = {
  user: User | null;
  loading: boolean;
  refresh: () => Promise<void>;
  setSession: (user: User, csrf: string) => void;
  logout: () => Promise<void>;
  clearSession: () => void;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const qc = useQueryClient();

  const refresh = useCallback(async () => {
    try {
      const me = await api<{ user: User | null; csrfToken: string | null }>('/api/auth/me');
      setCsrf(me.csrfToken);
      setUser(me.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const setSession = useCallback((u: User, csrf: string) => {
    setCsrf(csrf);
    setUser(u);
  }, []);

  const clearSession = useCallback(() => {
    setCsrf(null);
    setUser(null);
    qc.clear();
  }, [qc]);

  const logout = useCallback(async () => {
    try {
      await api('/api/auth/logout', { method: 'POST' });
    } finally {
      setCsrf(null);
      setUser(null);
      qc.clear();
    }
  }, [qc]);

  return <AuthContext.Provider value={{ user, loading, refresh, setSession, logout, clearSession }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
