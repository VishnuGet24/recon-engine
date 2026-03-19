import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from 'react';

import { getAccessToken } from '../../api/client';
import { getSession, login as loginRequest, logout as logoutRequest, ApiUser, SessionResponse } from '../../api/auth';

type AuthContextValue = {
  loading: boolean;
  session: SessionResponse | null;
  user: ApiUser | null;
  permissions: string[];
  refreshSession: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<SessionResponse | null>(null);

  const refreshSession = async () => {
    const token = getAccessToken();
    if (!token) {
      setSession(null);
      setLoading(false);
      return;
    }

    try {
      const next = await getSession();
      setSession(next);
    } catch {
      setSession(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshSession();
  }, []);

  useEffect(() => {
    const onLogout = () => setSession(null);
    window.addEventListener('auth:logout', onLogout);
    return () => window.removeEventListener('auth:logout', onLogout);
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const response = await loginRequest(email, password);
      setSession({ user: response.user, permissions: response.permissions, sessionExpiry: null });
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    await logoutRequest();
    setSession(null);
    window.location.assign('/signin');
  };

  const value = useMemo(
    () => ({
      loading,
      session,
      user: session?.user ?? null,
      permissions: session?.permissions ?? [],
      refreshSession,
      login,
      logout,
    }),
    [loading, session],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return value;
}
