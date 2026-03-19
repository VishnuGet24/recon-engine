import { AUTH_STORAGE_KEYS } from '../config/api';
import { apiRequest, clearTokens, setTokens } from './client';

export type ApiUser = {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'viewer' | 'operator';
  avatar?: string;
  organizationId?: string;
};

export type SessionResponse = {
  user: ApiUser;
  permissions: string[];
  sessionExpiry: string | null;
};

export type LoginResponse = {
  user: ApiUser;
  tokens: { accessToken: string; refreshToken: string; expiresIn: number };
  permissions: string[];
};

export async function login(email: string, password: string) {
  const response = await apiRequest<LoginResponse>('/auth/login', {
    method: 'POST',
    body: { email, password },
    disableAuthRefresh: true,
  });

  setTokens({ accessToken: response.tokens.accessToken, refreshToken: response.tokens.refreshToken });
  localStorage.setItem(AUTH_STORAGE_KEYS.user, JSON.stringify(response.user));
  return response;
}

export async function getSession() {
  return apiRequest<SessionResponse>('/auth/session');
}

export async function logout() {
  try {
    await apiRequest<{ message: string }>('/auth/logout', { method: 'POST', disableAuthRefresh: true });
  } finally {
    clearTokens();
  }
}

