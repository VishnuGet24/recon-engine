const rawApiBase = (import.meta.env.VITE_API_BASE || '').replace(/\/$/, '');
const rawApiBaseUrl = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

function defaultWsUrl() {
  if (typeof window === 'undefined') return '';
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}/ws`;
}

export const API_CONFIG = {
  baseURL: rawApiBaseUrl || (rawApiBase ? `${rawApiBase}/api` : '/api'),
  timeout: Number.parseInt(import.meta.env.VITE_API_TIMEOUT || '', 10) || 30000,
  wsURL: (import.meta.env.VITE_WS_URL || '').trim() || defaultWsUrl(),
};

export const AUTH_STORAGE_KEYS = {
  accessToken: (import.meta.env.VITE_AUTH_TOKEN_KEY || 'sf_recon_auth_token').trim(),
  refreshToken: (import.meta.env.VITE_REFRESH_TOKEN_KEY || 'sf_recon_refresh_token').trim(),
  user: 'sf_recon_user',
};

// Legacy export retained for older session/csrf client code paths.
export const API_BASE = rawApiBase || rawApiBaseUrl.replace(/\/api$/, '');
