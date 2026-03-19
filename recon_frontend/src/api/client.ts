import { API_CONFIG, AUTH_STORAGE_KEYS } from '../config/api';

export type ApiErrorDetail = { field: string; message: string };
export type ApiErrorEnvelope = {
  error: {
    code?: string;
    message?: string;
    details?: ApiErrorDetail[];
    timestamp?: string;
    requestId?: string;
  };
};

export class ApiError extends Error {
  status: number;
  code?: string;
  details?: ApiErrorDetail[];
  requestId?: string;
  payload?: unknown;

  constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;

    const envelope = payload as Partial<ApiErrorEnvelope> | undefined;
    this.code = envelope?.error?.code;
    this.details = envelope?.error?.details;
    this.requestId = envelope?.error?.requestId;
  }
}

type ApiRequestOptions = Omit<RequestInit, 'body' | 'headers'> & {
  headers?: Record<string, string>;
  body?: unknown;
  rawResponse?: boolean;
  disableAuthRefresh?: boolean;
};

let refreshInFlight: Promise<string | null> | null = null;

export function getAccessToken() {
  return localStorage.getItem(AUTH_STORAGE_KEYS.accessToken);
}

export function getRefreshToken() {
  return localStorage.getItem(AUTH_STORAGE_KEYS.refreshToken);
}

export function setTokens(tokens: { accessToken: string; refreshToken?: string }) {
  localStorage.setItem(AUTH_STORAGE_KEYS.accessToken, tokens.accessToken);
  if (tokens.refreshToken) {
    localStorage.setItem(AUTH_STORAGE_KEYS.refreshToken, tokens.refreshToken);
  }
}

export function clearTokens() {
  localStorage.removeItem(AUTH_STORAGE_KEYS.accessToken);
  localStorage.removeItem(AUTH_STORAGE_KEYS.refreshToken);
  localStorage.removeItem(AUTH_STORAGE_KEYS.user);
  window.dispatchEvent(new Event('auth:logout'));
}

function buildUrl(path: string) {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_CONFIG.baseURL}${cleanPath}`;
}

async function parsePayload(response: Response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  if (contentType.includes('text/')) {
    return response.text();
  }
  return response.arrayBuffer();
}

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    return null;
  }

  const response = await fetch(buildUrl('/auth/refresh'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ refreshToken }),
  });

  const payload = await parsePayload(response);
  if (!response.ok) {
    clearTokens();
    return null;
  }

  const accessToken = (payload as any)?.accessToken;
  const newRefreshToken = (payload as any)?.refreshToken;
  if (typeof accessToken !== 'string' || !accessToken) {
    clearTokens();
    return null;
  }

  setTokens({ accessToken, refreshToken: typeof newRefreshToken === 'string' ? newRefreshToken : undefined });
  return accessToken;
}

async function getRefreshedTokenOnce() {
  if (!refreshInFlight) {
    refreshInFlight = refreshAccessToken().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

export async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const {
    headers: userHeaders,
    body,
    rawResponse = false,
    disableAuthRefresh = false,
    method = 'GET',
    ...rest
  } = options;

  const headers: Record<string, string> = { Accept: 'application/json', ...(userHeaders || {}) };
  if (body !== undefined && body !== null && !(body instanceof FormData)) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }

  const token = getAccessToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const timeoutMs = API_CONFIG.timeout;
  const controller = !rest.signal ? new AbortController() : null;
  const timeoutId =
    controller && timeoutMs > 0
      ? window.setTimeout(() => controller.abort(), timeoutMs)
      : null;

  let response: Response;
  try {
    response = await fetch(buildUrl(path), {
      ...rest,
      signal: rest.signal || controller?.signal,
      method,
      headers,
      body: body === undefined || body === null || body instanceof FormData ? (body as any) : JSON.stringify(body),
    });
  } catch (error: any) {
    if (timeoutId) window.clearTimeout(timeoutId);
    const message = error?.name === 'AbortError' ? 'Request timed out' : 'Network error';
    throw new ApiError(message, 0, error);
  } finally {
    if (timeoutId) window.clearTimeout(timeoutId);
  }

  if (response.status === 401 && !disableAuthRefresh) {
    const refreshed = await getRefreshedTokenOnce();
    if (refreshed) {
      return apiRequest<T>(path, { ...options, disableAuthRefresh: true });
    }
  }

  if (rawResponse) {
    return response as unknown as T;
  }

  const payload = await parsePayload(response);
  if (!response.ok) {
    const message =
      (payload && typeof payload === 'object' && 'error' in (payload as any) && (payload as any).error?.message) ||
      response.statusText ||
      'Request failed';
    throw new ApiError(String(message), response.status, payload);
  }

  return payload as T;
}

export async function apiDownload(path: string, options: ApiRequestOptions = {}) {
  const response = await apiRequest<Response>(path, { ...options, rawResponse: true });
  if (!response.ok) {
    const payload = await parsePayload(response);
    const message =
      (payload && typeof payload === 'object' && 'error' in (payload as any) && (payload as any).error?.message) ||
      response.statusText ||
      'Download failed';
    throw new ApiError(String(message), response.status, payload);
  }
  return response;
}
