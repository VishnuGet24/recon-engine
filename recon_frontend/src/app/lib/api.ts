import { API_BASE } from '../../config/api';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

let csrfToken: string | null = null;

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

export type UserRecord = {
  id: number;
  username: string;
  email: string;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  created_at: string | null;
};

export type SessionResponse = {
  user: UserRecord;
  session_user_id: number;
  csrf_token?: string;
};

export type ScanRecord = {
  id: number;
  user_id: number | null;
  target: string;
  scan_mode: string;
  status: string | null;
  risk_score: number | null;
  overall_risk: string | null;
  confidence_score: number | null;
  results: Record<string, any>;
  created_at: string | null;
  completed_at: string | null;
};

type RequestOptions = Omit<RequestInit, 'body'> & {
  body?: BodyInit | Record<string, unknown> | null;
  disableAuthRedirect?: boolean;
};

function readCsrfFromResponse(response: Response) {
  const headerToken = response.headers.get('X-CSRF-Token');
  if (headerToken) {
    csrfToken = headerToken;
  }
}

async function parseResponse(response: Response) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  const text = await response.text();
  return text ? { detail: text } : null;
}

async function ensureCsrfToken() {
  if (csrfToken) {
    return csrfToken;
  }

  const response = await fetch(`${API_BASE}/csrf`, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  readCsrfFromResponse(response);

  const payload = (await parseResponse(response)) as { csrf_token?: string } | null;
  if (!response.ok) {
    throw new ApiError('Failed to fetch CSRF token', response.status, payload);
  }

  csrfToken = payload?.csrf_token || csrfToken;
  if (!csrfToken) {
    throw new ApiError('CSRF token missing from backend response', 500, payload);
  }

  return csrfToken;
}

async function requestJson<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { disableAuthRedirect = false, headers: rawHeaders, body: rawBody, method = 'GET', ...rest } = options;
  const headers = new Headers(rawHeaders);
  const upperMethod = method.toUpperCase();
  let body = rawBody as BodyInit | null | undefined;

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  if (rawBody && !(rawBody instanceof FormData) && !(rawBody instanceof Blob) && typeof rawBody === 'object') {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(rawBody);
  }

  if (!SAFE_METHODS.has(upperMethod)) {
    headers.set('X-CSRF-Token', await ensureCsrfToken());
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...rest,
    method: upperMethod,
    body,
    headers,
    credentials: 'include',
  });

  readCsrfFromResponse(response);
  const payload = await parseResponse(response);

  if (!response.ok) {
    const message =
      (payload && typeof payload === 'object' && 'error' in payload && typeof payload.error === 'string' && payload.error) ||
      response.statusText ||
      'Request failed';

    if (response.status === 401 && !disableAuthRedirect) {
      window.location.assign('/login');
    }

    throw new ApiError(message, response.status, payload);
  }

  return payload as T;
}

export async function getSession() {
  const payload = await requestJson<SessionResponse>('/me', { disableAuthRedirect: true });
  csrfToken = payload.csrf_token || csrfToken;
  return payload;
}

export function listScans() {
  return requestJson<{ scans: ScanRecord[] }>('/scans');
}

export function getScanById(scanId: number) {
  return requestJson<{ scan: ScanRecord }>(`/scan/${scanId}`);
}

export function startScan(target: string, scanMode: 'passive' | 'active' | 'full') {
  return requestJson<{ scan: ScanRecord }>('/scan', {
    method: 'POST',
    body: { target, scan_mode: scanMode },
  });
}

export async function logoutRequest() {
  try {
    await requestJson<{ message: string }>('/logout', {
      method: 'POST',
      disableAuthRedirect: true,
    });
  } finally {
    csrfToken = null;
  }
}
