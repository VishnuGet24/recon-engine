# SF Recon Engine — Frontend ↔ Backend Integration Guide

**Scope:** React SPA integration with the JWT-authenticated API (`/api/*`)  
**Backend:** Flask (`backend/app.py`), `/api` routes in `backend/routes/api_routes.py`  
**Frontend reference implementation:** `recon_frontend/src/api/*`  
**Last updated:** 2026-03-16  
**Document version:** 1.0

---

## 1) Architecture overview

### Components

- **React SPA** (Vite) renders the UI and calls backend endpoints.
- **Flask backend** serves:
  - REST API under `/api/*` (Bearer JWT)
  - legacy session routes (cookies + CSRF) for older code paths
  - the built SPA bundle (`recon_frontend/dist`) in production
- **Database** persists users, scans, findings, audit logs (SQLAlchemy models in `backend/models.py`).

### Recommended integration choice

- **Use `/api/*` (JWT) for production-grade SPA integrations.**
- Legacy session routes remain supported, but are less convenient for a modern SPA because they require cookies + CSRF.

---

## 2) Data flow (high level)

1. User logs in via `POST /api/auth/login` → receive `accessToken` + `refreshToken`.
2. SPA stores tokens (recommended: `localStorage`) and uses `Authorization: Bearer ...` for all `/api/*` calls.
3. SPA fetches session context via `GET /api/auth/session` to populate current user + permissions.
4. User queues scans via `POST /api/scans`.
5. UI polls `GET /api/scans/{id}` until `status` becomes `completed`/`failed`/`cancelled`.
6. Findings are queried via `GET /api/findings` and updated via `PATCH /api/findings/{id}`.

---

## 3) Environment and base URLs

### Frontend env vars (Vite)

`recon_frontend/src/config/api.ts` supports:

```env
VITE_API_BASE_URL=http://localhost:5000/api
VITE_API_TIMEOUT=30000
VITE_WS_URL=ws://localhost:8000/ws
VITE_AUTH_TOKEN_KEY=sf_recon_auth_token
VITE_REFRESH_TOKEN_KEY=sf_recon_refresh_token
```

Notes:

- The backend default dev port is `5000` (`backend/app.py`) when using `flask run`.
- In Docker Compose, the recommended browser-facing base is `http://localhost/api` (Nginx reverse proxy).
- WebSocket (`/ws`) is **not implemented** in the current backend. Treat `VITE_WS_URL` as future-ready.

---

## 4) API client setup

The repo already includes a production-ready, fetch-based API client with automatic token refresh:

- `recon_frontend/src/api/client.ts` (`apiRequest`, refresh-on-401, error envelope parsing)
- `recon_frontend/src/api/auth.ts`, `recon_frontend/src/api/scans.ts`, `recon_frontend/src/api/findings.ts`, etc.

### Option A (recommended): use the existing fetch client

Example usage:

```ts
import { apiRequest } from '@/api/client';

export function getDashboardMetrics() {
  return apiRequest('/dashboard/metrics');
}
```

### Option B: Axios client (if you prefer interceptors)

The backend expects `Authorization: Bearer <accessToken>` and supports refresh via `POST /api/auth/refresh`.

```ts
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api',
  timeout: Number(import.meta.env.VITE_API_TIMEOUT) || 30000,
  headers: { Accept: 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sf_recon_auth_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(undefined, async (error) => {
  if (error?.response?.status !== 401) throw error;
  const refreshToken = localStorage.getItem('sf_recon_refresh_token');
  if (!refreshToken) throw error;

  const refreshed = await api.post('/auth/refresh', { refreshToken }, { headers: { Authorization: undefined } });
  localStorage.setItem('sf_recon_auth_token', refreshed.data.accessToken);
  localStorage.setItem('sf_recon_refresh_token', refreshed.data.refreshToken);

  error.config.headers.Authorization = `Bearer ${refreshed.data.accessToken}`;
  return api.request(error.config);
});
```

---

## 5) Authentication flow (JWT)

### Login

1. Call `POST /api/auth/login` with `{ email, password }`.
2. Store:
   - `tokens.accessToken`
   - `tokens.refreshToken`
   - optionally `user` for quick initial render
3. Load/validate session:
   - `GET /api/auth/session`

### Refresh

On a `401` from an API call:

- Call `POST /api/auth/refresh` with `{ refreshToken }`
- Retry the original request with the new access token

### Logout

- Call `POST /api/auth/logout` (optional server acknowledgement)
- Clear stored tokens

---

## 6) Scan management integration

### Create scan

- Endpoint: `POST /api/scans`
- Minimal body:

```json
{
  "targets": ["example.com"],
  "scanType": "quick_scan",
  "schedule": { "type": "immediate", "scheduledAt": null }
}
```

Important implementation detail (backend):

- The backend validates and normalizes **only `targets[0]`** today.

### Scan status polling

Use `GET /api/scans/{scanId}` and poll until terminal state:

- `completed`, `failed`, `cancelled` (terminal)
- `pending`, `queued`, `in_progress` (non-terminal)

Practical pattern with React Query:

```ts
import { useQuery } from '@tanstack/react-query';
import { getScanById } from '@/api/scans';

export function useScan(scanId: string) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScanById(scanId),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && ['completed', 'failed', 'cancelled'].includes(status) ? false : 2000;
    },
  });
}
```

### Cancel / retry

- `POST /api/scans/{scanId}/cancel`
- `POST /api/scans/{scanId}/retry`

---

## 7) Findings table integration

### List findings

Use `GET /api/findings` with filters:

- `scan_id` (or `scanId`)
- `severity`, `status`, `category`
- `page`, `limit`

React Query hook example:

```ts
import { useQuery } from '@tanstack/react-query';
import { getFindingsByScanId } from '@/api/findings';

export function useFindingsForScan(scanId: string, page = 1) {
  return useQuery({
    queryKey: ['findings', { scanId, page }],
    queryFn: () => getFindingsByScanId(scanId, { page, limit: 20 }),
    enabled: Boolean(scanId),
    keepPreviousData: true,
  });
}
```

### Update finding status

Endpoint: `PATCH /api/findings/{findingId}` with `{ status }`

Allowed values:

`open | investigating | mitigated | false_positive`

---

## 8) Risk score visualization

### Current API sources

- `GET /api/dashboard/metrics` — top-line current metrics (including a risk score value)
- `GET /api/dashboard/risk-trend` — historical series for charts
- `GET /api/scans/{scanId}` — includes `findings` summary and `raw` scan output (module-driven)

UI guidance:

- Prefer `dashboard/*` endpoints for dashboard charts/cards.
- Use `scan.raw` and `scan.discovery` for drill-down views.

---

## 9) Subdomain map visualization

Web UI typically needs nodes/edges (graph) or grouped lists (table).

### Current API source

- `GET /api/scans/{scanId}` → `discovery.subdomains` (normalized list)
- `GET /api/scans/{scanId}/raw` → module payloads (when present) under `results.modules.subdomain_enum`

Suggested mapping strategy:

- **Nodes:** target domain + discovered subdomains + resolved IPs + discovered URLs
- **Edges:** `target → subdomain`, `subdomain → ip`, `subdomain → url`

---

## 10) Real-time updates

### Current state (implementation reality)

The backend does **not** currently expose WebSocket/SSE endpoints. Implement real-time UX using:

- **Polling** (`refetchInterval` in React Query) for scan status and queue
- **Optimistic UI** for quick feedback (e.g., after starting a scan)

### Future-ready WebSocket event model (planned)

If `/ws` is introduced later, recommended event names:

- `scan.created`, `scan.updated`, `scan.completed`, `scan.failed`
- `finding.created`, `finding.updated`
- `notification.created`

Payload should include at least: `{ type, entityId, timestamp, data }`.

---

## 11) Error handling patterns

### API error envelope (recommended handling)

Most `/api/*` errors use:

```json
{ "error": { "code": "...", "message": "...", "details": [], "requestId": "..." } }
```

UI guidance:

- Show `error.message` in toast/snackbar.
- If `details` includes field-level validation, render inline form errors.
- Log `requestId` to correlate client errors with backend logs.

### 401 behavior

- Attempt refresh once (`POST /api/auth/refresh`).
- If refresh fails, clear tokens and redirect to login.

---

## 12) React Query integration (recommended defaults)

Suggested configuration:

- Use React Query for **server state** (everything fetched from `/api/*`).
- Use local component state (or a small store) for **UI state** (filters, table sort, modals).

Example `QueryClient` defaults:

```ts
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 10_000, refetchOnWindowFocus: false },
    mutations: { retry: 0 },
  },
});
```

---

## 13) State management suggestions

- **Auth state:** context + localStorage (tokens + minimal user snapshot).
- **Server state:** React Query.
- **Complex UI state:** optional lightweight store (e.g., Zustand) for global filters and layout state.

---

## Appendix — Legacy session + CSRF integration (still supported)

Some older frontend code paths call session-based routes (cookies + CSRF), e.g.:

- `POST /login`, `POST /logout`, `GET /me`
- `POST /scan`, `GET /scan`

If integrating with these endpoints:

- Use `credentials: 'include'` on `fetch`/Axios
- For non-GET requests, include `X-CSRF-Token` (obtain via `GET /csrf` or response header exposure)
