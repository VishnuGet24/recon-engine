# SF Recon Engine — Backend API Specification

**Scope:** JWT-authenticated REST API (`/api/*`) exposed by the Flask backend  
**Status:** Matches current implementation in `backend/routes/api_routes.py`  
**Last updated:** 2026-03-16  
**Document version:** 1.0

---

## 1) API Overview

### Base URLs

The backend serves both the SPA static bundle and the API.

- **Local development (Flask, default):** `http://localhost:5000`
- **Docker Compose (recommended):** `http://localhost` (Nginx reverse proxy → backend)
  - The backend app listens on `:8000` inside the Compose network; Nginx exposes port `80` by default (`docker-compose.yml`, `deploy/nginx/recon.conf`).
- **API base path:** `/api`
  - Example: `http://localhost:5000/api/scans/recent`

### Content types

- Requests with JSON bodies: `Content-Type: application/json`
- Responses: `application/json` (except CSV exports)

### Authentication

All `/api/*` endpoints require an **access token** unless explicitly documented otherwise.

- **Header:** `Authorization: Bearer <accessToken>`
- Access/refresh tokens are issued via `POST /api/auth/login`.

### Rate limiting (built-in)

The backend enforces a process-local sliding-window rate limit for:

- `POST /api/auth/login`
- `POST /api/scans`

When the limit is exceeded, the backend responds with:

```json
{
  "error": "Too many login attempts",
  "retry_after": 42
}
```

or:

```json
{
  "error": "Scan rate limit exceeded",
  "retry_after": 120
}
```

### Error response structure (API envelope)

Most API validation and domain errors use the following envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": [{ "field": "targets", "message": "At least one target is required" }],
    "timestamp": "2026-03-16T12:34:56.789+00:00",
    "requestId": "8f0b79f2-3d1f-4b8b-9c98-5a9f6db0bdf1"
  }
}
```

Notes:

- `details` is always an array (possibly empty).
- `requestId` is generated per error response.
- Some cross-cutting errors (e.g., rate limiting) and global Flask error handlers may return a simpler shape: `{ "error": "...", "detail": "..." }`.

### Common HTTP status codes

- `200 OK` — success
- `201 Created` — scan created/queued/scheduled
- `400 Bad Request` — invalid pagination, malformed input
- `401 Unauthorized` — missing/invalid/expired access token
- `403 Forbidden` — (typically reserved for RBAC session routes; `/api/*` is token-based)
- `404 Not Found` — resource missing
- `409 Conflict` — invalid state transition (e.g., cancel completed scan)
- `422 Unprocessable Entity` — validation errors (typed fields, missing required params)
- `429 Too Many Requests` — rate limit exceeded
- `500 Internal Server Error` — unexpected server error
- `503 Service Unavailable` — DB unavailable (global handler)

---

## 2) Authentication API (`/api/auth/*`)

### 2.1 Login

`POST /api/auth/login`

Issues a JWT access token + refresh token.

**Request body**

```json
{
  "email": "admin@example.com",
  "password": "correct horse battery staple"
}
```

**Response (200)**

```json
{
  "user": {
    "id": "1",
    "email": "admin@example.com",
    "name": "admin",
    "role": "admin",
    "avatar": "",
    "organizationId": "default"
  },
  "tokens": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
    "expiresIn": 3600
  },
  "permissions": ["scan:active", "scan:read", "scan:passive"]
}
```

**Errors**

- `401 INVALID_CREDENTIALS`
- `422 VALIDATION_ERROR` (missing `email` and/or `password`)
- `429` (rate limited; non-envelope response)

---

### 2.2 Session validation

`GET /api/auth/session`

Returns the authenticated user, permissions, and access token expiry.

**Headers**

`Authorization: Bearer <accessToken>`

**Response (200)**

```json
{
  "user": {
    "id": "1",
    "email": "admin@example.com",
    "name": "admin",
    "role": "admin",
    "avatar": "",
    "organizationId": "default"
  },
  "permissions": ["scan:active", "scan:read", "scan:passive"],
  "sessionExpiry": "2026-03-16T13:34:56+00:00"
}
```

**Errors**

- `401 AUTHENTICATION_REQUIRED` (missing/invalid/expired token)

---

### 2.3 Token refresh

`POST /api/auth/refresh`

Exchanges a refresh token for a new access token (and a new refresh token).

**Request body**

```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200)**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
  "expiresIn": 3600
}
```

**Errors**

- `401 AUTHENTICATION_REQUIRED` (invalid/expired refresh token)
- `422 VALIDATION_ERROR` (missing `refreshToken`)

---

### 2.4 Logout

`POST /api/auth/logout`

Currently a stateless operation (server does not blacklist tokens). Clients should delete stored tokens.

**Headers**

`Authorization: Bearer <accessToken>`

**Response (200)**

```json
{ "message": "Logged out successfully" }
```

---

## 3) Scan Management API (`/api/scans/*`)

### 3.1 Start scan (queue or schedule)

`POST /api/scans`

Creates a scan row and runs the scan asynchronously (or schedules it for later).

**Request body (minimal)**

```json
{
  "targets": ["example.com"],
  "scanType": "quick_scan",
  "schedule": { "type": "immediate", "scheduledAt": null }
}
```

**Request schema**

- `targets`: string | string[] (required; at least one non-empty target)
- `scanType`: `"quick_scan" | "custom_scan" | "full_scan"` (optional; default `quick_scan`)
  - `quick_scan` → backend scan mode: `passive`
  - `custom_scan` → backend scan mode: `active`
  - `full_scan` → backend scan mode: `full`
- `schedule`: object (optional)
  - `type`: `"immediate" | "scheduled"` (default `immediate`)
  - `scheduledAt`: ISO8601 timestamp string when `type="scheduled"`

Notes:

- The current backend **normalizes and validates only the first target** (`targets[0]`).
- Wildcard domains (`*.example.com`) are accepted and normalized for scanning.
- CIDR targets are normalized to a representative host IP for validation.
- Additional fields (e.g., `options`, `notifications`, `priority`) are accepted but **currently ignored** by the backend.

**Response (201, immediate)**

```json
{
  "scanId": "123",
  "status": "queued",
  "estimatedStartTime": "2026-03-16T12:34:56.789+00:00",
  "estimatedDuration": 300,
  "queuePosition": 1,
  "targetCount": 1,
  "message": "Scan created successfully"
}
```

**Response (201, scheduled)**

```json
{
  "scanId": "124",
  "status": "scheduled",
  "estimatedStartTime": "2026-03-16T14:00:00+00:00",
  "estimatedDuration": 300,
  "queuePosition": 1,
  "targetCount": 1,
  "message": "Scan created successfully"
}
```

**Errors**

- `422 VALIDATION_ERROR` (missing/invalid targets, invalid `schedule.scheduledAt`)
- `429` (rate limited; non-envelope response)

---

### 3.2 List recent scans

`GET /api/scans/recent?limit=10&offset=0`

**Query parameters**

- `limit`: integer (default `10`, max `50`)
- `offset`: integer (default `0`)

**Response (200)**

```json
{
  "scans": [
    {
      "id": "123",
      "target": "example.com",
      "type": "quick_scan",
      "typeLabel": "Quick Scan",
      "status": "completed",
      "findings": 4,
      "startedAt": "2026-03-16T12:00:00+00:00",
      "completedAt": "2026-03-16T12:01:12+00:00",
      "duration": 72,
      "relativeTime": "5 minutes ago"
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

---

### 3.3 Get scan status + summary (primary)

`GET /api/scans/{scanId}`

Returns a normalized scan payload for the UI, including a `discovery` section derived from stored scan results and a `raw` section containing the persisted result JSON.

**Response (200, shape)**

```json
{
  "id": "123",
  "target": "example.com",
  "targets": ["example.com"],
  "scanType": "quick_scan",
  "status": "in_progress",
  "progress": 55,
  "startedAt": "2026-03-16T12:00:00+00:00",
  "completedAt": null,
  "duration": null,
  "findings": { "total": 4, "critical": 0, "high": 0, "medium": 0, "low": 4 },
  "assetsDiscovered": 3,
  "options": {},
  "createdBy": { "userId": "1", "userName": "admin", "email": "admin@example.com" },
  "logs": [{ "timestamp": "2026-03-16T12:00:12+00:00", "level": "info", "message": "..." }],
  "results": { "summary": "Target: ... | ...", "detailedReport": "/api/scans/123/raw" },
  "discovery": {
    "resolvedIps": ["93.184.216.34"],
    "subdomains": ["www.example.com"],
    "openPorts": [80, 443],
    "technologies": ["nginx"],
    "vulnerabilities": ["Potential outdated TLS configuration"],
    "urls": ["https://example.com"],
    "assetsDiscovered": 3
  },
  "raw": { "meta": {}, "modules": {}, "status": "in_progress" }
}
```

**Errors**

- `404 RESOURCE_NOT_FOUND` (unknown scan id)

---

### 3.4 Get scan raw results (verbatim persisted JSON)

`GET /api/scans/{scanId}/raw`

**Response (200)**

```json
{
  "scanId": "123",
  "target": "example.com",
  "status": "completed",
  "createdAt": "2026-03-16T12:00:00+00:00",
  "completedAt": "2026-03-16T12:01:12+00:00",
  "results": { "meta": {}, "modules": {}, "status": "completed" }
}
```

---

### 3.5 Cancel scan

`POST /api/scans/{scanId}/cancel`

**Response (200)**

```json
{
  "scanId": "123",
  "status": "cancelled",
  "message": "Scan cancelled successfully",
  "timestamp": "2026-03-16T12:34:56.789+00:00"
}
```

**Errors**

- `404 RESOURCE_NOT_FOUND`
- `409 CONFLICT` (cannot cancel a completed/failed/cancelled scan)

---

### 3.6 Retry scan

`POST /api/scans/{scanId}/retry`

Creates a new scan row with the same target and mode and queues it.

**Response (200)**

```json
{ "newScanId": "125", "status": "queued", "message": "Scan retried successfully" }
```

---

### 3.7 Queue view

`GET /api/scans/queue`

**Response (200)**

```json
{
  "activeScans": 0,
  "queuedScans": 1,
  "completedToday": 0,
  "averageWaitTime": 0,
  "estimatedQueueClearTime": "2026-03-16T12:34:56.789+00:00",
  "queue": [
    {
      "scanId": "124",
      "position": 1,
      "target": "example.com",
      "scanType": "quick_scan",
      "priority": "normal",
      "estimatedStartTime": "2026-03-16T12:34:56.789+00:00",
      "submittedBy": "admin",
      "submittedAt": "2026-03-16T12:30:00+00:00"
    }
  ]
}
```

---

### 3.8 Scan options and templates (UI helpers)

- `GET /api/scans/options` — returns available scan option metadata + categories
- `GET /api/scans/templates` — returns predefined scan templates

These are informational endpoints used by the scan configuration UI.

---

### 3.9 Validate targets (pre-flight validation)

`POST /api/scans/validate-targets`

**Request body**

```json
{ "targets": ["example.com", "*.example.com", "10.0.0.0/24"] }
```

**Response (200)**

```json
{
  "valid": [{ "target": "example.com", "type": "domain", "resolved": true, "ipAddress": null }],
  "invalid": [{ "target": "", "reason": "Empty target", "suggestion": null }],
  "summary": { "totalTargets": 3, "validTargets": 2, "invalidTargets": 1 }
}
```

---

## 4) Findings API (`/api/findings*`)

### 4.1 List findings

`GET /api/findings`

**Query parameters**

- `scan_id` (or `scanId`): integer scan id (optional)
- `severity`: string (optional; exact match)
- `status`: string (optional; exact match)
- `category`: string (optional; exact match)
- `page`: integer (default `1`)
- `limit`: integer (default `20`, max `100`)

**Response (200)**

```json
{
  "findings": [
    {
      "id": "a1b2c3d4e5f6a7b8c9d0e1f2",
      "severity": "low",
      "title": "Missing security header: X-Frame-Options",
      "description": "The response is missing X-Frame-Options.",
      "category": "reconnaissance",
      "cvss": null,
      "cve": null,
      "asset": { "id": null, "name": "example.com", "type": "domain" },
      "scan": { "id": "123", "timestamp": "2026-03-16T12:01:12+00:00" },
      "status": "open",
      "discoveredAt": "2026-03-16T12:01:12+00:00",
      "updatedAt": "2026-03-16T12:01:12+00:00",
      "assignedTo": null,
      "proof": {},
      "remediation": {}
    }
  ],
  "pagination": { "total": 1, "page": 1, "limit": 20, "totalPages": 1 }
}
```

**Errors**

- `422 VALIDATION_ERROR` when `scan_id` is provided but is not an integer
- `400 VALIDATION_ERROR` for invalid pagination values

---

### 4.2 Update finding status

`PATCH /api/findings/{findingId}`

**Request body**

```json
{ "status": "mitigated" }
```

**Allowed values**

`open | investigating | mitigated | false_positive`

Any other value is normalized to `open`.

**Response (200)**

```json
{
  "id": "a1b2c3d4e5f6a7b8c9d0e1f2",
  "status": "mitigated",
  "updatedAt": "2026-03-16T12:34:56.789+00:00",
  "message": "Finding updated successfully"
}
```

**Errors**

- `404 RESOURCE_NOT_FOUND`

---

## 5) Additional implemented endpoint groups (for completeness)

### Dashboard

- `GET /api/dashboard/metrics`
- `GET /api/dashboard/risk-trend?timeframe=30d&granularity=daily`
- `GET /api/dashboard/findings-distribution`

### Asset inventory (derived from stored scans)

- `GET /api/assets` (pagination + filtering + sorting)
- `GET /api/assets/stats`
- `GET /api/assets/{assetId}`
- `POST /api/assets/{assetId}/scan`
- `GET /api/assets/export?format=csv|json&filter=all|domains|ips`

### System health

- `GET /api/system/health`

### Notifications (derived from audit logs)

- `GET /api/notifications`
- `POST /api/notifications/{notificationId}/read`

---

## 6) Future-ready endpoint groups (documentation only)

The following endpoint groups are **not implemented yet** in the backend. They are reserved for future expansion and should be treated as a roadmap. Where possible, this section points to current equivalent data sources.

### 6.1 Risk Score API (planned)

- `GET /api/risk-score`
- `GET /api/risk-score/by-asset-type`
- `GET /api/risk-score/timeline`

**Current equivalents**

- `GET /api/dashboard/metrics` provides a current aggregate score.
- `GET /api/dashboard/risk-trend` provides a timeline series.
- `GET /api/scans/{id}` includes per-scan `findings` and derived risk metadata in `raw`.

### 6.2 Subdomain Map API (planned)

- `GET /api/subdomains/map`
- `GET /api/subdomains/{id}`
- `GET /api/subdomains/search`

**Current equivalents**

- `GET /api/scans/{id}` → `discovery.subdomains` (normalized list)
- `GET /api/scans/{id}/raw` → may include module output under `results.modules.subdomain_enum`

### 6.3 Vulnerabilities API (planned)

- `GET /api/vulnerabilities`
- `GET /api/vulnerabilities/{id}`
- `PATCH /api/vulnerabilities/{id}/status`
- `PATCH /api/vulnerabilities/bulk`
- `POST /api/vulnerabilities/export`

**Current equivalents**

- `GET /api/findings` is the canonical “work queue” for issues discovered by scans.
- `GET /api/scans/{id}` and `GET /api/scans/{id}/raw` contain scan module output suitable for deeper vulnerability drill-down.

---

## Appendix A — Legacy session-based routes (still implemented)

The project also exposes session + CSRF protected endpoints (used by older frontend code paths):

Auth (session):

- `GET /auth/csrf` (also `GET /csrf`)
- `GET /auth/login` / `POST /auth/login` (also `/login`)
- `POST /auth/logout` (also `/logout`)
- `GET /auth/me` (also `/me`)

Scans (session):

- `POST /scan` / `GET /scan` / `GET /scan/<id>`
- `POST /scans` / `POST /scans/passive` / `POST /scans/active` / `POST /scans/full`
- `GET /scans` / `GET /scans/<id>`

Admin:

- `GET /admin/users` / `POST /admin/users`
- `GET /admin/audit-logs`
