# Backend API Capabilities

## 1. Overview

This document describes what the backend actually exposes from code in `backend/app.py`, `backend/routes/*`, `backend/services/*`, `backend/models.py`, `backend/security.py`, and `backend/scanners/*`.

Key findings:

- The live backend is a Flask app with session authentication, CSRF protection, RBAC, and SQLAlchemy models.
- The live HTTP surface is under `/auth`, `/admin`, `/scans`, plus legacy aliases under `/login`, `/logout`, `/me`, `/csrf`, and `/scan`.
- There is no `/api` prefix anywhere in the Flask route map.
- There are no websocket handlers, no `flask_socketio`, no SSE endpoints, and no async scan-progress API.
- Scan execution is synchronous inside the request handler. `POST /scans` and `POST /scan` do not enqueue background work; they return only after the scan finishes or fails.
- There is no dedicated `schemas/` package and no Marshmallow/Pydantic app schemas. Request/response shapes are assembled from literal dicts and model `to_dict()` methods.
- The codebase contains a second scanner package in `backend/scanners/*`, but those modules are not imported by the live Flask routes/services. They exist on disk but are not part of the runtime HTTP contract.
- There are no `controllers/` or websocket-handler directories in this repository.
- There are no backend models for `Asset`, `Finding`, `Notification`, or `AttackSurfaceGraph`.

Shared request/response behavior:

- Authentication model: session cookie (`recon_session`), not JWT.
- CSRF model: every non-safe request (`POST`) requires a valid CSRF token except the explicitly exempt `GET /auth/csrf`, `GET /csrf`, `GET /healthz`, and static files.
- CSRF transport: header `X-CSRF-Token` by default, fallback headers `X-XSRF-TOKEN`, or body field `csrf_token`.
- CSRF response behavior: the current CSRF token is also returned in the response header named by `CSRF_HEADER_NAME` (default `X-CSRF-Token`).
- Login rate limit: default 10 `POST /auth/login` or `POST /login` attempts per 300 seconds per client IP.
- Scan rate limit: default 30 scan-start POSTs per 300 seconds per session user or client IP.
- JSON vs HTML: `GET /auth/login`, `GET /login`, `GET /admin/users/new`, `POST /auth/login`, `POST /login`, `POST /auth/logout`, `POST /logout`, and `POST /admin/users` can render HTML/redirects when not used as JSON APIs.

Reusable response objects:

```json
User
{
  "id": 1,
  "username": "alice",
  "email": "alice@example.com",
  "is_active": true,
  "roles": ["admin"],
  "permissions": ["audit:read", "scan:active", "scan:passive", "scan:read", "user:create", "user:read"],
  "created_at": "2026-03-09T10:00:00"
}
```

```json
AuditLog
{
  "id": 1,
  "user_id": 1,
  "action": "scan.completed",
  "target": "example.com",
  "ip_address": "203.0.113.10",
  "created_at": "2026-03-09T10:00:00"
}
```

```json
Scan
{
  "id": 1,
  "user_id": 1,
  "target": "example.com",
  "scan_mode": "full",
  "status": "completed",
  "risk_score": 6.0,
  "overall_risk": "Medium",
  "confidence_score": 96.36,
  "results": { "...": "See Section 6" },
  "created_at": "2026-03-09T10:00:00",
  "completed_at": "2026-03-09T10:01:10"
}
```

## 2. API Endpoints

### GET `/`

Description

- Server-rendered dashboard landing page.
- Redirects to the login page when no authenticated session exists.

Query Parameters

- None.

Request Body

- None.

Response

- Authenticated: HTML string with backend banner and current username.
- Unauthenticated: HTTP redirect to `/auth/login`.

Status Codes

- `200` authenticated HTML response.
- `302` redirect to login.

### GET `/healthz`

Description

- Lightweight health probe.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "status": "ok"
}
```

Status Codes

- `200` success.

### GET `/readyz`

Description

- Readiness probe that performs `SELECT 1` against the configured SQL database.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "status": "ready"
}
```

Status Codes

- `200` database query succeeded.
- `503` database unavailable.
- `500` generic database operation failure.

### GET `/auth/csrf`
### GET `/csrf`

Description

- Returns the current session CSRF token.
- Also creates a session-scoped token if one does not yet exist.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "csrf_token": "<token>"
}
```

Status Codes

- `200` success.

### GET `/auth/login`
### GET `/login`

Description

- Returns the login HTML page.
- If the user is already authenticated, redirects to `/`.

Query Parameters

- None.

Request Body

- None.

Response

- HTML template `backend/templates/login.html`.

Status Codes

- `200` login page.
- `302` redirect to `/` when already logged in.

### POST `/auth/login`
### POST `/login`

Description

- Authenticates a user by username or email and establishes a server session.
- Requires a valid CSRF token even though the route is public.

Query Parameters

- None.

Request Body

JSON or form fields:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "identity": "alice",
  "password": "StrongPassword123!",
  "csrf_token": "<optional if header used>"
}
```

Notes

- Only one identity field is needed. The code checks `username`, then `email`, then `identity`.
- On JSON requests the route returns JSON.
- On non-JSON form requests the route renders/redirects HTML.

Response

JSON mode:

```json
{
  "message": "Login successful",
  "user": { "User": "See reusable schema above" },
  "csrf_token": "<token>"
}
```

HTML mode:

- `302` redirect to `/` on success.
- Login page with error message on failure.

Status Codes

- `200` JSON success.
- `302` HTML redirect success.
- `400` missing identity or password.
- `401` invalid credentials.
- `403` CSRF validation failed.
- `429` too many login attempts.

### POST `/auth/logout`
### POST `/logout`

Description

- Clears the current session and audit-logs the logout event.
- Requires authentication and CSRF.

Query Parameters

- None.

Request Body

```json
{
  "csrf_token": "<optional if header used>"
}
```

Response

JSON mode:

```json
{
  "message": "Logged out"
}
```

HTML mode:

- `302` redirect to `/auth/login`.

Status Codes

- `200` JSON success.
- `302` HTML redirect success.
- `401` unauthenticated.
- `403` CSRF validation failed.

### GET `/auth/me`
### GET `/me`

Description

- Returns the current authenticated user and session metadata.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "user": { "User": "See reusable schema above" },
  "session_user_id": 1,
  "csrf_token": "<token>"
}
```

Status Codes

- `200` success.
- `401` unauthenticated.

### POST `/scans`
### POST `/scan`

Description

- Starts a synchronous scan and persists the resulting `Scan` record.
- The request thread runs the scan immediately, updates the DB record, and returns the completed `scan` payload.
- This is the primary frontend scan-start API. `/scan` is the legacy alias.

Query Parameters

- None.

Request Body

```json
{
  "target": "example.com",
  "scan_mode": "passive"
}
```

Supported `scan_mode` values:

- `passive`
- `active`
- `full`

Important constraints

- `target` is required.
- `target` may be a domain or IP address.
- Raw URLs are normalized to hostnames.
- Private/reserved IP targets are blocked unless `ALLOW_PRIVATE_TARGETS=true`.
- `full` mode requires the caller to have the `admin` role.
- The backend ignores any extra `scans` array or per-module selection fields; there is no API support for choosing individual modules.

Response

```json
{
  "scan": { "Scan": "See reusable schema above" }
}
```

Status Codes

- `201` scan completed and stored successfully.
- `400` missing target, invalid `scan_mode`, invalid target, or blocked private/reserved target.
- `401` unauthenticated.
- `403` missing permission, missing `admin` role for `full`, or CSRF validation failed.
- `429` scan rate limit exceeded.
- `500` unexpected scan failure or DB persistence failure.

### POST `/scans/passive`

Description

- Shortcut scan-start route that forces passive mode.
- Requires `scan:passive`.

Query Parameters

- None.

Request Body

```json
{
  "target": "example.com"
}
```

Response

```json
{
  "scan": { "Scan": "See reusable schema above" }
}
```

Status Codes

- `201` success.
- `400` invalid target or blocked target.
- `401` unauthenticated.
- `403` missing permission or CSRF validation failed.
- `429` scan rate limit exceeded.
- `500` unexpected failure.

### POST `/scans/active`

Description

- Shortcut scan-start route that forces active mode.
- Requires `scan:active`.

Query Parameters

- None.

Request Body

```json
{
  "target": "example.com"
}
```

Response

```json
{
  "scan": { "Scan": "See reusable schema above" }
}
```

Status Codes

- `201` success.
- `400` invalid target or blocked target.
- `401` unauthenticated.
- `403` missing permission or CSRF validation failed.
- `429` scan rate limit exceeded.
- `500` unexpected failure.

### POST `/scans/full`

Description

- Shortcut scan-start route that forces full mode.
- Requires `scan:active` permission plus `admin` role.

Query Parameters

- None.

Request Body

```json
{
  "target": "example.com"
}
```

Response

```json
{
  "scan": { "Scan": "See reusable schema above" }
}
```

Status Codes

- `201` success.
- `400` invalid target or blocked target.
- `401` unauthenticated.
- `403` missing role/permission or CSRF validation failed.
- `429` scan rate limit exceeded.
- `500` unexpected failure.

### GET `/scans`
### GET `/scan`
### GET `/scan/history`

Description

- Returns scan history ordered by newest first.
- `/scan` and `/scan/history` are legacy aliases.

Query Parameters

- `all`: optional boolean string. Only effective for admins. When `all=true`, admins can see all users' scans; non-admins still only see their own scans.

Request Body

- None.

Response

```json
{
  "scans": [
    { "Scan": "See reusable schema above" }
  ]
}
```

Notes

- Hard-coded maximum: 200 records.
- No pagination, cursor, page number, search, or filter parameters beyond `all`.

Status Codes

- `200` success.
- `401` unauthenticated.
- `403` missing `scan:read` permission.

### GET `/scans/<scan_id>`
### GET `/scan/<scan_id>`

Description

- Returns one persisted scan by numeric ID.
- The caller must either own the scan or have the `admin` role.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "scan": { "Scan": "See reusable schema above" }
}
```

Status Codes

- `200` success.
- `401` unauthenticated.
- `403` missing `scan:read` permission, or authenticated but not owner/admin.
- `404` scan ID not found.

### GET `/admin/users/new`

Description

- Returns the server-rendered user-creation page.

Query Parameters

- None.

Request Body

- None.

Response

- HTML template `backend/templates/create_user.html`.

Status Codes

- `200` success.
- `401` unauthenticated.
- `403` missing `admin` role or `user:create` permission.

### POST `/admin/users`

Description

- Creates a user and assigns one or more roles.
- Requires authentication, `admin` role, `user:create`, and CSRF.

Query Parameters

- None.

Request Body

JSON or form fields:

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "StrongPassword123!",
  "roles": ["basic", "authorized"]
}
```

Accepted `roles` formats:

- JSON array of strings.
- Comma-separated string.
- HTML form multi-select values.

Validation rules

- Username: `^[a-zA-Z0-9_.-]{3,64}$`
- Email: simple regex validation.
- Password: minimum 12 chars, at least one lowercase, uppercase, digit, and special character.
- Empty/omitted roles default to `["basic"]`.

Response

JSON mode:

```json
{
  "message": "User created",
  "user": { "User": "See reusable schema above" }
}
```

HTML mode:

- `201` rendered success state of `create_user.html`.

Status Codes

- `201` success.
- `400` invalid username, email, password, or unknown role.
- `401` unauthenticated.
- `403` missing role/permission or CSRF validation failed.
- `409` username or email already exists.
- `500` database error while creating user.

### GET `/admin/users`

Description

- Returns user list for admins.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "users": [
    { "User": "See reusable schema above" }
  ]
}
```

Notes

- Hard-coded maximum: 500 records.
- No pagination or filtering.

Status Codes

- `200` success.
- `401` unauthenticated.
- `403` missing `admin` role or `user:read` permission.

### GET `/admin/audit-logs`

Description

- Returns audit log list for admins.

Query Parameters

- None.

Request Body

- None.

Response

```json
{
  "audit_logs": [
    { "AuditLog": "See reusable schema above" }
  ]
}
```

Notes

- Hard-coded maximum: 500 records.
- No pagination or filtering.
- The backend stores only `action`, `target`, `ip_address`, `user_id`, and `created_at`. It does not return a richer details blob.

Status Codes

- `200` success.
- `401` unauthenticated.
- `403` missing `admin` role or `audit:read` permission.

## 3. WebSocket Events

No websocket capability is implemented in the application code.

What was checked:

- No websocket route registration in `backend/app.py`.
- No `flask_socketio`, `SocketIO`, `emit`, `websocket`, `ws://`, or `wss://` usage in app routes/services.
- No websocket handler modules exist in `backend/`.

Event support matrix:

| Event | Supported | Notes |
| --- | --- | --- |
| `scan.progress` | no | No background job or progress event emitter exists. |
| `scan.completed` | no | Completion is only visible through synchronous POST response or later GET of the stored scan. |
| `scan.failed` | no | Failure is only visible through synchronous POST response or later GET of the stored scan. |
| `finding.new` | no | No `Finding` model or realtime finding pipeline exists. |
| `asset.updated` | no | No `Asset` model exists. |
| `system.status` | no | Only HTTP probes `/healthz` and `/readyz` exist. |

Frontend implication:

- The backend does not provide realtime push.
- The only way to observe scan state is polling `GET /scans`, `GET /scans/<id>`, `GET /scan`, or `GET /scan/<id>`.
- Even polling has limited value for live progress because scan execution is synchronous and there is no per-module progress field.

## 4. Scan Engine Outputs

### 4.1 Live scan engine used by the HTTP API

The live API uses `backend/services/scan_service.py`.

Mode-to-module mapping:

| Scan mode | Modules actually executed |
| --- | --- |
| `passive` | `dns_enum`, `whois`, `subdomain_enum` |
| `active` | `port_scan`, `http_probe`, `ssl_check` |
| `full` | `dns_enum`, `whois`, `subdomain_enum`, `port_scan`, `http_probe`, `ssl_check`, `headers_analysis`, `technology_fingerprint`, `hosting_detection`, `vulnerability_surface`, `risk_scoring` |

Each module is stored in the `results.modules` object with one of these envelopes:

```json
{
  "status": "completed",
  "data": { "...": "module-specific payload" }
}
```

```json
{
  "status": "failed",
  "error": "failure message"
}
```

Live module payloads:

### `dns_enum`

What it produces

- Primary IP
- All resolved IPs
- IPv6 addresses
- DNS records for `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`

Output schema

```json
{
  "primary_ip": "93.184.216.34",
  "resolved_ips": ["93.184.216.34"],
  "ipv6_addresses": [],
  "dns_records": {
    "A": ["93.184.216.34"],
    "AAAA": [],
    "MX": [],
    "TXT": [],
    "NS": [],
    "CNAME": []
  }
}
```

### `whois`

What it produces

- RDAP data when available.
- Falls back to raw WHOIS-over-port-43 parsing.

Primary RDAP-shaped output

```json
{
  "query": "example.com",
  "source": "rdap",
  "rdap_url": "https://rdap.org/domain/example.com",
  "handle": "EXAMPLE",
  "name": "example.com",
  "status": ["active"],
  "port43": "whois.iana.org",
  "nameservers": ["a.iana-servers.net"],
  "entities": ["ABC123"],
  "events": {
    "registration": "2020-01-01T00:00:00Z"
  }
}
```

Fallback WHOIS-shaped output

```json
{
  "query": "example.com",
  "source": "whois",
  "whois_server": "whois.verisign-grs.com",
  "parsed": {
    "domain_name": "EXAMPLE.COM",
    "registrar": "Registrar Name",
    "creation_date": "2020-01-01",
    "expiration_date": "2030-01-01",
    "name_servers": ["NS1.EXAMPLE.COM"],
    "registrant_org": "Example Org"
  },
  "rdap_error": "..."
}
```

### `subdomain_enum`

What it produces

- Wordlist-based subdomain discovery against a fixed built-in list.

Output schema

```json
{
  "count": 2,
  "subdomains": [
    {
      "hostname": "api.example.com",
      "resolved_ips": ["203.0.113.10"]
    }
  ]
}
```

Notes

- For IP targets this module raises an error and the module status becomes `failed`.

### `port_scan`

What it produces

- TCP port status for a fixed common-port list:
  `21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443`

Output schema

```json
{
  "tested_ports": [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443],
  "open_ports": [80, 443],
  "closed_ports": [21, 22, 25, 53, 110, 143, 445, 3306, 3389, 8080, 8443]
}
```

### `http_probe`

What it produces

- One live HTTP(S) response snapshot.
- Redirect chain.
- Response headers.
- Small HTML snippet.

Output schema

```json
{
  "url": "https://example.com/",
  "status_code": 200,
  "headers": {
    "Server": "nginx"
  },
  "redirects": ["http://example.com", "https://example.com/"],
  "server_banner": "nginx",
  "html_snippet": "<!doctype html>..."
}
```

### `ssl_check`

What it produces

- TLS certificate subject/issuer metadata.
- Validity dates.
- TLS version and cipher.

Output schema

```json
{
  "issuer": {
    "organizationName": "Example CA"
  },
  "subject": {
    "commonName": "example.com"
  },
  "valid_from": "Jan  1 00:00:00 2026 GMT",
  "valid_to": "Mar 31 23:59:59 2026 GMT",
  "tls_version": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "ssl_version": "TLSv1.3",
  "not_before": "Jan  1 00:00:00 2026 GMT",
  "not_after": "Mar 31 23:59:59 2026 GMT"
}
```

### `headers_analysis`

What it produces

- Missing/present security headers and a heuristic risk summary.

Output schema

```json
{
  "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security"],
  "present_headers": {
    "X-Frame-Options": "DENY"
  },
  "risk_score": 5,
  "severity_summary": {
    "high": 1,
    "medium": 1,
    "low": 0,
    "risk_level": "medium"
  }
}
```

### `technology_fingerprint`

What it produces

- Framework hints from HTML/cookies/headers.
- Server banner.
- CDN/reverse-proxy/WAF hints.

Output schema

```json
{
  "framework": ["React", "WordPress"],
  "server": "nginx",
  "cdn": "Cloudflare",
  "reverse_proxy": "Nginx",
  "waf": "Cloudflare WAF"
}
```

### `hosting_detection`

What it produces

- Heuristic hosting and CDN/cloud attribution from DNS, WHOIS, reverse DNS, and fingerprint data.

Output schema

```json
{
  "cloud_provider": "AWS",
  "cdn_provider": "Cloudflare",
  "hosting_provider": "Cloudflare (CDN-proxied origin)"
}
```

### `vulnerability_surface`

What it produces

- Heuristic exposure summary only.
- This is not a CVE scanner in the live API path.

Output schema

```json
{
  "potential_risks": [
    "Sensitive service exposed on port 22",
    "Missing security header: Content-Security-Policy"
  ],
  "exposed_services": [
    {
      "port": 22,
      "service": "ssh"
    }
  ],
  "misconfigurations": [
    "Header misconfiguration: Content-Security-Policy"
  ]
}
```

### `risk_scoring`

What it produces

- Heuristic attack-surface score and summarized findings.

Output schema

```json
{
  "attack_surface_score": 8.5,
  "overall_risk": "High",
  "key_findings": [
    "Open ports: 22, 80, 443",
    "Missing security header: Content-Security-Policy",
    "Technologies detected: React"
  ]
}
```

Data categories supported by the live API engine:

| Data category | Supported by live API | Source module |
| --- | --- | --- |
| Subdomains | yes | `subdomain_enum` |
| IP addresses | yes | `dns_enum` |
| Open ports | yes | `port_scan` |
| Technologies | yes | `technology_fingerprint` |
| HTTP response snapshot | yes | `http_probe` |
| TLS certificate metadata | yes | `ssl_check` |
| DNS records | yes | `dns_enum` |
| Hosting/CDN/WAF hints | yes | `hosting_detection`, `technology_fingerprint` |
| Vulnerabilities (heuristic exposure only) | partial | `vulnerability_surface` |
| CVE-level vulnerability list | no | Not produced by the live API path |
| Screenshots | no | No screenshot module exists |

### 4.2 Standalone scanner package present on disk but not wired to the live API

These modules exist under `backend/scanners/*` but are not imported by the runtime Flask routes/services.

### `backend/scanners/subdomain.py`

Output

```json
[
  "www.example.com",
  "api.example.com"
]
```

Notes

- Returns a plain list of hostnames.
- Raises `ModuleTimeoutError` if every lookup times out.

### `backend/scanners/osint.py`

Output

```json
{
  "resolved_ip": "93.184.216.34",
  "whois": {
    "domain_name": "EXAMPLE.COM",
    "registrar": "Registrar Name",
    "creation_date": "2020-01-01 00:00:00",
    "expiration_date": "2030-01-01 00:00:00",
    "name_servers": ["NS1.EXAMPLE.COM"]
  }
}
```

Possible degraded output

```json
{
  "resolved_ip": "DNS resolution failed: ...",
  "whois": "WHOIS failed: ..."
}
```

### `backend/scanners/ssl_scan.py`

Output

```json
{
  "ssl_version": "TLSv1.3",
  "cipher": ["TLS_AES_256_GCM_SHA384", "TLSv1.3", 256]
}
```

Or

```json
{
  "error": "..."
}
```

### `backend/scanners/header_scanner.py`

Output

```json
{
  "X-Frame-Options": {
    "status": "Present",
    "value": "DENY"
  },
  "Content-Security-Policy": {
    "status": "Missing",
    "issue": "Missing protection against XSS",
    "severity": "High"
  },
  "summary": {
    "total_missing": 2,
    "risk_score": 5,
    "risk_level": "Medium"
  }
}
```

### `backend/scanners/tech_fingerprint.py`

Output

```json
{
  "server": "nginx",
  "reverse_proxy": "Nginx",
  "cdn": "Cloudflare",
  "waf": "Cloudflare WAF",
  "framework_detection": {
    "WordPress": {
      "confidence": "High",
      "evidence": ["wp-content found in HTML"]
    }
  }
}
```

### `backend/scanners/intel.py`

Output

```json
{
  "hosting_provider": "Behind CDN (Origin Obfuscated)",
  "cdn_provider": "Cloudflare",
  "waf_provider": "Cloudflare WAF"
}
```

### `backend/scanners/nmap_scan.py`

Output

```json
{
  "target": "example.com",
  "ports": [
    {
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "product": "nginx",
      "version": "1.25.0",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-12345",
          "cvss_score": 7.5,
          "severity": "High",
          "title": "Example vulnerability",
          "exploit_available": false
        }
      ]
    }
  ],
  "summary": {
    "total_ports": 10,
    "open_ports": 2,
    "total_cves": 1,
    "total_services": 2,
    "highest_cvss": 7.5,
    "risk_level": "High"
  }
}
```

Notes

- This is the only code path in the repo that assembles a CVE-level vulnerability list.
- It is not exposed through the live Flask API.

### `backend/scanners/scoring.py`

Output

```json
{
  "attack_surface_score": 14.5,
  "overall_risk": "HIGH",
  "confidence": "High",
  "key_findings": [
    "CDN detected: Cloudflare",
    "Open ports detected: 22, 443",
    "High CVEs (CVSS 7-8.9): 1"
  ]
}
```

### `backend/scanners/vulners_api.py`

Support helper output

```json
{
  "cvss": 7.5,
  "severity": "High",
  "title": "Example vulnerability",
  "exploit_available": false
}
```

Or

```json
{
  "error": "Request failed: ..."
}
```

## 5. Data Models

There is one SQLAlchemy model file: `backend/models.py`.

There are no dedicated frontend-facing schema classes. Serialization is done with `to_dict()` or literal dicts.

### `UserRole`

Purpose

- Join table between users and roles.

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `user_id` | integer FK | Primary key component, `users.id` |
| `role_id` | integer FK | Primary key component, `roles.id` |

Relationships

- Many-to-many bridge between `User` and `Role`.

### `RolePermission`

Purpose

- Join table between roles and permissions.

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `role_id` | integer FK | Primary key component, `roles.id` |
| `permission_id` | integer FK | Primary key component, `permissions.id` |

Relationships

- Many-to-many bridge between `Role` and `Permission`.

### `User`

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | integer | Primary key |
| `username` | string(100) | Unique, indexed |
| `email` | string(150) | Unique, indexed |
| `password_hash` | string(255) | bcrypt hash |
| `is_active` | boolean | Defaults true |
| `created_at` | datetime | DB timestamp default |

Relationships

- Many-to-many with `Role` via `user_roles`.
- One-to-many with `Scan`.

Derived fields exposed to frontend

- `roles`: sorted role names
- `permissions`: sorted permission names

### `Role`

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | integer | Primary key |
| `name` | string(50) | Stored in column `role_name`, unique, indexed |
| `description` | text | Nullable |

Relationships

- Many-to-many with `User`.
- Many-to-many with `Permission`.

### `Permission`

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | integer | Primary key |
| `name` | string(100) | Stored in column `permission_name`, unique, indexed |
| `description` | text | Nullable |

Relationships

- Many-to-many with `Role`.

### `Scan`

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | integer | Primary key |
| `user_id` | integer FK nullable | Owner, `users.id` |
| `target` | string(255) | Indexed |
| `scan_mode` | string(16) | Indexed |
| `status` | string(16) | Defaults `queued`; runtime uses `running`, `completed`, `failed` |
| `risk_score` | numeric(5,2) nullable | Stored summary score |
| `overall_risk` | string(16) nullable | Indexed |
| `confidence_score` | numeric(5,2) nullable | Stored summary confidence |
| `results_json` | JSON | Stored in DB column `result_json` |
| `created_at` | datetime | DB timestamp default |
| `completed_at` | datetime nullable | Completion timestamp |

Relationships

- Many-to-one with `User`.

Frontend-visible serialized fields

- `id`
- `user_id`
- `target`
- `scan_mode`
- `status`
- `risk_score`
- `overall_risk`
- `confidence_score`
- `results`
- `created_at`
- `completed_at`

### `AuditLog`

Fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | integer | Primary key |
| `user_id` | integer FK nullable | `users.id` |
| `action` | string(255) | Audit event name |
| `target` | string(255) nullable | Target/resource label |
| `ip_address` | string(45) nullable | IPv4/IPv6 text |
| `created_at` | datetime | Indexed timestamp |

Relationships

- Many-to-one with `User`.

Important model absences

- No `Asset` model.
- No `Finding` model.
- No `Notification` model.
- No `ScanTask`/background-job model.
- No `AttackSurfaceGraph` model.

## 6. Raw Scan Output Schema

The backend returns the raw scan result inside the serialized `Scan.results` field.

### 6.1 Outer scan object returned by scan endpoints

```json
{
  "scan": {
    "id": 1,
    "user_id": 1,
    "target": "example.com",
    "scan_mode": "full",
    "status": "completed",
    "risk_score": 6.0,
    "overall_risk": "Medium",
    "confidence_score": 96.36,
    "results": { "...": "see below" },
    "created_at": "2026-03-09T10:00:00",
    "completed_at": "2026-03-09T10:01:10"
  }
}
```

### 6.2 Successful `results` payload shape

```json
{
  "meta": {
    "target": "example.com",
    "mode": "full",
    "requested_mode": "full",
    "started_at": "2026-03-09T10:00:00+00:00",
    "completed_at": "2026-03-09T10:01:10+00:00",
    "duration_ms": 70123
  },
  "modules": {
    "dns_enum": {
      "status": "completed",
      "data": {
        "primary_ip": "93.184.216.34",
        "resolved_ips": ["93.184.216.34"],
        "ipv6_addresses": [],
        "dns_records": {
          "A": ["93.184.216.34"],
          "AAAA": [],
          "MX": [],
          "TXT": [],
          "NS": [],
          "CNAME": []
        }
      }
    },
    "whois": {
      "status": "completed",
      "data": { "...": "RDAP or WHOIS fallback payload" }
    },
    "subdomain_enum": {
      "status": "completed",
      "data": {
        "count": 1,
        "subdomains": [
          {
            "hostname": "api.example.com",
            "resolved_ips": ["203.0.113.10"]
          }
        ]
      }
    },
    "port_scan": {
      "status": "completed",
      "data": {
        "tested_ports": [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443],
        "open_ports": [80, 443],
        "closed_ports": [21, 22, 25, 53, 110, 143, 445, 3306, 3389, 8080, 8443]
      }
    },
    "http_probe": {
      "status": "completed",
      "data": {
        "url": "https://example.com/",
        "status_code": 200,
        "headers": {},
        "redirects": [],
        "server_banner": "nginx",
        "html_snippet": "<!doctype html>..."
      }
    },
    "ssl_check": {
      "status": "completed",
      "data": {
        "issuer": {},
        "subject": {},
        "valid_from": "...",
        "valid_to": "...",
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "ssl_version": "TLSv1.3",
        "not_before": "...",
        "not_after": "..."
      }
    },
    "headers_analysis": {
      "status": "completed",
      "data": {
        "missing_headers": [],
        "present_headers": {},
        "risk_score": 0,
        "severity_summary": {
          "high": 0,
          "medium": 0,
          "low": 0,
          "risk_level": "low"
        }
      }
    },
    "technology_fingerprint": {
      "status": "completed",
      "data": {
        "framework": [],
        "server": "nginx",
        "cdn": null,
        "reverse_proxy": "Nginx",
        "waf": null
      }
    },
    "hosting_detection": {
      "status": "completed",
      "data": {
        "cloud_provider": null,
        "cdn_provider": null,
        "hosting_provider": "Unknown (93.184.216.34)"
      }
    },
    "vulnerability_surface": {
      "status": "completed",
      "data": {
        "potential_risks": [],
        "exposed_services": [],
        "misconfigurations": []
      }
    },
    "risk_scoring": {
      "status": "completed",
      "data": {
        "attack_surface_score": 3.5,
        "overall_risk": "Low",
        "key_findings": []
      }
    }
  },
  "target": "example.com",
  "scan_mode": "full",
  "requested_mode": "full",
  "resolved_ips": ["93.184.216.34"],
  "port_scan": {
    "tested_ports": [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443],
    "open_ports": [80, 443],
    "closed_ports": [21, 22, 25, 53, 110, 143, 445, 3306, 3389, 8080, 8443]
  }
}
```

Notes

- `results.resolved_ips` and `results.port_scan` are compatibility duplicates of module data.
- Module failures do not necessarily fail the whole scan. Individual modules can be `failed` while the overall scan status is still `completed`.
- Successful `results` objects do not include a top-level `results.status` field.

### 6.3 Failed `results` payload shape

When target validation fails or an unhandled exception bubbles out of the route, the stored `results` payload uses a different shape:

```json
{
  "meta": {
    "target": "example.com",
    "mode": "full",
    "requested_mode": "full",
    "started_at": "2026-03-09T10:00:00+00:00",
    "completed_at": "2026-03-09T10:00:05+00:00",
    "duration_ms": null
  },
  "modules": {},
  "target": "example.com",
  "scan_mode": "full",
  "requested_mode": "full",
  "status": "failed",
  "error": "Target must be a valid domain or IP address"
}
```

### 6.4 Initial running placeholder persisted before scan completion

Before the scan finishes, the DB row is first created with:

```json
{
  "meta": {
    "target": "example.com",
    "mode": "full",
    "requested_mode": "full",
    "started_at": "2026-03-09T10:00:00+00:00",
    "completed_at": null,
    "duration_ms": null
  },
  "modules": {},
  "target": "example.com",
  "scan_mode": "full",
  "requested_mode": "full",
  "status": "running"
}
```

Important asymmetry

- `results.status` exists in the initial running payload and failure payload.
- `results.status` does not exist in successful `_run_modules()` output.
- Frontends must use outer `scan.status` as the reliable status field.

## 7. Feature Capability Matrix

Supported values:

- `yes`: exposed through the live backend API.
- `partial`: limited support or support exists only in non-wired modules.
- `no`: not present in backend code.

| Feature | Supported | Endpoint / Module |
| --- | --- | --- |
| Session-based login | yes | `POST /auth/login`, `POST /login` |
| CSRF token retrieval | yes | `GET /auth/csrf`, `GET /csrf` |
| Current authenticated user lookup | yes | `GET /auth/me`, `GET /me` |
| Health probe | yes | `GET /healthz` |
| Readiness probe with DB check | yes | `GET /readyz` |
| Start passive scan | yes | `POST /scans` with `scan_mode=passive`, `POST /scans/passive`, `POST /scan` |
| Start active scan | yes | `POST /scans` with `scan_mode=active`, `POST /scans/active`, `POST /scan` |
| Start full scan | yes | `POST /scans` with `scan_mode=full`, `POST /scans/full`, `POST /scan` |
| Per-module scan selection | no | Request body field `scans` is ignored by live routes |
| Scan history listing | yes | `GET /scans`, `GET /scan`, `GET /scan/history` |
| Single scan retrieval | yes | `GET /scans/<id>`, `GET /scan/<id>` |
| Subdomain discovery | yes | `services.scan_service.py` -> `subdomain_enum` |
| DNS record collection | yes | `services.scan_service.py` -> `dns_enum` |
| IP resolution | yes | `services.scan_service.py` -> `dns_enum` |
| Port scanning | yes | `services.scan_service.py` -> `port_scan` |
| HTTP response probing | yes | `services.scan_service.py` -> `http_probe` |
| TLS certificate inspection | yes | `services.scan_service.py` -> `ssl_check` |
| Security header analysis | yes | `services.scan_service.py` -> `headers_analysis` |
| Technology fingerprinting | yes | `services.scan_service.py` -> `technology_fingerprint` |
| Hosting/CDN detection | yes | `services.scan_service.py` -> `hosting_detection` |
| Heuristic vulnerability surfacing | partial | `services.scan_service.py` -> `vulnerability_surface` |
| CVE-level vulnerability list | partial | `backend/scanners/nmap_scan.py` exists but is not wired to HTTP API |
| Attack-surface score | yes | `services.scan_service.py` -> `risk_scoring`, persisted on `Scan` |
| Real-time scan progress | no | No progress field, queue, or event stream |
| WebSocket events | no | None found |
| Server-sent events | no | None found |
| Background scan jobs | no | Scans execute inline in request handlers |
| Pollable scan status endpoint | partial | `GET /scans/<id>` exists, but no separate progress/status API |
| Raw scan output retrieval | yes | `Scan.results` via scan create/get/list endpoints |
| Admin user creation | yes | `POST /admin/users` |
| Admin user listing | yes | `GET /admin/users` |
| Admin audit log listing | yes | `GET /admin/audit-logs` |
| Role/permission management API | no | Roles and permissions are seeded by CLI only |
| HTML login page | yes | `GET /auth/login`, `GET /login` |
| HTML admin user-create page | yes | `GET /admin/users/new` |
| Asset model / asset APIs | no | Not present |
| Finding model / finding APIs | no | Not present |
| Notification model / notification APIs | no | Not present |
| Attack-surface graph data | no | Not present |
| Screenshot capture | no | Not present |
| Pagination on scans/users/audit logs | partial | Hard-coded limits only; no page/limit cursors |

Bottom line for frontend comparison:

- The backend currently provides authentication, admin user management, scan creation/history, and heuristic attack-surface analysis.
- The backend does not provide realtime push, asset/finding entities, graph data, screenshot capture, or per-module scan orchestration.
- The codebase contains extra scanner utilities, including an Nmap+CVE path, but those modules are not part of the live HTTP contract unless the backend is refactored to call them.
