# Recon / Attack Surface Scanner

## Folder Structure

```text
project_recon/
  backend/
    app.py
    config.py
    extensions.py
    models.py
    decorators.py
    security.py
    gunicorn_conf.py
    Dockerfile
    .dockerignore
    requirements.txt
    .env
    .env.example
    routes/
      __init__.py
      auth_routes.py
      scan_routes.py
      admin_routes.py
    services/
      auth_service.py
      scan_service.py
      audit_service.py
      rbac_service.py
    templates/
      login.html
      create_user.html
  recon_frontend/
    src/
      app/
        context/AuthContext.tsx
        lib/api.ts
        components/auth/RequireAuth.tsx
        pages/recon/NewScan.tsx
        pages/recon/ScanResults.tsx
        pages/recon/ReconDashboard.tsx
    vite.config.ts
  deploy/
    nginx/recon.conf
  docker-compose.yml
```

## Security Model

- No public registration route.
- Session-based auth (Flask session, no JWT).
- bcrypt password hashing.
- CSRF protection for state-changing requests.
- RBAC with DB tables `roles`, `permissions`, `role_permissions`, `user_roles`.
- Roles:
  - `basic`: passive scans only
  - `authorized`: passive + active
  - `admin`: full scans + user management
- Decorator and runtime permission enforcement with HTTP `403`.
- Audit logs written to `audit_logs` table.

## API Endpoints

Auth:
- `GET /csrf` (or `/auth/csrf`)
- `POST /login` (or `/auth/login`)
- `POST /logout` (or `/auth/logout`)
- `GET /me` (or `/auth/me`)

Scan:
- `POST /scan` (payload: `target`, `scan_mode`)
- `GET /scan`
- `GET /scan/<id>`
- Also available: `/scans`, `/scans/passive`, `/scans/active`, `/scans/full`

Admin:
- `POST /admin/users`
- `GET /admin/users`
- `GET /admin/audit-logs`

## Local Setup

### 1) Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set DB config in `.env` (example already uses `scanner_db`):

```env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=ROOT
DB_NAME=scanner_db
```

Seed RBAC and create admin:

```powershell
flask --app app.py seed-rbac
flask --app app.py create-admin
```

Run backend:

```powershell
flask --app app.py run --host 0.0.0.0 --port 5000
```

### 2) Frontend

```powershell
cd ..\recon_frontend
npm install
npm run dev
```

Frontend dev server: `http://localhost:5173`

## Frontend Integration Notes

- All frontend requests use `credentials: include`.
- CSRF token is fetched from `/csrf` automatically by `src/app/lib/api.ts`.
- Login page posts to `/login`.
- Scan page posts to `/scan`.
- Unauthorized routes redirect to `/login`.
- Permission errors are surfaced in UI.

## Database Notes

- ORM models are aligned to existing MySQL schema:
  - `roles.role_name`
  - `permissions.permission_name`
  - `scans.result_json`
- Scan records are created as `running` then updated to `completed`/`failed` with full JSON result.

## Production (Gunicorn + Docker + Nginx)

### Gunicorn (Linux)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
gunicorn -c gunicorn_conf.py app:app
```

### Docker Compose

```bash
docker compose up -d --build
```

- MySQL service
- Flask backend (`gunicorn`) serving `recon_frontend/dist`
- Nginx reverse proxy (`deploy/nginx/recon.conf`)

## Linux VPS Deployment Steps

1. Provision Ubuntu server and open ports 80/443.
2. Install Docker + Docker Compose plugin.
3. Copy project to `/opt/recon`.
4. Set secure production env values:
   - strong `SECRET_KEY`
   - `SESSION_COOKIE_SECURE=1`
   - production DB credentials
   - `CORS_ORIGINS=https://your-domain.com`
5. Run `docker compose up -d --build`.
6. Put TLS in front (Let's Encrypt + nginx/certbot or external LB).
7. Enable log shipping and monitoring.

## Security Hardening Recommendations

1. Add MFA for admin users.
2. Store secrets in a secret manager (not plain `.env` on prod).
3. Add account lockout and IP reputation checks for login.
4. Add centralized audit log pipeline (SIEM).
5. Add background job queue for long scans (Celery/RQ).
6. Add DB migrations (Alembic) and CI policy checks.
7. Add automated tests for auth/RBAC/scan flows.
