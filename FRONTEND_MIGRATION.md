# Frontend Migration

## Summary

The active frontend has been switched from the old `Cybersecurity SaaS Dashboard` project to `recon_frontend`.
The Flask backend now serves the built Vite bundle from `recon_frontend/dist` with SPA fallback routing.

## Dependency Map Found During Repository Scan

The old frontend was not wired into runtime serving code.
Direct references to the old project were found in:

- `backend/README.md`
- `note2.txt`
- `note3.txt`
- `Cybersecurity SaaS Dashboard/README.md`
- `Cybersecurity SaaS Dashboard/index.html`

Production runtime and deploy files before migration:

- `backend/app.py`: served a simple HTML response at `/` and did not serve either frontend
- `backend/Dockerfile`: built only the Flask backend
- `docker-compose.yml`: built from `./backend` only
- `deploy/nginx/recon.conf`: proxied all traffic to Flask

## What Changed

- Flask now serves `recon_frontend/dist` and falls back to `index.html` for SPA routes.
- Docker now builds `recon_frontend` first, then copies its `dist/` output into the backend image.
- `docker-compose.yml` now builds from the repository root so Docker can access both backend and frontend.
- `recon_frontend` was wired to the existing Flask APIs:
  - `GET /me`
  - `GET /scans`
  - `GET /scan/<id>`
  - `POST /scan`
  - `POST /logout`
  - `GET /csrf`
- A frontend API config was added at `recon_frontend/src/config/api.ts`.
- Auth/session bootstrapping and a route guard were added to the new frontend.
- A new scan results page was added to `recon_frontend`.

## Files Updated

- `backend/app.py`
- `backend/config.py`
- `backend/Dockerfile`
- `backend/README.md`
- `docker-compose.yml`
- `.dockerignore`
- `recon_frontend/package.json`
- `recon_frontend/index.html`
- `recon_frontend/src/main.tsx`
- `recon_frontend/src/styles/fonts.css`
- `recon_frontend/src/app/routes.tsx`
- `recon_frontend/src/app/layouts/ReconLayout.tsx`
- `recon_frontend/src/app/pages/recon/ReconDashboard.tsx`
- `recon_frontend/src/app/pages/recon/NewScan.tsx`
- `recon_frontend/src/app/pages/recon/AssetInventory.tsx`
- `recon_frontend/src/config/api.ts`
- `recon_frontend/src/app/lib/api.ts`
- `recon_frontend/src/app/context/AuthContext.tsx`
- `recon_frontend/src/app/components/auth/RequireAuth.tsx`
- `recon_frontend/src/app/pages/recon/ScanResults.tsx`

## Backend Serving Behavior

- Built frontend path: `recon_frontend/dist`
- API paths remain handled by Flask blueprints:
  - `/auth`
  - `/admin`
  - `/scan`
  - `/scans`
  - `/csrf`
  - `/login`
  - `/logout`
  - `/me`
  - `/healthz`
  - `/readyz`
- All other unknown routes return the frontend `index.html`.

## How To Run

### Local frontend development

```powershell
cd recon_frontend
npm install
npm run dev
```

Optional API override:

```powershell
$env:VITE_API_BASE = "http://127.0.0.1:5000"
```

### Local backend

```powershell
cd backend
.\venv\Scripts\Activate.ps1
flask --app app.py run --host 0.0.0.0 --port 5000
```

### Docker

```powershell
docker compose up -d --build
```

The backend container builds `recon_frontend`, copies `dist/`, and serves it automatically.
