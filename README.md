# Server Management Panel v2.0

Production-oriented admin console for monitoring its current Render runtime and managing an explicit allowlist of Render services. PostgreSQL stores users, sessions and audit records.

## What changed

- Replaces unauthenticated Docker container operations with a server-side Render API integration. Render web services do not get privileged access to the host Docker socket, so arbitrary Docker start/stop commands are intentionally not exposed.
- Opaque server-side sessions; HttpOnly and SameSite=Strict cookies; Secure cookies in production; CSRF token checks; login rate limiting; strict same-origin mutation checks.
- PostgreSQL schema bootstrap, scrypt password hashes, Admin/Operator/Viewer roles, user activation/role/password changes, and protection against removing the last active admin.
- Audit trail for login attempts, user changes and Render service operations.
- Runtime health checks, process memory/uptime telemetry, Render service inventory and deployment history.
- Admin-only deploy/restart actions restricted to RENDER_ALLOWED_SERVICE_IDS.
- Helmet security headers, parameterized SQL, bounded request bodies, sanitized client errors and structured logging.

## Render deployment

1. Review render.yaml in branch production-v2 before syncing the Blueprint. It defines a Starter web service and a `basic_256mb` Render Postgres database in Singapore; both are paid resources. Confirm current pricing and billing authorization in Render before provisioning.
2. Sync the Blueprint. Render creates the web service and database and wires DATABASE_URL through the private database connection. SESSION_SECRET is generated automatically.
3. Configure APP_ORIGIN (exact HTTPS origin without trailing slash), BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD when prompted. Confirm the generated service URL and set APP_ORIGIN to that exact `https://...onrender.com` origin.
4. Deploy and wait for /healthz to pass. Sign in using the bootstrap admin once the first boot finishes.
5. Remove BOOTSTRAP_ADMIN_PASSWORD from the live environment after the admin account is created. Existing users are not reset on subsequent restarts.
6. For Render service control, configure RENDER_API_KEY and a narrow list of exact IDs in RENDER_ALLOWED_SERVICE_IDS. Without an allowlist, no remote service can be controlled. Never commit API keys.

The service fails startup when DATABASE_URL or a 32+ character SESSION_SECRET is missing. Production startup also requires APP_ORIGIN to be the exact HTTPS origin. An empty database requires the bootstrap admin credentials. The Blueprint uses sync:false for secrets; Render prompts for them at setup.

## Local workflow

Use Node.js 20+ and PostgreSQL. Copy .env.example to .env, supply local values, then run:

    npm install
    npm run check
    npm test
    npm start

CI uses Node.js 22 and runs syntax checks and tests for main and production-v2 pushes and pull requests targeting main.

## API endpoints

- GET /healthz: readiness check including database connectivity.
- GET /api/v1/meta: service metadata.
- POST /api/v1/auth/login, GET /api/v1/auth/me, POST /api/v1/auth/logout: session auth.
- GET /api/v1/monitoring/local: current process and instance runtime snapshot.
- GET /api/v1/services and GET /api/v1/services/:id/deploys: Admin/Operator only.
- POST /api/v1/services/:id/deploy and POST /api/v1/services/:id/restart: Admin only; CSRF token required.
- GET /api/v1/users, POST /api/v1/users, PATCH /api/v1/users/:id: Admin only.
- GET /api/v1/audit-logs: Admin only.

Mutation requests must send X-CSRF-Token returned by login or /api/v1/auth/me. Session tokens are never returned in JSON or stored in local storage.

## Scope and operational notes

Runtime telemetry describes the current app instance, not an account-wide host or full metrics history. Remote operations affect only allowlisted Render service IDs. No public shell execution, arbitrary Docker access, secret disclosure or destructive service deletion endpoint is provided.

Configure database backups, secret rotation, minimum-privilege API keys and your organization’s MFA requirements before broad exposure. A green CI run does not by itself prove a Render deployment is live; verify deployment and /healthz after completing environment setup.