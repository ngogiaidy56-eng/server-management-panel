# Production Operations Runbook

## Architecture
- Node.js 22 + Express web application.
- Render PostgreSQL stores users, sessions and audit records.
- Browser sessions use opaque random tokens; only an HMAC hash is stored.
- Optional Render service control is restricted by the exact IDs in `RENDER_ALLOWED_SERVICE_IDS`.
- Readiness endpoint: `GET /healthz`. Metadata endpoint: `GET /api/v1/meta`.

## First deployment checklist
1. Review `render.yaml` and current resource pricing before syncing the Blueprint.
2. Set `APP_ORIGIN` to the exact HTTPS service origin without a trailing slash.
3. Provide a unique `BOOTSTRAP_ADMIN_EMAIL` and strong `BOOTSTRAP_ADMIN_PASSWORD`. Do not commit these values.
4. Confirm the service is connected to PostgreSQL and `DATABASE_URL` is populated. Confirm `SESSION_SECRET` has at least 32 characters.
5. Deploy and confirm `GET /healthz` returns HTTP 200. A successful build alone does not prove a live service.
6. Sign in, create any additional named accounts, assign least-privilege roles, and remove `BOOTSTRAP_ADMIN_PASSWORD` from the service environment after bootstrap.
7. Configure `RENDER_API_KEY` and `RENDER_ALLOWED_SERVICE_IDS` only when remote Render control is required. Use a least-privilege key and exact service IDs.
8. Verify sign-in, logout, CSRF rejection, a 401 for an unauthenticated protected API and a 403 when Viewer attempts an Admin-only route.

## Required environment

| Variable | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | Yes | Prefer the Render Postgres internal connection URL. |
| `SESSION_SECRET` | Yes | At least 32 characters. |
| `APP_ORIGIN` | Production | Exact HTTPS origin without trailing slash. |
| `BOOTSTRAP_ADMIN_EMAIL` | Empty database only | Creates the first Admin once. |
| `BOOTSTRAP_ADMIN_PASSWORD` | Empty database only | Remove after bootstrap. |
| `PG_POOL_MAX` | No | Integer 1–50; defaults to 10. |
| `RENDER_API_KEY` | Optional | Server-side only. |
| `RENDER_ALLOWED_SERVICE_IDS` | Optional | Comma-separated exact IDs; empty means no remote control. |

## Release verification
- Confirm the latest deployment uses the expected commit and reaches a terminal `live` state.
- Request `/healthz` and verify HTTP 200.
- Inspect recent application logs for `startup_failed`, `request_failed` and `session_cleanup_failed`.
- Run smoke tests for sign-in, logout, CSRF rejection, role restrictions and user deactivation.
- Do not declare a release healthy based only on a successful image/build step.

## Common failures
- `DATABASE_URL is required`: connect PostgreSQL or set the correct connection URL.
- `SESSION_SECRET must be at least 32 characters`: set a long random secret in Render.
- `APP_ORIGIN must be HTTPS`: use the exact public HTTPS origin without a trailing slash.
- `No admin exists`: provide bootstrap credentials when starting an empty database.
- Build failure: inspect the earliest failing build step rather than the final generic error.
- GitHub Actions run with no runner steps/logs: inspect repository/organization Actions billing, policy and runner availability. Repeating an identical job cannot fix a runner that never starts.

## Recovery
- Restore dependency connectivity or service capacity before making data changes.
- Use Render Postgres backup/restore for the configured database plan; test restoration procedures before relying on them.
- Never place a DB URL, API key, deploy hook, session cookie or password in a ticket or log.
- Do not delete/recreate a database to fix an application startup issue without confirming whether it contains production data.
- After recovery, verify the live deploy, readiness endpoint, login, role boundaries and fresh runtime logs.
