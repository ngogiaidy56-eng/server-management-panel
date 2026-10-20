# Security Model

## Identity and sessions
- Passwords use salted scrypt; plaintext passwords are not persisted or logged.
- Session tokens are random and opaque. PostgreSQL stores an HMAC hash, not the token.
- Cookies are HttpOnly and SameSite=Strict; Secure is enabled in production.
- Sessions expire after 12 hours and expired rows are periodically removed.
- Login success/failure, user changes and Render operations are written to the audit log.

## Request defenses
- Helmet configures security headers and a restrictive same-origin Content Security Policy.
- API responses use no-store caching headers.
- State-changing API requests require `Content-Type: application/json` and a trusted origin. If Origin is absent, Fetch Metadata must explicitly identify a same-origin request.
- Authenticated state-changing requests additionally require `X-CSRF-Token`.
- JSON body size and request rates are bounded, SQL parameters are bound, user-controlled output is inserted as text in the UI, and server errors are sanitized for clients.
- Requests receive an `X-Request-Id` and structured path/method/status/duration logs.

## Role matrix

| Capability | Viewer | Operator | Admin |
| --- | --- | --- | --- |
| Read runtime snapshot and health | Yes | Yes | Yes |
| Read allowlisted Render services | No | Yes | Yes |
| Read deployment history | No | Yes | Yes |
| Trigger deployment or restart | No | No | Yes |
| List/create/edit users | No | No | Yes |
| Read audit history | No | No | Yes |

Role checks execute in backend middleware; hiding a UI tab is not considered authorization.

## Render integration
- `RENDER_API_KEY` is used only on the server.
- Operations require an exact ID in `RENDER_ALLOWED_SERVICE_IDS`.
- There is no public shell execution, arbitrary Docker socket access, environment-secret disclosure or destructive service deletion route.
- Missing integration configuration does not grant wider permissions.

## Operational boundaries
- `/healthz` checks PostgreSQL because authentication depends on the database.
- Resource statistics describe the current application instance, not account-wide infrastructure or historical metrics.
- The login rate limiter uses the in-process store. Multi-instance deployments needing globally consistent limits should add a shared store.
- SSO, MFA, identity-provider provisioning and automated secret rotation are not implemented by this application; add them if required by the threat model.
- PostgreSQL backup retention, recovery drills, workspace governance and API-key rotation remain operational responsibilities.
