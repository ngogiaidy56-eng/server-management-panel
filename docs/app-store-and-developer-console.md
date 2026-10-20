# App Store and Developer Console

Two separate web experiences are served by the Express app:

- / is the public Hendy App Store. It reads only published app metadata and published releases.
- /admin is the existing operations console for users, monitoring and Render service operations.
- /admin/studio is the authenticated Developer Console for app metadata, releases and publishing.

## Release workflow

1. Sign in at /admin/studio using an existing account.
2. Create an app. It starts as draft and is not shown publicly.
3. Upload the binary to object storage or a CDN using your storage workflow. The console records an HTTPS package URL; it does not upload binary files.
4. Add a semantic version, platform, package URL, optional SHA-256 checksum and release notes. A release defaults to draft.
5. Publish a release and then publish the app. The public API filters drafts server-side.
6. Verify GET /api/v1/store/apps and GET /api/v1/store/apps/:slug before distributing the link.

## API

- GET /api/v1/store/apps: public published catalog.
- GET /api/v1/store/apps/:slug: app detail and published releases.
- GET /api/v1/admin/apps: authenticated Admin/Operator inventory.
- POST /api/v1/admin/apps: Admin-only app creation.
- POST /api/v1/admin/apps/:id/releases: Admin-only release creation.
- POST /api/v1/admin/apps/:id/publish: Admin-only publish action; requires a published release.

Mutation requests retain the existing same-origin and CSRF checks. Package URLs must be HTTPS and cannot contain embedded credentials. Optional checksums must be 64 hexadecimal SHA-256 characters. Package files remain in external object storage; PostgreSQL stores metadata and links.

## Production validation

Verify migrations, API tests, GitHub Actions, Render build, database connectivity and a live /healthz response before treating the release as production-ready. Do not put private package URLs or unpublished releases into public API responses.
