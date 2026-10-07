# ADR-007: Authentication
- Passwords: Argon2id, hashed in a worker thread; unknown-email logins spend the same time as real ones.
- Access token: HS256 JWT, 15 minutes, carries user id and tenant id; the server also checks the user is active and in that tenant on every request.
- Refresh token: random opaque value in an HttpOnly, SameSite=Strict cookie limited to /api/v1/auth; only its SHA-256 hash is stored; rotated on every use; reuse of an old token revokes all of the user's sessions.
- Tests run against a separate shield_test database with a NullPool engine.
Known limitations (accepted for now):
- Access tokens stay valid until they expire (15 minutes) after logout; deactivation takes effect immediately because of the per-request check.
- Registration reveals whether an email exists (409). Mitigation planned: rate limiting. Email verification is out of scope.
- Login and registration rate limiting is NOT done yet (step 1.3c, using Redis).
- Two browser tabs refreshing at the exact same moment can look like token reuse and log the user out. Acceptable for this project.
