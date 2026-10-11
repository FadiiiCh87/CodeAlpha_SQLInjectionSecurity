# SQL Injection Defense — CodeAlpha

## Features
- SQLAlchemy ORM for parameterized SQL access; password hashes, AES-256-GCM encrypted notes.
- Session-bound capability required for reading notes; logout invalidates session.
- Basic per-process login throttling (8 failed attempts per username/IP per five minutes), security headers, secure cookies when COOKIE_SECURE=1.
- Automated regression tests for injection attempts, access controls, encryption and throttling.

## API
POST /api/register, POST /api/login, GET /api/note (X-Capability header), POST /api/logout, GET /health.

## Configuration
Required: `AES256_KEY_HEX` (64 random hex characters), `SECRET_KEY` (long random value). Production: `COOKIE_SECURE=1`, `DATABASE_URL` (PostgreSQL). Set these privately in Render; never commit keys.

## Tests
`python -m pytest -q`. CI runs on pushes.

## Limitations
Educational security demo, not a penetration-tested production service. In-memory rate limiting is per process and should be replaced with Redis-backed limits for multiple instances. Add CSRF protection for cookie-authenticated mutations, centralized audit logs, migration management and external security assessment before production. SQLite on ephemeral storage is not persistent.
