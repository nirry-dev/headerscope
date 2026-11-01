# Changelog

All notable changes to headerscope are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-11-01

First release.

### Added
- `inspect(url, ...)` — fetch a URL and grade its HTTP security headers, returning
  a `Report` (truthy when nothing fails) with a letter grade, a score, and a
  `Finding` (ok / warn / fail + the fix) per check. `audit_headers(url, headers)`
  grades headers you already have.
- Checks: Transport (HTTPS), HSTS, CSP (incl. `'unsafe-inline'` / `'unsafe-eval'`),
  X-Content-Type-Options, X-Frame-Options (or CSP `frame-ancestors`),
  Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Set-Cookie
  flags, and information-disclosure headers.
- A `headerscope` command-line tool: URLs from arguments or stdin, `--summary`,
  `--insecure`, `--json`, and a CI-friendly exit code. Also `python -m headerscope`.
- Pure standard library.
