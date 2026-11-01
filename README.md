# headerscope

**Audit a site's HTTP security headers.**

Fetch a URL and headerscope grades the response's security headers — HSTS, CSP,
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and the rest — with
a letter grade and, for every gap, the one-line fix.

```text
$ headerscope example.com
https://example.com/  C (72)  2 fail, 3 warn
  ok    Transport                   HTTPS
  fail  Strict-Transport-Security   missing (add: max-age=31536000; includeSubDomains)
  warn  Content-Security-Policy     missing (recommended)
  ok    X-Content-Type-Options      nosniff
  fail  X-Frame-Options             missing (clickjacking risk; add DENY or SAMEORIGIN)
  warn  Referrer-Policy             missing (recommended: strict-origin-when-cross-origin)
  warn  Permissions-Policy          missing (recommended)
  warn  Cross-Origin-Opener-Policy  missing (recommended: same-origin)
```

No dependencies — just the Python standard library. Python 3.9+.

---

## Why

Security headers are the cheapest hardening a site has and the easiest to forget.
headerscope turns "are the headers set?" into a single command with a grade you
can watch over time and a non-zero exit you can wire into CI — so a regression
(someone drops the CSP, or HSTS quietly expires) fails the build instead of
sitting unnoticed. It reads the real response, including error responses, and
won't follow you down a rabbit hole: one fetch, one report.

## Install

```bash
pip install headerscope
```

Or vendor the `headerscope/` package — it's pure standard library, no build step.

## Use it

### On the command line

```bash
headerscope example.com                       # one site (https:// assumed)
headerscope https://a.example https://b.example --json
cat urls.txt | headerscope --summary          # one grade line per URL from stdin
headerscope https://internal.box --insecure   # skip TLS verification (internal certs)
```

Exit status: `0` when no URL has a failing header and all were reachable, `1` when
any does or can't be reached, `2` for a bad call. That makes it a CI gate:

```bash
headerscope https://example.com || echo "security headers regressed"
```

### In Python

```python
from headerscope import inspect

r = inspect("https://example.com")
r.grade, r.score      # 'C', 72
r.fails, r.warns      # 2, 3
r.ok                  # False  (there's a failing header)
for f in r.findings:
    f.status, f.header, f.detail   # 'fail', 'X-Frame-Options', 'missing (...)'
```

`inspect(url, *, timeout=10, insecure=False)` returns a `Report`; it never raises
for a bad host (that lands in `r.error`). `audit_headers(url, headers)` grades a
set of headers you already have.

## What it checks

- **Transport** — served over HTTPS at all.
- **Strict-Transport-Security** — present, with a reasonable `max-age` and
  `includeSubDomains`.
- **Content-Security-Policy** — present, and not quietly undone by `'unsafe-inline'`
  / `'unsafe-eval'`.
- **X-Content-Type-Options** — `nosniff`.
- **X-Frame-Options** — `DENY` / `SAMEORIGIN`, or a CSP `frame-ancestors`.
- **Referrer-Policy**, **Permissions-Policy**, **Cross-Origin-Opener-Policy** —
  present and sane.
- **Set-Cookie** — `Secure`, `HttpOnly`, `SameSite` on each cookie.
- **Information disclosure** — a `Server` version, `X-Powered-By`, `X-AspNet-Version`.

The grade starts at 100 and loses points per warning and more per failure
(A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F).

## What it is not

- **Not a web scanner.** It checks response headers on the URLs you give it; it
  doesn't crawl, fuzz, or test the application. Pair it with
  [netprobe](https://github.com/nirry-dev/netprobe) to find the services and
  [certpeek](https://github.com/nirry-dev/certpeek) to check the certificate.
- **Not a CSP analyzer.** It flags the obvious CSP foot-guns; it doesn't fully
  parse a policy for every bypass.

## License

MIT. Part of [Nirry Labs](https://nirry.net) — local-first AI and security tools,
dependency-light and auditable by design.
