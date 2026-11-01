# Security Policy

## Reporting a vulnerability

Please report security issues privately to **info@nirry.net** rather than in a
public issue. You'll get an acknowledgement, and a fix or a clear explanation.

## Design notes

- headerscope makes one GET request per URL you give it, reads the response
  headers, and reports. It does not crawl, follow its own links, submit forms, or
  execute anything from the response.
- TLS certificates are verified by default; `--insecure` disables verification
  for internal hosts and is opt-in.
- An error response (4xx/5xx) is still audited — its security headers are the
  server's, and worth grading — rather than discarded.

## Supported versions

Fixes land on the latest release.
