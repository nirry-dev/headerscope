"""headerscope — audit a site's HTTP security headers.

Fetch a URL and grade the response's security headers — HSTS, CSP,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy and the rest — with a
letter grade and, for each gap, the fix.

    >>> from headerscope import inspect
    >>> r = inspect("https://example.com")       # doctest: +SKIP
    >>> r.grade, r.fails                           # doctest: +SKIP
    ('B', 1)

Pure standard library.
"""

from .audit import Finding, Headers, Report, audit_headers, inspect

__version__ = "0.1.0"

__all__ = ["inspect", "audit_headers", "Report", "Finding", "Headers", "__version__"]
