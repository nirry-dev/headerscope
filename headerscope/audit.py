"""Fetch a URL's response headers and grade its HTTP security headers.

The checks are small, independent functions over the response headers; each
returns a :class:`Finding` (ok / warn / fail) with a one-line detail and, where
it fails, the fix. A letter grade rolls them up.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

__all__ = ["Finding", "Report", "Headers", "audit_headers", "inspect"]

_UA = "headerscope/0.1 (+https://nirry.net)"
_HSTS_MIN = 15_552_000  # 180 days, in seconds


class Headers:
    """Case-insensitive view over a list of (name, value) header pairs."""

    def __init__(self, pairs: Sequence[Tuple[str, str]]) -> None:
        self._map: dict[str, List[str]] = {}
        for name, value in pairs:
            self._map.setdefault(name.lower(), []).append(value)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        values = self._map.get(name.lower())
        return values[0] if values else default

    def get_all(self, name: str) -> List[str]:
        return self._map.get(name.lower(), [])


@dataclass(frozen=True)
class Finding:
    header: str
    status: str  # "ok" | "warn" | "fail"
    detail: str


@dataclass
class Report:
    url: str
    error: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    fails: int = 0
    warns: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.fails == 0

    def __bool__(self) -> bool:
        return self.ok


# --- checks ----------------------------------------------------------------

def _transport(h: Headers, scheme: str) -> Finding:
    if scheme != "https":
        return Finding("Transport", "fail", "served over HTTP, not HTTPS")
    return Finding("Transport", "ok", "HTTPS")


def _hsts(h: Headers, scheme: str) -> Finding:
    name = "Strict-Transport-Security"
    value = h.get(name)
    if scheme != "https":
        return Finding(name, "warn", "ignored over HTTP (serve over HTTPS first)")
    if not value:
        return Finding(name, "fail", "missing (add: max-age=31536000; includeSubDomains)")
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    notes = []
    if age < _HSTS_MIN:
        notes.append(f"max-age {age} is short (< 180 days)")
    if "includesubdomains" not in value.lower():
        notes.append("no includeSubDomains")
    return Finding(name, "warn", "; ".join(notes)) if notes else Finding(name, "ok", value)


def _csp(h: Headers, scheme: str) -> Finding:
    name = "Content-Security-Policy"
    value = h.get(name)
    if not value:
        return Finding(name, "warn", "missing (recommended)")
    low = value.lower()
    notes = [note for token, note in (("'unsafe-inline'", "allows 'unsafe-inline'"), ("'unsafe-eval'", "allows 'unsafe-eval'")) if token in low]
    return Finding(name, "warn", "; ".join(notes)) if notes else Finding(name, "ok", "present")


def _xcto(h: Headers, scheme: str) -> Finding:
    name = "X-Content-Type-Options"
    value = h.get(name)
    if not value:
        return Finding(name, "fail", "missing (add: nosniff)")
    if value.strip().lower() != "nosniff":
        return Finding(name, "warn", f"is {value!r}, expected nosniff")
    return Finding(name, "ok", "nosniff")


def _xfo(h: Headers, scheme: str) -> Finding:
    name = "X-Frame-Options"
    value = h.get(name)
    if "frame-ancestors" in (h.get("content-security-policy") or "").lower():
        return Finding(name, "ok", "covered by CSP frame-ancestors")
    if not value:
        return Finding(name, "fail", "missing (clickjacking risk; add DENY or SAMEORIGIN)")
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(name, "warn", f"is {value!r}")
    return Finding(name, "ok", value.strip().upper())


def _referrer(h: Headers, scheme: str) -> Finding:
    name = "Referrer-Policy"
    value = h.get(name)
    if not value:
        return Finding(name, "warn", "missing (recommended: strict-origin-when-cross-origin)")
    if "unsafe-url" in value.lower():
        return Finding(name, "warn", "is 'unsafe-url' (leaks the full URL cross-origin)")
    return Finding(name, "ok", value)


def _permissions(h: Headers, scheme: str) -> Finding:
    name = "Permissions-Policy"
    return Finding(name, "ok", "present") if h.get(name) else Finding(name, "warn", "missing (recommended)")


def _coop(h: Headers, scheme: str) -> Finding:
    name = "Cross-Origin-Opener-Policy"
    value = h.get(name)
    return Finding(name, "ok", value) if value else Finding(name, "warn", "missing (recommended: same-origin)")


def _cookies(h: Headers, scheme: str) -> Optional[Finding]:
    cookies = h.get_all("set-cookie")
    if not cookies:
        return None
    issues = []
    for cookie in cookies:
        low = cookie.lower()
        missing = [flag for flag in ("secure", "httponly") if flag not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            issues.append(f"{cookie.split('=', 1)[0].strip()}: no {', '.join(missing)}")
    if issues:
        return Finding("Set-Cookie", "warn", "; ".join(issues[:4]))
    return Finding("Set-Cookie", "ok", f"{len(cookies)} cookie(s), flags set")


def _info_leak(h: Headers, scheme: str) -> Optional[Finding]:
    leaks = []
    server = h.get("server")
    if server and re.search(r"\d", server):
        leaks.append(f"Server: {server}")
    for header in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = h.get(header)
        if value:
            leaks.append(f"{header}: {value}")
    return Finding("Info disclosure", "warn", "; ".join(leaks)) if leaks else None


CHECKS: List[Callable[[Headers, str], Optional[Finding]]] = [
    _transport, _hsts, _csp, _xcto, _xfo, _referrer, _permissions, _coop, _cookies, _info_leak,
]


def _grade(findings: List[Finding]) -> Tuple[int, str, int, int]:
    fails = sum(1 for f in findings if f.status == "fail")
    warns = sum(1 for f in findings if f.status == "warn")
    score = max(0, 100 - 12 * fails - 4 * warns)
    letter = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return score, letter, fails, warns


def audit_headers(url: str, headers: Headers) -> Report:
    """Grade the security headers in *headers*, for a response from *url*."""
    scheme = urlsplit(url).scheme or "http"
    findings = [f for check in CHECKS if (f := check(headers, scheme)) is not None]
    score, grade, fails, warns = _grade(findings)
    return Report(url=url, findings=findings, score=score, grade=grade, fails=fails, warns=warns)


def inspect(url: str, *, timeout: float = 10.0, insecure: bool = False) -> Report:
    """Fetch *url* and audit its response headers."""
    if "://" not in url:
        url = "https://" + url
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA, "Accept": "*/*"})
    context = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            return audit_headers(resp.geturl(), Headers(resp.getheaders()))
    except urllib.error.HTTPError as err:  # an error response still has headers worth auditing
        return audit_headers(url, Headers(list(err.headers.items())))
    except urllib.error.URLError as err:
        return Report(url=url, error=str(getattr(err, "reason", err)))
    except (OSError, ValueError) as err:
        return Report(url=url, error=str(err))
