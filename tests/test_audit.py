import unittest

from headerscope.audit import Headers, audit_headers

SECURE = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
]


def find(report, header):
    return next(f for f in report.findings if f.header == header)


class TestAudit(unittest.TestCase):
    def test_fully_secured_is_an_A(self):
        r = audit_headers("https://x.example/", Headers(SECURE))
        self.assertEqual(r.grade, "A")
        self.assertEqual(r.fails, 0)
        self.assertEqual(r.warns, 0)
        self.assertTrue(r.ok)

    def test_bare_https_fails_the_essentials(self):
        r = audit_headers("https://x.example/", Headers([]))
        self.assertEqual(r.fails, 3)  # HSTS, X-Content-Type-Options, X-Frame-Options
        self.assertEqual(find(r, "Strict-Transport-Security").status, "fail")
        self.assertEqual(find(r, "X-Frame-Options").status, "fail")
        self.assertEqual(r.grade, "F")
        self.assertFalse(r.ok)

    def test_http_scheme_fails_transport(self):
        r = audit_headers("http://x.example/", Headers(SECURE))
        self.assertEqual(find(r, "Transport").status, "fail")
        self.assertEqual(find(r, "Strict-Transport-Security").status, "warn")

    def test_xcto_wrong_value(self):
        r = audit_headers("https://x/", Headers([("X-Content-Type-Options", "sniff")]))
        self.assertEqual(find(r, "X-Content-Type-Options").status, "warn")

    def test_frame_ancestors_covers_xfo(self):
        r = audit_headers("https://x/", Headers([("Content-Security-Policy", "frame-ancestors 'none'")]))
        self.assertEqual(find(r, "X-Frame-Options").status, "ok")

    def test_csp_unsafe_inline_warns(self):
        r = audit_headers("https://x/", Headers([("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")]))
        self.assertEqual(find(r, "Content-Security-Policy").status, "warn")

    def test_cookie_flags(self):
        bad = audit_headers("https://x/", Headers([("Set-Cookie", "sid=abc; Path=/")]))
        self.assertEqual(find(bad, "Set-Cookie").status, "warn")
        good = audit_headers("https://x/", Headers([("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")]))
        self.assertEqual(find(good, "Set-Cookie").status, "ok")
        none = audit_headers("https://x/", Headers([]))
        self.assertFalse(any(f.header == "Set-Cookie" for f in none.findings))

    def test_info_disclosure(self):
        r = audit_headers("https://x/", Headers([("Server", "nginx/1.25.3"), ("X-Powered-By", "PHP/8.1")]))
        self.assertEqual(find(r, "Info disclosure").status, "warn")


if __name__ == "__main__":
    unittest.main()
