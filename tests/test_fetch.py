import unittest

from headerscope import inspect
from tests.server import serve, stop, url_of


def find(report, header):
    return next(f for f in report.findings if f.header == header)


class TestFetch(unittest.TestCase):
    def test_reads_headers_from_a_server(self):
        srv = serve([("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Server", "tiny/9.9")])
        try:
            r = inspect(url_of(srv), timeout=5)
            self.assertIsNone(r.error)
            self.assertEqual(find(r, "X-Content-Type-Options").status, "ok")
            self.assertEqual(find(r, "X-Frame-Options").status, "ok")
            self.assertEqual(find(r, "Transport").status, "fail")  # the test server is plain HTTP
            self.assertEqual(find(r, "Info disclosure").status, "warn")  # Server reveals a version
        finally:
            stop(srv)

    def test_unreachable_host(self):
        r = inspect("http://127.0.0.1:1/", timeout=2)
        self.assertIsNotNone(r.error)
        self.assertFalse(r.ok)


if __name__ == "__main__":
    unittest.main()
