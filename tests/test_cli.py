import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from headerscope.cli import main
from tests.server import serve, stop, url_of


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_table_and_exit(self):
        srv = serve([("X-Content-Type-Options", "nosniff")])  # still HTTP -> a transport fail
        try:
            code, out, _ = run([url_of(srv)])
            self.assertEqual(code, 1)  # a failing header is present
            self.assertIn("X-Content-Type-Options", out)
            self.assertIn("fail", out)
        finally:
            stop(srv)

    def test_summary_only(self):
        srv = serve([("X-Content-Type-Options", "nosniff")])
        try:
            _, out, _ = run([url_of(srv), "--summary"])
            self.assertNotIn("Transport", out)  # findings suppressed
            self.assertIn("fail", out)  # the grade line still shows counts
        finally:
            stop(srv)

    def test_json(self):
        srv = serve([("X-Content-Type-Options", "nosniff")])
        try:
            _, out, _ = run([url_of(srv), "--json"])
            data = json.loads(out)
            self.assertEqual(len(data), 1)
            self.assertIn("findings", data[0])
            self.assertIn("grade", data[0])
        finally:
            stop(srv)

    def test_unreachable_exits_1(self):
        code, out, _ = run(["http://127.0.0.1:1/", "--timeout", "2"])
        self.assertEqual(code, 1)
        self.assertIn("ERROR", out)


if __name__ == "__main__":
    unittest.main()
