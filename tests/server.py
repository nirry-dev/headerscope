"""A local HTTP server that returns chosen headers — for the fetch tests."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    extra = ()

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        for name, value in self.extra:
            self.send_header(name, value)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"ok")


def serve(headers):
    handler = type("_H", (_Handler,), {"extra": tuple(headers)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop(server):
    server.shutdown()
    server.server_close()


def url_of(server):
    return f"http://127.0.0.1:{server.server_address[1]}/"
