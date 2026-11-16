"""Deliberately vulnerable SQLi target for proving the vendored nuclei templates
actually DETECT an injection (not just run without error).

The template matchers look for SQL error strings, so echoing an error when the
query parameter carries quote characters is a faithful, minimal reproduction.
Run: python3 tests/sqli_target.py [port]
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        raw = urlparse(self.path).query
        body = "<html><body><h1>Product</h1><p>id=%s</p>" % (q.get("id", [""])[0])
        # Emit a realistic backend error whenever the input looks like an injection.
        if any(tok in raw for tok in ("'", '"', "%22", "%27", "OR 1=1", "or 1=1")):
            body += ('<p>You have an error in your SQL syntax; check the manual that '
                     'corresponds to your MySQL server version for the right syntax to use near '
                     "''' at line 1</p>")
        body += "</body></html>"
        data = body.encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
    HTTPServer(("127.0.0.1", port), H).serve_forever()
