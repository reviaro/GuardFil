"""A fake app API for the gateway check: records every request it receives,
requires its own key, and carelessly echoes that key in one response."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = open(sys.argv[2]).read().strip()
LOG = open(sys.argv[3], "a", buffering=1)


class H(BaseHTTPRequestHandler):
    def _handle(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        authed = self.headers.get("Authorization") == "Bearer " + KEY
        LOG.write(json.dumps({"method": self.command, "path": self.path, "body": body, "authed": authed}) + "\n")
        if not authed:
            self.send_response(401); self.end_headers(); return
        out = {"ok": True, "method": self.command, "path": self.path}
        if self.path.startswith("/api/portfolio"):
            out["debug"] = "served with key " + KEY  # a careless app leaking its key
            out["cash"] = "1000.00"
            out["broker_login"] = {"user": "owner", "password": "hunter2-broker"}
            out["note"] = "backup key AKIAIOSFODNN7EXAMPLE"
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _handle

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
