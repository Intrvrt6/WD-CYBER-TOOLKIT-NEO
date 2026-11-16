"""Minimal OpenAI-compatible mock so the Artax endpoint path is provably exercised."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"no key"}')
            return
        msgs = body.get("messages", [])
        user = next((m["content"] for m in reversed(msgs) if m["role"] == "user"), "")
        has_ctx = any("EVIDENCE CONTEXT" in (m.get("content") or "") for m in msgs)
        answer = ("MODEL-ANSWER ok=1 context_attached=%s question=%r" % (has_ctx, user[:60]))
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for chunk in answer.split(" "):
                payload = {"choices": [{"delta": {"content": chunk + " "}}]}
                self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            return
        payload = {"model": body.get("model", "mock"),
                   "choices": [{"message": {"role": "assistant", "content": answer}}],
                   "usage": {"prompt_tokens": 10, "completion_tokens": 12}}
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8791), H).serve_forever()
