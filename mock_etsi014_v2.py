"""Minimal mock of an ETSI GS QKD 014 key-delivery server. TESTING ONLY: no TLS, no authentication.

Same behaviour as mock_etsi014.py, plus --host/--port (so the R-NOC can serve the Z-NOC over the
network) and HTTP/1.1 keep-alive. Default stays 127.0.0.1:8080.
Because there is no TLS here, measured fetch latency EXCLUDES the cost of the PQC-protected
delivery channel described in the paper.
"""
import argparse, base64, json, os, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

STORE = {}  # key_ID -> key bytes


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 65536               # send headers+body in one segment (avoids 40 ms Nagle/delayed-ACK stalls)
    disable_nagle_algorithm = True

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.strip("/").split("/")  # api/v1/keys/{SAE_ID}/{op}
        if len(p) != 5 or p[:3] != ["api", "v1", "keys"]:
            return self._send(400, {"message": "bad request"})
        op = p[4]
        if op == "status":
            return self._send(200, {"key_size": 256, "stored_key_count": len(STORE)})
        if op == "enc_keys":
            n = int(q.get("number", ["1"])[0])
            size = int(q.get("size", ["256"])[0])
            keys = []
            for _ in range(n):
                kid, k = str(uuid.uuid4()), os.urandom(size // 8)
                STORE[kid] = k
                keys.append({"key_ID": kid, "key": base64.b64encode(k).decode()})
            return self._send(200, {"keys": keys})
        if op == "dec_keys":
            ids = q.get("key_ID", [])
            if any(i not in STORE for i in ids):
                return self._send(400, {"message": "unknown key_ID"})
            return self._send(200, {"keys": [
                {"key_ID": i, "key": base64.b64encode(STORE.pop(i)).decode()} for i in ids]})
        self._send(404, {"message": "not found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    print("mock ETSI 014 on http://%s:%d  (no TLS, no auth: isolated test network only)" % (a.host, a.port))
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()
