"""E2/E3/E4: K_tunnel = HKDF(K_QKD || K_PQC || K_ECDHE, ctx) cost, plus AES-256-GCM throughput.

Improves hkdf_bench.py: untimed warm-up (the first call was inflating the mean), mean/median/sd/95% CI,
refuses to run with a SIMULATED ML-KEM unless --allow-simulated (a simulated KEM makes the 'hybrid'
numbers meaningless), isolates the QKD fetch, optional keep-alive fetch, macOS-safe RSS, GCM median of 3.

Usage: python hkdf_bench_v2.py --role znoc [--n 200] [--qkd-url http://<R-NOC>:8080] [--out hkdf_znoc.json]
Needs: pip install cryptography liboqs-python
"""
import argparse, base64, http.client, json, math, os, resource, socket, statistics as st, sys, time, urllib.request
from urllib.parse import urlparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import oqs
    HAVE_OQS = True
except Exception:
    HAVE_OQS = False

CTX = b"znoc1|rnoc1|session-0001|2026-10-07"
PATH = "/api/v1/keys/ZNOC1/enc_keys?number=1&size=256"


def timeit(fn, n, warmup=20):
    for _ in range(warmup):
        fn()
    t, c0 = [], time.process_time()
    for _ in range(n):
        s = time.perf_counter()
        fn()
        t.append((time.perf_counter() - s) * 1e3)
    cpu = (time.process_time() - c0) / n * 1e3
    sd = st.stdev(t) if n > 1 else 0.0
    ts = sorted(t)
    return {"n": n, "mean_ms": st.mean(t), "median_ms": st.median(t), "sd_ms": sd,
            "ci95_ms": 1.96 * sd / math.sqrt(n), "p95_ms": ts[min(n - 1, int(0.95 * n))], "cpu_ms": cpu}


def get_qkd_new(url):
    """New TCP connection per fetch."""
    with urllib.request.urlopen(url + PATH) as r:
        return base64.b64decode(json.load(r)["keys"][0]["key"])


class KeepAlive:
    """One persistent HTTP/1.1 connection (needs mock_etsi014_v2.py)."""
    def __init__(self, url):
        u = urlparse(url)
        self.c = http.client.HTTPConnection(u.hostname, u.port or 80)
        self.c.connect()
        self.c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def get(self):
        self.c.request("GET", PATH)
        r = self.c.getresponse()
        return base64.b64decode(json.loads(r.read())["keys"][0]["key"])


def k_ecdhe():
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    return a.exchange(b.public_key())


def k_pqc():
    if not HAVE_OQS:
        return os.urandom(32)  # SIMULATED
    with oqs.KeyEncapsulation("ML-KEM-768") as cli, oqs.KeyEncapsulation("ML-KEM-768") as srv:
        pk = cli.generate_keypair()
        ct, ss = srv.encap_secret(pk)
        return cli.decap_secret(ct)


def derive(*secrets):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CTX).derive(b"".join(secrets))


def gcm_throughput(size, seconds=1.0):
    aead, ctr, buf = AESGCM(os.urandom(32)), 0, os.urandom(size)
    done, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        aead.encrypt(ctr.to_bytes(12, "big"), buf, None)
        ctr += 1
        done += size
    return done / seconds / 1e6


def rss_mb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024 * 1024) if sys.platform == "darwin" else r / 1024


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", required=True, choices=["endpoint", "znoc", "rnoc"])
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--qkd-url", default="")
    ap.add_argument("--allow-simulated", action="store_true")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    if not HAVE_OQS and not a.allow_simulated:
        sys.exit("ERROR: liboqs-python not importable, so ML-KEM-768 would be SIMULATED. "
                 "Install it, or pass --allow-simulated for a dry run (never for paper numbers).")

    kq, kp, ke = os.urandom(32), os.urandom(32), os.urandom(32)
    res = {"role": a.role,
           "pqc_source": "liboqs ML-KEM-768 (%s)" % oqs.oqs_version() if HAVE_OQS else "SIMULATED random",
           "qkd_source": a.qkd_url or "SIMULATED random",
           "hkdf_only": timeit(lambda: derive(kq, kp, ke), a.n),
           "ecdhe_only": timeit(lambda: derive(k_ecdhe()), a.n),
           "hybrid_pqc_ecdhe": timeit(lambda: derive(k_pqc(), k_ecdhe()), a.n)}
    if a.qkd_url:
        ka = KeepAlive(a.qkd_url)
        res["qkd_fetch_only"] = timeit(lambda: get_qkd_new(a.qkd_url), a.n)
        res["qkd_fetch_only_keepalive"] = timeit(ka.get, a.n)
        res["hybrid_plus_qkd"] = timeit(lambda: derive(get_qkd_new(a.qkd_url), k_pqc(), k_ecdhe()), a.n)
        res["hybrid_plus_qkd_keepalive"] = timeit(lambda: derive(ka.get(), k_pqc(), k_ecdhe()), a.n)
    else:
        res["hybrid_plus_qkd"] = timeit(lambda: derive(os.urandom(32), k_pqc(), k_ecdhe()), a.n)
    res["gcm_MBps"] = {str(s): st.median([gcm_throughput(s) for _ in range(3)]) for s in (1024, 65536, 1048576)}
    res["benchmark_process_peak_rss_MB"] = rss_mb()
    out = a.out or "hkdf_%s.json" % a.role
    json.dump(res, open(out, "w"), indent=2)
    for k, v in res.items():
        print(k, v)
    print("wrote", out)
