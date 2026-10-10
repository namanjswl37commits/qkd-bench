#!/usr/bin/env python3
"""Round-trip-time sweep on ONE Linux host, using tc netem on the loopback interface.

For each one-way delay d (ms) it adds `netem delay d` to `lo`, so every packet is delayed d ms in each
direction and the round-trip time (RTT) is about 2*d. It then measures, at that RTT:
  * ping RTT to 127.0.0.1 (confirms the emulated RTT),
  * the ETSI GS QKD 014 key fetch from the mock server (new TCP connection per fetch, and keep-alive),
  * TLS 1.3 handshakes, classical X25519 vs hybrid X25519MLKEM768 (via bench_tls.py; needs OpenSSL >= 3.5).

The RTT is EMULATED, not measured on a real network path: say so in the paper.
Needs root (or CAP_NET_ADMIN), `tc` (iproute2) and the sch_netem kernel module. Standard library only.

Usage: sudo python3 rtt_sweep.py [--delays 0,5,25,50] [--n-fetch 50] [--n-tls 30]
                                 [--openssl /opt/ossl/bin/openssl] [--skip-tls] [--out rtt_sweep.json]
       --no-netem  skips tc (all delays then equal ~0 ms): only to test the script itself.
"""
import argparse, base64, http.client, json, math, os, re, socket, statistics as st, subprocess, sys, tempfile, time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = "/api/v1/keys/ZNOC1/enc_keys?number=1&size=256"
PORT_MOCK = 8080
DEVNULL = subprocess.DEVNULL


def stats(v):
    n = len(v)
    sd = st.stdev(v) if n > 1 else 0.0
    return {"n": n, "mean_ms": st.mean(v), "median_ms": st.median(v), "sd_ms": sd,
            "ci95_ms": 1.96 * sd / math.sqrt(n) if n else 0.0}


def timeit(fn, n, warmup=3):
    for _ in range(warmup):
        fn()
    t = []
    for _ in range(n):
        s = time.perf_counter()
        fn()
        t.append((time.perf_counter() - s) * 1e3)
    return stats(t)


def netem_set(iface, one_way_ms):
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stdout=DEVNULL, stderr=DEVNULL)
    if one_way_ms > 0:
        subprocess.run(["tc", "qdisc", "add", "dev", iface, "root", "netem", "delay", "%gms" % one_way_ms],
                       check=True)


def netem_clear(iface):
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], stdout=DEVNULL, stderr=DEVNULL)


def ping_rtt(n=8):
    try:
        r = subprocess.run(["ping", "-c", str(n), "-i", "0.2", "-q", "127.0.0.1"], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", r.stdout)
    return {"min": float(m.group(1)), "avg": float(m.group(2)), "max": float(m.group(3))} if m else None


def fetch_new(url):
    with urllib.request.urlopen(url + PATH) as r:
        return base64.b64decode(json.load(r)["keys"][0]["key"])


class KeepAlive:
    def __init__(self, url):
        host, port = url.split("//")[1].split(":")
        self.c = http.client.HTTPConnection(host, int(port))
        self.c.connect()
        self.c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def get(self):
        self.c.request("GET", PATH)
        return json.loads(self.c.getresponse().read())["keys"][0]["key"]

    def close(self):
        self.c.close()


def wait_port(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 2).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def tls_at_delay(openssl, n, port):
    out = os.path.join(tempfile.gettempdir(), "tls_sweep_tmp.json")
    cmd = [sys.executable, os.path.join(HERE, "bench_tls.py"), "--role", "znoc", "--n", str(n), "--warmup", "3",
           "--openssl", openssl, "--port", str(port), "--out", out]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": (r.stdout + r.stderr).strip()[-400:]}
    j = json.load(open(out))
    g = j["groups"]
    return {k: g[k]["wall"] for k in g}


def md(res):
    head = ["one-way delay (ms)", "ping RTT avg (ms)", "fetch, new conn (ms)", "fetch, keep-alive (ms)",
            "TLS classical (ms)", "TLS hybrid (ms)", "hybrid - classical (ms)"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in res["points"]:
        def m(x):
            return "n/a" if not x else "%.2f ± %.2f" % (x["mean_ms"], x["ci95_ms"])
        tls = r.get("tls") or {}
        c, h = tls.get("X25519"), tls.get("X25519MLKEM768")
        diff = "n/a" if not (c and h) else "%.2f" % (h["mean_ms"] - c["mean_ms"])
        rtt = r["ping_rtt_ms"]["avg"] if r.get("ping_rtt_ms") else None
        lines.append("| %g | %s | %s | %s | %s | %s | %s |" % (
            r["one_way_delay_ms"], "n/a" if rtt is None else "%.2f" % rtt, m(r["fetch_new_conn"]),
            m(r["fetch_keepalive"]), m(c), m(h), diff))
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--delays", default="0,5,25,50", help="comma list of ONE-WAY delays in ms (RTT = 2x)")
    ap.add_argument("--n-fetch", type=int, default=50)
    ap.add_argument("--n-tls", type=int, default=30)
    ap.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"))
    ap.add_argument("--iface", default="lo")
    ap.add_argument("--skip-tls", action="store_true")
    ap.add_argument("--no-netem", action="store_true", help="test mode: do not touch tc")
    ap.add_argument("--out", default="rtt_sweep.json")
    a = ap.parse_args()
    delays = [float(x) for x in a.delays.split(",")]

    if not a.no_netem:
        try:
            netem_set(a.iface, 1)
            netem_clear(a.iface)
        except Exception as e:
            sys.exit("ERROR: cannot add a netem qdisc on %s (%s). Need root, iproute2 and the sch_netem module."
                     % (a.iface, e))

    mock = subprocess.Popen([sys.executable, os.path.join(HERE, "mock_etsi014_v2.py"), "--port", str(PORT_MOCK)],
                            stdout=DEVNULL, stderr=DEVNULL)
    res = {"emulated": not a.no_netem, "iface": a.iface, "method": "tc netem delay on loopback; RTT = 2 x one-way delay",
           "points": []}
    url = "http://127.0.0.1:%d" % PORT_MOCK
    try:
        if not wait_port(PORT_MOCK):
            sys.exit("ERROR: mock server did not start")
        for d in delays:
            if not a.no_netem:
                netem_set(a.iface, d)
            time.sleep(0.5)
            pt = {"one_way_delay_ms": d, "ping_rtt_ms": ping_rtt()}
            pt["fetch_new_conn"] = timeit(lambda: fetch_new(url), a.n_fetch)
            ka = KeepAlive(url)
            pt["fetch_keepalive"] = timeit(ka.get, a.n_fetch)
            ka.close()
            if not a.skip_tls:
                pt["tls"] = tls_at_delay(a.openssl, a.n_tls, 4433)
                if "error" in pt["tls"]:
                    print("TLS step failed at %g ms: %s" % (d, pt["tls"]["error"]))
                    pt["tls_error"] = pt.pop("tls")["error"]
            res["points"].append(pt)
            print("delay %g ms one-way: ping %s, fetch new %.2f ms, keep-alive %.2f ms" % (
                d, pt["ping_rtt_ms"] and pt["ping_rtt_ms"]["avg"], pt["fetch_new_conn"]["mean_ms"],
                pt["fetch_keepalive"]["mean_ms"]))
    finally:
        if not a.no_netem:
            netem_clear(a.iface)
        mock.terminate()

    json.dump(res, open(a.out, "w"), indent=2)
    table = md(res)
    note = ("\nTEST MODE (no netem): no delay was applied.\n" if a.no_netem else "") + ("\nRTT is emulated with tc netem on the loopback interface (RTT = 2 x one-way delay), not measured on a "
            "real path. The mock key server has no TLS, so the fetch excludes the PQC-protected channel; TLS rows "
            "include openssl process start-up.\n")
    open(os.path.splitext(a.out)[0] + ".md", "w").write(table + "\n" + note)
    print("\n" + table + note)
    print("wrote", a.out)
