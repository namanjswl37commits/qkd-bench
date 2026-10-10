#!/usr/bin/env python3
"""Emulated Z-NOC <-> R-NOC uplink in two Linux network namespaces, with a real AES-256-GCM (ESP) tunnel.

Measures what the single-host scripts cannot:
  * tunnel throughput through the Z-NOC uplink: plain vs ESP AES-256-GCM vs ESP while keys are refreshed every tau s
    (iperf3, at several emulated one-way delays);
  * cost of one key refresh: ETSI-014-style key fetch + ML-KEM-768 + X25519 + HKDF + install of the new SA pair;
  * cost of refreshing N tunnels at once (default N = 100 and 1000) and kernel memory taken by N SA pairs.

How it works
  - namespaces `znoc` and `rnoc` joined by a veth pair (10.0.2.1 <-> 10.0.2.2); `tc netem` adds delay on both ends;
  - K_tunnel = HKDF-SHA256(K_QKD || K_PQC || K_ECDHE, ctx) -> 72 bytes = two (32-byte key + 4-byte salt), one per direction;
  - the keys are installed as kernel IPsec (ESP, transport mode, rfc4106(gcm(aes)) 256-bit) SAs with `ip xfrm`;
  - a refresh adds the new SA pair, then deletes the old one (make-before-break).
Limits (state them in the paper): links are emulated, both ends run on one host, the harness hands both ends the same
derived key (the key-agreement messages are computed locally, not exchanged), SAs are installed through the `ip`
command (a netlink implementation would be cheaper), and the key source is an ETSI-014-style mock with no QKD hardware.

Needs: Linux, root, Python >= 3.12 (os.setns), iproute2, iperf3, kernel modules for xfrm/esp/gcm/netem,
pip install cryptography [liboqs-python].   Usage: sudo python3 topo_bench.py [--delays 0,10] [--dur 10] [--tau 1]
"""
import argparse, base64, http.client, itertools, json, math, os, re, socket, statistics as st, subprocess, sys
import tempfile, threading, time
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    import oqs
    HAVE_OQS = True
except Exception:
    HAVE_OQS = False

HERE = os.path.dirname(os.path.abspath(__file__))
L, R = "10.0.2.1", "10.0.2.2"
PATH = "/api/v1/keys/ZNOC1/enc_keys?number=1&size=256"
ALG = "rfc4106(gcm(aes))"
SPI = itertools.count(0x1000)


def run(cmd, ns=None, check=True, timeout=None):
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError("%s -> %s" % (" ".join(cmd), (r.stderr or r.stdout).strip()))
    return r


@contextmanager
def in_ns(name):
    """Create sockets inside a namespace (a socket stays in the namespace it was created in)."""
    home = os.open("/proc/self/ns/net", os.O_RDONLY)
    tgt = os.open("/var/run/netns/" + name, os.O_RDONLY)
    try:
        os.setns(tgt, os.CLONE_NEWNET)
        yield
    finally:
        os.setns(home, os.CLONE_NEWNET)
        os.close(home)
        os.close(tgt)


class KeepAlive:
    def __init__(self, ns, host, port):
        with in_ns(ns):
            self.c = http.client.HTTPConnection(host, port, timeout=10)
            self.c.connect()
        self.c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            self.c.request("GET", PATH)
            return base64.b64decode(json.loads(self.c.getresponse().read())["keys"][0]["key"])


def k_ecdhe():
    return X25519PrivateKey.generate().exchange(X25519PrivateKey.generate().public_key())


def k_pqc():
    if not HAVE_OQS:
        return os.urandom(32)  # SIMULATED
    with oqs.KeyEncapsulation("ML-KEM-768") as cli, oqs.KeyEncapsulation("ML-KEM-768") as srv:
        ct, _ = srv.encap_secret(cli.generate_keypair())
        return cli.decap_secret(ct)


def derive(kq, kp, ke, ctx):
    return HKDF(algorithm=hashes.SHA256(), length=72, salt=None, info=ctx).derive(kq + kp + ke)


def st_add(src, dst, spi, key):
    return "xfrm state add src %s dst %s proto esp spi 0x%x mode transport aead %s 0x%s 128" % (
        src, dst, spi, ALG, key.hex())


def st_del(src, dst, spi):
    return "xfrm state delete src %s dst %s proto esp spi 0x%x" % (src, dst, spi)


def batch(ns, lines):
    with tempfile.NamedTemporaryFile("w", suffix=".batch", delete=False) as f:
        f.write("\n".join(lines) + "\n")
    try:
        run(["ip", "-batch", f.name], ns=ns)
    finally:
        os.unlink(f.name)


class Tunnel:
    def __init__(self, ka):
        self.ka, self.cur, self.n = ka, None, 0

    def flush(self):
        for ns in ("znoc", "rnoc"):
            run(["ip", "xfrm", "state", "flush"], ns=ns, check=False)
            run(["ip", "xfrm", "policy", "flush"], ns=ns, check=False)
        self.cur = None

    def policies(self):
        pol = lambda s, d, dr: "xfrm policy add src %s/32 dst %s/32 dir %s tmpl src %s dst %s proto esp mode transport" % (
            s, d, dr, s, d)
        batch("znoc", [pol(L, R, "out"), pol(R, L, "in")])
        batch("rnoc", [pol(R, L, "out"), pol(L, R, "in")])

    def new_keys(self):
        """Fetch K_QKD, run ML-KEM + X25519, HKDF. Returns (spi_ab, spi_ba, key_ab, key_ba)."""
        self.n += 1
        okm = derive(self.ka.get(), k_pqc(), k_ecdhe(), b"znoc1|rnoc1|session-%06d" % self.n)
        return next(SPI), next(SPI), okm[:36], okm[36:]

    def rekey(self):
        t0 = time.perf_counter()
        a, b, ka_, kb_ = self.new_keys()
        t1 = time.perf_counter()
        add = [st_add(L, R, a, ka_), st_add(R, L, b, kb_)]
        batch("znoc", add)
        batch("rnoc", add)
        if self.cur:
            old = [st_del(L, R, self.cur[0]), st_del(R, L, self.cur[1])]
            batch("znoc", old)
            batch("rnoc", old)
        self.cur = (a, b)
        t2 = time.perf_counter()
        return (t1 - t0) * 1e3, (t2 - t1) * 1e3


def cpu_s():
    a = os.times()
    return a.user + a.system + a.children_user + a.children_system


def slab_kb():
    d = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":")
        d[k] = int(v.split()[0])
    return d["Slab"], d["MemAvailable"]


def stats(v):
    n = len(v)
    sd = st.stdev(v) if n > 1 else 0.0
    return {"n": n, "mean": st.mean(v), "median": st.median(v), "sd": sd, "ci95": 1.96 * sd / math.sqrt(n) if n else 0}


def iperf(dur):
    r = run(["iperf3", "-c", R, "-t", str(dur), "-J"], ns="znoc", check=False, timeout=dur + 40)
    try:
        j = json.loads(r.stdout)
        e = j["end"]
        return {"mbps": e["sum_received"]["bits_per_second"] / 1e6,
                "retransmits": e["sum_sent"].get("retransmits"),
                "cpu_sender_pct": e["cpu_utilization_percent"]["host_total"],
                "cpu_receiver_pct": e["cpu_utilization_percent"]["remote_total"]}
    except Exception:
        return {"error": (r.stdout + r.stderr)[-300:]}


def set_delay(ms):
    for ns, dev in (("znoc", "vz"), ("rnoc", "vr")):
        run(["tc", "qdisc", "del", "dev", dev, "root"], ns=ns, check=False)
        if ms > 0:
            run(["tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", "%gms" % ms, "limit", "100000"], ns=ns)


def ping_avg():
    r = run(["ping", "-c", "5", "-i", "0.2", "-q", R], ns="znoc", check=False)
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", r.stdout)
    return float(m.group(1)) if m else None


def setup():
    cleanup()
    run(["ip", "netns", "add", "znoc"])
    run(["ip", "netns", "add", "rnoc"])
    run(["ip", "link", "add", "vz", "type", "veth", "peer", "name", "vr"])
    run(["ip", "link", "set", "vz", "netns", "znoc"])
    run(["ip", "link", "set", "vr", "netns", "rnoc"])
    for ns, dev, ip in (("znoc", "vz", L), ("rnoc", "vr", R)):
        run(["ip", "addr", "add", ip + "/24", "dev", dev], ns=ns)
        run(["ip", "link", "set", dev, "up"], ns=ns)
        run(["ip", "link", "set", "lo", "up"], ns=ns)


def cleanup():
    for ns in ("znoc", "rnoc"):
        run(["ip", "netns", "del", ns], check=False)


def md(res):
    o = ["### Uplink throughput (iperf3, single TCP stream, %s s)\n" % res["dur_s"],
         "| one-way delay (ms) | ping RTT (ms) | plain (Mbit/s) | ESP AES-256-GCM (Mbit/s) | ESP + refresh every %g s (Mbit/s) | sender CPU plain / ESP (%%) |" % res["tau_s"],
         "|---|---|---|---|---|---|"]
    for p in res["throughput"]:
        g = lambda k: ("%.0f" % p[k]["mbps"]) if k in p and "mbps" in p[k] else "n/a"
        c = lambda k: ("%.0f" % p[k]["cpu_sender_pct"]) if k in p and "cpu_sender_pct" in p[k] else "n/a"
        o.append("| %g | %s | %s | %s | %s | %s / %s |" % (p["one_way_delay_ms"], p["ping_rtt_ms"], g("plain"), g("esp"), g("esp_rekey"), c("plain"), c("esp")))
    r = res.get("refresh")
    if r:
        o += ["\n### One key refresh (fetch + ML-KEM-768 + X25519 + HKDF, then install new SA pair and delete old)\n",
              "derive: %.2f ± %.2f ms; install via `ip xfrm`: %.2f ± %.2f ms; CPU per refresh (incl. `ip` processes): %.2f ms" % (
                  r["derive_ms"]["mean"], r["derive_ms"]["ci95"], r["install_ms"]["mean"], r["install_ms"]["ci95"], r["cpu_ms_per_refresh"]),
              "Refresh CPU load at tau = 1 s: %.3f %%; at tau = 60 s: %.4f %%" % (r["cpu_ms_per_refresh"] / 10.0, r["cpu_ms_per_refresh"] / 600.0)]
    if res.get("scale"):
        o += ["\n### N tunnels refreshed at once\n", "| N | derive all (ms) | install all (ms) | per tunnel (ms) | kernel Slab delta (MB) |", "|---|---|---|---|---|"]
        for s in res["scale"]:
            o.append("| %d | %.0f | %.0f | %.3f | %.1f |" % (s["n"], s["derive_ms"], s["install_ms"], (s["derive_ms"] + s["install_ms"]) / s["n"], s["slab_delta_mb"]))
    o.append("\nPQC source: %s. Links emulated with tc netem; both ends on one host; SAs installed through the `ip` command." % res["pqc_source"])
    return "\n".join(o)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--delays", default="0,10", help="one-way delays in ms (RTT = 2x)")
    ap.add_argument("--dur", type=int, default=10, help="iperf3 seconds per run")
    ap.add_argument("--tau", type=float, default=1.0, help="refresh period during the ESP+refresh run (s)")
    ap.add_argument("--n-refresh", type=int, default=50)
    ap.add_argument("--scale", default="100,1000")
    ap.add_argument("--out", default="topo_results.json")
    a = ap.parse_args()
    if sys.version_info < (3, 12):
        sys.exit("ERROR: Python >= 3.12 needed (os.setns).")

    res = {"dur_s": a.dur, "tau_s": a.tau, "throughput": [], "scale": [], "kernel": os.uname().release,
           "pqc_source": "liboqs ML-KEM-768 (%s)" % oqs.oqs_version() if HAVE_OQS else "SIMULATED random (do not publish)",
           "cpu_has_aes": any("aes" in l.split() for l in open("/proc/cpuinfo") if l.startswith("flags"))}
    mock = srv = None
    try:
        setup()
        mock = subprocess.Popen(["ip", "netns", "exec", "rnoc", sys.executable, os.path.join(HERE, "mock_etsi014_v2.py"),
                                 "--host", R, "--port", "8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        srv = subprocess.Popen(["ip", "netns", "exec", "rnoc", "iperf3", "-s", "-B", R], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        ka = KeepAlive("znoc", R, 8080)
        tun = Tunnel(ka)
        # preflight: can the kernel do ESP with AES-GCM?
        try:
            tun.policies()
            tun.rekey()
        except Exception as e:
            res["error"] = "xfrm/ESP AES-GCM not available on this kernel: %s" % e
            print(res["error"])
            sys.exit(2)
        tun.flush()

        for d in [float(x) for x in a.delays.split(",")]:
            set_delay(d)
            time.sleep(0.5)
            pt = {"one_way_delay_ms": d, "ping_rtt_ms": ping_avg()}
            tun.flush()
            pt["plain"] = iperf(a.dur)
            tun.policies()
            tun.rekey()
            pt["esp"] = iperf(a.dur)
            stop, times = threading.Event(), []

            def loop():
                while not stop.wait(a.tau):
                    times.append(tun.rekey())
            th = threading.Thread(target=loop)
            th.start()
            pt["esp_rekey"] = iperf(a.dur)
            stop.set()
            th.join()
            pt["esp_rekey"]["refreshes_during_run"] = len(times)
            res["throughput"].append(pt)
            print("delay %g ms:" % d, {k: pt[k].get("mbps") for k in ("plain", "esp", "esp_rekey")})

        # cost of one refresh, no traffic
        set_delay(0)
        tun.flush()
        tun.policies()
        tun.rekey()
        c0, dv, ins = cpu_s(), [], []
        for _ in range(a.n_refresh):
            x, y = tun.rekey()
            dv.append(x)
            ins.append(y)
        res["refresh"] = {"n": a.n_refresh, "derive_ms": stats(dv), "install_ms": stats(ins),
                          "cpu_ms_per_refresh": (cpu_s() - c0) / a.n_refresh * 1e3}
        print("refresh:", res["refresh"]["derive_ms"]["mean"], "+", res["refresh"]["install_ms"]["mean"], "ms")

        # N tunnels at once
        for n in [int(x) for x in a.scale.split(",") if x]:
            tun.flush()
            s0, _ = slab_kb()
            t0 = time.perf_counter()
            lines_z = []
            for i in range(n):
                tun.n += 1
                okm = derive(ka.get(), k_pqc(), k_ecdhe(), b"znoc1|rnoc1|bulk-%06d" % i)
                a_, b_ = next(SPI), next(SPI)
                add = [st_add(L, R, a_, okm[:36]), st_add(R, L, b_, okm[36:])]
                lines_z += add
            t1 = time.perf_counter()
            batch("znoc", lines_z)
            batch("rnoc", lines_z)
            t2 = time.perf_counter()
            s1, _ = slab_kb()
            res["scale"].append({"n": n, "derive_ms": (t1 - t0) * 1e3, "install_ms": (t2 - t1) * 1e3,
                                 "slab_delta_mb": (s1 - s0) / 1024.0})
            print("N=%d: derive %.0f ms, install %.0f ms" % (n, (t1 - t0) * 1e3, (t2 - t1) * 1e3))
            tun.flush()
    finally:
        for p in (srv, mock):
            if p:
                p.terminate()
        cleanup()
        json.dump(res, open(a.out, "w"), indent=2)
        open(os.path.splitext(a.out)[0] + ".md", "w").write(md(res) if "error" not in res else res["error"])
        print("wrote", a.out)
