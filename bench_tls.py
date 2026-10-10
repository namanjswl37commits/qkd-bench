#!/usr/bin/env python3
"""E1: classical (X25519) vs hybrid (X25519MLKEM768) TLS 1.3 handshake cost, loopback, one host.

Replaces bench_tls.sh. Differences: verifies the negotiated group (so a failed hybrid handshake can
never be timed as 'fast'), reports mean/median/sd/95% CI, client+server CPU per handshake, and a
process-spawn baseline. Wall times include process spawn: compare groups relatively.

Usage: python3 bench_tls.py --role znoc [--n 200] [--openssl /path/to/openssl] [--sig mldsa65]
Needs OpenSSL >= 3.5 for X25519MLKEM768.
"""
import argparse, json, math, os, resource, socket, statistics as st, subprocess, sys, tempfile, time

DEVNULL = subprocess.DEVNULL


def stats(v):
    n = len(v)
    sd = st.stdev(v) if n > 1 else 0.0
    return {'n': n, 'mean_ms': st.mean(v), 'median_ms': st.median(v), 'sd_ms': sd,
            'ci95_ms': 1.96 * sd / math.sqrt(n), 'p95_ms': sorted(v)[min(n - 1, int(0.95 * n))]}


def group_supported(ossl, g):
    r = subprocess.run([ossl, 's_client', '-groups', g, '-connect', '127.0.0.1:1'],
                       input=b'', capture_output=True)
    return b'cannot be set' not in (r.stdout + r.stderr)


def wait_port(port, timeout=8.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def proc_cpu_s(pid):
    """utime+stime of a running process in seconds (Linux only)."""
    try:
        f = open('/proc/%d/stat' % pid).read().rsplit(')', 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf('SC_CLK_TCK')
    except Exception:
        return None


def children_cpu_s():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def client_cmd(ossl, port, g):
    return [ossl, 's_client', '-connect', '127.0.0.1:%d' % port, '-tls1_3', '-groups', g]


def bench_group(ossl, g, port, cert, key, n, warmup):
    srv = subprocess.Popen([ossl, 's_server', '-accept', '127.0.0.1:%d' % port, '-cert', cert, '-key', key,
                            '-tls1_3', '-groups', g, '-www', '-quiet'], stdout=DEVNULL, stderr=DEVNULL)
    try:
        if not wait_port(port):
            raise RuntimeError('s_server did not start for group %s' % g)
        # verify the negotiated group once
        out = subprocess.run(client_cmd(ossl, port, g), input=b'', capture_output=True)
        text = (out.stdout + out.stderr).decode(errors='replace')
        ok = (g in text) and (g != 'X25519' or 'MLKEM' not in text)
        if out.returncode != 0 or not ok:
            raise RuntimeError('group %s was NOT negotiated (rc=%s)' % (g, out.returncode))
        for _ in range(warmup):
            subprocess.run(client_cmd(ossl, port, g), input=b'', stdout=DEVNULL, stderr=DEVNULL)
        s0, c0 = proc_cpu_s(srv.pid), children_cpu_s()
        t, fail = [], 0
        for _ in range(n):
            t0 = time.perf_counter()
            r = subprocess.run(client_cmd(ossl, port, g), input=b'', stdout=DEVNULL, stderr=DEVNULL)
            dt = (time.perf_counter() - t0) * 1e3
            if r.returncode == 0:
                t.append(dt)
            else:
                fail += 1
        s1, c1 = proc_cpu_s(srv.pid), children_cpu_s()
        cli_cpu = (c1 - c0) / n * 1e3
        srv_cpu = (s1 - s0) / n * 1e3 if (s0 is not None and s1 is not None) else None
        return {'wall': stats(t), 'failures': fail, 'negotiated_group_verified': True,
                'client_cpu_ms': cli_cpu, 'server_cpu_ms': srv_cpu,
                'cpu_ms_total': cli_cpu + (srv_cpu or 0.0)}
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=3)
        except Exception:
            srv.kill()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--role', required=True, choices=['endpoint', 'znoc', 'rnoc'])
    ap.add_argument('--n', type=int, default=200)
    ap.add_argument('--warmup', type=int, default=10)
    ap.add_argument('--openssl', default=os.environ.get('OPENSSL', 'openssl'))
    ap.add_argument('--port', type=int, default=4433)
    ap.add_argument('--sig', default='', help='e.g. mldsa65 (needs ML-DSA support in your OpenSSL)')
    ap.add_argument('--classical-only', action='store_true')
    ap.add_argument('--out', default='')
    a = ap.parse_args()

    groups = ['X25519'] + ([] if a.classical_only else ['X25519MLKEM768'])
    for g in groups:
        if not group_supported(a.openssl, g):
            sys.exit('ERROR: %s cannot be set in this OpenSSL (%s). Hybrid TLS needs OpenSSL >= 3.5.'
                     % (g, subprocess.run([a.openssl, 'version'], capture_output=True, text=True).stdout.strip()))

    with tempfile.TemporaryDirectory() as d:
        cert, key = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
        gen = [a.openssl, 'req', '-x509', '-nodes', '-keyout', key, '-out', cert, '-subj', '/CN=localhost', '-days', '2']
        gen += ['-newkey', a.sig] if a.sig else ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']
        subprocess.run(gen, check=True, stdout=DEVNULL, stderr=DEVNULL)

        res = {'role': a.role, 'n': a.n, 'cert': a.sig or 'ecdsa-P-256',
               'openssl': subprocess.run([a.openssl, 'version'], capture_output=True, text=True).stdout.strip(),
               'groups': {}}
        for g in groups:
            res['groups'][g] = bench_group(a.openssl, g, a.port, cert, key, a.n, a.warmup)
            w = res['groups'][g]['wall']
            print('%-16s %.2f +/- %.2f ms (median %.2f), CPU %.2f ms/handshake, failures %d' % (
                g, w['mean_ms'], w['ci95_ms'], w['median_ms'], res['groups'][g]['cpu_ms_total'],
                res['groups'][g]['failures']))

        # process-spawn baseline: an empty openssl invocation
        t = []
        c0 = children_cpu_s()
        for _ in range(a.n):
            t0 = time.perf_counter()
            subprocess.run([a.openssl, 'version'], stdout=DEVNULL, stderr=DEVNULL)
            t.append((time.perf_counter() - t0) * 1e3)
        res['spawn_baseline'] = {'wall': stats(t), 'cpu_ms': (children_cpu_s() - c0) / a.n * 1e3}
        print('spawn baseline   %.2f ms' % res['spawn_baseline']['wall']['mean_ms'])

    out = a.out or 'tls_%s.json' % a.role
    json.dump(res, open(out, 'w'), indent=2)
    print('wrote', out)
