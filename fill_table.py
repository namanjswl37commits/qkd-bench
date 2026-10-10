#!/usr/bin/env python3
"""Turn the three hosts' result files into the paper's table, configuration table and text snippets.

Put config_<role>.json, tls_<role>.json, hkdf_<role>.json for role in endpoint, znoc, rnoc in one folder:
    python3 fill_table.py results/ [--main znoc]
Writes filled_table.md as well as printing it.
"""
import argparse, json, os, sys

ROLES = ['endpoint', 'znoc', 'rnoc']
NAMES = {'endpoint': 'Endpoint', 'znoc': 'Z-NOC', 'rnoc': 'R-NOC'}
COLS = ['Classical', 'Hybrid', 'Hybrid + QKD']


def load(d, kind, role):
    p = os.path.join(d, '%s_%s.json' % (kind, role))
    return json.load(open(p)) if os.path.exists(p) else None


def f(mean, ci=None, nd=2):
    if mean is None:
        return 'n/a'
    return ('%.*f ± %.*f' % (nd, mean, nd, ci)) if ci is not None else ('%.*f' % (nd, mean))


def table(tls, hk):
    """Return {row: [classical, hybrid, hybrid+qkd]} for one host, or None if inputs are missing."""
    if not tls or not hk:
        return None
    c, h = tls['groups']['X25519'], tls['groups'].get('X25519MLKEM768')
    e, p, q = hk['ecdhe_only'], hk['hybrid_pqc_ecdhe'], hk['hybrid_plus_qkd']
    if h is None:
        return None
    fetch_ms = q['mean_ms'] - p['mean_ms']
    fetch_cpu = q['cpu_ms'] - p['cpu_ms']
    rows = {
        'Handshake latency (ms)': [f(c['wall']['mean_ms'], c['wall']['ci95_ms']),
                                   f(h['wall']['mean_ms'], h['wall']['ci95_ms']),
                                   f(h['wall']['mean_ms'] + fetch_ms)],
        'Key derivation (ms)': [f(e['mean_ms'], e['ci95_ms'], 3), f(p['mean_ms'], p['ci95_ms'], 3),
                                f(q['mean_ms'], q['ci95_ms'], 3)],
        'CPU per handshake (ms)': [f(c['cpu_ms_total']), f(h['cpu_ms_total']), f(h['cpu_ms_total'] + fetch_cpu)],
        'Key refresh at τ = 1 s (CPU %)': [f(x['cpu_ms'] / 10.0, None, 4) for x in (e, p, q)],
        'Key refresh at τ = 60 s (CPU %)': [f(x['cpu_ms'] / 600.0, None, 5) for x in (e, p, q)],
        'Tunnel throughput through a Z-NOC (not evaluated)': ['n/e'] * 3,
        'Z-NOC peak memory (not evaluated)': ['n/e'] * 3,
    }
    extra = {'ml_kem_added_ms': h['wall']['mean_ms'] - c['wall']['mean_ms'],
             'ml_kem_added_pct': (h['wall']['mean_ms'] / c['wall']['mean_ms'] - 1) * 100,
             'fetch_ms': fetch_ms, 'fetch_cpu_ms': fetch_cpu,
             'hkdf_ms': hk['hkdf_only']['mean_ms'],
             'hkdf_pct_of_handshake': hk['hkdf_only']['mean_ms'] / h['wall']['mean_ms'] * 100,
             'gcm': hk['gcm_MBps'], 'pqc_source': hk['pqc_source'], 'qkd_source': hk['qkd_source']}
    return rows, extra


def md_table(header, rows):
    out = ['| ' + ' | '.join(header) + ' |', '|' + '---|' * len(header)]
    out += ['| ' + ' | '.join(str(x) for x in r) + ' |' for r in rows]
    return '\n'.join(out)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('dir')
    ap.add_argument('--main', default='znoc', choices=ROLES)
    a = ap.parse_args()
    out = []

    cfgs = {r: load(a.dir, 'config', r) for r in ROLES}
    out.append('## Configuration\n')
    keys = [('CPU', lambda c: c['cpu_model']),
            ('Cores / threads', lambda c: '%s / %s' % ((int(c['cpu_sockets'] or 1) * int(c['cpu_cores_per_socket'] or 0)) or '?', c['cpu_threads_total'])),
            ('RAM (GB)', lambda c: c['ram_gb']),
            ('OS / kernel', lambda c: '%s / %s' % (c['os'], c['kernel'])),
            ('Virtualisation', lambda c: c['virtualization']),
            ('CPU governor', lambda c: c['cpu_governor']),
            ('OpenSSL', lambda c: c['openssl']),
            ('Python / cryptography', lambda c: '%s / %s' % (c['python'], c['cryptography'])),
            ('liboqs / liboqs-python', lambda c: '%s / %s' % (c['liboqs'], c['liboqs_python'])),
            ('RTT to R-NOC (ms, avg)', lambda c: (c['peer_rtt_ms'] or {}).get('avg'))]
    rows = []
    for label, fn in keys:
        rows.append([label] + [(fn(cfgs[r]) if cfgs[r] else 'n/a') for r in ROLES])
    out.append(md_table([''] + [NAMES[r] for r in ROLES], rows))

    out.append('\n## Setup sentence (paper)\n')
    parts = []
    for r in ROLES:
        c = cfgs[r]
        if c:
            parts.append('%s: %s | %s GB RAM | %s' % (NAMES[r], c['os'], c['ram_gb'], c['cpu_model']))
    out.append('Hardware: ' + '; '.join(parts) + '.')
    zc = cfgs.get('znoc') or {}
    out.append('Software: %s; liboqs %s; Python %s; cryptography %s.' % (
        zc.get('openssl'), zc.get('liboqs'), zc.get('python'), zc.get('cryptography')))
    rtt = (zc.get('peer_rtt_ms') or {}).get('avg')
    out.append('Z-NOC to R-NOC round-trip time (E2): %s ms.' % rtt)

    main = table(load(a.dir, 'tls', a.main), load(a.dir, 'hkdf', a.main))
    out.append('\n## Table 7 (host: %s)\n' % NAMES[a.main])
    if main:
        out.append(md_table(['Metric'] + COLS, [[k] + v for k, v in main[0].items()]))
        ex = main[1]
        out.append('\nAES-256-GCM throughput (single thread, in memory): %.0f / %.0f / %.0f MB/s for 1 KB / 64 KB / 1 MB.' % (
            ex['gcm']['1024'], ex['gcm']['65536'], ex['gcm']['1048576']))
        out.append('Added handshake cost of ML-KEM-768 (hybrid vs classical): %.2f ms (%.0f%%).' % (ex['ml_kem_added_ms'], ex['ml_kem_added_pct']))
        out.append('Added cost of the QKD key fetch: %.2f ms wall, %.2f ms CPU.' % (ex['fetch_ms'], ex['fetch_cpu_ms']))
        out.append('HKDF step alone: %.4f ms = %.2f%% of the hybrid handshake.' % (ex['hkdf_ms'], ex['hkdf_pct_of_handshake']))
        out.append('Sources: ML-KEM = %s; QKD = %s.' % (ex['pqc_source'], ex['qkd_source']))
        if 'SIMULATED' in ex['pqc_source'] or 'SIMULATED' in ex['qkd_source']:
            out.append('\n**WARNING: simulated source(s) in use; do not publish these numbers.**')
    else:
        out.append('Missing tls_%s.json / hkdf_%s.json or no hybrid result.' % (a.main, a.main))

    out.append('\n## Per-host results (supplementary table)\n')
    for r in ROLES:
        t = table(load(a.dir, 'tls', r), load(a.dir, 'hkdf', r))
        out.append('**%s**\n' % NAMES[r])
        out.append(md_table(['Metric'] + COLS, [[k] + v for k, v in t[0].items()]) if t else 'n/a (files missing)')
        out.append('')

    text = '\n'.join(out)
    open(os.path.join(a.dir, 'filled_table.md'), 'w').write(text)
    print(text)
