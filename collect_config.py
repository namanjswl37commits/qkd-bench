#!/usr/bin/env python3
"""Collect the hardware/software configuration of one test host.

Usage:  python3 collect_config.py --role znoc [--peer <ip-of-R-NOC>] [--out config_znoc.json]
Roles:  endpoint | znoc | rnoc
The hostname is deliberately NOT recorded.
"""
import argparse, json, os, platform, re, subprocess, sys


def sh(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""


def lscpu(field):
    m = re.search(r'^%s:\s*(.+)$' % re.escape(field), sh('lscpu'), re.M)
    return m.group(1).strip() if m else None


def pkg_version(name):
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        return None


def cpu_model():
    m = lscpu('Model name')
    if m:
        return m
    try:
        for line in open('/proc/cpuinfo'):
            if line.lower().startswith('model name'):
                return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return sh('sysctl -n machdep.cpu.brand_string') or platform.processor() or None


def ram_gb():
    try:
        for line in open('/proc/meminfo'):
            if line.startswith('MemTotal'):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except Exception:
        pass
    v = sh('sysctl -n hw.memsize')
    return round(int(v) / 2**30, 1) if v.isdigit() else None


def os_name():
    try:
        for line in open('/etc/os-release'):
            if line.startswith('PRETTY_NAME='):
                return line.split('=', 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.platform()


def hybrid_supported(ossl='openssl'):
    out = sh('%s s_client -groups X25519MLKEM768 -connect 127.0.0.1:1 </dev/null' % ossl)
    return 'cannot be set' not in out


def peer_rtt(peer):
    out = sh('ping -c 10 -q %s' % peer, timeout=40)
    m = re.search(r'=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', out)
    return {'min': float(m.group(1)), 'avg': float(m.group(2)), 'max': float(m.group(3))} if m else None


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--role', required=True, choices=['endpoint', 'znoc', 'rnoc'])
    ap.add_argument('--peer', default='', help='address of the peer (R-NOC) for an RTT measurement')
    ap.add_argument('--out', default='')
    a = ap.parse_args()

    oqs_ver = None
    try:
        import oqs
        oqs_ver = oqs.oqs_version()
    except Exception:
        pass

    cfg = {
        'role': a.role,
        'os': os_name(),
        'kernel': platform.release(),
        'arch': platform.machine(),
        'cpu_model': cpu_model(),
        'cpu_sockets': lscpu('Socket(s)'),
        'cpu_cores_per_socket': lscpu('Core(s) per socket'),
        'cpu_threads_total': os.cpu_count(),
        'cpu_max_mhz': lscpu('CPU max MHz'),
        'ram_gb': ram_gb(),
        'virtualization': sh('systemd-detect-virt') or 'unknown',
        'cpu_governor': (open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor').read().strip()
                         if os.path.exists('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor') else None),
        'python': platform.python_version(),
        'cryptography': pkg_version('cryptography'),
        'liboqs_python': pkg_version('liboqs-python'),
        'liboqs': oqs_ver,
        'openssl': sh('openssl version'),
        'openssl_has_X25519MLKEM768': hybrid_supported(),
        'peer_rtt_ms': peer_rtt(a.peer) if a.peer else None,
    }
    out = a.out or 'config_%s.json' % a.role
    json.dump(cfg, open(out, 'w'), indent=2)
    for k, v in cfg.items():
        print('%-28s %s' % (k, v))
    print('\nwrote', out)
    if not cfg['openssl_has_X25519MLKEM768']:
        print('\nWARNING: this OpenSSL cannot negotiate X25519MLKEM768 (needs >= 3.5).', file=sys.stderr)
    if not oqs_ver:
        print('WARNING: liboqs-python not importable; ML-KEM-768 would be SIMULATED.', file=sys.stderr)
