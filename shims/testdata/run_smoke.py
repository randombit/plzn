#!/usr/bin/env python3
"""
Smoke-test an interop shim against the plzn_stub oracle across a small matrix of
roles and versions. Proves the shim does a real handshake with an independent
TLS stack. Not the real plzn runner -- just enough to validate the shim binary.

Usage: run_smoke.py <path-to-shim-binary>
Exit status 0 iff every case passes.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(HERE, "plzn_stub.py")
CERT = os.path.join(HERE, "ec_cert.pem")
KEY = os.path.join(HERE, "ec_key.pem")

TLS12 = 771
TLS13 = 772


def run_case(name, shim_bin, shim_role, version):
    """Start the stub, run the shim against it, return (ok, detail)."""
    stub_role_flag = ["--shim-role", shim_role]
    ver_flag = []
    if version == TLS12:
        ver_flag = ["--min-version", "TLSv1_2"]
    elif version == TLS13:
        ver_flag = ["--min-version", "TLSv1_3"]

    stub_cmd = [sys.executable, STUB, "--port", "0"] + stub_role_flag + ver_flag
    if shim_role == "client":
        # runner is the TLS server, needs a cert
        stub_cmd += ["--cert", CERT, "--key", KEY]

    stub = subprocess.Popen(stub_cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    # Read the LISTENING line to learn the ephemeral port.
    line = stub.stdout.readline().strip()
    if not line.startswith("LISTENING"):
        stub.kill()
        return False, "stub did not report LISTENING: %r / %s" % (
            line, stub.stderr.read())
    port = int(line.split()[1])

    cfg = {
        "role": shim_role,
        "protocol": "tls",
        "runner": {"host": "127.0.0.1", "port": port},
        "shim_id": 1234,
        "min_version": version,
        "max_version": version,
        "verify": {"peer": False},
        "app_data": {"mode": "echo"},
        "expect": {"version": version},
    }
    if shim_role == "server":
        cfg["credentials"] = {"cert_file": CERT, "key_file": KEY}

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    try:
        shim = subprocess.run([shim_bin, "-config", cfg_path],
                              capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        stub.kill()
        os.unlink(cfg_path)
        return False, "shim timed out"

    try:
        stub_rc = stub.wait(timeout=10)
    except subprocess.TimeoutExpired:
        stub.kill()
        stub_rc = -1
    stub_err = stub.stderr.read()
    os.unlink(cfg_path)

    ok = (shim.returncode == 0 and stub_rc == 0)
    detail = "shim_rc=%d stub_rc=%d | shim: %s | stub: %s" % (
        shim.returncode, stub_rc,
        (shim.stdout + shim.stderr).strip().replace("\n", " ; "),
        stub_err.strip().replace("\n", " ; "))
    return ok, detail


def main():
    if len(sys.argv) != 2:
        print("usage: run_smoke.py <shim-binary>", file=sys.stderr)
        return 2
    shim_bin = sys.argv[1]
    if not os.path.exists(shim_bin):
        print("shim binary not found: %s" % shim_bin, file=sys.stderr)
        return 2

    cases = [
        ("client-tls13", "client", TLS13),
        ("client-tls12", "client", TLS12),
        ("server-tls13", "server", TLS13),
        ("server-tls12", "server", TLS12),
    ]

    failures = 0
    for name, role, version in cases:
        ok, detail = run_case(name, shim_bin, role, version)
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print("[%s] %-14s %s" % (status, name, detail))

    print("\n%d/%d cases passed" % (len(cases) - failures, len(cases)))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
