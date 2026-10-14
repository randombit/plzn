#!/usr/bin/env python3
"""
Minimal stand-in for the plzn runner, used to smoke-test the interop shims
against an independent TLS stack (Python's ssl / OpenSSL) before the real Rust
runner is wired up.

It plays the runner: listens on a port, accepts the shim's connection, reads the
8-byte little-endian ShimID prefix, then runs a TLS handshake in the role
OPPOSITE the shim's, exchanges one application-data round trip, and reports.

Usage:
  plzn_stub.py --shim-role server --port N          # runner is TLS client
  plzn_stub.py --shim-role client --port N --cert C --key K   # runner is server

Exit status: 0 if the handshake (and app-data round trip) succeeded, 1 otherwise.
"""

import argparse
import socket
import ssl
import sys


def read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short read waiting for %d bytes" % n)
        buf += chunk
    return buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shim-role", choices=["client", "server"], required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--app-data", default="GET / HTTP/1.0\r\n\r\n")
    ap.add_argument("--min-version", default=None,
                    help="TLSv1_2 or TLSv1_3 to pin")
    args = ap.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(1)
    # The bound port is printed so a caller that passed --port 0 can learn it.
    print("LISTENING %d" % listener.getsockname()[1], flush=True)

    listener.settimeout(10)
    conn, _ = listener.accept()
    conn.settimeout(10)

    shim_id = read_exactly(conn, 8)
    print("shim_id=%d" % int.from_bytes(shim_id, "little"), file=sys.stderr)

    # The runner plays the opposite role from the shim.
    runner_is_server = (args.shim_role == "client")

    if runner_is_server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if args.min_version == "TLSv1_2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    elif args.min_version == "TLSv1_3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    try:
        tls = ctx.wrap_socket(conn, server_side=runner_is_server)
    except ssl.SSLError as e:
        print("HANDSHAKE FAILED: %s" % e, file=sys.stderr)
        return 1

    print("HANDSHAKE OK version=%s cipher=%s" %
          (tls.version(), tls.cipher()[0]), file=sys.stderr)

    # One app-data round trip. The runner sends; the shim echoes (default
    # app_data mode), so the runner should read back the same bytes.
    payload = args.app_data.encode()
    round_trip_ok = True
    try:
        tls.sendall(payload)
        echoed = tls.recv(len(payload))
        if echoed != payload:
            print("ECHO MISMATCH: sent %r got %r" % (payload, echoed),
                  file=sys.stderr)
            round_trip_ok = False
        else:
            print("ECHO OK (%d bytes)" % len(echoed), file=sys.stderr)
    except (ssl.SSLError, OSError) as e:
        print("APP DATA FAILED: %s" % e, file=sys.stderr)
        round_trip_ok = False

    try:
        tls.close()
    except OSError:
        pass

    return 0 if round_trip_ok else 1


if __name__ == "__main__":
    sys.exit(main())
