#!/usr/bin/env python3
"""Generate suite/server/tls12_client_compatibility.plzn from tlsfuzzer's
test-client-compatibility.py (140 named real-world ClientHello captures).

Each tlsfuzzer probe is `ClientHelloGenerator(ciphers, version, compression,
extensions)` followed by `ExpectServerHello()`; the port sends the same
ClientHello byte for byte (legacy_version, cipher list, compression list, empty
session id, and the serialized extension block as an `extensions:` override --
so the script's literal key shares and supported_versions go out unchanged) and
stops after the ServerHello. The three `ssl2=True` probes use the SSLv2-format
ClientHello (`format: sslv2`).

Usage:
  tools/gen_client_compat.py [--script PATH] [--out FILE]
  tools/gen_client_compat.py --probe PLZN_BIN   # run the generated file on the
     repository's three corpus shims and pin each per-backend outcome

Several names in the upstream corpus carry byte-for-byte identical hellos. The
generator keeps the lowest-numbered name for each distinct wire fingerprint so
the conformance corpus does not execute duplicate scenarios. The generator is
deterministic; re-run it when the upstream script changes.
"""
import argparse
import ast
import os
import re
import subprocess
import sys

DEFAULT_SCRIPT = "3rd_party/tlsfuzzer/tlsfuzzer/_apps/test_client_compatibility.py"
DEFAULT_OUT = "suite/server/tls12_client_compatibility.plzn"
HOST = "localhost"


def lit(node):
    """Evaluate a literal-ish AST node (numbers, bytes, tuples, lists)."""
    return ast.literal_eval(node)


def ext_bytes(call, host):
    """Serialize one `ext[N] = <Ctor>(...).create(...)` right-hand side to the
    extension body bytes; returns (type, body)."""
    # call is `X().create(args)` or `TLSExtension(extType=N).create(args)`
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "create"
    ctor = call.func.value
    assert isinstance(ctor, ast.Call)
    name = ctor.func.id
    if name == "TLSExtension":
        ty = None
        for kw in ctor.keywords:
            if kw.arg == "extType":
                ty = lit(kw.value)
        assert ty is not None
        arg = call.args[0]
        # bytearray(b'...')
        assert isinstance(arg, ast.Call) and arg.func.id == "bytearray"
        body = bytes(lit(arg.args[0])) if arg.args else b""
        return ty, body
    if name == "SNIExtension":
        # SNIExtension().create(bytearray(host, "ascii"))
        h = host.encode()
        body = len(h) + 3 + 2
        sni = bytes([0x00]) + len(h).to_bytes(2, "big") + h
        return 0, len(sni).to_bytes(2, "big") + sni
    if name == "SupportedVersionsExtension":
        vers = lit(call.args[0])
        body = bytes()
        for (a, b) in vers:
            body += bytes([a, b])
        return 43, bytes([len(body)]) + body
    if name == "ClientKeyShareExtension":
        entries = b""
        for e in call.args[0].elts:
            # KeyShareEntry().create(group, bytearray(pub), private)
            g = lit(e.args[0])
            pub = bytes(lit(e.args[1].args[0])) if e.args[1].args else b""
            entries += g.to_bytes(2, "big") + len(pub).to_bytes(2, "big") + pub
        return 51, len(entries).to_bytes(2, "big") + entries
    raise SystemExit(f"unhandled extension constructor {name}")


def serialize_exts(exts):
    out = b""
    for ty, body in exts:
        out += ty.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body
    return out


def hexlist(b):
    return "[" + ", ".join(f"0x{x:02x}" for x in b) + "]"


def slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:70]


def parse_script(path):
    tree = ast.parse(open(path).read())
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    probes = []
    ciphers = None
    exts = None
    hello = None
    compression = None
    version = None
    ssl2 = False
    for st in main.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1:
            t = st.targets[0]
            if isinstance(t, ast.Name) and t.id == "ciphers":
                ciphers = lit(st.value)
                continue
            if isinstance(t, ast.Name) and t.id == "ext":
                exts = []
                continue
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == "ext":
                exts.append(ext_bytes(st.value, HOST))
                continue
            if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == "conversations":
                name = lit(t.slice)
                if hello is not None:
                    probes.append(dict(name=name, ciphers=ciphers, exts=exts or [], version=version,
                                       compression=compression, ssl2=ssl2))
                hello = None
                exts = None
                ssl2 = False
                continue
            if isinstance(t, ast.Name) and t.id == "node" and isinstance(st.value, ast.Call):
                call = st.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "add_child" and call.args:
                    inner = call.args[0]
                    if isinstance(inner, ast.Call) and getattr(inner.func, "id", "") == "ClientHelloGenerator":
                        version = (3, 3)
                        compression = [0]
                        for kw in inner.keywords:
                            if kw.arg == "version":
                                version = lit(kw.value)
                            elif kw.arg == "compression":
                                compression = lit(kw.value)
                            elif kw.arg == "ssl2":
                                ssl2 = bool(lit(kw.value))
                            elif kw.arg == "ciphers":
                                if not isinstance(kw.value, ast.Name):
                                    ciphers = lit(kw.value)
                            elif kw.arg == "extensions":
                                pass  # `ext` dict, collected above
                        if inner.args and isinstance(inner.args[0], ast.Name) and inner.args[0].id == "ciphers":
                            pass
                        hello = inner
                continue
    return probes


def probe_number(probe):
    """The numeric prefix in upstream names such as `51: Firefox ...`."""
    try:
        return int(probe["name"].split(":", 1)[0])
    except ValueError:
        return sys.maxsize


def fingerprint(probe):
    """Fields that determine the serialized ClientHello sent by plzn."""
    return (
        tuple(probe["version"]),
        tuple(probe["ciphers"]),
        tuple(probe["compression"]),
        bool(probe["ssl2"]),
        serialize_exts(probe["exts"]),
    )


def distinct_probes(probes):
    """Keep one stable representative for every distinct wire fingerprint."""
    representatives = {}
    for probe in probes:
        key = fingerprint(probe)
        old = representatives.get(key)
        if old is None or probe_number(probe) < probe_number(old):
            representatives[key] = probe
    return [probe for probe in probes if representatives[fingerprint(probe)] is probe]


HEADER = '''# GENERATED by tools/gen_client_compat.py from tlsfuzzer's
# test-client-compatibility.py -- do not edit by hand; re-run the generator.
#
# Real-world ClientHello fingerprints (browsers, phones, libraries, 2010-2020,
# from tlsfuzzer's corpus of captured hellos). Each case sends the fingerprint
# byte for byte -- legacy_version, cipher list, compression list, empty session
# id and the serialized extension block (its literal key shares and
# supported_versions included) -- and stops after the ServerHello, which is all
# the upstream script checks (RFC 5246 7.4.1.2: a server must accept any
# well-formed ClientHello it can negotiate with; RFC 8446 4.1.2 for the TLS 1.3
# hellos). The record-layer version tlsfuzzer used for the first record
# (mostly 0x0301) is not reproduced: plzn's client writes its own.
# Byte-identical captures under different browser/version labels are represented
# once; labels do not add protocol coverage when every serialized field matches.
#
# `expect ok` = the server answered with a ServerHello; a per-backend
# `expect alert ... if <lib>` records what that library sends back to a hello
# it will not negotiate with (old-versions-only, export-only or SSLv2-format
# hellos), pinned from a probe run (`tools/gen_client_compat.py --probe`).
'''


def render(probes, pins=None):
    out = [HEADER]
    for p in probes:
        name = p["name"]
        v = p["version"]
        lv = (v[0] << 8) | v[1]
        cs = ", ".join(f"0x{c:04x}" for c in p["ciphers"])
        comp = ", ".join(f"0x{c:02x}" for c in p["compression"])
        exts = serialize_exts(p["exts"])
        fields = [f"legacy_version: 0x{lv:04x}", f"legacy_session_id: []", f"cipher_suites: [{cs}]",
                  f"compression_methods: [{comp}]"]
        if p["ssl2"]:
            # SSLv2 CIPHER-SPECs are three bytes (0x010080 etc.); hand the list
            # over as `cipher_specs` bytes and let the encoder frame it.
            specs = b"".join(c.to_bytes(3, "big") for c in p["ciphers"])
            fields = [f"format: sslv2", f"legacy_version: 0x{lv:04x}", f"cipher_specs: {hexlist(specs)}"]
        else:
            fields.append(f"extensions: {hexlist(exts)}")
        out.append(f'# tlsfuzzer probe: {name}')
        out.append(f'plzn tls "server/client-compat-{slug(name)}" {{')
        out.append('  rfc 5246 section 7.4.1.2')
        out.append('  chain: [default]')
        out.append('  uut server { versions: [tls12] }')
        out.append('  flow {')
        out.append('    send ClientHello { ' + ", ".join(fields) + ' }')
        out.append('    recv ServerHello')
        out.append('    close')
        out.append('  }')
        pin = (pins or {}).get(name, {})
        out.append('  expect ok')
        for backend in ("botan", "boringssl", "openssl", "rustls"):
            if backend in pin and pin[backend] != "ok":
                out.append(f'  expect {pin[backend]} if {backend}')
        out.append('}')
        out.append('')
    return "\n".join(out)


def probe(plzn, out_file, probes):
    """Run the generated file per backend; map each case to an outcome string."""
    pins = {}
    by_test = {f"server/client-compat-{slug(p['name'])}": p["name"] for p in probes}
    shims = (
        ("botan", "shims/build/botan_shim"),
        ("boringssl", "shims/build/boringssl_shim"),
        ("openssl", "shims/build/openssl_shim"),
        ("rustls", "shims/build/rustls_shim"),
    )
    for backend, shim in shims:
        res = subprocess.run([plzn, "run", "--shim", shim, out_file], capture_output=True, text=True)
        text = res.stdout + res.stderr
        cur = None
        for line in text.splitlines():
            m = re.match(r"\[(PASS|FAIL|SKIP)\] (\S+) ", line)
            if m:
                cur = m.group(2)
                if m.group(1) == "PASS":
                    pins.setdefault(by_test[cur], {})[backend] = "ok"
                continue
            m = re.search(r"observed: (.*)", line)
            if m and cur in by_test:
                obs = m.group(1)
                am = re.match(r"alert fatal/([a-z_]+)", obs)
                if am:
                    pins.setdefault(by_test[cur], {})[backend] = f"alert fatal/{am.group(1)}"
                elif obs.startswith("peer closed") or "closed without" in obs or obs.startswith("close"):
                    pins.setdefault(by_test[cur], {})[backend] = "close"
                elif "reset" in obs:
                    pins.setdefault(by_test[cur], {})[backend] = "reset"
                else:
                    pins.setdefault(by_test[cur], {})[backend] = f"UNPINNED: {obs}"
    return pins


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--script", default=DEFAULT_SCRIPT)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--probe", metavar="PLZN_BIN", help="run the file on every shim and pin per-backend outcomes")
    a = ap.parse_args()
    probes = parse_script(a.script)
    probes = [p for p in probes if p["name"] != "sanity"]
    before = len(probes)
    probes = distinct_probes(probes)
    open(a.out, "w").write(render(probes))
    print(f"wrote {a.out}: {len(probes)} distinct fingerprints ({before - len(probes)} duplicate names omitted)")
    if a.probe:
        pins = probe(a.probe, a.out, probes)
        unp = {k: v for k, v in pins.items() if any(s.startswith("UNPINNED") for s in v.values())}
        for k, v in unp.items():
            print("UNPINNED", k, v, file=sys.stderr)
        open(a.out, "w").write(render(probes, pins))
        n_ok = sum(1 for v in pins.values() if all(s == "ok" for s in v.values()))
        print(f"pinned: {n_ok} accepted by all four, {len(pins) - n_ok} with per-backend outcomes, {len(unp)} unpinned")


if __name__ == "__main__":
    main()
