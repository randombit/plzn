#!/usr/bin/env python3
"""Rewrite numeric constants that have a name into the named form.

`plzn lint` rejects a numeric literal wherever the value is a known cipher
suite, named group, signature scheme, extension type or certificate type
(`0xc02f` is ECDHE_RSA_WITH_AES_128_GCM_SHA256; write the name ...). This tool
runs the lint over the given paths, parses those diagnostics and replaces each
literal with the name it reports, then re-runs the lint until it is clean (a
matrix literal feeds several cases, so one pass may not reach everything).

    tools/name_constants.py [--plzn target/debug/plzn] [paths...]

Defaults to `suite tests/cases`. Prints how many literals were rewritten per
name domain. Anything the lint still reports afterwards is printed and the
exit status is 1.
"""

import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

DIAG = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<col>\d+): lower error: "
    r"`(?P<lit>[^`]+)` is (?P<name>\S+); write the name"
)
TOKEN = re.compile(r"0[xX][0-9a-fA-F]+|\d+")


def lint(plzn, paths):
    proc = subprocess.run([plzn, "lint", *paths], capture_output=True, text=True)
    hits = {}
    for line in (proc.stdout + proc.stderr).splitlines():
        m = DIAG.match(line)
        if m:
            key = (m["path"], int(m["line"]), int(m["col"]))
            hits[key] = m["name"]
    return hits


def domain_of(name):
    if name.isupper() or name.endswith("_SCSV"):
        return "cipher suites"
    if name in ("rsa_sign", "dss_sign", "rsa_fixed_dh", "dss_fixed_dh", "ecdsa_sign", "rsa_fixed_ecdh", "ecdsa_fixed_ecdh"):
        return "certificate types"
    if re.match(r"^(secp|x25519|x448|ffdhe|brainpool|MLKEM|SecP|X25519|X448)", name):
        return "named groups"
    if re.match(r"^(rsa_|ecdsa_|dsa_|ed25519|ed448)", name):
        return "signature schemes"
    return "extension types"


def rewrite(hits):
    """Apply every hit; returns a Counter of rewrites per domain."""
    by_file = defaultdict(list)
    for (path, line, col), name in hits.items():
        by_file[path].append((line, col, name))
    done = Counter()
    for path, edits in by_file.items():
        p = Path(path)
        lines = p.read_text().split("\n")
        # Right-to-left within a line keeps earlier columns valid.
        for line, col, name in sorted(edits, key=lambda e: (e[0], -e[1])):
            text = lines[line - 1]
            start = col - 1
            m = TOKEN.match(text, start)
            if not m:
                # The column may sit on a leading `-` or a space; look ahead a little.
                m = TOKEN.search(text, start, start + 4)
                if not m:
                    print(f"{path}:{line}:{col}: no numeric token at the diagnostic's column", file=sys.stderr)
                    continue
            lines[line - 1] = text[: m.start()] + name + text[m.end() :]
            done[domain_of(name)] += 1
        p.write_text("\n".join(lines))
    return done


def main():
    args = sys.argv[1:]
    plzn = "target/debug/plzn"
    if args[:1] == ["--plzn"]:
        plzn = args[1]
        args = args[2:]
    paths = args or ["suite", "tests/cases"]
    total = Counter()
    for _ in range(8):
        hits = lint(plzn, paths)
        if not hits:
            break
        total += rewrite(hits)
    else:
        print("the lint still reports named literals after 8 passes", file=sys.stderr)
    for domain, n in sorted(total.items()):
        print(f"{n:5d} {domain}")
    print(f"{sum(total.values()):5d} total")
    left = lint(plzn, paths)
    for (path, line, col), name in sorted(left.items()):
        print(f"still numeric: {path}:{line}:{col} -> {name}", file=sys.stderr)
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
