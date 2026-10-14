# plzn

plzn is a TLS/DTLS test harness. You write short declarative test files
(`.plzn`) that describe a handshake flow, and `plzn` executes that flow
against a TLS implementation.

This test performs a TLS 1.2 handshake, xor's the first byte of the server's
Finished message's verify_data with 0xff before sending it, and asserts the
client responds with a fatal `decrypt_error`:

```
plzn tls "client/tls12-server-finished-corrupt" {
  rfc 5246 section 7.4.9
  chain: [default]
  uut client {
    versions: [tls12]
  }
  flow handshake {
    send Finished @ xor[handshake.verify_data, 0] = 0xff
  }
  expect alert fatal/decrypt_error
}
```

It's easy to run one or more tests against an implementation (though a shim binary):

```
$ plzn run --verbose --shim shims/build/botan_shim suite/client/tls12_server_finished_corrupt.plzn
[shim] botan (shims/build/botan_shim)
PLZN-RESULT case=ok detail=TLS exception (alert decrypt_error): Finished message didn't verify
[PASS] client/tls12-server-finished-corrupt — botan (127.0.0.1:37159) (23.315143ms)
       negotiated cipher suite: 0xcca9
   0. ok     handshake (5.711125ms)
       expected: alert fatal/decrypt_error
       observed: alert fatal/decrypt_error (level=2, description=51)
--- 1 tests, 1 passed, 0 failed (26.9ms) [botan] ---
```

## Building

Requires Rust 1.87 or higher.

The C/C++ shims (Botan, OpenSSL, LibreSSL, BoringSSL, GnuTLS, wolfSSL) need a C++20
compiler plus their development headers.

```
cargo build --locked                                # build plzn itself
make -C shims                                       # build rustls and every detected shim
make -C shims boringssl PLZN_BORINGSSL_ROOT=/path/to/boringssl
```

All C++ shims include `shims/common/plzn_shim.h` and link
`shims/build/libplzn-shim.a`. Build it on its own with
`make -C shims libplzn-shim`; see the [out-of-tree shim build instructions](shims/DESIGN.md#using-the-helper-library-out-of-tree)
for headers and linking.

Test certificates and keys are embedded in plzn; the installed binary does
not need the source checkout at runtime.

## Suite

Probably the more interesting part of plzn is the shipped suite which covers
many different aspects of the TLS/DTLS protocols. These were derived from a
combination of a read of the RFCs (eg if an implementation MUST or MUST NOT do
some particular action in a specified situation, there is or should be a plzn
test that covers this case) and flows that match historical bugs in notable
implementations, since it is not uncommon for more than one TLS implementation
to make the same mistake.

## Quick start

```
# Run against a library through its shim
plzn run --shim shims/build/botan_shim test.plzn
plzn run --shim shims/build/libressl_shim test.plzn
plzn run --shim shims/build/gnutls_shim test.plzn
plzn run --shim shims/build/wolfssl_shim test.plzn
plzn run --shim shims/build/rustls_shim test.plzn

# Stream schema-versioned NDJSON reports for automation
plzn lint --json suite
plzn run --json --shim shims/build/botan_shim suite

# --cert names the run's default chain, used only by tests that explicitly say
# `chain: [default]`; tests that name a concrete chain are unaffected.
plzn run --shim shims/build/botan_shim --cert ecdsa test.plzn

# Lint a test file (parse + schema check, no execution)
plzn lint test.plzn

# Canonically format one file or a directory tree
plzn fmt test.plzn
plzn fmt --check suite

# Dial your own already-running server (with an optional packet capture)
plzn dial --addr 127.0.0.1:4433 --pcap trace.pcap test.plzn

# Compare the wire outcome across implementations
plzn diff --shim shims/build/openssl_shim --shim shims/build/rustls_shim test.plzn

# Generate typed mutations and retain stable differential findings
plzn diff --mutate --budget 500 --reruns 3 --out findings \
  --shim shims/build/openssl_shim --shim shims/build/gnutls_shim test.plzn

# Lint the corpus, printing only diagnostics
plzn lint --errors-only suite

# Everything the pre-commit hook checks
./check.sh
```

## Documentation

- **[USAGE.md](docs/USAGE.md)**: quick reference for writing and running tests (syntax, steps,
  expectations, capability selectors, fields, mutations)
- **[DSL.md](docs/DSL.md)**: full DSL design document with grammar, examples and design decisions
- **[shims/DESIGN.md](shims/DESIGN.md)**: how the shims and their JSON config work

## License

Apache2

## Trophy Case

- Rustls accepted TLS 1.3 handshake records across encryption key changes
  [https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc]
