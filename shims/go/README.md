# Go `crypto/tls` shim

`go_tls_shim` runs Go's standard-library TLS stack as a plzn unit under test.
It implements protocol version 1, both TLS client and server roles, TLS 1.2 and
TLS 1.3, certificate and trust-store loading, client authentication, SNI, ALPN,
TLS 1.2 cipher selection, curve selection, session caching, OCSP staples,
application-data framing, and structured result reporting.

Build and smoke-test it from the repository root:

```sh
make -C shims go
make -C shims go-test
python3 shims/testdata/run_smoke.py shims/build/go_tls_shim
```

Run a plzn case or suite with:

```sh
plzn run --shim shims/build/go_tls_shim test.plzn
```

The shim identifies `go-expectations.json` as its expectation sidecar. The
build copies this next to the binary, so the fully triaged corpus can retain
Go-specific alert choices and known-failure annotations without weakening the
shared test flows.

Go does not expose every policy control in the shared shim configuration.
DTLS, external PSKs, TLS 1.3 cipher selection, signature-scheme preferences,
early data, raw public keys, certificate compression, multiple tickets, and
post-handshake controls return `unsupported_config` before connecting.
