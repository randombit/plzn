# Harness test shims

`dtls_test_shim` tests plzn's own DTLS receive/reassembly path. Its source
and byte rewriter live here; the seven flow fixtures are in
[`../cases/dtls_reassembly/`](../cases/dtls_reassembly/). Cargo builds the test
shim and runs its byte-level tests along with the other package targets.

Run the integration coverage with:

```sh
make -C shims botan openssl
cargo test --test dtls_reassembly
```

Each backend's test skips when that backend shim is unavailable. The regular
`cargo test` and `./check.sh` runs include this coverage.

The test shim launches an ordinary Botan or OpenSSL shim with a temporary
runner address, relays the runner's traffic unchanged, and rewrites the
backend's outgoing plaintext DTLS handshake records. It forwards the ShimID,
datagram framing, timer acknowledgements, backend diagnostics, and exit status.
Encrypted records remain unchanged. Child processes and relay threads have
bounded waits and are cleaned up when forwarding fails.

The integration test selects the backend and rewrite mode using the private
`PLZN_TEST_DTLS_BACKEND` and `PLZN_TEST_DTLS_REWRITE` environment variables.
Modes are `fragment:48`, `fragment:16`, `duplicate`, `overlap_mismatch`,
`offset_overflow`, and `length_mismatch`. A test fails if its configured
rewrite never occurs. These controls belong to the test shim; the fixtures
use ordinary DSL and the backend receives ordinary shim configuration.

The valid-fragment cases require plzn to finish the handshake. The malformed
cases require a local `decode_error` rejection, covering both plzn roles.
These are harness self-tests and stay outside the conformance `suite/`.
