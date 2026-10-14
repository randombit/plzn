# plzn usage guide

This document is for LLMs (and humans) writing and running plzn tests. For the
full DSL grammar and design rationale, see [DSL.md](DSL.md). Historical coverage
audits against BoGo, tlsfuzzer and TLS-Anvil are under `notes/audit/`.

Start each TLS or DTLS test with `plzn tls "name" { ... }`. A `.plzn` file may
also contain other protocols: `plzn` ignores `plzn quic`, `plzn http`, and
other protocol declarations, and leaves their text intact when formatting.

## Workflow

1. Write a `.plzn` file
2. `plzn fmt file.plzn` -- apply canonical whitespace formatting
3. `plzn lint file.plzn` -- parse + schema check, instant, no network
4. `plzn run --shim shims/build/botan_shim file.plzn` -- or pass any compatible shim executable
5. Read the output and iterate

No server setup, no cert generation, no config files. For every test case
`plzn run` spawns the library's shim process, hands it a generated JSON config
(certificates, version bounds, policy, expectations), drives the flow, and tears
it down.

## Running tests

```bash
# Run against a library through its config-file shim
plzn run --shim shims/build/botan_shim test.plzn
plzn run --shim shims/build/openssl_shim test.plzn
plzn run --shim shims/build/libressl_shim test.plzn
plzn run --shim shims/build/rustls_shim test.plzn
plzn run --shim shims/build/gnutls_shim test.plzn
plzn run --shim shims/build/wolfssl_shim test.plzn

# Directories recurse; several inputs at once
plzn run --shim shims/build/botan_shim suite/server suite/dtls

# What an explicit `chain: [default]` means in this run: ecdsa (P-256, the default), rsa,
# ecdsa-p384, ecdsa-p521, ed25519, rsa-pss. A test that is ABOUT its certificate
# names it (`chain: [rsa_2048]`) instead of relying on the run default.
plzn run --shim shims/build/botan_shim --cert rsa test.plzn

# Against a server you manage yourself (`uut server` tests only). Packet
# capture and verbose reporting are options of the direct-dial command.
plzn dial --addr 127.0.0.1:4433 --pcap trace.pcap -v test.plzn

# Cases run on a worker pool against a shim backend (eight workers per CPU by
# default -- cases are mostly idle, so oversubscribing wins -- or PLZN_JOBS);
# output stays in input order. --jobs 1 runs serially.
plzn run --shim shims/build/botan_shim --jobs 4 suite/server

# Lint only (parse + schema check); directories recurse
plzn lint test.plzn
plzn lint --errors-only suite

# Newline-delimited JSON for CI and report ingestion
plzn lint --json suite
plzn run --json --shim shims/build/botan_shim suite/server

# Format files in place, or only check them; directories recurse
plzn fmt test.plzn suite/server
plzn fmt --check suite
```

`plzn run` always owns and configures a shim process. `plzn dial` instead
connects directly to an already-running endpoint, so it accepts only `uut
server` tests and does not apply shim expectation sidecars.

### Machine-readable reports

`plzn lint --json` and `plzn run --json` emit newline-delimited JSON (NDJSON)
to stdout. Every object has `schema_version: 1` and a `type`; the final object
is always a `summary`. Normal human output, including shim stderr, is not mixed
into the stream. Command-line usage errors still go to stderr and use exit code
2, while test/lint failures retain the ordinary exit code 1.

Lint emits one `type: "file"` record per input with `status: "ok"` or
`"error"`. Diagnostics are structured into source name, line, column, excerpt,
caret, category, message, and suggestions. JSON mode always reports successful
files too; `--errors-only` remains a human-output convenience.

Run emits one `type: "case"` record per concrete matrix/repeat/session case.
Its `status` is one of `pass`, `fail`, `skip`, `xfail`, `xpass`, or `crash`.
Executed cases include the expectation and observation, a tagged raw wire
`outcome`, nanosecond timings, individual step results, captures in hex, the
negotiated cipher suite as numeric, hexadecimal, and named forms, and the
shim's structured result. Cases rejected before execution instead carry a
`classification` such as `setup_error`, `not_applicable`, or
`unsupported_config`. Cross-run assertions are case records classified as
`cross_run_assertion`. The summary contains every disposition count, total
duration, shim identity/path, and whether the crash breaker aborted the run.

NDJSON is used so consumers can stream a full-corpus run without buffering the
entire report. For example:

```bash
plzn run --json --shim shims/build/botan_shim suite \
  | jq -c 'select(.type == "case" and (.status == "fail" or .status == "xpass"))'
```

### Differential comparison and mutation discovery

`plzn diff` runs the same concrete program and deterministic peer randomness
against two or more shims, then compares expectation-independent outcomes:

```bash
plzn diff \
  --shim shims/build/botan_shim \
  --shim shims/build/openssl_shim \
  --shim shims/build/rustls_shim \
  suite/server/tls13_close_notify.plzn
```

The comparison buckets success, alert level/code and failing step, clean close,
reset, timeout, internal/I/O failure, and shim crash. Unsupported UUT
configuration is reported but excluded from the comparison. The test's UUT and
peer policy are preserved; its terminal expectations and per-backend
expectation overrides are deliberately replaced with an accept-either
observation mode. The JSON record retains the negotiated cipher suite and shim
detail. Supplying two builds that identify as the same backend is supported;
their paths distinguish them in reports.

Embedded and sidecar `expect`, `skip`, and `xfail` dispositions do not decide a
differential verdict. This mode is meant to observe the implementations anew;
unsupported shim configuration remains the mechanism for declaring that a
backend cannot execute a case.

At least two comparable observations are required. A case with fewer is marked
`INCOMPLETE`, not incorrectly reported as agreement.

Add `--mutate` to turn eligible successful tests into seed programs:

```bash
plzn diff --mutate --budget 1000 --reruns 3 --out findings \
  --shim shims/build/openssl_shim \
  --shim shims/build/gnutls_shim \
  suite/server
```

For every unambiguous harness-sent message kind in the selected base handshake
flight, the generator tries deterministic, single-operation probes. Validity-preserving
probes (record fragmentation, TLS 1.3 record padding, and DTLS fragment
duplication/reordering) run first, followed by handshake-length, truncation,
padding, trailing-byte, record-version, and content corruptions. Candidates
are expressed as ordinary `send Message @ ...` DSL overrides, formatted,
parsed, checked, and lowered through the same path as checked-in tests.

A seed must currently be one non-matrix, non-repeat, single-connection
`flow handshake` with no anchor, existing send mutation, or extension delta,
and its unmodified handshake must succeed on every comparable shim. Session
flows and occurrence-specific targeting (notably the second ClientHello after
HRR and the two DTLS 1.2 cookie-exchange ClientHellos) are intentionally
deferred rather than mutating an ambiguous message. Explicit post-handshake
steps are also deferred because inserting another step would duplicate rather
than mutate the original.

Human output is quiet for agreeing mutation candidates. Differences are rerun
(`--reruns 2` by default) and ranked: crashes, accept/reject splits,
violations of a mutation's declared accept/reject semantics, disagreement on
validity-preserving transformations, timeouts, alert-versus-close splits, then
other alert differences. A consensus can therefore still be a finding: all
backends rejecting a validity-preserving transformation, or all accepting a
structurally invalid one, is reported as `EXPECTATION`. One stable
representative per case/message/outcome cluster is written beneath `--out`
(default `findings`):

```
findings/<case-and-mutation>/
  case.plzn    # isolated, canonical, one-mutation reproducer
  result.json  # observations, score, stability and shim details
  repro.sh     # reruns the exact shim paths
```

`--json` emits one schema-versioned JSON object for every ordinary case or
generated candidate, including agreements, and suppresses the text summary.
Differential agreement is evidence, not a correctness oracle: triage findings
against the RFC and the generated case before promoting one into `suite/`.

`--cert` names the run's default chain: what an explicit `chain: [default]`
resolves to (see "Certificate chains"). It defaults to ECDSA P-256. Omitting
`chain:` is a lint error, and `peer.capabilities` never supplies one implicitly; tests that
depend on a certificate type name it and therefore run identically in a file,
directory, or whole-corpus invocation. The full `--cert` set is `rsa`, `ecdsa`
(P-256), `ecdsa-p384`, `ecdsa-p521`, `ed25519`
and `rsa-pss` (an id-RSASSA-PSS key, RFC 4055: rsa_pss_pss_* signatures only).
The P-521 and RSA-PSS bundles are file-backed (`shims/testdata/server_*`,
regenerated by `shims/testdata/gen_client_ee.sh`). Their cases live in the
ordinary role directories and carry the key type in the filename. A shim whose
library cannot use a key type refuses the case (SKIP): rustls's ring provider
has no P-521 signing and cannot load RSASSA-PSS keys, Botan has no
rsa_pss_pss_* schemes.

### Backends (shims)

Backends are selected by executable path; there is no registry compiled into
plzn. A shim identifies itself when invoked with `--plzn-shim-info`, returning
protocol version 1, its stable annotation/report name, and optionally a JSON
expectation sidecar. Relative sidecar paths resolve beside the executable and
can override `expect`, `skip`, or `xfail` for exact concrete test IDs. The full
protocol and schemas are documented in [shims/DESIGN.md](../shims/DESIGN.md).

This repository provides shims under `shims/`: small programs that link the real
library, read the config plzn writes, and connect back to plzn. Botan,
OpenSSL, LibreSSL, BoringSSL, GnuTLS, and wolfSSL are C++; rustls is a separate Cargo
crate under `shims/rustls`. `make -C shims` builds rustls without adding it to
plzn's dependency graph, detects the installed C++ libraries with `pkg-config`,
and builds the ones it finds (LibreSSL from its side-by-side pkg-config
directory, or `PLZN_LIBRESSL_ROOT=<install prefix>`). To test a Botan checkout
instead of the installed package:

```bash
make -C shims botan PLZN_BOTAN_ROOT=/path/to/botan
make -C shims boringssl PLZN_BORINGSSL_ROOT=/path/to/boringssl
make -C shims configure PLZN_BOTAN_ROOT=/path/to/botan \
  PLZN_BORINGSSL_ROOT=/path/to/boringssl
```

`make configure` persists checkout roots in the ignored
`shims/build/config.mk`; command-line values still override it. `./check.sh`
runs `make -C shims` first. The library file a shim links against is a
prerequisite, so a rebuilt or upgraded library relinks the shim and an
up-to-date shim is left alone. Configure an empty root to return that library
to package discovery.

A shim process that dies by signal is reported on its own line and counted as
failed, whatever plzn saw on the wire:

```
[CRASH] server/tls13-empty-key-share-triggers-hrr — botan shim killed by signal 11 (SIGSEGV)
```

A single crash is a finding. If the shim crashes on three consecutive cases
the run stops with exit status 2, because that shape points at a broken shim
binary or environment (a library rebuilt after the shim was linked, a missing
shared library) rather than at the tests; `PLZN_CRASH_LIMIT=N` changes the
threshold and `0` disables the stop. A shim that exits before it even connects
is reported immediately with its exit reason instead of after the accept
deadline.

Botan, OpenSSL, and LibreSSL are the fully corpus-enabled DTLS 1.2 backends
(LibreSSL's retransmit schedule is fixed, so it skips cases that set another
one or rescale a live timer). BoringSSL is
the oracle for the focused DTLS 1.3 corpus. GnuTLS supports
baseline DTLS 1.2 in both roles, but currently skips virtual-clock, timeout-
policy, datagram-rewrite, PSK, and renegotiation cases. The wolfSSL shim skips
DTLS until its datagram framing is wired (and an installed wolfSSL build may
also have DTLS compiled out); rustls has no DTLS.

Every shim receives the explicit DTLS wire-version bounds. A DTLS-1.2-only
shim reports `unsupported_config` for `0xFEFC`, so running all of `suite/dtls`
cleanly skips its DTLS 1.3 cases instead of accidentally negotiating DTLS 1.2.

`PLZN_SHIM_LIMIT` (default 8) caps concurrently live shim processes;
`PLZN_CORPUS_LIMIT` (default 2) caps concurrent corpus subprocesses under
`cargo test --test shim_corpus -- --ignored` (the corpus tests are `#[ignore]`d,
so a plain `cargo test` leaves them out); `PLZN_CRASH_LIMIT` (default 3) is the
consecutive-crash stop.

### Outcomes

Each case prints `[PASS]`, `[FAIL]`, `[SKIP]`, `[XFAIL]`, or `[XPASS]` (plus
`[CRASH]` when the shim process died), followed by a summary line:

```
--- 12 tests, 10 passed, 0 failed, 1 skipped, 1 xfailed, 0 xpassed (1.3s) [botan] ---
```

The exit status is 1 if any case failed or unexpectedly passed an `xfail`, 2
if the run was stopped by consecutive shim crashes, and 0 otherwise; skips
and expected failures do not affect it. A case
is skipped when the test says `skip <backend>`, or when a `uut client`
test's `peer.capabilities` capability set has nothing in common with what the connecting
client offered. A case is also skipped when the shim reports that its library
cannot apply a `uut` knob value (or the protocol: DTLS on rustls); the reason
is printed inline and again in the `--- skipped on <backend> (N) ---` list
after the summary, so a run's skips can be audited the way BoGo's UNSUPPORTED
list can.

## Anatomy of a test

```
plzn tls "group/name" {
  rfc 8446 section 4.1.2     # optional, repeatable; cited in the report
  uut server {                         # required: policy applied to the UUT/shim
    versions: [tls13]           # first is plzn's peer driver; all are enabled in the shim
  }
  peer {                        # optional: configuration owned by plzn's endpoint
    capabilities: [ecdhe_ecdsa] # offer/selection and scenario selectors
  }
  skip rustls "why"          # optional, repeatable: this backend is not applicable (the reason goes in the skip log)
  xfail openssl "why"        # optional, repeatable: run a known-broken backend; failure=XFAIL, success=XPASS
  chain: [ecdsa_p256]        # required: the SERVER's chain(s); [] = none, [default] = run-specific choice
  client_chain: [rsa, ecdsa_p256]  # optional: client-authentication credentials, in preference order
  matrix { ... }             # optional: sweep axes, referenced as $var
  psk { ... }                # optional: external pre-shared key
  flow handshake { ... }     # the steps
  expect ok                  # the outcome
  expect alert fatal/decode_error if openssl   # optional per-backend override
  assert no_duplicate_record_seqnums           # optional post-trace assert (DTLS)
  assert max_datagram_size 1200                 # every datagram emitted by the DTLS UUT fits
}
```

Resumption tests replace `flow` and `expect` with `session` blocks (below).
Comments start with `#`. Statements end at newlines; inside `{ }`, `[ ]` and
`( )` newlines are not significant. Several `test` blocks per file are fine.

## Writing a test (`uut server`)

### Minimal happy-path test

```
plzn tls "usage/happy" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [x25519, aes128_gcm_sha256] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
```

- `uut server` -- the UUT is a server; plzn plays the client.
- `uut.versions` -- non-empty version list; its first entry selects plzn's peer.
- `peer.capabilities` -- key-exchange, cipher-suite, group, signature, and scenario
  selectors. The schema validates them; typos get "did you mean?" suggestions.
- `peer.request_client_cert` -- makes plzn's server request a client
  certificate (`uut client` only). An empty Certificate is accepted, and the
  handshake continues without client authentication.
- `flow handshake { ... }` -- run the full handshake preset, then the steps inside.
- `expect ok` -- the handshake and every step complete without error.

A `uut server` flow that expects `ok` must end with `send AppData` then
`recv AppData`, a key-material comparison (`recv Exporter` / `recv TLSUnique`),
or with `close` or `wait`, so a server that defers its rejection cannot hide
behind a completed handshake; lint rejects the test otherwise, even for a bare
`flow handshake {}`. DTLS flows are exempt.

`send AppData` sends a reproducible random 32-byte request and asks the shim
for 32 random response bytes. Use `send AppData { size: N }` to change both
lengths, or `{ size: N, reply: M }` to choose them independently. `reply: none`
requests no response. The declared `size` is the exact TLS plaintext length,
including plzn's small request header, so record-boundary tests remain exact.
Requests shorter than that 12-byte header support only the default same-size
response; a zero-length request requests no response. A following bare `recv
AppData` checks the response length requested by the oldest send, while an
explicit `{ size: N }` matcher overrides it. Payload contents are deliberately
not part of the test language: both sides generate their test bytes from the
request instead of carrying HTTP or other application-specific literals.
`send AppData { size: 0 }` therefore emits one empty application-data record
and continues immediately. `send AppData { size: 32 } @ fragment 1` puts each
of the 32 bytes in its own record; the shim's incremental request decoder
supports this fragmented delivery. An exact 1/n-1 split would instead put the
remaining 31 bytes together in a second record, which this modifier does not do.

### Negative test (expect a specific alert)

```
plzn tls "usage/bad-finished" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    send Finished { verify_data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }
  }
  expect alert fatal/decrypt_error
}
```

plzn sends a Finished with all-zero verify_data. The server rejects it with
`decrypt_error`, which matches the expectation, so the test passes.

### Byte-level mutation

```
plzn tls "usage/xor-last-byte" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    send Finished @ xor[-1] = 0xff
  }
  expect alert fatal/decrypt_error
}
```

`@ xor[-1] = 0xff` -- after encoding the Finished normally, xor its last byte
with 0xff. Negative indices count from the end.

### Structured field-path mutation

```
plzn tls "usage/xor-verify-data-byte-0" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    send Finished @ xor[handshake.verify_data, 0] = 0xff
  }
  expect alert fatal/decrypt_error
}
```

`handshake.verify_data` resolves to the byte range of that field inside the
encoded body; the index is relative to the range. `handshake.msg_type` and
`handshake.length` target the 4-byte handshake header, and `record.*` paths
target the record after encryption (see the mutation table below).

### Field override on a sent message

```
plzn tls "usage/high-legacy-version" {
  chain: [rsa_2048]
  # Botan rejects the out-of-range version (decode_error); see the note on
  # mixed ok/failure expectations under "Per-backend expectations" below.
  skip botan
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello { legacy_version: 0xfefe }
    send AppData
    recv AppData
  }
  expect ok
}
```

The preset still runs; when it builds the ClientHello, `legacy_version` is
0xfefe instead of 0x0303. OpenSSL and rustls negotiate down to TLS 1.2 and
the app-data round trip completes.

### Receive-side matcher

```
plzn tls "usage/check-server-version" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    recv ServerHello { legacy_version: 0x0303 }
    send AppData
    recv AppData
  }
  expect ok
}
```

When the preset receives the ServerHello, its `legacy_version` must equal
0x0303, else the test fails with a matcher-mismatch diagnostic. `has_ext: 0xNNNN`
and `lacks_ext: 0xNNNN` assert an extension's presence or absence;
`random_suffix: [...]` matches the tail of the server random.

### Extension deltas

```
plzn tls "usage/extension-deltas" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      +ext server_name = "localhost"
      +ext signature_algorithms = [rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256]
      -ext extended_master_secret
      +ext 0x1a1a = raw "cafe"
    }
    recv ServerHello { lacks_ext: extended_master_secret }
    send AppData
    recv AppData
  }
  expect ok
}
```

`+ext name = value` replaces an extension in place (or appends it if absent);
`+ext name` with no value gives it an empty body; `+ext dup ...` appends a
second copy of an already-present type; `-ext name` removes one;
`reverse_extensions` reverses the whole block. Many extensions take a typed
value (`status_request = ocsp`, `padding = 300`, `ec_point_formats =
[uncompressed]`); `raw "HEX"` always works and a numeric type such as
`0x1a1a` takes only `raw` or no value. The full table, and which messages
accept deltas in each role, is under "Extension deltas" in the reference.
Lint rejects a delta on a message the driver would not apply it to.

### Matrix sweep

```
plzn tls "usage/sweep-finished-bytes" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  matrix {
    pos in [-1, -2, -6, -12]
    val in [0x01, 0xff]
  }
  flow handshake {
    send Finished @ xor[$pos] = $val
  }
  expect alert fatal/decrypt_error
}
```

This produces 4 x 2 = 8 cases. Each substitutes concrete values for `$pos` and
`$val`, and the axes appear in the report:

```
[PASS] usage/sweep-finished-bytes[pos=-1,val=1] — ...
[PASS] usage/sweep-finished-bytes[pos=-1,val=255] — ...
```

A list may name its entries instead of numbering them: `suite in
[ECDHE_RSA_WITH_AES_128_GCM_SHA256, DHE_RSA_WITH_AES_128_CBC_SHA]`, `scheme in
[rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256]`, `grp in [x25519, secp384r1]`
(any name from the version, cipher-suite, group, signature-scheme, extension-type or
certificate-type tables, resolved unambiguously; see "Named constants" below).
A value that HAS a name must be written by name: the lint rejects
`suite in [0xc02f]` with the name to use.

Named sets: `suite in cipher_suites(tls13)` sweeps the implemented TLS 1.3
suites (the `suite` axis pins the offered list to one suite per case),
`group in groups(tls13)` sweeps the three groups every backend implements
(x25519, secp256r1, secp384r1; the `group` axis pins supported_groups and the
key share to one group per case, so each case is a 1-RTT handshake on that
curve; a matrix cannot skip one value per backend, so P-521 and FFDHE get
their own `skip rustls` cases), and `cert in cert_models()` sweeps the
certificate models. A `sigalg` axis pins the offered signature_algorithms.
`grease in grease` expands to all 16 RFC 8701 reserved values; naming the
axis `grease` also renders its report suffix as a four-digit wire value.
`matrix { version in [tls10, tls11, tls12] }` together with
`uut client|server { versions: [$version] }` runs one case per protocol version
and renders the symbolic version in each case suffix.
Use `uut client|server { cipher_suites: [$suite], curves: [$group] }` when the
UUT's own policy and first key share must also be pinned to the matrix point;
this is especially important for anchored client-UUT and resumption flows that
cannot insert an automatic HelloRetryRequest.
Matrices also apply to multi-session tests. Each Cartesian-product point runs
the complete `session` sequence in a fresh shim process, so resumption state is
shared within that point and isolated from every other point.

### Per-backend expectations, skips, and expected failures

Libraries legitimately disagree on alert codes for underspecified cases. Pin
each one rather than loosening the expectation:

```
plzn tls "usage/bad-record-after-handshake" {
  rfc 5246 section 6.2
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send raw "ff 0303 0005 deadbeefca"
    send AppData
    recv AppData
  }
  expect alert fatal/unexpected_message
  expect alert fatal/bad_record_mac if openssl
  expect alert fatal/decode_error if rustls
}
```

`send raw "HEX"` writes bytes straight to the transport (spaces are ignored).
Raw bytes are not hashed into the transcript, so a flow that continues past a
raw handshake message cannot complete the Finished exchange; end such flows
with `wait` and pin the peer's alert. In a TLS 1.3 client flow a second
`send ClientHello` (before any HelloRetryRequest) resends the identical bytes
without touching the transcript, so the server's rejection of the duplicate
can be read after its flight.
When a backend cannot run a case at all (rustls has no CBC, static RSA, DHE,
renegotiation, or DTLS), nothing is needed: the shim refuses the case itself and
reports `[SKIP]` with the reason, without affecting the exit status. An explicit
`skip <backend> "why"` is for capability and harness gaps the shim cannot infer.
Use `xfail <backend> "why"` when the backend can run the test but is known to
behave incorrectly. The test still runs: its ordinary failure becomes XFAIL;
if it starts passing, XPASS makes the run fail so the stale annotation is found.
Setup failures, unsupported configurations, runtime skips, crashes, shim-local
exceptions and runner-internal/codec faults are never converted to XFAIL.
An established peer's protocol rejection, matcher mismatch or missing expected
application response can be XFAIL; a missing resumption state or follow-up
connection cannot.

Overrides may also swap `ok` for a failure or vice versa. The effective
backend expectation configures both the runner and the shim self-check.

### Record-layer mutation

```
plzn tls "usage/aead-tag-flip" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa, gcm] }
  flow handshake {
    send AppData { size: 18 } @ xor[record.aead_tag, 0] = 0xff
    recv AppData
  }
  expect alert fatal/bad_record_mac
}
```

`record.*` mutations apply after encryption: `record.aead_tag`, `record.mac`
(under RFC 7366 encrypt-then-MAC the MAC is the cleartext trailer of the record,
so a `record.mac` flip must draw bad_record_mac before the peer decrypts anything)
(CBC suites), `record.encrypted_record`, `record.content_type`, and the
length-preserving record-header fields `record.version` (offset 1, TLS and
DTLS), `record.epoch` and `record.sequence_number` (the DTLS 1.2 header only).
Flipping a sealed DTLS record's epoch, sequence number, or version produces an
"otherwise invalid" record a conforming peer silently discards (RFC 6347
4.1.2.7). The header length field is not a mutation target: a raw datagram
expresses a lying length directly, and changing it on a sealed record would
desynchronize plzn's own datagram packer.

### Post-handshake: KeyUpdate, renegotiation, close_notify

```
plzn tls "usage/keyupdate-requested" {
  rfc 8446 section 4.6.3
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send KeyUpdate { request_update: update_requested }
    send AppData
    recv KeyUpdate { request_update: update_not_requested }
    recv AppData
  }
  expect ok
}

plzn tls "usage/tls13-renegotiation-forbidden" {
  rfc 8446 section 4.1.2
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send Renegotiation
    recv AppData
  }
  expect alert fatal/unexpected_message
}

plzn tls "usage/tls12-renegotiation" {
  rfc 5746 section 3.5
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  skip rustls
  flow handshake {
    send AppData
    recv AppData
    renegotiate
    send AppData
    recv AppData
    close alert warning/close_notify
  }
  expect ok
}
```

- `send KeyUpdate` rotates plzn's write keys; `recv KeyUpdate` reads the
  server's and rotates read keys.
- In the client role, `send Renegotiation` replays the ClientHello as an
  encrypted post-handshake record (TLS 1.3 must reject). In the server role it
  sends an empty HelloRequest by default. `send Renegotiation { msg_type: 0x0b }`
  relabels that post-handshake message to inject another unexpected type.
- `renegotiate` drives an RFC 5746 second handshake on the live connection
  (TLS 1.2 and DTLS 1.2). plzn tells the shim to permit renegotiation; the
  renegotiation_info binding is verified both ways. `renegotiate { ClientHello
  overrides / +ext / -ext }` customizes the renegotiation ClientHello only (the
  initial handshake keeps the program-level overrides), so a test can offer
  `+ext encrypt_then_mac`, drop an extension the session used (`-ext
  extended_master_secret`, RFC 7627 5.3), or add the SCSV
  (`cipher_suites: [0xc02f, 0x00ff]`, forbidden in a renegotiation by RFC 5746
  4.2) on the second handshake alone. `renegotiate insecure` omits
  renegotiation_info entirely (RFC 5746 3.5 legacy renegotiation): pair it with
  `send ClientHello { -ext renegotiation_info }` on the initial hello for a
  connection that is insecure from the start (whether the server performs it is
  library policy). `renegotiate resumed` presents the established session ID or
  ticket and requires an abbreviated TLS 1.2 second handshake; it may be
  combined with the ClientHello block or with `insecure`. For a stepped second
  handshake, `begin_renegotiation` (the
  same keyword as the DTLS flight step; over TLS it drives plzn's TLS 1.2
  client) resets to a renegotiation and the flow then names the second
  handshake's messages itself -- `send ClientHello`, `recv ServerHello`, ...,
  `recv Finished` -- so `send AppData` and `@ fragment N hold` /
  `flush_fragment` can go between them (RFC 5246 7.4.1.1 lets application data
  cross a renegotiation under the old keys; a server's answer that arrives
  while plzn is still reading the handshake is set aside and delivered by the
  next `recv AppData`). Overrides, mutations and `+ext` deltas declared after
  `begin_renegotiation` shape the second handshake only. The other direction, a
  shim CLIENT's own renegotiation (`uut client { renegotiate_after_handshake }`), is
  taken by plzn's TLS 1.2 and DTLS servers: stepped (`recv ClientHello` after
  the initial Finished, then the second handshake's steps), unprompted (the
  ClientHello arrives during `recv AppData`), or refused with `send alert
  warning/no_renegotiation` (RFC 5246 7.4.1.1; the connection carries on
  under the established keys -- Botan accepts that, OpenSSL's client answers
  with a fatal handshake_failure).
- `close` closes the transport; `close alert warning/close_notify` first sends
  the alert under the current keys.
- In TLS 1.3 the server's reaction to a bad final client message only surfaces
  when plzn reads, so follow the bad send with `recv AppData`.

### The `uut` block: the shim's own policy

```
plzn tls "usage/tls12-client-version-too-old" {
  rfc 8446 section 4.2.1
  chain: [rsa_2048]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake until send ClientHello {
    send ClientHello { -ext supported_versions }
  }
  expect alert fatal/protocol_version
}
```

`uut client|server { ... }` is the single source of the library's policy. Configuration
owned by plzn's endpoint lives in `peer { ... }` instead; in particular,
`peer.capabilities` shapes plzn's offers, selections, and handshake scenario.
The first `versions` entry selects plzn's peer driver; the full list is enabled
in the shim. The driver does not itself negotiate down to another entry: a
test of a wider UUT negotiating with a TLS 1.0 peer uses `tls10` first and lists
the UUT's higher versions after it. Conversely, a test of a legacy ServerHello
selection while sending a higher ClientHello version keeps the selected
version first and overrides `ClientHello.legacy_version`; static RSA copies
that actual offered value into its premaster secret. Explicit message and extension overrides create intentional
peer/UUT mismatches, as above. The shims expose
everything their library implements (a Botan default that hides a feature does
not hide it from the suite), so the `uut` block is how a test turns a feature
OFF: list-valued fields are exact sets, and whatever is absent is disabled.
`uut server { curves: [x25519, secp256r1] }` is a server with finite-field DH
disabled, so a client offering only ffdhe2048 must be refused; the same block on
a client makes a server naming ffdhe2048 a protocol error it must reject.
The planned control surface is in `shims/DESIGN.md`. Fields today:

| Field | Value | Effect on the shim |
|-------|-------|--------------------|
| `versions` | `[tls10]`, `[tls11]`, `[tls12]`, `[tls13]`, mixed TLS ranges, `[$version]`, `[dtls12]`, or `[dtls13]` | enabled versions; first entry selects plzn's fixed peer driver; matrix variables are supported |
| `cipher_suites` | `[0xc02f, ...]` | allowed suites |
| `curves` | `[x25519, secp256r1]` or wire values | allowed groups |
| `require_client_cert`, `request_client_cert` | `true` / `false` | client authentication |
| `verify_peer` | `true` / `false` | verify plzn's certificate |
| `alpn_advertise` | `["h2", "http/1.1"]` | protocols a shim CLIENT advertises |
| `alpn_select` | `"h2"` | protocol a shim SERVER selects |
| `alpn_select_from` | `["h2", "http/1.1"]` | protocols a shim SERVER supports, in preference order; selection may vary with the client offer |
| `expect_alpn` | `"h2"` | assert the library reports this negotiated protocol |
| `alpn_decline` | `true` / `false` | shim refuses every offered protocol |
| `srtp_profiles` | `[srtp_aes128_cm_hmac_sha1_80, ...]` | DTLS-SRTP profiles the UUT offers/accepts, in preference order |
| `expect_srtp_profile` | a profile name or wire value | assert the library reports this negotiated profile (`0` = none) |
| `signing_prefs`, `verify_prefs` | `[rsa_pss_rsae_sha256, 0x0403]` | signature schemes the shim signs with / accepts from plzn (`verify_prefs` on a client is its signature_algorithms extension and is enforced on the ServerKeyExchange it receives; OpenSSL keeps a client's two lists in one, so it refuses `signing_prefs` and `verify_prefs` together on a client unless they name the same list; the rustls shim applies it to its accept-any verifier, client role only) |
| `server_preference` | `true` / `false` | server selects by its own suite (and, Botan/OpenSSL, group) order instead of the client's |
| `renegotiation` | `none` / `client` / `server` / `both` | which side may initiate renegotiation; `none` refuses with a `no_renegotiation` warning |
| `session_tickets` | `0`, `1`, `2`, ... | tickets issued per handshake; `0` also disables resumption |
| `max_early_data` | `0`, `1024`, ... | TLS 1.3 server: maximum 0-RTT bytes advertised in each ticket and accepted on resumption |
| `max_cert_list` | `16384`, ... | maximum encoded peer certificate chain size in bytes |
| `record_size_limit` | `64` ... `16385` | RFC 8449 receive limit the UUT advertises and enforces |
| `records_per_traffic_key` | `0`, `4`, ... | TLS 1.3: send an automatic KeyUpdate after this many records (Botan only; `0` = never) |
| `key_update` | `true` / `false` | initiate one post-handshake KeyUpdate before application data (BoringSSL; useful for DTLS 1.3 ACK/epoch tests) |
| `extended_master_secret` | `require` / `allow` / `off` | RFC 7627 posture; `require` rejects a client without it, `off` never negotiates it |
| `encrypt_then_mac` | `true` / `false` | negotiate RFC 7366 on CBC suites |
| `middlebox_compat` | `true` / `false` | TLS 1.3 compatibility-mode ChangeCipherSpec |
| `compress_certificate` | `true` / `false` | enable RFC 8879 certificate compression in the UUT; `peer.capabilities: [compress_cert]` independently makes plzn offer it |
| `raw_public_key` | `true` / `false` | present an RFC 7250 raw public key when `peer.capabilities: [offer_rpk]` makes plzn offer or select it |
| `mtu`, `initial_timeout_ms` | `1200`, `250` | DTLS path MTU and initial retransmit timer |
| `min_key_update_interval_ms` | `0`, `60000`, ... | TLS 1.3: refuse a peer KeyUpdate that arrives sooner than this after the previous one (Botan `minimum_key_update_interval_ms`; a reciprocation the shim asked for is exempt). `0` = no limit, which is what OpenSSL and rustls always do, so they accept `0` and refuse anything else |
| `psk_secret`, `psk_identity` | `"0a0b0c0d"`, `"name"` | the pre-shared key the shim actually holds when it must differ from the test's `psk { }` block: a wrong key, an unknown identity |
| `client_cert` | `valid` / `untrusted` / `none` / `expired` | the credential a shim CLIENT answers a CertificateRequest with: the trusted self-signed default, an untrusted self-signed one, no certificate at all (an empty Certificate), or a trusted but expired one (`shims/testdata/*_client_*`) |
| `renegotiate_after_handshake` | `true` / `false` | a shim CLIENT starts a renegotiation once one application-data round trip has completed (TLS 1.2 and DTLS 1.2; plzn's server takes it, see the flight-step table) |
| `hello_request_after_app_data` | `true` / `false` | a shim SERVER sends a HelloRequest once application data has flowed (RFC 5246 7.4.1.1, tlsfuzzer's protected-resource renegotiation); rustls SKIPs |
| `require_client_cert_on_renegotiation` | `true` / `false` | with `hello_request_after_app_data`, that renegotiation requires a client certificate the initial handshake did not (plzn's client answers with the CA-issued test credential) |
| `half_rtt_data` | `["h", "r", "t"]` | a TLS 1.3 shim SERVER writes each string as one application record after its own Finished and before the client's |
| `ocsp_stapling` | `true` / `false` | the shim server staples an OCSP response for its certificate (the runner generates a fresh, signed "good" response); OpenSSL 3.6 drops the staple for a self-signed leaf |
| `post_handshake_auth` | `request` / `require` | TLS 1.3 server: send a post-handshake CertificateRequest once the client's first application data arrives (OpenSSL only; Botan and rustls refuse the knob) |

A library that cannot apply a knob value says so instead of ignoring it: the
shim exits with `unsupported_config` naming the knob, and the case is reported
as `[SKIP] <id> — <backend> cannot apply: uut.<knob>: <why>` rather than
passing vacuously. What each library can switch:

| Knob | Botan | OpenSSL | rustls |
|------|-------|---------|--------|
| `server_preference` | suites and groups | suites and groups | suites only (a group-order case needs `skip rustls`) |
| `renegotiation` | all four | all four | `none` only |
| `session_tickets` | any | any | any |
| `max_early_data` / 0-RTT I/O | unsupported | any / wired | any / wired |
| `max_cert_list` | any | any | unsupported |
| `record_size_limit` | TLS 1.3 | unsupported | unsupported |
| `records_per_traffic_key` | any | unsupported | unsupported |
| `key_update` | unsupported | unsupported | unsupported |
| `extended_master_secret` | `require`, `allow` | `allow`, `off` | `require`, `allow` |
| `encrypt_then_mac` | both | both | `false` only (no CBC) |
| `middlebox_compat` | both | both | `true` only |
| `mtu`, `initial_timeout_ms` | DTLS | DTLS | no DTLS |
| `srtp_profiles`, `expect_srtp_profile` | DTLS | DTLS | no DTLS |
| `min_key_update_interval_ms` | any | `0` only | `0` only |
| `psk_secret`, `psk_identity` | both | both | no external PSK |
| `client_cert` | all four | all four | all four |
| `renegotiate_after_handshake` | client | client | unsupported |
| `half_rtt_data` | TLS 1.3 server | unsupported | unsupported |

**Encrypt-then-MAC (RFC 7366).** plzn's TLS 1.0-1.2 client offers the extension only
when a test adds it (`+ext encrypt_then_mac`) and switches its record layer to
encrypt-then-MAC when a server echoes it on a CBC suite; plzn's TLS 1.0-1.2 server
echoes it whenever the client offered it and a CBC suite was selected (override
with `send ServerHello { +ext encrypt_then_mac }` / `-ext encrypt_then_mac`). The
server also honours `peer.capabilities` suite tokens now, so `uut client { versions: [tls12] }; peer { capabilities: [ecdhe_rsa, cbc] }` in
`uut client` mode is a CBC server. `recv ClientHello { lacks_ext: 0xNNNN }`
asserts a client did NOT send an extension (e.g. under `uut client { encrypt_then_mac:
false }`). ClientHello byte mutations are applied after the PSK binder is
patched in, so `send ClientHello @ xor[-1] = 0x01` corrupts the binder.

The same refusal covers what plzn OFFERS: the shim config carries the suites
and groups the `peer.capabilities` selectors produce (`requires`), and a shim whose library has
none of them refuses the case -- `uut client|server { versions: [tls12] }; peer { capabilities: [cbc] }`, `uut client|server { versions: [tls12] }; peer { capabilities: [rsa] }`,
`uut client|server { versions: [tls13] }; peer { capabilities: [secp521r1] }` and `ffdhe*` groups, a `renegotiate` step, an external
`psk`, or DTLS on rustls all SKIP there with the reason, per matrix point, and
without a `skip` line in the test. Explicit `skip <backend>` remains available
for a capability or harness gap the shim cannot infer. Known incorrect behavior
uses an `xfail` annotation instead:

```
xfail rustls "does not enforce the 2^14-byte plaintext record limit"
```

Actual expected failures are also listed after the summary under
`--- xfailed on <backend> (N) ---`.

Every skipped case is listed with its reason after the summary line:

```
--- skipped on rustls (2) ---
    server/tls12-ems-off-server — rustls cannot apply uut.extended_master_secret: rustls always offers extended_master_secret; only require/allow
    server/tls12-etm-off-server — rustls cannot apply peer.capabilities: rustls (ring) has none of the offered cipher suites [0xc013]
    server/tls13-record-overflow — does not enforce the 2^14-byte plaintext record limit
```

An `expect ok` flow that never sends plzn's own Finished (`flow handshake after
recv ServerHelloDone { close }`, a ROBOT timing probe that stops after
ClientKeyExchange) abandons the handshake on purpose. The shim is told so
(`handshake_abandoned`) and accepts whatever its library makes of the abrupt
close, so such a case runs on every backend instead of only on the one whose
shim happened to report success. And a per-backend `expect ... if <backend>`
override now reaches the shim's self-check too: `expect ok if botan` on a test
the others reject, or `expect alert fatal/decode_error if botan` on one the
others accept, is consistent on both sides of the wire.


### Certificate chains

plzn's client-authentication validator is a restricted fixture validator, not
a general-purpose PKIX verifier. It checks path signatures, validity, CA and
path-length constraints, key usage and client-auth EKU. Unknown critical
extensions and unsupported name/policy constraints are rejected, not ignored.
Certificate PSS signatures require SHA-256/384/512, matching MGF1 hash,
digest-length salt and the standard trailer. Other PSS profiles are refused.
Identity matching, revocation and general name/policy-constraint evaluation are
outside this profile. TLS 1.3 CertificateVerify separately enforces its stricter
signature-scheme/key rules and the schemes requested for client authentication.

Two header lines name the certificates a test runs with, so a baseline test
need not care which signature algorithm happens to be in use and a test that
does care says so:

```
chain: [ecdsa_p256]              # the SERVER's chain(s): the shim server's in `uut server`,
                                 # plzn's server's in `uut client`
client_chain: [ecdsa_p256, rsa]  # the client-authentication credentials, in preference order:
                                 # plzn's client's in `uut server`, the shim client's in `uut client`
```

Names: `default` (plzn's explicit run-specific `--cert` choice, P-256 today), `rsa_2048`
(alias `rsa`), `rsa_pss` (an id-RSASSA-PSS key), `ecdsa_p256`, `ecdsa_p384`,
`ecdsa_p521`, `ed25519`. `[]` is no chain at all (PSK, anon, negatives).
`chain:` is mandatory; neither omission nor a `peer.capabilities` key-exchange token chooses
a certificate implicitly. A test that pins a specific chain, even today's
default P-256, names it directly; `[default]` deliberately opts into the
run-specific choice.
`client_chain: [default]` is always the P-256 `client_ee` credential.

Rule of thumb for writing a test: always write `chain:`. Name a concrete chain
when the test is ABOUT the certificate -- RSA signature schemes, an RSA-only
signature_algorithms offer, static RSA, a CertificateVerify probe, a suite
sweep that lists RSA-authenticated suites; everything else takes the default
and the `ecdhe` capability, so the corpus does not pay for RSA signatures it never
checks; use `[default]` only when the choice is deliberately immaterial.
`recv Certificate { leaf_key: ecdsa_p384 }` asserts which chain a
peer holding several presented (TLS 1.2 semantics let an ECDSA key sign any
hash, so the ServerKeyExchange / CertificateVerify scheme alone does not
identify the curve).

Lint rejects a list that cannot serve a kex capability (`rsa` with
`chain: [ecdsa_p256]`, `ecdhe_ecdsa` with `chain: [rsa_pss]`) and an
empty list on a certificate handshake (`chain: []` needs a `psk { }` block, a
PSK kex capability, or a non-`ok` expectation). `ecdhe` is ECDHE under
whatever the chain signs with: ECDHE_RSA suites for an RSA chain, ECDHE_ECDSA
for an ECDSA or Ed25519 chain, both families when several chains are named,
so a legacy-TLS baseline test can stop naming RSA. Every chain is generated (or
loaded from `shims/testdata`) once per run on first use.

**Several chains.** plzn's own SERVER picks per handshake. TLS 1.0-1.2: the
client's suite order, then the configured chain order, the first chain that
can authenticate the suite's family (an rsaEncryption key the RSA families,
static RSA included; an RSA-PSS key ECDHE_RSA / DHE_RSA only; an ECDSA or
Ed25519 key ECDHE_ECDSA, RFC 8422 5.1.3) and, for a signed key exchange, sign
with a scheme in the client's signature_algorithms (RFC 5246 7.4.1.4.1; a
client that listed none gets the key's default). TLS 1.3: the first chain
with a CertificateVerify scheme the client listed (RFC 8446 4.4.2.2). With
nothing fitting, the first chain is kept and the handshake fails as a
single-chain server's would (handshake_failure at suite selection, a
CertificateVerify the client cannot take). The intermediates of
`extra_chain_der` belong to the first chain only. plzn's own CLIENT picks on
the CertificateRequest, when `client_chain:` names two or more: legacy TLS the
first credential whose ClientCertificateType the request lists and that can
sign with a scheme it listed (RFC 5246 7.4.4 / 7.4.6; an empty scheme list
accepts any), TLS 1.3 the first with a scheme in its signature_algorithms
(RFC 8446 4.4.2); none fitting sends an empty Certificate. A single
credential is presented as configured, so a mismatch stays testable; `send
Certificate { credential: ... }` and `certificate_list:` still override the
choice, and `credential: valid` is the first `client_chain:` entry. The shim
side gets every chain too (`credentials.chains`, `credentials.client_chains`
and `requires.server_keys` in the shim config, see shims/DESIGN.md). Botan,
OpenSSL, rustls and Go select among them; GnuTLS selects multiple server chains
but reports multi-chain client selection unsupported until its retrieval
callback is wired. wolfSSL and BoringSSL report all multi-chain configurations
unsupported. `uut client { client_cert: ... }` still overrides the shim
client's credential outright.

Cases: `suite/server/tls13_chain_ecdsa`, `tls12_ecdhe_follows_chain`,
`tls12_psk_no_chain`, `tls12_client_chain_selection`,
`suite/client/tls13_server_chain_selection`,
`tls12_server_chain_selection`.

### Sessions and resumption

Session names must be unique, and `resumes:` must name an earlier session.
Top-level flow/expect/assert blocks cannot be mixed with session-local blocks.
Failure to capture the required session state is an error, never an implicit
fresh handshake. Go's stateful TLS 1.2 session-ID resumption is reported as
unsupported; its ticket resumption remains supported.

With `dial --pcap`, multi-session captures use `stem-<test-id-hash>.pcap`
(preserving the supplied extension), one distinct file per session/repetition.

```
plzn tls "usage/tls13-resume" {
  rfc 8446 section 4.6.1
  chain: [default]
  uut server {
    versions: [tls13]
  }

  session initial {
    flow handshake {
      send AppData
      recv AppData
    }
    expect ok
  }

  session resumed [resumes: initial] {
    flow handshake {
      send AppData
      recv AppData
    }
    expect ok
  }
}
```

Two connections to the same server. The first captures the server's
NewSessionTicket; the second runs the abbreviated preset (PSK for TLS 1.3, no
Certificate or ServerKeyExchange for TLS 1.2), so it passes only if the server
genuinely resumed.

`session` tests run through `plzn run --shim` and `plzn dial --addr` alike. With
a shim, plzn spawns ONE shim process for the whole test (its `resume_count` is
the session count minus one), runs the sessions in order over successive
connections, carries the ticket / PSK between them, and prints one PASS/FAIL
line per session; the shim's own verdict is charged to the last session, and
when the sessions' expectations differ the shim self-check runs in accept-any
mode. A per-session `expect <kind> if <backend>` override works inside a
`session` block too.

A session may select one of the versions enabled by the test-level UUT block:
`session initial [version: tls12]` or `session resumed [resumes: initial,
version: tls13]`. This changes the protocol plzn drives on that connection; the
shim keeps one process and one session cache for the whole sequence, while a
shim client is pinned to that connection's selected version. Captured state is
tagged with its protocol and version, so plzn never accidentally uses a TLS 1.2
ticket/master secret in a TLS 1.3 handshake (or vice versa).

`assert resumed == true|false` checks the actual abbreviated/full-handshake
outcome after a successful flow. For adversarial client tests,
`force_resume: true` may be added to a cross-version session that `resumes`
another session under `uut client`: plzn's server then falsely claims the old
state in the new version, allowing the test to require the client to abort.
This control is deliberately rejected for same-version sessions and for
`uut server` tests.

In `uut client` mode plzn is the server: `send NewSessionTicket` (after the
client's Finished) issues a ticket -- overrides `ticket_lifetime`,
`ticket_lifetime_days`, `ticket_age_add`, `ticket_nonce`, `ticket`; default
lifetime 7200 s -- and a session with `[resumes: ...]` runs the abbreviated PSK
server preset (ServerHello with pre_shared_key, no Certificate), accepting the
PSK only when the ticket is the one it issued, the hash matches and the binder
verifies. A session WITHOUT `resumes:` after one that issued a ticket makes the
server decline the offer (full handshake; the client must fall back). `send
ServerHello { psk_mode: psk_ke | psk_dhe_ke }` forces the mode regardless of
what the client offered (RFC 8446 4.2.9 negative). End the first connection
with `close alert warning/close_notify`: OpenSSL never resumes a session whose
connection it did not close cleanly. In `uut server` mode the `psk_ke` capability
makes the resuming plzn client offer psk_ke only (no key share).

TLS 1.3 0-RTT is an explicit resumed flow rather than part of the handshake
preset. A shim server advertises and accepts it with `uut server {
max_early_data: N }`; plzn then uses `send EarlyData { size: M }` immediately
after the resumed ClientHello. In the other direction, add `+ext early_data =
N` to the NewSessionTicket, `recv EarlyData`, and acknowledge acceptance with
`send EncryptedExtensions { +ext early_data }`. An EncryptedExtensions without
that extension rejects the early data while retaining PSK resumption. Accepted
data is followed by `send`/`recv EndOfEarlyData` before the client's Finished.
EarlyData payloads are raw reproducible random bytes, without the AppData shim
request header. OpenSSL, GnuTLS, and rustls implement both roles. wolfSSL does
so when built with `WOLFSSL_EARLY_DATA` and `HAVE_SESSION_TICKET`, and otherwise
returns a reasoned SKIP. Botan returns a reasoned SKIP because it has no 0-RTT
API.

For TLS 1.0 through TLS 1.2 (RFC 5077) plzn's server promises a ticket whenever the client
offers the SessionTicket extension and the session issues tickets (a session
another session `resumes`, or the `session_ticket` capability for every connection): the
ServerHello echoes an empty SessionTicket extension and a NewSessionTicket
goes out just before the server's ChangeCipherSpec, automatically, unless the
flow sends it explicitly -- `send NewSessionTicket { ticket_lifetime |
ticket_lifetime_days | ticket }`, e.g. `ticket: ""` for the zero-length ticket
a client must not present (RFC 5077 3.3). `send ServerHello { -ext
session_ticket }` withdraws the promise and no NewSessionTicket follows (a
NewSessionTicket sent anyway is the RFC 5077 3.3 negative the clients reject
with unexpected_message). A session with `[resumes: ...]` accepts only the
ticket it issued, under RFC 5077 3.3 / RFC 7627 5.3 / RFC 5246 7.4.1.2: the
abbreviated preset (ServerHello echoing the client's session_id, then CCS and
Finished before the client's) runs when it does, and a full handshake
otherwise -- an unknown, corrupt or empty ticket, a suite the client no longer
offers, or a legacy-master-secret session resumed by a client that now offers
extended_master_secret. A session that WAS extended-master-secret but is
resumed by a client without the extension is aborted (handshake_failure).
`send ServerHello { -ext extended_master_secret }` makes the first connection
a legacy-master-secret session. Anchor the resumed session's flow (`flow
handshake after recv Finished { ... }`) to force the abbreviated flight, so a
fallback to a full handshake fails the case; spell out the full flight to
assert a decline. The shims' own `expect.resumed` self-check cannot be armed
per session (one shim config serves every connection).

**Session-ID resumption (TLS 1.0 through TLS 1.2).** The `session_id` capability resumes without
tickets (RFC 5246 7.4.1.3): the initial session's ClientHello carries no
SessionTicket extension, so the shim server assigns a session_id and caches the
session (the shims keep one cache per process: Botan's hybrid manager, OpenSSL's
internal cache, rustls's memory cache); the `resumes:` session echoes that id
and, when the server echoes it back, runs the abbreviated flight. A server that
declines (a different server_name, a session whose suite the new offer lacks, a
dropped EMS) answers with a full handshake or an alert, and plzn's client follows
either: `recv ServerHello { resumed: false }` pins the fresh handshake. The
The behavior-oriented resumption cases `tls12_session_id_resumption`,
`tls12_resumption_with_wrong_ciphers`,
`tls12_invalid_server_name_extension_resumption` and
`tls12_extended_master_secret_extension_resumption` exercise it.

### External PSK

```
plzn tls "usage/tls13-psk-ke" {
  rfc 8446 section 4.2.9
  chain: []
  skip rustls
  uut server {
    versions: [tls13]
  }
  psk {
    identity: "Client_identity"
    secret: "6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
```

The same block configures the shim with the key. TLS 1.3 uses `psk_ke`
(no ECDHE); `uut client|server { versions: [dtls12] }` with a `psk` block runs a DTLS PSK suite.

For TLS 1.3 server tests, ordered `offer` blocks replace the peer's default
single ClientHello identity. Each carries the identity, secret used for its
binder, and an optional `hash: sha256` or `hash: sha384` (SHA-256 by default):

```
psk {
  identity: "known"
  secret: "000102030405060708090a0b0c0d0e0f"
  offer {
    identity: "decoy"
    secret: "101112131415161718191a1b1c1d1e1f"
  }
  offer {
    identity: "known"
    secret: "000102030405060708090a0b0c0d0e0f"
  }
}
```

The top-level identity and secret remain the PSK configured in the shim. This
allows tests to put unknown identities or invalid binders before and after it.
`recv ServerHello { selected_psk_identity: 1 }` checks the selected index;
the same field on `send ServerHello` can deliberately select an unoffered index.

With `uut client|server { versions: [tls12] }` the block switches both roles to the pre-shared-key
families: plzn's client offers, and plzn's server serves, the RFC 4279 plain
PSK suites (the server sends the optional psk_identity_hint ServerKeyExchange;
the client absorbs one if it arrives) and the RFC 5489 / RFC 8442 ECDHE_PSK
suites (an unsigned ServerECDHParams after the hint). `uut client|server { versions: [tls12] }; peer { capabilities: [psk] }` or
`uut client|server { versions: [tls12] }; peer { capabilities: [ecdhe_psk] }` narrows to one family; `matrix { suite in [...] }`
sweeps them one at a time from either side
(`suite/server/tls12_psk_sweep.plzn`, `suite/client/tls12_client_psk_sweep`).
plzn's server answers only the configured identity, and the client can present
another -- `send ClientKeyExchange { psk_identity: "other" }` -- for the
RFC 4279 2 unknown-identity negative (Botan and OpenSSL: unknown_psk_identity).
rustls has no external pre-shared keys (SKIP); DHE_PSK is not implemented.

In `uut client` mode plzn's TLS 1.3 server accepts the block's external
PSK too (the client's identity must match and its binder verify, RFC 8446
4.2.11), and the shim can be handed a DIFFERENT key or identity than the
block: `uut client { psk_secret: "0f0e0d0c" }` makes its binder fail (plzn answers
decrypt_error and the flow reports the rejection; TLS 1.2 and DTLS servers
fail the client's Finished instead), `uut client { psk_identity: "other" }` offers
an identity plzn declines, so the TLS 1.3 handshake falls back to
certificates (`suite/client/tls13_client_psk_unknown_identity.plzn`). Tests of
plzn's own PSK rejection paths live under `tests/cases/local_rejections/`
in `tls/psk/` and `dtls/psk/`.

### Timing probe: `wait`

```
plzn tls "usage/robot-oracle-probe" {
  rfc 5246 section 7.4.7.1
  chain: [rsa_2048]
  skip rustls
  skip openssl
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [rsa] }
  flow handshake after send ClientKeyExchange {
    wait 200 ms
  }
  expect ok
}
```

`wait N ms` sleeps, then probes the socket. Silence passes; anything the peer
sent fails the step and is reported. Here the static-RSA ClientKeyExchange has
been sent and a server that answered before Finished would be a Bleichenbacher
oracle. (OpenSSL's shim reports the abandoned handshake as its own failure, so
that backend is skipped; the ROBOT corpus files carry the full rationale.)

### Anchored presets

```
flow handshake until send Finished { ... }      # preset stops BEFORE sending Finished
flow handshake after recv ServerHelloDone { ... } # preset runs THROUGH ServerHelloDone
flow { ... }                                      # no preset: every step is explicit
```

Inside an anchored flow the remaining messages are sent or received one step at
a time, so each can carry overrides, mutations, or be omitted or repeated.

## Testing a client (`uut client`)

plzn plays the TLS server; the shim plays the client. Same CLI, same DSL.

```
plzn tls "usage/client-tls13-roundtrip" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello {
      legacy_version: 0x0303
      compression_methods: [0x00]
      cipher_suites: [AES_128_GCM_SHA256]
    }
    send AppData
    recv AppData
  }
  expect ok
}
```

- **`peer.capabilities` is the server's capability set.** `uut client { versions: [tls13] }` negotiates any
  implemented suite (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) and group
  (x25519, x448, secp256r1, secp384r1), picking from the client's offer.
  `uut client { versions: [tls13] }; peer { capabilities: [aes256_gcm_sha384] }` is willing to do only that suite;
  `uut client { versions: [tls13] }; peer { capabilities: [secp256r1] }` only that group. If the client key-shared only X25519,
  plzn sends a HelloRetryRequest and completes on the retry. If nothing in the
  offer is implementable (`uut client { versions: [tls13] }; peer { capabilities: [brainpoolP512r1tls13] }`) the case is **SKIPPED**.
- **`recv ClientHello { ... }` matchers** assert what the client sent:
  `legacy_version`, `random`, `legacy_session_id`, `compression_methods`
  (exact), `cipher_suites`, `supported_groups`, `signature_algorithms`
  (contains-all; names or wire values), `has_ext: 0xNNNN`, `lacks_ext`.
- **TLS 1.2 negotiation** in plzn's server follows the client's offer: the
  ECDHE curve comes from the client's supported_groups against the server's
  set (`peer.capabilities` group tokens; default x25519, secp256r1, secp384r1, secp521r1;
  `ffdhe2048` / `ffdhe3072` pick the DHE_RSA group), the signature scheme
  from the client's signature_algorithms against the certificate key (RSA:
  RSA-PSS and PKCS#1 v1.5 under SHA-256/384/512; an id-RSASSA-PSS key
  rsa_pss_pss_* only; ECDSA P-256 / P-384 / P-521; Ed25519 with an
  `ed25519` chain), in the client's order -- and, with several chains, the
  chain itself (see "Certificate chains"); signature-scheme
  `peer.capabilities` tokens restrict what it signs with. `send ServerKeyExchange {
  named_group: secp256r1, signature_scheme: rsa_pkcs1_sha256 }` forces a
  choice the client did not offer (the RFC 8422 5.4 / RFC 5246 7.4.3
  negatives), and `send ServerKeyExchange { key_share_point: zero | truncated
  | padded | compressed }` corrupts the server's ECDHE point while keeping the
  real ephemeral for the agreement, so the client must reject a bad point
  (RFC 8422 5.11; parity with plzn's DTLS server). For DHE_RSA, `dh_p`, `dh_g`
  and `dh_Ys` replace the explicit finite-field parameters before plzn signs
  them; compact `zero`, `one`, `two`, `p_minus_1`, `p`, `p_plus_1` and
  `small_order` recipes are available for `dh_g` and `dh_Ys`, and `dh_p:
  rfc5114_2048_256` names RFC 5114's non-safe 2048-bit prime. `send Certificate {
  entries: 0 }` sends an empty certificate_list; `send ServerHelloDone @ pad
  +1` a non-empty ServerHelloDone. A `psk { }` block turns the server into an
  RFC 4279 PSK / RFC 5489 ECDHE_PSK server (see "External PSK").
- The **`hrr` peer capability** expands `flow handshake` into explicit CH, HRR, CH, SH, ...
  steps so the retry flight is addressable; **`second_hrr`** sends a second
  HelloRetryRequest (the client must abort). The HelloRetryRequest requests the
  first selectable group the client listed but did not key-share (RFC 8446
  4.2.8); when the client key-shared every selectable group, the request names
  the shared group anyway, which a conforming client rejects with
  illegal_parameter. LibreSSL's client key-shares its first two groups, so
  cases that pin plzn to `secp256r1` list it third (`curves: [x25519,
  secp384r1, secp256r1]`) to keep the retry legitimate.
- **`peer { request_client_cert: true }`** makes plzn's server send a CertificateRequest;
  the shim client is given the test client certificate, so the handshake
  completes. plzn's TLS 1.2, TLS 1.3, and DTLS 1.2 servers verify the chain against the
  `shims/testdata` client anchors (`src/tls/client_auth.rs`: issuer links,
  signatures, basicConstraints, validity), not just the CertificateVerify
  signature; `uut client { client_cert: untrusted | expired }` hands the shim
  client a credential plzn rejects with unknown_ca / certificate_expired.
  plzn sends the alert and the flow reports the rejection, so these
  self-tests use `expect reject fatal/...` and live under
  `tests/cases/local_rejections/{tls,dtls}/client_auth/`. With `client_cert: none`,
  plzn accepts the empty Certificate and continues without CertificateVerify.
  The `client_auth_no_cert` cases assert `recv Certificate { entries: 0 }`,
  complete the handshake, and exchange application data. `send
  CertificateRequest { -ext signature_algorithms }` and
  `send Certificate { +ext ... }` (an extension on the leaf entry) drive the
  RFC 8446 4.3.2 / 4.4.2 client-side negatives. In TLS 1.2 the request lists
  rsa_sign + ecdsa_sign and the schemes plzn verifies (or the `peer.capabilities`
  signature-scheme tokens), and plzn verifies the client's CertificateVerify
  over the handshake transcript; `send CertificateRequest {
  certificate_types: [], signature_algorithms: [] }` drive the RFC 5246 7.4.4
  bounds negatives, `certificate_types: [1]` the type-mismatch probe.
- **`renegotiate`** in client mode sends a HelloRequest and runs the server side
  of the second handshake (TLS 1.2 and DTLS 1.2).

Adversarial ServerHello overrides force values negotiation would never produce:

```
plzn tls "usage/client-tls12-bogus-cipher" {
  rfc 5246 section 7.4.1.3
  chain: [default]
  uut client {
    versions: [tls12]
  }
  flow handshake {
    send ServerHello { cipher_suite: 0xfe00 }
  }
  expect alert fatal/handshake_failure
  expect alert fatal/illegal_parameter if openssl
  expect reset if rustls
}
```

`send ServerHello { key_share_group: 0x0017 }` names a group the client did
not key-share; `send HelloRetryRequest { key_share_group: 0x001d }` retries
onto a group the client already shared. Server-flight messages accept
mutations too, for example the wrong-message-type family:

```
plzn tls "usage/client-tls13-wrong-finished-type" {
  rfc 8446 section 4.4.4
  chain: [default]
  uut client {
    versions: [tls13]
  }
  matrix {
    mtype in [0x01, 0x02, 0x0b, 0xff]
  }
  flow handshake {
    send Finished @ set[handshake.msg_type, 0] = $mtype
  }
  expect handshake-fails
}
```

`uut` applies to the client too. The downgrade-sentinel test raises the client's
maximum to TLS 1.3 while plzn negotiates 1.2 and stamps `DOWNGRD\x01` into
ServerHello.random (see `suite/client/downgrade_sentinel_tls12.plzn`).

## DTLS 1.3

`uut client|server { versions: [dtls13] }` runs the TLS 1.3 state machines over
DTLS handshake framing and the RFC 9147 record layer. BoringSSL is the current
oracle and is exercised in both directions:

```bash
make -C shims boringssl PLZN_BORINGSSL_ROOT=/path/to/boringssl
plzn run --shim shims/build/boringssl_shim suite/dtls/dtls13_*.plzn
```

The implemented surface includes all three TLS 1.3 AEAD suites, X25519,
P-256/P-384 and X25519MLKEM768, HRR, RSA-PSS and ECDSA signatures, client
authentication, adversarial handshake fragmentation/reassembly, both unified
record-number widths and lengthless headers, replay-window mappings, explicit
and selective ACKs, partial-flight/delayed-ACK handling, virtual retransmission
timers, live MTU changes, previous-epoch injection and retransmission, session
resumption, and malformed-record discard. DTLS 1.3 0-RTT/epoch 1,
negotiated connection IDs, RFC 9258 imported-PSK credentials, and the remaining
exhaustive loss/partial-ACK permutations remain open.

## DTLS 1.2

`uut client|server { versions: [dtls12] }` routes the test to the datagram record layer and the DTLS drivers
(both roles). Botan, OpenSSL, and LibreSSL run the full DTLS corpus; GnuTLS can run the
baseline cases that do not require virtual timer/control frames. Every case in
`suite/dtls` explicitly selects its chain; RSA, ECDSA P-256/P-384, and Ed25519
coverage therefore lives together and is identified by the filename:

```bash
plzn run --shim shims/build/openssl_shim suite/dtls
plzn run --shim shims/build/gnutls_shim suite/dtls/dtls12_replay.plzn
```

**Cipher suites over DTLS.** The DTLS drivers read the same suite table as the
TLS ones (`ir::ALL_SUITES`) and run the same record-protection code, fed
`epoch||sequence` and the DTLS wire version instead of the TLS counter and
0x0303. The default DTLS offer follows Botan's rule for datagram versions
(`ir::SuiteInfo::dtls_default`): AEAD suites with a full tag (AES-GCM, AES-CCM,
ARIA-GCM, Camellia-GCM, ChaCha20-Poly1305) and the NULL suites; no
CBC-with-HMAC (a residual Lucky13 channel that DTLS's repeated observations
amplify) and no CCM_8 (a 64-bit tag DTLS lets an attacker brute-force without
a teardown). Naming an excluded suite explicitly -- `suite in [0xc009]` or a
cipher token such as `cbc` -- lets it through as a probe of what the library
does with it; both libraries turn out to run CBC, encrypt-then-MAC CBC and
CCM_8 over DTLS when a client insists. A `psk { }` block switches the offer to
the PSK families under the same rule: RFC 4279 plain PSK (`0x00a8`, `0xccab`,
`0xc0a4`, `0x002c`, ...) and RFC 5489 / RFC 8442 ECDHE_PSK (`0xd001`,
`0xd002`, `0xccac`, `0xd005`, `0xc039`-`0xc03b`; no CBC, no CCM_8), narrowed
to one family by the `psk` / `ecdhe_psk` capabilities.
Both DTLS roles run the certificate families' three key exchanges -- ECDHE,
finite-field DHE (explicit ffdhe2048 `ServerDHParams`, RFC 5246 7.4.3) and
static RSA (RFC 5246 7.4.7.1, with the DTLS client_version in the premaster,
RFC 6347 4.1) -- and both PSK families (RFC 4279 / RFC 5489: the `psk { }`
block is the client's offer in `uut server` and the server's
identity/secret in `uut client`; ECDHE_PSK mixes the ephemeral ECDH
secret into the premaster, RFC 5489 3.4, on the group negotiated from
supported_groups, and the hint-only ServerKeyExchange of plain PSK is sent
by plzn's server only when `send ServerKeyExchange { psk_identity_hint }`
asks for it). The DTLS client sends server_name like the TLS 1.2 client
(`-ext server_name` removes it, `+ext server_name = "..."` renames it).
ALPN and DTLS-SRTP are driven in both roles: `uut client|server { alpn_advertise,
alpn_select, alpn_select_from, expect_alpn }` configures and checks the UUT API while `+ext alpn`
sets the wire value; `uut client|server { srtp_profiles, expect_srtp_profile }` and `+ext
use_srtp` do the same for RFC 5764.
`suite/dtls/dtls12_{,client_}suite_sweep_rsa.plzn` sweeps the RSA-authenticated suites of all
three exchanges from both sides. `uut client|server { cipher_suites: [$suite] }` takes a
matrix variable, which is
how the client-side sweeps pin the shim's client to each point. A record with
a bad tag or MAC is silently discarded over DTLS (RFC 6347 4.1.2.7): `send
AppData @ xor[record.aead_tag, 0] = 0x01` followed by a clean request
shows the peer ignoring the first and answering the second (`record.mac` for
the NULL and CBC families). `dtls12_stray_records_to_{server,client}.plzn`
widen this to a header that lies about its epoch, sequence number, or version
(`@ set[record.epoch, 1] = 0x05`), a datagram shorter than a record header, a
record whose length exceeds its datagram, and a stray datagram injected during
the handshake, in both roles: each stray is its own datagram, and the case
proves the association survives with a following application-data round trip
and a silent `wait`. `dtls12_replay_window.plzn` adds
`assert app_data_records == N` so a replayed request datagram is proven dropped
rather than answered twice.

```
plzn tls "usage/dtls12-replay-final-flight" {
  rfc 6347 section 4.1.2.6
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after send Finished {
    resend_flight
    recv ChangeCipherSpec
    recv Finished
  }
  expect ok
  assert no_duplicate_record_seqnums
}
```

**Negotiation, client authentication, overrides.** The DTLS client offers the
`peer.capabilities` group tokens as its supported_groups (default `secp256r1, x25519`, like
the TLS 1.2 client) and every signature scheme it verifies, completes the
ECDHE on whichever offered group the server picks (a group it did not offer
fails the step) and verifies the ServerKeyExchange with TLS 1.2 semantics: a
scheme names a hash and an algorithm, so a P-256 certificate signed under
`ecdsa_secp521r1_sha512` is ECDSA over SHA-512, which is what both libraries
send when that is the best scheme listed. The DTLS server picks the first
group of the client's list that `peer.capabilities` allows (all of x25519, secp256r1/384/521
by default) and a scheme from the client's signature_algorithms its key can
produce (RSA: PSS 256/384/512 then PKCS#1 256/384; ECDSA P-256 / P-384 /
P-521; Ed25519 -- `chain: [ecdsa_p384]`, `ecdsa_p521`, `ed25519`, or
`rsa_pss`). Client authentication is owned by the server: with `uut server`,
`uut server { require_client_cert: true }` makes the shim server request the certificate
and plzn's client answers with `shims/testdata/client_ee_cert.der`; with
`uut client`, `peer { request_client_cert: true }` makes plzn's server
request and receive the shim client's Certificate, verifying a non-empty chain
or continuing unauthenticated after an empty one. Both roles
take the TLS 1.2 field overrides -- `send ClientHello { legacy_version,
random, legacy_session_id, cipher_suites, compression_methods, cookie }`,
`send HelloVerifyRequest { legacy_version, cookie, cookie_len }` (server role;
valid cookies may be 0..255 bytes), `send ServerHello { ... }`, `send
ClientKeyExchange { key_share_point, ecdh_Yc,
dh_Yc, encrypted_premaster, premaster_secret, psk_identity }`, `send
ServerKeyExchange { named_group, signature_scheme, dh_p_bits,
psk_identity_hint, key_share_point }` (the server's ECDHE point corrupted the
way the client's can be -- `zero`, `truncated`, `padded`, `compressed` -- in
the certificate and ECDHE_PSK families), `send Certificate {
certificate_list: [], entries: N }` (either role), `send CertificateRequest {
certificate_types, signature_algorithms }` (server role; `[]` is the RFC 5246
7.4.4 bounds negative), `send Finished { verify_data }` (either role), a
mutation on `CertificateVerify` -- so the unoffered-group / unoffered-scheme,
bad-point, empty-certificate, unknown-identity and wrong-Finished negatives
run over DTLS from either side. Structured mutation paths resolve on every
DTLS message both roles send -- the hellos (`handshake.random`,
`handshake.cookie`, `handshake.cipher_suites`, ...), `Certificate`
(`handshake.certificate_list`), the key exchanges (`handshake.ecdh_point`,
`handshake.ecdh_Yc`, `handshake.dh_Ys`, `handshake.psk_identity`, ...),
`CertificateVerify` (`handshake.signature`), `CertificateRequest` and
`Finished`; `schema::handshake_byte_fields` lists each message's fields and a
`handshake.<field>` the message does not map is a lint error (`msg_type` /
`length` apply to any handshake message). `close alert
warning/close_notify` (any level/code) ends the association with that alert
from either role.

**Session resumption.** `session` blocks work under `uut client|server { versions: [dtls12] }` in both roles
with RFC 5077 tickets, exactly like TLS 1.2: the initial session offers (or,
as server, promises and issues) a ticket, and a session that `resumes` it runs
the abbreviated flight -- the cookie exchange, ServerHello,
[NewSessionTicket], CCS, Finished from the server, then the client's CCS and
Finished (`ir::DTLS12_RESUMED_CLIENT_PRESET` / `_SERVER_PRESET`). plzn's DTLS
server applies its TLS 1.2 server's `decide_resumption` rules (only the ticket
it issued, RFC 7627 5.3 / RFC 5246 7.4.1.2) and takes `send NewSessionTicket {
ticket_lifetime, ticket_lifetime_days, ticket }`; the client absorbs an optional
renewal ticket on its ChangeCipherSpec step (`recv NewSessionTicket` for an
explicit flow). Anchor the resumed flow at `recv Finished` to drive the final
flight by hand: Botan's two resumed-flight scenarios are
`dtls12_resumed_final_flight_retransmit` (`hold_flight`, `advance_clock`,
`expect_retransmit`, `retransmit_flight`, `release_flight`: the server must
accept the retransmitted final flight and tolerate the delayed original
Finished) and `dtls12_resumed_flight_with_app_data` (`send AppData` right after
`send Finished` puts CCS, Finished and the data in one datagram). The shims
resume DTLS inside their multi-session loop, so no knob is needed.

Cross-version DTLS sequences use the same per-session `version: dtls12|dtls13`,
`assert resumed`, and adversarial `force_resume` controls described above.
Only BoringSSL currently runs the DTLS 1.3 half; the other shims report the
mixed-version tests unsupported before connecting.

DTLS-only steps:

Matchers are enforced over DTLS on every message the drivers parse: `recv
ServerHello`, `recv HelloVerifyRequest { legacy_version, cookie_len, cookie }`, `recv
Certificate { entries }`, `recv ServerKeyExchange { named_group /
named_group, signature_scheme, psk_identity_hint }`, `recv CertificateRequest
{ has_sigalg, has_cert_type }`
(uut server) and `recv ClientHello { cookie, cookie_len, server_name,
has_ext, ... }` (`uut client`); matchers on other DTLS messages are a lint error rather than silently
ignored.

| Step | Effect |
|------|--------|
| `advance_clock 1s` (also `ns`, `us`, `ms`) | advance the shim's virtual retransmit clock and wait until timeout handling completes; emitted datagrams are buffered for the next receive step |
| `expect next_timeout 1s` | require the UUT's currently reported remaining retransmission timeout to equal the duration exactly |
| `expect no_timeout` | require that the UUT has no retransmission timer armed |
| `set_timeout 250ms` | rescale the UUT's live timeout schedule, preserving the current backoff level; OpenSSL and BoringSSL (Botan has no live setter API and SKIPs) |
| `set_mtu 512` | DTLS 1.3: change the UUT's live path MTU before a retransmission |
| `expect_retransmit` | read one datagram and require the peer's resent flight |
| `suppress_ack` | DTLS 1.3: stop plzn's automatic ACKs and capture the received flight's record numbers for explicit ACK tests |
| `send_ack all \| first \| last \| even \| odd` | DTLS 1.3: ACK the selected captured records; optional `outer_epoch N` and `overflow_epoch` encode bad-epoch negatives |
| `expect_ack` | DTLS 1.3: read, authenticate, and require one ACK record |
| `send_previous_epoch Finished` | DTLS 1.3: send a fresh message_seq copy of the prior Finished under the retained previous write epoch |
| `retransmit_previous_epoch Finished` | DTLS 1.3: retransmit the prior Finished with its original message_seq, a fresh record number, and the retained previous write epoch |
| `resend_flight` | flush the buffered flight, then resend the identical datagram (same sequence numbers) |
| `recv Alert` (`uut client`) | read the client's next datagram and report the alert it carries (a malformed HelloVerifyRequest sent with `send raw`, say); anything else fails the step |
| `send ClientHello @ reorder 16` | split into 16-byte handshake fragments sent in reverse order (both roles) |
| `send ClientHello @ fragment 16` | split into 16-byte handshake fragments in offset order; a conforming peer MUST reassemble (both roles) |
| `send ClientHello @ duplicate_fragment 16` | fragment, then send each fragment twice (harmless exact retransmits) |
| `send ClientHello @ reorder_overlap 16` | matching overlapping fragments and exact duplicates in reverse order (valid reassembly input) |
| `send ClientHello @ complete_and_fragments 16` | smaller fragments plus a redundant complete fragment for the same message_seq |
| `send ClientHello @ empty_fragments` | legal zero-length fragments at offsets zero and total_length around the complete fragment |
| `send ClientHello @ split_fragment_record 12` | split one encoded fragment across records (malformed; the peer must reject) |
| `send ClientHello @ overlap_mismatch 16` | fragment, then re-send the first fragment with one byte flipped before completion (overlapping bytes that disagree; the peer MUST reject) |
| `send ClientHello @ type_mismatch 16` | fragments at one message_seq disagree on handshake type (the peer MUST reject) |
| `send ClientHello @ offset_overflow` | one fragment whose fragment_offset + fragment_length runs past the declared length (the peer MUST reject) |
| `send ClientHello @ length_mismatch 16` | fragment; a later fragment for the same message_seq advertises a different total length (inconsistent metadata; the peer MUST reject) |
| `send ClientHello @ fragment_length_mismatch 16` | fragment_length claims one more byte than the record carries (the peer MUST reject) |
| `future_seq_first` | reverse the pending flight's records so higher message_seqs arrive first; the peer must buffer until the gap fills (both roles; a no-op on a one-message flight) |
| `header_only_flood 8` | send N header-only handshake records at far-future message_seqs, then the real flight; the peer's reassembler must bound the pending claims (both roles) |
| `large_length_fragment 16777215` | send one far-future-message_seq handshake fragment whose 24-bit total-length field claims N bytes while it carries a single byte at offset 0; the peer must bound the buffer a single claim may reserve from the announced length, not pre-allocate it (both roles) |
| `interleave_flight` / `interleave_flight split` | after fragmenting two consecutive messages (`send Certificate @ fragment 64`, `send ClientKeyExchange @ fragment 16`), round-robin the pending flight's records so the messages' fragments alternate on the wire (A0 B0 A1 B1 ...) within one datagram; `split` sends each interleaved record as its own datagram so the interleaving crosses datagram boundaries (both roles; the peer MUST reassemble by message_seq + fragment_offset, RFC 6347 4.2.3) |
| `assert no_duplicate_record_seqnums` | post-trace: the peer never reused an (epoch, seq) pair |
| `assert max_datagram_size 256` | post-trace: every datagram the UUT emitted was at most N bytes |
| `expect_retransmit no_ccs` | as `expect_retransmit`, and the resent flight must carry no ChangeCipherSpec (a renegotiation ClientHello retransmit) |
| `discard_flight` | flush our pending flight, then read and drop everything the peer has in flight until it falls silent (simulated loss) |
| `retransmit_flight` | re-send the last flight's records under FRESH record sequence numbers, as a real retransmission timer would (`resend_flight` replays the identical datagram) |
| `retransmit_flight split [0, 2, 1]` | the same, one datagram per listed record in that order; the peer must stay silent until the last one |
| `hold_flight` | set the pending flight aside instead of flushing it (a delayed datagram) |
| `hold_retransmit` | set a fresh-sequence retransmission of the last flight aside |
| `release_flight` / `release_flight [1]` | send the held datagram, or only its listed records; an indexed release retains the unselected records for a later `release_flight` (whose indices refer to the smaller held set) |
| `replay_flight 2` | send the Nth flushed datagram (1-based) again, byte-identical |
| `map_record_sequences identity` / `multiply N` / `xor N` | map subsequently allocated outbound record sequence numbers before sealing; use `multiply 1023` for large replay-window gaps or `xor 255` for backwards groups with forward jumps |
| `send HelloRequest` (server role) | open a stepped renegotiation; a second one while it is pending is a crossed request |
| `recv ClientHello` after the initial Finished (server role) | take a client-initiated renegotiation (`uut client { renegotiate_after_handshake }`): spell out the second handshake, `send HelloVerifyRequest` first for a cookie exchange on it, or refuse it with `send alert warning/no_renegotiation` and carry on at epoch 1; a renegotiation ClientHello that arrives during `recv AppData` is accepted on its own, and application data crossing it under the old keys is delivered by the next read |
| `begin_renegotiation` (client role) | reset to a renegotiation handshake, then drive it with explicit `send`/`recv` steps |
| `restart` (client role) | forget the association and start a fresh one at epoch 0 on the same 5-tuple (RFC 6347 4.2.8) |
| `hvr_flood 24 max_answers 4` (server role) | send N HelloVerifyRequests with distinct cookies; the client may answer at most M |
| `rotate_cookie_secret` (server role) | tell the shim server to rotate its DTLS cookie secret (a runtime control frame); a cookie it issued earlier stops verifying, so the client must answer a fresh HelloVerifyRequest (RFC 6347 4.2.1) |
| `send alert warning/no_renegotiation` | an alert record under the current keys, without closing (both roles, TLS and DTLS) |

`wait` on the DTLS server side fails on any datagram except a close_notify
warning (a clean close in progress); a peer that closes the connection during a
`wait` is reported as a clean close (`expect close`), unless plzn itself sent
close_notify first. `send AppData` / `recv AppData` use the same random-data
request/response protocol in both DTLS roles.

A flow that uses timer controls sets `requires.virtual_clock`. Both shims
honour it: Botan runs its DTLS timer on the shim's monotonic clock and exposes
`Channel::next_retransmission_timeout`; the OpenSSL shim freezes
`gettimeofday`, drives OpenSSL's timer from acknowledged `T` frames through
`DTLS_set_timer_cb`, and normalizes OpenSSL's 15 ms early-expiry window to the
semantic timer reported by `expect next_timeout`. Terminal budget exhaustion
is a structured `timeout` outcome, not an ambiguous EOF. `set_timeout` also
sets `requires.dynamic_timeout`: OpenSSL emulates BoringSSL's live rescaling,
while Botan refuses the case as unsupported because its public API has no live
setter. A few retransmission cases still `skip openssl` for a genuine
behavioural difference, not the clock: OpenSSL re-sends its flight only when its
own timer fires, not on receiving a duplicate ClientHello (`dtls12/lost-server-flight`);
it answers a partial retransmitted flight at once
(`dtls12/reordered-retransmitted-final-flight`); a timed-out renegotiation is
fatal to the whole connection rather than leaving the association up
(`dtls12/client-reneg-timeout-keeps-association`). Botan's DTLS policy is
reachable through `uut`:

| `uut` field | Botan policy method | OpenSSL |
|-------------|---------------------|---------|
| `initial_timeout_ms`, `dtls_max_timeout_ms` | `dtls_initial_timeout`, `dtls_maximum_timeout` | the virtual-clock retransmit schedule (`DTLS_set_timer_cb`, doubling, capped) |
| `dtls_max_retransmissions` | `dtls_maximum_retransmissions` (the handshake gives up past it) | the budget the timer callback enforces before it stops re-sending |
| `dtls_max_hello_verify_requests` | `dtls_maximum_hello_verify_requests` | unsupported (SKIPs) |
| `dtls_require_cookie` | `dtls_server_require_cookie_exchange` | `SSL_OP_COOKIE_EXCHANGE` |
| `dtls_epoch0_restart` | `allow_dtls_epoch0_restart` | unsupported (SKIPs) |

Inside a non-anchored `flow handshake { ... }` body, `send`/`recv` of handshake
messages configure the preset's messages (overrides and matchers); to drive
extra handshake messages after the preset (a stepped renegotiation, a restart),
anchor the flow at its last step -- `flow handshake after recv Finished { ... }`
in the client role, `after send Finished` in the server role -- so the body is
literal. Both shims strictly verify the HelloVerifyRequest cookie (Botan by its
`dtls_cookie_secret`, the OpenSSL shim by an HMAC bound to the ClientHello
random), so cookie-mismatch and cookie-secret-rotation negatives are testable:
Botan follows the RFC SHOULD and re-challenges an invalid cookie with a fresh
HelloVerifyRequest, while OpenSSL's stateful `SSL_accept` path treats one that
fails to verify as fatal (`SSL_R_COOKIE_MISMATCH` -> handshake_failure).

## Reference

### Expectations

| Syntax | Meaning |
|--------|---------|
| `expect ok` | handshake and every step complete without error |
| `expect alert fatal/code` | UUT sends a fatal alert with the named code |
| `expect alert fatal` | UUT sends any fatal alert |
| `expect alert fatal/{a,b}` | fatal alert with code `a` or `b` |
| `expect reject fatal/code` | plzn rejects the UUT and sends this fatal alert |
| `expect any { ok, alert fatal/protocol_version }` | any listed outcome is conforming |
| `expect close` | UUT closes the TCP connection without an alert |
| `expect reset` | abortive close (TCP RST), rustls's usual rejection |
| `expect timeout` | the UUT exhausts its DTLS retransmission budget |
| `expect handshake-fails` | the UUT alerts, closes, resets, or times out; plzn assertion, codec, crypto, I/O, and local-rejection errors never satisfy it |
| `expect <any of the above> if botan\|openssl\|libressl\|rustls\|gnutls\|wolfssl` | override for one backend; the unsuffixed line is the default |

### Named constants

Every cipher suite, named group, signature scheme, extension type and client
certificate type plzn knows has a name, and a known value MUST be written by
name wherever it lands: field overrides and matchers (`cipher_suites`,
`cipher_suite`, `named_group`, `key_share_group`, `supported_groups`,
`dh_group`, `signature_scheme`, `signature_algorithms`, `sign_with`,
`algorithm`, `has_ext`, `lacks_ext`, `extensions_exactly`, `leaf_has_ext`,
`leaf_lacks_ext`, `certificate_types`), `+ext` / `-ext` / `ext ... ==` /
`+ext each` targets and the typed bodies of `supported_groups`, `key_share`,
`signature_algorithms(_cert)`, `uut client|server { cipher_suites / curves / signing_prefs /
verify_prefs }`, and matrix lists whose variable flows into one of those
positions. The lint says which name a literal should have been:

```
suite/x.plzn:9:24: lower error: `0xc02f` is ECDHE_RSA_WITH_AES_128_GCM_SHA256; write the name (numeric values are for unassigned or deliberately unknown codepoints)
```

Numeric literals are for what has no name: unassigned codepoints, GREASE
values (`0x0a0a`), reserved ranges; ranges (`0x0100..0x01ff`) are never
checked. `tools/name_constants.py` rewrites a corpus with the lint as its
oracle.

The names: cipher suites are the IANA names without the `TLS_` prefix
(`ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `AES_128_GCM_SHA256`,
`PSK_WITH_AES_128_CBC_SHA`; a `TLS_` prefix and any letter case are accepted,
the canonical form is printed), plus `EMPTY_RENEGOTIATION_INFO_SCSV` and
`FALLBACK_SCSV`; groups are the IANA spellings (`secp256r1`, `x25519`,
`ffdhe2048`, `brainpoolP256r1tls13`, `X25519MLKEM768`, `X448MLKEM1024`, `MLKEM768`); signature
schemes the RFC 8446 / RFC 5246 names (`rsa_pss_rsae_sha256`,
`ecdsa_secp256r1_sha256`, `rsa_pkcs1_sha1`, `ecdsa_sha224`); extension types
the RFC names (`key_share`, `alpn`, `renegotiation_info`); certificate types
`rsa_sign`, `dss_sign`, `rsa_fixed_dh`, `dss_fixed_dh`, `ecdsa_sign`,
`rsa_fixed_ecdh`, `ecdsa_fixed_ecdh`. `plzn names` prints every table with
its wire values.

### Alert codes

`close_notify`, `unexpected_message`, `bad_record_mac`, `decryption_failed`,
`record_overflow`, `decompression_failure`, `handshake_failure`,
`no_certificate`, `bad_certificate`, `unsupported_certificate`,
`certificate_revoked`, `certificate_expired`, `certificate_unknown`,
`illegal_parameter`, `unknown_ca`, `access_denied`, `decode_error`,
`decrypt_error`, `export_restriction`, `protocol_version`,
`insufficient_security`, `internal_error`, `inappropriate_fallback`,
`user_canceled`, `no_renegotiation`, `missing_extension`,
`unsupported_extension`, `unrecognized_name`, `bad_certificate_status_response`,
`unknown_psk_identity`, `certificate_required`, `no_application_protocol`

### `peer.capabilities` tokens

Protocol versions are not capabilities: put one or more of `tls10`, `tls11`,
`tls12`, `tls13`, `dtls12`, and `dtls13` in `uut.versions` (without mixing TLS and DTLS). The first version
selects plzn's driver and the complete list is enabled in the shim.

The TLS 1.0 and TLS 1.1 drivers use the legacy MD5/SHA-1 PRF and Finished
digest, their pre-TLS-1.2 signature encodings, and the applicable CBC/NULL
SHA-1 suites. TLS 1.0 CBC uses the key-block IV and chains the last ciphertext
block into the next record; TLS 1.1 carries an explicit per-record IV. AEAD and
SHA-2 CBC suites remain TLS 1.2-only.

| Kind | Tokens | Effect |
|------|--------|--------|
| Key exchange | `rsa`, `dhe_rsa`, `ecdhe_rsa`, `ecdhe_ecdsa`, `ecdhe`, `psk`, `ecdhe_psk` | `ecdhe` is ECDHE under whatever the explicitly named chain signs with (both families when several chains are named; see "Certificate chains"). `uut server`: filters the suites plzn offers; `uut client`: what plzn's TLS 1.0-1.2 / DTLS 1.2 server may select. `psk` / `ecdhe_psk` (RFC 4279 / RFC 5489, TLS 1.0-1.2 and DTLS 1.2, both roles) need a `psk { }` block and normally use `chain: []`. Filters are ANDed, so a `matrix { suite in [...] }` over several exchanges takes no kex token |
| Cipher mode | `aead`, `gcm`, `cbc`, `aes128_cbc_sha`, `aes128_gcm_sha256` | Filters plzn's offered suites (`uut server`) or selectable suites (`uut client`) by record protection |
| TLS 1.3 suites | `aes128_gcm_sha256`, `aes256_gcm_sha384`, `chacha20_poly1305_sha256` | `uut client`: the server's suite capability set |
| Groups | `x25519`, `x448`, `secp256r1`, `secp384r1`, `secp521r1`, all five RFC 7919 groups (`ffdhe2048` through `ffdhe8192`), the RFC 7027 / RFC 8734 brainpool curves `brainpoolP256r1`, `brainpoolP384r1` (TLS 1.2) and `brainpoolP256r1tls13`, `brainpoolP384r1tls13` (TLS 1.3), the ML-KEM groups `mlkem512`, `mlkem768`, `mlkem1024` and the hybrids `x25519mlkem768`, `x448mlkem1024`, `secp256r1mlkem768`, `secp384r1mlkem1024` (all key-shareable); `brainpoolP512r1[tls13]` (advertise only) | `uut server`: the client's supported_groups, in order, with a key share for the first (so `uut server { versions: [tls13] }; peer { capabilities: [secp256r1] }` is a 1-RTT P-256 handshake); `uut client`: the server's group capability set -- for TLS 1.2 the ECDHE curves it may select from the client's supported_groups, in this order, and the DHE_RSA group (`ffdhe2048` default). X448 uses a deliberately simple, non-constant-time `num-bigint` implementation suitable only for the harness. The ML-KEM groups are TLS 1.3 only (draft-ietf-tls-mlkem / draft-ietf-tls-ecdhe-mlkem: the X25519MLKEM768 share is ML-KEM || X25519; the other hybrids follow name order, ECDH || ML-KEM; plzn is the encapsulation-key side as a client and encapsulates as a server). `X448MLKEM1024` uses the repository's pre-existing experimental codepoint 0x11ee; it is not one of the three hybrids in the current IETF draft. rustls's aws-lc-rs provider has no X448, FFDHE, brainpool or P-521, and of the KEM groups only X25519MLKEM768, SecP256r1MLKEM768, MLKEM768 and MLKEM1024 (`requires.any_group` SKIPs the rest). Botan's default policy no longer offers FFDHE though the library implements it, so the Botan shim re-enables the RFC 7919 groups (and appends the pure ML-KEM groups, which its default policy also leaves out); a test wanting Botan's exact default posture pins `uut client|server { curves }` |
| Signature schemes | `rsa_pss_rsae_sha256`, `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ed25519`, ... | `uut server`: plzn's TLS/DTLS client advertises these signature algorithms in order. `uut client` (TLS 1.2 only): plzn's server signing preferences and CertificateRequest schemes. Other server drivers reject these capabilities |
| Flags | `hrr`, `second_hrr` | `uut client`: explicit HelloRetryRequest preset / second HRR |
| | `session_id` | `uut server`, TLS 1.0-1.2: session-ID resumption -- the initial session offers no SessionTicket extension and remembers the id the server assigned, the `resumes:` session echoes it; `recv ServerHello { resumed: true \| false }` asserts whether the server accepted (echoed the id) or answered with a fresh full handshake, which plzn's client then follows |
| | `offer_rpk`, `compress_cert` | `uut server`: offer raw public keys (RFC 7250) / certificate compression (RFC 8879) |

Client authentication is explicit server policy rather than a capability token:
use `uut server { require_client_cert: true }` while testing a server, or
`peer { request_client_cert: true }` while testing a client. Either selects the
client-authentication handshake preset.

**Cipher suites.** plzn implements 98 suites (`src/ir.rs` `ALL_SUITES`, the
one table every driver reads): for TLS 1.2, every AES-GCM, AES-CCM / CCM_8,
ARIA-GCM, Camellia-GCM, ChaCha20-Poly1305, AES-128/256-CBC (HMAC-SHA1, -SHA256,
-SHA384), 3DES-EDE-CBC and NULL-SHA suite Botan defines for the ECDHE_RSA,
ECDHE_ECDSA, DHE_RSA and static-RSA key exchanges (the SHA-384 suites use the
SHA-384 PRF and handshake hash), the RFC 4279 plain-PSK and RFC 5489 /
RFC 8442 ECDHE_PSK families (offered or served only with a `psk { }` block;
TLS 1.2 and DTLS 1.2, both roles), and for TLS 1.3 the
five RFC 8446 suites including AES-128-CCM and CCM_8. Not implemented:
DHE_PSK (Botan has none either) and Botan's private OCB suites. `peer.capabilities` tokens
narrow the offer (client role) or the server's selection (server role):

| Token | Selects |
|-------|---------|
| `aead`, `gcm`, `cbc`, `ccm`, `ccm8`, `aria`, `camellia`, `chacha20_poly1305`, `des3`, `null` | a cipher family, any key exchange and hash |
| `sha384` | the suites whose PRF / handshake hash is SHA-384 |
| `aes128_gcm_sha256`, `aes256_gcm_sha384`, `aes128_cbc_sha`, `aes256_cbc_sha`, `aes128_ccm_sha256`, `aes128_ccm_8_sha256` | one bulk cipher (and, for `*_cbc_sha`, HMAC-SHA1) |
| `matrix { suite in [0xc02f, ...] }` | exactly one suite per point, in either role (`recv ServerHello { cipher_suite: $suite }` pins the server's choice) |

The shims expose every suite their library implements when `uut client|server {
cipher_suites }` is absent (Botan's own preference order first, the rest
appended; OpenSSL's `ALL:COMPLEMENTOFALL`, with security level 0 only when a
NULL or CCM_8 suite is in play), and refuse a case whose offer they cannot
serve at all: `requires.any_suite` is checked against the build, so a
per-suite sweep SKIPs the points a library lacks (rustls: everything but
ECDHE AES-GCM / ChaCha20; OpenSSL's usual build: 3DES and Camellia-GCM).
`suite/server/tls12_suite_sweep_{rsa,ecdsa}.plzn`,
`server/tls13_cipher_negotiation`, `server/tls12_etm_sweep_cbc` and the
`suite/client/*_sweep*` cases run each suite from each side.

Signature-algorithm peer capabilities set plzn's client offer in `uut server`
mode, or its TLS 1.2 server signing preferences in `uut client` mode. Use
`matrix { sigalg in [...] }` for a single-scheme ClientHello offer per point.
`psk_ke` / `psk_dhe_ke` select the TLS 1.3 resumption key-exchange mode.
Cipher selectors with no supported suites in common are lint errors, not a
request to fall back to the driver's default offer.
`session_ticket` is real in both roles: plzn's client advertises the empty
SessionTicket extension (so the shim server issues a ticket), plzn's TLS 1.0-1.2
server issues and renews tickets on every connection (see "Sessions").

### Flow steps

| Step | Modes | Effect |
|------|-------|--------|
| `send Msg [{ fields / ext deltas }] [@ mutations]` | both | send a handshake message (or `ChangeCipherSpec`) built by the driver, with overrides |
| `recv Msg [{ matchers }]` | both | receive and check a message |
| `send AppData [{ size: N, reply: M \| none }] [@ record mutations]` | both | send an exact-size random request (default 32 bytes) asking the shim for M random response bytes (default: the request size) |
| `recv AppData [{ size: N }]` | both | read application data and check its inferred or explicit response length; a response split over several records is reassembled (N may be a matrix variable) |
| `recv Exporter { label: "...", context: "..." \| none, length: N }` | TLS/DTLS after Server Finished | independently derive RFC 5705/TLS 1.3 exported keying material on both endpoints and compare every byte; omitted context means no context, while `""` is an explicitly empty context; length defaults to 32 |
| `recv TLSUnique [{ unavailable: true }]` | TLS 1.0-1.2 | compare the RFC 5929 `tls-unique` binding (the first Finished), including its reversed direction on an EMS resumption; `unavailable: true` requires both APIs to reject it (RFC 7627 non-EMS resumption) |
| `send EarlyData [{ size: N }] [@ record mutations]` | TLS 1.3 resumed client | send raw random 0-RTT plaintext (default 32 bytes), protected by `client_early_traffic_secret` |
| `recv EarlyData [{ size: N }]` | TLS 1.3 resumed server | receive 0-RTT plaintext and optionally require its length |
| `send/recv EndOfEarlyData` | TLS 1.3 resumed | mark the end of accepted 0-RTT data before the client's Finished |
| `send raw "HEX"` | both | raw bytes to the transport, bypassing the record layer |
| `send KeyUpdate { request_update: update_requested \| update_not_requested }`, `recv KeyUpdate [{ ... }]` | TLS 1.3 | post-handshake key update |
| `send Renegotiation [{ msg_type: N }]` | TLS 1.3, server | replay the ClientHello (or another type byte) as an encrypted post-handshake record |
| `renegotiate [resumed] [insecure] [{ ClientHello overrides / +ext / -ext }]` | TLS 1.0-1.2, DTLS 1.2 | drive a second handshake (client-initiated in `uut server`, HelloRequest in `uut client`); `resumed` requires abbreviated legacy-TLS resumption using the established session ID or ticket, the optional block customizes the ClientHello, and `insecure` omits renegotiation_info |
| `recv HelloRequest` | TLS 1.0-1.2, `uut server` | read a server HelloRequest asking plzn's client to renegotiate; answer with `renegotiate` or `send alert warning/no_renegotiation` |
| `begin_renegotiation` | TLS 1.0-1.2 client, DTLS 1.2 | start a renegotiation the flow then drives message by message (`send ClientHello` ... `recv Finished`), with app data and held fragments in between; later declarations shape the second handshake only |
| `wait N ms` | both | sleep, then fail if the peer sent anything |
| `repeat N { steps }` | both | the block N times over (0..4096; N may be a matrix variable), unrolled at lowering; nests with `coalesce` |
| `send alert level/code` | both | an alert record under the current keys, no close (every TLS and DTLS driver, both roles) |
| `close [alert level/code]` | both | close, optionally sending an alert first |
| `close reset` | both, TLS | abortive close: SO_LINGER 0 so the peer sees a TCP RST, not a FIN (tlsfuzzer's CloseRST) |
| `recv alert level[/code]` | both, TLS | the next record must be that alert (`recv alert warning/close_notify` after `send alert warning/close_notify` asserts the peer's reply, a warning it answers with); a different alert is reported as the alert it is, and the flow continues |
| `send Heartbeat "text" [{ payload_length: N, padding: N, type: request \| response }]`, `recv Heartbeat [{ payload, padding_min }]` | TLS, client | RFC 6520 heartbeat records (content type 24); `payload_length` bigger than the payload is the Heartbleed shape |
| `recv CertificateStatus { status_type: ocsp }` / `send CertificateStatus [{ response }]` | TLS 1.2 or DTLS 1.2, client/server | RFC 6066 stapled OCSP after Certificate; a received response must parse as a successful OCSPResponse |
| `recv Certificate { compressed: 1 \| 0 }`, `recv CompressedCertificate { algorithm }` | TLS 1.3, client | the server's RFC 8879 CompressedCertificate (or, with `compressed: 0`, a plain Certificate) after a `+ext compress_certificate` offer (the `compress_cert` capability offers zlib) |
| `send CompressedCertificate [{ algorithm, uncompressed_length, payload, payload_zeros, bomb, credential }]` | TLS 1.3, either plzn role | plzn's certificate zlib-compressed in place of `send Certificate` (anchored flow); the fields forge the label, the length field, or the payload (`payload_zeros: N` zero bytes, `bomb: N` a stream inflating to N MiB) |
| `recv CertificateRequest` after `send Finished` | TLS 1.3, client | RFC 8446 4.6.2 post-handshake authentication: the request the shim server sends under `uut server { post_handshake_auth: request \| require }` when the hello carried `+ext post_handshake_auth`; answer with `send Certificate`, `send CertificateVerify`, `send Finished` |
| `send ClientHello { format: sslv2 [, cipher_specs: [bytes]] }` | TLS 1.2, client | the RFC 5246 E.2 SSLv2-compatible CLIENT-HELLO (SSLv2 record framing, no extensions, the 32-byte challenge as the client random); `cipher_specs` carries genuine 3-byte SSLv2 specs |
| `send ClientHello raw "HEX" [+ ...]` | TLS, client | the literal ClientHello body as sent (a captured fingerprint); plzn decodes it for the state the handshake needs |
| `send empty_record handshake` (or `alert`, `change_cipher_spec`, `application_data`, or a numeric content type such as `0x00` / `24`) | both, TLS/DTLS | a zero-length record of that content type: plaintext before any write keys, sealed under the current ones after |
| `send record N "text"` / `send record N raw "HEX" [+ raw ...]` | both, TLS/DTLS | a record of content type N carrying those bytes, sealed under the current write keys, without changing the driver's handshake state |
| `coalesce [hold_keys \| old_keys] { steps }` | both, TLS | every handshake message sent inside the block goes into ONE record, flushed at the block's end, before a key change, or before any non-handshake record; `hold_keys` keeps buffering across a key change (the record is sealed under the keys current at the flush), `old_keys` defers the key change itself until the flush (the record goes out under the keys from before it) |
| `atomic { steps }` | both, TLS | every record the steps produce is written to the socket in ONE segment at the block's end (tlsfuzzer's TCPBuffering); reads inside the block are not allowed |
| `flush_fragment` | both, TLS or DTLS 1.3 | TLS sends the next record held by `@ fragment N hold` / `hold_all` / `hold_old_keys`; DTLS 1.3 releases the withheld remainder of a handshake-fragmented message, already sealed under its original epoch |
| `advance_clock`, `expect_retransmit`, `resend_flight` | DTLS | see the DTLS section |

ChangeCipherSpec records follow the protocol: in TLS 1.2 the handshake's own first CCS goes in the clear (and a renegotiation CCS under the old keys), while any later CCS, whether a repeated `send ChangeCipherSpec` or `send record 20`, is sealed under the active keys; a TLS 1.3 CCS record is always the plaintext middlebox-compatibility form.

Messages plzn can build as the **client**: `ClientHello`, `ClientKeyExchange`,
`Certificate`, `CertificateVerify`, `ChangeCipherSpec`, `Finished`. As the
**server**: `HelloVerifyRequest`, `ServerHello`, `HelloRetryRequest`,
`EncryptedExtensions`, `Certificate`, `CertificateRequest`,
`CertificateVerify`, `ServerKeyExchange`, `ServerHelloDone`,
`ChangeCipherSpec`, `Finished`.

### Overridable fields and matchers

**Sent by plzn as client (`uut server`):**

- `ClientHello`: `legacy_version` (u16), `random` (32 bytes),
  `legacy_session_id` (bytes), `cipher_suites` (u16 list),
  `compression_methods` (u8 list), `extensions` (bytes; `[]` for an empty block),
  `key_share_point` (`compressed` / `zero`, see below)
- `ServerKeyExchange` (plzn as a TLS 1.0-1.2 server): `named_group` (a group name
  or wire value; forces the ECDHE curve -- one plzn cannot generate, such as
  0x0100, relabels the selected curve's point), `signature_scheme` (a scheme
  name or wire value the key can produce), `psk_identity_hint` (bytes, PSK
  families), `key_share_point` (`zero` / `truncated` / `padded` /
  `compressed`: the server's ECDHE point; plzn's DTLS server applies it, the
  TLS 1.2 server does not yet), `dh_p_bits` (DHE_RSA: 8192 / 3072 / 2048 =
  RFC 7919 groups, with ffdhe2048 the default; 1024 / 768 = the RFC 2409
  Oakley groups), `dh_p` (exact big-endian modulus bytes, including `file
  "path"`, or `rfc5114_2048_256`: RFC 5114 2.3's prime, whose p - 1 has the
  small factors 7, 13, ...), and `dh_g` / `dh_Ys` (exact bytes or `zero`,
  `one`, `two`, `p_minus_1`, `p`, `p_plus_1`, or `small_order`: an element of
  the largest odd prime order up to 4096 dividing p - 1, 2549 for
  `rfc5114_2048_256`, an error for a safe prime). The
  exact values are signed as sent; omit `dh_Ys` to generate a usable public
  value for an arbitrary `dh_p` / `dh_g`. An explicit `dh_Ys` has no private
  value, so a client that accepts it normally leaves plzn unable to finish
  the handshake (a local error) -- except when `dh_Ys` has small order (at
  most 4096; `small_order`, or the boundary values): the client's secret is
  then one of its powers whatever the client's exponent, and plzn keeps the
  one whose keys open the client's first protected record, so acceptance runs
  to a completed handshake. `dh_p: rfc5114_2048_256, dh_g: one, dh_Ys:
  small_order` is how a degenerate-generator case records a client that
  accepts it.
  `dh_p_bits` and `dh_p` are mutually exclusive, and each encoded parameter is
  limited to the TLS u16 vector maximum of 65535 bytes. `format: tls11 | tls12`
  chooses whether the signature is encoded without or with the TLS 1.2
  SignatureAndHashAlgorithm field. Under TLS 1.0/1.1, using
  `signature_scheme` requires explicit `format: tls12` so a requested wire
  field is never silently discarded.
- `ClientKeyExchange`: `ecdh_Yc` (bytes), `dh_Yc` (bytes, DHE), `key_share_point:
  zero | one | p | p_minus_1 | all_ones | empty | truncated | padded | [bytes]`
  (DHE: the numeric `1 < Y < p-1` bounds; TLS 1.2 permits an unpadded integer,
  unlike RFC 8446's fixed-width FFDHE share; ECDHE: the encodings below),
  `premaster_secret`
  (bytes, static RSA, pre-encryption), `encrypted_premaster` (bytes, the whole
  ciphertext; `modulus` = the server key's n; `file "path"` = a pre-generated
  ciphertext such as one of tlsfuzzer's Marvin corpus), `padding_byte: 0xNN`
  (static RSA: plzn builds the PKCS#1 v1.5 EM itself with that byte as the
  padding string, which the `pkcs1.*` mutation paths then address), `rsa_plaintext`
  (bytes: the raw RSA block to encrypt, no PKCS#1 encoding -- the Hamming-weight
  classes of the Marvin scripts), `shared_secret_leading_zeros: N` (DHE / ECDHE:
  plzn searches its ephemeral until the shared secret starts with N zero bytes,
  so the RFC 5246 8.1.2 stripping / RFC 8422 5.10 non-stripping rules are
  exercised; a few hundred key generations per zero byte),
  `psk_identity` (bytes, PSK / ECDHE_PSK suites)
- `Certificate` (the TLS 1.2 / DTLS client's, after a CertificateRequest):
  `entries` (u16; 0 = the RFC 5246 7.4.6 "no suitable certificate" empty list,
  and no CertificateVerify follows), `certificate_list` (bytes, or a list of
  names, below), and `credential: valid | rsa | rsa_pss | ecdsa_p256 |
  ecdsa_p384 | ecdsa_p521 | ed25519 | untrusted | none` -- pick the testdata
  credential plzn's own client presents (and the key its CertificateVerify
  signs with; TLS 1.2, TLS 1.3 and DTLS): `valid` the first `client_chain:`
  entry (the CA-issued P-256 end-entity, `ecdsa_p256`, when the test names
  none); `rsa` an RSA-2048 one; `rsa_pss`
  an RSA-2048 key whose certificate says id-RSASSA-PSS (rsa_pss_pss_* only);
  `ecdsa_p384` / `ecdsa_p521` / `ed25519` the other CA-issued key types (all
  `shims/testdata/client_ee_<type>_*`, issued by client_ee_ca, which every
  shim server trusts); `untrusted` a self-signed chain the shim server rejects
  with unknown_ca (every shim server verifies the client chain whenever it
  required or requested one; `uut client { verify_peer }` is the client-side switch);
  `none` an empty certificate_list. `certificate_list: [rsa, empty, ecdsa_p256]`
  composes the list from named credentials and `empty` (a zero-length entry);
  the CertificateVerify signs with the first named credential's key. In
  `uut server` mode plzn's client answers a CertificateRequest with the shim
  test credential. `uut server { require_client_cert: true }` tells the shim server to
  require and trust it; `uut server { request_client_cert: true }` requests it without
  rejecting an empty Certificate.
- `Finished`: `verify_data` (bytes)
- `ChangeCipherSpec`: `type` (u8)
- `KeyUpdate`: `request_update` (`update_requested` / `update_not_requested`)
- `EncryptedExtensions` (TLS 1.3): `has_ext`, `lacks_ext`
- `CertificateRequest` (TLS 1.3): `has_ext`, `lacks_ext`, `certificate_authorities_count`
- `Certificate`: `entries` (every receiving role), `leaf_key` (`rsa_2048` / `rsa`, `rsa_pss`,
  `ecdsa_p256`, `ecdsa_p384`, `ecdsa_p521`, `ed25519`: the presented leaf's key type, so a
  multi-chain peer's pick is observable; every receiving role), `leaf_has_ext`,
  `leaf_lacks_ext` (TLS 1.3)
- `NewSessionTicket` (TLS 1.3): `has_ext`, `lacks_ext`, `max_ticket_lifetime_hours`
  (ticket_lifetime <= N hours; RFC 8446 4.6.1 caps it at 168)
- `Renegotiation`: `msg_type` (u8)

**Matchers on messages plzn receives as client:** `ServerHello`
`legacy_version` (u16), `cipher_suite` (u16), `legacy_compression_method` (u8),
`key_share_group` (u16, the group the server's key share answers with),
`has_ext` / `lacks_ext` (u16 extension type), `extensions_exactly` (u16 list:
these extension types and no others, in any order), `random_suffix` (bytes),
`resumed` (`true` / `false`, TLS 1.0-1.2: whether the server echoed the session_id
plzn's client offered -- a `session_id` capability resumption or, alongside a ticket,
the fresh id RFC 5077 3.4 has the server echo to signal acceptance),
and extension BODY matchers `ext NAME == value` (or `ext NAME: value`, `ext
0xNNNN == raw "HEX"`), which take the same typed values as `+ext` deltas and
compare the extension body byte for byte (`ext ec_point_formats ==
[uncompressed]`, `ext record_size_limit == 16385`, `ext alpn == "h2"`).
`HelloRetryRequest`, `EncryptedExtensions`, `CertificateRequest` and
`NewSessionTicket` take `has_ext` / `lacks_ext` / `extensions_exactly` / `ext`
the same way. TLS 1.0-1.2: `Certificate` `entries` (u16, the number of
certificates); `ServerKeyExchange` `named_group`, `signature_scheme` (u16 or a
name; what the server chose -- `matrix { group in [...] }` / `sigalg in [...]`
sweeps pin them; a list `named_group: [ffdhe2048, ffdhe3072]` accepts any of
them), `dh_group` (an RFC 7919 group name or a list of them: the explicit DHE
parameters must be that group's p and g -- how a server that ignores the
client's FFDHE list and serves its own MODP prime is caught),
`psk_identity_hint` (bytes); `CertificateRequest` `certificate_types`
(u8 list) and `signature_algorithms` (u16 list or names), contains-all.
Once the flow has received a `HelloRetryRequest`, a `send ClientHello { ... }`
binds its overrides, `+ext` deltas and mutations to the RETRY hello (CH2),
which is how `reverse_extensions` or a changed field on the second hello is
expressed.

**Sent by plzn as server (`uut client`):** `ServerHello` and
`HelloRetryRequest`: `legacy_version`, `random`, `legacy_session_id_echo`,
`cipher_suite`, `legacy_compression_method`, `key_share_group` (u16, forces the
key_share group); `ServerHello` and `EncryptedExtensions` also take `+ext`
deltas. TLS 1.0-1.2: `ServerKeyExchange` as above; `Certificate` `entries` (u16;
0 = an empty certificate_list) and `certificate_list` (bytes, the raw list
contents); `CertificateRequest` `certificate_types` (u8 list; 1 = rsa_sign,
64 = ecdsa_sign) and `signature_algorithms` (u16 list or names), each
replacing the list outright (`[]` is the RFC 5246 7.4.4 bounds negative).
Byte mutations work on every server-flight message (`certificate_list`,
`certificate_types`, `signature_algorithms`, `certificate_authorities`,
`ecdh_point`, `signature` and `psk_identity_hint` are field paths).

**Matchers on the ClientHello plzn receives as server:** `legacy_version`,
`random`, `legacy_session_id`, `compression_methods` (exact),
`cipher_suites`, `supported_groups`, `signature_algorithms` (contains-all),
`lacks_cipher_suite` (one suite or signalling value that must be absent),
`lacks_obsolete_key_exchange: true` (none of the TLS 1.2 finite-field DH/DHE or
RSA suites prohibited by RFC 10015), `supported_versions` (contains-all),
`lacks_supported_version` (one version that must be absent),
`supported_groups_unique: true`, `key_shares_consistent: true`,
`secure_renegotiation_signal: true` (empty `renegotiation_info` or the SCSV),
`server_name` (the RFC 6066 3 host_name, TLS 1.2 and DTLS), `has_ext`,
`lacks_ext`. `random`, `legacy_session_id`, and `key_share` can also capture
their raw bytes with `capture $name`.

The schema also lists fields on `Alert`, but the message-shaped form is
superseded by `send alert level/code` and lint rejects field overrides on it.
`Certificate` overrides are applied in both server implementations.
`NewSessionTicket { ticket_lifetime,
ticket_lifetime_days, ticket }` is applied by the TLS 1.0-1.2 server
(`ticket_age_add` and `ticket_nonce` are TLS 1.3 fields).

**`send CertificateVerify { ... }` on plzn's own client** (TLS 1.2 and TLS
1.3) shapes the signature the way tlsfuzzer's CertificateVerifyGenerator
does. `sign_with: <scheme>` REALLY signs with that scheme -- any RSA PKCS#1
v1.5 hash (`rsa_pkcs1_md5` .. `rsa_pkcs1_sha512`), RSA-PSS (`rsa_pss_rsae_*`,
`rsa_pss_pss_*`, on either RSA key kind), ECDSA over any hash on the key's own
curve (`ecdsa_md5`, `ecdsa_sha1`, `ecdsa_sha224`, `ecdsa_secp256r1_sha256`, ...
read the TLS 1.2 way), `ed25519` -- and by default labels the message with
it; `algorithm: <scheme>` sets the SignatureScheme on the wire independently
(a relabel: `sign_with: rsa_pkcs1_md5, algorithm: rsa_pkcs1_sha256` is the
SLOTH probe, `sign_with: ecdsa_secp256r1_sha256, algorithm:
ecdsa_brainpoolP256r1tls13_sha256` a mislabelled curve). `salt_length: N` and
`mgf1_hash: sha1 | sha224 | sha256 | sha384 | sha512` shape an RSA-PSS
signature away from the RFC 8446 form (salt = hash length, MGF1 = the same
hash); `format: tls11` produces the TLS 1.0/1.1 signature -- RSA over
MD5(transcript) || SHA-1(transcript) with no DigestInfo, ECDSA over SHA-1;
`signature: <bytes>` replaces the signature bytes outright (the label still
follows `sign_with` / `algorithm`). Without any of these the scheme is the
first the CertificateRequest listed that the key can use in that version
(TLS 1.3: PSS only for RSA keys, the key's own curve for ECDSA). The
mutation path `signature.em` edits the RSA encoded message BEFORE the
private-key operation (tlsfuzzer `padding_xors`): byte 0 is the leading
0x00, byte 1 the PKCS#1 block type, -1 the PSS 0xbc trailer, so `@
xor[signature.em, 1] = 0x02` yields a signature no verifier accepts.
`format: tls12` deliberately adds SignatureAndHashAlgorithm under TLS 1.0/1.1;
without it, an `algorithm` override is rejected by lint. The same explicit
format control applies to `CertificateRequest.signature_algorithms` and
`ServerKeyExchange.signature_scheme`.
`recv CertificateRequest { signature_algorithms: [...] }` (contains-all) and
`certificate_types` work in TLS 1.3 as in TLS 1.2.

### Extension deltas

Inside a `send X { ... }` body:

| Form | Effect |
|------|--------|
| `+ext NAME = value` | replace the extension of that type in place, or append it |
| `+ext NAME` | the same with an empty body (`extended_master_secret`, `post_handshake_auth`, an `early_data` offer, a server's `server_name` acknowledgement) |
| `+ext dup NAME = value` | append a second copy even when the type is present (duplicate-extension negatives) |
| `+ext 0xNNNN = raw "HEX"`, `+ext 0xNNNN = zeros N` (any bytes value: a list, a string), `+ext 0xNNNN` | numeric type: that body, or empty |
| `-ext NAME`, `-ext 0xNNNN` | remove |
| `reverse_extensions` | reverse the order of the whole block |
| `+ext each <types> [= value]` | one extension per listed wire type (`each 90..4185`, `each [64..13171, 13173..16064]`), all with the same body (default empty): the tlsfuzzer "N unknown extensions" shape |
| `+ext $id [= value]` | a matrix variable as the wire type |
| `+ext padding = $i` | a matrix variable as a typed integer value |

Messages that take deltas. plzn as client: `ClientHello` (TLS 1.2, TLS 1.3,
DTLS 1.2) and the TLS 1.3 client `Certificate` (leaf entry, client auth).
plzn as server: `ServerHello` (TLS and DTLS), `HelloRetryRequest`,
`EncryptedExtensions`, `CertificateRequest` and `Certificate` (leaf entry).
Lint rejects a delta on any other message. The post-HelloRetryRequest retry
ClientHello re-applies CH1's deltas except anything touching key_share, since
RFC 8446 4.1.2 requires the retry to be the same hello apart from key_share,
cookie and pre_shared_key (Botan checks this and answers illegal_parameter
"Extension content changed" when a delta is dropped).

Typed values (`raw "HEX"` is accepted everywhere):

| Extension | Value |
|-----------|-------|
| `server_name` | `"hostname"` |
| `alpn` | `["h2", "http/1.1"]`, or `"h2"` for a server's selection |
| `supported_versions` | `[tls12, tls13]` (ClientHello) or `tls13` (ServerHello) |
| `supported_groups` | `[x25519, secp256r1, secp384r1, ...]` |
| `key_share` | `[x25519, secp256r1]` on the ClientHello: generate a real ephemeral per listed group (x25519, secp256r1, secp384r1, secp521r1, ffdhe2048, ffdhe3072) and offer those shares (the server may pick any; the client completes with the matching key); `[0x0022..0x00fe : 0xab * 32, secp256r1]` mixes verbatim `group : bytes` entries (a range or list of groups shares one opaque key) with real shares, in that order; `[]` is an empty key_share (forces an HRR); `secp256r1` on a HelloRetryRequest: the retry group |
| `signature_algorithms`, `signature_algorithms_cert` | `[rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, rsa_pkcs1_sha256, ...]` |
| `max_fragment_length` | `512`, `1024`, `2048` or `4096` |
| `record_size_limit` | an integer 64..65535 |
| `padding` | an integer: that many zero bytes |
| `ec_point_formats` | `[uncompressed, ansix962_compressed_prime, ansix962_compressed_char2]` |
| `psk_key_exchange_modes` | `[psk_ke, psk_dhe_ke]` |
| `client_certificate_type`, `server_certificate_type` | `[raw_public_key, x509]` (offer) or `x509` (server selection) |
| `status_request` | `ocsp` |
| `heartbeat` | `peer_allowed_to_send` or `peer_not_allowed_to_send` |
| `use_srtp` | `[srtp_aes128_cm_hmac_sha1_80, srtp_aead_aes_128_gcm, ...]` |
| `compress_certificate` | `[zlib, brotli, zstd]` |
| `early_data` | an integer (NewSessionTicket max_early_data_size); bare `+ext early_data` for the offer |

Other known names (`status_request_v2`, `session_ticket`, `pre_shared_key`,
`cookie`, `certificate_authorities`, `oid_filters`, `post_handshake_auth`,
`renegotiation_info`, `signed_certificate_timestamp`, `delegated_credential`,
`encrypt_then_mac`, `next_protocol_negotiation`, `quic_transport_parameters`,
`application_settings`, `encrypted_client_hello`, `trust_anchors`) take `raw`
or the empty form. A wrong value form is a lint error naming the accepted
forms.

### Mutation operations

| Syntax | Effect |
|--------|--------|
| `@ xor[N] = V` | XOR byte N of the encoded body with V |
| `@ xor[-N] = V` | the Nth byte from the end |
| `@ xor[path, N] = V` | byte N within the named field or record region |
| `@ set[N] = V`, `@ set[path, N] = V` | set the byte to V |
| `@ add[path] = N`, `@ sub[path] = N` | add to or subtract from a complete named big-endian length field without changing its payload; arithmetic wraps at that field's wire width |
| `@ pad +N [0xNN]` / `@ pad -N` | append N bytes (zero, or the given byte) / drop N trailing bytes; N may be a matrix variable. On a handshake message the handshake length is recomputed (tlsfuzzer's pad_handshake / truncate_handshake), so the fault is the body, not a lying header |
| `@ pad "HEX"` | append exactly these bytes (`@ pad "ff01000100"`: a stray extension after the extensions block) |
| `@ truncate N` | keep only the first N bytes (N may be a matrix variable) |
| `@ trailing "HEX"` | TLS handshake messages only: append bytes after the complete framed message without changing its declared length or transcript; this places a prefix of the next handshake message in the current record |
| `@ omit_prefix N` | TLS handshake messages only: omit the first N encoded bytes on the wire while retaining the complete logical message in the transcript; pair with an earlier `@ trailing` to finish a message across a flight or key boundary |
| `@ xor[a..b] = V`, `@ set[path, a..b] = V` | every byte of the range (end exclusive; negatives count from the end) |
| `@ record_version 0xNNNN` | the record header's version field for this send (tlsfuzzer's Connect(version) / SetRecordVersion) |
| `@ record_pad N` / `@ record_pad fill` | TLS or DTLS 1.3: N zero bytes of record padding after the inner content type, or pad the record to the 2^14 + 1 plaintext maximum |
| `@ dtls13_short_sequence` | DTLS 1.3: use the one-byte unified-header record number instead of two bytes |
| `@ dtls13_omit_length` | DTLS 1.3: omit the unified-header length field (the record must occupy the rest of its datagram) |
| `@ dtls13_set_cid_bit` | DTLS 1.3 negative: set the CID-present bit without negotiating a CID |
| `@ dtls13_legacy_header` | DTLS 1.3 negative: protect the record but encode the classic 13-byte DTLS header |
| `@ plaintext` | send the record in the clear even though write keys are installed (a plaintext Finished or alert after the key change) |
| `@ plaintext = "HEX" [+ 0xNN * N ...]` | replace the whole record plaintext before encryption (CBC: data + MAC + padding as tlsfuzzer's replace_plaintext; `0x0f * 63` is a fill segment) |
| `@ cbc_pad N` | CBC suites: pad the record to N bytes of padding including the length byte (tlsfuzzer's min_length), for the atypical / Lucky13 padding shapes |
| `@ reorder N` | DTLS: N-byte handshake fragments in reverse order |
| `@ fragment N [hold \| hold_all \| hold_old_keys]` | TLS: split the framed message into N-byte records; DTLS 1.3: split into handshake fragments, with `hold` withholding the last or `hold_all` every fragment after the first until `flush_fragment`; `hold_old_keys` is TLS-only |

DTLS handshake fragmentation schemes are a separate `@` suffix on a `send` step
(they lower to a DTLS fragmentation plan, not a byte mutation, and apply to both
roles). At most one per send; a scheme and byte mutations may share the `@` list.

| Syntax | Effect |
|--------|--------|
| `@ fragment N` | split into N-byte handshake fragments, in offset order (the peer MUST reassemble) |
| `@ duplicate_fragment N` | fragment, then send each fragment twice (harmless exact retransmits) |
| `@ reorder_overlap N` | matching overlaps and duplicates in reverse order (valid) |
| `@ complete_and_fragments N` | N-byte fragments plus a redundant whole fragment (valid) |
| `@ empty_fragments` | zero-length boundary fragments around the whole message (valid) |
| `@ split_fragment_record N` | split the encoded fragment bytes across two records (invalid) |
| `@ overlap_mismatch N` | fragment, then re-send the first fragment with one byte flipped before completion (the peer MUST reject) |
| `@ type_mismatch N` | fragments for one message_seq disagree on msg_type (invalid) |
| `@ offset_overflow` | one fragment whose fragment_offset + fragment_length runs past the declared length (the peer MUST reject) |
| `@ length_mismatch N` | fragment; a later fragment advertises a different total length for the same message_seq (the peer MUST reject) |
| `@ fragment_length_mismatch N` | fragment_length exceeds the bytes carried by the record (invalid) |
| `@ future_sequence N` | prefix the real message with a complete copy at message_seq + N; used for the +7 reassembly-window bound and reordered-extra-message cases |
| `@ future_sequence_packed N` | put the future and valid fragments into one record; a clean in-sequence retransmission is retained for `flush_fragment` |

Paths: `handshake.verify_data`, `handshake.signature`, `handshake.msg_type`,
`handshake.length`, `handshake.key_share` (the first KeyShareEntry's public
value in a TLS 1.3 hello, without its length prefix),
`handshake.ecdh_point` (the same for a TLS 1.2 ServerKeyExchange or
ClientKeyExchange), the ClientHello length prefixes
`handshake.session_id_length`, `handshake.cipher_suites_length`,
`handshake.compression_methods_length`, `handshake.extensions_length`,
the message sub-vector prefixes (`handshake.certificate_list_length`,
`handshake.first_certificate_length`, `handshake.signature_length`, and the
key-exchange `*_length` names), and extension prefixes named
`handshake.extension_<extension>_length` or
`handshake.extension_<extension>_<vector>_length`,
`record.content_type`, `record.version` (the 2-byte header version),
`record.epoch` and `record.sequence_number` (DTLS 1.2 header only),
`record.mac`, `record.aead_tag`,
`record.encrypted_record`, the pre-encryption regions `record.plaintext`
(CBC: IV + data + MAC + padding; AEAD: the inner plaintext), `record.padding`
(CBC: the padding bytes, index -1 the length byte) and `record.inner_type`
(TLS 1.3: the inner content type byte; a bare `set[record.inner_type] = 0`
means byte 0 of it), `signature.em` (the RSA encoded message of a client
CertificateVerify, edited before the private-key operation; see "Overridable
fields"), and on a static-RSA ClientKeyExchange the PKCS#1 v1.5 encoded
message BEFORE encryption: `pkcs1.em` (the whole EM: byte 0 is the leading
0x00), `pkcs1.block_type` (the 0x02), `pkcs1.padding` (the non-zero padding
string PS; `-1` is its last byte), `pkcs1.separator` (the 0x00 before the
premaster) and `pkcs1.premaster` -- the Bleichenbacher padding-fault classes,
which a server must answer exactly like a good ciphertext (RFC 5246 7.4.7.1).
Handshake mutations apply after encoding and before encryption;
`record.plaintext` / `record.padding` / `record.inner_type` / `signature.em` /
`pkcs1.*` before encryption; the other record mutations after. Positions and
values may be matrix variables; an index may be a range (`xor[0..4] = 0xff`,
`set[record.plaintext, -48..-1] = 0x31`). Combine with commas, each item with
its own `@`: `@ xor[0] = 0x01, @ xor[1] = 0x02`, `@ pad +3, @ set[-4] = 3`.
Multi-byte values are not supported by `xor`/`set` (use a range with one value,
or `set` several bytes). Use `add`/`sub` when the target is a complete named
length field.

### Record-layer fragmentation and coalescing

Over DTLS the same `@ fragment N` means handshake-layer fragmentation (see the
DTLS section); DTLS 1.3 also supports `hold` / `hold_all` and `flush_fragment`.
Over TLS, `@ fragment N`
is applied by the record layer of the four TLS drivers (both
roles, TLS 1.2 and 1.3), on any message including `send KeyUpdate ... @
fragment 3 hold`; it is a lint error under `uut client|server { versions: [dtls12] }`, where `@ reorder N`
drives DTLS handshake fragments instead. Each fragment is its own record --
its own sequence number, MAC or AEAD tag -- and `record.*` mutations apply to
the first fragment only. With `hold`, the last fragment is kept back until a
`flush_fragment` step, so other records (`send ChangeCipherSpec`, `send
AppData`, `send empty_record application_data`, a KeyUpdate's own key
rotation) can go between the two halves; the remainder is sealed under
whatever write keys are current at the flush, which is how a Finished is
split across the TLS 1.2 ChangeCipherSpec or a KeyUpdate across its own key
change. `coalesce { ... }` buffers the handshake messages sent inside it and
writes them as one record; a key change, a CCS or any non-handshake record
flushes the buffer first (so `coalesce { send ServerHello ... send Finished }`
on a TLS 1.3 server yields the ServerHello alone, then EE + Certificate +
CertificateVerify + Finished in one record). Blocks do not nest.

### Invalid key-share points

Byte mutations and one symbolic override cover the RFC 8446 4.2.8.2 and RFC 8422
5.11 point-validation family. The private key always stays real, so the peer
either rejects the point or completes the handshake:

| Form | Effect |
|------|--------|
| `@ xor[handshake.key_share, -1] = 0x01` | flip a coordinate byte: on a NIST curve the point is no longer on the curve (all three libraries answer `illegal_parameter`) |
| `@ xor[handshake.key_share, -1] = 0x80` | set the x25519 high bit, which RFC 7748 requires the receiver to mask, so the handshake still completes |
| `key_share_point: compressed` | re-encode the public value as a SEC1 compressed point, which RFC 8446 4.2.8.2 forbids in key_share (NIST curves only; x25519 has no compressed form) |
| `key_share_point: zero` | an all-zero public value: the low-order x25519 point (RFC 8446 7.4.2 requires an abort on an all-zero shared secret), or an invalid encoding on a NIST curve |
| `key_share_point: truncated` | the real point minus its last byte |
| `key_share_point: padded` | the real point plus one zero byte |
| `key_share_point: one`, `key_share_point: p_minus_1`, `key_share_point: p` | finite-field groups: the RFC 8446 4.2.8.1 bounds `1 < Y < p-1` and `Y = p`, encoded at the prime's length; on x25519 `one` is the little-endian u-coordinate 1 (another low-order point) |
| `key_share_point: all_ones` | every byte 0xff at the share's length (an FFDHE value above p; an invalid point elsewhere) |
| `key_share_point: empty` | a zero-length key_exchange (RFC 8446 4.2.8: a decode error on every library) |
| `key_share_point: hybrid`, `key_share_point: xy` | NIST curves: the SEC1 hybrid form (0x06/0x07 || X || Y) and the bare X || Y without the 0x04 prefix (RFC 8422 5.7 / RFC 8446 4.2.8.2 allow uncompressed only) |
| `key_share_point: [0x00, ...]`, `key_share_point: 0x37 * 31` | a literal public value: any bytes, or a fill (`byte * count`) |
| `key_share_point: <group name>` | a VALID share of another group (`secp384r1`, `ffdhe2048`, `mlkem768`, ...) under this group's id: the peer must notice the wrong length or encoding |

Byte fills (`0x00 * 256`) are accepted wherever a byte list is: `premaster_secret:
0x03 * 49`, `dh_Yc: 0x01 * 1025`, `rsa_plaintext: 0xff * 256`.

On the KEM groups the same recipes reshape the whole share (the ML-KEM
encapsulation key, or ML-KEM || X25519 / ECDH || ML-KEM for a hybrid);
`compressed` / `hybrid` / `xy` re-encode the ECDH half of a NIST hybrid, and a
`set` on `handshake.key_share` reaches any byte -- e.g. an ML-KEM coefficient
written as q = 3329 for the FIPS 203 7.2 modulus check
(`suite/server/tls13_mlkem.plzn`).

`truncated` and `padded` recompute every enclosing length prefix, so the message
stays structurally well formed and the only fault is that the point is the wrong
size for its group. That is the distinction from `@ truncate N`, which shortens
the whole message and leaves the outer lengths lying.

`key_share_point` works on `ClientHello` and `ClientKeyExchange` when plzn is
the client, and on `ServerHello` when plzn is the server. On x25519 a flipped
byte is not a validity error at all, since every 32-byte string is a valid
u-coordinate: both sides derive different secrets and the failure surfaces at
Finished as `bad_record_mac`. The corpus keeps that contrast pair.

### Values and generators

Every place that takes a list or bytes -- field overrides and matchers and
typed extension values -- shares one value grammar:

| Form | Meaning |
|------|---------|
| `0x1301`, `secp256r1`, `"str"`, `$var` | a number, a schema name, a string, a matrix variable |
| `[a, b, c]` | a list; nested lists flatten, so `[0x00 * 4, 0x01]` is five bytes |
| `lo..hi` inside a list | every value from lo to hi inclusive (`cipher_suites: [0x0100..0x1000]`, `+ext supported_groups = [secp256r1, 0x0022..0x00fe]`); bounds may be `$var` or `$var + N` |
| `x * N` | x repeated N times: a byte (`0xab * 32`), a name, a list (`[0x01, 0x00] * 512`) or a range; N may be `$var`. A string repeats into ONE string (`"A" * 255` is a 255-byte ALPN name); `["A" * 255] * 2` is two entries |
| `zeros N` | `0x00 * N` |
| `key : value` inside a list | an entry (the key_share `group : bytes` form) |
| `capture $name` (matchers only) | record the peer's value instead of comparing it |

Numbers are accepted inside every typed list next to names
(`+ext signature_algorithms = [rsa_pss_rsae_sha256, 0x0904]`), so unassigned
code points need no `raw`. Ranges span at most 65536 values, a repeat at most
2^24 items, and an extension delta list at most 65279 bytes (the extension
block is a u16 length and the hello's own extensions need room).

Matrix axes take the same ranges: `matrix { g in [0x0001..0x0016, 0x001a..0x001c] }`
and `matrix { base in 0x0300..0xff00 step 0x0100 }`.

### Repeats and captures

`repeat N` at test level runs the whole test N times, each repetition a fresh
connection with its own sub-seed (`$repeat` is the index, and each becomes its
own case `name[repeat=k]`). `capture $name` on a `recv` matcher records the
peer's value -- `ClientHello { key_share: capture $ks }`, `ServerHello {
random: capture $r, legacy_session_id_echo: capture $sid, key_share: capture
$ks }`, `ServerKeyExchange { key_share: capture $ks }` (the ECDHE point or
DHE Ys), and `NewSessionTicket { ticket_age_add: capture $age }`, also on a
`HelloRetryRequest` -- and `assert unique $r, $ks`
compares the captures across the repetitions (and the matrix points of the
same test): no two runs may have captured the same value. The verbose report
prints every capture. This is how tlsfuzzer's key-share-random and
serverhello-random scripts are expressed.

Uniqueness assertions run in both `run` and `dial`, including multi-session
tests. Each session and non-repeat matrix cell has its own repetition group;
every run must capture each asserted variable, and at least two runs are needed.

Explicit/anchored message declarations belong to their own occurrence. Preset
declarations for the same message are merged; conflicting field values or
multiple fragmentation schemes are lint errors. Unsupported special-message
extension/modifier combinations are rejected during lint.
The pre-HRR duplicate TLS 1.3 ClientHello path replays CH1: only record-field
edits are supported on that replay; other occurrence modifiers fail lint.

Sized application receives consume exactly the requested number of bytes,
retaining excess for the next receive. They have a ten-second total read
deadline, including intervening post-handshake traffic, and no record-count cap.

### Asserts

Post-trace asserts run after an otherwise-passing run:

| Syntax | Meaning |
|--------|---------|
| `assert no_duplicate_record_seqnums` | DTLS: no two received records share (epoch, sequence_number) |
| `assert gcm_nonces_unique` | TLS 1.2 AES-GCM/CCM: the explicit nonce (RFC 5288 3) of every record received is distinct |
| `assert gcm_nonces_monotonic` | the explicit nonces strictly increase (the sequence-number form RFC 5288 suggests; rustls draws a random one per record, so `skip rustls` it) |
| `assert new_session_tickets == N` | TLS 1.3 client: exactly N post-handshake NewSessionTicket messages arrived over the flow (read by an explicit `recv NewSessionTicket`, absorbed while waiting for another message, or during a `wait`); unlike N repeated `recv NewSessionTicket` steps, an N+1th ticket fails the assert |
| `assert app_data_records == N` | exactly N application-data records arrived from the peer over the whole flow (every content-type-23 record read, including those drained by a `wait`); a replay test asserts the UUT answered a request once and discarded the duplicate it was sent, rather than merely ignoring a second echo (RFC 6347 4.1.2.6) |
| `assert resumed == true\|false` | TLS/DTLS session: the completed connection used (or did not use) an abbreviated/resumed handshake |
| `assert negotiated.cipher == SUITE` | the cipher suite selected on the wire, using its registry name (or an unknown numeric value) |
| `assert negotiated.early_data_accepted == true\|false` | TLS 1.3: whether the server accepted offered early data |
| `assert unique $a, $b` | cross-run: see "Repeats and captures" |

Other `assert path == value` forms parse but are rejected at lowering.

## Reading failure output

A failing test with `expect ok`:

```
[FAIL] usage/happy — botan (127.0.0.1:44715) (12ms)
       negotiated cipher suite: 0x1301
    0. FAIL   handshake (11ms)
              alert fatal/handshake_failure (level=2, description=40)
       expected: ok
       observed: alert fatal/handshake_failure (level=2, description=40)
       at step:  0
```

- **expected** -- what the `.plzn` file asked for, in DSL terms
- **observed** -- what actually happened, symbolic name plus wire value
- **at step** -- which step in the flow was executing when it happened
- **shim self-check FAILED** -- the library-side process disagreed with plzn
  (it saw a handshake failure plzn did not expect, or vice versa); the
  `PLZN-RESULT` line above it carries the library's own error classification

A passing negative test (`-v` shows this for passes too):

```
[PASS] usage/bad-finished — botan (127.0.0.1:44715) (9ms)
       negotiated cipher suite: 0xc02f
    0. FAIL   handshake (8.8ms)
              alert fatal/decrypt_error (level=2, description=51)
       expected: alert fatal/decrypt_error
       observed: alert fatal/decrypt_error (level=2, description=51)
```

The step shows FAIL (the handshake did fail) but the test shows PASS (the
failure matched the expectation).

## Tips for LLMs

- **Start with `plzn lint`** to catch syntax and schema errors before running.
- **Verify against the corpus-enabled backends** (Botan, OpenSSL, LibreSSL,
  rustls, and Go) before committing an expectation; also probe GnuTLS and wolfSSL when
  the case is within their current shim surface. Then
  read `notes/audit/coverage_matrix.md` for the known alert-code splits (OpenSSL
  says `decode_error` where Botan and rustls say `decrypt_error` for malformed
  Finished; `handshake_failure` versus `protocol_version` for bad versions).
- **Pin per backend** with `expect ... if openssl` rather than widening to
  `handshake-fails`; use `handshake-fails` only when the UUT's transport-level
  rejection is the property under test, `expect reject` when plzn is the
  rejecting endpoint, `xfail <backend>` for known incorrect behavior, and `skip <backend>`
  when the library cannot run the case at all.
- **Negative indices** (`xor[-1]`) target authenticators at the end of
  variable-length messages without counting bytes.
- **Matrix variables** work in field-override values and in mutation positions
  and values, not in message names or other structural positions.
- **TLS 1.3 servers answer late.** Nothing flows server-to-client after the
  client Finished, so after a bad final message add `recv AppData` to force the
  read that surfaces the alert.
- **A lone `flow handshake {}`** is a complete negative test when the
  interesting part is the UUT policy or peer capability selection (version and cipher negotiation
  failures); a positive one still needs the app-data tail.
- **Cite the RFC** with `rfc 8446 section 4.1.2` and say in a comment which sentence
  the test enforces. The corpus under `suite/` does this for every case and is
  the best source of templates.
