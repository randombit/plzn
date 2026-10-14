# plzn interop shims

This directory holds config-file-driven TLS/DTLS **shims** that wrap a real TLS
library (Botan, OpenSSL, LibreSSL, BoringSSL, rustls, GnuTLS, wolfSSL, or Go `crypto/tls`) as the unit-under-test
(UUT), plus the shared support code the shims are built on.

Botan, OpenSSL, and rustls are the corpus-enabled backends described by the
full policy matrix below. LibreSSL is also fully triaged against the corpus
(TLS and DTLS 1.2, both roles); see [LibreSSL](#libressl). BoringSSL is the DTLS 1.3 oracle. GnuTLS, wolfSSL, and Go are newer: all cover TLS 1.2/1.3,
both roles, certificate authentication, SNI, application data, and structured
results; GnuTLS additionally has DTLS 1.2 datagram framing in both roles. They
report `unsupported_config` for unwired controls so incomplete coverage cannot
look like a pass. Their permanent tests are the `gnutls_shim_*` and
`wolfssl_shim_*` cases in `tests/shim_interop.rs`.

Harness self-tests live under `tests/cases/`, including
[plzn's local rejection checks](../tests/cases/local_rejections/README.md).
Tests that rewrite shim traffic use separate [test shims](../tests/shims/README.md).

## Why shims (and how this differs from `plzn dial`)

`plzn`'s existing `src/server/` backends drive a library's *stock CLI tool*
(`openssl s_server`, `botan tls_http_server`) as a fixed-behaviour peer. That is
fine for happy-path oracle checks but gives almost no control over policy,
version bounds, cipher/curve/sig-alg selection, resumption, client auth, or the
many "expect the UUT to notice X" assertions that BoGo-style testing needs.

A **shim** is a small program that links the library directly and exposes its
full policy/behaviour/expectation surface. This mirrors BoringSSL's BoGo model
(runner drives an adversarial TLS stack; the shim wraps the UUT and connects
back over a socket), with one deliberate change:

> **BoGo passes dozens of command-line flags. We pass a single config file.**

The runner (`plzn`) writes one JSON config file to a tempfile that lives only
for the duration of the test, and passes its path as the shim's sole per-test
configuration argument. This keeps the "control the tested implementation" surface in one
structured, versioned, diffable place instead of an ever-growing flag list.

## Roles

```
        +------------------+                         +-------------------+
        |     plzn      |  TCP (TLS/DTLS bytes)   |    <lib> shim     |
        | (adversarial     | <---------------------> | (real TLS library|
        |  TLS stack, Rust)|                         |       UUT)        |
        +------------------+                         +-------------------+
              runner: listens, drives the flow          UUT: dials back,
              per the .plzn DSL, may send               runs a normal
              deliberately malformed messages           handshake + app data
```

`plzn` is the runner: it listens on a loopback port, spawns the shim with the
config-file path, and drives its own TLS implementation over the accepted
connection according to the `.plzn` test. The shim is the UUT: it reads the
config, dials the runner, runs a *normal* handshake with the real library, and
self-checks any expectations the config asked for.

This is the inverse of `plzn dial --addr` (there, `plzn` dials a listening server).
Having `plzn` listen lets one runner coordinate multi-
connection tests (resumption, renegotiation) the way BoGo does: the shim makes
`resume_count + 1` separate connections to the same runner port.

## Discovery and identity

`plzn run --shim PATH ...` first executes:

```
PATH --plzn-shim-info
```

The shim must exit successfully and write exactly one JSON object to stdout:

```json
{
  "protocol": "plzn-shim",
  "protocol_version": 1,
  "name": "mytls",
  "expectations": "mytls-expectations.json"
}
```

`name` is the stable identifier used in reports and by the DSL's `expect ...
if`, `skip`, and `xfail` annotations. It may contain ASCII letters, digits,
periods, dashes, and underscores. `expectations` is optional; a relative path
is resolved against the shim executable's directory. Protocol mismatches,
malformed output, and a named but unreadable sidecar are setup errors.

The expectation sidecar lets the project owning the shim carry its local
compatibility policy without patching plzn's shared suite:

```json
{
  "schema_version": 1,
  "overrides": {
    "server/untrusted-client-cert":
      "alert fatal/{unknown_ca,bad_certificate,certificate_unknown}",
    "server/known-defect": {
      "expect": "alert fatal/decode_error",
      "xfail": "accepted by MyTLS 4.1"
    },
    "server/not-built": {
      "skip": "feature disabled in this build"
    }
  },
  "patterns": [
    {
      "pattern": "server/large-client-hello*",
      "expect": "any { ok, alert fatal, close }"
    }
  ]
}
```

Keys are exact concrete test IDs, including matrix parameters. A string is
shorthand for `{ "expect": "..." }`. `expect` accepts the DSL spellings `ok`,
`close`, `reset`, `timeout`, `handshake-fails`, `alert fatal`, `alert warning`,
and alerts with one code or a set of codes. An entry may specify `skip` or
`xfail`, but not both. `{ "normal": true }` clears an in-suite skip or xfail
for that backend. Sidecar values take precedence over an in-suite annotation
for the identified backend.
`patterns` applies the same object form to shell-style `*` and `?` patterns;
exact IDs take precedence, and otherwise the first matching pattern wins.

## Connection protocol

Adopted from BoGo (proven, and it already solves DTLS packetisation):

1. On each connection the shim first writes an 8-byte little-endian **ShimID**
   (`shim_id` from the config). The runner uses it to correlate connections.
2. **TLS**: after the ShimID, the socket carries raw TLS record bytes in both
   directions.
3. **DTLS**: after the ShimID, traffic is framed with one-byte opcodes so a
   reliable stream can carry unreliable datagrams, a virtual clock, and runtime
   control:
   - `P` + `uint32be len` + `len` bytes -- one datagram (packet).
   - `T` + `uint64be nanos` -- advance the shim's DTLS retransmit clock. Botan
     runs its timer on the shim's monotonic clock; the OpenSSL shim freezes
     `gettimeofday` (a definition in the executable preempts libc's) and drives
     OpenSSL's timer from these frames through `DTLS_set_timer_cb`. The shim
     answers with `t` after timeout handling completes; `P` frames emitted in
     between are buffered by the runner.
   - `E` + `uint64be nanos` -- assert the UUT's exact next timeout; `UINT64_MAX`
     means no timer. The shim answers `e` on a match.
   - `U` + `uint32be millis` -- rescale a live timeout and answer `u`. OpenSSL
     implements this; Botan refuses configurations requiring it up front.
   - `X` -- the UUT exhausted its retransmission budget. The runner maps this
     to the terminal `expect timeout` outcome.
   - `C` + `uint8 command` -- a runtime control command applied between
     datagrams. Command `1` = rotate the DTLS cookie secret (the
     `rotate_cookie_secret` step): cookies issued so far stop verifying.
   The shim answers each inbound packet with `P`-framed outbound datagrams.

## Application-data phase

After the handshake the shim runs an app-data loop whose behaviour comes from
the config `app_data` block. The default, retained under the config name
**echo**, implements plzn's random-data request/response protocol. A request's
12-byte header contains `PLZN`, its exact plaintext size, and the requested
random-response size; the rest is generated test data. The responder buffers
fragmented TLS reads, emits exactly the requested number of bytes, and permits
a zero response length. Unframed data is still echoed verbatim for older or
non-DSL callers. Other modes: `shim_writes` (shim sends fixed bytes then
closes), `shim_shuts_down` (shim closes immediately after handshake).

`key_material` requests make the shim derive exporter output or `tls-unique`
from the live library connection and write it before entering that loop. Each
request carries a zero-based connection index so resumed sessions can be
checked independently. The runner derives the same value from its own key
schedule and compares the raw application bytes.

## Config file format

A single JSON object. Schema is documented in `common/plzn_shim.h` (the typed
struct is the source of truth). Top level, abbreviated:

```json
{
  "role": "client" | "server",
  "protocol": "tls" | "dtls",
  "runner": { "host": "127.0.0.1", "port": 12345, "ipv6": false },
  "shim_id": 0,
  "resume_count": 0,
  "min_version": 771, "max_version": 772,
  "connection_versions": [771, 772],
  "cipher_limit": "...", "curves": [23,29], "signing_prefs": [...],
  "credentials": { "cert_file": "...", "key_file": "...", "trust_file": "...",
                   "chains": [ { "cert_file": "...", "key_file": "...", "key_type": "ecdsa-p256" }, ... ],
                   "client_chains": [ { "cert_file": "...", "key_file": "...", "key_type": "rsa-2048" }, ... ] },
  "server_certificate_types": [2, 0],
  "client_certificate_types": [2, 0],
  "requires": { "any_suite": [4865], "any_group": [23], "virtual_clock": false,
                "dynamic_timeout": false,
                "server_key": ["ecdsa-p256", "rsa-2048"] },
  "psk": { "identity": "...", "secret_hex": "..." },
  "verify": { "peer": false, "require_client_cert": false, "fail": false },
  "alpn": { "advertise": ["h2"], "select": "h2", "expect": "h2" },
  "app_data": { "mode": "echo" },
  "key_material": [ { "connection": 0, "kind": "exporter",
                      "label": "label", "context": "context", "length": 32 } ],
  "expect": { "version": 772, "cipher": 4865, "alpn": "h2",
              "resumed": true, "hrr": false, ... }
}
```

Versions are the on-the-wire 16-bit codes (TLS 1.0 = 0x0301, TLS 1.1 =
0x0302, TLS 1.2 = 0x0303 = 771, TLS 1.3 = 0x0304 = 772, DTLS 1.2 =
0xFEFD, DTLS 1.3 = 0xFEFC).
DTLS version numbers run backwards, so a `[dtls12, dtls13]` range is encoded
with `min_version = 0xFEFD` and `max_version = 0xFEFC`. A shim must inspect both
bounds and report `unsupported_config` if the range includes a version it does
not implement; silently ignoring `0xFEFC` and negotiating DTLS 1.2 is forbidden.
For a multi-session shim-client run, `connection_versions` gives the exact wire
version for each successive connection. The shim must retain its process-wide
session cache while pinning each client connection to the corresponding entry;
this is what makes TLS/DTLS cross-version resumption tests deterministic.

`connection_early_data` optionally supplies one `{ "send": N, "expect": N,
"accepted": true|false|null }` object per connection. It overrides the
corresponding process-wide early-data fields, so an accepted connection and
a rejected replay can share one shim/session cache. Backends without an
early-data API continue to refuse that capability before execution.

`requires.session_id_resumption` distinguishes stateful TLS 1.2 session IDs
from tickets. A backend without the former must report unsupported, rather
than let a resumption test pass through a fresh handshake.

The runner drains stdout and stderr throughout the shim's lifetime, retaining
the last 256 KiB of each. Its process deadline defaults to 60 seconds times
the connection count; `PLZN_SHIM_TIMEOUT_MS` overrides that whole-process
deadline. Once the runner finishes, the child has at most five seconds to exit.
Timeout/cancellation is a local harness error, not an expected TLS failure.
The nonblocking-pipe supervisor currently requires Unix.

### Certificate chains

A shim may hold several chains and must pick the one its peer can use:

- `credentials.chains` is the list the shim SERVES (server role);
  `credentials.client_chains` the list it PRESENTS when a server asks for a
  client certificate (client role). Each entry names its PEM files and the
  leaf's key type in the runner's spelling -- `rsa_2048`, `rsa_pss`,
  `ecdsa_p256`, `ecdsa_p384`, `ecdsa_p521`, `ed25519` (the `--cert` spellings
  `rsa`, `ecdsa`, `ecdsa-p384`, `rsa-pss`, ... are normalized to those). A
  missing `key_type` is inferred from the key or the leaf's SPKI. The order
  is the shim's preference among chains the peer accepts.
- An explicit EMPTY `chains` array means "serve no chain at all" (a PSK-only
  server; a client with an empty `client_chains` answers a CertificateRequest
  with an empty Certificate). When a list is ABSENT the shim derives it from
  the legacy `cert_file` / `key_file` (+ `second_cert_file` / `second_key_file`)
  pair, so a single-chain config behaves exactly as before; `cert_file` /
  `key_file` stay equal to `chains[0]` for the code that still reads them
  (OCSP stapling, raw public keys).
- `requires.server_key` is a string or a list: the key types plzn's SERVER
  may present. A shim CLIENT refuses (unsupported_config) only when its
  library can verify none of them.

Selection, per shim. The rule everywhere is "prefer the first chain the
peer's signature_algorithms can use, else present the first chain and let the
library judge it" -- so a multi-chain no-match reads exactly like the
single-chain corpus (Botan aborts, OpenSSL and rustls send an empty client
Certificate / fail the server handshake with their own alert), and nothing
the shim does is a finding in itself:

| shim | server role | client role | cannot express |
|---|---|---|---|
| Botan | `Credentials_Manager::cert_chain` over the list: the peer's key types (from its signature_algorithms) first, then its schemes; Botan hands over SIGNATURE OIDs without a curve, so the TLS 1.3 curve is inferred from the hash (P-256/SHA-256, P-384/SHA-384, P-521/SHA-512) with a relaxed any-curve pass for TLS 1.2 | the same, from the CertificateRequest's types + schemes | id-RSASSA-PSS chains (no rsa_pss_pss_* schemes): never selected; refused when every chain is one |
| OpenSSL | one chain per key-type slot (RSA, RSA-PSS, ECDSA, Ed25519) loaded into the CTX, OpenSSL selects the slot from the ClientHello; several ECDSA chains are chosen per connection in `SSL_client_hello_cb` from the raw signature_algorithms (curve-bound code points first) via `SSL_use_certificate_chain_file` | one chain: CTX; several: nothing in the CTX and `SSL_CTX_set_client_cert_cb` picks by `SSL_get_sigalgs` (raw code points, TLS 1.3 curve-bound) or returns 0 (empty Certificate) | two chains in the same non-ECDSA slot (two RSA chains): refused, unsupported_config; Ed448 / DSA slots unhandled |
| rustls | a `ResolvesServerCert` over one `CertifiedKey` per chain, picking by `ClientHello::signature_schemes()`; rustls signing keys are scheme-bound (a P-256 key signs ecdsa_secp256r1_sha256 only), so the pairing is exact in both versions | one credential: `with_client_auth_cert`; several: the same resolver as `ResolvesClientCert` on the CertificateRequest's schemes | id-RSASSA-PSS keys (no rustls signer / no webpki SPKI): never selected, refused when nothing else loads; P-521 loads and verifies on aws-lc-rs |

The config-file wrapper used to prove this (a `PLZN_<KIND>_SHIM` script that
merges a JSON override into the runner's config) lives in the session notes;
the corpus cases follow once the DSL's `chain: [...]` selector lands.

## Expectations and exit status

The shim self-checks `expectations` and exits non-zero with a diagnostic on
mismatch, just like BoGo. On a handshake/alert failure the shim maps the
library's error string to a canonical code (see `common/plzn_shim.h`) so the
runner can assert on an implementation-independent alert/error taxonomy rather
than raw library messages.

## Policy controls (`uut client|server { ... }`)

Two rules, in tension, decide what a shim does with its library:

1. **Expose the whole library.** The shim presents everything the library
   implements, not the library's shipped default posture. Botan is the primary
   target and the other shims are cross-checks, so a Botan default that hides a
   feature must not hide it from the suite: when Botan's default policy stopped
   offering finite-field DH (commit 52007ebf58), `botan_shim` re-enabled the RFC
   7919 groups. A capability that can be reached only through configuration is
   still a capability.
2. **Let the test set the UUT's local policy.** A feature that is on cannot be
   tested for the off case, and most negotiation negatives need the UUT to
   *refuse* something it could do. The `.plzn` `uut client|server { ... }` block is the
   control surface: it flows `ast -> ir::UutConfig -> ShimConfig`, every field
   is applied by every shim that can, and the test author sees one vocabulary.

### Conventions

- **List-valued knobs are exact sets.** `curves: [x25519, secp256r1]` means
  those and nothing else; whatever is absent is disabled. This is how a
  feature-disabled negative is written today
  (`tls13_ffdhe_only_client_disabled_server`, `tls13_serverhello_ffdhe_unoffered`,
  `tls13_hrr_ffdhe_unoffered`): pin the list without the feature, then have plzn
  offer or select it. Boolean and enum knobs default to the library's capability
  posture (rule 1). Every test still declares `uut.versions` explicitly.
- **A knob a library cannot apply is a SKIP, never a silent no-op.** The shim
  reports the result case `unsupported_config` (exit 16) before dialing, naming
  the knob and why (`report_unsupported("extended_master_secret", ...)` in the
  C++ shims, `check_policy` in the rustls shim), and `plzn run` prints
  `[SKIP] <id> — <backend> cannot apply: uut.<knob>: <why>`, counts it as
  skipped, and lists it in the `--- skipped on <backend> (N) ---` block after
  the summary (BoGo's UNSUPPORTED list). The same case covers the protocol:
  `rustls has no DTLS` is a SKIP, not a FAIL. Botan, OpenSSL, LibreSSL, GnuTLS,
  wolfSSL, Go, and rustls likewise reject a DTLS 1.3 configuration before dialing;
  BoringSSL is currently the only DTLS 1.3 shim. The same refusal covers the
  OFFER: `ShimConfig.requires` carries the suites and groups the
  `peer.capabilities` selectors produce (any-of), plus `renegotiate_freely` for a `renegotiate` step and the
  external `psk`; every shim checks them against its library before dialing
  and refuses with the reason (rustls: its crypto provider; Botan:
  `Ciphersuite::by_id(id)->valid()` and `Group_Params::is_available()`;
  OpenSSL: a scratch context with `ALL:COMPLEMENTOFALL` at security level
  0, so a `uut` restriction on the real context never masquerades as a gap).
- **Every suite the library implements is on offer.** With no `uut client|server {
  cipher_suites }`, the Botan shim's `ciphersuite_list` is the policy's own
  order followed by every other suite `all_known_ciphersuites()` reports
  usable for the version; the OpenSSL shim sets `ALL:COMPLEMENTOFALL` (and
  drops to security level 0 only when a NULL or CCM_8 suite is in play, so
  the level's other effects stay out of unrelated tests). GnuTLS starts from
  `NORMAL`, but selectively admits the SHA-256 or SHA-384 record MAC when a
  test requires one of the TLS 1.2 CBC suites that `NORMAL` excludes. With `uut client|server {
  cipher_suites }` the list is exactly the configured ids the build can run. No `.plzn` file needs a `skip` line for
  a capability gap any more; `skip <backend> "why"` is reserved for genuine
  behavioural differences and its reason is printed in the skip log.
- **The shim follows the per-backend expectation.** `for_program` takes the
  backend label and resolves `expect ... if <backend>` the way the runtime
  does, so a per-library `ok` or alert override is self-checked consistently.
- **An abandoned handshake is not self-checked.** An `expect ok` flow without
  plzn's Finished sets `expect.handshake_abandoned`; the shim accepts success
  or a handshake failure from the abrupt close (only crashes and local errors
  count). Before this, such cases ran on Botan alone because only its shim
  reported success on a mid-handshake close.
- **Flush the alert before closing (rustls and GnuTLS).** rustls queues its fatal alert
  and `complete_io` returns the error before writing it; closing a socket with
  unread data then sends an RST that can discard the alert in flight. The
  rustls shim now writes the pending alert, half-closes and drains, so every
  "rustls tears the connection down" observation in the corpus turned out to
  be this shim artifact and is pinned to the real alert. GnuTLS instead returns
  record-processing failures without automatically generating the appropriate
  alert; its shim calls `gnutls_alert_send_appropriate` before the shared socket
  performs the same half-close and drain.
- **The shim self-checks for success when the expected failure is a warning.**
  `ShimConfig::for_program` tells the shim to expect its handshake to fail for
  every non-`ok` expectation EXCEPT a warning-level alert: the peer keeps the
  connection after `no_renegotiation`, so the shim's flow succeeded and an
  "expect failure" self-check would report `unexpected_success`.
- **Role-independent names.** One knob covers both roles where the library
  concept is the same (`renegotiation` governs initiating and accepting); the
  shim applies it to whichever side it plays.

### Corpus-enabled knob matrix

What each library can switch, from its API. "partial" = only some values.

| `uut` knob | Botan (`TLS::Policy`) | OpenSSL 3 | rustls 0.23 | Status |
|---|---|---|---|---|
| `versions: [...]` (serialized as min/max bounds) | `allow_tls12/13`, `allow_dtls12` | `set_min/max_proto_version` | `versions` | done |
| `cipher_suites: [...]` | `ciphersuite_list` | `set_cipher_list` / `set_ciphersuites` | provider `cipher_suites` | done |
| `curves: [...]` | `key_exchange_groups` (absent: the default policy's groups plus the RFC 7919 FFDHE groups and the pure ML-KEM groups it leaves out) | `set1_groups` (absent: `DEFAULT` plus every group the build has, ML-KEM hybrids and brainpool included) | provider `kx_groups` (aws-lc-rs: X25519, P-256/384, X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, MLKEM1024) | done |
| `signing_prefs: [...]` / `verify_prefs: [...]` | `allowed_signature_schemes` / `acceptable_signature_schemes` | server: `set1_sigalgs_list` (sign) / `set1_client_sigalgs_list` (accept); client: both share `set1_sigalgs_list`, so the pair is refused unless equal | verify: provider algorithms; sign: fixed by the key | done (`uut client|server { signing_prefs, verify_prefs }`) |
| `require_client_cert` / `request_client_cert` / `verify_peer` | `require/request_client_certificate_authentication`, callbacks (a requested client chain is always verified) | `set_verify` modes | `WebPkiClientVerifier` (`allow_unauthenticated` for a request), `with_no_client_auth` | done |
| `--cert rsa \| ecdsa \| ecdsa-p384 \| ecdsa-p521 \| ed25519 \| rsa-pss` (server key kind; `requires.server_key`, a string or a list, tells a shim CLIENT what plzn's server may present -- refused only when none is verifiable) | loads any; refuses `rsa-pss` (no rsa_pss_pss_* schemes) | loads any | loads any but RSASSA-PSS keys (no rustls signer, no webpki SPKI); P-521 loads and verifies on aws-lc-rs | done; see "Certificate chains" for several chains |
| `alpn_advertise` / `alpn_select` / `expect_alpn` / `alpn_decline` | callbacks / `application_protocol` | `set_alpn_select_cb` / `set_alpn_protos` / `get0_alpn_selected` | `alpn_protocols` | done |
| `srtp_profiles` / `expect_srtp_profile` | `Policy::srtp_profiles` / session summary | `SSL_CTX_set_tlsext_use_srtp` / `SSL_get_selected_srtp_profile` | no DTLS | done |
| `server_preference: bool` | `server_uses_own_ciphersuite_preferences`; groups via `choose_key_exchange_group` | `SSL_OP_CIPHER_SERVER_PREFERENCE` (suites and groups) | `ignore_client_order` (suites) | done; rustls: suites only (a group-order case is `skip rustls`) |
| `renegotiation: none \| client \| server \| both` | `allow_client/server_initiated_renegotiation`, `allow_insecure_renegotiation` | `SSL_OP_NO_RENEGOTIATION`, `SSL_OP_ALLOW_CLIENT_RENEGOTIATION` | none only | done; an explicit knob overrides the auto-set `renegotiate_freely`; rustls refuses every value but `none` |
| `session_tickets: N` (0 = off) | `new_session_tickets_upon_handshake_success`, session manager | `set_num_tickets`, `SSL_OP_NO_TICKET` | `send_tls13_tickets`, `Resumption` | done (0 = `Session_Manager_Noop` / `SSL_SESS_CACHE_OFF` / `NoServerSessionStorage`) |
| `max_cert_list: N` | `maximum_certificate_chain_size` | `SSL_CTX_set_max_cert_list` | no configurable limit | done (rustls SKIPs) |
| `extended_master_secret: require \| allow \| off` | `require_extended_master_secret` (require/allow) | `SSL_OP_NO_EXTENDED_MASTER_SECRET` (off/allow) | `require_ems` (require/allow) | done; the value a library lacks (`off` on Botan/rustls, `require` on OpenSSL) SKIPs |
| `encrypt_then_mac: bool` | `negotiate_encrypt_then_mac` | `SSL_OP_NO_ENCRYPT_THEN_MAC` | no CBC (`true` SKIPs) | done |
| `middlebox_compat: bool` | `tls_13_middlebox_compatibility_mode` | `SSL_OP_ENABLE_MIDDLEBOX_COMPAT` | always on (`false` SKIPs) | done |
| `min_key_update_interval_ms: N` | `minimum_key_update_interval_ms` (the shim's TLS monotonic clock is real time, so the limit counts) | no rate limit (`0` only) | no rate limit (`0` only) | done |
| `psk_secret: "hex"` / `psk_identity: "..."` | `Credentials_Manager::psk` / `find_preshared_keys` | PSK callbacks | no external PSK | done; overrides the mirrored `psk { }` block on the shim side only (wrong-key / unknown-identity negatives) |
| `client_cert: valid \| untrusted \| none \| expired` | `Credentials_Manager::cert_chain` (empty for `none`) | `use_certificate_chain_file` (nothing loaded for `none`) | `with_client_auth_cert` / `with_no_client_auth` | done (client role); the files are `shims/testdata/{client,untrusted_client,expired_client}_{cert,key}.pem` |
| `renegotiate_after_handshake: bool` | `Channel::renegotiate` after the first echo | `SSL_renegotiate` after the first echo; the next `SSL_read` runs the handshake (an `SSL_do_handshake` loop rejected application data crossing the ClientHello as an unexpected record) | never renegotiates (SKIPs) | done (client role, TLS 1.2 and DTLS 1.2); plzn's TLS 1.2 and DTLS servers take it stepped, unprompted, or refuse it with no_renegotiation |
| `hello_request_after_app_data: bool` | `Channel::renegotiate(true)` after the first echo (server HelloRequest) | `SSL_renegotiate` + one `SSL_do_handshake` after the first echo | never renegotiates (SKIPs) | server role, TLS 1.2; RFC 5246 7.4.1.1 protected-resource renegotiation |
| `require_client_cert_on_renegotiation: bool` | policy flag flipped before the HelloRequest, so only the renegotiation requests/verifies a client cert | `SSL_set_verify(PEER\|FAIL_IF_NO_PEER_CERT)` before `SSL_renegotiate` | n/a (SKIPs with the knob above) | server role; the initial handshake stays anonymous |
| `half_rtt_data: [...]` | `Channel::send` while `is_active()` and before the client's Finished | `SSL_write_early_data` on the server (not wired: SKIPs) | `send_half_rtt_data` (not wired: SKIPs) | done on Botan (TLS 1.3 server role) |
| `sni: bool` (client) / `expect_server_name` | `Server_Information` | `set_tlsext_host_name` | `enable_sni` | config only |
| `record_size_limit: N` | `Policy::record_size_limit` | unavailable | unavailable | Botan + GnuTLS (`gnutls_record_set_max_recv_size`); other shims skip |
| `max_early_data: N` plus explicit `send/recv EarlyData` | none (clean `unsupported_config`) | `SSL_CTX_set_max_early_data`, `SSL_write_early_data`, `SSL_read_early_data` | `max_early_data_size`, `ClientConnection::early_data`, `ServerConnection::early_data` | done on OpenSSL, GnuTLS, and rustls; wolfSSL is wired behind `WOLFSSL_EARLY_DATA` + `HAVE_SESSION_TICKET`; Botan unsupported |
| `post_handshake_auth: bool` | none (no server-side RFC 8446 4.6.2) | `SSL_CTX_set_post_handshake_auth` + `SSL_verify_client_post_handshake` after the first app-data record | none | done (OpenSSL only; Botan and rustls refuse the knob) |
| `chain:` / `client_chain:` (A, 2026-09-08): `credentials.chains` = every chain a shim SERVER holds, in preference order (`cert_file` / `key_file` stay the first, `second_cert_file` / `second_key_file` the second; an empty list with an empty `cert_file` = no chain, `chain: []`); `credentials.client_chains` = the credentials a shim CLIENT picks from for a CertificateRequest (`cert_file` / `key_file` the first; empty = answer with an empty Certificate); `requires.server_keys` = every key type plzn's server may present (`server_key` the first) -- a shim client refuses only when none is verifiable. `key_type` spellings: `rsa-2048`, `rsa-pss`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519` | selects by key type and signature scheme; the Botan API does not expose TLS 1.2 certificate groups | native key slots plus callbacks for same-slot ECDSA curves and client certificate types | resolver applies TLS 1.2 suite/group and signature-scheme criteria; its client resolver cannot inspect TLS 1.2 certificate types | done for Botan/OpenSSL/rustls/Go and GnuTLS servers; GnuTLS clients, wolfSSL and BoringSSL report unsupported multi-chain configuration |
| `ocsp_stapling: bool` (+ `credentials.ocsp_file`, a DER OCSPResponse the runner generates for the server cert) | `Credentials_Manager::ocsp_response` (TLS 1.2 CertificateStatus, TLS 1.3 status_request in the leaf entry) | `SSL_CTX_set_tlsext_status_cb` + `SSL_set0_tlsext_status_ocsp_resp_ex` (OpenSSL 3.6 drops the staple for a self-signed leaf) | `CertifiedKey.ocsp` | done |
| `compress_certificate: bool` | none (RFC 8879 not implemented: the offer is ignored unparsed) | `SSL_CTX_compress_certs` + `set1_cert_comp_preference` (zlib/brotli/zstd as built), client certs decompressed too | `cert_compressors` / `cert_decompressors` (zlib, brotli) | done; `peer.capabilities: [compress_cert]` independently controls plzn's offer |
| `security: {min_rsa_bits, min_dh_bits, ...}` | `minimum_*_bits`, `check_peer_key_acceptable` | `set_security_level` | fixed | later |
| DTLS `mtu`, `initial_timeout_ms`, `require_cookie` | `dtls_default_mtu`, `dtls_initial_timeout`, `dtls_server_require_cookie_exchange` | `SSL_set_mtu` + `SSL_OP_NO_QUERY_MTU`, `DTLS_set_timer_cb`, `SSL_OP_COOKIE_EXCHANGE` | no DTLS | done in `uut` |
| DTLS `dtls_max_retransmissions`, `dtls_max_timeout_ms` | `dtls_maximum_retransmissions`, `dtls_maximum_timeout` | the `DTLS_set_timer_cb` schedule (doubling, capped, budget-limited) on the shim's frozen clock | no DTLS | done in `uut` |
| DTLS `dtls_require_cookie` (strict) | `dtls_cookie_secret` (HMAC over client identity + parameters) | cookie callbacks: HMAC-SHA256 over the ClientHello random, generation-tagged for `rotate_cookie_secret` | no DTLS | done; `rotate_cookie_secret` is a `C` control frame |

Botan has ~68 overridable policy methods; the rows above are the ones with a
cross-library meaning or a negotiation negative behind them. Botan-only knobs
worth exposing under a `botan { ... }` sub-block later: `hide_unknown_users`,
`include_time_in_hello_random`, `record_padding_bytes`,
`maximum_certificate_chain_size`, `only_resume_with_exact_version`,
`abort_connection_on_undesired_renegotiation`, `dtls_maximum_hello_verify_requests`.

### Order of work

1. DONE: plumbing. `unsupported_config` exit case and its SKIP mapping; the
   `uut` parser accepts the new keys (with value validation and a listing of
   every key on an unknown one); ShimConfig carries them; each shim applies
   or refuses.
2. DONE: first knobs, each with the corpus case that exercises it:
   `server_preference` (`tls13_server_preference_suites` /
   `tls13_client_preference_suites` flip the selection on all three;
   `tls13_server_preference_groups`), `renegotiation: none`
   (`tls12_renegotiation_refused`, `client/tls12_client_refuses_renegotiation`:
   every library answers a `no_renegotiation` warning on both sides),
   `extended_master_secret` (`tls12_ems_required_client_without`,
   `tls12_ems_off_server`), `encrypt_then_mac: false` (`tls12_etm_off_server`),
   `middlebox_compat: false` (`tls13_middlebox_compat_off`). `session_tickets`
   is plumbed but has no corpus case yet: plzn's client does not advertise
   psk_key_exchange_modes outside a `session` test, so a server never issues a
   ticket to refuse.
3. DONE: hand-written `skip <backend>` lines that only encoded a capability gap
   are gone (75 directives -> 18, all with reasons); the shim refuses instead.
4. Later knobs: `early_data`, `post_handshake_auth`, `ocsp_stapling`,
   `cert_compression`, security minima, a `botan { ... }` sub-block.

## Layout

```
shims/
  DESIGN.md            -- this file
  Makefile             -- builds libplzn-shim.a + detected shims + unit tests
  build/
    libplzn-shim.a      -- static C++ helper library linked by every C++ shim
  common/              -- shared C++20 helper library (no library deps)
    plzn_shim.h             -- single public header for the helper library
    json.cpp                -- self-contained JSON parser
    shim_config.cpp         -- typed config + JSON -> ShimConfig
    shim_socket.cpp         -- dial + framed (TLS/DTLS) socket IO
    shim_error.cpp          -- canonical error names and result reporting
    app_data_protocol.cpp   -- framed application-data responder
    test_common.cpp          -- unit tests for the helper library
  botan/
    botan_shim.cpp
  openssl/
    openssl_shim.cpp
  libressl/
    libressl_shim.cpp
    libressl-expectations.json
  gnutls/
    gnutls_shim.cpp
  wolfssl/
    wolfssl_shim.cpp
  boringssl/
    boringssl_shim.cpp
    packeted_bio.cpp
  rustls/
    Cargo.toml
    src/main.rs
```

## LibreSSL

`libressl/libressl_shim.cpp` is derived from the OpenSSL shim. LibreSSL keeps
the OpenSSL 1.1 SSL API but none of OpenSSL 3's provider, `EVP_MAC`,
client-hello-callback or `DTLS_set_timer_cb` surface, so the shim differs in
these ways:

- **Capability refusals.** LibreSSL has no external PSK, TLS 1.0/1.1 or DTLS
  1.0 (any `uut` bound below 1.2 is refused), TLS 1.3 tickets on the server or
  TLS 1.3 resumption on the client, 0-RTT, post-handshake authentication,
  KeyUpdate initiation, extended master secret, encrypt-then-MAC,
  `record_size_limit`, raw public keys, certificate compression, Ed25519 or
  RSA-PSS (SPKI) certificates, or signature-algorithm list configuration. It
  holds one RSA and one ECC certificate with no callback to choose among
  several of one type. All of these report `unsupported_config`.
- **DTLS timer.** LibreSSL's retransmit timer reads `gettimeofday` (so the
  same virtual-clock preemption as the OpenSSL shim works) but its schedule
  is fixed: 1 s, doubling to 60 s, failing after 12 timeouts. Other
  `initial_timeout_ms` / `dtls_max_*` values and live `set_timeout` rescaling
  are refused. `expect next_timeout` reads `DTLSv1_get_timeout` directly,
  which is exact on the frozen clock.
- **Clean EOF.** There is no `SSL_OP_IGNORE_UNEXPECTED_EOF`; the shim marks
  the connection shut down itself when the runner closes TCP without
  `close_notify`, otherwise `SSL_free` evicts the session (the TLS 1.0 rule
  RFC 5246 7.2.1 relaxed) and session-ID resumption could never be tested.
- **Failures without an error.** Some LibreSSL rejections (refusing
  client-initiated renegotiation, an unknown record type, a stray CCS) fail
  `SSL_read` with neither a queued error nor, sometimes, an alert, so
  `SSL_get_error` reports `SSL_ERROR_SYSCALL`. The shim treats that (and any
  read after an info-callback-observed fatal alert) as a failed flow, unless
  errno shows the peer reset or closed the pipe.
- **Default suites.** With no `cipher_suites`, LibreSSL's own `DEFAULT`
  (`ALL:!aNULL:!eNULL`), adding `eNULL` only when the peer offers nothing but
  NULL-encryption suites.
- **Expectation sidecar.** `libressl-expectations.json` (copied beside the
  binary) pins the matrix points whose LibreSSL outcome differs from the rest
  of their declaration; everything else is an inline `expect/xfail/skip
  libressl` in the suite.

Notable LibreSSL 4.3.2 findings recorded as `xfail`: a TLS 1.3 AEAD failure
closes without the RFC 8446 5.2 `bad_record_mac`; a silently discarded
bad-MAC DTLS record leaves an error queued, so `SSL_read` reports
`SSL_ERROR_SSL` and kills the association; the DTLS 1.2 client fails every
abbreviated handshake with an internal error (`ssl3_connect` never frees the
transcript on the resumed DTLS path); a TLS 1.2 server resumes a session whose
cipher suite the new ClientHello no longer offers; and the client offers RC4,
static RSA, DHE and SHA-1 signature schemes by default.

LibreSSL 4.4.0 (retriaged 2026-11-03) fixed several of the earlier pins: the
client checks that the ALPN selection was offered (illegal_parameter); a
HelloRetryRequest naming an unlisted group, or one the client already
key-shared (including its second share), draws illegal_parameter instead of a
silent close; malformed, non-uncompressed or off-curve ECDH points and TLS 1.3
key shares draw decode_error instead of internal_error or a close; a TLS 1.3
ClientHello with no shared group draws handshake_failure and one without
supported_groups draws missing_extension; and the DTLS application-data queue
is gone, so data before Finished is discarded. Two defaults tightened: the
client no longer sets `SSL_OP_LEGACY_SERVER_CONNECT`, so a ServerHello without
renegotiation_info is a handshake_failure, and a compressed ECDH point is
rejected although only uncompressed was ever advertised. An extra DTLS
Finished after the handshake is now dropped silently, as OpenSSL does.

## Build

`make` in this directory builds `build/libplzn-shim.a` and every shim it can
find libraries for. All six C++ shims and the helper unit tests link this
archive. Go and rustls keep their native support implementations. The helper
library has no TLS-library dependency, and its unit tests run under
`make check`. The Botan shim needs a Botan install (headers + `libbotan-3`), the
OpenSSL shim needs OpenSSL 3.x, the LibreSSL shim finds a side-by-side LibreSSL
install (`/usr/lib/libressl/pkgconfig`, or `PLZN_LIBRESSL_ROOT=<prefix>`) and
links it with an rpath so it never resolves OpenSSL's same-named libraries, BoringSSL requires a built checkout explicitly
selected with `PLZN_BORINGSSL_ROOT` (there is no default), and GnuTLS/wolfSSL need their
development packages. The rustls shim is a separate, non-default Cargo
workspace member and is built explicitly by this Makefile. Installed-library
detection uses `pkg-config`. Pass the resulting binary directly to
`plzn run --shim`; no installation or registration step is required. The
`PLZN_*_SHIM` variables remain an internal convenience for Rust interop tests
that construct a `ShimKind` rather than exercising the CLI.
Those look beside the running executable and under the current directory's
development build paths, never at a compile-time checkout path.

Both the helper archive and the TLS library files are prerequisites of each
C++ shim binary, so `make` relinks the shim when either library is rebuilt or
upgraded and does nothing otherwise; `check.sh` runs it before every test run.
`PLZN_BOTAN_ROOT=<checkout>` links a Botan source tree instead of the installed
package (rpath). Persist the selection with
`make configure PLZN_BOTAN_ROOT=<checkout>`; later plain `make` runs read
`build/config.mk`.

A shim that dies by signal never reaches `report_result`; the runner classifies
the wait status itself and reports the case as `[CRASH] ... killed by signal N`.
A shim that exits before dialing the runner is reported immediately with its
exit code and `PLZN-RESULT` detail rather than after the accept deadline.

### Using the helper library out of tree

Build just the archive with a C++20 compiler and `ar`; this target does not
build any shim or require a TLS library, Rust, or Go:

```sh
make -C /path/to/plzn/shims libplzn-shim
```

The single public header, `shims/common/plzn_shim.h`, exposes JSON parsing,
`ShimConfig`, `ShimSocket` with TLS/DTLS framing, result reporting, and the
application-data responder in the `plzn` namespace. It depends only on
standard C++ headers. In your shim source, include:

```cpp
#include "plzn_shim.h"
```

Link `shims/build/libplzn-shim.a` after your source or object files.
For example, an out-of-tree OpenSSL shim can use:

```sh
PLZN_ROOT=/path/to/plzn
c++ -std=c++20 -I"$PLZN_ROOT/shims/common" \
    $(pkg-config --cflags libssl libcrypto) my_openssl_shim.cpp \
    -L"$PLZN_ROOT/shims/build" -lplzn-shim \
    $(pkg-config --libs libssl libcrypto) -o my_openssl_shim
```

The helper code is linked into the executable, so the resulting shim does not
need the archive or source checkout at runtime. Out-of-tree build rules should
track the archive and public header as prerequisites, just as the in-tree
shim rules do.
