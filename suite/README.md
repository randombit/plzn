# suite -- plzn conformance corpus

`.plzn` tests that run against a production TLS library through its config-file
shim. This is the corpus plzn exists to run; the plzn-internal fixtures (parser,
lowering, and expectation-matcher unit tests) live under `tests/cases/` instead.

The layout follows protocol, shim role, and scenario kind. Certificate type is
not a directory dimension: every test explicitly selects its own `chain:`, and
certificate-specific filenames include `_ecdsa_`, `_ed25519_`, or `_rsa_pss_`.

| Directory | Shim role | Contents |
|-----------|-----------|----------|
| `server/` | server (plzn = client) | TLS handshakes and sweeps, malformed ClientHello/extension families, record and handshake mutations, certificate/signature variants, static-RSA oracle resistance, resumption, renegotiation, and KeyUpdate |
| `client/` | client (plzn = server) | suite/group/signature sweeps, ClientHello conformance, authentication, PSK, resumption, selection, adversarial server flights, renegotiation, and KeyUpdate |
| `dtls/` | both | DTLS 1.2 sweeps and certificate variants, cookies, epochs, replay, fragmentation, retransmission/timer policy, resumption, renegotiation, and malformed records |

Files are named `tls{12,13}_<category>_<detail>.plzn` (`dtls12_*` under
`dtls/`). Each directory is run against each fully triaged corpus backend
(`tests/shim_corpus.rs`: Botan, OpenSSL, LibreSSL, rustls, and Go) by
`cargo test --test shim_corpus -- --ignored`, which `check.sh` runs; a plain
`cargo test` leaves the corpus out. GnuTLS and
wolfSSL currently have targeted interop coverage. Per-case `skip <backend>` directives cover genuine
library differences (static-RSA and CBC on rustls, DTLS, etc.).

Run one directory by hand:

```
plzn run --shim shims/build/botan_shim suite/server/
plzn run --shim shims/build/openssl_shim suite/client/
```

Every case explicitly names its server chain (or explicitly requests no chain),
so no directory-level certificate option is needed.

The inventory currently contains 951 files and 2,646 source test declarations;
matrices and repeats expand these into thousands of concrete cases.
`tests/suite_inventory.rs` rejects duplicate IDs, byte-equivalent scenarios,
provenance-labelled filenames, and IDs outside the canonical `server/`,
`client/`, and `dtls12/` namespaces. It also fixes the complete mandatory-message
omission inventory and the TLS 1.3 signature-scheme/`signature_algorithms_cert`
matrices. See
`notes/audit/test_inventory.md` for the audit and the intentionally retained
coverage dimensions.
