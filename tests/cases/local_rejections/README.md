# Local rejection self-tests

These fixtures test plzn's server implementations. A real-library shim supplies
ordinary client traffic; each case expects **plzn** to reject it. They belong
outside the UUT conformance corpus in `suite/`.

- `tls/client_auth/` and `dtls/client_auth/` exercise expired and untrusted client
  certificates in the TLS 1.2, TLS 1.3, and DTLS 1.2 server drivers.
- `tls/psk/` and `dtls/psk/` exercise unknown identities, mismatched secrets,
  and TLS 1.3 binder validation.
- `tls/tls13_no_signing_scheme.plzn` exercises plzn's failure to select a
  signing scheme for its server key from the client's advertised preferences.

Unit tests cover certificate validation and chain selection in isolation.
These cases also cover the protocol drivers and their reported local alerts.
They use ordinary shim configuration and require no special shim behavior.

Run them with `cargo test --test local_rejections`. Botan and OpenSSL run all
14 cases; rustls runs the five TLS certificate cases, and Go runs the four
client-auth cases (it cannot configure signature-scheme preferences). Tests
skip when a backend binary is absent. With a backend present, every selected
case must pass and report a local rejection; a skipped or expected-failure
case fails the integration test. `cargo test` and `./check.sh` include them.
