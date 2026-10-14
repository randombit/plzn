# client-under-test corpus

`uut client` tests: plzn plays the TLS **server** and the unit under test is an
external TLS **client**. This directory combines positive negotiation sweeps,
ClientHello conformance, certificate and PSK authentication, resumption,
selection, and adversarial server-flight cases. Each filename states the TLS
version and behavior being exercised; test IDs use the `client/` namespace.

This is enabled by `match_client_hello_field` in `src/tls/driver.rs`,
wired into the ClientHello receive path of both server drivers
(`src/tls/server12.rs`, `src/tls/server13.rs`).

`shim_corpus::client_corpus` (`cargo test --test shim_corpus -- --ignored`)
runs the whole directory against the config-file shims, so adding a case is
just dropping a `.plzn` file here. Reproduce manually:

```
plzn run --shim shims/build/botan_shim suite/client/
```

### Matcher semantics (`recv ClientHello { ... }`)

| Field | Type | Semantic |
|-------|------|----------|
| `legacy_version` | u16 | exact equality |
| `random` | bytes | exact equality (32 bytes) |
| `legacy_session_id` / `session_id` | bytes | exact equality |
| `compression_methods` / `legacy_compression_methods` | u8 list | exact equality (order-sensitive) |
| `cipher_suites` / `ciphers` | u16 list | **contains-all** — passes iff every listed suite appears in the offer (order/length independent) |
| `lacks_cipher_suite` | u16 | passes iff the suite or signalling value is absent |

### Cases

| File | RFC | Asserts |
|------|-----|---------|
| `tls13_ch_legacy_version.plzn` | 8446 §4.1.2 | TLS 1.3 CH pins legacy_version to 0x0303 |
| `tls13_ch_null_compression.plzn` | 8446 §4.1.2 | exactly one null compression method |
| `tls13_ch_mandatory_suite.plzn` | 8446 §9.1 | offers TLS_AES_128_GCM_SHA256 (0x1301) |
| `tls12_ch_legacy_version.plzn` | 5246 §7.4.1.2 | TLS 1.2 CH client_version is 0x0303 |
| `tls12_ch_null_compression.plzn` | 5246 §7.4.1.2 | offers only the null compression method |
