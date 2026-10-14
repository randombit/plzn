# The plzn language

This is a reference for the `.plzn` language accepted by the lexer, parser,
schema checker, and lowering pass. For commands, library-specific behavior,
and detailed field examples, see [USAGE.md](USAGE.md). Run `plzn lint file.plzn` to check all four
stages without connecting to a peer; run `plzn fmt file.plzn` to format a file.

Acceptance and execution support are separate: a valid test can still require
a protocol, credential, or option that a particular shim does not support.
Unsupported shim configuration is reported separately from a test failure.

Complete examples are marked `plzn` and checked by
[`tests/dsl_docs.rs`](../tests/dsl_docs.rs). Other code blocks show fragments or
syntax notation. In syntax notation, `NAME`, `N`, and similar uppercase words
are placeholders; square brackets denote optional syntax only where stated.

## A complete test

```plzn
plzn tls "tls13/application-data" {
  chain: [ecdsa_p256]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData { size: 32 }
    recv AppData { size: 32 }
  }
  expect ok
}
```

`uut` names the unit under test: `uut server` makes plzn the client;
`uut client` makes plzn the server. Every `send` and `recv` is from **plzn's**
perspective. A `send` constructs a message; a `recv` consumes and checks one.
The `handshake` preset supplies the appropriate handshake for the configured
role, version, and capabilities.

The equivalent basic client test needs no explicit application-data exchange:

```plzn
plzn tls "tls13/client-handshake" {
  chain: [ecdsa_p256]
  uut client {
    versions: [tls13]
  }
  flow handshake {}
  expect ok
}
```

## Lexical rules

- A file contains zero or more `plzn PROTOCOL "name" { ... }` declarations.
  `plzn` processes only `plzn tls "name" { ... }`, for both TLS and DTLS.
  Other protocols, including `plzn quic` and `plzn http`, are ignored even in
  mixed files. Their bodies can use different syntax; the shared envelope
  requires balanced braces, with double-quoted strings (backslash escapes)
  and `#` line comments shielding any braces they contain. The formatter
  preserves other protocols' declarations verbatim. The old `test` header
  is not supported.
- Spaces and tabs separate tokens. Indentation is cosmetic; braces delimit
  blocks. Newlines terminate statements, and a closing brace can terminate the
  last statement in its block. There are no semicolon terminators.
- `#` starts a comment through the end of the line.
- Identifiers start with a letter or `_`, followed by letters, digits, `_`, or
  `-`. Keywords and message names are case-sensitive.
- Integers are decimal or hexadecimal with a `0x` prefix. A leading `-` is
  accepted in signed-value contexts. Individual fields impose their own ranges.
- Strings use double quotes. Recognized escapes are `\n`, `\r`, `\t`, `\\`,
  `\"`, and `\0`. Literal newlines are not allowed inside strings.
- `$name` refers to a matrix binding, or to a capture where capture syntax is
  explicitly supported. Strings do not interpolate variables.

Commas are context-specific, not general statement separators. Configuration
fields and ordinary message fields may be comma- or newline-separated. Flow
steps, extension delta lines, matrix axes, and PSK fields are line-oriented.
Use comma-separated lists. Ordinary field-value lists accept trailing commas;
matrix lists, session qualifiers, and expectation alternatives do not.

## Test structure and scope

A test requires a `chain:` declaration and exactly one `uut` block. It then
contains either one flow and its expectation, or a sequence of named sessions.

| Scope | Declarations |
| --- | --- |
| File | `plzn tls "name" { ... }` |
| Test configuration | `chain: [...]`, `client_chain: [...]`, `uut client\|server { ... }`, `peer { ... }`, `psk { ... }`, `matrix { ... }`, `repeat N` |
| Test metadata | `rfc N [section PATH]`, `skip BACKENDS ["reason"]`, `xfail BACKENDS ["reason"]` |
| Single-connection test | One `flow`, one primary `expect`, optional backend expectation overrides and `assert` lines |
| Multi-connection test | Ordered `session NAME [...] { ... }` blocks, each with its own flow, expectation, and assertions |

Do not mix sessions with test-level flows, expectations, or assertions.
Configuration stays at test scope; sessions inherit it. Put the primary,
unconditional `expect` before its backend overrides.

Test-level `matrix`, `psk`, and `repeat` declarations may occur only once.
Fields within `uut`, `peer`, `psk`, and each PSK `offer` must be unique;
duplicates are errors even when their values agree. Multiple `offer` blocks
remain supported.

RFC metadata is repeatable. A section is an unquoted dotted path, for example
`rfc 8446 section 4.1.2` or `rfc 5246 section B.4`.

`skip` and `xfail` take one or more comma-separated backend identifiers and an
optional reason:

```text
skip BACKEND_A, BACKEND_B "reason"
xfail BACKEND_C "tracked discrepancy"
```

`skip` prevents execution on the named backend. `xfail` marks a failure as
expected; an unexpected pass is a failure of that annotation. Backend IDs used
by the bundled shims are `botan`, `openssl`, `rustls`, `gnutls`, `wolfssl`,
`boringssl`, and `go`.

### Credentials

`chain:` selects the **server's** credentials regardless of which side plzn
plays. `client_chain:` selects the client's credentials and defaults to
`[default]` when omitted.

Accepted chain names are `default`, `rsa_2048` (also `rsa`),
`rsa_2048_ecdsa_signed`, `rsa_pss`, `ecdsa_p256`, `ecdsa_p384`, `ecdsa_p521`,
and `ed25519`. Write chain lists on one line, with commas between names.

`chain: [default]` explicitly selects the run's default credential; it does not
make the declaration optional. `chain: []` requests no server certificate,
for example for a PSK connection. Certificate-based key-exchange requirements
are checked against the declared chain types. A list of several chains is a
credential selection set, not a list of certificates concatenated into one
certificate chain.

## UUT and peer configuration

`uut` configures the library being tested. `peer` configures plzn's endpoint.
Changing plzn's offers or a sent field does not implicitly configure the UUT.

### `uut client` / `uut server`

`versions` is required: a nonempty list of distinct `tls10`, `tls11`, `tls12`,
`tls13`, `dtls12`, or `dtls13`. Do not mix TLS and DTLS in one list. The **first** entry chooses
plzn's driver; all entries are enabled on the UUT. A session's `version:` can
choose a different entry from that list. The driver is fixed rather than a
version-negotiating meta-driver; use a higher `ClientHello.legacy_version`
override when exercising negotiation down to the first entry. A matrix value
is accepted as `versions: [$version]`.

The following is the accepted field inventory. `bool` means bare `true` or
`false`; `u32` means a nonnegative integer fitting in 32 bits. Lists here are
typed configuration lists, not the general field-value expression language.
Omitted options leave their defaults to the harness/shim unless stated below.

| Field(s) | Value |
| --- | --- |
| `versions` | Version-name or version-matrix list; required; `$var` supported |
| `cipher_suites` | Cipher-suite list; names or permitted wire values; `$var` supported |
| `curves` | Named-group list; names or permitted wire values; `$var` supported |
| `signing_prefs`, `verify_prefs` | Signature-scheme lists |
| `require_client_cert`, `request_client_cert`, `verify_peer` | `bool` |
| `client_cert` | `valid`, `untrusted`, `none`, or `expired` |
| `alpn_advertise`, `alpn_select_from` | String lists |
| `alpn_select`, `expect_alpn` | String |
| `alpn_decline` | `bool` |
| `srtp_profiles` | SRTP-profile list |
| `expect_srtp_profile` | SRTP-profile name or permitted wire value |
| `server_preference` | `bool` |
| `renegotiation` | `none`, `client`, `server`, or `both` |
| `extended_master_secret` | `require`, `allow`, or `off` |
| `encrypt_then_mac`, `middlebox_compat` | `bool` |
| `session_tickets`, `max_early_data`, `max_cert_list` | `u32` |
| `record_size_limit` | Integer from 64 through 16385 |
| `key_update` | `bool` |
| `records_per_traffic_key`, `min_key_update_interval_ms` | `u32` |
| `compress_certificate`, `raw_public_key` | `bool` |
| `server_certificate_types`, `client_certificate_types` | Lists of `x509` and/or `raw_public_key`, without duplicates |
| `mtu`, `initial_timeout_ms`, `dtls_max_retransmissions`, `dtls_max_timeout_ms` | `u32` |
| `dtls_max_hello_verify_requests` | `u32` |
| `dtls_require_cookie`, `dtls_epoch0_restart` | `bool` |
| `psk_identity` | String |
| `psk_secret` | Nonempty, even-length hexadecimal string; whitespace permitted |
| `renegotiate_after_handshake`, `hello_request_after_app_data`, `require_client_cert_on_renegotiation` | `bool` |
| `half_rtt_data` | String list |
| `ocsp_stapling` | `bool` |
| `post_handshake_auth` | `request` or `require` |

`require_client_cert` and `request_client_cert` are server-UUT settings.
`max_early_data` also requires a server UUT with TLS 1.3 enabled.
`alpn_select` cannot be combined with a nonempty `alpn_select_from`.
`raw_public_key: true` is shorthand for the two certificate-type settings;
do not combine it with nonempty explicit certificate-type lists.

### `peer`

The peer block accepts `capabilities: [...]` and
`request_client_cert: true|false`. The latter is meaningful only with
`uut client`, where plzn is the server. It sends CertificateRequest and
accepts an empty Certificate, continuing without CertificateVerify. Non-empty
client chains and their CertificateVerify signatures are validated.
The former `peer.require_client_cert` setting is no longer supported;
use `peer.request_client_cert` to request the client Certificate message.

Capabilities are bare identifiers describing plzn's offers, selection filters,
or handshake mode. Versions belong in `uut.versions`, not this list.

| Capability category | Accepted tokens |
| --- | --- |
| Key exchange | `rsa`, `dhe_rsa`, `ecdhe_rsa`, `ecdhe_ecdsa`, `ecdhe`, `psk`, `ecdhe_psk`, `psk_ke`, `psk_dhe_ke` |
| Specific cipher selectors | `aes128_cbc_sha`, `aes256_cbc_sha`, `aes128_gcm_sha256`, `aes256_gcm_sha384`, `chacha20_poly1305_sha256`, `aes128_ccm_sha256`, `aes128_ccm_8_sha256` |
| Cipher/hash filters | `aead`, `cbc`, `gcm`, `ccm`, `ccm8`, `aria`, `camellia`, `des3`, `null`, `sha384`, `chacha20_poly1305` |
| Handshake modes | `session_ticket`, `session_id`, `hrr`, `second_hrr`, `offer_rpk`, `compress_cert` |
| Groups | The identifiers in `schema::GROUPS` |
| Signature schemes | The identifiers in `schema::SIG_ALGS` |

The group and signature capability lists are defined in
[`src/schema.rs`](../src/schema.rs). They are narrower than the complete wire
name registry: recognizing a wire name does not make it a peer capability or
an implemented cryptographic algorithm. Multiple suite filters constrain the
same selection; they are not independent test alternatives.
Selectors whose intersection contains no supported suites are rejected rather
than replaced by a default offer. Chain-dependent filtering is checked again
when `chain: [default]` is resolved for a run. With `uut server` and `chain: []`,
the client still offers suites so the UUT can reject the missing credentials.

Signature capabilities with `uut server` set plzn's advertised
`signature_algorithms`, in order, for TLS and DTLS. With `uut client`, they
configure plzn's TLS 1.2 server signing preferences; other server drivers
reject these capabilities because they do not implement that preference.

## Values and named constants

Message fields and extension values are typed. An identifier can be an enum
member or a named wire constant; its meaning depends on the field.
`plzn names` lists the wire-name registry. Known cipher suites, groups,
signature schemes, extensions, and other audited named domains must be
written by name where the checker requires it. Unassigned and GREASE wire
values may be numeric. A recognized name does not imply execution support.

The general field-value forms are:

| Form | Meaning |
| --- | --- |
| `N`, `0xNN`, `-N` | Integer, subject to the destination's bounds |
| `NAME` | Typed name or enum member |
| `"text"` | String; UTF-8 bytes in a byte field |
| `$axis` | Current integer matrix binding |
| `[VALUE, ...]` | List; nested lists flatten during lowering |
| `LO..HI` | Inclusive integer range; bounds may be matrix variables |
| `VALUE * COUNT` | Repetition; count may be a matrix variable |
| `zeros COUNT` | Zero bytes |
| `file "path"` | File bytes, read during lowering |
| `capture $name` | Capture a supported receive field instead of comparing it |

Repeating a string concatenates it into one string; repeating a list of
strings repeats its elements. Thus `"h2" * 2` is one string, whereas
`["h2"] * 2` supplies two entries. Byte lists must resolve to bytes; numeric
lists must fit the destination's element width. Expansion limits are enforced
to bound generated values and tests.

`file` paths are relative to the process's working directory, **not** the
`.plzn` file's directory. Linting reads these files because it runs lowering.

There is no general arithmetic-expression evaluator. `$axis + N` and
`$axis - N` are supported only in integer-or-variable positions, such as
repetition counts, range ends, and mutation indices. A scalar field written
as `field: $axis + 1` is not a general expression. Captures cannot be used as
matrix bindings or substituted into later sends.

Some typed lists also accept `KEY: VALUE` entries. In particular, a
ClientHello `key_share` extension accepts group entries with share
descriptors; this is extension-specific, not a general dictionary type.

### Raw bytes versus strings

Ordinary strings are text. `raw "..."` and `pad "..."` use hexadecimal bytes,
ignoring whitespace and requiring complete byte pairs. A raw segment is a hex
string or an integer encoded in big-endian form (minimal width for nonnegative
values). `BYTE * COUNT` repeats one byte, using the integer's low eight bits;
it does not repeat a multi-byte integer encoding. Join segments with `+`.
Counts in raw segments are literal integers from 0 through 65536, not
arbitrary expressions.

```text
send raw HEX-SEGMENT [+ HEX-SEGMENT ...]
send ClientHello raw HEX-SEGMENT [+ HEX-SEGMENT ...]
send record CONTENT-TYPE raw HEX-SEGMENT [+ HEX-SEGMENT ...]
```

The first form writes raw wire bytes. The ClientHello form supplies a literal
handshake body that plzn also decodes for handshake state. The record form
supplies a record payload; normal record protection still applies. It uses
one `raw` keyword before the whole segment sequence.

## Flows

There is one preset, `handshake`, and three ways to use it:

| Form | Execution |
| --- | --- |
| `flow handshake { ... }` | Full configured handshake, then explicit additional steps |
| `flow handshake until send\|recv MESSAGE { ... }` | Preset prefix **before** the named occurrence, then body steps |
| `flow handshake after send\|recv MESSAGE { ... }` | Preset prefix **through** the named occurrence, then body steps |
| `flow { ... }` | No preset; the body is the whole execution sequence |

An anchor must name a message and direction present in the selected preset;
it selects the first matching occurrence. There is no implicit handshake
suffix after an anchored flow.

In an **unanchored full preset**, declarations such as `send ClientHello { ... }`
and `recv ServerHello { ... }` configure that handshake's existing messages.
They do not send or receive those handshake messages again. Additional steps
such as application data and post-handshake messages execute after the preset.
Conflicting declarations or configuration for messages the flow cannot use
are diagnosed during lowering.

In **explicit and anchored flows**, send/receive declarations are actual
ordered occurrences, with configuration attached to that occurrence. A
comma-separated send sequence is ordered, not an alternative branch.
Multi-message sends require an explicit or anchored flow and cannot carry
payloads or configuration. Receives take one message per step. Use one message
per line when attaching per-message configuration.

For example, this runs the preset up to plzn's Finished, sends that message
explicitly, and then repeats an application-data exchange on the connection:

```plzn
plzn tls "tls13/explicit-finish-and-repeated-data" {
  chain: [ecdsa_p256]
  uut server { versions: [tls13] }
  flow handshake until send Finished {
    send Finished
    repeat 2 {
      send AppData
      recv AppData
    }
  }
  expect ok
}
```

### Send overrides and receive matchers

```text
send MESSAGE {
  field: VALUE
}
recv MESSAGE {
  field: VALUE
  other_field: VALUE
}
```

A send override changes the constructed message before byte modifiers run.
A receive matcher checks a decoded field. Ordinary fields use `:` on both
sends and receives; `==` is also accepted specifically for `ext` matchers.
Predicates such as `has_ext` are checks, not fields to serialize. Fields are
validated by message, direction, role, and protocol;
a field accepted on a receive is not automatically a supported send override.

For `send MessageName` / `recv MessageName`, inline payloads are accepted only
on a single `send Heartbeat "text"` (the raw `send record` form is separate).
Do not combine that shorthand with a `payload:` field on the same send.
Other sends and all receives must use their supported body fields/matchers.
`ClientHello.cookie` requires DTLS; `ClientHello.key_share_point` requires
TLS 1.3 or DTLS 1.3. These protocol checks also apply to ClientHello fields in
a `renegotiate` body.

The handshake message vocabulary includes `ClientHello`, `ServerHello`,
`HelloRetryRequest`, `EncryptedExtensions`, `Certificate`,
`CompressedCertificate`, `CertificateRequest`, `CertificateVerify`,
`ServerKeyExchange`, `ServerHelloDone`, `ClientKeyExchange`, `Finished`,
`NewSessionTicket`, `KeyUpdate`, `HelloVerifyRequest`, `HelloRequest`,
`EndOfEarlyData`, and `CertificateStatus`. `ChangeCipherSpec` and `Heartbeat`
are record-level message forms. Their availability depends on the selected
driver and handshake state. The special `alert`, `AppData`, `EarlyData`,
`Exporter`, and `TLSUnique` forms are described below.

Frequently used typed fields include:

| Message | Fields and checks |
| --- | --- |
| `ClientHello` | `legacy_version`, `random`, `legacy_session_id`, `cipher_suites` (alias `ciphers`), `legacy_compression_methods` (alias `compression_methods`), `supported_groups`, `supported_versions`, `signature_algorithms`, `has_ext`, `lacks_ext` |
| `ServerHello` | `legacy_version`, `random`, `legacy_session_id_echo`, `cipher_suite`, `selected_version`, `key_share_group`, `has_ext`, `lacks_ext`, `extensions_exactly`, `resumed` |
| `HelloRetryRequest` | `selected_version`, `cipher_suite`, `key_share_group`, `has_ext`, `lacks_ext`, `extensions_exactly` |
| `EncryptedExtensions` | `has_ext`, `lacks_ext`, `extensions_exactly` |
| `Certificate` | `credential` on sends; `entries`, `leaf_key`, `certificate_type`, `leaf_has_ext`, `leaf_lacks_ext` on receives |
| `CertificateRequest` | `signature_algorithms`, `certificate_types`, `format`, `has_sigalg`, `has_cert_type`, `has_ext`, `lacks_ext` |
| `CertificateVerify` | `algorithm`, `signature`, `sign_with`, `salt_length`, `mgf1_hash`, `format` |
| `ServerKeyExchange` | `named_group`, `signature_scheme`, `format`, explicit DH and key-share controls |
| `Finished` | `verify_data` |
| `ChangeCipherSpec` | `type` |
| `KeyUpdate` | `request_update`: `update_requested` (send default), `update_not_requested`, or an integer |
| `NewSessionTicket` | `ticket_lifetime`, `ticket_age_add`, `ticket_nonce`, `ticket`, `has_ext`, `lacks_ext` |
| `HelloVerifyRequest` | `legacy_version`, `cookie_len`, `cookie` |
| `Heartbeat` | `type`, `payload`, `padding`, `payload_length`, `padding_min` |
| `CertificateStatus` | `status_type`, `response` |

For the complete field-name/type registry see `fields_for` in
[`src/schema.rs`](../src/schema.rs); for supported send overrides and typed
value checks see [`src/lower.rs`](../src/lower.rs). The
[field reference in USAGE.md](USAGE.md#overridable-fields-and-matchers) describes
the protocol-specific controls. These registries are not interchangeable with
the byte-field paths used by modifiers.

### Extensions

Inside a supported send body, extension edits occupy their own lines:

```text
+ext TARGET [= VALUE]
+ext dup TARGET [= VALUE]
+ext each TYPES [= VALUE]
-ext TARGET
reverse_extensions
```

`TARGET` is an extension name, permitted numeric type, or `$matrix_variable`.
`+ext` adds or replaces that type; `+ext dup` appends another occurrence.
`+ext each` appends an occurrence for every item in a numeric type list/range,
copying the same empty or raw body; it does not deduplicate. `-ext` removes the
type. `reverse_extensions` reverses the list. Edits apply in declaration order.
Omitting the value, or supplying `[]`, means an empty body. `raw "HEX"` supplies
an encoded body for any extension type.

`dup` cannot be combined with a generated `key_share` list or with `each`.
Generated key-share lists do not implement duplicate extensions, and `each`
already appends every entry.

Typed values encode the extension body rather than copying text to the wire:

| Extension | Typed value |
| --- | --- |
| `server_name` | Hostname string |
| `application_layer_protocol_negotiation` (alias `alpn`) | String or string list |
| `supported_versions` | Client list such as `[tls12, tls13]`, or one server-selected version |
| `supported_groups` | Group list |
| `key_share` | Client group/share list, or the retry group in HelloRetryRequest |
| `signature_algorithms`, `signature_algorithms_cert` | Signature-scheme list |
| `max_fragment_length` | `512`, `1024`, `2048`, or `4096` |
| `record_size_limit` | Integer from 64 through 65535 |
| `padding` | Number of zero bytes |
| `ec_point_formats` | List of `uncompressed`, `ansix962_compressed_prime`, `ansix962_compressed_char2` |
| `psk_key_exchange_modes` | List of `psk_ke`, `psk_dhe_ke` |
| `client_certificate_type`, `server_certificate_type` | Client list of certificate types or one server selection |
| `status_request` | `ocsp` |
| `heartbeat` | `peer_allowed_to_send` or `peer_not_allowed_to_send` |
| `use_srtp` | SRTP-profile list |
| `compress_certificate` | List of `zlib`, `brotli`, `zstd` |
| `early_data` | Integer ticket allowance in NewSessionTicket |

The extension `record_size_limit` body's accepted integer range differs from
the UUT configuration option's range. For extensions without a typed encoder,
use an empty body or raw bytes as appropriate.

On receives, `ext NAME == VALUE` (also `ext NAME: VALUE`) compares the encoded
extension body. A receive extension target may be a name or permitted numeric
type, not a matrix variable. `has_ext`, `lacks_ext`, and `extensions_exactly`
are separate ordinary field matchers.

```plzn
plzn tls "tls13/hello-extension-checks" {
  chain: [ecdsa_p256]
  uut server { versions: [tls13] }
  flow handshake {
    send ClientHello {
      +ext server_name = "localhost"
    }
    recv ServerHello {
      selected_version: tls13
      has_ext: key_share
      ext supported_versions == tls13
    }
    send AppData
    recv AppData
  }
  expect ok
}
```

Extension edits are supported on ClientHello, and on TLS 1.3 client
Certificate, when plzn is the client. When plzn is the server they are
supported on ServerHello, plus TLS 1.3 HelloRetryRequest, EncryptedExtensions,
CertificateRequest, Certificate, and NewSessionTicket. Not every message with
an `extensions` field accepts every edit in every protocol.

### Application data and key-material checks

```text
send AppData { size: N, reply: M }
send AppData { size: N, reply: none }
recv AppData { size: N }
send EarlyData { size: N }
recv EarlyData { size: N }
recv Exporter { label: "label", context: "context", length: N }
recv TLSUnique { unavailable: true }
```

`send AppData` generates deterministic bytes using the shim application
protocol; it does not take a literal string payload. Size defaults to 32 and
is bounded by 1 MiB. The reply defaults to the same size for a nonempty
request; `reply: none` requests no response. An explicit reply size must be
positive. Requests of 1–11 bytes only support the default same-size reply.
`recv AppData` defaults to a 32-byte check; it does not inherit a preceding
send's custom size.

Early data uses the same size-oriented interface in supported TLS 1.3
resumption flows. `Exporter` compares locally derived and shim-reported
exported key material: `label` is required, `context` defaults to `none`, and
`length` defaults to 32 (accepted range 1–65535). An empty context string is
distinct from `none`. TLS PRF-reserved labels are rejected. `TLSUnique`
compares channel-binding data; `unavailable: true` checks its absence.

### Alerts, records, closing, and waiting

```text
send alert LEVEL[/CODE]
recv alert LEVEL[/CODE]
send empty_record CONTENT-TYPE
send record INTEGER "text"
close
close reset
close alert LEVEL[/CODE]
wait N ms
```

Levels are `warning` or `fatal`; codes are alert names. A receive without a
code accepts any code at that level. The special alert forms are distinct
from an end-of-test `expect alert`.

`Heartbeat` also accepts an inline text payload as `send Heartbeat "text"`,
equivalent to using its `payload:` field.

An empty record's content type can be numeric or `handshake`, `alert`,
`change_cipher_spec`, or `application_data`. `send record` takes a numeric
content type and either a text payload or the raw-segment form described
above. It sends under the current record keys without advancing handshake
state. `close reset` requests an abortive transport close.

`wait N ms` is a silence check: it waits for the specified nonnegative number
of milliseconds and probes for unexpected peer traffic. It is not an
unconditional sleep and is distinct from a DTLS virtual-clock advance.

### Repetition, buffering, and renegotiation

```text
repeat COUNT { STEPS }
coalesce { STEPS }
coalesce hold_keys { STEPS }
coalesce old_keys { STEPS }
atomic { STEPS }
flush_fragment
renegotiate [resumed] [insecure] [{ CLIENTHELLO-FIELDS-AND-EXTENSIONS }]
begin_renegotiation
```

A flow `repeat` expands its body in order. Counts are literals or matrix
variables, from 1 through 100000. This repeats steps on the **same connection**,
unlike test-level `repeat`. It is expansion, not a runtime loop or conditional.

For TLS, `coalesce` buffers handshake messages into a record, flushing at the
block's end, before a key change, or before a non-handshake record.
`hold_keys` keeps buffering across a key change and seals with the keys active
at flush time. `old_keys` defers the key change until the buffer is flushed.
`atomic` buffers generated records into one transport write; reads inside it
are not allowed. Buffering blocks cannot be directly nested. A transport
write is not a guarantee of a particular TCP packet boundary.

`flush_fragment` releases data withheld by a fragment modifier. TLS releases
the next held record; DTLS 1.3 releases the held handshake remainder using its
original epoch.

`renegotiate` performs a supported renegotiation using an optional ClientHello
configuration; `resumed` and `insecure` may appear in either order.
`begin_renegotiation`
starts an explicitly driven renegotiation phase. Both require the appropriate
TLS/DTLS driver, role, and UUT renegotiation policy; they are not TLS 1.3
post-handshake authentication commands.

`send Renegotiation` is a separate TLS 1.3 client-side post-handshake replay
step, not a complete renegotiation. It accepts an optional `msg_type:` byte
field but no send modifiers.

## Send modifiers

A send may have an `@` suffix containing comma-separated modifiers. Additional
`@` markers after commas are optional. Byte modifications are applied in
order, in their relevant encoding stage. Availability is checked against the
message, role, protocol, and cipher.

In this section, `TARGET` is an index, an inclusive range, or a named path
with an optional index/range: `N`, `LO..HI`, `handshake.FIELD`,
`handshake.FIELD, N`, or `record.FIELD, LO..HI`. A path without an index selects
its first byte. Negative indices count from the end of that region.
Both endpoints are included, just as in value and matrix ranges.

| Modifier | Meaning |
| --- | --- |
| `xor[TARGET] = VALUE`, `set[TARGET] = VALUE` | Change selected bytes |
| `add[PATH] = N`, `sub[PATH] = N` | Adjust an entire named big-endian length field, wrapping at its wire width |
| `pad +N [BYTE]`, `pad -N`, `pad "HEX"` | Append zero/fill/literal bytes, or remove trailing bytes |
| `truncate N` | Retain at most the first N bytes |
| `trailing SEGMENT` | Append bytes after the framed TLS handshake message |
| `omit_prefix N` | Omit an encoded TLS handshake prefix from the wire |
| `record_version INTEGER` | Override the record version |
| `record_pad INTEGER`, `record_pad fill` | TLS/DTLS 1.3 record padding |
| `cbc_pad INTEGER` | CBC padding size, including its length byte |
| `plaintext` | Send without record protection despite installed keys |
| `plaintext = SEGMENT [+ SEGMENT ...]` | Replace the plaintext supplied to record encryption |
| `fragment N [hold\|hold_all\|hold_old_keys]` | Fragment and optionally retain part for `flush_fragment`; mode support is protocol-specific |
| `reorder N` | Reverse the order of N-byte DTLS handshake fragments |
| `dtls13_short_sequence` | Use a one-byte DTLS 1.3 record sequence encoding |
| `dtls13_omit_length` | Omit the DTLS 1.3 unified-header length |
| `dtls13_set_cid_bit`, `dtls13_legacy_header` | DTLS 1.3 header-format controls |

Bare offsets and `handshake.*` body paths normally run before handshake
framing and record protection. Handshake-header paths run after framing.
`record.*` paths normally run after protection, except `record.plaintext`,
`record.padding`, and `record.inner_type`, which select pre-encryption regions.
Paths refer to the encoder's byte-field map, not to arbitrary object members.

Dedicated DTLS fragmentation plans can share the suffix with byte modifiers,
but only one such plan is permitted per send. These plans require a
handshake-message send; they are rejected on `send Heartbeat` and the special
`send alert`, `send empty_record`, and `send record` forms. Accepted plans are:

```text
duplicate_fragment N
reorder_overlap N
complete_and_fragments N
empty_fragments
split_fragment_record N
overlap_mismatch N
type_mismatch N
length_mismatch N
fragment_length_mismatch N
future_sequence N
future_sequence_packed N
offset_overflow
```

These names select fragment-layout controls; their counts are literal
integers. The [modifier reference](USAGE.md#mutation-operations) and
[`src/tls/mutate.rs`](../src/tls/mutate.rs) describe the individual encoding
effects. Not every path or plan is available in every driver.

## Matrices and test repetition

A matrix expands one test into the Cartesian product of its axes, in
declaration order. Bindings are integer values; `$axis` substitutes the
current value. Expanded test IDs include their bindings.

```text
matrix {
  axis in [VALUE, VALUE, LO..HI]
  other in LO..HI step N
  third in CATALOGUE(ARGUMENT)
}
```

Matrix lists contain integers, named wire constants, or inclusive integer
ranges. Standalone ranges are inclusive and increasing; `step` is optional
and must be positive. List-element ranges do not take a `step`.

Accepted catalogues are `cipher_suites(tls10)`, `cipher_suites(tls11)`,
`cipher_suites(tls12)`, `cipher_suites(tls13)`, `groups(tls10)`,
`groups(tls11)`, `groups(tls12)`, `groups(tls13)`, `grease`, and `cert_models()`.
`grease()` and bare `cert_models` are also accepted. Suite catalogues enumerate
implemented suites, not the whole name registry. The TLS 1.2 group catalogue
and the TLS 1.0/1.1 catalogues are `x25519, secp256r1`; the TLS 1.3 one also
includes `secp384r1`.
`grease` contains the 16 GREASE values. `cert_models()` yields integers 0 and
1; it does not replace an explicit `chain:` declaration.

Axis names `suite`, `group`, and `sigalg` have additional peer-selection
semantics: `suite` pins suite selection, `group` pins the group/key share, and
`sigalg` pins the ClientHello signature-algorithms offer. Use other axis names
for values that should affect only explicit substitutions. UUT suite/group
configuration is still separate. A `suite` axis must select suites plzn
implements; an unsupported selection is a lint error.

```plzn
plzn tls "tls13/application-data-sizes" {
  chain: [ecdsa_p256]
  uut server { versions: [tls13] }
  matrix {
    size in [16, 32, 64]
  }
  flow handshake {
    send AppData { size: $size }
    recv AppData { size: $size }
  }
  expect ok
}
```

At test scope, `repeat N` creates N executions per matrix point, with N from
1 through 4096. It adds the zero-based implicit `$repeat` axis. Each execution
gets its own deterministic test seed and connection/session sequence.

### Captures and cross-run uniqueness

`capture $name` is a whole-field receive matcher on supported byte/integer
fields. `assert unique $name` compares that capture across test repetitions;
several names can be comma-separated. Captures are not general variables.

```plzn
plzn tls "tls13/fresh-server-random" {
  chain: [ecdsa_p256]
  uut server { versions: [tls13] }
  repeat 3
  flow handshake {
    recv ServerHello { random: capture $server_random }
    send AppData
    recv AppData
  }
  expect ok
  assert unique $server_random
}
```

Each matrix point and session name is a separate uniqueness group; values are
not compared across unrelated matrix cells or sessions. At least two runs
are needed, and a missing capture is a failed assertion. The asserted name
must be captured in that flow.

## Sessions and resumption

Named sessions describe successive connections that may share resumption
state. Session order is significant. Each matrix point executes its entire
session sequence with isolated state.

```text
session NAME {
  flow ...
  expect OUTCOME
}
session NAME [resumes: EARLIER_NAME, version: VERSION, force_resume: BOOL] {
  flow ...
  expect OUTCOME
  assert ...
}
```

The square brackets here are **literal syntax** around optional qualifiers.
Qualifiers are comma-separated; specify each at most once. `resumes` must
refer to an earlier session. `version` must be enabled in the test's
`uut.versions`. Omit the qualifier brackets when there are no qualifiers.
There are no session-local UUT, peer, matrix, or credential blocks.

```plzn
plzn tls "tls13/ticket-resumption" {
  chain: [ecdsa_p256]
  uut server {
    versions: [tls13]
    session_tickets: 1
  }
  session initial {
    flow handshake {
      recv NewSessionTicket
      send AppData
      recv AppData
    }
    expect ok
    assert resumed == false
  }
  session resumed [resumes: initial] {
    flow handshake {
      send AppData
      recv AppData
    }
    expect ok
    assert resumed == true
  }
}
```

`resumes` requests use of saved state; `assert resumed == true` checks that
resumption actually happened. Arrange ticket issuance and receipt in the
source session when using tickets. TLS 1.2 session-ID resumption uses the
`session_id` peer capability. `force_resume: true` is restricted to
cross-version resumption with `uut client` and a `resumes` source; it changes
plzn's server behavior, not the UUT's policy.

### External PSKs

A test-level PSK block supplies a default external identity and secret:

```plzn
plzn tls "tls13/external-psk" {
  chain: []
  uut server { versions: [tls13] }
  psk {
    identity: "example-identity"
    secret: "00112233445566778899aabbccddeeff"
    offer {
      identity: "example-identity"
      secret: "00112233445566778899aabbccddeeff"
      hash: sha256
    }
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
```

The `offer` blocks are optional and ordered. They require a TLS 1.3 or
DTLS 1.3 server UUT. The outer `identity` and `secret` remain required when
offers are present. Every offer requires both fields; `hash` is `sha256`
(default) or `sha384`.
Secrets are nonempty even-length hexadecimal strings with optional whitespace.
PSK fields are **newline-separated, without commas**. `uut.psk_identity` and
`uut.psk_secret` can independently override the UUT's configured values.
Protocol, role, and backend support determine which PSK modes can execute.

## DTLS flow controls

DTLS uses the same test, flow, value, and expectation syntax. For example:

```plzn
plzn tls "dtls12/basic-handshake" {
  chain: [ecdsa_p256]
  uut server { versions: [dtls12] }
  flow handshake {}
  expect ok
  assert no_duplicate_record_seqnums
}
```

The following additional flow statements control the DTLS harness. Optional
arguments are shown in brackets; `INDICES` means a literal list such as
`[0, 2]`. Counts and durations here are integer literals.

| Statements | Purpose |
| --- | --- |
| `advance_clock N UNIT` | Advance virtual time |
| `expect next_timeout N UNIT`, `expect no_timeout` | Check the current timeout state |
| `set_timeout N UNIT` | Set the harness timeout |
| `expect_retransmit [no_ccs]`, `resend_flight` | Check or resend a flight |
| `discard_flight`, `hold_flight`, `hold_retransmit`, `release_flight [INDICES]` | Control queued flight delivery |
| `retransmit_flight [split INDICES]`, `replay_flight N` | Retransmit or replay recorded traffic |
| `interleave_flight [split]`, `future_seq_first` | Control flight ordering |
| `map_record_sequences identity`, `map_record_sequences multiply N`, `map_record_sequences xor N` | Select a record-sequence mapping |
| `set_mtu N` | Change the datagram size limit |
| `rotate_cookie_secret`, `restart` | Cookie-key or endpoint lifecycle control |
| `suppress_ack`, `expect_ack` | DTLS 1.3 ACK controls |
| `send_ack SELECTION [outer_epoch N] [overflow_epoch]` | DTLS 1.3 ACK emission control |
| `send_previous_epoch Finished`, `retransmit_previous_epoch Finished` | DTLS 1.3 previous-epoch Finished controls |
| `header_only_flood N`, `large_length_fragment N`, `hvr_flood N max_answers M` | Count- and size-bounded DTLS robustness probes |

`UNIT` is `ns`, `us`, `ms`, or `s`; durations are nonnegative. `set_timeout`
must resolve to whole milliseconds fitting in a u32. `set_mtu` takes a
positive u32. Selected record indices are zero-based, whereas `replay_flight`
numbers saved flights starting at **1**. ACK selections are `all`, `first`,
`last`, `even`, or `odd`.

These statements require DTLS and the relevant driver/shim hooks; DTLS 1.3
ACK/epoch operations are not DTLS 1.2 operations. `expect next_timeout` and
`expect no_timeout` are **flow steps**, unlike final test/session expectations.
See the [DTLS guide](USAGE.md#dtls-12) for backend-specific operation details.

## Expectations and assertions

Every ordinary test or session has one primary outcome expectation. Additional
lines of the form `expect OUTCOME if BACKEND` override it for one backend;
without a matching override the primary expectation applies.

| Outcome | Meaning |
| --- | --- |
| `ok` | The flow completes successfully |
| `alert LEVEL[/CODE]` | The UUT sends the matching alert |
| `alert LEVEL/{CODE, CODE, ...}` | The UUT sends one of the listed codes |
| `reject LEVEL[/CODE]` | plzn locally rejects the UUT with the matching alert |
| `reject LEVEL/{CODE, CODE, ...}` | Local rejection with one of the listed codes |
| `close` | Peer transport EOF without an alert |
| `reset` | Abortive peer connection close |
| `timeout` | The UUT's DTLS timeout outcome |
| `handshake-fails` | Peer alert, close, reset, or DTLS timeout |
| `any { OUTCOME, OUTCOME, ... }` | Any listed outcome; at least two alternatives |

Alert levels are `warning` and `fatal`. Omitting a code accepts any code at
that level. `handshake-fails` does **not** accept local rejection, assertion,
codec, cryptographic, or general I/O failures. A socket read deadline alone is
not interchangeable with the UUT's DTLS timeout outcome.

For a TLS server UUT, a success-accepting flow is normally required to end
with an application-data round trip or a key-material check (`recv Exporter`
or `recv TLSUnique`). Explicit close, silence-probe, and receive-alert endings
are also accepted, as is an explicit terminal `recv Message { matcher: value }`
when the test is intentionally bounded at the property being checked. An empty
`recv Message` is not a matcher. This prevents a bare handshake preset from
silently passing without checking the connection. Client-UUT and DTLS flows
have different completion checks and can use `flow handshake {}` with
`expect ok`.

Assertions add checks to an otherwise successful outcome match:

| Assertion | Check |
| --- | --- |
| `assert no_duplicate_record_seqnums` | Record-sequence uniqueness |
| `assert gcm_nonces_unique` | TLS 1.2 explicit GCM nonce uniqueness |
| `assert gcm_nonces_monotonic` | TLS 1.2 explicit GCM nonce ordering |
| `assert max_datagram_size N` | DTLS datagram bound; positive u32 |
| `assert new_session_tickets == N` | Observed ticket count; nonnegative integer |
| `assert resumed == true\|false` | Actual resumption state |
| `assert negotiated.cipher == SUITE` | Negotiated cipher suite |
| `assert negotiated.early_data_accepted == true\|false` | TLS 1.3 early-data result |
| `assert unique $name[, $other...]` | Captured-value uniqueness across repetitions |

Cipher suites use their registry names; unknown/private-use values may be
written numerically. Early-data state is available only for TLS 1.3. `assert`
is not a general expression or arbitrary trace-query language.

## Implementation references

- [`src/lex.rs`](../src/lex.rs): tokens, comments, and string handling.
- [`src/parse.rs`](../src/parse.rs): accepted statement and value forms.
- [`src/schema.rs`](../src/schema.rs): field, capability, and wire-name registries.
- [`src/check.rs`](../src/check.rs): structural and schema validation.
- [`src/lower.rs`](../src/lower.rs): expansion, typed values, and executable
  role/protocol restrictions.
- [`suite/`](../suite/): tests using the language against real-library shims.

Use `plzn lint` rather than parsing alone when checking whether a construct is
accepted: lowering rejects combinations that the grammar can represent but
the runtime cannot implement.
