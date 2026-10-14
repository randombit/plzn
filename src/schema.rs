// Wedge schema registry.
//
// Hand-written, RFC-faithful symbol catalogue covering exactly what the
// ten wedge stress-test ports need. Expand as new tests demand.
//
// Each category is a static slice of &str. The checker does a string
// lookup; misses trigger "did you mean?" via the diag module.

pub const VERSIONS: &[&str] = &["tls10", "tls11", "tls12", "tls13", "dtls12", "dtls13"];

pub const KEY_EXCHANGES: &[&str] = &[
    "rsa",
    "dhe_rsa",
    "ecdhe_rsa",
    // A: ECDHE under whatever the chain signs with (see `chain:`).
    "ecdhe",
    "ecdhe_ecdsa",
    // TLS 1.2 pre-shared-key families (with a `psk { }` block).
    "psk",
    "ecdhe_psk",
    "psk_ke",
    "psk_dhe_ke",
];

pub const CIPHER_SUITES: &[&str] = &[
    // TLS 1.2
    "aes128_cbc_sha",
    "aes256_cbc_sha",
    "aes128_gcm_sha256",
    "aes256_gcm_sha384",
    "chacha20_poly1305_sha256",
    "aes128_ccm_sha256",
    "aes128_ccm_8_sha256",
    // TLS 1.3 uses the same names; mapping is context-dependent.
];

pub const GROUPS: &[&str] = &[
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "x25519",
    "x448",
    "ffdhe2048",
    "ffdhe3072",
    "ffdhe4096",
    "ffdhe6144",
    "ffdhe8192",
    // T4: RFC 7027 brainpool (TLS 1.2 codepoints), RFC 8734 brainpool (TLS 1.3
    // codepoints), FIPS 203 ML-KEM and the ECDH+ML-KEM hybrids. P512 and
    // Hybrid ML-KEM groups.
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
    "brainpoolP256r1tls13",
    "brainpoolP384r1tls13",
    "brainpoolP512r1tls13",
    "mlkem512",
    "mlkem768",
    "mlkem1024",
    "x25519mlkem768",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
    "x448mlkem1024",
];

pub const SIG_ALGS: &[&str] = &[
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ed25519",
    "ed448",
];

// A: `chain:` / `client_chain:` entries (`rsa` is an alias of `rsa_2048`).
pub const CHAIN_NAMES: &[&str] = &[
    "default",
    "rsa_2048",
    "rsa",
    "rsa_2048_ecdsa_signed",
    "rsa_pss",
    "ecdsa_p256",
    "ecdsa_p384",
    "ecdsa_p521",
    "ed25519",
];

pub fn is_chain_name(name: &str) -> bool {
    CHAIN_NAMES.contains(&name)
}

/// Cipher-mode predicates (suite filter shorthand).
pub const CIPHER_MODES: &[&str] = &[
    "aead",
    "cbc",
    "gcm",
    "ccm",
    "ccm8",
    "aria",
    "camellia",
    "des3",
    "null",
    "sha384",
    "chacha20_poly1305",
];

/// Miscellaneous peer/scenario selectors that don't belong to any category above.
pub const PEER_CAPABILITY_FLAGS: &[&str] = &[
    "session_ticket",
    "session_id",
    "hrr",
    "second_hrr",
    "offer_rpk",
    "compress_cert",
];

pub fn is_peer_capability(tok: &str) -> bool {
    VERSIONS.contains(&tok)
        || KEY_EXCHANGES.contains(&tok)
        || CIPHER_SUITES.contains(&tok)
        || CIPHER_MODES.contains(&tok)
        || GROUPS.contains(&tok)
        || SIG_ALGS.contains(&tok)
        || PEER_CAPABILITY_FLAGS.contains(&tok)
}

pub fn peer_capability_candidates() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();
    v.extend_from_slice(VERSIONS);
    v.extend_from_slice(KEY_EXCHANGES);
    v.extend_from_slice(CIPHER_SUITES);
    v.extend_from_slice(CIPHER_MODES);
    v.extend_from_slice(GROUPS);
    v.extend_from_slice(SIG_ALGS);
    v.extend_from_slice(PEER_CAPABILITY_FLAGS);
    v
}

// ========================== Messages ==========================

pub const MESSAGES: &[&str] = &[
    // TLS 1.2 + 1.3 handshake messages
    "ClientHello",
    "ServerHello",
    "HelloRetryRequest",
    "EncryptedExtensions",
    "Certificate",
    "CertificateRequest",
    "CertificateVerify",
    "ServerKeyExchange",
    "ServerHelloDone",
    "ClientKeyExchange",
    "Finished",
    "NewSessionTicket",
    "KeyUpdate",
    "HelloVerifyRequest",
    // RFC 5246 7.4.1.1 renegotiation request (TLS 1.2 / DTLS 1.2 server).
    "HelloRequest",
    // Non-handshake
    "ChangeCipherSpec",
    "Alert",
    "AppData",
    "Exporter",
    "TLSUnique",
    "EarlyData",
    // TLS 1.3-only but schema-wise harmless
    "EndOfEarlyData",
    // Pseudo-message: replay the ClientHello post-handshake (renegotiation attempt).
    "Renegotiation",
    // T6: RFC 6520 heartbeat record, RFC 6066 CertificateStatus (OCSP
    // stapling), RFC 8879 CompressedCertificate.
    "Heartbeat",
    "CertificateStatus",
    "CompressedCertificate",
];

/// The on-wire shape of a field, as seen by field overrides /
/// matchers. The lowering layer coerces each AST FieldValue to the
/// matching shape and rejects mismatches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U8List,
    U16List,
    Bytes,
    /// Symbolic enum field (e.g. `request_update: update_requested`).
    /// Lowering resolves each message's supported symbols into typed IR values.
    Enum,
    /// T6: a 32-bit integer (u24 wire fields such as RFC 8879's
    /// uncompressed_length, which a u16 cannot express).
    U32,
}

/// Fields legal on a given message, by message name, with their
/// wire shape. Only the subset the wedge touches is listed —
/// everything else surfaces as an "unknown field" at check time.
pub fn fields_for(msg: &str) -> &'static [(&'static str, FieldType)] {
    match msg {
        "ClientHello" => &[
            // T6: `send ClientHello raw "HEX"` (the whole body as sent, decoded
            // for the state the handshake needs) and `format: sslv2` (the
            // RFC 5246 E.2 SSLv2-compatible CLIENT-HELLO framing).
            ("raw_body", FieldType::Bytes),
            ("format", FieldType::Enum),
            ("cipher_specs", FieldType::Bytes),
            ("legacy_version", FieldType::U16),
            ("random", FieldType::Bytes),
            ("legacy_session_id", FieldType::Bytes),
            ("cipher_suites", FieldType::U16List),
            ("ciphers", FieldType::U16List), // alias the stress-test files use
            // Matcher-only: assert a cipher suite signalling value is absent.
            ("lacks_cipher_suite", FieldType::U16),
            // Matcher-only: assert that the client offers none of the TLS 1.2
            // finite-field DH/DHE or RSA suites prohibited by RFC 10015.
            ("lacks_obsolete_key_exchange", FieldType::Enum),
            ("legacy_compression_methods", FieldType::U8List),
            ("compression_methods", FieldType::U8List), // alias
            ("extensions", FieldType::Bytes),
            // Matcher-only: assert an extension of the given IANA type is present.
            ("has_ext", FieldType::U16),
            // Matcher-only: assert a ClientHello extension of the given IANA type is
            // ABSENT (e.g. a client whose policy switched encrypt_then_mac off).
            ("lacks_ext", FieldType::U16),
            // Matcher-only (plzn as server): the client's supported_groups /
            // signature_algorithms contain all of these (names or wire values).
            ("supported_groups", FieldType::U16List),
            // Matcher-only, contains-all: versions advertised in the TLS 1.3
            // supported_versions extension (ordering is not significant).
            ("supported_versions", FieldType::U16List),
            ("lacks_supported_version", FieldType::U16),
            ("signature_algorithms", FieldType::U16List),
            // TLS 1.3 sender-conformance matchers.
            ("supported_groups_unique", FieldType::Enum),
            ("key_shares_consistent", FieldType::Enum),
            // RFC 5746 initial-handshake signal: an empty renegotiation_info
            // extension or TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
            ("secure_renegotiation_signal", FieldType::Enum),
            // Matcher-only: assert a signature scheme is absent from the
            // signature_algorithms extension.
            ("lacks_signature_algorithm", FieldType::U16),
            // Matcher-only: assert a group is absent from the supported_groups
            // extension.
            ("lacks_supported_group", FieldType::U16),
            // Matcher-only capture: the first key_exchange value in key_share.
            ("key_share", FieldType::Bytes),
            // Matcher-only (plzn as TLS 1.2 / DTLS server): the host_name in the
            // client's server_name extension (RFC 6066 3).
            ("server_name", FieldType::Bytes),
            ("cookie", FieldType::Bytes),
            // How the client's key_share public values are encoded: `compressed`
            // (SEC1 compressed point, illegal in TLS 1.3 key_share), `zero` (an
            // all-zero value: the low-order x25519 point / not a NIST point), or
            // `truncated` / `padded` (one byte short of / over the group's fixed
            // length, with every enclosing length prefix still consistent), or for
            // a finite-field group `one` / `p_minus_1` (the RFC 8446 4.2.8.1 bounds).
            ("key_share_point", FieldType::Enum),
            // RFC 8446 4.2.11 PskIdentity. For a resumption PSK the generated
            // default is ticket_age_add (zero elapsed age); an override allows
            // boundary and skew tests. Servers MUST ignore it for external PSKs.
            ("obfuscated_ticket_age", FieldType::U32),
            // RFC 8446 4.2.11 PskIdentity.identity. Unlike the UUT-level
            // psk_identity setting, this changes only the identity on the wire;
            // the generated binder is still recomputed after the override.
            ("psk_identity", FieldType::Bytes),
            // `encrypted_premaster` on ClientHello is technically
            // a ClientKeyExchange field — we accept it here with a
            // comment because the tlsfuzzer-style stress tests
            // reach into it via the alias.
            ("encrypted_premaster", FieldType::Bytes),
        ],
        "ServerHello" => &[
            ("legacy_version", FieldType::U16),
            ("random", FieldType::Bytes),
            ("legacy_session_id_echo", FieldType::Bytes),
            ("cipher_suite", FieldType::U16),
            ("legacy_compression_method", FieldType::U8),
            // Matcher-only: the version selected by the supported_versions
            // extension in a TLS 1.3 ServerHello.
            ("selected_version", FieldType::U16),
            ("extensions", FieldType::Bytes),
            // T5, matcher-only (client role, TLS 1.2): `resumed: true | false` --
            // whether the server echoed the session_id plzn's client offered
            // (RFC 5246 7.4.1.3 / RFC 5077 3.4), i.e. accepted the resumption.
            ("resumed", FieldType::Enum),
            // Matcher-only: assert a ServerHello extension of the given IANA type
            // is present (e.g. extended_master_secret 0x0017, RFC 7627).
            ("has_ext", FieldType::U16),
            // Matcher-only: assert a ServerHello extension of the given IANA type is
            // ABSENT (e.g. the server MUST NOT echo extended_master_secret when the
            // client did not offer it, RFC 7627 5.3).
            ("lacks_ext", FieldType::U16),
            // Matcher-only: assert ServerHello.random ends with these bytes -- used
            // for the TLS 1.3 downgrade sentinel (RFC 8446 4.1.3).
            ("random_suffix", FieldType::Bytes),
            // T2 matcher: exactly this set of extension types (any order;
            // names or wire values), RFC 8446 4.2 / tlsfuzzer
            // ExpectServerHello(extensions=...).
            ("extensions_exactly", FieldType::U16List),
            // The named group carried in the TLS 1.3 ServerHello
            // key_share (RFC 8446 §4.2.8), as a raw IANA wire value.
            // Overriding it lets a `uut client` test force the
            // server to select a group the client didn't key-share
            // (or a GREASE/reserved value) and observe the client
            // abort. Adversarial counterpart to capability-driven selection.
            ("key_share_group", FieldType::U16),
            // Matcher-only capture: the ServerHello KeyShareEntry value.
            ("key_share", FieldType::Bytes),
            // Encoding of the server's key_share public value (see ClientHello).
            ("key_share_point", FieldType::Enum),
            // Search the server's FFDHE private value until the TLS 1.3 shared
            // secret begins with N zero octets. The wire key share remains
            // valid; this exercises the fixed-width secret representation
            // required by RFC 8446 7.4.1.
            ("shared_secret_leading_zeros", FieldType::U8),
            // `psk_ke` | `psk_dhe_ke`: the PSK key-exchange mode plzn's server
            // selects on a resumed session, regardless of what the client
            // offered (RFC 8446 4.2.9: the server MUST NOT select a mode the
            // client did not list -- forcing psk_ke against a psk_dhe_ke-only
            // client checks the client aborts).
            ("psk_mode", FieldType::Enum),
            // TLS 1.3 pre_shared_key selected_identity. As a matcher this
            // observes which offered PSK the UUT chose; as a send override it
            // can force an unoffered index for the client-side negative.
            ("selected_psk_identity", FieldType::U16),
        ],
        // A HelloRetryRequest is a ServerHello on the wire (magic
        // random), so it takes the same overridable fields. The
        // interesting adversarial one is `key_share_group`: forcing
        // the retry group to one the client already key-shared (or
        // never offered) must make a conformant client abort
        // (RFC 8446 §4.1.4, illegal_parameter).
        "HelloRetryRequest" => &[
            ("legacy_version", FieldType::U16),
            ("random", FieldType::Bytes),
            ("legacy_session_id_echo", FieldType::Bytes),
            ("cipher_suite", FieldType::U16),
            ("legacy_compression_method", FieldType::U8),
            ("selected_version", FieldType::U16),
            ("key_share_group", FieldType::U16),
            // T2 matchers (plzn as client): the HRR's extensions.
            ("has_ext", FieldType::U16),
            ("lacks_ext", FieldType::U16),
            ("extensions_exactly", FieldType::U16List),
        ],
        "Finished" => &[("verify_data", FieldType::Bytes)],
        "ClientKeyExchange" => &[
            // Encoding of the client's ECDHE public value: `compressed` (SEC1
            // compressed, which RFC 8422 5.1.2 allows only if negotiated) or
            // `zero` (not a valid point).
            ("key_share_point", FieldType::Enum),
            // Static RSA: the ciphertext whole (bytes, `modulus` for the
            // server key's n, or `file "path"`), the 48-byte premaster
            // before encryption, the PS byte of a shaped PKCS#1 v1.5 EM, or
            // the raw k-byte block encrypted with no PKCS#1 encoding at all.
            ("encrypted_premaster", FieldType::Bytes),
            ("premaster_secret", FieldType::Bytes),
            ("padding_byte", FieldType::U8),
            ("rsa_plaintext", FieldType::Bytes),
            // DHE / ECDHE (TLS 1.2 client): search the private value until the
            // shared secret starts with N zero bytes (RFC 5246 8.1.2 strips
            // them for DHE; RFC 8422 5.10 keeps them for ECDHE).
            ("shared_secret_leading_zeros", FieldType::U8),
            ("dh_Yc", FieldType::Bytes),
            ("ecdh_Yc", FieldType::Bytes),
            // PSK / ECDHE_PSK suites: the identity the client presents (RFC 4279
            // 2); override it for the unknown-identity negative.
            ("psk_identity", FieldType::Bytes),
        ],
        // plzn as a TLS 1.2 server: the finite-field group its DHE
        // ServerKeyExchange carries (2048 = RFC 7919 ffdhe2048, the default;
        // 1024 / 768 = the RFC 2409 Oakley groups, below what current clients
        // accept -- the "DH group too small" negative). Exact p/g/Ys fields
        // allow arbitrary and deliberately invalid explicit groups. dh_p also
        // takes the named prime rfc5114_2048_256; dh_g and dh_Ys also take
        // zero/one/two/p_minus_1/p/p_plus_1/small_order recipes.
        "ServerKeyExchange" => &[
            ("dh_p_bits", FieldType::U16),
            ("dh_p", FieldType::Bytes),
            ("dh_g", FieldType::Enum),
            ("dh_Ys", FieldType::Enum),
            // ServerKeyExchange: as a server override (TLS 1.2) or as client matchers
            // (TLS 1.2 and DTLS): the ECDHE group (`named_group`; a name or wire value), the signature scheme of the
            // signed params, and the PSK / ECDHE_PSK psk_identity_hint.
            ("named_group", FieldType::U16),
            ("signature_scheme", FieldType::U16),
            // Force the pre-1.2 or TLS 1.2 SignatureAndHashAlgorithm wire form.
            ("format", FieldType::Enum),
            ("psk_identity_hint", FieldType::Bytes),
            // T2 matcher: the explicit DHE parameters are this RFC 7919 group
            // (`dh_group: ffdhe2048`), compared against the group's p and g.
            ("dh_group", FieldType::U16),
            // plzn as a DTLS server: corrupt the ECDHE / ECDHE_PSK public point
            // (zero / truncated / padded / compressed) -- the client must reject.
            ("key_share_point", FieldType::Enum),
            // T1: matcher-only (TLS 1.2 client): the server's public value
            // (ECDHE point or DHE Ys), for `key_share: capture $ks`.
            ("key_share", FieldType::Bytes),
        ],
        // Matcher-only (DTLS client): the cookie's length / exact value.
        "HelloVerifyRequest" => &[
            ("legacy_version", FieldType::U16),
            ("cookie_len", FieldType::U16),
            ("cookie", FieldType::Bytes),
        ],
        // CertificateRequest: TLS 1.2 / DTLS server overrides (certificate_types,
        // signature_algorithms) and client matchers for every version
        // (contains-all lists, single-entry has_sigalg / has_cert_type, the TLS 1.3
        // extension matchers).
        "CertificateRequest" => &[
            ("has_sigalg", FieldType::U16),
            ("has_cert_type", FieldType::U8),
            ("certificate_types", FieldType::U8List),
            ("signature_algorithms", FieldType::U16List),
            // Force inclusion/omission of supported_signature_algorithms.
            ("format", FieldType::Enum),
            ("has_ext", FieldType::U16),
            ("lacks_ext", FieldType::U16),
            // Number of DNs in certificate_authorities (0 = extension absent).
            ("certificate_authorities_count", FieldType::U16),
        ],
        "KeyUpdate" => &[("request_update", FieldType::Enum)],
        // `send AppData { size: N, reply: M }` and `recv AppData { size: N }`.
        "AppData" => &[("size", FieldType::U32), ("reply", FieldType::U32)],
        "Exporter" => &[
            ("label", FieldType::Bytes),
            ("context", FieldType::Bytes),
            ("length", FieldType::U32),
        ],
        "TLSUnique" => &[("unavailable", FieldType::Enum)],
        "EarlyData" => &[("size", FieldType::U32)],
        "ChangeCipherSpec" => &[("type", FieldType::U8)],
        // Matcher-only fields for the TLS 1.3 messages plzn's client receives
        // after the ServerHello (RFC 8446 4.3.1 / 4.3.2 / 4.4.2 / 4.6.1).
        "EncryptedExtensions" => &[
            ("has_ext", FieldType::U16),
            ("lacks_ext", FieldType::U16),
            ("extensions_exactly", FieldType::U16List),
        ],
        "Certificate" => &[
            ("certificate_list", FieldType::Bytes),
            ("certificate_request_context", FieldType::Bytes),
            // plzn's own client answering a CertificateRequest picks a testdata
            // credential by name (TLS 1.2 and DTLS): `valid` the CA-issued
            // end-entity (the default), `untrusted` a self-signed chain the
            // servers reject with unknown_ca, `none` an empty certificate_list.
            ("credential", FieldType::Enum),
            // Matcher-only: the number of certificates in the list (`entries`; every
            // client role, and a TLS 1.2 / DTLS server override)
            // and the TLS 1.3 leaf entry's extensions (status_request / SCT must
            // answer a ClientHello request).
            ("entries", FieldType::U16),
            // Matcher-only: the leaf certificate's public-key type (every
            // receiving role) -- which chain a multi-chain peer presented:
            // rsa / rsa_2048, rsa_pss, ecdsa_p256, ecdsa_p384, ecdsa_p521, ed25519.
            ("leaf_key", FieldType::Enum),
            // On send, override the Certificate payload encoding independently
            // of the negotiated RFC 7250 type. On recv, match the negotiated
            // encoding independently of an explicit/default selection.
            ("certificate_type", FieldType::Enum),
            ("leaf_has_ext", FieldType::U16),
            ("leaf_lacks_ext", FieldType::U16),
            // T6: matcher (plzn's TLS 1.3 client): 1 = the server MUST have
            // sent a CompressedCertificate, 0 = a plain Certificate.
            ("compressed", FieldType::U8),
        ],
        "CertificateVerify" => &[
            ("algorithm", FieldType::U16),
            ("signature", FieldType::Bytes),
            // T3: signing controls on plzn's own client (TLS 1.2 and 1.3):
            // `sign_with` really signs with that scheme (`algorithm` keeps its
            // relabel meaning and defaults to it), `salt_length` / `mgf1_hash`
            // shape an RSASSA-PSS signature, `format: tls11` is the TLS 1.0/1.1
            // MD5 || SHA-1 form with no DigestInfo (SLOTH, CVE-2015-7575).
            ("sign_with", FieldType::U16),
            ("salt_length", FieldType::U16),
            ("mgf1_hash", FieldType::Enum),
            ("format", FieldType::Enum),
        ],
        "NewSessionTicket" => &[
            ("ticket_lifetime", FieldType::U16),
            ("ticket_age_add", FieldType::U16),
            ("ticket_nonce", FieldType::Bytes),
            ("ticket", FieldType::Bytes),
            // Matcher-only (plzn as client): the ticket's extensions and an
            // upper bound on ticket_lifetime in HOURS (RFC 8446 4.6.1: servers
            // MUST NOT use more than 604800 s = 168 h).
            ("has_ext", FieldType::U16),
            ("lacks_ext", FieldType::U16),
            ("max_ticket_lifetime_hours", FieldType::U16),
            // Override (plzn as server): lifetime in DAYS, for the RFC 8446
            // 4.6.1 seven-day bound a u16 of seconds cannot express.
            ("ticket_lifetime_days", FieldType::U16),
        ],
        "Alert" => &[("level", FieldType::U8), ("description", FieldType::U8)],
        // Post-handshake ClientHello replay; msg_type overrides the replayed
        // handshake type byte so other unexpected post-handshake messages can be
        // injected (e.g. a Certificate or ServerHello arriving after the handshake).
        "Renegotiation" => &[("msg_type", FieldType::U8)],
        // T6: RFC 6520 heartbeat record. Send: `type` (request | response),
        // `payload` (bytes; or the `send Heartbeat "text"` form), `padding`
        // (bytes of zero padding, RFC 6520 4 wants >= 16), `payload_length`
        // (the length FIELD, so a lie -- the heartbleed shape -- is one
        // override). Matchers: `type`, `payload`, `padding_min`.
        "Heartbeat" => &[
            ("type", FieldType::Enum),
            ("payload", FieldType::Bytes),
            ("padding", FieldType::U16),
            ("payload_length", FieldType::U16),
            ("padding_min", FieldType::U16),
        ],
        // T6: RFC 6066 8 CertificateStatus. `status_type: ocsp` as a matcher
        // also requires a syntactically successful OCSPResponse; `response`
        // permits exact matching or deliberate server-side malformed bodies.
        "CertificateStatus" => &[
            ("status_type", FieldType::Enum),
            ("response", FieldType::Bytes),
        ],
        // T6: RFC 8879 CompressedCertificate. Send (either plzn TLS 1.3 role):
        // `algorithm` (zlib | brotli | zstd | a number: the
        // LABEL; the payload is always zlib-compressed unless overridden),
        // `uncompressed_length` (the length field), `payload` (the compressed
        // bytes verbatim), `payload_zeros: N` (N zero bytes as the payload),
        // `bomb: N` (a zlib stream that inflates to N MiB of zeros),
        // `credential: none` (compress an empty certificate_list). Matcher
        // (plzn's client): `algorithm`.
        "CompressedCertificate" => &[
            ("algorithm", FieldType::U16),
            ("uncompressed_length", FieldType::U32),
            ("payload", FieldType::Bytes),
            ("payload_zeros", FieldType::U32),
            ("bomb", FieldType::U16),
            ("credential", FieldType::Enum),
        ],
        _ => &[],
    }
}

/// Just the names, for `did you mean?` suggestions.
pub fn field_names_for(msg: &str) -> Vec<&'static str> {
    fields_for(msg).iter().map(|(n, _)| *n).collect()
}

/// Look up the type of a specific field on a known message. Returns
/// None if the field isn't registered for that message.
pub fn field_type(msg: &str, field: &str) -> Option<FieldType> {
    fields_for(msg)
        .iter()
        .find_map(|(n, t)| if *n == field { Some(*t) } else { None })
}

pub fn is_message(name: &str) -> bool {
    MESSAGES.contains(&name)
}

// ========================== Extensions ==========================

pub const EXTENSIONS: &[&str] = &[
    "server_name",
    "max_fragment_length",
    "status_request",
    "supported_groups",
    "signature_algorithms",
    "signature_algorithms_cert",
    "use_srtp",
    "heartbeat",
    "application_layer_protocol_negotiation", // alias
    "alpn",
    "signed_certificate_timestamp",
    "client_certificate_type",
    "server_certificate_type",
    "padding",
    "extended_master_secret",
    "session_ticket",
    "pre_shared_key",
    "early_data",
    "supported_versions",
    "cookie",
    "psk_key_exchange_modes",
    "certificate_authorities",
    "oid_filters",
    "post_handshake_auth",
    "key_share",
    "renegotiation_info",
    "ec_point_formats",
    "record_size_limit",
    "compress_certificate",
    "delegated_credential",
    "encrypt_then_mac",
    "status_request_v2",
    "next_protocol_negotiation",
    "quic_transport_parameters",
    "application_settings",
    "encrypted_client_hello",
    "trust_anchors",
];

pub fn is_extension(name: &str) -> bool {
    EXTENSIONS.contains(&name)
}

/// Resolve a named TLS version to its wire value.
pub fn version_wire_value(name: &str) -> Option<u16> {
    Some(match name {
        "tls10" | "tls1.0" => 0x0301,
        "tls11" | "tls1.1" => 0x0302,
        "tls12" | "tls1.2" => 0x0303,
        "tls13" | "tls1.3" => 0x0304,
        "dtls12" | "dtls1.2" => 0xfefd,
        "dtls13" | "dtls1.3" => 0xfefc,
        _ => return None,
    })
}

/// Resolve a named ECDHE/FFDHE group to its IANA wire value.
pub fn group_wire_value(name: &str) -> Option<u16> {
    Some(match name {
        "secp256r1" => 0x0017,
        "secp384r1" => 0x0018,
        "secp521r1" => 0x0019,
        "x25519" => 0x001d,
        "x448" => 0x001e,
        "ffdhe2048" => 0x0100,
        "ffdhe3072" => 0x0101,
        "ffdhe4096" => 0x0102,
        "ffdhe6144" => 0x0103,
        "ffdhe8192" => 0x0104,
        // T4: brainpool, ML-KEM and hybrid names, accepted in any letter case
        // (the IANA spellings are mixed-case: brainpoolP256r1, X25519MLKEM768).
        _ => match name.to_ascii_lowercase().as_str() {
            "brainpoolp256r1" => 0x001a,
            "brainpoolp384r1" => 0x001b,
            "brainpoolp512r1" => 0x001c,
            "brainpoolp256r1tls13" => 0x001f,
            "brainpoolp384r1tls13" => 0x0020,
            "brainpoolp512r1tls13" => 0x0021,
            "mlkem512" => 0x0200,
            "mlkem768" => 0x0201,
            "mlkem1024" => 0x0202,
            "secp256r1mlkem768" => 0x11eb,
            "x25519mlkem768" => 0x11ec,
            "secp384r1mlkem1024" => 0x11ed,
            "x448mlkem1024" => 0x11ee,
            _ => return None,
        },
    })
}

/// Resolve a cipher-suite capability name to its TLS 1.3 wire value, for
/// the suites the harness-server driver implements. Returns None for
/// names that aren't TLS 1.3 suites (the CBC-only legacy names). Used
/// in `uut client` mode to build the server's suite capability
/// set from `peer.capabilities`.
pub fn tls13_suite_wire_value(name: &str) -> Option<u16> {
    Some(match name {
        "aes128_gcm_sha256" => 0x1301,
        "aes256_gcm_sha384" => 0x1302,
        "chacha20_poly1305_sha256" => 0x1303,
        "aes128_ccm_sha256" => 0x1304,
        "aes128_ccm_8_sha256" => 0x1305,
        _ => return None,
    })
}

/// Resolve a named TLS SignatureScheme to its IANA wire value.
/// Covers the TLS 1.3 SignatureScheme registry (RFC 8446 §4.2.3)
/// plus the legacy TLS 1.2 hash/sig pairs (RFC 5246 §7.4.1.4.1)
/// that tlsfuzzer's signature-algorithm tests reach for — including
/// the obsolete MD5/SHA-1 codepoints a hardened server must reject.
pub fn sigalg_wire_value(name: &str) -> Option<u16> {
    Some(match name {
        // Legacy TLS 1.2 {hash, signature} pairs.
        "rsa_pkcs1_md5" => 0x0101,
        "rsa_pkcs1_sha1" => 0x0201,
        "rsa_pkcs1_sha224" => 0x0301,
        "rsa_pkcs1_sha256" => 0x0401,
        "rsa_pkcs1_sha384" => 0x0501,
        "rsa_pkcs1_sha512" => 0x0601,
        "ecdsa_sha1" => 0x0203,
        // T3: the remaining RFC 5246 7.4.1.4.1 ECDSA pairs and the RFC 8734
        // TLS 1.3 brainpool codepoints (labels for the mismatch negatives).
        "ecdsa_md5" => 0x0103,
        "ecdsa_sha224" => 0x0303,
        "ecdsa_brainpoolP256r1tls13_sha256" => 0x081a,
        "ecdsa_brainpoolP384r1tls13_sha384" => 0x081b,
        "ecdsa_brainpoolP512r1tls13_sha512" => 0x081c,
        "dsa_sha1" => 0x0202,
        "dsa_sha256" => 0x0402,
        // ECDSA (TLS 1.3 names; same wire values usable in 1.2).
        "ecdsa_secp256r1_sha256" => 0x0403,
        "ecdsa_secp384r1_sha384" => 0x0503,
        "ecdsa_secp521r1_sha512" => 0x0603,
        // RSASSA-PSS with rsaEncryption OID.
        "rsa_pss_rsae_sha256" => 0x0804,
        "rsa_pss_rsae_sha384" => 0x0805,
        "rsa_pss_rsae_sha512" => 0x0806,
        // EdDSA.
        "ed25519" => 0x0807,
        "ed448" => 0x0808,
        // RSASSA-PSS with RSASSA-PSS OID.
        "rsa_pss_pss_sha256" => 0x0809,
        "rsa_pss_pss_sha384" => 0x080a,
        "rsa_pss_pss_sha512" => 0x080b,
        _ => return None,
    })
}

/// Resolve a named extension to its IANA wire type number.
/// Returns None for unknown names.
pub fn extension_wire_type(name: &str) -> Option<u16> {
    Some(match name {
        "server_name" => 0x0000,
        "max_fragment_length" => 0x0001,
        "status_request" => 0x0005,
        "supported_groups" => 0x000a,
        "ec_point_formats" => 0x000b,
        "signature_algorithms" => 0x000d,
        "use_srtp" => 0x000e,
        "heartbeat" => 0x000f,
        "application_layer_protocol_negotiation" | "alpn" => 0x0010,
        "signed_certificate_timestamp" => 0x0012,
        "client_certificate_type" => 0x0013,
        "server_certificate_type" => 0x0014,
        "padding" => 0x0015,
        "extended_master_secret" => 0x0017,
        "session_ticket" => 0x0023,
        "pre_shared_key" => 0x0029,
        "early_data" => 0x002a,
        "supported_versions" => 0x002b,
        "cookie" => 0x002c,
        "psk_key_exchange_modes" => 0x002d,
        "certificate_authorities" => 0x002f,
        "oid_filters" => 0x0030,
        "post_handshake_auth" => 0x0031,
        "signature_algorithms_cert" => 0x0032,
        "key_share" => 0x0033,
        "renegotiation_info" => 0xff01,
        "status_request_v2" => 0x0011,
        "encrypt_then_mac" => 0x0016,
        "compress_certificate" => 0x001b,
        "record_size_limit" => 0x001c,
        "delegated_credential" => 0x0022,
        "quic_transport_parameters" => 0x0039,
        "next_protocol_negotiation" => 0x3374,
        "application_settings" => 0x4469,
        "trust_anchors" => 0xca34,
        "encrypted_client_hello" => 0xfe0d,
        _ => return None,
    })
}

// ================== Typed extension value vocabularies ==================
//
// Symbolic names accepted on the right-hand side of `+ext NAME = ...` for the
// extensions with typed encoders (see lower::encode_ext_body). Each maps a name
// to its IANA wire value.

/// ECPointFormat (RFC 8422 5.1.2).
pub fn ec_point_format_value(name: &str) -> Option<u8> {
    Some(match name {
        "uncompressed" => 0,
        "ansix962_compressed_prime" => 1,
        "ansix962_compressed_char2" => 2,
        _ => return None,
    })
}

/// CertificateType (RFC 7250 / RFC 6091): `x509`, `raw_public_key`, `openpgp`.
pub fn cert_type_value(name: &str) -> Option<u8> {
    Some(match name {
        "x509" => 0,
        "openpgp" => 1,
        "raw_public_key" => 2,
        _ => return None,
    })
}

/// PskKeyExchangeMode (RFC 8446 4.2.9).
pub fn psk_mode_value(name: &str) -> Option<u8> {
    Some(match name {
        "psk_ke" => 0,
        "psk_dhe_ke" => 1,
        _ => return None,
    })
}

/// SRTP protection profile (RFC 5764 / RFC 7714) for `use_srtp`.
pub fn srtp_profile_value(name: &str) -> Option<u16> {
    Some(match name {
        "srtp_aes128_cm_hmac_sha1_80" => 0x0001,
        "srtp_aes128_cm_hmac_sha1_32" => 0x0002,
        "srtp_null_hmac_sha1_80" => 0x0005,
        "srtp_null_hmac_sha1_32" => 0x0006,
        "srtp_aead_aes_128_gcm" => 0x0007,
        "srtp_aead_aes_256_gcm" => 0x0008,
        _ => return None,
    })
}

/// HeartbeatMode (RFC 6520 2).
pub fn heartbeat_mode_value(name: &str) -> Option<u8> {
    Some(match name {
        "peer_allowed_to_send" => 1,
        "peer_not_allowed_to_send" => 2,
        _ => return None,
    })
}

/// CertificateCompressionAlgorithm (RFC 8879 3).
pub fn cert_compression_value(name: &str) -> Option<u16> {
    Some(match name {
        "zlib" => 1,
        "brotli" => 2,
        "zstd" => 3,
        _ => return None,
    })
}

/// MaxFragmentLength code (RFC 6066 4) for a fragment size in bytes.
pub fn max_fragment_length_code(size: i64) -> Option<u8> {
    Some(match size {
        512 => 1,
        1024 => 2,
        2048 => 3,
        4096 => 4,
        _ => return None,
    })
}

// ========================== Alert codes ==========================

pub const ALERT_LEVELS: &[(&str, u8)] = &[("warning", 1), ("fatal", 2)];

/// TLS alert descriptions with their RFC wire values.
/// RFC 5246 §7.2 (TLS 1.2) + RFC 8446 §6 (TLS 1.3).
pub const ALERT_CODES: &[(&str, u8)] = &[
    ("close_notify", 0),
    ("unexpected_message", 10),
    ("bad_record_mac", 20),
    ("decryption_failed", 21),
    ("record_overflow", 22),
    ("decompression_failure", 30),
    ("handshake_failure", 40),
    ("no_certificate", 41),
    ("bad_certificate", 42),
    ("unsupported_certificate", 43),
    ("certificate_revoked", 44),
    ("certificate_expired", 45),
    ("certificate_unknown", 46),
    ("illegal_parameter", 47),
    ("unknown_ca", 48),
    ("access_denied", 49),
    ("decode_error", 50),
    ("decrypt_error", 51),
    ("export_restriction", 60),
    ("protocol_version", 70),
    ("insufficient_security", 71),
    ("internal_error", 80),
    ("inappropriate_fallback", 86),
    ("user_canceled", 90),
    ("no_renegotiation", 100),
    ("missing_extension", 109),
    ("unsupported_extension", 110),
    ("unrecognized_name", 112),
    ("bad_certificate_status_response", 113),
    ("unknown_psk_identity", 115),
    ("certificate_required", 116),
    ("no_application_protocol", 120),
];

pub fn is_alert_level(s: &str) -> bool {
    ALERT_LEVELS.iter().any(|(n, _)| *n == s)
}

pub fn is_alert_code(s: &str) -> bool {
    ALERT_CODES.iter().any(|(n, _)| *n == s)
}

pub fn alert_level_value(s: &str) -> Option<u8> {
    ALERT_LEVELS
        .iter()
        .find_map(|(n, v)| if *n == s { Some(*v) } else { None })
}

pub fn alert_code_value(s: &str) -> Option<u8> {
    ALERT_CODES
        .iter()
        .find_map(|(n, v)| if *n == s { Some(*v) } else { None })
}

pub fn alert_level_name(v: u8) -> Option<&'static str> {
    ALERT_LEVELS
        .iter()
        .find_map(|(n, val)| if *val == v { Some(*n) } else { None })
}

pub fn alert_code_name(v: u8) -> Option<&'static str> {
    ALERT_CODES
        .iter()
        .find_map(|(n, val)| if *val == v { Some(*n) } else { None })
}

/// Just the names, for `did you mean?` suggestions in the checker.
pub fn alert_code_name_list() -> Vec<&'static str> {
    ALERT_CODES.iter().map(|(n, _)| *n).collect()
}

pub fn alert_level_name_list() -> Vec<&'static str> {
    ALERT_LEVELS.iter().map(|(n, _)| *n).collect()
}

// ========================== Byte paths ==========================

/// Valid structured byte-target path prefixes.
pub const BYTE_PATHS: &[&[&str]] = &[
    // T4: the PKCS#1 v1.5 EM of a static-RSA ClientKeyExchange, before
    // encryption (`00 || 02 || PS || 00 || premaster`): `em` the whole block,
    // `block_type` byte 1, `padding` the PS, `separator` the 0x00 before the
    // premaster, `premaster` the 48 bytes. The Bleichenbacher / Marvin
    // padding-fault classes are set through these.
    &["pkcs1", "em"],
    &["pkcs1", "block_type"],
    &["pkcs1", "padding"],
    &["pkcs1", "separator"],
    &["pkcs1", "premaster"],
    &["record", "content_type"],
    &["record", "mac"],
    &["record", "aead_tag"],
    &["record", "encrypted_record"],
    // Length-preserving record-header fields, edited after sealing so the body
    // stays protected under the header the sender actually used: a record
    // whose header lies about its version, epoch or sequence number is
    // "otherwise invalid" (RFC 6347 4.1.2.7) and a DTLS peer discards it.
    // `record.version` is the 2-byte version at header offset 1 (TLS and
    // DTLS); `record.epoch` (offset 3..5) and `record.sequence_number`
    // (5..11) exist only on the 13-byte DTLS 1.2 header. The header length
    // field is deliberately not a target: changing it without changing the
    // body desynchronizes plzn's own datagram packer, and a raw datagram
    // expresses a lying length directly.
    &["record", "version"],
    &["record", "epoch"],
    &["record", "sequence_number"],
    // T2: pre-encryption regions. `record.padding` is the CBC padding
    // (index -1 = the length byte); `record.plaintext` the whole block before
    // encryption (CBC: data || MAC || padding, AEAD: the AEAD plaintext, which
    // for TLS 1.3 ends in the inner content type and any record padding);
    // `record.inner_type` the TLS 1.3 inner content type byte.
    &["record", "padding"],
    &["record", "plaintext"],
    &["record", "inner_type"],
    &["handshake", "verify_data"],
    &["handshake", "signature"],
    // The (EC)DHE public value: the first KeyShareEntry's key_exchange in a
    // ClientHello / ServerHello key_share (TLS 1.3), or the point in a TLS 1.2
    // ServerKeyExchange / ClientKeyExchange. Flip a byte of a NIST-curve point
    // to take it off the curve; set bit 255 of an x25519 share (masked per
    // RFC 7748); the peer must validate (RFC 8446 4.2.8.2, 7.4.2).
    &["handshake", "key_share"],
    &["handshake", "ecdh_point"],
    // Handshake message header (applied post-framing): msg_type = 1-byte type,
    // length = 3-byte length. For WrongMessageType / bad-length tests.
    &["handshake", "msg_type"],
    &["handshake", "length"],
    // T3: the RSASSA encoded message of plzn's client CertificateVerify, edited
    // BEFORE the private-key operation (tlsfuzzer `padding_xors`): byte 0 is
    // the leading 0x00, 1 the block type (PKCS#1 v1.5), -1 the trailer (PSS).
    &["signature", "em"],
];

/// The `handshake.<field>` byte regions each TLS 1.2 / DTLS message's mapped
/// encoder produces. Both DTLS roles route every sender through a mapped
/// encoder, so these are exactly the structured targets that resolve over DTLS
/// (`lower` rejects any other `handshake.<field>` on a DTLS send); the TLS 1.2
/// drivers share the encoders where they use the same message forms. The
/// TLS 1.3 `key_share` and the framing targets `msg_type` / `length` are
/// listed in `BYTE_PATHS`.
pub fn handshake_byte_fields(msg: &str) -> &'static [&'static str] {
    match msg {
        "ClientHello" => &[
            "legacy_version",
            "random",
            "legacy_session_id",
            "cookie",
            "cipher_suites",
            "compression_methods",
            "extensions",
            // T2: the length prefixes, for length-field fuzzing (tlsfuzzer
            // test-invalid-client-hello): 1, 2, 1 and 2 bytes respectively.
            "session_id_length",
            "cipher_suites_length",
            "compression_methods_length",
            "extensions_length",
            "key_share",
            // The first generated PSK identity and binder. These are named so
            // tests do not depend on pre_shared_key being the final extension.
            "obfuscated_ticket_age",
            "psk_binder",
        ],
        "ServerHello" | "HelloRetryRequest" => &[
            "legacy_version",
            "random",
            "legacy_session_id_echo",
            "cipher_suite",
            "legacy_compression_method",
            "extensions",
            "session_id_length",
            "extensions_length",
            "key_share",
        ],
        "EncryptedExtensions" => &["extensions_length"],
        "Certificate" => &[
            "request_context_length",
            "certificate_list_length",
            "certificate_list",
            "first_certificate_length",
            "first_certificate_extensions_length",
        ],
        "CertificateRequest" => &[
            "certificate_types",
            "certificate_types_length",
            "signature_algorithms",
            "signature_algorithms_length",
            "certificate_authorities",
            "certificate_authorities_length",
            "first_authority_length",
            "request_context_length",
            "extensions_length",
        ],
        "ServerKeyExchange" => &[
            "ecdh_point",
            "ecdh_point_length",
            "signature",
            "signature_length",
            "dh_p",
            "dh_p_length",
            "dh_g",
            "dh_g_length",
            "dh_Ys",
            "dh_Ys_length",
            "psk_identity_hint",
            "psk_identity_hint_length",
            "named_group",
        ],
        "ClientKeyExchange" => &[
            "ecdh_Yc",
            "ecdh_point",
            "ecdh_point_length",
            "encrypted_premaster",
            "encrypted_premaster_length",
            "dh_Yc",
            "dh_Yc_length",
            "psk_identity",
            "psk_identity_length",
        ],
        "CertificateVerify" => &["algorithm", "signature", "signature_length"],
        "Finished" => &["verify_data"],
        "NewSessionTicket" => &[
            "lifetime",
            "ticket_lifetime",
            "ticket_age_add",
            "ticket_nonce",
            "ticket_nonce_length",
            "ticket",
            "ticket_length",
            "extensions_length",
        ],
        "CertificateStatus" => &["status_type", "response", "response_length"],
        _ => &[],
    }
}

const HANDSHAKE_FIELD_MESSAGES: &[&str] = &[
    "ClientHello",
    "ServerHello",
    "EncryptedExtensions",
    "Certificate",
    "CertificateRequest",
    "ServerKeyExchange",
    "ClientKeyExchange",
    "CertificateVerify",
    "Finished",
    "NewSessionTicket",
    "CertificateStatus",
];

/// Every `handshake.<field>` name some mapped encoder produces, deduplicated.
fn all_handshake_byte_fields() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for m in HANDSHAKE_FIELD_MESSAGES {
        for f in handshake_byte_fields(m) {
            if !out.contains(f) {
                out.push(f);
            }
        }
    }
    out
}

pub fn is_byte_path(parts: &[&str]) -> bool {
    BYTE_PATHS
        .iter()
        .any(|p| p.len() == parts.len() && p.iter().zip(parts).all(|(a, b)| a == b))
        || (parts.len() == 2
            && parts[0] == "handshake"
            && all_handshake_byte_fields().contains(&parts[1]))
}

pub fn byte_path_candidates() -> Vec<String> {
    let mut out: Vec<String> = BYTE_PATHS.iter().map(|p| p.join(".")).collect();
    for f in all_handshake_byte_fields() {
        let path = format!("handshake.{}", f);
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// Complete integer fields accepted by `add[...]` / `sub[...]`. These are
/// deliberately separate from byte targets: an adjustment reads and writes
/// the whole big-endian prefix atomically.
pub const LENGTH_FIELD_NAMES: &[&str] = &[
    "length",
    "session_id_length",
    "cipher_suites_length",
    "compression_methods_length",
    "extensions_length",
    "request_context_length",
    "certificate_list_length",
    "first_certificate_length",
    "first_certificate_extensions_length",
    "signature_length",
    "ecdh_point_length",
    "encrypted_premaster_length",
    "dh_Yc_length",
    "dh_p_length",
    "dh_g_length",
    "dh_Ys_length",
    "psk_identity_hint_length",
    "psk_identity_length",
    "certificate_types_length",
    "signature_algorithms_length",
    "certificate_authorities_length",
    "first_authority_length",
    "ticket_nonce_length",
    "ticket_length",
    "response_length",
    "extension_server_name_length",
    "extension_server_name_list_length",
    "extension_server_name_host_name_length",
    "extension_supported_groups_length",
    "extension_supported_groups_list_length",
    "extension_ec_point_formats_length",
    "extension_ec_point_formats_list_length",
    "extension_signature_algorithms_length",
    "extension_signature_algorithms_list_length",
    "extension_signature_algorithms_cert_length",
    "extension_signature_algorithms_cert_list_length",
    "extension_extended_master_secret_length",
    "extension_session_ticket_length",
    "extension_renegotiation_info_length",
    "extension_renegotiation_info_info_length",
    "extension_supported_versions_length",
    "extension_supported_versions_list_length",
    "extension_key_share_length",
    "extension_key_share_list_length",
    "extension_key_share_key_exchange_length",
    "extension_psk_key_exchange_modes_length",
    "extension_psk_key_exchange_modes_list_length",
    "extension_pre_shared_key_length",
    "extension_pre_shared_key_identity_list_length",
    "extension_pre_shared_key_identity_length",
    "extension_pre_shared_key_binder_list_length",
    "extension_pre_shared_key_binder_length",
    "extension_alpn_length",
    "extension_alpn_list_length",
    "extension_encrypt_then_mac_length",
    "extension_heartbeat_length",
    "extension_padding_length",
    "extension_use_srtp_length",
    "extension_use_srtp_profiles_length",
    "extension_use_srtp_mki_length",
    "extension_compress_certificate_length",
    "extension_compress_certificate_list_length",
    "extension_certificate_authorities_length",
    "extension_certificate_authorities_list_length",
    "extension_certificate_authorities_first_authority_length",
];

pub fn is_length_path(parts: &[&str]) -> bool {
    parts.len() == 2 && parts[0] == "handshake" && LENGTH_FIELD_NAMES.contains(&parts[1])
}

pub fn length_path_candidates() -> Vec<String> {
    LENGTH_FIELD_NAMES
        .iter()
        .map(|name| format!("handshake.{}", name))
        .collect()
}

// ========================== Named asserts ==========================

pub const NAMED_ASSERTS: &[&str] = &[
    "no_duplicate_record_seqnums",
    "gcm_nonces_unique",
    "gcm_nonces_monotonic",
];

pub fn is_named_assert(s: &str) -> bool {
    NAMED_ASSERTS.contains(&s)
}

// ========================== Values for field overrides ==========================

/// Enum-valued symbolic values recognised in field override RHS.
/// E.g. `request_update: update_requested`.
pub const FIELD_VALUE_IDENTS: &[&str] = &[
    "update_requested",
    "update_not_requested",
    // key_share_point recipes
    "compressed",
    "zero",
    "truncated",
    "padded",
    "one",
    "p_minus_1",
    // send Certificate { credential: ... }
    "valid",
    "untrusted",
    "none",
];

pub fn is_field_value_ident(s: &str) -> bool {
    FIELD_VALUE_IDENTS.contains(&s) || is_alert_code(s) || is_alert_level(s)
}

// ========================== Matrix named sets ==========================

pub const MATRIX_NAMED_SETS: &[&str] = &["cipher_suites", "cert_models", "groups", "grease"];

pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub fn is_matrix_named_set(s: &str) -> bool {
    MATRIX_NAMED_SETS.contains(&s)
}

// ======================= Named constants (track D) =======================
//
// Every cipher suite, named group, signature scheme, extension type and
// client certificate type the DSL knows has a name, and a known value MUST be
// written by name: numeric literals are for unassigned, reserved or GREASE
// codepoints. `NameDomain` says which table a field or extension body draws
// from; `domain_name` is the reverse lookup the lint uses to say which name a
// literal should have been.

/// The value domains that carry names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NameDomain {
    /// Cipher suites: the IANA names without the `TLS_` prefix
    /// (`ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `AES_128_GCM_SHA256`) plus the
    /// two signalling values (`EMPTY_RENEGOTIATION_INFO_SCSV`, `FALLBACK_SCSV`).
    Suite,
    /// Named groups (RFC 8422 / 7919 / 8734 / the ML-KEM drafts).
    Group,
    /// Signature schemes (RFC 8446 4.2.3 plus the RFC 5246 pairs).
    Sigalg,
    /// Extension types (RFC 8446 4.2 and the registry).
    Extension,
    /// ClientCertificateType (RFC 5246 7.4.4, RFC 8422 5.5).
    CertType,
}

impl NameDomain {
    pub fn label(self) -> &'static str {
        match self {
            NameDomain::Suite => "cipher suite",
            NameDomain::Group => "named group",
            NameDomain::Sigalg => "signature scheme",
            NameDomain::Extension => "extension type",
            NameDomain::CertType => "certificate type",
        }
    }
}

/// The two cipher-suite signalling values (RFC 5746 3.3, RFC 7507 2).
const SIGNALLING_SUITES: &[(&str, u16)] = &[
    ("EMPTY_RENEGOTIATION_INFO_SCSV", 0x00ff),
    ("FALLBACK_SCSV", 0x5600),
];

/// Resolve a cipher-suite name (`ECDHE_RSA_WITH_AES_128_GCM_SHA256`, an
/// optional `TLS_` prefix, any letter case) to its wire value.
pub fn suite_wire_value(name: &str) -> Option<u16> {
    let upper = name.to_ascii_uppercase();
    let bare = upper.strip_prefix("TLS_").unwrap_or(&upper);
    crate::ir::ALL_SUITES
        .iter()
        .find(|s| s.name == bare)
        .map(|s| s.wire)
        .or_else(|| {
            SIGNALLING_SUITES
                .iter()
                .find(|(n, _)| *n == bare)
                .map(|(_, w)| *w)
        })
}

/// The canonical name of a cipher-suite wire value plzn knows.
pub fn suite_name(wire: u16) -> Option<&'static str> {
    crate::ir::ALL_SUITES
        .iter()
        .find(|s| s.wire == wire)
        .map(|s| s.name)
        .or_else(|| {
            SIGNALLING_SUITES
                .iter()
                .find(|(_, w)| *w == wire)
                .map(|(n, _)| *n)
        })
}

/// Canonical group names (the IANA spellings), one per wire value.
const GROUP_NAMES: &[(&str, u16)] = &[
    ("secp256r1", 0x0017),
    ("secp384r1", 0x0018),
    ("secp521r1", 0x0019),
    ("x25519", 0x001d),
    ("x448", 0x001e),
    ("ffdhe2048", 0x0100),
    ("ffdhe3072", 0x0101),
    ("ffdhe4096", 0x0102),
    ("ffdhe6144", 0x0103),
    ("ffdhe8192", 0x0104),
    ("brainpoolP256r1", 0x001a),
    ("brainpoolP384r1", 0x001b),
    ("brainpoolP512r1", 0x001c),
    ("brainpoolP256r1tls13", 0x001f),
    ("brainpoolP384r1tls13", 0x0020),
    ("brainpoolP512r1tls13", 0x0021),
    ("MLKEM512", 0x0200),
    ("MLKEM768", 0x0201),
    ("MLKEM1024", 0x0202),
    ("SecP256r1MLKEM768", 0x11eb),
    ("X25519MLKEM768", 0x11ec),
    ("SecP384r1MLKEM1024", 0x11ed),
    ("X448MLKEM1024", 0x11ee),
];

/// The canonical name of a named-group wire value.
pub fn group_name(wire: u16) -> Option<&'static str> {
    GROUP_NAMES
        .iter()
        .find(|(_, w)| *w == wire)
        .map(|(n, _)| *n)
}

/// Canonical signature-scheme names, one per wire value.
const SIGALG_NAMES: &[(&str, u16)] = &[
    ("rsa_pkcs1_md5", 0x0101),
    ("rsa_pkcs1_sha1", 0x0201),
    ("rsa_pkcs1_sha224", 0x0301),
    ("rsa_pkcs1_sha256", 0x0401),
    ("rsa_pkcs1_sha384", 0x0501),
    ("rsa_pkcs1_sha512", 0x0601),
    ("ecdsa_md5", 0x0103),
    ("ecdsa_sha1", 0x0203),
    ("ecdsa_sha224", 0x0303),
    ("dsa_sha1", 0x0202),
    ("dsa_sha256", 0x0402),
    ("ecdsa_secp256r1_sha256", 0x0403),
    ("ecdsa_secp384r1_sha384", 0x0503),
    ("ecdsa_secp521r1_sha512", 0x0603),
    ("rsa_pss_rsae_sha256", 0x0804),
    ("rsa_pss_rsae_sha384", 0x0805),
    ("rsa_pss_rsae_sha512", 0x0806),
    ("ed25519", 0x0807),
    ("ed448", 0x0808),
    ("rsa_pss_pss_sha256", 0x0809),
    ("rsa_pss_pss_sha384", 0x080a),
    ("rsa_pss_pss_sha512", 0x080b),
    ("ecdsa_brainpoolP256r1tls13_sha256", 0x081a),
    ("ecdsa_brainpoolP384r1tls13_sha384", 0x081b),
    ("ecdsa_brainpoolP512r1tls13_sha512", 0x081c),
];

/// The canonical name of a signature-scheme wire value.
pub fn sigalg_name(wire: u16) -> Option<&'static str> {
    SIGALG_NAMES
        .iter()
        .find(|(_, w)| *w == wire)
        .map(|(n, _)| *n)
}

/// Canonical extension names, one per wire type (`alpn` for 0x0010).
const EXTENSION_NAMES: &[(&str, u16)] = &[
    ("server_name", 0x0000),
    ("max_fragment_length", 0x0001),
    ("status_request", 0x0005),
    ("supported_groups", 0x000a),
    ("ec_point_formats", 0x000b),
    ("signature_algorithms", 0x000d),
    ("use_srtp", 0x000e),
    ("heartbeat", 0x000f),
    ("alpn", 0x0010),
    ("status_request_v2", 0x0011),
    ("signed_certificate_timestamp", 0x0012),
    ("client_certificate_type", 0x0013),
    ("server_certificate_type", 0x0014),
    ("padding", 0x0015),
    ("encrypt_then_mac", 0x0016),
    ("extended_master_secret", 0x0017),
    ("compress_certificate", 0x001b),
    ("record_size_limit", 0x001c),
    ("delegated_credential", 0x0022),
    ("session_ticket", 0x0023),
    ("pre_shared_key", 0x0029),
    ("early_data", 0x002a),
    ("supported_versions", 0x002b),
    ("cookie", 0x002c),
    ("psk_key_exchange_modes", 0x002d),
    ("certificate_authorities", 0x002f),
    ("oid_filters", 0x0030),
    ("post_handshake_auth", 0x0031),
    ("signature_algorithms_cert", 0x0032),
    ("key_share", 0x0033),
    ("quic_transport_parameters", 0x0039),
    ("next_protocol_negotiation", 0x3374),
    ("application_settings", 0x4469),
    ("trust_anchors", 0xca34),
    ("encrypted_client_hello", 0xfe0d),
    ("renegotiation_info", 0xff01),
];

/// The canonical name of an extension wire type.
pub fn extension_name(wire: u16) -> Option<&'static str> {
    EXTENSION_NAMES
        .iter()
        .find(|(_, w)| *w == wire)
        .map(|(n, _)| *n)
}

/// ClientCertificateType names (RFC 5246 7.4.4, RFC 8422 5.5).
const CERT_TYPE_NAMES: &[(&str, u16)] = &[
    ("rsa_sign", 1),
    ("dss_sign", 2),
    ("rsa_fixed_dh", 3),
    ("dss_fixed_dh", 4),
    ("ecdsa_sign", 64),
    ("rsa_fixed_ecdh", 65),
    ("ecdsa_fixed_ecdh", 66),
];

pub fn cert_type_wire_value(name: &str) -> Option<u8> {
    CERT_TYPE_NAMES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, w)| *w as u8)
}

pub fn cert_type_name(wire: u8) -> Option<&'static str> {
    CERT_TYPE_NAMES
        .iter()
        .find(|(_, w)| *w == wire as u16)
        .map(|(n, _)| *n)
}

/// The canonical name of `value` in `domain`, if the value has one.
pub fn domain_name(domain: NameDomain, value: i64) -> Option<&'static str> {
    if !(0..=0xffff).contains(&value) {
        return None;
    }
    let w = value as u16;
    match domain {
        NameDomain::Suite => suite_name(w),
        NameDomain::Group => group_name(w),
        NameDomain::Sigalg => sigalg_name(w),
        NameDomain::Extension => extension_name(w),
        NameDomain::CertType => u8::try_from(w).ok().and_then(cert_type_name),
    }
}

/// Resolve a name in `domain` to its wire value.
pub fn domain_wire_value(domain: NameDomain, name: &str) -> Option<u16> {
    match domain {
        NameDomain::Suite => suite_wire_value(name),
        NameDomain::Group => group_wire_value(name),
        NameDomain::Sigalg => sigalg_wire_value(name),
        NameDomain::Extension => extension_wire_type(name),
        NameDomain::CertType => cert_type_wire_value(name).map(u16::from),
    }
}

/// Every (name, value) pair of a domain, canonical names only, in table order.
pub fn domain_names(domain: NameDomain) -> Vec<(&'static str, u16)> {
    match domain {
        NameDomain::Suite => {
            let mut v: Vec<(&'static str, u16)> = crate::ir::ALL_SUITES
                .iter()
                .map(|s| (s.name, s.wire))
                .collect();
            v.extend(SIGNALLING_SUITES.iter().copied());
            v
        }
        NameDomain::Group => GROUP_NAMES.to_vec(),
        NameDomain::Sigalg => SIGALG_NAMES.to_vec(),
        NameDomain::Extension => EXTENSION_NAMES.to_vec(),
        NameDomain::CertType => CERT_TYPE_NAMES.to_vec(),
    }
}

/// The lint text for a numeric literal that has a name; stable, since
/// `tools/name_constants.py` parses it to rewrite the corpus.
pub fn named_literal_message(domain: NameDomain, value: i64, name: &str) -> String {
    let literal = match domain {
        NameDomain::CertType => format!("{}", value),
        _ => format!("0x{:04x}", value),
    };
    format!(
        "`{}` is {}; write the name (numeric values are for unassigned or deliberately unknown codepoints)",
        literal, name
    )
}

/// Which name domain a message field draws its values from, when it has one.
/// `algorithm` on a CompressedCertificate names a compression algorithm, not
/// a signature scheme, so that one stays unnamed here.
pub fn field_domain(msg: &str, field: &str) -> Option<NameDomain> {
    Some(match field {
        "cipher_suites" | "cipher_suite" | "lacks_cipher_suite" => NameDomain::Suite,
        "named_group"
        | "key_share_group"
        | "supported_groups"
        | "lacks_supported_group"
        | "dh_group" => NameDomain::Group,
        "signature_scheme" | "signature_algorithms" | "sign_with" => NameDomain::Sigalg,
        "algorithm" if msg == "CertificateVerify" => NameDomain::Sigalg,
        "has_ext" | "lacks_ext" | "extensions_exactly" | "leaf_has_ext" | "leaf_lacks_ext" => {
            NameDomain::Extension
        }
        "certificate_types" => NameDomain::CertType,
        _ => return None,
    })
}

/// The domain of an extension's typed body, for the encoders that take a
/// list of names or wire values.
pub fn extension_body_domain(ext_name: &str) -> Option<NameDomain> {
    Some(match ext_name {
        "supported_groups" | "key_share" => NameDomain::Group,
        "signature_algorithms" | "signature_algorithms_cert" => NameDomain::Sigalg,
        _ => return None,
    })
}

#[cfg(test)]
mod named_constant_tests {
    use super::*;

    #[test]
    fn suite_names_round_trip_with_optional_prefix() {
        assert_eq!(
            suite_wire_value("ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            Some(0xc02f)
        );
        assert_eq!(
            suite_wire_value("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            Some(0xc02f)
        );
        assert_eq!(suite_wire_value("tls_aes_128_gcm_sha256"), Some(0x1301));
        assert_eq!(suite_name(0x1301), Some("AES_128_GCM_SHA256"));
        assert_eq!(suite_name(0x00ff), Some("EMPTY_RENEGOTIATION_INFO_SCSV"));
        assert_eq!(suite_name(0x0a0a), None);
    }

    #[test]
    fn reverse_tables_agree_with_the_forward_lookups() {
        for (name, wire) in GROUP_NAMES {
            assert_eq!(group_wire_value(name), Some(*wire), "{}", name);
        }
        for (name, wire) in SIGALG_NAMES {
            assert_eq!(sigalg_wire_value(name), Some(*wire), "{}", name);
        }
        for (name, wire) in EXTENSION_NAMES {
            assert_eq!(extension_wire_type(name), Some(*wire), "{}", name);
        }
        for (name, wire) in CERT_TYPE_NAMES {
            assert_eq!(cert_type_wire_value(name), Some(*wire as u8), "{}", name);
        }
    }

    #[test]
    fn named_literal_message_is_stable() {
        assert_eq!(
            named_literal_message(
                NameDomain::Suite,
                0xc02f,
                "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ),
            "`0xc02f` is ECDHE_RSA_WITH_AES_128_GCM_SHA256; write the name (numeric values are for unassigned or deliberately unknown codepoints)"
        );
        assert_eq!(domain_name(NameDomain::CertType, 64), Some("ecdsa_sign"));
        assert_eq!(domain_name(NameDomain::Extension, 0x0a0a), None);
    }
}
