// Intermediate representation: the parsed AST, lowered into a flat
// program where presets are expanded and matrix variables resolved.
//
// One `ir::Program` = one concrete test case. The runtime walks
// Programs and never touches the raw AST.
//
// Design goals carried over from `DSL.md §6` / `STRESS_TEST.md §3`:
//
//   * **Flat and inspectable.** Presets expand into concrete steps, with
//     occurrence-specific configuration attached to explicit messages.
//   * **All substitutions resolved.** No matrix variables, no
//     unresolved presets. The runtime sees concrete work.
//   * **Spans preserved.** Every step carries an `ast::Span`
//     pointing back at the source so the diagnostic layer can
//     render a caret.

use crate::ast::Span;
use crate::server::certs::KeyType;
use crate::tls::crypto::HashAlg;
use crate::tls::record::TlsVersion;

#[derive(Clone, Debug)]
pub struct Program {
    pub test_id: String,
    pub test_id_span: Span,
    pub version: TlsVersion,
    /// Wire protocol. DTLS reuses `version` for its crypto (DTLS 1.2 = TLS 1.2
    /// key schedule) but runs a datagram record layer with epoch + explicit
    /// sequence numbers, and a dedicated driver.
    pub protocol: Protocol,
    pub subject: Subject,
    pub server_name: String,
    pub steps: Vec<Step>,
    /// Handshake messages the harness sends in this concrete program. The
    /// lowering pass records the selected preset as well as explicit steps so
    /// discovery tooling can enumerate typed mutation sites without guessing
    /// which role/version flight is active.
    pub mutation_messages: Vec<MessageKind>,
    pub expect: Expectation,
    /// Per-UUT expectation overrides. Checked in order; the first
    /// whose `uut` substring-matches the peer description wins.
    pub expect_overrides: Vec<(String, Expectation)>,
    pub rfc_refs: Vec<RfcRef>,
    /// Field overrides to apply to preset-handshake messages that
    /// the harness *sends*.
    pub send_overrides: Vec<MessageOverrides>,
    /// Field matchers to apply to preset-handshake messages that
    /// the harness *receives*.
    pub recv_matchers: Vec<MessageOverrides>,
    /// Byte-level mutations to apply to preset-handshake messages
    /// the harness sends, post-serialisation. Separated from
    /// `send_overrides` because they fire at a different pipeline
    /// stage (after encoding, not before).
    pub send_mutations: Vec<MessageMutations>,
    /// Per-message extension list deltas: add/remove entries
    /// before encoding.
    pub send_ext_deltas: Vec<MessageExtDeltas>,
    /// T5: overrides / mutations / deltas declared AFTER a TLS
    /// `begin_renegotiation` step. The TLS 1.2 client appends them to its
    /// lists when the renegotiation begins, so they shape the second
    /// handshake's messages only (the initial handshake never sees them).
    pub reneg_send_overrides: Vec<MessageOverrides>,
    pub reneg_send_mutations: Vec<MessageMutations>,
    pub reneg_send_ext_deltas: Vec<MessageExtDeltas>,
    /// For `uut client` (harness = server): the cert DER and
    /// private key PKCS#8 DER the harness presents. Populated by
    /// the runtime from a CertBundle before execution. None for
    /// `uut server` (harness = client).
    pub cert_der: Option<Vec<u8>>,
    pub private_key_der: Option<Vec<u8>>,
    // A: certificate chains. `chain_names` / `client_chain_names` are the
    // header's required `chain:` list and optional `client_chain:` list. The
    // runner resolves them per run: `server_chains` are the chains plzn's own
    // SERVER holds (uut client), `client_credentials` are the client-auth
    // credentials plzn's own CLIENT picks from (uut server), and the
    // `shim_*` lists the PEM files
    // the shim gets in the opposite role. `cert_der` / `private_key_der` stay
    // the first entry of the relevant list for the older code paths.
    pub chain_names: Vec<ChainName>,
    pub client_chain_names: Vec<ChainName>,
    /// The `ecdhe` capability makes the ECDHE family follow the chain (the runner adds a
    /// `SuiteFilter::ChainKeys` once the names are resolved).
    pub ecdhe_by_chain: bool,
    pub server_chains: Vec<Chain>,
    pub client_credentials: Vec<Chain>,
    pub shim_server_chains: Vec<ChainFiles>,
    pub shim_client_chains: Vec<ChainFiles>,
    /// For `uut client` (harness = server): intermediate CA certificates
    /// (DER) the harness-server presents after its leaf, so the peer can build a
    /// path to a trusted root. Empty = present the leaf only.
    pub extra_chain_der: Vec<Vec<u8>>,
    /// True if the `rsa` capability was specified — the driver should ONLY
    /// offer static RSA suites (no ECDHE). This forces the server
    /// to pick `TLS_RSA_WITH_AES_128_GCM_SHA256`.
    /// Filters over the cipher suite list. Each peer capability that
    /// names a kex type, cipher mode, or specific suite adds a
    /// filter. The driver starts with all supported suites and
    /// keeps only those matching ALL filters (intersection).
    /// Empty = no filtering = offer everything.
    pub suite_filters: Vec<SuiteFilter>,
    /// For `uut client` (harness = server): the TLS 1.3 cipher
    /// suites the harness-server is willing to negotiate, in
    /// preference order, derived from peer capability selectors. Empty =
    /// the driver's full implemented default set. The server selects
    /// the first of these the client also offered; if none is mutual
    /// the test is SKIPPED. Ignored in `uut server` mode.
    pub server_suites: Vec<u16>,
    /// For `uut client`: the named groups (by IANA wire value)
    /// the harness-server will select a key_share from, in preference
    /// order, derived from peer capability selectors. Empty = full default
    /// set. Selection requires the client to have *key-shared* the
    /// group (not merely listed it); otherwise SKIPPED. Ignored in
    /// `uut server` mode.
    pub server_groups: Vec<u16>,
    /// Groups the TLS 1.3 client (`uut server`) generates key shares for,
    /// in offer order. Empty = the driver default: the first of `server_groups`
    /// (the group capabilities), or x25519 when none were given. Set by the
    /// `group` matrix axis; a `+ext key_share = [...]` delta overrides both.
    pub key_share_groups: Vec<u16>,
    /// For `uut client`: the `hrr` / `second_hrr` peer capability is set, so
    /// the harness-server will send a HelloRetryRequest and should select a
    /// retry group the client listed but did not key-share (RFC 8446 4.2.8).
    pub force_hrr: bool,
    /// External PSK configuration for TLS 1.3 PSK-only mode.
    pub psk: Option<PskConfig>,
    /// Unit-under-test policy overrides (shim backends only). Independent of
    /// what the harness offers, so negotiation-failure tests can pin the UUT to
    /// reject a version/cipher/curve the harness sends.
    pub uut: Option<UutConfig>,
    /// Session name (for multi-session tests).
    pub session_name: Option<String>,
    /// Name of the session this one resumes from.
    pub resumes: Option<String>,
    /// Adversarial server mode: claim that an incompatible prior session was
    /// resumed even though the current-version ClientHello did not offer it.
    pub force_resumption: bool,
    /// Advertise psk_key_exchange_modes in the TLS 1.3 ClientHello so the
    /// server issues a NewSessionTicket. Set for the initial session of a
    /// resumption test; a realistic client always sends it, but eliciting a
    /// ticket complicates non-resumption tests, so it is opt-in here.
    pub advertise_psk_modes: bool,
    /// T5: the `session_id` capability resumes by session ID (RFC 5246 7.4.1.3): the
    /// initial session does not advertise tickets, the resuming one echoes the
    /// id the server assigned. TLS 1.2, `uut server`.
    pub resume_by_session_id: bool,
    /// The `psk_ke` capability makes a resuming TLS 1.3 client offer psk_ke only (no key
    /// share, RFC 8446 4.2.9) instead of psk_dhe_ke.
    pub resume_psk_ke: bool,
    /// Offer the server_certificate_type extension advertising RawPublicKey (RFC 7250).
    pub offer_raw_public_key: bool,
    /// Server side: compress the Certificate (RFC 8879 zlib) when the client advertises
    /// compress_certificate. Drives the client-decompression direction.
    pub server_compress_certificate: bool,
    /// Server side: DER-encoded Distinguished Names to advertise in the CertificateRequest's
    /// certificate_authorities extension (RFC 8446 4.2.4). Empty = omit.
    pub cert_request_authorities: Vec<Vec<u8>>,
    /// Signature-scheme peer capabilities: the TLS/DTLS client's advertised
    /// signature_algorithms, or the TLS 1.2 server's signing preferences.
    /// None keeps the driver's default set; unsupported server roles fail lint.
    pub client_signature_schemes: Option<Vec<u16>>,
    /// Backend labels (e.g. "rustls") this test does not apply to, each with
    /// the optional reason string from `skip <backend> "why"`; the runner
    /// reports SKIP (with the reason) instead of running it on those backends.
    pub skip_backends: Vec<(String, Option<String>)>,
    /// Backend labels for which a protocol failure is currently expected.
    /// These cases still run: failure is XFAIL and success is XPASS.
    pub xfail_backends: Vec<(String, Option<String>)>,
    /// Post-trace assertions evaluated after an otherwise-successful run
    /// (e.g. `assert no_duplicate_record_seqnums`).
    pub asserts: Vec<Assert>,
    // T1: `repeat N` and `capture $x` / `assert unique $x`. Programs of one
    // test share a `repeat_group` (the test name plus its non-repeat matrix
    // suffix); the runner evaluates `cross_asserts` over every program of the
    // group once all of them have run, using the values each captured.
    pub repeat_group: Option<String>,
    pub cross_asserts: Vec<CrossAssert>,
}

impl Program {
    /// Includes both preset declarations and occurrence-bound declarations.
    pub fn receive_configurations(&self) -> impl Iterator<Item = (MessageKind, &[FieldOverride])> {
        self.recv_matchers
            .iter()
            .map(|m| (m.message, m.fields.as_slice()))
            .chain(self.steps.iter().filter_map(|step| match step {
                Step::HandshakeSteps {
                    config: Some(config),
                    ..
                } if !config.send => Some((config.message, config.fields.as_slice())),
                Step::RecvKeyUpdate { matchers, .. } => {
                    Some((MessageKind::KeyUpdate, matchers.as_slice()))
                }
                _ => None,
            }))
    }

    pub fn send_extension_configurations(&self) -> impl Iterator<Item = &MessageExtDeltas> {
        self.send_ext_deltas.iter().chain(
            self.steps
                .iter()
                .filter_map(|step| match step {
                    Step::HandshakeSteps {
                        config: Some(config),
                        ..
                    } if config.send => Some(config.ext_deltas.as_slice()),
                    _ => None,
                })
                .flatten(),
        )
    }
}

/// An assertion over the values several runs of one test captured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossAssert {
    /// `assert unique $a, $b`: no two runs captured the same value for a name.
    Unique(Vec<String>),
}

/// Wire protocol family. Selects the record layer and the driver, orthogonal to
/// the crypto `version`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tls,
    Dtls,
}

/// A named post-trace assertion, checked after a run completes successfully.
#[derive(Clone, Debug)]
pub enum Assert {
    /// RFC 6347 4.1.2: no two records the harness received share an
    /// (epoch, sequence_number). Meaningful only for DTLS (the record-seq trace
    /// is absent for TLS).
    NoDuplicateRecordSeqnums,
    /// Every datagram emitted by the UUT and received by plzn was no larger
    /// than this many bytes. Meaningful only for DTLS endpoints.
    MaxDatagramSize(u32),
    /// T5: `assert new_session_tickets == N` -- exactly N post-handshake
    /// NewSessionTicket messages arrived over the whole flow (read explicitly,
    /// swallowed while waiting for another message, or during a `wait`).
    NewSessionTickets(u32),
    /// `assert app_data_records == N`: exactly N application-data records
    /// arrived from the peer over the whole flow (every record of content type
    /// 23 the endpoint read, whether a `recv AppData` consumed it or not), so
    /// a replay test can prove the duplicate it sent was discarded rather than
    /// answered a second time (RFC 6347 4.1.2.6).
    AppDataRecords(u32),
    /// Whether this connection negotiated an abbreviated/resumed handshake.
    Resumed(bool),
    /// The cipher suite selected on the wire.
    NegotiatedCipher(u16),
    /// Whether TLS 1.3 early data was accepted, independently of resumption.
    EarlyDataAccepted(bool),
    // T1: the TLS 1.2 explicit AEAD nonces (GCM/CCM, RFC 5288 3) of every
    // record the endpoint received: no two equal / strictly increasing.
    GcmNoncesUnique,
    GcmNoncesMonotonic,
}

/// State captured from a completed session, available for the
/// next session to resume from.
#[derive(Clone, Debug)]
pub struct SessionState {
    /// The wire protocol and handshake generation that created this state.
    /// Cross-version tests must opt into reusing incompatible state rather
    /// than relying on ticket/cipher sentinel values to imply its origin.
    pub protocol: Protocol,
    pub version: TlsVersion,
    /// NewSessionTicket bytes issued by the server.
    pub ticket: Vec<u8>,
    /// Master secret from the original handshake.
    pub master_secret: Vec<u8>,
    /// T5: the session_id the server assigned (RFC 5246 7.4.1.3), for
    /// session-ID resumption when no ticket was issued (`ticket` empty).
    pub session_id: Vec<u8>,
    /// TLS 1.3 NewSessionTicket.ticket_age_add. Zero for TLS 1.2 / DTLS.
    /// A resuming client sends this plus the elapsed ticket age modulo 2^32.
    pub ticket_age_add: u32,
    /// TLS 1.3 cipher suite that created this ticket. Zero for TLS 1.2 / DTLS.
    pub cipher_suite: u16,
    /// RFC 8446 NewSessionTicket early_data.max_early_data_size. Zero means
    /// the ticket cannot be used for 0-RTT.
    pub max_early_data_size: u32,
}

impl SessionState {
    pub fn is_compatible_with(&self, protocol: Protocol, version: TlsVersion) -> bool {
        self.protocol == protocol && self.version == version
    }
}

#[derive(Clone, Debug)]
pub struct UutConfig {
    /// Enabled TLS versions in source order. The first selects plzn's driver;
    /// the complete list becomes the shim's version range.
    pub versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub curves: Vec<u16>,
    pub require_client_cert: bool,
    pub request_client_cert: bool,
    pub verify_peer: bool,
    pub alpn_advertise: Vec<String>,
    pub alpn_select: Option<String>,
    /// Server-supported protocols in preference order. Unlike `alpn_select`,
    /// this permits the negotiated value to vary with the client's offer.
    pub alpn_select_from: Vec<String>,
    pub expect_alpn: Option<String>,
    pub alpn_decline: bool,
    pub srtp_profiles: Vec<u16>,
    pub expect_srtp_profile: Option<u16>,
    pub signing_prefs: Vec<u16>,
    pub verify_prefs: Vec<u16>,
    /// Local-policy knobs; None = the library's capability posture (see
    /// shims/DESIGN.md). A shim that cannot honour one SKIPs the case.
    pub server_preference: Option<bool>,
    pub renegotiation: Option<String>,
    pub session_tickets: Option<u32>,
    pub max_early_data: Option<u32>,
    pub max_cert_list: Option<u32>,
    /// RFC 8449 receive limit advertised by the UUT.
    pub record_size_limit: Option<u32>,
    /// Botan `records_per_traffic_key`: automatic TLS 1.3 KeyUpdate after N sent records.
    pub records_per_traffic_key: Option<u32>,
    /// Initiate one post-handshake KeyUpdate before application data.
    pub key_update: bool,
    pub extended_master_secret: Option<String>,
    pub encrypt_then_mac: Option<bool>,
    pub middlebox_compat: Option<bool>,
    /// RFC 8879 certificate compression support in the UUT.
    pub compress_certificate: bool,
    /// RFC 7250 raw-public-key credential mode.
    pub raw_public_key: bool,
    /// RFC 7250 certificate-type preferences. Empty means implementation default.
    pub server_certificate_types: Vec<u8>,
    pub client_certificate_types: Vec<u8>,
    pub mtu: Option<u32>,
    pub initial_timeout_ms: Option<u32>,
    /// DTLS policy (Botan): retransmission budget, maximum timer, cookie
    /// exchange, epoch-0 restart, HelloVerifyRequest bound.
    pub dtls_max_retransmissions: Option<u32>,
    pub dtls_max_timeout_ms: Option<u32>,
    pub dtls_require_cookie: Option<bool>,
    pub dtls_epoch0_restart: Option<bool>,
    pub dtls_max_hello_verify_requests: Option<u32>,
    /// Botan `minimum_key_update_interval_ms` (0 = no rate limit).
    pub min_key_update_interval_ms: Option<u32>,
    /// The shim's own PSK when it must differ from the `psk { }` block
    /// (hex secret / identity string): wrong-key and unknown-identity negatives.
    pub psk_secret: Option<String>,
    pub psk_identity: Option<String>,
    /// Shim CLIENT credential for a CertificateRequest:
    /// `valid` | `untrusted` | `none` | `expired`.
    pub client_cert: Option<String>,
    /// Shim CLIENT renegotiates once application data has flowed.
    pub renegotiate_after_handshake: bool,
    /// T5: shim SERVER sends a HelloRequest once application data has flowed
    /// (RFC 5246 7.4.1.1; tlsfuzzer's "protected resource" renegotiation).
    pub hello_request_after_app_data: bool,
    /// T5: with `hello_request_after_app_data`, the renegotiation handshake
    /// requires a client certificate (the initial one did not).
    pub require_client_cert_on_renegotiation: bool,
    /// Shim SERVER half-RTT application records (one per string).
    pub half_rtt_data: Vec<String>,
    /// T6: shim SERVER staples an OCSP response; shim SERVER requests
    /// post-handshake client authentication.
    pub ocsp_stapling: bool,
    /// `request` | `require` (RFC 8446 4.4.2.4: an empty Certificate is fatal
    /// under `require`).
    pub post_handshake_auth: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PskConfig {
    pub identity: Vec<u8>,
    pub secret: Vec<u8>,
    /// Ordered TLS 1.3 ClientHello offers. Empty means the single PSK above.
    pub offers: Vec<PskOfferConfig>,
    /// PSK key exchange mode: true = psk_ke (no DHE), false = psk_dhe_ke.
    /// Note: most servers (openssl, etc.) require psk_dhe_ke for
    /// forward secrecy and don't support pure psk_ke.
    pub ke_only: bool,
    /// True for external PSK (configured out-of-band), false for
    /// resumption PSK (derived from a prior session ticket).
    /// Affects the binder key label: "ext binder" vs "res binder".
    pub is_external: bool,
    /// RFC 8446 PskIdentity.obfuscated_ticket_age. External PSKs use zero;
    /// immediate resumption starts at the ticket's ticket_age_add value.
    pub obfuscated_ticket_age: u32,
    /// The suite that issued a resumption PSK; needed before ServerHello to
    /// select the early-data hash and AEAD. None for external PSKs.
    pub cipher_suite: Option<u16>,
    /// Ticket's advertised 0-RTT allowance. Zero means early data is forbidden.
    pub max_early_data_size: u32,
}

#[derive(Clone, Debug)]
pub struct PskOfferConfig {
    pub identity: Vec<u8>,
    pub secret: Vec<u8>,
    pub hash: crate::tls::crypto::HashAlg,
    pub is_external: bool,
    pub obfuscated_ticket_age: u32,
}

// ============================================================
//                     suite filtering
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuiteFilter {
    /// Only suites with this key exchange.
    Kex(KexType),
    /// Only suites of this cipher family / mode.
    Mode(CipherMode),
    /// Only suites using exactly this bulk cipher.
    Cipher(BulkCipher),
    /// Only suites whose PRF / handshake hash is this.
    Prf(HashAlg),
    /// Only suites with this HMAC hash (CBC / NULL suites).
    Mac(HashAlg),
    /// Exactly this suite (by wire value).
    Exact(u16),
    // A: `ecdhe` capability -- either ECDHE certificate family (ECDHE_RSA and
    // ECDHE_ECDSA); the configured chains decide which one is servable.
    Ecdhe,
    // A: the certificate families the configured chains can serve, as a bit
    // mask of CHAIN_RSA / CHAIN_ECDSA / CHAIN_RSA_PSS. The runner pushes it once
    // `chain:` names are resolved (`ecdhe` with chains, or an empty `chain: []`
    // for plzn's own server selection set). PSK
    // suites and the TLS 1.3 suites (whose authentication is not in the suite)
    // are unaffected.
    ChainKeys(u8),
}

// A: chain key masks (see `SuiteFilter::ChainKeys`, `Chain::key_mask`).
/// An rsaEncryption key: static RSA, ECDHE_RSA and DHE_RSA suites.
pub const CHAIN_RSA: u8 = 1;
/// An ECDSA or EdDSA key: the ECDHE_ECDSA suites (RFC 8422 5.1.3).
pub const CHAIN_ECDSA: u8 = 2;
/// An id-RSASSA-PSS key: ECDHE_RSA and DHE_RSA (it cannot do RSA key transport).
pub const CHAIN_RSA_PSS: u8 = 4;

/// A: a `chain:` / `client_chain:` entry. `Default` is plzn's explicitly
/// requested run-specific choice, resolved by the runner from `--cert`
/// (P-256 when unset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainName {
    Default,
    Rsa2048,
    /// An rsaEncryption leaf issued with ecdsa-with-SHA256. Unlike the
    /// self-signed rsa_2048 fixture, this makes signature_algorithms_cert
    /// observable independently of CertificateVerify's RSA-PSS scheme.
    Rsa2048EcdsaSigned,
    RsaPss,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
}

impl ChainName {
    /// The DSL spelling (`rsa` is an alias of `rsa_2048`).
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "default" => ChainName::Default,
            "rsa" | "rsa_2048" => ChainName::Rsa2048,
            "rsa_2048_ecdsa_signed" => ChainName::Rsa2048EcdsaSigned,
            "rsa_pss" => ChainName::RsaPss,
            "ecdsa_p256" => ChainName::EcdsaP256,
            "ecdsa_p384" => ChainName::EcdsaP384,
            "ecdsa_p521" => ChainName::EcdsaP521,
            "ed25519" => ChainName::Ed25519,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ChainName::Default => "default",
            ChainName::Rsa2048 => "rsa_2048",
            ChainName::Rsa2048EcdsaSigned => "rsa_2048_ecdsa_signed",
            ChainName::RsaPss => "rsa_pss",
            ChainName::EcdsaP256 => "ecdsa_p256",
            ChainName::EcdsaP384 => "ecdsa_p384",
            ChainName::EcdsaP521 => "ecdsa_p521",
            ChainName::Ed25519 => "ed25519",
        }
    }

    /// The key type this name stands for in a run whose `default` is
    /// `run_default`.
    pub fn resolve(self, run_default: KeyType) -> KeyType {
        match self {
            ChainName::Default => run_default,
            ChainName::Rsa2048 | ChainName::Rsa2048EcdsaSigned => KeyType::Rsa2048,
            ChainName::RsaPss => KeyType::RsaPss,
            ChainName::EcdsaP256 => KeyType::EcdsaP256,
            ChainName::EcdsaP384 => KeyType::EcdsaP384,
            ChainName::EcdsaP521 => KeyType::EcdsaP521,
            ChainName::Ed25519 => KeyType::Ed25519,
        }
    }

    /// The families this name can serve at lint time (`None` = not known
    /// until the run resolves `default`).
    pub fn key_mask(self) -> Option<u8> {
        match self {
            ChainName::Default => None,
            other => Some(key_type_mask(other.resolve(KeyType::EcdsaP256))),
        }
    }
}

/// The certificate families a key of this type can authenticate.
pub fn key_type_mask(kt: KeyType) -> u8 {
    match kt {
        KeyType::Rsa2048 => CHAIN_RSA,
        KeyType::RsaPss => CHAIN_RSA_PSS,
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 | KeyType::Ed25519 => {
            CHAIN_ECDSA
        }
    }
}

/// A: a resolved certificate chain -- the leaf certificate (DER) and its
/// PKCS#8 private key -- of a known key type.
#[derive(Clone, Debug)]
pub struct Chain {
    pub key_type: KeyType,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// Parsed once by the run's chain store, then cloned into endpoints.
    pub parsed_key: crate::tls::crypto::PrivateKey,
}

impl Chain {
    pub fn key_mask(&self) -> u8 {
        key_type_mask(self.key_type)
    }
}

/// A: a chain as the PEM files a shim loads (`credentials.chains` /
/// `credentials.client_chains` in the shim config).
#[derive(Clone, Debug)]
pub struct ChainFiles {
    pub key_type: KeyType,
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexType {
    Rsa,
    EcdheRsa,
    EcdheEcdsa,
    DheRsa,
    /// RFC 4279 plain pre-shared key: the TLS 1.2 client and server (with a
    /// `psk { }` block) and the DTLS client speak it; without a PSK block the
    /// TLS 1.2 drivers never offer or select these suites unless a test names
    /// one explicitly.
    Psk,
    /// RFC 5489 ECDHE_PSK: an ephemeral ECDH exchange (unsigned
    /// ServerKeyExchange) mixed with the pre-shared key. TLS 1.2 both roles.
    EcdhePsk,
}

impl KexType {
    /// A pre-shared-key family (no certificate, `psk { }` block required).
    pub fn is_psk(self) -> bool {
        matches!(self, KexType::Psk | KexType::EcdhePsk)
    }
}

/// Cipher families a peer capability can select. Coarser than [`BulkCipher`]:
/// `cbc` is every CBC suite, `gcm` every GCM one whatever the block cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherMode {
    /// Any AEAD cipher (GCM, CCM, ChaCha20-Poly1305).
    Aead,
    /// Any CBC block cipher (AES-128/256, 3DES).
    Cbc,
    /// Any GCM cipher (AES, ARIA, Camellia).
    Gcm,
    /// AES-CCM with either tag length.
    Ccm,
    /// AES-CCM_8 only.
    Ccm8,
    /// ARIA-GCM.
    Aria,
    /// Camellia-GCM.
    Camellia,
    /// ChaCha20-Poly1305.
    ChaCha,
    /// 3DES-EDE-CBC.
    TripleDes,
    /// NULL cipher (MAC only).
    Null,
}

/// The record-protection algorithm of a suite. Every TLS 1.2 record family
/// plzn implements is here: explicit-nonce AEADs (GCM, CCM: RFC 5288 / 6655),
/// the implicit-nonce ChaCha20-Poly1305 (RFC 7905), CBC block ciphers with an
/// HMAC (RFC 5246 6.2.3.2), and the NULL cipher (MAC only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkCipher {
    Aes128Gcm,
    Aes256Gcm,
    Aes128Ccm,
    Aes256Ccm,
    Aes128Ccm8,
    Aes256Ccm8,
    Aria128Gcm,
    Aria256Gcm,
    Camellia128Gcm,
    Camellia256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
    Aes256Cbc,
    TripleDesCbc,
    Null,
}

impl BulkCipher {
    /// Encryption key length in the key block.
    pub fn key_len(self) -> usize {
        match self {
            BulkCipher::Aes128Gcm
            | BulkCipher::Aes128Ccm
            | BulkCipher::Aes128Ccm8
            | BulkCipher::Aria128Gcm
            | BulkCipher::Camellia128Gcm
            | BulkCipher::Aes128Cbc => 16,
            BulkCipher::Aes256Gcm
            | BulkCipher::Aes256Ccm
            | BulkCipher::Aes256Ccm8
            | BulkCipher::Aria256Gcm
            | BulkCipher::Camellia256Gcm
            | BulkCipher::ChaCha20Poly1305
            | BulkCipher::Aes256Cbc => 32,
            BulkCipher::TripleDesCbc => 24,
            BulkCipher::Null => 0,
        }
    }
    /// Implicit IV length drawn from the key block: the 4-byte salt of the
    /// explicit-nonce AEADs, the full 12-byte IV of ChaCha20-Poly1305, none
    /// for CBC (explicit per-record IVs) and NULL.
    pub fn implicit_iv_len(self) -> usize {
        match self {
            BulkCipher::ChaCha20Poly1305 => 12,
            BulkCipher::Aes128Cbc
            | BulkCipher::Aes256Cbc
            | BulkCipher::TripleDesCbc
            | BulkCipher::Null => 0,
            _ => 4,
        }
    }
    pub fn is_aead(self) -> bool {
        !matches!(
            self,
            BulkCipher::Aes128Cbc
                | BulkCipher::Aes256Cbc
                | BulkCipher::TripleDesCbc
                | BulkCipher::Null
        )
    }
    pub fn is_cbc(self) -> bool {
        matches!(
            self,
            BulkCipher::Aes128Cbc | BulkCipher::Aes256Cbc | BulkCipher::TripleDesCbc
        )
    }
    pub fn is_gcm(self) -> bool {
        matches!(
            self,
            BulkCipher::Aes128Gcm
                | BulkCipher::Aes256Gcm
                | BulkCipher::Aria128Gcm
                | BulkCipher::Aria256Gcm
                | BulkCipher::Camellia128Gcm
                | BulkCipher::Camellia256Gcm
        )
    }
    pub fn is_ccm(self) -> bool {
        matches!(
            self,
            BulkCipher::Aes128Ccm
                | BulkCipher::Aes256Ccm
                | BulkCipher::Aes128Ccm8
                | BulkCipher::Aes256Ccm8
        )
    }
    pub fn is_ccm8(self) -> bool {
        matches!(self, BulkCipher::Aes128Ccm8 | BulkCipher::Aes256Ccm8)
    }
    /// AEAD tag length (16, or 8 for CCM_8); 0 for non-AEAD ciphers.
    pub fn tag_len(self) -> usize {
        if self.is_ccm8() {
            8
        } else if self.is_aead() {
            16
        } else {
            0
        }
    }
}

/// A cipher suite plzn implements, with everything the drivers need to run
/// it: key exchange, record cipher, MAC hash (None for AEAD) and the PRF /
/// handshake hash (RFC 5246 5: SHA-256 unless the suite names SHA-384).
#[derive(Clone, Copy, Debug)]
pub struct SuiteInfo {
    pub wire: u16,
    pub name: &'static str,
    pub kex: KexType,
    pub cipher: BulkCipher,
    pub mac: Option<HashAlg>,
    pub prf: HashAlg,
    pub version: TlsVersion,
}

impl SuiteInfo {
    /// MAC key length in the key block (0 for AEAD suites).
    pub fn mac_key_len(&self) -> usize {
        self.mac.map(|h| h.output_len()).unwrap_or(0)
    }

    /// Offered over DTLS 1.2 by default. Botan's policy (tls_policy.cpp,
    /// `Policy::ciphersuite_list`) refuses two families for datagram versions
    /// and plzn's default DTLS offer follows it: CBC-with-HMAC suites, because
    /// the non-EtM CBC decryption keeps a residual Lucky13 timing channel that
    /// DTLS's unlimited repeated observations would amplify, and short-tag
    /// (CCM_8) suites, because DTLS allows repeated forgery attempts without a
    /// connection teardown. AEAD suites with a full tag and the NULL suites
    /// remain. A test can still name an excluded suite explicitly (`suite in
    /// [...]` or a cipher token) to probe what a library does with it over
    /// DTLS; `filter_suites_dtls` lets those through.
    pub fn dtls_default(&self) -> bool {
        self.version == TlsVersion::Tls12 && !self.cipher.is_cbc() && !self.cipher.is_ccm8()
    }

    pub fn matches_filter(&self, f: &SuiteFilter) -> bool {
        match f {
            SuiteFilter::Kex(k) => self.kex == *k,
            SuiteFilter::Mode(CipherMode::Aead) => self.cipher.is_aead(),
            SuiteFilter::Mode(CipherMode::Cbc) => self.cipher.is_cbc(),
            SuiteFilter::Mode(CipherMode::Gcm) => self.cipher.is_gcm(),
            SuiteFilter::Mode(CipherMode::Ccm) => self.cipher.is_ccm(),
            SuiteFilter::Mode(CipherMode::Ccm8) => self.cipher.is_ccm8(),
            SuiteFilter::Mode(CipherMode::Aria) => {
                matches!(self.cipher, BulkCipher::Aria128Gcm | BulkCipher::Aria256Gcm)
            }
            SuiteFilter::Mode(CipherMode::Camellia) => {
                matches!(
                    self.cipher,
                    BulkCipher::Camellia128Gcm | BulkCipher::Camellia256Gcm
                )
            }
            SuiteFilter::Mode(CipherMode::ChaCha) => self.cipher == BulkCipher::ChaCha20Poly1305,
            SuiteFilter::Mode(CipherMode::TripleDes) => self.cipher == BulkCipher::TripleDesCbc,
            SuiteFilter::Mode(CipherMode::Null) => self.cipher == BulkCipher::Null,
            SuiteFilter::Cipher(c) => self.cipher == *c,
            SuiteFilter::Prf(h) => self.prf == *h,
            SuiteFilter::Mac(h) => self.mac == Some(*h),
            SuiteFilter::Exact(w) => self.wire == *w,
            SuiteFilter::Ecdhe => matches!(self.kex, KexType::EcdheRsa | KexType::EcdheEcdsa),
            // TLS 1.3 suites carry a placeholder kex: their authentication is
            // negotiated by signature_algorithms, not the suite.
            SuiteFilter::ChainKeys(_) if self.version == TlsVersion::Tls13 => true,
            SuiteFilter::ChainKeys(mask) => match self.kex {
                KexType::Rsa => mask & CHAIN_RSA != 0,
                KexType::EcdheRsa | KexType::DheRsa => mask & (CHAIN_RSA | CHAIN_RSA_PSS) != 0,
                KexType::EcdheEcdsa => mask & CHAIN_ECDSA != 0,
                KexType::Psk | KexType::EcdhePsk => true,
            },
        }
    }

    pub fn matches_all(&self, filters: &[SuiteFilter]) -> bool {
        filters.iter().all(|f| self.matches_filter(f))
    }
}

/// Every cipher suite plzn implements, in offer order. The first seven are
/// the historical set and stay first so a client-preferring server keeps
/// selecting what it always did; the rest mirror Botan's catalogue for the
/// key exchanges plzn has (ECDHE_RSA, ECDHE_ECDSA, DHE_RSA, static RSA). PSK
/// key exchanges and Botan's private OCB suites are not here.
pub const ALL_SUITES: &[SuiteInfo] = &[
    SuiteInfo {
        wire: 0xc02f,
        name: "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc02b,
        name: "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x009c,
        name: "RSA_WITH_AES_128_GCM_SHA256",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc013,
        name: "ECDHE_RSA_WITH_AES_128_CBC_SHA",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc009,
        name: "ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x009e,
        name: "DHE_RSA_WITH_AES_128_GCM_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x0033,
        name: "DHE_RSA_WITH_AES_128_CBC_SHA",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x002f,
        name: "RSA_WITH_AES_128_CBC_SHA",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc030,
        name: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc02c,
        name: "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x009d,
        name: "RSA_WITH_AES_256_GCM_SHA384",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x009f,
        name: "DHE_RSA_WITH_AES_256_GCM_SHA384",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xcca8,
        name: "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xcca9,
        name: "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xccaa,
        name: "DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc027,
        name: "ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc023,
        name: "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x003c,
        name: "RSA_WITH_AES_128_CBC_SHA256",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x0067,
        name: "DHE_RSA_WITH_AES_128_CBC_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc014,
        name: "ECDHE_RSA_WITH_AES_256_CBC_SHA",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc00a,
        name: "ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x0035,
        name: "RSA_WITH_AES_256_CBC_SHA",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x0039,
        name: "DHE_RSA_WITH_AES_256_CBC_SHA",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc028,
        name: "ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc024,
        name: "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x003d,
        name: "RSA_WITH_AES_256_CBC_SHA256",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x006b,
        name: "DHE_RSA_WITH_AES_256_CBC_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc012,
        name: "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc008,
        name: "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x000a,
        name: "RSA_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::Rsa,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x0016,
        name: "DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::DheRsa,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc010,
        name: "ECDHE_RSA_WITH_NULL_SHA",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc006,
        name: "ECDHE_ECDSA_WITH_NULL_SHA",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc060,
        name: "ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aria128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc05c,
        name: "ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aria128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc050,
        name: "RSA_WITH_ARIA_128_GCM_SHA256",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aria128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc052,
        name: "DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aria128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc061,
        name: "ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aria256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc05d,
        name: "ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aria256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc051,
        name: "RSA_WITH_ARIA_256_GCM_SHA384",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aria256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc053,
        name: "DHE_RSA_WITH_ARIA_256_GCM_SHA384",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aria256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc08a,
        name: "ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Camellia128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc086,
        name: "ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Camellia128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc07a,
        name: "RSA_WITH_CAMELLIA_128_GCM_SHA256",
        kex: KexType::Rsa,
        cipher: BulkCipher::Camellia128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc07c,
        name: "DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Camellia128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc08b,
        name: "ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Camellia256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc087,
        name: "ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Camellia256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc07b,
        name: "RSA_WITH_CAMELLIA_256_GCM_SHA384",
        kex: KexType::Rsa,
        cipher: BulkCipher::Camellia256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc07d,
        name: "DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Camellia256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0ac,
        name: "ECDHE_ECDSA_WITH_AES_128_CCM",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc09c,
        name: "RSA_WITH_AES_128_CCM",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc09e,
        name: "DHE_RSA_WITH_AES_128_CCM",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0ad,
        name: "ECDHE_ECDSA_WITH_AES_256_CCM",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes256Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc09d,
        name: "RSA_WITH_AES_256_CCM",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes256Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc09f,
        name: "DHE_RSA_WITH_AES_256_CCM",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes256Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0ae,
        name: "ECDHE_ECDSA_WITH_AES_128_CCM_8",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a0,
        name: "RSA_WITH_AES_128_CCM_8",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a2,
        name: "DHE_RSA_WITH_AES_128_CCM_8",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0af,
        name: "ECDHE_ECDSA_WITH_AES_256_CCM_8",
        kex: KexType::EcdheEcdsa,
        cipher: BulkCipher::Aes256Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a1,
        name: "RSA_WITH_AES_256_CCM_8",
        kex: KexType::Rsa,
        cipher: BulkCipher::Aes256Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a3,
        name: "DHE_RSA_WITH_AES_256_CCM_8",
        kex: KexType::DheRsa,
        cipher: BulkCipher::Aes256Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    // RFC 4279 / 5487 / 6209 / 6367 / 6655 / 7905 plain-PSK suites (DTLS client only).
    SuiteInfo {
        wire: 0x00a8,
        name: "PSK_WITH_AES_128_GCM_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x00a9,
        name: "PSK_WITH_AES_256_GCM_SHA384",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xccab,
        name: "PSK_WITH_CHACHA20_POLY1305_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc06a,
        name: "PSK_WITH_ARIA_128_GCM_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::Aria128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc06b,
        name: "PSK_WITH_ARIA_256_GCM_SHA384",
        kex: KexType::Psk,
        cipher: BulkCipher::Aria256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc08e,
        name: "PSK_WITH_CAMELLIA_128_GCM_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::Camellia128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc08f,
        name: "PSK_WITH_CAMELLIA_256_GCM_SHA384",
        kex: KexType::Psk,
        cipher: BulkCipher::Camellia256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a4,
        name: "PSK_WITH_AES_128_CCM",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a5,
        name: "PSK_WITH_AES_256_CCM",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes256Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a8,
        name: "PSK_WITH_AES_128_CCM_8",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc0a9,
        name: "PSK_WITH_AES_256_CCM_8",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes256Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x008c,
        name: "PSK_WITH_AES_128_CBC_SHA",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x008d,
        name: "PSK_WITH_AES_256_CBC_SHA",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x00ae,
        name: "PSK_WITH_AES_128_CBC_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x00af,
        name: "PSK_WITH_AES_256_CBC_SHA384",
        kex: KexType::Psk,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x008b,
        name: "PSK_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::Psk,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x002c,
        name: "PSK_WITH_NULL_SHA",
        kex: KexType::Psk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x00b0,
        name: "PSK_WITH_NULL_SHA256",
        kex: KexType::Psk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x00b1,
        name: "PSK_WITH_NULL_SHA384",
        kex: KexType::Psk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    // RFC 5489 / RFC 8442 ECDHE_PSK (Botan's catalogue; there is no DHE_PSK there).
    SuiteInfo {
        wire: 0xd001,
        name: "ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xd002,
        name: "ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xccac,
        name: "ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xd005,
        name: "ECDHE_PSK_WITH_AES_128_CCM_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xd003,
        name: "ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc035,
        name: "ECDHE_PSK_WITH_AES_128_CBC_SHA",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc036,
        name: "ECDHE_PSK_WITH_AES_256_CBC_SHA",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc037,
        name: "ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes128Cbc,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc038,
        name: "ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Aes256Cbc,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc034,
        name: "ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::TripleDesCbc,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc039,
        name: "ECDHE_PSK_WITH_NULL_SHA",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha1),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc03a,
        name: "ECDHE_PSK_WITH_NULL_SHA256",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha256),
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0xc03b,
        name: "ECDHE_PSK_WITH_NULL_SHA384",
        kex: KexType::EcdhePsk,
        cipher: BulkCipher::Null,
        mac: Some(HashAlg::Sha384),
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls12,
    },
    SuiteInfo {
        wire: 0x1301,
        name: "AES_128_GCM_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Gcm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls13,
    },
    SuiteInfo {
        wire: 0x1302,
        name: "AES_256_GCM_SHA384",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes256Gcm,
        mac: None,
        prf: HashAlg::Sha384,
        version: TlsVersion::Tls13,
    },
    SuiteInfo {
        wire: 0x1303,
        name: "CHACHA20_POLY1305_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::ChaCha20Poly1305,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls13,
    },
    SuiteInfo {
        wire: 0x1304,
        name: "AES_128_CCM_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Ccm,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls13,
    },
    SuiteInfo {
        wire: 0x1305,
        name: "AES_128_CCM_8_SHA256",
        kex: KexType::EcdheRsa,
        cipher: BulkCipher::Aes128Ccm8,
        mac: None,
        prf: HashAlg::Sha256,
        version: TlsVersion::Tls13,
    },
];

/// Look a suite up by wire value.
pub fn suite_info(wire: u16) -> Option<&'static SuiteInfo> {
    ALL_SUITES.iter().find(|s| s.wire == wire)
}

/// Apply filters to produce the offered suite list for a given
/// TLS version. Returns wire values only.
pub fn filter_suites(version: TlsVersion, filters: &[SuiteFilter]) -> Vec<u16> {
    ALL_SUITES
        .iter()
        .filter(|s| suite_supports_version(s, version))
        // Without a `psk { }` block a PSK suite is only in the offer when a
        // test names it (a PSK kex token or its id); `filter_suites_tls12`
        // is the PSK-aware entry point the TLS 1.2 drivers use.
        .filter(|s| !s.kex.is_psk() || psk_named(s, filters))
        .filter(|s| s.matches_all(filters))
        .map(|s| s.wire)
        .collect()
}

/// Whether a catalogue entry can be negotiated in the requested protocol.
/// `SuiteInfo::version == Tls12` denotes the pre-TLS-1.3 suite namespace, not
/// the earliest protocol that assigned the suite. TLS 1.0/1.1 support the CBC
/// and NULL suites with the original SHA-1 MAC; AEAD and SHA-2 CBC suites were
/// introduced for TLS 1.2.
pub fn suite_supports_version(suite: &SuiteInfo, version: TlsVersion) -> bool {
    match version {
        TlsVersion::Tls13 => suite.version == TlsVersion::Tls13,
        TlsVersion::Tls12 => suite.version == TlsVersion::Tls12,
        TlsVersion::Tls10 | TlsVersion::Tls11 => {
            suite.version == TlsVersion::Tls12
                && !suite.cipher.is_aead()
                && suite.mac == Some(HashAlg::Sha1)
        }
    }
}

fn psk_named(s: &SuiteInfo, filters: &[SuiteFilter]) -> bool {
    filters.iter().any(|f| {
        matches!(f, SuiteFilter::Kex(k) if k.is_psk())
            || matches!(f, SuiteFilter::Exact(w) if *w == s.wire)
    })
}

/// The TLS 1.2 offer (client role) or selection set (server role): with a
/// `psk { }` block, the pre-shared-key families (RFC 4279 PSK and RFC 5489
/// ECDHE_PSK) matching `filters`; without one, the certificate-authenticated
/// suites as `filter_suites` gives them.
pub fn filter_suites_tls12(filters: &[SuiteFilter], psk: bool) -> Vec<u16> {
    filter_suites_legacy(TlsVersion::Tls12, filters, psk)
}

/// Offer or selection set for TLS 1.0 through TLS 1.2.
pub fn filter_suites_legacy(version: TlsVersion, filters: &[SuiteFilter], psk: bool) -> Vec<u16> {
    if !psk {
        return filter_suites(version, filters);
    }
    // A matrix suite pin is authoritative. Keeping PSK credentials available
    // must not hide certificate-authenticated rows from a full catalogue
    // sweep; the selected suite decides whether the configured PSK is used.
    if filters
        .iter()
        .any(|filter| matches!(filter, SuiteFilter::Exact(_)))
    {
        return ALL_SUITES
            .iter()
            .filter(|suite| suite_supports_version(suite, version))
            .filter(|suite| suite.matches_all(filters))
            .map(|suite| suite.wire)
            .collect();
    }
    ALL_SUITES
        .iter()
        .filter(|s| suite_supports_version(s, version) && s.kex.is_psk())
        .filter(|s| s.matches_all(filters))
        .map(|s| s.wire)
        .collect()
}

/// The DTLS 1.2 offer (or the DTLS server's selection set): the TLS 1.2 suites
/// matching `filters`, restricted to `SuiteInfo::dtls_default` unless a filter
/// names a cipher or suite outright (a probe of CBC / CCM_8 over DTLS), and to
/// the PSK family when the test has a `psk { }` block (else to the
/// certificate-authenticated families).
pub fn filter_suites_dtls(filters: &[SuiteFilter], psk: bool) -> Vec<u16> {
    let explicit_cipher = filters.iter().any(|f| {
        matches!(
            f,
            SuiteFilter::Exact(_) | SuiteFilter::Mode(_) | SuiteFilter::Cipher(_)
        )
    });
    ALL_SUITES
        .iter()
        .filter(|s| s.version == TlsVersion::Tls12)
        // A `psk { }` block switches the offer to the PSK families (RFC 4279
        // plain PSK and RFC 5489 ECDHE_PSK; `psk` / `ecdhe_psk` narrow
        // to one). DHE_PSK is in no peer plzn tests against (Botan does not
        // implement it), so it is not in the catalogue.
        .filter(|s| if psk { s.kex.is_psk() } else { !s.kex.is_psk() })
        .filter(|s| s.matches_all(filters))
        .filter(|s| s.dtls_default() || explicit_cipher)
        .map(|s| s.wire)
        .collect()
}

#[derive(Clone, Debug)]
pub struct MessageMutations {
    pub message: MessageKind,
    pub mutations: Vec<Mutation>,
    /// DTLS only: how to fragment / forge this message on the wire (a `send Msg @
    /// <scheme>` in a DTLS flow). `None` = one fragment per message, the default.
    /// Threaded through the same channel as `mutations` so it reaches the DTLS
    /// drivers without new plumbing. See `DtlsFragScheme`.
    pub dtls_frag: Option<DtlsFragScheme>,
}

/// A deliberate DTLS handshake-fragmentation deviation applied when plzn emits a
/// message (RFC 6347 4.2.3), used to exercise a peer's reassembler. Attached to a
/// `send <Msg> @ <scheme>` in a DTLS flow and keyed by message, so it works both
/// in preset flows (as an override) and in explicit flows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DtlsFragScheme {
    /// `fragment N`: split into N-byte handshake fragments, in offset order. A
    /// conforming peer MUST reassemble regardless of fragment size.
    Fragment { size: usize },
    /// `fragment N hold|hold_all`: as above, but withhold the selected trailing
    /// fragment records until `flush_fragment`. The records are sealed before
    /// the hold so a ServerHello/Finished epoch transition cannot re-key them.
    HeldFragment { size: usize, hold: FragHold },
    /// `duplicate_fragment N`: split into N-byte fragments, then send each
    /// fragment twice. Exact duplicates are harmless retransmissions.
    DuplicateFragment { size: usize },
    /// `reorder_overlap N`: split into overlapping N-byte fragments, duplicate
    /// each one, and send them in reverse order. Matching overlaps and exact
    /// duplicates must be accepted.
    ReorderOverlap { size: usize },
    /// `complete_and_fragments N`: send N-byte fragments and a redundant whole
    /// fragment for the same message_seq. Matching redundant coverage is valid.
    CompleteAndFragments { size: usize },
    /// `empty_fragments`: bracket the normal fragment with zero-length
    /// fragments at offsets zero and total_length.
    EmptyFragments,
    /// `split_fragment_record N`: split one encoded handshake fragment at byte
    /// N and place the two pieces in separate Handshake records. Neither piece
    /// is independently well-formed, so the receiver must reject it.
    SplitFragmentRecord { at: usize },
    /// `overlap_mismatch N`: split into >=2 N-byte fragments, then re-send the
    /// first fragment with one byte flipped before the message completes.
    /// Overlapping bytes that disagree are a protocol error the peer MUST reject.
    OverlapMismatch { size: usize },
    /// `type_mismatch N`: split into >=2 fragments; a later fragment for the
    /// same message_seq advertises a different handshake type. Inconsistent
    /// metadata the peer MUST reject.
    TypeMismatch { size: usize },
    /// `offset_overflow`: one fragment whose fragment_offset + fragment_length
    /// runs past the declared message length. The peer MUST reject it.
    OffsetOverflow,
    /// `length_mismatch N`: split into >=2 N-byte fragments; a later fragment for
    /// the same message_seq advertises a different total length. Inconsistent
    /// metadata the peer MUST reject.
    LengthMismatch { size: usize },
    /// `fragment_length_mismatch N`: one N-byte fragment advertises one more
    /// byte in fragment_length than the record actually carries. The peer MUST
    /// reject the malformed fragment.
    FragmentLengthMismatch { size: usize },
    /// Prefix the valid message with a complete fragment whose message_seq is
    /// `delta` ahead. The fragment-window upper bound must be discarded.
    FutureSequence { delta: u16 },
    /// As `FutureSequence`, but pack the discarded future fragment and the
    /// valid in-sequence fragment into one record. RFC 9147 requires the whole
    /// record to remain unacknowledged when any contained fragment is discarded.
    FutureSequencePacked { delta: u16 },
}

#[derive(Clone, Debug)]
pub struct MessageExtDeltas {
    pub message: MessageKind,
    pub deltas: Vec<ExtDeltaOp>,
}

/// Resolved extension delta in the IR. Either the bytes are
/// fully encoded by the driver from a typed value (e.g.
/// `server_name = "host"`) or supplied verbatim (`raw "F00F"`).
#[derive(Clone, Debug)]
pub enum ExtDeltaOp {
    /// Add or replace an extension. The driver inserts/replaces
    /// at the natural position (before pre_shared_key if absent). When `dup` is
    /// set, always append -- even if an extension of this type is
    /// already present -- producing a duplicate.
    Add {
        wire_type: u16,
        body: Vec<u8>,
        dup: bool,
    },
    /// Remove an extension by wire type. No-op if absent.
    Remove { wire_type: u16 },
    /// Reverse the order of all extensions (RFC 8446 4.2 permits any order).
    Reverse,
    /// `+ext key_share = [g1, g2, ...]` on the ClientHello: the client generates
    /// a real ephemeral for each listed group, in this order, and offers those
    /// key shares instead of its default set. Consumed by the TLS 1.3 client
    /// before the generic delta pass; `apply_ext_deltas` ignores it.
    KeyShareGroups(Vec<u16>),
    /// T1: `+ext key_share = [x25519, 0x0022..0x00fe : 0xab * 32]` -- the
    /// client's key_share list spelled out entry by entry: real shares for the
    /// named groups, verbatim opaque keys for the `group : bytes` entries, in
    /// this order. Consumed by the TLS 1.3 client like `KeyShareGroups`.
    KeyShareEntries(Vec<KeyShareEntrySpec>),
}

/// T1: one entry of an explicit ClientHello key_share list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyShareEntrySpec {
    Generate(u16),
    Raw { group: u16, key: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct MessageOverrides {
    pub message: MessageKind,
    pub fields: Vec<FieldOverride>,
}

#[derive(Clone, Debug)]
pub struct FieldOverride {
    pub field: String,
    pub value: FieldValue,
    pub span: Span,
}

/// Runtime-ready field values. The lowering layer has already
/// coerced AST integer literals / lists to concrete widths and
/// range-checked them, so the driver just pattern-matches and
/// writes through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldValue {
    U8(u8),
    U16(u16),
    U8List(Vec<u8>),
    U16List(Vec<u16>),
    Bytes(Vec<u8>),
    /// A symbolic enum value (schema `FieldType::Enum`), e.g.
    /// `key_share_point: compressed`; the driver interprets the name.
    Ident(String),
    // T3: a list of names on a bytes field (`certificate_list: [rsa, empty]`);
    // the driver composes the bytes from the named parts.
    IdentList(Vec<String>),
    /// T6: a 32-bit value (u24 wire lengths).
    U32(u32),
    /// T1: `capture $name` on a matcher -- the driver records the peer's value
    /// under `name` instead of comparing it (see `TlsEndpoint::captures`).
    Capture(String),
}

impl FieldValue {
    pub fn describe(&self) -> String {
        match self {
            FieldValue::U8(v) => format!("0x{:02x}", v),
            FieldValue::U32(v) => format!("{}", v),
            FieldValue::U16(v) => format!("0x{:04x}", v),
            FieldValue::U8List(v) => format!("{:?}", v),
            FieldValue::U16List(v) => {
                let hex: Vec<String> = v.iter().map(|x| format!("0x{:04x}", x)).collect();
                format!("[{}]", hex.join(", "))
            }
            FieldValue::Bytes(v) => format!("{} bytes", v.len()),
            FieldValue::Ident(s) => s.clone(),
            FieldValue::IdentList(v) => format!("[{}]", v.join(", ")),
            FieldValue::Capture(s) => format!("capture ${}", s),
        }
    }
}

// ============================================================
//                   byte-level mutations
// ============================================================

/// A single post-serialise mutation on a message or record.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub op: MutationOp,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum MutationOp {
    /// `xor[target] = value`
    Xor {
        target: ResolvedByteTarget,
        value: i64,
    },
    /// `set[target] = value`
    Set {
        target: ResolvedByteTarget,
        value: i64,
    },
    /// Adjust an entire named big-endian integer field, preserving every
    /// payload byte and every other enclosing or nested length prefix.
    AdjustLength { path: Vec<String>, delta: i64 },
    /// `pad +N` — append N zero bytes to the message body.
    PadPlus(usize),
    /// `pad +N 0xNN` / `pad "HEX"` — append these bytes to the message body
    /// (tlsfuzzer `pad_handshake` with a pad byte or explicit pad bytes). The
    /// handshake header length is recomputed, as for `pad +N`.
    PadBytes(Vec<u8>),
    /// `pad -N` — remove N trailing bytes.
    PadMinus(usize),
    /// `truncate N` — keep only the first N bytes.
    Truncate(usize),
    /// `trailing "HEX"` — append bytes after the framed handshake message,
    /// without changing its length or adding them to the transcript.
    TrailingBytes(Vec<u8>),
    /// `omit_prefix N` — omit N bytes from the framed handshake message on
    /// the wire. The logical complete message remains in the transcript.
    OmitPrefix(usize),
    /// `record_version 0xNNNN` — the record header's version field for every
    /// record this send produces (tlsfuzzer `SetRecordVersion` / `Connect(version)`).
    RecordVersion(u16),
    /// `record_pad N` / `record_pad fill` — TLS/DTLS 1.3 record padding (RFC 8446
    /// 5.4): N zero bytes after the inner content type, or enough to reach the
    /// 2^14 + 1 byte TLSInnerPlaintext maximum. Applied by the TLS 1.3 record
    /// layer; a lint error under TLS/DTLS 1.2.
    RecordPad(Option<usize>),
    /// Use the one-byte record-number form of the DTLS 1.3 unified header.
    Dtls13ShortSequence,
    /// Omit the unified-header length field; the record consumes its datagram.
    Dtls13OmitLength,
    /// Set the unified-header CID bit without a negotiated/provided CID.
    Dtls13SetCidBit,
    /// Carry protected DTLS 1.3 data under the legacy 13-byte DTLS header.
    Dtls13LegacyHeader,
    /// `plaintext` — write this send's records unencrypted although write keys
    /// are installed (tlsfuzzer `PlaintextMessageGenerator`).
    Plaintext,
    /// `plaintext = <bytes>` — replace the whole pre-encryption block (CBC:
    /// data || MAC || padding; AEAD: the AEAD plaintext) with these bytes
    /// (tlsfuzzer `replace_plaintext`). Must be block-aligned on CBC.
    ReplacePlaintext(Vec<u8>),
    /// `cbc_pad N` — CBC: at least N bytes of padding including the length byte
    /// (tlsfuzzer `fuzz_padding(min_length=N)`): the padding grows to the next
    /// block boundary at or above N. 1..=256.
    CbcPad(usize),
    /// `reorder N` — fragment into N-byte handshake fragments sent in reverse
    /// order. Interpreted by the DTLS driver at framing time; skipped by the
    /// body-mutation pass and ignored by the TLS drivers.
    Reorder(usize),
    /// `fragment N [hold | hold_all]` — split the framed message into N-byte
    /// records at the record layer (RFC 5246 6.2.1 / RFC 8446 5.1). With `hold`
    /// the last fragment stays back until a `flush_fragment` step sends it under
    /// the then-current write keys; with `hold_all` every fragment after the
    /// first is held and each `flush_fragment` releases the next one.
    /// Interpreted by the TLS record layer; skipped by the body-mutation pass; a
    /// lint error under DTLS.
    Fragment { size: usize, hold: FragHold },
}

/// What a `coalesce { }` block does at a key change inside it (T2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoalesceMode {
    /// The buffered record goes out under the old keys before the change.
    Flush,
    /// `coalesce hold_keys`: keep buffering; seal at the block's end under
    /// the keys current then (the post-rotation keys).
    HoldKeys,
    /// `coalesce old_keys`: keep buffering and DEFER the key change: seal at
    /// the block's end under the keys current at its start, then install the
    /// deferred keys (two KeyUpdates in one record under the original keys).
    OldKeys,
}

/// How `@ fragment N` holds fragments back for `flush_fragment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragHold {
    /// Every fragment goes out at once.
    None,
    /// The last fragment is held.
    Last,
    /// Every fragment after the first is held, released one per `flush_fragment`.
    All,
    /// The last fragment is held AND the key change the message itself
    /// triggers (a KeyUpdate's rotation) is deferred until the fragment is
    /// flushed, so records sent in between still use the old keys.
    LastOldKeys,
}

impl FragHold {
    pub fn holds(self) -> bool {
        self != FragHold::None
    }
}

/// Fully-resolved byte target: no matrix vars, no symbolic field
/// names — everything is a concrete integer offset or a named
/// byte-path prefix with a concrete integer index.
#[derive(Clone, Debug)]
pub struct ResolvedByteTarget {
    /// None = bare byte offset into the encoded message body.
    /// Some(["record","aead_tag"]) = offset within a named
    ///   record-layer or handshake-field byte region.
    pub path: Option<Vec<String>>,
    /// Byte index within the target region. Negative = from end.
    pub index: i64,
    /// `xor[lo..hi]`: the inclusive end of a byte range starting at `index`
    /// (negative = from end). None = the single byte at `index`.
    pub end: Option<i64>,
}

impl ResolvedByteTarget {
    pub fn is_record_level(&self) -> bool {
        matches!(&self.path, Some(parts) if !parts.is_empty() && parts[0] == "record")
    }

    pub fn is_handshake_field(&self) -> bool {
        matches!(&self.path, Some(parts) if !parts.is_empty() && parts[0] == "handshake")
    }

    pub fn field_name(&self) -> Option<&str> {
        self.path
            .as_ref()
            .and_then(|p| p.get(1).map(|s| s.as_str()))
    }

    pub fn path_str(&self) -> String {
        let idx = match self.end {
            None => format!("{}", self.index),
            Some(e) => format!("{}..{}", self.index, e),
        };
        match &self.path {
            None => format!("[{}]", idx),
            Some(p) => format!("[{}, {}]", p.join("."), idx),
        }
    }

    /// A target with a single index and no path.
    pub fn at(index: i64) -> Self {
        ResolvedByteTarget {
            path: None,
            index,
            end: None,
        }
    }

    /// The absolute byte positions this target names within a region of `len`
    /// bytes: one for a single index, every position of an inclusive range
    /// (`lo..hi`, either end negative = from the end). Errors when any end is
    /// out of range or the range is empty.
    pub fn indices(&self, len: usize) -> Result<Vec<usize>, String> {
        let resolve = |i: i64| -> Result<usize, String> {
            let abs = if i >= 0 {
                Some(i as usize)
            } else {
                len.checked_sub((-i) as usize)
            };
            match abs {
                Some(a) if a < len => Ok(a),
                _ => Err(format!(
                    "byte index {} is out of range for {} (region is {} bytes)",
                    i,
                    self.path_str(),
                    len
                )),
            }
        };
        let lo = resolve(self.index)?;
        let Some(end) = self.end else {
            return Ok(vec![lo]);
        };
        let hi = resolve(end)?;
        if hi < lo {
            return Err(format!(
                "empty byte range {} (region is {} bytes)",
                self.path_str(),
                len
            ));
        }
        Ok((lo..=hi).collect())
    }
}

/// Every message kind the runtime can recognise on a send/recv
/// step. Mirrors `schema::MESSAGES` but in enum form for pattern
/// matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    ClientHello,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    ServerKeyExchange,
    ServerHelloDone,
    ClientKeyExchange,
    Finished,
    NewSessionTicket,
    HelloRetryRequest,
    HelloVerifyRequest,
    /// RFC 5246 7.4.1.1: a server's request to renegotiate (TLS 1.2 / DTLS 1.2).
    HelloRequest,
    /// The post-HelloRetryRequest ClientHello (T2): overrides, mutations and
    /// extension deltas of a `send ClientHello` that follows `recv
    /// HelloRetryRequest` in an anchored flow lower under this kind, so the
    /// TLS 1.3 client applies them to CH2 and not to CH1. Never named in the
    /// DSL; `name()` is still "ClientHello".
    ClientHelloRetry,
    KeyUpdate,
    ChangeCipherSpec,
    Alert,
    AppData,
    /// TLS 1.3 application_data records protected with client_early_traffic_secret.
    EarlyData,
    /// TLS 1.3 handshake type 5, sent after an accepted 0-RTT flight.
    EndOfEarlyData,
    // T6: RFC 6520 heartbeat record (content type 24, never a handshake
    // message; a MessageKind so `send/recv Heartbeat { ... }` carries
    // overrides and matchers like any message).
    Heartbeat,
    /// RFC 6066 8 CertificateStatus (TLS 1.2 handshake type 22, OCSP stapling).
    CertificateStatus,
    /// RFC 8879 CompressedCertificate (TLS 1.3 handshake type 25).
    CompressedCertificate,
}

impl MessageKind {
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "ClientHello" => MessageKind::ClientHello,
            "ServerHello" => MessageKind::ServerHello,
            "EncryptedExtensions" => MessageKind::EncryptedExtensions,
            "Certificate" => MessageKind::Certificate,
            "CertificateRequest" => MessageKind::CertificateRequest,
            "CertificateVerify" => MessageKind::CertificateVerify,
            "ServerKeyExchange" => MessageKind::ServerKeyExchange,
            "ServerHelloDone" => MessageKind::ServerHelloDone,
            "ClientKeyExchange" => MessageKind::ClientKeyExchange,
            "Finished" => MessageKind::Finished,
            "NewSessionTicket" => MessageKind::NewSessionTicket,
            "HelloRetryRequest" => MessageKind::HelloRetryRequest,
            "HelloVerifyRequest" => MessageKind::HelloVerifyRequest,
            "HelloRequest" => MessageKind::HelloRequest,
            "KeyUpdate" => MessageKind::KeyUpdate,
            "ChangeCipherSpec" => MessageKind::ChangeCipherSpec,
            "Alert" => MessageKind::Alert,
            "AppData" => MessageKind::AppData,
            "EarlyData" => MessageKind::EarlyData,
            "EndOfEarlyData" => MessageKind::EndOfEarlyData,
            // T6:
            "Heartbeat" => MessageKind::Heartbeat,
            "CertificateStatus" => MessageKind::CertificateStatus,
            "CompressedCertificate" => MessageKind::CompressedCertificate,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            MessageKind::ClientHello => "ClientHello",
            MessageKind::ServerHello => "ServerHello",
            MessageKind::EncryptedExtensions => "EncryptedExtensions",
            MessageKind::Certificate => "Certificate",
            MessageKind::CertificateRequest => "CertificateRequest",
            MessageKind::CertificateVerify => "CertificateVerify",
            MessageKind::ServerKeyExchange => "ServerKeyExchange",
            MessageKind::ServerHelloDone => "ServerHelloDone",
            MessageKind::ClientKeyExchange => "ClientKeyExchange",
            MessageKind::Finished => "Finished",
            MessageKind::NewSessionTicket => "NewSessionTicket",
            MessageKind::HelloRetryRequest => "HelloRetryRequest",
            MessageKind::HelloVerifyRequest => "HelloVerifyRequest",
            MessageKind::HelloRequest => "HelloRequest",
            MessageKind::ClientHelloRetry => "ClientHello",
            MessageKind::KeyUpdate => "KeyUpdate",
            MessageKind::ChangeCipherSpec => "ChangeCipherSpec",
            MessageKind::Alert => "Alert",
            MessageKind::AppData => "AppData",
            MessageKind::EarlyData => "EarlyData",
            MessageKind::EndOfEarlyData => "EndOfEarlyData",
            // T6:
            MessageKind::Heartbeat => "Heartbeat",
            MessageKind::CertificateStatus => "CertificateStatus",
            MessageKind::CompressedCertificate => "CompressedCertificate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// The unit under test is a client; the harness plays the
    /// server (`uut client`).
    Client,
    /// The unit under test is a server; the harness dials it as a
    /// client (`uut server`).
    Server,
}

#[derive(Clone, Debug)]
pub enum Step {
    /// Run the preset handshake through to completion
    /// (no anchor — used when there's no until/after).
    Handshake {
        span: Span,
    },
    /// Run a specific sub-sequence of the handshake. Produced by
    /// lowering when an anchor (`until`/`after`) truncates the
    /// preset. Each entry maps to one driver call.
    HandshakeSteps {
        steps: Vec<HandshakeStep>,
        /// Configuration for this occurrence, not every message of this type.
        config: Option<Box<MessageConfig>>,
        span: Span,
    },
    /// Send an application-data request of exactly `size` plaintext bytes.
    /// The payload is generated at runtime and asks the shim for
    /// `reply_size` random response bytes (`None` = no response).
    /// If `mutations` is non-empty, they are applied at the record
    /// layer (e.g. `record.mac`, `record.aead_tag`).
    SendAppData {
        size: usize,
        reply_size: Option<usize>,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// Read one application-data record.
    /// `recv AppData [{ size: N }]`: one application-data record, optionally
    /// of exactly N plaintext bytes (tlsfuzzer's ExpectApplicationData(size)).
    RecvAppData {
        size: Option<usize>,
        span: Span,
    },
    /// Compare RFC 5705 / RFC 8446 exported keying material with the value
    /// independently computed by the UUT shim. `None` distinguishes an absent
    /// context from a present, zero-length context (RFC 5705 section 4).
    RecvExporter {
        label: Vec<u8>,
        context: Option<Vec<u8>>,
        length: usize,
        span: Span,
    },
    /// Compare the RFC 5929 `tls-unique` channel binding (TLS 1.2 only).
    RecvTlsUnique {
        unavailable: bool,
        span: Span,
    },
    /// Send a TLS 1.3 0-RTT application-data record. Unlike AppData this is raw
    /// random plaintext: it carries no shim request/response framing.
    SendEarlyData {
        size: usize,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// Receive 0-RTT plaintext and optionally pin its length.
    RecvEarlyData {
        size: Option<usize>,
        span: Span,
    },
    /// Close the connection. If `alert` is set, send a `[level, description]`
    /// alert record (e.g. warning/close_notify) before closing the transport.
    Close {
        alert: Option<[u8; 2]>,
        reset: bool,
        span: Span,
    },
    /// T6: `recv alert level[/code]`: the next record must be an alert of
    /// that level (and code, when given).
    RecvAlert {
        level: u8,
        code: Option<u8>,
        span: Span,
    },
    /// Pause then probe: sleep for `millis`, then try a short
    /// read. If the peer sent something (alert), the step FAILS
    /// with the alert. If the read times out (silence), the step
    /// SUCCEEDS. Used for Bleichenbacher oracle detection.
    Wait {
        millis: u64,
        span: Span,
    },
    /// Advance the peer's DTLS retransmit clock by `nanos` (the shim 'T' frame)
    /// to fire retransmission timers deterministically (RFC 6347 4.2.4).
    AdvanceClock {
        nanos: u64,
        span: Span,
    },
    /// Assert the remaining duration of the UUT's armed DTLS timer.
    ExpectNextTimeout {
        nanos: u64,
        span: Span,
    },
    /// Assert that the UUT has no armed DTLS timer.
    ExpectNoTimeout {
        span: Span,
    },
    /// Rescale the UUT's live DTLS timeout schedule.
    SetTimeout {
        millis: u32,
        span: Span,
    },
    /// Read one datagram and require it to carry handshake records (the peer's
    /// resent flight after a clock advance). DTLS only.
    ExpectRetransmit {
        span: Span,
    },
    /// Tell the shim server to rotate its DTLS cookie secret (the 'C' control
    /// frame, RFC 6347 4.2.1): cookies issued so far stop verifying.
    RotateCookieSecret {
        span: Span,
    },
    /// Flush the buffered flight, then resend the identical datagram (same record
    /// sequence numbers) so the peer's anti-replay window drops it. DTLS only.
    ResendFlight {
        span: Span,
    },
    /// Drive a renegotiation: a second handshake on the live connection
    /// (TLS 1.2 / DTLS 1.2). T5: `resumed` offers the established session ID
    /// or ticket and requires an abbreviated handshake; `insecure` omits renegotiation_info on the
    /// renegotiation ClientHello (RFC 5746 3.5 legacy renegotiation); the
    /// override / ext-delta lists customize the renegotiation ClientHello only
    /// (the initial handshake keeps the program-level overrides).
    Renegotiate {
        resumed: bool,
        insecure: bool,
        overrides: Vec<FieldOverride>,
        ext_deltas: Vec<ExtDeltaOp>,
        span: Span,
    },
    /// T5: `begin_renegotiation` over TLS (plzn's TLS 1.2 client): reset to a
    /// renegotiation handshake so the following explicit `send` / `recv`
    /// steps drive the second handshake message by message, with application
    /// data (RFC 5246 7.4.1.1 allows it under the old keys) and record-layer
    /// fragmentation in between. Overrides declared after this step apply to
    /// the renegotiation phase only (`Program::reneg_*`).
    BeginRenegotiation {
        span: Span,
    },
    /// Write raw bytes directly to the transport, bypassing the
    /// TLS record layer. Used for injecting malformed records.
    SendRaw {
        data: Vec<u8>,
        span: Span,
    },
    /// Send a TLS 1.3 KeyUpdate message and rotate write keys.
    SendKeyUpdate {
        request_update: u8,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// Read a TLS 1.3 KeyUpdate message and rotate read keys.
    RecvKeyUpdate {
        matchers: Vec<FieldOverride>,
        span: Span,
    },
    /// Replay the initial ClientHello as an encrypted post-handshake record
    /// (a renegotiation attempt). RFC 8446 4.1.2 forbids this in TLS 1.3.
    /// `msg_type`, if set, overrides the replayed handshake type byte so other
    /// unexpected post-handshake messages can be injected.
    SendRenegotiation {
        msg_type: Option<u8>,
        span: Span,
    },
    /// DTLS flight-level control (loss, delay, replay, retransmission,
    /// association restart); see `DtlsOp`. DTLS drivers only.
    Dtls {
        op: DtlsOp,
        span: Span,
    },
    /// Send a `[level, description]` alert under the current write keys WITHOUT
    /// closing (a warning the peer must tolerate, or a fatal alert whose
    /// aftermath the flow then observes).
    SendAlert {
        level: u8,
        code: u8,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `coalesce { ... }` boundaries: between them every handshake message goes
    /// into one buffered record, flushed at the end of the block, before a key
    /// change, or before any non-handshake record. With `hold_keys` a key
    /// change does NOT flush: the record is sealed at the block's end under the
    /// keys current then (a KeyUpdate and what follows it in one record). TLS
    /// drivers only.
    CoalesceBegin {
        mode: CoalesceMode,
        span: Span,
    },
    CoalesceEnd {
        span: Span,
    },
    /// `atomic { ... }` boundaries: every record written between them is
    /// buffered and goes to the transport in ONE write (tlsfuzzer
    /// TCPBufferingEnable / TCPBufferingFlush). TLS drivers only.
    AtomicBegin {
        span: Span,
    },
    AtomicEnd {
        span: Span,
    },
    /// `send record N "..."`: a record of content type N carrying these bytes,
    /// sealed under the current write keys (plaintext before any). TLS/DTLS.
    SendRecord {
        content_type: u8,
        data: Vec<u8>,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `send empty_record <type>`: a zero-length record of that content type
    /// under the current write keys (plaintext before any). TLS/DTLS drivers.
    SendEmptyRecord {
        content_type: u8,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `flush_fragment`: send the fragment held back by `@ fragment N hold`
    /// under whatever write keys are current now. TLS drivers only.
    FlushFragment {
        span: Span,
    },
}

/// DTLS-only flight control steps. plzn drives datagram loss, delay, replay and
/// retransmission from outside the library the way Botan's test_dtls12.cpp does
/// from inside it: by holding, dropping and re-sending whole flights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DtlsOp {
    /// `discard_flight`: flush our own pending flight, then read and drop every
    /// datagram the peer has in flight until it falls silent (simulated loss).
    DiscardFlight,
    /// `retransmit_flight [split [i, j, ...]]`: re-send the last flight's records
    /// with FRESH record sequence numbers (a real retransmission, unlike
    /// `resend_flight` which replays the identical datagram). With `split`, each
    /// listed record goes in its own datagram in the listed order and the peer
    /// must stay silent until the last one.
    RetransmitFlight { order: Option<Vec<usize>> },
    /// `hold_flight`: set the pending flight aside instead of flushing it.
    HoldFlight,
    /// `hold_retransmit`: build a fresh-sequence retransmission of the last
    /// flight and set it aside (a delayed datagram the network will deliver
    /// later, via `release_flight`).
    HoldRetransmit,
    /// `release_flight [i, j, ...]`: send the datagram set aside by
    /// hold_flight / hold_retransmit -- all of its records, or only the listed
    /// ones. An indexed release retains the other records for a later release.
    ReleaseFlight { records: Option<Vec<usize>> },
    /// `replay_flight N`: send the Nth flight (1-based, counting every flushed
    /// datagram) again, byte-identical.
    ReplayFlight(usize),
    /// Apply a deterministic mapping to every subsequently allocated outbound
    /// DTLS record sequence number. This produces validly authenticated records
    /// with large gaps or non-monotonic numbering for replay-window tests.
    MapRecordSequences(DtlsSequenceMap),
    /// Change the UUT's live DTLS path MTU before a retransmission.
    SetMtu(u32),
    /// Stop the DTLS 1.3 record layer from automatically acknowledging
    /// protected handshake records. Their record numbers remain available to
    /// a later `send_ack` step.
    SuppressAck,
    /// Send an explicit DTLS 1.3 ACK for selected records received since ACK
    /// suppression was enabled. `outer_epoch` is a negative-test override;
    /// `overflow_epoch` adds 2^63 to the acknowledged epoch field.
    SendAck {
        selection: DtlsAckSelection,
        outer_epoch: Option<u16>,
        overflow_epoch: bool,
    },
    /// Read and authenticate one DTLS 1.3 ACK record.
    ExpectAck,
    /// Send the endpoint's last Finished again with a fresh handshake
    /// message_seq and record number, but protect it with the retained previous
    /// write epoch. This expresses DTLS 1.3's old-epoch acceptance window.
    SendPreviousEpochFinished,
    /// Retransmit the endpoint's last Finished with its original handshake
    /// message_seq but a fresh protected-record number under the retained
    /// previous write epoch.
    RetransmitPreviousEpochFinished,
    /// `begin_renegotiation` (client): reset to a renegotiation handshake so the
    /// following explicit steps drive it message by message (RFC 5746 3.5).
    BeginRenegotiation,
    /// `restart` (client): forget the association and start a fresh one at
    /// epoch 0 on the same 5-tuple (RFC 6347 4.2.8; Botan
    /// `allow_dtls_epoch0_restart`).
    Restart,
    /// `hvr_flood N max_answers M` (server): after the first ClientHello, send N
    /// HelloVerifyRequests with distinct cookies and require the client to
    /// answer at most M of them (RFC 6347 4.2.1 note; Botan
    /// `dtls_maximum_hello_verify_requests`).
    HvrFlood { count: usize, max_answers: usize },
    /// `expect_retransmit no_ccs`: like `expect_retransmit`, and the resent
    /// flight must not carry a ChangeCipherSpec record (a renegotiation
    /// ClientHello retransmit rides under the active epoch with no CCS).
    ExpectRetransmitNoCcs,
    /// `header_only_flood N`: before flushing the pending flight, emit N
    /// header-only handshake records at far-future message_seqs claiming a large
    /// length (fragment_length 0). A peer's reassembler must bound the pending
    /// claims so the real in-sequence flight still completes (RFC 6347 4.2.3;
    /// Botan "header-only future-seq records do not block legit ClientHello").
    HeaderOnlyFlood { count: usize },
    /// `large_length_fragment N`: before flushing the pending flight, emit one
    /// handshake fragment at a far-future message_seq whose 24-bit total-length
    /// field claims N bytes while the fragment itself carries a single byte at
    /// offset 0. Where `header_only_flood` bounds the *count* of pending
    /// future-seq claims, this bounds the *size* a single claim may reserve: a
    /// peer must not pre-allocate N bytes from the announced length, and the
    /// real in-sequence flight must still complete (RFC 6347 4.2.3; Botan
    /// "far-future fragments memory-exhaustible", fixed 3.13.0).
    LargeLengthFragment { length: u32 },
    /// `future_seq_first`: reverse the order of the pending flight's handshake
    /// records so higher message_seqs are delivered before lower ones. The peer
    /// must buffer the out-of-order messages until the gap fills (RFC 6347
    /// 4.2.3). A no-op on a single-message flight.
    FutureSeqFirst,
    /// `interleave_flight [split]`: round-robin the pending flight's plaintext
    /// handshake records across the messages they belong to, so two (or more)
    /// consecutive messages' fragments alternate on the wire -- A0 B0 A1 B1 ...
    /// -- within one datagram (RFC 6347 4.2.3: a peer MUST reassemble each
    /// message by message_seq and fragment_offset regardless of interleaving).
    /// With `split` every interleaved record goes out as its own datagram, so
    /// the interleaving also crosses datagram boundaries. Needs fragments of at
    /// least two messages pending (`send X @ fragment N`, `send Y @ fragment M`).
    InterleaveFlight { split: bool },
}

impl DtlsOp {
    pub fn keyword(&self) -> String {
        match self {
            DtlsOp::DiscardFlight => "discard_flight".into(),
            DtlsOp::RetransmitFlight { order: None } => "retransmit_flight".into(),
            DtlsOp::RetransmitFlight { order: Some(o) } => {
                format!("retransmit_flight split {:?}", o)
            }
            DtlsOp::HoldFlight => "hold_flight".into(),
            DtlsOp::HoldRetransmit => "hold_retransmit".into(),
            DtlsOp::ReleaseFlight { records: None } => "release_flight".into(),
            DtlsOp::ReleaseFlight { records: Some(r) } => format!("release_flight {:?}", r),
            DtlsOp::ReplayFlight(n) => format!("replay_flight {}", n),
            DtlsOp::MapRecordSequences(DtlsSequenceMap::Identity) => {
                "map_record_sequences identity".into()
            }
            DtlsOp::MapRecordSequences(DtlsSequenceMap::Multiply(n)) => {
                format!("map_record_sequences multiply {}", n)
            }
            DtlsOp::MapRecordSequences(DtlsSequenceMap::Xor(n)) => {
                format!("map_record_sequences xor {}", n)
            }
            DtlsOp::SetMtu(mtu) => format!("set_mtu {}", mtu),
            DtlsOp::SuppressAck => "suppress_ack".into(),
            DtlsOp::SendAck {
                selection,
                outer_epoch,
                overflow_epoch,
            } => {
                let mut out = format!("send_ack {}", selection.keyword());
                if let Some(epoch) = outer_epoch {
                    out.push_str(&format!(" outer_epoch {}", epoch));
                }
                if *overflow_epoch {
                    out.push_str(" overflow_epoch");
                }
                out
            }
            DtlsOp::ExpectAck => "expect_ack".into(),
            DtlsOp::SendPreviousEpochFinished => "send_previous_epoch Finished".into(),
            DtlsOp::RetransmitPreviousEpochFinished => "retransmit_previous_epoch Finished".into(),
            DtlsOp::BeginRenegotiation => "begin_renegotiation".into(),
            DtlsOp::Restart => "restart".into(),
            DtlsOp::HvrFlood { count, max_answers } => {
                format!("hvr_flood {} max_answers {}", count, max_answers)
            }
            DtlsOp::ExpectRetransmitNoCcs => "expect_retransmit no_ccs".into(),
            DtlsOp::HeaderOnlyFlood { count } => format!("header_only_flood {}", count),
            DtlsOp::LargeLengthFragment { length } => {
                format!("large_length_fragment {}", length)
            }
            DtlsOp::FutureSeqFirst => "future_seq_first".into(),
            DtlsOp::InterleaveFlight { split: false } => "interleave_flight".into(),
            DtlsOp::InterleaveFlight { split: true } => "interleave_flight split".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtlsAckSelection {
    All,
    First,
    Last,
    Even,
    Odd,
}

impl DtlsAckSelection {
    pub fn keyword(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::First => "first",
            Self::Last => "last",
            Self::Even => "even",
            Self::Odd => "odd",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DtlsSequenceMap {
    #[default]
    Identity,
    Multiply(u64),
    Xor(u64),
}

impl DtlsSequenceMap {
    pub fn apply(self, sequence: u64) -> u64 {
        (match self {
            Self::Identity => sequence,
            Self::Multiply(n) => sequence.wrapping_mul(n),
            Self::Xor(n) => sequence ^ n,
        }) & 0x0000_FFFF_FFFF_FFFF
    }
}

/// One sub-step of a TLS handshake: the harness sends or receives
/// a specific message. The driver executes these in order,
/// performing any implicit internal work (key transitions, ECDH
/// agreement, key schedule advancement) between the visible
/// message steps. The test author doesn't name the internal
/// transitions — they fire automatically.
///
/// Generic over both client-harness and server-harness modes:
/// `Send(ClientHello)` means "the harness sends a CH" (which
/// makes sense when the harness IS the client). `Recv(ClientHello)`
/// means "the harness receives a CH" (which makes sense when the
/// harness IS the server). The preset constant for each
/// (version, subject) combo determines which direction each
/// message goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeStep {
    Send(MessageKind),
    Recv(MessageKind),
}

#[derive(Clone, Debug)]
pub struct MessageConfig {
    pub message: MessageKind,
    pub send: bool,
    pub fields: Vec<FieldOverride>,
    pub mutations: Vec<MessageMutations>,
    pub ext_deltas: Vec<MessageExtDeltas>,
}

impl MessageConfig {
    pub(crate) fn apply(
        &self,
        send_overrides: &mut Vec<MessageOverrides>,
        recv_matchers: &mut Vec<MessageOverrides>,
        send_mutations: &mut Vec<MessageMutations>,
        send_ext_deltas: &mut Vec<MessageExtDeltas>,
    ) {
        let fields = if self.send {
            send_overrides
        } else {
            recv_matchers
        };
        fields.retain(|m| m.message != self.message);
        fields.push(MessageOverrides {
            message: self.message,
            fields: self.fields.clone(),
        });
        if self.send {
            send_mutations.retain(|m| m.message != self.message);
            send_mutations.extend(self.mutations.clone());
            send_ext_deltas.retain(|m| m.message != self.message);
            send_ext_deltas.extend(self.ext_deltas.clone());
        }
    }
}

impl HandshakeStep {
    pub fn message_name(self) -> &'static str {
        match self {
            HandshakeStep::Send(mk) | HandshakeStep::Recv(mk) => mk.name(),
        }
    }

    pub fn is_send(self) -> bool {
        matches!(self, HandshakeStep::Send(_))
    }

    pub fn is_recv(self) -> bool {
        matches!(self, HandshakeStep::Recv(_))
    }

    pub fn message_kind(self) -> MessageKind {
        match self {
            HandshakeStep::Send(mk) | HandshakeStep::Recv(mk) => mk,
        }
    }
}

use HandshakeStep::{Recv as R, Send as S};

// ============================================================
//                     client-harness presets
// ============================================================

/// Full TLS 1.2 ECDHE handshake from the client's perspective.
pub const TLS12_ECDHE_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::Certificate),
    R(MessageKind::ServerKeyExchange),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// DTLS 1.2 (PSK or ECDHE-ECDSA). The recv steps tolerate the optional cookie
/// exchange (OpenSSL skips HelloVerifyRequest) and `ServerHelloDone` absorbs any
/// Certificate/ServerKeyExchange, so one sequence covers both shims and both key
/// exchanges. Mirrors `DtlsClient::do_handshake`. Used by `lower` to slice
/// anchored DTLS flows (`flow handshake until/after send X`).
pub const DTLS12_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::HelloVerifyRequest),
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// DTLS 1.2 with client authentication, client view (`versions: [dtls12]`,
/// UUT server `require_client_cert`): the server's CertificateRequest sits between its
/// ServerKeyExchange and ServerHelloDone (RFC 5246 7.4.4); the client answers
/// with Certificate, ClientKeyExchange, CertificateVerify (7.4.6 / 7.4.8).
pub const DTLS12_CLIENT_AUTH_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::HelloVerifyRequest),
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::Certificate),
    R(MessageKind::ServerKeyExchange),
    R(MessageKind::CertificateRequest),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::Certificate),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::CertificateVerify),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// DTLS 1.2 with client authentication, server view (`uut client` +
/// `peer.request_client_cert`): plzn's server requests, receives and verifies the
/// client's certificate, accepting an empty response without CertificateVerify.
pub const DTLS12_CLIENT_AUTH_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::HelloVerifyRequest),
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::Certificate),
    S(MessageKind::ServerKeyExchange),
    S(MessageKind::CertificateRequest),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::Certificate),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::CertificateVerify),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// DTLS 1.2 abbreviated (RFC 5077 ticket) handshake, client view: the cookie
/// exchange still runs, then ServerHello, [NewSessionTicket], CCS, Finished
/// from the server before the client's CCS + Finished. The optional ticket is
/// absorbed by the ChangeCipherSpec step (a server may omit it).
pub const DTLS12_RESUMED_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::HelloVerifyRequest),
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// DTLS 1.2 abbreviated handshake, server view (`uut client`, a session
/// that `resumes` an earlier one): the renewal ticket rides on the
/// ChangeCipherSpec step.
pub const DTLS12_RESUMED_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::HelloVerifyRequest),
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// DTLS 1.2 ECDHE-ECDSA server (`uut client`): plzn drives the server view,
/// including the HelloVerifyRequest cookie exchange. Mirrors
/// `DtlsServer::do_handshake`.
pub const DTLS12_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::HelloVerifyRequest),
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::Certificate),
    S(MessageKind::ServerKeyExchange),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// TLS 1.2 abbreviated (resumed) handshake from the client's
/// perspective. Server sends an OPTIONAL NewSessionTicket then CCS + Finished,
/// then client sends CCS + Finished (reversed from full). The optional
/// NewSessionTicket (RFC 5077 3.3, "the server MAY renew the ticket") is drained
/// and absorbed by recv_change_cipher_spec rather than an explicit recv step,
/// since the server may omit it.
pub const TLS12_RESUMED_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// Abbreviated TLS 1.2 (session-ticket) handshake from the SERVER's
/// perspective (RFC 5077 3.1 figure 2): ServerHello, [NewSessionTicket],
/// CCS, Finished first, then the client's CCS and Finished. The optional
/// renewal ticket rides on the ChangeCipherSpec step (`session_ticket` capability).
pub const TLS12_RESUMED_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// Full TLS 1.2 static-RSA handshake from the client's
/// perspective. No ServerKeyExchange — the client encrypts the
/// PMS directly under the server's RSA public key.
pub const TLS12_RSA_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::Certificate),
    // No R(ServerKeyExchange) — that's the key difference.
    R(MessageKind::ServerHelloDone),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// Full TLS 1.3 handshake from the client's perspective.
pub const TLS13_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::EncryptedExtensions),
    R(MessageKind::Certificate),
    R(MessageKind::CertificateVerify),
    R(MessageKind::Finished),
    // Middlebox-compat dummy CCS (RFC 8446 D.4) sent before the client's Finished,
    // matching real TLS 1.3 clients; the server drops it.
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// TLS 1.3 handshake with HelloRetryRequest from the client's perspective.
/// CH1 → HRR → CH2 → SH → EE → Cert → CV → Fin → Fin.
pub const TLS13_HRR_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::HelloRetryRequest),
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::EncryptedExtensions),
    R(MessageKind::Certificate),
    R(MessageKind::CertificateVerify),
    R(MessageKind::Finished),
    S(MessageKind::Finished),
];

/// TLS 1.3 PSK-only handshake (no Certificate or CertificateVerify).
pub const TLS13_PSK_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::EncryptedExtensions),
    R(MessageKind::Finished),
    S(MessageKind::Finished),
];

// ============================================================
//                     server-harness presets
// ============================================================

/// Full TLS 1.2 ECDHE handshake from the server's perspective.
pub const TLS12_ECDHE_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::Certificate),
    S(MessageKind::ServerKeyExchange),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// Full TLS 1.2 static-RSA handshake from the server's perspective.
pub const TLS12_RSA_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::Certificate),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// TLS 1.2 ECDHE with client auth from the client's perspective. The server
/// interleaves a CertificateRequest before ServerHelloDone; the client answers
/// with Certificate, ClientKeyExchange, then CertificateVerify (RFC 5246 §7.3).
pub const TLS12_CLIENT_AUTH_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::Certificate),
    R(MessageKind::ServerKeyExchange),
    R(MessageKind::CertificateRequest),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::Certificate),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::CertificateVerify),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// TLS 1.2 ECDHE with client auth from the server's perspective (RFC 5246
/// 7.3): CertificateRequest before ServerHelloDone, then the client's
/// Certificate, ClientKeyExchange and CertificateVerify.
pub const TLS12_CLIENT_AUTH_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::Certificate),
    S(MessageKind::ServerKeyExchange),
    S(MessageKind::CertificateRequest),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::Certificate),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::CertificateVerify),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// TLS 1.2 plain PSK (RFC 4279) from the client's perspective: no Certificate;
/// the ServerKeyExchange (an identity hint) is OPTIONAL, so the client's
/// `recv ServerHelloDone` absorbs one when the server sends it.
pub const TLS12_PSK_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// TLS 1.2 ECDHE_PSK (RFC 5489) from the client's perspective: no
/// Certificate; the ServerKeyExchange carries the hint and the (unsigned)
/// ephemeral ECDH parameters.
pub const TLS12_ECDHE_PSK_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::ServerKeyExchange),
    R(MessageKind::ServerHelloDone),
    S(MessageKind::ClientKeyExchange),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
];

/// TLS 1.2 PSK / ECDHE_PSK from the server's perspective: plzn's server
/// always sends the ServerKeyExchange (the identity hint, plus the ECDH
/// parameters for ECDHE_PSK).
pub const TLS12_PSK_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::ServerKeyExchange),
    S(MessageKind::ServerHelloDone),
    R(MessageKind::ClientKeyExchange),
    R(MessageKind::ChangeCipherSpec),
    R(MessageKind::Finished),
    S(MessageKind::ChangeCipherSpec),
    S(MessageKind::Finished),
];

/// TLS 1.3 with client auth from the client's perspective.
/// Server sends CertificateRequest; client sends Cert + CV + Finished.
pub const TLS13_CLIENT_AUTH_CLIENT_PRESET: &[HandshakeStep] = &[
    S(MessageKind::ClientHello),
    R(MessageKind::ServerHello),
    R(MessageKind::EncryptedExtensions),
    R(MessageKind::CertificateRequest),
    R(MessageKind::Certificate),
    R(MessageKind::CertificateVerify),
    R(MessageKind::Finished),
    S(MessageKind::Certificate),
    S(MessageKind::CertificateVerify),
    S(MessageKind::Finished),
];

/// Full TLS 1.3 handshake from the server's perspective.
pub const TLS13_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::EncryptedExtensions),
    S(MessageKind::Certificate),
    S(MessageKind::CertificateVerify),
    S(MessageKind::Finished),
    R(MessageKind::Finished),
];

/// TLS 1.3 PSK-resumed handshake from the server's perspective (RFC 8446
/// 2.2): the server answers the client's pre_shared_key and sends no
/// Certificate / CertificateVerify. Selected for a `session` that `resumes`
/// an earlier one in `uut client` mode.
pub const TLS13_PSK_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::EncryptedExtensions),
    S(MessageKind::Finished),
    R(MessageKind::Finished),
];

/// TLS 1.3 handshake with HelloRetryRequest from the server's
/// perspective. CH1 → HRR → CH2 → SH → EE → Cert → CV → Fin → Fin.
pub const TLS13_HRR_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::HelloRetryRequest),
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::EncryptedExtensions),
    S(MessageKind::Certificate),
    S(MessageKind::CertificateVerify),
    S(MessageKind::Finished),
    R(MessageKind::Finished),
];

/// TLS 1.3 with a second HelloRetryRequest from the server's
/// perspective: CH1 -> HRR -> CH2 -> HRR. A conforming client must
/// abort on the second HRR (RFC 8446 §4.1.4: "If a client receives a
/// second HelloRetryRequest in the same connection ... it MUST abort
/// the handshake with an "unexpected_message" alert."). The
/// post-flow drain catches the client's alert after the last send.
pub const TLS13_SECOND_HRR_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::HelloRetryRequest),
    R(MessageKind::ClientHello),
    S(MessageKind::HelloRetryRequest),
];

/// TLS 1.3 with client auth from the server's perspective.
pub const TLS13_CLIENT_AUTH_SERVER_PRESET: &[HandshakeStep] = &[
    R(MessageKind::ClientHello),
    S(MessageKind::ServerHello),
    S(MessageKind::EncryptedExtensions),
    S(MessageKind::CertificateRequest),
    S(MessageKind::Certificate),
    S(MessageKind::CertificateVerify),
    S(MessageKind::Finished),
    R(MessageKind::Certificate),
    R(MessageKind::CertificateVerify),
    R(MessageKind::Finished),
];

impl Step {
    pub fn span(&self) -> Span {
        match self {
            Step::Handshake { span }
            | Step::HandshakeSteps { span, .. }
            | Step::SendAppData { span, .. }
            | Step::RecvAppData { span, .. }
            | Step::RecvExporter { span, .. }
            | Step::RecvTlsUnique { span, .. }
            | Step::SendEarlyData { span, .. }
            | Step::RecvEarlyData { span, .. }
            | Step::Close { span, .. }
            | Step::RecvAlert { span, .. }
            | Step::Wait { span, .. }
            | Step::AdvanceClock { span, .. }
            | Step::ExpectNextTimeout { span, .. }
            | Step::ExpectNoTimeout { span }
            | Step::SetTimeout { span, .. }
            | Step::ExpectRetransmit { span }
            | Step::RotateCookieSecret { span }
            | Step::ResendFlight { span }
            | Step::Renegotiate { span, .. }
            | Step::BeginRenegotiation { span }
            | Step::SendRaw { span, .. }
            | Step::SendKeyUpdate { span, .. }
            | Step::RecvKeyUpdate { span, .. }
            | Step::SendRenegotiation { span, .. }
            | Step::Dtls { span, .. }
            | Step::SendAlert { span, .. }
            | Step::CoalesceBegin { span, .. }
            | Step::CoalesceEnd { span }
            | Step::AtomicBegin { span }
            | Step::AtomicEnd { span }
            | Step::SendRecord { span, .. }
            | Step::SendEmptyRecord { span, .. }
            | Step::FlushFragment { span } => *span,
        }
    }

    pub fn description(&self) -> String {
        match self {
            Step::Handshake { .. } => "handshake".into(),
            Step::HandshakeSteps { steps, .. } => {
                if steps.is_empty() {
                    "handshake (empty)".into()
                } else {
                    let last = steps.last().unwrap();
                    let dir = if last.is_send() { "send" } else { "recv" };
                    format!("handshake (through {} {})", dir, last.message_name())
                }
            }
            Step::SendAppData {
                size, reply_size, ..
            } => match reply_size {
                Some(reply) => format!("send AppData ({} bytes; reply {})", size, reply),
                None => format!("send AppData ({} bytes; no reply)", size),
            },
            Step::RecvAppData { size: None, .. } => "recv AppData".into(),
            Step::RecvAppData { size: Some(n), .. } => format!("recv AppData (size {})", n),
            Step::RecvExporter { length, .. } => {
                format!("recv Exporter ({} bytes)", length)
            }
            Step::RecvTlsUnique {
                unavailable: true, ..
            } => "recv TLSUnique (unavailable)".into(),
            Step::RecvTlsUnique { .. } => "recv TLSUnique".into(),
            Step::SendEarlyData { size, .. } => format!("send EarlyData ({} bytes)", size),
            Step::RecvEarlyData { size: None, .. } => "recv EarlyData".into(),
            Step::RecvEarlyData { size: Some(n), .. } => {
                format!("recv EarlyData (size {})", n)
            }
            Step::Close { reset: true, .. } => "close reset".into(),
            Step::Close { .. } => "close".into(),
            Step::RecvAlert { level, code, .. } => match code {
                Some(c) => format!("recv alert {}/{}", level, c),
                None => format!("recv alert {}", level),
            },
            Step::Wait { millis, .. } => format!("wait {}ms", millis),
            Step::AdvanceClock { nanos, .. } => format!("advance_clock {}ns", nanos),
            Step::ExpectNextTimeout { nanos, .. } => {
                format!("expect next_timeout {}ns", nanos)
            }
            Step::ExpectNoTimeout { .. } => "expect no_timeout".into(),
            Step::SetTimeout { millis, .. } => format!("set_timeout {}ms", millis),
            Step::ExpectRetransmit { .. } => "expect_retransmit".into(),
            Step::RotateCookieSecret { .. } => "rotate_cookie_secret".into(),
            Step::ResendFlight { .. } => "resend_flight".into(),
            Step::Renegotiate { .. } => "renegotiate".into(),
            Step::BeginRenegotiation { .. } => "begin_renegotiation".into(),
            Step::SendRaw { data, .. } => format!("send raw ({} bytes)", data.len()),
            Step::SendKeyUpdate { request_update, .. } => {
                format!("send KeyUpdate (request_update={})", request_update)
            }
            Step::RecvKeyUpdate { .. } => "recv KeyUpdate".into(),
            Step::SendRenegotiation {
                msg_type: Some(t), ..
            } => {
                format!("send Renegotiation (msg_type=0x{:02x})", t)
            }
            Step::SendRenegotiation { msg_type: None, .. } => "send Renegotiation".into(),
            Step::Dtls { op, .. } => op.keyword(),
            Step::SendAlert { level, code, .. } => format!("send alert {}/{}", level, code),
            Step::CoalesceBegin {
                mode: CoalesceMode::Flush,
                ..
            } => "coalesce {".into(),
            Step::CoalesceBegin {
                mode: CoalesceMode::HoldKeys,
                ..
            } => "coalesce hold_keys {".into(),
            Step::CoalesceBegin {
                mode: CoalesceMode::OldKeys,
                ..
            } => "coalesce old_keys {".into(),
            Step::CoalesceEnd { .. } => "} (end of coalesce)".into(),
            Step::AtomicBegin { .. } => "atomic {".into(),
            Step::AtomicEnd { .. } => "} (end of atomic)".into(),
            Step::SendRecord {
                content_type, data, ..
            } => {
                format!("send record {} ({} bytes)", content_type, data.len())
            }
            Step::SendEmptyRecord { content_type, .. } => {
                format!("send empty_record (content type {})", content_type)
            }
            Step::FlushFragment { .. } => "flush_fragment".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Expectation {
    /// Handshake and flow complete without error.
    Ok,
    /// Peer (UUT) sends an alert at some point during the flow.
    /// `codes` empty means "any code at this level"; non-empty is
    /// a set of acceptable codes.
    Alert { level: AlertLevel, codes: Vec<u8> },
    /// plzn rejects the UUT's input and sends this alert.
    Reject { level: AlertLevel, codes: Vec<u8> },
    /// Peer TCP-closes cleanly (FIN / EOF) without sending an alert record.
    Close,
    /// Peer ABORTS the connection without an alert -- a TCP reset or a
    /// broken-pipe/aborted close (ConnectionReset / BrokenPipe /
    /// ConnectionAborted). Distinct from `Close` (a clean FIN): some stacks
    /// (rustls, s2n) commonly drop the connection this way instead of alerting,
    /// and pinning it catches a regression to (or from) a real alert.
    Reset,
    /// The UUT exhausted its DTLS retransmission budget.
    Timeout,
    /// Any failure during the handshake or flow counts — wildcard
    /// for state-machine tests that don't pin a specific mode of
    /// failure.
    HandshakeFails,
    /// Any one of the listed outcomes is conforming.
    Any(Vec<Expectation>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertLevel {
    Warning,
    Fatal,
}

impl AlertLevel {
    pub fn wire_value(self) -> u8 {
        match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AlertLevel::Warning => "warning",
            AlertLevel::Fatal => "fatal",
        }
    }
}

impl Expectation {
    /// Short DSL-style description for diagnostics: `ok`,
    /// `alert fatal/unexpected_message`, etc.
    pub fn describe(&self) -> String {
        match self {
            Expectation::Ok => "ok".into(),
            Expectation::Close => "close".into(),
            Expectation::Reset => "reset".into(),
            Expectation::Timeout => "timeout".into(),
            Expectation::HandshakeFails => "handshake-fails".into(),
            Expectation::Any(alternatives) => format!(
                "any {{ {} }}",
                alternatives
                    .iter()
                    .map(Expectation::describe)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Expectation::Alert { level, codes } => {
                if codes.is_empty() {
                    format!("alert {}", level.name())
                } else if codes.len() == 1 {
                    let name = crate::schema::alert_code_name(codes[0])
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{}", codes[0]));
                    format!("alert {}/{}", level.name(), name)
                } else {
                    let names: Vec<String> = codes
                        .iter()
                        .map(|c| {
                            crate::schema::alert_code_name(*c)
                                .map(String::from)
                                .unwrap_or_else(|| format!("{}", c))
                        })
                        .collect();
                    format!("alert {}/{{{}}}", level.name(), names.join(","))
                }
            }
            Expectation::Reject { level, codes } => {
                let alert = Expectation::Alert {
                    level: *level,
                    codes: codes.clone(),
                }
                .describe();
                format!("reject{}", alert.strip_prefix("alert").unwrap_or(&alert))
            }
        }
    }

    pub fn accepts_success(&self) -> bool {
        match self {
            Expectation::Ok => true,
            Expectation::Any(alternatives) => alternatives.iter().any(Self::accepts_success),
            _ => false,
        }
    }

    pub fn contains_timeout(&self) -> bool {
        match self {
            Expectation::Timeout => true,
            Expectation::Any(alternatives) => alternatives.iter().any(Self::contains_timeout),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RfcRef {
    pub number: u32,
    pub section: Option<String>,
}

/// Named groups the TLS 1.3 client can generate a key share for: x25519, x448,
/// secp256r1, secp384r1, secp521r1, brainpoolP256r1tls13 / P384r1tls13
/// (RFC 8734 codepoints), all five RFC 7919 FFDHE groups, ML-KEM-512/768/1024 and the
/// X25519MLKEM768 / X448MLKEM1024 / SecP256r1MLKEM768 /
/// SecP384r1MLKEM1024 hybrids. brainpoolP512r1tls13 can be advertised
/// in supported_groups but not key-shared, and the RFC 7027 brainpool
/// codepoints are TLS 1.2-only. Not every backend implements all of these
/// (rustls has neither P-521, brainpool nor FFDHE), which is why the
/// `groups(tls13)` matrix set is narrower.
pub const CLIENT_KEY_SHARE_GROUPS: &[u16] = &[
    0x001d, 0x001e, 0x0017, 0x0018, 0x0019, 0x001f, 0x0020, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
    0x0200, 0x0201, 0x0202, 0x11eb, 0x11ec, 0x11ed, 0x11ee,
];

#[cfg(test)]
mod suite_catalogue_tests {
    use super::*;

    #[test]
    fn suite_wire_values_are_unique_and_parameters_consistent() {
        let mut seen = std::collections::HashSet::new();
        for s in ALL_SUITES {
            assert!(seen.insert(s.wire), "duplicate suite 0x{:04x}", s.wire);
            // AEAD suites have no MAC hash; the others do.
            assert_eq!(s.mac.is_none(), s.cipher.is_aead(), "{}", s.name);
            // SHA-384 PRF exactly for the *_SHA384 suites.
            assert_eq!(
                s.prf == HashAlg::Sha384,
                s.name.ends_with("SHA384"),
                "{}",
                s.name
            );
            // Names carry the cipher.
            if s.cipher == BulkCipher::Null {
                assert!(s.name.contains("NULL"), "{}", s.name);
            }
        }
        assert_eq!(ALL_SUITES.len(), 98);
    }

    /// Botan's DTLS rule: no CBC-with-HMAC, no CCM_8; AEAD-with-full-tag and
    /// NULL stay. PSK suites are a family of their own, offered only with a
    /// `psk { }` block over DTLS and never by the TLS 1.2 drivers unless named.
    #[test]
    fn dtls_offer_follows_botans_rule_and_psk_is_opt_in() {
        let dtls_default: Vec<&SuiteInfo> =
            ALL_SUITES.iter().filter(|s| s.dtls_default()).collect();
        assert!(
            dtls_default
                .iter()
                .all(|s| !s.cipher.is_cbc() && !s.cipher.is_ccm8())
        );
        assert!(dtls_default.iter().any(|s| s.cipher == BulkCipher::Null));
        assert!(!dtls_default.iter().any(|s| s.version == TlsVersion::Tls13));
        // Certificate families by default, no PSK.
        let cert = filter_suites_dtls(&[], false);
        assert!(
            cert.iter()
                .all(|w| suite_info(*w).unwrap().kex != KexType::Psk)
        );
        assert!(
            cert.contains(&0xc02b)
                && cert.contains(&0xc006)
                && !cert.contains(&0xc009)
                && !cert.contains(&0xc0ae)
        );
        // PSK families with a psk block, same rule: plain PSK and ECDHE_PSK.
        let psk = filter_suites_dtls(&[], true);
        assert!(psk.iter().all(|w| suite_info(*w).unwrap().kex.is_psk()));
        assert!(
            psk.contains(&0x00a8)
                && psk.contains(&0x002c)
                && !psk.contains(&0x008c)
                && !psk.contains(&0xc0a8)
        );
        assert!(
            psk.contains(&0xd001)
                && psk.contains(&0xccac)
                && !psk.contains(&0xc035)
                && !psk.contains(&0xd003)
        );
        // `ecdhe_psk` / `psk` capabilities narrow to one family.
        let ecdhe_psk = filter_suites_dtls(&[SuiteFilter::Kex(KexType::EcdhePsk)], true);
        assert!(
            !ecdhe_psk.is_empty()
                && ecdhe_psk
                    .iter()
                    .all(|w| suite_info(*w).unwrap().kex == KexType::EcdhePsk)
        );
        let plain = filter_suites_dtls(&[SuiteFilter::Kex(KexType::Psk)], true);
        assert!(
            !plain.is_empty()
                && plain
                    .iter()
                    .all(|w| suite_info(*w).unwrap().kex == KexType::Psk)
        );
        // Naming a suite lets a CBC / CCM_8 probe through.
        assert_eq!(
            filter_suites_dtls(&[SuiteFilter::Exact(0xc009)], false),
            vec![0xc009]
        );
        assert_eq!(
            filter_suites_dtls(&[SuiteFilter::Exact(0xc0a8)], true),
            vec![0xc0a8]
        );
        assert_eq!(
            filter_suites_dtls(
                &[
                    SuiteFilter::Mode(CipherMode::Cbc),
                    SuiteFilter::Kex(KexType::EcdheEcdsa)
                ],
                false
            )
            .len(),
            5
        );
        // The TLS 1.2 offer never carries PSK suites unless a filter names them.
        assert!(
            filter_suites(TlsVersion::Tls12, &[])
                .iter()
                .all(|w| suite_info(*w).unwrap().kex != KexType::Psk)
        );
        assert_eq!(
            filter_suites(TlsVersion::Tls12, &[SuiteFilter::Exact(0x00a8)]),
            vec![0x00a8]
        );
        assert!(!filter_suites(TlsVersion::Tls12, &[SuiteFilter::Kex(KexType::Psk)]).is_empty());
    }

    #[test]
    fn family_filters_partition_sensibly() {
        let tls12: Vec<&SuiteInfo> = ALL_SUITES
            .iter()
            .filter(|s| s.version == TlsVersion::Tls12)
            .collect();
        let aead = tls12
            .iter()
            .filter(|s| s.matches_filter(&SuiteFilter::Mode(CipherMode::Aead)))
            .count();
        let cbc = tls12
            .iter()
            .filter(|s| s.matches_filter(&SuiteFilter::Mode(CipherMode::Cbc)))
            .count();
        let null = tls12
            .iter()
            .filter(|s| s.matches_filter(&SuiteFilter::Mode(CipherMode::Null)))
            .count();
        assert_eq!(aead + cbc + null, tls12.len());
        assert_eq!(
            filter_suites(
                TlsVersion::Tls12,
                &[SuiteFilter::Mode(CipherMode::TripleDes)]
            )
            .len(),
            4
        );
        assert_eq!(
            filter_suites(TlsVersion::Tls12, &[SuiteFilter::Mode(CipherMode::Ccm8)]).len(),
            6
        );
        assert_eq!(
            filter_suites(TlsVersion::Tls13, &[SuiteFilter::Mode(CipherMode::Ccm)]),
            vec![0x1304, 0x1305]
        );
        // The historical offer order is preserved at the head of the table.
        assert_eq!(
            &filter_suites(TlsVersion::Tls12, &[])[..7],
            &[0xc02f, 0xc02b, 0x009c, 0xc013, 0xc009, 0x009e, 0x0033]
        );
    }
}
