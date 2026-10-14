// AST for a .plzn test file.
//
// Spans are byte offsets into the source, closed-open [start, end).
// Every node that can surface in a diagnostic carries one.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn dummy() -> Self {
        Self { start: 0, end: 0 }
    }
    pub fn join(self, other: Span) -> Span {
        Span::new(self.start.min(other.start), self.end.max(other.end))
    }
}

#[derive(Clone, Debug)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct File {
    pub tests: Vec<Test>,
}

#[derive(Clone, Debug)]
pub struct Test {
    pub name: StrLit, // e.g. "tls12/happy-rsa"
    pub header: Vec<HeaderLine>,
    pub matrix: Option<Matrix>,
    pub psk: Option<PskBlock>,
    pub uut: Option<UutBlock>,
    pub peer: Option<PeerBlock>,
    pub sessions: Vec<SessionBlock>,
    pub flow: Option<Flow>,
    pub expect: Option<Expect>,
    pub asserts: Vec<AssertLine>,
    // T1: `repeat N` -- run the whole test N times, each repetition a fresh
    // connection with its own sub-seed; `assert unique $x` compares captures
    // across the repetitions.
    pub repeat: Option<IntLit>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct SessionBlock {
    pub name: Ident,
    pub resumes: Option<Ident>,
    /// Select which one of the test-level `uut.versions` this connection uses.
    /// Multi-session shims retain one process/cache while pinning this
    /// connection to the selected version.
    pub version: Option<Ident>,
    /// Deliberately make plzn's server claim that an incompatible prior
    /// session was resumed. This is an adversarial peer control for checking
    /// that a UUT client rejects a cross-version ServerHello.
    pub force_resume: bool,
    pub flow: Flow,
    pub expect: Expect,
    pub asserts: Vec<AssertLine>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct PskBlock {
    pub identity: StrLit,
    pub secret: Vec<u8>,
    /// Ordered external identities sent by plzn's TLS 1.3 client. Empty keeps
    /// the historical single offer described by `identity` and `secret`.
    pub offers: Vec<PskOffer>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct PskOffer {
    pub identity: StrLit,
    pub secret: Vec<u8>,
    pub hash: Ident,
    pub span: Span,
}

/// Policy owned by plzn's endpoint (the peer of the unit under test). Keeping
/// this separate from `uut` makes role ownership explicit in the source.
#[derive(Clone, Debug)]
pub struct PeerBlock {
    /// Coarse selectors that shape plzn's offer or selection and become shim
    /// participation requirements.
    pub capabilities: Vec<Ident>,
    /// The plzn server requests a certificate; an empty response is allowed.
    /// This is meaningful with `uut client`, where the peer is the server.
    pub request_client_cert: bool,
    pub span: Span,
}

/// `uut client|server { ... }` — the unit-under-test's policy. The first
/// entry in `versions` selects plzn's matching protocol driver; every entry is
/// enabled in the shim, so `[tls12, tls13]` can exercise downgrade behavior.
/// The remaining fields are exact UUT policy controls.
#[derive(Clone, Debug)]
pub struct UutBlock {
    pub role: UutRole,
    pub versions: Vec<VersionRef>,
    /// Suite ids, each a literal or a matrix variable (`[$suite]` pins the
    /// UUT to the sweep point).
    pub cipher_suites: Vec<IntOrVar>,
    /// Named-group ids, each a literal or a matrix variable (`[$group]` pins
    /// the UUT to the sweep point).
    pub curves: Vec<IntOrVar>,
    pub require_client_cert: bool,
    pub request_client_cert: bool,
    pub verify_peer: bool,
    pub alpn_advertise: Vec<String>,
    pub alpn_select: Option<String>,
    pub alpn_select_from: Vec<String>,
    pub expect_alpn: Option<String>,
    pub alpn_decline: bool,
    /// DTLS-SRTP protection profiles the UUT offers/accepts, in preference order.
    pub srtp_profiles: Vec<u16>,
    pub expect_srtp_profile: Option<u16>,
    /// Signature schemes the UUT signs with / accepts (wire values).
    pub signing_prefs: Vec<u16>,
    pub verify_prefs: Vec<u16>,
    /// Local-policy knobs; None = the library's capability posture. See
    /// shims/DESIGN.md "Policy controls" for what each library can honour.
    pub server_preference: Option<bool>,
    /// `none` | `client` | `server` | `both`
    pub renegotiation: Option<String>,
    /// Tickets per handshake; 0 = no resumption at all.
    pub session_tickets: Option<u32>,
    /// TLS 1.3 maximum early-data bytes. Zero explicitly disables 0-RTT.
    pub max_early_data: Option<u32>,
    /// Maximum encoded peer certificate chain size in bytes.
    pub max_cert_list: Option<u32>,
    /// RFC 8449 maximum TLSPlaintext/TLSInnerPlaintext size advertised to the peer.
    pub record_size_limit: Option<u32>,
    /// `records_per_traffic_key: N`: automatic TLS 1.3 KeyUpdate after N records (0 = never).
    pub records_per_traffic_key: Option<u32>,
    /// Ask the shim to initiate one post-handshake KeyUpdate before its
    /// application-data loop (currently exercised by the BoringSSL shim).
    pub key_update: bool,
    /// `require` | `allow` | `off`
    pub extended_master_secret: Option<String>,
    pub encrypt_then_mac: Option<bool>,
    pub middlebox_compat: Option<bool>,
    /// RFC 8879 certificate compression support in the UUT. In server role,
    /// this enables compression of its Certificate when the peer offers it.
    pub compress_certificate: bool,
    /// RFC 7250: present a raw public key when the peer negotiates it.
    pub raw_public_key: bool,
    /// RFC 7250 certificate-type preferences, in wire order. Empty means the
    /// implementation default (X.509). `raw_public_key: true` is the legacy
    /// shorthand for setting both lists to `[raw_public_key]`.
    pub server_certificate_types: Vec<Ident>,
    pub client_certificate_types: Vec<Ident>,
    /// DTLS: datagram MTU and initial retransmit timeout.
    pub mtu: Option<u32>,
    pub initial_timeout_ms: Option<u32>,
    pub dtls_max_retransmissions: Option<u32>,
    pub dtls_max_timeout_ms: Option<u32>,
    pub dtls_require_cookie: Option<bool>,
    pub dtls_epoch0_restart: Option<bool>,
    pub dtls_max_hello_verify_requests: Option<u32>,
    /// D: the numeric literals written in the `curves` / `signing_prefs` /
    /// `verify_prefs` lists (their values are resolved at parse time; the
    /// named-constant lint still needs to see them).
    pub numeric_literals: Vec<(crate::schema::NameDomain, IntLit)>,
    /// Botan `minimum_key_update_interval_ms`: a peer KeyUpdate arriving sooner
    /// than this after the previous one is rejected (0 = no rate limit).
    pub min_key_update_interval_ms: Option<u32>,
    /// The pre-shared key the shim actually holds, when it must differ from the
    /// test's `psk { }` block: `psk_secret` is hex, `psk_identity` a string.
    pub psk_secret: Option<String>,
    pub psk_identity: Option<String>,
    /// Which credential the shim CLIENT answers a CertificateRequest with:
    /// `valid` | `untrusted` | `none` | `expired`.
    pub client_cert: Option<String>,
    /// The shim CLIENT starts a renegotiation once application data has flowed.
    pub renegotiate_after_handshake: bool,
    pub hello_request_after_app_data: bool,
    pub require_client_cert_on_renegotiation: bool,
    /// The shim SERVER writes each string as one half-RTT application record,
    /// after its own Finished and before the client's.
    pub half_rtt_data: Vec<String>,
    /// T6: the shim SERVER staples an OCSP response for its certificate
    /// (RFC 6066 8 / RFC 8446 4.4.2.1), and requests post-handshake client
    /// authentication once the handshake is done (RFC 8446 4.6.2).
    pub ocsp_stapling: bool,
    pub post_handshake_auth: Option<String>,
    pub span: Span,
}

/// A concrete protocol version or a matrix variable resolved to one.
#[derive(Clone, Debug)]
pub enum VersionRef {
    Name(Ident),
    Var(Ident),
}

impl VersionRef {
    pub fn span(&self) -> Span {
        match self {
            Self::Name(id) | Self::Var(id) => id.span,
        }
    }
}

#[derive(Clone, Debug)]
pub enum HeaderLine {
    Rfc {
        number: u32,
        section: Option<SectionRef>, // optional `section 4.1.3`
        span: Span,
    },
    // `skip <backend> [<backend>...]` -- names backends this test does not apply
    // to (e.g. `skip rustls` for a DHE/CBC test rustls cannot negotiate).
    // The runner reports SKIP instead of running the case on those backends.
    Skip {
        backends: Vec<Ident>,
        /// `skip rustls "no CBC suites"`: why, printed in the skip log.
        reason: Option<StrLit>,
        span: Span,
    },
    // `xfail <backend> [<backend>...] "reason"` -- names backends which are
    // expected to fail because of a known implementation defect. Unlike
    // `skip`, the runner executes the test: a failure is XFAIL and a success
    // is XPASS (and therefore fails the run).
    Xfail {
        backends: Vec<Ident>,
        reason: Option<StrLit>,
        span: Span,
    },
    // A: `chain: [names]` (the SERVER's certificate chains) / `client_chain:
    // [names]` (the client-authentication credentials). Names: `default`,
    // `rsa_2048` (`rsa`), `rsa_pss`, `ecdsa_p256`, `ecdsa_p384`, `ecdsa_p521`,
    // `ed25519`; `[]` = no chain at all.
    Chain {
        client: bool,
        names: Vec<Ident>,
        span: Span,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UutRole {
    Client,
    Server,
}

#[derive(Clone, Debug)]
pub struct Matrix {
    pub axes: Vec<MatrixAxis>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct MatrixAxis {
    pub var: Ident, // e.g. "pos"
    pub values: MatrixValues,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum MatrixValues {
    // `0..15` (inclusive) or `1..0xff`; T1: `0x0100..0xff00 step 0x100`
    Range {
        lo: IntLit,
        hi: IntLit,
        step: Option<IntLit>,
        span: Span,
    },
    // `[-1, -2, -6, -12]` or `[0x01, 0x80]` or `[0x0001..0x0016, 0x001a..0x001c]`
    // (T1: ranges inside the list expand inclusively)
    List {
        items: Vec<MatrixItem>,
        span: Span,
    },
    // `in cipher_suites(tls13)` — named set with optional arg
    Named {
        name: Ident,
        arg: Option<Ident>,
        span: Span,
    },
}

/// T1: one entry of a matrix value list: a literal or an inclusive range;
/// D: or a name from the cipher-suite / group / signature-scheme /
/// extension-type tables (`matrix { suite in [ECDHE_RSA_WITH_AES_128_GCM_SHA256] }`).
#[derive(Clone, Debug)]
pub enum MatrixItem {
    Int(IntLit),
    Range { lo: IntLit, hi: IntLit },
    Name(Ident),
}

#[derive(Clone, Copy, Debug)]
pub struct IntLit {
    pub value: i64,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ExtDelta {
    // `+ext server_name = "example.com"`
    // `+ext supported_groups = [secp256r1, x25519]`
    // `+ext server_name = raw "F00F"`
    // `+ext 0x0a0a = raw "F00F"`   (unknown extension by wire type)
    Add {
        target: ExtTarget,
        value: ExtValue,
        // `+ext dup TYPE = ...` appends even if an extension of this type is
        // already present, producing a duplicate (for DuplicateExtension tests).
        dup: bool,
        span: Span,
    },
    // `-ext server_name`
    // `-ext 0x000d`
    Remove {
        target: ExtTarget,
        span: Span,
    },
    // T1: `+ext each 0x0100..0x01ff [= value]` / `+ext each [90..13171,
    // 13173..16473]` -- one extension per listed wire type (any list-valued
    // expression), all with the same (default: empty) body.
    AddEach {
        types: FieldValue,
        value: ExtValue,
        span: Span,
    },
    // `reverse_extensions` — reverse the order of all extensions (RFC 8446 4.2
    // permits any order except pre_shared_key last).
    Reverse {
        span: Span,
    },
}

#[derive(Clone, Debug)]
pub enum ExtTarget {
    /// `server_name`, `supported_groups`, etc. — looked up in schema.
    Named(Ident),
    /// `0x0a0a` — wire type number directly.
    Wire(u16, Span),
    /// T1: `$id` — a matrix variable holding the wire type.
    Var(Ident),
}

#[derive(Clone, Debug)]
pub enum ExtValue {
    /// `raw "F00F"` — exact bytes for the extension body.
    Raw(Vec<u8>, Span),
    /// `"example.com"` — string interpreted by the named-extension encoder.
    Str(StrLit),
    /// `[secp256r1, x25519, 0x01ff, 0x0022..0x00fe]` / `["h2", "http/1.1"]` /
    /// `[ffdhe2048, 0x0100..0x01ff : 0xab * 256]` — a list whose items are
    /// names, numbers, strings, ranges, repeats or `key : bytes` entries (T1:
    /// the shared list grammar of `FieldValue`); each typed encoder resolves
    /// the items it accepts.
    List(Vec<FieldValue>, Span),
    /// `0x1234` — single integer, e.g. for max_fragment_length.
    Int(IntLit),
    /// T1: `$i` — a matrix variable where an integer value is expected
    /// (`+ext padding = $i`).
    Var(Ident),
    /// `ocsp`, `x509`, `tls13` — a single symbolic name, for extensions whose
    /// body is one enum value (status_request, a server's certificate-type
    /// selection, the ServerHello supported_versions form).
    Ident(Ident),
    /// `+ext NAME` with no `= value`: an empty extension body
    /// (extended_master_secret, post_handshake_auth, early_data in a
    /// ClientHello, a server's server_name acknowledgement, ...).
    Empty(Span),
}

#[derive(Clone, Debug)]
pub struct StrLit {
    pub value: String,
    pub span: Span,
}

/// A section reference in an `rfc` header line: the dotted path written after
/// `section`, e.g. `4.1.2` or the appendix `B.4`. Stored without a `§`.
#[derive(Clone, Debug)]
pub struct SectionRef {
    pub text: String,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Flow {
    pub preset: Option<FlowPreset>,
    pub steps: Vec<Step>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct FlowPreset {
    pub base: Ident,                // "handshake"
    pub anchor: Option<FlowAnchor>, // "until send Finished" etc.
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct FlowAnchor {
    pub when: AnchorWhen,
    pub verb: AnchorVerb,
    pub msg: Ident,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorWhen {
    Until,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorVerb {
    Send,
    Recv,
}

#[derive(Clone, Debug)]
pub enum Step {
    Send {
        msgs: Vec<MessageRef>,
        overrides: Vec<FieldOverride>,
        mutations: Vec<Mutation>,
        ext_deltas: Vec<ExtDelta>,
        /// DTLS only: a `@ fragment N` / `@ duplicate_fragment N` / etc. suffix
        /// describing how to fragment this message on the wire. Parsed from the
        /// same `@` list as `mutations`. `None` = the default one-fragment emit.
        dtls_frag: Option<DtlsFrag>,
        span: Span,
    },
    Recv {
        msgs: Vec<MessageRef>,
        matchers: Vec<FieldOverride>,
        /// `ext NAME == value` / `ext NAME: value`: the received extension's
        /// BODY must equal the typed value's encoding (T2).
        ext_matchers: Vec<ExtMatcher>,
        span: Span,
    },
    SendRaw {
        hex: Vec<u8>,
        span: Span,
    },
    Close {
        alert: Option<AlertSpec>,
        /// T6: `close reset` -- an abortive close (TCP RST, tlsfuzzer's
        /// CloseRST) instead of a FIN.
        reset: bool,
        span: Span,
    },
    /// T6: `recv alert warning/close_notify` -- read one record and require
    /// it to be that alert (the code may be omitted: any alert of that level).
    RecvAlert {
        alert: AlertSpec,
        span: Span,
    },
    /// T6: `repeat N { steps }` -- the block's steps N times over. Expanded
    /// by the parser right after the flow is read (`expand_repeats`), so no
    /// later stage sees it.
    Repeat {
        /// T1: the count may be a matrix variable; literal counts are expanded
        /// by the parser, variable ones by lowering (`unroll_repeats`).
        count: IntOrVar,
        steps: Vec<Step>,
        span: Span,
    },
    /// `wait 200ms` — pause for a duration, then check if the
    /// peer sent anything. If data arrived (typically an alert),
    /// it surfaces as a step failure. If the read times out,
    /// the step succeeds (silence = the peer is correct).
    Wait {
        millis: u64,
        span: Span,
    },
    /// `advance_clock 1s` — advance the peer's DTLS retransmit clock (RFC 6347
    /// 4.2.4) by a virtual duration (the shim's 'T' frame), to fire retransmit
    /// timers deterministically. DTLS only.
    AdvanceClock {
        nanos: u64,
        span: Span,
    },
    /// `expect next_timeout 1s` / `expect no_timeout` — assert the UUT's
    /// currently armed DTLS timer exactly. DTLS only.
    ExpectNextTimeout {
        nanos: u64,
        span: Span,
    },
    ExpectNoTimeout {
        span: Span,
    },
    /// `set_timeout 250ms` — rescale the UUT's live DTLS timer. DTLS only;
    /// backends without a corresponding library API skip the test.
    SetTimeout {
        millis: u32,
        span: Span,
    },
    /// `expect_retransmit` — read one datagram and require it to carry handshake
    /// records (the peer's resent flight). DTLS only.
    ExpectRetransmit {
        span: Span,
    },
    /// `rotate_cookie_secret` — tell the shim SERVER to rotate its DTLS cookie
    /// secret (the 'C' control frame), so a cookie it issued earlier no longer
    /// verifies (RFC 6347 4.2.1). DTLS, `uut server` only.
    RotateCookieSecret {
        span: Span,
    },
    /// `resend_flight` — flush the buffered flight, then send the identical
    /// datagram again (same record sequence numbers). The peer's anti-replay
    /// window must drop the duplicate (RFC 6347 4.1.2.6). DTLS only.
    ResendFlight {
        span: Span,
    },
    /// `renegotiate` — drive a renegotiation (a second handshake on the live
    /// connection). TLS 1.2 / DTLS 1.2 only.
    // T5: `renegotiate [resumed] [insecure] [{ ClientHello overrides + ext deltas }]`
    // drives a second handshake (client-initiated in `uut server`,
    // HelloRequest in `uut client`). The optional body customizes the
    // renegotiation ClientHello only (not the initial one); `insecure` omits
    // renegotiation_info (RFC 5746 3.5 legacy renegotiation), while `resumed`
    // offers the current session ID or ticket for an abbreviated handshake.
    Renegotiate {
        resumed: bool,
        insecure: bool,
        overrides: Vec<FieldOverride>,
        ext_deltas: Vec<ExtDelta>,
        span: Span,
    },
    /// DTLS flight control (`discard_flight`, `retransmit_flight`, `hold_flight`,
    /// `hold_retransmit`, `release_flight`, `replay_flight N`,
    /// `begin_renegotiation`, `restart`, `hvr_flood N max_answers M`,
    /// `expect_retransmit no_ccs`). See `ir::DtlsOp`.
    Dtls {
        op: crate::ir::DtlsOp,
        span: Span,
    },
    /// `send alert warning/no_renegotiation [@ mutations]` -- an alert record
    /// without closing.
    SendAlert {
        alert: AlertSpec,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `coalesce [hold_keys] { ... }` boundaries: the handshake messages sent
    /// between them are buffered into ONE record (TLS only); `hold_keys` keeps
    /// buffering across a key change.
    CoalesceBegin {
        mode: crate::ir::CoalesceMode,
        span: Span,
    },
    CoalesceEnd {
        span: Span,
    },
    /// `atomic { ... }` boundaries: the records written between them go to the
    /// transport in one write (TLS only).
    AtomicBegin {
        span: Span,
    },
    AtomicEnd {
        span: Span,
    },
    /// `send empty_record handshake` / `send empty_record 0x00` -- a zero-length
    /// record of that content type under the current write keys (TLS or DTLS).
    SendEmptyRecord {
        content_type: ContentTypeSpec,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `send record 24 "text"` / `send record 24 raw "HEX"` -- a record of an
    /// arbitrary content type, sealed under the current write keys (TLS or DTLS).
    SendRecord {
        content_type: IntLit,
        data: Vec<u8>,
        mutations: Vec<Mutation>,
        span: Span,
    },
    /// `flush_fragment` -- send the fragment held back by `@ fragment N hold`.
    FlushFragment {
        span: Span,
    },
}

/// A record content type named (`handshake`, `alert`, ...) or numeric (`0x00`, `24`).
#[derive(Clone, Debug)]
pub enum ContentTypeSpec {
    Named(Ident),
    Numeric(IntLit),
}

impl ContentTypeSpec {
    pub fn span(&self) -> Span {
        match self {
            ContentTypeSpec::Named(i) => i.span,
            ContentTypeSpec::Numeric(n) => n.span,
        }
    }
}

/// `recv X { ext NAME == value }`: an extension-body matcher on a received
/// hello. The value takes the `+ext` forms and is encoded by the same typed
/// encoders, so the received body must be byte-identical to that encoding.
#[derive(Clone, Debug)]
pub struct ExtMatcher {
    pub target: ExtTarget,
    pub value: ExtValue,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct MessageRef {
    pub name: Ident,
    /// Legacy message payload syntax. AppData now uses `{ size, reply }`, but
    /// the parser retains this node so lowering can give a migration error.
    pub payload: Option<FieldValue>,
}

#[derive(Clone, Debug)]
pub struct FieldOverride {
    pub field: Ident,
    pub value: FieldValue,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum FieldValue {
    Int(IntLit),
    Ident(Ident), // symbolic, e.g. update_requested
    Str(StrLit),
    /// `file "path"`: the bytes of a file (T4; a byte field's value).
    File(StrLit),
    List(Vec<FieldValue>), // [0x1301]
    Empty,                 // [] (zero-length list sentinel when parser chooses)
    MatrixVar(Ident),      // $pos
    // T1 generators (see USAGE "Values and generators"):
    /// `lo..hi` inside a list: every value from lo to hi inclusive.
    Range {
        lo: IntOrVar,
        hi: IntOrVar,
        span: Span,
    },
    /// `item * N`: the item (a number, string, name, list or range) N times;
    /// `zeros N` is `0x00 * N`.
    Repeat {
        item: Box<FieldValue>,
        count: IntOrVar,
        span: Span,
    },
    /// `key : value` inside a list (a key_share entry `group : bytes`).
    Entry {
        key: Box<FieldValue>,
        value: Box<FieldValue>,
        span: Span,
    },
    /// `capture $name` on a matcher: record the peer's value under the name
    /// instead of comparing it (for `assert unique $name` across repeats).
    Capture(Ident),
}

#[derive(Clone, Debug)]
pub struct Mutation {
    pub op: MutationOp,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum MutationOp {
    Xor {
        target: ByteTarget,
        value: MutValue,
    },
    Set {
        target: ByteTarget,
        value: MutValue,
    },
    /// `add[handshake.some_length] = N` / `sub[...] = N` — adjust the complete
    /// big-endian integer field without changing any payload bytes.
    Add {
        target: FieldPath,
        value: MutValue,
    },
    Sub {
        target: FieldPath,
        value: MutValue,
    },
    /// `pad +N [0xNN]` — append N bytes (zero, or the given pad byte); N may
    /// be a matrix variable.
    PadPlus {
        n: MutValue,
        byte: Option<IntLit>,
    },
    /// `pad "HEX"` — append exactly these bytes.
    PadBytes {
        bytes: Vec<u8>,
        span: Span,
    },
    PadMinus {
        n: MutValue,
    },
    Truncate {
        n: MutValue,
    },
    /// `trailing "HEX"` — append raw bytes after the encoded handshake
    /// message without changing its handshake length.
    TrailingBytes {
        bytes: Vec<u8>,
        span: Span,
    },
    /// `omit_prefix N` — omit the first N encoded handshake bytes on the
    /// wire. Used to finish a message whose prefix was sent by `trailing`.
    OmitPrefix {
        n: MutValue,
    },
    /// `record_version 0xNNNN` — the record header version for this send.
    RecordVersion {
        v: IntLit,
    },
    /// `record_pad N` / `record_pad fill` — TLS/DTLS 1.3 record padding.
    RecordPad {
        n: Option<IntLit>,
        span: Span,
    },
    /// DTLS 1.3 authenticated record-header controls. These must be applied
    /// before sealing, unlike the generic post-seal byte mutations.
    Dtls13ShortSequence,
    Dtls13OmitLength,
    Dtls13SetCidBit,
    Dtls13LegacyHeader,
    /// `plaintext [= bytes]` — send unencrypted / replace the pre-encryption block.
    Plaintext {
        replace: Option<Vec<u8>>,
        span: Span,
    },
    /// `cbc_pad N` — minimum CBC padding length including the length byte.
    CbcPad {
        n: IntLit,
    },
    /// `reorder N` — fragment the message into N-byte handshake fragments and
    /// send them in reverse order (out-of-order delivery). DTLS only; a no-op on
    /// TLS, which does not fragment handshake messages.
    Reorder {
        n: IntLit,
    },
    /// `fragment N [hold | hold_all]` — split the framed message into N-byte
    /// records at the TLS record layer (RFC 5246 6.2.1 / RFC 8446 5.1). `hold`
    /// keeps the last fragment back until a `flush_fragment` step; `hold_all`
    /// keeps every fragment after the first, one per `flush_fragment`. TLS only.
    Fragment {
        n: MutValue,
        hold: crate::ir::FragHold,
    },
}

/// A DTLS handshake-fragmentation suffix on a `send` step (`@ fragment N`, etc.).
/// Parsed from the same `@` list as byte mutations, but carried separately
/// because it is DTLS-specific and lowers to `ir::DtlsFragScheme`, not a
/// `MutationOp`. See `DtlsFragScheme` for the semantics of each variant.
#[derive(Clone, Debug)]
pub enum DtlsFrag {
    Fragment { n: IntLit },
    DuplicateFragment { n: IntLit },
    ReorderOverlap { n: IntLit },
    CompleteAndFragments { n: IntLit },
    EmptyFragments { span: Span },
    SplitFragmentRecord { n: IntLit },
    OverlapMismatch { n: IntLit },
    TypeMismatch { n: IntLit },
    OffsetOverflow { span: Span },
    LengthMismatch { n: IntLit },
    FragmentLengthMismatch { n: IntLit },
    FutureSequence { n: IntLit },
    FutureSequencePacked { n: IntLit },
}

#[derive(Clone, Debug)]
pub struct ByteTarget {
    // Optional structured path prefix: `record.aead_tag` / `handshake.verify_data`.
    // None means the mutation targets the serialised message body.
    pub path: Option<FieldPath>,
    pub index: ByteIndex,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct FieldPath {
    pub parts: Vec<Ident>, // [record, aead_tag]
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ByteIndex {
    Single(IntOrVar),
    Range { lo: IntOrVar, hi: IntOrVar },
}

#[derive(Clone, Debug)]
pub enum IntOrVar {
    Int(IntLit),
    Var(Ident),
    /// T1: `$var + N` / `$var - N` -- a matrix variable plus a constant
    /// offset (range bounds, repeat counts, `each` lists).
    VarOffset {
        var: Ident,
        offset: i64,
    },
}

#[derive(Clone, Debug)]
pub enum MutValue {
    Int(IntLit),
    Var(Ident),
    Hex(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct AlertSpec {
    pub level: Ident,        // warning | fatal
    pub code: Option<Ident>, // close_notify | unexpected_message | ...
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Expect {
    pub kind: ExpectKind,
    /// Per-UUT overrides: `expect ok if openssl`.
    pub overrides: Vec<ExpectOverride>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ExpectOverride {
    pub kind: ExpectKind,
    pub uut: Ident,
}

#[derive(Clone, Debug)]
pub enum ExpectKind {
    Ok,
    Close,
    Reset,
    Timeout,
    HandshakeFails,
    // plzn's endpoint rejects the UUT and sends this alert.
    Reject {
        level: Ident,
        codes: Vec<Ident>,
    },
    // `expect any { ok, alert fatal/protocol_version }`
    Any(Vec<ExpectKind>),
    // `expect alert fatal` or `expect alert fatal/close_notify` or
    // `expect alert fatal/{a,b,c}`
    Alert {
        level: Ident,
        codes: Vec<Ident>, // empty = any code at that level
    },
}

#[derive(Clone, Debug)]
pub struct AssertLine {
    pub kind: AssertKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum AssertKind {
    // assert no_duplicate_record_seqnums
    Named(Ident),
    // assert max_datagram_size 256
    MaxDatagramSize(IntLit),
    // assert negotiated.version == tls13
    Eq { path: FieldPath, value: FieldValue },
    // T1: assert unique $r, $s -- every captured value differs across the
    // test's repetitions (and matrix points).
    Unique(Vec<Ident>),
}
