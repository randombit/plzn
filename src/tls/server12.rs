// TLS 1.2 ECDHE server-side driver.
//
// The mirror of `Tls12Client` in driver.rs. The harness plays the
// server: it receives a ClientHello, sends its flight
// (SH+Cert+SKE+SHD), receives the client flight (CKE+CCS+Fin),
// and sends CCS+Fin. Then application data.
//
// Used when the .plzn file says `uut client`.

use crate::ir::{
    ExtDeltaOp, FieldOverride, FieldValue, HandshakeStep, MessageExtDeltas, MessageKind,
    MessageMutations, MessageOverrides, Mutation,
};
use crate::tls::codec::EXT_ENCRYPT_THEN_MAC;
use crate::tls::codec::{
    CLIENT_CERT_TYPE_ECDSA_SIGN, CLIENT_CERT_TYPE_RSA_SIGN, CONTENT_TYPE_CCS,
    CONTENT_TYPE_HANDSHAKE, Extension, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_STATUS, HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_CLIENT_KEY_EXCHANGE,
    HS_FINISHED, HS_HELLO_REQUEST, HS_SERVER_HELLO, HS_SERVER_HELLO_DONE, HS_SERVER_KEY_EXCHANGE,
    ServerHelloBuilder, decode_certificate_12_body, decode_certificate_verify_13_body,
    decode_client_hello_body, decode_ecdhe_client_key_exchange_body, decode_finished_body,
    encode_certificate_12_body_mapped, encode_certificate_request_12_body_mapped,
    encode_certificate_status_body_mapped, encode_ecdhe_server_key_exchange_body_mapped,
    encode_ecdhe_server_key_exchange_body_mapped_legacy, encode_finished_body_mapped,
    encode_handshake, encode_server_hello_done_body,
};
use crate::tls::crypto::{
    EcdheGroup, EcdhePrivate, HashAlg, PrivateKey, PublicKey, Rng, SignatureScheme, TranscriptHash,
};
use crate::tls::driver::{
    TlsEndpoint, TlsError, apply_server_hello_override, collect_mutations, collect_overrides,
    match_client_hello_field,
};
use crate::tls::handshake::{
    compute_verify_data_for, derive_master_secret_ems_for, derive_master_secret_for,
    export_keying_material_legacy,
};
use crate::tls::kex12::{
    decode_psk_cke, encode_ecdhe_psk_ske_mapped, encode_psk_hint_ske_mapped, psk_premaster,
    psk_premaster_with, select_ecdhe_group, select_signature_scheme,
};
use crate::tls::record::{DirectionKeys, RecordError, RecordLayer, TlsVersion};
use crate::transport::UutTransport;

use crate::tls::codec::ByteCursor;
use crate::tls::codec::parse_handshake_header;

pub struct Tls12ServerConfig {
    pub version: TlsVersion,
    pub cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    /// A: every chain this server holds (`chain:`), in preference order;
    /// `cert_der` / `private_key_der` are the initially selected one. With two
    /// or more, the ClientHello picks (`tls::chains`).
    pub chains: Vec<crate::ir::Chain>,
    pub seed: [u8; 32],
    pub send_overrides: Vec<MessageOverrides>,
    pub recv_matchers: Vec<MessageOverrides>,
    pub send_mutations: Vec<MessageMutations>,
    pub send_ext_deltas: Vec<MessageExtDeltas>,
    /// Suites this server may select, in preference order (suite capabilities
    /// via `ir::filter_suites`); empty = every TLS 1.2 suite plzn implements.
    /// The single certificate further restricts the family.
    pub cipher_suites: Vec<u16>,
    /// Groups the server may select for ECDHE (named curves) and DHE (ffdhe*),
    /// in preference order (group capabilities); empty = the default set.
    pub groups: Vec<u16>,
    /// Signature schemes the server may sign with (signature-scheme
    /// capabilities); empty = everything the key supports. Intersected with the
    /// client's signature_algorithms in the client's order.
    pub signature_schemes: Vec<u16>,
    /// RFC 4279 pre-shared key `(identity, secret)`; enables the PSK and
    /// ECDHE_PSK families (the identity is also the psk_identity_hint).
    pub psk: Option<(Vec<u8>, Vec<u8>)>,
    /// DER-encoded Distinguished Names for the CertificateRequest's
    /// certificate_authorities (RFC 5246 7.4.4). Empty = none.
    pub cert_request_authorities: Vec<Vec<u8>>,
    /// RFC 5077: the session this connection may resume -- the ticket plzn's
    /// server issued on an earlier connection of the same test and that
    /// session's master secret (the runner carries it between `session`
    /// blocks). A presented ticket is accepted only when it is exactly this one.
    pub resumption: Option<crate::ir::SessionState>,
    /// Deliberately claim an incompatible session was resumed. Used only by
    /// cross-version client-rejection tests.
    pub force_resumption: bool,
    /// RFC 5077 3.2: answer a client's SessionTicket extension with the empty
    /// SessionTicket extension and issue (or renew) a ticket before our
    /// ChangeCipherSpec. Set for the session a later one resumes and for
    /// the `session_ticket` capability; a ServerHello `+ext` / `-ext session_ticket`
    /// delta overrides the promise either way.
    pub issue_tickets: bool,
    /// Negotiate RawPublicKey in either authentication direction when offered.
    pub offer_raw_public_key: bool,
}

/// Prefix of the tickets plzn's TLS 1.2 server issues; the bytes after it are
/// the EMS flag (RFC 7627 5.3 needs it on resumption) and the suite (RFC 5246
/// 7.4.1.2: a resumed session keeps its suite), then random filler.
pub const TICKET12_MAGIC: &[u8] = b"PZ12";

/// What a presented ticket means for this connection (RFC 5077 3.3, RFC 7627
/// 5.3, RFC 5246 7.4.1.2). Pure, so the rules are unit-testable without a
/// peer: `presented` is the ClientHello's SessionTicket extension body,
/// `known` the ticket plzn's server issued earlier and its master secret,
/// `client_ems` whether the new ClientHello offers extended_master_secret and
/// `offered` the client's cipher suites.
pub fn decide_resumption(
    presented: Option<&[u8]>,
    known: Option<&crate::ir::SessionState>,
    client_ems: bool,
    offered: &[u16],
) -> Result<Option<(u16, Vec<u8>)>, TlsError> {
    let (Some(ticket), Some(ss)) = (presented, known) else {
        return Ok(None);
    };
    if ticket.is_empty() || ticket != ss.ticket.as_slice() {
        // Unknown, corrupt or empty ticket: fall back to a full handshake
        // (RFC 5077 3.2 "If the server fails to verify the ticket, then it
        // falls back to performing a full handshake").
        return Ok(None);
    }
    let Some((ems, suite)) = ticket_fields(ticket) else {
        return Ok(None);
    };
    // RFC 7627 5.3: "If the original session used the "extended_master_secret"
    // extension but the new ClientHello does not contain it, the server MUST
    // abort the abbreviated handshake."
    if ems && !client_ems {
        return Err(TlsError::Internal(
            "RFC 7627 5.3: the session used extended_master_secret but the resuming ClientHello does not offer it",
        ));
    }
    // "If the original session did not use the "extended_master_secret"
    // extension but the new ClientHello contains the extension, then the server
    // MUST NOT perform the abbreviated handshake."
    if !ems && client_ems {
        return Ok(None);
    }
    // RFC 5246 7.4.1.2: the resumed session keeps its cipher suite; a client
    // that no longer offers it cannot be resumed.
    if !offered.contains(&suite) {
        return Ok(None);
    }
    Ok(Some((suite, ss.master_secret.clone())))
}

/// `(ems, suite)` from a ticket plzn's server issued, `None` for foreign bytes.
pub fn ticket_fields(ticket: &[u8]) -> Option<(bool, u16)> {
    if !ticket.starts_with(TICKET12_MAGIC) || ticket.len() < TICKET12_MAGIC.len() + 3 {
        return None;
    }
    let m = TICKET12_MAGIC.len();
    Some((
        ticket[m] == 1,
        u16::from_be_bytes([ticket[m + 1], ticket[m + 2]]),
    ))
}

pub struct Tls12Server {
    cfg: Tls12ServerConfig,
    records: RecordLayer,
    transcript: TranscriptHash,
    private_key: PrivateKey,
    /// A: the parsed keys of `cfg.chains` (empty unless several chains).
    chain_keys: Vec<PrivateKey>,

    server_random: [u8; 32],
    client_random: [u8; 32],
    negotiated_suite: u16,
    use_ems: bool,
    master_secret: Vec<u8>,
    ephemeral: Option<EcdhePrivate>,
    /// The client's supported_groups and signature_algorithms (RFC 5246
    /// 7.4.1.4.1 / RFC 8422 5.1), captured from the ClientHello for the
    /// ServerKeyExchange group and signature-scheme selection.
    client_groups: Vec<u16>,
    client_sigalgs: Vec<u16>,
    /// The ECDHE group selected for this handshake (ECDHE_* and ECDHE_PSK).
    ecdhe_group: EcdheGroup,
    /// The client's leaf public key from its Certificate (client auth), used to
    /// verify the CertificateVerify.
    client_pubkey: Option<PublicKey>,
    received_empty_certificate: bool,
    client_accepts_server_rpk: bool,
    client_offers_client_rpk: bool,
    negotiated_server_cert_type: u8,
    negotiated_client_cert_type: u8,
    /// The DHE server half (`DHE_RSA_*` suites), generated at ServerKeyExchange.
    dhe: Option<crate::tls::kex12::DheServer>,
    /// ClientHello.client_version, stamped into the static-RSA premaster
    /// (RFC 5246 7.4.7.1).
    client_version: u16,
    client_session_id: Vec<u8>,

    /// Stashed key material from recv_client_key_exchange.
    pending_read_keys: Option<DirectionKeys>,
    pending_write_keys: Option<DirectionKeys>,
    /// When the premaster secret is one of several (a small-order explicit
    /// dh_Ys): each candidate's client write keys, armed at the client's CCS,
    /// and its master secret and server write keys, kept until the client's
    /// first protected record picks one (`settle_premaster`).
    pending_read_key_candidates: Option<Vec<DirectionKeys>>,
    premaster_candidates: Option<Vec<(Vec<u8>, DirectionKeys)>>,
    /// Every handshake message so far, verbatim, so the transcript can be
    /// restarted under the suite's hash once the suite is chosen.
    raw_transcript: Vec<u8>,
    /// RFC 7366: client offered encrypt_then_mac and a CBC suite was selected.
    use_etm: bool,
    /// RFC 5746: the client offered renegotiation_info or its signaling suite.
    client_supports_secure_renegotiation: bool,

    pre_client_finished_digest: Vec<u8>,

    /// True while running a renegotiation (a second handshake on the live
    /// connection). Drives a non-empty renegotiation_info extension (RFC 5746).
    renegotiating: bool,
    /// The client/server Finished verify_data from the *previous* handshake,
    /// bound into the renegotiation_info of the renegotiation ServerHello /
    /// verified against the client's ClientHello (RFC 5746 3.7).
    last_client_verify_data: Vec<u8>,
    last_server_verify_data: Vec<u8>,
    /// Both Finished messages of the current handshake have been exchanged; a
    /// further ClientHello is then a client-initiated renegotiation
    /// (RFC 5246 7.4.1.2). Cleared by `begin_renegotiation`.
    finished_sent: bool,
    finished_received: bool,
    /// RFC 5077: this handshake resumes the session in `cfg.resumption`.
    resumed: bool,
    /// The ClientHello's SessionTicket extension body (empty = "send me one").
    client_ticket: Option<Vec<u8>>,
    /// The ServerHello carried the SessionTicket extension, so a
    /// NewSessionTicket MUST follow before our ChangeCipherSpec (RFC 5077 3.3).
    promised_ticket: bool,
    ticket_sent: bool,
    /// The last ticket issued and the master secret it stands for (what
    /// `session_state` hands to a resuming session).
    issued_ticket: Option<(Vec<u8>, Vec<u8>)>,
    tickets_issued: u32,
    captures: Vec<(String, Vec<u8>)>,
}

impl Tls12Server {
    pub fn new(transport: Box<dyn UutTransport>, cfg: Tls12ServerConfig) -> Self {
        let version = cfg.version;
        let chain_keys =
            crate::tls::chains::parse_chain_keys(&cfg.chains).expect("valid chain keys");
        let private_key = chain_keys.first().cloned().unwrap_or_else(|| {
            PrivateKey::from_pkcs8_der(&cfg.private_key_der).expect("valid private key PKCS#8 DER")
        });
        Self {
            cfg,
            records: RecordLayer::new(transport, version),
            transcript: TranscriptHash::new(HashAlg::Sha256),
            private_key,
            chain_keys,
            server_random: [0; 32],
            client_random: [0; 32],
            negotiated_suite: 0,
            use_ems: false,
            master_secret: Vec::new(),
            ephemeral: None,
            client_groups: Vec::new(),
            client_sigalgs: Vec::new(),
            ecdhe_group: EcdheGroup::P256,
            client_pubkey: None,
            received_empty_certificate: false,
            client_accepts_server_rpk: false,
            client_offers_client_rpk: false,
            negotiated_server_cert_type: crate::tls::codec::CERT_TYPE_X509,
            negotiated_client_cert_type: crate::tls::codec::CERT_TYPE_X509,
            dhe: None,
            client_version: version.wire_value(),
            client_session_id: Vec::new(),
            pending_read_keys: None,
            pending_write_keys: None,
            pending_read_key_candidates: None,
            premaster_candidates: None,
            raw_transcript: Vec::new(),
            use_etm: false,
            client_supports_secure_renegotiation: false,
            pre_client_finished_digest: Vec::new(),
            resumed: false,
            client_ticket: None,
            promised_ticket: false,
            ticket_sent: false,
            issued_ticket: None,
            tickets_issued: 0,
            captures: Vec::new(),
            renegotiating: false,
            last_client_verify_data: Vec::new(),
            last_server_verify_data: Vec::new(),
            finished_sent: false,
            finished_received: false,
        }
    }

    fn ensure_init(&mut self) {
        if self.server_random != [0; 32] {
            return;
        }
        let mut sr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"server_random"));
        self.server_random = sr_rng.random_array();
        // The ECDHE ephemeral is generated at ServerKeyExchange time, once the
        // group is selected from the client's supported_groups.
    }

    pub fn do_handshake(&mut self) -> Result<(), TlsError> {
        self.ensure_init();
        self.recv_client_hello()?;
        self.send_server_hello()?;
        if self.resumed {
            // RFC 5077 3.1 figure 2: the abbreviated handshake -- the server's
            // [NewSessionTicket], CCS and Finished come first.
            self.send_change_cipher_spec()?;
            self.send_finished()?;
            self.recv_change_cipher_spec()?;
            self.recv_finished_msg()?;
            return Ok(());
        }
        // PSK families carry no Certificate (RFC 4279 2); every other family
        // does. ServerKeyExchange is a per-family no-op where it does not apply.
        if !self.kex().is_psk() {
            self.send_certificate()?;
        }
        self.send_server_key_exchange()?;
        self.send_server_hello_done()?;
        self.recv_client_key_exchange()?;
        self.recv_change_cipher_spec()?;
        self.recv_finished_msg()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        Ok(())
    }

    pub fn do_handshake_step(&mut self, step: &HandshakeStep) -> Result<(), TlsError> {
        use HandshakeStep as HS;
        use MessageKind as MK;
        self.ensure_init();
        match step {
            HS::Recv(MK::ClientHello) => {
                // A ClientHello after a completed handshake is a client-initiated
                // renegotiation (RFC 5246 7.4.1.2): the second handshake runs under
                // the current keys with the RFC 5746 3.7 binding.
                if self.finished_sent && self.finished_received {
                    self.begin_renegotiation();
                }
                self.recv_client_hello()
            }
            HS::Send(MK::ServerHello) => self.send_server_hello(),
            HS::Send(MK::Certificate) => self.send_certificate(),
            HS::Send(MK::CertificateStatus) => self.send_certificate_status(),
            HS::Send(MK::ServerKeyExchange) => self.send_server_key_exchange(),
            HS::Send(MK::ServerHelloDone) => self.send_server_hello_done(),
            HS::Send(MK::CertificateRequest) => self.send_certificate_request(),
            HS::Recv(MK::Certificate) => self.recv_client_certificate(),
            HS::Recv(MK::CertificateVerify) => self.recv_client_certificate_verify(),
            HS::Recv(MK::ClientKeyExchange) => self.recv_client_key_exchange(),
            HS::Recv(MK::ChangeCipherSpec) => self.recv_change_cipher_spec(),
            HS::Recv(MK::Finished) => self.recv_finished_msg(),
            HS::Send(MK::ChangeCipherSpec) => self.send_change_cipher_spec(),
            HS::Send(MK::Finished) => self.send_finished(),
            HS::Send(MK::NewSessionTicket) => self.send_new_session_ticket(),
            HS::Send(MK::HelloRequest) => self.send_hello_request(),
            // T6: a heartbeat record (RFC 6520) under the current write keys.
            HS::Send(MK::Heartbeat) => {
                let (body, muts) = crate::tls::driver::t6_heartbeat_record_body(
                    &self.cfg.send_overrides,
                    &self.cfg.send_mutations,
                )?;
                self.records
                    .write_record_with_mutations(
                        crate::tls::codec::CONTENT_TYPE_HEARTBEAT,
                        &body,
                        &muts,
                    )
                    .map_err(TlsError::from)
            }
            _ => Err(TlsError::Internal(
                "unsupported handshake step for TLS 1.2 server",
            )),
        }
    }

    /// Reset the per-handshake state for a renegotiation (a second handshake on
    /// the live connection). The installed record keys are RETAINED -- the
    /// renegotiation handshake runs encrypted under the current keys and only
    /// transitions to the new keys at the new ChangeCipherSpec (RFC 5246 7.4.1.1).
    /// The previous handshake's Finished verify_data is kept for the RFC 5746
    /// renegotiation_info binding.
    fn begin_renegotiation(&mut self) {
        self.renegotiating = true;
        self.records.begin_renegotiation();
        self.transcript = TranscriptHash::new(HashAlg::Sha256);
        // A fresh server_random / ephemeral, distinct from the initial handshake.
        // ensure_init short-circuits once server_random is non-zero, so set them here.
        let mut sr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"server_random_reneg"));
        self.server_random = sr_rng.random_array();
        self.ephemeral = None;
        self.client_groups.clear();
        self.client_sigalgs.clear();
        self.client_pubkey = None;
        self.received_empty_certificate = false;
        self.client_random = [0; 32];
        self.client_session_id.clear();
        self.negotiated_suite = 0;
        self.dhe = None;
        self.use_ems = false;
        self.master_secret.clear();
        self.pending_read_keys = None;
        self.pending_write_keys = None;
        self.pending_read_key_candidates = None;
        self.premaster_candidates = None;
        self.raw_transcript.clear();
        self.use_etm = false;
        self.pre_client_finished_digest.clear();
        self.resumed = false;
        self.client_ticket = None;
        self.promised_ticket = false;
        self.ticket_sent = false;
        self.finished_sent = false;
        self.finished_received = false;
    }

    /// Drive a server-initiated renegotiation: send a HelloRequest, then run the
    /// server side of a second handshake (RFC 5246 7.4.1.1). The HelloRequest goes
    /// out encrypted under the current keys and is excluded from the transcript.
    pub fn renegotiate(&mut self) -> Result<(), TlsError> {
        self.ensure_init();
        self.send_hello_request()?;
        self.begin_renegotiation();
        self.do_handshake()
    }

    /// Send a HelloRequest (RFC 5246 7.4.1.1: "struct { } HelloRequest;"). It is
    /// "not included in the message hashes", so it never touches the transcript.
    fn send_hello_request(&mut self) -> Result<(), TlsError> {
        // The body is empty, but `send HelloRequest @ pad +1` must still
        // produce a non-empty body under a matching header (RFC 5246 7.4.1.1
        // has no room for one, so the peer must decode_error), so run the
        // body and header mutation stages like every other message.
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::HelloRequest).to_vec();
        let encoded = crate::tls::codec::EncodedBody {
            bytes: Vec::new(),
            fields: std::collections::HashMap::new(),
        };
        let body = crate::tls::mutate::apply_handshake_mutations(Vec::new(), &encoded, &muts)
            .map_err(|_| TlsError::Internal("server HelloRequest mutation failed"))?;
        let mut framed = encode_handshake(HS_HELLO_REQUEST, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, &muts);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, &muts)?;
        Ok(())
    }

    pub fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        if mutations.is_empty() {
            self.records.write_app_data(data)?;
        } else {
            use crate::tls::codec::CONTENT_TYPE_APP_DATA;
            self.records
                .write_record_with_mutations(CONTENT_TYPE_APP_DATA, data, mutations)?;
        }
        Ok(())
    }

    pub fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        match self.records.read_app_data() {
            Ok(data) => Ok(data),
            // RFC 5246 7.4.1.2: "the client can request a renegotiation by
            // sending a new ClientHello" at any time after the handshake. Accept
            // it: run the server side of the second handshake under the current
            // keys (RFC 5746 3.7 binds it to the previous Finished values), then
            // keep waiting for the application data the caller asked for.
            Err(RecordError::UnexpectedContentType { .. })
                if self.records.buffered_client_hello()
                    && self.finished_sent
                    && self.finished_received =>
            {
                self.begin_renegotiation();
                self.do_handshake()?;
                self.read_app_data()
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn close(&mut self) -> Result<(), TlsError> {
        self.records
            .close()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }

    pub fn negotiated_cipher_suite(&self) -> u16 {
        self.negotiated_suite
    }

    // ---- per-message methods ----

    fn absorb(&mut self, framed: &[u8]) {
        self.transcript.update(framed);
        self.raw_transcript.extend_from_slice(framed);
    }

    /// The negotiated suite's PRF / handshake hash.
    fn prf_hash(&self) -> HashAlg {
        crate::ir::suite_info(self.negotiated_suite)
            .map(|s| s.prf)
            .unwrap_or(HashAlg::Sha256)
    }

    fn handshake_digest(&self) -> Vec<u8> {
        if matches!(self.cfg.version, TlsVersion::Tls10 | TlsVersion::Tls11) {
            crate::tls::crypto::tls10_transcript_digest(&self.raw_transcript)
        } else {
            self.transcript.digest()
        }
    }

    /// A: switch to chain `idx`: the ServerKeyExchange signs with its key and
    /// the Certificate carries its leaf.
    fn select_chain(&mut self, idx: usize) -> Result<(), TlsError> {
        let chain = self.cfg.chains[idx].clone();
        self.private_key = self.chain_keys[idx].clone();
        self.cfg.cert_der = chain.cert_der;
        self.cfg.private_key_der = chain.key_der;
        Ok(())
    }

    fn recv_client_hello(&mut self) -> Result<(), TlsError> {
        let ch_body = self.read_handshake(HS_CLIENT_HELLO)?;
        let ch = decode_client_hello_body(&ch_body)?;
        // Enforce any `recv ClientHello { field: ... }` matchers
        // against what the UUT client actually sent.
        for matcher in &self.cfg.recv_matchers {
            if matcher.message == MessageKind::ClientHello {
                for f in &matcher.fields {
                    if let FieldValue::Capture(name) = &f.value {
                        let value = crate::tls::driver::capture_client_hello_field(&ch, &f.field)?;
                        self.captures.push((name.clone(), value));
                        continue;
                    }
                    match_client_hello_field(&ch, f)?;
                }
            }
        }
        self.client_random = ch.random;
        self.client_version = ch.legacy_version;
        self.client_session_id = ch.session_id;

        // RFC 5077: a SessionTicket extension either presents a ticket or
        // (empty) asks for one. Resume only the session the runner handed us
        // (the ticket we issued on the earlier connection), and only under the
        // RFC 7627 5.3 / RFC 5246 7.4.1.2 rules.
        self.client_ticket = ch.extensions.iter().find_map(|e| match e {
            Extension::SessionTicket(t) => Some(t.clone()),
            _ => None,
        });
        let client_ems = ch
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::ExtendedMasterSecret));
        self.resumed = false;
        let force_resumption = self.cfg.force_resumption
            && self.cfg.resumption.as_ref().is_some_and(|state| {
                !state.is_compatible_with(crate::ir::Protocol::Tls, self.cfg.version)
            });
        if !self.renegotiating {
            if let Some((suite, ms)) = decide_resumption(
                self.client_ticket.as_deref(),
                self.cfg.resumption.as_ref(),
                client_ems,
                &ch.cipher_suites,
            )? {
                self.resumed = true;
                self.negotiated_suite = suite;
                self.master_secret = ms;
            }
        }
        // Promise a (renewal) ticket when the client offered the extension and
        // this session issues tickets; the ServerHello deltas get the last word.
        self.promised_ticket = self.client_ticket.is_some() && self.cfg.issue_tickets;
        self.ticket_sent = false;

        // Pick the first offered suite we support. We hold a single certificate,
        // so only the key-exchange/authentication family matching that key type is
        // usable: an RSA key can serve ECDHE_RSA, an ECDSA key ECDHE_ECDSA.
        // Offering the wrong family would negotiate a suite our cert can't sign.
        // Of the suites the test allows (peer capabilities; else everything we
        // implement), keep the family our key can sign for.
        let allowed: Vec<u16> = if self.cfg.cipher_suites.is_empty() {
            crate::ir::filter_suites(self.cfg.version, &[])
        } else {
            self.cfg.cipher_suites.clone()
        };
        // T3: an id-RSASSA-PSS key signs the ECDHE_RSA / DHE_RSA suites (with
        // rsa_pss_pss_*) but cannot do the static-RSA key exchange.
        let rsa_kex = self.private_key.is_rsa();
        let rsa = rsa_kex || self.private_key.is_rsa_pss();
        let have_psk = self.cfg.psk.is_some();
        // An RSA key serves the ECDHE_RSA, DHE_RSA and static-RSA suites, an
        // ECDSA or EdDSA key the ECDHE_ECDSA ones (RFC 8422 5.1.3 puts EdDSA
        // under the ECDSA suites); a configured PSK serves the PSK families
        // (`kex12` holds the RSA / DHE / PSK halves).
        let supported: Vec<u16> = allowed
            .into_iter()
            .filter(|w| match crate::ir::suite_info(*w).map(|s| s.kex) {
                Some(crate::ir::KexType::EcdheRsa | crate::ir::KexType::DheRsa) => rsa,
                Some(crate::ir::KexType::Rsa) => rsa_kex,
                Some(crate::ir::KexType::EcdheEcdsa) => !rsa,
                Some(crate::ir::KexType::Psk | crate::ir::KexType::EcdhePsk) => have_psk,
                _ => false,
            })
            .collect();
        // What the client can do, for the ServerKeyExchange choices below.
        self.client_groups = ch
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::SupportedGroups(g) => Some(g.clone()),
                _ => None,
            })
            .unwrap_or_default();
        self.client_sigalgs = ch
            .extensions
            .iter()
            .find_map(|e| match e {
                Extension::SignatureAlgorithms(a) => Some(a.clone()),
                _ => None,
            })
            .unwrap_or_default();
        self.client_accepts_server_rpk = ch.extensions.iter().any(|ext| match ext {
            Extension::Unknown { ty, data }
                if *ty == crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE =>
            {
                crate::tls::codec::decode_cert_type_list(data)
                    .is_ok_and(|types| types.contains(&crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY))
            }
            _ => false,
        });
        self.client_offers_client_rpk = ch.extensions.iter().any(|ext| match ext {
            Extension::Unknown { ty, data }
                if *ty == crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE =>
            {
                crate::tls::codec::decode_cert_type_list(data)
                    .is_ok_and(|types| types.contains(&crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY))
            }
            _ => false,
        });
        // A: several chains -- the suite and the chain are picked together: the
        // client's suite order, then the configured chain order, the first chain
        // that can serve the suite's family and (for a signed key exchange) sign
        // with a scheme the client listed. Nothing fitting falls through to the
        // single-chain path, which fails as it always did.
        let mut picked = false;
        if !self.resumed && self.chain_keys.len() > 1 {
            let allowed_all: Vec<u16> = if self.cfg.cipher_suites.is_empty() {
                crate::ir::filter_suites(self.cfg.version, &[])
            } else {
                self.cfg.cipher_suites.clone()
            };
            let pick = ch.cipher_suites.iter().find_map(|w| {
                if !allowed_all.contains(w) {
                    return None;
                }
                let kex = crate::ir::suite_info(*w)?.kex;
                crate::tls::chains::select_server_chain_12(
                    &self.chain_keys,
                    kex,
                    have_psk,
                    &self.client_sigalgs,
                    &self.cfg.signature_schemes,
                )
                .map(|i| (*w, i))
            });
            if let Some((suite, idx)) = pick {
                self.select_chain(idx)?;
                self.negotiated_suite = suite;
                picked = true;
            }
        }
        if !self.resumed && !picked {
            self.negotiated_suite = *ch
                .cipher_suites
                .iter()
                .find(|s| supported.contains(s))
                .ok_or(TlsError::Internal(
                    "client offered no supported cipher suite",
                ))?;
        }
        if force_resumption && !self.resumed {
            self.resumed = true;
            let prior = self
                .cfg
                .resumption
                .as_ref()
                .expect("force_resumption checked above");
            self.master_secret = prior.master_secret.clone();
            // Claim the prior session verbatim. In particular, use the TLS 1.3
            // compatibility session id learned with that state rather than
            // merely reflecting whatever the new TLS 1.2 ClientHello used.
            if !prior.session_id.is_empty() {
                self.client_session_id = prior.session_id.clone();
            }
        }
        // The ECDHE group: the server's capability set against the client's
        // supported_groups, server order (RFC 8422 5.1: the server MUST use the
        // client's enumerated capabilities). A resumed session exchanges no keys.
        if !self.resumed
            && matches!(
                self.kex(),
                crate::ir::KexType::EcdheRsa
                    | crate::ir::KexType::EcdheEcdsa
                    | crate::ir::KexType::EcdhePsk
            )
        {
            let wire = select_ecdhe_group(&self.cfg.groups, &self.client_groups).ok_or(
                TlsError::SelectionUnsatisfiable {
                    reason: format!(
                        "no ECDHE group in common: server offers {:?}, client offered {:?}",
                        if self.cfg.groups.is_empty() {
                            crate::tls::kex12::DEFAULT_SERVER_ECDHE_GROUPS.to_vec()
                        } else {
                            self.cfg.groups.clone()
                        },
                        self.client_groups
                    ),
                },
            )?;
            self.ecdhe_group = EcdheGroup::from_wire(wire).unwrap_or(EcdheGroup::P256);
        }
        // Restart the transcript under the suite's hash if it is not SHA-256
        // (RFC 5289 *_SHA384 suites); the ClientHello is already in it.
        let prf = self.prf_hash();
        if prf != self.transcript.alg() {
            let mut rebuilt = TranscriptHash::new(prf);
            rebuilt.update(&self.raw_transcript);
            self.transcript = rebuilt;
        }

        // Check if client offered EMS.
        self.use_ems = ch
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::ExtendedMasterSecret));
        // RFC 7366 2: echo encrypt_then_mac only when the client offered it AND
        // the selected suite is a block cipher; with an AEAD suite the server
        // MUST NOT send it. A test overrides either way with a ServerHello
        // extension delta (`+ext encrypt_then_mac` / `-ext encrypt_then_mac`).
        let client_etm = ch
            .extensions
            .iter()
            .any(|e| e.wire_type() == EXT_ENCRYPT_THEN_MAC);
        self.use_etm = client_etm && self.suite_is_cbc();
        self.client_supports_secure_renegotiation = ch.cipher_suites.contains(&0x00ff)
            || ch
                .extensions
                .iter()
                .any(|e| matches!(e, Extension::RenegotiationInfo(_)));

        if self.renegotiating {
            let ri = ch.extensions.iter().find_map(|e| match e {
                Extension::RenegotiationInfo(d) => Some(d.as_slice()),
                _ => None,
            });
            // RFC 5746 3.7: "The server MUST verify that the "renegotiation_info"
            // extension is present; if it is not, the server MUST abort the
            // handshake."
            //
            // "The server MUST verify that the value of the
            // "renegotiated_connection" field is equal to the saved
            // client_verify_data value; if it is not, the server MUST abort the
            // handshake."
            if ri != Some(self.last_client_verify_data.as_slice()) {
                return Err(TlsError::Internal(
                    "renegotiation_info mismatch on renegotiation ClientHello",
                ));
            }
        }
        Ok(())
    }

    fn send_server_hello(&mut self) -> Result<(), TlsError> {
        use crate::ir::MessageKind;
        use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
        // RFC 5746 3.7: on a renegotiation the server binds the extension by
        // sending "the saved client_verify_data and server_verify_data"; an empty
        // value is the initial-handshake signal.
        let mut ri = self.last_client_verify_data.clone();
        ri.extend_from_slice(&self.last_server_verify_data);
        let mut extensions = Vec::new();
        // RFC 5746 3.6: only signal secure renegotiation when the client did.
        // Explicit extension deltas below can still override this default.
        if self.client_supports_secure_renegotiation {
            extensions.push(Extension::RenegotiationInfo(ri));
        }
        if self.use_ems {
            extensions.push(Extension::ExtendedMasterSecret);
        }
        if self.use_etm {
            extensions.push(Extension::Unknown {
                ty: EXT_ENCRYPT_THEN_MAC,
                data: Vec::new(),
            });
        }
        // RFC 5077 3.2: the empty SessionTicket extension promises a
        // NewSessionTicket; "The server MUST NOT send this extension if it
        // does not receive one in the ClientHello."
        if self.promised_ticket {
            extensions.push(Extension::SessionTicket(Vec::new()));
        }
        if self.cfg.offer_raw_public_key && self.client_accepts_server_rpk {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE,
                data: vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY],
            });
        }
        if self.cfg.offer_raw_public_key && self.client_offers_client_rpk {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE,
                data: vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY],
            });
        }
        let ext_deltas = collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ServerHello);
        apply_ext_deltas(&mut extensions, ext_deltas);
        // The deltas have the last word on what this ServerHello promises and
        // negotiates: `-ext extended_master_secret` really drops to the legacy
        // master secret, `+ext session_ticket` / `-ext session_ticket` force or
        // withhold the ticket promise (the RFC 5077 3.3 negatives).
        self.use_ems = extensions
            .iter()
            .any(|e| matches!(e, Extension::ExtendedMasterSecret));
        self.promised_ticket = extensions
            .iter()
            .any(|e| matches!(e, Extension::SessionTicket(_)));
        let mut sh = ServerHelloBuilder {
            legacy_version: self.cfg.version.wire_value(),
            random: self.server_random,
            // RFC 5246 7.4.1.3: the server echoes the client's session_id only
            // when resuming that session (RFC 5077 3.4: with an accepted ticket
            // and a non-empty id the server MUST echo it). Otherwise send an
            // empty id: echoing a TLS 1.3 client's compatibility session_id in
            // a TLS 1.2 ServerHello made Botan and rustls reject the downgrade
            // as a bogus resumption.
            session_id: if self.resumed {
                self.client_session_id.clone()
            } else {
                Vec::new()
            },
            cipher_suite: self.negotiated_suite,
            compression_method: 0,
            extensions,
        };
        for ov in &self.cfg.send_overrides {
            if ov.message == MessageKind::ServerHello {
                for f in &ov.fields {
                    apply_server_hello_override(&mut sh, f)?;
                }
            }
        }
        // A raw `extensions` field override is applied after extension deltas.
        // Derive negotiated state from the bytes we will actually send, just as
        // we do after the deltas above. In particular, an extensionless
        // ServerHello must also disable EMS locally or the Finished keys differ.
        self.use_ems = sh
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::ExtendedMasterSecret));
        self.promised_ticket = sh
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::SessionTicket(_)));
        self.negotiated_server_cert_type = sh
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE =>
                {
                    crate::tls::codec::decode_cert_type_selection(data).ok()
                }
                _ => None,
            })
            .unwrap_or(crate::tls::codec::CERT_TYPE_X509);
        self.negotiated_client_cert_type = sh
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE =>
                {
                    crate::tls::codec::decode_cert_type_selection(data).ok()
                }
                _ => None,
            })
            .unwrap_or(crate::tls::codec::CERT_TYPE_X509);
        let encoded = crate::tls::codec::encode_server_hello_body_mapped(&sh);
        let sh_muts =
            collect_mutations(&self.cfg.send_mutations, MessageKind::ServerHello).to_vec();
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            &sh_muts,
        )
        .map_err(|_| TlsError::Internal("server ServerHello mutation failed"))?;
        let mut framed = encode_handshake(HS_SERVER_HELLO, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, &sh_muts);
        self.absorb(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, &sh_muts)?;
        if self.resumed {
            // The abbreviated handshake exchanges no keys: derive both
            // directions from the resumed master secret and the new randoms
            // now (RFC 5246 7.3), installed at the respective CCS.
            let suite = crate::ir::suite_info(self.negotiated_suite)
                .ok_or(TlsError::Internal("resumed suite not in the catalogue"))?;
            let (client_keys, server_keys) = crate::tls::handshake::legacy_direction_keys(
                self.cfg.version,
                suite,
                &self.master_secret,
                &self.server_random,
                &self.client_random,
                self.use_etm,
            )?;
            self.pending_read_keys = Some(client_keys);
            self.pending_write_keys = Some(server_keys);
        }
        Ok(())
    }

    /// Issue a NewSessionTicket (RFC 5077 3.3). The ticket is opaque to the
    /// client: a magic prefix, the EMS flag and suite the resumption rules need,
    /// and random filler; the runner carries it (with the master secret) to the
    /// session that resumes. `send NewSessionTicket { ticket_lifetime |
    /// ticket_lifetime_days | ticket }` override the fields (`ticket: ""` is the
    /// RFC 5077 3.3 zero-length "no ticket after all"); `@` mutations apply.
    fn send_new_session_ticket(&mut self) -> Result<(), TlsError> {
        use crate::tls::codec::{HS_NEW_SESSION_TICKET, encode_new_session_ticket_body_mapped};
        let counter = self.tickets_issued;
        self.tickets_issued += 1;
        let mut rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"session_ticket_12"));
        let mut ticket = TICKET12_MAGIC.to_vec();
        ticket.push(if self.use_ems { 1 } else { 0 });
        ticket.extend_from_slice(&self.negotiated_suite.to_be_bytes());
        let mut filler: [u8; 32] = rng.random_array();
        filler[0] ^= counter as u8; // distinct renewals
        ticket.extend_from_slice(&filler);
        let mut lifetime: u32 = 7200;
        for ov in &self.cfg.send_overrides {
            if ov.message != MessageKind::NewSessionTicket {
                continue;
            }
            for f in &ov.fields {
                match (f.field.as_str(), &f.value) {
                    ("ticket_lifetime", FieldValue::U16(v)) => lifetime = *v as u32,
                    ("ticket_lifetime_days", FieldValue::U16(v)) => {
                        lifetime = (*v as u32).saturating_mul(86_400)
                    }
                    ("ticket", FieldValue::Bytes(v)) => ticket = v.clone(),
                    _ => {
                        return Err(TlsError::UnknownFieldOverride {
                            message: "NewSessionTicket",
                            field: f.field.clone(),
                        });
                    }
                }
            }
        }
        let encoded = encode_new_session_ticket_body_mapped(lifetime, &ticket);
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::NewSessionTicket);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
                .map_err(|_| TlsError::Internal("NewSessionTicket mutation failed"))?;
        let mut framed = encode_handshake(HS_NEW_SESSION_TICKET, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, muts);
        // RFC 5077 3.3: "This message is included in the hash used to create and
        // verify the Finished message."
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::NewSessionTicket),
        )?;
        self.ticket_sent = true;
        if !ticket.is_empty() {
            self.issued_ticket = Some((ticket, self.master_secret.clone()));
        }
        Ok(())
    }

    fn send_certificate(&mut self) -> Result<(), TlsError> {
        // Overrides: `entries: N` sends the certificate N times (0 = an empty
        // certificate_list, which a client MUST reject for a certificate-
        // authenticated suite); `certificate_list: <bytes>` replaces the list
        // contents outright.
        let cert_overrides = collect_overrides(&self.cfg.send_overrides, MessageKind::Certificate);
        let wire_certificate_type = cert_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("certificate_type", crate::ir::FieldValue::Ident(name)) => {
                    Some(match name.as_str() {
                        "x509" => crate::tls::codec::CERT_TYPE_X509,
                        "raw_public_key" => crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                        _ => unreachable!("certificate_type was validated while lowering"),
                    })
                }
                _ => None,
            })
            .unwrap_or(self.negotiated_server_cert_type);
        let rpk_leaf = if wire_certificate_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
            Some(crate::tls::crypto::certificate_spki_der(
                &self.cfg.cert_der,
            )?)
        } else {
            None
        };
        let leaf = rpk_leaf.as_deref().unwrap_or(&self.cfg.cert_der);
        let mut entries: Vec<&[u8]> = vec![leaf];
        let mut raw_list: Option<Vec<u8>> = None;
        for ov in cert_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("entries", crate::ir::FieldValue::U16(n)) => {
                    entries = std::iter::repeat_n(leaf, *n as usize).collect();
                }
                ("certificate_list", crate::ir::FieldValue::Bytes(b)) => raw_list = Some(b.clone()),
                ("certificate_type", crate::ir::FieldValue::Ident(_)) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "Certificate",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let encoded = match raw_list {
            Some(list) => {
                let mut out = Vec::with_capacity(3 + list.len());
                out.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
                out.extend_from_slice(&list);
                let mut fields = std::collections::HashMap::new();
                fields.insert("certificate_list_length".to_string(), 0..3);
                fields.insert("certificate_list".to_string(), 3..out.len());
                crate::tls::codec::EncodedBody { bytes: out, fields }
            }
            None if wire_certificate_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY => {
                crate::tls::codec::encode_raw_public_key_certificate_12_body_mapped(
                    entries.first().copied().unwrap_or(&[]),
                )
            }
            None => encode_certificate_12_body_mapped(&entries),
        };
        // Apply body then header mutations (e.g. `@ set[handshake.msg_type, 0]` to
        // relabel the message, so a client that mis-parses a wrong-typed message is
        // caught -- the client-side wrong-message-type family). The list contents
        // are the `certificate_list` mutation target.
        let cert_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate);
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            cert_muts,
        )
        .map_err(|_| TlsError::Internal("server Certificate mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, cert_muts);
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate),
        )?;
        Ok(())
    }

    /// Send an RFC 6066 CertificateStatus with a freshly generated successful
    /// OCSP response for the certificate selected for this connection.
    fn send_certificate_status(&mut self) -> Result<(), TlsError> {
        let mut status_type = crate::tls::codec::CERT_STATUS_TYPE_OCSP;
        let mut response =
            crate::server::ocsp::good_response_now(&self.cfg.cert_der, &self.cfg.private_key_der)
                .map_err(|_| TlsError::Internal("generate OCSP response"))?;
        for field in collect_overrides(&self.cfg.send_overrides, MessageKind::CertificateStatus) {
            match (field.field.as_str(), &field.value) {
                ("status_type", FieldValue::Ident(value)) if value == "ocsp" => {
                    status_type = crate::tls::codec::CERT_STATUS_TYPE_OCSP;
                }
                ("response", FieldValue::Bytes(value)) => response = value.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateStatus",
                        field: field.field.clone(),
                    });
                }
            }
        }
        let encoded = encode_certificate_status_body_mapped(status_type, &response);
        let muts =
            collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateStatus).to_vec();
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, &muts)
                .map_err(|_| TlsError::Internal("CertificateStatus mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_STATUS, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, &muts);
        self.absorb(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, &muts)?;
        Ok(())
    }

    /// The negotiated suite's key exchange (ECDHE before a suite is known).
    fn kex(&self) -> crate::ir::KexType {
        crate::ir::suite_info(self.negotiated_suite)
            .map(|s| s.kex)
            .unwrap_or(crate::ir::KexType::EcdheRsa)
    }

    fn send_server_key_exchange(&mut self) -> Result<(), TlsError> {
        match self.kex() {
            // RFC 5246 7.4.3: no ServerKeyExchange for the RSA key exchange; the
            // preset step is a no-op so one flow serves every family.
            crate::ir::KexType::Rsa => return Ok(()),
            crate::ir::KexType::DheRsa => return self.send_dhe_server_key_exchange(),
            // RFC 4279 2: an (optional) psk_identity_hint; plzn's server always
            // sends it so the client side of the hint path is exercised.
            crate::ir::KexType::Psk => return self.send_psk_hint_server_key_exchange(),
            // RFC 5489 3.2: the hint then unsigned ServerECDHParams.
            crate::ir::KexType::EcdhePsk => return self.send_ecdhe_psk_server_key_exchange(),
            _ => {}
        }
        use crate::ir::MessageKind;
        // Overrides: `named_group` forces the ECDHE group (one the client did not
        // offer is the negative; a value plzn cannot generate keeps the selected
        // group's point and only relabels the curve), `signature_scheme` forces
        // a known scheme (and signs with it), while an unknown/GREASE value
        // only relabels the signature made with the normally selected scheme.
        let mut wire_group = self.ecdhe_group.wire_value();
        let mut label_group = wire_group;
        let mut forced_scheme: Option<SignatureScheme> = None;
        let mut signature_label: Option<u16> = None;
        let mut tls12_wire = self.cfg.version >= TlsVersion::Tls12;
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::ServerKeyExchange) {
            match (ov.field.as_str(), &ov.value) {
                ("named_group", crate::ir::FieldValue::U16(g)) => {
                    label_group = *g;
                    if let Some(gr) = EcdheGroup::from_wire(*g) {
                        if !gr.is_ffdhe() && !gr.is_tls13_only() {
                            wire_group = *g;
                            self.ecdhe_group = gr;
                        }
                    }
                }
                ("signature_scheme", crate::ir::FieldValue::U16(w)) => {
                    signature_label = Some(*w);
                    if let Some(scheme) = SignatureScheme::from_wire_value(*w) {
                        if !self.private_key.signature_schemes().contains(&scheme) {
                            return Err(TlsError::Internal(
                                "signature_scheme: the server's key cannot sign with that scheme",
                            ));
                        }
                        forced_scheme = Some(scheme);
                    }
                }
                ("format", crate::ir::FieldValue::Ident(format)) => tls12_wire = format == "tls12",
                // Consumed below by the key_share_point recipe.
                ("key_share_point", _) => {}
                ("dh_p_bits", _) | ("psk_identity_hint", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let _ = wire_group;
        let ephemeral = self.ecdhe_ephemeral();
        // `send ServerKeyExchange { key_share_point: zero | truncated | padded |
        // compressed }` corrupts the WIRE point while the real ephemeral is kept
        // for the agreement, so the client sees a bad point it must reject
        // (RFC 8422 5.11); parity with plzn's DTLS server.
        let overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ServerKeyExchange).to_vec();
        let public_point = self.server_point_with_recipe(&ephemeral, &overrides)?;
        self.ephemeral = Some(ephemeral);

        // Build the params that get signed: ECParameters + ECPoint.
        let mut params = Vec::new();
        params.push(3u8); // curve_type = named_curve
        params.extend_from_slice(&label_group.to_be_bytes());
        params.push(public_point.len() as u8);
        params.extend_from_slice(&public_point);

        // Signed blob: client_random || server_random || params.
        let signed_bytes =
            crate::tls::kex12::ske_signed_input(&self.client_random, &self.server_random, &params);

        // The scheme: the client's signature_algorithms against what the key can
        // sign (and the capability pin), in the client's order; RFC 5246 7.4.1.4.1
        // makes a server without a usable pair fail the handshake.
        let sig_scheme = match forced_scheme {
            Some(s) => s,
            None if !tls12_wire => match self.private_key.kind() {
                crate::tls::crypto::KeyKind::Rsa | crate::tls::crypto::KeyKind::RsaPss => {
                    SignatureScheme::RsaPkcs1Sha1
                }
                _ => SignatureScheme::EcdsaSha1,
            },
            None => select_signature_scheme(
                &self.private_key,
                &self.client_sigalgs,
                &self.cfg.signature_schemes,
            )
            .ok_or(TlsError::SelectionUnsatisfiable {
                reason: format!(
                    "no signature scheme in common: key signs {:?}, client offered {:?}",
                    self.private_key.signature_schemes(),
                    self.client_sigalgs
                ),
            })?,
        };
        let signature = if !tls12_wire {
            self.private_key.sign_with_options(
                sig_scheme,
                &signed_bytes,
                &crate::tls::crypto::SigningOptions {
                    tls11: true,
                    ..Default::default()
                },
            )?
        } else {
            self.private_key.sign(sig_scheme, &signed_bytes)?
        };

        let encoded = if !tls12_wire {
            encode_ecdhe_server_key_exchange_body_mapped_legacy(
                label_group,
                &public_point,
                &signature,
            )
        } else {
            encode_ecdhe_server_key_exchange_body_mapped(
                label_group,
                &public_point,
                signature_label.unwrap_or(sig_scheme.wire_value()),
                &signature,
            )
        };
        self.write_server_key_exchange(encoded)
    }

    /// The ECDHE ephemeral for the selected group, deterministic for the seed
    /// (a distinct sub-seed on a renegotiation).
    fn ecdhe_ephemeral(&mut self) -> EcdhePrivate {
        if let Some(e) = self.ephemeral.take() {
            return e;
        }
        let label: &[u8] = if self.renegotiating {
            b"ecdh_private_reneg"
        } else {
            b"ecdh_private"
        };
        let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, label));
        EcdhePrivate::generate(self.ecdhe_group, &mut ec_rng)
    }

    /// The server's ECDHE public value under a `key_share_point` recipe (the
    /// "server sends a bad point" negative: zero / truncated / padded /
    /// compressed). The ephemeral itself is untouched, so plzn still agrees with
    /// the client's real point; only the wire bytes deviate. Mirrors the DTLS
    /// server's `server_ecdh_point`.
    fn server_point_with_recipe(
        &self,
        ephemeral: &EcdhePrivate,
        overrides: &[crate::ir::FieldOverride],
    ) -> Result<Vec<u8>, TlsError> {
        use crate::tls::driver::key_share_point_recipe;
        let recipe = key_share_point_recipe(overrides)?;
        crate::tls::driver::encode_key_share_point(ephemeral, &recipe)
    }

    /// Apply `send ServerKeyExchange @ ...` mutations, frame and send.
    fn write_server_key_exchange(
        &mut self,
        encoded: crate::tls::codec::EncodedBody,
    ) -> Result<(), TlsError> {
        let ske_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ServerKeyExchange);
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            ske_muts,
        )
        .map_err(|_| TlsError::Internal("server ServerKeyExchange mutation failed"))?;
        let mut framed = encode_handshake(HS_SERVER_KEY_EXCHANGE, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, ske_muts);
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ServerKeyExchange),
        )?;
        Ok(())
    }

    /// The psk_identity_hint plzn's server sends: the configured identity, or
    /// a `send ServerKeyExchange { psk_identity_hint: ... }` override.
    fn psk_hint(&self) -> Vec<u8> {
        let mut hint = self
            .cfg
            .psk
            .as_ref()
            .map(|(id, _)| id.clone())
            .unwrap_or_default();
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::ServerKeyExchange) {
            if let ("psk_identity_hint", crate::ir::FieldValue::Bytes(b)) =
                (ov.field.as_str(), &ov.value)
            {
                hint = b.clone();
            }
        }
        hint
    }

    fn send_psk_hint_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let encoded = encode_psk_hint_ske_mapped(&self.psk_hint());
        self.write_server_key_exchange(encoded)
    }

    fn send_ecdhe_psk_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let hint = self.psk_hint();
        let ephemeral = self.ecdhe_ephemeral();
        let public_point = ephemeral.public_bytes();
        self.ephemeral = Some(ephemeral);
        let encoded =
            encode_ecdhe_psk_ske_mapped(&hint, self.ecdhe_group.wire_value(), &public_point);
        self.write_server_key_exchange(encoded)
    }

    /// TLS 1.2 CertificateRequest (RFC 5246 7.4.4): rsa_sign and ecdsa_sign
    /// certificate types, the schemes plzn can verify (or the capability pin), and
    /// any configured certificate_authorities. `send CertificateRequest {
    /// certificate_types: [...], signature_algorithms: [...] }` replaces a list
    /// outright (an empty one violates the `<1..>` / `<2..>` bounds).
    fn send_certificate_request(&mut self) -> Result<(), TlsError> {
        let mut types = vec![CLIENT_CERT_TYPE_RSA_SIGN, CLIENT_CERT_TYPE_ECDSA_SIGN];
        let mut sig_algs: Vec<u16> = if self.cfg.signature_schemes.is_empty() {
            vec![
                SignatureScheme::EcdsaSecp256r1Sha256.wire_value(),
                SignatureScheme::EcdsaSecp384r1Sha384.wire_value(),
                SignatureScheme::RsaPssRsaeSha256.wire_value(),
                SignatureScheme::RsaPssRsaeSha384.wire_value(),
                SignatureScheme::RsaPssRsaeSha512.wire_value(),
                SignatureScheme::RsaPkcs1Sha256.wire_value(),
                SignatureScheme::RsaPkcs1Sha384.wire_value(),
                SignatureScheme::RsaPkcs1Sha512.wire_value(),
                SignatureScheme::Ed25519.wire_value(),
            ]
        } else {
            self.cfg.signature_schemes.clone()
        };
        let mut tls12_wire = self.cfg.version >= TlsVersion::Tls12;
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::CertificateRequest) {
            match (ov.field.as_str(), &ov.value) {
                ("certificate_types", crate::ir::FieldValue::U8List(t)) => types = t.clone(),
                ("signature_algorithms", crate::ir::FieldValue::U16List(a)) => sig_algs = a.clone(),
                ("format", crate::ir::FieldValue::Ident(format)) => tls12_wire = format == "tls12",
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateRequest",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let encoded = if !tls12_wire {
            crate::tls::codec::encode_certificate_request_legacy_body_mapped(
                &types,
                &self.cfg.cert_request_authorities,
            )
        } else {
            encode_certificate_request_12_body_mapped(
                &types,
                &sig_algs,
                &self.cfg.cert_request_authorities,
            )
        };
        let cr_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateRequest);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cr_muts)
                .map_err(|_| TlsError::Internal("server CertificateRequest mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_REQUEST, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, cr_muts);
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateRequest),
        )?;
        Ok(())
    }

    /// Receive the requested Certificate, allowing an empty list to decline
    /// authentication. Non-empty chains are verified against the test trust
    /// anchors and their CertificateVerify signatures are checked separately.
    fn recv_client_certificate(&mut self) -> Result<(), TlsError> {
        let cert_body = self.read_handshake(HS_CERTIFICATE)?;
        let cert =
            if self.negotiated_client_cert_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
                crate::tls::codec::Certificate12 {
                    entries: vec![
                        crate::tls::codec::decode_raw_public_key_certificate_12_body(&cert_body)?,
                    ],
                }
            } else {
                decode_certificate_12_body(&cert_body)?
            };
        let chain: Vec<&[u8]> = cert.entries.iter().map(|e| e.as_slice()).collect();
        crate::tls::client_auth::match_client_certificate(
            &chain,
            self.negotiated_client_cert_type,
            &self.cfg.recv_matchers,
        )?;
        self.received_empty_certificate = cert.entries.is_empty();
        self.client_pubkey = None;
        if cert.entries.is_empty() {
            return Ok(());
        }
        if self.negotiated_client_cert_type != crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
            crate::tls::client_auth::verify_client_chain(
                &chain,
                &crate::tls::client_auth::default_trust_anchors(),
            )?;
        }
        self.client_pubkey = Some(PublicKey::from_certificate_entry(
            &cert.entries[0],
            self.negotiated_client_cert_type,
        )?);
        Ok(())
    }

    /// RFC 5246 7.4.8: the signature covers "all handshake messages sent or
    /// received, starting at ClientHello and ending at ClientKeyExchange"
    /// (the raw bytes, hashed under the scheme's hash), with the scheme
    /// carried in the message.
    fn recv_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        // An empty Certificate omits CertificateVerify. The preset still
        // includes this step, so leave the next handshake message unread.
        if self.received_empty_certificate {
            return Ok(());
        }
        let signed = self.raw_transcript.clone();
        let cv_body = self.read_handshake(HS_CERTIFICATE_VERIFY)?;
        let legacy_algorithm = self.client_pubkey.as_ref().map(|pk| match pk.kind() {
            crate::tls::crypto::KeyKind::Rsa | crate::tls::crypto::KeyKind::RsaPss => {
                SignatureScheme::RsaPkcs1Sha1.wire_value()
            }
            _ => SignatureScheme::EcdsaSha1.wire_value(),
        });
        let cv = if let Some(algorithm) =
            legacy_algorithm.filter(|_| self.cfg.version < TlsVersion::Tls12)
        {
            crate::tls::codec::decode_certificate_verify_legacy_body(&cv_body, algorithm)?
        } else {
            decode_certificate_verify_13_body(&cv_body)?
        };
        for matcher in collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateVerify) {
            crate::tls::driver::match_certificate_verify_field(&cv, matcher)?;
        }
        let sig_scheme = SignatureScheme::from_wire_value(cv.algorithm)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm))?;
        let pk = self.client_pubkey.as_ref().ok_or(TlsError::Internal(
            "client CertificateVerify before its Certificate",
        ))?;
        let verified = if self.cfg.version < TlsVersion::Tls12 {
            pk.verify_tls11(&signed, &cv.signature)
        } else {
            pk.verify(sig_scheme, &signed, &cv.signature)
        };
        verified.map_err(|_| TlsError::SignatureVerificationFailed)?;
        Ok(())
    }

    /// DHE ServerKeyExchange (RFC 5246 7.4.3): explicit `ServerDHParams` for
    /// ffdhe2048 -- or exact parameters selected by `dh_p_bits` / `dh_p` /
    /// `dh_g` / `dh_Ys` overrides -- signed with the RSA key over
    /// `client_random || server_random || params`.
    fn send_dhe_server_key_exchange(&mut self) -> Result<(), TlsError> {
        use crate::ir::MessageKind;
        // The group (RFC 7919 3): a client that listed FFDHE groups gets one it
        // listed (the server's configured order, else the client's), and the server
        // MUST NOT pick another; a client that listed none gets the server's
        // first configured ffdhe* group, else ffdhe2048. `dh_p_bits` overrides.
        let client_ffdhe: Vec<u16> = self
            .client_groups
            .iter()
            .copied()
            .filter(|g| (0x0100..=0x01ff).contains(g))
            .collect();
        let cfg_ffdhe: Vec<u16> = self
            .cfg
            .groups
            .iter()
            .copied()
            .filter(|g| crate::tls::kex12::DhGroup::by_named_group(*g).is_some())
            .collect();
        let mut group = if client_ffdhe.is_empty() {
            cfg_ffdhe
                .first()
                .and_then(|g| crate::tls::kex12::DhGroup::by_named_group(*g))
                .unwrap_or_else(crate::tls::kex12::DhGroup::ffdhe2048)
        } else {
            let prefs: Vec<u16> = if cfg_ffdhe.is_empty() {
                client_ffdhe.clone()
            } else {
                cfg_ffdhe
                    .iter()
                    .copied()
                    .filter(|g| client_ffdhe.contains(g))
                    .collect()
            };
            prefs
                .iter()
                .find_map(|g| crate::tls::kex12::DhGroup::by_named_group(*g))
                .ok_or(TlsError::SelectionUnsatisfiable {
                    reason: format!(
                        "no FFDHE group in common: server offers {:?}, client offered {:?}",
                        if cfg_ffdhe.is_empty() {
                            vec![0x0100u16, 0x0101]
                        } else {
                            cfg_ffdhe.clone()
                        },
                        client_ffdhe
                    ),
                })?
        };
        let mut forced_scheme: Option<SignatureScheme> = None;
        let mut signature_label: Option<u16> = None;
        let mut tls12_wire = self.cfg.version >= TlsVersion::Tls12;
        let mut forced_bits = false;
        let mut forced_p: Option<Vec<u8>> = None;
        let mut forced_g: Option<crate::ir::FieldValue> = None;
        let mut forced_ys: Option<crate::ir::FieldValue> = None;
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::ServerKeyExchange) {
            match (ov.field.as_str(), &ov.value) {
                ("dh_p_bits", crate::ir::FieldValue::U16(bits)) => {
                    forced_bits = true;
                    group = crate::tls::kex12::DhGroup::by_bits(bits.to_owned())
                        .ok_or(TlsError::Internal(
                        "dh_p_bits takes 8192 / 3072 / 2048 (RFC 7919), or 1024 / 768 (RFC 2409)",
                    ))?;
                }
                ("dh_p", crate::ir::FieldValue::Bytes(bytes)) => {
                    forced_p = Some(bytes.clone());
                }
                ("dh_p", crate::ir::FieldValue::Ident(name)) => {
                    forced_p = Some(
                        crate::tls::kex12::dh_prime_recipe(name)
                            .ok_or(TlsError::Internal("dh_p: unknown named prime"))?,
                    );
                }
                (
                    "dh_g",
                    value @ (crate::ir::FieldValue::Bytes(_) | crate::ir::FieldValue::Ident(_)),
                ) => {
                    forced_g = Some(value.clone());
                }
                (
                    "dh_Ys",
                    value @ (crate::ir::FieldValue::Bytes(_) | crate::ir::FieldValue::Ident(_)),
                ) => {
                    forced_ys = Some(value.clone());
                }
                ("signature_scheme", crate::ir::FieldValue::U16(w)) => {
                    signature_label = Some(*w);
                    forced_scheme = SignatureScheme::from_wire_value(*w);
                }
                ("format", crate::ir::FieldValue::Ident(format)) => tls12_wire = format == "tls12",
                ("named_group", _) | ("psk_identity_hint", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        if forced_bits && forced_p.is_some() {
            return Err(TlsError::Internal(
                "ServerKeyExchange cannot set both dh_p_bits and exact dh_p",
            ));
        }
        if let Some(p) = forced_p {
            group.p = p;
        }
        let resolve_parameter = |field: &'static str,
                                 value: Option<crate::ir::FieldValue>|
         -> Result<Option<Vec<u8>>, TlsError> {
            value
                .map(|value| match value {
                    crate::ir::FieldValue::Bytes(bytes) => Ok(bytes),
                    crate::ir::FieldValue::Ident(recipe) => crate::tls::kex12::dh_parameter_recipe(
                        &group.p, &recipe,
                    )
                    .ok_or(TlsError::Internal(match field {
                        "dh_g" => "dh_g: unknown boundary recipe, or `small_order` on a p - 1 without a small odd prime factor",
                        _ => "dh_Ys: unknown boundary recipe, or `small_order` on a p - 1 without a small odd prime factor",
                    })),
                    _ => Err(TlsError::Internal("invalid explicit DH parameter")),
                })
                .transpose()
        };
        if let Some(g) = resolve_parameter("dh_g", forced_g)? {
            group.g = g;
        }
        let forced_ys = resolve_parameter("dh_Ys", forced_ys)?;
        let seed = if self.renegotiating {
            Rng::sub_seed(self.cfg.seed, b"reneg")
        } else {
            self.cfg.seed
        };
        let server = crate::tls::kex12::DheServer::generate_with_public(group, seed, forced_ys);
        let params = server.params();
        let signed =
            crate::tls::kex12::ske_signed_input(&self.client_random, &self.server_random, &params);
        let sig_scheme = match forced_scheme {
            Some(s) => s,
            None if !tls12_wire => SignatureScheme::RsaPkcs1Sha1,
            None => select_signature_scheme(
                &self.private_key,
                &self.client_sigalgs,
                &self.cfg.signature_schemes,
            )
            .ok_or(TlsError::SelectionUnsatisfiable {
                reason: format!(
                    "no signature scheme in common: key signs {:?}, client offered {:?}",
                    self.private_key.signature_schemes(),
                    self.client_sigalgs
                ),
            })?,
        };
        let signature = if !tls12_wire {
            self.private_key.sign_with_options(
                sig_scheme,
                &signed,
                &crate::tls::crypto::SigningOptions {
                    tls11: true,
                    ..Default::default()
                },
            )?
        } else {
            self.private_key.sign(sig_scheme, &signed)?
        };
        let encoded = if !tls12_wire {
            crate::tls::codec::encode_dhe_server_key_exchange_body_mapped_legacy(
                &server.group().p,
                &server.group().g,
                server.ys(),
                &signature,
            )
        } else {
            crate::tls::codec::encode_dhe_server_key_exchange_body_mapped(
                &server.group().p,
                &server.group().g,
                server.ys(),
                signature_label.unwrap_or(sig_scheme.wire_value()),
                &signature,
            )
        };
        self.dhe = Some(server);
        self.write_server_key_exchange(encoded)
    }

    fn send_server_hello_done(&mut self) -> Result<(), TlsError> {
        let body = encode_server_hello_done_body();
        // Apply header mutations (e.g. `@ set[handshake.msg_type, 0]` to relabel the
        // message) -- the client-side wrong-message-type family. The body is empty.
        let shd_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ServerHelloDone);
        let encoded = crate::tls::codec::EncodedBody {
            bytes: body.clone(),
            fields: std::collections::HashMap::new(),
        };
        let body = crate::tls::mutate::apply_handshake_mutations(body, &encoded, shd_muts)
            .map_err(|_| TlsError::Internal("server ServerHelloDone mutation failed"))?;
        let mut framed = encode_handshake(HS_SERVER_HELLO_DONE, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, shd_muts);
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ServerHelloDone),
        )?;
        Ok(())
    }

    fn recv_client_key_exchange(&mut self) -> Result<(), TlsError> {
        let cke_body = self.read_handshake(HS_CLIENT_KEY_EXCHANGE)?;
        let pms_candidates = match self.kex() {
            crate::ir::KexType::Rsa => {
                // RFC 5246 7.4.7.1: a bad ciphertext is never an alert; the
                // handshake continues on a random premaster and fails at Finished.
                let encrypted = crate::tls::codec::decode_rsa_client_key_exchange_body(&cke_body)?;
                vec![crate::tls::kex12::rsa_server_premaster(
                    &self.private_key,
                    &encrypted,
                    self.client_version,
                    self.cfg.seed,
                )]
            }
            crate::ir::KexType::DheRsa => {
                let yc = crate::tls::codec::decode_dhe_client_key_exchange_body(&cke_body)?;
                let dhe = self.dhe.take().ok_or(TlsError::Internal(
                    "DHE ClientKeyExchange before ServerKeyExchange",
                ))?;
                dhe.premaster_candidates(&yc)?
            }
            // RFC 4279 2 / RFC 5489 3.3: the identity must be the one this
            // server knows (a server MAY answer unknown_psk_identity or
            // decrypt_error; plzn's simply fails the handshake).
            crate::ir::KexType::Psk | crate::ir::KexType::EcdhePsk => {
                let with_point = self.kex() == crate::ir::KexType::EcdhePsk;
                let (identity, point) = decode_psk_cke(&cke_body, with_point)?;
                let (known_id, secret) = self.cfg.psk.clone().ok_or(TlsError::Internal(
                    "PSK suite negotiated without a configured PSK",
                ))?;
                if identity != known_id {
                    // RFC 4279 2: a server that holds no key for the offered
                    // identity MAY answer unknown_psk_identity (or decrypt_error,
                    // or continue and fail at Finished). plzn sends the alert so
                    // the client sees a definite rejection.
                    return Err(TlsError::Rejected {
                        alert: 115, // unknown_psk_identity
                        reason: format!(
                            "no PSK for identity {:?} (serving {:?})",
                            String::from_utf8_lossy(&identity),
                            String::from_utf8_lossy(&known_id)
                        ),
                    });
                }
                vec![match point {
                    Some(point) => {
                        let ephemeral = self
                            .ephemeral
                            .take()
                            .ok_or(TlsError::Internal("missing ephemeral"))?;
                        let z = ephemeral.agree(&point)?;
                        psk_premaster_with(&z, &secret)
                    }
                    None => psk_premaster(&secret),
                }]
            }
            _ => {
                let client_point = decode_ecdhe_client_key_exchange_body(&cke_body)?;
                // ECDHE agreement.
                let ephemeral = self
                    .ephemeral
                    .take()
                    .ok_or(TlsError::Internal("missing ephemeral"))?;
                vec![ephemeral.agree(&client_point)?]
            }
        };

        // Derive the master secret with the suite's PRF hash, then both
        // directions' record keys straight from the catalogue.
        let prf_hash = self.prf_hash();
        let session_hash = self.use_ems.then(|| self.handshake_digest());
        let suite = crate::ir::suite_info(self.negotiated_suite)
            .ok_or(TlsError::Internal("negotiated suite not in the catalogue"))?;
        let mut derived = Vec::with_capacity(pms_candidates.len());
        for pms in &pms_candidates {
            let ms = match &session_hash {
                Some(session_hash) => {
                    derive_master_secret_ems_for(self.cfg.version, prf_hash, pms, session_hash)
                }
                None => derive_master_secret_for(
                    self.cfg.version,
                    prf_hash,
                    pms,
                    &self.client_random,
                    &self.server_random,
                ),
            };
            let (client_keys, server_keys) = crate::tls::handshake::legacy_direction_keys(
                self.cfg.version,
                suite,
                &ms,
                &self.server_random,
                &self.client_random,
                self.use_etm,
            )?;
            derived.push((ms, client_keys, server_keys));
        }
        // Install them at the right moment: read keys after the client's CCS,
        // write keys after ours.
        if derived.len() == 1 {
            let (ms, client_keys, server_keys) = derived.pop().expect("one candidate");
            self.master_secret = ms;
            self.pending_read_keys = Some(client_keys);
            self.pending_write_keys = Some(server_keys);
        } else {
            let (read, rest): (Vec<_>, Vec<_>) = derived
                .into_iter()
                .map(|(ms, client_keys, server_keys)| (client_keys, (ms, server_keys)))
                .unzip();
            self.pending_read_key_candidates = Some(read);
            self.premaster_candidates = Some(rest);
        }
        Ok(())
    }

    /// Adopt the premaster candidate whose client write keys opened the
    /// client's first protected record. A no-op once settled or when there was
    /// only ever one premaster.
    fn settle_premaster(&mut self) -> Result<(), TlsError> {
        let Some(mut candidates) = self.premaster_candidates.take() else {
            return Ok(());
        };
        let index = self.records.take_read_key_selection().ok_or(TlsError::Internal(
            "the DHE premaster is one of several and the client has not yet sent a protected record to choose it",
        ))?;
        let (ms, server_keys) = candidates.swap_remove(index);
        self.master_secret = ms;
        self.pending_write_keys = Some(server_keys);
        Ok(())
    }

    fn suite_is_cbc(&self) -> bool {
        crate::ir::suite_info(self.negotiated_suite).is_some_and(|s| s.cipher.is_cbc())
    }

    fn recv_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        self.records.read_change_cipher_spec()?;
        // Install READ keys (client_write = our read).
        if let Some(keys) = self.pending_read_keys.take() {
            self.records.install_read_keys(keys)?;
        } else if let Some(candidates) = self.pending_read_key_candidates.take() {
            self.records.install_read_key_candidates(candidates);
        }
        Ok(())
    }

    fn recv_finished_msg(&mut self) -> Result<(), TlsError> {
        let fin_body = self.read_handshake(HS_FINISHED)?;
        self.settle_premaster()?;
        let got = decode_finished_body(&fin_body)?;
        crate::tls::driver::match_finished_fields(&fin_body, &self.cfg.recv_matchers)?;
        let expected = compute_verify_data_for(
            self.cfg.version,
            self.prf_hash(),
            &self.master_secret,
            b"client finished",
            &self.pre_client_finished_digest,
        );
        if got != expected {
            return Err(TlsError::FinishedMismatch);
        }
        // Save for the RFC 5746 renegotiation_info of a subsequent renegotiation.
        self.last_client_verify_data = expected;
        self.finished_received = true;
        Ok(())
    }

    fn send_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        // RFC 5077 3.3: a promised NewSessionTicket goes out before the
        // ChangeCipherSpec (after the client's Finished in a full handshake,
        // after the ServerHello in an abbreviated one) unless an explicit
        // `send NewSessionTicket` step already sent it.
        self.settle_premaster()?;
        if self.promised_ticket && !self.ticket_sent {
            self.send_new_session_ticket()?;
        }
        // Write the CCS first, then install the WRITE keys (server_write = our
        // write): the initial CCS is plaintext, but a renegotiation CCS must ride
        // under the current (old) keys before the switch, so it precedes the install.
        let ccs = crate::tls::driver::resolve_ccs_byte(&self.cfg.send_overrides)?;
        self.records.write_record_with_mutations(
            CONTENT_TYPE_CCS,
            &[ccs],
            collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
        )?;
        if let Some(keys) = self.pending_write_keys.take() {
            self.records.install_write_keys(keys)?;
        }
        Ok(())
    }

    fn send_finished(&mut self) -> Result<(), TlsError> {
        self.settle_premaster()?;
        let transcript_hash = self.handshake_digest();
        let server_vd = compute_verify_data_for(
            self.cfg.version,
            self.prf_hash(),
            &self.master_secret,
            b"server finished",
            &transcript_hash,
        );
        // Save for the RFC 5746 renegotiation_info of a subsequent renegotiation.
        self.last_server_verify_data = server_vd.clone();
        self.finished_sent = true;
        // Apply any `send Finished @ ...` mutations so a client that fails to verify
        // the server's Finished (client-side crypto rejection) is exercised.
        let fin_encoded = encode_finished_body_mapped(&server_vd);
        let fin_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        let fin_body = crate::tls::mutate::apply_handshake_mutations(
            fin_encoded.bytes.clone(),
            &fin_encoded,
            fin_muts,
        )
        .map_err(|_| TlsError::Internal("server Finished mutation failed"))?;
        let mut fin_framed = encode_handshake(HS_FINISHED, &fin_body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut fin_framed, fin_muts);
        self.absorb(&fin_framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &fin_framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::Finished),
        )?;
        Ok(())
    }

    // ---- helpers ----

    fn read_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        let header = self.records.read_handshake_bytes(4)?;
        let mut cursor = ByteCursor::new(&header);
        let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
        let body = self.records.read_handshake_bytes(body_len)?;
        if msg_type != expected_type {
            return Err(TlsError::UnexpectedHandshake {
                expected: expected_type,
                got: msg_type,
            });
        }
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&body);
        // Snapshot transcript before client Finished for
        // server's verify_data computation.
        if msg_type == HS_FINISHED {
            self.pre_client_finished_digest = self.handshake_digest();
        }
        self.absorb(&framed);
        Ok(body)
    }
}

impl TlsEndpoint for Tls12Server {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> Result<(), TlsError> {
        self.records
            .set_read_deadline(deadline)
            .map_err(|error| TlsError::Record(crate::tls::record::RecordError::Io(error)))
    }
    fn app_data_records_received(&self) -> Option<u32> {
        Some(self.records.app_data_records_read())
    }
    fn configure_message(&mut self, config: &crate::ir::MessageConfig) -> Result<(), TlsError> {
        config.apply(
            &mut self.cfg.send_overrides,
            &mut self.cfg.recv_matchers,
            &mut self.cfg.send_mutations,
            &mut self.cfg.send_ext_deltas,
        );
        Ok(())
    }
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        self.captures.clone()
    }
    fn recv_alert(&mut self, level: u8, code: Option<u8>) -> Result<(), TlsError> {
        crate::tls::driver::t6_expect_alert_record(&mut self.records, level, code)
    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        Tls12Server::do_handshake(self)
    }
    fn do_handshake_step(&mut self, step: &HandshakeStep) -> Result<(), TlsError> {
        Tls12Server::do_handshake_step(self, step)
    }
    fn renegotiate_with(
        &mut self,
        _resumed: bool,
        _insecure: bool,
        _overrides: &[FieldOverride],
        _ext_deltas: &[ExtDeltaOp],
    ) -> Result<(), TlsError> {
        Tls12Server::renegotiate(self)
    }
    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        Tls12Server::write_app_data(self, data, mutations)
    }
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Tls12Server::read_app_data(self)
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError> {
        Ok(export_keying_material_legacy(
            self.cfg.version,
            self.prf_hash(),
            &self.master_secret,
            label,
            &self.client_random,
            &self.server_random,
            context,
            length,
        ))
    }
    fn tls_unique(&self) -> Result<Vec<u8>, TlsError> {
        if self.resumed && !self.use_ems {
            return Err(TlsError::Internal(
                "tls-unique is undefined for a resumed TLS 1.2 session without EMS",
            ));
        }
        let value = if self.resumed {
            &self.last_server_verify_data
        } else {
            &self.last_client_verify_data
        };
        if value.is_empty() {
            return Err(TlsError::Internal(
                "tls-unique requested before the first Finished",
            ));
        }
        Ok(value.clone())
    }
    fn close(&mut self) -> Result<(), TlsError> {
        Tls12Server::close(self)
    }
    fn close_reset(&mut self) -> Result<(), TlsError> {
        self.records
            .close_reset()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }
    fn negotiated_cipher_suite(&self) -> u16 {
        Tls12Server::negotiated_cipher_suite(self)
    }
    fn probe(&mut self, millis: u64) -> Result<(), TlsError> {
        self.records.probe(millis).map_err(TlsError::from)
    }
    fn write_raw(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.records.write_raw(data).map_err(TlsError::from)
    }
    fn send_key_update(&mut self, _: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is a TLS 1.3 feature"))
    }
    fn recv_key_update(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is a TLS 1.3 feature"))
    }
    fn send_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(crate::tls::codec::CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)?;
        // RFC 5246 7.4.1.1: a no_renegotiation warning after `recv ClientHello`
        // refuses the pending client-initiated renegotiation; the connection
        // continues under the established keys (which `begin_renegotiation`
        // retained), so the server is back in the established state.
        const NO_RENEGOTIATION: u8 = 100;
        if (level, code) == (1, NO_RENEGOTIATION) && self.renegotiating {
            self.renegotiating = false;
            self.finished_sent = true;
            self.finished_received = true;
        }
        Ok(())
    }
    fn send_alert_with(
        &mut self,
        level: u8,
        code: u8,
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        self.records
            .write_record_with_mutations(
                crate::tls::codec::CONTENT_TYPE_ALERT,
                &[level, code],
                mutations,
            )
            .map_err(TlsError::Record)
    }
    fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(crate::tls::codec::CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)?;
        Tls12Server::close(self)
    }
    fn begin_coalesce(&mut self, mode: crate::ir::CoalesceMode) -> Result<(), TlsError> {
        self.records.begin_coalesce(mode).map_err(TlsError::Record)
    }
    fn end_coalesce(&mut self) -> Result<(), TlsError> {
        self.records.end_coalesce().map_err(TlsError::Record)
    }
    fn begin_atomic(&mut self) -> Result<(), TlsError> {
        self.records.begin_atomic().map_err(TlsError::Record)
    }
    fn end_atomic(&mut self) -> Result<(), TlsError> {
        self.records.end_atomic().map_err(TlsError::Record)
    }
    fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), TlsError> {
        self.records
            .write_record(content_type, data)
            .map_err(TlsError::Record)
    }
    fn send_record_with(
        &mut self,
        content_type: u8,
        data: &[u8],
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        self.records
            .write_standalone_record(content_type, data, mutations)
            .map_err(TlsError::Record)
    }
    fn send_empty_record(&mut self, content_type: u8) -> Result<(), TlsError> {
        self.records
            .write_empty_record(content_type)
            .map_err(TlsError::Record)
    }
    fn flush_fragment(&mut self) -> Result<(), TlsError> {
        match self.records.flush_held() {
            Ok(true) => Ok(()),
            Ok(false) => Err(TlsError::Internal(
                "flush_fragment: nothing is held back (send a message with `@ fragment N hold` first)",
            )),
            Err(e) => Err(TlsError::Record(e)),
        }
    }
    fn session_state(&self) -> Option<crate::ir::SessionState> {
        let (ticket, master_secret) = self.issued_ticket.as_ref()?;
        Some(crate::ir::SessionState {
            protocol: crate::ir::Protocol::Tls,
            version: self.cfg.version,
            ticket: ticket.clone(),
            master_secret: master_secret.clone(),
            session_id: Vec::new(),
            ticket_age_add: 0,
            cipher_suite: 0,
            max_early_data_size: 0,
        })
    }
    fn negotiated_resumed(&self) -> Option<bool> {
        Some(self.resumed)
    }
}

#[cfg(test)]
mod ticket_tests {
    use super::*;
    use crate::ir::SessionState;

    fn ticket(ems: bool, suite: u16) -> Vec<u8> {
        let mut t = TICKET12_MAGIC.to_vec();
        t.push(if ems { 1 } else { 0 });
        t.extend_from_slice(&suite.to_be_bytes());
        t.extend_from_slice(&[0x5a; 32]);
        t
    }

    fn known(ems: bool, suite: u16) -> SessionState {
        SessionState {
            protocol: crate::ir::Protocol::Tls,
            version: crate::tls::record::TlsVersion::Tls12,
            ticket: ticket(ems, suite),
            master_secret: vec![0x11; 48],
            session_id: Vec::new(),
            ticket_age_add: 0,
            cipher_suite: 0,
            max_early_data_size: 0,
        }
    }

    #[test]
    fn resumes_only_the_ticket_it_issued() {
        let ss = known(true, 0xc02f);
        let ok = decide_resumption(Some(&ss.ticket), Some(&ss), true, &[0xc02f, 0xc02b]).unwrap();
        assert_eq!(ok, Some((0xc02f, vec![0x11; 48])));
        // Unknown, corrupt, empty, or no ticket: full handshake.
        let mut corrupt = ss.ticket.clone();
        corrupt[10] ^= 1;
        assert!(
            decide_resumption(Some(&corrupt), Some(&ss), true, &[0xc02f])
                .unwrap()
                .is_none()
        );
        assert!(
            decide_resumption(Some(&[]), Some(&ss), true, &[0xc02f])
                .unwrap()
                .is_none()
        );
        assert!(
            decide_resumption(None, Some(&ss), true, &[0xc02f])
                .unwrap()
                .is_none()
        );
        assert!(
            decide_resumption(Some(&ss.ticket), None, true, &[0xc02f])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rfc7627_rules_on_resumption() {
        // Original session used EMS, new ClientHello lacks it: MUST abort.
        let ss = known(true, 0xc02f);
        assert!(decide_resumption(Some(&ss.ticket), Some(&ss), false, &[0xc02f]).is_err());
        // Original session did not use EMS, new ClientHello offers it: MUST NOT
        // resume (full handshake instead).
        let ss = known(false, 0xc02f);
        assert!(
            decide_resumption(Some(&ss.ticket), Some(&ss), true, &[0xc02f])
                .unwrap()
                .is_none()
        );
        // Neither used EMS: resumes.
        assert!(
            decide_resumption(Some(&ss.ticket), Some(&ss), false, &[0xc02f])
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn resumed_session_keeps_its_suite() {
        let ss = known(true, 0xc02f);
        // The client no longer offers the session's suite: full handshake.
        assert!(
            decide_resumption(Some(&ss.ticket), Some(&ss), true, &[0xc02b])
                .unwrap()
                .is_none()
        );
        assert_eq!(ticket_fields(&ss.ticket), Some((true, 0xc02f)));
        assert_eq!(ticket_fields(b"nope"), None);
    }
}
