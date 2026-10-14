// TLS 1.3 server-side driver.
//
// The mirror of `Tls13Client` in driver.rs. The harness plays the
// server: receives ClientHello, sends ServerHello + encrypted
// flight (EE + Cert + CertVerify + Finished), receives client
// Finished, exchanges app data.
//
// Key transitions (server perspective):
//   1. After ServerHello: install handshake keys (both directions)
//   2. After sending server Finished: switch WRITE to app keys
//   3. After receiving client Finished: switch READ to app keys

use crate::ir::FieldValue;
use crate::ir::{HandshakeStep, MessageKind, MessageMutations, MessageOverrides};
use crate::tls::codec::{
    ByteCursor, CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE, EXT_COOKIE, EXT_PRE_SHARED_KEY,
    EXT_PSK_KEY_EXCHANGE_MODES, EXT_SIGNATURE_ALGORITHMS, Extension, GROUP_SECP256R1,
    GROUP_SECP384R1, GROUP_X25519, HRR_RANDOM, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_END_OF_EARLY_DATA,
    HS_FINISHED, HS_KEY_UPDATE, HS_NEW_SESSION_TICKET, HS_SERVER_HELLO, KeyShareEntry,
    NewSessionTicket13, PROTOCOL_VERSION_TLS12, PROTOCOL_VERSION_TLS13, PSK_DHE_KE, PSK_KE,
    ServerHelloBuilder, decode_certificate_13_body, decode_certificate_verify_13_body,
    decode_client_hello_body, decode_finished_body, decode_key_update_body,
    decode_pre_shared_key_offer, decode_psk_key_exchange_modes,
    encode_certificate_verify_13_body_mapped, encode_encrypted_extensions_body_mapped,
    encode_finished_body_mapped, encode_handshake, encode_key_update_body,
    encode_new_session_ticket_13_body_mapped, encode_pre_shared_key_selection,
    parse_handshake_header, tls13_certificate_verify_signed_input,
    tls13_client_certificate_verify_signed_input,
};
use crate::tls::crypto::{
    AeadAlg, EcdheGroup, EcdhePrivate, HashAlg, PrivateKey, PublicKey, Rng, SignatureScheme,
    TranscriptHash,
};
use crate::tls::driver::{
    TlsEndpoint, TlsError, apply_server_hello_override, collect_mutations, collect_overrides,
    match_client_hello_field, write_tls13_handshake_message,
};
use crate::tls::handshake::{Tls13KeySchedule, replace_transcript_for_hrr};
use crate::tls::record::{DirectionKeys, RecordError, RecordLayer, TlsVersion};
use crate::transport::UutTransport;

/// Magic prefix of the tickets plzn's server issues; the byte after it is the
/// suite hash (0 = SHA-256, 1 = SHA-384) so a resumption attempt with a suite
/// of a different KDF hash is refused (RFC 8446 4.6.1).
const TICKET_MAGIC: &[u8] = b"plzn13";

pub struct Tls13ServerConfig {
    pub cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    /// A: every chain this server holds (`chain:`), in preference order;
    /// `cert_der` / `private_key_der` are the initially selected one. With two
    /// or more, the ClientHello picks (`tls::chains`).
    pub chains: Vec<crate::ir::Chain>,
    /// Intermediate CA certificates (DER) presented after the leaf so the peer
    /// can build a path to a trusted root. Empty = leaf only.
    pub extra_chain_der: Vec<Vec<u8>>,
    pub seed: [u8; 32],
    pub send_overrides: Vec<MessageOverrides>,
    pub recv_matchers: Vec<MessageOverrides>,
    pub send_mutations: Vec<MessageMutations>,
    pub send_ext_deltas: Vec<crate::ir::MessageExtDeltas>,
    /// Cipher suites the server is willing to negotiate, in
    /// preference order (from peer capabilities). Empty = full implemented set.
    pub server_suites: Vec<u16>,
    /// Named groups (IANA wire values) the server will select a
    /// key_share from, in preference order. Empty = full set.
    pub server_groups: Vec<u16>,
    /// The flow sends a HelloRetryRequest: ClientHello selection then prefers
    /// a listed group the client did not key-share, so the retry is one a
    /// conforming client accepts (RFC 8446 4.2.8).
    pub force_hrr: bool,
    /// Compress the Certificate (RFC 8879 zlib) when the client advertises
    /// compress_certificate. Off leaves the Certificate uncompressed.
    pub compress_certificate: bool,
    /// Select RawPublicKey for server authentication when the client offers it.
    pub offer_raw_public_key: bool,
    /// Negotiate client_certificate_type=RawPublicKey (RFC 7250) when the client
    /// offers it, so the client authenticates with a bare SubjectPublicKeyInfo
    /// instead of an X.509 certificate. Off = always expect an X.509 client cert.
    pub accept_client_rpk: bool,
    /// Distinguished names (DER-encoded X.501 Name) to advertise in the
    /// CertificateRequest's certificate_authorities extension (RFC 8446 4.2.4).
    /// Empty = omit the extension.
    pub cert_request_authorities: Vec<Vec<u8>>,
    /// The session this connection may resume: the ticket plzn's server issued
    /// on an earlier connection and the resumption PSK it derived (RFC 8446
    /// 4.6.1). `None` = every pre_shared_key offer is declined, which falls
    /// back to a full handshake.
    pub resumption: Option<crate::ir::SessionState>,
    /// Deliberately select an incompatible prior session even when the client
    /// did not offer it. The resulting unsolicited pre_shared_key selection
    /// checks that a UUT client rejects a cross-version ServerHello.
    pub force_resumption: bool,
    /// Trust anchors (DER) a client's X.509 certificate chain must reach
    /// (`client_auth::verify_client_chain`). Empty = no trust check: any chain
    /// whose CertificateVerify signature verifies is accepted.
    pub client_trust_anchors: Vec<Vec<u8>>,
    /// The external PSK of the test's `psk { }` block: accepted when the
    /// client offers its identity and the "ext binder" verifies (RFC 8446
    /// 4.2.11). `None` = every external identity is declined.
    pub psk: Option<crate::ir::PskConfig>,
}

pub struct Tls13Server {
    cfg: Tls13ServerConfig,
    records: RecordLayer,
    transcript: TranscriptHash,
    schedule: Tls13KeySchedule,
    private_key: PrivateKey,
    /// A: the parsed keys of `cfg.chains` (empty unless several chains).
    chain_keys: Vec<PrivateKey>,

    server_random: [u8; 32],
    client_random: [u8; 32],
    /// `legacy_session_id` from the client's ClientHello. TLS 1.3
    /// requires the server to echo this back verbatim in its
    /// ServerHello (RFC 8446 §4.1.3) — middlebox compatibility.
    client_session_id: Vec<u8>,
    negotiated_suite: u16,
    /// Hash + AEAD implied by the negotiated cipher suite. Set in
    /// `recv_client_hello` once the suite is chosen; default until then.
    hash: HashAlg,
    aead: AeadAlg,
    /// The ECDHE group the server selected a key_share for.
    selected_group: EcdheGroup,
    client_key_share: Option<Vec<u8>>,
    client_key_share_group: u16,
    /// Set by ClientHello selection when the chosen group was merely
    /// *listed* in supported_groups (no key_share): the wire value
    /// the server must request via HelloRetryRequest before it can
    /// send its ServerHello.
    needs_hrr: Option<u16>,
    /// Set once a HelloRetryRequest has gone out: the group it
    /// requested. Makes the next ClientHello parse as the retry.
    hrr_requested_group: Option<u16>,
    pre_client_finished_digest: Vec<u8>,
    /// Set in recv_client_hello if the client advertised compress_certificate with zlib.
    client_offered_cert_compression: bool,
    /// The client's leaf public key, extracted from its Certificate when
    /// client authentication is requested. Used to verify the client's
    /// CertificateVerify signature (RFC 8446 4.4.3).
    client_pubkey: Option<PublicKey>,
    received_empty_certificate: bool,
    /// Set in recv_client_hello if the client offered client_certificate_type
    /// including RawPublicKey (RFC 7250).
    client_offered_rpk_cert_type: bool,
    client_accepts_server_rpk: bool,
    negotiated_server_cert_type: u8,
    /// The certificate type selected for the client's Certificate (X.509 by
    /// default, RawPublicKey when negotiated). Chosen in send_encrypted_extensions.
    negotiated_client_cert_type: u8,
    /// The client's signature_algorithms (RFC 8446 4.2.3): CertificateVerify
    /// must use a scheme from this list that our key can produce.
    client_sig_schemes: Vec<u16>,
    requested_client_sig_schemes: Vec<u16>,
    /// The cookie extension body our HelloRetryRequest carried, which the retry
    /// ClientHello must echo verbatim (RFC 8446 4.2.2).
    hrr_cookie: Option<Vec<u8>>,
    /// A pre_shared_key offer was accepted: abbreviated flow, PSK-seeded schedule.
    resumed: bool,
    /// The identity index we accepted (goes into the ServerHello pre_shared_key).
    selected_identity: u16,
    /// The PSK selected from ClientHello1. Retained across HelloRetryRequest so
    /// ClientHello2 can be matched and its freshly computed binder verified.
    selected_psk: Option<SelectedPsk>,
    /// psk_ke was selected: no key_share, zero (EC)DHE input.
    psk_ke_only: bool,
    /// Set once the client's Finished has been verified.
    handshake_complete: bool,
    /// resumption_master_secret, derived after the client's Finished; tickets
    /// issued on this connection draw their PSK from it.
    resumption_master_secret: Option<Vec<u8>>,
    /// The last ticket issued and its PSK (what `session_state` hands to a
    /// resuming session).
    issued_ticket: Option<(Vec<u8>, Vec<u8>, u32, u32)>,
    tickets_issued: u32,
    /// Monotonic, non-zero context for post-handshake CertificateRequest.
    post_handshake_cert_requests_sent: u32,
    /// A received KeyUpdate asked for reciprocation: send ours before the next
    /// application-data record (RFC 8446 4.6.3).
    key_update_response_pending: bool,
    client_offered_early_data: bool,
    early_data_accepted: bool,
    early_read_keys_installed: bool,
    /// EndOfEarlyData is opened with the early keys; client handshake read keys
    /// become active immediately after that message.
    pending_handshake_read_keys: Option<DirectionKeys>,
    /// The exact encoded Finished last sent. An explicit second `send Finished`
    /// is a wire replay of that message, not a newly computed Finished over a
    /// transcript which already contains the first copy.
    last_finished_framed: Option<Vec<u8>>,
    /// Values captured by `recv ClientHello { ...: capture $name }` for
    /// cross-connection freshness assertions.
    captures: Vec<(String, Vec<u8>)>,
}

#[derive(Clone)]
struct SelectedPsk {
    identity: Vec<u8>,
    secret: Vec<u8>,
    is_external: bool,
}

/// The TLS 1.3 cipher suites the harness-server implements, in
/// default preference order. Used when peer capabilities pin no suite.
const DEFAULT_TLS13_SUITES: &[u16] = &[0x1301, 0x1302, 0x1303, 0x1304, 0x1305];

/// The named groups the harness-server can select a key_share for,
/// in default preference order. X25519 first because it's the group
/// clients almost always send an actual key_share for (others are
/// typically only *listed*, needing a HelloRetryRequest we don't yet
/// generate).
const DEFAULT_TLS13_GROUPS: &[u16] = &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];

/// Map a TLS 1.3 cipher suite wire value to the (hash, AEAD) it
/// implies. Returns None for suites the driver doesn't implement.
fn tls13_suite_params(wire: u16) -> Option<(HashAlg, AeadAlg)> {
    Some(match wire {
        0x1301 => (HashAlg::Sha256, AeadAlg::Aes128Gcm),
        0x1302 => (HashAlg::Sha384, AeadAlg::Aes256Gcm),
        0x1303 => (HashAlg::Sha256, AeadAlg::ChaCha20Poly1305),
        // RFC 8446 B.4 CCM suites (RFC 6655 nonce/tag rules apply).
        0x1304 => (HashAlg::Sha256, AeadAlg::Aes128Ccm),
        0x1305 => (HashAlg::Sha256, AeadAlg::Aes128Ccm8),
        _ => return None,
    })
}

/// Map a named-group wire value to the key-exchange group the driver
/// implements, or None if unsupported.
fn ecdhe_group_from_wire(wire: u16) -> Option<EcdheGroup> {
    EcdheGroup::from_wire(wire)
}

/// The IANA wire value for a key-share group.
fn group_wire(g: EcdheGroup) -> u16 {
    g.wire_value()
}

fn capture_client_hello_field(
    ch: &crate::tls::codec::ClientHelloDecoded,
    field: &str,
) -> Result<Vec<u8>, TlsError> {
    match field {
        "random" => Ok(ch.random.to_vec()),
        "legacy_session_id" => Ok(ch.session_id.clone()),
        "key_share" => ch
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShare(entries) => {
                    entries.first().map(|entry| entry.key_exchange.clone())
                }
                Extension::KeyShareSingle(entry) => Some(entry.key_exchange.clone()),
                _ => None,
            })
            .ok_or(TlsError::Internal(
                "capture: ClientHello has no key_share value",
            )),
        _ => Err(TlsError::Internal(
            "capture: only random, legacy_session_id and key_share can be captured from a ClientHello",
        )),
    }
}

impl Tls13Server {
    pub fn new(transport: Box<dyn UutTransport>, cfg: Tls13ServerConfig) -> Self {
        Self::new_protocol(transport, cfg, false)
    }

    pub fn new_dtls13(transport: Box<dyn UutTransport>, cfg: Tls13ServerConfig) -> Self {
        Self::new_protocol(transport, cfg, true)
    }

    fn new_protocol(
        transport: Box<dyn UutTransport>,
        cfg: Tls13ServerConfig,
        dtls13: bool,
    ) -> Self {
        let chain_keys =
            crate::tls::chains::parse_chain_keys(&cfg.chains).expect("valid chain keys");
        let private_key = chain_keys.first().cloned().unwrap_or_else(|| {
            PrivateKey::from_pkcs8_der(&cfg.private_key_der).expect("valid private key PKCS#8 DER")
        });
        Self {
            cfg,
            records: if dtls13 {
                RecordLayer::new_dtls13(transport)
            } else {
                RecordLayer::new(transport, TlsVersion::Tls13)
            },
            transcript: TranscriptHash::new(HashAlg::Sha256),
            schedule: if dtls13 {
                Tls13KeySchedule::new_dtls(HashAlg::Sha256)
            } else {
                Tls13KeySchedule::new(HashAlg::Sha256)
            },
            private_key,
            chain_keys,
            server_random: [0; 32],
            client_random: [0; 32],
            client_session_id: Vec::new(),
            negotiated_suite: 0,
            hash: HashAlg::Sha256,
            aead: AeadAlg::Aes128Gcm,
            selected_group: EcdheGroup::X25519,
            client_key_share: None,
            client_key_share_group: 0,
            needs_hrr: None,
            hrr_requested_group: None,
            pre_client_finished_digest: Vec::new(),
            client_offered_cert_compression: false,
            client_pubkey: None,
            received_empty_certificate: false,
            client_offered_rpk_cert_type: false,
            client_accepts_server_rpk: false,
            negotiated_server_cert_type: crate::tls::codec::CERT_TYPE_X509,
            negotiated_client_cert_type: crate::tls::codec::CERT_TYPE_X509,
            client_sig_schemes: Vec::new(),
            requested_client_sig_schemes: Vec::new(),
            hrr_cookie: None,
            resumed: false,
            selected_identity: 0,
            selected_psk: None,
            psk_ke_only: false,
            handshake_complete: false,
            resumption_master_secret: None,
            issued_ticket: None,
            tickets_issued: 0,
            post_handshake_cert_requests_sent: 0,
            key_update_response_pending: false,
            client_offered_early_data: false,
            early_data_accepted: false,
            early_read_keys_installed: false,
            pending_handshake_read_keys: None,
            last_finished_framed: None,
            captures: Vec::new(),
        }
    }

    fn ensure_init(&mut self) {
        if self.server_random != [0; 32] {
            return;
        }
        let mut sr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"server_random"));
        self.server_random = sr_rng.random_array();
    }

    pub fn do_handshake(&mut self) -> Result<(), TlsError> {
        self.ensure_init();
        self.recv_client_hello()?;
        if self.needs_hrr.is_some() {
            // The client key-shared none of the selectable groups
            // but listed one in supported_groups — request it via
            // HelloRetryRequest and take the retry ClientHello
            // (RFC 8446 §4.1.4).
            self.send_hello_retry_request()?;
            self.recv_client_hello()?;
        }
        self.send_server_hello_and_install_hs_keys()?;
        self.send_encrypted_extensions()?;
        // A PSK-resumed handshake carries no Certificate / CertificateVerify
        // (RFC 8446 2.2): the PSK authenticates the server.
        if !self.resumed {
            self.send_certificate()?;
            self.send_certificate_verify()?;
        }
        self.send_finished_and_install_write_app_keys()?;
        self.recv_finished_and_install_read_app_keys()?;
        Ok(())
    }

    pub fn do_handshake_step(&mut self, step: &HandshakeStep) -> Result<(), TlsError> {
        use HandshakeStep as HS;
        use MessageKind as MK;
        self.ensure_init();
        match step {
            HS::Recv(MK::ClientHello) => self.recv_client_hello(),
            HS::Send(MK::HelloVerifyRequest) => self.send_legacy_hello_verify_request(),
            HS::Send(MK::HelloRetryRequest) => self.send_hello_retry_request(),
            HS::Send(MK::ServerHello) => self.send_server_hello_and_install_hs_keys(),
            HS::Send(MK::EncryptedExtensions) => self.send_encrypted_extensions(),
            HS::Send(MK::Certificate) => self.send_certificate(),
            HS::Send(MK::CompressedCertificate) => self.send_compressed_certificate(),
            HS::Send(MK::CertificateRequest) => self.send_certificate_request(),
            HS::Send(MK::CertificateVerify) => self.send_certificate_verify(),
            HS::Send(MK::Finished) => self.send_finished_and_install_write_app_keys(),
            HS::Recv(MK::Certificate) => self.recv_client_certificate(),
            HS::Recv(MK::CertificateVerify) => self.recv_client_certificate_verify(),
            HS::Recv(MK::Finished) => self.recv_finished_and_install_read_app_keys(),
            HS::Recv(MK::EndOfEarlyData) => self.recv_end_of_early_data(),
            HS::Recv(MK::Alert) => self.recv_any_alert(),
            HS::Send(MK::NewSessionTicket) => self.send_new_session_ticket(),
            // RFC 8446 D.4: a middlebox-compatibility ChangeCipherSpec (the single
            // byte 0x01, always plaintext) anywhere in the server's flight; the
            // client MUST drop it (5) -- unless it splits a handshake message (5.1).
            HS::Send(MK::ChangeCipherSpec) => {
                let ccs = crate::tls::driver::resolve_ccs_byte(&self.cfg.send_overrides)?;
                self.records
                    .write_record_with_mutations(
                        crate::tls::codec::CONTENT_TYPE_CCS,
                        &[ccs],
                        collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
                    )
                    .map_err(TlsError::from)
            }
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
                "unsupported handshake step for TLS 1.3 server",
            )),
        }
    }

    /// Read and surface an alert sent in response to an injected server
    /// message. Keeping this as a handshake step lets negative client tests
    /// distinguish a real alert from a transport close.
    fn recv_any_alert(&mut self) -> Result<(), TlsError> {
        let (content_type, body) = self.records.read_record().map_err(TlsError::Record)?;
        if content_type != crate::tls::codec::CONTENT_TYPE_ALERT || body.len() != 2 {
            return Err(TlsError::Internal(
                "expected an alert record after the injected handshake message",
            ));
        }
        Err(TlsError::Alert {
            level: body[0],
            description: body[1],
        })
    }

    /// Emit the pre-1.3 HelloVerifyRequest so a DTLS 1.3 client can be tested
    /// for rejecting it. This message is never part of a valid DTLS 1.3
    /// handshake; unlike HelloRetryRequest it deliberately does not alter the
    /// transcript or server state.
    fn send_legacy_hello_verify_request(&mut self) -> Result<(), TlsError> {
        if !self.records.is_dtls13() {
            return Err(TlsError::Internal(
                "legacy HelloVerifyRequest injection is a DTLS-only step",
            ));
        }
        let mut version = 0xfeff;
        let mut cookie = vec![0u8; 32];
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::HelloVerifyRequest) {
            match (&*ov.field, &ov.value) {
                ("legacy_version", FieldValue::U16(v)) => version = *v,
                ("cookie", FieldValue::Bytes(v)) => cookie = v.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "HelloVerifyRequest",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        if cookie.len() > u8::MAX as usize {
            return Err(TlsError::Internal(
                "HelloVerifyRequest cookie is longer than 255 bytes",
            ));
        }
        let bytes = crate::tls::dtls_handshake::encode_hello_verify_request(version, &cookie);
        // Body and header mutation stages as on every other server message:
        // `send HelloVerifyRequest @ pad +1` / `@ set[handshake.msg_type, 0]`.
        let mut fields = std::collections::HashMap::new();
        fields.insert("legacy_version".to_string(), 0..2);
        fields.insert("cookie_length".to_string(), 2..3);
        fields.insert("cookie".to_string(), 3..bytes.len());
        let encoded = crate::tls::codec::EncodedBody { bytes, fields };
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::HelloVerifyRequest);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
                .map_err(|_| TlsError::Internal("server HelloVerifyRequest mutation failed"))?;
        let mut framed = crate::tls::codec::encode_handshake(3, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, muts);
        self.records
            .write_tls13_handshake(
                &framed,
                muts,
                crate::tls::dtls_handshake::frag_scheme_for(
                    &self.cfg.send_mutations,
                    MessageKind::HelloVerifyRequest,
                ),
            )
            .map_err(TlsError::from)
    }

    // ---- post-handshake: NewSessionTicket, KeyUpdate, alerts ----

    /// Issue a NewSessionTicket (RFC 8446 4.6.1). The ticket is an opaque
    /// label (`plzn13` || hash id || counter || 16 random bytes); the PSK is
    /// HKDF-Expand-Label(resumption_master_secret, "resumption", nonce).
    /// `send NewSessionTicket { ticket_lifetime | ticket_lifetime_days |
    /// ticket_age_add | ticket_nonce | ticket }` override the fields and
    /// `+ext early_data = N` adds the ticket extension; byte mutations and
    /// header mutations apply as on every server message.
    fn send_new_session_ticket(&mut self) -> Result<(), TlsError> {
        let rms = self
            .resumption_master_secret
            .clone()
            .ok_or(TlsError::Internal(
                "NewSessionTicket before the client's Finished (RFC 8446 4.6.1)",
            ))?;
        let counter = self.tickets_issued;
        self.tickets_issued += 1;
        let nonce = counter.to_be_bytes().to_vec();
        let psk = self.schedule.derive_resumption_psk(&rms, &nonce);
        let mut rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"session_ticket"));
        let mut ticket = TICKET_MAGIC.to_vec();
        ticket.push(match self.hash {
            HashAlg::Sha384 => 1,
            _ => 0,
        });
        ticket.extend_from_slice(&nonce);
        let label: [u8; 16] = rng.random_array();
        ticket.extend_from_slice(&label);
        let age_add: [u8; 4] = rng.random_array();
        let mut nst = NewSessionTicket13 {
            ticket_lifetime: 7200,
            ticket_age_add: u32::from_be_bytes(age_add),
            ticket_nonce: nonce,
            ticket: ticket.clone(),
            extensions: Vec::new(),
        };
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::NewSessionTicket) {
            match (ov.field.as_str(), &ov.value) {
                ("ticket_lifetime", FieldValue::U16(v)) => nst.ticket_lifetime = *v as u32,
                // Hours cannot express "more than 7 days" in a u16 of seconds,
                // so a days form exists for the RFC 8446 4.6.1 bound.
                ("ticket_lifetime_days", FieldValue::U16(v)) => {
                    nst.ticket_lifetime = (*v as u32).saturating_mul(86_400)
                }
                ("ticket_age_add", FieldValue::U16(v)) => nst.ticket_age_add = *v as u32,
                ("ticket_nonce", FieldValue::Bytes(v)) => nst.ticket_nonce = v.clone(),
                ("ticket", FieldValue::Bytes(v)) => nst.ticket = v.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "NewSessionTicket",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas =
                collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::NewSessionTicket);
            apply_ext_deltas(&mut nst.extensions, deltas);
        }
        let encoded = encode_new_session_ticket_13_body_mapped(&nst);
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::NewSessionTicket);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
                .map_err(|_| TlsError::Internal("server NewSessionTicket mutation failed"))?;
        let mut framed = encode_handshake(HS_NEW_SESSION_TICKET, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, muts);
        // Post-handshake: not part of the transcript, sent under the
        // application write keys.
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::NewSessionTicket,
            &framed,
            muts,
        )?;
        let max_early_data_size = nst
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_EARLY_DATA && data.len() == 4 =>
                {
                    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
                }
                _ => None,
            })
            .unwrap_or(0);
        self.issued_ticket = Some((ticket, psk, nst.ticket_age_add, max_early_data_size));
        Ok(())
    }

    /// Read one post-handshake handshake message of `expected_type` (not
    /// hashed into the transcript, which is complete).
    fn read_post_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
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
        Ok(body)
    }

    fn rotate_read_keys(&mut self) -> Result<(), TlsError> {
        let client_ap = self
            .schedule
            .client_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client ap traffic secret missing"))?;
        let next = self.schedule.rotate_traffic_secret(&client_ap);
        let keys = self.schedule.direction_keys(&next, self.aead)?;
        self.records.install_read_keys(keys)?;
        self.schedule.client_ap_traffic_secret = Some(next);
        Ok(())
    }

    /// Apply a received KeyUpdate body (RFC 8446 4.6.3): validate
    /// request_update, rotate the read keys, remember a reciprocation debt.
    fn apply_received_key_update(&mut self, body: &[u8]) -> Result<u8, TlsError> {
        if !self.handshake_complete {
            return Err(TlsError::Internal(
                "KeyUpdate before the client's Finished (RFC 8446 4.6.3: unexpected_message)",
            ));
        }
        let request_update = decode_key_update_body(body)?;
        if request_update > 1 {
            return Err(TlsError::Internal(
                "KeyUpdate.request_update is not update_not_requested(0) or update_requested(1)",
            ));
        }
        self.rotate_read_keys()?;
        if request_update == 1 {
            self.key_update_response_pending = true;
        }
        Ok(request_update)
    }

    /// `send KeyUpdate { request_update }`: allowed once our Finished is out
    /// ("This message can be sent by either peer after it has sent a Finished
    /// message"); the write keys rotate to the next generation. Sent BEFORE our
    /// Finished (inside `flow handshake until send Finished`) it goes out under
    /// the handshake keys with no rotation -- the RFC 8446 4.6.3 violation a
    /// client must answer with unexpected_message.
    fn send_key_update_msg(&mut self, request_update: u8) -> Result<(), TlsError> {
        self.send_key_update_with_msg(request_update, &[])
    }

    /// `send KeyUpdate ... @ mutations`: body / header mutations apply before
    /// the record layer, record-level ones (`@ fragment N hold`, `record.*`)
    /// inside it -- so a held fragment goes out AFTER the key rotation below.
    fn send_key_update_with_msg(
        &mut self,
        request_update: u8,
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        let encoded = encode_key_update_body(request_update);
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            mutations,
        )
        .map_err(|_| TlsError::Internal("KeyUpdate mutation failed"))?;
        let mut framed = encode_handshake(HS_KEY_UPDATE, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, mutations);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::KeyUpdate,
            &framed,
            mutations,
        )?;
        if let Some(server_ap) = self.schedule.server_ap_traffic_secret.clone() {
            let next = self.schedule.rotate_traffic_secret(&server_ap);
            let keys = self.schedule.direction_keys(&next, self.aead)?;
            self.records.install_key_update_write_keys(keys)?;
            self.schedule.server_ap_traffic_secret = Some(next);
        }
        self.key_update_response_pending = false;
        Ok(())
    }

    /// `send Renegotiation [{ msg_type }]` from the server: a post-handshake
    /// handshake message TLS 1.3 has no use for -- a HelloRequest (0x00) by
    /// default, the TLS 1.2 way for a server to ask for a renegotiation, or any
    /// `msg_type` with an empty body. RFC 8446 4.1.2 / 4.6: a client receiving
    /// it MUST abort with unexpected_message.
    fn send_renegotiation_msg(&mut self, msg_type: Option<u8>) -> Result<(), TlsError> {
        let framed = encode_handshake(msg_type.unwrap_or(crate::tls::codec::HS_HELLO_REQUEST), &[]);
        self.records.write_record(CONTENT_TYPE_HANDSHAKE, &framed)?;
        Ok(())
    }

    /// `recv KeyUpdate [{ request_update: ... }]`: an explicit step. The
    /// reciprocation, if requested, is the test's own `send KeyUpdate`, unless
    /// application data is sent first (then it goes out automatically).
    fn recv_key_update_msg(&mut self) -> Result<(), TlsError> {
        let body = self.read_post_handshake(HS_KEY_UPDATE)?;
        let got = self.apply_received_key_update(&body)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::KeyUpdate) {
            if let ("request_update", FieldValue::Ident(want)) = (m.field.as_str(), &m.value) {
                let want_v = match want.as_str() {
                    "update_not_requested" => 0,
                    "update_requested" => 1,
                    _ => 0xff,
                };
                if want_v != got {
                    return Err(TlsError::MatcherFailed {
                        message: "KeyUpdate",
                        field: "request_update".into(),
                        expected: want.clone(),
                        observed: match got {
                            0 => "update_not_requested".into(),
                            1 => "update_requested".into(),
                            v => format!("{}", v),
                        },
                    });
                }
            }
        }
        Ok(())
    }

    pub fn write_app_data(
        &mut self,
        data: &[u8],
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        // RFC 8446 4.6.3: a KeyUpdate with update_requested that we absorbed
        // while reading must be answered "prior to sending its next
        // Application Data record".
        if self.key_update_response_pending {
            self.send_key_update_msg(0)?;
        }
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
        loop {
            match self.records.read_app_data() {
                Ok(data) => return Ok(data),
                // A peer-initiated KeyUpdate between application records:
                // rotate our read keys and keep reading (the next record is
                // under the new generation).
                Err(RecordError::KeyUpdateReceived { framed }) => {
                    if framed.len() < 4 {
                        return Err(TlsError::Internal("truncated KeyUpdate"));
                    }
                    self.apply_received_key_update(&framed[4..])?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn read_early_data(&mut self) -> Result<Vec<u8>, TlsError> {
        if !self.early_read_keys_installed {
            return Err(TlsError::Internal(
                "peer did not offer acceptable TLS 1.3 early data",
            ));
        }
        let data = self.records.read_app_data()?;
        let limit = self
            .cfg
            .resumption
            .as_ref()
            .map(|s| s.max_early_data_size as usize)
            .unwrap_or(0);
        if data.len() > limit {
            return Err(TlsError::Rejected {
                alert: 10,
                reason: format!(
                    "early data is {} bytes, exceeding ticket limit {}",
                    data.len(),
                    limit
                ),
            });
        }
        Ok(data)
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

    fn recv_client_hello(&mut self) -> Result<(), TlsError> {
        if self.hrr_requested_group.is_some() {
            return self.recv_client_hello_retry();
        }
        // Read the ClientHello but DON'T feed the transcript yet: the
        // transcript-hash algorithm depends on the cipher suite we're
        // about to select from this very message. We buffer the raw
        // bytes, select, (re)initialise the transcript for the chosen
        // hash, then feed them in.
        let header = self.records.read_handshake_bytes(4)?;
        let mut cursor = ByteCursor::new(&header);
        let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
        if msg_type != HS_CLIENT_HELLO {
            return Err(TlsError::UnexpectedHandshake {
                expected: HS_CLIENT_HELLO,
                got: msg_type,
            });
        }
        let body = self.records.read_handshake_bytes(body_len)?;
        let normalized_body = if self.records.is_dtls13() {
            crate::tls::driver::strip_dtls_legacy_cookie(&body)?
        } else {
            body.clone()
        };
        let ch = decode_client_hello_body(&normalized_body)?;

        // Enforce any `recv ClientHello { field: ... }` matchers
        // against what the UUT client actually sent.
        for matcher in &self.cfg.recv_matchers {
            if matcher.message == MessageKind::ClientHello {
                for f in &matcher.fields {
                    if let FieldValue::Capture(name) = &f.value {
                        let value = capture_client_hello_field(&ch, &f.field)?;
                        self.captures.push((name.clone(), value));
                    } else {
                        match_client_hello_field(&ch, f)?;
                    }
                }
            }
        }
        self.client_random = ch.random;
        if !self.records.is_dtls13() {
            self.records.set_tls13_ccs_allowed(true);
        }
        self.client_session_id = ch.session_id.clone();
        self.client_sig_schemes = client_signature_schemes(&ch.extensions);
        self.client_offered_early_data = ch
            .extensions
            .iter()
            .any(|ext| ext.wire_type() == crate::tls::codec::EXT_EARLY_DATA);
        // A: several chains -- the first (configured order) with a
        // CertificateVerify scheme the client listed (RFC 8446 4.4.2.2); none
        // fitting keeps the first chain, whose CertificateVerify then fails as
        // it always did.
        if self.chain_keys.len() > 1 {
            if let Some(idx) = crate::tls::chains::select_server_chain_13(
                &self.chain_keys,
                &self.client_sig_schemes,
            ) {
                self.select_chain(idx)?;
            }
        }

        // --- cooperative cipher-suite selection ---
        // Walk the server's capability set in preference order and
        // pick the first suite the client also offered.
        let suite_cap: &[u16] = if self.cfg.server_suites.is_empty() {
            DEFAULT_TLS13_SUITES
        } else {
            &self.cfg.server_suites
        };
        let chosen_suite = suite_cap
            .iter()
            .copied()
            .find(|s| tls13_suite_params(*s).is_some() && ch.cipher_suites.contains(s));
        let chosen_suite = match chosen_suite {
            Some(s) => s,
            None => {
                return Err(TlsError::SelectionUnsatisfiable {
                    reason: format!(
                        "no mutual cipher suite: server offers {:#06x?}, \
                         client offered {:#06x?}",
                        suite_cap, ch.cipher_suites
                    ),
                });
            }
        };
        self.negotiated_suite = chosen_suite;
        let (hash, aead) = tls13_suite_params(chosen_suite)
            .ok_or(TlsError::Internal("selected an unimplemented suite"))?;
        self.hash = hash;
        self.aead = aead;

        // --- cooperative group selection, two-phase ---
        // Phase 1: a group the client sent an actual key_share for
        // can be selected directly. Phase 2: a group the client
        // merely *listed* in supported_groups is still selectable,
        // but requires a HelloRetryRequest round-trip first
        // (RFC 8446 §4.1.4) — queue it in `needs_hrr`.
        let mut client_shares: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut client_listed: Vec<u16> = Vec::new();
        for ext in &ch.extensions {
            match ext {
                Extension::KeyShare(entries) => {
                    for e in entries {
                        client_shares.push((e.group, e.key_exchange.clone()));
                    }
                }
                Extension::SupportedGroups(groups) => {
                    client_listed.extend(groups.iter().copied());
                }
                // compress_certificate (RFC 8879): algorithms<2..2^8-2> is a 1-byte length
                // then 2-byte algorithm IDs. Note zlib support so send_certificate may compress.
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_COMPRESS_CERTIFICATE && !data.is_empty() =>
                {
                    self.client_offered_cert_compression = data[1..].chunks_exact(2).any(|c| {
                        u16::from_be_bytes([c[0], c[1]]) == crate::tls::codec::CERT_COMPRESSION_ZLIB
                    });
                }
                // client_certificate_type (RFC 7250): the client lists the cert types it can
                // present. Note RawPublicKey so we can select it in EncryptedExtensions.
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE =>
                {
                    if let Ok(types) = crate::tls::codec::decode_cert_type_list(data) {
                        self.client_offered_rpk_cert_type =
                            types.contains(&crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY);
                    }
                }
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE =>
                {
                    if let Ok(types) = crate::tls::codec::decode_cert_type_list(data) {
                        self.client_accepts_server_rpk =
                            types.contains(&crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY);
                    }
                }
                _ => {}
            }
        }
        // --- pre_shared_key (RFC 8446 4.2.9 / 4.2.11): resumption ---
        // Accept the offer only when it names the ticket THIS server issued
        // on the session being resumed, the suite's hash matches the ticket's,
        // and the binder verifies; anything else declines the PSK and falls
        // back to a full handshake (the client then sees no pre_shared_key in
        // the ServerHello).
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&body);
        self.transcript = TranscriptHash::new(self.hash);
        self.schedule = if self.records.is_dtls13() {
            Tls13KeySchedule::new_dtls(self.hash)
        } else {
            Tls13KeySchedule::new(self.hash)
        };
        self.resumed = false;
        self.selected_psk = None;
        self.psk_ke_only = false;
        let mut psk_modes: Vec<u8> = Vec::new();
        let mut psk_offer = None;
        for (position, ext) in ch.extensions.iter().enumerate() {
            if let Extension::Unknown { ty, data } = ext {
                if *ty == EXT_PSK_KEY_EXCHANGE_MODES {
                    psk_modes = decode_psk_key_exchange_modes(data)?;
                } else if *ty == EXT_PRE_SHARED_KEY {
                    // RFC 8446 4.2.11: pre_shared_key MUST be the final
                    // ClientHello extension and a server MUST check this before
                    // selecting a PSK. Give the mandated error instead of
                    // accidentally treating trailing extensions as binder bytes.
                    if position + 1 != ch.extensions.len() {
                        return Err(TlsError::Rejected {
                            alert: 47,
                            reason: "pre_shared_key is not the final ClientHello extension (RFC 8446 4.2.11: illegal_parameter)".into(),
                        });
                    }
                    psk_offer = Some(decode_pre_shared_key_offer(data)?);
                }
            }
        }
        if let Some(offer) = psk_offer {
            // RFC 8446 4.2.9: "If clients offer "pre_shared_key" without a
            // "psk_key_exchange_modes" extension, servers MUST abort".
            if psk_modes.is_empty() {
                return Err(TlsError::Internal(
                    "pre_shared_key offered without psk_key_exchange_modes (RFC 8446 4.2.9)",
                ));
            }
            // `send ServerHello { psk_mode: psk_ke | psk_dhe_ke }` forces the
            // mode regardless of the client's psk_key_exchange_modes (a server
            // MUST NOT do this, RFC 8446 4.2.9 -- the point is to check the
            // client aborts).
            let forced_mode = collect_overrides(&self.cfg.send_overrides, MessageKind::ServerHello)
                .iter()
                .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                    ("psk_mode", FieldValue::Ident(name)) if name == "psk_ke" => Some(true),
                    ("psk_mode", FieldValue::Ident(name)) if name == "psk_dhe_ke" => Some(false),
                    _ => None,
                });
            let mode = if forced_mode.is_some() {
                forced_mode
            } else if psk_modes.contains(&PSK_DHE_KE) {
                Some(false)
            } else if psk_modes.contains(&PSK_KE) {
                Some(true)
            } else {
                None
            };
            // The PSK the offer names: the ticket this server issued on the
            // session being resumed (its hash must match the suite's, "res
            // binder"), or the external PSK of the test's `psk { }` block
            // ("ext binder"). Any other identity is declined.
            let mut candidate: Option<(usize, Vec<u8>, bool)> = None;
            if let Some(ss) = self.cfg.resumption.clone() {
                if let Some(idx) = offer
                    .identities
                    .iter()
                    .position(|id| id.identity == ss.ticket)
                {
                    let ticket_hash_ok = ss.ticket.len() > TICKET_MAGIC.len()
                        && ss.ticket.starts_with(TICKET_MAGIC)
                        && ss.ticket[TICKET_MAGIC.len()]
                            == match self.hash {
                                HashAlg::Sha384 => 1,
                                _ => 0,
                            };
                    if ticket_hash_ok {
                        candidate = Some((idx, ss.master_secret.clone(), false));
                    }
                }
            }
            if candidate.is_none() {
                if let Some(psk) = self.cfg.psk.as_ref().filter(|p| p.is_external) {
                    if let Some(idx) = offer
                        .identities
                        .iter()
                        .position(|id| id.identity == psk.identity)
                    {
                        candidate = Some((idx, psk.secret.clone(), true));
                    }
                }
            }
            if let (Some((idx, secret, is_external)), Some(ke_only)) = (candidate, mode) {
                // Binder check over the ClientHello up to the binders list
                // (RFC 8446 4.2.11.2). A binder that does not verify is a
                // wrong key or an impersonation attempt: decrypt_error.
                let truncated = &framed[..framed.len() - offer.binders_len];
                let mut t = TranscriptHash::new(self.hash);
                t.update(truncated);
                let sched = if self.records.is_dtls13() {
                    Tls13KeySchedule::with_psk_dtls(self.hash, &secret)
                } else {
                    Tls13KeySchedule::with_psk(self.hash, &secret)
                };
                let expected = sched.compute_binder(&t.digest(), is_external);
                if offer.binders.get(idx).map(|b| b.as_slice()) != Some(expected.as_slice()) {
                    return Err(TlsError::Rejected {
                        alert: 51,
                        reason: "pre_shared_key binder does not verify (RFC 8446 4.2.11.2: decrypt_error)".into(),
                    });
                }
                self.schedule = sched;
                self.resumed = true;
                self.selected_identity = idx as u16;
                self.selected_psk = Some(SelectedPsk {
                    identity: offer.identities[idx].identity.clone(),
                    secret,
                    is_external,
                });
                self.psk_ke_only = ke_only;
            }
        }
        if !self.resumed && self.cfg.force_resumption {
            let state = self
                .cfg
                .resumption
                .as_ref()
                .filter(|state| {
                    !state.is_compatible_with(
                        if self.records.is_dtls13() {
                            crate::ir::Protocol::Dtls
                        } else {
                            crate::ir::Protocol::Tls
                        },
                        crate::tls::record::TlsVersion::Tls13,
                    )
                })
                .ok_or(TlsError::Internal(
                    "force_resumption requires incompatible captured session state",
                ))?;
            self.schedule = if self.records.is_dtls13() {
                Tls13KeySchedule::with_psk_dtls(self.hash, &state.master_secret)
            } else {
                Tls13KeySchedule::with_psk(self.hash, &state.master_secret)
            };
            self.resumed = true;
            self.selected_identity = 0;
            self.selected_psk = Some(SelectedPsk {
                identity: state.ticket.clone(),
                secret: state.master_secret.clone(),
                is_external: false,
            });
            self.psk_ke_only = false;
        }

        if self.resumed && self.psk_ke_only {
            // psk_ke: no (EC)DHE at all (RFC 8446 4.2.9), so no group to pick.
            self.transcript.update(&framed);
            self.install_early_read_keys_if_offered()?;
            return Ok(());
        }

        let group_cap: &[u16] = if self.cfg.server_groups.is_empty() {
            DEFAULT_TLS13_GROUPS
        } else {
            &self.cfg.server_groups
        };
        let selectable = || {
            group_cap
                .iter()
                .copied()
                .filter(|g| ecdhe_group_from_wire(*g).is_some())
        };
        let direct = selectable().find_map(|g| {
            client_shares
                .iter()
                .find(|(cg, _)| *cg == g)
                .map(|(_, ks)| (g, ks.clone()))
        });
        // A flow that will send a HelloRetryRequest needs a group the client
        // listed but did not key-share: RFC 8446 4.2.8 has the client abort a
        // retry for a group it already shared. Prefer such a group over a
        // usable share. When the client shared every selectable group, fall
        // through to the shared group, which is the deliberately illegal
        // retry that send_hello_retry_request describes.
        let retry_without_share = if self.cfg.force_hrr {
            selectable()
                .find(|g| client_listed.contains(g) && !client_shares.iter().any(|(cg, _)| cg == g))
        } else {
            None
        };
        let group_wire_val = match (retry_without_share, direct) {
            (Some(g), _) => {
                self.needs_hrr = Some(g);
                g
            }
            (None, Some((g, ks))) => {
                self.client_key_share = Some(ks);
                self.client_key_share_group = g;
                g
            }
            (None, None) => match selectable().find(|g| client_listed.contains(g)) {
                Some(g) => {
                    self.needs_hrr = Some(g);
                    g
                }
                None => {
                    let shared: Vec<u16> = client_shares.iter().map(|(g, _)| *g).collect();
                    return Err(TlsError::SelectionUnsatisfiable {
                        reason: format!(
                            "client neither key-shared nor listed any \
                             server-selectable group {:#06x?}; client key-shared \
                             {:#06x?}, listed {:#06x?}",
                            group_cap, shared, client_listed
                        ),
                    });
                }
            },
        };
        self.selected_group =
            ecdhe_group_from_wire(group_wire_val).expect("filtered to implemented groups");

        // Feed the buffered ClientHello now that the hash (and, for a
        // resumption, the PSK-seeded schedule) is settled.
        self.transcript.update(&framed);
        self.install_early_read_keys_if_offered()?;
        Ok(())
    }

    fn install_early_read_keys_if_offered(&mut self) -> Result<(), TlsError> {
        if !self.client_offered_early_data || !self.resumed || self.selected_identity != 0 {
            return Ok(());
        }
        let Some(session) = self.cfg.resumption.as_ref() else {
            return Ok(());
        };
        if session.max_early_data_size == 0 || session.cipher_suite != self.negotiated_suite {
            return Ok(());
        }
        let secret = self.schedule.client_early_traffic_secret(&self.transcript);
        let keys = self.schedule.direction_keys(&secret, self.aead)?;
        self.records.install_read_keys(keys)?;
        self.early_read_keys_installed = true;
        Ok(())
    }

    /// Send a HelloRetryRequest: a ServerHello with the magic random
    /// whose key_share carries only the group the client must retry
    /// with. Replaces the transcript with the synthetic message_hash
    /// construct per RFC 8446 §4.4.1.
    fn send_hello_retry_request(&mut self) -> Result<(), TlsError> {
        // The group to request: the one CH1 selection queued, or —
        // when the flow demands an HRR that selection didn't need —
        // the already-selected group. The latter is deliberately
        // illegal (requesting a group the client key-shared, RFC
        // 8446 §4.1.4) and exists for adversarial tests; overrides
        // can also rewrite the group outright.
        let group = self
            .needs_hrr
            .take()
            .unwrap_or_else(|| group_wire(self.selected_group));
        let ch1_hash = self.transcript.digest();

        let mut extensions = vec![
            Extension::SupportedVersionsSingle(if self.records.is_dtls13() {
                0xfefc
            } else {
                PROTOCOL_VERSION_TLS13
            }),
            Extension::KeyShareRetryGroup(group),
        ];
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas =
                collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::HelloRetryRequest);
            apply_ext_deltas(&mut extensions, deltas);
        }
        // RFC 8446 4.2.2: a cookie we send must come back verbatim in the
        // retry ClientHello; remember it for recv_client_hello_retry.
        self.hrr_cookie = extensions.iter().find_map(|e| match e {
            Extension::Unknown { ty, data } if *ty == EXT_COOKIE => Some(data.clone()),
            _ => None,
        });
        let mut sh = ServerHelloBuilder {
            legacy_version: if self.records.is_dtls13() {
                0xfefd
            } else {
                PROTOCOL_VERSION_TLS12
            },
            random: HRR_RANDOM,
            session_id: self.client_session_id.clone(),
            cipher_suite: self.negotiated_suite,
            compression_method: 0,
            extensions,
        };
        for ov in &self.cfg.send_overrides {
            if ov.message == MessageKind::HelloRetryRequest {
                for f in &ov.fields {
                    apply_server_hello_override(&mut sh, f)?;
                }
            }
        }
        let sent_retry_group = sh
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShareRetryGroup(group) => Some(*group),
                _ => None,
            })
            .unwrap_or(group);
        // Field-mapped + mutable like the ServerHello, so `handshake.key_share`
        // (the retry group) and the header can be targeted on an HRR too.
        let encoded = crate::tls::codec::encode_server_hello_body_mapped(&sh);
        let hrr_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::HelloRetryRequest);
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            hrr_muts,
        )
        .map_err(|_| TlsError::Internal("server HelloRetryRequest mutation failed"))?;
        let mut framed = encode_handshake(HS_SERVER_HELLO, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, hrr_muts);
        replace_transcript_for_hrr(&mut self.transcript, &ch1_hash, &framed, self.hash);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::HelloRetryRequest,
            &framed,
            hrr_muts,
        )?;
        if self.client_offered_early_data {
            self.records.clear_read_keys();
            self.early_read_keys_installed = false;
        }
        self.hrr_requested_group = Some(sent_retry_group);
        Ok(())
    }

    /// Receive the retry ClientHello that answers our
    /// HelloRetryRequest. The suite and transcript hash are already
    /// fixed by CH1; what's new is the key_share for the group we
    /// requested.
    fn recv_client_hello_retry(&mut self) -> Result<(), TlsError> {
        let requested = self
            .hrr_requested_group
            .expect("dispatched on hrr_requested_group");
        let header = self.records.read_handshake_bytes(4)?;
        let mut cursor = ByteCursor::new(&header);
        let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
        if msg_type != HS_CLIENT_HELLO {
            return Err(TlsError::UnexpectedHandshake {
                expected: HS_CLIENT_HELLO,
                got: msg_type,
            });
        }
        let body = self.records.read_handshake_bytes(body_len)?;
        let normalized_body = if self.records.is_dtls13() {
            crate::tls::driver::strip_dtls_legacy_cookie(&body)?
        } else {
            body.clone()
        };
        let ch = decode_client_hello_body(&normalized_body)?;

        // A flow may give CH2 its own matchers after sending HRR. This is
        // required for the fields RFC 8446 permits or requires to change,
        // notably removal of early_data. For older flows without a CH2 list,
        // retain the historical behavior of applying the CH1 assertions.
        let has_retry_matchers = self
            .cfg
            .recv_matchers
            .iter()
            .any(|m| m.message == MessageKind::ClientHelloRetry);
        let matcher_kind = if has_retry_matchers {
            MessageKind::ClientHelloRetry
        } else {
            MessageKind::ClientHello
        };
        for matcher in &self.cfg.recv_matchers {
            if matcher.message == matcher_kind {
                for f in &matcher.fields {
                    if let FieldValue::Capture(name) = &f.value {
                        let value = capture_client_hello_field(&ch, &f.field)?;
                        self.captures.push((name.clone(), value));
                    } else {
                        match_client_hello_field(&ch, f)?;
                    }
                }
            }
        }
        if !ch.cipher_suites.contains(&self.negotiated_suite) {
            return Err(TlsError::Internal(
                "retry ClientHello no longer offers the negotiated cipher suite",
            ));
        }
        if ch.session_id != self.client_session_id {
            return Err(TlsError::Rejected {
                alert: 47,
                reason: "retry ClientHello changed legacy_session_id (RFC 8446 4.1.2: illegal_parameter)"
                    .into(),
            });
        }
        self.client_session_id = ch.session_id.clone();
        // RFC 8446 4.2.2: "When sending the new ClientHello, the client MUST
        // copy the contents of the extension received in the HelloRetryRequest
        // into a "cookie" extension in the new ClientHello."
        if let Some(sent) = &self.hrr_cookie {
            let echoed = ch.extensions.iter().find_map(|e| match e {
                Extension::Unknown { ty, data } if *ty == EXT_COOKIE => Some(data),
                _ => None,
            });
            match echoed {
                None => {
                    return Err(TlsError::Rejected {
                        alert: 109,
                        reason: "retry ClientHello omitted the HelloRetryRequest cookie (RFC 8446 4.2.2: missing_extension)".into(),
                    })
                }
                Some(d) if d != sent => {
                    return Err(TlsError::Rejected {
                        alert: 47,
                        reason: "retry ClientHello cookie differs from the one the HelloRetryRequest sent (RFC 8446 4.2.2: illegal_parameter)".into(),
                    })
                }
                _ => {}
            }
        }

        let mut ks: Option<Vec<u8>> = None;
        for ext in &ch.extensions {
            if let Extension::KeyShare(entries) = ext {
                for e in entries {
                    if e.group == requested {
                        ks = Some(e.key_exchange.clone());
                    }
                }
            }
        }
        self.client_key_share = Some(ks.ok_or(TlsError::Internal(
            "retry ClientHello has no key_share for the group the \
             HelloRetryRequest asked for",
        ))?);
        self.client_key_share_group = requested;
        self.selected_group = ecdhe_group_from_wire(requested).ok_or(TlsError::Internal(
            "HelloRetryRequest requested a group the driver doesn't implement",
        ))?;

        // Re-evaluate the PSK selection against ClientHello2. Its identities
        // may be filtered after HRR and every binder is newly computed over
        // synthetic(CH1) || HRR || truncated(CH2) (RFC 8446 4.1.4,
        // 4.2.11.2). A server must not carry its CH1 binder decision across
        // the retry without authenticating this message too.
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&body);
        let mut psk_modes = Vec::new();
        let mut psk_offer = None;
        for (position, ext) in ch.extensions.iter().enumerate() {
            if let Extension::Unknown { ty, data } = ext {
                if *ty == EXT_PSK_KEY_EXCHANGE_MODES {
                    psk_modes = decode_psk_key_exchange_modes(data)?;
                } else if *ty == EXT_PRE_SHARED_KEY {
                    if position + 1 != ch.extensions.len() {
                        return Err(TlsError::Rejected {
                            alert: 47,
                            reason: "pre_shared_key is not the final retry ClientHello extension (RFC 8446 4.2.11: illegal_parameter)".into(),
                        });
                    }
                    psk_offer = Some(decode_pre_shared_key_offer(data)?);
                }
            }
        }
        if psk_offer.is_some() && psk_modes.is_empty() {
            return Err(TlsError::Internal(
                "pre_shared_key offered without psk_key_exchange_modes (RFC 8446 4.2.9)",
            ));
        }
        if self.resumed {
            let selected = self.selected_psk.clone().ok_or(TlsError::Internal(
                "accepted PSK has no retained key material",
            ))?;
            let candidate = psk_offer.as_ref().and_then(|offer| {
                offer
                    .identities
                    .iter()
                    .position(|identity| identity.identity == selected.identity)
                    .map(|index| (offer, index))
            });
            // HRR is only reached for psk_dhe_ke. If the retry no longer
            // offers that mode or identity, decline PSK and finish a full
            // certificate handshake instead of selecting an unoffered PSK.
            if let Some((offer, index)) = candidate.filter(|_| psk_modes.contains(&PSK_DHE_KE)) {
                let truncated = &framed[..framed.len() - offer.binders_len];
                let mut binder_transcript = self.transcript.clone();
                binder_transcript.update(truncated);
                let schedule = if self.records.is_dtls13() {
                    Tls13KeySchedule::with_psk_dtls(self.hash, &selected.secret)
                } else {
                    Tls13KeySchedule::with_psk(self.hash, &selected.secret)
                };
                let expected =
                    schedule.compute_binder(&binder_transcript.digest(), selected.is_external);
                if offer.binders.get(index).map(Vec::as_slice) != Some(expected.as_slice()) {
                    return Err(TlsError::Rejected {
                        alert: 51,
                        reason: "retry ClientHello pre_shared_key binder does not verify (RFC 8446 4.2.11.2: decrypt_error)".into(),
                    });
                }
                self.schedule = schedule;
                self.selected_identity = index as u16;
            } else {
                self.resumed = false;
                self.selected_psk = None;
                self.psk_ke_only = false;
                self.schedule = if self.records.is_dtls13() {
                    Tls13KeySchedule::new_dtls(self.hash)
                } else {
                    Tls13KeySchedule::new(self.hash)
                };
            }
        }

        // Transcript already holds synthetic(CH1) || HRR — append the complete CH2.
        self.transcript.update(&framed);
        Ok(())
    }

    fn send_server_hello_and_install_hs_keys(&mut self) -> Result<(), TlsError> {
        // Generate our ECDHE ephemeral for the selected group -- or, for an
        // ML-KEM group, encapsulate against the client's share now: the
        // ServerHello carries the ciphertext, and the secret is fixed here.
        let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"ecdh_private"));
        let leading_zeros = crate::tls::driver::collect_overrides(
            &self.cfg.send_overrides,
            MessageKind::ServerHello,
        )
        .iter()
        .find_map(|ov| match (ov.field.as_str(), &ov.value) {
            ("shared_secret_leading_zeros", crate::ir::FieldValue::U8(n)) => Some(*n as usize),
            _ => None,
        });
        let ephemeral = if let Some(n) = leading_zeros {
            if !self.selected_group.is_ffdhe() {
                return Err(TlsError::Internal(
                    "ServerHello.shared_secret_leading_zeros requires an FFDHE group",
                ));
            }
            let client_share = self.client_key_share.as_deref().ok_or(TlsError::Internal(
                "ServerHello.shared_secret_leading_zeros requires a client key share",
            ))?;
            let mut found = None;
            for attempt in 0u32..(1 << 20) {
                let label = format!("ecdh_private:lz:{}", attempt);
                let seed = Rng::sub_seed(self.cfg.seed, label.as_bytes());
                let shared = EcdhePrivate::generate(self.selected_group, &mut Rng::from_seed(seed))
                    .agree(client_share)?;
                if shared.iter().take(n).all(|b| *b == 0) {
                    found = Some(seed);
                    break;
                }
            }
            let seed = found.ok_or(TlsError::Internal(
                "ServerHello.shared_secret_leading_zeros: no private value found within 2^20 attempts",
            ))?;
            EcdhePrivate::generate(self.selected_group, &mut Rng::from_seed(seed))
        } else {
            match &self.client_key_share {
                Some(share) if self.selected_group.is_kem() => {
                    EcdhePrivate::respond(self.selected_group, share, &mut ec_rng).map_err(
                        |_| {
                            TlsError::Internal(
                                "client key_share is not a valid encapsulation key for the selected ML-KEM group",
                            )
                        },
                    )?
                }
                _ => EcdhePrivate::generate(self.selected_group, &mut ec_rng),
            }
        };
        // `send ServerHello { key_share_point: compressed | zero }` re-encodes the
        // public value; the private key stays real.
        let our_public = {
            use crate::tls::driver::{
                collect_overrides, encode_key_share_point, key_share_point_recipe,
            };
            let recipe = key_share_point_recipe(collect_overrides(
                &self.cfg.send_overrides,
                MessageKind::ServerHello,
            ))?;
            encode_key_share_point(&ephemeral, &recipe)?
        };

        // Build ServerHello with supported_versions + key_share (+ the
        // pre_shared_key selection when resuming; no key_share for psk_ke).
        let mut extensions = vec![Extension::SupportedVersionsSingle(
            if self.records.is_dtls13() {
                0xfefc
            } else {
                PROTOCOL_VERSION_TLS13
            },
        )];
        if !(self.resumed && self.psk_ke_only) {
            extensions.push(Extension::KeyShareSingle(KeyShareEntry {
                group: group_wire(self.selected_group),
                key_exchange: our_public.clone(),
            }));
        }
        if self.resumed {
            extensions.push(encode_pre_shared_key_selection(self.selected_identity));
        }
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas = collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ServerHello);
            apply_ext_deltas(&mut extensions, deltas);
        }
        let mut sh = ServerHelloBuilder {
            legacy_version: if self.records.is_dtls13() {
                0xfefd
            } else {
                PROTOCOL_VERSION_TLS12
            },
            random: self.server_random,
            session_id: self.client_session_id.clone(),
            cipher_suite: self.negotiated_suite,
            compression_method: 0,
            extensions,
        };
        // Apply any send overrides on ServerHello.
        for ov in &self.cfg.send_overrides {
            if ov.message == MessageKind::ServerHello {
                for f in &ov.fields {
                    if f.field == "shared_secret_leading_zeros" {
                        continue;
                    }
                    apply_server_hello_override(&mut sh, f)?;
                }
            }
        }
        // Field-mapped so byte mutations can target `handshake.key_share` (the
        // server's public value), `handshake.random`, etc.; then body and header
        // mutations (e.g. `@ set[handshake.msg_type, 0]` to relabel the message, so
        // a client that mis-parses a wrong-typed ServerHello is caught -- the
        // client-side wrong-message-type family).
        let encoded = crate::tls::codec::encode_server_hello_body_mapped(&sh);
        let body = encoded.bytes.clone();
        let sh_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ServerHello);
        let body = crate::tls::mutate::apply_handshake_mutations(body, &encoded, sh_muts)
            .map_err(|_| TlsError::Internal("server ServerHello mutation failed"))?;
        let mut framed = encode_handshake(HS_SERVER_HELLO, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, sh_muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::ServerHello,
            &framed,
            sh_muts,
        )?;

        // (EC)DHE agreement + handshake key installation. psk_ke replaces the
        // (EC)DHE input with Hash.length zero bytes (RFC 8446 7.1).
        let shared = if self.resumed && self.psk_ke_only {
            vec![0u8; self.hash.output_len()]
        } else {
            let client_point = self
                .client_key_share
                .take()
                .ok_or(if self.needs_hrr.is_some() {
                    TlsError::Internal(
                        "selected group has no client key_share yet — it needs a \
                     HelloRetryRequest round-trip before ServerHello (use \
                     `flow handshake` or add `send HelloRetryRequest` + a second \
                     `recv ClientHello` to the flow)",
                    )
                } else {
                    TlsError::Internal("missing client key share")
                })?;
            ephemeral.agree(&client_point)?
        };
        self.schedule
            .advance_to_handshake(&shared, &self.transcript);

        let aead = self.aead;
        let server_hs = self
            .schedule
            .server_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server hs ts missing"))?;
        let client_hs = self
            .schedule
            .client_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client hs ts missing"))?;
        let server_hs_keys = self.schedule.direction_keys(&server_hs, aead)?;
        let client_hs_keys = self.schedule.direction_keys(&client_hs, aead)?;
        self.records.install_write_keys(server_hs_keys)?;
        if self.client_offered_early_data && self.early_read_keys_installed {
            self.pending_handshake_read_keys = Some(client_hs_keys);
        } else {
            self.records.install_read_keys(client_hs_keys)?;
        }
        Ok(())
    }

    fn send_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        // Default: empty extensions. Apply deltas if any were declared
        // (e.g. `send EncryptedExtensions { +ext alpn = raw "..." }`).
        let mut extensions: Vec<Extension> = Vec::new();
        // client_certificate_type (RFC 7250): if we accept RawPublicKey client certs and the
        // client offered it, select it here so the client presents a bare SPKI. The server's
        // response is a single CertificateType byte (not a list).
        if self.cfg.accept_client_rpk && self.client_offered_rpk_cert_type {
            self.negotiated_client_cert_type = crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY;
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE,
                data: vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY],
            });
        }
        if self.cfg.offer_raw_public_key && self.client_accepts_server_rpk {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE,
                data: vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY],
            });
        }
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas =
                collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::EncryptedExtensions);
            apply_ext_deltas(&mut extensions, deltas);
        }
        self.negotiated_server_cert_type = extensions
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
        self.negotiated_client_cert_type = extensions
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
        let encoded = encode_encrypted_extensions_body_mapped(&extensions);
        // Apply body then header mutations (e.g. `@ set[handshake.msg_type, 0]` to
        // relabel the message, so a client that mis-parses a wrong-typed message is
        // caught -- the client-side wrong-message-type family).
        let ee_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::EncryptedExtensions);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, ee_muts)
                .map_err(|_| TlsError::Internal("server EncryptedExtensions mutation failed"))?;
        let mut framed = encode_handshake(HS_ENCRYPTED_EXTENSIONS, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, ee_muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::EncryptedExtensions,
            &framed,
            ee_muts,
        )?;
        let accepted_early_data = extensions
            .iter()
            .any(|ext| ext.wire_type() == crate::tls::codec::EXT_EARLY_DATA);
        self.early_data_accepted = accepted_early_data;
        if !accepted_early_data {
            if let Some(keys) = self.pending_handshake_read_keys.take() {
                self.records.install_read_keys(keys)?;
            }
        }
        Ok(())
    }

    /// A: switch to chain `idx`: the CertificateVerify signs with its key and
    /// the Certificate carries its leaf (the configured intermediates belong to
    /// the first chain only).
    fn select_chain(&mut self, idx: usize) -> Result<(), TlsError> {
        let chain = self.cfg.chains[idx].clone();
        self.private_key = self.chain_keys[idx].clone();
        self.cfg.cert_der = chain.cert_der;
        self.cfg.private_key_der = chain.key_der;
        if idx != 0 {
            self.cfg.extra_chain_der.clear();
        }
        Ok(())
    }

    fn send_certificate(&mut self) -> Result<(), TlsError> {
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
        // Present the leaf followed by any configured intermediates so the peer
        // can build a path to a trusted root.
        let rpk_leaf = if wire_certificate_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
            Some(crate::tls::crypto::certificate_spki_der(
                &self.cfg.cert_der,
            )?)
        } else {
            None
        };
        let mut chain: Vec<&[u8]> = Vec::with_capacity(1 + self.cfg.extra_chain_der.len());
        chain.push(rpk_leaf.as_deref().unwrap_or(&self.cfg.cert_der));
        if rpk_leaf.is_none() {
            for c in &self.cfg.extra_chain_der {
                chain.push(c);
            }
        }
        let mut raw_list: Option<Vec<u8>> = None;
        for ov in cert_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("entries", crate::ir::FieldValue::U16(n)) => {
                    chain = chain
                        .first()
                        .map(|c| std::iter::repeat_n(*c, *n as usize).collect())
                        .unwrap_or_default();
                }
                ("certificate_list", crate::ir::FieldValue::Bytes(bytes)) => {
                    raw_list = Some(bytes.clone());
                }
                ("certificate_type", crate::ir::FieldValue::Ident(_)) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "Certificate",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        // `send Certificate { +ext ... }` attaches extensions to the leaf entry
        // (RFC 8446 4.4.2: status_request / SCT there must answer a ClientHello
        // request; unsolicited or unknown ones are the client-side negatives).
        let mut leaf_extensions: Vec<Extension> = Vec::new();
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas = collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::Certificate);
            apply_ext_deltas(&mut leaf_extensions, deltas);
        }
        let encoded = match raw_list {
            Some(list) => {
                let mut bytes = vec![0u8];
                bytes.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
                bytes.extend_from_slice(&list);
                let mut fields = std::collections::HashMap::new();
                fields.insert("request_context_length".to_string(), 0..1);
                fields.insert("certificate_list_length".to_string(), 1..4);
                fields.insert("certificate_list".to_string(), 4..bytes.len());
                crate::tls::codec::EncodedBody { bytes, fields }
            }
            None => crate::tls::codec::encode_certificate_13_body_with_leaf_extensions_mapped(
                &chain,
                &leaf_extensions,
            ),
        };
        let cert_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate);
        // Apply body-level mutations (e.g. `@ pad +N` to append trailing data after the
        // certificate_list) then header mutations (e.g. `set[handshake.msg_type, 0]` to
        // relabel as a CompressedCertificate the client never negotiated, RFC 8879).
        let body = crate::tls::mutate::apply_handshake_mutations(
            encoded.bytes.clone(),
            &encoded,
            cert_muts,
        )
        .map_err(|_| TlsError::Internal("server Certificate mutation failed"))?;
        // RFC 8879: send a CompressedCertificate (type 25) if we are configured to compress
        // and the client advertised compress_certificate; otherwise a plain Certificate.
        let mut framed = if self.cfg.compress_certificate && self.client_offered_cert_compression {
            let compressed = crate::tls::codec::encode_compressed_certificate_13(&body);
            encode_handshake(crate::tls::codec::HS_COMPRESSED_CERTIFICATE, &compressed)
        } else {
            encode_handshake(HS_CERTIFICATE, &body)
        };
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, cert_muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::Certificate,
            &framed,
            cert_muts,
        )?;
        Ok(())
    }

    /// `send CompressedCertificate { algorithm, uncompressed_length, payload,
    /// payload_zeros, bomb, credential }` (RFC 8879 4): the server's
    /// Certificate, zlib-compressed unless a payload is given, with the
    /// algorithm label and uncompressed-length field independently mutable.
    fn send_compressed_certificate(&mut self) -> Result<(), TlsError> {
        use crate::tls::codec::{CERT_COMPRESSION_ZLIB, zlib_bomb, zlib_compress};

        let overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::CompressedCertificate);
        let none = overrides.iter().any(|o| {
            matches!(
                (o.field.as_str(), &o.value),
                ("credential", FieldValue::Ident(c)) if c == "none"
            )
        });
        let mut chain: Vec<&[u8]> = Vec::with_capacity(1 + self.cfg.extra_chain_der.len());
        if !none {
            chain.push(&self.cfg.cert_der);
            for cert in &self.cfg.extra_chain_der {
                chain.push(cert);
            }
        }
        let cert_body = crate::tls::codec::encode_certificate_13_body(&chain);
        let mut algorithm = CERT_COMPRESSION_ZLIB;
        let mut uncompressed_length: Option<u32> = None;
        let mut payload: Option<Vec<u8>> = None;
        for field in overrides {
            match (field.field.as_str(), &field.value) {
                ("algorithm", FieldValue::U16(value)) => algorithm = *value,
                ("uncompressed_length", FieldValue::U32(value)) => {
                    uncompressed_length = Some(*value)
                }
                ("payload", FieldValue::Bytes(value)) => payload = Some(value.clone()),
                ("payload_zeros", FieldValue::U32(value)) => {
                    payload = Some(vec![0; *value as usize])
                }
                ("bomb", FieldValue::U16(mib)) => payload = Some(zlib_bomb(*mib as u32)),
                ("credential", FieldValue::Ident(_)) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CompressedCertificate",
                        field: field.field.clone(),
                    });
                }
            }
        }
        let compressed = payload.unwrap_or_else(|| zlib_compress(&cert_body));
        let encoded = crate::tls::codec::encode_compressed_certificate_13_mapped(
            algorithm,
            uncompressed_length.unwrap_or(cert_body.len() as u32),
            &compressed,
        );
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::CompressedCertificate);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
                .map_err(|_| TlsError::Internal("CompressedCertificate mutation failed"))?;
        let mut framed = encode_handshake(crate::tls::codec::HS_COMPRESSED_CERTIFICATE, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::CompressedCertificate,
            &framed,
            muts,
        )?;
        Ok(())
    }

    fn send_certificate_verify(&mut self) -> Result<(), TlsError> {
        // Sign the transcript through Certificate.
        let transcript_hash = self.transcript.digest();
        let signed_input = tls13_certificate_verify_signed_input(&transcript_hash);
        // RFC 8446 4.2.3 / 4.4.3: the scheme MUST be one the client listed in
        // signature_algorithms that our key can produce (RSA keys sign with
        // RSA-PSS only; ECDSA keys with the scheme of their curve; Ed25519).
        // `algorithm` is the wire label; signing still uses a scheme this key
        // can produce. This makes unknown/GREASE and key-mismatch labels
        // expressible without asking the crypto backend to implement them.
        let cv_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::CertificateVerify);
        let forced_label =
            cv_overrides
                .iter()
                .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                    ("algorithm", FieldValue::U16(v)) => Some(*v),
                    _ => None,
                });
        let forced_signature =
            cv_overrides
                .iter()
                .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                    ("signature", FieldValue::Bytes(v)) => Some(v.clone()),
                    _ => None,
                });
        let forced_scheme = match forced_label.and_then(SignatureScheme::from_wire_value) {
            Some(scheme) if self.private_key.supports_scheme(scheme) => Some(scheme),
            Some(_) => {
                return Err(TlsError::Internal(
                    "CertificateVerify.algorithm override names a scheme this key cannot produce",
                ));
            }
            None => None,
        };
        let sig_scheme = match forced_scheme {
            Some(scheme) => scheme,
            None => self
                .private_key
                .tls13_signing_schemes()
                .iter()
                .copied()
                .find(|s| self.client_sig_schemes.contains(&s.wire_value()))
                .ok_or(TlsError::Rejected {
                    alert: 40,
                    reason: "the client's signature_algorithms lists no scheme this server key can sign with"
                        .to_string(),
                })?,
        };
        let signature = match forced_signature {
            Some(signature) => signature,
            None => self.private_key.sign(sig_scheme, &signed_input)?,
        };
        let encoded = encode_certificate_verify_13_body_mapped(
            forced_label.unwrap_or(sig_scheme.wire_value()),
            &signature,
        );
        // Apply any `send CertificateVerify @ ...` mutations so a client that fails
        // to verify the server's signature (broken server authentication) is caught.
        let cv_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateVerify);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cv_muts)
                .map_err(|_| TlsError::Internal("server CertificateVerify mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_VERIFY, &body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, cv_muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::CertificateVerify,
            &framed,
            cv_muts,
        )?;
        Ok(())
    }

    fn send_certificate_request(&mut self) -> Result<(), TlsError> {
        // Request client authentication, advertising the signature schemes
        // we can verify. The client answers with Certificate +
        // CertificateVerify before its Finished.
        let sig_algs = [
            SignatureScheme::EcdsaSecp256r1Sha256.wire_value(),
            SignatureScheme::EcdsaSecp384r1Sha384.wire_value(),
            SignatureScheme::RsaPssRsaeSha256.wire_value(),
            SignatureScheme::RsaPssRsaeSha384.wire_value(),
            SignatureScheme::RsaPssRsaeSha512.wire_value(),
            SignatureScheme::RsaPkcs1Sha256.wire_value(),
        ];
        // `send CertificateRequest { +ext / -ext ... }` edits the extension list
        // (e.g. `-ext signature_algorithms`: RFC 8446 4.3.2 makes it mandatory, so
        // the client must abort; an unknown extension it must ignore).
        let mut extensions = crate::tls::codec::certificate_request_13_extensions(
            &sig_algs,
            &self.cfg.cert_request_authorities,
        );
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas =
                collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::CertificateRequest);
            apply_ext_deltas(&mut extensions, deltas);
        }
        let request_context = if self.handshake_complete {
            self.post_handshake_cert_requests_sent = self
                .post_handshake_cert_requests_sent
                .wrapping_add(1)
                .max(1);
            self.post_handshake_cert_requests_sent
                .to_be_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        let encoded = crate::tls::codec::encode_certificate_request_13_body_with_context(
            &extensions,
            &request_context,
        );
        let cr_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateRequest);
        let body =
            crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cr_muts)
                .map_err(|_| TlsError::Internal("server CertificateRequest mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_REQUEST, &body);
        self.requested_client_sig_schemes =
            crate::tls::codec::decode_certificate_request_13_full(&body)
                .map(|cr| crate::tls::driver::cr13_signature_algorithms(&cr.extensions))
                .unwrap_or_default();
        crate::tls::mutate::apply_handshake_header_mutations(&mut framed, cr_muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::CertificateRequest,
            &framed,
            cr_muts,
        )?;
        Ok(())
    }

    fn recv_client_certificate(&mut self) -> Result<(), TlsError> {
        // The client's authentication Certificate. read_hs already folds
        // it into the transcript (needed for the CertificateVerify hash).
        let cert_body = self.read_encrypted_handshake(HS_CERTIFICATE)?;
        let cert = decode_certificate_13_body(&cert_body)?;
        let chain: Vec<&[u8]> = cert
            .entries
            .iter()
            .map(|e| e.cert_data.as_slice())
            .collect();
        crate::tls::client_auth::match_client_certificate(
            &chain,
            self.negotiated_client_cert_type,
            &self.cfg.recv_matchers,
        )?;
        self.received_empty_certificate = cert.entries.is_empty();
        self.client_pubkey = None;
        // Continue without client authentication when the client declines.
        let Some(leaf) = cert.entries.first() else {
            return Ok(());
        };
        // Decode the client leaf per the negotiated certificate type (X.509 or, when
        // client_certificate_type=RawPublicKey was selected, a bare SPKI -- RFC 7250).
        self.client_pubkey = Some(PublicKey::from_certificate_entry(
            &leaf.cert_data,
            self.negotiated_client_cert_type,
        )?);
        // Chain trust (X.509 only; a RawPublicKey has no chain): the leaf must
        // reach one of the configured anchors through the presented
        // intermediates, every certificate within its validity period.
        if self.negotiated_client_cert_type != crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY
            && !self.cfg.client_trust_anchors.is_empty()
        {
            crate::tls::client_auth::verify_client_chain(&chain, &self.cfg.client_trust_anchors)?;
        }
        Ok(())
    }

    fn recv_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        // An empty Certificate omits CertificateVerify. The preset still
        // includes this step, so leave the next handshake message unread.
        if self.received_empty_certificate {
            return Ok(());
        }
        // Snapshot the transcript *before* CertificateVerify hashes in —
        // that's the transcript hash the client signed (through its
        // Certificate).
        let transcript_for_sig = self.transcript.digest();
        let cv_body = self.read_encrypted_handshake(HS_CERTIFICATE_VERIFY)?;
        let cv = decode_certificate_verify_13_body(&cv_body)?;
        for matcher in crate::tls::driver::collect_overrides(
            &self.cfg.recv_matchers,
            MessageKind::CertificateVerify,
        ) {
            crate::tls::driver::match_certificate_verify_field(&cv, matcher)?;
        }
        let sig_scheme = SignatureScheme::from_wire_value(cv.algorithm)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm))?;
        let signed_input = tls13_client_certificate_verify_signed_input(&transcript_for_sig);
        if !self.requested_client_sig_schemes.contains(&cv.algorithm) {
            return Err(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm));
        }
        let pk = self
            .client_pubkey
            .as_ref()
            .ok_or(TlsError::Internal("client pubkey not set"))?;
        pk.verify_tls13(sig_scheme, &signed_input, &cv.signature)
            .map_err(|_| TlsError::SignatureVerificationFailed)?;
        Ok(())
    }

    fn recv_end_of_early_data(&mut self) -> Result<(), TlsError> {
        let body = self.read_encrypted_handshake(HS_END_OF_EARLY_DATA)?;
        if !body.is_empty() {
            return Err(TlsError::Rejected {
                alert: 50,
                reason: "EndOfEarlyData must have an empty body".into(),
            });
        }
        if let Some(keys) = self.pending_handshake_read_keys.take() {
            self.records.install_read_keys(keys)?;
        }
        Ok(())
    }

    fn send_finished_and_install_write_app_keys(&mut self) -> Result<(), TlsError> {
        let fin_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        if let Some(fin_framed) = self.last_finished_framed.clone() {
            return write_tls13_handshake_message(
                &mut self.records,
                &self.cfg.send_mutations,
                MessageKind::Finished,
                &fin_framed,
                fin_muts,
            );
        }

        // Server Finished: HMAC under server_handshake_traffic_secret.
        let transcript_hash = self.transcript.digest();
        let server_hs = self
            .schedule
            .server_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server hs ts missing"))?;
        let verify_data = self.schedule.compute_finished(&server_hs, &transcript_hash);
        // Apply any `send Finished @ ...` mutations so client-side rejection paths
        // (e.g. a corrupted server verify_data) can be exercised. The record is
        // sealed under the handshake write key, so corrupting the plaintext here
        // makes the client's Finished verification fail rather than the AEAD open.
        let fin_encoded = encode_finished_body_mapped(&verify_data);
        let fin_body = crate::tls::mutate::apply_handshake_mutations(
            fin_encoded.bytes.clone(),
            &fin_encoded,
            fin_muts,
        )
        .map_err(|_| TlsError::Internal("server Finished mutation failed"))?;
        let mut fin_framed = encode_handshake(HS_FINISHED, &fin_body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut fin_framed, fin_muts);
        self.last_finished_framed = Some(fin_framed.clone());
        self.transcript.update(&fin_framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::Finished,
            &fin_framed,
            fin_muts,
        )?;

        // Advance to application secrets. Per RFC 8446 §4.4.4,
        // "Upon sending Finished, the sender immediately changes
        // its write key." So we switch WRITE to server_app_ts
        // but keep READ on client_hs_ts (client hasn't sent
        // Finished yet).
        self.schedule.advance_to_application(&self.transcript);
        let aead = self.aead;
        let server_ap = self
            .schedule
            .server_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server ap ts missing"))?;
        let keys = self.schedule.direction_keys(&server_ap, aead)?;
        self.records.install_write_keys(keys)?;
        // READ stays on client_hs_ts — switched after client Finished.
        Ok(())
    }

    fn recv_finished_and_install_read_app_keys(&mut self) -> Result<(), TlsError> {
        // Client Finished is encrypted under client_hs_ts (still
        // the read key at this point).
        let fin_body = self.read_encrypted_handshake(HS_FINISHED)?;
        let got = decode_finished_body(&fin_body)?;
        crate::tls::driver::match_finished_fields(&fin_body, &self.cfg.recv_matchers)?;
        // Pre-Finished transcript for verification.
        // The read_encrypted_handshake already snapshotted it.
        let client_hs = self
            .schedule
            .client_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client hs ts missing"))?;
        let expected = self
            .schedule
            .compute_finished(&client_hs, &self.pre_client_finished_digest);
        if got != expected {
            return Err(TlsError::FinishedMismatch);
        }

        // Switch READ to client_app_ts.
        let aead = self.aead;
        let client_ap = self
            .schedule
            .client_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client ap ts missing"))?;
        let keys = self.schedule.direction_keys(&client_ap, aead)?;
        self.records.install_read_keys(keys)?;
        self.handshake_complete = true;
        self.records.set_tls13_ccs_allowed(false);
        // resumption_master_secret covers the transcript through the client's
        // Finished (RFC 8446 7.1); tickets issued from here draw on it.
        self.resumption_master_secret = Some(
            self.schedule
                .derive_resumption_master_secret(&self.transcript),
        );
        Ok(())
    }

    // ---- helpers ----

    fn read_encrypted_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        self.read_hs(expected_type)
    }

    fn read_hs(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
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
        if msg_type == HS_FINISHED {
            self.pre_client_finished_digest = self.transcript.digest();
        }
        self.transcript.update(&framed);
        Ok(body)
    }
}

impl TlsEndpoint for Tls13Server {
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
    fn recv_alert(&mut self, level: u8, code: Option<u8>) -> Result<(), TlsError> {
        crate::tls::driver::t6_expect_alert_record(&mut self.records, level, code)
    }
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        self.captures.clone()
    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        Tls13Server::do_handshake(self)
    }
    fn do_handshake_step(&mut self, step: &HandshakeStep) -> Result<(), TlsError> {
        Tls13Server::do_handshake_step(self, step)
    }
    fn write_app_data(
        &mut self,
        data: &[u8],
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        Tls13Server::write_app_data(self, data, mutations)
    }
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Tls13Server::read_app_data(self)
    }
    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError> {
        self.schedule
            .export_keying_material(label, context, length)
            .ok_or(TlsError::Internal(
                "exporter requested before the server Finished",
            ))
    }
    fn read_early_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Tls13Server::read_early_data(self)
    }
    fn close(&mut self) -> Result<(), TlsError> {
        Tls13Server::close(self)
    }
    fn close_reset(&mut self) -> Result<(), TlsError> {
        self.records
            .close_reset()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }
    fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)?;
        Tls13Server::close(self)
    }
    fn negotiated_cipher_suite(&self) -> u16 {
        Tls13Server::negotiated_cipher_suite(self)
    }
    fn negotiated_early_data_accepted(&self) -> Option<bool> {
        Some(self.early_data_accepted)
    }
    fn probe(&mut self, millis: u64) -> Result<(), TlsError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(millis);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let result = self.records.probe(remaining.as_millis().max(1) as u64);

            match result {
                Err(RecordError::KeyUpdateReceived { framed }) => {
                    self.apply_received_key_update(&framed[4..])?;
                }
                other => return other.map_err(TlsError::from),
            }
        }
    }
    fn write_raw(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.records.write_raw(data).map_err(TlsError::from)
    }
    fn advance_clock(&mut self, nanos: u64) -> Result<(), TlsError> {
        self.records
            .dtls_advance_clock(nanos)
            .map_err(TlsError::from)
    }
    fn expect_next_timeout(&mut self, nanos: Option<u64>) -> Result<(), TlsError> {
        self.records
            .dtls_expect_next_timeout(nanos)
            .map_err(TlsError::from)
    }
    fn set_timeout(&mut self, millis: u32) -> Result<(), TlsError> {
        self.records
            .dtls_set_timeout(millis)
            .map_err(TlsError::from)
    }
    fn expect_retransmit(&mut self) -> Result<(), TlsError> {
        self.records
            .dtls_expect_retransmit()
            .map_err(TlsError::from)
    }
    fn resend_flight(&mut self) -> Result<(), TlsError> {
        self.records
            .dtls_resend_last_datagram()
            .map_err(TlsError::from)
    }
    fn dtls_op(&mut self, op: &crate::ir::DtlsOp) -> Result<(), TlsError> {
        match op {
            crate::ir::DtlsOp::MapRecordSequences(map) => {
                self.records.dtls_map_record_sequences(*map);
                Ok(())
            }
            crate::ir::DtlsOp::SetMtu(mtu) => {
                self.records.dtls_set_mtu(*mtu).map_err(TlsError::from)
            }
            crate::ir::DtlsOp::ReplayFlight(n) => self
                .records
                .dtls_replay_datagram(*n)
                .map_err(TlsError::from),
            crate::ir::DtlsOp::SuppressAck => {
                self.records.dtls_suppress_ack();
                Ok(())
            }
            crate::ir::DtlsOp::SendAck {
                selection,
                outer_epoch,
                overflow_epoch,
            } => self
                .records
                .dtls_send_ack(*selection, *outer_epoch, *overflow_epoch)
                .map_err(TlsError::from),
            crate::ir::DtlsOp::ExpectAck => self.records.dtls_expect_ack().map_err(TlsError::from),
            crate::ir::DtlsOp::SendPreviousEpochFinished => {
                let framed = self
                    .last_finished_framed
                    .clone()
                    .ok_or(TlsError::Internal("no Finished has been sent"))?;
                self.records
                    .dtls_write_previous_epoch_handshake(&framed)
                    .map_err(TlsError::from)
            }
            crate::ir::DtlsOp::RetransmitPreviousEpochFinished => {
                let framed = self
                    .last_finished_framed
                    .clone()
                    .ok_or(TlsError::Internal("no Finished has been sent"))?;
                self.records
                    .dtls_retransmit_previous_epoch_handshake(&framed)
                    .map_err(TlsError::from)
            }
            _ => Err(TlsError::Internal(
                "this DTLS flight operation is not implemented for DTLS 1.3",
            )),
        }
    }
    fn send_key_update(&mut self, request_update: u8) -> Result<(), TlsError> {
        Tls13Server::send_key_update_msg(self, request_update)
    }
    fn recv_key_update(&mut self) -> Result<(), TlsError> {
        Tls13Server::recv_key_update_msg(self)
    }
    fn recv_key_update_matching(
        &mut self,
        matchers: &[crate::ir::FieldOverride],
    ) -> Result<(), TlsError> {
        self.cfg
            .recv_matchers
            .retain(|m| m.message != MessageKind::KeyUpdate);
        self.cfg.recv_matchers.push(crate::ir::MessageOverrides {
            message: MessageKind::KeyUpdate,
            fields: matchers.to_vec(),
        });
        let result = self.recv_key_update();
        self.cfg
            .recv_matchers
            .retain(|m| m.message != MessageKind::KeyUpdate);
        result
    }
    fn send_renegotiation(&mut self, msg_type: Option<u8>) -> Result<(), TlsError> {
        Tls13Server::send_renegotiation_msg(self, msg_type)
    }
    fn send_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)
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
    fn send_key_update_with(
        &mut self,
        request_update: u8,
        mutations: &[crate::ir::Mutation],
    ) -> Result<(), TlsError> {
        Tls13Server::send_key_update_with_msg(self, request_update, mutations)
    }
    fn session_state(&self) -> Option<crate::ir::SessionState> {
        let (ticket, psk, ticket_age_add, max_early_data_size) = self.issued_ticket.as_ref()?;
        Some(crate::ir::SessionState {
            protocol: if self.records.is_dtls13() {
                crate::ir::Protocol::Dtls
            } else {
                crate::ir::Protocol::Tls
            },
            version: crate::tls::record::TlsVersion::Tls13,
            ticket: ticket.clone(),
            master_secret: psk.clone(),
            session_id: self.client_session_id.clone(),
            ticket_age_add: *ticket_age_add,
            cipher_suite: self.negotiated_suite,
            max_early_data_size: *max_early_data_size,
        })
    }
    fn negotiated_resumed(&self) -> Option<bool> {
        Some(self.resumed)
    }
}

/// The client's signature_algorithms (RFC 8446 4.2.3), whether the codec
/// decoded it typed or left it opaque.
fn client_signature_schemes(exts: &[Extension]) -> Vec<u16> {
    for ext in exts {
        match ext {
            Extension::SignatureAlgorithms(v) => return v.clone(),
            Extension::Unknown { ty, data } if *ty == EXT_SIGNATURE_ALGORITHMS => {
                let mut c = ByteCursor::new(data);
                if let Ok(list) = c.u16_vec() {
                    return list
                        .chunks_exact(2)
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

#[cfg(test)]
mod selection_tests {
    use super::{ecdhe_group_from_wire, group_wire, tls13_suite_params};
    use crate::tls::codec::{GROUP_SECP256R1, GROUP_SECP384R1, GROUP_X448, GROUP_X25519};
    use crate::tls::crypto::{AeadAlg, EcdheGroup, HashAlg};

    #[test]
    fn suite_params_cover_the_three_tls13_suites() {
        assert_eq!(
            tls13_suite_params(0x1301),
            Some((HashAlg::Sha256, AeadAlg::Aes128Gcm))
        );
        assert_eq!(
            tls13_suite_params(0x1302),
            Some((HashAlg::Sha384, AeadAlg::Aes256Gcm))
        );
        assert_eq!(
            tls13_suite_params(0x1303),
            Some((HashAlg::Sha256, AeadAlg::ChaCha20Poly1305))
        );
        assert_eq!(
            tls13_suite_params(0x1304),
            Some((HashAlg::Sha256, AeadAlg::Aes128Ccm))
        );
        assert_eq!(
            tls13_suite_params(0x1305),
            Some((HashAlg::Sha256, AeadAlg::Aes128Ccm8))
        );
        // A TLS 1.2 suite / unassigned value is not a TLS 1.3 suite.
        assert_eq!(tls13_suite_params(0xc02f), None);
        assert_eq!(tls13_suite_params(0xfe00), None);
    }

    #[test]
    fn group_wire_roundtrips_for_implemented_groups() {
        for (wire, group) in [
            (GROUP_X25519, EcdheGroup::X25519),
            (GROUP_X448, EcdheGroup::X448),
            (GROUP_SECP256R1, EcdheGroup::P256),
            (GROUP_SECP384R1, EcdheGroup::P384),
            (crate::tls::codec::GROUP_SECP521R1, EcdheGroup::P521),
            (crate::tls::codec::GROUP_FFDHE2048, EcdheGroup::Ffdhe2048),
            (crate::tls::codec::GROUP_FFDHE3072, EcdheGroup::Ffdhe3072),
            (0x0102, EcdheGroup::Ffdhe4096),
            (0x0103, EcdheGroup::Ffdhe6144),
            (0x0104, EcdheGroup::Ffdhe8192),
        ] {
            assert_eq!(ecdhe_group_from_wire(wire), Some(group));
            assert_eq!(group_wire(group), wire);
        }
        // The server's implemented set matches the client's.
        for &wire in crate::ir::CLIENT_KEY_SHARE_GROUPS {
            assert!(
                ecdhe_group_from_wire(wire).is_some(),
                "group 0x{:04x}",
                wire
            );
        }
    }
}
