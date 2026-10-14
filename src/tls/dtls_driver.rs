// DTLS 1.2 endpoint for the IR runtime.
//
// `DtlsClient` implements the same `TlsEndpoint` trait the TLS drivers do, so
// DTLS tests flow through `lower -> ir::Program -> runtime::run` exactly like
// TLS. It reuses the verified DTLS substrate (dtls_record / dtls_handshake /
// dtls_transport) and the DTLS crypto helpers from `dtls_client`.
//
// Unlike the monolithic `DtlsPskClient::handshake()` engine (still driven
// directly by the Rust integration tests), this driver is STEPPED: each
// handshake message is a `do_handshake_step`, so a `.plzn` flow can send
// messages out of order, twice, or with byte-mutations, and `do_handshake()`
// runs the canonical flight sequence over the same per-message methods.
//
// Flights (RFC 6347 Fig. 1): CH1 -> [HVR -> CH2(cookie)] -> ServerHello
// [, Certificate, ServerKeyExchange], ServerHelloDone -> CKE, CCS, Finished
// (epoch 1) -> server CCS, Finished. HelloVerifyRequest is optional (OpenSSL
// without DTLSv1_listen skips it); the recv step tolerates its absence and the
// second ClientHello is suppressed when no cookie arrived, so the same sequence
// works against both shims.

use crate::ir::FieldValue;
use crate::ir::{
    DtlsOp, ExtDeltaOp, FieldOverride, HandshakeStep, MessageKind, MessageMutations,
    MessageOverrides, Mutation, SessionState,
};
use crate::tls::codec::encode_finished_body_mapped;
use crate::tls::codec::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APP_DATA, CONTENT_TYPE_CCS, CONTENT_TYPE_HANDSHAKE,
    EncodedBody, Extension, GROUP_SECP256R1, GROUP_X25519, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_CLIENT_KEY_EXCHANGE, HS_FINISHED,
    HS_HELLO_VERIFY_REQUEST, HS_NEW_SESSION_TICKET, HS_SERVER_HELLO, HS_SERVER_HELLO_DONE,
    HS_SERVER_KEY_EXCHANGE,
};
use crate::tls::codec::{
    decode_certificate_12_body, decode_dhe_server_key_exchange_body,
    decode_ecdhe_server_key_exchange_body, encode_certificate_12_body_mapped,
    encode_certificate_verify_13_body_mapped, encode_dhe_client_key_exchange_body_mapped,
    encode_ecdhe_client_key_exchange_body_mapped, encode_extensions_sequence,
    encode_rsa_client_key_exchange_body_mapped,
};
use crate::tls::crypto::{
    EcdheGroup, HashAlg, PrivateKey, PublicKey, SignatureScheme, hash, tls12_prf,
};
use crate::tls::driver::{
    KeySharePoint, collect_overrides, ecdhe_group_from_wire, key_share_point_recipe,
    validate_tls12_server_certificate_key,
};
use crate::tls::driver::{TlsEndpoint, TlsError, collect_mutations};
use crate::tls::dtls_handshake::{
    DtlsClientHello, HandshakeMessage, Reassembler, build_fragment_payloads,
    encode_dtls_client_hello_body_mapped, parse_hello_verify_request, parse_server_hello,
    transcript_bytes,
};
use crate::tls::dtls_kex::finished_verify_data_override;
use crate::tls::dtls_kex::{
    apply_dtls_client_hello_override, certificate_list_override, default_client_credential,
    parse_certificate_request_12, select_signature_scheme, verify_scheme_wires,
};
use crate::tls::dtls_record::{
    DTLS_HANDSHAKE_HEADER_LEN, DtlsHandshakeHeader, dtls12_open, dtls12_seal, encode_record,
    parse_record,
};
use crate::tls::dtls_transport::{DtlsFramer, is_timeout_error};
use crate::tls::handshake::{derive_master_secret, tls12_direction_keys};
use crate::tls::record::DirectionKeys;
use crate::transport::UutTransport;

const DTLS12_WIRE_U16: u16 = 0xFEFD;

enum Kex {
    Psk {
        identity: Vec<u8>,
        psk: Vec<u8>,
    },
    /// Certificate-authenticated: ECDHE, DHE or static RSA, decided by the
    /// suite the server selects.
    Cert,
}

pub struct DtlsClientConfig {
    pub client_random: [u8; 32],
    /// The server_name (SNI, RFC 6066 3) the ClientHello carries; empty = none.
    pub server_name: String,
    /// The suites to offer, in order (`ir::filter_suites_dtls`): the PSK
    /// family when `psk` is set, else the certificate-authenticated ones.
    pub cipher_suites: Vec<u16>,
    /// `Some((identity, secret))` = PSK; `None` = ECDHE.
    pub psk: Option<(Vec<u8>, Vec<u8>)>,
    /// supported_groups, in offer order (the group capabilities); empty =
    /// secp256r1 then x25519, the TLS 1.2 client's default.
    pub groups: Vec<u16>,
    /// signature_algorithms to advertise; empty = every scheme plzn verifies.
    pub signature_schemes: Vec<u16>,
    /// The credential to answer a CertificateRequest with (DER cert, PKCS#8
    /// key); `None` = the shims/testdata end-entity client certificate.
    pub client_cert_der: Option<Vec<u8>>,
    pub client_private_key_der: Option<Vec<u8>>,
    /// A: every client-auth credential `client_chain:` named (with two or more
    /// the CertificateRequest picks; none fitting = an empty Certificate), and
    /// whether `client_chain: []` said "no credential at all".
    pub client_credentials: Vec<crate::ir::Chain>,
    pub client_chain_none: bool,
    /// `send Msg { field: value }` overrides (ClientHello, ClientKeyExchange,
    /// Certificate, CertificateVerify).
    pub send_overrides: Vec<MessageOverrides>,
    pub send_mutations: Vec<MessageMutations>,
    /// `recv Msg { ... }` matchers (ServerHello, HelloVerifyRequest, Certificate,
    /// ServerKeyExchange, CertificateRequest).
    pub recv_matchers: Vec<MessageOverrides>,
    /// `send ClientHello { +ext / -ext ... }` deltas.
    pub send_ext_deltas: Vec<crate::ir::MessageExtDeltas>,
    /// RFC 5077 over DTLS: the ticket of a prior session to present, and that
    /// session's master secret (the abbreviated handshake derives from it).
    pub session_ticket: Option<Vec<u8>>,
    pub prior_master_secret: Option<Vec<u8>>,
    /// Offer an empty SessionTicket extension so the server issues a ticket
    /// (the initial session of a resumption test, or the `session_ticket` capability).
    pub advertise_session_ticket: bool,
}

/// One epoch's key material: the master secret (for Finished) and both
/// directions' record keys for the negotiated suite's family.
struct Keys {
    master: Vec<u8>,
    client: DirectionKeys,
    server: DirectionKeys,
}

pub struct DtlsClient {
    framer: DtlsFramer,
    kex: Kex,
    /// The ClientHello's cipher_suites, in offer order.
    offer: Vec<u16>,
    /// RFC 7366: the ClientHello (after deltas) carried encrypt_then_mac, and
    /// the server echoed it on a CBC suite.
    offered_etm: bool,
    use_etm: bool,
    /// RFC 7627: the ClientHello (after deltas) carried extended_master_secret,
    /// and the server echoed it.
    offered_ems: bool,
    use_ems: bool,
    /// With the extended master secret the master secret depends on the
    /// transcript including the ClientKeyExchange, so the premaster waits here.
    pending_premaster: Option<Vec<u8>>,
    client_random: [u8; 32],
    send_mutations: Vec<MessageMutations>,
    send_overrides: Vec<MessageOverrides>,
    recv_matchers: Vec<MessageOverrides>,
    captures: Vec<(String, Vec<u8>)>,
    send_ext_deltas: Vec<crate::ir::MessageExtDeltas>,
    /// supported_groups / signature_algorithms the ClientHello advertises.
    groups: Vec<u16>,
    signature_schemes: Vec<u16>,
    /// Client authentication: the credential, whether the server asked, the
    /// schemes its CertificateRequest listed, and whether we sent a non-empty
    /// Certificate (only then does a CertificateVerify follow).
    client_cert: Option<(Vec<u8>, Vec<u8>)>,
    client_credentials: Vec<crate::ir::Chain>,
    client_chain_none: bool,
    cert_requested: bool,
    cr_sigalgs: Vec<u16>,
    sent_client_cert: bool,
    /// `send Certificate { credential: ... }` was used: the CertificateVerify
    /// signs with `override_client_key` (None for `credential: none`, so no CV).
    credential_selected: bool,
    override_client_key: Option<Vec<u8>>,
    /// Alternate encodings of the ECDHE public value for `key_share_point`
    /// recipes (the ephemeral itself is consumed by the agreement).
    ecdhe_compressed: Option<Vec<u8>>,
    /// The DHE prime, kept for the `key_share_point` finite-field bounds.
    dhe_p: Vec<u8>,

    // Record sequence counters, one per epoch (index = epoch). Each epoch's
    // counter is independent and starts at zero (RFC 6347 4.1).
    write_seqs: Vec<u64>,
    record_sequence_map: crate::ir::DtlsSequenceMap,
    // The epoch outbound records are written under: 0 (initial handshake), 1
    // (established connection + renegotiation handshake), 2 (post-renegotiation).
    write_epoch: u16,
    // Next client handshake message_seq. Resets to 0 at each (re)handshake
    // (RFC 6347 4.2.2: "The first message each side transmits in each handshake
    // always has message_seq = 0.").
    client_next_msg_seq: u16,

    // Handshake-message transcript (DTLS whole-message form, excludes CH1+HVR).
    transcript: Vec<u8>,
    // A ClientHello whose transcript membership is not yet decided (CH1: dropped
    // if an HVR follows, committed if the ServerHello comes directly).
    pending_ch: Option<Vec<u8>>,
    first_ch_sent: bool,
    hello_template: Option<(DtlsClientHello, Vec<Extension>)>,
    // Cookie from a received HelloVerifyRequest; drives the second ClientHello.
    hvr_cookie: Option<Vec<u8>>,
    // A ServerHello received while the HVR recv step was tolerating its absence.
    stashed_server_hello: Option<HandshakeMessage>,

    // Inbound reassembly.
    reassembler: Reassembler,
    pending_handshakes: std::collections::VecDeque<HandshakeMessage>,
    pending_records: Vec<(u8, u16, u64, Vec<u8>)>, // (content_type, epoch, seq, body)
    received_record_seqs: Vec<u64>,
    received_datagram_sizes: Vec<usize>,
    // Application-data records received (`assert app_data_records == N`).
    received_app_data_records: u32,

    // Outbound datagram buffer, flushed at each flight boundary.
    outgoing: Vec<u8>,
    // The last datagram flushed, for `resend_flight` (DTLS replay tests).
    last_flushed: Option<Vec<u8>>,
    // Plaintext records of the flight being assembled, and of the last flight
    // flushed, as (content_type, epoch, payload, mutations): a retransmission
    // re-seals them under fresh record sequence numbers while preserving the
    // deliberate wire corruption requested by the scenario.
    flight_records: Vec<(u8, u16, Vec<u8>, Vec<Mutation>)>,
    last_flight_records: Vec<(u8, u16, Vec<u8>, Vec<Mutation>)>,
    // Every datagram flushed so far (`replay_flight N`).
    flight_history: Vec<Vec<u8>>,
    // A datagram set aside by `hold_flight` / `hold_retransmit`, sent by
    // `release_flight` (a delayed datagram).
    held: Option<Vec<Vec<u8>>>,
    // We sent close_notify: the peer closing afterwards is the shutdown we asked
    // for, not a failure.
    sent_close_notify: bool,

    // The SNI to send (RFC 6066 3); `-ext server_name` removes it.
    server_name: String,
    // RFC 4279 2 / RFC 5489 3.2: the psk_identity_hint a PSK-family
    // ServerKeyExchange carried (`recv ServerKeyExchange { psk_identity_hint }`).
    psk_identity_hint: Option<Vec<u8>>,

    // Captured server parameters.
    server_random: [u8; 32],
    server_ecdhe_point: Vec<u8>,
    ecdhe_group: EcdheGroup,
    ecdhe_public: Vec<u8>,
    // The server certificate's key (used for ServerKeyExchange verification,
    // and to encrypt the static-RSA premaster), the DHE ServerDHParams, and the
    // client half of the RSA / DHE exchange that goes into ClientKeyExchange.
    server_pubkey: Option<PublicKey>,
    pending_dhe: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    dhe_yc: Vec<u8>,
    rsa_encrypted_pms: Vec<u8>,

    keys: Option<Keys>,
    // Epoch-2 keys, derived during a renegotiation.
    reneg_keys: Option<Keys>,
    negotiated_suite: u16,

    // Renegotiation (RFC 5746): true while running a second handshake. The
    // previous handshake's Finished verify_data binds the renegotiation_info.
    renegotiating: bool,
    last_client_verify_data: Vec<u8>,
    last_server_verify_data: Vec<u8>,

    // RFC 5077 session tickets: what to present / whether to ask, and the
    // NewSessionTicket captured on this connection for a later session.
    session_ticket: Option<Vec<u8>>,
    prior_master_secret: Option<Vec<u8>>,
    advertise_session_ticket: bool,
    captured_ticket: Option<Vec<u8>>,
    /// Set once the post-ServerHello flight proves that the server accepted
    /// the offered ticket and entered the abbreviated handshake.
    resumed: bool,
}

impl DtlsClient {
    pub fn new(transport: Box<dyn UutTransport>, cfg: DtlsClientConfig) -> Self {
        let kex = match cfg.psk {
            Some((identity, psk)) => Kex::Psk { identity, psk },
            None => Kex::Cert,
        };
        DtlsClient {
            framer: DtlsFramer::new(transport),
            kex,
            offer: cfg.cipher_suites,
            offered_etm: false,
            use_etm: false,
            offered_ems: false,
            use_ems: false,
            pending_premaster: None,
            client_random: cfg.client_random,
            server_name: cfg.server_name,
            psk_identity_hint: None,
            send_mutations: cfg.send_mutations,
            send_overrides: cfg.send_overrides,
            send_ext_deltas: cfg.send_ext_deltas,
            recv_matchers: cfg.recv_matchers,
            captures: Vec::new(),
            groups: if cfg.groups.is_empty() {
                vec![GROUP_SECP256R1, GROUP_X25519]
            } else {
                cfg.groups
            },
            signature_schemes: if cfg.signature_schemes.is_empty() {
                verify_scheme_wires()
            } else {
                cfg.signature_schemes
            },
            client_cert: match (cfg.client_cert_der, cfg.client_private_key_der) {
                (Some(c), Some(k)) => Some((c, k)),
                _ => None,
            },
            client_credentials: cfg.client_credentials,
            client_chain_none: cfg.client_chain_none,
            cert_requested: false,
            cr_sigalgs: Vec::new(),
            sent_client_cert: false,
            credential_selected: false,
            override_client_key: None,
            ecdhe_compressed: None,
            dhe_p: Vec::new(),
            write_seqs: Vec::new(),
            record_sequence_map: crate::ir::DtlsSequenceMap::Identity,
            write_epoch: 0,
            client_next_msg_seq: 0,
            transcript: Vec::new(),
            pending_ch: None,
            first_ch_sent: false,
            hello_template: None,
            hvr_cookie: None,
            stashed_server_hello: None,
            reassembler: Reassembler::new(),
            pending_handshakes: std::collections::VecDeque::new(),
            pending_records: Vec::new(),
            received_record_seqs: Vec::new(),
            received_app_data_records: 0,
            received_datagram_sizes: Vec::new(),
            outgoing: Vec::new(),
            last_flushed: None,
            flight_records: Vec::new(),
            last_flight_records: Vec::new(),
            flight_history: Vec::new(),
            held: None,
            sent_close_notify: false,
            server_random: [0u8; 32],
            server_ecdhe_point: Vec::new(),
            ecdhe_group: EcdheGroup::P256,
            ecdhe_public: Vec::new(),
            server_pubkey: None,
            pending_dhe: None,
            dhe_yc: Vec::new(),
            rsa_encrypted_pms: Vec::new(),
            keys: None,
            reneg_keys: None,
            negotiated_suite: 0,
            renegotiating: false,
            last_client_verify_data: Vec::new(),
            last_server_verify_data: Vec::new(),
            session_ticket: cfg.session_ticket,
            prior_master_secret: cfg.prior_master_secret,
            advertise_session_ticket: cfg.advertise_session_ticket,
            captured_ticket: None,
            resumed: false,
        }
    }

    /// Next record sequence number for `epoch` (each epoch counts independently).
    fn next_write_seq(&mut self, epoch: u16) -> u64 {
        let e = epoch as usize;
        if self.write_seqs.len() <= e {
            self.write_seqs.resize(e + 1, 0);
        }
        let logical = self.write_seqs[e];
        self.write_seqs[e] = logical.wrapping_add(1);
        self.record_sequence_map.apply(logical)
    }

    /// The negotiated suite's parameters (`ir::ALL_SUITES`).
    fn suite_info(&self) -> Result<&'static crate::ir::SuiteInfo, TlsError> {
        crate::ir::suite_info(self.negotiated_suite).ok_or_else(|| {
            TlsError::Dtls(format!(
                "suite 0x{:04x} is not in plzn's catalogue",
                self.negotiated_suite
            ))
        })
    }

    /// The record keys protecting `epoch`: epoch 1 is the established
    /// connection, epoch 2 is a renegotiation. Epoch 0 is plaintext (no keys).
    fn keys_for_epoch(&self, epoch: u16) -> Option<&Keys> {
        match epoch {
            1 => self.keys.as_ref(),
            2 => self.reneg_keys.as_ref(),
            _ => None,
        }
    }

    /// Reset per-handshake state for a renegotiation (a second handshake on the
    /// live connection). The established epoch-1 keys are RETAINED -- the reneg
    /// handshake is sealed under them until its own ChangeCipherSpec activates
    /// epoch 2. The previous verify_data is kept for the RFC 5746 binding.
    fn begin_renegotiation(&mut self) {
        self.renegotiating = true;
        self.transcript.clear();
        // RFC 6347 4.2.2: message_seq restarts at 0 for each handshake.
        self.client_next_msg_seq = 0;
        // A fresh client_random / ephemeral, distinct from the initial handshake.
        self.client_random = seed_from(&self.client_random, b"dtls-client-random-reneg");
        self.server_random = [0u8; 32];
        self.server_ecdhe_point.clear();
        self.ecdhe_public.clear();
        self.server_pubkey = None;
        self.pending_dhe = None;
        self.dhe_yc.clear();
        self.dhe_p.clear();
        self.ecdhe_compressed = None;
        self.rsa_encrypted_pms.clear();
        self.cert_requested = false;
        self.cr_sigalgs.clear();
        self.sent_client_cert = false;
        self.pending_ch = None;
        self.first_ch_sent = false;
        self.hello_template = None;
        self.hvr_cookie = None;
        self.stashed_server_hello = None;
        // Inbound message_seq also restarts at 0.
        self.reassembler = Reassembler::new();
        self.pending_handshakes.clear();
        self.pending_records.clear();
        self.reneg_keys = None;
        // write_epoch stays 1: the renegotiation handshake rides under the
        // established epoch-1 keys until its CCS bumps writing to epoch 2.
    }

    /// Drive a client-initiated renegotiation: a second handshake over the live
    /// connection (RFC 5746).
    pub fn renegotiate(&mut self) -> Result<(), TlsError> {
        self.begin_renegotiation();
        self.do_handshake()
    }

    // ---- outbound ----

    fn flush(&mut self) -> Result<(), TlsError> {
        if self.outgoing.is_empty() {
            return Ok(());
        }
        let dg = std::mem::take(&mut self.outgoing);
        self.send_flight(&dg)?;
        self.last_flushed = Some(dg.clone());
        self.flight_history.push(dg);
        self.last_flight_records = std::mem::take(&mut self.flight_records);
        Ok(())
    }

    fn send_flight(&mut self, flight: &[u8]) -> Result<(), TlsError> {
        for dg in pack_records_into_datagrams(flight, 16 * 1024)? {
            self.send_datagram(&dg)?;
        }
        Ok(())
    }

    /// Seal `payload` as a record under `epoch` with the next sequence number,
    /// append it to the pending flight and remember its plaintext for a later
    /// retransmission.
    fn push_record(
        &mut self,
        content_type: u8,
        epoch: u16,
        payload: &[u8],
    ) -> Result<(), TlsError> {
        self.push_record_with_mutations(content_type, epoch, payload, &[])
    }

    /// `push_record` with the message's `record.*` mutations. This is shared by
    /// handshake, CCS, alert, and application-data sends so DTLS does not expose
    /// syntax that only happens to work on AppData.
    fn push_record_with_mutations(
        &mut self,
        content_type: u8,
        epoch: u16,
        payload: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        let seqno = self.next_write_seq(epoch);
        let rec =
            self.seal_record_with_mutations(content_type, epoch, seqno, payload, mutations)?;
        self.outgoing.extend_from_slice(&rec);
        self.flight_records
            .push((content_type, epoch, payload.to_vec(), mutations.to_vec()));
        Ok(())
    }

    /// Re-seal the last flushed flight's records under fresh sequence numbers,
    /// one encoded record per entry of `order` (all of them, in order, when
    /// `order` is None).
    fn build_retransmission(&mut self, order: Option<&[usize]>) -> Result<Vec<Vec<u8>>, TlsError> {
        let recs = self.last_flight_records.clone();
        if recs.is_empty() {
            return Err(TlsError::Dtls("no flight to retransmit".into()));
        }
        let indices: Vec<usize> = match order {
            Some(o) => o.to_vec(),
            None => (0..recs.len()).collect(),
        };
        let mut out = Vec::with_capacity(indices.len());
        for &i in &indices {
            let (ct, epoch, payload, mutations) = recs
                .get(i)
                .ok_or_else(|| {
                    TlsError::Dtls(format!(
                        "split index {} out of range ({} records)",
                        i,
                        recs.len()
                    ))
                })?
                .clone();
            let seqno = self.next_write_seq(epoch);
            out.push(self.seal_record_with_mutations(ct, epoch, seqno, &payload, &mutations)?);
        }
        Ok(out)
    }

    fn send_datagram(&mut self, dg: &[u8]) -> Result<(), TlsError> {
        self.framer
            .send_datagram(dg)
            .map_err(|e| TlsError::Dtls(format!("send datagram: {}", e)))
    }

    fn recv_datagram_traced(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let got = self.framer.recv_datagram();
        if let Ok(Some(dg)) = &got {
            self.received_datagram_sizes.push(dg.len());
        }
        got
    }

    /// `header_only_flood N`: send N header-only handshake records at far-future
    /// message_seqs (each claiming a length but carrying no body) as one datagram.
    /// A peer's reassembler must bound these pending claims so the real flight
    /// still completes (RFC 6347 4.2.3).
    fn header_only_flood(&mut self, count: usize) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        let base = self.client_next_msg_seq.wrapping_add(1000);
        let mut dg = Vec::new();
        for i in 0..count as u16 {
            let hdr = DtlsHandshakeHeader {
                msg_type: HS_CLIENT_HELLO,
                length: 4096,
                message_seq: base.wrapping_add(i),
                fragment_offset: 0,
                fragment_length: 0,
            };
            let seqno = self.next_write_seq(epoch);
            let rec = self.seal_record(CONTENT_TYPE_HANDSHAKE, epoch, seqno, &hdr.encode())?;
            dg.extend_from_slice(&rec);
        }
        self.send_datagram(&dg)
    }

    /// `large_length_fragment N`: send one header-at-a-far-future-message_seq
    /// handshake fragment whose 24-bit total-length field claims N bytes while
    /// the fragment carries a single byte at offset 0. The peer must bound the
    /// buffer a single pending claim may reserve from the announced length
    /// (RFC 6347 4.2.3; Botan "far-future fragments memory-exhaustible").
    fn large_length_fragment(&mut self, length: u32) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        let msg_seq = self.client_next_msg_seq.wrapping_add(1000);
        let hdr = DtlsHandshakeHeader {
            msg_type: HS_CLIENT_HELLO,
            length,
            message_seq: msg_seq,
            fragment_offset: 0,
            fragment_length: 1,
        };
        let mut body = hdr.encode().to_vec();
        body.push(0x00);
        let seqno = self.next_write_seq(epoch);
        let rec = self.seal_record(CONTENT_TYPE_HANDSHAKE, epoch, seqno, &body)?;
        self.send_datagram(&rec)
    }

    /// `future_seq_first`: reverse the order of the pending flight's records so
    /// higher message_seqs are delivered before lower ones; the peer must buffer
    /// them until the gap fills (RFC 6347 4.2.3). A no-op on a single-record flight.
    fn future_seq_first(&mut self) -> Result<(), TlsError> {
        if self.outgoing.is_empty() {
            return Err(TlsError::Dtls(
                "future_seq_first with nothing pending".into(),
            ));
        }
        let recs = split_records(&self.outgoing)?;
        let mut reversed = Vec::with_capacity(self.outgoing.len());
        for r in recs.into_iter().rev() {
            reversed.extend_from_slice(&r);
        }
        self.outgoing = reversed;
        Ok(())
    }

    /// Read and drop whatever the peer has in flight until it falls silent
    /// (simulated datagram loss).
    fn discard_inbound(&mut self) -> Result<(), TlsError> {
        self.framer
            .set_read_timeout(Some(std::time::Duration::from_millis(150)))
            .map_err(|e| TlsError::Dtls(format!("set read timeout: {}", e)))?;
        while let Ok(Some(_)) = self.recv_datagram_traced() {}
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        self.pending_records.clear();
        Ok(())
    }

    /// Require the peer to say nothing for `millis` (a partial flight must not
    /// draw a response).
    fn expect_silence(&mut self, millis: u64) -> Result<(), TlsError> {
        self.framer
            .set_read_timeout(Some(std::time::Duration::from_millis(millis)))
            .map_err(|e| TlsError::Dtls(format!("set read timeout: {}", e)))?;
        let got = self.recv_datagram_traced();
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        match got {
            Ok(Some(dg)) => {
                if let Some((level, description)) = self.alert_in_datagram(&dg) {
                    return Err(TlsError::Alert { level, description });
                }
                Err(TlsError::Dtls("peer responded to a partial flight".into()))
            }
            Ok(None) => Ok(()),
            Err(error)
                if is_timeout_error(&error)
                    || matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
            {
                Ok(())
            }
            Err(error) => Err(TlsError::Dtls(format!(
                "error while checking for DTLS silence: {}",
                error
            ))),
        }
    }

    /// Forget the association and start a fresh one at epoch 0 over the same
    /// connection (RFC 6347 4.2.8: a new client on the same 5-tuple).
    fn restart(&mut self) {
        self.write_seqs.clear();
        self.write_epoch = 0;
        self.client_next_msg_seq = 0;
        self.transcript.clear();
        self.pending_ch = None;
        self.first_ch_sent = false;
        self.hello_template = None;
        self.hvr_cookie = None;
        self.stashed_server_hello = None;
        self.reassembler = Reassembler::new();
        self.pending_handshakes.clear();
        self.pending_records.clear();
        self.outgoing.clear();
        self.flight_records.clear();
        self.last_flight_records.clear();
        self.held = None;
        self.server_random = [0u8; 32];
        self.server_ecdhe_point.clear();
        self.ecdhe_public.clear();
        self.server_pubkey = None;
        self.pending_dhe = None;
        self.dhe_yc.clear();
        self.dhe_p.clear();
        self.ecdhe_compressed = None;
        self.rsa_encrypted_pms.clear();
        self.cert_requested = false;
        self.cr_sigalgs.clear();
        self.sent_client_cert = false;
        self.keys = None;
        self.reneg_keys = None;
        self.negotiated_suite = 0;
        self.resumed = false;
        self.renegotiating = false;
        self.last_client_verify_data.clear();
        self.last_server_verify_data.clear();
        self.client_random = seed_from(&self.client_random, b"dtls-client-random-restart");
    }

    fn expect_retransmit_impl(&mut self, no_ccs: bool) -> Result<(), TlsError> {
        // Read the peer's resent flight (give its timer time to fire). Its
        // records are duplicates of ones already reassembled, so they are
        // asserted-and-discarded rather than fed back to the reassembler.
        self.framer
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .map_err(|e| TlsError::Dtls(format!("set read timeout: {}", e)))?;
        let dg = self.recv_datagram_traced();
        let mut dg = match dg {
            Ok(Some(d)) => d,
            Ok(None) => {
                return Err(TlsError::Dtls(
                    "peer closed instead of retransmitting".into(),
                ));
            }
            Err(e) => {
                return Err(TlsError::Dtls(format!(
                    "no retransmit within timeout: {}",
                    e
                )));
            }
        };
        // The rest of the flight (a shim may send one datagram per record).
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_millis(100)));
        while let Ok(Some(more)) = self.recv_datagram_traced() {
            dg.extend_from_slice(&more);
        }
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut off = 0;
        let mut saw_handshake = false;
        while off < dg.len() {
            let (hdr, _body, consumed) = parse_record(&dg[off..])
                .map_err(|e| TlsError::Dtls(format!("bad retransmit record: {:?}", e)))?;
            self.received_record_seqs
                .push(((hdr.epoch as u64) << 48) | (hdr.sequence_number & 0x0000_FFFF_FFFF_FFFF));
            if hdr.content_type == CONTENT_TYPE_APP_DATA {
                self.received_app_data_records = self.received_app_data_records.saturating_add(1);
            }
            if hdr.content_type == CONTENT_TYPE_HANDSHAKE {
                saw_handshake = true;
            }
            if no_ccs && hdr.content_type == CONTENT_TYPE_CCS {
                return Err(TlsError::Dtls(
                    "retransmitted flight carried a ChangeCipherSpec".into(),
                ));
            }
            off += consumed;
        }
        if !saw_handshake {
            return Err(TlsError::Dtls(
                "retransmit carried no handshake records".into(),
            ));
        }
        Ok(())
    }

    /// Apply the flow's byte-mutations for `kind` to a mapped body, so structured
    /// paths (`handshake.random`, `handshake.ecdh_point`, ...) resolve like they
    /// do on the TLS drivers; an unmapped body takes offsets only.
    fn mutate_encoded(&self, kind: MessageKind, encoded: EncodedBody) -> Result<Vec<u8>, TlsError> {
        let muts = collect_mutations(&self.send_mutations, kind);
        if muts.is_empty() {
            return Ok(encoded.bytes);
        }
        crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|e| TlsError::Dtls(format!("mutation: {}", e)))
    }

    /// Frame a plaintext handshake message (epoch 0) into the outbound buffer,
    /// after applying any byte-mutations. Returns the post-mutation body.
    /// Encode an outbound record: plaintext at epoch 0, AEAD-sealed under the
    /// client write key at epoch >= 1 (a renegotiation handshake rides under the
    /// established epoch-1 keys).
    fn seal_record(
        &self,
        content_type: u8,
        epoch: u16,
        seq: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if epoch == 0 {
            return Ok(encode_record(content_type, 0, seq, payload));
        }
        let k = self
            .keys_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to seal", epoch)))?;
        let sealed = dtls12_seal(&k.client, content_type, epoch, seq, payload)
            .map_err(|e| TlsError::Dtls(format!("seal: {}", e)))?;
        Ok(encode_record(content_type, epoch, seq, &sealed))
    }

    /// `seal_record` with `record.*` byte mutations (application data under a
    /// tampered MAC / tag: RFC 6347 4.1.2.7 says the peer discards it).
    fn seal_record_with_mutations(
        &self,
        content_type: u8,
        epoch: u16,
        seq: u64,
        payload: &[u8],
        mutations: &[Mutation],
    ) -> Result<Vec<u8>, TlsError> {
        if mutations.is_empty() {
            return self.seal_record(content_type, epoch, seq, payload);
        }
        if epoch == 0 {
            let mut record = encode_record(content_type, epoch, seq, payload);
            crate::tls::mutate::apply_record_mutations(
                &mut record,
                crate::tls::dtls_record::DTLS_RECORD_HEADER_LEN,
                payload.len(),
                false,
                0,
                mutations,
            )
            .map_err(|e| TlsError::Dtls(format!("record mutation: {}", e)))?;
            return Ok(record);
        }
        let k = self
            .keys_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to seal", epoch)))?;
        let sealed = crate::tls::dtls_record::dtls12_seal_with_mutations(
            &k.client,
            content_type,
            epoch,
            seq,
            payload,
            mutations,
        )
        .map_err(|e| TlsError::Dtls(format!("seal: {}", e)))?;
        let mut record = encode_record(content_type, epoch, seq, &sealed);
        crate::tls::dtls_record::apply_dtls_record_mutations(
            &mut record,
            payload.len(),
            &k.client,
            mutations,
        )
        .map_err(|e| TlsError::Dtls(format!("record mutation: {}", e)))?;
        Ok(record)
    }

    /// Recover a handshake record's plaintext: verbatim at epoch 0, AEAD-opened
    /// under the server write key at epoch >= 1.
    fn open_handshake_record(
        &self,
        epoch: u16,
        seq: u64,
        body: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if epoch == 0 {
            return Ok(body.to_vec());
        }
        let k = self
            .keys_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to open", epoch)))?;
        dtls12_open(&k.server, CONTENT_TYPE_HANDSHAKE, epoch, seq, body).map_err(|e| match e {
            crate::tls::record::RecordError::Crypto(
                crate::tls::crypto::CryptoError::AeadOpenFailed,
            ) => TlsError::Rejected {
                alert: 20,
                reason: "peer record authentication failed".to_string(),
            },
            _ => TlsError::Dtls(format!("open handshake: {}", e)),
        })
    }

    /// `emit_handshake` for a body whose encoder produced a field map: every
    /// DTLS client message goes through here, so `@ xor[handshake.<field>, i]`
    /// resolves on the hellos, key exchanges, Certificate and CertificateVerify
    /// as well as Finished.
    fn emit_encoded(
        &mut self,
        msg_type: u8,
        seq: u16,
        encoded: EncodedBody,
        kind: MessageKind,
    ) -> Result<Vec<u8>, TlsError> {
        let body = self.mutate_encoded(kind, encoded)?;
        let mutations = collect_mutations(&self.send_mutations, kind).to_vec();
        let epoch = self.write_epoch;
        for fragment in build_fragment_payloads(&self.send_mutations, kind, msg_type, seq, &body) {
            self.push_record_with_mutations(CONTENT_TYPE_HANDSHAKE, epoch, &fragment, &mutations)?;
        }
        Ok(body)
    }

    fn add_to_transcript(&mut self, msg_type: u8, seq: u16, body: &[u8]) {
        self.transcript
            .extend_from_slice(&transcript_bytes(&HandshakeMessage {
                msg_type,
                message_seq: seq,
                body: body.to_vec(),
            }));
    }

    fn client_hello_body(&mut self, cookie: &[u8]) -> Result<EncodedBody, TlsError> {
        // server_name first (RFC 6066 3), like the TLS 1.2 client; `-ext
        // server_name` removes it. The certificate families advertise groups,
        // point formats and signature schemes (RFC 8422 5.1, RFC 5246
        // 7.4.1.4.1); plain PSK needs none of those, ECDHE_PSK (RFC 5489 3.1)
        // the groups and point formats so the server can pick a curve.
        let mut list: Vec<Extension> = Vec::new();
        if !self.server_name.is_empty() {
            list.push(Extension::ServerName(self.server_name.clone()));
        }
        let offers_ecdhe_psk = self.offer.iter().any(|w| {
            crate::ir::suite_info(*w).is_some_and(|s| s.kex == crate::ir::KexType::EcdhePsk)
        });
        match self.kex {
            Kex::Psk { .. } if offers_ecdhe_psk => {
                list.push(Extension::SupportedGroups(self.groups.clone()));
                list.push(Extension::EcPointFormats(vec![0]));
            }
            Kex::Psk { .. } => {}
            Kex::Cert => {
                list.push(Extension::SupportedGroups(self.groups.clone()));
                list.push(Extension::EcPointFormats(vec![0]));
                list.push(Extension::SignatureAlgorithms(
                    self.signature_schemes.clone(),
                ));
            }
        }
        // RFC 7627; `-ext extended_master_secret` removes it.
        list.push(Extension::ExtendedMasterSecret);
        // renegotiation_info (RFC 5746): empty on the initial handshake (the
        // secure-renegotiation signal a server needs to later allow a reneg), the
        // saved client_verify_data on a renegotiation ClientHello.
        list.push(Extension::RenegotiationInfo(
            self.last_client_verify_data.clone(),
        ));
        // RFC 5077: a ticket presents the session to resume; an empty extension
        // asks the server to issue one.
        if let Some(ticket) = &self.session_ticket {
            list.push(Extension::SessionTicket(ticket.clone()));
        } else if self.advertise_session_ticket {
            list.push(Extension::SessionTicket(Vec::new()));
        }
        // `send ClientHello { +ext / -ext ... }` edits the typed list.
        let deltas = crate::tls::driver::collect_ext_deltas(
            &self.send_ext_deltas,
            crate::ir::MessageKind::ClientHello,
        );
        crate::tls::driver::apply_ext_deltas(&mut list, deltas);
        let mut ch = DtlsClientHello {
            client_version: DTLS12_WIRE_U16,
            random: self.client_random,
            session_id: vec![],
            cookie: cookie.to_vec(),
            cipher_suites: self.offer.clone(),
            compression_methods: vec![0x00],
            extensions: encode_extensions_sequence(&list),
        };
        if !cookie.is_empty() {
            if let Some((template, original_extensions)) = &self.hello_template {
                ch = template.clone();
                ch.cookie = cookie.to_vec();
                // Preserve even deliberately malformed extension bodies. Do not
                // decode our own negative-test bytes with the strict peer decoder.
                let mut extensions = original_extensions.clone();
                crate::tls::driver::apply_ext_deltas(&mut extensions, deltas);
                ch.extensions = encode_extensions_sequence(&extensions);
            }
        }
        // `send ClientHello { field: value }` overrides, applied last. A
        // `random` override is the random the handshake then runs with (the
        // ServerKeyExchange signature and the PRF both take it).
        for ov in collect_overrides(&self.send_overrides, MessageKind::ClientHello) {
            apply_dtls_client_hello_override(&mut ch, ov)?;
        }
        self.client_random = ch.random;
        if !self.first_ch_sent {
            self.hello_template = Some((ch.clone(), list));
        }
        Ok(encode_dtls_client_hello_body_mapped(&ch))
    }

    /// Whether the ClientHello (after extension deltas) offers RFC 7366
    /// encrypt_then_mac: decided from the encoded hello so a `+ext` delta counts.
    fn hello_offers_etm(&self, body: &[u8]) -> bool {
        crate::tls::dtls_handshake::parse_dtls_client_hello(body)
            .map(|f| f.use_etm)
            .unwrap_or(false)
    }

    /// Whether the ClientHello (after extension deltas) offers RFC 7627
    /// extended_master_secret.
    fn hello_offers_ems(&self, body: &[u8]) -> bool {
        crate::tls::dtls_handshake::parse_dtls_client_hello(body)
            .map(|f| f.use_ems)
            .unwrap_or(false)
    }

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        if !self.first_ch_sent {
            // CH1: no cookie, message_seq 0. Not committed to the transcript
            // until we learn whether the server demands a cookie exchange.
            let seq = self.client_next_msg_seq;
            let encoded = self.client_hello_body(&[])?;
            self.offered_etm = self.hello_offers_etm(&encoded.bytes);
            self.offered_ems = self.hello_offers_ems(&encoded.bytes);
            let body =
                self.emit_encoded(HS_CLIENT_HELLO, seq, encoded, MessageKind::ClientHello)?;
            self.pending_ch = Some(transcript_bytes(&HandshakeMessage {
                msg_type: HS_CLIENT_HELLO,
                message_seq: seq,
                body,
            }));
            self.first_ch_sent = true;
            self.client_next_msg_seq += 1;
            return Ok(());
        }
        // A subsequent ClientHello only makes sense after an HVR: echo its cookie
        // (CH2). If the server skipped the cookie exchange, suppress it so the
        // same flow works against both shims.
        let cookie = match &self.hvr_cookie {
            Some(c) if !c.is_empty() => c.clone(),
            _ => return Ok(()),
        };
        let seq = self.client_next_msg_seq;
        let encoded = self.client_hello_body(&cookie)?;
        self.offered_etm = self.hello_offers_etm(&encoded.bytes);
        self.offered_ems = self.hello_offers_ems(&encoded.bytes);
        let body = self.emit_encoded(HS_CLIENT_HELLO, seq, encoded, MessageKind::ClientHello)?;
        // Hold the cookie ClientHello aside instead of committing it: only the
        // ClientHello the server ACCEPTS enters the transcript (RFC 6347 4.2.1).
        // If this one draws another HelloVerifyRequest -- a stale cookie after a
        // `rotate_cookie_secret` -- `recv_rechallenge_hvr` discards it; otherwise
        // `recv_server_hello` commits it. This matches CH1's held handling and is
        // transcript-equivalent to committing it now in the common single-cookie
        // flow (nothing precedes it in the transcript).
        self.pending_ch = Some(transcript_bytes(&HandshakeMessage {
            msg_type: HS_CLIENT_HELLO,
            message_seq: seq,
            body,
        }));
        self.client_next_msg_seq += 1;
        Ok(())
    }

    fn derive_keys(&mut self) -> Result<(), TlsError> {
        // A renegotiation derives a fresh key set for epoch 2; the initial
        // handshake for epoch 1.
        let reneg = self.renegotiating;
        if (reneg && self.reneg_keys.is_some())
            || (!reneg && self.keys.is_some())
            || self.pending_premaster.is_some()
        {
            return Ok(());
        }
        let psk_secret: Option<Vec<u8>> = match &self.kex {
            Kex::Psk { psk, .. } => Some(psk.clone()),
            Kex::Cert => None,
        };
        let premaster = match psk_secret {
            // RFC 5489 3.4: the ECDHE_PSK premaster mixes the ECDH shared secret
            // with the key; RFC 4279 2: plain PSK pads the other_secret with
            // zeros of the key's length.
            Some(psk) if self.suite_info()?.kex == crate::ir::KexType::EcdhePsk => {
                let z = self.ecdhe_shared_secret()?;
                crate::tls::kex12::psk_premaster_with(&z, &psk)
            }
            Some(psk) => psk_premaster(&psk),
            None => match self.suite_info()?.kex {
                crate::ir::KexType::Rsa => {
                    // RFC 6347 4.1: the premaster carries the DTLS client_version.
                    let (pms, encrypted) = {
                        let pk = self.server_pubkey.as_ref().ok_or(TlsError::Dtls(
                            "RSA key exchange: no server certificate key captured".into(),
                        ))?;
                        crate::tls::kex12::rsa_client_premaster(
                            pk,
                            DTLS12_WIRE_U16,
                            seed_from(&self.client_random, b"dtls-rsa-pms"),
                        )?
                    };
                    self.rsa_encrypted_pms = encrypted;
                    pms
                }
                crate::ir::KexType::DheRsa => {
                    let (p, g, ys) = self.pending_dhe.take().ok_or(TlsError::Dtls(
                        "DHE ClientKeyExchange before ServerKeyExchange".into(),
                    ))?;
                    let (yc, pms) = crate::tls::kex12::dhe_client_premaster(
                        &p,
                        &g,
                        &ys,
                        seed_from(&self.client_random, b"dtls-dhe"),
                    )?;
                    self.dhe_yc = yc;
                    self.dhe_p = p;
                    pms
                }
                _ => self.ecdhe_shared_secret()?,
            },
        };
        // RFC 7627 4: the extended master secret covers the transcript up to
        // and including the ClientKeyExchange, see finish_ems_keys.
        if self.use_ems {
            self.pending_premaster = Some(premaster);
            return Ok(());
        }
        let suite = self.suite_info()?;
        let master = derive_master_secret(
            suite.prf,
            &premaster,
            &self.client_random,
            &self.server_random,
        );
        self.install_keys(master)
    }

    /// The extended master secret (RFC 7627 4), once the ClientKeyExchange
    /// entered the transcript.
    fn finish_ems_keys(&mut self) -> Result<(), TlsError> {
        let Some(premaster) = self.pending_premaster.take() else {
            return Ok(());
        };
        let suite = self.suite_info()?;
        let session_hash = crate::tls::crypto::hash(suite.prf, &self.transcript);
        let master =
            crate::tls::handshake::derive_master_secret_ems(suite.prf, &premaster, &session_hash);
        self.install_keys(master)
    }

    fn install_keys(&mut self, master: Vec<u8>) -> Result<(), TlsError> {
        let reneg = self.renegotiating;
        let suite = self.suite_info()?;
        let (client, server) = tls12_direction_keys(
            suite,
            &master,
            &self.server_random,
            &self.client_random,
            self.use_etm,
        )
        .map_err(|e| TlsError::Dtls(e.to_string()))?;
        let derived = Keys {
            master,
            client,
            server,
        };
        if reneg {
            self.reneg_keys = Some(derived);
        } else {
            self.keys = Some(derived);
        }
        Ok(())
    }

    /// The ECDH agreement for the ECDHE and ECDHE_PSK families: a fresh
    /// ephemeral for the group the server named, its public value kept for the
    /// ClientKeyExchange, the shared secret returned.
    fn ecdhe_shared_secret(&mut self) -> Result<Vec<u8>, TlsError> {
        if self.server_ecdhe_point.is_empty() {
            return Err(TlsError::Dtls(
                "ECDHE ClientKeyExchange before ServerKeyExchange".into(),
            ));
        }
        let mut rng =
            crate::tls::crypto::Rng::from_seed(seed_from(&self.client_random, b"dtls-ecdhe"));
        let sk = crate::tls::crypto::EcdhePrivate::generate(self.ecdhe_group, &mut rng);
        self.ecdhe_public = sk.public_bytes();
        self.ecdhe_compressed = sk.public_bytes_compressed();
        sk.agree(&self.server_ecdhe_point)
            .map_err(|e| TlsError::Dtls(format!("ECDH agree: {}", e)))
    }

    /// The PSK-family ClientKeyExchange (RFC 4279 2 / RFC 5489 3.3): the
    /// identity (`send ClientKeyExchange { psk_identity: ... }` overrides it
    /// for the unknown-identity negative), plus the client's ECDH point for
    /// ECDHE_PSK, where the `key_share_point` recipes and `ecdh_Yc` apply.
    fn psk_client_key_exchange_body(&self, identity: &[u8]) -> Result<EncodedBody, TlsError> {
        let overrides = collect_overrides(&self.send_overrides, MessageKind::ClientKeyExchange);
        let ecdhe = self.suite_info()?.kex == crate::ir::KexType::EcdhePsk;
        let mut identity = identity.to_vec();
        let mut point = if ecdhe {
            Some(self.ecdhe_public_with_recipe(overrides)?)
        } else {
            None
        };
        for ov in overrides {
            match (ov.field.as_str(), &ov.value) {
                ("psk_identity", FieldValue::Bytes(v)) => identity = v.clone(),
                ("ecdh_Yc", FieldValue::Bytes(v)) if ecdhe => point = Some(v.clone()),
                ("key_share_point", _) if ecdhe => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ClientKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        Ok(crate::tls::kex12::encode_psk_cke_mapped(
            &identity,
            point.as_deref(),
        ))
    }

    /// The client's ECDH public value under a `key_share_point` recipe
    /// (`zero`, `truncated`, `padded`, `compressed`; `one` / `p_minus_1` are
    /// finite-field bounds and a lint error here).
    fn ecdhe_public_with_recipe(
        &self,
        overrides: &[crate::ir::FieldOverride],
    ) -> Result<Vec<u8>, TlsError> {
        Ok(match key_share_point_recipe(overrides)? {
            KeySharePoint::Real => self.ecdhe_public.clone(),
            KeySharePoint::Compressed => self
                .ecdhe_compressed
                .clone()
                .ok_or(TlsError::Internal(
                "key_share_point: compressed has no meaning for x25519/x448 (RFC 7748 u-coordinate); \
                 use a NIST group",
            ))?,
            KeySharePoint::Zero => vec![0u8; self.ecdhe_public.len()],
            KeySharePoint::Truncated => {
                let mut p = self.ecdhe_public.clone();
                p.pop();
                p
            }
            KeySharePoint::Padded => {
                let mut p = self.ecdhe_public.clone();
                p.push(0);
                p
            }
            KeySharePoint::AllOnes => vec![0xffu8; self.ecdhe_public.len()],
            KeySharePoint::Empty => Vec::new(),
            KeySharePoint::Raw(b) => b,
            KeySharePoint::OtherGroup(g) => {
                let seed = crate::tls::crypto::Rng::sub_seed([0u8; 32], &self.ecdhe_public);
                crate::tls::crypto::EcdhePrivate::generate(
                    g,
                    &mut crate::tls::crypto::Rng::from_seed(seed),
                )
                .public_bytes()
            }
            _ => return Err(TlsError::Internal(
                "key_share_point: `one` / `p_minus_1` / `p` are finite-field bounds (use a DHE \
                     suite) and `hybrid` needs a prime curve",
            )),
        })
    }

    fn send_client_key_exchange(&mut self) -> Result<(), TlsError> {
        self.derive_keys()?;
        let seq = self.client_next_msg_seq;
        let cke = match &self.kex {
            Kex::Psk { identity, .. } => self.psk_client_key_exchange_body(identity)?,
            Kex::Cert => self.cert_client_key_exchange_body()?,
        };
        let body = self.emit_encoded(
            HS_CLIENT_KEY_EXCHANGE,
            seq,
            cke,
            MessageKind::ClientKeyExchange,
        )?;
        self.add_to_transcript(HS_CLIENT_KEY_EXCHANGE, seq, &body);
        self.client_next_msg_seq += 1;
        self.finish_ems_keys()
    }

    /// The certificate families' ClientKeyExchange body, with the `send
    /// ClientKeyExchange { ... }` overrides the TLS 1.2 client takes: a
    /// `key_share_point` recipe (zero / truncated / padded / compressed for a
    /// curve, zero / one / p_minus_1 for DHE), an explicit `ecdh_Yc` / `dh_Yc`,
    /// or an `encrypted_premaster` replacement for static RSA. The agreement
    /// keeps using the real key, so the server's rejection (or its failure at
    /// Finished) is what the test observes.
    fn cert_client_key_exchange_body(&self) -> Result<EncodedBody, TlsError> {
        let overrides = collect_overrides(&self.send_overrides, MessageKind::ClientKeyExchange);
        let recipe = key_share_point_recipe(overrides)?;
        match self.suite_info()?.kex {
            crate::ir::KexType::Rsa => {
                let mut enc = self.rsa_encrypted_pms.clone();
                for ov in overrides {
                    match (ov.field.as_str(), &ov.value) {
                        ("encrypted_premaster", FieldValue::Bytes(v)) => enc = v.clone(),
                        // A chosen plaintext premaster (wrong version bytes, wrong
                        // length), PKCS#1 v1.5-encrypted under the server's key.
                        ("premaster_secret", FieldValue::Bytes(v)) => {
                            let pk = self.server_pubkey.as_ref().ok_or(TlsError::Dtls(
                                "premaster_secret override before the server Certificate".into(),
                            ))?;
                            enc = crate::tls::crypto::rsa_pkcs1v15_encrypt(pk, v)?;
                        }
                        ("key_share_point", _) => {}
                        _ => {
                            return Err(TlsError::UnknownFieldOverride {
                                message: "ClientKeyExchange",
                                field: ov.field.clone(),
                            });
                        }
                    }
                }
                Ok(encode_rsa_client_key_exchange_body_mapped(&enc))
            }
            crate::ir::KexType::DheRsa => {
                let mut yc = match recipe {
                    KeySharePoint::Real => self.dhe_yc.clone(),
                    KeySharePoint::Zero => crate::tls::kex12::dh_public_recipe(
                        &self.dhe_p,
                        crate::tls::kex12::DhPublicRecipe::Zero,
                    ),
                    KeySharePoint::One => crate::tls::kex12::dh_public_recipe(
                        &self.dhe_p,
                        crate::tls::kex12::DhPublicRecipe::One,
                    ),
                    KeySharePoint::PMinusOne => crate::tls::kex12::dh_public_recipe(
                        &self.dhe_p,
                        crate::tls::kex12::DhPublicRecipe::PMinusOne,
                    ),
                    KeySharePoint::P => crate::tls::kex12::dh_public_recipe(
                        &self.dhe_p,
                        crate::tls::kex12::DhPublicRecipe::P,
                    ),
                    _ => {
                        return Err(TlsError::Internal(
                            "key_share_point: only zero / one / p_minus_1 / p apply to a DHE ClientKeyExchange",
                        ));
                    }
                };
                for ov in overrides {
                    match (ov.field.as_str(), &ov.value) {
                        ("dh_Yc", FieldValue::Bytes(v)) => yc = v.clone(),
                        ("key_share_point", _) => {}
                        _ => {
                            return Err(TlsError::UnknownFieldOverride {
                                message: "ClientKeyExchange",
                                field: ov.field.clone(),
                            });
                        }
                    }
                }
                Ok(encode_dhe_client_key_exchange_body_mapped(&yc))
            }
            _ => {
                let mut point = self.ecdhe_public_with_recipe(overrides)?;
                for ov in overrides {
                    match (ov.field.as_str(), &ov.value) {
                        ("ecdh_Yc", FieldValue::Bytes(v)) => point = v.clone(),
                        ("key_share_point", _) => {}
                        _ => {
                            return Err(TlsError::UnknownFieldOverride {
                                message: "ClientKeyExchange",
                                field: ov.field.clone(),
                            });
                        }
                    }
                }
                Ok(encode_ecdhe_client_key_exchange_body_mapped(&point))
            }
        }
    }

    /// The client credential for a CertificateRequest: the configured one, else
    /// the shims/testdata end-entity certificate. Loaded once.
    fn client_credential(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        // A: `client_chain: []`, or no configured credential fitting the
        // CertificateRequest: an empty Certificate, not the default.
        if self.client_chain_none {
            return None;
        }
        if self.client_cert.is_none() {
            self.client_cert = default_client_credential();
        }
        self.client_cert.clone()
    }

    /// Answer a CertificateRequest (RFC 5246 7.4.6): the client certificate, or
    /// an empty certificate_list when there is none / `send Certificate {
    /// certificate_list: [] }` asks for the "no certificate" answer.
    fn send_client_certificate(&mut self) -> Result<(), TlsError> {
        let overrides = collect_overrides(&self.send_overrides, MessageKind::Certificate).to_vec();
        // `send Certificate { credential: valid | untrusted | none }` picks a
        // testdata credential by name (and the key its CertificateVerify signs
        // with); `certificate_list` still takes a raw DER blob.
        // A: `credential: valid` is the first `client_chain:` entry when the
        // test named any.
        let selected =
            crate::tls::chains::valid_credential_from(&overrides, &self.client_credentials)
                .or_else(|| crate::tls::dtls_kex::client_credential_override(&overrides));
        if let Some((list, key)) = selected {
            self.override_client_key = key;
            self.credential_selected = true;
            self.sent_client_cert = !list.is_empty();
            let refs: Vec<&[u8]> = list.iter().map(|c| c.as_slice()).collect();
            let encoded = encode_certificate_12_body_mapped(&refs);
            let seq = self.client_next_msg_seq;
            let body = self.emit_encoded(HS_CERTIFICATE, seq, encoded, MessageKind::Certificate)?;
            self.add_to_transcript(HS_CERTIFICATE, seq, &body);
            self.client_next_msg_seq += 1;
            return Ok(());
        }
        let list: Vec<Vec<u8>> = match certificate_list_override(&overrides)? {
            Some(l) => l,
            None => match self.client_credential() {
                Some((cert, _)) => vec![cert],
                None => Vec::new(),
            },
        };
        self.sent_client_cert = !list.is_empty();
        let refs: Vec<&[u8]> = list.iter().map(|c| c.as_slice()).collect();
        let encoded = encode_certificate_12_body_mapped(&refs);
        let seq = self.client_next_msg_seq;
        let body = self.emit_encoded(HS_CERTIFICATE, seq, encoded, MessageKind::Certificate)?;
        self.add_to_transcript(HS_CERTIFICATE, seq, &body);
        self.client_next_msg_seq += 1;
        Ok(())
    }

    /// CertificateVerify (RFC 5246 7.4.8): a signature over every handshake
    /// message so far (DTLS whole-message form, RFC 6347 4.2.6) with the first
    /// scheme the CertificateRequest listed that the key can produce. Skipped when
    /// no certificate was sent -- a CertificateVerify without one is a
    /// protocol error a test asks for explicitly via `send CertificateVerify`
    /// on a flow that sent an empty Certificate.
    fn send_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        let overrides =
            collect_overrides(&self.send_overrides, MessageKind::CertificateVerify).to_vec();
        let forced = !overrides.is_empty();
        if !self.sent_client_cert && !forced {
            return Ok(());
        }
        // A `credential: ...` selector signs the CertificateVerify with the
        // selected key (none, when `credential: none` sent an empty Certificate,
        // means no CertificateVerify); otherwise the configured credential.
        let key_der = if self.credential_selected {
            match self.override_client_key.clone() {
                Some(k) => k,
                None => return Ok(()),
            }
        } else {
            self.client_credential()
                .ok_or(TlsError::Dtls(
                    "CertificateVerify: no client credential available".into(),
                ))?
                .1
        };
        let key = PrivateKey::from_pkcs8_der(&key_der)?;
        let mut scheme = select_signature_scheme(&key, &self.cr_sigalgs);
        let mut signature = key.sign(scheme, &self.transcript)?;
        for ov in &overrides {
            match (ov.field.as_str(), &ov.value) {
                ("algorithm", FieldValue::U16(v)) => {
                    scheme = SignatureScheme::from_wire_value(*v).unwrap_or(scheme);
                }
                ("signature", FieldValue::Bytes(v)) => signature = v.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateVerify",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let algorithm = overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("algorithm", FieldValue::U16(v)) => Some(*v),
                _ => None,
            })
            .unwrap_or(scheme.wire_value());
        // The TLS 1.2 and TLS 1.3 CertificateVerify wire formats are identical.
        let encoded = encode_certificate_verify_13_body_mapped(algorithm, &signature);
        let seq = self.client_next_msg_seq;
        let body = self.emit_encoded(
            HS_CERTIFICATE_VERIFY,
            seq,
            encoded,
            MessageKind::CertificateVerify,
        )?;
        self.add_to_transcript(HS_CERTIFICATE_VERIFY, seq, &body);
        self.client_next_msg_seq += 1;
        Ok(())
    }

    fn send_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        // CCS is a record, not a handshake message: no message_seq, not hashed. It
        // rides under the current write epoch (plaintext at epoch 0, sealed during
        // a renegotiation at epoch 1) and activates the next epoch for writing.
        let epoch = self.write_epoch;
        // `send ChangeCipherSpec { type: N }` as on TLS.
        let ccs = crate::tls::driver::resolve_ccs_byte(&self.send_overrides)?;
        let mutations =
            collect_mutations(&self.send_mutations, MessageKind::ChangeCipherSpec).to_vec();
        self.push_record_with_mutations(CONTENT_TYPE_CCS, epoch, &[ccs], &mutations)?;
        self.write_epoch += 1;
        Ok(())
    }

    fn send_finished(&mut self) -> Result<(), TlsError> {
        self.derive_keys()?;
        let epoch = self.write_epoch; // 1 (initial handshake) or 2 (renegotiation)
        let seq = self.client_next_msg_seq;
        let master = self
            .keys_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("Finished without epoch-{} keys", epoch)))?
            .master
            .clone();
        let vd = verify_data(
            self.suite_info()?.prf,
            &master,
            b"client finished",
            &self.transcript,
        );
        // Save the clean verify_data for the RFC 5746 renegotiation_info of a
        // subsequent renegotiation.
        self.last_client_verify_data = vd.clone();
        // `send Finished { verify_data: ... }` replaces the value outright;
        // byte-mutations then target the verify_data body.
        let vd = finished_verify_data_override(
            collect_overrides(&self.send_overrides, MessageKind::Finished),
            vd,
        )?;
        let vd = self.mutate_encoded(MessageKind::Finished, encode_finished_body_mapped(&vd))?;
        let mutations = collect_mutations(&self.send_mutations, MessageKind::Finished).to_vec();
        let mut fin_msg = build_handshake(HS_FINISHED, seq, &vd);
        crate::tls::mutate::apply_handshake_header_mutations(&mut fin_msg, &mutations);
        // The client Finished is hashed for the server-Finished verification.
        self.transcript.extend_from_slice(&fin_msg);
        for fragment in build_fragment_payloads(
            &self.send_mutations,
            MessageKind::Finished,
            HS_FINISHED,
            seq,
            &vd,
        ) {
            self.push_record_with_mutations(CONTENT_TYPE_HANDSHAKE, epoch, &fragment, &mutations)?;
        }
        self.client_next_msg_seq += 1;
        Ok(())
    }

    // ---- inbound ----

    fn read_datagram_into_pending(&mut self) -> Result<(), TlsError> {
        let dg = self
            .recv_datagram_traced()
            .map_err(|e| TlsError::Record(crate::tls::record::RecordError::Io(e)))?
            .ok_or_else(|| {
                TlsError::Record(crate::tls::record::RecordError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed the DTLS transport",
                )))
            })?;
        let mut off = 0;
        let mut recs = Vec::new();
        while off < dg.len() {
            let (hdr, body, consumed) = parse_record(&dg[off..])
                .map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
            let limit = if hdr.epoch == 0 {
                1 << 14
            } else {
                (1 << 14) + 2048
            };
            if body.len() > limit {
                return Err(TlsError::Record(
                    crate::tls::record::RecordError::RecordTooLarge(body.len()),
                ));
            }
            self.received_record_seqs
                .push(((hdr.epoch as u64) << 48) | (hdr.sequence_number & 0x0000_FFFF_FFFF_FFFF));
            if hdr.content_type == CONTENT_TYPE_APP_DATA {
                self.received_app_data_records = self.received_app_data_records.saturating_add(1);
            }
            recs.push((
                hdr.content_type,
                hdr.epoch,
                hdr.sequence_number,
                body.to_vec(),
            ));
            off += consumed;
        }
        recs.reverse(); // pop() yields wire order
        self.pending_records = recs;
        Ok(())
    }

    /// Reassemble handshake records until a message of one of `want` types is
    /// delivered. A plaintext alert aborts; other content types (CCS) are
    /// skipped. Flushes any buffered outbound flight first.
    fn recv_message(&mut self, want: &[u8]) -> Result<HandshakeMessage, TlsError> {
        self.flush()?;
        loop {
            if let Some(message) = self.pending_handshakes.pop_front() {
                if want.contains(&message.msg_type) {
                    return Ok(message);
                }
                return Err(TlsError::Dtls(format!(
                    "unexpected handshake message {} (wanted {:?})",
                    message.msg_type, want
                )));
            }
            if self.pending_records.is_empty() {
                self.read_datagram_into_pending()
                    .map_err(|error| match error {
                        TlsError::Record(crate::tls::record::RecordError::Io(ref e))
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            TlsError::MatcherFailed {
                                message: "DTLS handshake",
                                field: "message".into(),
                                expected: format!("message type in {want:?}"),
                                observed: "no message before the receive deadline".into(),
                            }
                        }
                        other => other,
                    })?;
            }
            let (ct, epoch, seq, body) = self.pending_records.pop().unwrap();
            if ct == crate::tls::codec::CONTENT_TYPE_ALERT {
                if let Some((level, description)) = self.decode_alert(epoch, seq, &body) {
                    return Err(TlsError::Alert { level, description });
                }
                return Err(TlsError::Dtls("undecodable alert".into()));
            }
            if ct != CONTENT_TYPE_HANDSHAKE {
                continue;
            }
            if self.renegotiating && epoch == 0 {
                continue;
            }
            if want == [HS_FINISHED] && epoch != if self.renegotiating { 2 } else { 1 } {
                // Older flights can be retransmitted while waiting for Finished.
                continue;
            }
            let body = self.open_handshake_record(epoch, seq, &body)?;
            self.pending_handshakes.extend(
                self.reassembler
                    .accept_record_in_epoch(&body, epoch == if self.renegotiating { 2 } else { 1 })
                    .map_err(|reason| TlsError::Rejected { alert: 50, reason })?,
            );
        }
    }

    fn check_hvr_matchers(&self, legacy_version: u16, cookie: &[u8]) -> Result<(), TlsError> {
        for m in self.matchers_for(MessageKind::HelloVerifyRequest) {
            match (m.field.as_str(), &m.value) {
                ("legacy_version", FieldValue::U16(want)) => {
                    if legacy_version != *want {
                        return Err(TlsError::MatcherFailed {
                            message: "HelloVerifyRequest",
                            field: "legacy_version".into(),
                            expected: format!("0x{want:04x}"),
                            observed: format!("0x{legacy_version:04x}"),
                        });
                    }
                }
                ("cookie_len", FieldValue::U16(want)) => {
                    if cookie.len() != *want as usize {
                        return Err(TlsError::MatcherFailed {
                            message: "HelloVerifyRequest",
                            field: "cookie_len".into(),
                            expected: want.to_string(),
                            observed: cookie.len().to_string(),
                        });
                    }
                }
                ("cookie", FieldValue::Bytes(want)) => {
                    if cookie != want.as_slice() {
                        return Err(TlsError::MatcherFailed {
                            message: "HelloVerifyRequest",
                            field: "cookie".into(),
                            expected: hex(want),
                            observed: hex(cookie),
                        });
                    }
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "HelloVerifyRequest",
                        field: m.field.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn recv_hello_verify_request(&mut self) -> Result<(), TlsError> {
        // A re-challenge: we already hold a cookie, and the server has sent
        // another HelloVerifyRequest. Its message_seq is not fixed -- Botan
        // recreates the stateless HVR at message_seq 0 for a retransmitted
        // cookieless ClientHello (RFC 6347 4.2.1), but issues a *fresh* HVR at
        // the next message_seq when a presented cookie fails to verify (a
        // `rotate_cookie_secret` step invalidated it). HVR carries no transcript
        // bytes and is idempotent, so accept it at whatever message_seq arrives
        // rather than pinning the reassembler, then expect the ServerHello at
        // the seq after it.
        if self.hvr_cookie.is_some() {
            return self.recv_rechallenge_hvr();
        }
        // Tolerant: the server may skip the cookie exchange and send ServerHello
        // directly (OpenSSL). In that case stash it for the ServerHello step.
        let msg = self.recv_message(&[HS_HELLO_VERIFY_REQUEST, HS_SERVER_HELLO])?;
        if msg.msg_type == HS_HELLO_VERIFY_REQUEST {
            let hvr = parse_hello_verify_request(&msg.body)
                .map_err(|e| TlsError::Dtls(format!("bad HelloVerifyRequest: {:?}", e)))?;
            self.check_hvr_matchers(hvr.server_version, &hvr.cookie)?;
            self.hvr_cookie = Some(hvr.cookie);
            self.pending_ch = None; // CH1 is excluded from the transcript
            // The server's next message_seq restarts at 1 (HVR was 0).
            self.reassembler = Reassembler::with_next_seq(1);
            self.pending_handshakes.clear();
            self.pending_records.clear();
        } else {
            self.stashed_server_hello = Some(msg);
        }
        Ok(())
    }

    /// Read a re-challenge HelloVerifyRequest at any message_seq (see
    /// `recv_hello_verify_request`). A ServerHello here means the server chose
    /// not to re-challenge (it accepted the cookie): stash it for the
    /// ServerHello step. Reads whole, unfragmented epoch-0 records directly, so
    /// the reassembler's monotonic-seq gate does not drop an HVR that repeats a
    /// seq (the retransmit case) or skips ahead of the reset (the rotation case).
    fn recv_rechallenge_hvr(&mut self) -> Result<(), TlsError> {
        self.flush()?; // push the retried ClientHello before waiting for the answer
        loop {
            while let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                if ct == crate::tls::codec::CONTENT_TYPE_ALERT {
                    if let Some((level, description)) = self.decode_alert(epoch, seq, &body) {
                        return Err(TlsError::Alert { level, description });
                    }
                    continue;
                }
                if ct != CONTENT_TYPE_HANDSHAKE {
                    continue;
                }
                let body = self.open_handshake_record(epoch, seq, &body)?;
                if body.len() < DTLS_HANDSHAKE_HEADER_LEN {
                    return Err(TlsError::Dtls("short handshake record".into()));
                }
                let hdr = DtlsHandshakeHeader::parse(&body[..DTLS_HANDSHAKE_HEADER_LEN])
                    .map_err(|e| TlsError::Dtls(format!("bad hs header: {:?}", e)))?;
                let msg_body = body[DTLS_HANDSHAKE_HEADER_LEN..].to_vec();
                match hdr.msg_type {
                    HS_HELLO_VERIFY_REQUEST => {
                        let hvr = parse_hello_verify_request(&msg_body).map_err(|e| {
                            TlsError::Dtls(format!("bad HelloVerifyRequest: {:?}", e))
                        })?;
                        self.check_hvr_matchers(hvr.server_version, &hvr.cookie)?;
                        self.hvr_cookie = Some(hvr.cookie);
                        self.pending_ch = None;
                        // The ServerHello (once the retried cookie is accepted)
                        // continues from the seq after this HVR.
                        self.reassembler = Reassembler::with_next_seq(hdr.message_seq + 1);
                        self.pending_handshakes.clear();
                        self.pending_records.clear();
                        return Ok(());
                    }
                    HS_SERVER_HELLO => {
                        // The server accepted the retried cookie without another
                        // challenge: hand the ServerHello to its step and pin the
                        // reassembler so its own add_to_transcript lands in order.
                        self.reassembler = Reassembler::with_next_seq(hdr.message_seq);
                        self.pending_handshakes.clear();
                        self.stashed_server_hello = Some(HandshakeMessage {
                            msg_type: HS_SERVER_HELLO,
                            message_seq: hdr.message_seq,
                            body: msg_body,
                        });
                        return Ok(());
                    }
                    other => {
                        return Err(TlsError::Dtls(format!(
                            "expected HelloVerifyRequest or ServerHello on re-challenge, got type {}",
                            other
                        )));
                    }
                }
            }
            self.read_datagram_into_pending()?;
        }
    }

    fn recv_server_hello(&mut self) -> Result<(), TlsError> {
        let msg = match self.stashed_server_hello.take() {
            Some(m) => m,
            None => self.recv_message(&[HS_SERVER_HELLO])?,
        };
        // Commit CH1 to the transcript if the server skipped the cookie exchange.
        if let Some(ch1) = self.pending_ch.take() {
            let mut t = ch1;
            t.extend_from_slice(&self.transcript);
            self.transcript = t;
        }
        let sh = parse_server_hello(&msg.body)
            .map_err(|e| TlsError::Dtls(format!("bad ServerHello: {:?}", e)))?;
        // `recv ServerHello { ... }` matchers: the DTLS ServerHello body has
        // the TLS layout, so the TLS codec and the TLS matchers apply as is.
        if self
            .recv_matchers
            .iter()
            .any(|m| m.message == MessageKind::ServerHello)
        {
            let decoded = crate::tls::codec::decode_server_hello_body(&msg.body)
                .map_err(|e| TlsError::Dtls(format!("bad ServerHello: {:?}", e)))?;
            for matcher in &self.recv_matchers {
                if matcher.message == MessageKind::ServerHello {
                    for f in &matcher.fields {
                        if let FieldValue::Capture(name) = &f.value {
                            let value =
                                crate::tls::driver::capture_server_hello_field(&decoded, &f.field)?;
                            self.captures.push((name.clone(), value));
                            continue;
                        }
                        crate::tls::driver::match_server_hello_field(&decoded, f)?;
                    }
                }
            }
        }
        // RFC 5246 7.4.1.3: the server's choice must be one the client offered.
        if !self.offer.contains(&sh.cipher_suite) {
            return Err(TlsError::Dtls(format!(
                "server chose suite 0x{:04x} that was not offered",
                sh.cipher_suite
            )));
        }
        self.server_random = sh.random;
        self.negotiated_suite = sh.cipher_suite;
        // RFC 7366: encrypt-then-MAC only when both sides sent it and a block
        // cipher was selected (echoing it with AEAD is the server's violation;
        // the client just ignores it, as the TLS driver does).
        let selected_cbc = self
            .suite_info()
            .map(|s| s.cipher.is_cbc())
            .unwrap_or(false);
        self.use_etm = self.offered_etm && sh.extensions.contains(&0x0016) && selected_cbc;
        self.use_ems = self.offered_ems && sh.extensions.contains(&0x0017);
        self.add_to_transcript(HS_SERVER_HELLO, msg.message_seq, &msg.body);
        Ok(())
    }

    fn install_resumed_keys(&mut self) -> Result<(), TlsError> {
        if self.keys.is_some() || self.renegotiating {
            return Ok(());
        }
        let ms = self.prior_master_secret.clone().ok_or(TlsError::Internal(
            "resumed DTLS flight has no prior secret",
        ))?;
        let suite = self.suite_info()?;
        let (client, server) = tls12_direction_keys(
            suite,
            &ms,
            &self.server_random,
            &self.client_random,
            self.use_etm,
        )
        .map_err(|e| TlsError::Dtls(e.to_string()))?;
        self.keys = Some(Keys {
            master: ms,
            client,
            server,
        });
        Ok(())
    }

    /// Inspect, without consuming, the first record after ServerHello. An
    /// abbreviated RFC 5077 flight continues with [NewSessionTicket] or CCS;
    /// a declined ticket continues with the full certificate/key-exchange
    /// flight. The ServerHello SessionTicket extension cannot distinguish the
    /// two because it is also used to promise a replacement ticket.
    fn next_server_flight_is_resumed(&mut self) -> Result<bool, TlsError> {
        self.flush()?;
        if self.pending_records.is_empty() {
            self.read_datagram_into_pending()?;
        }
        let (ct, epoch, seq, body) = self
            .pending_records
            .last()
            .ok_or_else(|| TlsError::Dtls("empty server flight after ServerHello".into()))?;
        if *ct == CONTENT_TYPE_ALERT {
            if let Some((level, description)) = self.decode_alert(*epoch, *seq, body) {
                return Err(TlsError::Alert { level, description });
            }
        }
        if *ct == CONTENT_TYPE_CCS {
            return Ok(true);
        }
        if *ct == CONTENT_TYPE_HANDSHAKE && *epoch == 0 {
            if body.len() < DTLS_HANDSHAKE_HEADER_LEN {
                return Err(TlsError::Dtls(
                    "short first handshake record after ServerHello".into(),
                ));
            }
            return Ok(body[0] == HS_NEW_SESSION_TICKET);
        }
        Ok(false)
    }

    /// `recv NewSessionTicket` (RFC 5077 3.3): the ticket a server issues just
    /// before its ChangeCipherSpec, captured for a later session and folded into
    /// the transcript (the server Finished covers it). The preset flows absorb
    /// it on the ChangeCipherSpec step instead, since a server may omit it.
    fn recv_new_session_ticket(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(&[HS_NEW_SESSION_TICKET])?;
        self.capture_new_session_ticket(&msg)?;
        Ok(())
    }

    fn capture_new_session_ticket(&mut self, msg: &HandshakeMessage) -> Result<(), TlsError> {
        let (_lifetime, ticket) = crate::tls::codec::decode_new_session_ticket_body(&msg.body)?;
        self.captured_ticket = Some(ticket);
        self.add_to_transcript(HS_NEW_SESSION_TICKET, msg.message_seq, &msg.body);
        Ok(())
    }

    fn recv_certificate(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(&[HS_CERTIFICATE])?;
        self.capture_certificate(&msg.body)?;
        self.add_to_transcript(HS_CERTIFICATE, msg.message_seq, &msg.body);
        Ok(())
    }

    /// Receive and validate an RFC 6066 CertificateStatus. The message is part
    /// of the DTLS 1.2 transcript just as it is in TLS 1.2.
    fn recv_certificate_status(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(&[crate::tls::codec::HS_CERTIFICATE_STATUS])?;
        let status = crate::tls::codec::decode_certificate_status_body(&msg.body)?;
        for matcher in self.matchers_for(MessageKind::CertificateStatus) {
            match (matcher.field.as_str(), &matcher.value) {
                ("status_type", FieldValue::Ident(want)) if want == "ocsp" => {
                    if status.status_type != crate::tls::codec::CERT_STATUS_TYPE_OCSP {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateStatus",
                            field: "status_type".into(),
                            expected: "ocsp (1)".into(),
                            observed: status.status_type.to_string(),
                        });
                    }
                    if !crate::tls::codec::ocsp_response_is_successful(&status.response) {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateStatus",
                            field: "response".into(),
                            expected: "a successful OCSPResponse (RFC 6960 4.2.1)".into(),
                            observed: format!(
                                "{} bytes that do not parse as one",
                                status.response.len()
                            ),
                        });
                    }
                }
                ("response", FieldValue::Bytes(want)) => {
                    if status.response != *want {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateStatus",
                            field: "response".into(),
                            expected: hex(want),
                            observed: hex(&status.response),
                        });
                    }
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateStatus",
                        field: matcher.field,
                    });
                }
            }
        }
        if status.response.is_empty() {
            return Err(TlsError::Dtls(
                "CertificateStatus carries an empty response".into(),
            ));
        }
        self.add_to_transcript(
            crate::tls::codec::HS_CERTIFICATE_STATUS,
            msg.message_seq,
            &msg.body,
        );
        Ok(())
    }

    /// Remember the leaf certificate's public key (static RSA encrypts the
    /// premaster under it). A certificate plzn cannot parse is not an error
    /// here -- the RSA path reports the missing key when it needs it.
    fn capture_certificate(&mut self, body: &[u8]) -> Result<(), TlsError> {
        if let Ok(cert) = decode_certificate_12_body(body) {
            for m in self.matchers_for(MessageKind::Certificate) {
                match (m.field.as_str(), &m.value) {
                    ("entries", FieldValue::U16(want)) => {
                        if cert.entries.len() != *want as usize {
                            return Err(TlsError::MatcherFailed {
                                message: "Certificate",
                                field: "entries".into(),
                                expected: want.to_string(),
                                observed: cert.entries.len().to_string(),
                            });
                        }
                    }
                    ("leaf_key", FieldValue::Ident(want)) => {
                        crate::tls::driver::match_leaf_key(
                            cert.entries.first().map(|entry| entry.as_slice()),
                            want,
                        )?;
                    }
                    _ => {
                        return Err(TlsError::UnknownFieldOverride {
                            message: "Certificate",
                            field: m.field.clone(),
                        });
                    }
                }
            }
            if let Some(leaf) = cert.entries.into_iter().next() {
                if let Ok(key) = PublicKey::from_certificate_der(&leaf) {
                    validate_tls12_server_certificate_key(self.negotiated_suite, key.kind())?;
                    self.server_pubkey = Some(key);
                }
            }
        }
        Ok(())
    }

    /// The `recv <kind> { ... }` matchers declared for a message kind.
    fn matchers_for(&self, kind: MessageKind) -> Vec<crate::ir::FieldOverride> {
        self.recv_matchers
            .iter()
            .filter(|m| m.message == kind)
            .flat_map(|m| m.fields.iter().cloned())
            .collect()
    }

    /// Verify a ServerKeyExchange signature (RFC 5246 7.4.3: over client_random
    /// || server_random || params) under the certificate's key, and check the
    /// server signed with a scheme the ClientHello listed (7.4.1.4.1).
    fn verify_ske_signature(
        &self,
        scheme_wire: u16,
        signed_params: &[u8],
        signature: &[u8],
    ) -> Result<SignatureScheme, TlsError> {
        let scheme = SignatureScheme::from_wire_value(scheme_wire)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(scheme_wire))?;
        if !self.signature_schemes.contains(&scheme_wire) {
            return Err(TlsError::Dtls(format!(
                "server signed ServerKeyExchange with scheme 0x{:04x}, which the ClientHello did not list",
                scheme_wire
            )));
        }
        let pk = self.server_pubkey.as_ref().ok_or(TlsError::Dtls(
            "ServerKeyExchange before a Certificate with a usable key".into(),
        ))?;
        let signed = crate::tls::kex12::ske_signed_input(
            &self.client_random,
            &self.server_random,
            signed_params,
        );
        pk.verify_tls12(scheme, &signed, signature)
            .map_err(|_| TlsError::SignatureVerificationFailed)?;
        Ok(scheme)
    }

    fn recv_certificate_request(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(&[HS_CERTIFICATE_REQUEST])?;
        self.capture_certificate_request(&msg)?;
        self.add_to_transcript(HS_CERTIFICATE_REQUEST, msg.message_seq, &msg.body);
        Ok(())
    }

    fn capture_certificate_request(&mut self, msg: &HandshakeMessage) -> Result<(), TlsError> {
        let cr = parse_certificate_request_12(&msg.body)
            .map_err(|e| TlsError::Dtls(format!("bad CertificateRequest: {:?}", e)))?;
        for m in self.matchers_for(MessageKind::CertificateRequest) {
            match (m.field.as_str(), &m.value) {
                ("has_sigalg", FieldValue::U16(want)) => {
                    if !cr.signature_algorithms.contains(want) {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateRequest",
                            field: "has_sigalg".into(),
                            expected: format!("0x{:04x} listed", want),
                            observed: cr
                                .signature_algorithms
                                .iter()
                                .map(|v| format!("0x{:04x}", v))
                                .collect::<Vec<_>>()
                                .join(", "),
                        });
                    }
                }
                ("has_cert_type", FieldValue::U8(want)) => {
                    if !cr.certificate_types.contains(want) {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateRequest",
                            field: "has_cert_type".into(),
                            expected: format!("{} listed", want),
                            observed: format!("{:?}", cr.certificate_types),
                        });
                    }
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateRequest",
                        field: m.field.clone(),
                    });
                }
            }
        }
        self.cert_requested = true;
        // A: several credentials (`client_chain:`): the CertificateRequest picks
        // (certificate_types + signature_algorithms); none fitting = empty.
        if self.client_credentials.len() > 1 {
            let keys = crate::tls::chains::parse_chain_keys(&self.client_credentials)?;
            match crate::tls::chains::select_client_credential_12(
                &keys,
                &cr.certificate_types,
                &cr.signature_algorithms,
            ) {
                Some(i) => {
                    let c = &self.client_credentials[i];
                    self.client_cert = Some((c.cert_der.clone(), c.key_der.clone()));
                }
                None => {
                    self.client_cert = None;
                    self.client_chain_none = true;
                }
            }
        }
        self.cr_sigalgs = cr.signature_algorithms;
        Ok(())
    }

    fn recv_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(&[HS_SERVER_KEY_EXCHANGE])?;
        self.capture_ske(&msg)?;
        self.add_to_transcript(HS_SERVER_KEY_EXCHANGE, msg.message_seq, &msg.body);
        Ok(())
    }

    fn capture_ske(&mut self, msg: &HandshakeMessage) -> Result<(), TlsError> {
        if matches!(self.kex, Kex::Psk { .. }) {
            return self.capture_psk_ske(msg);
        }
        if matches!(self.kex, Kex::Cert) {
            let matchers = self.matchers_for(MessageKind::ServerKeyExchange);
            match self.suite_info()?.kex {
                crate::ir::KexType::DheRsa => {
                    let ske = decode_dhe_server_key_exchange_body(&msg.body)?;
                    let scheme = self.verify_ske_signature(
                        ske.sig_scheme,
                        &ske.signed_params,
                        &ske.signature,
                    )?;
                    for m in &matchers {
                        match (m.field.as_str(), &m.value) {
                            ("signature_scheme", FieldValue::U16(want))
                                if *want != scheme.wire_value() =>
                            {
                                return Err(TlsError::MatcherFailed {
                                    message: "ServerKeyExchange",
                                    field: "signature_scheme".into(),
                                    expected: format!("0x{:04x}", want),
                                    observed: format!("0x{:04x}", scheme.wire_value()),
                                });
                            }
                            ("signature_scheme", _) => {}
                            ("named_group", _) => {
                                return Err(TlsError::MatcherFailed {
                                    message: "ServerKeyExchange",
                                    field: "named_group".into(),
                                    expected: "an ECDHE ServerKeyExchange".into(),
                                    observed: "explicit DH parameters".into(),
                                });
                            }
                            _ => {
                                return Err(TlsError::UnknownFieldOverride {
                                    message: "ServerKeyExchange",
                                    field: m.field.clone(),
                                });
                            }
                        }
                    }
                    self.pending_dhe = Some((ske.dh_p, ske.dh_g, ske.dh_ys));
                }
                // RFC 5246 7.4.3: the RSA key exchange sends no ServerKeyExchange;
                // one that arrives anyway is absorbed into the transcript only.
                crate::ir::KexType::Rsa => {}
                _ => {
                    let ske = decode_ecdhe_server_key_exchange_body(&msg.body)?;
                    let scheme = self.verify_ske_signature(
                        ske.sig_scheme,
                        &ske.signed_params,
                        &ske.signature,
                    )?;
                    for m in &matchers {
                        match (m.field.as_str(), &m.value) {
                            ("named_group", FieldValue::U16(want)) if *want != ske.named_curve => {
                                return Err(TlsError::MatcherFailed {
                                    message: "ServerKeyExchange",
                                    field: m.field.clone(),
                                    expected: format!("0x{:04x}", want),
                                    observed: format!("0x{:04x}", ske.named_curve),
                                });
                            }
                            ("signature_scheme", FieldValue::U16(want))
                                if *want != scheme.wire_value() =>
                            {
                                return Err(TlsError::MatcherFailed {
                                    message: "ServerKeyExchange",
                                    field: "signature_scheme".into(),
                                    expected: format!("0x{:04x}", want),
                                    observed: format!("0x{:04x}", scheme.wire_value()),
                                });
                            }
                            ("named_group", _) | ("signature_scheme", _) => {}
                            _ => {
                                return Err(TlsError::UnknownFieldOverride {
                                    message: "ServerKeyExchange",
                                    field: m.field.clone(),
                                });
                            }
                        }
                    }
                    // RFC 4492 5.4: the server's curve must be one the client
                    // listed in supported_groups.
                    if !self.groups.contains(&ske.named_curve) {
                        return Err(TlsError::Dtls(format!(
                            "server chose group 0x{:04x}, which the ClientHello did not offer",
                            ske.named_curve
                        )));
                    }
                    let group = match ecdhe_group_from_wire(ske.named_curve) {
                        Some(g) if !g.is_ffdhe() && !g.is_tls13_only() => g,
                        _ => return Err(TlsError::ServerChoseUnsupportedGroup(ske.named_curve)),
                    };
                    self.ecdhe_group = group;
                    self.server_ecdhe_point = ske.public_point;
                }
            }
        }
        Ok(())
    }

    /// A PSK-family ServerKeyExchange: RFC 4279 2's optional identity hint, or
    /// RFC 5489 3.2's hint plus the unsigned ephemeral ECDH parameters. The
    /// server's group must be one this client offered (RFC 4492 5.1); matchers:
    /// `psk_identity_hint`, `named_group`.
    fn capture_psk_ske(&mut self, msg: &HandshakeMessage) -> Result<(), TlsError> {
        let matchers = self.matchers_for(MessageKind::ServerKeyExchange);
        let ecdhe = self.suite_info()?.kex == crate::ir::KexType::EcdhePsk;
        let (hint, group) = if ecdhe {
            let (hint, group, point) = crate::tls::kex12::decode_ecdhe_psk_ske(&msg.body)?;
            match ecdhe_group_from_wire(group) {
                Some(g) if !g.is_ffdhe() && !g.is_tls13_only() => self.ecdhe_group = g,
                _ => return Err(TlsError::ServerChoseUnsupportedGroup(group)),
            }
            if !self.groups.contains(&group) {
                return Err(TlsError::Dtls(format!(
                    "server chose ECDHE group 0x{:04x} that was not offered",
                    group
                )));
            }
            self.server_ecdhe_point = point;
            (hint, Some(group))
        } else {
            (crate::tls::kex12::decode_psk_hint_ske(&msg.body)?, None)
        };
        for m in &matchers {
            match (m.field.as_str(), &m.value) {
                ("psk_identity_hint", FieldValue::Bytes(want)) if *want != hint => {
                    return Err(TlsError::MatcherFailed {
                        message: "ServerKeyExchange",
                        field: "psk_identity_hint".into(),
                        expected: String::from_utf8_lossy(want).into_owned(),
                        observed: String::from_utf8_lossy(&hint).into_owned(),
                    });
                }
                ("named_group", FieldValue::U16(want)) => match group {
                    Some(g) if g == *want => {}
                    Some(g) => {
                        return Err(TlsError::MatcherFailed {
                            message: "ServerKeyExchange",
                            field: m.field.clone(),
                            expected: format!("0x{:04x}", want),
                            observed: format!("0x{:04x}", g),
                        });
                    }
                    None => {
                        return Err(TlsError::MatcherFailed {
                            message: "ServerKeyExchange",
                            field: m.field.clone(),
                            expected: "an ECDHE_PSK ServerKeyExchange".into(),
                            observed: "a plain-PSK identity hint".into(),
                        });
                    }
                },
                ("psk_identity_hint", _) | ("named_group", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: m.field.clone(),
                    });
                }
            }
        }
        self.psk_identity_hint = Some(hint);
        Ok(())
    }

    fn recv_server_hello_done(&mut self) -> Result<(), TlsError> {
        // Absorb any Certificate / ServerKeyExchange that precede ServerHelloDone
        // (a PSK server may send an SKE hint; a happy `flow handshake {}` never
        // recvs Cert/SKE explicitly), capturing the ECDHE point on the way.
        loop {
            let msg = self.recv_message(&[
                HS_CERTIFICATE,
                crate::tls::codec::HS_CERTIFICATE_STATUS,
                HS_SERVER_KEY_EXCHANGE,
                HS_CERTIFICATE_REQUEST,
                HS_SERVER_HELLO_DONE,
            ])?;
            match msg.msg_type {
                crate::tls::codec::HS_CERTIFICATE_STATUS => {
                    self.add_to_transcript(
                        crate::tls::codec::HS_CERTIFICATE_STATUS,
                        msg.message_seq,
                        &msg.body,
                    );
                }
                HS_SERVER_KEY_EXCHANGE => {
                    self.capture_ske(&msg)?;
                    self.add_to_transcript(HS_SERVER_KEY_EXCHANGE, msg.message_seq, &msg.body);
                }
                HS_CERTIFICATE_REQUEST => {
                    self.capture_certificate_request(&msg)?;
                    self.add_to_transcript(HS_CERTIFICATE_REQUEST, msg.message_seq, &msg.body);
                }
                HS_SERVER_HELLO_DONE => {
                    self.add_to_transcript(HS_SERVER_HELLO_DONE, msg.message_seq, &msg.body);
                    return Ok(());
                }
                _ => {
                    self.capture_certificate(&msg.body)?;
                    self.add_to_transcript(HS_CERTIFICATE, msg.message_seq, &msg.body)
                }
            }
        }
    }

    fn recv_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        self.flush()?;
        // A datagram may place an epoch-1 Finished before the plaintext CCS.
        // Preserve records encountered while looking for the CCS so the
        // following `recv Finished` can process them (DTLS does not promise
        // record order within a datagram).
        let mut deferred = Vec::new();
        loop {
            if let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                match ct {
                    CONTENT_TYPE_CCS => {
                        let plaintext = if epoch == 0 {
                            body
                        } else {
                            let keys = self.keys_for_epoch(epoch).ok_or_else(|| {
                                TlsError::Dtls(format!(
                                    "ChangeCipherSpec at epoch {} without keys",
                                    epoch
                                ))
                            })?;
                            dtls12_open(&keys.server, CONTENT_TYPE_CCS, epoch, seq, &body).map_err(
                                |e| TlsError::Dtls(format!("ChangeCipherSpec decrypt: {}", e)),
                            )?
                        };
                        if plaintext != [0x01] {
                            return Err(TlsError::Dtls(
                                "ChangeCipherSpec payload is not the single byte 0x01".into(),
                            ));
                        }
                        if self.prior_master_secret.is_some()
                            && !self.resumed
                            && !self.renegotiating
                            && self.keys.is_none()
                        {
                            self.resumed = true;
                            self.install_resumed_keys()?;
                        }
                        for record in deferred.into_iter().rev() {
                            self.pending_records.push(record);
                        }
                        return Ok(());
                    }
                    CONTENT_TYPE_ALERT => {
                        if let Some((level, description)) = self.decode_alert(epoch, seq, &body) {
                            return Err(TlsError::Alert { level, description });
                        }
                    }
                    // A NewSessionTicket rides just before the server CCS (RFC 5077
                    // 3.3): reassemble and capture it (it is in the server Finished's
                    // transcript). Any other stray record before the CCS (a
                    // retransmitted flight after a clock advance) is skipped.
                    CONTENT_TYPE_HANDSHAKE
                        if epoch == 0
                            && body.len() >= DTLS_HANDSHAKE_HEADER_LEN
                            && body[0] == HS_NEW_SESSION_TICKET =>
                    {
                        let hdr = DtlsHandshakeHeader::parse(&body[..DTLS_HANDSHAKE_HEADER_LEN])
                            .map_err(|e| TlsError::Dtls(format!("bad hs header: {:?}", e)))?;
                        let frag = crate::tls::dtls_handshake::HandshakeFragment {
                            header: hdr,
                            body: body[DTLS_HANDSHAKE_HEADER_LEN..].to_vec(),
                        };
                        let delivered =
                            self.reassembler
                                .accept(&frag)
                                .map_err(|e| TlsError::Rejected {
                                    alert: 50,
                                    reason: format!("DTLS handshake fragment is malformed: {}", e),
                                })?;
                        for m in delivered {
                            if m.msg_type == HS_NEW_SESSION_TICKET {
                                self.capture_new_session_ticket(&m)?;
                            }
                        }
                    }
                    _ => deferred.push((ct, epoch, seq, body)),
                }
            } else {
                self.read_datagram_into_pending()?;
            }
        }
    }

    fn recv_finished(&mut self) -> Result<(), TlsError> {
        let keys = self
            .keys_for_epoch(if self.renegotiating { 2 } else { 1 })
            .ok_or_else(|| TlsError::Dtls("Finished without keys".into()))?;
        let expected = verify_data(
            self.suite_info()?.prf,
            &keys.master,
            b"server finished",
            &self.transcript,
        );
        let message = self.recv_message(&[HS_FINISHED])?;
        if message.body != expected {
            return Err(TlsError::FinishedMismatch);
        }
        self.transcript
            .extend_from_slice(&crate::tls::dtls_handshake::transcript_bytes(&message));
        self.last_server_verify_data = expected;
        Ok(())
    }

    // ---- alert detection (post-flow drain) ----

    fn scan_pending_for_alert(&mut self) -> Option<TlsError> {
        let recs = std::mem::take(&mut self.pending_records);
        for (ct, epoch, seq, body) in &recs {
            if *ct == CONTENT_TYPE_ALERT {
                if let Some((level, description)) = self.decode_alert(*epoch, *seq, body) {
                    return Some(TlsError::Alert { level, description });
                }
            }
        }
        None
    }

    /// A `wait` drains whatever the peer sends while looking for an alert.
    /// Application-data records it drains still count for `assert
    /// app_data_records == N`, so a late duplicate answer (a replayed request
    /// the peer should have dropped) is not silently absorbed.
    fn count_drained_app_data(&mut self, dg: &[u8]) {
        let mut off = 0;
        while off < dg.len() {
            let Ok((hdr, _body, consumed)) = parse_record(&dg[off..]) else {
                return;
            };
            if hdr.content_type == CONTENT_TYPE_APP_DATA {
                self.received_app_data_records = self.received_app_data_records.saturating_add(1);
            }
            off += consumed;
        }
    }

    fn alert_in_datagram(&self, dg: &[u8]) -> Option<(u8, u8)> {
        let mut off = 0;
        while off < dg.len() {
            let (hdr, body, consumed) = parse_record(&dg[off..]).ok()?;
            if hdr.content_type == CONTENT_TYPE_ALERT {
                if let Some(a) = self.decode_alert(hdr.epoch, hdr.sequence_number, body) {
                    return Some(a);
                }
            }
            off += consumed;
        }
        None
    }

    /// Decode a `(level, description)` alert record. Epoch 0 is plaintext; an
    /// encrypted alert is opened with the server's key for that epoch (we hold it
    /// from the handshake), so pinned-alert expectations work for post-handshake
    /// and post-renegotiation rejects.
    fn decode_alert(&self, epoch: u16, seq: u64, body: &[u8]) -> Option<(u8, u8)> {
        if epoch == 0 {
            if body.len() >= 2 {
                Some((body[0], body[1]))
            } else {
                None
            }
        } else {
            let k = self.keys_for_epoch(epoch)?;
            let pt = dtls12_open(&k.server, CONTENT_TYPE_ALERT, epoch, seq, body).ok()?;
            if pt.len() >= 2 {
                Some((pt[0], pt[1]))
            } else {
                None
            }
        }
    }
}

impl TlsEndpoint for DtlsClient {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> Result<(), TlsError> {
        self.framer
            .set_read_deadline(deadline)
            .map_err(|error| TlsError::Record(crate::tls::record::RecordError::Io(error)))
    }
    fn configure_message(&mut self, config: &crate::ir::MessageConfig) -> Result<(), TlsError> {
        config.apply(
            &mut self.send_overrides,
            &mut self.recv_matchers,
            &mut self.send_mutations,
            &mut self.send_ext_deltas,
        );
        Ok(())
    }
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        self.captures.clone()
    }

    fn do_handshake(&mut self) -> Result<(), TlsError> {
        // The canonical DTLS 1.2 flight sequence, driven over the same
        // per-message methods `do_handshake_step` uses. `recv_server_hello_done`
        // absorbs Certificate/ServerKeyExchange (capturing the ECDHE point), so a
        // single sequence covers PSK and ECDHE; the HVR steps tolerate the
        // optional cookie exchange, so both shims complete. This mirrors
        // ir::DTLS12_PRESET, the list `lower` slices for anchored flows.
        self.send_client_hello()?;
        self.recv_hello_verify_request()?;
        self.send_client_hello()?;
        self.recv_server_hello()?;
        if self.prior_master_secret.is_some()
            && !self.renegotiating
            && self.next_server_flight_is_resumed()?
        {
            self.resumed = true;
            self.install_resumed_keys()?;
            self.recv_change_cipher_spec()?;
            self.recv_finished()?;
            self.send_change_cipher_spec()?;
            self.send_finished()?;
            self.flush()?;
            return Ok(());
        }
        self.resumed = false;
        self.recv_server_hello_done()?;
        // A server that asked for a certificate gets one (RFC 5246 7.4.6 / 7.4.8).
        if self.cert_requested {
            self.send_client_certificate()?;
        }
        self.send_client_key_exchange()?;
        if self.cert_requested {
            self.send_client_certificate_verify()?;
        }
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.recv_change_cipher_spec()?;
        self.recv_finished()?;
        self.flush()?;
        Ok(())
    }

    fn do_handshake_step(&mut self, step: &HandshakeStep) -> Result<(), TlsError> {
        use HandshakeStep::{Recv, Send};
        match step {
            Send(MessageKind::ClientHello) => self.send_client_hello(),
            Send(MessageKind::Certificate) => self.send_client_certificate(),
            Send(MessageKind::ClientKeyExchange) => self.send_client_key_exchange(),
            Send(MessageKind::CertificateVerify) => self.send_client_certificate_verify(),
            Send(MessageKind::ChangeCipherSpec) => self.send_change_cipher_spec(),
            Send(MessageKind::Finished) => self.send_finished(),
            Recv(MessageKind::HelloVerifyRequest) => self.recv_hello_verify_request(),
            Recv(MessageKind::ServerHello) => self.recv_server_hello(),
            Recv(MessageKind::Certificate) => self.recv_certificate(),
            Recv(MessageKind::CertificateStatus) => self.recv_certificate_status(),
            Recv(MessageKind::ServerKeyExchange) => self.recv_server_key_exchange(),
            Recv(MessageKind::CertificateRequest) => self.recv_certificate_request(),
            Recv(MessageKind::ServerHelloDone) => self.recv_server_hello_done(),
            Recv(MessageKind::ChangeCipherSpec) => self.recv_change_cipher_spec(),
            Recv(MessageKind::Finished) => self.recv_finished(),
            Recv(MessageKind::NewSessionTicket) => self.recv_new_session_ticket(),
            other => Err(TlsError::Dtls(format!(
                "unsupported DTLS step: {:?}",
                other
            ))),
        }
    }

    fn renegotiate_with(
        &mut self,
        _resumed: bool,
        _insecure: bool,
        _overrides: &[FieldOverride],
        _ext_deltas: &[ExtDeltaOp],
    ) -> Result<(), TlsError> {
        DtlsClient::renegotiate(self)
    }

    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        // Application data under the current write epoch (1 established, 2 after
        // a renegotiation), flushed at once. `record.*` mutations tamper with
        // this one record's MAC / tag.
        let epoch = self.write_epoch;
        self.push_record_with_mutations(CONTENT_TYPE_APP_DATA, epoch, data, mutations)?;
        self.flush()
    }

    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        self.flush()?;
        loop {
            while let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                if ct == CONTENT_TYPE_ALERT {
                    if let Some((level, description)) = self.decode_alert(epoch, seq, &body) {
                        return Err(TlsError::Alert { level, description });
                    }
                    continue;
                }
                if ct == CONTENT_TYPE_APP_DATA && epoch >= 1 {
                    let k = self.keys_for_epoch(epoch).ok_or_else(|| {
                        TlsError::Dtls(format!("application data at epoch {} without keys", epoch))
                    })?;
                    return dtls12_open(&k.server, CONTENT_TYPE_APP_DATA, epoch, seq, &body)
                        .map_err(|e| TlsError::Dtls(format!("application data decrypt: {}", e)));
                }
                // Handshake / CCS records (a retransmitted flight) are not what
                // the step waits for; keep reading.
            }
            self.read_datagram_into_pending()?;
        }
    }

    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError> {
        let keys = self
            .keys_for_epoch(self.write_epoch)
            .ok_or(TlsError::Internal(
                "exporter requested before the DTLS handshake",
            ))?;
        Ok(crate::tls::handshake::export_keying_material_tls12(
            self.suite_info()?.prf,
            &keys.master,
            label,
            &self.client_random,
            &self.server_random,
            context,
            length,
        ))
    }

    fn send_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        self.push_record(CONTENT_TYPE_ALERT, epoch, &[level, code])?;
        if (level, code) == (1, 0) {
            self.sent_close_notify = true;
        }
        self.flush()
    }

    fn send_alert_with(
        &mut self,
        level: u8,
        code: u8,
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        self.push_record_with_mutations(CONTENT_TYPE_ALERT, epoch, &[level, code], mutations)?;
        if (level, code) == (1, 0) {
            self.sent_close_notify = true;
        }
        self.flush()
    }

    fn send_record(&mut self, content_type: u8, data: &[u8]) -> Result<(), TlsError> {
        self.push_record(content_type, self.write_epoch, data)?;
        self.flush()
    }

    fn send_record_with(
        &mut self,
        content_type: u8,
        data: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        self.push_record_with_mutations(content_type, self.write_epoch, data, mutations)?;
        self.flush()
    }

    fn send_empty_record(&mut self, content_type: u8) -> Result<(), TlsError> {
        self.push_record(content_type, self.write_epoch, &[])?;
        self.flush()
    }

    fn dtls_op(&mut self, op: &DtlsOp) -> Result<(), TlsError> {
        match op {
            DtlsOp::DiscardFlight => {
                self.flush()?;
                self.discard_inbound()
            }
            DtlsOp::RetransmitFlight { order } => {
                self.flush()?;
                let dgs = self.build_retransmission(order.as_deref())?;
                match order {
                    None => self.send_flight(&dgs.concat()),
                    Some(_) => {
                        let n = dgs.len();
                        for (i, dg) in dgs.iter().enumerate() {
                            self.send_datagram(dg)?;
                            if i + 1 < n {
                                self.expect_silence(100)?;
                            }
                        }
                        Ok(())
                    }
                }
            }
            DtlsOp::HoldFlight => {
                if self.outgoing.is_empty() {
                    return Err(TlsError::Dtls("hold_flight with nothing pending".into()));
                }
                let dg = std::mem::take(&mut self.outgoing);
                self.last_flight_records = std::mem::take(&mut self.flight_records);
                self.held = Some(split_records(&dg)?);
                Ok(())
            }
            DtlsOp::HoldRetransmit => {
                self.flush()?;
                let dgs = self.build_retransmission(None)?;
                self.held = Some(dgs);
                Ok(())
            }
            DtlsOp::ReleaseFlight { records } => {
                let dg = release_held_records(&mut self.held, records.as_deref())?;
                self.send_datagram(&dg)
            }
            DtlsOp::ReplayFlight(n) => {
                self.flush()?;
                let dg = self.flight_history.get(n - 1).cloned().ok_or_else(|| {
                    TlsError::Dtls(format!(
                        "replay_flight {}: only {} flights sent",
                        n,
                        self.flight_history.len()
                    ))
                })?;
                self.send_datagram(&dg)
            }
            DtlsOp::MapRecordSequences(map) => {
                self.flush()?;
                self.record_sequence_map = *map;
                Ok(())
            }
            DtlsOp::BeginRenegotiation => {
                self.flush()?;
                self.begin_renegotiation();
                Ok(())
            }
            DtlsOp::Restart => {
                self.flush()?;
                self.restart();
                Ok(())
            }
            DtlsOp::HvrFlood { .. } => Err(TlsError::Dtls(
                "hvr_flood is a DTLS server (`uut client`) step".into(),
            )),
            DtlsOp::ExpectRetransmitNoCcs => self.expect_retransmit_impl(true),
            DtlsOp::HeaderOnlyFlood { count } => self.header_only_flood(*count),
            DtlsOp::LargeLengthFragment { length } => self.large_length_fragment(*length),
            DtlsOp::FutureSeqFirst => self.future_seq_first(),
            DtlsOp::InterleaveFlight { split } => {
                let recs = interleave_records(&self.outgoing)?;
                if *split {
                    // Each interleaved record is its own datagram, sent now; the
                    // plaintext bookkeeping stays with the flight for a retransmit.
                    self.outgoing.clear();
                    for r in &recs {
                        self.send_datagram(r)?;
                    }
                } else {
                    self.outgoing = recs.concat();
                }
                Ok(())
            }
            DtlsOp::SuppressAck
            | DtlsOp::SetMtu(_)
            | DtlsOp::SendAck { .. }
            | DtlsOp::ExpectAck
            | DtlsOp::SendPreviousEpochFinished
            | DtlsOp::RetransmitPreviousEpochFinished => Err(TlsError::Dtls(
                "explicit ACK controls require DTLS 1.3".into(),
            )),
        }
    }

    /// `close alert LEVEL/CODE`: the alert, then the flush the plain close does.
    fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        TlsEndpoint::send_alert(self, level, code)?;
        TlsEndpoint::close(self)
    }
    fn close(&mut self) -> Result<(), TlsError> {
        self.flush()
    }

    fn negotiated_cipher_suite(&self) -> u16 {
        self.negotiated_suite
    }

    fn probe(&mut self, millis: u64) -> Result<(), TlsError> {
        self.flush()?;
        // A record left in the buffer from an earlier read (rare) is checked
        // first, then a single timed read for a deferred alert.
        if let Some(err) = self.scan_pending_for_alert() {
            return Err(err);
        }
        self.framer
            .set_read_timeout(Some(std::time::Duration::from_millis(millis.max(1))))
            .map_err(|e| TlsError::Dtls(format!("set read timeout: {}", e)))?;
        // Read immediately-available datagrams until an alert appears or the peer
        // falls silent (a benign record, e.g. a retransmitted Finished, may
        // precede the alert). EOF / timeout / read hiccup ends the loop as
        // silence.
        let mut result = Ok(());
        loop {
            match self.recv_datagram_traced() {
                Ok(Some(dg)) => {
                    self.count_drained_app_data(&dg);
                    if let Some((level, description)) = self.alert_in_datagram(&dg) {
                        result = Err(TlsError::Alert { level, description });
                        break;
                    }
                }
                // The peer closed the connection: a clean close, not silence --
                // unless it is the shutdown our own close_notify asked for.
                Ok(None) => {
                    if !self.sent_close_notify {
                        result = Err(TlsError::Record(crate::tls::record::RecordError::Io(
                            std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "peer closed during a wait",
                            ),
                        )));
                    }
                    break;
                }
                Err(e) if is_timeout_error(&e) => {
                    result = Err(TlsError::Timeout);
                    break;
                }
                Err(_) => break,
            }
        }
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        result
    }

    fn write_raw(&mut self, data: &[u8]) -> Result<(), TlsError> {
        // A raw datagram, sent immediately after any buffered flight.
        self.flush()?;
        self.framer
            .send_datagram(data)
            .map_err(|e| TlsError::Dtls(format!("send raw datagram: {}", e)))
    }

    fn advance_clock(&mut self, nanos: u64) -> Result<(), TlsError> {
        // Advance the peer's virtual retransmit clock. Deliberately does NOT
        // flush our own pending flight -- the point is to withhold it so the
        // peer's timer fires and it retransmits.
        self.framer.advance_clock(nanos).map_err(|e| {
            if is_timeout_error(&e) {
                TlsError::Timeout
            } else {
                TlsError::Dtls(format!("advance clock: {}", e))
            }
        })
    }

    fn expect_next_timeout(&mut self, nanos: Option<u64>) -> Result<(), TlsError> {
        self.framer
            .expect_next_timeout(nanos)
            .map_err(|e| TlsError::Dtls(format!("expect next timeout: {}", e)))
    }

    fn set_timeout(&mut self, millis: u32) -> Result<(), TlsError> {
        self.framer
            .set_timeout(millis)
            .map_err(|e| TlsError::Dtls(format!("set timeout: {}", e)))
    }

    fn expect_retransmit(&mut self) -> Result<(), TlsError> {
        self.expect_retransmit_impl(false)
    }

    fn rotate_cookie_secret(&mut self) -> Result<(), TlsError> {
        // A runtime control frame; nothing of ours is flushed (the next
        // ClientHello still carries the cookie issued under the old secret).
        self.framer
            .send_control(crate::tls::dtls_transport::control::ROTATE_COOKIE_SECRET)
            .map_err(|e| TlsError::Dtls(format!("rotate cookie secret: {}", e)))
    }

    fn resend_flight(&mut self) -> Result<(), TlsError> {
        self.flush()?; // send the buffered flight and capture it
        let dg = self
            .last_flushed
            .clone()
            .ok_or_else(|| TlsError::Dtls("resend_flight with no prior flight".into()))?;
        self.send_flight(&dg)
    }

    fn send_key_update(&mut self, _request_update: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is not a DTLS 1.2 feature"))
    }

    fn recv_key_update(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is not a DTLS 1.2 feature"))
    }

    fn session_state(&self) -> Option<SessionState> {
        let ticket = self.captured_ticket.clone()?;
        let master_secret = self.keys.as_ref()?.master.clone();
        Some(SessionState {
            protocol: crate::ir::Protocol::Dtls,
            version: crate::tls::record::TlsVersion::Tls12,
            ticket,
            master_secret,
            session_id: Vec::new(),
            ticket_age_add: 0,
            cipher_suite: 0,
            max_early_data_size: 0,
        })
    }

    fn negotiated_resumed(&self) -> Option<bool> {
        Some(self.resumed)
    }

    fn record_seq_trace(&self) -> Option<Vec<u64>> {
        Some(self.received_record_seqs.clone())
    }

    fn datagram_size_trace(&self) -> Option<Vec<usize>> {
        Some(self.received_datagram_sizes.clone())
    }

    fn app_data_records_received(&self) -> Option<u32> {
        Some(self.received_app_data_records)
    }
}

// ---- DTLS crypto/codec helpers (moved from the retired dtls_client engine) ----

/// TLS 1.2 Finished verify_data over the whole-message DTLS transcript, with
/// the negotiated suite's PRF hash (RFC 5246 7.4.9: SHA-256 unless the suite
/// names SHA-384).
pub(crate) fn verify_data(prf: HashAlg, master: &[u8], label: &[u8], transcript: &[u8]) -> Vec<u8> {
    let h = hash(prf, transcript);
    tls12_prf(prf, master, label, &h, 12)
}

/// RFC 4279 2: for a pure-PSK ciphersuite the premaster secret is
/// uint16(len(psk)) || zeros[len(psk)] || uint16(len(psk)) || psk.
fn psk_premaster(psk: &[u8]) -> Vec<u8> {
    let n = psk.len();
    let mut out = Vec::with_capacity(4 + 2 * n);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, n));
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(psk);
    out
}

/// ECDHE ClientKeyExchange body (RFC 4492 5.7): opaque point<1..2^8-1>.
#[cfg(test)]
fn ecdhe_client_key_exchange_body(public_point: &[u8]) -> Vec<u8> {
    let mut w = crate::tls::codec::ByteWriter::new();
    w.u8_vec(public_point);
    w.into_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Derive a deterministic 32-byte RNG seed from the client random + a label.
fn seed_from(client_random: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + label.len());
    input.extend_from_slice(client_random);
    input.extend_from_slice(label);
    let h = hash(HashAlg::Sha256, &input);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&h);
    seed
}

/// `interleave_flight`: round-robin the pending flight's plaintext (epoch 0)
/// handshake records across their message_seqs -- A0 B0 A1 B1 ... -- and keep
/// every other record (a sealed record, a ChangeCipherSpec) after them in its
/// original order. Shared by both DTLS roles. Needs at least two messages'
/// records pending.
pub(crate) fn interleave_records(pending: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    let mut groups: Vec<(u16, Vec<Vec<u8>>)> = Vec::new();
    let mut others: Vec<Vec<u8>> = Vec::new();
    for rec in split_records(pending)? {
        let (hdr, body, _) =
            parse_record(&rec).map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
        let seq = if hdr.content_type == CONTENT_TYPE_HANDSHAKE
            && hdr.epoch == 0
            && body.len() >= DTLS_HANDSHAKE_HEADER_LEN
        {
            DtlsHandshakeHeader::parse(&body[..DTLS_HANDSHAKE_HEADER_LEN])
                .ok()
                .map(|h| h.message_seq)
        } else {
            None
        };
        match seq {
            Some(seq) => match groups.iter_mut().find(|(s, _)| *s == seq) {
                Some((_, recs)) => recs.push(rec),
                None => groups.push((seq, vec![rec])),
            },
            None => others.push(rec),
        }
    }
    if groups.len() < 2 {
        return Err(TlsError::Dtls(format!(
            "interleave_flight needs fragments of at least two handshake messages pending ({} found); \
             fragment two consecutive messages first (`send X @ fragment N`, `send Y @ fragment M`)",
            groups.len()
        )));
    }
    let mut out = Vec::new();
    let longest = groups.iter().map(|(_, r)| r.len()).max().unwrap_or(0);
    for i in 0..longest {
        for (_, recs) in &groups {
            if let Some(r) = recs.get(i) {
                out.push(r.clone());
            }
        }
    }
    out.extend(others);
    Ok(out)
}

/// Split a datagram into its encoded records (each with its 13-byte header).
pub(crate) fn split_records(dg: &[u8]) -> Result<Vec<Vec<u8>>, TlsError> {
    let mut off = 0;
    let mut out = Vec::new();
    while off < dg.len() {
        let (_hdr, _body, consumed) =
            parse_record(&dg[off..]).map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
        out.push(dg[off..off + consumed].to_vec());
        off += consumed;
    }
    Ok(out)
}

/// Pack a serialized flight into bounded datagrams without splitting a DTLS
/// record. A flight may be much larger than a receiver's datagram buffer even
/// when each handshake fragment is MTU-sized.
pub(crate) fn pack_records_into_datagrams(
    flight: &[u8],
    max_datagram: usize,
) -> Result<Vec<Vec<u8>>, TlsError> {
    if max_datagram == 0 {
        return Err(TlsError::Dtls("datagram size limit is zero".into()));
    }
    let mut out = Vec::new();
    let mut datagram = Vec::new();
    for record in split_records(flight)? {
        if !datagram.is_empty() && datagram.len() + record.len() > max_datagram {
            out.push(std::mem::take(&mut datagram));
        }
        datagram.extend_from_slice(&record);
        if datagram.len() >= max_datagram {
            out.push(std::mem::take(&mut datagram));
        }
    }
    if !datagram.is_empty() {
        out.push(datagram);
    }
    Ok(out)
}

/// Remove selected records from a held flight and return them packed in one
/// datagram. An indexed release leaves every unselected record held, allowing a
/// test to interpose another datagram before releasing the remainder. Indices
/// are interpreted against the records that are held at the time of the step.
pub(crate) fn release_held_records(
    slot: &mut Option<Vec<Vec<u8>>>,
    records: Option<&[usize]>,
) -> Result<Vec<u8>, TlsError> {
    let held = slot
        .as_ref()
        .ok_or_else(|| TlsError::Dtls("release_flight with nothing held".into()))?;
    let Some(indices) = records else {
        return Ok(slot.take().expect("held flight checked above").concat());
    };

    for &i in indices {
        if i >= held.len() {
            return Err(TlsError::Dtls(format!(
                "release_flight index {} out of range ({} records held)",
                i,
                held.len()
            )));
        }
    }

    let mut selected = vec![false; held.len()];
    let mut datagram = Vec::new();
    for &i in indices {
        datagram.extend_from_slice(&held[i]);
        selected[i] = true;
    }
    let remaining: Vec<Vec<u8>> = slot
        .take()
        .expect("held flight checked above")
        .into_iter()
        .enumerate()
        .filter_map(|(i, record)| (!selected[i]).then_some(record))
        .collect();
    *slot = (!remaining.is_empty()).then_some(remaining);
    Ok(datagram)
}

/// A whole DTLS handshake message: 12-byte header (single fragment) + body.
pub(crate) fn build_handshake(msg_type: u8, message_seq: u16, body: &[u8]) -> Vec<u8> {
    let hdr = DtlsHandshakeHeader::whole(msg_type, message_seq, body.len() as u32);
    let mut out = Vec::with_capacity(DTLS_HANDSHAKE_HEADER_LEN + body.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_client(suite: u16) -> DtlsClient {
        let cfg = DtlsClientConfig {
            client_random: [0x42; 32],
            server_name: "localhost".into(),
            cipher_suites: vec![suite],
            psk: None,
            groups: Vec::new(),
            signature_schemes: Vec::new(),
            client_cert_der: None,
            client_private_key_der: None,
            client_credentials: Vec::new(),
            client_chain_none: true,
            send_overrides: Vec::new(),
            send_mutations: Vec::new(),
            recv_matchers: Vec::new(),
            send_ext_deltas: Vec::new(),
            session_ticket: None,
            prior_master_secret: None,
            advertise_session_ticket: false,
        };
        let mut client = DtlsClient::new(
            Box::new(crate::transport::MockTransport::new(
                "dtls-certificate-auth",
            )),
            cfg,
        );
        client.negotiated_suite = suite;
        client
    }

    #[test]
    fn psk_premaster_format() {
        let pm = psk_premaster(&[0xAA, 0xBB]);
        assert_eq!(pm, vec![0, 2, 0, 0, 0, 2, 0xAA, 0xBB]);
    }

    #[test]
    fn indexed_release_retains_unselected_records() {
        let mut held = Some(vec![vec![0], vec![1], vec![2]]);
        assert_eq!(
            release_held_records(&mut held, Some(&[1])).unwrap(),
            vec![1]
        );
        assert_eq!(held, Some(vec![vec![0], vec![2]]));
        assert_eq!(release_held_records(&mut held, None).unwrap(), vec![0, 2]);
        assert!(held.is_none());
    }

    #[test]
    fn invalid_index_does_not_consume_held_flight() {
        let mut held = Some(vec![vec![0], vec![1]]);
        assert!(release_held_records(&mut held, Some(&[2])).is_err());
        assert_eq!(held, Some(vec![vec![0], vec![1]]));
    }

    #[test]
    fn large_flights_are_packed_at_record_boundaries() {
        let records: Vec<Vec<u8>> = (0..3)
            .map(|seq| crate::tls::dtls_record::encode_record(22, 0, seq, &[0x42; 10]))
            .collect();
        let flight = records.concat();
        let datagrams = pack_records_into_datagrams(&flight, 50).unwrap();
        assert_eq!(datagrams.len(), 2);
        assert_eq!(datagrams[0].len(), 46);
        assert_eq!(datagrams[1].len(), 23);
        assert_eq!(datagrams.concat(), flight);
        assert!(pack_records_into_datagrams(&flight, 0).is_err());
    }

    #[test]
    fn cke_body_is_length_prefixed_identity() {
        let b = crate::tls::kex12::encode_psk_cke_mapped(b"id", None).bytes;
        assert_eq!(b, vec![0, 2, b'i', b'd']);
        let with_point = crate::tls::kex12::encode_psk_cke_mapped(b"id", Some(&[0x04, 0xAA])).bytes;
        assert_eq!(with_point, vec![0, 2, b'i', b'd', 2, 0x04, 0xAA]);
        let e = ecdhe_client_key_exchange_body(&[0x04, 0xAA, 0xBB]);
        assert_eq!(e, vec![3, 0x04, 0xAA, 0xBB]);
    }

    #[test]
    fn build_handshake_has_whole_header() {
        let m = build_handshake(HS_FINISHED, 3, &[0u8; 12]);
        assert_eq!(m.len(), DTLS_HANDSHAKE_HEADER_LEN + 12);
        assert_eq!(m[0], HS_FINISHED);
        let hdr = DtlsHandshakeHeader::parse(&m[..DTLS_HANDSHAKE_HEADER_LEN]).unwrap();
        assert_eq!(hdr.message_seq, 3);
        assert_eq!(hdr.fragment_length, 12);
    }

    #[test]
    fn certificate_capture_rejects_a_key_from_the_wrong_authentication_family() {
        use crate::server::certs::{CertBundle, KeyType};

        let cert = CertBundle::generate(KeyType::EcdsaP256).unwrap();
        let body = crate::tls::codec::encode_certificate_12_body(&[cert.cert_der.as_slice()]);
        let mut client = certificate_client(0xc02f); // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        assert!(matches!(
            client.capture_certificate(&body),
            Err(TlsError::Rejected { alert: 43, .. })
        ));
    }
}
