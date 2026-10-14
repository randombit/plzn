// DTLS 1.2 server-side endpoint for the IR runtime.
//
// The mirror of `DtlsClient`: the harness plays the DTLS SERVER and the shim is
// the DTLS client (`uut client` + `versions: [dtls12]`). It fuses `Tls12Server`'s
// server-side crypto (signing the ServerKeyExchange, deriving keys from the
// client's ClientKeyExchange, verifying/computing Finished) with the verified
// DTLS substrate (dtls_record / dtls_handshake / dtls_transport).
//
// Flights (RFC 6347 Fig. 1, server view): recv ClientHello(1) -> send
// HelloVerifyRequest(cookie) -> recv ClientHello(2, cookie) -> send ServerHello,
// Certificate, ServerKeyExchange, ServerHelloDone -> recv ClientKeyExchange,
// ChangeCipherSpec, Finished (epoch 1) -> send ChangeCipherSpec, Finished
// (epoch 1).

use crate::ir::{
    DtlsOp, ExtDeltaOp, FieldOverride, MessageKind, MessageMutations, MessageOverrides, Mutation,
    SessionState,
};
use crate::tls::codec::{
    CONTENT_TYPE_CCS, CONTENT_TYPE_HANDSHAKE, Extension, GROUP_SECP256R1, GROUP_SECP384R1,
    GROUP_SECP521R1, GROUP_X25519, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST, HS_CERTIFICATE_VERIFY,
    HS_CLIENT_HELLO, HS_CLIENT_KEY_EXCHANGE, HS_FINISHED, HS_HELLO_REQUEST,
    HS_HELLO_VERIFY_REQUEST, HS_NEW_SESSION_TICKET, HS_SERVER_HELLO, HS_SERVER_HELLO_DONE,
    HS_SERVER_KEY_EXCHANGE, ServerHelloBuilder, decode_certificate_12_body,
    decode_certificate_verify_13_body, decode_ecdhe_client_key_exchange_body,
    encode_certificate_12_body_mapped, encode_ecdhe_server_key_exchange_body_mapped,
    encode_finished_body_mapped, encode_server_hello_body_mapped, encode_server_hello_done_body,
};
use crate::tls::crypto::{EcdhePrivate, PrivateKey, PublicKey, Rng, SignatureScheme};
use crate::tls::driver::key_share_point_recipe;
use crate::tls::driver::{TlsEndpoint, TlsError, collect_mutations};
use crate::tls::driver::{apply_server_hello_override, collect_overrides, ecdhe_group_from_wire};
use crate::tls::dtls_driver::{
    build_handshake, interleave_records, pack_records_into_datagrams, release_held_records,
    split_records, verify_data,
};
use crate::tls::dtls_handshake::{
    HandshakeMessage, Reassembler, build_fragment_payloads, encode_hello_verify_request,
    parse_dtls_client_hello, transcript_bytes,
};
use crate::tls::dtls_kex::{
    CERT_TYPE_ECDSA_SIGN, CERT_TYPE_RSA_SIGN, psk_premaster, select_signature_scheme,
    verify_scheme_wires,
};
use crate::tls::dtls_kex::{certificate_list_override, finished_verify_data_override};
use crate::tls::dtls_record::{dtls12_open, dtls12_seal, encode_record, parse_record};
use crate::tls::dtls_transport::{DtlsFramer, is_timeout_error};
use crate::tls::handshake::{derive_master_secret, tls12_direction_keys};
use crate::tls::record::DirectionKeys;
use crate::tls::server12::{TICKET12_MAGIC, decide_resumption};
use crate::transport::UutTransport;

const DTLS12_WIRE_U16: u16 = 0xFEFD;
const SERVER_COOKIE: [u8; 16] = *b"plzn-dtls-cookie";

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// What a datagram carries: its record content types and the alerts among them.
type DatagramSummary = (Vec<u8>, Vec<(u8, u8)>);

/// Outcome of a bounded read.
enum Read {
    Data(Vec<u8>),
    Silence,
    Eof,
}

pub struct DtlsServerConfig {
    pub cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    /// A: every chain this server holds (`chain:`), in preference order;
    /// `cert_der` / `private_key_der` are the initially selected one. With two
    /// or more, the ClientHello picks (`tls::chains`).
    pub chains: Vec<crate::ir::Chain>,
    pub seed: [u8; 32],
    /// Suites this server may select, in preference order
    /// (`ir::filter_suites_dtls`); the certificate's family narrows it further.
    pub cipher_suites: Vec<u16>,
    /// ECDHE groups this server may select (the group capabilities), in
    /// preference order; empty = every curve plzn implements, client order.
    pub groups: Vec<u16>,
    /// `Some((identity, secret))` serves the RFC 4279 plain-PSK and RFC 5489
    /// ECDHE_PSK suites.
    pub psk: Option<(Vec<u8>, Vec<u8>)>,
    /// `send Msg { field: value }` overrides (ServerHello, ServerKeyExchange).
    pub send_overrides: Vec<MessageOverrides>,
    pub send_mutations: Vec<MessageMutations>,
    pub recv_matchers: Vec<MessageOverrides>,
    /// `send ServerHello { +ext / -ext ... }` deltas.
    pub send_ext_deltas: Vec<crate::ir::MessageExtDeltas>,
    /// RFC 5077 over DTLS: the session this connection may resume (the ticket
    /// plzn's DTLS server issued on an earlier connection of the same test and
    /// that session's master secret, carried between `session` blocks by the
    /// runner). A presented ticket is accepted only when it is exactly this one.
    pub resumption: Option<SessionState>,
    /// Deliberately claim an incompatible session was resumed.
    pub force_resumption: bool,
    /// RFC 5077 3.2: answer a client's SessionTicket extension with the empty
    /// extension and issue (or renew) a ticket before our ChangeCipherSpec.
    pub issue_tickets: bool,
}

/// One epoch's record keys: what the client writes (our read side) and what
/// the server writes.
struct EpochKeys {
    client: DirectionKeys,
    server: DirectionKeys,
}

pub struct DtlsServer {
    framer: DtlsFramer,
    private_key: PrivateKey,
    /// A: the parsed keys of `cfg.chains` (empty unless several chains).
    chain_keys: Vec<PrivateKey>,
    certificate_der: Vec<u8>,
    /// PKCS#8 for the currently selected certificate. CertificateStatus uses
    /// it to sign the generated OCSP response.
    private_key_der: Vec<u8>,
    /// A: every chain (`chain:`); `certificate_der` / `private_key` are the selected one.
    chains: Vec<crate::ir::Chain>,
    send_mutations: Vec<MessageMutations>,
    send_ext_deltas: Vec<crate::ir::MessageExtDeltas>,
    send_overrides: Vec<MessageOverrides>,
    recv_matchers: Vec<MessageOverrides>,
    seed: [u8; 32],
    /// Negotiation inputs: the groups this server may pick, what the client's
    /// hello offered, and the choices made.
    allowed_groups: Vec<u16>,
    client_groups: Vec<u16>,
    client_sigalgs: Vec<u16>,
    selected_group: u16,
    /// RFC 4279 PSK credential (identity, secret), when serving PSK suites.
    psk: Option<(Vec<u8>, Vec<u8>)>,
    /// Client authentication: whether we sent a CertificateRequest, and the key
    /// from the client's Certificate for its CertificateVerify.
    cert_requested: bool,
    client_pubkey: Option<PublicKey>,
    received_empty_certificate: bool,

    server_random: [u8; 32],
    client_random: [u8; 32],
    client_session_id: Vec<u8>,
    negotiated_suite: u16,
    use_ems: bool,
    // True once a HelloVerifyRequest has been sent, so the next ClientHello is
    // treated as the cookie ClientHello (CH2): folded into the transcript.
    hvr_sent: bool,
    /// Cookie carried by the most recently scripted HelloVerifyRequest. A UUT
    /// client must echo it in CH2, including the legal empty/255-byte bounds.
    expected_cookie: Option<Vec<u8>>,
    ephemeral: Option<EcdhePrivate>,
    /// The DHE server half (`DHE_RSA_*` suites), generated at ServerKeyExchange.
    dhe: Option<crate::tls::kex12::DheServer>,
    /// ClientHello.client_version, stamped into the static-RSA premaster
    /// (RFC 5246 7.4.7.1; 0xfefd for a DTLS 1.2 client).
    client_version: u16,
    master: Vec<u8>,

    // Record keys (both directions, the negotiated suite's family), derived at
    // ClientKeyExchange (epoch 1), plus a second set derived during a
    // renegotiation (epoch 2).
    keys: Option<EpochKeys>,
    reneg_keys: Option<EpochKeys>,
    /// The suites this server may select (`DtlsServerConfig::cipher_suites`).
    allowed_suites: Vec<u16>,
    /// RFC 7366: the client offered encrypt_then_mac and a CBC suite was chosen.
    use_etm: bool,

    // Renegotiation (RFC 5746): true while running a second handshake; the prior
    // handshake's verify_data binds the renegotiation_info.
    renegotiating: bool,
    last_client_verify_data: Vec<u8>,
    last_server_verify_data: Vec<u8>,

    // Handshake transcript (DTLS whole-message form, from ClientHello(2)).
    transcript: Vec<u8>,
    pre_client_finished_transcript: Vec<u8>,

    // Record sequence counters, one per epoch (index = epoch). The write epoch is
    // 0 (initial handshake), 1 (established + renegotiation handshake), 2
    // (post-renegotiation); each ChangeCipherSpec advances it.
    write_seqs: Vec<u64>,
    record_sequence_map: crate::ir::DtlsSequenceMap,
    write_epoch: u16,
    server_next_msg_seq: u16,

    // Inbound reassembly.
    reassembler: Reassembler,
    pending_handshakes: std::collections::VecDeque<HandshakeMessage>,
    pending_records: Vec<(u8, u16, u64, Vec<u8>)>, // (content_type, epoch, seq, body)
    received_datagram_sizes: Vec<usize>,
    // `(epoch << 48 | seq)` of every record received, in wire order, for
    // `assert no_duplicate_record_seqnums`; and the application-data record
    // count for `assert app_data_records == N`.
    received_record_seqs: Vec<u64>,
    received_app_data_records: u32,
    /// Application-data records (epoch, seq, body) that arrived while a
    /// renegotiation handshake was being read: the established epoch stays
    /// valid until the new ChangeCipherSpec, so they are delivered by the next
    /// `read_app_data` instead of being dropped.
    deferred_app_data: Vec<(u16, u64, Vec<u8>)>,

    // Outbound datagram buffer.
    outgoing: Vec<u8>,
    // Last datagram flushed, for `resend_flight`.
    last_flushed: Option<Vec<u8>>,
    // Plaintext records of the pending / last flushed flight (content_type,
    // epoch, payload, mutations) for fresh-sequence retransmission; every
    // flushed datagram for `replay_flight N`; a datagram set aside by
    // hold_flight/hold_retransmit.
    flight_records: Vec<(u8, u16, Vec<u8>, Vec<Mutation>)>,
    last_flight_records: Vec<(u8, u16, Vec<u8>, Vec<Mutation>)>,
    flight_history: Vec<Vec<u8>>,
    held: Option<Vec<Vec<u8>>>,
    // We sent close_notify: the peer closing afterwards is the shutdown we asked
    // for, not a failure.
    sent_close_notify: bool,

    // RFC 5077 session tickets (the TLS 1.2 server's rules, `server12.rs`).
    resumption: Option<SessionState>,
    force_resumption: bool,
    issue_tickets: bool,
    /// The ClientHello's SessionTicket extension body (empty = "send me one").
    client_ticket: Option<Vec<u8>>,
    /// The ServerHello carried the SessionTicket extension, so a
    /// NewSessionTicket MUST precede our ChangeCipherSpec (RFC 5077 3.3).
    promised_ticket: bool,
    ticket_sent: bool,
    /// This handshake resumes the configured session (abbreviated flight).
    resumed: bool,
    /// The last ticket issued and the master secret it stands for.
    issued_ticket: Option<(Vec<u8>, Vec<u8>)>,
    tickets_issued: u32,
    captures: Vec<(String, Vec<u8>)>,
}

impl DtlsServer {
    pub fn new(transport: Box<dyn UutTransport>, cfg: DtlsServerConfig) -> Self {
        let chain_keys =
            crate::tls::chains::parse_chain_keys(&cfg.chains).expect("valid chain keys");
        let private_key = chain_keys.first().cloned().unwrap_or_else(|| {
            PrivateKey::from_pkcs8_der(&cfg.private_key_der).expect("valid private key PKCS#8 DER")
        });
        let chains = cfg.chains.clone();
        let mut sr_rng = Rng::from_seed(Rng::sub_seed(cfg.seed, b"server_random"));
        let server_random = sr_rng.random_array();
        DtlsServer {
            framer: DtlsFramer::new(transport),
            private_key,
            chain_keys,
            certificate_der: cfg.cert_der,
            private_key_der: cfg.private_key_der,
            chains,
            send_mutations: cfg.send_mutations,
            send_ext_deltas: cfg.send_ext_deltas,
            send_overrides: cfg.send_overrides,
            recv_matchers: cfg.recv_matchers,
            seed: cfg.seed,
            allowed_groups: if cfg.groups.is_empty() {
                vec![
                    GROUP_X25519,
                    GROUP_SECP256R1,
                    GROUP_SECP384R1,
                    GROUP_SECP521R1,
                ]
            } else {
                cfg.groups
            },
            client_groups: Vec::new(),
            client_sigalgs: Vec::new(),
            selected_group: GROUP_SECP256R1,
            psk: cfg.psk,
            cert_requested: false,
            client_pubkey: None,
            received_empty_certificate: false,
            server_random,
            client_random: [0u8; 32],
            client_session_id: Vec::new(),
            negotiated_suite: 0,
            allowed_suites: cfg.cipher_suites.clone(),
            use_etm: false,
            use_ems: false,
            hvr_sent: false,
            expected_cookie: None,
            ephemeral: None,
            dhe: None,
            client_version: DTLS12_WIRE_U16,
            master: Vec::new(),
            keys: None,
            reneg_keys: None,
            renegotiating: false,
            last_client_verify_data: Vec::new(),
            last_server_verify_data: Vec::new(),
            transcript: Vec::new(),
            pre_client_finished_transcript: Vec::new(),
            write_seqs: Vec::new(),
            record_sequence_map: crate::ir::DtlsSequenceMap::Identity,
            write_epoch: 0,
            server_next_msg_seq: 0,
            reassembler: Reassembler::new(),
            pending_handshakes: std::collections::VecDeque::new(),
            pending_records: Vec::new(),
            received_datagram_sizes: Vec::new(),
            received_record_seqs: Vec::new(),
            received_app_data_records: 0,
            deferred_app_data: Vec::new(),
            outgoing: Vec::new(),
            last_flushed: None,
            flight_records: Vec::new(),
            last_flight_records: Vec::new(),
            flight_history: Vec::new(),
            held: None,
            sent_close_notify: false,
            resumption: cfg.resumption,
            force_resumption: cfg.force_resumption,
            issue_tickets: cfg.issue_tickets,
            client_ticket: None,
            promised_ticket: false,
            ticket_sent: false,
            resumed: false,
            issued_ticket: None,
            tickets_issued: 0,
            captures: Vec::new(),
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

    /// The key block protecting `epoch`: epoch 1 is the established connection,
    /// epoch 2 a renegotiation. Epoch 0 is plaintext (no keys).
    /// The negotiated suite's parameters (`ir::ALL_SUITES`).
    fn suite_info(&self) -> Result<&'static crate::ir::SuiteInfo, TlsError> {
        crate::ir::suite_info(self.negotiated_suite).ok_or_else(|| {
            TlsError::Dtls(format!(
                "suite 0x{:04x} is not in plzn's catalogue",
                self.negotiated_suite
            ))
        })
    }

    fn keyblock_for_epoch(&self, epoch: u16) -> Option<&EpochKeys> {
        match epoch {
            1 => self.keys.as_ref(),
            2 => self.reneg_keys.as_ref(),
            _ => None,
        }
    }

    /// Encode an outbound record: plaintext at epoch 0, AEAD-sealed under the
    /// server write key at epoch >= 1 (a renegotiation flight rides under the
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
        let kb = self
            .keyblock_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to seal", epoch)))?;
        let sealed = dtls12_seal(&kb.server, content_type, epoch, seq, payload)
            .map_err(|e| TlsError::Dtls(format!("seal: {}", e)))?;
        Ok(encode_record(content_type, epoch, seq, &sealed))
    }

    /// `seal_record` with `record.*` byte mutations on one application-data record.
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
        let kb = self
            .keyblock_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to seal", epoch)))?;
        let sealed = crate::tls::dtls_record::dtls12_seal_with_mutations(
            &kb.server,
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
            &kb.server,
            mutations,
        )
        .map_err(|e| TlsError::Dtls(format!("record mutation: {}", e)))?;
        Ok(record)
    }

    /// Recover a handshake record's plaintext: verbatim at epoch 0, AEAD-opened
    /// under the client write key at epoch >= 1.
    fn open_handshake_record(
        &self,
        epoch: u16,
        seq: u64,
        body: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        if epoch == 0 {
            return Ok(body.to_vec());
        }
        let kb = self
            .keyblock_for_epoch(epoch)
            .ok_or_else(|| TlsError::Dtls(format!("no epoch-{} keys to open", epoch)))?;
        dtls12_open(&kb.client, CONTENT_TYPE_HANDSHAKE, epoch, seq, body).map_err(|e| match e {
            crate::tls::record::RecordError::Crypto(
                crate::tls::crypto::CryptoError::AeadOpenFailed,
            ) => TlsError::Rejected {
                alert: 20,
                reason: "peer record authentication failed".to_string(),
            },
            _ => TlsError::Dtls(format!("open handshake: {}", e)),
        })
    }

    /// Decode an alert `(level, description)`: epoch 0 is plaintext; an encrypted
    /// alert is opened under the client write key for that epoch.
    fn decode_alert(&self, epoch: u16, seq: u64, body: &[u8]) -> Option<(u8, u8)> {
        if epoch == 0 {
            return if body.len() >= 2 {
                Some((body[0], body[1]))
            } else {
                None
            };
        }
        let kb = self.keyblock_for_epoch(epoch)?;
        let pt = dtls12_open(
            &kb.client,
            crate::tls::codec::CONTENT_TYPE_ALERT,
            epoch,
            seq,
            body,
        )
        .ok()?;
        if pt.len() >= 2 {
            Some((pt[0], pt[1]))
        } else {
            None
        }
    }

    // ---- framing ----

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

    /// Seal `payload` under `epoch` with the next sequence number, append it to
    /// the pending flight and remember its plaintext for a retransmission.
    fn push_record(
        &mut self,
        content_type: u8,
        epoch: u16,
        payload: &[u8],
    ) -> Result<(), TlsError> {
        self.push_record_with_mutations(content_type, epoch, payload, &[])
    }

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
    fn header_only_flood(&mut self, count: usize, base_seq: u16) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        let base = base_seq.wrapping_add(1000);
        let mut dg = Vec::new();
        for i in 0..count as u16 {
            let hdr = crate::tls::dtls_record::DtlsHandshakeHeader {
                msg_type: HS_CERTIFICATE,
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

    /// `large_length_fragment N`: send one handshake fragment at a far-future
    /// message_seq whose 24-bit total-length field claims N bytes while the
    /// fragment carries a single byte at offset 0. The peer must bound the
    /// buffer a single pending claim may reserve from the announced length
    /// (RFC 6347 4.2.3; Botan "far-future fragments memory-exhaustible").
    fn large_length_fragment(&mut self, length: u32, base_seq: u16) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        let msg_seq = base_seq.wrapping_add(1000);
        let hdr = crate::tls::dtls_record::DtlsHandshakeHeader {
            msg_type: HS_CERTIFICATE,
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
    /// the out-of-order messages until the gap fills (RFC 6347 4.2.3).
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

    /// Read one datagram within `millis`; None on silence, EOF or an empty frame.
    fn read_within(&mut self, millis: u64) -> Result<Option<Vec<u8>>, TlsError> {
        Ok(match self.read_within_raw(millis)? {
            Read::Data(dg) => Some(dg),
            _ => None,
        })
    }

    fn read_within_raw(&mut self, millis: u64) -> Result<Read, TlsError> {
        self.framer
            .set_read_timeout(Some(std::time::Duration::from_millis(millis.max(1))))
            .map_err(|e| TlsError::Dtls(format!("set read timeout: {}", e)))?;
        let got = self.recv_datagram_traced();
        let _ = self
            .framer
            .set_read_timeout(Some(std::time::Duration::from_secs(5)));
        Ok(match got {
            Ok(Some(dg)) if !dg.is_empty() => Read::Data(dg),
            Ok(Some(_)) => Read::Silence,
            Ok(None) => Read::Eof,
            Err(e) if is_timeout_error(&e) => return Err(TlsError::Timeout),
            Err(_) => Read::Silence,
        })
    }

    /// What a datagram carries, for `wait`: the record types and any alerts.
    fn summarize_datagram(&self, dg: &[u8]) -> Result<DatagramSummary, TlsError> {
        let mut off = 0;
        let mut types = Vec::new();
        let mut alerts = Vec::new();
        while off < dg.len() {
            let (hdr, body, consumed) = parse_record(&dg[off..])
                .map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
            types.push(hdr.content_type);
            if hdr.content_type == crate::tls::codec::CONTENT_TYPE_ALERT {
                if let Some(a) = self.decode_alert(hdr.epoch, hdr.sequence_number, body) {
                    alerts.push(a);
                }
            }
            off += consumed;
        }
        Ok((types, alerts))
    }

    /// Queue a datagram's records for the following recv steps (wire order).
    fn queue_records(&mut self, dg: &[u8]) -> Result<(), TlsError> {
        let mut off = 0;
        let mut recs = Vec::new();
        while off < dg.len() {
            let (hdr, body, consumed) = parse_record(&dg[off..])
                .map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
            recs.push((
                hdr.content_type,
                hdr.epoch,
                hdr.sequence_number,
                body.to_vec(),
            ));
            off += consumed;
        }
        // pending_records pops from the end; keep wire order after what is queued.
        let mut queued = std::mem::take(&mut self.pending_records);
        queued.reverse();
        queued.extend(recs);
        queued.reverse();
        self.pending_records = queued;
        Ok(())
    }

    /// The peer's resent flight: read one datagram, require handshake records
    /// (and no ChangeCipherSpec when `no_ccs`), and queue it so the following
    /// recv steps can process what a discarded original never reached.
    fn expect_retransmit_impl(&mut self, no_ccs: bool) -> Result<(), TlsError> {
        self.flush()?;
        // The first datagram gets the peer's timer a full 2 s; the rest of the
        // flight (a shim may send one datagram per record) follows at once.
        let mut dg = self
            .read_within(2000)?
            .ok_or_else(|| TlsError::Dtls("no retransmit within timeout".into()))?;
        while let Some(more) = self.read_within(100)? {
            dg.extend_from_slice(&more);
        }
        let mut off = 0;
        let mut saw_handshake = false;
        while off < dg.len() {
            let (hdr, _body, consumed) = parse_record(&dg[off..])
                .map_err(|e| TlsError::Dtls(format!("bad retransmit record: {:?}", e)))?;
            self.note_received_record(&hdr);
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
        self.queue_records(&dg)
    }

    /// A HelloRequest that CROSSES a client-initiated renegotiation: the same
    /// message_seq 0 the first one had, under the current epoch, no state change.
    fn send_crossed_hello_request(&mut self) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        self.emit_unhashed_handshake(HS_HELLO_REQUEST, 0, &[], MessageKind::HelloRequest, epoch)
    }

    /// RFC 6347 4.2.1 note: a client may receive several HelloVerifyRequests
    /// with different cookies. Send `count` of them (message_seq i, record
    /// sequence 1000 + i, cookie = eight bytes of i) and count the ClientHellos
    /// the client answers with; a bounded client (Botan
    /// `dtls_maximum_hello_verify_requests`) stops answering and closes.
    fn hvr_flood(&mut self, count: usize, max_answers: usize) -> Result<(), TlsError> {
        self.flush()?;
        let mut answered = 0usize;
        for i in 0..count {
            let cookie = vec![i as u8; 8];
            let body = encode_hello_verify_request(DTLS12_WIRE_U16, &cookie);
            let msg = build_handshake(HS_HELLO_VERIFY_REQUEST, i as u16, &body);
            let rec = encode_record(CONTENT_TYPE_HANDSHAKE, 0, 1000 + i as u64, &msg);
            self.send_datagram(&rec)?;
            // Silence means the client ignored it; EOF that it gave up and closed.
            if let Some(dg) = self.read_within(100)? {
                let mut off = 0;
                let mut is_alert = false;
                while off < dg.len() {
                    let (hdr, _b, consumed) = parse_record(&dg[off..])
                        .map_err(|e| TlsError::Dtls(format!("bad record: {:?}", e)))?;
                    if hdr.content_type == crate::tls::codec::CONTENT_TYPE_ALERT {
                        is_alert = true;
                    }
                    off += consumed;
                }
                if is_alert {
                    break;
                }
                answered += 1;
            }
        }
        self.hvr_sent = true;
        if answered > max_answers {
            return Err(TlsError::Dtls(format!(
                "client answered {} HelloVerifyRequests; the bound is {}",
                answered, max_answers
            )));
        }
        Ok(())
    }

    /// Apply the flow's byte-mutations for `kind` to an encoded body. A body
    /// whose encoder produced a field map lets structured paths
    /// (`handshake.verify_data`, `handshake.signature_algorithms`) resolve
    /// like they do on the TLS 1.2 server; unmapped bodies take offsets.
    fn mutate_encoded(
        &self,
        kind: MessageKind,
        encoded: crate::tls::codec::EncodedBody,
    ) -> Result<Vec<u8>, TlsError> {
        let muts = collect_mutations(&self.send_mutations, kind);
        if muts.is_empty() {
            return Ok(encoded.bytes);
        }
        crate::tls::mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|e| TlsError::Dtls(format!("mutation: {}", e)))
    }

    /// Frame a handshake message into the outbound buffer under the current write
    /// epoch (plaintext at epoch 0, sealed during a renegotiation at epoch 1),
    /// after applying byte-mutations, and fold it into the transcript.
    fn emit_handshake(
        &mut self,
        msg_type: u8,
        kind: MessageKind,
        body: Vec<u8>,
    ) -> Result<(), TlsError> {
        self.emit_encoded(
            msg_type,
            kind,
            crate::tls::codec::EncodedBody {
                bytes: body,
                fields: std::collections::HashMap::new(),
            },
        )
    }

    /// `emit_handshake` for a mapped body (structured mutation paths).
    fn emit_encoded(
        &mut self,
        msg_type: u8,
        kind: MessageKind,
        encoded: crate::tls::codec::EncodedBody,
    ) -> Result<(), TlsError> {
        let body = self.mutate_encoded(kind, encoded)?;
        let seq = self.server_next_msg_seq;
        self.server_next_msg_seq += 1;
        let epoch = self.write_epoch;
        // `send Msg @ <scheme>` / `@ reorder N` fragments this message; default is
        // one fragment. The transcript still covers the whole message once.
        let mutations = collect_mutations(&self.send_mutations, kind).to_vec();
        for fragment in build_fragment_payloads(&self.send_mutations, kind, msg_type, seq, &body) {
            self.push_record_with_mutations(CONTENT_TYPE_HANDSHAKE, epoch, &fragment, &mutations)?;
        }
        self.transcript
            .extend_from_slice(&transcript_bytes(&HandshakeMessage {
                msg_type,
                message_seq: seq,
                body,
            }));
        Ok(())
    }

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
            self.note_received_record(&hdr);
            recs.push((
                hdr.content_type,
                hdr.epoch,
                hdr.sequence_number,
                body.to_vec(),
            ));
            off += consumed;
        }
        recs.reverse();
        self.pending_records = recs;
        Ok(())
    }

    /// Trace one received record for the post-trace asserts.
    fn note_received_record(&mut self, hdr: &crate::tls::dtls_record::DtlsRecordHeader) {
        self.received_record_seqs
            .push(((hdr.epoch as u64) << 48) | (hdr.sequence_number & 0x0000_FFFF_FFFF_FFFF));
        if hdr.content_type == crate::tls::codec::CONTENT_TYPE_APP_DATA {
            self.received_app_data_records = self.received_app_data_records.saturating_add(1);
        }
    }

    fn recv_message(&mut self, want: u8) -> Result<HandshakeMessage, TlsError> {
        self.flush()?;
        loop {
            if let Some(message) = self.pending_handshakes.pop_front() {
                if message.msg_type == want {
                    return Ok(message);
                }
                return Err(TlsError::Dtls(format!(
                    "unexpected handshake message {} (wanted {:?})",
                    message.msg_type, want
                )));
            }
            if self.pending_records.is_empty() {
                self.read_datagram_into_pending()?;
            }
            let (ct, epoch, seq, body) = self.pending_records.pop().unwrap();
            if ct == crate::tls::codec::CONTENT_TYPE_ALERT {
                if let Some((level, description)) = self.decode_alert(epoch, seq, &body) {
                    return Err(TlsError::Alert { level, description });
                }
                return Err(TlsError::Dtls("undecodable alert".into()));
            }
            if ct != CONTENT_TYPE_HANDSHAKE {
                if ct == crate::tls::codec::CONTENT_TYPE_APP_DATA
                    && self.renegotiating
                    && epoch >= 1
                {
                    self.deferred_app_data.push((epoch, seq, body));
                }
                continue;
            }
            if want == HS_FINISHED && epoch != if self.renegotiating { 2 } else { 1 } {
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

    // ---- handshake ----

    pub fn do_handshake(&mut self) -> Result<(), TlsError> {
        // The canonical server flight sequence, driven over the same per-message
        // methods `do_handshake_step` uses (mirrors ir::DTLS12_SERVER_PRESET).
        self.recv_client_hello()?; // CH1
        self.send_hello_verify_request()?;
        self.recv_client_hello()?; // CH2 (cookie)
        self.send_server_hello()?;
        if self.resumed {
            // RFC 5077 3.1 figure 2: the abbreviated flight -- [NewSessionTicket],
            // CCS and Finished first, then the client's.
            self.send_change_cipher_spec()?;
            self.send_finished()?;
            self.recv_change_cipher_spec()?;
            self.recv_client_finished()?;
            self.flush()?;
            return Ok(());
        }
        self.send_certificate()?;
        self.send_server_key_exchange()?;
        self.send_server_hello_done()?;
        self.recv_client_key_exchange()?;
        self.recv_change_cipher_spec()?;
        self.recv_client_finished()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.flush()?;
        Ok(())
    }

    fn recv_client_hello(&mut self) -> Result<(), TlsError> {
        let ch = self.recv_message(HS_CLIENT_HELLO)?;
        let fields = parse_dtls_client_hello(&ch.body)
            .map_err(|e| TlsError::Dtls(format!("bad ClientHello: {:?}", e)))?;
        if self.hvr_sent {
            if let Some(expected) = &self.expected_cookie {
                if fields.cookie != *expected {
                    return Err(TlsError::MatcherFailed {
                        message: "ClientHello",
                        field: "cookie".into(),
                        expected: hex_bytes(expected),
                        observed: hex_bytes(&fields.cookie),
                    });
                }
            }
        }
        // `recv ClientHello { ... }` matchers: strip the DTLS cookie so the TLS
        // codec and the TLS matchers apply to the rest of the body unchanged.
        if self
            .recv_matchers
            .iter()
            .any(|m| m.message == MessageKind::ClientHello)
        {
            let tls_body = crate::tls::dtls_handshake::strip_dtls_cookie(&ch.body)
                .map_err(|e| TlsError::Dtls(format!("bad ClientHello: {:?}", e)))?;
            let decoded = crate::tls::codec::decode_client_hello_body(&tls_body)
                .map_err(|e| TlsError::Dtls(format!("bad ClientHello: {:?}", e)))?;
            for matcher in &self.recv_matchers {
                if matcher.message == MessageKind::ClientHello {
                    for f in &matcher.fields {
                        match (f.field.as_str(), &f.value) {
                            ("cookie", crate::ir::FieldValue::Bytes(want)) => {
                                if fields.cookie != *want {
                                    return Err(TlsError::MatcherFailed {
                                        message: "ClientHello",
                                        field: "cookie".into(),
                                        expected: hex_bytes(want),
                                        observed: hex_bytes(&fields.cookie),
                                    });
                                }
                            }
                            ("cookie_len", crate::ir::FieldValue::U16(want)) => {
                                if fields.cookie.len() != *want as usize {
                                    return Err(TlsError::MatcherFailed {
                                        message: "ClientHello",
                                        field: "cookie_len".into(),
                                        expected: want.to_string(),
                                        observed: fields.cookie.len().to_string(),
                                    });
                                }
                            }
                            ("legacy_version", crate::ir::FieldValue::U16(want)) => {
                                if fields.client_version != *want {
                                    return Err(TlsError::MatcherFailed {
                                        message: "ClientHello",
                                        field: "legacy_version".into(),
                                        expected: format!("0x{:04x}", want),
                                        observed: format!("0x{:04x}", fields.client_version),
                                    });
                                }
                            }
                            (_, crate::ir::FieldValue::Capture(name)) => {
                                let value = crate::tls::driver::capture_client_hello_field(
                                    &decoded, &f.field,
                                )?;
                                self.captures.push((name.clone(), value));
                            }
                            _ => crate::tls::driver::match_client_hello_field(&decoded, f)?,
                        }
                    }
                }
            }
        }
        // What the client offered for negotiation (RFC 4492 5.1 / RFC 5246
        // 7.4.1.4.1). A hello whose extension block plzn cannot decode simply
        // offers nothing, which selects the defaults below.
        self.client_groups.clear();
        self.client_sigalgs.clear();
        self.client_ticket = None;
        if let Ok(tls_body) = crate::tls::dtls_handshake::strip_dtls_cookie(&ch.body) {
            if let Ok(decoded) = crate::tls::codec::decode_client_hello_body(&tls_body) {
                for e in &decoded.extensions {
                    match e {
                        Extension::SupportedGroups(g) => self.client_groups = g.clone(),
                        Extension::SignatureAlgorithms(a) => self.client_sigalgs = a.clone(),
                        Extension::SessionTicket(t) => self.client_ticket = Some(t.clone()),
                        _ => {}
                    }
                }
            }
        }
        self.client_random = fields.random;
        self.client_version = fields.client_version;
        self.client_session_id = fields.session_id.clone();
        // RFC 5077 over DTLS: resume only the session the runner handed us,
        // under the same RFC 7627 5.3 / RFC 5246 7.4.1.2 rules as the TLS 1.2
        // server (`decide_resumption`); a resumed session keeps its suite and
        // exchanges no keys.
        self.resumed = false;
        let force_resumption = self.force_resumption
            && self.resumption.as_ref().is_some_and(|state| {
                !state.is_compatible_with(
                    crate::ir::Protocol::Dtls,
                    crate::tls::record::TlsVersion::Tls12,
                )
            });
        if !self.renegotiating {
            if let Some((suite, ms)) = decide_resumption(
                self.client_ticket.as_deref(),
                self.resumption.as_ref(),
                fields.use_ems,
                &fields.cipher_suites,
            )? {
                self.resumed = true;
                self.negotiated_suite = suite;
                self.master = ms;
            }
        }
        self.promised_ticket = self.client_ticket.is_some() && self.issue_tickets;
        self.ticket_sent = false;
        if !self.resumed {
            self.select_suite(&fields.cipher_suites)?;
            if force_resumption {
                self.resumed = true;
                self.master = self
                    .resumption
                    .as_ref()
                    .expect("force_resumption checked above")
                    .master_secret
                    .clone();
            } else {
                self.select_group()?;
            }
        }
        // RFC 7366 2: echo encrypt_then_mac only when offered AND a block cipher
        // was selected (with an AEAD suite the server MUST NOT send it).
        self.use_etm = fields.use_etm && self.suite_info()?.cipher.is_cbc();
        if self.renegotiating {
            // RFC 5746 3.7: "The server MUST verify that the value of the
            // "renegotiated_connection" field is equal to the saved
            // client_verify_data value; if it is not, the server MUST abort the
            // handshake." The renegotiation ClientHello starts a fresh transcript
            // (message_seq already advanced past the HelloRequest).
            if fields.reneg_info.as_deref() != Some(self.last_client_verify_data.as_slice()) {
                return Err(TlsError::Dtls(
                    "renegotiation_info mismatch on renegotiation ClientHello".into(),
                ));
            }
            self.use_ems = fields.use_ems;
            self.transcript.extend_from_slice(&transcript_bytes(&ch));
        } else if self.hvr_sent {
            // The cookie ClientHello (CH2) starts the transcript; the server's
            // first sent message_seq is 1 (HVR was 0).
            self.use_ems = fields.use_ems;
            self.transcript.extend_from_slice(&transcript_bytes(&ch));
            self.server_next_msg_seq = 1;
        }
        Ok(())
    }

    fn send_hello_verify_request(&mut self) -> Result<(), TlsError> {
        // HVR is message_seq 0 and is NOT part of the transcript.
        let mut version = DTLS12_WIRE_U16;
        let mut cookie = SERVER_COOKIE.to_vec();
        let mut cookie_len = None;
        for ov in collect_overrides(&self.send_overrides, MessageKind::HelloVerifyRequest) {
            match (ov.field.as_str(), &ov.value) {
                ("legacy_version", crate::ir::FieldValue::U16(v)) => version = *v,
                ("cookie", crate::ir::FieldValue::Bytes(v)) => cookie = v.clone(),
                ("cookie_len", crate::ir::FieldValue::U16(v)) if *v <= 255 => {
                    cookie_len = Some(*v as u8)
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "HelloVerifyRequest",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        if cookie.len() > 255 {
            return Err(TlsError::Dtls(format!(
                "HelloVerifyRequest cookie is {} bytes; the wire maximum is 255",
                cookie.len()
            )));
        }
        let mut hvr = encode_hello_verify_request(version, &cookie);
        if let Some(n) = cookie_len {
            hvr[2] = n;
        }
        self.expected_cookie = Some(cookie.clone());
        if self.renegotiating {
            // A cookie exchange on a renegotiation (RFC 6347 4.2.1 leaves it to
            // the server): the HVR rides sealed under the established epoch,
            // and only the cookie ClientHello that follows is in the transcript.
            self.transcript.clear();
            let seq = self.server_next_msg_seq;
            self.server_next_msg_seq += 1;
            let epoch = self.write_epoch;
            self.emit_unhashed_handshake(
                HS_HELLO_VERIFY_REQUEST,
                seq,
                &hvr,
                MessageKind::HelloVerifyRequest,
                epoch,
            )?;
        } else {
            self.emit_unhashed_handshake(
                HS_HELLO_VERIFY_REQUEST,
                0,
                &hvr,
                MessageKind::HelloVerifyRequest,
                0,
            )?;
        }
        self.hvr_sent = true;
        Ok(())
    }

    /// The first suite in the client's offer that this server may select
    /// (`cipher_suites` from peer capabilities, else every DTLS-default suite)
    /// and whose key exchange its certificate can serve: an RSA key the
    /// ECDHE_RSA, DHE_RSA and static-RSA suites, an ECDSA key the ECDHE_ECDSA
    /// ones. No PSK key exchange on this side.
    fn select_suite(&mut self, offered: &[u16]) -> Result<(), TlsError> {
        use crate::ir::KexType;
        // T3: an id-RSASSA-PSS key signs the ECDHE_RSA / DHE_RSA suites (with
        // rsa_pss_pss_*) but cannot do the static-RSA key exchange.
        let rsa_kex = self.private_key.is_rsa();
        let rsa = rsa_kex || self.private_key.is_rsa_pss();
        let psk = self.psk.is_some();
        let allowed: Vec<u16> = if self.allowed_suites.is_empty() {
            crate::ir::filter_suites_dtls(&[], psk)
        } else {
            self.allowed_suites.clone()
        };
        let usable = |w: u16| {
            crate::ir::suite_info(w).is_some_and(|s| match s.kex {
                KexType::EcdheRsa | KexType::DheRsa => rsa,
                KexType::Rsa => rsa_kex,
                KexType::EcdheEcdsa => !rsa,
                KexType::Psk | KexType::EcdhePsk => psk,
            })
        };
        // A: several chains -- pick the (suite, chain) pair together, as the
        // TLS 1.2 server does; nothing fitting falls through to the single-chain
        // path below.
        if self.chain_keys.len() > 1 {
            let pick = offered.iter().find_map(|w| {
                if !allowed.contains(w) {
                    return None;
                }
                let kex = crate::ir::suite_info(*w)?.kex;
                crate::tls::chains::select_server_chain_12(
                    &self.chain_keys,
                    kex,
                    psk,
                    &self.client_sigalgs,
                    &[],
                )
                .map(|i| (*w, i))
            });
            if let Some((suite, idx)) = pick {
                let chain = self.chains[idx].clone();
                self.private_key = self.chain_keys[idx].clone();
                self.certificate_der = chain.cert_der;
                self.private_key_der = chain.key_der;
                self.negotiated_suite = suite;
                return Ok(());
            }
        }
        match offered.iter().find(|w| allowed.contains(w) && usable(**w)) {
            Some(w) => {
                self.negotiated_suite = *w;
                Ok(())
            }
            None => Err(TlsError::Dtls(format!(
                "client offered no suite this server can serve ({} cert{}) among {:?}",
                if rsa {
                    "RSA"
                } else if self.private_key.is_ed25519() {
                    "Ed25519"
                } else {
                    "ECDSA"
                },
                if psk { ", PSK" } else { "" },
                allowed
                    .iter()
                    .map(|w| format!("0x{:04x}", w))
                    .collect::<Vec<_>>()
            ))),
        }
    }

    /// The ECDHE group for the ServerKeyExchange: the first group the client
    /// listed that this server may use (RFC 4492 5.1: a server MUST NOT pick a
    /// curve the client did not list); a client that sent no supported_groups
    /// gets secp256r1. Only the ECDHE families need one.
    fn select_group(&mut self) -> Result<(), TlsError> {
        use crate::ir::KexType;
        if !matches!(
            self.suite_info()?.kex,
            KexType::EcdheRsa | KexType::EcdheEcdsa | KexType::EcdhePsk
        ) {
            return Ok(());
        }
        if self.client_groups.is_empty() {
            self.selected_group = GROUP_SECP256R1;
            return Ok(());
        }
        let implementable =
            |w: u16| ecdhe_group_from_wire(w).is_some_and(|g| !g.is_ffdhe() && !g.is_tls13_only());
        match self
            .client_groups
            .iter()
            .find(|w| self.allowed_groups.contains(w) && implementable(**w))
        {
            Some(w) => {
                self.selected_group = *w;
                Ok(())
            }
            None => Err(TlsError::SelectionUnsatisfiable {
                reason: format!(
                    "no common ECDHE group: client offered {:?}, server allows {:?}",
                    self.client_groups
                        .iter()
                        .map(|w| format!("0x{:04x}", w))
                        .collect::<Vec<_>>(),
                    self.allowed_groups
                        .iter()
                        .map(|w| format!("0x{:04x}", w))
                        .collect::<Vec<_>>()
                ),
            }),
        }
    }

    /// Emit a handshake message that DTLS excludes from the transcript (HVR and
    /// HelloRequest), while still honoring its body/header/record mutations and
    /// fragmentation directives.
    fn emit_unhashed_handshake(
        &mut self,
        msg_type: u8,
        seq: u16,
        body: &[u8],
        kind: MessageKind,
        epoch: u16,
    ) -> Result<(), TlsError> {
        let body = self.mutate_encoded(
            kind,
            crate::tls::codec::EncodedBody {
                bytes: body.to_vec(),
                fields: std::collections::HashMap::new(),
            },
        )?;
        let mutations = collect_mutations(&self.send_mutations, kind).to_vec();
        for fragment in build_fragment_payloads(&self.send_mutations, kind, msg_type, seq, &body) {
            self.push_record_with_mutations(CONTENT_TYPE_HANDSHAKE, epoch, &fragment, &mutations)?;
        }
        Ok(())
    }

    fn send_server_hello(&mut self) -> Result<(), TlsError> {
        // RFC 5746 3.7: a renegotiation ServerHello binds the extension by sending
        // the saved client_verify_data and server_verify_data; empty on the initial.
        let mut ri = self.last_client_verify_data.clone();
        ri.extend_from_slice(&self.last_server_verify_data);
        let mut extensions = vec![Extension::RenegotiationInfo(ri)];
        if self.use_ems {
            extensions.push(Extension::ExtendedMasterSecret);
        }
        if self.use_etm {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_ENCRYPT_THEN_MAC,
                data: Vec::new(),
            });
        }
        // RFC 5077 3.2: the empty SessionTicket extension promises a
        // NewSessionTicket ("MUST NOT send this extension if it does not
        // receive one in the ClientHello").
        if self.promised_ticket {
            extensions.push(Extension::SessionTicket(Vec::new()));
        }
        {
            use crate::tls::driver::{apply_ext_deltas, collect_ext_deltas};
            let deltas = collect_ext_deltas(&self.send_ext_deltas, MessageKind::ServerHello);
            apply_ext_deltas(&mut extensions, deltas);
        }
        // The deltas have the last word on the ticket promise (`+ext` / `-ext
        // session_ticket`, the RFC 5077 3.3 negatives).
        self.promised_ticket = extensions
            .iter()
            .any(|e| matches!(e, Extension::SessionTicket(_)));
        let mut sh = ServerHelloBuilder {
            legacy_version: DTLS12_WIRE_U16,
            random: self.server_random,
            session_id: self.client_session_id.clone(),
            cipher_suite: self.negotiated_suite,
            compression_method: 0,
            extensions,
        };
        for ov in collect_overrides(&self.send_overrides, MessageKind::ServerHello) {
            apply_server_hello_override(&mut sh, ov)?;
        }
        self.emit_encoded(
            HS_SERVER_HELLO,
            MessageKind::ServerHello,
            encode_server_hello_body_mapped(&sh),
        )?;
        if self.resumed {
            // The abbreviated handshake exchanges no keys: epoch 1 derives from
            // the resumed master secret and the new randoms now (RFC 5246 7.3).
            let suite = self.suite_info()?;
            let (client, server) = tls12_direction_keys(
                suite,
                &self.master,
                &self.server_random,
                &self.client_random,
                self.use_etm,
            )?;
            self.keys = Some(EpochKeys { client, server });
        }
        Ok(())
    }

    /// Send an RFC 6066 CertificateStatus with a freshly generated successful
    /// OCSP response for the certificate selected for this connection.
    fn send_certificate_status(&mut self) -> Result<(), TlsError> {
        let mut status_type = crate::tls::codec::CERT_STATUS_TYPE_OCSP;
        let mut response =
            crate::server::ocsp::good_response_now(&self.certificate_der, &self.private_key_der)
                .map_err(|e| TlsError::Dtls(format!("generate OCSP response: {}", e)))?;
        for field in collect_overrides(&self.send_overrides, MessageKind::CertificateStatus) {
            match (field.field.as_str(), &field.value) {
                ("status_type", crate::ir::FieldValue::Ident(value)) if value == "ocsp" => {
                    status_type = crate::tls::codec::CERT_STATUS_TYPE_OCSP;
                }
                ("response", crate::ir::FieldValue::Bytes(value)) => response = value.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateStatus",
                        field: field.field.clone(),
                    });
                }
            }
        }
        self.emit_encoded(
            crate::tls::codec::HS_CERTIFICATE_STATUS,
            MessageKind::CertificateStatus,
            crate::tls::codec::encode_certificate_status_body_mapped(status_type, &response),
        )
    }

    /// Issue a NewSessionTicket (RFC 5077 3.3) over DTLS: the TLS 1.2 server's
    /// opaque ticket (magic, EMS flag, suite, random filler) so the same
    /// resumption rules apply; `send NewSessionTicket { ticket_lifetime |
    /// ticket_lifetime_days | ticket }` override the fields, `@` mutations apply.
    fn send_new_session_ticket(&mut self) -> Result<(), TlsError> {
        let counter = self.tickets_issued;
        self.tickets_issued += 1;
        let mut rng = Rng::from_seed(Rng::sub_seed(self.seed, b"session_ticket_dtls12"));
        let mut ticket = TICKET12_MAGIC.to_vec();
        ticket.push(if self.use_ems { 1 } else { 0 });
        ticket.extend_from_slice(&self.negotiated_suite.to_be_bytes());
        let mut filler: [u8; 32] = rng.random_array();
        filler[0] ^= counter as u8;
        ticket.extend_from_slice(&filler);
        let mut lifetime: u32 = 7200;
        for ov in collect_overrides(&self.send_overrides, MessageKind::NewSessionTicket) {
            match (ov.field.as_str(), &ov.value) {
                ("ticket_lifetime", crate::ir::FieldValue::U16(v)) => lifetime = *v as u32,
                ("ticket_lifetime_days", crate::ir::FieldValue::U16(v)) => {
                    lifetime = (*v as u32) * 86_400
                }
                ("ticket", crate::ir::FieldValue::Bytes(v)) => ticket = v.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "NewSessionTicket",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let encoded = crate::tls::codec::encode_new_session_ticket_body_mapped(lifetime, &ticket);
        self.emit_encoded(
            HS_NEW_SESSION_TICKET,
            MessageKind::NewSessionTicket,
            encoded,
        )?;
        self.ticket_sent = true;
        if !ticket.is_empty() {
            self.issued_ticket = Some((ticket, self.master.clone()));
        }
        Ok(())
    }

    fn send_certificate(&mut self) -> Result<(), TlsError> {
        // RFC 4279 2 / RFC 5489 3.2: the PSK families carry no server
        // Certificate; the preset step is a no-op so one flow serves every family.
        if self.suite_info()?.kex.is_psk() {
            return Ok(());
        }
        // `send Certificate { certificate_list: [...] }` replaces the list (an
        // empty one is the "no certificate" negative); `entries: N` repeats the
        // server certificate N times (0 = empty).
        let overrides = collect_overrides(&self.send_overrides, MessageKind::Certificate).to_vec();
        let list: Vec<Vec<u8>> = match certificate_list_override(&overrides)? {
            Some(l) => l,
            None => {
                let mut n = 1usize;
                for ov in &overrides {
                    match (ov.field.as_str(), &ov.value) {
                        ("entries", crate::ir::FieldValue::U16(v)) => n = *v as usize,
                        ("certificate_list", _) => {}
                        _ => {
                            return Err(TlsError::UnknownFieldOverride {
                                message: "Certificate",
                                field: ov.field.clone(),
                            });
                        }
                    }
                }
                vec![self.certificate_der.clone(); n]
            }
        };
        let refs: Vec<&[u8]> = list.iter().map(|c| c.as_slice()).collect();
        self.emit_encoded(
            HS_CERTIFICATE,
            MessageKind::Certificate,
            encode_certificate_12_body_mapped(&refs),
        )
    }

    fn send_server_key_exchange(&mut self) -> Result<(), TlsError> {
        match self.suite_info()?.kex {
            // RFC 5246 7.4.3: no ServerKeyExchange for the RSA key exchange; the
            // preset step is a no-op so one flow serves every family. RFC 4279 2:
            // the plain-PSK ServerKeyExchange (an identity hint) is optional; none
            // is sent unless `send ServerKeyExchange { psk_identity_hint: ... }`
            // asks for one.
            crate::ir::KexType::Rsa => return Ok(()),
            crate::ir::KexType::Psk => return self.send_psk_hint_server_key_exchange(),
            crate::ir::KexType::DheRsa => return self.send_dhe_server_key_exchange(),
            crate::ir::KexType::EcdhePsk => return self.send_ecdhe_psk_server_key_exchange(),
            _ => {}
        }
        // `send ServerKeyExchange { named_curve: G }` announces (and runs the
        // ECDHE over) a group other than the one selected at ClientHello -- the
        // "server picks a group the client did not offer" negative;
        // `signature_scheme: S` signs with a scheme the client did not list;
        // `key_share_point: zero | truncated | padded | compressed` corrupts the
        // point (the client must reject it, RFC 8422 5.11).
        let mut wire_group = self.selected_group;
        let mut scheme_override: Option<u16> = None;
        let overrides =
            collect_overrides(&self.send_overrides, MessageKind::ServerKeyExchange).to_vec();
        for ov in &overrides {
            match (ov.field.as_str(), &ov.value) {
                ("named_group", crate::ir::FieldValue::U16(g)) => wire_group = *g,
                ("signature_scheme", crate::ir::FieldValue::U16(sch)) => {
                    scheme_override = Some(*sch)
                }
                ("key_share_point", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let (point, ephemeral) = self.server_ecdh_point(wire_group, &overrides)?;
        self.ephemeral = Some(ephemeral);
        let mut params = Vec::new();
        params.push(3u8); // named_curve
        params.extend_from_slice(&wire_group.to_be_bytes());
        params.push(point.len() as u8);
        params.extend_from_slice(&point);
        let signed =
            crate::tls::kex12::ske_signed_input(&self.client_random, &self.server_random, &params);
        // RFC 5246 7.4.1.4.1: sign with a scheme the client listed that the key
        // can produce (RSA-PSS / PKCS#1, ECDSA P-256 / P-384, Ed25519).
        let scheme = match scheme_override {
            Some(wire) => SignatureScheme::from_wire_value(wire).ok_or(TlsError::Internal(
                "ServerKeyExchange.signature_scheme: not a scheme plzn can sign with",
            ))?,
            None => select_signature_scheme(&self.private_key, &self.client_sigalgs),
        };
        let signature = self.private_key.sign(scheme, &signed)?;
        let encoded = encode_ecdhe_server_key_exchange_body_mapped(
            wire_group,
            &point,
            scheme.wire_value(),
            &signature,
        );
        self.emit_encoded(
            HS_SERVER_KEY_EXCHANGE,
            MessageKind::ServerKeyExchange,
            encoded,
        )
    }

    /// A fresh ECDHE ephemeral for `wire_group` and its public value, under the
    /// `key_share_point` recipe of the ServerKeyExchange overrides (the "server
    /// sends a bad point" negatives: zero / truncated / padded / compressed).
    fn server_ecdh_point(
        &self,
        wire_group: u16,
        overrides: &[crate::ir::FieldOverride],
    ) -> Result<(Vec<u8>, EcdhePrivate), TlsError> {
        let group = match ecdhe_group_from_wire(wire_group) {
            Some(g) if !g.is_ffdhe() => g,
            _ => return Err(TlsError::ServerChoseUnsupportedGroup(wire_group)),
        };
        let label: &[u8] = if self.renegotiating {
            b"ecdh_private_reneg"
        } else {
            b"ecdh_private"
        };
        let ephemeral =
            EcdhePrivate::generate(group, &mut Rng::from_seed(Rng::sub_seed(self.seed, label)));
        let recipe = key_share_point_recipe(overrides)?;
        let point = crate::tls::driver::encode_key_share_point(&ephemeral, &recipe)?;
        Ok((point, ephemeral))
    }

    /// The psk_identity_hint plzn's DTLS server sends in a PSK-family
    /// ServerKeyExchange: the configured identity, or a `send ServerKeyExchange
    /// { psk_identity_hint: ... }` override (the "hint the client does not
    /// know" negative).
    fn psk_hint(&self) -> Vec<u8> {
        let mut hint = self
            .psk
            .as_ref()
            .map(|(id, _)| id.clone())
            .unwrap_or_default();
        for ov in collect_overrides(&self.send_overrides, MessageKind::ServerKeyExchange) {
            if let ("psk_identity_hint", crate::ir::FieldValue::Bytes(b)) =
                (ov.field.as_str(), &ov.value)
            {
                hint = b.clone();
            }
        }
        hint
    }

    /// Plain PSK (RFC 4279 2): the ServerKeyExchange is optional and plzn's
    /// server sends none unless a test asks for a hint explicitly.
    fn send_psk_hint_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let asked = collect_overrides(&self.send_overrides, MessageKind::ServerKeyExchange)
            .iter()
            .any(|ov| ov.field == "psk_identity_hint");
        if !asked {
            return Ok(());
        }
        let encoded = crate::tls::kex12::encode_psk_hint_ske_mapped(&self.psk_hint());
        self.emit_encoded(
            HS_SERVER_KEY_EXCHANGE,
            MessageKind::ServerKeyExchange,
            encoded,
        )
    }

    /// ECDHE_PSK ServerKeyExchange (RFC 5489 3.2): the identity hint, then the
    /// unsigned ServerECDHParams for the group chosen at ClientHello
    /// (`named_curve` / `named_group` and `key_share_point` overrides apply as
    /// for the certificate ECDHE families).
    fn send_ecdhe_psk_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let overrides =
            collect_overrides(&self.send_overrides, MessageKind::ServerKeyExchange).to_vec();
        let mut wire_group = self.selected_group;
        for ov in &overrides {
            match (ov.field.as_str(), &ov.value) {
                ("named_group", crate::ir::FieldValue::U16(g)) => wire_group = *g,
                ("psk_identity_hint", _) | ("key_share_point", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let hint = self.psk_hint();
        let (point, ephemeral) = self.server_ecdh_point(wire_group, &overrides)?;
        self.ephemeral = Some(ephemeral);
        let encoded = crate::tls::kex12::encode_ecdhe_psk_ske_mapped(&hint, wire_group, &point);
        self.emit_encoded(
            HS_SERVER_KEY_EXCHANGE,
            MessageKind::ServerKeyExchange,
            encoded,
        )
    }

    /// CertificateRequest (RFC 5246 7.4.4): ask for an RSA or ECDSA client
    /// certificate signed with any scheme plzn verifies; no CA list (any).
    /// CertificateRequest (RFC 5246 7.4.4). `send CertificateRequest {
    /// certificate_types: [...], signature_algorithms: [...] }` replace either
    /// list outright, like the TLS 1.2 server (`[]` is the bounds negative).
    fn send_certificate_request(&mut self) -> Result<(), TlsError> {
        let mut types = vec![CERT_TYPE_ECDSA_SIGN, CERT_TYPE_RSA_SIGN];
        let mut sig_algs = verify_scheme_wires();
        for ov in collect_overrides(&self.send_overrides, MessageKind::CertificateRequest) {
            match (ov.field.as_str(), &ov.value) {
                ("certificate_types", crate::ir::FieldValue::U8List(t)) => types = t.clone(),
                ("signature_algorithms", crate::ir::FieldValue::U16List(a)) => sig_algs = a.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateRequest",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let encoded =
            crate::tls::codec::encode_certificate_request_12_body_mapped(&types, &sig_algs, &[]);
        self.cert_requested = true;
        self.emit_encoded(
            HS_CERTIFICATE_REQUEST,
            MessageKind::CertificateRequest,
            encoded,
        )
    }

    /// The client's Certificate answering our request. An empty
    /// certificate_list is the "no certificate" answer (RFC 5246 7.4.6); this
    /// server continues without client authentication in that case.
    fn recv_client_certificate(&mut self) -> Result<(), TlsError> {
        let msg = self.recv_message(HS_CERTIFICATE)?;
        self.transcript.extend_from_slice(&transcript_bytes(&msg));
        let cert = decode_certificate_12_body(&msg.body)?;
        let chain: Vec<&[u8]> = cert.entries.iter().map(|e| e.as_slice()).collect();
        crate::tls::client_auth::match_client_certificate(
            &chain,
            crate::tls::codec::CERT_TYPE_X509,
            &self.recv_matchers,
        )?;
        self.received_empty_certificate = cert.entries.is_empty();
        self.client_pubkey = None;
        if self.received_empty_certificate {
            return Ok(());
        }
        // Chain trust against the test anchors, as the TLS 1.2 / 1.3 servers do
        // (`client_auth::verify_client_chain`): unknown_ca / certificate_expired.
        crate::tls::client_auth::verify_client_chain(
            &chain,
            &crate::tls::client_auth::default_trust_anchors(),
        )?;
        self.client_pubkey = Some(PublicKey::from_certificate_der(&cert.entries[0])?);
        Ok(())
    }

    /// The client's CertificateVerify (RFC 5246 7.4.8): a signature over every
    /// handshake message so far (DTLS whole-message form, RFC 6347 4.2.6) under
    /// the key from its Certificate, with the scheme the message names.
    fn recv_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        // An empty Certificate omits CertificateVerify. The preset still
        // includes this step, so leave the next handshake message unread.
        if self.received_empty_certificate {
            return Ok(());
        }
        let msg = self.recv_message(HS_CERTIFICATE_VERIFY)?;
        let cv = decode_certificate_verify_13_body(&msg.body)?;
        let scheme = SignatureScheme::from_wire_value(cv.algorithm)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm))?;
        let pk = self.client_pubkey.as_ref().ok_or(TlsError::Dtls(
            "CertificateVerify without a client Certificate".into(),
        ))?;
        pk.verify_tls12(scheme, &self.transcript, &cv.signature)
            .map_err(|_| TlsError::SignatureVerificationFailed)?;
        self.transcript.extend_from_slice(&transcript_bytes(&msg));
        Ok(())
    }

    /// DHE ServerKeyExchange (RFC 5246 7.4.3) over DTLS: explicit ffdhe2048
    /// `ServerDHParams` signed with the RSA key over `client_random ||
    /// server_random || params`. (The DTLS server takes no `dh_p_bits`
    /// override; the too-small-group negative is a TLS case.)
    fn send_dhe_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let seed = if self.renegotiating {
            Rng::sub_seed(self.seed, b"reneg")
        } else {
            self.seed
        };
        let mut group = crate::tls::kex12::DhGroup::ffdhe2048();
        for ov in collect_overrides(&self.send_overrides, MessageKind::ServerKeyExchange) {
            match (ov.field.as_str(), &ov.value) {
                ("dh_p_bits", crate::ir::FieldValue::U16(bits)) => {
                    group = crate::tls::kex12::DhGroup::by_bits(*bits).ok_or(
                        TlsError::Internal("ServerKeyExchange.dh_p_bits: 2048, 1024 or 768"),
                    )?;
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let server = crate::tls::kex12::DheServer::generate(group, seed);
        let params = server.params();
        let signed =
            crate::tls::kex12::ske_signed_input(&self.client_random, &self.server_random, &params);
        let scheme = select_signature_scheme(&self.private_key, &self.client_sigalgs);
        let signature = self.private_key.sign(scheme, &signed)?;
        let encoded = crate::tls::codec::encode_dhe_server_key_exchange_body_mapped(
            &server.group().p,
            &server.group().g,
            server.ys(),
            scheme.wire_value(),
            &signature,
        );
        self.dhe = Some(server);
        self.emit_encoded(
            HS_SERVER_KEY_EXCHANGE,
            MessageKind::ServerKeyExchange,
            encoded,
        )
    }

    fn send_server_hello_done(&mut self) -> Result<(), TlsError> {
        let body = encode_server_hello_done_body();
        self.emit_handshake(HS_SERVER_HELLO_DONE, MessageKind::ServerHelloDone, body)
    }

    fn recv_client_key_exchange(&mut self) -> Result<(), TlsError> {
        let cke = self.recv_message(HS_CLIENT_KEY_EXCHANGE)?;
        // The EMS session_hash (RFC 7627) is over the transcript THROUGH the
        // ClientKeyExchange, so fold it in before deriving the master secret.
        self.transcript.extend_from_slice(&transcript_bytes(&cke));
        let pms = match self.suite_info()?.kex {
            crate::ir::KexType::Rsa => {
                // RFC 5246 7.4.7.1: a bad ciphertext is never an alert; the
                // handshake continues on a random premaster and fails at Finished.
                let encrypted = crate::tls::codec::decode_rsa_client_key_exchange_body(&cke.body)?;
                crate::tls::kex12::rsa_server_premaster(
                    &self.private_key,
                    &encrypted,
                    self.client_version,
                    self.seed,
                )
            }
            crate::ir::KexType::DheRsa => {
                let yc = crate::tls::codec::decode_dhe_client_key_exchange_body(&cke.body)?;
                let dhe = self.dhe.take().ok_or(TlsError::Internal(
                    "DHE ClientKeyExchange before ServerKeyExchange",
                ))?;
                dhe.premaster(&yc)?
            }
            crate::ir::KexType::Psk | crate::ir::KexType::EcdhePsk => {
                // RFC 4279 2 / RFC 5489 3.3: the ClientKeyExchange carries the
                // psk_identity (and, for ECDHE_PSK, the client's ECDH point); an
                // identity this server does not know is a fatal error (the RFC
                // allows unknown_psk_identity or decrypt_error).
                let with_point = self.suite_info()?.kex == crate::ir::KexType::EcdhePsk;
                let (identity, point) = crate::tls::kex12::decode_psk_cke(&cke.body, with_point)?;
                let (want, secret) = self.psk.clone().ok_or(TlsError::Internal(
                    "PSK suite selected without a PSK credential",
                ))?;
                if identity != want {
                    // RFC 4279 2 / RFC 5489 3.3: no key for this identity. plzn
                    // answers unknown_psk_identity (the RFC also permits
                    // decrypt_error or continuing to a Finished failure) so the
                    // client sees a definite rejection rather than a bare close.
                    return Err(TlsError::Rejected {
                        alert: 115, // unknown_psk_identity
                        reason: format!(
                            "no PSK for identity {:?} (serving {:?})",
                            String::from_utf8_lossy(&identity),
                            String::from_utf8_lossy(&want)
                        ),
                    });
                }
                match point {
                    Some(point) => {
                        let ephemeral = self.ephemeral.take().ok_or(TlsError::Internal(
                            "ECDHE_PSK ClientKeyExchange before ServerKeyExchange",
                        ))?;
                        let z = ephemeral.agree(&point)?;
                        crate::tls::kex12::psk_premaster_with(&z, &secret)
                    }
                    None => psk_premaster(&secret),
                }
            }
            _ => {
                let client_point = decode_ecdhe_client_key_exchange_body(&cke.body)?;
                let ephemeral = self
                    .ephemeral
                    .take()
                    .ok_or(TlsError::Internal("missing ephemeral"))?;
                ephemeral.agree(&client_point)?
            }
        };
        let suite = self.suite_info()?;
        let prf = suite.prf;
        self.master = if self.use_ems {
            let session_hash = crate::tls::crypto::hash(prf, &self.transcript);
            crate::tls::handshake::derive_master_secret_ems(prf, &pms, &session_hash)
        } else {
            derive_master_secret(prf, &pms, &self.client_random, &self.server_random)
        };
        let (client, server) = tls12_direction_keys(
            suite,
            &self.master,
            &self.server_random,
            &self.client_random,
            self.use_etm,
        )?;
        let kb = EpochKeys { client, server };
        // A renegotiation installs epoch-2 keys; the initial handshake epoch-1.
        if self.renegotiating {
            self.reneg_keys = Some(kb);
        } else {
            self.keys = Some(kb);
        }
        Ok(())
    }

    /// `recv Alert`: read the peer's next record and surface it as the alert the
    /// runner classifies (a malformed message the client rejects, say). Anything
    /// other than an alert is a step failure naming the content type.
    fn recv_alert(&mut self) -> Result<(), TlsError> {
        self.flush()?;
        loop {
            if let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                if ct == crate::tls::codec::CONTENT_TYPE_ALERT {
                    if let Some((l, d)) = self.decode_alert(epoch, seq, &body) {
                        return Err(TlsError::Alert {
                            level: l,
                            description: d,
                        });
                    }
                    return Err(TlsError::Dtls("undecodable alert record".into()));
                }
                self.pending_records.push((ct, epoch, seq, body));
                return Err(TlsError::Record(
                    crate::tls::record::RecordError::UnexpectedContentType {
                        expected: crate::tls::codec::CONTENT_TYPE_ALERT,
                        got: ct,
                    },
                ));
            }
            self.read_datagram_into_pending()?;
        }
    }

    fn recv_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        self.flush()?;
        loop {
            if let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                match ct {
                    CONTENT_TYPE_CCS => {
                        let plaintext = if epoch == 0 {
                            body
                        } else {
                            let keys = self.keyblock_for_epoch(epoch).ok_or_else(|| {
                                TlsError::Dtls(format!(
                                    "ChangeCipherSpec at epoch {} without keys",
                                    epoch
                                ))
                            })?;
                            dtls12_open(&keys.client, CONTENT_TYPE_CCS, epoch, seq, &body).map_err(
                                |e| TlsError::Dtls(format!("ChangeCipherSpec decrypt: {}", e)),
                            )?
                        };
                        if plaintext != [0x01] {
                            return Err(TlsError::Rejected {
                                alert: 10,
                                reason: "ChangeCipherSpec payload is not the single byte 0x01"
                                    .to_string(),
                            });
                        }
                        return Ok(());
                    }
                    crate::tls::codec::CONTENT_TYPE_ALERT => {
                        if let Some((l, d)) = self.decode_alert(epoch, seq, &body) {
                            return Err(TlsError::Alert {
                                level: l,
                                description: d,
                            });
                        }
                        return Err(TlsError::Dtls(
                            "undecodable alert before ChangeCipherSpec".into(),
                        ));
                    }
                    _ => {
                        self.pending_records.push((ct, epoch, seq, body));
                        return Err(TlsError::Dtls(format!(
                            "expected ChangeCipherSpec, got content type {}",
                            ct
                        )));
                    }
                }
            } else {
                self.read_datagram_into_pending()?;
            }
        }
    }

    fn recv_client_finished(&mut self) -> Result<(), TlsError> {
        self.pre_client_finished_transcript = self.transcript.clone();
        let expected = verify_data(
            self.suite_info()?.prf,
            &self.master,
            b"client finished",
            &self.pre_client_finished_transcript,
        );
        let message = self.recv_message(HS_FINISHED)?;
        if message.body != expected {
            return Err(TlsError::FinishedMismatch);
        }
        self.transcript
            .extend_from_slice(&crate::tls::dtls_handshake::transcript_bytes(&message));
        self.last_client_verify_data = expected;
        Ok(())
    }

    fn send_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        // RFC 5077 3.3: a promised NewSessionTicket goes out before the
        // ChangeCipherSpec, unless an explicit step already sent it.
        if self.promised_ticket && !self.ticket_sent {
            self.send_new_session_ticket()?;
        }
        // The CCS rides under the current write epoch (plaintext at epoch 0, sealed
        // during a renegotiation at epoch 1) and activates the next epoch.
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
        // Server Finished over the transcript through the client Finished, sealed
        // under the just-activated epoch (1 initial, 2 renegotiation).
        let epoch = self.write_epoch;
        let server_vd = verify_data(
            self.suite_info()?.prf,
            &self.master,
            b"server finished",
            &self.transcript,
        );
        // Save for the RFC 5746 renegotiation_info of a further reneg.
        self.last_server_verify_data = server_vd.clone();
        // `send Finished { verify_data: ... }` replaces the value outright;
        // byte-mutations then target the verify_data body.
        let server_vd = finished_verify_data_override(
            collect_overrides(&self.send_overrides, MessageKind::Finished),
            server_vd,
        )?;
        let fin_body = self.mutate_encoded(
            MessageKind::Finished,
            encode_finished_body_mapped(&server_vd),
        )?;
        let seq = self.server_next_msg_seq;
        self.server_next_msg_seq += 1;
        let mutations = collect_mutations(&self.send_mutations, MessageKind::Finished).to_vec();
        let mut fin_msg = build_handshake(HS_FINISHED, seq, &fin_body);
        crate::tls::mutate::apply_handshake_header_mutations(&mut fin_msg, &mutations);
        // In the abbreviated handshake the client's Finished covers ours
        // (RFC 5246 7.4.9), so fold it into the transcript.
        self.transcript.extend_from_slice(&fin_msg);
        for fragment in build_fragment_payloads(
            &self.send_mutations,
            MessageKind::Finished,
            HS_FINISHED,
            seq,
            &fin_body,
        ) {
            self.push_record_with_mutations(CONTENT_TYPE_HANDSHAKE, epoch, &fragment, &mutations)?;
        }
        Ok(())
    }

    /// Reset per-handshake state for a renegotiation. The established epoch-1 keys
    /// are RETAINED; the reneg flight is sealed under them until its CCS activates
    /// epoch 2. The previous verify_data is kept for the RFC 5746 binding.
    fn begin_renegotiation(&mut self) {
        self.renegotiating = true;
        self.transcript.clear();
        self.pre_client_finished_transcript.clear();
        // RFC 6347 4.2.2: message_seq restarts at 0 for each handshake.
        self.server_next_msg_seq = 0;
        // Fresh server_random, distinct from the initial handshake; the ephemeral
        // is generated at ServerKeyExchange for the group the new hello selects.
        self.server_random =
            Rng::from_seed(Rng::sub_seed(self.seed, b"server_random_reneg")).random_array();
        self.ephemeral = None;
        self.client_groups.clear();
        self.client_sigalgs.clear();
        self.selected_group = GROUP_SECP256R1;
        self.cert_requested = false;
        self.client_pubkey = None;
        self.received_empty_certificate = false;
        self.client_random = [0u8; 32];
        self.client_session_id.clear();
        self.negotiated_suite = 0;
        self.use_ems = false;
        self.master.clear();
        self.dhe = None;
        self.reneg_keys = None;
        self.hvr_sent = false;
        self.expected_cookie = None;
        self.client_ticket = None;
        self.promised_ticket = false;
        self.ticket_sent = false;
        self.resumed = false;
        // Inbound message_seq also restarts at 0.
        self.reassembler = Reassembler::new();
        self.pending_handshakes.clear();
        self.pending_records.clear();
        // write_epoch stays 1: the renegotiation flight rides under the established
        // epoch-1 keys until its CCS bumps writing to epoch 2.
    }

    /// True once the initial handshake has completed and no renegotiation is in
    /// progress: both Finished values are saved for the RFC 5746 binding.
    fn handshake_complete(&self) -> bool {
        !self.renegotiating
            && !self.last_client_verify_data.is_empty()
            && !self.last_server_verify_data.is_empty()
    }

    /// A client-initiated renegotiation (RFC 5246 7.4.1.2) arrived while the
    /// server was reading application data: `record` is the epoch-1 handshake
    /// record carrying the ClientHello. Run the server side of the second
    /// handshake under the current keys (the RFC 5746 3.7 binding is verified
    /// in `recv_client_hello`) exactly as after a HelloRequest, minus the
    /// HelloRequest; application data then continues at epoch 2.
    fn accept_client_renegotiation(
        &mut self,
        record: (u8, u16, u64, Vec<u8>),
    ) -> Result<(), TlsError> {
        // begin_renegotiation clears the inbound queue; the rest of this datagram
        // (and the ClientHello itself, popped first) must survive it.
        let rest = std::mem::take(&mut self.pending_records);
        self.begin_renegotiation();
        self.pending_records = rest;
        self.pending_records.push(record);
        self.recv_client_hello()?;
        self.send_server_hello()?;
        self.send_certificate()?;
        self.send_server_key_exchange()?;
        self.send_server_hello_done()?;
        self.recv_client_key_exchange()?;
        self.recv_change_cipher_spec()?;
        self.recv_client_finished()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.flush()
    }

    /// Refuse a client-initiated renegotiation: a `send alert
    /// warning/no_renegotiation` after `recv ClientHello` abandons the pending
    /// second handshake (RFC 5246 7.4.1.1: the peer "MAY respond with a
    /// no_renegotiation alert" and the connection continues under the
    /// established keys). `begin_renegotiation` touched only per-handshake
    /// scratch, so clearing the flag is the return to the established state.
    fn abandon_renegotiation(&mut self) {
        self.renegotiating = false;
        self.reassembler = Reassembler::new();
        self.pending_handshakes.clear();
        self.hvr_sent = false;
        self.expected_cookie = None;
    }

    /// Send a HelloRequest (RFC 5246 7.4.1.1: "struct { } HelloRequest;"), sealed
    /// under the current epoch. It is excluded from the transcript.
    fn send_hello_request(&mut self) -> Result<(), TlsError> {
        let seq = self.server_next_msg_seq;
        self.server_next_msg_seq += 1;
        let epoch = self.write_epoch;
        self.emit_unhashed_handshake(HS_HELLO_REQUEST, seq, &[], MessageKind::HelloRequest, epoch)
    }

    /// Drive a server-initiated renegotiation: send a HelloRequest, then run the
    /// server side of a second handshake (RFC 5246 7.4.1.1). Unlike the initial
    /// handshake there is no HelloVerifyRequest cookie exchange.
    pub fn renegotiate(&mut self) -> Result<(), TlsError> {
        self.begin_renegotiation();
        self.send_hello_request()?;
        self.recv_client_hello()?;
        self.send_server_hello()?;
        self.send_certificate()?;
        self.send_server_key_exchange()?;
        self.send_server_hello_done()?;
        self.recv_client_key_exchange()?;
        self.recv_change_cipher_spec()?;
        self.recv_client_finished()?;
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.flush()?;
        Ok(())
    }
}

impl TlsEndpoint for DtlsServer {
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
        DtlsServer::do_handshake(self)
    }
    fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError> {
        use crate::ir::HandshakeStep::{Recv, Send};
        match step {
            // A ClientHello after a completed handshake is a client-initiated
            // renegotiation (RFC 5246 7.4.1.2): the second handshake runs under
            // the established epoch-1 keys with the RFC 5746 3.7 binding.
            Recv(MessageKind::ClientHello) => {
                if self.handshake_complete() {
                    self.begin_renegotiation();
                }
                self.recv_client_hello()
            }
            Send(MessageKind::HelloVerifyRequest) => self.send_hello_verify_request(),
            Send(MessageKind::ServerHello) => self.send_server_hello(),
            Send(MessageKind::Certificate) => self.send_certificate(),
            Send(MessageKind::CertificateStatus) => self.send_certificate_status(),
            Send(MessageKind::ServerKeyExchange) => self.send_server_key_exchange(),
            Send(MessageKind::CertificateRequest) => self.send_certificate_request(),
            Send(MessageKind::ServerHelloDone) => self.send_server_hello_done(),
            Recv(MessageKind::Certificate) => self.recv_client_certificate(),
            Recv(MessageKind::ClientKeyExchange) => self.recv_client_key_exchange(),
            Recv(MessageKind::CertificateVerify) => self.recv_client_certificate_verify(),
            Recv(MessageKind::ChangeCipherSpec) => self.recv_change_cipher_spec(),
            Recv(MessageKind::Finished) => self.recv_client_finished(),
            Send(MessageKind::ChangeCipherSpec) => self.send_change_cipher_spec(),
            Send(MessageKind::Finished) => self.send_finished(),
            Send(MessageKind::NewSessionTicket) => self.send_new_session_ticket(),
            Recv(MessageKind::Alert) => self.recv_alert(),
            // `send HelloRequest`: the first opens a stepped renegotiation; a
            // second one while it is pending is a crossed request (RFC 5246
            // 7.4.1.1: the client is already negotiating and must ignore it).
            Send(MessageKind::HelloRequest) => {
                if self.renegotiating {
                    self.send_crossed_hello_request()
                } else {
                    self.begin_renegotiation();
                    self.send_hello_request()
                }
            }
            other => Err(TlsError::Dtls(format!(
                "unsupported DTLS server step: {:?}",
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
        DtlsServer::renegotiate(self)
    }
    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        // Application data under the server's current write epoch. Buffered like a
        // handshake record so it can be sent before Finished (out-of-order
        // application data the client must discard). `record.*` mutations tamper
        // with this one record's MAC / tag.
        let epoch = self.write_epoch;
        self.push_record_with_mutations(
            crate::tls::codec::CONTENT_TYPE_APP_DATA,
            epoch,
            data,
            mutations,
        )
    }
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        self.flush()?;
        // Application data that crossed a renegotiation handshake, in order.
        if !self.deferred_app_data.is_empty() {
            let (epoch, seq, body) = self.deferred_app_data.remove(0);
            let kb = self.keyblock_for_epoch(epoch).ok_or_else(|| {
                TlsError::Dtls(format!("application data at epoch {} without keys", epoch))
            })?;
            return dtls12_open(
                &kb.client,
                crate::tls::codec::CONTENT_TYPE_APP_DATA,
                epoch,
                seq,
                &body,
            )
            .map_err(|e| TlsError::Dtls(format!("application data decrypt: {}", e)));
        }
        loop {
            while let Some((ct, epoch, seq, body)) = self.pending_records.pop() {
                if ct == crate::tls::codec::CONTENT_TYPE_ALERT {
                    if let Some((l, d)) = self.decode_alert(epoch, seq, &body) {
                        return Err(TlsError::Alert {
                            level: l,
                            description: d,
                        });
                    }
                    continue;
                }
                // RFC 5246 7.4.1.2: "the client can request a renegotiation by
                // sending a new ClientHello" at any time after the handshake.
                // Any other handshake record here (a delayed duplicate Finished
                // after a retransmission, RFC 6347 4.2.4) is ordinary DTLS
                // reordering and is dropped, as before.
                if ct == CONTENT_TYPE_HANDSHAKE && epoch >= 1 && self.handshake_complete() {
                    let is_client_hello = self
                        .open_handshake_record(epoch, seq, &body)
                        .ok()
                        .is_some_and(|pt| pt.first() == Some(&HS_CLIENT_HELLO));
                    if is_client_hello {
                        self.accept_client_renegotiation((ct, epoch, seq, body))?;
                        return self.read_app_data();
                    }
                    continue;
                }
                if ct == crate::tls::codec::CONTENT_TYPE_APP_DATA && epoch >= 1 {
                    let kb = self.keyblock_for_epoch(epoch).ok_or_else(|| {
                        TlsError::Dtls(format!("application data at epoch {} without keys", epoch))
                    })?;
                    return dtls12_open(
                        &kb.client,
                        crate::tls::codec::CONTENT_TYPE_APP_DATA,
                        epoch,
                        seq,
                        &body,
                    )
                    .map_err(|e| TlsError::Dtls(format!("application data decrypt: {}", e)));
                }
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
        if self.master.is_empty() {
            return Err(TlsError::Internal(
                "exporter requested before the DTLS handshake",
            ));
        }
        Ok(crate::tls::handshake::export_keying_material_tls12(
            self.suite_info()?.prf,
            &self.master,
            label,
            &self.client_random,
            &self.server_random,
            context,
            length,
        ))
    }
    fn send_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        let epoch = self.write_epoch;
        self.push_record(crate::tls::codec::CONTENT_TYPE_ALERT, epoch, &[level, code])?;
        if (level, code) == (1, 0) {
            self.sent_close_notify = true;
        }
        // RFC 5246 7.4.1.1: a no_renegotiation warning refuses the pending
        // client-initiated renegotiation; the association continues at epoch 1.
        const NO_RENEGOTIATION: u8 = 100;
        if (level, code) == (1, NO_RENEGOTIATION) && self.renegotiating && self.keys.is_some() {
            self.abandon_renegotiation();
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
        self.push_record_with_mutations(
            crate::tls::codec::CONTENT_TYPE_ALERT,
            epoch,
            &[level, code],
            mutations,
        )?;
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
    fn advance_clock(&mut self, nanos: u64) -> Result<(), TlsError> {
        // Advance the client's virtual retransmit clock; our own pending flight is
        // deliberately withheld so the client's timer fires.
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
                            if i + 1 < n && self.read_within(100)?.is_some() {
                                return Err(TlsError::Dtls(
                                    "peer responded to a partial flight".into(),
                                ));
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
                self.send_flight(&dg)
            }
            DtlsOp::MapRecordSequences(map) => {
                self.flush()?;
                self.record_sequence_map = *map;
                Ok(())
            }
            DtlsOp::HvrFlood { count, max_answers } => self.hvr_flood(*count, *max_answers),
            DtlsOp::ExpectRetransmitNoCcs => self.expect_retransmit_impl(true),
            DtlsOp::HeaderOnlyFlood { count } => {
                self.header_only_flood(*count, self.server_next_msg_seq)
            }
            DtlsOp::LargeLengthFragment { length } => {
                self.large_length_fragment(*length, self.server_next_msg_seq)
            }
            DtlsOp::FutureSeqFirst => self.future_seq_first(),
            DtlsOp::InterleaveFlight { split } => {
                let recs = interleave_records(&self.outgoing)?;
                if *split {
                    self.outgoing.clear();
                    for r in &recs {
                        self.send_datagram(r)?;
                    }
                } else {
                    self.outgoing = recs.concat();
                }
                Ok(())
            }
            DtlsOp::BeginRenegotiation | DtlsOp::Restart => Err(TlsError::Dtls(format!(
                "`{}` is a DTLS client (`uut server`) step; a server opens a renegotiation with `send HelloRequest`",
                op.keyword()
            ))),
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
        // `wait`: after (e.g.) a partial flight, the client must stay silent.
        // Anything but silence is reported: an alert as the alert (so a pinned
        // expectation can match it), a clean close as a close, other data as the
        // peer advancing early. A close_notify warning is a clean close in
        // progress and is tolerated.
        self.flush()?;
        loop {
            match self.read_within_raw(millis)? {
                Read::Silence => return Ok(()),
                Read::Eof => {
                    if self.sent_close_notify {
                        return Ok(()); // the shutdown we asked for
                    }
                    return Err(TlsError::Record(crate::tls::record::RecordError::Io(
                        std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "peer closed during a wait",
                        ),
                    )));
                }
                Read::Data(dg) => {
                    let (types, alerts) = self.summarize_datagram(&dg)?;
                    let only_alerts = types
                        .iter()
                        .all(|t| *t == crate::tls::codec::CONTENT_TYPE_ALERT);
                    if only_alerts && !alerts.is_empty() {
                        if let Some(&(level, description)) = alerts.iter().find(|a| **a != (1, 0)) {
                            return Err(TlsError::Alert { level, description });
                        }
                        continue; // close_notify warning(s): a clean close in progress
                    }
                    return Err(TlsError::Record(
                        crate::tls::record::RecordError::UnexpectedContentType {
                            expected: 0,
                            got: *types
                                .iter()
                                .find(|ct| **ct != crate::tls::codec::CONTENT_TYPE_APP_DATA)
                                .unwrap_or(&crate::tls::codec::CONTENT_TYPE_APP_DATA),
                        },
                    ));
                }
            }
        }
    }
    fn resend_flight(&mut self) -> Result<(), TlsError> {
        self.flush()?;
        let dg = self
            .last_flushed
            .clone()
            .ok_or_else(|| TlsError::Dtls("resend_flight with no prior flight".into()))?;
        self.send_flight(&dg)
    }
    fn write_raw(&mut self, data: &[u8]) -> Result<(), TlsError> {
        self.flush()?;
        self.framer
            .send_datagram(data)
            .map_err(|e| TlsError::Dtls(format!("send raw datagram: {}", e)))
    }
    fn send_key_update(&mut self, _request_update: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is not a DTLS 1.2 feature"))
    }
    fn recv_key_update(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal("KeyUpdate is not a DTLS 1.2 feature"))
    }
    fn session_state(&self) -> Option<SessionState> {
        let (ticket, master_secret) = self.issued_ticket.as_ref()?;
        Some(SessionState {
            protocol: crate::ir::Protocol::Dtls,
            version: crate::tls::record::TlsVersion::Tls12,
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
