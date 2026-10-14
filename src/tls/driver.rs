// TLS 1.2 ECDHE happy-path client driver.
//
// Orchestrates:
//
//   ClientHello -> (server flight) -> ClientKeyExchange ->
//   ChangeCipherSpec -> Finished -> (server CCS, Finished) ->
//   [app data exchange]
//
// Scope is the happy path for TLS_ECDHE_{RSA,ECDSA}_WITH_AES_128_GCM_SHA256
// with secp256r1 as the ECDHE curve. Everything else rejects with a
// specific error so we can grow coverage deliberately.

use crate::tls::codec::{
    ByteCursor, CONTENT_TYPE_CCS, CONTENT_TYPE_HANDSHAKE, ClientHello, CodecError, Extension,
    GROUP_SECP256R1, GROUP_SECP384R1, GROUP_X25519, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_CLIENT_KEY_EXCHANGE, HS_ENCRYPTED_EXTENSIONS,
    HS_END_OF_EARLY_DATA, HS_FINISHED, HS_HELLO_REQUEST, HS_KEY_UPDATE, HS_NEW_SESSION_TICKET,
    HS_SERVER_HELLO, HS_SERVER_HELLO_DONE, HS_SERVER_KEY_EXCHANGE, KeyShareEntry,
    PROTOCOL_VERSION_TLS12, PROTOCOL_VERSION_TLS13, PskIdentity,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256, TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256,
    decode_certificate_12_body, decode_certificate_13_body, decode_certificate_request_13_body,
    decode_certificate_verify_13_body, decode_dhe_server_key_exchange_body,
    decode_dhe_server_key_exchange_body_legacy, decode_ecdhe_server_key_exchange_body,
    decode_ecdhe_server_key_exchange_body_legacy, decode_encrypted_extensions_body,
    decode_finished_body, decode_key_update_body, decode_new_session_ticket_13_body,
    decode_new_session_ticket_body, decode_server_hello_body, decode_server_hello_done_body,
    encode_client_hello_body_mapped, encode_dhe_client_key_exchange_body_mapped,
    encode_ecdhe_client_key_exchange_body_mapped, encode_finished_body_mapped, encode_handshake,
    encode_key_update_body, encode_rsa_client_key_exchange_body_mapped, parse_handshake_header,
    tls13_certificate_verify_signed_input, tls13_client_certificate_verify_signed_input,
};
use crate::tls::crypto::{
    AeadAlg, CryptoError, EcdheGroup, EcdhePrivate, HashAlg, KeyKind, PublicKey, Rng,
    SignatureScheme, TranscriptHash, rsa_pkcs1v15_encrypt,
};
use crate::tls::handshake::{
    Tls13KeySchedule, compute_verify_data, compute_verify_data_for, derive_master_secret,
    derive_master_secret_ems_for, derive_master_secret_for, export_keying_material_legacy,
};
use crate::tls::record::{DirectionKeys, RecordError, RecordLayer, TlsVersion};
use crate::transport::UutTransport;

use crate::ir::{
    ExtDeltaOp, FieldOverride, FieldValue, MessageExtDeltas, MessageKind, MessageMutations,
    MessageOverrides, Mutation,
};
use crate::tls::mutate;

// ============================================================
//                       TlsEndpoint trait
// ============================================================
//
// Minimum interface the runtime needs from a TLS client. Both
// `Tls12Client` and `Tls13Client` implement it via delegation to
// their existing methods. Keeping the trait narrow: just the
// happy-path surface for now. Add methods here as the runtime
// grows to need them.

pub trait TlsEndpoint {
    /// Bound all reads in one application-response operation, including
    /// intervening post-handshake traffic. Implementations restore their normal
    /// timeout when the deadline is cleared.
    fn set_read_deadline(&mut self, _deadline: Option<std::time::Instant>) -> Result<(), TlsError> {
        Ok(())
    }
    fn configure_message(&mut self, _config: &crate::ir::MessageConfig) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "per-step configuration unsupported by this endpoint",
        ))
    }
    fn do_handshake(&mut self) -> Result<(), TlsError>;
    fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError>;
    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError>;
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError>;
    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, TlsError>;
    fn tls_unique(&self) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::Internal("tls-unique is defined only for TLS 1.2"))
    }
    fn write_early_data(&mut self, _data: &[u8], _mutations: &[Mutation]) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "early data is only supported by TLS 1.3",
        ))
    }
    fn read_early_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::Internal(
            "early data is only supported by TLS 1.3",
        ))
    }
    fn close(&mut self) -> Result<(), TlsError>;
    /// Abortive close (`close reset`): a TCP RST instead of a FIN. Endpoints
    /// on transports without the notion just close.
    fn close_reset(&mut self) -> Result<(), TlsError> {
        self.close()
    }
    /// T6: `recv alert level[/code]`: read one record; it must be an alert of
    /// that level (and code). Any other record, or a different alert, fails.
    fn recv_alert(&mut self, _level: u8, _code: Option<u8>) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "`recv alert` is not supported by this driver",
        ))
    }
    /// Send a `[level, description]` alert record (e.g. warning/close_notify)
    /// under the installed write keys, then close the transport. The default is
    /// only overridden by the client drivers, which is the direction that drives
    /// a graceful `close alert warning/close_notify` shutdown.
    fn close_with_alert(&mut self, _level: u8, _code: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "close with alert is only implemented for the client drivers",
        ))
    }
    fn negotiated_cipher_suite(&self) -> u16;
    /// Probe: try to read for up to `millis` milliseconds. If
    /// data arrives (typically an alert), return Err with the
    /// alert. If the read times out (silence), return Ok.
    /// Used for Bleichenbacher oracle detection.
    fn probe(&mut self, millis: u64) -> Result<(), TlsError>;
    /// Write raw bytes directly to the transport, bypassing the
    /// TLS record layer entirely. Used for injecting malformed
    /// or crafted records.
    fn write_raw(&mut self, data: &[u8]) -> Result<(), TlsError>;
    /// Send a TLS 1.3 KeyUpdate message and rotate write keys.
    fn send_key_update(&mut self, request_update: u8) -> Result<(), TlsError>;
    /// Read a TLS 1.3 KeyUpdate message and rotate read keys.
    fn recv_key_update(&mut self) -> Result<(), TlsError>;
    fn recv_key_update_matching(&mut self, matchers: &[FieldOverride]) -> Result<(), TlsError> {
        if !matchers.is_empty() {
            return Err(TlsError::Internal(
                "KeyUpdate matchers unsupported by this endpoint",
            ));
        }
        self.recv_key_update()
    }
    /// Replay the initial ClientHello as an encrypted post-handshake record
    /// (a renegotiation attempt). Only meaningful for a TLS 1.3 client.
    fn send_renegotiation(&mut self, _msg_type: Option<u8>) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "renegotiation injection is only implemented for the TLS 1.3 client",
        ))
    }
    /// Drive a full renegotiation: a second handshake on the live connection
    /// (TLS 1.2). Only the TLS 1.2 client implements it today. `insecure` omits
    /// renegotiation_info on the renegotiation ClientHello (RFC 5746 3.5 legacy
    /// renegotiation); `overrides` / `ext_deltas` customize that ClientHello.
    fn renegotiate_with(
        &mut self,
        _resumed: bool,
        _insecure: bool,
        _overrides: &[FieldOverride],
        _ext_deltas: &[ExtDeltaOp],
    ) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "renegotiation is only implemented for the TLS 1.2 client",
        ))
    }
    /// T5: `begin_renegotiation` over TLS -- reset to a renegotiation handshake
    /// and let the flow's explicit steps drive it. TLS 1.2 client only.
    fn begin_renegotiation_step(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "begin_renegotiation over TLS is only implemented for the TLS 1.2 client",
        ))
    }
    /// T5: overrides / mutations / ext deltas declared after a TLS
    /// `begin_renegotiation` (see `Program::reneg_*`). Only the TLS 1.2 client
    /// keeps them; every other endpoint ignores them.
    fn install_reneg_lists(
        &mut self,
        _overrides: Vec<MessageOverrides>,
        _mutations: Vec<MessageMutations>,
        _ext_deltas: Vec<MessageExtDeltas>,
    ) {
    }
    /// Advance the peer's DTLS retransmit clock by `nanos` (RFC 6347 4.2.4).
    /// Only the DTLS driver implements it.
    fn advance_clock(&mut self, _nanos: u64) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "advance_clock is only implemented for the DTLS driver",
        ))
    }
    /// Assert the UUT's next DTLS retransmission deadline. `None` means no
    /// timer may be armed.
    fn expect_next_timeout(&mut self, _nanos: Option<u64>) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "timeout assertions are only implemented for the DTLS driver",
        ))
    }
    /// Rescale the UUT's live DTLS timeout schedule.
    fn set_timeout(&mut self, _millis: u32) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "set_timeout is only implemented for the DTLS driver",
        ))
    }
    /// Tell the shim server to rotate its DTLS cookie secret (the 'C' control
    /// frame). Only the DTLS client implements it.
    fn rotate_cookie_secret(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "rotate_cookie_secret is only implemented for the DTLS client",
        ))
    }
    /// Read one datagram and require it to carry handshake records (the peer's
    /// resent flight). Only the DTLS driver implements it.
    fn expect_retransmit(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "expect_retransmit is only implemented for the DTLS driver",
        ))
    }
    /// Flush the buffered flight, then resend the identical datagram (a DTLS
    /// replay). Only the DTLS driver implements it.
    fn resend_flight(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "resend_flight is only implemented for the DTLS driver",
        ))
    }
    /// DTLS flight control (loss, delay, replay, retransmission, restart); see
    /// `ir::DtlsOp`. Only the DTLS drivers implement it.
    fn dtls_op(&mut self, _op: &crate::ir::DtlsOp) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "DTLS flight steps are only implemented for the DTLS drivers",
        ))
    }
    /// Send a `[level, description]` alert record under the current write keys
    /// without closing. Only the DTLS drivers implement it today.
    fn send_alert(&mut self, _level: u8, _code: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "send alert (without close) is only implemented for the DTLS drivers",
        ))
    }
    /// `send alert level/code @ mutations` (T2): record mutations on the alert
    /// record. Only the TLS drivers implement the mutated form.
    fn send_alert_with(
        &mut self,
        level: u8,
        code: u8,
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        if mutations.is_empty() {
            self.send_alert(level, code)
        } else {
            Err(TlsError::Internal(
                "mutations on `send alert` are only implemented for the TLS drivers",
            ))
        }
    }
    /// `coalesce [hold_keys] { ... }`: buffer handshake messages into one
    /// record until `end_coalesce`. Only the TLS drivers implement it.
    fn begin_coalesce(&mut self, _mode: crate::ir::CoalesceMode) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "coalesce is only implemented for the TLS drivers",
        ))
    }
    /// `atomic { ... }`: every record until `end_atomic` goes out in one write.
    /// Only the TLS drivers implement it (T2).
    fn begin_atomic(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "atomic is only implemented for the TLS drivers",
        ))
    }
    fn end_atomic(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "atomic is only implemented for the TLS drivers",
        ))
    }
    /// `send record N "..."`: a record of content type N under the current
    /// write keys. TLS and DTLS drivers implement it (T2).
    fn send_record(&mut self, _content_type: u8, _data: &[u8]) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "send record is not implemented for this endpoint",
        ))
    }
    /// `send record N ... @ mutations` / `send empty_record T @ mutations`.
    fn send_record_with(
        &mut self,
        content_type: u8,
        data: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        if mutations.is_empty() {
            if data.is_empty() {
                self.send_empty_record(content_type)
            } else {
                self.send_record(content_type, data)
            }
        } else {
            Err(TlsError::Internal(
                "mutations on `send record` are not implemented for this endpoint",
            ))
        }
    }
    fn end_coalesce(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "coalesce is only implemented for the TLS drivers",
        ))
    }
    /// `send empty_record <type>`: a zero-length record under the current keys.
    /// TLS and DTLS drivers implement it.
    fn send_empty_record(&mut self, _content_type: u8) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "send empty_record is not implemented for this endpoint",
        ))
    }
    /// `flush_fragment`: send the fragment held back by `@ fragment N hold`.
    /// Only the TLS drivers implement it.
    fn flush_fragment(&mut self) -> Result<(), TlsError> {
        Err(TlsError::Internal(
            "flush_fragment is only implemented for the TLS drivers",
        ))
    }
    // T1: the values recorded by `capture $name` matchers, in capture order.
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        Vec::new()
    }
    // T1: the explicit nonces (RFC 5288 3) of every TLS 1.2 explicit-nonce AEAD
    // record the endpoint received, in wire order; None where the record layer
    // keeps no such trace.
    fn explicit_nonce_trace(&self) -> Option<Vec<u64>> {
        None
    }
    /// `send KeyUpdate ... @ mutations`: as `send_key_update`, with byte and
    /// record mutations (a fragment held across the key change, say). Only the
    /// TLS 1.3 drivers implement the mutated form.
    fn send_key_update_with(
        &mut self,
        request_update: u8,
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        if mutations.is_empty() {
            self.send_key_update(request_update)
        } else {
            Err(TlsError::Internal(
                "mutations on KeyUpdate are only implemented for the TLS 1.3 drivers",
            ))
        }
    }
    /// Capture session state for resumption (ticket + master secret).
    fn session_state(&self) -> Option<crate::ir::SessionState>;
    /// Whether the completed connection used an abbreviated/resumed handshake.
    /// Endpoints that implement resumption return `Some` for both the resumed
    /// and full-handshake outcomes so `assert resumed == false` is meaningful.
    fn negotiated_resumed(&self) -> Option<bool> {
        None
    }
    /// Whether TLS 1.3 early data was accepted. TLS 1.2/DTLS endpoints return
    /// None so an inapplicable assertion cannot silently read as false.
    fn negotiated_early_data_accepted(&self) -> Option<bool> {
        None
    }
    /// The `(epoch << 48 | sequence_number)` identity of every record the
    /// endpoint received, in wire order — for post-trace asserts like
    /// `no_duplicate_record_seqnums` (RFC 6347 4.1.2). `None` for endpoints that
    /// keep no such trace (the TLS drivers); DTLS overrides it.
    fn record_seq_trace(&self) -> Option<Vec<u64>> {
        None
    }
    /// Sizes of all datagrams received from the UUT, in wire order. DTLS
    /// endpoints override this for `assert max_datagram_size N`.
    fn datagram_size_trace(&self) -> Option<Vec<usize>> {
        None
    }
    /// T5: how many post-handshake NewSessionTicket messages this endpoint
    /// received over the flow (explicit `recv`, swallowed while waiting for
    /// another message, or during a `wait`) -- `assert new_session_tickets`.
    /// `None` for endpoints that do not count (servers).
    fn new_session_tickets_seen(&self) -> Option<u32> {
        None
    }
    /// How many application-data records (content type 23) this endpoint
    /// received over the flow -- `assert app_data_records == N`. Every
    /// endpoint that reads records counts them; `None` means the assert cannot
    /// be evaluated here.
    fn app_data_records_received(&self) -> Option<u32> {
        None
    }
}

impl TlsEndpoint for Tls12Client {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> Result<(), TlsError> {
        self.records
            .set_read_deadline(deadline)
            .map_err(|error| TlsError::Record(RecordError::Io(error)))
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
    fn new_session_tickets_seen(&self) -> Option<u32> {
        Some(self.nst_seen + self.records.swallowed_nst_count())
    }
    fn app_data_records_received(&self) -> Option<u32> {
        Some(self.records.app_data_records_read())
    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        Tls12Client::do_handshake(self)
    }
    fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError> {
        Tls12Client::do_handshake_step(self, step)
    }
    fn renegotiate_with(
        &mut self,
        resumed: bool,
        insecure: bool,
        overrides: &[FieldOverride],
        ext_deltas: &[ExtDeltaOp],
    ) -> Result<(), TlsError> {
        Tls12Client::renegotiate_with(self, resumed, insecure, overrides, ext_deltas)
    }
    fn begin_renegotiation_step(&mut self) -> Result<(), TlsError> {
        self.begin_renegotiation();
        Ok(())
    }
    fn install_reneg_lists(
        &mut self,
        overrides: Vec<MessageOverrides>,
        mutations: Vec<MessageMutations>,
        ext_deltas: Vec<MessageExtDeltas>,
    ) {
        self.cfg.reneg_send_overrides = overrides;
        self.cfg.reneg_send_mutations = mutations;
        self.cfg.reneg_send_ext_deltas = ext_deltas;
    }
    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        Tls12Client::write_app_data(self, data, mutations)
    }
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Tls12Client::read_app_data(self)
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
        Tls12Client::close(self)
    }
    fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        Tls12Client::close_with_alert(self, level, code)
    }
    fn close_reset(&mut self) -> Result<(), TlsError> {
        self.records
            .close_reset()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }
    fn recv_alert(&mut self, level: u8, code: Option<u8>) -> Result<(), TlsError> {
        t6_expect_alert_record(&mut self.records, level, code)
    }
    fn negotiated_cipher_suite(&self) -> u16 {
        Tls12Client::negotiated_cipher_suite(self)
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
            .map_err(TlsError::Record)
    }
    fn send_alert_with(
        &mut self,
        level: u8,
        code: u8,
        mutations: &[Mutation],
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
        mutations: &[Mutation],
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
        // T5: a ticket when one was issued, else the server-assigned session
        // id (RFC 5246 7.4.1.3) so the next session can resume by echoing it.
        match &self.captured_ticket {
            Some(t) => Some(crate::ir::SessionState {
                protocol: crate::ir::Protocol::Tls,
                version: self.cfg.version,
                ticket: t.clone(),
                master_secret: self.master_secret.clone(),
                session_id: self.established_session_id.clone(),
                ticket_age_add: 0,
                cipher_suite: 0,
                max_early_data_size: 0,
            }),
            None if !self.established_session_id.is_empty() && !self.master_secret.is_empty() => {
                Some(crate::ir::SessionState {
                    protocol: crate::ir::Protocol::Tls,
                    version: self.cfg.version,
                    ticket: Vec::new(),
                    master_secret: self.master_secret.clone(),
                    session_id: self.established_session_id.clone(),
                    ticket_age_add: 0,
                    cipher_suite: 0,
                    max_early_data_size: 0,
                })
            }
            None => None,
        }
    }
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        self.captures.clone()
    }
    fn negotiated_resumed(&self) -> Option<bool> {
        Some(self.resumed)
    }
    fn explicit_nonce_trace(&self) -> Option<Vec<u64>> {
        Some(self.records.explicit_nonce_trace())
    }
}

/// T1: the bytes a `capture $name` matcher records from a ServerHello (or
/// HelloRetryRequest) field.
pub(crate) fn capture_server_hello_field(
    sh: &crate::tls::codec::ServerHello,
    field: &str,
) -> Result<Vec<u8>, TlsError> {
    match field {
        "random" => Ok(sh.random.to_vec()),
        "legacy_session_id_echo" => Ok(sh.session_id.clone()),
        "cipher_suite" => Ok(sh.cipher_suite.to_be_bytes().to_vec()),
        "legacy_version" => Ok(sh.legacy_version.to_be_bytes().to_vec()),
        "key_share" => sh
            .extensions
            .iter()
            .find_map(|ext| match ext {
                crate::tls::codec::Extension::KeyShare(entries) => {
                    entries.first().map(|entry| entry.key_exchange.clone())
                }
                crate::tls::codec::Extension::KeyShareSingle(entry) => {
                    Some(entry.key_exchange.clone())
                }
                _ => None,
            })
            .ok_or(TlsError::Internal(
                "capture: ServerHello has no key_share value",
            )),
        _ => Err(TlsError::Internal(
            "capture: only random, legacy_session_id_echo, cipher_suite, legacy_version and key_share can be captured from a ServerHello",
        )),
    }
}

impl TlsEndpoint for Tls13Client {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> Result<(), TlsError> {
        self.records
            .set_read_deadline(deadline)
            .map_err(|error| TlsError::Record(RecordError::Io(error)))
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
    fn new_session_tickets_seen(&self) -> Option<u32> {
        Some(self.nst_seen + self.records.swallowed_nst_count())
    }
    fn app_data_records_received(&self) -> Option<u32> {
        Some(self.records.app_data_records_read())
    }
    fn captures(&self) -> Vec<(String, Vec<u8>)> {
        self.captures.clone()
    }
    fn do_handshake(&mut self) -> Result<(), TlsError> {
        Tls13Client::do_handshake(self)
    }
    fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError> {
        Tls13Client::do_handshake_step(self, step)
    }
    fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        Tls13Client::write_app_data(self, data, mutations)
    }
    fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        Tls13Client::read_app_data(self)
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
    fn write_early_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        Tls13Client::write_early_data(self, data, mutations)
    }
    fn close(&mut self) -> Result<(), TlsError> {
        Tls13Client::close(self)
    }
    fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        Tls13Client::close_with_alert(self, level, code)
    }
    fn close_reset(&mut self) -> Result<(), TlsError> {
        self.records
            .close_reset()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }
    fn recv_alert(&mut self, level: u8, code: Option<u8>) -> Result<(), TlsError> {
        loop {
            let (ct, body) = self.records.read_record().map_err(TlsError::Record)?;
            if ct == CONTENT_TYPE_HANDSHAKE {
                let mut cursor = ByteCursor::new(&body);
                let mut only_tickets = !body.is_empty();
                while !cursor.is_empty() {
                    let Ok((msg_type, len)) = parse_handshake_header(&mut cursor) else {
                        only_tickets = false;
                        break;
                    };
                    let Ok(ticket_body) = cursor.take(len) else {
                        only_tickets = false;
                        break;
                    };
                    if msg_type != HS_NEW_SESSION_TICKET {
                        only_tickets = false;
                        break;
                    }
                    if let Ok(nst) = decode_new_session_ticket_13_body(ticket_body) {
                        self.nst_seen += 1;
                        self.captured_nst = Some(nst);
                    }
                }
                if only_tickets {
                    continue;
                }
            }
            return t6_match_alert_record(ct, &body, level, code);
        }
    }
    fn negotiated_cipher_suite(&self) -> u16 {
        Tls13Client::negotiated_cipher_suite(self)
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
            while let Some(framed) = self.records.take_swallowed_nst() {
                self.captured_nst = Some(decode_new_session_ticket_13_body(&framed[4..])?);
            }
            match result {
                Err(RecordError::KeyUpdateReceived { framed }) => {
                    let request = decode_key_update_body(&framed[4..])?;
                    self.rotate_read_keys()?;
                    self.key_update_response_pending |= request == 1;
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
        Tls13Client::send_key_update(self, request_update)
    }
    fn recv_key_update(&mut self) -> Result<(), TlsError> {
        Tls13Client::recv_key_update(self)
    }
    fn recv_key_update_matching(&mut self, matchers: &[FieldOverride]) -> Result<(), TlsError> {
        self.cfg
            .recv_matchers
            .retain(|m| m.message != MessageKind::KeyUpdate);
        self.cfg.recv_matchers.push(MessageOverrides {
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
        Tls13Client::send_renegotiation(self, msg_type)
    }
    fn send_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(crate::tls::codec::CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)
    }
    fn send_alert_with(
        &mut self,
        level: u8,
        code: u8,
        mutations: &[Mutation],
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
        mutations: &[Mutation],
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
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        Tls13Client::send_key_update_with(self, request_update, mutations)
    }
    fn session_state(&self) -> Option<crate::ir::SessionState> {
        let rms = self.resumption_master_secret.as_ref()?;
        let nst = self.captured_nst.as_ref()?;
        let psk = self.schedule.derive_resumption_psk(rms, &nst.ticket_nonce);
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
        Some(crate::ir::SessionState {
            protocol: if self.records.is_dtls13() {
                crate::ir::Protocol::Dtls
            } else {
                crate::ir::Protocol::Tls
            },
            version: TlsVersion::Tls13,
            ticket: nst.ticket.clone(),
            master_secret: psk, // for TLS 1.3, "master_secret" carries the resumption PSK
            session_id: Vec::new(),
            ticket_age_add: nst.ticket_age_add,
            cipher_suite: self.negotiated_suite,
            max_early_data_size,
        })
    }
    fn negotiated_resumed(&self) -> Option<bool> {
        Some(self.server_selected_psk)
    }
}

/// Construct the right TLS endpoint for a (version, subject)
/// combination. `uut server` → client driver, `uut client` → server
/// driver.
//
// Many args, but they all come straight from `ir::Program` fields;
// bundling them into a config struct would just shift the noise.
#[allow(clippy::too_many_arguments)]
pub fn make_endpoint(
    version: TlsVersion,
    protocol: crate::ir::Protocol,
    subject: crate::ir::Subject,
    server_name: &str,
    transport: Box<dyn UutTransport>,
    seed: [u8; 32],
    send_overrides: Vec<MessageOverrides>,
    recv_matchers: Vec<MessageOverrides>,
    send_mutations: Vec<MessageMutations>,
    send_ext_deltas: Vec<MessageExtDeltas>,
    cert_der: Option<Vec<u8>>,
    private_key_der: Option<Vec<u8>>,
    extra_chain_der: Vec<Vec<u8>>,
    suite_filters: &[crate::ir::SuiteFilter],
    server_suites: Vec<u16>,
    server_groups: Vec<u16>,
    key_share_groups: Vec<u16>,
    psk: Option<crate::ir::PskConfig>,
    session_state: Option<&crate::ir::SessionState>,
    force_resumption: bool,
    advertise_psk_modes: bool,
    resume_psk_ke: bool,
    offer_raw_public_key: bool,
    server_compress_certificate: bool,
    cert_request_authorities: Vec<Vec<u8>>,
    client_signature_schemes: Option<Vec<u16>>,
    // A: every chain plzn's SERVER holds (uut client), the client-auth
    // credentials plzn's CLIENT picks from (uut server), and whether
    // `client_chain: []` said "no credential at all".
    server_chains: Vec<crate::ir::Chain>,
    client_credentials: Vec<crate::ir::Chain>,
    client_chain_none: bool,
    use_early_data: bool,
    force_hrr: bool,
) -> Box<dyn TlsEndpoint> {
    use crate::ir::Subject;
    // A conforming plzn server only accepts state created by the same protocol
    // generation. `force_resume: true` deliberately bypasses this for the
    // malicious-server half of the cross-version matrix. A plzn client always
    // receives the state: offering it to a UUT server is itself the test.
    let server_resumption = session_state
        .filter(|state| state.is_compatible_with(protocol, version) || force_resumption)
        .cloned();
    // DTLS routes to its own datagram driver, reusing the TLS 1.2 crypto. Only
    // `uut server` (harness = DTLS client) is supported today. The IR
    // override/mutate/matcher channels are threaded in Phase 2 (per-message
    // steps); the whole-handshake path here does not consume them.
    if protocol == crate::ir::Protocol::Dtls && version == TlsVersion::Tls12 {
        return match subject {
            // `uut server`: plzn is the DTLS client, the shim is the server.
            Subject::Server => {
                let cfg = crate::tls::dtls_driver::DtlsClientConfig {
                    client_random: seed,
                    server_name: server_name.to_string(),
                    // The DTLS offer: suite capabilities over Botan's DTLS rule,
                    // the PSK family when a `psk { }` block is present.
                    cipher_suites: crate::ir::filter_suites_dtls(suite_filters, psk.is_some()),
                    psk: psk.map(|p| (p.identity, p.secret)),
                    // Group capabilities are the client's supported_groups, in
                    // order; empty = the driver default.
                    groups: server_groups.clone(),
                    signature_schemes: client_signature_schemes.clone().unwrap_or_default(),
                    // A client-auth flow presents this credential (None = the
                    // shims/testdata end-entity client certificate).
                    client_cert_der: cert_der,
                    client_private_key_der: private_key_der,
                    client_credentials,
                    client_chain_none,
                    send_overrides,
                    send_mutations,
                    recv_matchers,
                    send_ext_deltas,
                    // RFC 5077 over DTLS: the prior session's ticket + master
                    // secret (a `session` that `resumes`), and whether to ask
                    // for a ticket (the session a later one resumes).
                    session_ticket: session_state.map(|ss| ss.ticket.clone()),
                    prior_master_secret: session_state.map(|ss| ss.master_secret.clone()),
                    advertise_session_ticket: advertise_psk_modes,
                };
                Box::new(crate::tls::dtls_driver::DtlsClient::new(transport, cfg))
            }
            // `uut client`: plzn is the DTLS server, the shim is the client.
            Subject::Client => {
                let psk_pair = psk.map(|p| (p.identity, p.secret));
                let cfg = crate::tls::dtls_server::DtlsServerConfig {
                    cert_der: cert_der.expect("DTLS server mode requires cert_der"),
                    private_key_der: private_key_der
                        .expect("DTLS server mode requires private_key_der"),
                    chains: server_chains,
                    seed,
                    // What plzn's DTLS server may select: the certificate
                    // families, or the PSK family when a `psk { }` block is present.
                    cipher_suites: crate::ir::filter_suites_dtls(suite_filters, psk_pair.is_some()),
                    // Group capabilities: the groups the server may pick from.
                    groups: server_groups.clone(),
                    psk: psk_pair,
                    send_overrides,
                    send_mutations,
                    recv_matchers,
                    send_ext_deltas,
                    resumption: server_resumption.clone(),
                    force_resumption,
                    issue_tickets: advertise_psk_modes,
                };
                Box::new(crate::tls::dtls_server::DtlsServer::new(transport, cfg))
            }
        };
    }
    match (version, subject) {
        (
            version @ (TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12),
            Subject::Server,
        ) => {
            let mut cfg = Tls12ClientConfig::default_for(server_name, seed);
            cfg.version = version;
            // Group capabilities are the client's supported_groups, in order.
            if !server_groups.is_empty() {
                cfg.groups = server_groups.clone();
            }
            // A `psk { }` block turns the offer into the PSK / ECDHE_PSK families.
            let filtered = crate::ir::filter_suites_legacy(version, suite_filters, psk.is_some());
            cfg.cipher_suites = filtered;
            if let Some(schemes) = client_signature_schemes {
                cfg.signature_schemes = schemes;
            }
            cfg.psk = psk.map(|p| (p.identity, p.secret));
            cfg.offer_raw_public_key = offer_raw_public_key;
            cfg.send_overrides = send_overrides;
            cfg.recv_matchers = recv_matchers;
            cfg.send_mutations = send_mutations;
            cfg.send_ext_deltas = send_ext_deltas;
            if let Some(ss) = session_state {
                // T5: resume by ticket when one was issued, else by session id.
                if !ss.ticket.is_empty() {
                    cfg.session_ticket = Some(ss.ticket.clone());
                } else if !ss.session_id.is_empty() {
                    cfg.resume_session_id = Some(ss.session_id.clone());
                }
                cfg.prior_master_secret = Some(ss.master_secret.clone());
            }
            // Client-auth: cert/key used when the server sends CertificateRequest.
            // The runner hands a `uut server` program no certificate, so the
            // shim test client credential (the one the shim server is told to
            // trust) stands in.
            match (cert_der, private_key_der) {
                (Some(c), Some(k)) => {
                    cfg.client_cert_der = Some(c);
                    cfg.client_private_key_der = Some(k);
                }
                // A: `client_chain: []` -- no credential, an empty Certificate.
                _ if client_chain_none => {}
                _ => {
                    if let Some((c, k)) = crate::shim::test_client_credential_der() {
                        cfg.client_cert_der = Some(c);
                        cfg.client_private_key_der = Some(k);
                    }
                }
            }
            cfg.client_credentials = client_credentials;
            cfg.advertise_session_ticket = advertise_psk_modes;
            Box::new(Tls12Client::new(transport, cfg))
        }
        (
            version @ (TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12),
            Subject::Client,
        ) => {
            let cfg = crate::tls::server12::Tls12ServerConfig {
                version,
                cert_der: cert_der.expect("server mode requires cert_der"),
                private_key_der: private_key_der.expect("server mode requires private_key_der"),
                chains: server_chains,
                seed,
                send_overrides,
                recv_matchers,
                send_mutations,
                send_ext_deltas,
                // Suite capabilities narrow what the server may select (so
                // `capabilities: [cbc]` is a CBC server); empty = every suite we
                // implement. A `psk { }` block switches to the PSK families.
                cipher_suites: crate::ir::filter_suites_legacy(
                    version,
                    suite_filters,
                    psk.is_some(),
                ),
                // RFC 5077 tickets: the session this connection may resume (the
                // ticket + master secret plzn's server issued on an earlier
                // connection), and whether to promise a (renewal) ticket when
                // the client offers the SessionTicket extension -- true for the
                // session a later one resumes and for the `session_ticket` capability.
                resumption: server_resumption.clone(),
                force_resumption,
                issue_tickets: advertise_psk_modes,
                offer_raw_public_key,
                // Group capabilities: the groups the server may select (ECDHE
                // named curves; ffdhe* for DHE). Empty = the default set.
                groups: server_groups,
                // Signature-scheme capabilities: what the server may sign with.
                signature_schemes: client_signature_schemes.unwrap_or_default(),
                psk: psk.map(|p| (p.identity, p.secret)),
                cert_request_authorities,
            };
            Box::new(crate::tls::server12::Tls12Server::new(transport, cfg))
        }
        (TlsVersion::Tls13, Subject::Server) => {
            let mut cfg = Tls13ClientConfig::default_for(server_name, seed);
            cfg.send_overrides = send_overrides;
            cfg.recv_matchers = recv_matchers;
            cfg.send_mutations = send_mutations;
            cfg.send_ext_deltas = send_ext_deltas;
            // Suite capabilities and the `suite` matrix axis narrow the TLS 1.3
            // offer too; key-exchange predicates mean nothing in TLS 1.3 and are
            // ignored, so `capabilities: [ecdhe_rsa]` keeps the default offer.
            let filters13: Vec<crate::ir::SuiteFilter> = suite_filters
                .iter()
                .filter(|f| !matches!(f, crate::ir::SuiteFilter::Kex(_)))
                .copied()
                .collect();
            if !filters13.is_empty() {
                let filtered = crate::ir::filter_suites(TlsVersion::Tls13, &filters13);
                cfg.cipher_suites = filtered;
            }
            // Group capabilities are the client's supported_groups (in order) and
            // a key share goes with the first; the `group` matrix axis
            // (key_share_groups) or a `+ext key_share = [...]` delta overrides
            // which groups get shares.
            if !server_groups.is_empty() {
                cfg.groups = server_groups.clone();
                cfg.key_share_groups = vec![server_groups[0]];
            }
            if !key_share_groups.is_empty() {
                cfg.key_share_groups = key_share_groups;
            }
            cfg.psk = psk;
            cfg.use_early_data = use_early_data;
            // For TLS 1.3 session resumption: session_state carries
            // the ticket (as PSK identity) and derived PSK (as secret).
            if let Some(ss) = session_state {
                cfg.psk = Some(crate::ir::PskConfig {
                    identity: ss.ticket.clone(),
                    secret: ss.master_secret.clone(),
                    offers: Vec::new(),
                    // `psk_ke` on the resuming session: PSK-only, no key share.
                    ke_only: resume_psk_ke,
                    is_external: false, // resumption PSK → "res binder"
                    // Sessions run back-to-back, so elapsed age starts at zero.
                    obfuscated_ticket_age: ss.ticket_age_add,
                    cipher_suite: Some(ss.cipher_suite),
                    max_early_data_size: ss.max_early_data_size,
                });
            }
            cfg.client_cert_der = cert_der;
            cfg.client_private_key_der = private_key_der;
            // A: the credentials `client_chain:` named (selection on the
            // CertificateRequest); `[]` means no credential at all.
            cfg.client_credentials = client_credentials;
            cfg.client_chain_none = client_chain_none;
            // Client-auth chain: intermediates presented after the client leaf.
            cfg.client_extra_chain_der = extra_chain_der;
            cfg.advertise_psk_modes = advertise_psk_modes;
            cfg.offer_raw_public_key = offer_raw_public_key;
            cfg.offer_cert_compression = server_compress_certificate;
            if let Some(schemes) = client_signature_schemes {
                cfg.signature_schemes = schemes;
            }
            if protocol == crate::ir::Protocol::Dtls {
                Box::new(Tls13Client::new_dtls13(transport, cfg))
            } else {
                Box::new(Tls13Client::new(transport, cfg))
            }
        }
        (TlsVersion::Tls13, Subject::Client) => {
            let cfg = crate::tls::server13::Tls13ServerConfig {
                cert_der: cert_der.expect("server mode requires cert_der"),
                private_key_der: private_key_der.expect("server mode requires private_key_der"),
                chains: server_chains,
                extra_chain_der,
                seed,
                send_overrides,
                recv_matchers,
                send_mutations,
                send_ext_deltas,
                server_suites,
                server_groups,
                force_hrr,
                compress_certificate: server_compress_certificate,
                offer_raw_public_key,
                accept_client_rpk: offer_raw_public_key,
                cert_request_authorities,
                // The ticket + PSK plzn's server issued on the session this one
                // resumes (None = decline every pre_shared_key offer).
                resumption: server_resumption,
                force_resumption,
                // A client certificate must chain to one of the testdata roots
                // (client_ee_ca, client_chain_root, the shim clients' own
                // self-signed credentials); see `client_auth`.
                client_trust_anchors: crate::tls::client_auth::default_trust_anchors(),
                // The external PSK of a `psk { }` block, accepted when the
                // client names its identity and the binder verifies.
                psk,
            };
            if protocol == crate::ir::Protocol::Dtls {
                Box::new(crate::tls::server13::Tls13Server::new_dtls13(
                    transport, cfg,
                ))
            } else {
                Box::new(crate::tls::server13::Tls13Server::new(transport, cfg))
            }
        }
    }
}

/// Look up mutations targeting a specific message kind.
pub(crate) fn collect_mutations(list: &[MessageMutations], kind: MessageKind) -> &[Mutation] {
    for entry in list {
        if entry.message == kind {
            return &entry.mutations;
        }
    }
    &[]
}

pub(crate) fn write_tls13_handshake_message(
    records: &mut RecordLayer,
    send_mutations: &[MessageMutations],
    kind: MessageKind,
    framed: &[u8],
    mutations: &[Mutation],
) -> Result<(), TlsError> {
    let fragment_scheme =
        crate::tls::dtls_handshake::frag_scheme_for(send_mutations, kind).cloned();
    records.write_tls13_handshake(framed, mutations, fragment_scheme.as_ref())?;
    Ok(())
}

pub(crate) fn collect_ext_deltas(list: &[MessageExtDeltas], kind: MessageKind) -> &[ExtDeltaOp] {
    for entry in list {
        if entry.message == kind {
            return &entry.deltas;
        }
    }
    &[]
}

/// Apply a sequence of extension deltas to a message's
/// extension list. Add ops replace any existing extension with the same wire
/// type. New extensions are inserted before pre_shared_key, whose required
/// final position should not be disturbed by an ordinary `+ext`.
/// `reverse_extensions` remains the explicit ordering violation. Remove ops
/// drop any matching wire type.
pub(crate) fn apply_ext_deltas(
    extensions: &mut Vec<crate::tls::codec::Extension>,
    deltas: &[ExtDeltaOp],
) {
    use crate::tls::codec::Extension;
    for d in deltas {
        match d {
            ExtDeltaOp::Remove { wire_type } => {
                extensions.retain(|e| e.wire_type() != *wire_type);
            }
            ExtDeltaOp::Add {
                wire_type,
                body,
                dup,
            } => {
                let new_ext = Extension::Unknown {
                    ty: *wire_type,
                    data: body.clone(),
                };
                // `dup` forces an append even when the type is already present,
                // producing a duplicate extension (RFC 8446 4.2 forbids these).
                if *dup {
                    extensions.push(new_ext);
                } else if let Some(pos) =
                    extensions.iter().position(|e| e.wire_type() == *wire_type)
                {
                    extensions[pos] = new_ext;
                } else {
                    let pos = extensions
                        .iter()
                        .position(|e| e.wire_type() == crate::tls::codec::EXT_PRE_SHARED_KEY)
                        .unwrap_or(extensions.len());
                    extensions.insert(pos, new_ext);
                }
            }
            ExtDeltaOp::Reverse => {
                extensions.reverse();
            }
            // Consumed by the TLS 1.3 client when it builds its key shares (it
            // needs the private keys, which a byte-level delta cannot carry).
            ExtDeltaOp::KeyShareGroups(_) | ExtDeltaOp::KeyShareEntries(_) => {}
        }
    }
}

/// Decode a u16-vector extension from the in-memory ClientHello after all
/// extension deltas have been applied. Known signature_algorithms entries use
/// their structured variant; signature_algorithms_cert currently travels as
/// an opaque typed-delta body.
fn hello_u16_vector(extensions: &[Extension], wire_type: u16) -> Option<Vec<u16>> {
    let ext = extensions.iter().find(|ext| ext.wire_type() == wire_type)?;
    if let Extension::SignatureAlgorithms(values) = ext {
        return (wire_type == crate::tls::codec::EXT_SIGNATURE_ALGORITHMS).then(|| values.clone());
    }
    let Extension::Unknown { data, .. } = ext else {
        return None;
    };
    if data.len() < 2 {
        return None;
    }
    let declared = u16::from_be_bytes([data[0], data[1]]) as usize;
    if declared != data.len() - 2 || declared & 1 != 0 {
        return None;
    }
    Some(
        data[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect(),
    )
}

/// T1: the entry list from a `+ext key_share = [name, group : bytes, ...]`
/// delta, if one is present (the last one wins).
fn key_share_entries_delta(deltas: &[ExtDeltaOp]) -> Option<Vec<crate::ir::KeyShareEntrySpec>> {
    deltas.iter().rev().find_map(|d| match d {
        ExtDeltaOp::KeyShareEntries(entries) => Some(entries.clone()),
        _ => None,
    })
}

/// The group list from a `+ext key_share = [...]` delta, if one is present
/// (the last one wins).
fn key_share_groups_delta(deltas: &[ExtDeltaOp]) -> Option<Vec<u16>> {
    deltas.iter().rev().find_map(|d| match d {
        ExtDeltaOp::KeyShareGroups(groups) => Some(groups.clone()),
        _ => None,
    })
}

/// Whether a ClientKeyExchange override list carries `rsa_plaintext`.
fn raw_plaintext_used(overrides: &[crate::ir::FieldOverride]) -> bool {
    overrides.iter().any(|ov| ov.field == "rsa_plaintext")
}

/// How a hello's key_share public value is encoded (`key_share_point` override).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum KeySharePoint {
    /// The real uncompressed point / u-coordinate.
    Real,
    /// SEC1 compressed point (prime curves only): well-formed, but RFC 8446
    /// 4.2.8.2 allows only the uncompressed form in key_share.
    Compressed,
    /// All zero bytes: a low-order X25519 / X448 point (RFC 7748 6 /
    /// RFC 8446 7.4.2: the peer MUST abort on an all-zero shared secret), or for
    /// a NIST curve a value that is not a valid point encoding at all.
    Zero,
    /// The real point with its last byte removed. Every enclosing length prefix
    /// is derived from the value, so the message stays well formed and only the
    /// point is the wrong size for its group (RFC 8446 4.2.8.2 fixes the length
    /// per group).
    Truncated,
    /// The real point with one zero byte appended; the mirror of `Truncated`.
    Padded,
    /// Finite-field groups: the public value Y = 1, the lower bound RFC 8446
    /// 4.2.8.1 excludes (`1 < Y`); its shared secret would be the constant 1.
    /// X25519 / X448: the u-coordinate 1 (little-endian), a low-order point.
    One,
    /// Finite-field groups only: Y = p - 1, the upper bound RFC 8446 4.2.8.1
    /// excludes (`Y < p-1`); a small-subgroup element whose shared secret is ±1.
    PMinusOne,
    /// Finite-field groups only: Y = p itself, just past the upper bound.
    P,
    /// Every byte 0xff at the group's share length (tlsfuzzer "all bits set").
    AllOnes,
    /// A zero-length key_exchange value.
    Empty,
    /// SEC1 hybrid encoding (0x06/0x07 || X || Y), prime curves only: both
    /// coordinates plus the parity tag, which RFC 8422 5.4.1 / RFC 8446
    /// 4.2.8.2 do not allow.
    HybridSec1,
    /// A prime-curve point as bare X || Y, without the SEC1 0x04 prefix
    /// (tlsfuzzer's "raw" encoding).
    Xy,
    /// Literal bytes (`key_share_point: [0x04, ...]`).
    Raw(Vec<u8>),
    /// A valid share of ANOTHER group, sent under this entry's group id
    /// (`key_share_point: secp384r1` on a secp256r1 share): the wrong size, or
    /// the wrong encoding, for the id it is labelled with.
    OtherGroup(EcdheGroup),
}

/// The `key_share_point` recipe among a message's send overrides, if any.
pub(crate) fn key_share_point_recipe(
    overrides: &[crate::ir::FieldOverride],
) -> Result<KeySharePoint, TlsError> {
    for ov in overrides {
        if ov.field == "key_share_point" {
            return match &ov.value {
                FieldValue::Ident(s) => match s.as_str() {
                    "compressed" => Ok(KeySharePoint::Compressed),
                    "zero" => Ok(KeySharePoint::Zero),
                    "truncated" => Ok(KeySharePoint::Truncated),
                    "padded" => Ok(KeySharePoint::Padded),
                    "one" => Ok(KeySharePoint::One),
                    "p_minus_1" => Ok(KeySharePoint::PMinusOne),
                    "p" => Ok(KeySharePoint::P),
                    "all_ones" => Ok(KeySharePoint::AllOnes),
                    "empty" => Ok(KeySharePoint::Empty),
                    "hybrid" => Ok(KeySharePoint::HybridSec1),
                    "xy" => Ok(KeySharePoint::Xy),
                    other => match crate::schema::group_wire_value(other)
                        .and_then(EcdheGroup::from_wire)
                    {
                        Some(g) => Ok(KeySharePoint::OtherGroup(g)),
                        None => Err(TlsError::Internal(
                            "key_share_point takes `compressed`, `zero`, `truncated`, `padded`, `one`, \
                             `p_minus_1`, `p`, `all_ones`, `empty`, `hybrid`, `xy`, a group name or a byte list",
                        )),
                    },
                },
                FieldValue::Bytes(b) => Ok(KeySharePoint::Raw(b.clone())),
                _ => Err(TlsError::Internal(
                    "key_share_point takes a symbolic value, a group name or a byte list",
                )),
            };
        }
    }
    Ok(KeySharePoint::Real)
}

/// Encode an ephemeral's public value per the recipe.
pub(crate) fn encode_key_share_point(
    eph: &EcdhePrivate,
    recipe: &KeySharePoint,
) -> Result<Vec<u8>, TlsError> {
    match recipe {
        KeySharePoint::Real => Ok(eph.public_bytes()),
        KeySharePoint::Compressed => eph.public_bytes_compressed().ok_or(TlsError::Internal(
            "key_share_point: compressed has no meaning for x25519/x448 (RFC 7748 u-coordinate) or a \
             finite-field / KEM group; use a prime curve",
        )),
        KeySharePoint::HybridSec1 => eph.public_bytes_hybrid_sec1().ok_or(TlsError::Internal(
            "key_share_point: hybrid is the SEC1 0x06/0x07 form of a prime-curve point; use a \
             NIST or brainpool curve",
        )),
        KeySharePoint::Xy => eph.public_bytes_xy().ok_or(TlsError::Internal(
            "key_share_point: xy strips the SEC1 0x04 prefix of a prime-curve point; use a NIST or \
             brainpool curve (or a NIST-curve ML-KEM hybrid)",
        )),
        KeySharePoint::Zero => Ok(vec![0u8; eph.public_bytes().len()]),
        KeySharePoint::AllOnes => Ok(vec![0xffu8; eph.public_bytes().len()]),
        KeySharePoint::Empty => Ok(Vec::new()),
        KeySharePoint::Raw(b) => Ok(b.clone()),
        KeySharePoint::Truncated => {
            let mut p = eph.public_bytes();
            p.pop();
            Ok(p)
        }
        KeySharePoint::Padded => {
            let mut p = eph.public_bytes();
            p.push(0);
            Ok(p)
        }
        // A real share of another group under this entry's id: the private
        // half is irrelevant (the peer must reject the entry), so it is drawn
        // from a seed bound to this ephemeral's own public value.
        KeySharePoint::OtherGroup(g) => {
            if *g == eph.group() {
                return Ok(eph.public_bytes());
            }
            let seed = Rng::sub_seed([0u8; 32], &eph.public_bytes());
            Ok(EcdhePrivate::generate(*g, &mut Rng::from_seed(seed)).public_bytes())
        }
        KeySharePoint::One
            if matches!(eph.group(), EcdheGroup::X25519 | EcdheGroup::X448) =>
        {
            let mut u = vec![0u8; eph.public_bytes().len()];
            u[0] = 1;
            Ok(u)
        }
        // RFC 8446 4.2.8.1 bounds, encoded at the prime's length like a real Y.
        KeySharePoint::One | KeySharePoint::PMinusOne | KeySharePoint::P => {
            let prime = eph.group().ffdhe_prime().ok_or(TlsError::Internal(
                "key_share_point: `one` / `p_minus_1` / `p` are finite-field bounds (`one` also \
                 the x25519/x448 u-coordinate 1); use an ffdhe group",
            ))?;
            let mut y = vec![0u8; prime.len()];
            match recipe {
                KeySharePoint::One => *y.last_mut().expect("prime is non-empty") = 1,
                KeySharePoint::PMinusOne => {
                    y.copy_from_slice(&prime);
                    // p is odd, so decrementing the last byte cannot borrow.
                    *y.last_mut().expect("prime is non-empty") -= 1;
                }
                _ => y.copy_from_slice(&prime),
            }
            Ok(y)
        }
    }
}

/// Map an IANA NamedGroup to the ECDHE group plzn can generate, or None for
/// groups it can only advertise.
pub(crate) fn ecdhe_group_from_wire(wire: u16) -> Option<EcdheGroup> {
    EcdheGroup::from_wire(wire)
}

// ============================================================
//                            errors
// ============================================================

#[derive(Debug)]
pub enum TlsError {
    Record(RecordError),
    Codec(CodecError),
    Crypto(CryptoError),
    UnexpectedHandshake {
        expected: u8,
        got: u8,
    },
    ServerChoseUnsupportedSuite(u16),
    /// The server selected a suite the ClientHello did not offer.
    ServerChoseUnofferedSuite(u16),
    ServerChoseUnsupportedGroup(u16),
    /// The TLS 1.3 server's key_share names a group the client offered no
    /// key share for (RFC 8446 4.2.8: it must answer one of the client's).
    ServerChoseUnsharedGroup(u16),
    ServerChoseUnsupportedSigScheme(u16),
    SignatureVerificationFailed,
    CertificateListEmpty,
    FinishedMismatch,
    /// plzn's own endpoint rejected what the peer sent: a client certificate
    /// that reaches no trusted root, an empty Certificate when one is required,
    /// a pre_shared_key binder that does not verify. `alert` is the alert a
    /// conformant endpoint answers with; the runtime sends it before reporting
    /// the step as failed, so the peer sees the rejection, not a bare close.
    Rejected {
        alert: u8,
        reason: String,
    },
    Alert {
        level: u8,
        description: u8,
    },
    /// The peer exhausted its DTLS retransmission budget. This is distinct
    /// from an ordinary EOF so `expect timeout` can pin the terminal outcome.
    Timeout,
    /// A `recv X { field: ... }` matcher didn't match the decoded
    /// message. This is a driver-initiated abort — the peer didn't
    /// misbehave, the test author's expectation did.
    MatcherFailed {
        message: &'static str,
        field: String,
        expected: String,
        observed: String,
    },
    /// A `send X { field: ... }` override couldn't be applied
    /// (e.g. unknown field name for this message, wrong type).
    /// Should be caught by lowering but surfaces here if a new
    /// field is added to the schema before the driver learns about
    /// it.
    UnknownFieldOverride {
        message: &'static str,
        field: String,
    },
    /// `uut client`: the harness-server could not select a cipher
    /// suite / named group from its peer capability set that the
    /// connecting client also offered / key-shared. Not a peer
    /// misbehaviour and not a test author error — the test's
    /// preconditions simply weren't met, so the runtime reports it as
    /// SKIPPED rather than pass/fail.
    SelectionUnsatisfiable {
        reason: String,
    },
    /// A DTLS driver error (handshake / record layer). Carries the driver's own
    /// message; `classify()` routes it to `FailureKind::Internal`. Structured
    /// DTLS alerts map to `TlsError::Alert` instead.
    Dtls(String),
    Internal(&'static str),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Record(e) => write!(f, "{}", e),
            TlsError::Codec(e) => write!(f, "{}", e),
            TlsError::Crypto(e) => write!(f, "{}", e),
            TlsError::UnexpectedHandshake { expected, got } => write!(
                f,
                "expected handshake type 0x{:02x}, got 0x{:02x}",
                expected, got
            ),
            TlsError::ServerChoseUnsupportedSuite(v) => {
                write!(f, "server chose unsupported cipher suite 0x{:04x}", v)
            }
            TlsError::ServerChoseUnofferedSuite(v) => {
                write!(
                    f,
                    "server chose cipher suite 0x{:04x}, which the ClientHello did not offer",
                    v
                )
            }
            TlsError::ServerChoseUnsupportedGroup(v) => {
                write!(f, "server chose unsupported named group 0x{:04x}", v)
            }
            TlsError::ServerChoseUnsharedGroup(v) => {
                write!(
                    f,
                    "server key_share names group 0x{:04x}, which the client offered no key share for",
                    v
                )
            }
            TlsError::ServerChoseUnsupportedSigScheme(v) => {
                write!(f, "server chose unsupported signature scheme 0x{:04x}", v)
            }
            TlsError::SignatureVerificationFailed => {
                write!(f, "server key exchange signature verification failed")
            }
            TlsError::CertificateListEmpty => write!(f, "server sent empty certificate list"),
            TlsError::FinishedMismatch => {
                write!(
                    f,
                    "server Finished verify_data did not match expected value"
                )
            }
            TlsError::Rejected { alert, reason } => write!(
                f,
                "{} [plzn answered with alert {}]",
                reason,
                crate::schema::alert_code_name(*alert).unwrap_or("?")
            ),
            TlsError::Alert { level, description } => {
                write!(f, "peer alert level={} description={}", level, description)
            }
            TlsError::Timeout => write!(f, "DTLS retransmission timeout expired"),
            TlsError::MatcherFailed {
                message,
                field,
                expected,
                observed,
            } => write!(
                f,
                "recv matcher failed: {}.{} expected {}, got {}",
                message, field, expected, observed
            ),
            TlsError::UnknownFieldOverride { message, field } => {
                write!(f, "unknown field override: {}.{}", message, field)
            }
            TlsError::SelectionUnsatisfiable { reason } => {
                write!(f, "selection unsatisfiable: {}", reason)
            }
            TlsError::Dtls(s) => write!(f, "dtls: {}", s),
            TlsError::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<RecordError> for TlsError {
    fn from(e: RecordError) -> Self {
        match e {
            RecordError::RemoteAlert { level, description } => {
                TlsError::Alert { level, description }
            }
            // Authentication failure while opening an inbound record is
            // malformed peer input, not a harness cryptography failure.
            RecordError::Crypto(CryptoError::AeadOpenFailed) => TlsError::Rejected {
                alert: 20,
                reason: "peer record authentication failed".to_string(),
            },
            // plzn's model of the peer's secret was wrong, not the peer's
            // record: the caller chose the candidates.
            RecordError::NoReadKeyCandidate { .. } => TlsError::Internal(
                "the peer's first protected record authenticated under none of plzn's candidate keys",
            ),
            _ => TlsError::Record(e),
        }
    }
}

impl From<CodecError> for TlsError {
    fn from(e: CodecError) -> Self {
        TlsError::Codec(e)
    }
}

impl From<CryptoError> for TlsError {
    fn from(e: CryptoError) -> Self {
        TlsError::Crypto(e)
    }
}

/// Enforce the TLS 1.2 Server Certificate authentication family selected by
/// the cipher suite. Verifying the ServerKeyExchange under the certificate's
/// key is not enough: without this separate check, an ECDSA certificate and
/// ECDSA-signed ServerKeyExchange would authenticate an ECDHE_RSA suite (and
/// the inverse would authenticate ECDHE_ECDSA).
///
/// RSA-PSS certificate keys may authenticate the signed RSA families, but not
/// static RSA key exchange because they cannot encrypt the premaster secret.
/// plzn follows its existing TLS 1.2 EdDSA behavior and treats Ed25519 as an
/// ECDHE_ECDSA authentication key.
pub(crate) fn validate_tls12_server_certificate_key(
    suite_wire: u16,
    kind: KeyKind,
) -> Result<(), TlsError> {
    use crate::ir::KexType;

    let suite = crate::ir::suite_info(suite_wire)
        .filter(|suite| suite.version == TlsVersion::Tls12)
        .ok_or(TlsError::ServerChoseUnsupportedSuite(suite_wire))?;
    let compatible = match suite.kex {
        KexType::Rsa => kind == KeyKind::Rsa,
        KexType::EcdheRsa | KexType::DheRsa => {
            matches!(kind, KeyKind::Rsa | KeyKind::RsaPss)
        }
        KexType::EcdheEcdsa => matches!(
            kind,
            KeyKind::EcdsaP256 | KeyKind::EcdsaP384 | KeyKind::EcdsaP521 | KeyKind::Ed25519
        ),
        // These suites do not carry a server Certificate at all.
        KexType::Psk | KexType::EcdhePsk => false,
    };
    if compatible {
        return Ok(());
    }

    Err(TlsError::Rejected {
        alert: 43, // unsupported_certificate
        reason: format!(
            "server certificate key {} cannot authenticate cipher suite {} (0x{:04x}); RFC 5246 7.4.2 requires the end-entity key to fit the selected key exchange",
            kind.dsl_name(),
            suite.name,
            suite.wire,
        ),
    })
}

/// An HRR commits the server to its selected cipher suite. ClientHello2 may
/// reorder the original offer, but a conformant retry cannot cause the final
/// ServerHello to select a different suite (RFC 9846 4.2.4).
fn validate_tls13_hrr_cipher_suite(
    hrr_suite: Option<u16>,
    server_hello_suite: u16,
) -> Result<(), TlsError> {
    let Some(hrr_suite) = hrr_suite else {
        return Ok(());
    };
    if server_hello_suite == hrr_suite {
        return Ok(());
    }

    Err(TlsError::Rejected {
        alert: 47, // illegal_parameter
        reason: format!(
            "ServerHello cipher suite 0x{server_hello_suite:04x} differs from HelloRetryRequest cipher suite 0x{hrr_suite:04x}; RFC 9846 4.2.4 requires them to match"
        ),
    })
}

// ============================================================
//                       TLS 1.2 client
// ============================================================

pub struct Tls12ClientConfig {
    pub version: TlsVersion,
    pub server_name: String,
    pub cipher_suites: Vec<u16>,
    pub groups: Vec<u16>,
    pub signature_schemes: Vec<u16>,
    pub seed: [u8; 32],
    pub send_overrides: Vec<MessageOverrides>,
    pub recv_matchers: Vec<MessageOverrides>,
    /// Byte-level mutations applied post-serialisation.
    pub send_mutations: Vec<MessageMutations>,
    /// Per-message extension deltas (+ext / -ext) applied
    /// before encoding.
    pub send_ext_deltas: Vec<MessageExtDeltas>,
    /// For session resumption: the ticket from a prior session.
    pub session_ticket: Option<Vec<u8>>,
    /// For session resumption: the master secret from a prior session.
    pub prior_master_secret: Option<Vec<u8>>,
    /// T5: for session-ID resumption (RFC 5246 7.4.1.3): the id the prior
    /// session's server assigned, echoed in the ClientHello (no ticket).
    pub resume_session_id: Option<Vec<u8>>,
    /// Client-auth: the client certificate (DER) to present when the
    /// server sends a CertificateRequest. None -> send an empty Certificate.
    pub client_cert_der: Option<Vec<u8>>,
    /// Client-auth: the client private key (PKCS#8 DER) used to sign
    /// the CertificateVerify.
    pub client_private_key_der: Option<Vec<u8>>,
    /// A: every client-auth credential `client_chain:` named, in preference
    /// order. With two or more, the CertificateRequest picks (certificate_types
    /// and signature_algorithms, RFC 5246 7.4.4 / 7.4.6): the first that fits
    /// is presented, and none fitting means an empty Certificate. A single
    /// credential is presented as configured, so a mismatch can be tested.
    pub client_credentials: Vec<crate::ir::Chain>,
    /// Advertise session-ticket support (empty SessionTicket extension, RFC 5077)
    /// on the initial ClientHello so the server issues a NewSessionTicket. Set for
    /// the initial session of a resumption test.
    pub advertise_session_ticket: bool,
    /// RFC 4279 pre-shared key `(identity, secret)` for the PSK / ECDHE_PSK
    /// suites (a `psk { }` block); the offer then consists of those families.
    pub psk: Option<(Vec<u8>, Vec<u8>)>,
    /// Offer both RFC 7250 certificate-type extensions with RPK preference.
    pub offer_raw_public_key: bool,
    /// T5: declarations after a TLS `begin_renegotiation` step. Appended to
    /// the lists above when a renegotiation begins (and removed again when
    /// the next one begins), so they shape the second handshake only.
    pub reneg_send_overrides: Vec<MessageOverrides>,
    pub reneg_send_mutations: Vec<MessageMutations>,
    pub reneg_send_ext_deltas: Vec<MessageExtDeltas>,
}

impl Tls12ClientConfig {
    pub fn default_for(server_name: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            version: TlsVersion::Tls12,
            server_name: server_name.into(),
            cipher_suites: vec![
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
            ],
            groups: vec![GROUP_SECP256R1, GROUP_X25519],
            // Everything plzn verifies (RFC 5246 7.4.1.4.1 lists in preference
            // order): the ECDSA and RSA-PSS pairs first, PKCS#1 v1.5 last, so a
            // P-384 or Ed25519 server can sign with its own scheme (rustls
            // refuses to mix an ECDSA key with another hash's codepoint).
            signature_schemes: vec![
                SignatureScheme::EcdsaSecp256r1Sha256.wire_value(),
                SignatureScheme::EcdsaSecp384r1Sha384.wire_value(),
                SignatureScheme::EcdsaSecp521r1Sha512.wire_value(),
                SignatureScheme::RsaPssRsaeSha256.wire_value(),
                SignatureScheme::RsaPssRsaeSha384.wire_value(),
                SignatureScheme::RsaPssRsaeSha512.wire_value(),
                SignatureScheme::RsaPssPssSha256.wire_value(),
                SignatureScheme::RsaPssPssSha384.wire_value(),
                SignatureScheme::RsaPssPssSha512.wire_value(),
                SignatureScheme::RsaPkcs1Sha256.wire_value(),
                SignatureScheme::RsaPkcs1Sha384.wire_value(),
                SignatureScheme::RsaPkcs1Sha512.wire_value(),
                SignatureScheme::Ed25519.wire_value(),
            ],
            seed,
            send_overrides: Vec::new(),
            recv_matchers: Vec::new(),
            send_mutations: Vec::new(),
            send_ext_deltas: Vec::new(),
            session_ticket: None,
            prior_master_secret: None,
            resume_session_id: None,
            client_cert_der: None,
            client_private_key_der: None,
            client_credentials: Vec::new(),
            advertise_session_ticket: false,
            psk: None,
            offer_raw_public_key: false,
            reneg_send_overrides: Vec::new(),
            reneg_send_mutations: Vec::new(),
            reneg_send_ext_deltas: Vec::new(),
        }
    }
}

pub struct Tls12Client {
    cfg: Tls12ClientConfig,
    records: RecordLayer,
    transcript: TranscriptHash,

    client_random: [u8; 32],
    server_random: [u8; 32],
    /// The ClientHello.client_version value actually sent on the wire.  Static
    /// RSA copies this value into the premaster secret (RFC 5246 7.4.7.1),
    /// which may differ from the driver version when a test overrides the
    /// ClientHello or uses the SSLv2-compatible encoding.
    client_hello_version: u16,

    ephemeral: Option<EcdhePrivate>,
    server_pubkey: Option<PublicKey>,
    negotiated_server_cert_type: u8,
    negotiated_client_cert_type: u8,
    pending_server_point: Option<Vec<u8>>,
    pending_server_group: u16,
    // DHE: server-sent group (p, g) and public value Ys captured from the DHE
    // ServerKeyExchange, consumed when sending the ClientKeyExchange.
    pending_dhe: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// The exact framed ClientKeyExchange last sent in this handshake. Keeping
    /// it lets negative tests retransmit the message before or after CCS
    /// without trying to perform the key agreement a second time.
    last_client_key_exchange: Option<Vec<u8>>,
    use_ems: bool,
    /// RFC 7366: the ClientHello (after deltas) carried encrypt_then_mac.
    offered_etm: bool,
    /// RFC 7366: both sides sent the extension and a CBC suite was selected.
    use_etm: bool,
    negotiated_suite: u16,
    /// The cipher suites actually offered in the ClientHello (after overrides).
    offered_suites: Vec<u16>,
    master_secret: Vec<u8>,

    /// Transcript digest captured just before the server's Finished
    /// is appended. Needed to compute the expected verify_data.
    pre_server_finished_digest: Vec<u8>,

    /// Stashed read-direction keys that are *derived* at the same
    /// moment as the write keys but must not be *installed* until
    /// the server's ChangeCipherSpec arrives. RFC 5246 §6.1: the
    /// read pending state only becomes active on the server's
    /// CCS. Installing them early causes plaintext alerts the
    /// server might send before its own CCS (e.g. on bad Finished
    /// decryption) to be mis-interpreted as encrypted records.
    pending_read_keys: Option<DirectionKeys>,
    /// Client-auth only: write keys are derived at ClientKeyExchange but must
    /// not be installed until the client's ChangeCipherSpec, because the
    /// CertificateVerify sent in between is plaintext (RFC 5246 6.1).
    pending_write_keys: Option<DirectionKeys>,
    /// Captured NewSessionTicket for resumption.
    pub captured_ticket: Option<Vec<u8>>,
    /// T1: values recorded by `capture $name` matchers.
    captures: Vec<(String, Vec<u8>)>,

    /// Raw concatenation of every framed handshake message, in order.
    /// The TLS 1.2 CertificateVerify signs Hash(handshake_messages)
    /// (RFC 5246 §7.4.8) over exactly these bytes through the
    /// ClientKeyExchange, so unlike the running transcript hash we
    /// need the literal bytes here.
    raw_transcript: Vec<u8>,
    /// Set when the server sent a CertificateRequest: the client must
    /// answer with Certificate (+ CertificateVerify if it has a key).
    certificate_requested: bool,
    /// The CertificateRequest's supported_signature_algorithms, for choosing
    /// the CertificateVerify scheme (RFC 5246 7.4.8).
    cr_signature_algorithms: Vec<u16>,
    /// The client Certificate went out with an empty certificate_list, so no
    /// CertificateVerify follows.
    sent_empty_certificate: bool,
    /// `send Certificate { credential: ... }` selected a testdata credential by
    /// name; the CertificateVerify signs with `override_client_key` (None for
    /// `credential: none`, so no CertificateVerify).
    credential_selected: bool,
    override_client_key: Option<Vec<u8>>,
    /// The psk_identity_hint from a PSK ServerKeyExchange, if the server sent one.
    psk_identity_hint: Option<Vec<u8>>,

    /// True while running a renegotiation (a second handshake on the live
    /// connection). Drives a non-empty renegotiation_info extension (RFC 5746).
    renegotiating: bool,
    /// The current renegotiation is attempting an abbreviated handshake with
    /// the session ID or ticket established on this connection.
    renegotiation_resumed: bool,
    /// The client/server Finished verify_data from the *previous* handshake,
    /// bound into the renegotiation_info of the renegotiation ClientHello /
    /// verified against the server's (RFC 5746 3.5).
    last_client_verify_data: Vec<u8>,
    last_server_verify_data: Vec<u8>,

    /// T5: overrides / ext deltas that apply to the renegotiation ClientHello
    /// only (set by `renegotiate_with`, consulted in `send_client_hello` while
    /// `renegotiating`, cleared when the second handshake finishes). `insecure`
    /// omits renegotiation_info entirely (RFC 5746 3.5 legacy renegotiation).
    reneg_overrides: Vec<FieldOverride>,
    reneg_ext_deltas: Vec<ExtDeltaOp>,
    reneg_insecure: bool,
    /// How many renegotiation-phase entries `begin_renegotiation` appended to
    /// `cfg.send_overrides` / `send_mutations` / `send_ext_deltas`; removed
    /// again before the next renegotiation appends its own.
    installed_reneg: (usize, usize, usize),
    /// T5: application-data records the server sent under the old keys while
    /// a renegotiation handshake was being read (RFC 5246 7.4.1.1). Delivered,
    /// in order, by the next `read_app_data` calls.
    deferred_app_data: std::collections::VecDeque<Vec<u8>>,
    /// T5: the session_id this ClientHello offered (a prior session's id, or a
    /// fresh one alongside a ticket so RFC 5077 3.4's echo signals acceptance),
    /// the id the ServerHello assigned, and whether it echoed the offer.
    offered_session_id: Vec<u8>,
    established_session_id: Vec<u8>,
    resumed: bool,
    /// T5: NewSessionTickets received (`assert new_session_tickets`).
    nst_seen: u32,
}

impl Tls12Client {
    pub fn new(transport: Box<dyn UutTransport>, cfg: Tls12ClientConfig) -> Self {
        let version = cfg.version;
        Self {
            cfg,
            records: RecordLayer::new(transport, version),
            transcript: TranscriptHash::new(HashAlg::Sha256),
            client_random: [0; 32],
            server_random: [0; 32],
            client_hello_version: version.wire_value(),
            ephemeral: None,
            server_pubkey: None,
            negotiated_server_cert_type: crate::tls::codec::CERT_TYPE_X509,
            negotiated_client_cert_type: crate::tls::codec::CERT_TYPE_X509,
            pending_server_point: None,
            pending_server_group: 0,
            pending_dhe: None,
            last_client_key_exchange: None,
            use_ems: false,
            offered_etm: false,
            use_etm: false,
            negotiated_suite: 0,
            offered_suites: Vec::new(),
            master_secret: Vec::new(),
            pre_server_finished_digest: Vec::new(),
            pending_read_keys: None,
            pending_write_keys: None,
            captured_ticket: None,
            captures: Vec::new(),
            raw_transcript: Vec::new(),
            certificate_requested: false,
            cr_signature_algorithms: Vec::new(),
            sent_empty_certificate: false,
            credential_selected: false,
            override_client_key: None,
            psk_identity_hint: None,
            renegotiating: false,
            renegotiation_resumed: false,
            last_client_verify_data: Vec::new(),
            last_server_verify_data: Vec::new(),
            reneg_overrides: Vec::new(),
            reneg_ext_deltas: Vec::new(),
            reneg_insecure: false,
            installed_reneg: (0, 0, 0),
            deferred_app_data: std::collections::VecDeque::new(),
            offered_session_id: Vec::new(),
            established_session_id: Vec::new(),
            resumed: false,
            nst_seen: 0,
        }
    }

    /// T5: the session_id the ClientHello carries. A prior session's id when
    /// resuming by id; alongside a ticket a fresh random id, so the server's
    /// echo (RFC 5077 3.4 MUST) tells the client the ticket was accepted; empty
    /// otherwise, and on a renegotiation.
    fn client_hello_session_id(&self) -> Vec<u8> {
        if self.renegotiating {
            if self.renegotiation_resumed {
                // RFC 5077 clients may use an empty session_id when presenting
                // a ticket. Session-ID resumption instead reuses the ID the
                // server assigned on the initial handshake.
                if matches!(&self.cfg.session_ticket, Some(t) if !t.is_empty()) {
                    return Vec::new();
                }
                if let Some(id) = &self.cfg.resume_session_id {
                    return id.clone();
                }
            }
            return Vec::new();
        }
        if let Some(id) = &self.cfg.resume_session_id {
            return id.clone();
        }
        if matches!(&self.cfg.session_ticket, Some(t) if !t.is_empty()) {
            let mut rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"resume_session_id"));
            return rng.random_array::<32>().to_vec();
        }
        Vec::new()
    }

    /// T5: `read_handshake_bytes` that sets crossing application data aside
    /// during a renegotiation instead of failing on it.
    fn hs_bytes(&mut self, n: usize) -> Result<Vec<u8>, TlsError> {
        loop {
            match self.records.read_handshake_bytes(n) {
                Ok(b) => return Ok(b),
                Err(RecordError::UnexpectedContentType { got, .. })
                    if got == crate::tls::codec::CONTENT_TYPE_APP_DATA && self.renegotiating =>
                {
                    let data = self.records.read_app_data()?;
                    self.deferred_app_data.push_back(data);
                }
                Err(e) => return Err(e.into()),
            }
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
        self.raw_transcript.clear();
        // A fresh client_random, distinct from the initial handshake.
        let mut cr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"client_random_reneg"));
        self.client_random = cr_rng.random_array();
        self.server_random = [0; 32];
        self.ephemeral = None;
        self.server_pubkey = None;
        self.pending_server_point = None;
        self.pending_server_group = 0;
        self.pending_dhe = None;
        self.last_client_key_exchange = None;
        self.use_ems = false;
        self.offered_etm = false;
        self.use_etm = false;
        self.negotiated_suite = 0;
        self.master_secret.clear();
        self.pre_server_finished_digest.clear();
        self.pending_read_keys = None;
        self.pending_write_keys = None;
        self.captured_ticket = None;
        self.certificate_requested = false;
        self.cr_signature_algorithms.clear();
        self.sent_empty_certificate = false;
        self.psk_identity_hint = None;
        // T5: swap in this renegotiation's phase declarations (the ones a
        // previous renegotiation appended come off first). They sit behind the
        // program-level entries, so both apply during the second handshake.
        let (a, b, c) = self.installed_reneg;
        let n = self.cfg.send_overrides.len();
        self.cfg.send_overrides.truncate(n - a);
        let n = self.cfg.send_mutations.len();
        self.cfg.send_mutations.truncate(n - b);
        let n = self.cfg.send_ext_deltas.len();
        self.cfg.send_ext_deltas.truncate(n - c);
        let ov = self.cfg.reneg_send_overrides.clone();
        let mu = self.cfg.reneg_send_mutations.clone();
        let de = self.cfg.reneg_send_ext_deltas.clone();
        self.installed_reneg = (ov.len(), mu.len(), de.len());
        self.cfg.send_overrides.extend(ov);
        self.cfg.send_mutations.extend(mu);
        self.cfg.send_ext_deltas.extend(de);
    }

    /// Drive a full renegotiation: reset per-handshake state, then run a second
    /// handshake encrypted under the current keys (which transitions to the new
    /// keys at the new ChangeCipherSpec).
    pub fn renegotiate(&mut self) -> Result<(), TlsError> {
        self.renegotiate_with(false, false, &[], &[])
    }

    /// T5: renegotiate with a customized renegotiation ClientHello. `insecure`
    /// omits renegotiation_info (RFC 5746 3.5 legacy renegotiation); `overrides`
    /// / `ext_deltas` apply to the renegotiation ClientHello only, so the same
    /// connection's initial handshake is untouched.
    pub fn renegotiate_with(
        &mut self,
        resumed: bool,
        insecure: bool,
        overrides: &[FieldOverride],
        ext_deltas: &[ExtDeltaOp],
    ) -> Result<(), TlsError> {
        self.renegotiation_resumed = resumed;
        if resumed {
            if self.master_secret.is_empty() {
                return Err(TlsError::Internal(
                    "renegotiate resumed requires an established session",
                ));
            }
            self.cfg.prior_master_secret = Some(self.master_secret.clone());
            if let Some(ticket) = self.captured_ticket.clone().filter(|t| !t.is_empty()) {
                self.cfg.session_ticket = Some(ticket);
                self.cfg.resume_session_id = None;
            } else if !self.established_session_id.is_empty() {
                self.cfg.resume_session_id = Some(self.established_session_id.clone());
            } else {
                return Err(TlsError::Internal(
                    "renegotiate resumed requires a session ID or ticket",
                ));
            }
        }
        self.reneg_overrides = overrides.to_vec();
        self.reneg_ext_deltas = ext_deltas.to_vec();
        self.reneg_insecure = insecure;
        self.begin_renegotiation();
        let mut r = self.do_handshake();
        // Declining the resumption is the server's protocol decision, reported
        // like a `recv ServerHello { resumed: true }` mismatch.
        if resumed && r.is_ok() && !self.resumed {
            r = Err(TlsError::MatcherFailed {
                message: "ServerHello",
                field: "resumed".into(),
                expected: "the renegotiation to resume the session".into(),
                observed: "a full handshake".into(),
            });
        }
        self.reneg_overrides.clear();
        self.reneg_ext_deltas.clear();
        self.reneg_insecure = false;
        self.renegotiation_resumed = false;
        r
    }

    /// Fold a framed handshake message into both the running transcript
    /// hash and the raw transcript log (needed for CertificateVerify).
    fn absorb(&mut self, framed: &[u8]) {
        self.transcript.update(framed);
        self.raw_transcript.extend_from_slice(framed);
    }

    fn ensure_init(&mut self) {
        if self.client_random != [0; 32] {
            return;
        }
        let mut cr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"client_random"));
        self.client_random = cr_rng.random_array();
        // ECDHE ephemeral generated lazily in send_client_key_exchange
        // (only needed for ECDHE suites, not static RSA).
    }

    pub fn do_handshake(&mut self) -> Result<(), TlsError> {
        self.ensure_init();
        self.send_client_hello()?;
        self.recv_server_hello()?;
        if self.resumed {
            // Abbreviated (resumed) handshake, RFC 5246 7.3 / RFC 5077 3.1: the
            // server's [NewSessionTicket], CCS and Finished come first. T5: a
            // declined offer (session_id not echoed) falls through to the full
            // handshake instead.
            self.recv_change_cipher_spec()?;
            self.recv_finished_msg()?;
            self.send_change_cipher_spec()?;
            self.send_finished()?;
            return Ok(());
        }
        let kex = crate::ir::suite_info(self.negotiated_suite).map(|s| s.kex);
        // PSK families carry no Certificate (RFC 4279 2); plain PSK's
        // ServerKeyExchange is optional and absorbed by recv_server_hello_done.
        if !matches!(kex, Some(k) if k.is_psk()) {
            self.recv_certificate()?;
        }
        if !matches!(
            kex,
            Some(crate::ir::KexType::Rsa) | Some(crate::ir::KexType::Psk)
        ) {
            self.recv_server_key_exchange()?;
        }
        // T5: a CertificateRequest may precede ServerHelloDone (RFC 5246
        // 7.4.4) -- a server that wants client authentication only on the
        // renegotiation it asked for (`uut server { hello_request_after_app_data,
        // require_client_cert_on_renegotiation }`) sends one there and not on
        // the initial handshake, so the full flow looks for it. PSK families
        // keep their SKE-absorbing ServerHelloDone reader.
        let mut cert_requested = false;
        if matches!(kex, Some(k) if k.is_psk()) {
            self.recv_server_hello_done()?;
        } else {
            let (msg_type, body) =
                self.read_handshake_oneof(&[HS_CERTIFICATE_REQUEST, HS_SERVER_HELLO_DONE])?;
            if msg_type == HS_CERTIFICATE_REQUEST {
                self.handle_certificate_request(&body)?;
                cert_requested = true;
                self.recv_server_hello_done()?;
            } else {
                decode_server_hello_done_body(&body)?;
            }
        }
        if cert_requested {
            self.send_client_certificate()?;
        }
        self.send_client_key_exchange()?;
        if cert_requested {
            self.send_client_certificate_verify()?;
        }
        self.send_change_cipher_spec()?;
        self.send_finished()?;
        self.recv_change_cipher_spec()?;
        self.recv_finished_msg()?;
        Ok(())
    }

    pub fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError> {
        use crate::ir::{HandshakeStep as HS, MessageKind as MK};
        self.ensure_init();
        match step {
            HS::Send(MK::ClientHello) => self.send_client_hello(),
            HS::Send(MK::Certificate) => self.send_client_certificate(),
            HS::Send(MK::ClientKeyExchange) => self.send_client_key_exchange(),
            HS::Send(MK::CertificateVerify) => self.send_client_certificate_verify(),
            HS::Send(MK::ChangeCipherSpec) => self.send_change_cipher_spec(),
            HS::Send(MK::Finished) => self.send_finished(),
            HS::Recv(MK::ServerHello) => self.recv_server_hello(),
            HS::Recv(MK::Certificate) => self.recv_certificate(),
            HS::Recv(MK::ServerKeyExchange) => self.recv_server_key_exchange(),
            HS::Recv(MK::CertificateRequest) => self.recv_certificate_request(),
            HS::Recv(MK::HelloRequest) => self.recv_hello_request(),
            HS::Recv(MK::ServerHelloDone) => self.recv_server_hello_done(),
            HS::Recv(MK::NewSessionTicket) => self.recv_new_session_ticket(),
            HS::Recv(MK::ChangeCipherSpec) => self.recv_change_cipher_spec(),
            HS::Recv(MK::Finished) => self.recv_finished_msg(),
            // T6: heartbeat records and the stapled CertificateStatus.
            HS::Send(MK::Heartbeat) => self.send_heartbeat(),
            HS::Recv(MK::Heartbeat) => self.recv_heartbeat(),
            HS::Recv(MK::CertificateStatus) => self.recv_certificate_status(),
            _ => Err(TlsError::Internal(
                "unsupported handshake step for TLS 1.2 client",
            )),
        }
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
        // T5: application data that crossed a renegotiation comes first.
        if let Some(d) = self.deferred_app_data.pop_front() {
            return Ok(d);
        }
        Ok(self.records.read_app_data()?)
    }

    pub fn close(&mut self) -> Result<(), TlsError> {
        self.records
            .close()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }

    /// Send a `[level, description]` alert record (encrypted under the installed
    /// write keys once the handshake has completed), then close the transport.
    pub fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(crate::tls::codec::CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)?;
        self.records
            .close()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }

    pub fn negotiated_cipher_suite(&self) -> u16 {
        self.negotiated_suite
    }

    pub fn extended_master_secret_in_use(&self) -> bool {
        self.use_ems
    }

    // ---- sub-steps ----

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        // T6: `send ClientHello raw "HEX"` replays a literal hello; `format:
        // sslv2` sends the RFC 5246 E.2 SSLv2-compatible CLIENT-HELLO.
        if let Some(raw) = t6_raw_client_hello_body(&self.cfg.send_overrides) {
            return self.send_client_hello_raw(raw);
        }
        if t6_client_hello_wants_sslv2(&self.cfg.send_overrides) {
            return self.send_client_hello_sslv2();
        }
        let mut extensions = vec![
            Extension::ServerName(self.cfg.server_name.clone()),
            Extension::SupportedGroups(self.cfg.groups.clone()),
            Extension::EcPointFormats(vec![0]),
            Extension::ExtendedMasterSecret,
            // RFC 5746 3.5: on a renegotiation the client binds the extension to
            // the previous handshake by sending its prior Finished verify_data;
            // an empty value is the initial-handshake signal.
            Extension::RenegotiationInfo(self.last_client_verify_data.clone()),
        ];
        if self.cfg.version == TlsVersion::Tls12 {
            extensions.push(Extension::SignatureAlgorithms(
                self.cfg.signature_schemes.clone(),
            ));
        }
        if self.cfg.offer_raw_public_key {
            for ty in [
                crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE,
                crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE,
            ] {
                extensions.push(Extension::Unknown {
                    ty,
                    data: crate::tls::codec::encode_cert_type_list(&[
                        crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                        crate::tls::codec::CERT_TYPE_X509,
                    ]),
                });
            }
        }
        // Include session_ticket extension for resumption. An empty ticket
        // advertises support (RFC 5077) so the server issues a NewSessionTicket;
        // a non-empty ticket presents it for an abbreviated handshake.
        if let Some(ref ticket) = self.cfg.session_ticket {
            extensions.push(Extension::SessionTicket(ticket.clone()));
        } else if self.cfg.advertise_session_ticket {
            extensions.push(Extension::SessionTicket(Vec::new()));
        }
        // T5: `renegotiate insecure` sends the renegotiation ClientHello with no
        // renegotiation_info at all (RFC 5746 3.5 legacy renegotiation). Drop it
        // before the deltas / overrides get a say.
        if self.renegotiating && self.reneg_insecure {
            extensions.retain(|e| !matches!(e, Extension::RenegotiationInfo(_)));
        }
        // Apply per-message extension deltas (+ext / -ext).
        let ext_deltas = collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ClientHello);
        apply_ext_deltas(&mut extensions, ext_deltas);
        // T5: the renegotiation ClientHello's own deltas apply on top, and only
        // on the renegotiation (the initial handshake keeps the program-level
        // deltas above).
        if self.renegotiating && !self.reneg_ext_deltas.is_empty() {
            apply_ext_deltas(&mut extensions, &self.reneg_ext_deltas);
        }
        self.offered_etm = extensions
            .iter()
            .any(|e| e.wire_type() == crate::tls::codec::EXT_ENCRYPT_THEN_MAC);
        let mut ch = ClientHello {
            legacy_version: self.cfg.version.wire_value(),
            random: self.client_random,
            session_id: self.client_hello_session_id(),
            cipher_suites: self.cfg.cipher_suites.clone(),
            compression_methods: vec![0],
            extensions,
        };
        // Apply any `send ClientHello { ... }` overrides the test
        // declared. Lowering has already range-checked values.
        let overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientHello).to_vec();
        for ov in &overrides {
            apply_client_hello_override(&mut ch, ov)?;
        }
        // T5: the renegotiation ClientHello's own field overrides (cipher_suites
        // with the SCSV, a garbage session_id, ...) apply only on the second
        // handshake.
        if self.renegotiating {
            let reneg_ovs = self.reneg_overrides.clone();
            for ov in &reneg_ovs {
                apply_client_hello_override(&mut ch, ov)?;
            }
        }
        self.client_hello_version = ch.legacy_version;
        self.offered_session_id = ch.session_id.clone();
        self.offered_suites = ch.cipher_suites.clone();
        let encoded = encode_client_hello_body_mapped(&ch)?;
        let ch_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello);
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, ch_muts)
            .map_err(|_| TlsError::Internal("ClientHello mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &body);
        // Corrupt the handshake header (msg_type/length) if the test asked for it
        // (BoGo WrongMessageType); the body-stage pass cannot reach it.
        mutate::apply_handshake_header_mutations(&mut framed, ch_muts);
        // Disjoint field borrows (transcript + raw_transcript) rather than
        // self.absorb(): ch_muts still holds an immutable borrow of self.cfg.
        self.transcript.update(&framed);
        self.raw_transcript.extend_from_slice(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, ch_muts)?;
        Ok(())
    }

    // ---- per-message methods (callable individually via
    //      do_handshake_step, or in sequence by do_handshake) ----

    fn recv_server_hello(&mut self) -> Result<(), TlsError> {
        let sh_body = self.read_handshake(HS_SERVER_HELLO)?;
        let sh = decode_server_hello_body(&sh_body)?;
        if sh.legacy_version != self.cfg.version.wire_value() {
            return Err(TlsError::Rejected {
                alert: 70,
                reason: format!(
                    "server selected TLS version 0x{:04x}, expected 0x{:04x}",
                    sh.legacy_version,
                    self.cfg.version.wire_value()
                ),
            });
        }
        // T5: did the server echo the session_id we offered (RFC 5246 7.4.1.3 /
        // RFC 5077 3.4)? That is the resumption signal for both the session-ID
        // and the ticket form; an empty offer can never be "echoed".
        let has_resumption_state = self.cfg.prior_master_secret.is_some()
            && (self.cfg.resume_session_id.is_some()
                || matches!(&self.cfg.session_ticket, Some(t) if !t.is_empty()));
        let echoed = has_resumption_state && sh.session_id == self.offered_session_id;
        self.established_session_id = sh.session_id.clone();
        let matchers =
            collect_overrides(&self.cfg.recv_matchers, MessageKind::ServerHello).to_vec();
        for m in &matchers {
            if let FieldValue::Capture(name) = &m.value {
                let v = capture_server_hello_field(&sh, &m.field)?;
                self.captures.push((name.clone(), v));
                continue;
            }
            if m.field == "resumed" {
                let want = match &m.value {
                    FieldValue::Ident(s) if s == "true" => true,
                    FieldValue::Ident(s) if s == "false" => false,
                    _ => return Err(TlsError::Internal("`resumed` takes `true` or `false`")),
                };
                if echoed != want {
                    return Err(TlsError::MatcherFailed {
                        message: "ServerHello",
                        field: "resumed".into(),
                        expected: if want {
                            "the offered session_id echoed (resumed)".into()
                        } else {
                            "a fresh session (session_id not echoed)".into()
                        },
                        observed: if echoed {
                            "the offered session_id echoed".into()
                        } else {
                            "session_id not echoed".into()
                        },
                    });
                }
                continue;
            }
            match_server_hello_field(&sh, m)?;
        }
        self.negotiated_suite = sh.cipher_suite;
        let suite = match crate::ir::suite_info(sh.cipher_suite) {
            Some(s) if crate::ir::suite_supports_version(s, self.cfg.version) => *s,
            _ => return Err(TlsError::ServerChoseUnsupportedSuite(sh.cipher_suite)),
        };
        // RFC 5246 7.4.1.3: "The single cipher suite selected by the server
        // from the list in ClientHello.cipher_suites."
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::ServerChoseUnofferedSuite(sh.cipher_suite));
        }
        // The PRF / handshake hash is fixed by the suite (RFC 5246 5, RFC 5289:
        // SHA-384 for the *_SHA384 suites). The transcript was started as
        // SHA-256 before the suite was known; rebuild it from the raw bytes.
        if suite.prf != self.transcript.alg() {
            let mut rebuilt = TranscriptHash::new(suite.prf);
            rebuilt.update(&self.raw_transcript);
            self.transcript = rebuilt;
        }
        self.server_random = sh.random;
        self.use_ems = sh
            .extensions
            .iter()
            .any(|e| matches!(e, Extension::ExtendedMasterSecret));
        // RFC 7366 2: encrypt-then-MAC is in effect only when both sides sent the
        // extension, and it is meaningless for AEAD suites (a server MUST NOT
        // echo it with one). plzn's client follows a server that echoes it on a
        // CBC suite; a misuse is not an abort here but something a test pins
        // (`recv ServerHello { lacks_ext: 0x0016 }`).
        let server_etm = sh
            .extensions
            .iter()
            .any(|e| e.wire_type() == crate::tls::codec::EXT_ENCRYPT_THEN_MAC);
        self.use_etm = self.offered_etm && server_etm && suite.cipher.is_cbc();
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

        if self.renegotiating && !self.reneg_insecure {
            let ri = sh.extensions.iter().find_map(|e| match e {
                Extension::RenegotiationInfo(d) => Some(d.as_slice()),
                _ => None,
            });
            // RFC 5746 3.5: "When a ServerHello is received, the client MUST verify
            // that the "renegotiation_info" extension is present; if it is not, the
            // client MUST abort the handshake."
            //
            // "The client MUST then verify that the first half of the
            // "renegotiated_connection" field is equal to the saved
            // client_verify_data value, and the second half is equal to the saved
            // server_verify_data value.  If they are not, the client MUST abort the
            // handshake."
            let mut expected = self.last_client_verify_data.clone();
            expected.extend_from_slice(&self.last_server_verify_data);
            if ri != Some(expected.as_slice()) {
                return Err(TlsError::Internal(
                    "renegotiation_info mismatch on renegotiation ServerHello",
                ));
            }
        }

        // For resumed sessions: derive keys from the prior master
        // secret + new randoms immediately. The abbreviated flow
        // doesn't have CKE/SKE so we do it here. T5: only when the server
        // accepted the offer (it echoed our session_id); a server that
        // declines answers with a full handshake, which the client follows.
        self.resumed = false;
        if let Some(ms) = self.cfg.prior_master_secret.clone() {
            if echoed {
                self.resumed = true;
                self.master_secret = ms;
                let (client_keys, server_keys) = self.derive_tls12_keys()?;
                if self.renegotiating {
                    // The renegotiation CCS is protected with the old write
                    // keys. Install the resumed session's keys only after it.
                    self.pending_write_keys = Some(client_keys);
                } else {
                    self.records.install_write_keys(client_keys)?;
                }
                self.pending_read_keys = Some(server_keys);
            } else {
                self.cfg.prior_master_secret = None;
                self.cfg.resume_session_id = None;
                self.cfg.session_ticket = self.cfg.session_ticket.as_ref().map(|_| Vec::new());
            }
        }
        Ok(())
    }

    fn recv_certificate(&mut self) -> Result<(), TlsError> {
        let cert_body = self.read_handshake(HS_CERTIFICATE)?;
        let cert_msg =
            if self.negotiated_server_cert_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
                crate::tls::codec::Certificate12 {
                    entries: vec![
                        crate::tls::codec::decode_raw_public_key_certificate_12_body(&cert_body)?,
                    ],
                }
            } else {
                decode_certificate_12_body(&cert_body)?
            };
        // `recv Certificate { entries: N }`: the number of certificates sent;
        // `leaf_key`: the leaf's key type.
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::Certificate) {
            match (m.field.as_str(), &m.value) {
                ("entries", FieldValue::U16(want)) => {
                    if cert_msg.entries.len() != *want as usize {
                        return Err(TlsError::MatcherFailed {
                            message: "Certificate",
                            field: "entries".into(),
                            expected: want.to_string(),
                            observed: cert_msg.entries.len().to_string(),
                        });
                    }
                }
                ("leaf_key", FieldValue::Ident(want)) => {
                    match_leaf_key(cert_msg.entries.first().map(|e| e.as_slice()), want)?;
                }
                ("certificate_type", FieldValue::Ident(want)) => {
                    match_certificate_type(self.negotiated_server_cert_type, want)?;
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "Certificate",
                        field: m.field.clone(),
                    });
                }
            }
        }
        let leaf = cert_msg
            .entries
            .into_iter()
            .next()
            .ok_or(TlsError::CertificateListEmpty)?;
        let key = PublicKey::from_certificate_entry(&leaf, self.negotiated_server_cert_type)?;
        validate_tls12_server_certificate_key(self.negotiated_suite, key.kind())?;
        self.server_pubkey = Some(key);
        Ok(())
    }

    /// `recv ServerKeyExchange { named_group / signature_scheme / psk_identity_hint }`
    /// matchers against what the server chose.
    fn match_server_key_exchange(
        &self,
        named_group: Option<u16>,
        signature_scheme: Option<u16>,
        hint: Option<&[u8]>,
        dh_p: Option<&[u8]>,
    ) -> Result<(), TlsError> {
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::ServerKeyExchange) {
            let (observed, expected) = match (m.field.as_str(), &m.value) {
                // T1: `capture $x` is recorded by `capture_server_key_exchange`.
                (_, FieldValue::Capture(_)) => continue,
                ("named_group", FieldValue::U16(want)) => (
                    named_group
                        .map(|g| format!("0x{:04x}", g))
                        .unwrap_or_else(|| "none".into()),
                    format!("0x{:04x}", want),
                ),
                // T2: any-of -- `named_group: [ffdhe2048, ffdhe3072]`,
                // `signature_scheme: [rsa_pss_rsae_sha256, rsa_pkcs1_sha256]`.
                ("named_group", FieldValue::U16List(want))
                | ("signature_scheme", FieldValue::U16List(want)) => {
                    let observed = if m.field == "named_group" {
                        named_group
                    } else {
                        signature_scheme
                    };
                    let got = observed
                        .map(|g| format!("0x{:04x}", g))
                        .unwrap_or_else(|| "none".into());
                    let list = want
                        .iter()
                        .map(|g| format!("0x{:04x}", g))
                        .collect::<Vec<_>>()
                        .join(", ");
                    if observed.map(|g| want.contains(&g)).unwrap_or(false) {
                        continue;
                    }
                    (got, format!("one of [{}]", list))
                }
                // T2: the explicit DHE parameters are this RFC 7919 group (or
                // one of these, for the any-of list form).
                ("dh_group", FieldValue::U16(_)) | ("dh_group", FieldValue::U16List(_)) => {
                    let wants: Vec<u16> = match &m.value {
                        FieldValue::U16(w) => vec![*w],
                        FieldValue::U16List(l) => l.clone(),
                        _ => unreachable!(),
                    };
                    let got = dh_p.map(|p| p.to_vec());
                    let mut matched = false;
                    for want in &wants {
                        let prime = ecdhe_group_from_wire(*want).and_then(|g| g.ffdhe_prime());
                        let Some(prime) = prime else {
                            return Err(TlsError::MatcherFailed {
                                message: "ServerKeyExchange",
                                field: "dh_group".into(),
                                expected: format!("an RFC 7919 group, not 0x{:04x}", want),
                                observed: "unknown group".into(),
                            });
                        };
                        if got.as_deref() == Some(prime.as_slice()) {
                            matched = true;
                        }
                    }
                    if matched {
                        continue;
                    }
                    let list = wants
                        .iter()
                        .map(|g| format!("0x{:04x}", g))
                        .collect::<Vec<_>>()
                        .join(", ");
                    (
                        got.map(|p| {
                            format!(
                                "{}-bit p {}..",
                                p.len() * 8,
                                p.iter()
                                    .take(16)
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<String>()
                            )
                        })
                        .unwrap_or_else(|| "no explicit DHE parameters".into()),
                        format!("the RFC 7919 prime of group [{}]", list),
                    )
                }
                ("signature_scheme", FieldValue::U16(want)) => (
                    signature_scheme
                        .map(|g| format!("0x{:04x}", g))
                        .unwrap_or_else(|| "none".into()),
                    format!("0x{:04x}", want),
                ),
                ("psk_identity_hint", FieldValue::Bytes(want)) => (
                    hint.map(|h| format!("{:02x?}", h))
                        .unwrap_or_else(|| "none".into()),
                    format!("{:02x?}", want),
                ),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ServerKeyExchange",
                        field: m.field.clone(),
                    });
                }
            };
            if observed != expected {
                return Err(TlsError::MatcherFailed {
                    message: "ServerKeyExchange",
                    field: m.field.clone(),
                    expected,
                    observed,
                });
            }
        }
        Ok(())
    }

    fn recv_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let ske_body = self.read_handshake(HS_SERVER_KEY_EXCHANGE)?;
        self.handle_server_key_exchange(&ske_body)
    }

    /// T1: `recv ServerKeyExchange { key_share: capture $ks }` -- record the
    /// server's public value (the ECDHE point or DHE Ys) under the name.
    fn capture_server_key_exchange(&mut self, key_share: &[u8]) -> Result<(), TlsError> {
        let matchers =
            collect_overrides(&self.cfg.recv_matchers, MessageKind::ServerKeyExchange).to_vec();
        for m in &matchers {
            if let FieldValue::Capture(name) = &m.value {
                match m.field.as_str() {
                    "key_share" | "ecdh_point" | "dh_Ys" => {
                        self.captures.push((name.clone(), key_share.to_vec()))
                    }
                    _ => {
                        return Err(TlsError::Internal(
                            "capture: only key_share (ecdh_point / dh_Ys) can be captured from a ServerKeyExchange",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Parse and act on a ServerKeyExchange body for the negotiated family.
    fn handle_server_key_exchange(&mut self, ske_body: &[u8]) -> Result<(), TlsError> {
        let kex = crate::ir::suite_info(self.negotiated_suite).map(|s| s.kex);
        match kex {
            // RFC 4279 2: the optional identity hint, nothing else.
            Some(crate::ir::KexType::Psk) => {
                let hint = crate::tls::kex12::decode_psk_hint_ske(ske_body)?;
                self.match_server_key_exchange(None, None, Some(&hint), None)?;
                self.psk_identity_hint = Some(hint);
                return Ok(());
            }
            // RFC 5489 3.2: the hint then unsigned ServerECDHParams.
            Some(crate::ir::KexType::EcdhePsk) => {
                let (hint, group, point) = crate::tls::kex12::decode_ecdhe_psk_ske(ske_body)?;
                self.match_server_key_exchange(Some(group), None, Some(&hint), None)?;
                match ecdhe_group_from_wire(group) {
                    Some(g) if !g.is_ffdhe() => {}
                    _ => return Err(TlsError::ServerChoseUnsupportedGroup(group)),
                }
                self.psk_identity_hint = Some(hint);
                self.pending_server_point = Some(point);
                self.pending_server_group = group;
                return Ok(());
            }
            _ => {}
        }
        let is_dhe = kex == Some(crate::ir::KexType::DheRsa);
        if is_dhe {
            let ske = if self.cfg.version < TlsVersion::Tls12 {
                decode_dhe_server_key_exchange_body_legacy(
                    ske_body,
                    SignatureScheme::RsaPkcs1Sha1.wire_value(),
                )?
            } else {
                decode_dhe_server_key_exchange_body(ske_body)?
            };
            self.match_server_key_exchange(None, Some(ske.sig_scheme), None, Some(&ske.dh_p))?;
            let sig_scheme = SignatureScheme::from_wire_value(ske.sig_scheme)
                .ok_or(TlsError::ServerChoseUnsupportedSigScheme(ske.sig_scheme))?;
            let mut signed_bytes = Vec::with_capacity(64 + ske.signed_params.len());
            signed_bytes.extend_from_slice(&self.client_random);
            signed_bytes.extend_from_slice(&self.server_random);
            signed_bytes.extend_from_slice(&ske.signed_params);
            let pk = self
                .server_pubkey
                .as_ref()
                .ok_or(TlsError::Internal("server pubkey not set"))?;
            let verified = if self.cfg.version < TlsVersion::Tls12 {
                pk.verify_tls11(&signed_bytes, &ske.signature)
            } else {
                pk.verify(sig_scheme, &signed_bytes, &ske.signature)
            };
            verified.map_err(|_| TlsError::SignatureVerificationFailed)?;
            self.capture_server_key_exchange(&ske.dh_ys)?;
            self.pending_dhe = Some((ske.dh_p, ske.dh_g, ske.dh_ys));
            return Ok(());
        }
        let legacy_scheme = self.server_pubkey.as_ref().map(|pk| match pk.kind() {
            KeyKind::Rsa | KeyKind::RsaPss => SignatureScheme::RsaPkcs1Sha1.wire_value(),
            _ => SignatureScheme::EcdsaSha1.wire_value(),
        });
        let ske =
            if let Some(scheme) = legacy_scheme.filter(|_| self.cfg.version < TlsVersion::Tls12) {
                decode_ecdhe_server_key_exchange_body_legacy(ske_body, scheme)?
            } else {
                decode_ecdhe_server_key_exchange_body(ske_body)?
            };
        self.match_server_key_exchange(Some(ske.named_curve), Some(ske.sig_scheme), None, None)?;
        // Any curve plzn can generate; a finite-field group has no named_curve
        // form here (TLS 1.2 DHE carries explicit parameters, handled above).
        match ecdhe_group_from_wire(ske.named_curve) {
            Some(g) if !g.is_ffdhe() => {}
            _ => return Err(TlsError::ServerChoseUnsupportedGroup(ske.named_curve)),
        }
        let sig_scheme = SignatureScheme::from_wire_value(ske.sig_scheme)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(ske.sig_scheme))?;
        let mut signed_bytes = Vec::with_capacity(64 + ske.signed_params.len());
        signed_bytes.extend_from_slice(&self.client_random);
        signed_bytes.extend_from_slice(&self.server_random);
        signed_bytes.extend_from_slice(&ske.signed_params);
        let pk = self
            .server_pubkey
            .as_ref()
            .ok_or(TlsError::Internal("server pubkey not set"))?;
        let verified = if self.cfg.version < TlsVersion::Tls12 {
            pk.verify_tls11(&signed_bytes, &ske.signature)
        } else {
            pk.verify(sig_scheme, &signed_bytes, &ske.signature)
        };
        verified.map_err(|_| TlsError::SignatureVerificationFailed)?;
        self.capture_server_key_exchange(&ske.public_point)?;
        self.pending_server_point = Some(ske.public_point);
        self.pending_server_group = ske.named_curve;
        Ok(())
    }

    fn recv_server_hello_done(&mut self) -> Result<(), TlsError> {
        // RFC 4279 2: a plain-PSK server MAY send a ServerKeyExchange with an
        // identity hint before ServerHelloDone; absorb it when it is there. The
        // same path serves ECDHE_PSK when the flow's preset did not read the
        // ServerKeyExchange itself (a `suite` sweep learns the family only at
        // ServerHello).
        let kex = crate::ir::suite_info(self.negotiated_suite).map(|s| s.kex);
        let ske_pending = match kex {
            Some(crate::ir::KexType::Psk) => self.psk_identity_hint.is_none(),
            Some(crate::ir::KexType::EcdhePsk) => self.pending_server_point.is_none(),
            _ => false,
        };
        if ske_pending {
            let (msg_type, body) =
                self.read_handshake_oneof(&[HS_SERVER_KEY_EXCHANGE, HS_SERVER_HELLO_DONE])?;
            if msg_type == HS_SERVER_KEY_EXCHANGE {
                self.handle_server_key_exchange(&body)?;
                let shd_body = self.read_handshake(HS_SERVER_HELLO_DONE)?;
                decode_server_hello_done_body(&shd_body)?;
            } else {
                decode_server_hello_done_body(&body)?;
            }
            return Ok(());
        }
        let shd_body = self.read_handshake(HS_SERVER_HELLO_DONE)?;
        decode_server_hello_done_body(&shd_body)?;
        Ok(())
    }

    fn recv_new_session_ticket(&mut self) -> Result<(), TlsError> {
        let body = self.read_handshake(HS_NEW_SESSION_TICKET)?;
        self.accept_tls12_ticket(&body)?;
        self.nst_seen += 1;
        Ok(())
    }

    fn accept_tls12_ticket(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let (lifetime, ticket) = decode_new_session_ticket_body(body)?;
        for matcher in collect_overrides(&self.cfg.recv_matchers, MessageKind::NewSessionTicket) {
            match (matcher.field.as_str(), &matcher.value) {
                ("max_ticket_lifetime_hours", FieldValue::U16(hours)) => {
                    if lifetime > u32::from(*hours) * 3600 {
                        return Err(TlsError::MatcherFailed {
                            message: "NewSessionTicket",
                            field: matcher.field.clone(),
                            expected: format!("at most {hours} hours"),
                            observed: format!("{lifetime} seconds"),
                        });
                    }
                }
                ("ticket", FieldValue::Capture(name)) => {
                    self.captures.push((name.clone(), ticket.clone()))
                }
                ("ticket_lifetime", FieldValue::Capture(name)) => self
                    .captures
                    .push((name.clone(), lifetime.to_be_bytes().to_vec())),
                ("ticket_lifetime", _) => {
                    match_value("NewSessionTicket", matcher, FieldValue::U32(lifetime))?
                }
                ("ticket", _) => match_value(
                    "NewSessionTicket",
                    matcher,
                    FieldValue::Bytes(ticket.clone()),
                )?,
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "NewSessionTicket",
                        field: matcher.field.clone(),
                    });
                }
            }
        }
        self.captured_ticket = Some(ticket);
        Ok(())
    }

    /// T5: `recv HelloRequest` -- the server asks for a renegotiation (RFC 5246
    /// 7.4.1.1: an empty handshake message of type 0, never part of the hashes;
    /// `begin_renegotiation` resets the transcript anyway). The flow answers
    /// with `renegotiate` or a `send alert warning/no_renegotiation`.
    fn recv_hello_request(&mut self) -> Result<(), TlsError> {
        let body = self.read_handshake(HS_HELLO_REQUEST)?;
        if !body.is_empty() {
            return Err(TlsError::Internal("HelloRequest with a non-empty body"));
        }
        Ok(())
    }

    fn recv_certificate_request(&mut self) -> Result<(), TlsError> {
        let body = self.read_handshake(HS_CERTIFICATE_REQUEST)?;
        self.handle_certificate_request(&body)
    }

    /// Absorbed into the transcript by read_handshake. The signature
    /// algorithms drive the CertificateVerify scheme (RFC 5246 7.4.8);
    /// `recv CertificateRequest { certificate_types / signature_algorithms }`
    /// matchers assert contains-all.
    fn handle_certificate_request(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let cr = if self.cfg.version < TlsVersion::Tls12 {
            crate::tls::codec::decode_certificate_request_legacy_body(body)?
        } else {
            crate::tls::codec::decode_certificate_request_12_body(body)?
        };
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateRequest) {
            match (m.field.as_str(), &m.value) {
                ("certificate_types", FieldValue::U8List(want)) => {
                    if let Some(missing) = want.iter().find(|t| !cr.certificate_types.contains(t)) {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateRequest",
                            field: "certificate_types".into(),
                            expected: format!("list to contain {}", missing),
                            observed: format!("{:?}", cr.certificate_types),
                        });
                    }
                }
                ("signature_algorithms", FieldValue::U16List(want)) => {
                    if let Some(missing) =
                        want.iter().find(|a| !cr.signature_algorithms.contains(a))
                    {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateRequest",
                            field: "signature_algorithms".into(),
                            expected: format!("list to contain 0x{:04x}", missing),
                            observed: cr
                                .signature_algorithms
                                .iter()
                                .map(|a| format!("0x{:04x}", a))
                                .collect::<Vec<_>>()
                                .join(", "),
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
        // A: several credentials (`client_chain:`): the first whose
        // ClientCertificateType the request lists and that can sign with a
        // scheme it listed; none fitting means an empty Certificate (RFC 5246
        // 7.4.6). A single credential is presented as configured.
        if self.cfg.client_credentials.len() > 1 {
            let keys = crate::tls::chains::parse_chain_keys(&self.cfg.client_credentials)?;
            match crate::tls::chains::select_client_credential_12(
                &keys,
                &cr.certificate_types,
                &cr.signature_algorithms,
            ) {
                Some(i) => {
                    let c = &self.cfg.client_credentials[i];
                    self.cfg.client_cert_der = Some(c.cert_der.clone());
                    self.cfg.client_private_key_der = Some(c.key_der.clone());
                }
                None => {
                    self.cfg.client_cert_der = None;
                    self.cfg.client_private_key_der = None;
                }
            }
        }
        self.cr_signature_algorithms = cr.signature_algorithms;
        self.certificate_requested = true;
        Ok(())
    }

    fn send_client_certificate(&mut self) -> Result<(), TlsError> {
        // RFC 5246 §7.4.6: if the client has no suitable certificate it MUST
        // send a Certificate message containing an empty certificate_list.
        // `send Certificate { entries: N }` sends the credential N times (0 =
        // the "no suitable certificate" answer, the missing-client-cert
        // negative against a server that requires one); `certificate_list`
        // replaces the list contents outright.
        // `send Certificate { credential: valid | untrusted | none }` picks a
        // testdata credential by name (and the key its CertificateVerify signs
        // with), so plzn's client can present a chain the server rejects.
        let cert_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::Certificate).to_vec();
        let wire_certificate_type = cert_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("certificate_type", FieldValue::Ident(name)) => Some(match name.as_str() {
                    "x509" => crate::tls::codec::CERT_TYPE_X509,
                    "raw_public_key" => crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    _ => unreachable!("certificate_type was validated while lowering"),
                }),
                _ => None,
            })
            .unwrap_or(self.negotiated_client_cert_type);
        // A: `credential: valid` is the first `client_chain:` entry when the
        // test named any; the other selector values are testdata credentials.
        let credential = crate::tls::chains::valid_credential_from(
            &cert_overrides,
            &self.cfg.client_credentials,
        )
        .or_else(|| crate::tls::dtls_kex::client_credential_override(&cert_overrides));
        // T3: `certificate_list: [name, empty, ...]` composes the list from
        // testdata credentials and zero-length entries.
        let composed = cert_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("certificate_list", FieldValue::IdentList(names)) => {
                    Some(compose_certificate_list(names))
                }
                _ => None,
            })
            .transpose()?;
        // Owns the selected credential's DER so `entries` can borrow it.
        let selected_list: Option<Vec<Vec<u8>>> = match (&composed, &credential) {
            (Some((list, _)), _) => Some(list.clone()),
            (None, Some((l, _))) => Some(l.clone()),
            (None, None) => None,
        };
        let mut entries: Vec<&[u8]> = match (&selected_list, &self.cfg.client_cert_der) {
            (Some(list), _) => list.iter().map(|c| c.as_slice()).collect(),
            (None, Some(der)) => vec![der.as_slice()],
            (None, None) => Vec::new(),
        };
        if let Some((_, key)) = credential {
            self.credential_selected = true;
            self.override_client_key = key;
        }
        if let Some((_, key)) = &composed {
            self.credential_selected = true;
            self.override_client_key = key.clone();
        }
        let mut raw_list: Option<Vec<u8>> = None;
        for ov in &cert_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("entries", FieldValue::U16(n)) => {
                    entries = match (&selected_list, &self.cfg.client_cert_der) {
                        (Some(list), _) => list
                            .first()
                            .map(|c| std::iter::repeat_n(c.as_slice(), *n as usize).collect())
                            .unwrap_or_default(),
                        (None, Some(der)) => {
                            std::iter::repeat_n(der.as_slice(), *n as usize).collect()
                        }
                        (None, None) => Vec::new(),
                    };
                }
                ("certificate_list", FieldValue::Bytes(b)) => raw_list = Some(b.clone()),
                // Consumed above.
                ("certificate_list", FieldValue::IdentList(_))
                | ("credential", _)
                | ("certificate_type", FieldValue::Ident(_)) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "Certificate",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let rpk_leaf = if wire_certificate_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY
            && raw_list.is_none()
        {
            entries
                .first()
                .map(|leaf| {
                    if leaf.is_empty() {
                        Ok(Vec::new())
                    } else {
                        crate::tls::crypto::certificate_spki_der(leaf)
                    }
                })
                .transpose()?
        } else {
            None
        };
        if let Some(rpk) = rpk_leaf.as_deref() {
            let count = entries.len();
            entries = std::iter::repeat_n(rpk, count).collect();
        }
        self.sent_empty_certificate =
            entries.is_empty() && raw_list.as_ref().is_none_or(|l| l.is_empty());
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
            None => crate::tls::codec::encode_certificate_12_body_mapped(&entries),
        };
        let cert_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate);
        let cert_body =
            mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cert_muts)
                .map_err(|_| TlsError::Internal("client Certificate mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE, &cert_body);
        mutate::apply_handshake_header_mutations(&mut framed, cert_muts);
        self.absorb(&framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate),
        )?;
        Ok(())
    }

    fn send_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        // RFC 5246 7.4.8: CertificateVerify only follows a client Certificate
        // "that has signing capability" -- none after an empty list.
        if self.sent_empty_certificate {
            return Ok(());
        }
        // A `credential: ...` selector signs with the selected key; otherwise the
        // configured credential's key.
        let key_der: Vec<u8> = if self.credential_selected {
            match self.override_client_key.clone() {
                Some(k) => k,
                None => return Ok(()),
            }
        } else {
            match &self.cfg.client_private_key_der {
                Some(der) => der.clone(),
                // No key -> we must have sent an empty Certificate; skip CV.
                None => return Ok(()),
            }
        };
        let pk = crate::tls::crypto::PrivateKey::from_pkcs8_der(&key_der)?;
        // RFC 5246 7.4.8: a scheme from the CertificateRequest's
        // supported_signature_algorithms the key can produce, in the server's
        // order; PKCS#1 v1.5 / ECDSA-P256 when the server listed nothing usable
        // (the historical TLS 1.2 defaults, so the negative still signs).
        let sig_scheme = if self.cfg.version < TlsVersion::Tls12 {
            if pk.is_rsa() {
                SignatureScheme::RsaPkcs1Sha1
            } else {
                SignatureScheme::EcdsaSha1
            }
        } else {
            crate::tls::kex12::select_signature_scheme(&pk, &self.cr_signature_algorithms, &[])
                .unwrap_or(if pk.is_rsa() {
                    SignatureScheme::RsaPkcs1Sha256
                } else {
                    pk.default_signature_scheme()
                })
        };
        // RFC 5246 §7.4.8: the signature is over all handshake messages from
        // ClientHello up to but not including CertificateVerify. sign() hashes
        // the message with the scheme's hash, so pass the raw transcript bytes.
        // `send CertificateVerify { sign_with, algorithm, signature, salt_length,
        // mgf1_hash, format }` and `@ xor[signature.em, i]` shape the signature
        // (see `plan_certificate_verify`): relabel the SignatureAndHashAlgorithm
        // (RFC 5246 7.4.8: the server rejects a scheme it did not list or one
        // that does not match the key), really sign with another scheme, or
        // replace the signature bytes outright.
        let cv_muts_all =
            collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateVerify);
        let cv_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::CertificateVerify);
        let tls12_wire = cv_overrides
            .iter()
            .find_map(|field| match (field.field.as_str(), &field.value) {
                ("format", FieldValue::Ident(format)) => Some(format == "tls12"),
                _ => None,
            })
            .unwrap_or(self.cfg.version >= TlsVersion::Tls12);
        let plan = plan_certificate_verify(
            &pk,
            sig_scheme,
            cv_overrides,
            cv_muts_all,
            &self.raw_transcript,
            self.cfg.version < TlsVersion::Tls12,
        )?;
        let cv_muts_vec = without_em_mutations(cv_muts_all);
        let cv_muts = cv_muts_vec.as_slice();
        // Mapped body so `send CertificateVerify @ ...` mutations can target the
        // signature (e.g. the client-auth bad-signature test). The TLS 1.2 and TLS 1.3
        // CertificateVerify wire formats are identical.
        let encoded = if !tls12_wire {
            crate::tls::codec::encode_certificate_verify_legacy_body_mapped(&plan.signature)
        } else {
            crate::tls::codec::encode_certificate_verify_13_body_mapped(plan.label, &plan.signature)
        };
        let cv_body =
            mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cv_muts)
                .map_err(|_| TlsError::Internal("client CertificateVerify mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_VERIFY, &cv_body);
        mutate::apply_handshake_header_mutations(&mut framed, cv_muts);
        self.absorb(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, cv_muts)?;
        Ok(())
    }

    /// Send ClientKeyExchange + compute ECDHE shared secret +
    /// derive master secret + install write keys (read keys
    /// deferred to recv_change_cipher_spec).
    fn send_client_key_exchange(&mut self) -> Result<(), TlsError> {
        if let Some(cke_framed) = self.last_client_key_exchange.clone() {
            let cke_muts =
                collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange)
                    .to_vec();
            self.absorb(&cke_framed);
            self.records.write_record_with_mutations(
                CONTENT_TYPE_HANDSHAKE,
                &cke_framed,
                &cke_muts,
            )?;
            return Ok(());
        }

        let kex = crate::ir::suite_info(self.negotiated_suite).map(|s| s.kex);
        let pms = match kex {
            Some(crate::ir::KexType::Rsa) => self.send_rsa_cke()?,
            Some(crate::ir::KexType::DheRsa) => self.send_dhe_cke()?,
            Some(crate::ir::KexType::Psk) => self.send_psk_cke(false)?,
            Some(crate::ir::KexType::EcdhePsk) => self.send_psk_cke(true)?,
            _ => self.send_ecdhe_cke()?,
        };

        // Derive the master secret with the suite's PRF hash (SHA-384 for the
        // *_SHA384 suites, SHA-256 otherwise: RFC 5246 5 / RFC 5289).
        let prf_hash = self.prf_hash();
        let ms = if self.use_ems {
            let session_hash = self.handshake_digest();
            derive_master_secret_ems_for(self.cfg.version, prf_hash, &pms, &session_hash)
        } else {
            derive_master_secret_for(
                self.cfg.version,
                prf_hash,
                &pms,
                &self.client_random,
                &self.server_random,
            )
        };
        self.master_secret = ms;

        let (client_keys, server_keys) = self.derive_tls12_keys()?;
        // New write keys take effect only after the client's CCS. Before it,
        // handshake records are plaintext in an initial handshake and use the
        // old keys during renegotiation (RFC 5246 6.1). This also matters for a
        // deliberately duplicated ClientKeyExchange inserted before CCS.
        self.pending_write_keys = Some(client_keys);
        self.pending_read_keys = Some(server_keys);
        Ok(())
    }

    /// The negotiated suite's PRF / handshake hash (SHA-256 before a suite is
    /// known).
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

    /// Record keys for both directions of the negotiated suite:
    /// `(client_writes, server_writes)`.
    fn derive_tls12_keys(&self) -> Result<(DirectionKeys, DirectionKeys), TlsError> {
        let suite = crate::ir::suite_info(self.negotiated_suite)
            .ok_or(TlsError::ServerChoseUnsupportedSuite(self.negotiated_suite))?;
        Ok(crate::tls::handshake::legacy_direction_keys(
            self.cfg.version,
            suite,
            &self.master_secret,
            &self.server_random,
            &self.client_random,
            self.use_etm,
        )?)
    }

    /// ECDHE CKE path: generate ephemeral, agree, send point.
    /// Returns the pre-master secret.
    fn send_ecdhe_cke(&mut self) -> Result<Vec<u8>, TlsError> {
        // Lazy ECDHE generation — use the group the server chose.
        if self.ephemeral.is_none() {
            let group = match ecdhe_group_from_wire(self.pending_server_group) {
                Some(g) if !g.is_ffdhe() && !g.is_tls13_only() => g,
                _ => {
                    return Err(TlsError::ServerChoseUnsupportedGroup(
                        self.pending_server_group,
                    ));
                }
            };
            let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"ecdh_private"));
            self.ephemeral = Some(EcdhePrivate::generate(group, &mut ec_rng));
        }
        let cke_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientKeyExchange).to_vec();
        // `shared_secret_leading_zeros: N`: search the scalar until the ECDH
        // shared secret (the x-coordinate, RFC 8422 5.10 keeps its leading
        // zeros) starts with N zero bytes; each attempt is its own sub-seed
        // so the winner is regenerated deterministically.
        if let Some(n) = cke_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("shared_secret_leading_zeros", FieldValue::U8(n)) => Some(*n as usize),
                _ => None,
            })
        {
            let group = self
                .ephemeral
                .as_ref()
                .map(|e| e.group())
                .ok_or(TlsError::Internal("missing ephemeral"))?;
            let server_point = self
                .pending_server_point
                .clone()
                .ok_or(TlsError::Internal("missing server ECDHE point"))?;
            let mut found = None;
            for attempt in 0u32..(1 << 20) {
                let label = format!("ecdh_private:lz:{}", attempt);
                let seed = Rng::sub_seed(self.cfg.seed, label.as_bytes());
                let z = EcdhePrivate::generate(group, &mut Rng::from_seed(seed))
                    .agree(&server_point)?;
                if z.iter().take(n).all(|b| *b == 0) {
                    found = Some(seed);
                    break;
                }
            }
            let seed = found.ok_or(TlsError::Internal(
                "shared_secret_leading_zeros: no scalar found within 2^20 attempts",
            ))?;
            self.ephemeral = Some(EcdhePrivate::generate(group, &mut Rng::from_seed(seed)));
        }
        let ephemeral = self
            .ephemeral
            .take()
            .ok_or(TlsError::Internal("missing ephemeral"))?;
        let server_point = self
            .pending_server_point
            .take()
            .ok_or(TlsError::Internal("missing server ECDHE point"))?;
        // `send ClientKeyExchange { key_share_point: ... }` re-encodes the point we
        // put on the wire while the agreement below still uses the real key. Done
        // before `agree`, which consumes the ephemeral.
        let recipe = key_share_point_recipe(&cke_overrides)?;
        let mut cke_pubkey = encode_key_share_point(&ephemeral, &recipe)?;
        let pms = ephemeral.agree(&server_point)?;

        // An explicit `ecdh_Yc: [...]` still wins over the recipe.
        for ov in &cke_overrides {
            apply_client_key_exchange_override(&mut cke_pubkey, ov)?;
        }
        let cke_encoded = encode_ecdhe_client_key_exchange_body_mapped(&cke_pubkey);
        let cke_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange);
        let cke_body =
            mutate::apply_handshake_mutations(cke_encoded.bytes.clone(), &cke_encoded, cke_muts)
                .map_err(|_| TlsError::Internal("CKE mutation failed"))?;
        let mut cke_framed = encode_handshake(HS_CLIENT_KEY_EXCHANGE, &cke_body);
        // Corrupt the handshake header (msg_type/length) if requested
        // (BoGo WrongMessageType).
        mutate::apply_handshake_header_mutations(&mut cke_framed, cke_muts);
        self.last_client_key_exchange = Some(cke_framed.clone());
        self.absorb(&cke_framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &cke_framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange),
        )?;
        Ok(pms)
    }

    /// DHE CKE path: generate a finite-field DH private, agree with the server's
    /// Ys, send our Yc. Returns the pre-master secret.
    fn send_dhe_cke(&mut self) -> Result<Vec<u8>, TlsError> {
        let (p, g, ys) = self
            .pending_dhe
            .take()
            .ok_or(TlsError::Internal("missing DHE params"))?;
        // `kex12` checks Ys is in (1, p-1) and strips the shared secret's leading
        // zero bytes (RFC 5246 8.1.2).
        let leading_zeros =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientKeyExchange)
                .iter()
                .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                    ("shared_secret_leading_zeros", FieldValue::U8(n)) => Some(*n as usize),
                    _ => None,
                });
        let (mut yc, pms) = match leading_zeros {
            Some(n) => crate::tls::kex12::dhe_client_premaster_leading_zeros(
                &p,
                &g,
                &ys,
                self.cfg.seed,
                n,
            )?,
            None => crate::tls::kex12::dhe_client_premaster(&p, &g, &ys, self.cfg.seed)?,
        };
        // `send ClientKeyExchange { dh_Yc: <bytes> }` replaces the public value
        // outright; `{ key_share_point: zero | one | p_minus_1 }` sends one of
        // the RFC 8446 4.2.8.1 bounds a server MUST reject, at p's length.
        let cke_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientKeyExchange).to_vec();
        for ov in &cke_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("dh_Yc", FieldValue::Bytes(b)) => yc = b.clone(),
                ("shared_secret_leading_zeros", _) => {}
                ("key_share_point", FieldValue::Ident(s)) => {
                    let recipe = match s.as_str() {
                        "zero" => crate::tls::kex12::DhPublicRecipe::Zero,
                        "one" => crate::tls::kex12::DhPublicRecipe::One,
                        "p_minus_1" => crate::tls::kex12::DhPublicRecipe::PMinusOne,
                        "p" => crate::tls::kex12::DhPublicRecipe::P,
                        _ => {
                            return Err(TlsError::Internal(
                                "key_share_point on a DHE ClientKeyExchange takes `zero`, `one`, `p_minus_1` or `p`",
                            ));
                        }
                    };
                    yc = crate::tls::kex12::dh_public_recipe(&p, recipe);
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ClientKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }

        let cke_encoded = encode_dhe_client_key_exchange_body_mapped(&yc);
        let cke_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange);
        let cke_body =
            mutate::apply_handshake_mutations(cke_encoded.bytes.clone(), &cke_encoded, cke_muts)
                .map_err(|_| TlsError::Internal("CKE mutation failed"))?;
        let mut cke_framed = encode_handshake(HS_CLIENT_KEY_EXCHANGE, &cke_body);
        mutate::apply_handshake_header_mutations(&mut cke_framed, cke_muts);
        self.last_client_key_exchange = Some(cke_framed.clone());
        self.absorb(&cke_framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &cke_framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange),
        )?;
        Ok(pms)
    }

    /// PSK / ECDHE_PSK CKE path (RFC 4279 2, RFC 5489 3.3): the identity
    /// (overridable with `psk_identity`, the unknown-identity negative) and, for
    /// ECDHE_PSK, the client's ephemeral point. Returns the premaster:
    /// `len(Z) || Z || len(psk) || psk` with Z = zeros for plain PSK.
    fn send_psk_cke(&mut self, ecdhe: bool) -> Result<Vec<u8>, TlsError> {
        let (mut identity, secret) = self.cfg.psk.clone().ok_or(TlsError::Internal(
            "PSK suite negotiated without a `psk { }` block",
        ))?;
        let cke_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientKeyExchange).to_vec();
        for ov in &cke_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("psk_identity", FieldValue::Bytes(b)) => identity = b.clone(),
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ClientKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        let (point, pms) = if ecdhe {
            let group = match ecdhe_group_from_wire(self.pending_server_group) {
                Some(g) if !g.is_ffdhe() && !g.is_tls13_only() => g,
                _ => {
                    return Err(TlsError::ServerChoseUnsupportedGroup(
                        self.pending_server_group,
                    ));
                }
            };
            let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"ecdh_private"));
            let ephemeral = EcdhePrivate::generate(group, &mut ec_rng);
            let server_point = self
                .pending_server_point
                .take()
                .ok_or(TlsError::Internal("missing server ECDHE point"))?;
            let point = ephemeral.public_bytes();
            let z = ephemeral.agree(&server_point)?;
            (
                Some(point),
                crate::tls::kex12::psk_premaster_with(&z, &secret),
            )
        } else {
            (None, crate::tls::kex12::psk_premaster(&secret))
        };
        let cke_encoded = crate::tls::kex12::encode_psk_cke_mapped(&identity, point.as_deref());
        let cke_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange);
        let cke_body =
            mutate::apply_handshake_mutations(cke_encoded.bytes.clone(), &cke_encoded, cke_muts)
                .map_err(|_| TlsError::Internal("CKE mutation failed"))?;
        let mut cke_framed = encode_handshake(HS_CLIENT_KEY_EXCHANGE, &cke_body);
        mutate::apply_handshake_header_mutations(&mut cke_framed, cke_muts);
        self.last_client_key_exchange = Some(cke_framed.clone());
        self.absorb(&cke_framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &cke_framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange),
        )?;
        Ok(pms)
    }

    /// Static RSA CKE path: generate PMS (version + random),
    /// encrypt under server's RSA public key, send encrypted blob.
    /// Returns the pre-master secret (plaintext).
    fn send_rsa_cke(&mut self) -> Result<Vec<u8>, TlsError> {
        let pk = self
            .server_pubkey
            .as_ref()
            .ok_or(TlsError::Internal("server pubkey not set"))?;

        // Build the 48-byte PMS: version(2) + random(46).
        // Overridable via `premaster_secret` field — the driver
        // then encrypts the provided bytes instead of generating
        // its own. Useful for PMS-version-check tests (ROBOT
        // probe #1: correct padding, wrong version).
        let cke_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientKeyExchange).to_vec();
        let mut pms = None;
        let mut raw_ciphertext = None;
        let mut padding_byte: Option<u8> = None;
        let mut raw_plaintext: Option<Vec<u8>> = None;
        for ov in &cke_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("premaster_secret", FieldValue::Bytes(b)) => {
                    pms = Some(b.clone());
                }
                ("encrypted_premaster", FieldValue::Bytes(b)) => {
                    raw_ciphertext = Some(b.clone());
                }
                // The server key's modulus n as the ciphertext: c = n is
                // congruent to 0, so the "plaintext" is all zeros.
                ("encrypted_premaster", FieldValue::Ident(s)) if s == "modulus" => {
                    raw_ciphertext = Some(crate::tls::crypto::rsa_modulus_bytes(pk).ok_or(
                        TlsError::Internal("encrypted_premaster: modulus needs an RSA server key"),
                    )?);
                }
                ("padding_byte", FieldValue::U8(b)) => padding_byte = Some(*b),
                ("rsa_plaintext", FieldValue::Bytes(b)) => raw_plaintext = Some(b.clone()),
                ("ecdh_Yc", _) | ("dh_Yc", _) => {
                    return Err(TlsError::Internal(
                        "ecdh_Yc/dh_Yc override on an RSA kex CKE",
                    ));
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "ClientKeyExchange",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        // Priority: raw_ciphertext > rsa_plaintext > premaster_secret > default PMS.
        let mut pms = pms.unwrap_or_else(|| {
            let mut p = Vec::with_capacity(48);
            p.extend_from_slice(&self.client_hello_version.to_be_bytes());
            let mut pms_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"pms_random"));
            let random_bytes: [u8; 46] = pms_rng.random_array();
            p.extend_from_slice(&random_bytes);
            p
        });

        // Apply byte mutations to the PMS plaintext BEFORE
        // encryption. This is where `@ set[1] = 0x04` (wrong PMS
        // version byte) or `@ pad +1` (oversized PMS) fire.
        // Bare offsets index the 48-byte PMS directly. Record-
        // level mutations (if any) are deferred to the record
        // layer as usual. `pkcs1.*` paths address the PKCS#1 v1.5
        // EM instead and are applied to it below.
        let cke_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange);
        let is_pkcs1 = |m: &crate::ir::Mutation| match &m.op {
            crate::ir::MutationOp::Xor { target, .. }
            | crate::ir::MutationOp::Set { target, .. } => {
                matches!(&target.path, Some(parts) if parts.first().map(String::as_str) == Some("pkcs1"))
            }
            _ => false,
        };
        let pkcs1_muts: Vec<crate::ir::Mutation> = cke_muts
            .iter()
            .filter(|m| is_pkcs1(m))
            .map(|m| {
                let mut m = m.clone();
                if let crate::ir::MutationOp::Xor { target, .. }
                | crate::ir::MutationOp::Set { target, .. } = &mut m.op
                {
                    if let Some(parts) = &mut target.path {
                        parts[0] = "handshake".to_string();
                    }
                }
                m
            })
            .collect();
        let pms_muts: Vec<crate::ir::Mutation> =
            cke_muts.iter().filter(|m| !is_pkcs1(m)).cloned().collect();
        if !pms_muts.is_empty() && raw_ciphertext.is_none() {
            // Build a synthetic EncodedBody with the whole PMS
            // as a "premaster_secret" field so both bare offsets
            // and `handshake.premaster_secret` paths work.
            let pms_field_map = crate::tls::codec::EncodedBody {
                bytes: pms.clone(),
                fields: [("premaster_secret".to_string(), 0..pms.len())]
                    .into_iter()
                    .collect(),
            };
            pms = mutate::apply_handshake_mutations(pms, &pms_field_map, &pms_muts)
                .map_err(|_| TlsError::Internal("RSA CKE PMS mutation failed"))?;
        }

        // A shaped EM (padding byte, pkcs1.* mutations) or a raw block goes
        // through textbook RSA; the plain path keeps the `rsa` crate encoder.
        let shaped = padding_byte.is_some() || !pkcs1_muts.is_empty();
        if raw_ciphertext.is_none() {
            if let Some(block) = raw_plaintext {
                raw_ciphertext = Some(crate::tls::crypto::rsa_raw_encrypt(pk, &block)?);
            } else if shaped {
                let k = crate::tls::kex12::rsa_key_len(pk).ok_or(TlsError::Internal(
                    "padding_byte / pkcs1.* need an RSA server key",
                ))?;
                let mut em =
                    crate::tls::kex12::pkcs1_type2_em(k, &pms, padding_byte, self.cfg.seed)?;
                if !pkcs1_muts.is_empty() {
                    let em_map = crate::tls::codec::EncodedBody {
                        bytes: em.clone(),
                        fields: crate::tls::kex12::pkcs1_em_layout(k, pms.len())
                            .into_iter()
                            .map(|(name, range)| (name.to_string(), range))
                            .collect(),
                    };
                    em = mutate::apply_handshake_mutations(em, &em_map, &pkcs1_muts)
                        .map_err(|_| TlsError::Internal("RSA CKE PKCS#1 EM mutation failed"))?;
                }
                raw_ciphertext = Some(crate::tls::crypto::rsa_raw_encrypt(pk, &em)?);
            }
        }
        let cke_muts: &[crate::ir::Mutation] =
            if raw_ciphertext.is_some() && (shaped || raw_plaintext_used(&cke_overrides)) {
                &[]
            } else {
                cke_muts
            };

        let had_raw_ciphertext = raw_ciphertext.is_some();
        let cke_payload = match raw_ciphertext {
            Some(ct) => ct,
            None => rsa_pkcs1v15_encrypt(pk, &pms)?,
        };

        let cke_encoded = encode_rsa_client_key_exchange_body_mapped(&cke_payload);
        // When we built the PMS here, byte mutations were ALREADY applied to the
        // plaintext PMS above (before encryption). Re-applying them to the encoded
        // body would corrupt the 2-byte EncryptedPreMasterSecret length prefix or
        // the ciphertext -- e.g. a bare `@ set[1]` meant for the PMS version byte
        // would instead flip the length low byte and make the server abort CKE
        // parsing BEFORE Finished, defeating a Bleichenbacher-countermeasure test.
        // Only when the ciphertext was supplied whole (encrypted_premaster, no
        // plaintext PMS) do the mutations apply to the wire body.
        let cke_body = if had_raw_ciphertext {
            mutate::apply_handshake_mutations(cke_encoded.bytes.clone(), &cke_encoded, cke_muts)
                .map_err(|_| TlsError::Internal("CKE mutation failed"))?
        } else {
            cke_encoded.bytes.clone()
        };
        let cke_framed = encode_handshake(HS_CLIENT_KEY_EXCHANGE, &cke_body);
        self.last_client_key_exchange = Some(cke_framed.clone());
        self.absorb(&cke_framed);
        self.records.write_record_with_mutations(
            CONTENT_TYPE_HANDSHAKE,
            &cke_framed,
            collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange),
        )?;
        Ok(pms)
    }

    fn send_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        let ccs_byte = resolve_ccs_byte(&self.cfg.send_overrides)?;
        self.records.write_record_with_mutations(
            CONTENT_TYPE_CCS,
            &[ccs_byte],
            collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
        )?;
        // Client-auth: the write keys were deferred so CertificateVerify could
        // go out in the clear; install them now, after the plaintext CCS, so the
        // following Finished is encrypted.
        if let Some(keys) = self.pending_write_keys.take() {
            self.records.install_write_keys(keys)?;
        }
        Ok(())
    }

    fn send_finished(&mut self) -> Result<(), TlsError> {
        let prf_hash = self.prf_hash();
        let transcript_for_client_fin = self.handshake_digest();
        let mut client_vd = compute_verify_data_for(
            self.cfg.version,
            prf_hash,
            &self.master_secret,
            b"client finished",
            &transcript_for_client_fin,
        );
        // Remember the (clean) verify_data for the RFC 5746 renegotiation_info of
        // a subsequent renegotiation.
        self.last_client_verify_data = client_vd.clone();
        let fin_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::Finished).to_vec();
        for ov in &fin_overrides {
            apply_finished_override(&mut client_vd, ov)?;
        }
        let fin_encoded = encode_finished_body_mapped(&client_vd);
        let fin_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        let fin_body =
            mutate::apply_handshake_mutations(fin_encoded.bytes.clone(), &fin_encoded, fin_muts)
                .map_err(|_| TlsError::Internal("Finished mutation failed"))?;
        let mut fin_framed = encode_handshake(HS_FINISHED, &fin_body);
        // Corrupt the handshake header (msg_type/length) if requested
        // (BoGo WrongMessageType), applied to the framed message pre-encryption.
        mutate::apply_handshake_header_mutations(&mut fin_framed, fin_muts);
        self.transcript.update(&fin_framed);
        self.raw_transcript.extend_from_slice(&fin_framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &fin_framed, fin_muts)?;
        Ok(())
    }

    fn recv_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        loop {
            match self.records.read_change_cipher_spec() {
                Ok(()) => break,
                // T5: application data crossing the renegotiation (see hs_bytes).
                Err(RecordError::UnexpectedContentType { got, .. })
                    if got == crate::tls::codec::CONTENT_TYPE_APP_DATA && self.renegotiating =>
                {
                    let data = self.records.read_app_data()?;
                    self.deferred_app_data.push_back(data);
                }
                Err(e) => return Err(e.into()),
            }
        }
        // A NewSessionTicket arrives just before the server CCS (RFC 5077). It is
        // part of the server Finished transcript, so absorb it now -- before
        // recv_finished_msg snapshots the digest -- and capture the ticket.
        while let Some(framed) = self.records.take_swallowed_nst() {
            self.absorb(&framed);
            self.accept_tls12_ticket(&framed[4..])?;
        }
        // Install read keys now that server has sent CCS.
        if let Some(keys) = self.pending_read_keys.take() {
            self.records.install_read_keys(keys)?;
        }
        Ok(())
    }

    fn recv_finished_msg(&mut self) -> Result<(), TlsError> {
        let fin_body = self.read_handshake(HS_FINISHED)?;
        let got = decode_finished_body(&fin_body)?;
        match_finished_fields(&fin_body, &self.cfg.recv_matchers)?;
        let expected = compute_verify_data_for(
            self.cfg.version,
            self.prf_hash(),
            &self.master_secret,
            b"server finished",
            &self.pre_server_finished_digest,
        );
        if got != expected {
            return Err(TlsError::FinishedMismatch);
        }
        self.last_server_verify_data = expected;
        Ok(())
    }

    /// Read the next handshake message, which must be one of `accepted`;
    /// returns `(type, body)` and folds the framed bytes into the transcript.
    fn read_handshake_oneof(&mut self, accepted: &[u8]) -> Result<(u8, Vec<u8>), TlsError> {
        let header = self.hs_bytes(4)?;
        let mut cursor = ByteCursor::new(&header);
        let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
        let body = self.hs_bytes(body_len)?;
        if !accepted.contains(&msg_type) {
            return Err(TlsError::UnexpectedHandshake {
                expected: accepted[0],
                got: msg_type,
            });
        }
        let mut framed = Vec::with_capacity(4 + body.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&body);
        self.absorb(&framed);
        Ok((msg_type, body))
    }

    /// Read the next handshake message, validating its type and
    /// appending its framed bytes to the transcript hash. Returns
    /// the body (bytes after the 4-byte handshake header).
    ///
    /// NewSessionTicket is silently absorbed when the caller is
    /// waiting on HS_FINISHED — it's a legitimate optional pre-
    /// Finished message in TLS 1.2 ticket flows.
    fn read_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        loop {
            let header = self.hs_bytes(4)?;
            let mut cursor = ByteCursor::new(&header);
            let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
            let body = self.hs_bytes(body_len)?;

            if expected_type == HS_FINISHED && msg_type == HS_NEW_SESSION_TICKET {
                self.accept_tls12_ticket(&body)?;
                self.nst_seen += 1;
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&header);
                framed.extend_from_slice(&body);
                self.absorb(&framed);
                continue;
            }
            // T6: RFC 6066 8: a server that staples sends CertificateStatus
            // right after Certificate. A preset that did not spell out `recv
            // CertificateStatus` absorbs it (it is part of the transcript);
            // an explicit step reads and checks it.
            if msg_type == crate::tls::codec::HS_CERTIFICATE_STATUS
                && matches!(
                    expected_type,
                    HS_SERVER_KEY_EXCHANGE | HS_CERTIFICATE_REQUEST | HS_SERVER_HELLO_DONE
                )
            {
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&header);
                framed.extend_from_slice(&body);
                self.absorb(&framed);
                continue;
            }
            if msg_type != expected_type {
                return Err(TlsError::UnexpectedHandshake {
                    expected: expected_type,
                    got: msg_type,
                });
            }
            let mut framed = Vec::with_capacity(4 + body.len());
            framed.extend_from_slice(&header);
            framed.extend_from_slice(&body);
            // Snapshot before hashing when the message is the
            // server Finished — we need the pre-hash digest to
            // verify the server's verify_data.
            if msg_type == HS_FINISHED {
                self.pre_server_finished_digest = self.handshake_digest();
            }
            self.absorb(&framed);
            return Ok(body);
        }
    }
}

// ============================================================
//                       TLS 1.3 client
// ============================================================

/// DTLS ClientHello retains the one-byte legacy_cookie vector between
/// legacy_session_id and cipher_suites. DTLS 1.3 requires that vector to be
/// empty; the rest of the body is the TLS 1.3 ClientHello layout.
fn add_dtls_legacy_cookie_mapped(
    mut encoded: crate::tls::codec::EncodedBody,
    cookie: &[u8],
) -> Result<crate::tls::codec::EncodedBody, TlsError> {
    if cookie.len() > u8::MAX as usize {
        return Err(TlsError::Internal(
            "DTLS ClientHello legacy cookie is longer than 255 bytes",
        ));
    }
    if encoded.bytes.len() < 35 {
        return Err(TlsError::Internal(
            "ClientHello is too short for session_id",
        ));
    }
    let position = 35usize
        .checked_add(encoded.bytes[34] as usize)
        .ok_or(TlsError::Internal("ClientHello session_id length overflow"))?;
    if position > encoded.bytes.len() {
        return Err(TlsError::Internal("ClientHello session_id is truncated"));
    }
    let mut wire_cookie = Vec::with_capacity(1 + cookie.len());
    wire_cookie.push(cookie.len() as u8);
    wire_cookie.extend_from_slice(cookie);
    encoded.bytes.splice(position..position, wire_cookie);
    let inserted = 1 + cookie.len();
    for range in encoded.fields.values_mut() {
        if range.start >= position {
            range.start += inserted;
        }
        if range.end > position {
            range.end += inserted;
        }
    }
    Ok(encoded)
}

pub(crate) fn strip_dtls_legacy_cookie(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    if body.len() < 36 {
        return Err(TlsError::Internal("DTLS ClientHello is too short"));
    }
    let cookie_pos = 35usize
        .checked_add(body[34] as usize)
        .ok_or(TlsError::Internal(
            "DTLS ClientHello session_id length overflow",
        ))?;
    if cookie_pos >= body.len() {
        return Err(TlsError::Internal(
            "DTLS ClientHello session_id is truncated",
        ));
    }
    let cookie_len = body[cookie_pos] as usize;
    if cookie_pos + 1 + cookie_len > body.len() {
        return Err(TlsError::Internal("DTLS ClientHello cookie is truncated"));
    }
    let mut normalized = body.to_vec();
    normalized.drain(cookie_pos..cookie_pos + 1 + cookie_len);
    Ok(normalized)
}

pub struct Tls13ClientConfig {
    pub server_name: String,
    pub cipher_suites: Vec<u16>,
    pub groups: Vec<u16>,
    /// Groups to generate key shares for, in offer order (a subset of `groups`
    /// in a conforming ClientHello; a test may deliberately share an unlisted
    /// group). Each must be one of ir::CLIENT_KEY_SHARE_GROUPS.
    pub key_share_groups: Vec<u16>,
    pub signature_schemes: Vec<u16>,
    pub seed: [u8; 32],
    pub send_overrides: Vec<MessageOverrides>,
    pub recv_matchers: Vec<MessageOverrides>,
    pub send_mutations: Vec<MessageMutations>,
    pub send_ext_deltas: Vec<MessageExtDeltas>,
    pub psk: Option<crate::ir::PskConfig>,
    /// Offer early_data and install client early write keys. Set only when the
    /// resumed flow contains an explicit `send EarlyData` step.
    pub use_early_data: bool,
    /// Client certificate + private key for client auth. None if
    /// client auth is not configured.
    pub client_cert_der: Option<Vec<u8>>,
    pub client_private_key_der: Option<Vec<u8>>,
    /// A: every client-auth credential `client_chain:` named, in preference
    /// order; with two or more the CertificateRequest's signature_algorithms
    /// pick (RFC 8446 4.4.2), none fitting = an empty Certificate. A single
    /// credential is presented as configured. `client_chain_none` = `[]`.
    pub client_credentials: Vec<crate::ir::Chain>,
    pub client_chain_none: bool,
    /// Intermediate CA certificates (DER) presented after the client leaf so the
    /// server can build a path to a trusted client-CA root. Empty = leaf only.
    pub client_extra_chain_der: Vec<Vec<u8>>,
    /// Advertise psk_key_exchange_modes so the server issues a NewSessionTicket
    /// (set for the initial session of a resumption test).
    pub advertise_psk_modes: bool,
    /// Offer the server_certificate_type extension advertising RawPublicKey then X509
    /// (RFC 7250). A server that supports RPK may select it; one that does not falls back
    /// to X.509. The client decodes the Certificate per the server's selection.
    pub offer_raw_public_key: bool,
    /// T6: the `compress_cert` capability (uut server): offer compress_certificate =
    /// [zlib] (RFC 8879 3) so the shim server may compress its Certificate.
    pub offer_cert_compression: bool,
}

impl Tls13ClientConfig {
    pub fn default_for(server_name: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            server_name: server_name.into(),
            cipher_suites: vec![TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256],
            // Advertise x25519, secp256r1 and secp384r1. By default a key_share is
            // sent only for x25519 (1-RTT); a server that requires one of the
            // P-curves will HRR for it and the client retries with that share.
            groups: vec![GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
            key_share_groups: vec![GROUP_X25519],
            signature_schemes: vec![
                SignatureScheme::EcdsaSecp256r1Sha256.wire_value(),
                SignatureScheme::EcdsaSecp384r1Sha384.wire_value(),
                SignatureScheme::EcdsaSecp521r1Sha512.wire_value(),
                SignatureScheme::RsaPssRsaeSha256.wire_value(),
                SignatureScheme::RsaPssRsaeSha384.wire_value(),
                SignatureScheme::RsaPssRsaeSha512.wire_value(),
                SignatureScheme::RsaPssPssSha256.wire_value(),
                SignatureScheme::RsaPssPssSha384.wire_value(),
                SignatureScheme::RsaPssPssSha512.wire_value(),
                SignatureScheme::Ed25519.wire_value(),
            ],
            seed,
            send_overrides: Vec::new(),
            recv_matchers: Vec::new(),
            send_mutations: Vec::new(),
            send_ext_deltas: Vec::new(),
            psk: None,
            use_early_data: false,
            client_cert_der: None,
            client_private_key_der: None,
            client_credentials: Vec::new(),
            client_chain_none: false,
            client_extra_chain_der: Vec::new(),
            advertise_psk_modes: false,
            offer_raw_public_key: false,
            offer_cert_compression: false,
        }
    }
}

pub struct Tls13Client {
    cfg: Tls13ClientConfig,
    records: RecordLayer,
    transcript: TranscriptHash,
    schedule: Tls13KeySchedule,

    client_random: [u8; 32],
    /// ECDHE ephemerals behind the offered key shares, (group, key) in offer
    /// order; the one the server answers is removed and agreed.
    ephemerals: Vec<(u16, EcdhePrivate)>,
    /// T1: values recorded by `capture $name` matchers.
    captures: Vec<(String, Vec<u8>)>,
    server_pubkey: Option<PublicKey>,
    /// Certificate type the server selected via server_certificate_type (RFC 7250);
    /// X509 unless the server echoes RawPublicKey in EncryptedExtensions.
    negotiated_server_cert_type: u8,
    /// Certificate type selected by the server for this client's credential.
    negotiated_client_cert_type: u8,
    negotiated_suite: u16,
    /// Whether ServerHello accepted one of the offered resumption/external
    /// PSKs. A declined PSK offer continues as a certificate handshake.
    server_selected_psk: bool,
    /// The cipher suites actually offered in the ClientHello (after overrides).
    offered_suites: Vec<u16>,
    /// The final CH1 legacy_session_id, which CH2 must repeat after HRR.
    client_session_id: Vec<u8>,
    /// The signature schemes actually advertised after ClientHello extension
    /// deltas, rather than the pre-delta config defaults.
    offered_signature_schemes: Vec<u16>,
    /// The certificate-signature schemes advertised in
    /// signature_algorithms_cert, or signature_algorithms when the former was
    /// absent (RFC 8446 4.2.3).
    offered_cert_signature_schemes: Vec<u16>,
    /// HRR state: selected suite, group requested by server, and cookie to echo.
    hrr_cipher_suite: Option<u16>,
    hrr_requested_group: Option<u16>,
    hrr_cookie: Option<Vec<u8>>,
    hrr_client_hello_framed: Option<Vec<u8>>,
    hrr_framed: Option<Vec<u8>>,
    /// Resumption state captured after handshake completion.
    resumption_master_secret: Option<Vec<u8>>,
    captured_nst: Option<crate::tls::codec::NewSessionTicket13>,
    /// T5: NewSessionTickets read by the driver itself (explicit `recv` or
    /// swallowed in `read_handshake_oneof`); the record layer counts the ones
    /// a `wait` absorbed.
    nst_seen: u32,
    /// A KeyUpdate(update_requested) absorbed while reading application data
    /// is answered before our next application-data record (RFC 8446 4.6.3).
    key_update_response_pending: bool,
    /// recv_server_finished installed the server's application read keys (so
    /// half-RTT data can be read before our Finished); send_client_finished
    /// must then leave the read side alone -- a KeyUpdate may have rotated it.
    server_app_read_keys_installed: bool,
    /// Transcript digest right AFTER the server's Finished. Application traffic
    /// secrets derive from this point (RFC 8446 7.1), which in client-auth
    /// precedes the client's own Certificate/CertificateVerify.
    post_server_finished_digest: Vec<u8>,
    // T3: client authentication controls, as on the TLS 1.2 client.
    /// `send Certificate { credential | certificate_list: [names] }` selected
    /// a testdata credential; the CertificateVerify signs with
    /// `override_client_key` (None: no CertificateVerify).
    credential_selected: bool,
    override_client_key: Option<Vec<u8>>,
    /// The client Certificate carried no entries, so no CertificateVerify
    /// follows (RFC 8446 4.4.2).
    sent_empty_certificate: bool,
    /// The CertificateRequest's signature_algorithms (RFC 8446 4.3.2), which
    /// the CertificateVerify scheme is chosen from.
    cr_signature_algorithms: Vec<u16>,
    /// Raw ClientHello (and, for a plain handshake, nothing else yet) captured so
    /// the transcript can be rebuilt under the negotiated hash. The TLS 1.3
    /// transcript hash is fixed by the cipher suite, which is unknown until
    /// ServerHello; the client hashes ClientHello first under an assumed SHA-256.
    /// If the server selects a SHA-384 suite we re-hash from these bytes.
    raw_transcript: Vec<u8>,
    /// The framed ClientHello as sent, so a repeated `send ClientHello` (a
    /// state-machine test) resends the identical bytes without adding them to
    /// the transcript; cleared by a HelloRetryRequest, whose retry is a new hello.
    last_client_hello_framed: Option<Vec<u8>>,
    /// The exact encoded Finished last sent. Repeating `send Finished` replays
    /// this message without advancing the transcript or key schedule again.
    last_finished_framed: Option<Vec<u8>>,
    /// T6: the transcript right after our Finished (the handshake is over from
    /// here), which a post-handshake authentication (RFC 8446 4.6.2) continues
    /// from; and the state of a post-handshake CertificateRequest being
    /// answered.
    post_client_finished_transcript: Option<TranscriptHash>,
    pha: Option<PhaState>,
    /// T6: the hello was a `raw "HEX"` replay whose key shares are not ours:
    /// the ServerHello is decoded and matched but no keys can follow.
    raw_hello_replay: bool,
    /// Whether the final encoded ClientHello carries the extension. This is
    /// deliberately distinct from cfg.use_early_data: negative tests may add
    /// the extension without a PSK, or remove it while still sending records.
    early_data_offered: bool,
    early_data_accepted: bool,
    /// Client handshake write keys are derived at ServerHello but an accepted
    /// EndOfEarlyData itself is still protected by the early write keys.
    pending_handshake_write_keys: Option<DirectionKeys>,
    /// A deliberately non-compliant ClientHello2 attempted to cross from an
    /// HRR into TLS 1.2 after CH1 offered a resumption PSK. If the peer answers
    /// with a TLS 1.2 ServerHello, the test driver follows the abbreviated
    /// handshake with an all-zero master secret. This reproduces the complete
    /// historical mbedTLS failure rather than stopping after the downgrade.
    tls12_zero_secret_resume_attempt: bool,
    tls12_zero_secret_resume_active: bool,
    tls12_zero_secret_pending_read_keys: Option<DirectionKeys>,
    tls12_zero_secret_server_random: [u8; 32],
    /// The non-resumption counterpart of the zero-secret probe above.  A peer
    /// which treats ClientHello2 as a fresh TLS 1.2 ClientHello sends the full
    /// Certificate / ServerKeyExchange flight.  Keep enough TLS 1.2 state here
    /// to complete that illegal cross-version handshake and prove application
    /// traffic works; stopping at ServerHello only proves version selection.
    tls12_fresh_downgrade_attempt: bool,
    tls12_fresh_downgrade_active: bool,
    tls12_fresh_server_random: [u8; 32],
    tls12_fresh_server_point: Option<Vec<u8>>,
    tls12_fresh_server_group: u16,
    tls12_fresh_master_secret: Vec<u8>,
    tls12_fresh_pending_write_keys: Option<DirectionKeys>,
    tls12_fresh_pending_read_keys: Option<DirectionKeys>,
}

impl Tls13Client {
    pub fn new(transport: Box<dyn UutTransport>, cfg: Tls13ClientConfig) -> Self {
        Self::new_protocol(transport, cfg, false)
    }

    pub fn new_dtls13(transport: Box<dyn UutTransport>, cfg: Tls13ClientConfig) -> Self {
        Self::new_protocol(transport, cfg, true)
    }

    fn new_protocol(
        transport: Box<dyn UutTransport>,
        cfg: Tls13ClientConfig,
        dtls13: bool,
    ) -> Self {
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
            client_random: [0; 32],
            ephemerals: Vec::new(),
            captures: Vec::new(),
            server_pubkey: None,
            negotiated_server_cert_type: crate::tls::codec::CERT_TYPE_X509,
            negotiated_client_cert_type: crate::tls::codec::CERT_TYPE_X509,
            negotiated_suite: 0,
            server_selected_psk: false,
            offered_suites: Vec::new(),
            client_session_id: Vec::new(),
            offered_signature_schemes: Vec::new(),
            offered_cert_signature_schemes: Vec::new(),
            hrr_cipher_suite: None,
            hrr_requested_group: None,
            hrr_cookie: None,
            hrr_client_hello_framed: None,
            hrr_framed: None,
            resumption_master_secret: None,
            captured_nst: None,
            nst_seen: 0,
            key_update_response_pending: false,
            server_app_read_keys_installed: false,
            post_server_finished_digest: Vec::new(),
            credential_selected: false,
            override_client_key: None,
            sent_empty_certificate: false,
            cr_signature_algorithms: Vec::new(),
            raw_transcript: Vec::new(),
            last_client_hello_framed: None,
            last_finished_framed: None,
            post_client_finished_transcript: None,
            pha: None,
            raw_hello_replay: false,
            early_data_offered: false,
            early_data_accepted: false,
            pending_handshake_write_keys: None,
            tls12_zero_secret_resume_attempt: false,
            tls12_zero_secret_resume_active: false,
            tls12_zero_secret_pending_read_keys: None,
            tls12_zero_secret_server_random: [0; 32],
            tls12_fresh_downgrade_attempt: false,
            tls12_fresh_downgrade_active: false,
            tls12_fresh_server_random: [0; 32],
            tls12_fresh_server_point: None,
            tls12_fresh_server_group: 0,
            tls12_fresh_master_secret: Vec::new(),
            tls12_fresh_pending_write_keys: None,
            tls12_fresh_pending_read_keys: None,
        }
    }

    fn ensure_init(&mut self) {
        if self.client_random != [0; 32] {
            return;
        }
        let mut cr_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"client_random"));
        self.client_random = cr_rng.random_array();
        // Generate ECDHE ephemeral unless pure psk_ke mode.
        let skip_ecdhe = matches!(&self.cfg.psk, Some(p) if p.ke_only);
        if !skip_ecdhe {
            let groups = self.cfg.key_share_groups.clone();
            self.generate_key_shares(&groups);
        }
        if self.cfg.psk.is_some() {
            let first = self.configured_psk_offers().into_iter().next().unwrap();
            let hash = first.hash;
            self.transcript = TranscriptHash::new(hash);
            self.schedule = if self.records.is_dtls13() {
                Tls13KeySchedule::with_psk_dtls(hash, &first.secret)
            } else {
                Tls13KeySchedule::with_psk(hash, &first.secret)
            };
        }
    }

    fn configured_psk_offers(&self) -> Vec<crate::ir::PskOfferConfig> {
        let Some(psk) = &self.cfg.psk else {
            return Vec::new();
        };
        if !psk.offers.is_empty() {
            return psk.offers.clone();
        }
        let hash = psk
            .cipher_suite
            .and_then(crate::ir::suite_info)
            .map(|suite| suite.prf)
            .unwrap_or(HashAlg::Sha256);
        vec![crate::ir::PskOfferConfig {
            identity: psk.identity.clone(),
            secret: psk.secret.clone(),
            hash,
            is_external: psk.is_external,
            obfuscated_ticket_age: psk.obfuscated_ticket_age,
        }]
    }

    fn patch_psk_binders(
        &self,
        encoded: &crate::tls::codec::EncodedBody,
        framed: &mut [u8],
        offers: &[crate::ir::PskOfferConfig],
        after_hrr: bool,
    ) -> Result<(), TlsError> {
        let first = encoded
            .field_range("psk_binder_0")
            .ok_or(TlsError::Internal("PSK binder has no encoded field range"))?;
        if first.start < 3 {
            return Err(TlsError::Internal("PSK binder field range is malformed"));
        }
        let truncated = framed[..4 + first.start - 3].to_vec();
        for (index, offer) in offers.iter().enumerate() {
            let name = format!("psk_binder_{}", index);
            let binder = encoded
                .field_range(&name)
                .ok_or(TlsError::Internal("PSK binder has no encoded field range"))?;
            if binder.len() != offer.hash.output_len() {
                return Err(TlsError::Internal("PSK binder field range is malformed"));
            }
            let mut transcript = TranscriptHash::new(offer.hash);
            if after_hrr {
                let ch1 = self
                    .hrr_client_hello_framed
                    .as_ref()
                    .ok_or(TlsError::Internal("retry PSK binder has no ClientHello1"))?;
                let hrr = self.hrr_framed.as_ref().ok_or(TlsError::Internal(
                    "retry PSK binder has no HelloRetryRequest",
                ))?;
                transcript.update(ch1);
                let ch1_hash = transcript.digest();
                crate::tls::handshake::replace_transcript_for_hrr(
                    &mut transcript,
                    &ch1_hash,
                    hrr,
                    offer.hash,
                );
            }
            transcript.update(&truncated);
            let schedule = if self.records.is_dtls13() {
                Tls13KeySchedule::with_psk_dtls(offer.hash, &offer.secret)
            } else {
                Tls13KeySchedule::with_psk(offer.hash, &offer.secret)
            };
            let value = schedule.compute_binder(&transcript.digest(), offer.is_external);
            let offset = 4 + binder.start;
            framed[offset..offset + binder.len()].copy_from_slice(&value);
        }
        Ok(())
    }

    /// (Re)generate the ECDHE ephemerals the ClientHello offers key shares for,
    /// one per listed group in offer order. Groups plzn has no key exchange for
    /// are skipped (lowering rejects them up front). The first share is drawn
    /// from the same sub-seed as the historical single x25519 share, so a
    /// default handshake's bytes are unchanged; later shares get their own.
    fn generate_key_shares(&mut self, groups: &[u16]) {
        self.ephemerals.clear();
        for (i, &wire) in groups.iter().enumerate() {
            let Some(group) = ecdhe_group_from_wire(wire) else {
                continue;
            };
            let label = if i == 0 {
                b"ecdh_private".to_vec()
            } else {
                format!("ecdh_private:{:04x}", wire).into_bytes()
            };
            let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, &label));
            self.ephemerals
                .push((wire, EcdhePrivate::generate(group, &mut ec_rng)));
        }
    }

    pub fn do_handshake(&mut self) -> Result<(), TlsError> {
        if self.cfg.psk.is_none() {
            for step in crate::ir::TLS13_CLIENT_PRESET {
                self.do_handshake_step(step)?;
            }
            return Ok(());
        }

        use crate::ir::{HandshakeStep as HS, MessageKind as MK};
        self.do_handshake_step(&HS::Send(MK::ClientHello))?;
        self.do_handshake_step(&HS::Recv(MK::ServerHello))?;
        self.do_handshake_step(&HS::Recv(MK::EncryptedExtensions))?;
        if !self.server_selected_psk {
            // RFC 8446 4.2.11: an unselected pre_shared_key is simply
            // ignored. Continue with the ordinary certificate flight.
            self.do_handshake_step(&HS::Recv(MK::Certificate))?;
            self.do_handshake_step(&HS::Recv(MK::CertificateVerify))?;
        }
        self.do_handshake_step(&HS::Recv(MK::Finished))?;
        if !self.server_selected_psk {
            self.do_handshake_step(&HS::Send(MK::ChangeCipherSpec))?;
        }
        self.do_handshake_step(&HS::Send(MK::Finished))?;
        Ok(())
    }

    pub fn do_handshake_step(&mut self, step: &crate::ir::HandshakeStep) -> Result<(), TlsError> {
        use crate::ir::{HandshakeStep as HS, MessageKind as MK};
        self.ensure_init();
        match step {
            HS::Send(MK::ClientHello) => {
                if self.hrr_requested_group.is_some() || self.hrr_cookie.is_some() {
                    self.send_client_hello_retry()
                } else {
                    self.send_client_hello()
                }
            }
            HS::Recv(MK::HelloRetryRequest) => self.recv_hello_retry_request(),
            HS::Recv(MK::ServerHello) => self.recv_server_hello(),
            HS::Recv(MK::EncryptedExtensions) => self.recv_encrypted_extensions(),
            HS::Recv(MK::Certificate) if self.tls12_fresh_downgrade_active => {
                self.recv_tls12_fresh_certificate()
            }
            HS::Recv(MK::ServerKeyExchange) if self.tls12_fresh_downgrade_active => {
                self.recv_tls12_fresh_server_key_exchange()
            }
            HS::Recv(MK::ServerHelloDone) if self.tls12_fresh_downgrade_active => {
                self.recv_tls12_fresh_server_hello_done()
            }
            // T6: after our Finished a CertificateRequest is a post-handshake
            // authentication request (RFC 8446 4.6.2), answered by the PHA
            // forms of Certificate / CertificateVerify / Finished.
            HS::Recv(MK::CertificateRequest) if self.post_client_finished_transcript.is_some() => {
                self.recv_post_handshake_certificate_request()
            }
            HS::Recv(MK::CertificateRequest) => self.recv_certificate_request(),
            HS::Recv(MK::Certificate) => self.recv_certificate_13(),
            HS::Recv(MK::CompressedCertificate) => self.recv_compressed_certificate_13(),
            HS::Recv(MK::CertificateVerify) => self.recv_certificate_verify(),
            HS::Recv(MK::NewSessionTicket) => self.recv_new_session_ticket(),
            HS::Recv(MK::ChangeCipherSpec) if self.tls12_zero_secret_resume_active => {
                self.recv_tls12_zero_secret_change_cipher_spec()
            }
            HS::Recv(MK::ChangeCipherSpec) if self.tls12_fresh_downgrade_active => {
                self.recv_tls12_fresh_change_cipher_spec()
            }
            HS::Recv(MK::Finished) if self.tls12_zero_secret_resume_active => {
                self.recv_tls12_zero_secret_finished()
            }
            HS::Recv(MK::Finished) if self.tls12_fresh_downgrade_active => {
                self.recv_tls12_fresh_finished()
            }
            HS::Recv(MK::Finished) => self.recv_server_finished(),
            HS::Send(MK::EndOfEarlyData) => self.send_end_of_early_data(),
            HS::Send(MK::Certificate) if self.pha.is_some() => self.send_pha_certificate(),
            HS::Send(MK::Certificate) => self.send_client_certificate(),
            HS::Send(MK::CompressedCertificate) => self.send_client_compressed_certificate(),
            HS::Send(MK::CertificateVerify) if self.pha.is_some() => {
                self.send_pha_certificate_verify()
            }
            HS::Send(MK::CertificateVerify) => self.send_client_certificate_verify(),
            HS::Send(MK::ClientKeyExchange) if self.tls12_fresh_downgrade_active => {
                self.send_tls12_fresh_client_key_exchange()
            }
            HS::Send(MK::ChangeCipherSpec) if self.tls12_zero_secret_resume_active => {
                self.send_tls12_zero_secret_change_cipher_spec()
            }
            HS::Send(MK::ChangeCipherSpec) if self.tls12_fresh_downgrade_active => {
                self.send_tls12_fresh_change_cipher_spec()
            }
            HS::Send(MK::ChangeCipherSpec) => self.send_change_cipher_spec(),
            HS::Send(MK::Finished) if self.pha.is_some() => self.send_pha_finished(),
            HS::Send(MK::Finished) if self.tls12_zero_secret_resume_active => {
                self.send_tls12_zero_secret_finished()
            }
            HS::Send(MK::Finished) if self.tls12_fresh_downgrade_active => {
                self.send_tls12_fresh_finished()
            }
            HS::Send(MK::Finished) => self.send_client_finished(),
            HS::Send(MK::Heartbeat) => self.send_heartbeat(),
            HS::Recv(MK::Heartbeat) => self.recv_heartbeat(),
            _ => Err(TlsError::Internal(
                "unsupported handshake step for TLS 1.3 client",
            )),
        }
    }

    pub fn write_app_data(&mut self, data: &[u8], mutations: &[Mutation]) -> Result<(), TlsError> {
        // RFC 8446 4.6.3: reciprocate an absorbed KeyUpdate(update_requested)
        // before the next application-data record.
        if self.key_update_response_pending {
            self.send_key_update(0)?;
            self.key_update_response_pending = false;
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

    pub fn write_early_data(
        &mut self,
        data: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        if !self.cfg.use_early_data {
            return Err(TlsError::Internal(
                "EarlyData requires a resumption ticket that advertised a nonzero allowance",
            ));
        }
        self.records.write_record_with_mutations(
            crate::tls::codec::CONTENT_TYPE_APP_DATA,
            data,
            mutations,
        )?;
        Ok(())
    }

    pub fn read_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        let data = loop {
            match self.records.read_app_data() {
                Ok(d) => break d,
                // A server-initiated KeyUpdate between application records
                // (e.g. Botan's records_per_traffic_key policy): rotate our
                // read keys and keep reading; reciprocate if asked.
                Err(RecordError::KeyUpdateReceived { framed }) => {
                    if framed.len() < 4 {
                        return Err(TlsError::Internal("truncated KeyUpdate"));
                    }
                    let request_update = decode_key_update_body(&framed[4..])?;
                    if request_update > 1 {
                        return Err(TlsError::Internal(
                            "KeyUpdate.request_update is not update_not_requested(0) or update_requested(1)",
                        ));
                    }
                    self.rotate_read_keys()?;
                    if request_update == 1 {
                        self.key_update_response_pending = true;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        };
        // A NewSessionTicket may arrive interleaved with (typically just before)
        // application data; the record layer swallows it and stashes it here.
        // Capture it so this session's state can drive a later resumption.
        while let Some(framed) = self.records.take_swallowed_nst() {
            if framed.len() > 4 {
                if let Ok(nst) = decode_new_session_ticket_13_body(&framed[4..]) {
                    self.captured_nst = Some(nst);
                }
            }
        }
        Ok(data)
    }

    /// Rotate the read keys to the next application traffic secret
    /// generation (RFC 8446 7.2), after a received KeyUpdate.
    fn rotate_read_keys(&mut self) -> Result<(), TlsError> {
        let server_ap = self
            .schedule
            .server_ap_traffic_secret
            .as_ref()
            .ok_or(TlsError::Internal("server ap traffic secret missing"))?;
        let new_secret = self.schedule.rotate_traffic_secret(server_ap);
        let aead = self.aead();
        let keys = self.schedule.direction_keys(&new_secret, aead)?;
        self.records.install_read_keys(keys)?;
        self.schedule.server_ap_traffic_secret = Some(new_secret);
        Ok(())
    }

    /// Read and capture a post-handshake NewSessionTicket.
    pub fn recv_new_session_ticket(&mut self) -> Result<(), TlsError> {
        let body = self.read_encrypted_handshake(HS_NEW_SESSION_TICKET)?;
        let nst = decode_new_session_ticket_13_body(&body)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::NewSessionTicket) {
            if let FieldValue::Capture(name) = &m.value {
                let value = capture_new_session_ticket_field(&nst, &m.field)?;
                self.captures.push((name.clone(), value));
            } else {
                match_new_session_ticket_field(&nst, m)?;
            }
        }
        self.nst_seen += 1;
        self.captured_nst = Some(nst);
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), TlsError> {
        self.records
            .close()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }

    /// Send a `[level, description]` alert record (encrypted under the installed
    /// application write keys), then close the transport.
    pub fn close_with_alert(&mut self, level: u8, code: u8) -> Result<(), TlsError> {
        self.records
            .write_record(crate::tls::codec::CONTENT_TYPE_ALERT, &[level, code])
            .map_err(TlsError::Record)?;
        self.records
            .close()
            .map_err(|e| TlsError::Record(RecordError::Io(e)))
    }

    pub fn negotiated_cipher_suite(&self) -> u16 {
        self.negotiated_suite
    }

    /// The record-protection AEAD for the negotiated TLS 1.3 suite.
    fn aead(&self) -> AeadAlg {
        crate::ir::suite_info(self.negotiated_suite)
            .and_then(|s| crate::tls::record::aead_alg_for(s.cipher))
            .unwrap_or(AeadAlg::Aes128Gcm)
    }

    /// The transcript-hash / key-schedule hash for the negotiated TLS 1.3 suite.
    fn suite_hash(&self) -> HashAlg {
        crate::ir::suite_info(self.negotiated_suite)
            .map(|s| s.prf)
            .unwrap_or(HashAlg::Sha256)
    }

    pub fn send_key_update(&mut self, request_update: u8) -> Result<(), TlsError> {
        self.send_key_update_with(request_update, &[])
    }

    /// `send KeyUpdate ... @ mutations`: body / header mutations apply before
    /// the record layer, record-level ones (`@ fragment N hold`, `record.*`)
    /// inside it -- so a held fragment goes out AFTER the key rotation below.
    pub fn send_key_update_with(
        &mut self,
        request_update: u8,
        mutations: &[Mutation],
    ) -> Result<(), TlsError> {
        let encoded = encode_key_update_body(request_update);
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, mutations)
            .map_err(|_| TlsError::Internal("KeyUpdate mutation failed"))?;
        let mut framed = encode_handshake(HS_KEY_UPDATE, &body);
        mutate::apply_handshake_header_mutations(&mut framed, mutations);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::KeyUpdate,
            &framed,
            mutations,
        )?;
        // Rotate write keys if application secrets are available.
        // If called before Finished (e.g., to test server rejection),
        // we skip rotation — the message was still sent.
        if let Some(ref secret) = self.schedule.client_ap_traffic_secret {
            let new_secret = self.schedule.rotate_traffic_secret(secret);
            let aead = self.aead();
            let keys = self.schedule.direction_keys(&new_secret, aead)?;
            self.records.install_key_update_write_keys(keys)?;
            self.schedule.client_ap_traffic_secret = Some(new_secret);
        }
        // An explicit KeyUpdate settles a pending reciprocation debt.
        self.key_update_response_pending = false;
        Ok(())
    }

    /// Replay the initial ClientHello as an encrypted post-handshake record.
    /// `raw_transcript` begins with the framed ClientHello, so we resend those
    /// exact (well-formed) bytes -- the server must reject them as a ClientHello
    /// received after the handshake (RFC 8446 4.1.2 forbids renegotiation).
    pub fn send_renegotiation(&mut self, msg_type: Option<u8>) -> Result<(), TlsError> {
        if self.raw_transcript.len() < 4 || self.raw_transcript[0] != HS_CLIENT_HELLO {
            return Err(TlsError::Internal(
                "no ClientHello at the head of the transcript to replay",
            ));
        }
        let body_len = u32::from_be_bytes([
            0,
            self.raw_transcript[1],
            self.raw_transcript[2],
            self.raw_transcript[3],
        ]) as usize;
        let ch_len = 4 + body_len;
        if self.raw_transcript.len() < ch_len {
            return Err(TlsError::Internal("truncated ClientHello in transcript"));
        }
        let mut ch_framed = self.raw_transcript[..ch_len].to_vec();
        // Optionally relabel the handshake type byte so an unexpected non-ClientHello
        // message can be injected post-handshake instead of a ClientHello.
        if let Some(t) = msg_type {
            ch_framed[0] = t;
        }
        // write_record encrypts under the installed application write key.
        self.records
            .write_record(CONTENT_TYPE_HANDSHAKE, &ch_framed)?;
        Ok(())
    }

    /// Middlebox-compatibility ChangeCipherSpec (RFC 8446 D.4): a real TLS 1.3 client
    /// sends a dummy 0x01 ChangeCipherSpec record; the server drops it. It is sent in
    /// plaintext and is NOT part of the handshake transcript. A `send ChangeCipherSpec
    /// { type: 0xNN }` override lets a test corrupt the byte (which the server must then
    /// reject, RFC 8446 5).
    fn send_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        let ccs_byte = resolve_ccs_byte(&self.cfg.send_overrides)?;
        self.records.write_record_with_mutations(
            CONTENT_TYPE_CCS,
            &[ccs_byte],
            collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
        )?;
        Ok(())
    }

    pub fn recv_key_update(&mut self) -> Result<(), TlsError> {
        let body = self.read_framed_handshake(HS_KEY_UPDATE)?;
        let request_update = decode_key_update_body(&body)?;
        // Rotate our read keys (RFC 8446 §4.6.3: "Upon receiving a
        // KeyUpdate, the receiver MUST update its receiving keys").
        let server_ap = self
            .schedule
            .server_ap_traffic_secret
            .as_ref()
            .ok_or(TlsError::Internal("server ap traffic secret missing"))?;
        let new_secret = self.schedule.rotate_traffic_secret(server_ap);
        let aead = self.aead();
        let keys = self.schedule.direction_keys(&new_secret, aead)?;
        self.records.install_read_keys(keys)?;
        self.schedule.server_ap_traffic_secret = Some(new_secret);
        // update_requested: answer with a KeyUpdate of our own before the next
        // application-data record (an explicit `send KeyUpdate` also settles it).
        if request_update == 1 {
            self.key_update_response_pending = true;
        }
        // `recv KeyUpdate { request_update: ... }` matcher.
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::KeyUpdate) {
            if let ("request_update", FieldValue::Ident(want)) = (m.field.as_str(), &m.value) {
                let want_v = match want.as_str() {
                    "update_not_requested" => 0,
                    "update_requested" => 1,
                    _ => 0xff,
                };
                if want_v != request_update {
                    return Err(TlsError::MatcherFailed {
                        message: "KeyUpdate",
                        field: "request_update".into(),
                        expected: want.clone(),
                        observed: match request_update {
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

    // ---- sub-steps ----

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        // A repeated `send ClientHello` before any HelloRetryRequest is a
        // state-machine test (RFC 8446 4.1.2 forbids a second hello); resend the
        // exact bytes and leave the transcript alone, as the peer (which must
        // reject the duplicate) keeps hashing the first hello only.
        if let Some(framed) = self.last_client_hello_framed.clone() {
            self.records.write_record_with_mutations(
                CONTENT_TYPE_HANDSHAKE,
                &framed,
                collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello),
            )?;
            return Ok(());
        }
        // T6: `send ClientHello raw "HEX"` replays a literal hello.
        if let Some(raw) = t6_raw_client_hello_body(&self.cfg.send_overrides) {
            return self.send_client_hello_raw(raw);
        }
        let mut extensions = vec![
            Extension::ServerName(self.cfg.server_name.clone()),
            Extension::SupportedGroups(self.cfg.groups.clone()),
            Extension::SignatureAlgorithms(self.cfg.signature_schemes.clone()),
            Extension::SupportedVersions(vec![if self.records.is_dtls13() {
                0xfefc
            } else {
                PROTOCOL_VERSION_TLS13
            }]),
        ];
        // `+ext key_share = [g, ...]` replaces the offered share set; the
        // ephemerals are regenerated so every share is real and completable.
        let delta_groups = key_share_groups_delta(collect_ext_deltas(
            &self.cfg.send_ext_deltas,
            MessageKind::ClientHello,
        ));
        if let Some(groups) = delta_groups {
            self.generate_key_shares(&groups);
        }
        // T1: an explicit entry list mixes real shares (named groups) with
        // verbatim `group : bytes` entries, in the listed order.
        let delta_entries = key_share_entries_delta(collect_ext_deltas(
            &self.cfg.send_ext_deltas,
            MessageKind::ClientHello,
        ));
        if let Some(specs) = delta_entries {
            let groups: Vec<u16> = specs
                .iter()
                .filter_map(|e| match e {
                    crate::ir::KeyShareEntrySpec::Generate(g) => Some(*g),
                    _ => None,
                })
                .collect();
            self.generate_key_shares(&groups);
            let recipe = key_share_point_recipe(collect_overrides(
                &self.cfg.send_overrides,
                MessageKind::ClientHello,
            ))?;
            let mut entries = Vec::with_capacity(specs.len());
            for spec in &specs {
                match spec {
                    crate::ir::KeyShareEntrySpec::Generate(g) => {
                        let eph = self
                            .ephemerals
                            .iter()
                            .find(|(w, _)| w == g)
                            .map(|(_, e)| e)
                            .ok_or(TlsError::Internal(
                                "key_share entry names a group with no ephemeral",
                            ))?;
                        entries.push(KeyShareEntry {
                            group: *g,
                            key_exchange: encode_key_share_point(eph, &recipe)?,
                        });
                    }
                    crate::ir::KeyShareEntrySpec::Raw { group, key } => {
                        entries.push(KeyShareEntry {
                            group: *group,
                            key_exchange: key.clone(),
                        });
                    }
                }
            }
            extensions.push(Extension::KeyShare(entries));
        } else if !self.ephemerals.is_empty() {
            // `send ClientHello { key_share_point: compressed | zero }` re-encodes
            // the public values while the private keys stay real.
            let recipe = key_share_point_recipe(collect_overrides(
                &self.cfg.send_overrides,
                MessageKind::ClientHello,
            ))?;
            let mut entries = Vec::with_capacity(self.ephemerals.len());
            for (group, eph) in &self.ephemerals {
                entries.push(KeyShareEntry {
                    group: *group,
                    key_exchange: encode_key_share_point(eph, &recipe)?,
                });
            }
            extensions.push(Extension::KeyShare(entries));
        }
        // Advertise psk_key_exchange_modes on the full handshake so the server
        // may issue a NewSessionTicket for later resumption (RFC 8446 4.2.9). The
        // PSK branch below supplies its own modes (possibly psk_ke) when resuming.
        if self.cfg.psk.is_none() && self.cfg.advertise_psk_modes {
            extensions.push(Extension::PskKeyExchangeModes(vec![
                crate::tls::codec::PSK_DHE_KE,
            ]));
        }
        // T6: the `compress_cert` capability: offer certificate compression (zlib).
        if self.cfg.offer_cert_compression {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_COMPRESS_CERTIFICATE,
                data: vec![0x02, 0x00, crate::tls::codec::CERT_COMPRESSION_ZLIB as u8],
            });
        }
        // Offer the server_certificate_type extension (RFC 7250): RawPublicKey then X509.
        if self.cfg.offer_raw_public_key {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE,
                data: crate::tls::codec::encode_cert_type_list(&[
                    crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    crate::tls::codec::CERT_TYPE_X509,
                ]),
            });
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE,
                data: crate::tls::codec::encode_cert_type_list(&[
                    crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    crate::tls::codec::CERT_TYPE_X509,
                ]),
            });
        }
        // PSK extensions must come last (pre_shared_key MUST be final).
        let psk_offers = self.configured_psk_offers();
        let has_binders = if let Some(psk) = &self.cfg.psk {
            let ke_modes = if psk.ke_only {
                vec![crate::tls::codec::PSK_KE]
            } else {
                vec![crate::tls::codec::PSK_DHE_KE, crate::tls::codec::PSK_KE]
            };
            extensions.push(Extension::PskKeyExchangeModes(ke_modes));
            if self.cfg.use_early_data {
                if psk.is_external || psk.max_early_data_size == 0 {
                    return Err(TlsError::Internal(
                        "EarlyData requires a resumption ticket with max_early_data_size > 0",
                    ));
                }
                extensions.push(Extension::Unknown {
                    ty: crate::tls::codec::EXT_EARLY_DATA,
                    data: Vec::new(),
                });
            }
            extensions.push(Extension::PreSharedKey {
                identities: psk_offers
                    .iter()
                    .map(|offer| PskIdentity {
                        identity: offer.identity.clone(),
                        obfuscated_ticket_age: offer.obfuscated_ticket_age,
                    })
                    .collect(),
                binder_lengths: psk_offers
                    .iter()
                    .map(|offer| offer.hash.output_len())
                    .collect(),
            });
            true
        } else {
            false
        };
        // Apply per-message extension deltas before encoding. The mapped
        // encoder records the binder's actual position after these operations,
        // so deliberately moving pre_shared_key away from the end remains a
        // well-formed (but RFC-invalid) encoding instead of corrupting whatever
        // extension happened to become last.
        let ext_deltas = collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ClientHello);
        apply_ext_deltas(&mut extensions, ext_deltas);
        self.early_data_offered = extensions
            .iter()
            .any(|ext| ext.wire_type() == crate::tls::codec::EXT_EARLY_DATA);
        let mut ch = ClientHello {
            legacy_version: if self.records.is_dtls13() {
                0xfefd
            } else {
                PROTOCOL_VERSION_TLS12
            },
            random: self.client_random,
            session_id: Vec::new(),
            cipher_suites: self.cfg.cipher_suites.clone(),
            compression_methods: vec![0],
            extensions,
        };
        let overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientHello).to_vec();
        for ov in &overrides {
            apply_client_hello_override(&mut ch, ov)?;
        }
        self.client_session_id = ch.session_id.clone();
        self.offered_suites = ch.cipher_suites.clone();
        self.offered_signature_schemes =
            hello_u16_vector(&ch.extensions, crate::tls::codec::EXT_SIGNATURE_ALGORITHMS)
                .unwrap_or_default();
        self.offered_cert_signature_schemes = hello_u16_vector(
            &ch.extensions,
            crate::tls::codec::EXT_SIGNATURE_ALGORITHMS_CERT,
        )
        .unwrap_or_else(|| self.offered_signature_schemes.clone());
        let encoded = encode_client_hello_body_mapped(&ch)?;
        let legacy_cookie = overrides
            .iter()
            .find_map(|ov| match (&*ov.field, &ov.value) {
                ("cookie", FieldValue::Bytes(value)) => Some(value.as_slice()),
                _ => None,
            });
        let encoded = if self.records.is_dtls13() {
            add_dtls_legacy_cookie_mapped(encoded, legacy_cookie.unwrap_or_default())?
        } else {
            encoded
        };
        let ch_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello);
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &encoded.bytes);

        // Patch PSK binders at the position recorded by the encoder. The binder
        // HMAC covers the truncated ClientHello through the identities vector,
        // excluding the u16 binders-vector length, u8 binder length and value.
        // RFC 8446 §4.2.11.2. In a conforming hello that is a suffix; keeping
        // the explicit position also lets tests encode the MUST-be-last error.
        // A `-ext pre_shared_key` delta leaves no binders to patch.
        if has_binders && encoded.field_range("psk_binder_0").is_some() {
            self.patch_psk_binders(&encoded, &mut framed, &psk_offers, false)?;
        }

        // Byte mutations apply to the FINAL encoding, after the binder patch, so
        // a mutation aimed at `handshake.psk_binder` corrupts
        // it instead of being overwritten by it. The field map still describes
        // the body: patching binders changes bytes, not offsets.
        let body = mutate::apply_handshake_mutations(framed[4..].to_vec(), &encoded, ch_muts)
            .map_err(|_| TlsError::Internal("ClientHello mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &body);

        // Corrupt the handshake header (msg_type/length) if requested (BoGo
        // WrongMessageType). Applied after binder patching; wrong-type tests do
        // not combine with PSK.
        mutate::apply_handshake_header_mutations(&mut framed, ch_muts);

        self.transcript.update(&framed);
        self.raw_transcript.extend_from_slice(&framed);
        self.last_client_hello_framed = Some(framed.clone());
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::ClientHello,
            &framed,
            ch_muts,
        )?;
        if !self.records.is_dtls13() {
            self.records.set_tls13_ccs_allowed(true);
        }
        if self.cfg.use_early_data {
            let psk = self
                .cfg
                .psk
                .as_ref()
                .ok_or(TlsError::Internal("early_data offered without a PSK"))?;
            let suite = psk
                .cipher_suite
                .ok_or(TlsError::Internal("resumption ticket has no cipher suite"))?;
            let aead = crate::ir::suite_info(suite)
                .and_then(|s| crate::tls::record::aead_alg_for(s.cipher))
                .ok_or(TlsError::Internal(
                    "ticket uses an unsupported early-data AEAD",
                ))?;
            let secret = self.schedule.client_early_traffic_secret(&self.transcript);
            let keys = self.schedule.direction_keys(&secret, aead)?;
            self.records.install_write_keys(keys)?;
        }
        Ok(())
    }

    /// Receive a HelloRetryRequest (same wire type as ServerHello,
    /// distinguished by the magic random). Extract the requested
    /// key share group and optional cookie, then replace the
    /// transcript per RFC 8446 §4.4.1.
    fn recv_hello_retry_request(&mut self) -> Result<(), TlsError> {
        let ch1_framed = self
            .last_client_hello_framed
            .clone()
            .ok_or(TlsError::Internal(
                "HelloRetryRequest arrived before ClientHello",
            ))?;
        // The retry hello is a new message; a later `send ClientHello` is not a duplicate of CH1.
        self.last_client_hello_framed = None;

        let hrr_body = self.read_plaintext_handshake(HS_SERVER_HELLO)?;
        let hrr = decode_server_hello_body(&hrr_body)?;

        // Verify this is actually an HRR (magic random).
        // A real ServerHello where the flow expects an HRR is the peer
        // choosing not to retry (e.g. accepting an offered share), which a
        // test may expect of one backend; report it as a failed expectation.
        if hrr.random != crate::tls::codec::HRR_RANDOM {
            return Err(TlsError::MatcherFailed {
                message: "HelloRetryRequest",
                field: "random".into(),
                expected: "the HelloRetryRequest magic random".into(),
                observed: "a real ServerHello (no retry)".into(),
            });
        }
        if hrr.session_id != self.client_session_id {
            return Err(TlsError::Rejected {
                alert: 47,
                reason: "HelloRetryRequest did not echo ClientHello legacy_session_id".into(),
            });
        }
        // T1: `recv HelloRetryRequest { has_ext / lacks_ext / key_share_group /
        // cipher_suite ... }` matchers (an HRR is a ServerHello on the wire).
        let hrr_matchers =
            collect_overrides(&self.cfg.recv_matchers, MessageKind::HelloRetryRequest).to_vec();
        for m in &hrr_matchers {
            if let FieldValue::Capture(name) = &m.value {
                let v = capture_server_hello_field(&hrr, &m.field)?;
                self.captures.push((name.clone(), v));
                continue;
            }
            match_hello_retry_request_field(&hrr, m)?;
        }
        self.negotiated_suite = hrr.cipher_suite;
        self.hrr_cipher_suite = Some(hrr.cipher_suite);

        // Extract the requested group from key_share extension.
        for ext in &hrr.extensions {
            match ext {
                Extension::KeyShare(entries) => {
                    if let Some(e) = entries.first() {
                        self.hrr_requested_group = Some(e.group);
                    }
                }
                Extension::Unknown { ty, data } if *ty == crate::tls::codec::EXT_COOKIE => {
                    // Cookie: u16-length-prefixed cookie value inside
                    // the extension body. We store the raw extension
                    // body to echo it back.
                    self.hrr_cookie = Some(data.clone());
                }
                _ => {}
            }
        }
        if self.hrr_requested_group.is_none() && self.hrr_cookie.is_none() {
            return Err(TlsError::Rejected {
                alert: 47,
                reason: "HelloRetryRequest requested no change".into(),
            });
        }

        // HRR rejects 0-RTT. ClientHello2 is sent in plaintext and MUST omit
        // early_data (RFC 8446 4.2.10), so discard the early write epoch before
        // the retry is encoded.
        if self.cfg.use_early_data {
            self.records.clear_write_keys();
            self.early_data_offered = false;
            self.early_data_accepted = false;
        }

        // Replace the transcript: synthetic(CH1) || HRR.
        // The framed HRR bytes are already in the transcript from
        // read_plaintext_handshake, so we need the raw framed bytes.
        // We reconstruct them from the body.
        let hrr_framed = encode_handshake(HS_SERVER_HELLO, &hrr_body);
        let hrr_hash = crate::ir::suite_info(hrr.cipher_suite)
            .filter(|suite| suite.version == TlsVersion::Tls13)
            .map(|suite| suite.prf)
            .ok_or(TlsError::ServerChoseUnsupportedSuite(hrr.cipher_suite))?;
        let mut ch1_transcript = TranscriptHash::new(hrr_hash);
        ch1_transcript.update(&ch1_framed);
        let ch1_hash = ch1_transcript.digest();
        crate::tls::handshake::replace_transcript_for_hrr(
            &mut self.transcript,
            &ch1_hash,
            &hrr_framed,
            hrr_hash,
        );
        self.hrr_client_hello_framed = Some(ch1_framed);
        self.hrr_framed = Some(hrr_framed);
        Ok(())
    }

    /// Send a second ClientHello after HRR. Uses the group the
    /// server requested and echoes any cookie.
    fn send_client_hello_retry(&mut self) -> Result<(), TlsError> {
        let new_ephemeral = if let Some(requested_group) = self.hrr_requested_group {
            let group = ecdhe_group_from_wire(requested_group)
                .ok_or(TlsError::ServerChoseUnsupportedGroup(requested_group))?;
            let mut ec_rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"ecdh_retry"));
            Some((requested_group, EcdhePrivate::generate(group, &mut ec_rng)))
        } else {
            None
        };
        let shares = if let Some((group, key)) = &new_ephemeral {
            vec![KeyShareEntry {
                group: *group,
                key_exchange: key.public_bytes(),
            }]
        } else {
            self.ephemerals
                .iter()
                .map(|(group, key)| KeyShareEntry {
                    group: *group,
                    key_exchange: key.public_bytes(),
                })
                .collect()
        };

        let mut extensions = vec![
            Extension::ServerName(self.cfg.server_name.clone()),
            Extension::SupportedGroups(self.cfg.groups.clone()),
            Extension::SignatureAlgorithms(self.cfg.signature_schemes.clone()),
            Extension::SupportedVersions(vec![if self.records.is_dtls13() {
                0xfefc
            } else {
                PROTOCOL_VERSION_TLS13
            }]),
            Extension::KeyShare(shares),
        ];
        // Retain psk_key_exchange_modes across the retry: RFC 8446 4.1.2 requires
        // CH2 to keep the extensions from CH1 that were not explicitly changed.
        if self.cfg.psk.is_none() && self.cfg.advertise_psk_modes {
            extensions.push(Extension::PskKeyExchangeModes(vec![
                crate::tls::codec::PSK_DHE_KE,
            ]));
        }
        if self.cfg.offer_cert_compression {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_COMPRESS_CERTIFICATE,
                data: vec![0x02, 0x00, crate::tls::codec::CERT_COMPRESSION_ZLIB as u8],
            });
        }
        // Offer the server_certificate_type extension (RFC 7250): RawPublicKey then X509.
        if self.cfg.offer_raw_public_key {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE,
                data: crate::tls::codec::encode_cert_type_list(&[
                    crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    crate::tls::codec::CERT_TYPE_X509,
                ]),
            });
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE,
                data: crate::tls::codec::encode_cert_type_list(&[
                    crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    crate::tls::codec::CERT_TYPE_X509,
                ]),
            });
        }
        // Echo cookie if HRR included one.
        if let Some(ref cookie) = self.hrr_cookie {
            extensions.push(Extension::Unknown {
                ty: crate::tls::codec::EXT_COOKIE,
                data: cookie.clone(),
            });
        }
        let psk_offers = self.configured_psk_offers();
        let has_binders = if let Some(psk) = &self.cfg.psk {
            let ke_modes = if psk.ke_only {
                vec![crate::tls::codec::PSK_KE]
            } else {
                vec![crate::tls::codec::PSK_DHE_KE, crate::tls::codec::PSK_KE]
            };
            extensions.push(Extension::PskKeyExchangeModes(ke_modes));
            extensions.push(Extension::PreSharedKey {
                identities: psk_offers
                    .iter()
                    .map(|offer| PskIdentity {
                        identity: offer.identity.clone(),
                        obfuscated_ticket_age: offer.obfuscated_ticket_age,
                    })
                    .collect(),
                binder_lengths: psk_offers
                    .iter()
                    .map(|offer| offer.hash.output_len())
                    .collect(),
            });
            true
        } else {
            false
        };
        // T1: RFC 8446 4.1.2 -- the retry MUST be the same ClientHello except
        // for key_share (the HRR's group), cookie, pre_shared_key and removed
        // early_data / padding, so CH1's extension deltas apply again here,
        // minus anything that touched key_share (Botan checks this and answers
        // illegal_parameter "Extension content changed in updated Client Hello"
        // when a delta is dropped).
        let ch1_deltas: Vec<ExtDeltaOp> =
            collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ClientHello)
                .iter()
                .filter(|d| {
                    self.hrr_requested_group.is_none()
                        || !matches!(
                            d,
                            ExtDeltaOp::KeyShareGroups(_)
                                | ExtDeltaOp::KeyShareEntries(_)
                                | ExtDeltaOp::Add {
                                    wire_type: 0x0033,
                                    ..
                                }
                                | ExtDeltaOp::Remove { wire_type: 0x0033 }
                        )
                })
                .cloned()
                .collect();
        apply_ext_deltas(&mut extensions, &ch1_deltas);

        // CH1's deltas are NOT replayed: the retry ClientHello reflects the
        // HRR's corrections. A `send ClientHello { ... }` written AFTER `recv
        // HelloRetryRequest` binds to `MessageKind::ClientHelloRetry` (T2) and
        // shapes this hello alone.
        let retry_deltas =
            collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::ClientHelloRetry);
        apply_ext_deltas(&mut extensions, retry_deltas);

        // RFC 8446 4.1.4: the retry carries a single share for the requested group.
        if let Some(ephemeral) = new_ephemeral {
            self.ephemerals = vec![ephemeral];
        }

        let mut ch = ClientHello {
            legacy_version: if self.records.is_dtls13() {
                0xfefd
            } else {
                PROTOCOL_VERSION_TLS12
            },
            random: self.client_random,
            session_id: self.client_session_id.clone(),
            cipher_suites: self.cfg.cipher_suites.clone(),
            compression_methods: vec![0],
            extensions,
        };
        let retry_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::ClientHelloRetry).to_vec();
        for ov in &retry_overrides {
            apply_client_hello_override(&mut ch, ov)?;
        }
        self.offered_suites = ch.cipher_suites.clone();
        let tls12_after_hrr = !self.records.is_dtls13()
            && ch.cipher_suites.iter().all(|wire| {
                crate::ir::suite_info(*wire).is_some_and(|s| s.version == TlsVersion::Tls12)
            })
            && !ch.extensions.iter().any(|ext| {
                matches!(ext, Extension::SupportedVersions(versions) if versions.contains(&PROTOCOL_VERSION_TLS13))
            });
        self.tls12_zero_secret_resume_attempt =
            self.cfg.psk.is_some() && !ch.session_id.is_empty() && tls12_after_hrr;
        // A fresh handshake normally has an empty legacy session id.  The
        // resumption probe above deliberately supplies one, so use the PSK
        // state rather than the id alone to distinguish the two continuations.
        self.tls12_fresh_downgrade_attempt = self.cfg.psk.is_none() && tls12_after_hrr;
        let encoded = encode_client_hello_body_mapped(&ch)?;
        let legacy_cookie = retry_overrides
            .iter()
            .find_map(|ov| match (&*ov.field, &ov.value) {
                ("cookie", FieldValue::Bytes(value)) => Some(value.as_slice()),
                _ => None,
            });
        let encoded = if self.records.is_dtls13() {
            add_dtls_legacy_cookie_mapped(encoded, legacy_cookie.unwrap_or_default())?
        } else {
            encoded
        };
        let has_retry_wire_override = self
            .cfg
            .send_mutations
            .iter()
            .any(|entry| entry.message == MessageKind::ClientHelloRetry);
        let retry_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHelloRetry);
        let ch_muts = if retry_muts.is_empty() {
            collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello)
        } else {
            retry_muts
        };
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &encoded.bytes);
        // A `-ext pre_shared_key` delta leaves no binders to patch
        if has_binders && encoded.field_range("psk_binder_0").is_some() {
            self.patch_psk_binders(&encoded, &mut framed, &psk_offers, true)?;
        }
        let body = mutate::apply_handshake_mutations(framed[4..].to_vec(), &encoded, ch_muts)
            .map_err(|_| TlsError::Internal("ClientHello2 mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &body);
        mutate::apply_handshake_header_mutations(&mut framed, ch_muts);
        self.transcript.update(&framed);
        // A DTLS fragmentation scheme is stored beside the byte mutations and
        // may leave `retry_muts` empty. Select ClientHelloRetry whenever either
        // form of wire override was attached to the explicit second hello.
        let retry_kind = if has_retry_wire_override {
            MessageKind::ClientHelloRetry
        } else {
            MessageKind::ClientHello
        };
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            retry_kind,
            &framed,
            ch_muts,
        )?;
        Ok(())
    }

    fn recv_server_hello(&mut self) -> Result<(), TlsError> {
        // ServerHello is still a plaintext handshake record.
        let sh_body = self.read_plaintext_handshake(HS_SERVER_HELLO)?;
        let sh = decode_server_hello_body(&sh_body)?;
        if sh.random == crate::tls::codec::HRR_RANDOM {
            return Err(TlsError::MatcherFailed {
                message: "ServerHello",
                field: "random".to_string(),
                expected: "a final ServerHello".to_string(),
                observed: "HelloRetryRequest".to_string(),
            });
        }
        // Matchers apply before the driver-internal cipher-suite
        // check, same reason as the TLS 1.2 path.
        let matchers =
            collect_overrides(&self.cfg.recv_matchers, MessageKind::ServerHello).to_vec();
        for m in &matchers {
            if let FieldValue::Capture(name) = &m.value {
                let v = capture_server_hello_field(&sh, &m.field)?;
                self.captures.push((name.clone(), v));
                continue;
            }
            match_server_hello_field(&sh, m)?;
        }
        self.negotiated_suite = sh.cipher_suite;
        if self.tls12_zero_secret_resume_attempt
            && crate::ir::suite_info(sh.cipher_suite)
                .is_some_and(|s| s.version == TlsVersion::Tls12)
        {
            return self.activate_tls12_zero_secret_resume(&sh);
        }
        if self.tls12_fresh_downgrade_attempt
            && crate::ir::suite_info(sh.cipher_suite)
                .is_some_and(|s| s.version == TlsVersion::Tls12)
        {
            return self.activate_tls12_fresh_downgrade(&sh);
        }
        validate_tls13_hrr_cipher_suite(self.hrr_cipher_suite, sh.cipher_suite)?;
        if crate::ir::suite_info(sh.cipher_suite).is_none_or(|s| s.version != TlsVersion::Tls13) {
            return Err(TlsError::ServerChoseUnsupportedSuite(sh.cipher_suite));
        }
        if sh.session_id != self.client_session_id {
            return Err(TlsError::Rejected {
                alert: 47,
                reason: "ServerHello did not echo ClientHello legacy_session_id".into(),
            });
        }
        // RFC 8446 4.1.3: the server's cipher_suite is "the single cipher suite
        // selected by the server from the list in ClientHello.cipher_suites".
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::ServerChoseUnofferedSuite(sh.cipher_suite));
        }
        // T6: a `raw "HEX"` hello replay carries key shares that are not
        // plzn's; the ServerHello has been checked and nothing can follow.
        if self.raw_hello_replay {
            return Ok(());
        }
        // The transcript hash and key schedule are fixed by the negotiated suite,
        // but the client provisionally built them as SHA-256 before the suite was
        // known. If the server picked a SHA-384 suite, rebuild both under SHA-384
        // from the raw transcript captured so far (ClientHello + ServerHello). The
        // schedule has not been advanced yet (non-PSK), so recreating it is safe;
        // SHA-384 suites are never offered alongside a PSK.
        let suite_hash = self.suite_hash();
        if suite_hash != self.transcript.alg() {
            let mut rebuilt = TranscriptHash::new(suite_hash);
            rebuilt.update(&self.raw_transcript);
            self.transcript = rebuilt;
            self.schedule = if self.records.is_dtls13() {
                Tls13KeySchedule::new_dtls(suite_hash)
            } else {
                Tls13KeySchedule::new(suite_hash)
            };
        }
        // Derive the (EC)DHE shared secret, or use zeros when the server chose
        // psk_ke. A client that offers both modes cannot infer the selection
        // from its own preference: RFC 8446 represents it by the presence
        // (psk_dhe_ke) or absence (psk_ke) of ServerHello.key_share. GnuTLS
        // legitimately selects psk_ke even when psk_dhe_ke was listed first.
        let mut selected_psk_index = None;
        for ext in &sh.extensions {
            if let Extension::Unknown { ty, data } = ext {
                if *ty != crate::tls::codec::EXT_PRE_SHARED_KEY {
                    continue;
                }
                if data.len() != 2 {
                    return Err(TlsError::Rejected {
                        alert: 50,
                        reason: "ServerHello pre_shared_key selection is not a uint16".into(),
                    });
                }
                selected_psk_index = Some(u16::from_be_bytes([data[0], data[1]]) as usize);
            }
        }
        let psk_offers = self.configured_psk_offers();
        if let Some(index) = selected_psk_index {
            let Some(offer) = psk_offers.get(index) else {
                return Err(TlsError::Rejected {
                    alert: 47,
                    reason: format!(
                        "server selected PSK identity {} but only {} identities were offered",
                        index,
                        psk_offers.len()
                    ),
                });
            };
            if offer.hash != suite_hash {
                return Err(TlsError::Rejected {
                    alert: 47,
                    reason:
                        "server selected a cipher suite with a different hash than the selected PSK"
                            .into(),
                });
            }
        }
        let selected_psk = selected_psk_index.is_some();
        self.server_selected_psk = selected_psk;
        let mut server_key_share: Option<(u16, Vec<u8>)> = None;
        for ext in &sh.extensions {
            if let Extension::KeyShare(entries) = ext {
                if let Some(e) = entries.first() {
                    server_key_share = Some((e.group, e.key_exchange.clone()));
                }
            }
        }
        let is_psk_ke = self.cfg.psk.is_some() && selected_psk && server_key_share.is_none();
        // The ClientHello binders use one provisional schedule per identity.
        // Now that ServerHello names the selected identity, install precisely
        // that PSK; a declined offer continues with an all-zero early secret.
        self.schedule = if let Some(index) = selected_psk_index {
            let offer = &psk_offers[index];
            if self.records.is_dtls13() {
                Tls13KeySchedule::with_psk_dtls(suite_hash, &offer.secret)
            } else {
                Tls13KeySchedule::with_psk(suite_hash, &offer.secret)
            }
        } else if self.records.is_dtls13() {
            Tls13KeySchedule::new_dtls(suite_hash)
        } else {
            Tls13KeySchedule::new(suite_hash)
        };
        let shared = if is_psk_ke {
            // PSK-only (psk_ke): no ECDHE, the (EC)DHE input is Hash.length
            // zero bytes (RFC 8446 7.1).
            vec![0u8; suite_hash.output_len()]
        } else {
            // ECDHE or PSK-DHE: extract the server's key_share.
            let (group, peer_public) =
                server_key_share.ok_or(TlsError::Internal("server omitted key_share"))?;
            // The server must answer one of the key shares we offered (RFC 8446
            // 4.2.8); the matching ephemeral carries its own curve, so agree()
            // validates the peer point against the right group.
            let idx = self
                .ephemerals
                .iter()
                .position(|(g, _)| *g == group)
                .ok_or(TlsError::ServerChoseUnsharedGroup(group))?;
            let (_, ephemeral) = self.ephemerals.remove(idx);
            ephemeral.agree(&peer_public)?
        };

        // Advance the schedule and install handshake traffic keys.
        self.schedule
            .advance_to_handshake(&shared, &self.transcript);
        let aead = self.aead();
        let client_hs = self
            .schedule
            .client_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client hs traffic secret missing"))?;
        let server_hs = self
            .schedule
            .server_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server hs traffic secret missing"))?;
        let client_hs_keys = self.schedule.direction_keys(&client_hs, aead)?;
        if self.cfg.use_early_data {
            self.pending_handshake_write_keys = Some(client_hs_keys);
        } else {
            self.records.install_write_keys(client_hs_keys)?;
        }
        let server_hs_keys = self.schedule.direction_keys(&server_hs, aead)?;
        self.records.install_read_keys(server_hs_keys)?;
        Ok(())
    }

    /// Follow the exact bad state reached by the historical mbedTLS server:
    /// after HRR it answers ClientHello2 with an abbreviated TLS 1.2
    /// ServerHello and uses the freshly zero-initialized 48-byte master-secret
    /// buffer. Completing both Finished messages proves the peer made the same
    /// mistake; merely beginning a fresh full TLS 1.2 handshake does not.
    fn activate_tls12_zero_secret_resume(
        &mut self,
        sh: &crate::tls::codec::ServerHello,
    ) -> Result<(), TlsError> {
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::ServerChoseUnofferedSuite(sh.cipher_suite));
        }
        let suite = crate::ir::suite_info(sh.cipher_suite)
            .filter(|s| s.version == TlsVersion::Tls12)
            .ok_or(TlsError::ServerChoseUnsupportedSuite(sh.cipher_suite))?;
        if suite.prf != self.transcript.alg() {
            return Err(TlsError::Internal(
                "the HRR zero-secret resumption probe requires a TLS 1.2 suite with the HRR transcript hash",
            ));
        }

        self.tls12_zero_secret_server_random = sh.random;
        let master_secret = [0u8; 48];
        let (client_keys, server_keys) = crate::tls::handshake::tls12_direction_keys(
            suite,
            &master_secret,
            &self.tls12_zero_secret_server_random,
            &self.client_random,
            false,
        )?;
        self.records.switch_to_tls12()?;
        // As in an ordinary abbreviated TLS 1.2 handshake, write keys are
        // ready at ServerHello but read keys take effect only after peer CCS.
        self.records.install_write_keys(client_keys)?;
        self.tls12_zero_secret_pending_read_keys = Some(server_keys);
        self.tls12_zero_secret_resume_active = true;
        Ok(())
    }

    fn recv_tls12_zero_secret_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        self.records.read_change_cipher_spec()?;
        let keys = self
            .tls12_zero_secret_pending_read_keys
            .take()
            .ok_or(TlsError::Internal(
                "zero-secret TLS 1.2 resumption has no pending server keys",
            ))?;
        self.records.install_read_keys(keys)?;
        Ok(())
    }

    fn recv_tls12_zero_secret_finished(&mut self) -> Result<(), TlsError> {
        let transcript_digest = self.transcript.digest();
        let body = self.read_framed_handshake(HS_FINISHED)?;
        let got = decode_finished_body(&body)?;
        let expected = compute_verify_data(
            self.suite_hash(),
            &[0u8; 48],
            b"server finished",
            &transcript_digest,
        );
        if got != expected {
            return Err(TlsError::FinishedMismatch);
        }
        Ok(())
    }

    fn send_tls12_zero_secret_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        let ccs = resolve_ccs_byte(&self.cfg.send_overrides)?;
        self.records.write_record_with_mutations(
            CONTENT_TYPE_CCS,
            &[ccs],
            collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
        )?;
        Ok(())
    }

    fn send_tls12_zero_secret_finished(&mut self) -> Result<(), TlsError> {
        let mut verify_data = compute_verify_data(
            self.suite_hash(),
            &[0u8; 48],
            b"client finished",
            &self.transcript.digest(),
        );
        // `send Finished { verify_data }` and `@` mutations apply as on the
        // ordinary TLS 1.2 client Finished.
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::Finished) {
            apply_finished_override(&mut verify_data, ov)?;
        }
        let fin_encoded = encode_finished_body_mapped(&verify_data);
        let fin_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        let fin_body =
            mutate::apply_handshake_mutations(fin_encoded.bytes.clone(), &fin_encoded, fin_muts)
                .map_err(|_| TlsError::Internal("Finished mutation failed"))?;
        let mut framed = encode_handshake(HS_FINISHED, &fin_body);
        mutate::apply_handshake_header_mutations(&mut framed, fin_muts);
        self.transcript.update(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, fin_muts)?;
        Ok(())
    }

    /// Follow a peer which discarded the TLS 1.3 HRR state and selected a
    /// fresh, full TLS 1.2 handshake from ClientHello2.  The transcript is not
    /// reset here: rustls 0.23.44 carries the TLS 1.3 message_hash + HRR into
    /// its TLS 1.2 state, so both sides authenticate that same unusual history.
    fn activate_tls12_fresh_downgrade(
        &mut self,
        sh: &crate::tls::codec::ServerHello,
    ) -> Result<(), TlsError> {
        if !self.offered_suites.contains(&sh.cipher_suite) {
            return Err(TlsError::ServerChoseUnofferedSuite(sh.cipher_suite));
        }
        let suite = crate::ir::suite_info(sh.cipher_suite)
            .filter(|s| s.version == TlsVersion::Tls12)
            .ok_or(TlsError::ServerChoseUnsupportedSuite(sh.cipher_suite))?;
        if suite.prf != self.transcript.alg() {
            return Err(TlsError::Internal(
                "the HRR-to-TLS-1.2 completion probe requires the same transcript hash on both suites",
            ));
        }
        if !matches!(
            suite.kex,
            crate::ir::KexType::EcdheRsa | crate::ir::KexType::EcdheEcdsa
        ) {
            return Err(TlsError::Internal(
                "the HRR-to-TLS-1.2 completion probe currently requires ECDHE",
            ));
        }

        self.tls12_fresh_server_random = sh.random;
        self.records.switch_to_tls12()?;
        self.tls12_fresh_downgrade_active = true;
        Ok(())
    }

    fn recv_tls12_fresh_certificate(&mut self) -> Result<(), TlsError> {
        let body = self.read_framed_handshake(HS_CERTIFICATE)?;
        let cert = decode_certificate_12_body(&body)?;
        let leaf = cert.entries.first().ok_or(TlsError::CertificateListEmpty)?;
        let key = PublicKey::from_certificate_der(leaf)?;
        validate_tls12_server_certificate_key(self.negotiated_suite, key.kind())?;
        self.server_pubkey = Some(key);
        Ok(())
    }

    fn recv_tls12_fresh_server_key_exchange(&mut self) -> Result<(), TlsError> {
        let body = self.read_framed_handshake(HS_SERVER_KEY_EXCHANGE)?;
        let ske = decode_ecdhe_server_key_exchange_body(&body)?;
        let group = ecdhe_group_from_wire(ske.named_curve)
            .filter(|g| !g.is_ffdhe() && !g.is_tls13_only())
            .ok_or(TlsError::ServerChoseUnsupportedGroup(ske.named_curve))?;
        let sig_scheme = SignatureScheme::from_wire_value(ske.sig_scheme)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(ske.sig_scheme))?;
        let mut signed = Vec::with_capacity(64 + ske.signed_params.len());
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&self.tls12_fresh_server_random);
        signed.extend_from_slice(&ske.signed_params);
        self.server_pubkey
            .as_ref()
            .ok_or(TlsError::Internal("server pubkey not set"))?
            .verify(sig_scheme, &signed, &ske.signature)
            .map_err(|_| TlsError::SignatureVerificationFailed)?;
        self.tls12_fresh_server_group = group.wire_value();
        self.tls12_fresh_server_point = Some(ske.public_point);
        Ok(())
    }

    fn recv_tls12_fresh_server_hello_done(&mut self) -> Result<(), TlsError> {
        let body = self.read_framed_handshake(HS_SERVER_HELLO_DONE)?;
        decode_server_hello_done_body(&body)?;
        Ok(())
    }

    fn send_tls12_fresh_client_key_exchange(&mut self) -> Result<(), TlsError> {
        let group = ecdhe_group_from_wire(self.tls12_fresh_server_group).ok_or(
            TlsError::ServerChoseUnsupportedGroup(self.tls12_fresh_server_group),
        )?;
        let mut rng = Rng::from_seed(Rng::sub_seed(self.cfg.seed, b"hrr_tls12_ecdh_private"));
        let ephemeral = EcdhePrivate::generate(group, &mut rng);
        let public = ephemeral.public_bytes();
        let peer = self
            .tls12_fresh_server_point
            .take()
            .ok_or(TlsError::Internal("missing server ECDHE point"))?;
        let premaster = ephemeral.agree(&peer)?;

        let encoded = encode_ecdhe_client_key_exchange_body_mapped(&public);
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientKeyExchange);
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|_| TlsError::Internal("CKE mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_KEY_EXCHANGE, &body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        self.transcript.update(&framed);
        self.raw_transcript.extend_from_slice(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, muts)?;

        self.tls12_fresh_master_secret = derive_master_secret(
            self.suite_hash(),
            &premaster,
            &self.client_random,
            &self.tls12_fresh_server_random,
        );
        let suite = crate::ir::suite_info(self.negotiated_suite)
            .ok_or(TlsError::ServerChoseUnsupportedSuite(self.negotiated_suite))?;
        let (client, server) = crate::tls::handshake::tls12_direction_keys(
            suite,
            &self.tls12_fresh_master_secret,
            &self.tls12_fresh_server_random,
            &self.client_random,
            false,
        )?;
        self.tls12_fresh_pending_write_keys = Some(client);
        self.tls12_fresh_pending_read_keys = Some(server);
        Ok(())
    }

    fn send_tls12_fresh_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        let ccs = resolve_ccs_byte(&self.cfg.send_overrides)?;
        self.records.write_record_with_mutations(
            CONTENT_TYPE_CCS,
            &[ccs],
            collect_mutations(&self.cfg.send_mutations, MessageKind::ChangeCipherSpec),
        )?;
        let keys = self
            .tls12_fresh_pending_write_keys
            .take()
            .ok_or(TlsError::Internal(
                "fresh TLS 1.2 downgrade has no write keys",
            ))?;
        self.records.install_write_keys(keys)?;
        Ok(())
    }

    fn send_tls12_fresh_finished(&mut self) -> Result<(), TlsError> {
        let mut verify_data = compute_verify_data(
            self.suite_hash(),
            &self.tls12_fresh_master_secret,
            b"client finished",
            &self.transcript.digest(),
        );
        // `send Finished { verify_data }` and `@` mutations apply as on the
        // ordinary TLS 1.2 client Finished.
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::Finished) {
            apply_finished_override(&mut verify_data, ov)?;
        }
        let fin_encoded = encode_finished_body_mapped(&verify_data);
        let fin_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        let fin_body =
            mutate::apply_handshake_mutations(fin_encoded.bytes.clone(), &fin_encoded, fin_muts)
                .map_err(|_| TlsError::Internal("Finished mutation failed"))?;
        let mut framed = encode_handshake(HS_FINISHED, &fin_body);
        mutate::apply_handshake_header_mutations(&mut framed, fin_muts);
        self.transcript.update(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, fin_muts)?;
        Ok(())
    }

    fn recv_tls12_fresh_change_cipher_spec(&mut self) -> Result<(), TlsError> {
        self.records.read_change_cipher_spec()?;
        let keys = self
            .tls12_fresh_pending_read_keys
            .take()
            .ok_or(TlsError::Internal(
                "fresh TLS 1.2 downgrade has no read keys",
            ))?;
        self.records.install_read_keys(keys)?;
        Ok(())
    }

    fn recv_tls12_fresh_finished(&mut self) -> Result<(), TlsError> {
        let before_finished = self.transcript.digest();
        let body = self.read_framed_handshake(HS_FINISHED)?;
        let got = decode_finished_body(&body)?;
        let expected = compute_verify_data(
            self.suite_hash(),
            &self.tls12_fresh_master_secret,
            b"server finished",
            &before_finished,
        );
        if got != expected {
            return Err(TlsError::FinishedMismatch);
        }
        Ok(())
    }

    fn recv_encrypted_extensions(&mut self) -> Result<(), TlsError> {
        let ee_body = self.read_encrypted_handshake(HS_ENCRYPTED_EXTENSIONS)?;
        let ee = decode_encrypted_extensions_body(&ee_body)?;
        self.early_data_accepted = ee
            .iter()
            .any(|ext| ext.wire_type() == crate::tls::codec::EXT_EARLY_DATA);
        if self.early_data_accepted && !self.early_data_offered {
            return Err(TlsError::Rejected {
                alert: 110,
                reason: "server accepted early_data that the client did not offer".into(),
            });
        }
        if self.cfg.use_early_data && !self.early_data_accepted {
            if let Some(keys) = self.pending_handshake_write_keys.take() {
                self.records.install_write_keys(keys)?;
            }
        }
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::EncryptedExtensions) {
            match_extension_list_field("EncryptedExtensions", &ee, m)?;
        }
        // Record the server's server_certificate_type selection (RFC 7250 §4.2); absent
        // means the server did not negotiate RPK, so X.509 is used.
        for ext in &ee {
            if ext.wire_type() == crate::tls::codec::EXT_SERVER_CERTIFICATE_TYPE {
                if let Extension::Unknown { data, .. } = ext {
                    self.negotiated_server_cert_type =
                        crate::tls::codec::decode_cert_type_selection(data)
                            .map_err(TlsError::Codec)?;
                }
            }
            if ext.wire_type() == crate::tls::codec::EXT_CLIENT_CERTIFICATE_TYPE {
                if let Extension::Unknown { data, .. } = ext {
                    self.negotiated_client_cert_type =
                        crate::tls::codec::decode_cert_type_selection(data)
                            .map_err(TlsError::Codec)?;
                }
            }
        }
        Ok(())
    }

    fn send_end_of_early_data(&mut self) -> Result<(), TlsError> {
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::EndOfEarlyData);
        let encoded = crate::tls::codec::EncodedBody {
            bytes: Vec::new(),
            fields: std::collections::HashMap::new(),
        };
        let body = mutate::apply_handshake_mutations(Vec::new(), &encoded, muts)
            .map_err(|_| TlsError::Internal("EndOfEarlyData mutation failed"))?;
        let mut framed = encode_handshake(HS_END_OF_EARLY_DATA, &body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        self.transcript.update(&framed);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::EndOfEarlyData,
            &framed,
            muts,
        )?;
        if let Some(keys) = self.pending_handshake_write_keys.take() {
            self.records.install_write_keys(keys)?;
        }
        Ok(())
    }

    fn recv_certificate_13(&mut self) -> Result<(), TlsError> {
        // Accept a Certificate (11) or a CompressedCertificate (25, RFC 8879). The framed
        // message (compressed form) is what feeds the transcript; we decompress only to
        // read the key.
        let (msg_type, raw) = self.read_framed_handshake_oneof(&[
            HS_CERTIFICATE,
            crate::tls::codec::HS_COMPRESSED_CERTIFICATE,
        ])?;
        // T6: `recv Certificate { compressed: 0 | 1 }` pins the wire form.
        t6_check_certificate_compressed(
            msg_type == crate::tls::codec::HS_COMPRESSED_CERTIFICATE,
            collect_overrides(&self.cfg.recv_matchers, MessageKind::Certificate),
        )?;
        let cert_body = if msg_type == crate::tls::codec::HS_COMPRESSED_CERTIFICATE {
            crate::tls::codec::decompress_certificate_13(&raw).map_err(TlsError::Codec)?
        } else {
            raw
        };
        let cert = decode_certificate_13_body(&cert_body)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::Certificate) {
            if m.field == "compressed" {
                continue;
            }
            match_certificate_13_field(&cert, m, self.negotiated_server_cert_type)?;
        }
        let leaf = cert.entries.first().ok_or(TlsError::CertificateListEmpty)?;
        if self.negotiated_server_cert_type == crate::tls::codec::CERT_TYPE_X509 {
            for entry in &cert.entries {
                let (scheme, self_issued) = crate::tls::crypto::certificate_signature_metadata(
                    &entry.cert_data,
                )
                .map_err(|err| TlsError::Rejected {
                    alert: 42, // bad_certificate
                    reason: err.to_string(),
                })?;
                if !self_issued
                    && !self
                        .offered_cert_signature_schemes
                        .contains(&scheme.wire_value())
                {
                    return Err(TlsError::Rejected {
                        alert: 42, // bad_certificate
                        reason: format!(
                            "server certificate uses signature scheme 0x{:04x}, which the ClientHello did not permit",
                            scheme.wire_value()
                        ),
                    });
                }
            }
        }
        // Decode the leaf per the negotiated certificate type (X.509 or RawPublicKey).
        self.server_pubkey = Some(PublicKey::from_certificate_entry(
            &leaf.cert_data,
            self.negotiated_server_cert_type,
        )?);
        Ok(())
    }

    fn recv_certificate_verify(&mut self) -> Result<(), TlsError> {
        // Snapshot the transcript *before* CertificateVerify hashes
        // in — that's the transcript hash the server signed.
        let transcript_for_sig = self.transcript.digest();

        let cv_body = self.read_encrypted_handshake(HS_CERTIFICATE_VERIFY)?;
        let cv = decode_certificate_verify_13_body(&cv_body)?;
        for matcher in collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateVerify) {
            match_certificate_verify_field(&cv, matcher)?;
        }
        // RFC 8446 4.4.3: a server CertificateVerify "signature algorithm MUST be one offered in
        // the client's 'signature_algorithms' extension". Reject a scheme we did not advertise --
        // this also makes signature_algorithms-driven server cert SELECTION verifiable.
        if !self.offered_signature_schemes.contains(&cv.algorithm) {
            return Err(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm));
        }
        let sig_scheme = SignatureScheme::from_wire_value(cv.algorithm)
            .ok_or(TlsError::ServerChoseUnsupportedSigScheme(cv.algorithm))?;
        let signed_input = tls13_certificate_verify_signed_input(&transcript_for_sig);
        let pk = self
            .server_pubkey
            .as_ref()
            .ok_or(TlsError::Internal("server pubkey not set"))?;
        pk.verify_tls13(sig_scheme, &signed_input, &cv.signature)
            .map_err(|_| TlsError::SignatureVerificationFailed)?;
        Ok(())
    }

    fn recv_server_finished(&mut self) -> Result<(), TlsError> {
        // Snapshot transcript before the Finished hashes in.
        let transcript_for_server_fin = self.transcript.digest();

        let fin_body = self.read_encrypted_handshake(HS_FINISHED)?;
        match_finished_fields(&fin_body, &self.cfg.recv_matchers)?;
        let server_hs = self
            .schedule
            .server_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server hs traffic secret missing"))?;
        let expected = self
            .schedule
            .compute_finished(&server_hs, &transcript_for_server_fin);
        if fin_body != expected {
            return Err(TlsError::FinishedMismatch);
        }
        // Snapshot the transcript through the server Finished; application traffic
        // secrets derive from exactly this point regardless of any later
        // client-auth Certificate/CertificateVerify.
        self.post_server_finished_digest = self.transcript.digest();
        // The server's application traffic keys are usable from its Finished on
        // (RFC 8446 7.1 derives them from the transcript through that message),
        // so derive both application secrets now and switch our READ side, which
        // lets half-RTT application data the server sends before our Finished
        // be read. The write side switches when our own Finished goes out.
        let digest = self.post_server_finished_digest.clone();
        self.schedule.advance_to_application_with_digest(&digest);
        let aead = self.aead();
        let server_ap = self
            .schedule
            .server_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server ap traffic secret missing"))?;
        let keys = self.schedule.direction_keys(&server_ap, aead)?;
        self.records.install_read_keys(keys)?;
        self.server_app_read_keys_installed = true;
        self.records.set_tls13_ccs_allowed(false);
        Ok(())
    }

    fn recv_certificate_request(&mut self) -> Result<(), TlsError> {
        let body = self.read_encrypted_handshake(HS_CERTIFICATE_REQUEST)?;
        let _context = decode_certificate_request_13_body(&body)?;
        let cr = crate::tls::codec::decode_certificate_request_13_full(&body)?;
        // RFC 8446 4.3.2: the schemes the server accepts in our CertificateVerify.
        self.cr_signature_algorithms = cr13_signature_algorithms(&cr.extensions);
        // A: several credentials (`client_chain:`): the first with a
        // CertificateVerify scheme the request listed (RFC 8446 4.4.2); none
        // fitting means an empty Certificate. A single credential is presented
        // as configured.
        if self.cfg.client_credentials.len() > 1 {
            let keys = crate::tls::chains::parse_chain_keys(&self.cfg.client_credentials)?;
            match crate::tls::chains::select_client_credential_13(
                &keys,
                &self.cr_signature_algorithms,
            ) {
                Some(i) => {
                    let c = &self.cfg.client_credentials[i];
                    self.cfg.client_cert_der = Some(c.cert_der.clone());
                    self.cfg.client_private_key_der = Some(c.key_der.clone());
                }
                None => {
                    self.cfg.client_cert_der = None;
                    self.cfg.client_private_key_der = None;
                }
            }
        }
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateRequest) {
            match_certificate_request_field(&cr, m)?;
        }
        // We don't inspect the CertificateRequest's extensions —
        // just acknowledge we received it. The subsequent
        // Send(Certificate) + Send(CertificateVerify) steps will
        // handle the response.
        Ok(())
    }

    fn send_client_certificate(&mut self) -> Result<(), TlsError> {
        // If we have a client cert, send it; otherwise send an empty
        // Certificate message (§4.4.2: "If the client does not have
        // an appropriate certificate, it MUST send ... a Certificate
        // message containing no certificates").
        // T3: `send Certificate { credential | certificate_list | entries }` as
        // on the TLS 1.2 client: a testdata credential by name (its key signs
        // the CertificateVerify), a composed list of names and `empty`
        // entries, raw list bytes, or the credential repeated N times.
        let cert_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::Certificate).to_vec();
        let wire_certificate_type = cert_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("certificate_type", FieldValue::Ident(name)) => Some(match name.as_str() {
                    "x509" => crate::tls::codec::CERT_TYPE_X509,
                    "raw_public_key" => crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
                    _ => unreachable!("certificate_type was validated while lowering"),
                }),
                _ => None,
            })
            .unwrap_or(self.negotiated_client_cert_type);
        // A: `credential: valid` is the first `client_chain:` entry when the
        // test named any; the other selector values are testdata credentials.
        let credential = crate::tls::chains::valid_credential_from(
            &cert_overrides,
            &self.cfg.client_credentials,
        )
        .or_else(|| crate::tls::dtls_kex::client_credential_override(&cert_overrides));
        let composed = cert_overrides
            .iter()
            .find_map(|ov| match (ov.field.as_str(), &ov.value) {
                ("certificate_list", FieldValue::IdentList(names)) => {
                    Some(compose_certificate_list(names))
                }
                _ => None,
            })
            .transpose()?;
        let selected_list: Option<Vec<Vec<u8>>> = match (&composed, &credential) {
            (Some((list, _)), _) => Some(list.clone()),
            (None, Some((l, _))) => Some(l.clone()),
            (None, None) => None,
        };
        if let Some((_, key)) = credential {
            self.credential_selected = true;
            self.override_client_key = key;
        }
        if let Some((_, key)) = &composed {
            self.credential_selected = true;
            self.override_client_key = key.clone();
        }
        // Present the client leaf followed by any configured intermediates so
        // the server can build a path to a trusted client-CA root.
        let mut chain: Vec<&[u8]> = match (&selected_list, &self.cfg.client_cert_der) {
            (Some(list), _) => list.iter().map(|c| c.as_slice()).collect(),
            (None, Some(der)) => {
                let mut chain: Vec<&[u8]> =
                    Vec::with_capacity(1 + self.cfg.client_extra_chain_der.len());
                chain.push(der.as_slice());
                for c in &self.cfg.client_extra_chain_der {
                    chain.push(c);
                }
                chain
            }
            (None, None) => Vec::new(),
        };
        let rpk_leaf = if wire_certificate_type == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
            chain
                .first()
                .map(|leaf| {
                    if leaf.is_empty() {
                        Ok(Vec::new())
                    } else {
                        crate::tls::crypto::certificate_spki_der(leaf)
                    }
                })
                .transpose()?
        } else {
            None
        };
        if let Some(rpk) = rpk_leaf.as_deref() {
            chain = vec![rpk];
        }
        let mut raw_list: Option<Vec<u8>> = None;
        for ov in &cert_overrides {
            match (ov.field.as_str(), &ov.value) {
                ("entries", FieldValue::U16(n)) => {
                    chain = chain
                        .first()
                        .map(|c| std::iter::repeat_n(*c, *n as usize).collect())
                        .unwrap_or_default();
                }
                ("certificate_list", FieldValue::Bytes(b)) => raw_list = Some(b.clone()),
                ("certificate_list", FieldValue::IdentList(_))
                | ("credential", _)
                | ("certificate_type", FieldValue::Ident(_)) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "Certificate",
                        field: ov.field.clone(),
                    });
                }
            }
        }
        self.sent_empty_certificate =
            chain.is_empty() && raw_list.as_ref().is_none_or(|l| l.is_empty());
        let encoded = match raw_list {
            Some(list) => {
                // request_context (empty) || u24 certificate_list
                let mut out = vec![0u8];
                out.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
                out.extend_from_slice(&list);
                let mut fields = std::collections::HashMap::new();
                fields.insert("request_context_length".to_string(), 0..1);
                fields.insert("certificate_list_length".to_string(), 1..4);
                fields.insert("certificate_list".to_string(), 4..out.len());
                crate::tls::codec::EncodedBody { bytes: out, fields }
            }
            None => {
                // `send Certificate { +ext ... }`: extensions on the client's leaf entry
                // (RFC 8446 4.4.2: they must answer the CertificateRequest's extensions).
                let mut leaf_extensions: Vec<Extension> = Vec::new();
                apply_ext_deltas(
                    &mut leaf_extensions,
                    collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::Certificate),
                );
                crate::tls::codec::encode_certificate_13_body_with_leaf_extensions_mapped(
                    &chain,
                    &leaf_extensions,
                )
            }
        };
        let cert_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate);
        let cert_body =
            mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cert_muts)
                .map_err(|_| TlsError::Internal("client Certificate mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE, &cert_body);
        mutate::apply_handshake_header_mutations(&mut framed, cert_muts);
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

    fn send_client_certificate_verify(&mut self) -> Result<(), TlsError> {
        // RFC 8446 4.4.2: no CertificateVerify after an empty Certificate.
        if self.sent_empty_certificate {
            return Ok(());
        }
        // A `credential` / composed `certificate_list` signs with the selected
        // key; otherwise the configured credential's key.
        let key_der: Vec<u8> = if self.credential_selected {
            match self.override_client_key.clone() {
                Some(k) => k,
                None => return Ok(()),
            }
        } else {
            match &self.cfg.client_private_key_der {
                Some(der) => der.clone(),
                // No client key → skip CertificateVerify (only valid
                // when we also sent an empty Certificate).
                None => return Ok(()),
            }
        };
        let pk = crate::tls::crypto::PrivateKey::from_pkcs8_der(&key_der)?;
        // RFC 8446 4.4.3: a scheme the CertificateRequest listed that this key
        // can use in TLS 1.3 (RSA keys: PSS only; an id-RSASSA-PSS key:
        // rsa_pss_pss_*; ECDSA: the key's own curve), in the server's order;
        // the key's default when the server listed nothing usable, so the
        // negative still signs.
        let tls13_schemes = pk.tls13_signing_schemes();
        let sig_scheme = self
            .cr_signature_algorithms
            .iter()
            .find_map(|w| {
                SignatureScheme::from_wire_value(*w).filter(|s| tls13_schemes.contains(s))
            })
            .unwrap_or(pk.default_signature_scheme());
        // Snapshot transcript before CertificateVerify hashes in.
        let transcript_hash = self.transcript.digest();
        let signed_input = tls13_client_certificate_verify_signed_input(&transcript_hash);
        // `send CertificateVerify { sign_with, algorithm, signature, salt_length,
        // mgf1_hash, format }` and `@ xor[signature.em, i]` shape the signature
        // (see `plan_certificate_verify`); the RFC 8446 4.4.3 MUST NOTs (PKCS#1
        // v1.5, a scheme the server did not list, a curve mismatch) are what
        // those probes provoke.
        let cv_muts_all =
            collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateVerify);
        let plan = plan_certificate_verify(
            &pk,
            sig_scheme,
            collect_overrides(&self.cfg.send_overrides, MessageKind::CertificateVerify),
            cv_muts_all,
            &signed_input,
            false,
        )?;
        let cv_muts_vec = without_em_mutations(cv_muts_all);
        let cv_muts = cv_muts_vec.as_slice();
        let encoded = crate::tls::codec::encode_certificate_verify_13_body_mapped(
            plan.label,
            &plan.signature,
        );
        // Apply any `send CertificateVerify @ ...` mutations so a server that fails
        // to verify the client's signature (broken client-auth) is caught.
        let cv_body =
            mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, cv_muts)
                .map_err(|_| TlsError::Internal("client CertificateVerify mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_VERIFY, &cv_body);
        mutate::apply_handshake_header_mutations(&mut framed, cv_muts);
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

    fn send_client_finished(&mut self) -> Result<(), TlsError> {
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

        // The transcript at this point covers everything through
        // the server's Finished — which is exactly the context for
        // both (a) computing our client Finished verify_data and
        // (b) deriving the application traffic secrets per RFC
        // 8446 §7.1. Application secrets derive from the transcript through the
        // SERVER's Finished (snapshotted in recv_server_finished); in client-auth
        // the live transcript now also includes our Certificate/CertificateVerify,
        // so we must use the snapshot, not the live transcript.
        // recv_server_finished already derived the application secrets (and
        // installed the server's read keys); only a flow that skipped it
        // derives them here, from the live transcript.
        if self.schedule.server_ap_traffic_secret.is_none() {
            if !self.post_server_finished_digest.is_empty() {
                let digest = self.post_server_finished_digest.clone();
                self.schedule.advance_to_application_with_digest(&digest);
            } else {
                self.schedule.advance_to_application(&self.transcript);
            }
        }

        // Client Finished: HMAC under client_handshake_traffic_secret
        // over the current transcript hash.
        let transcript_hash = self.transcript.digest();
        let client_hs = self
            .schedule
            .client_hs_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client hs traffic secret missing"))?;
        let mut verify_data = self.schedule.compute_finished(&client_hs, &transcript_hash);
        // Apply any `send Finished { verify_data: ... }` override.
        let fin_overrides =
            collect_overrides(&self.cfg.send_overrides, MessageKind::Finished).to_vec();
        for ov in &fin_overrides {
            apply_finished_override(&mut verify_data, ov)?;
        }
        let fin_encoded = encode_finished_body_mapped(&verify_data);
        let fin_body =
            mutate::apply_handshake_mutations(fin_encoded.bytes.clone(), &fin_encoded, fin_muts)
                .map_err(|_| TlsError::Internal("Finished mutation failed"))?;
        let mut fin_framed = encode_handshake(HS_FINISHED, &fin_body);
        // Corrupt the handshake header (msg_type/length) if requested
        // (BoGo WrongMessageType), applied to the framed message pre-encryption.
        mutate::apply_handshake_header_mutations(&mut fin_framed, fin_muts);
        self.last_finished_framed = Some(fin_framed.clone());
        // Hash post-mutation body into transcript.
        self.transcript.update(&fin_framed);
        // Send Finished UNDER THE HANDSHAKE KEYS. Pass mutations
        // for post-seal record-layer targets.
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::Finished,
            &fin_framed,
            fin_muts,
        )?;

        // Swap both directions to application traffic keys.
        let aead = self.aead();
        let client_ap = self
            .schedule
            .client_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client ap traffic secret missing"))?;
        let server_ap = self
            .schedule
            .server_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("server ap traffic secret missing"))?;
        let client_keys = self.schedule.direction_keys(&client_ap, aead)?;
        self.records.install_write_keys(client_keys)?;
        if !self.server_app_read_keys_installed {
            let server_keys = self.schedule.direction_keys(&server_ap, aead)?;
            self.records.install_read_keys(server_keys)?;
            self.server_app_read_keys_installed = true;
        }

        // Derive resumption_master_secret for session tickets.
        // The transcript now includes our Finished.
        self.resumption_master_secret = Some(
            self.schedule
                .derive_resumption_master_secret(&self.transcript),
        );
        // T6: a post-handshake authentication continues the transcript from here.
        self.post_client_finished_transcript = Some(self.transcript.clone());
        Ok(())
    }

    // ---- helpers ----

    /// Read a plaintext handshake message (for ServerHello, before
    /// keys are installed).
    fn read_plaintext_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        self.read_framed_handshake(expected_type)
    }

    /// Read one handshake message. The record layer transparently
    /// decrypts on TLS 1.3 once keys are installed, and silently
    /// swallows middlebox-compat CCS records.
    fn read_encrypted_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        self.read_framed_handshake(expected_type)
    }

    fn read_framed_handshake(&mut self, expected_type: u8) -> Result<Vec<u8>, TlsError> {
        let (_t, body) = self.read_framed_handshake_oneof(&[expected_type])?;
        Ok(body)
    }

    /// Like `read_framed_handshake` but accepts any of `accepted` and returns the actual
    /// message type. Used where the wire form may vary (e.g. Certificate vs
    /// CompressedCertificate, RFC 8879).
    fn read_framed_handshake_oneof(&mut self, accepted: &[u8]) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            let header = self.records.read_handshake_bytes(4)?;
            let mut cursor = ByteCursor::new(&header);
            let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
            let body = self.records.read_handshake_bytes(body_len)?;

            // Swallow post-handshake NewSessionTickets whenever we are waiting
            // for a different message (Finished, KeyUpdate, ...). A server may
            // send NSTs at any point post-handshake (RFC 8446 4.6.1); OpenSSL
            // does so before its KeyUpdate response. They are absorbed unless a
            // caller explicitly asked for one.
            if msg_type == HS_NEW_SESSION_TICKET && !accepted.contains(&HS_NEW_SESSION_TICKET) {
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&header);
                framed.extend_from_slice(&body);
                self.transcript.update(&framed);
                // Capture the ticket for resumption before discarding the frame.
                if let Ok(nst) = decode_new_session_ticket_13_body(&body) {
                    for m in
                        collect_overrides(&self.cfg.recv_matchers, MessageKind::NewSessionTicket)
                    {
                        if let FieldValue::Capture(name) = &m.value {
                            let value = capture_new_session_ticket_field(&nst, &m.field)?;
                            self.captures.push((name.clone(), value));
                        } else {
                            match_new_session_ticket_field(&nst, m)?;
                        }
                    }
                    self.nst_seen += 1;
                    self.captured_nst = Some(nst);
                }
                continue;
            }
            if !accepted.contains(&msg_type) {
                return Err(TlsError::UnexpectedHandshake {
                    expected: accepted[0],
                    got: msg_type,
                });
            }
            let mut framed = Vec::with_capacity(4 + body.len());
            framed.extend_from_slice(&header);
            framed.extend_from_slice(&body);
            self.transcript.update(&framed);
            self.raw_transcript.extend_from_slice(&framed);
            return Ok((msg_type, body));
        }
    }
}

pub(crate) fn match_certificate_verify_field(
    cv: &crate::tls::codec::CertificateVerify13,
    matcher: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (&*matcher.field, &matcher.value) {
        ("algorithm", FieldValue::U16(expected)) if cv.algorithm == *expected => Ok(()),
        ("algorithm", FieldValue::U16(expected)) => Err(TlsError::MatcherFailed {
            message: "CertificateVerify",
            field: matcher.field.clone(),
            expected: format!("0x{expected:04x}"),
            observed: format!("0x{:04x}", cv.algorithm),
        }),
        _ => Err(TlsError::UnknownFieldOverride {
            message: "CertificateVerify",
            field: matcher.field.clone(),
        }),
    }
}

// ============================================================
//                 override/matcher application
// ============================================================

/// Return the list of field overrides / matchers targeting a
/// specific message kind, or an empty slice if there are none.
pub(crate) fn collect_overrides(
    list: &[MessageOverrides],
    kind: MessageKind,
) -> &[crate::ir::FieldOverride] {
    for entry in list {
        if entry.message == kind {
            return &entry.fields;
        }
    }
    &[]
}

pub(crate) fn match_finished_fields(
    body: &[u8],
    matchers: &[MessageOverrides],
) -> Result<(), TlsError> {
    for matcher in collect_overrides(matchers, MessageKind::Finished) {
        match (matcher.field.as_str(), &matcher.value) {
            ("verify_data", FieldValue::Bytes(want)) if body == want => {}
            ("verify_data", FieldValue::Bytes(want)) => {
                return Err(TlsError::MatcherFailed {
                    message: "Finished",
                    field: matcher.field.clone(),
                    expected: format!("{want:02x?}"),
                    observed: format!("{body:02x?}"),
                });
            }
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Finished",
                    field: matcher.field.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Apply one field override to a ClientHello in-place.
fn apply_client_hello_override(
    ch: &mut ClientHello,
    ov: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (ov.field.as_str(), &ov.value) {
        ("legacy_version", FieldValue::U16(v)) => {
            ch.legacy_version = *v;
        }
        ("cipher_suites", FieldValue::U16List(v)) | ("ciphers", FieldValue::U16List(v)) => {
            ch.cipher_suites = v.clone();
        }
        ("legacy_compression_methods", FieldValue::U8List(v))
        | ("compression_methods", FieldValue::U8List(v)) => {
            ch.compression_methods = v.clone();
        }
        ("legacy_session_id", FieldValue::Bytes(v)) => {
            ch.session_id = v.clone();
        }
        // DTLS 1.3's legacy cookie sits outside the TLS ClientHello structure;
        // the mapped DTLS encoder inserts it after all ordinary overrides run.
        ("cookie", FieldValue::Bytes(_)) => {}
        ("random", FieldValue::Bytes(v)) => {
            if v.len() != 32 {
                return Err(TlsError::Internal(
                    "ClientHello.random override must be exactly 32 bytes",
                ));
            }
            ch.random.copy_from_slice(v);
        }
        // Raw extensions-block override: the bytes are the inner extension
        // entries (no outer u16 length prefix -- the encoder re-adds it). `[]`
        // decodes to an empty Vec, i.e. a ClientHello with an empty extensions
        // block (RFC 5246 7.4.1.2 / RFC 8446 4.1.2, extensions are optional).
        // Consumed by the key-share builder, not a ClientHello field.
        ("key_share_point", _) => {}
        ("obfuscated_ticket_age", FieldValue::U32(v)) => {
            let identity = ch
                .extensions
                .iter_mut()
                .find_map(|ext| match ext {
                    Extension::PreSharedKey { identities, .. } => identities.first_mut(),
                    _ => None,
                })
                .ok_or(TlsError::Internal(
                    "ClientHello.obfuscated_ticket_age requires a generated pre_shared_key extension",
                ))?;
            identity.obfuscated_ticket_age = *v;
        }
        ("psk_identity", FieldValue::Bytes(v)) => {
            let identity = ch
                .extensions
                .iter_mut()
                .find_map(|ext| match ext {
                    Extension::PreSharedKey { identities, .. } => identities.first_mut(),
                    _ => None,
                })
                .ok_or(TlsError::Internal(
                    "ClientHello.psk_identity requires a generated pre_shared_key extension",
                ))?;
            identity.identity = v.clone();
        }
        ("extensions", FieldValue::Bytes(v)) => {
            ch.extensions = crate::tls::codec::decode_extensions_block(v).map_err(|_| {
                TlsError::Internal("ClientHello.extensions override: malformed extension bytes")
            })?;
        }
        _ => {
            return Err(TlsError::UnknownFieldOverride {
                message: "ClientHello",
                field: ov.field.clone(),
            });
        }
    }
    Ok(())
}

/// Compare one matcher against a decoded ServerHello. Returns a
/// `MatcherFailed` TlsError on mismatch; Ok on match.
/// `has_ext` / `lacks_ext` on an extension list (EncryptedExtensions,
/// CertificateRequest, a Certificate entry, NewSessionTicket).
fn match_extension_list_field(
    message: &'static str,
    exts: &[Extension],
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    let present: Vec<String> = exts
        .iter()
        .map(|e| format!("0x{:04x}", e.wire_type()))
        .collect();
    match (m.field.as_str(), &m.value) {
        ("has_ext", FieldValue::U16(want)) => {
            if !exts.iter().any(|e| e.wire_type() == *want) {
                return Err(TlsError::MatcherFailed {
                    message,
                    field: "has_ext".into(),
                    expected: format!("extension 0x{:04x} present", want),
                    observed: format!("[{}]", present.join(", ")),
                });
            }
        }
        ("lacks_ext", FieldValue::U16(unwanted)) => {
            if exts.iter().any(|e| e.wire_type() == *unwanted) {
                return Err(TlsError::MatcherFailed {
                    message,
                    field: "lacks_ext".into(),
                    expected: format!("extension 0x{:04x} absent", unwanted),
                    observed: format!("[{}]", present.join(", ")),
                });
            }
        }
        // T2: `ext NAME == value` -- `type(2) || expected body`; the received
        // extension of that type must be present with exactly that body.
        ("ext", FieldValue::Bytes(v)) if v.len() >= 2 => {
            let ty = u16::from_be_bytes([v[0], v[1]]);
            let want = &v[2..];
            let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            let got = exts
                .iter()
                .find(|e| e.wire_type() == ty)
                .map(crate::tls::codec::extension_body);
            match got {
                Some(body) if body == want => {}
                Some(body) => {
                    return Err(TlsError::MatcherFailed {
                        message,
                        field: format!("ext 0x{:04x}", ty),
                        expected: format!("body {}", hex(want)),
                        observed: format!("body {}", hex(&body)),
                    });
                }
                None => {
                    return Err(TlsError::MatcherFailed {
                        message,
                        field: format!("ext 0x{:04x}", ty),
                        expected: format!("extension 0x{:04x} with body {}", ty, hex(want)),
                        observed: format!("[{}]", present.join(", ")),
                    });
                }
            }
        }
        // T2: exactly this set of extension types, in any order.
        ("extensions_exactly", FieldValue::U16List(want)) => {
            let mut got: Vec<u16> = exts.iter().map(|e| e.wire_type()).collect();
            let mut want_sorted = want.clone();
            got.sort_unstable();
            want_sorted.sort_unstable();
            if got != want_sorted {
                let fmt = |v: &[u16]| {
                    v.iter()
                        .map(|x| format!("0x{:04x}", x))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                return Err(TlsError::MatcherFailed {
                    message,
                    field: "extensions_exactly".into(),
                    expected: format!("[{}]", fmt(&want_sorted)),
                    observed: format!("[{}]", fmt(&got)),
                });
            }
        }
        _ => {
            return Err(TlsError::UnknownFieldOverride {
                message,
                field: m.field.clone(),
            });
        }
    }
    Ok(())
}

// T3: CertificateVerify signing controls shared by plzn's TLS 1.2 and TLS 1.3
// clients, and the composable client certificate_list.

/// The signature and label a client CertificateVerify goes out with once the
/// `send CertificateVerify { sign_with, algorithm, signature, salt_length,
/// mgf1_hash, format }` overrides and the `signature.em` mutations are applied
/// to the scheme the driver selected (`default_scheme`).
struct CertificateVerifyPlan {
    /// The SignatureScheme on the wire (tlsfuzzer `msg_alg`): `algorithm`,
    /// else the scheme that really signed.
    label: u16,
    signature: Vec<u8>,
}

fn plan_certificate_verify(
    pk: &crate::tls::crypto::PrivateKey,
    default_scheme: SignatureScheme,
    overrides: &[crate::ir::FieldOverride],
    mutations: &[Mutation],
    signed_input: &[u8],
    tls11: bool,
) -> Result<CertificateVerifyPlan, TlsError> {
    use crate::tls::crypto::{SigHash, SigningOptions};
    let mut scheme = default_scheme;
    let mut label: Option<u16> = None;
    let mut sig_override: Option<Vec<u8>> = None;
    let mut opts = SigningOptions {
        tls11,
        ..Default::default()
    };
    for ov in overrides {
        match (ov.field.as_str(), &ov.value) {
            // The scheme that REALLY signs (tlsfuzzer `sig_alg`): PKCS#1 v1.5
            // with any hash, PSS, ECDSA over any hash, Ed25519.
            ("sign_with", FieldValue::U16(v)) => {
                scheme = SignatureScheme::from_wire_value(*v).ok_or(TlsError::Internal(
                    "`sign_with` names a signature scheme plzn cannot produce (RSA PKCS#1 / PSS, ECDSA, Ed25519 only)",
                ))?;
            }
            // The scheme ADVERTISED in the message: relabel only.
            ("algorithm", FieldValue::U16(v)) => label = Some(*v),
            ("signature", FieldValue::Bytes(b)) => sig_override = Some(b.clone()),
            ("salt_length", FieldValue::U16(n)) => opts.salt_len = Some(*n as usize),
            ("mgf1_hash", FieldValue::Ident(h)) => opts.mgf1_hash = SigHash::from_name(h),
            ("format", FieldValue::Ident(f)) => opts.tls11 = f == "tls11",
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "CertificateVerify",
                    field: ov.field.clone(),
                });
            }
        }
    }
    opts.em_edits = mutations.iter().filter_map(em_edit).collect();
    let signature = match sig_override {
        Some(bytes) => bytes,
        None => pk.sign_with_options(scheme, signed_input, &opts)?,
    };
    Ok(CertificateVerifyPlan {
        label: label.unwrap_or(scheme.wire_value()),
        signature,
    })
}

/// A `@ xor[signature.em, i] = v` / `set` mutation as an edit to the RSASSA
/// encoded message (applied before the private-key operation), or None.
fn em_edit(m: &Mutation) -> Option<crate::tls::crypto::EmEdit> {
    let (target, value, xor) = match &m.op {
        crate::ir::MutationOp::Xor { target, value } => (target, *value, true),
        crate::ir::MutationOp::Set { target, value } => (target, *value, false),
        _ => return None,
    };
    match &target.path {
        Some(parts) if parts.len() == 2 && parts[0] == "signature" && parts[1] == "em" => {
            Some(crate::tls::crypto::EmEdit {
                index: target.index,
                value: value as u8,
                xor,
            })
        }
        _ => None,
    }
}

/// The mutations left for the encoded CertificateVerify once the
/// `signature.em` ones have been consumed by the signer.
fn without_em_mutations(mutations: &[Mutation]) -> Vec<Mutation> {
    mutations
        .iter()
        .filter(|m| em_edit(m).is_none())
        .cloned()
        .collect()
}

/// `send Certificate { certificate_list: [rsa, empty, ecdsa_p256] }`: each
/// name is a testdata credential (`valid` / `rsa` / `rsa_pss` / `ecdsa_p256` /
/// `ecdsa_p384` / `ecdsa_p521` / `ed25519` / `untrusted`) or `empty`, a
/// zero-length entry. The CertificateVerify signs with the FIRST named
/// credential's key (None when the list holds only empty entries).
/// The DER entries of a composed `certificate_list` and the PKCS#8 key of the
/// first named credential (None when only `empty` entries were named).
type ComposedCertificateList = (Vec<Vec<u8>>, Option<Vec<u8>>);

fn compose_certificate_list(names: &[String]) -> Result<ComposedCertificateList, TlsError> {
    let mut list = Vec::with_capacity(names.len());
    let mut key: Option<Vec<u8>> = None;
    for name in names {
        if name == "empty" {
            list.push(Vec::new());
            continue;
        }
        let (cert, k) = crate::tls::dtls_kex::named_client_credential(name).ok_or(TlsError::Internal(
            "`certificate_list` names must be testdata credentials (valid, rsa, rsa_pss, ecdsa_p256, ecdsa_p384, ecdsa_p521, ed25519, untrusted) or `empty`",
        ))?;
        list.push(cert);
        key.get_or_insert(k);
    }
    Ok((list, key))
}

/// The signature_algorithms a TLS 1.3 CertificateRequest carries (RFC 8446
/// 4.3.2), whichever way the extension decoded.
pub(crate) fn cr13_signature_algorithms(extensions: &[Extension]) -> Vec<u16> {
    for e in extensions {
        match e {
            Extension::SignatureAlgorithms(list) => return list.clone(),
            Extension::Unknown { ty, data }
                if *ty == crate::tls::codec::EXT_SIGNATURE_ALGORITHMS =>
            {
                let mut c = crate::tls::codec::ByteCursor::new(data);
                if let Ok(body) = c.u16_vec() {
                    return body
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

/// Matchers on a TLS 1.3 CertificateRequest (RFC 8446 4.3.2).
fn match_certificate_request_field(
    cr: &crate::tls::codec::CertificateRequest13,
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (m.field.as_str(), &m.value) {
        // T3: contains-all, like the TLS 1.2 matcher.
        ("signature_algorithms", FieldValue::U16List(want)) => {
            let have = cr13_signature_algorithms(&cr.extensions);
            if let Some(missing) = want.iter().find(|a| !have.contains(a)) {
                return Err(TlsError::MatcherFailed {
                    message: "CertificateRequest",
                    field: "signature_algorithms".into(),
                    expected: format!("list to contain 0x{:04x}", missing),
                    observed: have
                        .iter()
                        .map(|a| format!("0x{:04x}", a))
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
            Ok(())
        }
        ("certificate_authorities_count", FieldValue::U16(want)) => {
            // certificate_authorities (RFC 8446 4.2.4): DistinguishedName
            // authorities<3..2^16-1>, each a u16-length DER Name.
            let mut count = 0u16;
            for e in &cr.extensions {
                if let Extension::Unknown { ty, data } = e {
                    if *ty == crate::tls::codec::EXT_CERTIFICATE_AUTHORITIES {
                        let mut c = crate::tls::codec::ByteCursor::new(data);
                        if let Ok(list) = c.u16_vec() {
                            let mut lc = crate::tls::codec::ByteCursor::new(list);
                            while lc.u16_vec().is_ok() {
                                count += 1;
                            }
                        }
                    }
                }
            }
            if count != *want {
                return Err(TlsError::MatcherFailed {
                    message: "CertificateRequest",
                    field: "certificate_authorities_count".into(),
                    expected: format!("{}", want),
                    observed: format!("{}", count),
                });
            }
            Ok(())
        }
        _ => match_extension_list_field("CertificateRequest", &cr.extensions, m),
    }
}

/// Matchers on a TLS 1.3 Certificate (RFC 8446 4.4.2).
/// `recv Certificate { leaf_key: <kind> }`: the presented leaf certificate's
/// public-key type -- which chain a multi-chain peer chose. `leaf` is the
/// X.509 DER (or, under RawPublicKey, the bare SubjectPublicKeyInfo).
pub(crate) fn match_leaf_key(leaf: Option<&[u8]>, want: &str) -> Result<(), TlsError> {
    use crate::tls::crypto::{KeyKind, PublicKey};
    let want_kind = KeyKind::from_dsl_name(want).ok_or(TlsError::Internal(
        "`leaf_key` takes rsa_2048, rsa_pss, ecdsa_p256, ecdsa_p384, ecdsa_p521 or ed25519",
    ))?;
    let Some(leaf) = leaf else {
        return Err(TlsError::MatcherFailed {
            message: "Certificate",
            field: "leaf_key".into(),
            expected: want_kind.dsl_name().into(),
            observed: "an empty certificate_list".into(),
        });
    };
    let key = PublicKey::from_certificate_der(leaf).or_else(|_| PublicKey::from_spki_der(leaf))?;
    if key.kind() != want_kind {
        return Err(TlsError::MatcherFailed {
            message: "Certificate",
            field: "leaf_key".into(),
            expected: want_kind.dsl_name().into(),
            observed: key.kind().dsl_name().into(),
        });
    }
    Ok(())
}

pub(crate) fn match_certificate_type(got: u8, want: &str) -> Result<(), TlsError> {
    let want_wire = match want {
        "x509" => crate::tls::codec::CERT_TYPE_X509,
        "raw_public_key" => crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY,
        _ => {
            return Err(TlsError::Internal(
                "`certificate_type` takes x509 or raw_public_key",
            ));
        }
    };
    if got != want_wire {
        return Err(TlsError::MatcherFailed {
            message: "Certificate",
            field: "certificate_type".into(),
            expected: want.into(),
            observed: if got == crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY {
                "raw_public_key".into()
            } else {
                "x509".into()
            },
        });
    }
    Ok(())
}

fn match_certificate_13_field(
    cert: &crate::tls::codec::Certificate13,
    m: &crate::ir::FieldOverride,
    negotiated_certificate_type: u8,
) -> Result<(), TlsError> {
    match (m.field.as_str(), &m.value) {
        ("leaf_key", FieldValue::Ident(want)) => {
            match_leaf_key(cert.entries.first().map(|e| e.cert_data.as_slice()), want)
        }
        ("entries", FieldValue::U16(want)) => {
            if cert.entries.len() != *want as usize {
                return Err(TlsError::MatcherFailed {
                    message: "Certificate",
                    field: "entries".into(),
                    expected: format!("{}", want),
                    observed: format!("{}", cert.entries.len()),
                });
            }
            Ok(())
        }
        ("certificate_type", FieldValue::Ident(want)) => {
            match_certificate_type(negotiated_certificate_type, want)
        }
        ("leaf_has_ext", _) | ("leaf_lacks_ext", _) => {
            let leaf = cert.entries.first().ok_or(TlsError::CertificateListEmpty)?;
            let exts = crate::tls::codec::decode_extensions_block(&leaf.extensions)
                .map_err(TlsError::Codec)?;
            let inner = crate::ir::FieldOverride {
                field: m.field.trim_start_matches("leaf_").to_string(),
                value: m.value.clone(),
                span: m.span,
            };
            match_extension_list_field("Certificate", &exts, &inner)
        }
        _ => Err(TlsError::UnknownFieldOverride {
            message: "Certificate",
            field: m.field.clone(),
        }),
    }
}

/// Matchers on a TLS 1.3 NewSessionTicket (RFC 8446 4.6.1).
fn match_value(
    message: &'static str,
    matcher: &FieldOverride,
    observed: FieldValue,
) -> Result<(), TlsError> {
    let matches = match (&matcher.value, &observed) {
        (FieldValue::U16(want), FieldValue::U32(got)) => u32::from(*want) == *got,
        (want, got) => want == got,
    };
    if !matches {
        return Err(TlsError::MatcherFailed {
            message,
            field: matcher.field.clone(),
            expected: matcher.value.describe(),
            observed: observed.describe(),
        });
    }
    Ok(())
}

fn match_new_session_ticket_field(
    nst: &crate::tls::codec::NewSessionTicket13,
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (m.field.as_str(), &m.value) {
        ("ticket_lifetime", _) => {
            match_value("NewSessionTicket", m, FieldValue::U32(nst.ticket_lifetime))
        }
        ("ticket_age_add", _) => {
            match_value("NewSessionTicket", m, FieldValue::U32(nst.ticket_age_add))
        }
        ("ticket_nonce", _) => match_value(
            "NewSessionTicket",
            m,
            FieldValue::Bytes(nst.ticket_nonce.clone()),
        ),
        ("ticket", _) => match_value("NewSessionTicket", m, FieldValue::Bytes(nst.ticket.clone())),
        ("max_ticket_lifetime_hours", FieldValue::U16(hours)) => {
            let max = (*hours as u32).saturating_mul(3600);
            if nst.ticket_lifetime > max {
                return Err(TlsError::MatcherFailed {
                    message: "NewSessionTicket",
                    field: "max_ticket_lifetime_hours".into(),
                    expected: format!("ticket_lifetime <= {} s", max),
                    observed: format!("{} s", nst.ticket_lifetime),
                });
            }
            Ok(())
        }
        _ => match_extension_list_field("NewSessionTicket", &nst.extensions, m),
    }
}

fn capture_new_session_ticket_field(
    nst: &crate::tls::codec::NewSessionTicket13,
    field: &str,
) -> Result<Vec<u8>, TlsError> {
    match field {
        "ticket_lifetime" => Ok(nst.ticket_lifetime.to_be_bytes().to_vec()),
        "ticket_age_add" => Ok(nst.ticket_age_add.to_be_bytes().to_vec()),
        "ticket_nonce" => Ok(nst.ticket_nonce.clone()),
        "ticket" => Ok(nst.ticket.clone()),
        _ => Err(TlsError::Internal(
            "capture: only ticket_lifetime, ticket_age_add, ticket_nonce and ticket can be captured from NewSessionTicket",
        )),
    }
}

pub fn match_server_hello_field(
    sh: &crate::tls::codec::ServerHello,
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (m.field.as_str(), &m.value) {
        ("legacy_version", FieldValue::U16(want)) => {
            if sh.legacy_version != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "legacy_version".into(),
                    expected: format!("0x{:04x}", want),
                    observed: format!("0x{:04x}", sh.legacy_version),
                });
            }
        }
        ("cipher_suite", FieldValue::U16(want)) => {
            if sh.cipher_suite != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "cipher_suite".into(),
                    expected: format!("0x{:04x}", want),
                    observed: format!("0x{:04x}", sh.cipher_suite),
                });
            }
        }
        ("selected_psk_identity", FieldValue::U16(want)) => {
            let got = sh.extensions.iter().find_map(|ext| match ext {
                Extension::Unknown { ty, data }
                    if *ty == crate::tls::codec::EXT_PRE_SHARED_KEY && data.len() == 2 =>
                {
                    Some(u16::from_be_bytes([data[0], data[1]]))
                }
                _ => None,
            });
            if got != Some(*want) {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "selected_psk_identity".into(),
                    expected: want.to_string(),
                    observed: got
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "no valid pre_shared_key selection".into()),
                });
            }
        }
        ("legacy_session_id_echo", FieldValue::Bytes(want)) => {
            if sh.session_id != *want {
                let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "legacy_session_id_echo".into(),
                    expected: hex(want),
                    observed: hex(&sh.session_id),
                });
            }
        }
        ("legacy_compression_method", FieldValue::U8(want)) => {
            if sh.compression_method != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "legacy_compression_method".into(),
                    expected: format!("0x{:02x}", want),
                    observed: format!("0x{:02x}", sh.compression_method),
                });
            }
        }
        // Assert ServerHello.random ends with these bytes. For the TLS 1.3
        // downgrade sentinel (RFC 8446 4.1.3): a 1.3-capable server negotiating
        // TLS 1.2 sets random[24..32] = 44 4F 57 4E 47 52 44 01.
        ("random_suffix", FieldValue::Bytes(want)) => {
            let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
            if !sh.random.ends_with(want) {
                let n = want.len().min(sh.random.len());
                let tail = &sh.random[sh.random.len() - n..];
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "random_suffix".into(),
                    expected: hex(want),
                    observed: hex(tail),
                });
            }
        }
        // Assert an extension of the given IANA type is present in the ServerHello
        // (e.g. extended_master_secret 0x0017 per RFC 7627, or key_share 0x0033).
        ("has_ext", FieldValue::U16(want)) => {
            if !sh.extensions.iter().any(|e| e.wire_type() == *want) {
                let present: Vec<String> = sh
                    .extensions
                    .iter()
                    .map(|e| format!("0x{:04x}", e.wire_type()))
                    .collect();
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "has_ext".into(),
                    expected: format!("extension 0x{:04x} present", want),
                    observed: format!("[{}]", present.join(", ")),
                });
            }
        }
        // Assert an extension of the given IANA type is ABSENT from the ServerHello
        // (e.g. the server MUST NOT echo extended_master_secret unless the client
        // offered it, RFC 7627 5.3).
        ("lacks_ext", FieldValue::U16(unwanted)) => {
            if sh.extensions.iter().any(|e| e.wire_type() == *unwanted) {
                let present: Vec<String> = sh
                    .extensions
                    .iter()
                    .map(|e| format!("0x{:04x}", e.wire_type()))
                    .collect();
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "lacks_ext".into(),
                    expected: format!("extension 0x{:04x} absent", unwanted),
                    observed: format!("[{}]", present.join(", ")),
                });
            }
        }
        // Assert which group the server's key_share answers with (RFC 8446 4.2.8:
        // the ServerHello carries exactly one KeyShareEntry, for a group the
        // client offered a share for).
        ("key_share_group", FieldValue::U16(want)) => {
            let got = sh.extensions.iter().find_map(|e| match e {
                Extension::KeyShare(entries) => entries.first().map(|k| k.group),
                Extension::KeyShareSingle(k) => Some(k.group),
                Extension::KeyShareRetryGroup(g) => Some(*g),
                _ => None,
            });
            if got != Some(*want) {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "key_share_group".into(),
                    expected: format!("0x{:04x}", want),
                    observed: got
                        .map(|g| format!("0x{:04x}", g))
                        .unwrap_or_else(|| "no key_share".into()),
                });
            }
        }
        ("selected_version", FieldValue::U16(want)) => {
            let got = sh.extensions.iter().find_map(|ext| match ext {
                Extension::SupportedVersions(versions) => versions.first().copied(),
                Extension::SupportedVersionsSingle(version) => Some(*version),
                _ => None,
            });
            if got != Some(*want) {
                return Err(TlsError::MatcherFailed {
                    message: "ServerHello",
                    field: "selected_version".into(),
                    expected: format!("0x{:04x}", want),
                    observed: got
                        .map(|version| format!("0x{:04x}", version))
                        .unwrap_or_else(|| "no supported_versions extension".into()),
                });
            }
        }
        // T1: captures are recorded by the caller before matching.
        (_, FieldValue::Capture(_)) => {}
        // T2: `ext NAME == value`, `extensions_exactly: [...]`.
        _ => return match_extension_list_field("ServerHello", &sh.extensions, m),
    }
    Ok(())
}

/// T2: a HelloRetryRequest takes the ServerHello matchers (it is one on the
/// wire), reported under its own name.
pub fn match_hello_retry_request_field(
    hrr: &crate::tls::codec::ServerHello,
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match_server_hello_field(hrr, m).map_err(|e| match e {
        TlsError::MatcherFailed {
            field,
            expected,
            observed,
            ..
        } => TlsError::MatcherFailed {
            message: "HelloRetryRequest",
            field,
            expected,
            observed,
        },
        TlsError::UnknownFieldOverride { field, .. } => TlsError::UnknownFieldOverride {
            message: "HelloRetryRequest",
            field,
        },
        other => other,
    })
}

/// All (D)TLS 1.2 cipher-suite codepoints prohibited by RFC 10015 Tables 1,
/// 3, and 4. This is deliberately independent of `ALL_SUITES`: a client can
/// offer a suite that plzn does not implement, and that offer is precisely
/// what this policy matcher needs to detect. Static ECDH (Table 2) is omitted
/// because RFC 10015 only says SHOULD NOT for that family.
fn is_rfc10015_prohibited_suite(suite: u16) -> bool {
    matches!(
        suite,
        0x0001..=0x001b
            | 0x002d..=0x002e
            | 0x002f..=0x0046
            | 0x0067..=0x006d
            | 0x0084..=0x0089
            | 0x008e..=0x00a7
            | 0x00aa..=0x00ad
            | 0x00b2..=0x00c5
            | 0xc03c..=0xc047
            | 0xc050..=0xc05b
            | 0xc066..=0xc069
            | 0xc06c..=0xc06f
            | 0xc07a..=0xc085
            | 0xc090..=0xc093
            | 0xc096..=0xc099
            | 0xc09c..=0xc0a3
            | 0xc0a6..=0xc0a7
            | 0xc0aa..=0xc0ab
            | 0xccaa
            | 0xccad..=0xccae
    )
}

/// Compare one matcher against a ClientHello the UUT client sent.
/// Returns a `MatcherFailed` TlsError on mismatch; Ok on match.
///
/// This is the `uut client` mirror of `match_server_hello_field`:
/// when the harness plays the server, `recv ClientHello { field: ... }`
/// asserts on what the client actually put on the wire. RFC 9846
/// Section 4.2.2 makes several of these MUSTs for a TLS 1.3 client — e.g.
/// `legacy_version == 0x0303`, and exactly one null compression method.
pub fn match_client_hello_field(
    ch: &crate::tls::codec::ClientHelloDecoded,
    m: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    fn fmt_u16_list(v: &[u16]) -> String {
        let parts: Vec<String> = v.iter().map(|x| format!("0x{:04x}", x)).collect();
        format!("[{}]", parts.join(", "))
    }
    fn fmt_u8_list(v: &[u8]) -> String {
        let parts: Vec<String> = v.iter().map(|x| format!("0x{:02x}", x)).collect();
        format!("[{}]", parts.join(", "))
    }
    fn fmt_bytes(v: &[u8]) -> String {
        v.iter().map(|b| format!("{:02x}", b)).collect()
    }
    match (m.field.as_str(), &m.value) {
        ("legacy_version", FieldValue::U16(want)) => {
            if ch.legacy_version != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "legacy_version".into(),
                    expected: format!("0x{:04x}", want),
                    observed: format!("0x{:04x}", ch.legacy_version),
                });
            }
        }
        ("random", FieldValue::Bytes(want)) => {
            if ch.random.as_slice() != want.as_slice() {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "random".into(),
                    expected: fmt_bytes(want),
                    observed: fmt_bytes(&ch.random),
                });
            }
        }
        ("legacy_session_id" | "session_id", FieldValue::Bytes(want)) => {
            if ch.session_id != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "legacy_session_id".into(),
                    expected: fmt_bytes(want),
                    observed: fmt_bytes(&ch.session_id),
                });
            }
        }
        // cipher_suites uses a *contains-all* semantic rather than
        // exact equality: a client's offered list is long and its order
        // varies by implementation/config, but "did the client offer
        // suite X?" is the useful, RFC-grounded assertion (e.g. RFC 9846
        // §9.1 makes TLS_AES_128_GCM_SHA256 mandatory-to-offer). The
        // matcher passes iff every listed suite appears in the offer.
        ("cipher_suites" | "ciphers", FieldValue::U16List(want)) => {
            if let Some(missing) = want.iter().find(|s| !ch.cipher_suites.contains(s)) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "cipher_suites".into(),
                    expected: format!("offered list to contain 0x{:04x}", missing),
                    observed: fmt_u16_list(&ch.cipher_suites),
                });
            }
        }
        ("lacks_cipher_suite", FieldValue::U16(unwanted)) => {
            if ch.cipher_suites.contains(unwanted) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_cipher_suite".into(),
                    expected: format!("cipher suite 0x{:04x} absent", unwanted),
                    observed: fmt_u16_list(&ch.cipher_suites),
                });
            }
        }
        ("lacks_obsolete_key_exchange", FieldValue::Ident(want)) if want == "true" => {
            let obsolete: Vec<u16> = ch
                .cipher_suites
                .iter()
                .copied()
                .filter(|suite| is_rfc10015_prohibited_suite(*suite))
                .collect();
            if !obsolete.is_empty() {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_obsolete_key_exchange".into(),
                    expected: "no TLS 1.2 finite-field DHE or RSA key-transport suite".into(),
                    observed: fmt_u16_list(&obsolete),
                });
            }
        }
        ("compression_methods" | "legacy_compression_methods", FieldValue::U8List(want)) => {
            if ch.compression_methods != *want {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "compression_methods".into(),
                    expected: fmt_u8_list(want),
                    observed: fmt_u8_list(&ch.compression_methods),
                });
            }
        }
        // Contains-all over the client's supported_groups / signature_algorithms
        // extensions (plzn as server; names lower to wire values).
        ("supported_groups", FieldValue::U16List(want))
        | ("supported_versions", FieldValue::U16List(want))
        | ("signature_algorithms", FieldValue::U16List(want)) => {
            let (field, present): (&str, Vec<u16>) = match m.field.as_str() {
                "supported_groups" => (
                    "supported_groups",
                    ch.extensions
                        .iter()
                        .find_map(|e| match e {
                            crate::tls::codec::Extension::SupportedGroups(g) => Some(g.clone()),
                            _ => None,
                        })
                        .unwrap_or_default(),
                ),
                "supported_versions" => (
                    "supported_versions",
                    ch.extensions
                        .iter()
                        .find_map(|e| match e {
                            crate::tls::codec::Extension::SupportedVersions(v) => Some(v.clone()),
                            crate::tls::codec::Extension::SupportedVersionsSingle(v) => {
                                Some(vec![*v])
                            }
                            _ => None,
                        })
                        .unwrap_or_default(),
                ),
                _ => (
                    "signature_algorithms",
                    ch.extensions
                        .iter()
                        .find_map(|e| match e {
                            crate::tls::codec::Extension::SignatureAlgorithms(a) => Some(a.clone()),
                            _ => None,
                        })
                        .unwrap_or_default(),
                ),
            };
            if let Some(missing) = want.iter().find(|w| !present.contains(w)) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: field.into(),
                    expected: format!("list to contain 0x{:04x}", missing),
                    observed: fmt_u16_list(&present),
                });
            }
        }
        ("lacks_signature_algorithm", FieldValue::U16(unwanted)) => {
            let present = ch
                .extensions
                .iter()
                .find_map(|e| match e {
                    crate::tls::codec::Extension::SignatureAlgorithms(a) => Some(a.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            if present.contains(unwanted) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_signature_algorithm".into(),
                    expected: format!("signature scheme 0x{:04x} absent", unwanted),
                    observed: fmt_u16_list(&present),
                });
            }
        }
        ("lacks_supported_group", FieldValue::U16(unwanted)) => {
            let present = ch
                .extensions
                .iter()
                .find_map(|e| match e {
                    crate::tls::codec::Extension::SupportedGroups(g) => Some(g.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            if present.contains(unwanted) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_supported_group".into(),
                    expected: format!("group 0x{:04x} absent", unwanted),
                    observed: fmt_u16_list(&present),
                });
            }
        }
        ("lacks_supported_version", FieldValue::U16(unwanted)) => {
            let present = ch
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    crate::tls::codec::Extension::SupportedVersions(versions) => {
                        Some(versions.as_slice())
                    }
                    _ => None,
                })
                .unwrap_or_default();
            if present.contains(unwanted) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_supported_version".into(),
                    expected: format!("version 0x{:04x} absent", unwanted),
                    observed: fmt_u16_list(present),
                });
            }
        }
        ("secure_renegotiation_signal", FieldValue::Ident(want)) if want == "true" => {
            let has_empty_extension = ch.extensions.iter().any(|ext| {
                matches!(ext, crate::tls::codec::Extension::RenegotiationInfo(data) if data.is_empty())
            });
            let has_scsv = ch.cipher_suites.contains(&0x00ff);
            if !has_empty_extension && !has_scsv {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "secure_renegotiation_signal".into(),
                    expected: "empty renegotiation_info or TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
                        .into(),
                    observed: "neither signal was present".into(),
                });
            }
        }
        ("supported_groups_unique", FieldValue::Ident(want)) if want == "true" => {
            let groups = ch
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    crate::tls::codec::Extension::SupportedGroups(groups) => {
                        Some(groups.as_slice())
                    }
                    _ => None,
                })
                .unwrap_or_default();
            let mut seen = std::collections::HashSet::new();
            if let Some(duplicate) = groups.iter().find(|group| !seen.insert(**group)) {
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "supported_groups_unique".into(),
                    expected: "no duplicate supported group".into(),
                    observed: format!("duplicate 0x{:04x} in {}", duplicate, fmt_u16_list(groups)),
                });
            }
        }
        ("key_shares_consistent", FieldValue::Ident(want)) if want == "true" => {
            let groups = ch
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    crate::tls::codec::Extension::SupportedGroups(groups) => {
                        Some(groups.as_slice())
                    }
                    _ => None,
                })
                .unwrap_or_default();
            let shares: Vec<u16> = ch
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    crate::tls::codec::Extension::KeyShare(entries) => {
                        Some(entries.iter().map(|entry| entry.group).collect())
                    }
                    crate::tls::codec::Extension::KeyShareSingle(entry) => Some(vec![entry.group]),
                    _ => None,
                })
                .unwrap_or_default();
            let mut seen = std::collections::HashSet::new();
            let duplicate = shares.iter().find(|group| !seen.insert(**group)).copied();
            let unlisted = shares.iter().find(|group| !groups.contains(group)).copied();
            let positions: Vec<usize> = shares
                .iter()
                .filter_map(|share| groups.iter().position(|group| group == share))
                .collect();
            let out_of_order = positions.windows(2).any(|pair| pair[0] >= pair[1]);
            if duplicate.is_some() || unlisted.is_some() || out_of_order {
                let detail = if let Some(group) = duplicate {
                    format!("duplicate key share 0x{:04x}", group)
                } else if let Some(group) = unlisted {
                    format!("unlisted key share 0x{:04x}", group)
                } else {
                    "key shares are not in supported_groups order".into()
                };
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "key_shares_consistent".into(),
                    expected: "unique, listed key shares in supported_groups order".into(),
                    observed: format!(
                        "{}; shares {}, groups {}",
                        detail,
                        fmt_u16_list(&shares),
                        fmt_u16_list(groups)
                    ),
                });
            }
        }
        // The host_name in the client's server_name extension (RFC 6066 3); plzn
        // as a TLS 1.2 / DTLS server. A missing extension or a different name fails.
        ("server_name", FieldValue::Bytes(want)) => {
            let want = String::from_utf8_lossy(want).into_owned();
            let present = ch.extensions.iter().find_map(|e| match e {
                crate::tls::codec::Extension::ServerName(n) => Some(n.clone()),
                _ => None,
            });
            match present {
                Some(n) if n == want => {}
                Some(n) => {
                    return Err(TlsError::MatcherFailed {
                        message: "ClientHello",
                        field: "server_name".into(),
                        expected: want,
                        observed: n,
                    });
                }
                None => {
                    return Err(TlsError::MatcherFailed {
                        message: "ClientHello",
                        field: "server_name".into(),
                        expected: want,
                        observed: "no server_name extension".into(),
                    });
                }
            }
        }
        // Assert an extension of the given IANA type is ABSENT from the ClientHello
        // (e.g. a client whose `uut` policy switched encrypt_then_mac off).
        ("lacks_ext", FieldValue::U16(unwanted)) => {
            if ch.extensions.iter().any(|e| e.wire_type() == *unwanted) {
                let present: Vec<u16> = ch.extensions.iter().map(|e| e.wire_type()).collect();
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "lacks_ext".into(),
                    expected: format!("extension 0x{:04x} absent", unwanted),
                    observed: fmt_u16_list(&present),
                });
            }
        }
        // Assert an extension of the given IANA type is present in the ClientHello.
        // Useful for client-conformance checks (e.g. TLS 1.3 clients MUST send
        // supported_versions (0x002b) and key_share (0x0033)).
        ("has_ext", FieldValue::U16(want)) => {
            if !ch.extensions.iter().any(|e| e.wire_type() == *want) {
                let present: Vec<u16> = ch.extensions.iter().map(|e| e.wire_type()).collect();
                return Err(TlsError::MatcherFailed {
                    message: "ClientHello",
                    field: "has_ext".into(),
                    expected: format!("extension 0x{:04x} present", want),
                    observed: fmt_u16_list(&present),
                });
            }
        }
        // T2: `ext NAME == value`, `extensions_exactly: [...]`.
        _ => return match_extension_list_field("ClientHello", &ch.extensions, m),
    }
    Ok(())
}

/// Return the raw value named by a ClientHello capture matcher. Kept beside
/// the shared matcher so the TLS and DTLS server drivers expose identical
/// capture behavior.
pub fn capture_client_hello_field(
    ch: &crate::tls::codec::ClientHelloDecoded,
    field: &str,
) -> Result<Vec<u8>, TlsError> {
    match field {
        "random" => Ok(ch.random.to_vec()),
        "legacy_session_id" | "session_id" => Ok(ch.session_id.clone()),
        "key_share" => ch
            .extensions
            .iter()
            .find_map(|extension| match extension {
                Extension::KeyShare(entries) => {
                    entries.first().map(|entry| entry.key_exchange.clone())
                }
                _ => None,
            })
            .ok_or(TlsError::Internal(
                "capture: ClientHello carries no key_share entry",
            )),
        _ => Err(TlsError::Internal(
            "capture: only random, legacy_session_id and key_share can be captured from ClientHello",
        )),
    }
}

/// Apply an override to the ECDHE ClientKeyExchange public-point
/// bytes (the `ecdh_Yc` field in RFC 5246 §7.4.7.2).
///
/// We stash the override on the wire bytes only, not on the curve
/// math — the test harness still agrees with the server's *real*
/// public key to derive a valid PMS, because the point of a CKE
/// override is usually "what happens when the wire bytes don't
/// match what the client actually used for agreement".
fn apply_client_key_exchange_override(
    pubkey: &mut Vec<u8>,
    ov: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (ov.field.as_str(), &ov.value) {
        // Consumed by the key-share builder below, not a field of the message.
        ("key_share_point", _) | ("shared_secret_leading_zeros", _) => Ok(()),
        ("ecdh_Yc", FieldValue::Bytes(v)) => {
            *pubkey = v.clone();
            Ok(())
        }
        ("encrypted_premaster", FieldValue::Bytes(_)) | ("dh_Yc", FieldValue::Bytes(_)) => {
            Err(TlsError::Internal(
                "ClientKeyExchange override on RSA-kex or DH-kex field \
             but the driver only supports ECDHE",
            ))
        }
        _ => Err(TlsError::UnknownFieldOverride {
            message: "ClientKeyExchange",
            field: ov.field.clone(),
        }),
    }
}

/// Apply an override to Finished.verify_data. Shared between TLS
/// 1.2 and TLS 1.3 because the field is the same in both.
/// Apply a field override to a ServerHello being constructed.
/// Used by both TLS 1.2 and 1.3 server drivers.
pub(crate) fn apply_server_hello_override(
    sh: &mut crate::tls::codec::ServerHelloBuilder,
    ov: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (ov.field.as_str(), &ov.value) {
        // Consumed by the server's key-share builder, not a ServerHello field.
        ("key_share_point", _) => Ok(()),
        // Consumed by the TLS 1.3 server's PSK-acceptance logic (server13.rs),
        // not a ServerHello wire field.
        ("psk_mode", _) => Ok(()),
        ("selected_psk_identity", FieldValue::U16(v)) => {
            for ext in sh.extensions.iter_mut() {
                if let Extension::Unknown { ty, data } = ext {
                    if *ty == crate::tls::codec::EXT_PRE_SHARED_KEY {
                        *data = v.to_be_bytes().to_vec();
                        return Ok(());
                    }
                }
            }
            Err(TlsError::Internal(
                "ServerHello.selected_psk_identity requires an accepted PSK",
            ))
        }
        ("legacy_version", FieldValue::U16(v)) => {
            sh.legacy_version = *v;
            Ok(())
        }
        ("random", FieldValue::Bytes(v)) => {
            if v.len() == 32 {
                sh.random.copy_from_slice(v);
                Ok(())
            } else {
                Err(TlsError::Internal(
                    "ServerHello.random override must be exactly 32 bytes",
                ))
            }
        }
        ("legacy_session_id_echo", FieldValue::Bytes(v)) => {
            sh.session_id = v.clone();
            Ok(())
        }
        ("cipher_suite", FieldValue::U16(v)) => {
            sh.cipher_suite = *v;
            Ok(())
        }
        ("legacy_compression_method", FieldValue::U8(v)) => {
            sh.compression_method = *v;
            Ok(())
        }
        ("extensions", FieldValue::Bytes(v)) => {
            sh.extensions = crate::tls::codec::decode_extensions_block(v).map_err(|_| {
                TlsError::Internal("ServerHello.extensions override: malformed extension bytes")
            })?;
            Ok(())
        }
        ("key_share_group", FieldValue::U16(v)) => {
            // Rewrite the group in the TLS 1.3 key_share the server
            // already built (RFC 8446 §4.2.8). The key material is
            // left as-is: a conformant client rejects a group it
            // didn't offer a key_share for (illegal_parameter) before
            // it ever looks at the point. On a HelloRetryRequest the
            // key_share is the group-only retry form.
            for ext in sh.extensions.iter_mut() {
                match ext {
                    crate::tls::codec::Extension::KeyShareSingle(entry) => entry.group = *v,
                    crate::tls::codec::Extension::KeyShareRetryGroup(g) => *g = *v,
                    _ => {}
                }
            }
            Ok(())
        }
        _ => Err(TlsError::UnknownFieldOverride {
            message: "ServerHello",
            field: ov.field.clone(),
        }),
    }
}

fn apply_finished_override(
    verify_data: &mut Vec<u8>,
    ov: &crate::ir::FieldOverride,
) -> Result<(), TlsError> {
    match (ov.field.as_str(), &ov.value) {
        ("verify_data", FieldValue::Bytes(v)) => {
            *verify_data = v.clone();
            Ok(())
        }
        _ => Err(TlsError::UnknownFieldOverride {
            message: "Finished",
            field: ov.field.clone(),
        }),
    }
}

/// Resolve the ChangeCipherSpec content byte. Default per RFC 5246
/// §7.1 is 0x01; a `send ChangeCipherSpec { type: 0xNN }` override
/// replaces it.
pub(crate) fn resolve_ccs_byte(overrides: &[MessageOverrides]) -> Result<u8, TlsError> {
    let list = collect_overrides(overrides, MessageKind::ChangeCipherSpec);
    let Some(ov) = list.first() else {
        return Ok(0x01);
    };
    match (ov.field.as_str(), &ov.value) {
        ("type", FieldValue::U8(v)) => Ok(*v),
        _ => Err(TlsError::UnknownFieldOverride {
            message: "ChangeCipherSpec",
            field: ov.field.clone(),
        }),
    }
}

// ============================================================
//   T6: heartbeat (RFC 6520), CertificateStatus (RFC 6066 8), literal
//   and SSLv2-format ClientHellos, client-side CompressedCertificate
//   (RFC 8879), post-handshake authentication (RFC 8446 4.6.2)
// ============================================================

/// A post-handshake CertificateRequest being answered (RFC 8446 4.6.2): its
/// certificate_request_context, and the transcript that runs from the
/// handshake's client Finished through the request and our reply.
pub(crate) struct PhaState {
    context: Vec<u8>,
    transcript: TranscriptHash,
}

/// `send ClientHello raw "HEX"`: the literal body, if the step carries one.
pub(crate) fn t6_raw_client_hello_body(overrides: &[MessageOverrides]) -> Option<Vec<u8>> {
    collect_overrides(overrides, MessageKind::ClientHello)
        .iter()
        .find_map(|o| match (o.field.as_str(), &o.value) {
            ("raw_body", FieldValue::Bytes(b)) => Some(b.clone()),
            _ => None,
        })
}

/// `recv alert level[/code]`: the next record must be that alert.
pub(crate) fn t6_expect_alert_record(
    records: &mut RecordLayer,
    level: u8,
    code: Option<u8>,
) -> Result<(), TlsError> {
    let (ct, body) = records.read_record().map_err(TlsError::Record)?;
    t6_match_alert_record(ct, &body, level, code)
}

fn t6_match_alert_record(ct: u8, body: &[u8], level: u8, code: Option<u8>) -> Result<(), TlsError> {
    if ct != crate::tls::codec::CONTENT_TYPE_ALERT {
        return Err(TlsError::MatcherFailed {
            message: "`recv alert`: the next record is not an alert",
            field: "content_type".into(),
            expected: "21 (alert)".into(),
            observed: format!("{} ({} bytes)", ct, body.len()),
        });
    }
    if body.len() != 2 {
        return Err(TlsError::MatcherFailed {
            message: "`recv alert`: malformed alert record",
            field: "alert".into(),
            expected: "2 bytes".into(),
            observed: format!("{} bytes", body.len()),
        });
    }
    let ok = body[0] == level && code.is_none_or(|c| c == body[1]);
    if !ok {
        // A different alert: report it as the alert it is, so the failure
        // reads "alert fatal/handshake_failure", not a matcher message.
        return Err(TlsError::Alert {
            level: body[0],
            description: body[1],
        });
    }
    Ok(())
}

/// `send ClientHello { format: sslv2 }`.
pub(crate) fn t6_client_hello_wants_sslv2(overrides: &[MessageOverrides]) -> bool {
    collect_overrides(overrides, MessageKind::ClientHello)
        .iter()
        .any(|o| matches!((o.field.as_str(), &o.value), ("format", FieldValue::Ident(f)) if f == "sslv2"))
}

/// The `cipher_suites` override, when the step carries one.
fn t6_cipher_suites_override(overrides: &[MessageOverrides]) -> Option<Vec<u16>> {
    collect_overrides(overrides, MessageKind::ClientHello)
        .iter()
        .find_map(|o| match (o.field.as_str(), &o.value) {
            ("cipher_suites", FieldValue::U16List(v)) => Some(v.clone()),
            _ => None,
        })
}

/// `send Heartbeat { type, payload, padding, payload_length }` resolved:
/// (type, payload, padding bytes, the length FIELD when it lies).
pub(crate) fn t6_heartbeat_from_overrides(
    overrides: &[crate::ir::FieldOverride],
) -> Result<(u8, Vec<u8>, usize, Option<u16>), TlsError> {
    use crate::tls::codec::{HEARTBEAT_MIN_PADDING, HEARTBEAT_REQUEST, HEARTBEAT_RESPONSE};
    let mut msg_type = HEARTBEAT_REQUEST;
    let mut payload: Vec<u8> = Vec::new();
    let mut padding = HEARTBEAT_MIN_PADDING;
    let mut length_field = None;
    for o in overrides {
        match (o.field.as_str(), &o.value) {
            ("type", FieldValue::Ident(t)) => {
                msg_type = match t.as_str() {
                    "request" => HEARTBEAT_REQUEST,
                    "response" => HEARTBEAT_RESPONSE,
                    _ => {
                        return Err(TlsError::Internal(
                            "Heartbeat.type takes `request` or `response`",
                        ));
                    }
                }
            }
            ("payload", FieldValue::Bytes(b)) => payload = b.clone(),
            ("padding", FieldValue::U16(n)) => padding = *n as usize,
            ("payload_length", FieldValue::U16(n)) => length_field = Some(*n),
            ("padding_min", _) => {}
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Heartbeat",
                    field: o.field.clone(),
                });
            }
        }
    }
    Ok((msg_type, payload, padding, length_field))
}

/// `recv Heartbeat { type, payload, padding_min }` matchers.
pub(crate) fn t6_match_heartbeat(
    hb: &crate::tls::codec::Heartbeat,
    matchers: &[crate::ir::FieldOverride],
) -> Result<(), TlsError> {
    use crate::tls::codec::{HEARTBEAT_REQUEST, HEARTBEAT_RESPONSE};
    for m in matchers {
        match (m.field.as_str(), &m.value) {
            ("type", FieldValue::Ident(want)) => {
                let want_v = if want == "request" {
                    HEARTBEAT_REQUEST
                } else {
                    HEARTBEAT_RESPONSE
                };
                if hb.msg_type != want_v {
                    return Err(TlsError::MatcherFailed {
                        message: "Heartbeat",
                        field: "type".into(),
                        expected: want.clone(),
                        observed: format!("{}", hb.msg_type),
                    });
                }
            }
            ("payload", FieldValue::Bytes(want)) => {
                if &hb.payload != want {
                    return Err(TlsError::MatcherFailed {
                        message: "Heartbeat",
                        field: "payload".into(),
                        expected: format!("{:02x?}", want),
                        observed: format!("{:02x?}", hb.payload),
                    });
                }
            }
            ("padding_min", FieldValue::U16(n)) => {
                if hb.padding.len() < *n as usize {
                    return Err(TlsError::MatcherFailed {
                        message: "Heartbeat",
                        field: "padding_min".into(),
                        expected: format!(">= {} bytes", n),
                        observed: format!("{} bytes", hb.padding.len()),
                    });
                }
            }
            _ => {
                return Err(TlsError::UnknownFieldOverride {
                    message: "Heartbeat",
                    field: m.field.clone(),
                });
            }
        }
    }
    Ok(())
}

/// `recv Certificate { compressed: 0 | 1 }` (plzn's TLS 1.3 client).
fn t6_check_certificate_compressed(
    was_compressed: bool,
    matchers: &[crate::ir::FieldOverride],
) -> Result<(), TlsError> {
    for m in matchers {
        if let ("compressed", FieldValue::U8(want)) = (m.field.as_str(), &m.value) {
            if (*want != 0) != was_compressed {
                return Err(TlsError::MatcherFailed {
                    message: "Certificate",
                    field: "compressed".into(),
                    expected: if *want != 0 {
                        "a CompressedCertificate"
                    } else {
                        "a plain Certificate"
                    }
                    .into(),
                    observed: if was_compressed {
                        "a CompressedCertificate"
                    } else {
                        "a plain Certificate"
                    }
                    .into(),
                });
            }
        }
    }
    Ok(())
}

/// Read one record for `recv Heartbeat`: the peer's alert is surfaced, an
/// empty application record and a NewSessionTicket are skipped, anything but
/// a heartbeat record is a content-type mismatch.
fn t6_read_heartbeat_record(
    records: &mut RecordLayer,
) -> Result<crate::tls::codec::Heartbeat, TlsError> {
    use crate::tls::codec::{CONTENT_TYPE_HEARTBEAT, HS_NEW_SESSION_TICKET};
    loop {
        let (ct, body) = records.read_record()?;
        if ct == crate::tls::codec::CONTENT_TYPE_ALERT && body.len() == 2 {
            return Err(TlsError::Record(RecordError::RemoteAlert {
                level: body[0],
                description: body[1],
            }));
        }
        if ct == crate::tls::codec::CONTENT_TYPE_APP_DATA && body.is_empty() {
            continue;
        }
        if ct == CONTENT_TYPE_HANDSHAKE && body.first() == Some(&HS_NEW_SESSION_TICKET) {
            continue;
        }
        if ct != CONTENT_TYPE_HEARTBEAT {
            return Err(TlsError::Record(RecordError::UnexpectedContentType {
                expected: CONTENT_TYPE_HEARTBEAT,
                got: ct,
            }));
        }
        return crate::tls::codec::decode_heartbeat(&body).map_err(TlsError::Codec);
    }
}

/// Encode a heartbeat record body from the step's overrides and mutations.
pub(crate) fn t6_heartbeat_record_body(
    overrides: &[MessageOverrides],
    mutations: &[MessageMutations],
) -> Result<(Vec<u8>, Vec<Mutation>), TlsError> {
    let (msg_type, payload, padding, length_field) =
        t6_heartbeat_from_overrides(collect_overrides(overrides, MessageKind::Heartbeat))?;
    let encoded =
        crate::tls::codec::encode_heartbeat_mapped(msg_type, &payload, padding, length_field);
    let muts = collect_mutations(mutations, MessageKind::Heartbeat).to_vec();
    let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, &muts)
        .map_err(|_| TlsError::Internal("Heartbeat mutation failed"))?;
    Ok((body, muts))
}

impl Tls12Client {
    /// `send Heartbeat`: a heartbeat record (RFC 6520 4) under the current
    /// write keys -- plaintext during the handshake, encrypted after it.
    fn send_heartbeat(&mut self) -> Result<(), TlsError> {
        let (body, muts) =
            t6_heartbeat_record_body(&self.cfg.send_overrides, &self.cfg.send_mutations)?;
        self.records.write_record_with_mutations(
            crate::tls::codec::CONTENT_TYPE_HEARTBEAT,
            &body,
            &muts,
        )?;
        Ok(())
    }

    /// `recv Heartbeat { type, payload, padding_min }`.
    fn recv_heartbeat(&mut self) -> Result<(), TlsError> {
        let hb = t6_read_heartbeat_record(&mut self.records)?;
        t6_match_heartbeat(
            &hb,
            collect_overrides(&self.cfg.recv_matchers, MessageKind::Heartbeat),
        )
    }

    /// `recv CertificateStatus { status_type: ocsp }` (RFC 6066 8): the
    /// stapled OCSP response the server sends after its Certificate.
    fn recv_certificate_status(&mut self) -> Result<(), TlsError> {
        let body = self.read_handshake(crate::tls::codec::HS_CERTIFICATE_STATUS)?;
        let cs = crate::tls::codec::decode_certificate_status_body(&body)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateStatus) {
            match (m.field.as_str(), &m.value) {
                ("status_type", FieldValue::Ident(want)) if want == "ocsp" => {
                    if cs.status_type != crate::tls::codec::CERT_STATUS_TYPE_OCSP {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateStatus",
                            field: "status_type".into(),
                            expected: "ocsp (1)".into(),
                            observed: format!("{}", cs.status_type),
                        });
                    }
                    if !crate::tls::codec::ocsp_response_is_successful(&cs.response) {
                        return Err(TlsError::MatcherFailed {
                            message: "CertificateStatus",
                            field: "response".into(),
                            expected: "a successful OCSPResponse (RFC 6960 4.2.1)".into(),
                            observed: format!(
                                "{} bytes that do not parse as one",
                                cs.response.len()
                            ),
                        });
                    }
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CertificateStatus",
                        field: m.field.clone(),
                    });
                }
            }
        }
        if cs.response.is_empty() {
            return Err(TlsError::Internal(
                "CertificateStatus carries an empty response",
            ));
        }
        Ok(())
    }

    /// `send ClientHello raw "HEX"`: the literal body goes out as the hello;
    /// the state the rest of the handshake needs (client random, offered
    /// suites, the encrypt_then_mac offer) is read back out of it, so a TLS
    /// 1.2 handshake can run to completion on a replayed fingerprint.
    fn send_client_hello_raw(&mut self, body: Vec<u8>) -> Result<(), TlsError> {
        let ch = crate::tls::codec::decode_client_hello_body(&body)?;
        self.client_random = ch.random;
        self.client_hello_version = ch.legacy_version;
        self.offered_suites = ch.cipher_suites.clone();
        self.offered_etm = ch
            .extensions
            .iter()
            .any(|e| e.wire_type() == crate::tls::codec::EXT_ENCRYPT_THEN_MAC);
        let encoded = crate::tls::codec::EncodedBody {
            bytes: body.clone(),
            fields: Default::default(),
        };
        let ch_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello);
        let body = mutate::apply_handshake_mutations(body, &encoded, ch_muts)
            .map_err(|_| TlsError::Internal("ClientHello mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &body);
        mutate::apply_handshake_header_mutations(&mut framed, ch_muts);
        self.transcript.update(&framed);
        self.raw_transcript.extend_from_slice(&framed);
        self.records
            .write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, &framed, ch_muts)?;
        Ok(())
    }

    /// `send ClientHello { format: sslv2 }`: the SSLv2-compatible CLIENT-HELLO
    /// of RFC 5246 E.2 (an SSLv2 record, no extensions, the 32-byte challenge
    /// as the client random). The handshake hash covers the CLIENT-HELLO
    /// without its 2-byte record header; the server answers in TLS records.
    fn send_client_hello_sslv2(&mut self) -> Result<(), TlsError> {
        let suites = t6_cipher_suites_override(&self.cfg.send_overrides)
            .unwrap_or_else(|| self.cfg.cipher_suites.clone());
        let version = collect_overrides(&self.cfg.send_overrides, MessageKind::ClientHello)
            .iter()
            .find_map(|o| match (o.field.as_str(), &o.value) {
                ("legacy_version", FieldValue::U16(v)) => Some(*v),
                _ => None,
            })
            .unwrap_or(PROTOCOL_VERSION_TLS12);
        // `cipher_specs:` bytes carry genuine 3-byte SSLv2 specs (0x010080
        // ...) that no u16 suite list can; else the TLS suites, zero-prefixed.
        let specs = collect_overrides(&self.cfg.send_overrides, MessageKind::ClientHello)
            .iter()
            .find_map(|o| match (o.field.as_str(), &o.value) {
                ("cipher_specs", FieldValue::Bytes(b)) => Some(b.clone()),
                _ => None,
            })
            .unwrap_or_else(|| crate::tls::codec::sslv2_cipher_specs(&suites));
        let (record, body) =
            crate::tls::codec::encode_sslv2_client_hello(version, &specs, &self.client_random);
        self.client_hello_version = version;
        self.offered_suites = suites;
        self.transcript.update(&body);
        self.raw_transcript.extend_from_slice(&body);
        self.records.write_raw(&record)?;
        Ok(())
    }
}

impl Tls13Client {
    fn send_heartbeat(&mut self) -> Result<(), TlsError> {
        let (body, muts) =
            t6_heartbeat_record_body(&self.cfg.send_overrides, &self.cfg.send_mutations)?;
        self.records.write_record_with_mutations(
            crate::tls::codec::CONTENT_TYPE_HEARTBEAT,
            &body,
            &muts,
        )?;
        Ok(())
    }

    fn recv_heartbeat(&mut self) -> Result<(), TlsError> {
        let hb = t6_read_heartbeat_record(&mut self.records)?;
        t6_match_heartbeat(
            &hb,
            collect_overrides(&self.cfg.recv_matchers, MessageKind::Heartbeat),
        )
    }

    /// `send ClientHello raw "HEX"` (TLS 1.3 driver): the literal hello; the
    /// key shares inside it are not plzn's, so the flow stops at the
    /// ServerHello (a fingerprint replay checks the server's answer).
    fn send_client_hello_raw(&mut self, body: Vec<u8>) -> Result<(), TlsError> {
        let ch = crate::tls::codec::decode_client_hello_body(&body)?;
        self.client_random = ch.random;
        self.offered_suites = ch.cipher_suites.clone();
        let encoded = crate::tls::codec::EncodedBody {
            bytes: body.clone(),
            fields: Default::default(),
        };
        let ch_muts = collect_mutations(&self.cfg.send_mutations, MessageKind::ClientHello);
        let body = mutate::apply_handshake_mutations(body, &encoded, ch_muts)
            .map_err(|_| TlsError::Internal("ClientHello mutation failed"))?;
        let mut framed = encode_handshake(HS_CLIENT_HELLO, &body);
        mutate::apply_handshake_header_mutations(&mut framed, ch_muts);
        self.transcript.update(&framed);
        self.raw_transcript.extend_from_slice(&framed);
        self.last_client_hello_framed = Some(framed.clone());
        self.raw_hello_replay = true;
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::ClientHello,
            &framed,
            ch_muts,
        )?;
        Ok(())
    }

    /// `recv CompressedCertificate { algorithm }`: the server MUST have
    /// compressed (RFC 8879 4); the algorithm label is checked, then the
    /// message is decompressed and handled as the Certificate it carries.
    fn recv_compressed_certificate_13(&mut self) -> Result<(), TlsError> {
        let (_t, raw) =
            self.read_framed_handshake_oneof(&[crate::tls::codec::HS_COMPRESSED_CERTIFICATE])?;
        let algorithm =
            crate::tls::codec::compressed_certificate_algorithm(&raw).map_err(TlsError::Codec)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::CompressedCertificate) {
            match (m.field.as_str(), &m.value) {
                ("algorithm", FieldValue::U16(want)) => {
                    if algorithm != *want {
                        return Err(TlsError::MatcherFailed {
                            message: "CompressedCertificate",
                            field: "algorithm".into(),
                            expected: format!("{}", want),
                            observed: format!("{}", algorithm),
                        });
                    }
                }
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CompressedCertificate",
                        field: m.field.clone(),
                    });
                }
            }
        }
        let cert_body =
            crate::tls::codec::decompress_certificate_13(&raw).map_err(TlsError::Codec)?;
        let cert = decode_certificate_13_body(&cert_body)?;
        for m in collect_overrides(&self.cfg.recv_matchers, MessageKind::Certificate) {
            if m.field == "compressed" {
                continue;
            }
            match_certificate_13_field(&cert, m, self.negotiated_server_cert_type)?;
        }
        let leaf = cert
            .entries
            .into_iter()
            .next()
            .ok_or(TlsError::CertificateListEmpty)?;
        self.server_pubkey = Some(PublicKey::from_certificate_entry(
            &leaf.cert_data,
            self.negotiated_server_cert_type,
        )?);
        Ok(())
    }

    /// The client's Certificate body for a (post-)handshake request:
    /// the configured credential (leaf + extra chain) or, with `credential:
    /// none`, an empty certificate_list; with the request context given.
    fn t6_client_certificate_body(&self, kind: MessageKind, context: &[u8]) -> Vec<u8> {
        self.t6_client_certificate_body_mapped(kind, context).bytes
    }

    /// As `t6_client_certificate_body`, keeping the field map so `send
    /// Certificate @ xor[handshake.certificate_list, ...]` resolves on the
    /// post-handshake form too. A non-empty request context shifts every
    /// range after the context length byte.
    fn t6_client_certificate_body_mapped(
        &self,
        kind: MessageKind,
        context: &[u8],
    ) -> crate::tls::codec::EncodedBody {
        let none = collect_overrides(&self.cfg.send_overrides, kind)
            .iter()
            .any(|o| matches!((o.field.as_str(), &o.value), ("credential", FieldValue::Ident(c)) if c == "none"));
        let mut chain: Vec<&[u8]> = Vec::new();
        if !none {
            if let Some(cert) = &self.cfg.client_cert_der {
                chain.push(cert.as_slice());
                for c in &self.cfg.client_extra_chain_der {
                    chain.push(c);
                }
            }
        }
        let mut leaf_extensions: Vec<Extension> = Vec::new();
        apply_ext_deltas(
            &mut leaf_extensions,
            collect_ext_deltas(&self.cfg.send_ext_deltas, MessageKind::Certificate),
        );
        let encoded = crate::tls::codec::encode_certificate_13_body_with_leaf_extensions_mapped(
            &chain,
            &leaf_extensions,
        );
        if context.is_empty() {
            return encoded;
        }
        // Re-frame with the request context (the mapped encoder writes an
        // empty one): context<0..255> then the list as encoded.
        let shift = context.len();
        let mut bytes = Vec::with_capacity(encoded.bytes.len() + shift);
        bytes.push(shift as u8);
        bytes.extend_from_slice(context);
        bytes.extend_from_slice(&encoded.bytes[1..]);
        let mut fields: std::collections::HashMap<String, std::ops::Range<usize>> = encoded
            .fields
            .into_iter()
            .map(|(name, r)| {
                if r.end <= 1 {
                    (name, r)
                } else {
                    (name, r.start + shift..r.end + shift)
                }
            })
            .collect();
        fields.insert("request_context".to_string(), 1..1 + shift);
        crate::tls::codec::EncodedBody { bytes, fields }
    }

    /// `send CompressedCertificate { algorithm, uncompressed_length, payload,
    /// payload_zeros, bomb, credential }` (RFC 8879 4): the client's
    /// Certificate, zlib-compressed unless a payload is given, with the
    /// algorithm label and the length field free to lie. Replaces `send
    /// Certificate` in an anchored client-auth flow; CertificateVerify then
    /// signs a transcript that contains the compressed message as sent.
    fn send_client_compressed_certificate(&mut self) -> Result<(), TlsError> {
        use crate::tls::codec::{CERT_COMPRESSION_ZLIB, zlib_bomb, zlib_compress};
        let context: Vec<u8> = self
            .pha
            .as_ref()
            .map(|p| p.context.clone())
            .unwrap_or_default();
        let cert_body =
            self.t6_client_certificate_body(MessageKind::CompressedCertificate, &context);
        let mut algorithm = CERT_COMPRESSION_ZLIB;
        let mut uncompressed_length: Option<u32> = None;
        let mut payload: Option<Vec<u8>> = None;
        for o in collect_overrides(&self.cfg.send_overrides, MessageKind::CompressedCertificate) {
            match (o.field.as_str(), &o.value) {
                ("algorithm", FieldValue::U16(a)) => algorithm = *a,
                ("uncompressed_length", FieldValue::U32(n)) => uncompressed_length = Some(*n),
                ("payload", FieldValue::Bytes(b)) => payload = Some(b.clone()),
                ("payload_zeros", FieldValue::U32(n)) => payload = Some(vec![0u8; *n as usize]),
                ("bomb", FieldValue::U16(mib)) => payload = Some(zlib_bomb(*mib as u32)),
                ("credential", _) => {}
                _ => {
                    return Err(TlsError::UnknownFieldOverride {
                        message: "CompressedCertificate",
                        field: o.field.clone(),
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
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|_| TlsError::Internal("CompressedCertificate mutation failed"))?;
        let mut framed = encode_handshake(crate::tls::codec::HS_COMPRESSED_CERTIFICATE, &body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        match self.pha.as_mut() {
            Some(p) => p.transcript.update(&framed),
            None => self.transcript.update(&framed),
        }
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::CompressedCertificate,
            &framed,
            muts,
        )?;
        Ok(())
    }

    /// Read the next post-handshake handshake message of one of `accepted`
    /// types, absorbing NewSessionTickets (captured) and KeyUpdates (read keys
    /// rotated, a reply owed when requested) on the way; returns the framed
    /// message and its body without touching the handshake transcript.
    fn t6_read_post_handshake(
        &mut self,
        accepted: &[u8],
    ) -> Result<(u8, Vec<u8>, Vec<u8>), TlsError> {
        loop {
            let header = self.records.read_handshake_bytes(4)?;
            let mut cursor = ByteCursor::new(&header);
            let (msg_type, body_len) = parse_handshake_header(&mut cursor)?;
            let body = self.records.read_handshake_bytes(body_len)?;
            if msg_type == HS_NEW_SESSION_TICKET && !accepted.contains(&HS_NEW_SESSION_TICKET) {
                if let Ok(nst) = decode_new_session_ticket_13_body(&body) {
                    self.captured_nst = Some(nst);
                }
                continue;
            }
            if msg_type == HS_KEY_UPDATE && !accepted.contains(&HS_KEY_UPDATE) {
                let request_update = decode_key_update_body(&body)?;
                self.rotate_read_keys()?;
                if request_update == 1 {
                    self.key_update_response_pending = true;
                }
                continue;
            }
            if !accepted.contains(&msg_type) {
                return Err(TlsError::UnexpectedHandshake {
                    expected: accepted[0],
                    got: msg_type,
                });
            }
            let mut framed = Vec::with_capacity(4 + body.len());
            framed.extend_from_slice(&header);
            framed.extend_from_slice(&body);
            return Ok((msg_type, framed, body));
        }
    }

    /// A post-handshake CertificateRequest (RFC 8446 4.6.2): its context is
    /// remembered and the PHA transcript opened (handshake transcript through
    /// our Finished, then the request). `recv CertificateRequest { has_ext /
    /// lacks_ext / ... }` matchers apply as during the handshake.
    fn recv_post_handshake_certificate_request(&mut self) -> Result<(), TlsError> {
        let (_t, framed, body) = self.t6_read_post_handshake(&[HS_CERTIFICATE_REQUEST])?;
        let context = decode_certificate_request_13_body(&body)?;
        let matchers = collect_overrides(&self.cfg.recv_matchers, MessageKind::CertificateRequest);
        if !matchers.is_empty() {
            let cr = crate::tls::codec::decode_certificate_request_13_full(&body)?;
            for m in matchers {
                match_certificate_request_field(&cr, m)?;
            }
        }
        // RFC 8446 4.6.2: the context "MUST be unique for each request" and
        // non-empty in a post-handshake request (4.3.2).
        if context.is_empty() {
            return Err(TlsError::Internal(
                "post-handshake CertificateRequest carries an empty certificate_request_context (RFC 8446 4.3.2)",
            ));
        }
        let mut transcript =
            self.post_client_finished_transcript
                .clone()
                .ok_or(TlsError::Internal(
                    "post-handshake authentication before the handshake completed",
                ))?;
        transcript.update(&framed);
        self.pha = Some(PhaState {
            context,
            transcript,
        });
        Ok(())
    }

    /// PHA Certificate: the credential (or `credential: none`) with the
    /// request's context, under the application keys.
    fn send_pha_certificate(&mut self) -> Result<(), TlsError> {
        let context = self
            .pha
            .as_ref()
            .map(|p| p.context.clone())
            .unwrap_or_default();
        let encoded = self.t6_client_certificate_body_mapped(MessageKind::Certificate, &context);
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Certificate);
        let cert_body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|_| TlsError::Internal("client Certificate mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE, &cert_body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        if let Some(p) = self.pha.as_mut() {
            p.transcript.update(&framed);
        }
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::Certificate,
            &framed,
            muts,
        )?;
        Ok(())
    }

    /// PHA CertificateVerify: signs the PHA transcript hash with the client
    /// context string (RFC 8446 4.4.3), mutations as on the handshake form.
    fn send_pha_certificate_verify(&mut self) -> Result<(), TlsError> {
        let Some(der) = self.cfg.client_private_key_der.clone() else {
            return Ok(());
        };
        let pk = crate::tls::crypto::PrivateKey::from_pkcs8_der(&der)?;
        let sig_scheme = pk.default_signature_scheme();
        let transcript_hash =
            self.pha
                .as_ref()
                .map(|p| p.transcript.digest())
                .ok_or(TlsError::Internal(
                    "no post-handshake CertificateRequest to answer",
                ))?;
        let signed_input = tls13_client_certificate_verify_signed_input(&transcript_hash);
        let signature = pk.sign(sig_scheme, &signed_input)?;
        let encoded = crate::tls::codec::encode_certificate_verify_13_body_mapped(
            sig_scheme.wire_value(),
            &signature,
        );
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::CertificateVerify);
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|_| TlsError::Internal("client CertificateVerify mutation failed"))?;
        let mut framed = encode_handshake(HS_CERTIFICATE_VERIFY, &body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        if let Some(p) = self.pha.as_mut() {
            p.transcript.update(&framed);
        }
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::CertificateVerify,
            &framed,
            muts,
        )?;
        Ok(())
    }

    /// PHA Finished: HMAC over the PHA transcript under the finished key of
    /// the CURRENT client_application_traffic_secret (RFC 8446 4.4.4's base
    /// key for a post-handshake Finished, so a KeyUpdate sent in between
    /// changes it); closes the exchange.
    fn send_pha_finished(&mut self) -> Result<(), TlsError> {
        let transcript_hash =
            self.pha
                .as_ref()
                .map(|p| p.transcript.digest())
                .ok_or(TlsError::Internal(
                    "no post-handshake CertificateRequest to answer",
                ))?;
        let client_ap = self
            .schedule
            .client_ap_traffic_secret
            .clone()
            .ok_or(TlsError::Internal("client ap traffic secret missing"))?;
        let mut verify_data = self.schedule.compute_finished(&client_ap, &transcript_hash);
        for ov in collect_overrides(&self.cfg.send_overrides, MessageKind::Finished).to_vec() {
            apply_finished_override(&mut verify_data, &ov)?;
        }
        let encoded = encode_finished_body_mapped(&verify_data);
        let muts = collect_mutations(&self.cfg.send_mutations, MessageKind::Finished);
        let body = mutate::apply_handshake_mutations(encoded.bytes.clone(), &encoded, muts)
            .map_err(|_| TlsError::Internal("Finished mutation failed"))?;
        let mut framed = encode_handshake(HS_FINISHED, &body);
        mutate::apply_handshake_header_mutations(&mut framed, muts);
        write_tls13_handshake_message(
            &mut self.records,
            &self.cfg.send_mutations,
            MessageKind::Finished,
            &framed,
            muts,
        )?;
        self.pha = None;
        Ok(())
    }
}

#[cfg(test)]
mod tls12_certificate_auth_tests {
    use super::{
        KeyKind, Tls12Client, Tls12ClientConfig, TlsError, validate_tls12_server_certificate_key,
    };
    use crate::server::certs::{CertBundle, KeyType};
    use crate::tls::codec::{
        CONTENT_TYPE_HANDSHAKE, HS_CERTIFICATE, PROTOCOL_VERSION_TLS12,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_128_GCM_SHA256, encode_certificate_12_body, encode_handshake,
    };
    use crate::transport::MockTransport;

    const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009e;

    fn receive_certificate(suite: u16, key_type: KeyType) -> Result<(), TlsError> {
        let bundle = CertBundle::generate(key_type).expect("generate certificate");
        let body = encode_certificate_12_body(&[bundle.cert_der.as_slice()]);
        let handshake = encode_handshake(HS_CERTIFICATE, &body);
        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&PROTOCOL_VERSION_TLS12.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let transport = MockTransport::new("tls12-certificate-auth");
        transport.push_incoming(&record);
        let cfg = Tls12ClientConfig::default_for("localhost", [0x42; 32]);
        let mut client = Tls12Client::new(Box::new(transport), cfg);
        client.negotiated_suite = suite;
        client.recv_certificate()
    }

    #[test]
    fn certificate_key_kind_must_fit_the_suite_authentication_family() {
        for rsa in [KeyKind::Rsa, KeyKind::RsaPss] {
            assert!(
                validate_tls12_server_certificate_key(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, rsa,)
                    .is_ok()
            );
            assert!(
                validate_tls12_server_certificate_key(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, rsa,)
                    .is_ok()
            );
            assert!(validate_tls12_server_certificate_key(
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rsa,
            )
            .is_err());
        }
        assert!(
            validate_tls12_server_certificate_key(TLS_RSA_WITH_AES_128_GCM_SHA256, KeyKind::Rsa,)
                .is_ok()
        );
        assert!(validate_tls12_server_certificate_key(
            TLS_RSA_WITH_AES_128_GCM_SHA256,
            KeyKind::RsaPss,
        )
        .is_err());

        for ecdsa in [
            KeyKind::EcdsaP256,
            KeyKind::EcdsaP384,
            KeyKind::EcdsaP521,
            KeyKind::Ed25519,
        ] {
            assert!(
                validate_tls12_server_certificate_key(
                    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    ecdsa,
                )
                .is_ok()
            );
            assert!(validate_tls12_server_certificate_key(
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                ecdsa,
            )
            .is_err());
        }
    }

    #[test]
    fn certificate_handler_rejects_both_cross_family_pairings() {
        for (suite, key_type) in [
            (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, KeyType::EcdsaP256),
            (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, KeyType::Rsa2048),
        ] {
            match receive_certificate(suite, key_type) {
                Err(TlsError::Rejected { alert: 43, reason }) => {
                    assert!(reason.contains("cannot authenticate cipher suite"));
                    assert!(reason.contains("RFC 5246 7.4.2"));
                }
                other => panic!("expected unsupported_certificate, got {other:?}"),
            }
        }
    }

    #[test]
    fn certificate_handler_keeps_valid_rsa_and_ecdsa_pairings() {
        assert!(
            receive_certificate(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, KeyType::Rsa2048,).is_ok()
        );
        assert!(
            receive_certificate(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, KeyType::EcdsaP256,)
                .is_ok()
        );
    }
}

#[cfg(test)]
mod client_hello_matcher_tests {
    use super::{
        KeySharePoint, encode_key_share_point, is_rfc10015_prohibited_suite,
        key_share_point_recipe, match_certificate_verify_field, match_client_hello_field,
        match_server_hello_field, validate_tls13_hrr_cipher_suite,
    };
    use crate::ast::Span;
    use crate::ir::{FieldOverride, FieldValue};
    use crate::tls::codec::{
        ClientHelloDecoded, Extension, GROUP_SECP256R1, GROUP_SECP384R1, KeyShareEntry, ServerHello,
    };

    fn ch() -> ClientHelloDecoded {
        ClientHelloDecoded {
            legacy_version: 0x0303,
            random: [0x11; 32],
            session_id: vec![0xab, 0xcd],
            cipher_suites: vec![0x1301, 0x1302, 0xc02f],
            compression_methods: vec![0x00],
            extensions: Vec::new(),
        }
    }

    fn m(field: &str, value: FieldValue) -> FieldOverride {
        FieldOverride {
            field: field.into(),
            value,
            span: Span::dummy(),
        }
    }

    #[test]
    fn explicit_finished_matcher_is_enforced() {
        use crate::ir::{MessageKind, MessageOverrides};
        let matchers = vec![MessageOverrides {
            message: MessageKind::Finished,
            fields: vec![m("verify_data", FieldValue::Bytes(vec![1, 2, 3]))],
        }];
        assert!(super::match_finished_fields(&[1, 2, 3], &matchers).is_ok());
        assert!(matches!(
            super::match_finished_fields(&[3, 2, 1], &matchers),
            Err(super::TlsError::MatcherFailed { .. })
        ));
    }

    #[test]
    fn tls13_change_cipher_spec_applies_record_mutations() {
        use super::{Tls13Client, Tls13ClientConfig};
        use crate::ir::{MessageKind, MessageMutations, Mutation, MutationOp};
        let transport = crate::transport::MockTransport::new("CCS version override");
        let mut cfg = Tls13ClientConfig::default_for("example.test", [7; 32]);
        cfg.send_mutations.push(MessageMutations {
            message: MessageKind::ChangeCipherSpec,
            dtls_frag: None,
            mutations: vec![Mutation {
                span: Span::dummy(),
                op: MutationOp::RecordVersion(0x7f03),
            }],
        });
        let mut client = Tls13Client::new(Box::new(transport.clone()), cfg);
        client.send_change_cipher_spec().unwrap();
        assert_eq!(transport.take_written(), vec![20, 0x7f, 3, 0, 1, 1]);
    }

    #[test]
    fn cookie_only_hrr_preserves_the_original_key_share() {
        use super::{Tls13Client, Tls13ClientConfig};
        use crate::tls::codec::{
            HRR_RANDOM, ServerHelloBuilder, decode_client_hello_body, encode_handshake,
            encode_server_hello_body,
        };
        let transport = crate::transport::MockTransport::new("cookie retry");
        let mut client = Tls13Client::new(
            Box::new(transport.clone()),
            Tls13ClientConfig::default_for("example.test", [7; 32]),
        );
        client
            .do_handshake_step(&crate::ir::HandshakeStep::Send(
                crate::ir::MessageKind::ClientHello,
            ))
            .unwrap();
        let first = transport.take_written();
        let first = decode_client_hello_body(&first[9..]).unwrap();
        let hrr = encode_server_hello_body(&ServerHelloBuilder {
            legacy_version: 0x0303,
            random: HRR_RANDOM,
            session_id: first.session_id.clone(),
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![
                Extension::SupportedVersionsSingle(0x0304),
                Extension::Unknown {
                    ty: 44,
                    data: vec![0, 2, 7, 8],
                },
            ],
        });
        let mut writer = crate::tls::record::RecordLayer::new(
            Box::new(transport.clone()),
            crate::tls::record::TlsVersion::Tls13,
        );
        writer.write_record(22, &encode_handshake(2, &hrr)).unwrap();
        transport.push_incoming(&transport.take_written());
        client
            .do_handshake_step(&crate::ir::HandshakeStep::Recv(
                crate::ir::MessageKind::HelloRetryRequest,
            ))
            .unwrap();
        client
            .do_handshake_step(&crate::ir::HandshakeStep::Send(
                crate::ir::MessageKind::ClientHello,
            ))
            .unwrap();
        let retry = transport.take_written();
        let retry = decode_client_hello_body(&retry[9..]).unwrap();
        let share = |hello: &crate::tls::codec::ClientHelloDecoded| {
            hello
                .extensions
                .iter()
                .find_map(|ext| match ext {
                    Extension::KeyShare(entries) => Some(
                        entries
                            .iter()
                            .map(|entry| (entry.group, entry.key_exchange.clone()))
                            .collect::<Vec<_>>(),
                    ),
                    _ => None,
                })
                .unwrap()
        };
        assert_eq!(share(&first), share(&retry));
        assert!(retry.extensions.iter().any(
            |ext| matches!(ext, Extension::Unknown { ty: 44, data } if data == &[0, 2, 7, 8])
        ));
    }

    #[test]
    fn final_server_hello_must_keep_the_hrr_cipher_suite() {
        assert!(validate_tls13_hrr_cipher_suite(None, 0x1303).is_ok());
        assert!(validate_tls13_hrr_cipher_suite(Some(0x1301), 0x1301).is_ok());
        match validate_tls13_hrr_cipher_suite(Some(0x1301), 0x1303) {
            Err(super::TlsError::Rejected { alert: 47, reason }) => {
                assert!(reason.contains("differs from HelloRetryRequest"));
                assert!(reason.contains("RFC 9846 4.2.4"));
            }
            other => panic!("expected illegal_parameter rejection, got {other:?}"),
        }
    }

    #[test]
    fn certificate_verify_algorithm_matcher_is_enforced() {
        let cv = crate::tls::codec::CertificateVerify13 {
            algorithm: 0x0804,
            signature: vec![1, 2, 3],
        };
        assert!(
            match_certificate_verify_field(&cv, &m("algorithm", FieldValue::U16(0x0804))).is_ok()
        );
        assert!(
            match_certificate_verify_field(&cv, &m("algorithm", FieldValue::U16(0x0403))).is_err()
        );
    }

    #[test]
    fn legacy_version_exact_match() {
        assert!(
            match_client_hello_field(&ch(), &m("legacy_version", FieldValue::U16(0x0303))).is_ok()
        );
        assert!(
            match_client_hello_field(&ch(), &m("legacy_version", FieldValue::U16(0x0304))).is_err()
        );
    }

    #[test]
    fn compression_methods_exact_list() {
        assert!(
            match_client_hello_field(
                &ch(),
                &m("compression_methods", FieldValue::U8List(vec![0x00]))
            )
            .is_ok()
        );
        // exact equality: a superset must NOT match
        assert!(
            match_client_hello_field(
                &ch(),
                &m("compression_methods", FieldValue::U8List(vec![0x00, 0x01]))
            )
            .is_err()
        );
    }

    #[test]
    fn cipher_suites_contains_all() {
        // present → ok
        assert!(
            match_client_hello_field(
                &ch(),
                &m("cipher_suites", FieldValue::U16List(vec![0x1301]))
            )
            .is_ok()
        );
        // all-present subset, order-independent → ok
        assert!(
            match_client_hello_field(
                &ch(),
                &m("cipher_suites", FieldValue::U16List(vec![0xc02f, 0x1301]))
            )
            .is_ok()
        );
        // one missing → err
        assert!(
            match_client_hello_field(
                &ch(),
                &m("cipher_suites", FieldValue::U16List(vec![0x1301, 0xdead]))
            )
            .is_err()
        );

        assert!(
            match_client_hello_field(&ch(), &m("lacks_cipher_suite", FieldValue::U16(0x5600)))
                .is_ok()
        );
        assert!(
            match_client_hello_field(&ch(), &m("lacks_cipher_suite", FieldValue::U16(0x1301)))
                .is_err()
        );
    }

    #[test]
    fn current_tls12_offer_policy_matchers() {
        let mut hello = ch();
        assert!(
            match_client_hello_field(
                &hello,
                &m(
                    "lacks_obsolete_key_exchange",
                    FieldValue::Ident("true".into())
                )
            )
            .is_ok()
        );
        hello.cipher_suites.push(0x009c);
        assert!(
            match_client_hello_field(
                &hello,
                &m(
                    "lacks_obsolete_key_exchange",
                    FieldValue::Ident("true".into())
                )
            )
            .is_err()
        );

        for prohibited in [
            0x000c, // static DH
            0x0040, // DHE_DSS
            0x00aa, // DHE_PSK
            0xc068, // RSA_PSK
            0xccad, // DHE_PSK with ChaCha20-Poly1305
        ] {
            assert!(is_rfc10015_prohibited_suite(prohibited));
        }
        for permitted in [
            0xc02f, // ECDHE_RSA
            0xc02d, // static ECDH is only SHOULD NOT
            0xd001, // ECDHE_PSK
            0x1301, // TLS 1.3 suite
        ] {
            assert!(!is_rfc10015_prohibited_suite(permitted));
        }

        hello.cipher_suites.retain(|suite| *suite != 0x009c);
        assert!(
            match_client_hello_field(
                &hello,
                &m(
                    "secure_renegotiation_signal",
                    FieldValue::Ident("true".into())
                )
            )
            .is_err()
        );
        hello.cipher_suites.push(0x00ff);
        assert!(
            match_client_hello_field(
                &hello,
                &m(
                    "secure_renegotiation_signal",
                    FieldValue::Ident("true".into())
                )
            )
            .is_ok()
        );
    }

    #[test]
    fn tls13_offer_structure_matchers() {
        let mut hello = ch();
        hello.extensions = vec![
            Extension::SupportedVersions(vec![0x0304, 0x0303]),
            Extension::SupportedGroups(vec![GROUP_SECP256R1, GROUP_SECP384R1]),
            Extension::KeyShare(vec![
                KeyShareEntry {
                    group: GROUP_SECP256R1,
                    key_exchange: vec![1; 65],
                },
                KeyShareEntry {
                    group: GROUP_SECP384R1,
                    key_exchange: vec![2; 97],
                },
            ]),
        ];
        for field in ["supported_groups_unique", "key_shares_consistent"] {
            assert!(
                match_client_hello_field(&hello, &m(field, FieldValue::Ident("true".into())))
                    .is_ok()
            );
        }
        assert!(
            match_client_hello_field(
                &hello,
                &m(
                    "supported_versions",
                    FieldValue::U16List(vec![0x0303, 0x0304])
                )
            )
            .is_ok()
        );
        assert!(
            match_client_hello_field(
                &hello,
                &m("lacks_supported_version", FieldValue::U16(0x0302))
            )
            .is_ok()
        );

        hello.extensions[1] = Extension::SupportedGroups(vec![GROUP_SECP256R1, GROUP_SECP256R1]);
        assert!(
            match_client_hello_field(
                &hello,
                &m("supported_groups_unique", FieldValue::Ident("true".into()))
            )
            .is_err()
        );
        assert!(
            match_client_hello_field(
                &hello,
                &m("key_shares_consistent", FieldValue::Ident("true".into()))
            )
            .is_err()
        );
    }

    #[test]
    fn random_and_session_id_exact() {
        assert!(
            match_client_hello_field(&ch(), &m("random", FieldValue::Bytes(vec![0x11; 32])))
                .is_ok()
        );
        assert!(
            match_client_hello_field(&ch(), &m("random", FieldValue::Bytes(vec![0x22; 32])))
                .is_err()
        );
        assert!(
            match_client_hello_field(
                &ch(),
                &m("legacy_session_id", FieldValue::Bytes(vec![0xab, 0xcd]))
            )
            .is_ok()
        );
        assert!(
            match_client_hello_field(&ch(), &m("session_id", FieldValue::Bytes(vec![0x00])))
                .is_err()
        );
    }

    #[test]
    fn server_hello_session_id_echo_exact() {
        let sh = ServerHello {
            legacy_version: 0x0303,
            random: [0x22; 32],
            session_id: vec![0xa5; 32],
            cipher_suite: 0xc02b,
            compression_method: 0,
            extensions: Vec::new(),
        };
        assert!(
            match_server_hello_field(
                &sh,
                &m("legacy_session_id_echo", FieldValue::Bytes(vec![0xa5; 32]))
            )
            .is_ok()
        );
        assert!(
            match_server_hello_field(
                &sh,
                &m("legacy_session_id_echo", FieldValue::Bytes(vec![0x5a; 32]))
            )
            .is_err()
        );
    }

    #[test]
    fn server_hello_selected_version_matcher() {
        let sh = ServerHello {
            legacy_version: 0x0303,
            random: [0x22; 32],
            session_id: vec![],
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![Extension::SupportedVersionsSingle(0x0304)],
        };
        assert!(
            match_server_hello_field(&sh, &m("selected_version", FieldValue::U16(0x0304))).is_ok()
        );
        assert!(
            match_server_hello_field(&sh, &m("selected_version", FieldValue::U16(0x0303))).is_err()
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert!(match_client_hello_field(&ch(), &m("nope", FieldValue::U16(1))).is_err());
    }

    #[test]
    fn key_share_point_recipes_resize_without_touching_the_key() {
        use crate::tls::crypto::{EcdheGroup, EcdhePrivate, Rng};
        let mut rng = Rng::from_seed([3u8; 32]);
        let eph = EcdhePrivate::generate(EcdheGroup::P256, &mut rng);
        let real = eph.public_bytes();
        assert_eq!(real.len(), 65);

        // Truncated / padded differ from the real point by exactly one byte, and
        // keep the real point as their prefix, so only the length is wrong.
        let t = encode_key_share_point(&eph, &KeySharePoint::Truncated).unwrap();
        assert_eq!(t.len(), real.len() - 1);
        assert_eq!(t[..], real[..real.len() - 1]);
        let p = encode_key_share_point(&eph, &KeySharePoint::Padded).unwrap();
        assert_eq!(p.len(), real.len() + 1);
        assert_eq!(p[..real.len()], real[..]);
        assert_eq!(*p.last().unwrap(), 0);

        // The other recipes, for contrast.
        assert_eq!(
            encode_key_share_point(&eph, &KeySharePoint::Real).unwrap(),
            real
        );
        assert!(
            encode_key_share_point(&eph, &KeySharePoint::Zero)
                .unwrap()
                .iter()
                .all(|b| *b == 0)
        );
        assert_eq!(
            encode_key_share_point(&eph, &KeySharePoint::Compressed)
                .unwrap()
                .len(),
            33
        );

        // Montgomery u-coordinates resize too, but have no compressed form.
        let x = EcdhePrivate::generate(EcdheGroup::X25519, &mut rng);
        assert_eq!(
            encode_key_share_point(&x, &KeySharePoint::Truncated)
                .unwrap()
                .len(),
            31
        );
        assert_eq!(
            encode_key_share_point(&x, &KeySharePoint::Padded)
                .unwrap()
                .len(),
            33
        );
        assert!(encode_key_share_point(&x, &KeySharePoint::Compressed).is_err());
        let x = EcdhePrivate::generate(EcdheGroup::X448, &mut rng);
        assert_eq!(
            encode_key_share_point(&x, &KeySharePoint::Truncated)
                .unwrap()
                .len(),
            55
        );
        assert_eq!(
            encode_key_share_point(&x, &KeySharePoint::Padded)
                .unwrap()
                .len(),
            57
        );
        assert!(encode_key_share_point(&x, &KeySharePoint::Compressed).is_err());

        // The RFC 8446 4.2.8.1 bounds exist only for finite-field groups: Y = 1 and
        // Y = p-1 at the prime's length; a curve has no such values.
        let f = EcdhePrivate::generate(EcdheGroup::Ffdhe2048, &mut rng);
        let one = encode_key_share_point(&f, &KeySharePoint::One).unwrap();
        assert_eq!(one.len(), 256);
        assert!(one[..255].iter().all(|b| *b == 0) && one[255] == 1);
        let pm1 = encode_key_share_point(&f, &KeySharePoint::PMinusOne).unwrap();
        let p = EcdheGroup::Ffdhe2048.ffdhe_prime().unwrap();
        assert_eq!(pm1.len(), 256);
        assert_eq!(pm1[..255], p[..255]);
        assert_eq!(pm1[255], p[255] - 1);
        assert!(encode_key_share_point(&eph, &KeySharePoint::One).is_err());
        assert!(encode_key_share_point(&x, &KeySharePoint::PMinusOne).is_err());
    }

    #[test]
    fn key_share_point_recipe_reads_the_override() {
        let ov = |name: &str| FieldOverride {
            field: "key_share_point".into(),
            value: FieldValue::Ident(name.into()),
            span: Span::dummy(),
        };
        assert_eq!(key_share_point_recipe(&[]).unwrap(), KeySharePoint::Real);
        assert_eq!(
            key_share_point_recipe(&[ov("truncated")]).unwrap(),
            KeySharePoint::Truncated
        );
        assert_eq!(
            key_share_point_recipe(&[ov("padded")]).unwrap(),
            KeySharePoint::Padded
        );
        assert_eq!(
            key_share_point_recipe(&[ov("compressed")]).unwrap(),
            KeySharePoint::Compressed
        );
        assert_eq!(
            key_share_point_recipe(&[ov("zero")]).unwrap(),
            KeySharePoint::Zero
        );
        assert_eq!(
            key_share_point_recipe(&[ov("one")]).unwrap(),
            KeySharePoint::One
        );
        assert_eq!(
            key_share_point_recipe(&[ov("p_minus_1")]).unwrap(),
            KeySharePoint::PMinusOne
        );
        assert!(key_share_point_recipe(&[ov("nonsense")]).is_err());
    }

    #[test]
    fn ext_delta_reverse_flips_order() {
        use super::apply_ext_deltas;
        use crate::ir::ExtDeltaOp;
        use crate::tls::codec::Extension;
        let mut exts = vec![
            Extension::Unknown {
                ty: 0x0001,
                data: vec![],
            },
            Extension::Unknown {
                ty: 0x0002,
                data: vec![],
            },
            Extension::Unknown {
                ty: 0x0003,
                data: vec![],
            },
        ];
        apply_ext_deltas(&mut exts, &[ExtDeltaOp::Reverse]);
        let order: Vec<u16> = exts.iter().map(|e| e.wire_type()).collect();
        assert_eq!(order, vec![0x0003, 0x0002, 0x0001]);
    }

    #[test]
    fn ext_delta_add_preserves_final_psk_position() {
        use super::apply_ext_deltas;
        use crate::ir::ExtDeltaOp;
        use crate::tls::codec::Extension;
        let mut exts = vec![
            Extension::Unknown {
                ty: 0x0001,
                data: vec![],
            },
            Extension::Unknown {
                ty: crate::tls::codec::EXT_PRE_SHARED_KEY,
                data: vec![],
            },
        ];
        apply_ext_deltas(
            &mut exts,
            &[ExtDeltaOp::Add {
                wire_type: 0x0010,
                body: vec![],
                dup: false,
            }],
        );
        let order: Vec<u16> = exts.iter().map(|e| e.wire_type()).collect();
        assert_eq!(
            order,
            vec![0x0001, 0x0010, crate::tls::codec::EXT_PRE_SHARED_KEY]
        );
    }
}
