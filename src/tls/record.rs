// TLS 1.2/1.3 and DTLS 1.3 record layer: frame messages, seal on
// write, AEAD-open on read.
//
// The RecordLayer owns a UutTransport (the byte pipe to the peer),
// the client/server traffic keys (installed mid-handshake), and
// sequence counters. Before the keys are installed every record is
// plaintext; after `install_*_keys` is called the corresponding
// direction encrypts or decrypts.
//
// Read side buffers the next record's payload internally and the
// handshake driver pulls handshake bytes out of that buffer. That
// also preserves post-handshake message framing and traffic-key boundaries.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read, Write};

use crate::ir::{CoalesceMode, DtlsFragScheme, FragHold, Mutation, MutationOp};
use crate::tls::mutate;

use crate::tls::codec::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APP_DATA, CONTENT_TYPE_CCS, CONTENT_TYPE_HANDSHAKE,
    LEGACY_RECORD_VERSION, RecordHeader,
};
use crate::tls::crypto::{AeadAlg, AeadKey, CbcCipher, CryptoError};
use crate::transport::UutTransport;

use crate::tls::dtls_handshake::{HandshakeFragment, Reassembler};
use crate::tls::dtls_record::{DTLS_RECORD_HEADER_LEN, DtlsHandshakeHeader, DtlsRecordHeader};

#[derive(Debug)]
pub enum RecordError {
    Io(io::Error),
    Codec(crate::tls::codec::CodecError),
    Crypto(CryptoError),
    RecordTooLarge(usize),
    UnexpectedContentType {
        expected: u8,
        got: u8,
    },
    RemoteAlert {
        level: u8,
        description: u8,
    },
    /// A post-handshake KeyUpdate arrived while application data was
    /// expected. The framed handshake bytes are handed to the driver, which
    /// must rotate its read keys before the NEXT record can be opened
    /// (RFC 8446 4.6.3) and may owe a reciprocal KeyUpdate.
    KeyUpdateReceived {
        framed: Vec<u8>,
    },
    /// The first protected record after `install_read_key_candidates`
    /// authenticated under none of the candidate read keys.
    NoReadKeyCandidate {
        candidates: usize,
    },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Io(e) => write!(f, "record io error: {}", e),
            RecordError::Codec(e) => write!(f, "record codec error: {}", e),
            RecordError::Crypto(e) => write!(f, "record crypto error: {}", e),
            RecordError::RecordTooLarge(n) => write!(f, "record too large: {} bytes", n),
            RecordError::UnexpectedContentType { expected, got } => write!(
                f,
                "unexpected record content type: expected 0x{:02x}, got 0x{:02x}",
                expected, got
            ),
            RecordError::RemoteAlert { level, description } => write!(
                f,
                "peer sent alert level {} description {}",
                level, description
            ),
            RecordError::KeyUpdateReceived { .. } => {
                write!(
                    f,
                    "post-handshake KeyUpdate received while reading application data"
                )
            }
            RecordError::NoReadKeyCandidate { candidates } => write!(
                f,
                "the peer's first protected record authenticated under none of {} candidate read keys",
                candidates
            ),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<io::Error> for RecordError {
    fn from(e: io::Error) -> Self {
        RecordError::Io(e)
    }
}

impl From<crate::tls::codec::CodecError> for RecordError {
    fn from(e: crate::tls::codec::CodecError) -> Self {
        RecordError::Codec(e)
    }
}

impl From<CryptoError> for RecordError {
    fn from(e: CryptoError) -> Self {
        RecordError::Crypto(e)
    }
}

/// Maximum TLS record payload length (2^14 plaintext + room for
/// expansion). We never split records in the wedge so this only
/// guards against the peer sending oversized ones.
pub const MAX_RECORD_LENGTH: usize = (1 << 14) + 2048;
const MAX_RECORD_PLAINTEXT: usize = 1 << 14;
const MAX_TLS13_CIPHERTEXT: usize = MAX_RECORD_PLAINTEXT + 256;

/// TLS protocol version we're running — picks the seal/open path
/// and tunes the read-side CCS swallowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    pub const fn is_legacy(self) -> bool {
        !matches!(self, Self::Tls13)
    }
}

/// Traffic keys for one direction. The two TLS versions fan out:
/// TLS 1.2 GCM uses a 4-byte salt with an 8-byte explicit nonce on
/// the wire; TLS 1.3 uses a full 12-byte static IV XOR'd with a
/// zero-padded sequence number. The enum keeps them distinct so
/// the wrong math can't silently happen.
#[derive(Clone)]
pub enum DirectionKeys {
    /// TLS 1.2 explicit-nonce AEAD (GCM: RFC 5288, CCM: RFC 6655): nonce =
    /// salt(4) || explicit(8), the explicit part sent in the record.
    Tls12 {
        key: AeadKey,
        salt: [u8; 4],
        seq: u64,
    },
    /// TLS 1.2 implicit-nonce AEAD (ChaCha20-Poly1305, RFC 7905): nonce =
    /// iv(12) XOR seq, nothing explicit on the wire.
    Tls12ImplicitNonce {
        key: AeadKey,
        iv: [u8; 12],
        seq: u64,
    },
    Tls13 {
        key: AeadKey,
        iv: [u8; 12],
        /// DTLS 1.3 record-number encryption key (`sn`); absent for TLS.
        rn_key: Option<Vec<u8>>,
        seq: u64,
    },
    /// TLS 1.2 CBC block cipher + HMAC (RFC 5246 6.2.3.2), MAC-then-encrypt
    /// or, with `etm`, RFC 7366 encrypt-then-MAC.
    Tls12Cbc {
        cipher: CbcCipher,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_alg: crate::tls::crypto::HashAlg,
        /// RFC 7366 encrypt-then-MAC negotiated: MAC over the ciphertext,
        /// appended after it, verified before decryption.
        etm: bool,
        /// TLS 1.0 chains CBC records: the key block supplies the first IV and
        /// each record's final ciphertext block supplies the next. TLS 1.1+
        /// uses an explicit IV and leaves this absent.
        implicit_iv: Option<Vec<u8>>,
        seq: u64,
    },
    /// TLS 1.2 NULL cipher (RFC 5246 6.2.3.1 GenericStreamCipher with the
    /// null stream cipher): plaintext || HMAC, nothing encrypted.
    Tls12Null {
        mac_key: Vec<u8>,
        mac_alg: crate::tls::crypto::HashAlg,
        seq: u64,
    },
}

/// The AEAD algorithm behind an AEAD bulk cipher; None for CBC / NULL.
pub fn aead_alg_for(cipher: crate::ir::BulkCipher) -> Option<AeadAlg> {
    use crate::ir::BulkCipher as B;
    Some(match cipher {
        B::Aes128Gcm => AeadAlg::Aes128Gcm,
        B::Aes256Gcm => AeadAlg::Aes256Gcm,
        B::Aes128Ccm => AeadAlg::Aes128Ccm,
        B::Aes256Ccm => AeadAlg::Aes256Ccm,
        B::Aes128Ccm8 => AeadAlg::Aes128Ccm8,
        B::Aes256Ccm8 => AeadAlg::Aes256Ccm8,
        B::Aria128Gcm => AeadAlg::Aria128Gcm,
        B::Aria256Gcm => AeadAlg::Aria256Gcm,
        B::Camellia128Gcm => AeadAlg::Camellia128Gcm,
        B::Camellia256Gcm => AeadAlg::Camellia256Gcm,
        B::ChaCha20Poly1305 => AeadAlg::ChaCha20Poly1305,
        B::Aes128Cbc | B::Aes256Cbc | B::TripleDesCbc | B::Null => return None,
    })
}

impl DirectionKeys {
    pub fn new_tls12(key: AeadKey, salt: [u8; 4]) -> Self {
        DirectionKeys::Tls12 { key, salt, seq: 0 }
    }
    pub fn new_tls12_implicit(key: AeadKey, iv: [u8; 12]) -> Self {
        DirectionKeys::Tls12ImplicitNonce { key, iv, seq: 0 }
    }
    pub fn new_tls13(key: AeadKey, iv: [u8; 12]) -> Self {
        DirectionKeys::Tls13 {
            key,
            iv,
            rn_key: None,
            seq: 0,
        }
    }

    pub fn new_dtls13(key: AeadKey, iv: [u8; 12], rn_key: Vec<u8>) -> Self {
        DirectionKeys::Tls13 {
            key,
            iv,
            rn_key: Some(rn_key),
            seq: 0,
        }
    }
    pub fn new_tls12_cbc(
        cipher: CbcCipher,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_alg: crate::tls::crypto::HashAlg,
        etm: bool,
    ) -> Self {
        Self::new_legacy_cbc(cipher, enc_key, mac_key, mac_alg, etm, None)
    }

    fn new_legacy_cbc(
        cipher: CbcCipher,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        mac_alg: crate::tls::crypto::HashAlg,
        etm: bool,
        implicit_iv: Option<Vec<u8>>,
    ) -> Self {
        DirectionKeys::Tls12Cbc {
            cipher,
            enc_key,
            mac_key,
            mac_alg,
            etm,
            implicit_iv,
            seq: 0,
        }
    }
    pub fn new_tls12_null(mac_key: Vec<u8>, mac_alg: crate::tls::crypto::HashAlg) -> Self {
        DirectionKeys::Tls12Null {
            mac_key,
            mac_alg,
            seq: 0,
        }
    }

    /// One direction's record keys for a negotiated TLS 1.2 suite, from that
    /// direction's slice of the key block (RFC 5246 6.3): the encryption key,
    /// the MAC key (empty for AEAD) and the implicit IV (salt / ChaCha20 IV /
    /// empty for CBC and NULL).
    pub fn for_tls12_suite(
        suite: &crate::ir::SuiteInfo,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        iv: &[u8],
        etm: bool,
    ) -> Result<Self, CryptoError> {
        use crate::ir::BulkCipher as B;
        if let Some(alg) = aead_alg_for(suite.cipher) {
            let key = AeadKey::new(alg, &enc_key)?;
            if suite.cipher == B::ChaCha20Poly1305 {
                let full: [u8; 12] = iv.try_into().map_err(|_| CryptoError::BadNonceLength)?;
                return Ok(Self::new_tls12_implicit(key, full));
            }
            let salt: [u8; 4] = iv.try_into().map_err(|_| CryptoError::BadNonceLength)?;
            return Ok(Self::new_tls12(key, salt));
        }
        let mac_alg = suite.mac.ok_or(CryptoError::UnsupportedSuite)?;
        Ok(match suite.cipher {
            B::Aes128Cbc => Self::new_tls12_cbc(CbcCipher::Aes128, enc_key, mac_key, mac_alg, etm),
            B::Aes256Cbc => Self::new_tls12_cbc(CbcCipher::Aes256, enc_key, mac_key, mac_alg, etm),
            B::TripleDesCbc => {
                Self::new_tls12_cbc(CbcCipher::TripleDes, enc_key, mac_key, mac_alg, etm)
            }
            B::Null => Self::new_tls12_null(mac_key, mac_alg),
            _ => return Err(CryptoError::UnsupportedSuite),
        })
    }

    pub fn for_legacy_suite(
        version: TlsVersion,
        suite: &crate::ir::SuiteInfo,
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        iv: &[u8],
        etm: bool,
    ) -> Result<Self, CryptoError> {
        if version == TlsVersion::Tls12 {
            return Self::for_tls12_suite(suite, enc_key, mac_key, iv, etm);
        }
        use crate::ir::BulkCipher as B;
        let mac_alg = suite.mac.ok_or(CryptoError::UnsupportedSuite)?;
        let cipher = match suite.cipher {
            B::Aes128Cbc => CbcCipher::Aes128,
            B::Aes256Cbc => CbcCipher::Aes256,
            B::TripleDesCbc => CbcCipher::TripleDes,
            B::Null => return Ok(Self::new_tls12_null(mac_key, mac_alg)),
            _ => return Err(CryptoError::UnsupportedSuite),
        };
        let implicit_iv = (version == TlsVersion::Tls10).then(|| iv.to_vec());
        Ok(Self::new_legacy_cbc(
            cipher,
            enc_key,
            mac_key,
            mac_alg,
            etm,
            implicit_iv,
        ))
    }
}

pub struct RecordLayer {
    transport: Box<dyn UutTransport>,
    version: TlsVersion,
    write_keys: Option<DirectionKeys>,
    read_keys: Option<DirectionKeys>,
    // TLS 1.2: read keys of which the peer holds exactly one, decided by the
    // first protected record (the one that authenticates is installed and its
    // index kept for the driver to collect).
    read_key_candidates: Vec<DirectionKeys>,
    read_key_selected: Option<usize>,
    // Pending plaintext from the last record we read, still waiting
    // to be consumed by the handshake layer. The associated content
    // type is tracked separately so we know what kind of bytes these
    // are.
    read_buffer: Vec<u8>,
    read_buffer_ct: u8,
    // Framed tickets consumed while waiting for application data. TLS 1.2
    // needs every ticket for its transcript; drivers retain the latest for resumption.
    swallowed_nst: std::collections::VecDeque<Vec<u8>>,
    /// Partial wire bytes survive read timeouts (especially drain probes).
    wire_read_buffer: Vec<u8>,
    read_deadline: Option<std::time::Instant>,
    swallowed_nst_count: u32,
    // Set once a TLS 1.2 renegotiation begins. It makes the CCS of the second
    // handshake ride under the current (old) cipher rather than going plaintext.
    renegotiating: bool,
    // Whether a TLS 1.2 CCS has already been written / read on this
    // connection. The handshake's own CCS goes plaintext (a client may already
    // have installed its write keys before sending it), but a later CCS under
    // active keys, such as a repeated one after the switch, is protected.
    tls12_ccs_written: bool,
    tls12_ccs_read: bool,
    // `coalesce { ... }`: handshake payloads accumulate here and go out as ONE
    // record at the end of the block, before a key change, or before any
    // non-handshake record (RFC 5246 6.2.1 / RFC 8446 5.1 coalescing).
    coalesce: Option<Vec<u8>>,
    // `coalesce hold_keys | old_keys { ... }`: a key change does not flush the
    // buffer; with `old_keys` the new keys wait in `deferred_write_keys` until
    // the block ends (its record is sealed under the keys current at its start).
    coalesce_mode: CoalesceMode,
    deferred_write_keys: Option<DirectionKeys>,
    // The fragments kept back by `@ fragment N hold` / `hold_all` (content
    // type, plaintext), each sealed under whatever write keys are current when
    // `flush_held` releases it (front first).
    held: VecDeque<(u8, Vec<u8>)>,
    // DTLS 1.3 handshake-fragment records kept back by `@ fragment N hold` /
    // `hold_all`. These are already sealed so a handshake key transition while
    // they wait cannot change their epoch or ciphertext.
    held_dtls13_wires: VecDeque<Vec<u8>>,
    // `atomic { ... }`: every record's wire bytes accumulate here and go to the
    // transport in ONE write at the block's end.
    atomic: Option<Vec<u8>>,
    // `@ fragment N hold_old_keys`: while the held fragment is pending, a key
    // change is parked in `deferred_write_keys` and applied by `flush_held`.
    held_defers_keys: bool,
    // T1: the explicit nonce (RFC 5288 3: the first 8 bytes of the body) of
    // every TLS 1.2 explicit-nonce AEAD record read, in wire order, for the
    // `gcm_nonces_unique` / `gcm_nonces_monotonic` asserts.
    explicit_nonces: Vec<u64>,
    // Application-data records read so far (after decryption; the inner type
    // on TLS 1.3), for `assert app_data_records == N`.
    app_data_records_read: u32,
    tls13_ccs_allowed: bool,
    tls13_ccs_seen: u8,
    /// Datagram wire state when the TLS 1.3 handshake machine is running over
    /// DTLS 1.3. The handshake machine still sees ordinary four-byte TLS 1.3
    /// handshake framing; this layer adds/removes DTLS fragment headers.
    dtls13: Option<Dtls13State>,
}

struct Dtls13State {
    write_epoch: u16,
    read_epoch: u16,
    plain_write_seq: u64,
    write_handshake_seq: u16,
    reassembler: Reassembler,
    sequence_map: crate::ir::DtlsSequenceMap,
    last_sent_datagram: Option<Vec<u8>>,
    sent_datagrams: Vec<Vec<u8>>,
    auto_ack: bool,
    pending_acks: Vec<(u16, u64)>,
    surface_ack: bool,
    previous_write: Option<(u16, DirectionKeys)>,
    previous_read: Option<(u16, DirectionKeys)>,
    /// Highest successfully authenticated record number per inbound epoch.
    /// Needed to reconstruct protected 8/16-bit wire sequence numbers.
    read_highest: BTreeMap<u16, u64>,
    /// Handshake identities delivered to the handshake machine. A
    /// retransmitted flight must contain at least one of these. Requiring only
    /// the last identity is too strict after a selective ACK acknowledges it.
    received_handshakes: BTreeSet<(u8, u16)>,
    /// Records occupied by the most recent handshake message written through
    /// `write_tls13_handshake`. A DTLS KeyUpdate changes write epochs only
    /// after every one of these records has been acknowledged.
    last_handshake_records: Vec<(u16, u64)>,
    pending_key_update: Option<PendingDtls13KeyUpdate>,
}

struct PendingDtls13KeyUpdate {
    unacked_records: Vec<(u16, u64)>,
    next_keys: DirectionKeys,
}

impl RecordLayer {
    pub fn new(transport: Box<dyn UutTransport>, version: TlsVersion) -> Self {
        Self {
            transport,
            version,
            write_keys: None,
            read_keys: None,
            read_key_candidates: Vec::new(),
            read_key_selected: None,
            read_buffer: Vec::new(),
            read_buffer_ct: 0,
            swallowed_nst: std::collections::VecDeque::new(),
            wire_read_buffer: Vec::new(),
            read_deadline: None,
            swallowed_nst_count: 0,
            renegotiating: false,
            tls12_ccs_written: false,
            tls12_ccs_read: false,
            coalesce: None,
            coalesce_mode: CoalesceMode::Flush,
            deferred_write_keys: None,
            held: VecDeque::new(),
            held_dtls13_wires: VecDeque::new(),
            atomic: None,
            held_defers_keys: false,
            explicit_nonces: Vec::new(),
            app_data_records_read: 0,
            tls13_ccs_allowed: false,
            tls13_ccs_seen: 0,
            dtls13: None,
        }
    }

    pub fn new_dtls13(transport: Box<dyn UutTransport>) -> Self {
        let mut out = Self::new(
            Box::new(crate::tls::dtls_transport::DtlsFramer::new(transport)),
            TlsVersion::Tls13,
        );
        out.dtls13 = Some(Dtls13State {
            write_epoch: 0,
            read_epoch: 0,
            plain_write_seq: 0,
            write_handshake_seq: 0,
            reassembler: Reassembler::new(),
            sequence_map: crate::ir::DtlsSequenceMap::Identity,
            last_sent_datagram: None,
            sent_datagrams: Vec::new(),
            auto_ack: true,
            pending_acks: Vec::new(),
            surface_ack: false,
            previous_write: None,
            previous_read: None,
            read_highest: BTreeMap::new(),
            received_handshakes: BTreeSet::new(),
            last_handshake_records: Vec::new(),
            pending_key_update: None,
        });
        out
    }

    pub fn is_dtls13(&self) -> bool {
        self.dtls13.is_some()
    }

    pub fn set_tls13_ccs_allowed(&mut self, allowed: bool) {
        self.tls13_ccs_allowed = allowed;
        if !allowed {
            self.tls13_ccs_seen = 0;
        }
    }

    pub fn dtls_advance_clock(&mut self, nanos: u64) -> Result<(), RecordError> {
        Ok(self.transport.dtls_advance_clock(nanos)?)
    }

    pub fn dtls_expect_next_timeout(&mut self, nanos: Option<u64>) -> Result<(), RecordError> {
        Ok(self.transport.dtls_expect_next_timeout(nanos)?)
    }

    pub fn dtls_set_timeout(&mut self, millis: u32) -> Result<(), RecordError> {
        Ok(self.transport.dtls_set_timeout(millis)?)
    }

    pub fn dtls_expect_retransmit(&mut self) -> Result<(), RecordError> {
        self.transport
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        let result = (|| {
            let expected = &self
                .dtls13
                .as_ref()
                .expect("DTLS 1.3 state")
                .received_handshakes;
            if expected.is_empty() {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no previously received DTLS 1.3 handshake message to retransmit",
                )));
            }
            let first = self.transport.dtls_recv_datagram()?.ok_or_else(|| {
                RecordError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed instead of retransmitting",
                ))
            })?;
            if first.is_empty() {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer retransmitted an empty datagram",
                )));
            }
            let mut datagrams = vec![first];
            self.transport
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
            loop {
                match self.transport.dtls_recv_datagram() {
                    Ok(Some(datagram)) => datagrams.push(datagram),
                    Ok(None) => break,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => return Err(RecordError::Io(error)),
                }
            }
            let state = self.dtls13.as_ref().expect("DTLS 1.3 state");
            let mut saw_handshake = false;
            let mut matched = false;
            for datagram in &datagrams {
                for identity in
                    inspect_dtls13_handshake_identities(datagram, state, self.read_keys.as_ref())?
                {
                    saw_handshake = true;
                    matched |= expected.contains(&identity);
                }
            }
            if !saw_handshake {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retransmit carried no handshake records",
                )));
            }
            if !matched {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retransmit contained no previously received handshake identity",
                )));
            }
            Ok(())
        })();
        let _ = self.transport.set_read_timeout(None);
        result
    }

    pub fn dtls_map_record_sequences(&mut self, map: crate::ir::DtlsSequenceMap) {
        self.dtls13.as_mut().expect("DTLS 1.3 state").sequence_map = map;
    }

    pub fn dtls_set_mtu(&mut self, mtu: u32) -> Result<(), RecordError> {
        self.transport.dtls_set_mtu(mtu).map_err(RecordError::from)
    }

    pub fn dtls_suppress_ack(&mut self) {
        let state = self.dtls13.as_mut().expect("DTLS 1.3 state");
        state.auto_ack = false;
        state.pending_acks.clear();
    }

    pub fn dtls_send_ack(
        &mut self,
        selection: crate::ir::DtlsAckSelection,
        outer_epoch: Option<u16>,
        overflow_epoch: bool,
    ) -> Result<(), RecordError> {
        let state = self.dtls13.as_ref().expect("DTLS 1.3 state");
        let selected: Vec<(u16, u64)> = state
            .pending_acks
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, record)| {
                let include = match selection {
                    crate::ir::DtlsAckSelection::All => true,
                    crate::ir::DtlsAckSelection::First => index == 0,
                    crate::ir::DtlsAckSelection::Last => index + 1 == state.pending_acks.len(),
                    crate::ir::DtlsAckSelection::Even => index % 2 == 0,
                    crate::ir::DtlsAckSelection::Odd => index % 2 == 1,
                };
                include.then_some(record)
            })
            .collect();
        if selected.is_empty() {
            return Err(RecordError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "send_ack has no captured records to acknowledge",
            )));
        }
        self.send_dtls13_ack_records(&selected, outer_epoch, overflow_epoch)
    }

    pub fn dtls_expect_ack(&mut self) -> Result<(), RecordError> {
        self.transport
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        self.dtls13.as_mut().expect("DTLS 1.3 state").surface_ack = true;
        let result = self.read_dtls13_record();
        self.dtls13.as_mut().expect("DTLS 1.3 state").surface_ack = false;
        let _ = self.transport.set_read_timeout(None);
        match result? {
            (26, _) => Ok(()),
            (content_type, _) => Err(RecordError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected DTLS ACK, got content type {}", content_type),
            ))),
        }
    }

    pub fn dtls_write_previous_epoch_handshake(
        &mut self,
        framed: &[u8],
    ) -> Result<(), RecordError> {
        let payload = self.dtls13_encode_handshake(framed)?;
        let (epoch, mut keys) = self
            .dtls13
            .as_mut()
            .expect("DTLS 1.3 state")
            .previous_write
            .take()
            .ok_or_else(|| {
                RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no retained previous DTLS 1.3 write epoch",
                ))
            })?;
        let map = self.dtls13.as_ref().unwrap().sequence_map;
        let wire = seal_dtls13_aead(&mut keys, epoch, CONTENT_TYPE_HANDSHAKE, &payload, &[], map)?;
        self.dtls13.as_mut().unwrap().previous_write = Some((epoch, keys));
        self.remember_dtls13_datagram(&wire);
        self.emit(&wire)?;
        self.transport.flush().map_err(RecordError::from)
    }

    pub fn dtls_retransmit_previous_epoch_handshake(
        &mut self,
        framed: &[u8],
    ) -> Result<(), RecordError> {
        if framed.len() < 4 {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
        let body_len =
            ((framed[1] as usize) << 16) | ((framed[2] as usize) << 8) | framed[3] as usize;
        if framed.len() < 4 + body_len {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
        let sequence = self
            .dtls13
            .as_ref()
            .expect("DTLS 1.3 state")
            .write_handshake_seq
            .checked_sub(1)
            .ok_or_else(|| RecordError::Io(io::Error::other("no prior handshake message")))?;
        let header = DtlsHandshakeHeader::whole(framed[0], sequence, body_len as u32);
        let mut payload = header.encode().to_vec();
        payload.extend_from_slice(&framed[4..4 + body_len]);

        let (epoch, mut keys) = self
            .dtls13
            .as_mut()
            .expect("DTLS 1.3 state")
            .previous_write
            .take()
            .ok_or_else(|| {
                RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no retained previous DTLS 1.3 write epoch",
                ))
            })?;
        let map = self.dtls13.as_ref().unwrap().sequence_map;
        let wire = seal_dtls13_aead(&mut keys, epoch, CONTENT_TYPE_HANDSHAKE, &payload, &[], map)?;
        self.dtls13.as_mut().unwrap().previous_write = Some((epoch, keys));
        self.remember_dtls13_datagram(&wire);
        self.emit(&wire)?;
        self.transport.flush().map_err(RecordError::from)
    }

    /// Replay the last datagram byte-for-byte. Unlike a retransmission, this
    /// intentionally reuses the protected record number and ciphertext.
    pub fn dtls_resend_last_datagram(&mut self) -> Result<(), RecordError> {
        let wire = self
            .dtls13
            .as_ref()
            .and_then(|s| s.last_sent_datagram.clone())
            .ok_or_else(|| RecordError::Io(io::Error::other("no DTLS 1.3 datagram to replay")))?;
        self.transport.write_all(&wire)?;
        self.transport.flush()?;
        Ok(())
    }

    pub fn dtls_replay_datagram(&mut self, one_based: usize) -> Result<(), RecordError> {
        let wire = self
            .dtls13
            .as_ref()
            .and_then(|s| s.sent_datagrams.get(one_based.checked_sub(1)?))
            .cloned()
            .ok_or_else(|| {
                RecordError::Io(io::Error::other("DTLS 1.3 replay index is out of range"))
            })?;
        self.transport.write_all(&wire)?;
        self.transport.flush()?;
        Ok(())
    }

    fn remember_dtls13_datagram(&mut self, wire: &[u8]) {
        if let Some(state) = self.dtls13.as_mut() {
            state.last_sent_datagram = Some(wire.to_vec());
            state.sent_datagrams.push(wire.to_vec());
        }
    }

    /// Write wire bytes: straight to the transport, or into the `atomic { }`
    /// buffer while one is open.
    fn emit(&mut self, wire: &[u8]) -> Result<(), RecordError> {
        match self.atomic.as_mut() {
            Some(buf) => {
                buf.extend_from_slice(wire);
                Ok(())
            }
            None => Ok(self.transport.write_all(wire)?),
        }
    }

    /// `atomic { ... }`: start buffering wire bytes (an open block is flushed).
    pub fn begin_atomic(&mut self) -> Result<(), RecordError> {
        self.end_atomic()?;
        self.atomic = Some(Vec::new());
        Ok(())
    }

    /// End the `atomic { ... }` block: one write with everything buffered.
    pub fn end_atomic(&mut self) -> Result<(), RecordError> {
        self.flush_coalesced()?;
        if let Some(buf) = self.atomic.take() {
            if !buf.is_empty() {
                self.transport.write_all(&buf)?;
            }
        }
        Ok(())
    }

    /// Mark the record layer as entering a TLS 1.2 renegotiation. The CCS of the
    /// second handshake is then protected by the current cipher, not sent plaintext.
    pub fn begin_renegotiation(&mut self) {
        self.renegotiating = true;
    }

    /// True when a peer ClientHello is buffered (a client-initiated TLS 1.2
    /// renegotiation that arrived while waiting on application data).
    pub fn buffered_client_hello(&self) -> bool {
        self.read_buffer_ct == CONTENT_TYPE_HANDSHAKE
            && self.read_buffer.first() == Some(&crate::tls::codec::HS_CLIENT_HELLO)
    }

    /// Take the most recently swallowed post-handshake NewSessionTicket (framed
    /// handshake bytes), if any. Used by the TLS 1.3 driver to capture a ticket
    /// that arrived interleaved with application data, for resumption.
    pub fn take_swallowed_nst(&mut self) -> Option<Vec<u8>> {
        self.swallowed_nst.pop_front()
    }

    /// T5: how many NewSessionTickets the record layer swallowed so far (it
    /// keeps only the last one's bytes; a `wait` may absorb several).
    pub fn swallowed_nst_count(&self) -> u32 {
        self.swallowed_nst_count
    }

    /// Application-data records read so far (`assert app_data_records == N`).
    pub fn app_data_records_read(&self) -> u32 {
        self.app_data_records_read
    }

    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// Install new write keys. Anything buffered by `coalesce { ... }` goes out
    /// first, under the OLD keys: a coalesced record never spans a key change.
    /// (A fragment held back by `@ fragment N hold` deliberately does.)
    pub fn install_write_keys(&mut self, keys: DirectionKeys) -> Result<(), RecordError> {
        if self.held_defers_keys && !self.held.is_empty() {
            self.deferred_write_keys = Some(keys);
            return Ok(());
        }
        match self.coalesce_mode {
            CoalesceMode::Flush => self.flush_coalesced()?,
            CoalesceMode::HoldKeys => {}
            CoalesceMode::OldKeys if self.coalesce.is_some() => {
                self.deferred_write_keys = Some(keys);
                return Ok(());
            }
            CoalesceMode::OldKeys => {}
        }
        if let Some(dtls) = self.dtls13.as_mut() {
            if let Some(old_keys) = self.write_keys.clone() {
                dtls.previous_write = Some((dtls.write_epoch, old_keys));
            }
            dtls.write_epoch = match dtls.write_epoch {
                0 => 2, // epoch 1 is reserved for 0-RTT
                n => n.checked_add(1).ok_or_else(seq_overflow)?,
            };
        }
        self.write_keys = Some(keys);
        Ok(())
    }

    /// Install the next write generation after a KeyUpdate. TLS changes keys
    /// immediately. DTLS 1.3 retains the current epoch until an authenticated
    /// ACK covers every record carrying the KeyUpdate (RFC 9147 section 8).
    pub fn install_key_update_write_keys(
        &mut self,
        keys: DirectionKeys,
    ) -> Result<(), RecordError> {
        let Some(state) = self.dtls13.as_mut() else {
            return self.install_write_keys(keys);
        };
        if state.pending_key_update.is_some() {
            return Err(RecordError::Io(io::Error::other(
                "a DTLS 1.3 KeyUpdate is already awaiting acknowledgement",
            )));
        }
        if state.last_handshake_records.is_empty() {
            return Err(RecordError::Io(io::Error::other(
                "DTLS 1.3 KeyUpdate produced no protected handshake records",
            )));
        }
        state.pending_key_update = Some(PendingDtls13KeyUpdate {
            unacked_records: state.last_handshake_records.clone(),
            next_keys: keys,
        });
        Ok(())
    }

    /// Return to plaintext writes after a rejected TLS 1.3 early-data epoch.
    /// In particular, ClientHello2 after HelloRetryRequest is plaintext even
    /// though ClientHello1 was followed by records under the 0-RTT write key.
    pub fn clear_write_keys(&mut self) {
        self.write_keys = None;
    }

    /// Return to plaintext reads after a TLS 1.3 server rejects the 0-RTT
    /// epoch with HelloRetryRequest. ClientHello2 is never early-data
    /// protected.
    pub fn clear_read_keys(&mut self) {
        self.read_keys = None;
        self.read_key_candidates.clear();
    }

    /// Switch a stream record layer that began as TLS 1.3 to the TLS 1.2
    /// framing/protection rules. This is deliberately narrow: it exists for
    /// cross-version state-machine tests which continue far enough to prove
    /// whether a peer entered TLS 1.2 after sending an HRR. No conforming
    /// handshake takes this transition.
    pub fn switch_to_tls12(&mut self) -> Result<(), RecordError> {
        if self.dtls13.is_some() {
            return Err(RecordError::Io(io::Error::other(
                "cannot switch a DTLS 1.3 record layer to TLS 1.2",
            )));
        }
        self.version = TlsVersion::Tls12;
        Ok(())
    }

    pub fn install_read_keys(&mut self, keys: DirectionKeys) -> Result<(), RecordError> {
        if self.version == TlsVersion::Tls13
            && self.dtls13.is_none()
            && !self.read_buffer.is_empty()
        {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::InvalidValue(
                    "handshake bytes cross a traffic-key boundary",
                ),
            ));
        }
        if let Some(dtls) = self.dtls13.as_mut() {
            if let Some(old_keys) = self.read_keys.take() {
                dtls.previous_read = Some((dtls.read_epoch, old_keys));
            }
            dtls.read_epoch = match dtls.read_epoch {
                0 => 2,
                n => n.saturating_add(1),
            };
        }
        self.read_keys = Some(keys);
        Ok(())
    }

    /// TLS 1.2: arm a read-key change whose keys are not yet known. The next
    /// protected record is opened under each candidate in turn; the first that
    /// authenticates becomes the read keys, and `take_read_key_selection`
    /// reports its index.
    pub fn install_read_key_candidates(&mut self, candidates: Vec<DirectionKeys>) {
        self.read_keys = None;
        self.read_key_candidates = candidates;
        self.read_key_selected = None;
    }

    pub fn take_read_key_selection(&mut self) -> Option<usize> {
        self.read_key_selected.take()
    }

    pub fn transport_description(&self) -> String {
        self.transport.description()
    }

    pub fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        self.read_deadline = deadline;
        if deadline.is_some() {
            self.apply_read_deadline()
        } else {
            self.transport.set_read_deadline(None)
        }
    }

    /// Write a record with no post-seal mutations. Convenience
    /// wrapper — most call sites don't have mutations.
    pub fn write_record(&mut self, content_type: u8, payload: &[u8]) -> Result<(), RecordError> {
        self.write_record_with_mutations(content_type, payload, &[])
    }

    /// Write a TLS/DTLS 1.3 handshake message. On TLS this is the ordinary
    /// record path. On DTLS, an attached handshake-fragment scheme controls
    /// the DTLSHandshake headers and record ordering without changing the
    /// transcript bytes seen by the TLS 1.3 state machine.
    pub fn write_tls13_handshake(
        &mut self,
        payload: &[u8],
        mutations: &[Mutation],
        fragment_scheme: Option<&DtlsFragScheme>,
    ) -> Result<(), RecordError> {
        if let Some(state) = self.dtls13.as_mut() {
            state.last_handshake_records.clear();
        }
        let reorder = mutations.iter().find_map(|mutation| match mutation.op {
            MutationOp::Reorder(size) => Some(size.max(1)),
            _ => None,
        });
        if self.dtls13.is_none() || (fragment_scheme.is_none() && reorder.is_none()) {
            return self.write_record_with_mutations(CONTENT_TYPE_HANDSHAKE, payload, mutations);
        }
        self.flush_coalesced()?;

        let mut input = payload;
        while !input.is_empty() {
            if input.len() < 4 {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let body_len =
                ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
            if input.len() < 4 + body_len {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let sequence = self.dtls13.as_ref().unwrap().write_handshake_seq;
            self.dtls13.as_mut().unwrap().write_handshake_seq = sequence.wrapping_add(1);
            let body = &input[4..4 + body_len];
            let mut fragments = if let Some(scheme) = fragment_scheme {
                crate::tls::dtls_handshake::forge_fragments(input[0], sequence, body, scheme)
            } else {
                crate::tls::dtls_handshake::fragment_message(
                    input[0],
                    sequence,
                    body,
                    reorder.unwrap(),
                )
            };
            if reorder.is_some() && fragment_scheme.is_none() {
                fragments.reverse();
            }
            let mut encoded: Vec<Vec<u8>> = fragments.into_iter().map(|f| f.encode()).collect();
            if let Some(DtlsFragScheme::SplitFragmentRecord { at }) = fragment_scheme {
                let whole = encoded.pop().unwrap_or_default();
                let split = (*at).min(whole.len());
                encoded = vec![whole[..split].to_vec(), whole[split..].to_vec()];
            }
            let packed_valid_fragment = if matches!(
                fragment_scheme,
                Some(DtlsFragScheme::FutureSequencePacked { .. })
            ) {
                let valid = encoded.last().cloned();
                encoded = vec![encoded.concat()];
                valid
            } else {
                None
            };
            let hold = match fragment_scheme {
                Some(DtlsFragScheme::HeldFragment { hold, .. }) => *hold,
                _ => FragHold::None,
            };
            let count = encoded.len();
            for (index, fragment) in encoded.into_iter().enumerate() {
                let withhold = match hold {
                    FragHold::None => false,
                    FragHold::Last | FragHold::LastOldKeys => index + 1 == count,
                    FragHold::All => index > 0,
                };
                if withhold {
                    let wire = self.build_dtls13_fragment_record(&fragment, mutations)?;
                    self.held_dtls13_wires.push_back(wire);
                } else {
                    self.write_dtls13_fragment_record(&fragment, mutations)?;
                }
            }
            // The packed record is expected to be discarded as a unit. Keep a
            // clean copy of its in-sequence fragment for `flush_fragment`,
            // which models retransmitting only the usable fragment afterward
            // without advancing the handshake transcript or message_seq.
            if let Some(valid) = packed_valid_fragment {
                let wire = self.build_dtls13_fragment_record(&valid, mutations)?;
                self.held_dtls13_wires.push_back(wire);
            }
            input = &input[4 + body_len..];
        }
        Ok(())
    }

    fn write_dtls13_fragment_record(
        &mut self,
        fragment: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), RecordError> {
        let wire = self.build_dtls13_fragment_record(fragment, mutations)?;
        self.remember_dtls13_datagram(&wire);
        self.emit(&wire)
    }

    fn build_dtls13_fragment_record(
        &mut self,
        fragment: &[u8],
        mutations: &[Mutation],
    ) -> Result<Vec<u8>, RecordError> {
        if fragment.len() > MAX_RECORD_LENGTH {
            return Err(RecordError::RecordTooLarge(fragment.len()));
        }
        let encrypt = self.write_keys.is_some();
        let record_number = if encrypt {
            let state = self.dtls13.as_ref().unwrap();
            Some((
                state.write_epoch,
                state
                    .sequence_map
                    .apply(direction_keys_sequence(self.write_keys.as_ref().unwrap())),
            ))
        } else {
            None
        };
        let mut wire = if encrypt {
            let epoch = self.dtls13.as_ref().unwrap().write_epoch;
            let sequence_map = self.dtls13.as_ref().unwrap().sequence_map;
            seal_dtls13_aead(
                self.write_keys.as_mut().unwrap(),
                epoch,
                CONTENT_TYPE_HANDSHAKE,
                fragment,
                mutations,
                sequence_map,
            )?
        } else {
            let state = self.dtls13.as_mut().unwrap();
            let sequence = state.plain_write_seq;
            state.plain_write_seq = state.plain_write_seq.wrapping_add(1);
            crate::tls::dtls_record::encode_record(CONTENT_TYPE_HANDSHAKE, 0, sequence, fragment)
        };
        if !mutations.is_empty() {
            let tag_len = self
                .write_keys
                .as_ref()
                .map(DirectionKeys::aead_tag_len)
                .unwrap_or(0);
            mutate::apply_record_mutations(
                &mut wire,
                if encrypt {
                    dtls13_header_len(mutations)
                } else {
                    DTLS_RECORD_HEADER_LEN
                },
                fragment.len(),
                encrypt,
                tag_len,
                mutations,
            )
            .map_err(|e| RecordError::Io(io::Error::other(e.to_string())))?;
        }
        if let Some(record_number) = record_number {
            self.dtls13
                .as_mut()
                .unwrap()
                .last_handshake_records
                .push(record_number);
        }
        Ok(wire)
    }

    /// Write a record, applying any `record.*` byte mutations
    /// after sealing.
    ///
    /// Encryption rules:
    ///   * TLS 1.2 (RFC 5246 §7.1): ChangeCipherSpec records are
    ///     always plaintext — the CCS itself is the signal for the
    ///     switch, sent under the old cipher spec.
    ///   * TLS 1.3 (RFC 8446 §5): once handshake keys are installed,
    ///     every record except ChangeCipherSpec is encrypted, the
    ///     outer content_type is always `application_data` (0x17),
    ///     and the real content type is appended as an inner
    ///     trailing byte before encryption.
    ///
    /// `mutations` is the full mutation list for
    /// the message being sent — `apply_record_mutations` filters
    /// to only the `record.*` targets and skips the rest.
    pub fn write_record_with_mutations(
        &mut self,
        content_type: u8,
        payload: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), RecordError> {
        let payload = if content_type == CONTENT_TYPE_HANDSHAKE {
            apply_handshake_stream_mutations(payload, mutations)?
        } else {
            payload.to_vec()
        };
        let payload = payload.as_slice();
        let fragment = mutations.iter().find_map(|m| match m.op {
            MutationOp::Fragment { size, hold } => Some((size.max(1), hold)),
            _ => None,
        });
        // `coalesce { ... }`: handshake payloads are buffered; anything else
        // (CCS, alert, application data, an explicitly fragmented message)
        // flushes the buffer first and then goes out on its own.
        if self.coalesce.is_some() {
            if content_type == CONTENT_TYPE_HANDSHAKE && fragment.is_none() {
                self.coalesce.as_mut().unwrap().extend_from_slice(payload);
                return Ok(());
            }
            self.flush_coalesced()?;
        }
        let (size, hold) = match fragment {
            None => return self.write_one_record(content_type, payload, mutations),
            Some(f) => f,
        };
        // `@ fragment N [hold | hold_all]`: one record per N-byte chunk, each
        // sealed on its own (its own sequence number, MAC / AEAD tag).
        // `record.*` mutations apply to the first fragment only. With `hold`,
        // the last chunk stays back for `flush_held`; with `hold_all` every
        // chunk after the first does, released one per `flush_held`.
        // `[].chunks(size)` is empty, but a zero-length application-data send
        // still means one empty TLS record. This matters when the test attaches
        // a record mutation or an explicit `@ fragment` to `AppData { size: 0 }`.
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![&[]]
        } else {
            payload.chunks(size).collect()
        };
        let n = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let held = match hold {
                FragHold::None => false,
                FragHold::Last | FragHold::LastOldKeys => i + 1 == n,
                FragHold::All => i > 0,
            };
            if held {
                self.held.push_back((content_type, chunk.to_vec()));
                if hold == FragHold::LastOldKeys {
                    self.held_defers_keys = true;
                }
                continue;
            }
            let muts: &[Mutation] = if i == 0 { mutations } else { &[] };
            self.write_one_record(content_type, chunk, muts)?;
        }
        Ok(())
    }

    /// Start buffering handshake payloads (`coalesce { ... }`). Anything
    /// already buffered is flushed first. With `hold_keys` a key change inside
    /// the block does not flush: the record is sealed at the block's end under
    /// the keys current then.
    pub fn begin_coalesce(&mut self, mode: CoalesceMode) -> Result<(), RecordError> {
        self.flush_coalesced()?;
        self.coalesce = Some(Vec::new());
        self.coalesce_mode = mode;
        Ok(())
    }

    /// Send the buffered handshake payloads as one record and stop buffering;
    /// a key change deferred by `old_keys` takes effect now.
    pub fn end_coalesce(&mut self) -> Result<(), RecordError> {
        self.flush_coalesced()?;
        self.coalesce = None;
        self.coalesce_mode = CoalesceMode::Flush;
        if let Some(keys) = self.deferred_write_keys.take() {
            self.write_keys = Some(keys);
        }
        Ok(())
    }

    /// Write whatever `coalesce { ... }` has buffered as a single handshake
    /// record (nothing if the buffer is empty); buffering stays on.
    fn flush_coalesced(&mut self) -> Result<(), RecordError> {
        let buffered = match self.coalesce.as_mut() {
            Some(buf) if !buf.is_empty() => std::mem::take(buf),
            _ => return Ok(()),
        };
        self.write_one_record(CONTENT_TYPE_HANDSHAKE, &buffered, &[])
    }

    /// Send the next fragment held back by `@ fragment N hold` / `hold_all`
    /// under the current write keys. `Ok(false)` if nothing is held.
    pub fn flush_held(&mut self) -> Result<bool, RecordError> {
        if !self.held_dtls13_wires.is_empty() {
            // A DTLS handshake message may have many withheld fragments. Its
            // `flush_fragment` releases the withheld remainder as one logical
            // delivery event; TLS `hold_all` retains its historical one-record
            // per call behavior below.
            while let Some(wire) = self.held_dtls13_wires.pop_front() {
                self.remember_dtls13_datagram(&wire);
                self.emit(&wire)?;
            }
            self.transport.flush()?;
            return Ok(true);
        }
        match self.held.pop_front() {
            None => Ok(false),
            Some((content_type, data)) => {
                self.write_one_record(content_type, &data, &[])?;
                if self.held.is_empty() && self.held_defers_keys {
                    self.held_defers_keys = false;
                    if let Some(keys) = self.deferred_write_keys.take() {
                        self.write_keys = Some(keys);
                    }
                }
                Ok(true)
            }
        }
    }

    /// A zero-length record of `content_type`: plaintext before any write keys,
    /// sealed (an empty plaintext, so just the MAC / tag, plus the inner type
    /// byte on TLS 1.3) under the current keys otherwise. Never coalesced.
    pub fn write_empty_record(&mut self, content_type: u8) -> Result<(), RecordError> {
        self.write_standalone_record(content_type, &[], &[])
    }

    /// `send record N ... @ mutations` / `send empty_record T @ mutations`: one
    /// record of that content type under the current keys, never coalesced,
    /// with record-level mutations (`record_pad`, `plaintext`, `record.*`).
    pub fn write_standalone_record(
        &mut self,
        content_type: u8,
        data: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), RecordError> {
        self.flush_coalesced()?;
        self.write_one_record(content_type, data, mutations)
    }

    /// Seal and write exactly one record.
    fn write_one_record(
        &mut self,
        content_type: u8,
        payload: &[u8],
        mutations: &[Mutation],
    ) -> Result<(), RecordError> {
        if payload.len() > MAX_RECORD_LENGTH {
            return Err(RecordError::RecordTooLarge(payload.len()));
        }
        let payload = if content_type == CONTENT_TYPE_HANDSHAKE && self.dtls13.is_some() {
            self.dtls13_encode_handshake(payload)?
        } else {
            payload.to_vec()
        };
        let payload = payload.as_slice();
        let plaintext_len = payload.len();
        // T2: `@ record_version 0xNNNN` and `@ plaintext`.
        let mut record_version = if self.version == TlsVersion::Tls13 {
            u16::from_be_bytes(LEGACY_RECORD_VERSION)
        } else {
            self.version.wire_value()
        };
        let mut force_plain = false;
        for m in mutations {
            match &m.op {
                MutationOp::RecordVersion(v) => record_version = *v,
                MutationOp::Plaintext => force_plain = true,
                _ => {}
            }
        }
        // The initial-handshake CCS goes plaintext (the peer has not switched yet);
        // a TLS 1.2 renegotiation CCS is protected by the current (old) cipher, as
        // is any later TLS 1.2 CCS once keys are active. A TLS 1.3 CCS record is
        // always the plaintext middlebox-compatibility form.
        let is_ccs = content_type == CONTENT_TYPE_CCS;
        let encrypt = self.write_keys.is_some()
            && (!is_ccs
                || (self.version != TlsVersion::Tls13
                    && (self.renegotiating || self.tls12_ccs_written)))
            && !force_plain;
        if is_ccs && self.version != TlsVersion::Tls13 {
            self.tls12_ccs_written = true;
        }
        if self.dtls13.is_some() {
            let record_number = if encrypt && content_type == CONTENT_TYPE_HANDSHAKE {
                let state = self.dtls13.as_ref().unwrap();
                Some((
                    state.write_epoch,
                    state
                        .sequence_map
                        .apply(direction_keys_sequence(self.write_keys.as_ref().unwrap())),
                ))
            } else {
                None
            };
            let mut wire = if !encrypt {
                let state = self.dtls13.as_mut().unwrap();
                let seq = state.plain_write_seq;
                state.plain_write_seq = state.plain_write_seq.wrapping_add(1);
                crate::tls::dtls_record::encode_record(content_type, 0, seq, payload)
            } else {
                let epoch = self.dtls13.as_ref().unwrap().write_epoch;
                let sequence_map = self.dtls13.as_ref().unwrap().sequence_map;
                seal_dtls13_aead(
                    self.write_keys.as_mut().unwrap(),
                    epoch,
                    content_type,
                    payload,
                    mutations,
                    sequence_map,
                )?
            };
            if !mutations.is_empty() {
                let tag_len = self
                    .write_keys
                    .as_ref()
                    .map(DirectionKeys::aead_tag_len)
                    .unwrap_or(0);
                mutate::apply_record_mutations(
                    &mut wire,
                    if encrypt {
                        dtls13_header_len(mutations)
                    } else {
                        DTLS_RECORD_HEADER_LEN
                    },
                    plaintext_len,
                    encrypt,
                    tag_len,
                    mutations,
                )
                .map_err(|e| RecordError::Io(io::Error::other(e.to_string())))?;
            }
            if let Some(record_number) = record_number {
                self.dtls13
                    .as_mut()
                    .unwrap()
                    .last_handshake_records
                    .push(record_number);
            }
            self.remember_dtls13_datagram(&wire);
            self.emit(&wire)?;
            return Ok(());
        }
        let (outer_type, body) = if !encrypt {
            (content_type, payload.to_vec())
        } else {
            let keys = self.write_keys.as_mut().unwrap();
            match (self.version, keys) {
                (
                    TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12,
                    DirectionKeys::Tls12 { .. }
                    | DirectionKeys::Tls12Cbc { .. }
                    | DirectionKeys::Tls12ImplicitNonce { .. }
                    | DirectionKeys::Tls12Null { .. },
                ) => {
                    let keys = self.write_keys.as_mut().unwrap();
                    (
                        content_type,
                        seal_tls12(keys, content_type, payload, mutations, record_version)?,
                    )
                }
                (TlsVersion::Tls13, DirectionKeys::Tls13 { .. }) => {
                    let keys = self.write_keys.as_mut().unwrap();
                    let sealed =
                        seal_tls13_aead(keys, content_type, payload, mutations, record_version)?;
                    (crate::tls::codec::CONTENT_TYPE_APP_DATA, sealed)
                }
                _ => {
                    return Err(RecordError::Codec(
                        crate::tls::codec::CodecError::UnexpectedEof,
                    ));
                }
            }
        };
        if body.len() > u16::MAX as usize {
            return Err(RecordError::RecordTooLarge(body.len()));
        }
        let header = RecordHeader {
            content_type: outer_type,
            version: record_version,
            length: body.len() as u16,
        };
        let mut wire = Vec::with_capacity(RecordHeader::ENCODED_LEN + body.len());
        let mut hw = crate::tls::codec::ByteWriter::new();
        header.encode(&mut hw);
        wire.extend_from_slice(&hw.into_vec());
        wire.extend_from_slice(&body);
        // Apply any record-layer mutations (xor[record.aead_tag, N],
        // set[record.content_type, 0], etc.) post-seal.
        if !mutations.is_empty() {
            let is_tls13 = self.version == TlsVersion::Tls13;
            let tag_len = match self.write_keys.as_ref() {
                Some(DirectionKeys::Tls12 { key, .. })
                | Some(DirectionKeys::Tls12ImplicitNonce { key, .. })
                | Some(DirectionKeys::Tls13 { key, .. }) => key.alg().tag_len(),
                _ => 16,
            };
            mutate::apply_record_mutations(
                &mut wire,
                RecordHeader::ENCODED_LEN,
                plaintext_len,
                is_tls13,
                tag_len,
                mutations,
            )
            .map_err(|e| RecordError::Io(io::Error::other(e.to_string())))?;
        }
        self.emit(&wire)?;
        Ok(())
    }

    /// Read one record off the wire, decrypting if read keys are
    /// installed. Returns (content_type, plaintext).
    ///
    /// CCS records are always plaintext in TLS 1.2, and are silently
    /// dropped in TLS 1.3 (RFC 8446 §5: middlebox-compat CCS records
    /// "MUST be ignored by the receiver"). On the TLS 1.3 path we
    /// loop until we see something that isn't CCS.
    pub fn read_record(&mut self) -> Result<(u8, Vec<u8>), RecordError> {
        if self.dtls13.is_some() {
            return self.read_dtls13_record();
        }
        loop {
            self.fill_wire_buffer(RecordHeader::ENCODED_LEN)?;
            let header = RecordHeader::decode(&self.wire_read_buffer[..RecordHeader::ENCODED_LEN])?;
            let wire_limit = if self.version == TlsVersion::Tls13 {
                MAX_TLS13_CIPHERTEXT
            } else {
                MAX_RECORD_LENGTH
            };
            if (header.length as usize) > wire_limit {
                return Err(RecordError::RecordTooLarge(header.length as usize));
            }
            self.fill_wire_buffer(RecordHeader::ENCODED_LEN + header.length as usize)?;
            let body = self.wire_read_buffer.split_off(RecordHeader::ENCODED_LEN);
            self.wire_read_buffer.clear();

            // TLS 1.3 middlebox-compat CCS: drop and read the next
            // record instead. Sequence counters are untouched.
            if self.version == TlsVersion::Tls13 && header.content_type == CONTENT_TYPE_CCS {
                if !self.tls13_ccs_allowed
                    || body != [1]
                    || self.tls13_ccs_seen >= 8
                    || !self.read_buffer.is_empty()
                {
                    return Err(RecordError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid, mistimed, or excessive TLS 1.3 compatibility CCS",
                    )));
                }
                self.tls13_ccs_seen += 1;
                continue;
            }

            // A TLS 1.3 record carrying an outer ContentType of `alert` is a
            // plaintext alert: once traffic keys are in use every genuine record
            // is wrapped as `application_data`, so an outer `alert` type is only
            // ever a peer aborting before it installed keys (e.g. rejecting the
            // ServerHello). Do not try to AEAD-open it. TLS 1.2 alerts, by
            // contrast, keep their real ContentType even when encrypted, so this
            // exception is TLS 1.3-only.
            let tls13_plaintext_alert =
                self.version == TlsVersion::Tls13 && header.content_type == CONTENT_TYPE_ALERT;
            // The initial-handshake CCS arrives plaintext; a TLS 1.2
            // renegotiation CCS comes in under the current (old) cipher, as does
            // any later CCS once read keys are active.
            let is_ccs = header.content_type == CONTENT_TYPE_CCS;
            let decrypt = !tls13_plaintext_alert
                && (self.read_keys.is_some() || !self.read_key_candidates.is_empty())
                && (!is_ccs || self.renegotiating || self.tls12_ccs_read);
            if is_ccs {
                self.tls12_ccs_read = true;
            }
            if !decrypt {
                if body.len() > MAX_RECORD_PLAINTEXT {
                    return Err(RecordError::RecordTooLarge(body.len()));
                }
                return Ok((header.content_type, body));
            }
            if self.read_keys.is_none() {
                let candidates = std::mem::take(&mut self.read_key_candidates);
                let selected = candidates.iter().position(|keys| {
                    let mut trial = keys.clone();
                    open_tls12(&mut trial, header.content_type, &body, header.version).is_ok()
                });
                let Some(index) = selected else {
                    return Err(RecordError::NoReadKeyCandidate {
                        candidates: candidates.len(),
                    });
                };
                self.read_keys = candidates.into_iter().nth(index);
                self.read_key_selected = Some(index);
            }

            let keys = self.read_keys.as_mut().unwrap();
            let (real_ct, plaintext) = match (self.version, keys) {
                (
                    TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12,
                    DirectionKeys::Tls12 { .. }
                    | DirectionKeys::Tls12Cbc { .. }
                    | DirectionKeys::Tls12ImplicitNonce { .. }
                    | DirectionKeys::Tls12Null { .. },
                ) => {
                    let keys = self.read_keys.as_mut().unwrap();
                    // T1: remember the explicit nonce before opening (the
                    // assert wants what the peer put on the wire).
                    if matches!(keys, DirectionKeys::Tls12 { .. }) && body.len() >= 8 {
                        let mut n = [0u8; 8];
                        n.copy_from_slice(&body[..8]);
                        self.explicit_nonces.push(u64::from_be_bytes(n));
                    }
                    let plaintext = open_tls12(keys, header.content_type, &body, header.version)?;
                    (header.content_type, plaintext)
                }
                (TlsVersion::Tls13, DirectionKeys::Tls13 { .. }) => {
                    let keys = self.read_keys.as_mut().unwrap();
                    let (ct, plaintext) = open_tls13_aead(keys, &body)?;
                    (ct, plaintext)
                }
                _ => {
                    return Err(RecordError::Codec(
                        crate::tls::codec::CodecError::UnexpectedEof,
                    ));
                }
            };
            if plaintext.len() > MAX_RECORD_PLAINTEXT {
                return Err(RecordError::RecordTooLarge(plaintext.len()));
            }
            if real_ct == CONTENT_TYPE_APP_DATA {
                self.app_data_records_read = self.app_data_records_read.saturating_add(1);
            }
            return Ok((real_ct, plaintext));
        }
    }

    /// Add DTLSHandshake headers to one or more complete TLS-framed handshake
    /// messages. The transcript above this layer remains the TLS 1.3 form, as
    /// RFC 9147 requires; message_seq and fragment fields are wire-only.
    fn dtls13_encode_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>, RecordError> {
        let state = self.dtls13.as_mut().expect("DTLS 1.3 state");
        let mut input = payload;
        let mut out = Vec::with_capacity(payload.len() + 8);
        while !input.is_empty() {
            if input.len() < 4 {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let len = ((input[1] as usize) << 16) | ((input[2] as usize) << 8) | input[3] as usize;
            if input.len() < 4 + len {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let header =
                DtlsHandshakeHeader::whole(input[0], state.write_handshake_seq, len as u32);
            state.write_handshake_seq = state.write_handshake_seq.wrapping_add(1);
            out.extend_from_slice(&header.encode());
            out.extend_from_slice(&input[4..4 + len]);
            input = &input[4 + len..];
        }
        Ok(out)
    }

    fn read_dtls13_record(&mut self) -> Result<(u8, Vec<u8>), RecordError> {
        loop {
            while self.wire_read_buffer.is_empty() {
                self.apply_read_deadline()?;
                self.wire_read_buffer = self.transport.dtls_recv_datagram()?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF before DTLS datagram")
                })?;
            }
            let first = self.take_datagram_bytes(1)?;
            let (content_type, epoch, sequence, plaintext) = if first[0] & 0xe0 == 0x20 {
                if first[0] & 0x10 != 0 {
                    return Err(RecordError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported DTLS 1.3 CID",
                    )));
                }
                let seq_len = if first[0] & 0x08 != 0 { 2 } else { 1 };
                let has_length = first[0] & 0x04 != 0;
                let mut tail =
                    self.take_datagram_bytes(seq_len + if has_length { 2 } else { 0 })?;
                let len = if has_length {
                    u16::from_be_bytes([tail[seq_len], tail[seq_len + 1]]) as usize
                } else {
                    self.wire_read_buffer.len()
                };
                if len > MAX_TLS13_CIPHERTEXT {
                    return Err(RecordError::RecordTooLarge(len));
                }
                let body = self.take_datagram_bytes(len)?;
                let epoch_bits = u16::from(first[0] & 3);
                let (epoch, keys) = {
                    let state = self.dtls13.as_ref().unwrap();
                    if state.read_epoch & 3 == epoch_bits {
                        let keys = self.read_keys.clone().ok_or_else(|| {
                            RecordError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "encrypted DTLS 1.3 record arrived before keys",
                            ))
                        })?;
                        (state.read_epoch, keys)
                    } else if let Some((epoch, keys)) = &state.previous_read {
                        if epoch & 3 != epoch_bits {
                            return Err(RecordError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "DTLS 1.3 record is from an unavailable epoch",
                            )));
                        }
                        (*epoch, keys.clone())
                    } else {
                        return Err(RecordError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "DTLS 1.3 record is from an unavailable epoch",
                        )));
                    }
                };
                let mask = match &keys {
                    DirectionKeys::Tls13 {
                        key,
                        rn_key: Some(rn_key),
                        ..
                    } => crate::tls::crypto::dtls13_record_number_mask(key.alg(), rn_key, &body)?,
                    _ => return Err(RecordError::Crypto(CryptoError::BadKeyLength)),
                };
                for i in 0..seq_len {
                    tail[i] ^= mask[i];
                }
                let truncated = if seq_len == 2 {
                    u64::from(u16::from_be_bytes([tail[0], tail[1]]))
                } else {
                    u64::from(tail[0])
                };
                let sequence = reconstruct_dtls13_sequence(
                    self.dtls13
                        .as_ref()
                        .unwrap()
                        .read_highest
                        .get(&epoch)
                        .copied(),
                    truncated,
                    seq_len * 8,
                );
                let mut aad = Vec::with_capacity(1 + tail.len());
                aad.push(first[0]);
                aad.extend_from_slice(&tail);
                let (ct, plaintext) = open_dtls13_aead(&keys, sequence, &aad, &body)?;
                if plaintext.len() > MAX_RECORD_PLAINTEXT {
                    return Err(RecordError::RecordTooLarge(plaintext.len()));
                }
                self.dtls13
                    .as_mut()
                    .unwrap()
                    .read_highest
                    .entry(epoch)
                    .and_modify(|highest| *highest = (*highest).max(sequence))
                    .or_insert(sequence);
                (ct, epoch, sequence, plaintext)
            } else {
                let rest = self.take_datagram_bytes(12)?;
                let mut encoded = [0u8; 13];
                encoded[0] = first[0];
                encoded[1..].copy_from_slice(&rest);
                let header = DtlsRecordHeader::parse(&encoded).map_err(|_| {
                    RecordError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed DTLS plaintext record",
                    ))
                })?;
                if header.length as usize > MAX_RECORD_PLAINTEXT {
                    return Err(RecordError::RecordTooLarge(header.length as usize));
                }
                let body = self.take_datagram_bytes(header.length as usize)?;
                (
                    header.content_type,
                    header.epoch,
                    header.sequence_number,
                    body,
                )
            };

            // ACK records are record-layer control messages, not handshake
            // messages. They only affect retransmission state, which plzn does
            // not need for the lossless happy path, so consume them here.
            if content_type == 26 {
                self.process_dtls13_ack(epoch, &plaintext)?;
                if self.dtls13.as_ref().unwrap().surface_ack {
                    return Ok((content_type, plaintext));
                }
                continue;
            }
            if content_type != CONTENT_TYPE_HANDSHAKE {
                if content_type == CONTENT_TYPE_APP_DATA {
                    self.app_data_records_read = self.app_data_records_read.saturating_add(1);
                }
                return Ok((content_type, plaintext));
            }

            {
                let state = self.dtls13.as_mut().unwrap();
                if (!state.auto_ack || epoch > 0)
                    && !state.pending_acks.contains(&(epoch, sequence))
                {
                    state.pending_acks.push((epoch, sequence));
                }
                if epoch > 0 && self.write_keys.is_some() && state.auto_ack {
                    self.send_dtls13_ack(epoch, sequence)?;
                }
            }
            let mut input = plaintext.as_slice();
            let mut framed = Vec::new();
            while !input.is_empty() {
                if input.len() < crate::tls::dtls_record::DTLS_HANDSHAKE_HEADER_LEN {
                    return Err(RecordError::Codec(
                        crate::tls::codec::CodecError::UnexpectedEof,
                    ));
                }
                let header = DtlsHandshakeHeader::parse(input).map_err(|_| {
                    RecordError::Codec(crate::tls::codec::CodecError::UnexpectedEof)
                })?;
                let total = crate::tls::dtls_record::DTLS_HANDSHAKE_HEADER_LEN
                    + header.fragment_length as usize;
                if input.len() < total {
                    return Err(RecordError::Codec(
                        crate::tls::codec::CodecError::UnexpectedEof,
                    ));
                }
                let fragment = HandshakeFragment {
                    header,
                    body: input[crate::tls::dtls_record::DTLS_HANDSHAKE_HEADER_LEN..total].to_vec(),
                };
                let completed = self
                    .dtls13
                    .as_mut()
                    .unwrap()
                    .reassembler
                    .accept(&fragment)
                    .map_err(|e| {
                        RecordError::Io(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
                    })?;
                for message in completed {
                    self.dtls13
                        .as_mut()
                        .unwrap()
                        .received_handshakes
                        .insert((message.msg_type, message.message_seq));
                    framed.push(message.msg_type);
                    let len = message.body.len();
                    framed.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
                    framed.extend_from_slice(&message.body);
                }
                input = &input[total..];
            }
            if !framed.is_empty() {
                return Ok((CONTENT_TYPE_HANDSHAKE, framed));
            }
        }
    }

    fn send_dtls13_ack(&mut self, epoch: u16, sequence: u64) -> Result<(), RecordError> {
        self.send_dtls13_ack_records(&[(epoch, sequence)], None, false)
    }

    fn process_dtls13_ack(
        &mut self,
        outer_epoch: u16,
        plaintext: &[u8],
    ) -> Result<(), RecordError> {
        if plaintext.len() < 2 {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
        let encoded_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
        if encoded_len != plaintext.len() - 2 || !encoded_len.is_multiple_of(16) {
            return Err(RecordError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed DTLS 1.3 ACK record-number vector",
            )));
        }
        let mut acknowledged = Vec::with_capacity(encoded_len / 16);
        for entry in plaintext[2..].chunks_exact(16) {
            let epoch = u64::from_be_bytes(entry[..8].try_into().unwrap());
            let sequence = u64::from_be_bytes(entry[8..].try_into().unwrap());
            // RFC 9147's same-or-higher-epoch constraint applies during the
            // handshake. Application epochs are directional: after one peer
            // updates, its ACK can legitimately be sent at its unchanged
            // write epoch while acknowledging the other peer's next epoch.
            if outer_epoch < 3 && epoch > u64::from(outer_epoch) {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DTLS 1.3 ACK acknowledges a record from a higher epoch",
                )));
            }
            if let Ok(epoch) = u16::try_from(epoch) {
                acknowledged.push((epoch, sequence));
            }
        }

        let next_keys = {
            let state = self.dtls13.as_mut().unwrap();
            let Some(pending) = state.pending_key_update.as_mut() else {
                return Ok(());
            };
            pending
                .unacked_records
                .retain(|record| !acknowledged.contains(record));
            if pending.unacked_records.is_empty() {
                state
                    .pending_key_update
                    .take()
                    .map(|pending| pending.next_keys)
            } else {
                None
            }
        };
        if let Some(next_keys) = next_keys {
            let state = self.dtls13.as_mut().unwrap();
            let old_epoch = state.write_epoch;
            let old_keys = self.write_keys.replace(next_keys).ok_or_else(|| {
                RecordError::Io(io::Error::other(
                    "DTLS 1.3 KeyUpdate has no current write keys",
                ))
            })?;
            state.previous_write = Some((old_epoch, old_keys));
            state.write_epoch = old_epoch.checked_add(1).ok_or_else(seq_overflow)?;
        }
        Ok(())
    }

    fn send_dtls13_ack_records(
        &mut self,
        records: &[(u16, u64)],
        outer_epoch: Option<u16>,
        overflow_epoch: bool,
    ) -> Result<(), RecordError> {
        let write_epoch = outer_epoch.unwrap_or(self.dtls13.as_ref().unwrap().write_epoch);
        let mut ack = Vec::with_capacity(2 + 16 * records.len());
        ack.extend_from_slice(&(16u16 * records.len() as u16).to_be_bytes());
        for (epoch, sequence) in records {
            let embedded_epoch =
                u64::from(*epoch).wrapping_add(if overflow_epoch { 1u64 << 63 } else { 0 });
            ack.extend_from_slice(&embedded_epoch.to_be_bytes());
            ack.extend_from_slice(&sequence.to_be_bytes());
        }
        if write_epoch == 0 {
            let header = DtlsRecordHeader::new(
                26,
                0,
                self.dtls13.as_ref().unwrap().plain_write_seq,
                ack.len() as u16,
            );
            self.dtls13.as_mut().unwrap().plain_write_seq += 1;
            let mut wire = header.encode().to_vec();
            wire.extend_from_slice(&ack);
            self.emit(&wire)?;
            return self.transport.flush().map_err(RecordError::from);
        }
        let wire = seal_dtls13_aead(
            self.write_keys.as_mut().unwrap(),
            write_epoch,
            26,
            &ack,
            &[],
            self.dtls13.as_ref().unwrap().sequence_map,
        )?;
        self.emit(&wire)?;
        self.transport.flush().map_err(RecordError::from)
    }

    /// Pull up to `n` bytes of handshake payload, drawing from the
    /// buffered leftover and reading more records until we have
    /// enough. Any intervening non-handshake records (like an Alert
    /// during the handshake) surface as errors.
    pub fn read_handshake_bytes(&mut self, n: usize) -> Result<Vec<u8>, RecordError> {
        while self.read_buffer_ct != CONTENT_TYPE_HANDSHAKE || self.read_buffer.len() < n {
            self.refill_for(CONTENT_TYPE_HANDSHAKE)?;
        }
        let drained: Vec<u8> = self.read_buffer.drain(..n).collect();
        Ok(drained)
    }

    /// Pull one ChangeCipherSpec record, expecting exactly the byte
    /// 0x01 as its payload. TLS 1.2 emits CCS as a standalone
    /// content type, not a handshake message, so we can't read it
    /// via `read_handshake_bytes`.
    pub fn read_change_cipher_spec(&mut self) -> Result<(), RecordError> {
        while self.read_buffer_ct == CONTENT_TYPE_HANDSHAKE && !self.read_buffer.is_empty() {
            self.consume_post_handshake()?;
        }
        if !self.read_buffer.is_empty() {
            // The caller didn't consume everything; we're out of
            // sync.
            return Err(RecordError::UnexpectedContentType {
                expected: CONTENT_TYPE_CCS,
                got: self.read_buffer_ct,
            });
        }
        // In a TLS 1.2 ticket handshake the server sends a NewSessionTicket
        // (plaintext handshake record) immediately before its CCS. Stash it so
        // the driver can absorb it into the transcript (the server Finished MAC
        // covers it) and capture the ticket, then read the actual CCS.
        loop {
            let (ct, body) = self.read_record()?;
            if ct == CONTENT_TYPE_ALERT && body.len() == 2 {
                return Err(RecordError::RemoteAlert {
                    level: body[0],
                    description: body[1],
                });
            }
            if ct == CONTENT_TYPE_HANDSHAKE {
                self.read_buffer = body;
                self.read_buffer_ct = ct;
                while !self.read_buffer.is_empty() {
                    self.consume_post_handshake()?;
                }
                continue;
            }
            // T5: see `refill_for` -- app data crossing a renegotiation is kept.
            if self.renegotiating && ct == CONTENT_TYPE_APP_DATA {
                self.read_buffer = body;
                self.read_buffer_ct = ct;
                return Err(RecordError::UnexpectedContentType {
                    expected: CONTENT_TYPE_CCS,
                    got: ct,
                });
            }
            if ct != CONTENT_TYPE_CCS {
                return Err(RecordError::UnexpectedContentType {
                    expected: CONTENT_TYPE_CCS,
                    got: ct,
                });
            }
            if body != [0x01] {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::TrailingBytes,
                ));
            }
            return Ok(());
        }
    }

    /// Read one application data record's plaintext.
    pub fn read_app_data(&mut self) -> Result<Vec<u8>, RecordError> {
        loop {
            if self.read_buffer_ct == CONTENT_TYPE_HANDSHAKE && !self.read_buffer.is_empty() {
                self.consume_post_handshake()?;
                continue;
            }
            if !self.read_buffer.is_empty() {
                if self.read_buffer_ct != CONTENT_TYPE_APP_DATA {
                    return Err(RecordError::UnexpectedContentType {
                        expected: CONTENT_TYPE_APP_DATA,
                        got: self.read_buffer_ct,
                    });
                }
                return Ok(std::mem::take(&mut self.read_buffer));
            }
            self.refill_for(CONTENT_TYPE_APP_DATA)?;
        }
    }

    /// Consume exactly one framed post-handshake message. The same buffer is
    /// shared with explicit receives, including partial headers and bodies.
    fn consume_post_handshake(&mut self) -> Result<(), RecordError> {
        while self.read_buffer.len() < 4 {
            self.refill_for(CONTENT_TYPE_HANDSHAKE)?;
        }
        let kind = self.read_buffer[0];
        if !matches!(
            kind,
            crate::tls::codec::HS_NEW_SESSION_TICKET | crate::tls::codec::HS_KEY_UPDATE
        ) {
            return Err(RecordError::UnexpectedContentType {
                expected: CONTENT_TYPE_APP_DATA,
                got: CONTENT_TYPE_HANDSHAKE,
            });
        }
        let len = ((self.read_buffer[1] as usize) << 16)
            | ((self.read_buffer[2] as usize) << 8)
            | self.read_buffer[3] as usize;
        if len > 1 << 20 {
            return Err(RecordError::RecordTooLarge(len));
        }
        while self.read_buffer.len() < 4 + len {
            self.refill_for(CONTENT_TYPE_HANDSHAKE)?;
        }
        let framed: Vec<u8> = self.read_buffer.drain(..4 + len).collect();
        if kind == crate::tls::codec::HS_KEY_UPDATE {
            crate::tls::codec::decode_key_update_body(&framed[4..])?;
            return Err(RecordError::KeyUpdateReceived { framed });
        }
        match self.version {
            TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12 => {
                crate::tls::codec::decode_new_session_ticket_body(&framed[4..])?;
            }
            TlsVersion::Tls13 => {
                crate::tls::codec::decode_new_session_ticket_13_body(&framed[4..])?;
            }
        }
        // The driver only needs the last ticket for resumption, but TLS 1.2
        // must absorb every ticket into its transcript.
        if self.swallowed_nst.len() >= 1024 {
            return Err(RecordError::RecordTooLarge(self.swallowed_nst.len()));
        }
        self.swallowed_nst.push_back(framed);
        self.swallowed_nst_count += 1;
        Ok(())
    }

    /// Write application data as a single record.
    pub fn write_app_data(&mut self, data: &[u8]) -> Result<(), RecordError> {
        self.write_record(CONTENT_TYPE_APP_DATA, data)
    }

    /// Close the underlying transport (after any close_notify alert).
    pub fn close(&mut self) -> io::Result<()> {
        self.transport.close()
    }

    /// T6: abortive close (TCP RST): `close reset`.
    pub fn close_reset(&mut self) -> io::Result<()> {
        self.transport.close_reset()
    }

    /// Probe: temporarily set the read timeout to `millis`
    /// milliseconds, drain post-handshake records until the deadline. If the read times
    /// out (WouldBlock/TimedOut), return Ok — the peer was
    /// silent. If data arrives (typically an alert record),
    /// return the appropriate RecordError. Restores the normal five-second
    /// transport timeout afterwards. Partial wire bytes remain buffered.
    pub fn probe(&mut self, millis: u64) -> Result<(), RecordError> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_millis(millis);
        let previous_deadline = self.read_deadline.replace(deadline);
        let result = (|| loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let _ = self.transport.set_read_timeout(Some(remaining));
            if !self.read_buffer.is_empty() {
                if self.read_buffer_ct != CONTENT_TYPE_HANDSHAKE {
                    return Err(RecordError::UnexpectedContentType {
                        expected: 0,
                        got: self.read_buffer_ct,
                    });
                }
                self.consume_post_handshake()?;
                continue;
            }
            match self.read_record() {
                Ok((CONTENT_TYPE_HANDSHAKE, body)) => {
                    self.read_buffer = body;
                    self.read_buffer_ct = CONTENT_TYPE_HANDSHAKE;
                }
                Ok((CONTENT_TYPE_ALERT, body)) if body.len() == 2 => {
                    return Err(RecordError::RemoteAlert {
                        level: body[0],
                        description: body[1],
                    });
                }
                Ok((ct, _)) => {
                    return Err(RecordError::UnexpectedContentType {
                        expected: 0,
                        got: ct,
                    });
                }
                Err(RecordError::Io(ref e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && self.wire_read_buffer.is_empty() =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        })();
        self.read_deadline = previous_deadline;
        let _ = self.transport.set_read_deadline(previous_deadline);
        let _ = self
            .transport
            .set_read_timeout(Some(Duration::from_secs(5)));
        result
    }

    /// Write raw bytes directly to the transport, bypassing the
    /// record layer entirely. Used for injecting crafted records.
    /// T1: the explicit nonces of every TLS 1.2 explicit-nonce AEAD record
    /// read so far (empty for other suites / versions).
    pub fn explicit_nonce_trace(&self) -> Vec<u64> {
        self.explicit_nonces.clone()
    }

    /// T1: abortive close (`close reset`).
    pub fn reset(&mut self) -> io::Result<()> {
        self.transport.reset()
    }

    pub fn write_raw(&mut self, data: &[u8]) -> Result<(), RecordError> {
        self.flush_coalesced()?;
        self.emit(data)
    }

    // ---- internal helpers ----

    fn apply_read_deadline(&mut self) -> io::Result<()> {
        if let Some(deadline) = self.read_deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "record read deadline expired",
                ));
            }
            self.transport.set_read_deadline(Some(deadline))?;
        }
        Ok(())
    }

    fn fill_wire_buffer(&mut self, length: usize) -> Result<(), RecordError> {
        while self.wire_read_buffer.len() < length {
            self.apply_read_deadline()?;
            let mut buffer = [0u8; 16384];
            let want = (length - self.wire_read_buffer.len()).min(buffer.len());
            match self.transport.read(&mut buffer[..want]) {
                Ok(0) => {
                    if !self.wire_read_buffer.is_empty() || !self.read_buffer.is_empty() {
                        return Err(RecordError::Codec(
                            crate::tls::codec::CodecError::UnexpectedEof,
                        ));
                    }
                    return Err(
                        io::Error::new(io::ErrorKind::UnexpectedEof, "EOF in TLS record").into(),
                    );
                }
                Ok(n) => self.wire_read_buffer.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn take_datagram_bytes(&mut self, length: usize) -> Result<Vec<u8>, RecordError> {
        if self.wire_read_buffer.len() < length {
            self.wire_read_buffer.clear();
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::InvalidValue(
                    "DTLS record crosses datagram boundary",
                ),
            ));
        }
        Ok(self.wire_read_buffer.drain(..length).collect())
    }

    fn refill_for(&mut self, expected: u8) -> Result<(), RecordError> {
        loop {
            let (ct, body) = self.read_record()?;
            if ct == CONTENT_TYPE_ALERT && body.len() == 2 {
                return Err(RecordError::RemoteAlert {
                    level: body[0],
                    description: body[1],
                });
            }
            // A zero-length application_data record carries nothing (RFC 8446
            // 5.1 permits them; Botan echoes an empty write as one). Waiting on
            // app data means waiting on BYTES, so skip it and keep reading.
            if ct == CONTENT_TYPE_APP_DATA && expected == CONTENT_TYPE_APP_DATA && body.is_empty() {
                continue;
            }
            if ct == expected {
                // A handshake message may span records (a peer honouring
                // record_size_limit or max_fragment_length fragments its
                // Certificate): keep the partial message and append. Any
                // other type replaces the buffer; if there were leftover
                // bytes of a different type we should have errored earlier.
                if ct == CONTENT_TYPE_HANDSHAKE
                    && self.read_buffer_ct == CONTENT_TYPE_HANDSHAKE
                    && !self.read_buffer.is_empty()
                {
                    self.read_buffer.extend_from_slice(&body);
                } else {
                    self.read_buffer = body;
                    self.read_buffer_ct = ct;
                }
                return Ok(());
            }
            if expected == CONTENT_TYPE_APP_DATA && ct == CONTENT_TYPE_HANDSHAKE {
                self.read_buffer = body;
                self.read_buffer_ct = ct;
                return Ok(());
            }
            // T5: application data that arrives while a TLS 1.2 renegotiation
            // handshake is being read (RFC 5246 7.4.1.1 lets the peer keep
            // sending under the old keys) is kept as buffered app-data bytes so
            // the driver can set it aside (`read_app_data` drains it) and go on
            // reading the handshake; the mismatch is still reported.
            if self.renegotiating
                && expected == CONTENT_TYPE_HANDSHAKE
                && ct == CONTENT_TYPE_APP_DATA
            {
                self.read_buffer = body;
                self.read_buffer_ct = ct;
                return Err(RecordError::UnexpectedContentType { expected, got: ct });
            }
            return Err(RecordError::UnexpectedContentType { expected, got: ct });
        }
    }
}

/// Apply mutations which deliberately cross a handshake-message boundary
/// within one TLS record. These are kept out of the body encoder so the first
/// message's length and the logical transcript remain unchanged.
fn apply_handshake_stream_mutations(
    payload: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    let mut out = payload.to_vec();
    for mutation in mutations {
        match &mutation.op {
            MutationOp::TrailingBytes(bytes) => out.extend_from_slice(bytes),
            MutationOp::OmitPrefix(count) => {
                if *count > out.len() {
                    return Err(RecordError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "omit_prefix exceeds the encoded handshake message",
                    )));
                }
                out.drain(..*count);
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod handshake_stream_mutation_tests {
    use super::*;
    use crate::ast::Span;
    use crate::transport::MockTransport;

    fn mutation(op: MutationOp) -> Mutation {
        Mutation {
            op,
            span: Span::dummy(),
        }
    }

    #[test]
    fn trailing_bytes_do_not_change_the_framed_message() {
        let framed = [0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb];
        let output = apply_handshake_stream_mutations(
            &framed,
            &[mutation(MutationOp::TrailingBytes(vec![0x14, 0x00]))],
        )
        .unwrap();
        assert_eq!(output, [framed.as_slice(), &[0x14, 0x00]].concat());
        assert_eq!(&output[..4], &framed[..4]);
    }

    #[test]
    fn omit_prefix_finishes_a_prefix_sent_in_an_earlier_record() {
        let finished = [0x14, 0x00, 0x00, 0x02, 0xaa, 0xbb];
        let output =
            apply_handshake_stream_mutations(&finished, &[mutation(MutationOp::OmitPrefix(1))])
                .unwrap();
        assert_eq!(output, finished[1..]);
    }

    #[test]
    fn omit_prefix_rejects_a_count_past_the_message() {
        let err =
            apply_handshake_stream_mutations(&[0x14, 0x00], &[mutation(MutationOp::OmitPrefix(3))])
                .unwrap_err();
        assert!(err.to_string().contains("omit_prefix exceeds"));
    }

    #[test]
    fn fragmenting_empty_application_data_still_writes_one_record() {
        let transport = MockTransport::new("empty fragmented record");
        let mut records = RecordLayer::new(Box::new(transport.clone()), TlsVersion::Tls10);
        records
            .write_record_with_mutations(
                CONTENT_TYPE_APP_DATA,
                &[],
                &[mutation(MutationOp::Fragment {
                    size: 1,
                    hold: FragHold::None,
                })],
            )
            .unwrap();
        assert_eq!(transport.written(), [CONTENT_TYPE_APP_DATA, 3, 1, 0, 0]);
    }
}

// ============================================================
//                      TLS 1.2 AEAD wrappers
// ============================================================

fn seq_overflow() -> RecordError {
    RecordError::Io(io::Error::other("record sequence number overflow"))
}

// ============================================================
//        Record protection shared by TLS 1.2 and DTLS 1.2
// ============================================================
//
// RFC 6347 4.1.2 reuses the TLS 1.2 record protection unchanged except for
// what stands in as "the sequence number": TLS feeds its implicit 64-bit
// counter, DTLS the record header's explicit epoch(16) || sequence_number(48);
// and the version bytes in the AEAD additional data / MAC input are the wire
// version (0x0303 vs 0xfefd). Every family below takes those two things as a
// `RecordCtx`, so the TLS record layer and both DTLS drivers run one copy of
// the GCM/CCM, ChaCha20, CBC (MAC-then-encrypt and RFC 7366 encrypt-then-MAC)
// and NULL code.

/// The per-record inputs that differ between TLS and DTLS.
#[derive(Clone, Copy, Debug)]
pub struct RecordCtx {
    /// TLS: the implicit 64-bit record counter. DTLS: `epoch << 48 | seq`.
    pub seq: u64,
    /// Version bytes named in the AAD / MAC input: 0x0303 or 0xfefd.
    pub version: [u8; 2],
}

impl RecordCtx {
    pub fn tls(seq: u64) -> Self {
        RecordCtx {
            seq,
            version: LEGACY_RECORD_VERSION,
        }
    }

    /// `seq_num(8) || type(1) || version(2) || length(2)`: the AEAD additional
    /// data (RFC 5246 6.2.3.3) and the prefix of the CBC / NULL MAC input.
    fn header(&self, content_type: u8, len: usize) -> [u8; 13] {
        let mut h = [0u8; 13];
        h[..8].copy_from_slice(&self.seq.to_be_bytes());
        h[8] = content_type;
        h[9] = self.version[0];
        h[10] = self.version[1];
        h[11] = ((len >> 8) & 0xff) as u8;
        h[12] = (len & 0xff) as u8;
        h
    }
}

/// Explicit-nonce AEAD (GCM: RFC 5288, CCM: RFC 6655, ARIA/Camellia GCM):
/// wire body `explicit_nonce(8) || AEAD(key, salt || explicit, AAD, plaintext)`,
/// the explicit nonce being the sequence value.
pub fn seal_explicit_aead(
    key: &AeadKey,
    salt: &[u8; 4],
    ctx: RecordCtx,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let explicit = ctx.seq.to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(&explicit);
    let ciphertext = key.seal(
        &nonce,
        &ctx.header(content_type, plaintext.len()),
        plaintext,
    )?;
    let mut body = Vec::with_capacity(8 + ciphertext.len());
    body.extend_from_slice(&explicit);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

pub fn open_explicit_aead(
    key: &AeadKey,
    salt: &[u8; 4],
    ctx: RecordCtx,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let tag_len = key.alg().tag_len();
    if body.len() < 8 + tag_len {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let (explicit, ciphertext) = body.split_at(8);
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(explicit);
    Ok(key.open(
        &nonce,
        &ctx.header(content_type, ciphertext.len() - tag_len),
        ciphertext,
    )?)
}

/// Implicit-nonce AEAD (ChaCha20-Poly1305, RFC 7905 2): nonce = the 12-byte IV
/// XOR the zero-padded sequence value (the TLS 1.3 construction), nothing
/// explicit on the wire, the ordinary TLS 1.2 AAD.
pub fn seal_implicit_aead(
    key: &AeadKey,
    iv: &[u8; 12],
    ctx: RecordCtx,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let nonce = tls13_nonce(iv, ctx.seq);
    Ok(key.seal(
        &nonce,
        &ctx.header(content_type, plaintext.len()),
        plaintext,
    )?)
}

pub fn open_implicit_aead(
    key: &AeadKey,
    iv: &[u8; 12],
    ctx: RecordCtx,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let tag_len = key.alg().tag_len();
    if body.len() < tag_len {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let nonce = tls13_nonce(iv, ctx.seq);
    Ok(key.open(
        &nonce,
        &ctx.header(content_type, body.len() - tag_len),
        body,
    )?)
}

fn hmac_over(
    mac_alg: crate::tls::crypto::HashAlg,
    mac_key: &[u8],
    ctx: RecordCtx,
    content_type: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(13 + data.len());
    input.extend_from_slice(&ctx.header(content_type, data.len()));
    input.extend_from_slice(data);
    crate::tls::crypto::hmac(mac_alg, mac_key, &input)
}

/// `record.mac` byte mutations on a freshly computed MAC.
fn apply_mac_mutations(mac: &mut [u8], mutations: &[Mutation]) -> Result<(), RecordError> {
    for m in mutations {
        match &m.op {
            MutationOp::Xor { target, value } | MutationOp::Set { target, value }
                if target.is_record_level() && target.field_name() == Some("mac") =>
            {
                let idxs = mutate::resolve_target_indices_pub(target, mac.len())
                    .map_err(|e| RecordError::Io(io::Error::other(e.to_string())))?;
                for idx in idxs {
                    match &m.op {
                        MutationOp::Xor { .. } => mac[idx] ^= *value as u8,
                        MutationOp::Set { .. } => mac[idx] = *value as u8,
                        _ => unreachable!(),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// T2: apply `record.<field>` pre-encryption mutations to `buf`.
fn pre_encrypt_mutate(
    buf: &mut [u8],
    field: &str,
    mutations: &[Mutation],
) -> Result<(), RecordError> {
    mutate::apply_pre_encryption_mutations(buf, field, mutations)
        .map_err(|e| RecordError::Io(io::Error::other(e.to_string())))
}

/// T2: `@ plaintext = <bytes>` (replace the whole pre-encryption block) and
/// `record.plaintext` byte mutations, for the AEAD families whose
/// pre-encryption block is just the plaintext.
fn aead_pre_encrypt(plaintext: &[u8], mutations: &[Mutation]) -> Result<Vec<u8>, RecordError> {
    let mut block = plaintext.to_vec();
    for m in mutations {
        if let MutationOp::ReplacePlaintext(bytes) = &m.op {
            block = bytes.clone();
        }
    }
    pre_encrypt_mutate(&mut block, "plaintext", mutations)?;
    Ok(block)
}

/// T2: the CBC padding for `unpadded` bytes of content: the smallest padding
/// (including its length byte) of at least `min` bytes that reaches a block
/// boundary (RFC 5246 6.2.3.2; tlsfuzzer `fuzz_padding(min_length)`), then
/// any `record.padding` byte mutations (index -1 = the length byte).
fn cbc_padding(unpadded: usize, bl: usize, mutations: &[Mutation]) -> Result<Vec<u8>, RecordError> {
    let min = mutations
        .iter()
        .find_map(|m| match m.op {
            MutationOp::CbcPad(n) => Some(n),
            _ => None,
        })
        .unwrap_or(1);
    let padding_len = (unpadded + min).div_ceil(bl) * bl - unpadded;
    if padding_len > 256 {
        return Err(RecordError::Io(io::Error::other(format!(
            "cbc_pad: {} bytes of padding would be needed to reach a block boundary (max 256)",
            padding_len
        ))));
    }
    let mut padding = vec![(padding_len - 1) as u8; padding_len];
    pre_encrypt_mutate(&mut padding, "padding", mutations)?;
    Ok(padding)
}

/// T2: the `@ plaintext = <bytes>` replacement, if any.
fn replaced_plaintext(mutations: &[Mutation]) -> Option<&[u8]> {
    mutations.iter().rev().find_map(|m| match &m.op {
        MutationOp::ReplacePlaintext(bytes) => Some(bytes.as_slice()),
        _ => None,
    })
}

/// NULL cipher (RFC 5246 6.2.3.1 with the null stream cipher): `plaintext ||
/// HMAC(header || plaintext)`, integrity only.
pub fn seal_null(
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    ctx: RecordCtx,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    let plaintext = aead_pre_encrypt(plaintext, mutations)?;
    let mut mac = hmac_over(mac_alg, mac_key, ctx, content_type, &plaintext);
    apply_mac_mutations(&mut mac, mutations)?;
    let mut body = Vec::with_capacity(plaintext.len() + mac.len());
    body.extend_from_slice(&plaintext);
    body.extend_from_slice(&mac);
    Ok(body)
}

pub fn open_null(
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    ctx: RecordCtx,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let mac_len = mac_alg.output_len();
    if body.len() < mac_len {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let (plaintext, received_mac) = body.split_at(body.len() - mac_len);
    if received_mac != hmac_over(mac_alg, mac_key, ctx, content_type, plaintext).as_slice() {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    Ok(plaintext.to_vec())
}

/// The per-record CBC IV: random, derived from the sequence value so records
/// are reproducible across runs.
fn cbc_iv(cipher: CbcCipher, seq: u64) -> Vec<u8> {
    let mut iv_seed = [0u8; 32];
    iv_seed[..8].copy_from_slice(&seq.to_be_bytes());
    iv_seed[8] = 0xCB; // tag byte to distinguish from other sub-seeds
    let mut rng =
        crate::tls::crypto::Rng::from_seed(crate::tls::crypto::Rng::sub_seed(iv_seed, b"cbc_iv"));
    let iv_full: [u8; 16] = rng.random_array();
    iv_full[..cipher.block_len()].to_vec()
}

/// Strip and verify RFC 5246 6.2.3.2 padding; returns the content length.
fn cbc_unpad(decrypted: &[u8]) -> Result<usize, RecordError> {
    let pad_byte = *decrypted
        .last()
        .ok_or(RecordError::Crypto(CryptoError::AeadOpenFailed))? as usize;
    if pad_byte >= decrypted.len() {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    let content_end = decrypted.len() - pad_byte - 1;
    if decrypted[content_end..]
        .iter()
        .any(|&b| b as usize != pad_byte)
    {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    Ok(content_end)
}

/// CBC block cipher + HMAC (RFC 5246 6.2.3.2), MAC-then-encrypt or, with
/// `etm`, RFC 7366 encrypt-then-MAC.
///
/// MAC-then-encrypt wire body: `IV || CBC(plaintext || MAC || padding)` with
/// the MAC over `header || plaintext`. Encrypt-then-MAC: `IV ||
/// CBC(plaintext || padding) || MAC`, the MAC over `header || IV || ciphertext`
/// where the header's length is that of `IV || ciphertext`.
#[allow(clippy::too_many_arguments)]
pub fn seal_cbc(
    cipher: CbcCipher,
    enc_key: &[u8],
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    etm: bool,
    ctx: RecordCtx,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    let bl = cipher.block_len();
    let iv = cbc_iv(cipher, ctx.seq);
    // T2: `@ plaintext = <bytes>` replaces the whole block before encryption
    // (data || MAC || padding, or data || padding under EtM); it must be
    // block-aligned. `record.plaintext` / `record.padding` mutations and
    // `@ cbc_pad N` shape the block otherwise.
    let replaced = replaced_plaintext(mutations);
    if let Some(r) = replaced {
        if !r.len().is_multiple_of(bl) {
            return Err(RecordError::Io(io::Error::other(format!(
                "plaintext replacement of {} bytes is not a multiple of the {}-byte block",
                r.len(),
                bl
            ))));
        }
    }
    if etm {
        let mut block = match replaced {
            Some(r) => r.to_vec(),
            None => {
                let padding = cbc_padding(plaintext.len(), bl, mutations)?;
                let mut block = Vec::with_capacity(plaintext.len() + padding.len());
                block.extend_from_slice(plaintext);
                block.extend_from_slice(&padding);
                block
            }
        };
        pre_encrypt_mutate(&mut block, "plaintext", mutations)?;
        let ciphertext = crate::tls::crypto::cbc_encrypt(cipher, enc_key, &iv, &block)?;
        let mut body = Vec::with_capacity(bl + ciphertext.len() + 48);
        body.extend_from_slice(&iv);
        body.extend_from_slice(&ciphertext);
        // The MAC is in the clear here, so the peer MUST notice a flipped byte
        // before it decrypts anything (RFC 7366 3).
        let mut mac = hmac_over(mac_alg, mac_key, ctx, content_type, &body);
        apply_mac_mutations(&mut mac, mutations)?;
        body.extend_from_slice(&mac);
        return Ok(body);
    }
    let mut block = match replaced {
        Some(r) => r.to_vec(),
        None => {
            let mut mac = hmac_over(mac_alg, mac_key, ctx, content_type, plaintext);
            apply_mac_mutations(&mut mac, mutations)?;
            let unpadded_len = plaintext.len() + mac.len();
            let padding = cbc_padding(unpadded_len, bl, mutations)?;
            let mut block = Vec::with_capacity(unpadded_len + padding.len());
            block.extend_from_slice(plaintext);
            block.extend_from_slice(&mac);
            block.extend_from_slice(&padding);
            block
        }
    };
    pre_encrypt_mutate(&mut block, "plaintext", mutations)?;
    let ciphertext = crate::tls::crypto::cbc_encrypt(cipher, enc_key, &iv, &block)?;
    let mut body = Vec::with_capacity(bl + ciphertext.len());
    body.extend_from_slice(&iv);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
pub fn open_cbc(
    cipher: CbcCipher,
    enc_key: &[u8],
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    etm: bool,
    ctx: RecordCtx,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let bl = cipher.block_len();
    let mac_len = mac_alg.output_len();
    if etm {
        if body.len() < bl + bl + mac_len {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
        let (enc, received_mac) = body.split_at(body.len() - mac_len);
        // "The MAC SHALL be evaluated before any further processing such as
        // decryption is performed" (RFC 7366 3).
        if received_mac != hmac_over(mac_alg, mac_key, ctx, content_type, enc).as_slice() {
            return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
        }
        let (iv, ciphertext) = enc.split_at(bl);
        let decrypted = crate::tls::crypto::cbc_decrypt(cipher, enc_key, iv, ciphertext)?;
        let content_end = cbc_unpad(&decrypted)?;
        return Ok(decrypted[..content_end].to_vec());
    }
    if body.len() < bl + bl {
        // At least one IV block + one ciphertext block.
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let (iv, ciphertext) = body.split_at(bl);
    let decrypted = crate::tls::crypto::cbc_decrypt(cipher, enc_key, iv, ciphertext)?;
    let content_end = cbc_unpad(&decrypted)?;
    if content_end < mac_len {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    let plaintext_end = content_end - mac_len;
    let plaintext = &decrypted[..plaintext_end];
    let received_mac = &decrypted[plaintext_end..content_end];
    if received_mac != hmac_over(mac_alg, mac_key, ctx, content_type, plaintext).as_slice() {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    Ok(plaintext.to_vec())
}

/// TLS 1.0 CBC record protection. Unlike TLS 1.1+, no IV is carried on the
/// wire: the key-block IV protects the first record and the final ciphertext
/// block of each record protects the next (RFC 2246 section 6.2.3.2).
#[allow(clippy::too_many_arguments)]
fn seal_cbc_implicit(
    cipher: CbcCipher,
    enc_key: &[u8],
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    etm: bool,
    iv: &mut [u8],
    ctx: RecordCtx,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    let bl = cipher.block_len();
    if iv.len() != bl {
        return Err(RecordError::Crypto(CryptoError::BadNonceLength));
    }
    let replaced = replaced_plaintext(mutations);
    if replaced.is_some_and(|r| !r.len().is_multiple_of(bl)) {
        return Err(RecordError::Io(io::Error::other(
            "plaintext replacement is not block-aligned",
        )));
    }
    let mut block = if let Some(r) = replaced {
        r.to_vec()
    } else if etm {
        let mut v = plaintext.to_vec();
        v.extend_from_slice(&cbc_padding(v.len(), bl, mutations)?);
        v
    } else {
        let mut v = plaintext.to_vec();
        let mut mac = hmac_over(mac_alg, mac_key, ctx, content_type, plaintext);
        apply_mac_mutations(&mut mac, mutations)?;
        v.extend_from_slice(&mac);
        v.extend_from_slice(&cbc_padding(v.len(), bl, mutations)?);
        v
    };
    pre_encrypt_mutate(&mut block, "plaintext", mutations)?;
    let ciphertext = crate::tls::crypto::cbc_encrypt(cipher, enc_key, iv, &block)?;
    iv.copy_from_slice(&ciphertext[ciphertext.len() - bl..]);
    if !etm {
        return Ok(ciphertext);
    }
    let mut body = ciphertext;
    let mut mac = hmac_over(mac_alg, mac_key, ctx, content_type, &body);
    apply_mac_mutations(&mut mac, mutations)?;
    body.extend_from_slice(&mac);
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn open_cbc_implicit(
    cipher: CbcCipher,
    enc_key: &[u8],
    mac_key: &[u8],
    mac_alg: crate::tls::crypto::HashAlg,
    etm: bool,
    iv: &mut [u8],
    ctx: RecordCtx,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let bl = cipher.block_len();
    let mac_len = mac_alg.output_len();
    let ciphertext = if etm {
        if body.len() < bl + mac_len {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
        let (enc, received_mac) = body.split_at(body.len() - mac_len);
        if received_mac != hmac_over(mac_alg, mac_key, ctx, content_type, enc).as_slice() {
            return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
        }
        enc
    } else {
        body
    };
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(bl) || iv.len() != bl {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let decrypted = crate::tls::crypto::cbc_decrypt(cipher, enc_key, iv, ciphertext)?;
    iv.copy_from_slice(&ciphertext[ciphertext.len() - bl..]);
    let content_end = cbc_unpad(&decrypted)?;
    if etm {
        return Ok(decrypted[..content_end].to_vec());
    }
    if content_end < mac_len {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    let plaintext_end = content_end - mac_len;
    let plaintext = &decrypted[..plaintext_end];
    if decrypted[plaintext_end..content_end]
        != hmac_over(mac_alg, mac_key, ctx, content_type, plaintext)
    {
        return Err(RecordError::Crypto(CryptoError::AeadOpenFailed));
    }
    Ok(plaintext.to_vec())
}

impl DirectionKeys {
    /// The AEAD tag length this direction appends (0 for CBC / NULL, whose
    /// MAC is not a `record.aead_tag` target).
    pub fn aead_tag_len(&self) -> usize {
        match self {
            DirectionKeys::Tls12 { key, .. }
            | DirectionKeys::Tls12ImplicitNonce { key, .. }
            | DirectionKeys::Tls13 { key, .. } => key.alg().tag_len(),
            DirectionKeys::Tls12Cbc { .. } | DirectionKeys::Tls12Null { .. } => 0,
        }
    }

    /// The next record's sequence number (TLS 1.2 / 1.3 counters).
    pub fn seq(&self) -> u64 {
        match self {
            DirectionKeys::Tls12 { seq, .. }
            | DirectionKeys::Tls12ImplicitNonce { seq, .. }
            | DirectionKeys::Tls13 { seq, .. }
            | DirectionKeys::Tls12Cbc { seq, .. }
            | DirectionKeys::Tls12Null { seq, .. } => *seq,
        }
    }

    /// Protect one TLS 1.2-family record under an explicit sequence value and
    /// wire version -- the DTLS entry point (epoch || seq, 0xfefd). Does not
    /// touch the TLS counter; `record.mac` mutations apply where the family
    /// keeps its MAC (an AEAD tag is mutated by the caller after sealing).
    pub fn seal_with(
        &self,
        ctx: RecordCtx,
        content_type: u8,
        plaintext: &[u8],
        mutations: &[Mutation],
    ) -> Result<Vec<u8>, RecordError> {
        match self {
            DirectionKeys::Tls12 { key, salt, .. } => {
                let pt = aead_pre_encrypt(plaintext, mutations)?;
                seal_explicit_aead(key, salt, ctx, content_type, &pt)
            }
            DirectionKeys::Tls12ImplicitNonce { key, iv, .. } => {
                let pt = aead_pre_encrypt(plaintext, mutations)?;
                seal_implicit_aead(key, iv, ctx, content_type, &pt)
            }
            DirectionKeys::Tls12Cbc {
                cipher,
                enc_key,
                mac_key,
                mac_alg,
                etm,
                ..
            } => seal_cbc(
                *cipher,
                enc_key,
                mac_key,
                *mac_alg,
                *etm,
                ctx,
                content_type,
                plaintext,
                mutations,
            ),
            DirectionKeys::Tls12Null {
                mac_key, mac_alg, ..
            } => seal_null(mac_key, *mac_alg, ctx, content_type, plaintext, mutations),
            DirectionKeys::Tls13 { .. } => Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            )),
        }
    }

    pub fn open_with(
        &self,
        ctx: RecordCtx,
        content_type: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, RecordError> {
        match self {
            DirectionKeys::Tls12 { key, salt, .. } => {
                open_explicit_aead(key, salt, ctx, content_type, body)
            }
            DirectionKeys::Tls12ImplicitNonce { key, iv, .. } => {
                open_implicit_aead(key, iv, ctx, content_type, body)
            }
            DirectionKeys::Tls12Cbc {
                cipher,
                enc_key,
                mac_key,
                mac_alg,
                etm,
                ..
            } => open_cbc(
                *cipher,
                enc_key,
                mac_key,
                *mac_alg,
                *etm,
                ctx,
                content_type,
                body,
            ),
            DirectionKeys::Tls12Null {
                mac_key, mac_alg, ..
            } => open_null(mac_key, *mac_alg, ctx, content_type, body),
            DirectionKeys::Tls13 { .. } => Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            )),
        }
    }
}

// ============================================================
//                      TLS 1.2 wrappers
// ============================================================
//
// The TLS record layer feeds its own counter and bumps it per record.

fn seal_tls12(
    keys: &mut DirectionKeys,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
    record_version: u16,
) -> Result<Vec<u8>, RecordError> {
    let ctx = RecordCtx {
        seq: keys.seq(),
        version: record_version.to_be_bytes(),
    };
    let body = match keys {
        DirectionKeys::Tls12Cbc {
            cipher,
            enc_key,
            mac_key,
            mac_alg,
            etm,
            implicit_iv: Some(iv),
            ..
        } => seal_cbc_implicit(
            *cipher,
            enc_key,
            mac_key,
            *mac_alg,
            *etm,
            iv,
            ctx,
            content_type,
            plaintext,
            mutations,
        )?,
        _ => keys.seal_with(ctx, content_type, plaintext, mutations)?,
    };
    bump_seq(keys)?;
    Ok(body)
}

fn open_tls12(
    keys: &mut DirectionKeys,
    content_type: u8,
    body: &[u8],
    record_version: u16,
) -> Result<Vec<u8>, RecordError> {
    let ctx = RecordCtx {
        seq: keys.seq(),
        version: record_version.to_be_bytes(),
    };
    let plaintext = match keys {
        DirectionKeys::Tls12Cbc {
            cipher,
            enc_key,
            mac_key,
            mac_alg,
            etm,
            implicit_iv: Some(iv),
            ..
        } => open_cbc_implicit(
            *cipher,
            enc_key,
            mac_key,
            *mac_alg,
            *etm,
            iv,
            ctx,
            content_type,
            body,
        )?,
        _ => keys.open_with(ctx, content_type, body)?,
    };
    bump_seq(keys)?;
    Ok(plaintext)
}

#[cfg(test)]
fn seal_tls12_aead(
    keys: &mut DirectionKeys,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    seal_tls12(
        keys,
        content_type,
        plaintext,
        &[],
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn open_tls12_aead(
    keys: &mut DirectionKeys,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    open_tls12(
        keys,
        content_type,
        body,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn seal_tls12_implicit_aead(
    keys: &mut DirectionKeys,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    seal_tls12(
        keys,
        content_type,
        plaintext,
        &[],
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn open_tls12_implicit_aead(
    keys: &mut DirectionKeys,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    open_tls12(
        keys,
        content_type,
        body,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn seal_tls12_null(
    keys: &mut DirectionKeys,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    seal_tls12(
        keys,
        content_type,
        plaintext,
        mutations,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn open_tls12_null(
    keys: &mut DirectionKeys,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    open_tls12(
        keys,
        content_type,
        body,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn seal_tls12_cbc(
    keys: &mut DirectionKeys,
    content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
) -> Result<Vec<u8>, RecordError> {
    seal_tls12(
        keys,
        content_type,
        plaintext,
        mutations,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}
#[cfg(test)]
fn open_tls12_cbc(
    keys: &mut DirectionKeys,
    content_type: u8,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    open_tls12(
        keys,
        content_type,
        body,
        u16::from_be_bytes(LEGACY_RECORD_VERSION),
    )
}

// ============================================================
//                      TLS 1.3 AEAD wrappers
// ============================================================

fn dtls13_header_len(mutations: &[Mutation]) -> usize {
    if mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13LegacyHeader))
    {
        return DTLS_RECORD_HEADER_LEN;
    }
    let sequence_len = if mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13ShortSequence))
    {
        1
    } else {
        2
    };
    let length_len = if mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13OmitLength))
    {
        0
    } else {
        2
    };
    1 + sequence_len + length_len
}

/// Seal one DTLS 1.3 ciphertext record. The default is BoringSSL's ordinary
/// profile (no CID, a two-byte protected sequence number and an explicit
/// length); dedicated pre-seal mutations select the other RFC 9147 header
/// forms or BoGo's deliberately invalid legacy-header form.
fn seal_dtls13_aead(
    keys: &mut DirectionKeys,
    epoch: u16,
    real_content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
    sequence_map: crate::ir::DtlsSequenceMap,
) -> Result<Vec<u8>, RecordError> {
    let (key, iv, rn_key, seq_now) = match keys {
        DirectionKeys::Tls13 {
            key,
            iv,
            rn_key: Some(rn_key),
            seq,
        } => (key, *iv, rn_key, *seq),
        _ => return Err(RecordError::Crypto(CryptoError::BadKeyLength)),
    };
    let sequence = sequence_map.apply(seq_now);
    let mut ct_byte = [real_content_type];
    pre_encrypt_mutate(&mut ct_byte, "inner_type", mutations)?;
    let mut inner = plaintext.to_vec();
    inner.push(ct_byte[0]);
    if let Some(Some(n)) = mutations.iter().find_map(|m| match m.op {
        MutationOp::RecordPad(n) => Some(n),
        _ => None,
    }) {
        inner.extend(std::iter::repeat_n(0u8, n));
    }
    if let Some(r) = replaced_plaintext(mutations) {
        inner = r.to_vec();
    }
    pre_encrypt_mutate(&mut inner, "plaintext", mutations)?;

    let ciphertext_len = inner.len() + key.alg().tag_len();
    if ciphertext_len > u16::MAX as usize {
        return Err(RecordError::RecordTooLarge(ciphertext_len));
    }
    let legacy_header = mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13LegacyHeader));
    let short_sequence = mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13ShortSequence));
    let omit_length = mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13OmitLength));
    let set_cid = mutations
        .iter()
        .any(|m| matches!(m.op, MutationOp::Dtls13SetCidBit));

    let mut header = Vec::with_capacity(dtls13_header_len(mutations));
    let nonce_sequence = if legacy_header {
        // BoGo's DTLSUsePlaintextRecordHeader test authenticates a classic
        // DTLS 1.2 header and also retains the classic epoch||sequence nonce.
        header.push(real_content_type);
        header.extend_from_slice(&0xfefd_u16.to_be_bytes());
        header.extend_from_slice(&epoch.to_be_bytes());
        let be = sequence.to_be_bytes();
        header.extend_from_slice(&be[2..]);
        header.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
        ((u64::from(epoch)) << 48) | sequence
    } else {
        let mut first = 0x20 | ((epoch & 3) as u8);
        if set_cid {
            first |= 0x10;
        }
        if !short_sequence {
            first |= 0x08;
        }
        if !omit_length {
            first |= 0x04;
        }
        header.push(first);
        if short_sequence {
            header.push(sequence as u8);
        } else {
            header.extend_from_slice(&(sequence as u16).to_be_bytes());
        }
        if !omit_length {
            header.extend_from_slice(&(ciphertext_len as u16).to_be_bytes());
        }
        sequence
    };
    let nonce = tls13_nonce(&iv, nonce_sequence);
    let ciphertext = key.seal(&nonce, &header, &inner)?;
    if !legacy_header {
        let mask = crate::tls::crypto::dtls13_record_number_mask(key.alg(), rn_key, &ciphertext)?;
        let sequence_len = if short_sequence { 1 } else { 2 };
        for i in 0..sequence_len {
            header[1 + i] ^= mask[i];
        }
    }
    bump_seq(keys)?;

    let mut wire = Vec::with_capacity(header.len() + ciphertext.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

fn open_dtls13_aead(
    keys: &DirectionKeys,
    sequence: u64,
    aad: &[u8],
    body: &[u8],
) -> Result<(u8, Vec<u8>), RecordError> {
    let (key, iv) = match keys {
        DirectionKeys::Tls13 { key, iv, .. } => (key, *iv),
        _ => return Err(RecordError::Crypto(CryptoError::BadKeyLength)),
    };
    if body.len() < key.alg().tag_len() + 1 {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let nonce = tls13_nonce(&iv, sequence);
    let inner = key.open(&nonce, aad, body)?;
    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    Ok((inner[end - 1], inner[..end - 1].to_vec()))
}

/// Reconstruct an 8- or 16-bit DTLS 1.3 record number around the next value
/// after the greatest authenticated number in this epoch (RFC 9147 4.2.2).
fn reconstruct_dtls13_sequence(highest: Option<u64>, truncated: u64, bits: usize) -> u64 {
    let expected = highest.map_or(0, |value| value.saturating_add(1));
    let window = 1u64 << bits;
    let half = window / 2;
    let mask = window - 1;
    let mut candidate = (expected & !mask) | (truncated & mask);
    if candidate.saturating_add(half) <= expected {
        candidate = candidate.saturating_add(window);
    } else if candidate > expected.saturating_add(half) && candidate >= window {
        candidate -= window;
    }
    candidate
}

/// Decode a received DTLS 1.3 datagram without advancing record state, for
/// `expect_retransmit`. ACKs, alerts and application records contribute no
/// identities; malformed or unauthenticated records fail the assertion.
fn inspect_dtls13_handshake_identities(
    datagram: &[u8],
    state: &Dtls13State,
    current_read: Option<&DirectionKeys>,
) -> Result<Vec<(u8, u16)>, RecordError> {
    let mut cursor = 0usize;
    let mut identities = Vec::new();
    while cursor < datagram.len() {
        let first = datagram[cursor];
        let plaintext = if first & 0xe0 == 0x20 {
            if first & 0x10 != 0 || first & 0x04 == 0 {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported DTLS 1.3 retransmit header",
                )));
            }
            let seq_len = if first & 0x08 != 0 { 2 } else { 1 };
            let header_len = 1 + seq_len + 2;
            if datagram.len() - cursor < header_len {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let mut header = datagram[cursor..cursor + header_len].to_vec();
            let len_off = 1 + seq_len;
            let len = u16::from_be_bytes([header[len_off], header[len_off + 1]]) as usize;
            if datagram.len() - cursor - header_len < len {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let body = &datagram[cursor + header_len..cursor + header_len + len];
            cursor += header_len + len;
            let epoch_bits = u16::from(first & 3);
            let (epoch, keys) = if state.read_epoch & 3 == epoch_bits {
                (
                    state.read_epoch,
                    current_read.ok_or(CryptoError::BadKeyLength)?,
                )
            } else if let Some((epoch, keys)) = &state.previous_read {
                if epoch & 3 != epoch_bits {
                    return Err(RecordError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DTLS 1.3 retransmit is from an unavailable epoch",
                    )));
                }
                (*epoch, keys)
            } else {
                return Err(RecordError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DTLS 1.3 retransmit is from an unavailable epoch",
                )));
            };
            let mask = match keys {
                DirectionKeys::Tls13 {
                    key,
                    rn_key: Some(rn_key),
                    ..
                } => crate::tls::crypto::dtls13_record_number_mask(key.alg(), rn_key, body)?,
                _ => return Err(RecordError::Crypto(CryptoError::BadKeyLength)),
            };
            for index in 0..seq_len {
                header[1 + index] ^= mask[index];
            }
            let truncated = if seq_len == 2 {
                u64::from(u16::from_be_bytes([header[1], header[2]]))
            } else {
                u64::from(header[1])
            };
            let sequence = reconstruct_dtls13_sequence(
                state.read_highest.get(&epoch).copied(),
                truncated,
                seq_len * 8,
            );
            let (content_type, plaintext) = open_dtls13_aead(keys, sequence, &header, body)?;
            if content_type != CONTENT_TYPE_HANDSHAKE {
                continue;
            }
            plaintext
        } else {
            if datagram.len() - cursor < DTLS_RECORD_HEADER_LEN {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let header =
                DtlsRecordHeader::parse(&datagram[cursor..cursor + DTLS_RECORD_HEADER_LEN])
                    .map_err(|_| {
                        RecordError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed DTLS plaintext retransmit record",
                        ))
                    })?;
            let length = header.length as usize;
            if datagram.len() - cursor - DTLS_RECORD_HEADER_LEN < length {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let body = datagram
                [cursor + DTLS_RECORD_HEADER_LEN..cursor + DTLS_RECORD_HEADER_LEN + length]
                .to_vec();
            cursor += DTLS_RECORD_HEADER_LEN + length;
            if header.content_type != CONTENT_TYPE_HANDSHAKE {
                continue;
            }
            body
        };
        let mut handshake = plaintext.as_slice();
        while !handshake.is_empty() {
            if handshake.len() < crate::tls::dtls_record::DTLS_HANDSHAKE_HEADER_LEN {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            let header = DtlsHandshakeHeader::parse(handshake)
                .map_err(|_| RecordError::Codec(crate::tls::codec::CodecError::UnexpectedEof))?;
            let total = crate::tls::dtls_record::DTLS_HANDSHAKE_HEADER_LEN
                + header.fragment_length as usize;
            if handshake.len() < total {
                return Err(RecordError::Codec(
                    crate::tls::codec::CodecError::UnexpectedEof,
                ));
            }
            identities.push((header.msg_type, header.message_seq));
            handshake = &handshake[total..];
        }
    }
    Ok(identities)
}

/// TLS 1.3 RFC 8446 §5.2 AEAD record framing.
///
/// The plaintext we authenticate is `inner = payload ||
/// real_content_type (|| padding)`. We don't pad in the wedge. The
/// per-record nonce is `pad8(seq) XOR static_iv`, where `pad8` left-
/// pads the 8-byte seq to 12 bytes. AAD is the outer record header
/// with the outer (app_data=0x17) content type and the length of
/// the **encrypted** output, including the 16-byte tag.
fn seal_tls13_aead(
    keys: &mut DirectionKeys,
    real_content_type: u8,
    plaintext: &[u8],
    mutations: &[Mutation],
    record_version: u16,
) -> Result<Vec<u8>, RecordError> {
    let (iv, seq_now) = match keys {
        DirectionKeys::Tls13 { iv, seq, .. } => (*iv, *seq),
        _ => {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
    };
    let nonce = tls13_nonce(&iv, seq_now);
    // T2: `set[record.inner_type] = N` rewrites the inner content type;
    // `@ record_pad N | fill` appends N zero bytes (or up to the 2^14 + 1 byte
    // TLSInnerPlaintext maximum, RFC 8446 5.4); `record.plaintext` mutations
    // and `@ plaintext = <bytes>` then act on the whole inner plaintext.
    let mut ct_byte = [real_content_type];
    pre_encrypt_mutate(&mut ct_byte, "inner_type", mutations)?;
    let record_pad = mutations.iter().find_map(|m| match m.op {
        MutationOp::RecordPad(n) => Some(n),
        _ => None,
    });
    let mut inner = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(ct_byte[0]);
    match record_pad {
        Some(Some(n)) => inner.extend(std::iter::repeat_n(0u8, n)),
        Some(None) => {
            let max = (1usize << 14) + 1;
            if inner.len() < max {
                inner.extend(std::iter::repeat_n(0u8, max - inner.len()));
            }
        }
        None => {}
    }
    if let Some(r) = replaced_plaintext(mutations) {
        inner = r.to_vec();
    }
    pre_encrypt_mutate(&mut inner, "plaintext", mutations)?;
    let tag_len = match keys {
        DirectionKeys::Tls13 { key, .. } => key.alg().tag_len(),
        _ => 16,
    };
    let outer_len = inner.len() + tag_len;
    let aad = tls13_aad(record_version, outer_len);
    let ciphertext = match keys {
        DirectionKeys::Tls13 { key, .. } => key.seal(&nonce, &aad, &inner)?,
        _ => unreachable!(),
    };
    bump_seq(keys)?;
    Ok(ciphertext)
}

/// Returns `(real_content_type, plaintext)`.
fn open_tls13_aead(keys: &mut DirectionKeys, body: &[u8]) -> Result<(u8, Vec<u8>), RecordError> {
    let tag_len = match keys {
        DirectionKeys::Tls13 { key, .. } => key.alg().tag_len(),
        _ => 16,
    };
    if body.len() < tag_len + 1 {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let (iv, seq_now) = match keys {
        DirectionKeys::Tls13 { iv, seq, .. } => (*iv, *seq),
        _ => {
            return Err(RecordError::Codec(
                crate::tls::codec::CodecError::UnexpectedEof,
            ));
        }
    };
    let nonce = tls13_nonce(&iv, seq_now);
    let aad = tls13_aad(u16::from_be_bytes(LEGACY_RECORD_VERSION), body.len());
    let inner = match keys {
        DirectionKeys::Tls13 { key, .. } => key.open(&nonce, &aad, body)?,
        _ => unreachable!(),
    };
    bump_seq(keys)?;
    // Strip zero padding and recover the real content type. RFC
    // 8446 §5.4: the type byte is the last non-zero byte. Rustls
    // doesn't pad so in practice it's always the last byte, but
    // handle the general case for forward-compat.
    let mut end = inner.len();
    while end > 0 && inner[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(RecordError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof,
        ));
    }
    let real_ct = inner[end - 1];
    let plaintext = inner[..end - 1].to_vec();
    Ok((real_ct, plaintext))
}

fn tls13_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    for i in 0..12 {
        nonce[i] ^= iv[i];
    }
    nonce
}

fn tls13_aad(record_version: u16, outer_len: usize) -> [u8; 5] {
    let version = record_version.to_be_bytes();
    [
        crate::tls::codec::CONTENT_TYPE_APP_DATA,
        version[0],
        version[1],
        ((outer_len >> 8) & 0xff) as u8,
        (outer_len & 0xff) as u8,
    ]
}

fn bump_seq(keys: &mut DirectionKeys) -> Result<(), RecordError> {
    let seq = match keys {
        DirectionKeys::Tls12 { seq, .. } => seq,
        DirectionKeys::Tls12ImplicitNonce { seq, .. } => seq,
        DirectionKeys::Tls13 { seq, .. } => seq,
        DirectionKeys::Tls12Cbc { seq, .. } => seq,
        DirectionKeys::Tls12Null { seq, .. } => seq,
    };
    *seq = seq.checked_add(1).ok_or_else(seq_overflow)?;
    Ok(())
}

fn direction_keys_sequence(keys: &DirectionKeys) -> u64 {
    match keys {
        DirectionKeys::Tls12 { seq, .. }
        | DirectionKeys::Tls12ImplicitNonce { seq, .. }
        | DirectionKeys::Tls13 { seq, .. }
        | DirectionKeys::Tls12Cbc { seq, .. }
        | DirectionKeys::Tls12Null { seq, .. } => *seq,
    }
}

#[cfg(test)]
mod etm_tests {
    use super::*;

    fn keys(etm: bool) -> DirectionKeys {
        DirectionKeys::new_tls12_cbc(
            CbcCipher::Aes128,
            vec![0x11; 16],
            vec![0x22; 20],
            crate::tls::crypto::HashAlg::Sha1,
            etm,
        )
    }

    #[test]
    fn etm_round_trips_and_mac_is_outside_the_ciphertext() {
        let mut w = keys(true);
        let mut r = keys(true);
        let body = seal_tls12_cbc(&mut w, CONTENT_TYPE_APP_DATA, b"hello etm", &[]).unwrap();
        // IV(16) + one 16-byte block of padded plaintext + 20-byte SHA-1 MAC.
        assert_eq!(body.len(), 16 + 16 + 20);
        assert_eq!(
            open_tls12_cbc(&mut r, CONTENT_TYPE_APP_DATA, &body).unwrap(),
            b"hello etm"
        );
    }

    #[test]
    fn etm_rejects_a_flipped_mac_byte_and_a_flipped_ciphertext_byte() {
        let mut w = keys(true);
        let body = seal_tls12_cbc(&mut w, CONTENT_TYPE_APP_DATA, b"hello etm", &[]).unwrap();
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        assert!(open_tls12_cbc(&mut keys(true), CONTENT_TYPE_APP_DATA, &bad).is_err());
        let mut bad = body;
        bad[20] ^= 0x01;
        assert!(open_tls12_cbc(&mut keys(true), CONTENT_TYPE_APP_DATA, &bad).is_err());
    }

    #[test]
    fn mac_then_encrypt_still_round_trips() {
        let mut w = keys(false);
        let mut r = keys(false);
        let body = seal_tls12_cbc(&mut w, CONTENT_TYPE_APP_DATA, b"hello mte", &[]).unwrap();
        assert_eq!(
            open_tls12_cbc(&mut r, CONTENT_TYPE_APP_DATA, &body).unwrap(),
            b"hello mte"
        );
        // The two framings are not interchangeable.
        assert!(open_tls12_cbc(&mut keys(true), CONTENT_TYPE_APP_DATA, &body).is_err());
    }
}

#[cfg(test)]
mod tls10_cbc_tests {
    use super::*;

    fn keys() -> DirectionKeys {
        let suite = crate::ir::suite_info(0x002f).unwrap(); // RSA_WITH_AES_128_CBC_SHA
        crate::tls::handshake::legacy_direction_keys(
            TlsVersion::Tls10,
            suite,
            &[0x5a; 48],
            &[0x11; 32],
            &[0x22; 32],
            false,
        )
        .unwrap()
        .0
    }

    #[test]
    fn implicit_iv_chains_across_records() {
        let mut writer = keys();
        let mut reader = keys();
        for plaintext in [b"first record".as_slice(), b"second record".as_slice()] {
            let body =
                seal_tls12(&mut writer, CONTENT_TYPE_APP_DATA, plaintext, &[], 0x0301).unwrap();
            // Unlike TLS 1.1+, TLS 1.0 carries no explicit IV on the wire.
            assert_eq!(body.len(), 48);
            assert_eq!(
                open_tls12(&mut reader, CONTENT_TYPE_APP_DATA, &body, 0x0301).unwrap(),
                plaintext
            );
            let expected_iv = &body[body.len() - 16..];
            match (&writer, &reader) {
                (
                    DirectionKeys::Tls12Cbc {
                        implicit_iv: Some(write_iv),
                        ..
                    },
                    DirectionKeys::Tls12Cbc {
                        implicit_iv: Some(read_iv),
                        ..
                    },
                ) => {
                    assert_eq!(write_iv, expected_iv);
                    assert_eq!(read_iv, expected_iv);
                }
                _ => panic!("TLS 1.0 CBC keys lost their implicit IV"),
            }
        }
    }
}

#[cfg(test)]
mod suite_family_tests {
    use super::*;
    use crate::ir::suite_info;
    use crate::tls::crypto::HashAlg;

    fn pair(suite: u16, etm: bool) -> (DirectionKeys, DirectionKeys) {
        let s = suite_info(suite).expect("suite in catalogue");
        let ms = vec![0x5a; 48];
        let (c, srv) =
            crate::tls::handshake::tls12_direction_keys(s, &ms, &[0x11; 32], &[0x22; 32], etm)
                .expect("keys");
        (c, srv)
    }

    /// Seal with the client half, open with an independent copy of the same
    /// client half (the reader tracks the writer's sequence), for every record
    /// family plzn implements. A flipped last byte must always be caught.
    fn round_trip(suite: u16, etm: bool) {
        let (mut w, _) = pair(suite, etm);
        let (mut r, _) = pair(suite, etm);
        let msg = b"the quick brown fox";
        let body = match &w {
            DirectionKeys::Tls12 { .. } => {
                seal_tls12_aead(&mut w, CONTENT_TYPE_APP_DATA, msg).unwrap()
            }
            DirectionKeys::Tls12ImplicitNonce { .. } => {
                seal_tls12_implicit_aead(&mut w, CONTENT_TYPE_APP_DATA, msg).unwrap()
            }
            DirectionKeys::Tls12Cbc { .. } => {
                seal_tls12_cbc(&mut w, CONTENT_TYPE_APP_DATA, msg, &[]).unwrap()
            }
            DirectionKeys::Tls12Null { .. } => {
                seal_tls12_null(&mut w, CONTENT_TYPE_APP_DATA, msg, &[]).unwrap()
            }
            DirectionKeys::Tls13 { .. } => unreachable!(),
        };
        let open = |r: &mut DirectionKeys, b: &[u8]| match r {
            DirectionKeys::Tls12 { .. } => open_tls12_aead(r, CONTENT_TYPE_APP_DATA, b),
            DirectionKeys::Tls12ImplicitNonce { .. } => {
                open_tls12_implicit_aead(r, CONTENT_TYPE_APP_DATA, b)
            }
            DirectionKeys::Tls12Cbc { .. } => open_tls12_cbc(r, CONTENT_TYPE_APP_DATA, b),
            DirectionKeys::Tls12Null { .. } => open_tls12_null(r, CONTENT_TYPE_APP_DATA, b),
            DirectionKeys::Tls13 { .. } => unreachable!(),
        };
        assert_eq!(
            open(&mut r, &body).unwrap(),
            msg,
            "suite {:04x} etm={}",
            suite,
            etm
        );
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 0x01;
        let (mut r2, _) = pair(suite, etm);
        assert!(
            open(&mut r2, &bad).is_err(),
            "suite {:04x} etm={} accepted a flipped byte",
            suite,
            etm
        );
    }

    #[test]
    fn every_record_family_round_trips_and_detects_tampering() {
        for (suite, etm) in [
            (0xc030, false), // AES-256-GCM-SHA384 (explicit nonce, SHA-384 PRF)
            (0xc0ac, false), // AES-128-CCM
            (0xc0ae, false), // AES-128-CCM_8 (8-byte tag)
            (0xc0ad, false), // AES-256-CCM
            (0xc060, false), // ARIA-128-GCM
            (0xc061, false), // ARIA-256-GCM
            (0xc08a, false), // Camellia-128-GCM
            (0xc08b, false), // Camellia-256-GCM
            (0xcca8, false), // ChaCha20-Poly1305 (implicit nonce)
            (0xc013, false), // AES-128-CBC-SHA, MAC-then-encrypt
            (0xc013, true),  // ... encrypt-then-MAC
            (0xc027, true),  // AES-128-CBC-SHA256 EtM
            (0xc028, false), // AES-256-CBC-SHA384 MtE
            (0xc028, true),  // AES-256-CBC-SHA384 EtM
            (0xc012, false), // 3DES-EDE-CBC-SHA (8-byte blocks)
            (0xc012, true),
            (0xc010, false), // NULL-SHA
        ] {
            round_trip(suite, etm);
        }
    }

    #[test]
    fn ccm8_records_carry_an_eight_byte_tag() {
        let (mut w, _) = pair(0xc0ae, false);
        let body = seal_tls12_aead(&mut w, CONTENT_TYPE_APP_DATA, b"abc").unwrap();
        assert_eq!(body.len(), 8 + 3 + 8);
        let (mut w, _) = pair(0xc0ac, false);
        let body = seal_tls12_aead(&mut w, CONTENT_TYPE_APP_DATA, b"abc").unwrap();
        assert_eq!(body.len(), 8 + 3 + 16);
    }

    #[test]
    fn chacha20_records_have_no_explicit_nonce() {
        let (mut w, _) = pair(0xcca8, false);
        let body = seal_tls12_implicit_aead(&mut w, CONTENT_TYPE_APP_DATA, b"abc").unwrap();
        assert_eq!(body.len(), 3 + 16);
    }

    #[test]
    fn triple_des_uses_eight_byte_iv_and_blocks() {
        let (mut w, _) = pair(0xc012, false);
        // 3 bytes + 20-byte MAC = 23 -> padded to 24; plus an 8-byte IV.
        let body = seal_tls12_cbc(&mut w, CONTENT_TYPE_APP_DATA, b"abc", &[]).unwrap();
        assert_eq!(body.len(), 8 + 24);
    }

    #[test]
    fn null_cipher_is_plaintext_plus_mac() {
        let (mut w, _) = pair(0xc010, false);
        let body = seal_tls12_null(&mut w, CONTENT_TYPE_APP_DATA, b"abc", &[]).unwrap();
        assert_eq!(&body[..3], b"abc");
        assert_eq!(body.len(), 3 + HashAlg::Sha1.output_len());
    }
}

#[cfg(test)]
mod dtls13_sequence_tests {
    use super::reconstruct_dtls13_sequence;

    #[test]
    fn reconstructs_short_record_numbers_across_wraps_and_reordering() {
        assert_eq!(reconstruct_dtls13_sequence(None, 0, 8), 0);
        assert_eq!(reconstruct_dtls13_sequence(Some(255), 0, 8), 256);
        assert_eq!(reconstruct_dtls13_sequence(Some(65_535), 0, 16), 65_536);
        assert_eq!(
            reconstruct_dtls13_sequence(Some(65_540), 0xfffe, 16),
            65_534
        );
    }
}

#[cfg(test)]
mod reaudit_tests {
    use super::*;
    use crate::transport::MockTransport;

    fn keys() -> DirectionKeys {
        DirectionKeys::new_dtls13(
            AeadKey::new(AeadAlg::Aes128Gcm, &[7; 16]).unwrap(),
            [3; 12],
            vec![5; 16],
        )
    }

    fn push_packet(transport: &MockTransport, bytes: &[u8]) {
        transport.push_incoming(b"P");
        transport.push_incoming(&(bytes.len() as u32).to_be_bytes());
        transport.push_incoming(bytes);
    }

    #[test]
    fn dtls13_lengthless_record_and_empty_datagram_are_supported() {
        let transport = MockTransport::new("lengthless DTLS");
        let wire = seal_dtls13_aead(
            &mut keys(),
            2,
            CONTENT_TYPE_APP_DATA,
            b"reply",
            &[Mutation {
                op: MutationOp::Dtls13OmitLength,
                span: crate::ast::Span::new(0, 0),
            }],
            crate::ir::DtlsSequenceMap::Identity,
        )
        .unwrap();
        push_packet(&transport, &[]);
        push_packet(&transport, &wire);
        let mut reader = RecordLayer::new_dtls13(Box::new(transport));
        reader.install_read_keys(keys()).unwrap();
        assert_eq!(
            reader.read_record().unwrap(),
            (CONTENT_TYPE_APP_DATA, b"reply".to_vec())
        );
    }

    #[test]
    fn dtls13_rejects_records_crossing_a_datagram_boundary() {
        let transport = MockTransport::new("split datagram");
        let wire = seal_dtls13_aead(
            &mut keys(),
            2,
            CONTENT_TYPE_APP_DATA,
            b"reply",
            &[],
            crate::ir::DtlsSequenceMap::Identity,
        )
        .unwrap();
        push_packet(&transport, &wire[..4]);
        push_packet(&transport, &wire[4..]);
        let mut reader = RecordLayer::new_dtls13(Box::new(transport));
        reader.install_read_keys(keys()).unwrap();
        assert!(matches!(reader.read_record(), Err(RecordError::Codec(_))));
    }

    #[test]
    fn tls13_rejects_buffered_bytes_at_a_key_transition() {
        let mut reader = RecordLayer::new(
            Box::new(MockTransport::new("key boundary")),
            TlsVersion::Tls13,
        );
        reader.read_buffer = vec![4];
        reader.read_buffer_ct = CONTENT_TYPE_HANDSHAKE;
        assert!(reader.install_read_keys(keys()).is_err());
    }

    struct PauseOnce {
        inner: MockTransport,
        reads: usize,
    }
    impl Read for PauseOnce {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            match self.reads {
                1 => {
                    let n = bytes.len().min(2);
                    self.inner.read(&mut bytes[..n])
                }
                2 => Err(io::Error::from(io::ErrorKind::TimedOut)),
                _ => self.inner.read(bytes),
            }
        }
    }
    impl Write for PauseOnce {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.inner.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl UutTransport for PauseOnce {
        fn description(&self) -> String {
            "paused mock".into()
        }
        fn close(&mut self) -> io::Result<()> {
            self.inner.close()
        }
    }

    #[test]
    fn partial_tls_header_survives_a_timeout() {
        let transport = MockTransport::new("partial header");
        transport.push_incoming(&[23, 3, 3, 0, 3, b'a', b'b', b'c']);
        let mut reader = RecordLayer::new(
            Box::new(PauseOnce {
                inner: transport,
                reads: 0,
            }),
            TlsVersion::Tls13,
        );
        assert!(matches!(reader.read_record(), Err(RecordError::Io(_))));
        assert_eq!(
            reader.read_record().unwrap(),
            (CONTENT_TYPE_APP_DATA, b"abc".to_vec())
        );
    }

    fn tls12_client_keys(master_secret_byte: u8) -> DirectionKeys {
        let suite = crate::ir::suite_info(0x009f).expect("DHE_RSA_WITH_AES_256_GCM_SHA384");
        crate::tls::handshake::tls12_direction_keys(
            suite,
            &[master_secret_byte; 48],
            &[0x11; 32],
            &[0x22; 32],
            false,
        )
        .expect("keys")
        .0
    }

    fn push_tls12_record(transport: &MockTransport, keys: &mut DirectionKeys, msg: &[u8]) {
        let body = seal_tls12_aead(keys, CONTENT_TYPE_HANDSHAKE, msg).unwrap();
        transport.push_incoming(&[CONTENT_TYPE_HANDSHAKE, 3, 3]);
        transport.push_incoming(&(body.len() as u16).to_be_bytes());
        transport.push_incoming(&body);
    }

    #[test]
    fn tls12_change_cipher_spec_is_sealed_after_the_first() {
        let transport = MockTransport::new("repeated ccs out");
        let mut records = RecordLayer::new(Box::new(transport.clone()), TlsVersion::Tls12);
        // A client installs its write keys before its own CCS; that CCS still
        // goes in the clear.
        records.install_write_keys(tls12_client_keys(1)).unwrap();
        records.write_record(CONTENT_TYPE_CCS, &[1]).unwrap();
        assert_eq!(transport.take_written(), [CONTENT_TYPE_CCS, 3, 3, 0, 1, 1]);
        // A repeated CCS under the active keys is protected like any record.
        records.write_record(CONTENT_TYPE_CCS, &[1]).unwrap();
        let sealed = transport.take_written();
        assert_eq!(sealed[..3], [CONTENT_TYPE_CCS, 3, 3]);
        let mut opener = tls12_client_keys(1);
        assert_eq!(
            open_tls12(&mut opener, CONTENT_TYPE_CCS, &sealed[5..], 0x0303).unwrap(),
            [1]
        );

        // The reader mirrors it: the first CCS is read in the clear even once
        // keys are installed, a later one is opened.
        let transport = MockTransport::new("repeated ccs in");
        transport.push_incoming(&[CONTENT_TYPE_CCS, 3, 3, 0, 1, 1]);
        transport.push_incoming(&sealed);
        let mut reader = RecordLayer::new(Box::new(transport), TlsVersion::Tls12);
        reader.install_read_keys(tls12_client_keys(1)).unwrap();
        assert_eq!(reader.read_record().unwrap(), (CONTENT_TYPE_CCS, vec![1]));
        assert_eq!(reader.read_record().unwrap(), (CONTENT_TYPE_CCS, vec![1]));
    }

    #[test]
    fn read_key_candidates_install_the_one_the_first_record_authenticates() {
        let transport = MockTransport::new("candidates");
        let mut writer = tls12_client_keys(2);
        push_tls12_record(&transport, &mut writer, b"finished");
        push_tls12_record(&transport, &mut writer, b"second");
        let mut reader = RecordLayer::new(Box::new(transport), TlsVersion::Tls12);
        reader.install_read_key_candidates((1..=3).map(tls12_client_keys).collect());
        assert_eq!(
            reader.read_record().unwrap(),
            (CONTENT_TYPE_HANDSHAKE, b"finished".to_vec())
        );
        assert_eq!(reader.take_read_key_selection(), Some(1));
        // The chosen keys stay installed with their sequence number advanced.
        assert_eq!(
            reader.read_record().unwrap(),
            (CONTENT_TYPE_HANDSHAKE, b"second".to_vec())
        );
        assert_eq!(reader.take_read_key_selection(), None);

        let transport = MockTransport::new("no candidate");
        push_tls12_record(&transport, &mut tls12_client_keys(9), b"finished");
        let mut reader = RecordLayer::new(Box::new(transport), TlsVersion::Tls12);
        reader.install_read_key_candidates((1..=2).map(tls12_client_keys).collect());
        assert!(matches!(
            reader.read_record(),
            Err(RecordError::NoReadKeyCandidate { candidates: 2 })
        ));
    }
}
