// TLS message serialiser / parser. Hand-written, RFC-faithful,
// scoped to what the TLS 1.2 happy path needs. Grows as we add more
// messages and protocol versions.
//
// Style: each message is a plain struct with public fields. Free
// `encode_*` and `decode_*` functions do the wire translation. No
// traits, no type state, no builder patterns.
//
// Two independent layers live in this file:
//
//   1. Framing helpers (ByteWriter / ByteCursor) — length-prefix
//      vectors, big-endian integers, read-until-end. These are the
//      same primitives TLS presentation language uses.
//   2. Structured messages — ClientHello, ServerHello, Certificate,
//      ServerKeyExchange, ServerHelloDone, ClientKeyExchange,
//      Finished, handshake header, record header, the small set of
//      extensions we care about.
//
// The record layer and the handshake driver build on these without
// needing to know anything about presentation-language details.

use std::fmt;

// ============================================================
//                       errors + constants
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    InvalidValue(&'static str),
    UnexpectedEof,
    TrailingBytes,
    BadLengthPrefix,
    UnknownHandshakeType(u8),
    UnknownContentType(u8),
    MalformedExtension(u16),
    IntegerOverflow,
    LengthOverflow(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::InvalidValue(message) => f.write_str(message),
            CodecError::UnexpectedEof => write!(f, "unexpected end of input"),
            CodecError::TrailingBytes => write!(f, "trailing bytes after structured message"),
            CodecError::BadLengthPrefix => write!(f, "length prefix exceeds remaining input"),
            CodecError::UnknownHandshakeType(t) => write!(f, "unknown handshake type 0x{:02x}", t),
            CodecError::UnknownContentType(t) => {
                write!(f, "unknown record content type 0x{:02x}", t)
            }
            CodecError::MalformedExtension(t) => write!(f, "malformed extension 0x{:04x}", t),
            CodecError::IntegerOverflow => write!(f, "length field overflows u32"),
            CodecError::LengthOverflow(field) => {
                write!(f, "{field} does not fit its TLS length prefix")
            }
        }
    }
}

impl std::error::Error for CodecError {}

// Record content types (RFC 5246 §6.2.1, RFC 8446 §5.1).
pub const CONTENT_TYPE_CCS: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APP_DATA: u8 = 23;

// Legacy record version field. TLS 1.2 and 1.3 both put 0x0303 here
// after the first ClientHello (which may use 0x0301 for ancient
// middlebox compat). We always emit 0x0303.
pub const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
pub const PROTOCOL_VERSION_TLS12: u16 = 0x0303;

// Handshake message types (RFC 5246 §7.4 + RFC 8446 §4).
pub const HS_HELLO_REQUEST: u8 = 0; // TLS 1.2 server-initiated renegotiation (RFC 5246 7.4.1.1)
pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_HELLO_VERIFY_REQUEST: u8 = 3; // DTLS (RFC 6347 4.2.1)
pub const HS_NEW_SESSION_TICKET: u8 = 4;
pub const HS_END_OF_EARLY_DATA: u8 = 5;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_SERVER_KEY_EXCHANGE: u8 = 12;
pub const HS_CERTIFICATE_REQUEST: u8 = 13;
pub const HS_SERVER_HELLO_DONE: u8 = 14;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_CLIENT_KEY_EXCHANGE: u8 = 16;
pub const HS_FINISHED: u8 = 20;
pub const HS_KEY_UPDATE: u8 = 24;
pub const HS_MESSAGE_HASH: u8 = 254; // synthetic for transcript replacement

/// The magic ServerHello.random that identifies a HelloRetryRequest
/// (RFC 8446 §4.1.3). SHA-256("HelloRetryRequest").
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

// Cipher suites we care about in the wedge.
pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
// Static RSA suites (no forward secrecy).
pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;

// CBC suites.
pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xc009;
pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;

// TLS 1.3 suites (RFC 8446 §B.4).
pub const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// TLS 1.3 protocol version (appears inside supported_versions).
pub const PROTOCOL_VERSION_TLS13: u16 = 0x0304;

// Named groups (RFC 8422 §5.1.1 + RFC 8446 §4.2.7).
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;
pub const GROUP_SECP521R1: u16 = 0x0019;
pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_X448: u16 = 0x001e;
/// RFC 7919 finite-field groups (TLS 1.3 key_share; TLS 1.2 DHE uses explicit params).
pub const GROUP_FFDHE2048: u16 = 0x0100;
pub const GROUP_FFDHE3072: u16 = 0x0101;

// Extension types we encode or recognise.
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// RFC 7366 encrypt_then_mac (empty body; TLS 1.2 block-cipher suites only).
pub const EXT_ENCRYPT_THEN_MAC: u16 = 0x0016;
pub const EXT_SESSION_TICKET: u16 = 0x0023;
pub const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_COOKIE: u16 = 0x002c;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;
pub const EXT_EARLY_DATA: u16 = 0x002a;
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// Raw public key certificate-type negotiation (RFC 7250).
pub const EXT_CLIENT_CERTIFICATE_TYPE: u16 = 0x0013;
pub const EXT_SERVER_CERTIFICATE_TYPE: u16 = 0x0014;
/// certificate_authorities (RFC 8446 §4.2.4).
pub const EXT_CERTIFICATE_AUTHORITIES: u16 = 0x002f;
pub const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;

/// CertificateType values (RFC 7250 §3): X.509 (0) and RawPublicKey (2).
pub const CERT_TYPE_X509: u8 = 0;
pub const CERT_TYPE_RAW_PUBLIC_KEY: u8 = 2;

/// Encode a client's `{client,server}_certificate_type` extension body (RFC 7250 §3):
/// `CertificateType certificate_types<1..2^8-1>` -- a 1-byte length prefix followed by
/// one byte per supported type. Used in the ClientHello to advertise support.
pub fn encode_cert_type_list(types: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u8(types.len() as u8);
    for &t in types {
        w.u8(t);
    }
    w.into_vec()
}

/// Decode a client's certificate_type extension body (the `<1..2^8-1>` list form).
/// Rejects a length that does not match the remaining bytes (RFC 7250 §3).
pub fn decode_cert_type_list(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let len = c.u8()? as usize;
    if len == 0 || c.remaining() != len {
        return Err(CodecError::BadLengthPrefix);
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(c.u8()?);
    }
    Ok(out)
}

/// Decode the server's certificate_type selection (RFC 7250 §4.2): the response carries a
/// single `CertificateType` byte (no list prefix). Rejects a body that is not exactly one
/// byte.
pub fn decode_cert_type_selection(body: &[u8]) -> Result<u8, CodecError> {
    if body.len() != 1 {
        return Err(CodecError::BadLengthPrefix);
    }
    Ok(body[0])
}

/// TLS 1.3 compressed certificate handshake message type (RFC 8879 §5).
pub const HS_COMPRESSED_CERTIFICATE: u8 = 25;
/// compress_certificate extension type (RFC 8879 §3).
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
/// Certificate compression algorithms (RFC 8879 §7.3). Only zlib is implemented here.
pub const CERT_COMPRESSION_ZLIB: u16 = 1;

/// Decode a CompressedCertificate message body (RFC 8879 §4) and return the decompressed
/// inner Certificate message body. Only zlib is supported.
///
/// ```text
/// struct {
///     CertificateCompressionAlgorithm algorithm;
///     uint24 uncompressed_length;
///     opaque compressed_certificate_message<1..2^24-1>;
/// } CompressedCertificate;
/// ```
///
/// RFC 8879 §4: "If the received ... uncompressed length ... does not match ... the
/// receiving party MUST abort" -- enforced here.
pub fn decompress_certificate_13(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    use std::io::Read;
    let mut c = ByteCursor::new(body);
    let algorithm = c.u16()?;
    let uncompressed_length = c.u24()? as usize;
    let compressed = c.u24_vec()?;
    c.expect_empty()?;
    if algorithm != CERT_COMPRESSION_ZLIB {
        return Err(CodecError::MalformedExtension(algorithm));
    }
    let mut out = Vec::with_capacity(uncompressed_length.min(1 << 20));
    flate2::read::ZlibDecoder::new(compressed)
        .read_to_end(&mut out)
        .map_err(|_| CodecError::BadLengthPrefix)?;
    if out.len() != uncompressed_length {
        return Err(CodecError::BadLengthPrefix);
    }
    Ok(out)
}

/// Build a CompressedCertificate message body (RFC 8879 §4) that wraps a zlib-compressed
/// `cert_body` (the inner Certificate message body). The inverse of
/// `decompress_certificate_13`; used to present a compressed Certificate from the server.
pub fn encode_compressed_certificate_13(cert_body: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing to a Vec is infallible; finish() likewise.
    enc.write_all(cert_body).expect("zlib write to Vec");
    let compressed = enc.finish().expect("zlib finish to Vec");
    let mut w = ByteWriter::new();
    w.u16(CERT_COMPRESSION_ZLIB);
    w.u24(cert_body.len() as u32);
    w.u24_vec(&compressed);
    w.into_vec()
}

/// PSK key exchange modes (RFC 8446 §4.2.9).
pub const PSK_KE: u8 = 0;
pub const PSK_DHE_KE: u8 = 1;

// ============================================================
//                        ByteWriter
// ============================================================

/// An encoded message body plus the byte ranges of each named
/// field. Returned by `encode_*_body_mapped` so that byte-level
/// mutations can target field-relative offsets without hard-coded
/// offset tables.
#[derive(Clone, Debug)]
pub struct EncodedBody {
    pub bytes: Vec<u8>,
    pub fields: std::collections::HashMap<String, std::ops::Range<usize>>,
}

impl EncodedBody {
    pub fn field_range(&self, name: &str) -> Option<std::ops::Range<usize>> {
        self.fields.get(name).cloned()
    }
}

/// Append-only wire builder. Records a position when a length field
/// is reserved and patches it in-place when the body is complete.
/// Also supports `mark(name)` / `mark_end(name)` to record the
/// byte range of a named field, collected into a HashMap at the end.
#[derive(Default)]
pub struct ByteWriter {
    pub buf: Vec<u8>,
    marks: Vec<(String, usize, Option<usize>)>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u24(&mut self, v: u32) {
        assert!(v < 1 << 24, "u24 overflow: {}", v);
        self.buf.push(((v >> 16) & 0xff) as u8);
        self.buf.push(((v >> 8) & 0xff) as u8);
        self.buf.push((v & 0xff) as u8);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Write a u8-prefixed vector of bytes.
    pub fn u8_vec(&mut self, body: &[u8]) {
        assert!(body.len() <= u8::MAX as usize);
        self.u8(body.len() as u8);
        self.bytes(body);
    }

    /// Write a u16-prefixed vector of bytes.
    pub fn u16_vec(&mut self, body: &[u8]) {
        assert!(body.len() <= u16::MAX as usize);
        self.u16(body.len() as u16);
        self.bytes(body);
    }

    /// Write a u24-prefixed vector of bytes.
    pub fn u24_vec(&mut self, body: &[u8]) {
        assert!(body.len() < 1 << 24);
        self.u24(body.len() as u32);
        self.bytes(body);
    }

    /// Reserve a 2-byte length field, returning its position. Call
    /// `patch_u16_length` once the body is appended to fill it in.
    pub fn reserve_u16(&mut self) -> usize {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        pos
    }

    pub fn patch_u16(&mut self, pos: usize) {
        let len = self.buf.len() - pos - 2;
        assert!(len <= u16::MAX as usize, "reserved u16 length overflow");
        self.buf[pos] = ((len >> 8) & 0xff) as u8;
        self.buf[pos + 1] = (len & 0xff) as u8;
    }

    /// Start tracking the byte range for a named field.
    pub fn mark(&mut self, name: &str) {
        self.marks.push((name.to_string(), self.buf.len(), None));
    }

    /// Record an already-written byte range. This is useful for nested wire
    /// structures whose length offsets are most naturally discovered after
    /// their complete encoding is available (notably extensions).
    pub fn mark_range(&mut self, name: &str, range: std::ops::Range<usize>) {
        assert!(range.start <= range.end && range.end <= self.buf.len());
        self.marks
            .push((name.to_string(), range.start, Some(range.end)));
    }

    /// End the byte range for the most recent `mark(name)`.
    pub fn mark_end(&mut self, name: &str) {
        for entry in self.marks.iter_mut().rev() {
            if entry.0 == name && entry.2.is_none() {
                entry.2 = Some(self.buf.len());
                return;
            }
        }
        panic!("mark_end({:?}) without a matching mark", name);
    }

    /// Consume the writer and return the encoded body with named
    /// field ranges. Any unclosed marks are closed at the current
    /// position (i.e. the end of the buffer).
    pub fn into_encoded_body(self) -> EncodedBody {
        let end = self.buf.len();
        let mut fields = std::collections::HashMap::new();
        for (name, start, maybe_end) in self.marks {
            fields.insert(name, start..maybe_end.unwrap_or(end));
        }
        EncodedBody {
            bytes: self.buf,
            fields,
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ============================================================
//                        ByteCursor
// ============================================================

/// Read-only cursor over a byte slice with bounds-checked helpers.
#[derive(Clone, Copy)]
pub struct ByteCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    pub fn slice_from(&self, start: usize) -> &'a [u8] {
        &self.bytes[start..self.pos]
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return Err(CodecError::UnexpectedEof);
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u24(&mut self) -> Result<u32, CodecError> {
        let b = self.take(3)?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }

    pub fn u8_vec(&mut self) -> Result<&'a [u8], CodecError> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub fn u16_vec(&mut self) -> Result<&'a [u8], CodecError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    pub fn u24_vec(&mut self) -> Result<&'a [u8], CodecError> {
        let n = self.u24()? as usize;
        self.take(n)
    }

    /// Expect the cursor to be fully consumed, else TrailingBytes.
    pub fn expect_empty(&self) -> Result<(), CodecError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

// ============================================================
//                        record header
// ============================================================

#[derive(Clone, Debug)]
pub struct RecordHeader {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
}

impl RecordHeader {
    pub const ENCODED_LEN: usize = 5;

    pub fn encode(&self, out: &mut ByteWriter) {
        out.u8(self.content_type);
        out.u16(self.version);
        out.u16(self.length);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(CodecError::UnexpectedEof);
        }
        Ok(Self {
            content_type: bytes[0],
            version: u16::from_be_bytes([bytes[1], bytes[2]]),
            length: u16::from_be_bytes([bytes[3], bytes[4]]),
        })
    }
}

// ============================================================
//                      handshake header
// ============================================================

/// Wrap a handshake body in its `{type, length, body}` envelope.
///
/// This is the form fed to the transcript hash and the record layer.
pub fn encode_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u8(msg_type);
    w.u24(body.len() as u32);
    w.bytes(body);
    w.into_vec()
}

/// Split a handshake message buffer into `(type, body)` without
/// copying. Used by the driver to walk a record body that might
/// contain one or more coalesced handshake messages.
pub fn parse_handshake_header(cursor: &mut ByteCursor) -> Result<(u8, usize), CodecError> {
    let t = cursor.u8()?;
    let len = cursor.u24()? as usize;
    Ok((t, len))
}

// ============================================================
//                         extensions
// ============================================================

#[derive(Clone, Debug)]
pub enum Extension {
    ServerName(String),
    SupportedGroups(Vec<u16>),
    EcPointFormats(Vec<u8>),
    SignatureAlgorithms(Vec<u16>),
    ExtendedMasterSecret,
    SessionTicket(Vec<u8>),
    RenegotiationInfo(Vec<u8>),
    // TLS 1.3 bits — not used by the 1.2 driver but reserved for
    // forward-compat so we can share this enum across versions.
    SupportedVersions(Vec<u16>),
    KeyShare(Vec<KeyShareEntry>),
    // ServerHello single-value forms (TLS 1.3 §4.2.1 / §4.2.8).
    // The encode path uses these; the decode path normalises both
    // forms into the list variants above.
    SupportedVersionsSingle(u16),
    KeyShareSingle(KeyShareEntry),
    /// HelloRetryRequest key_share (RFC 8446 §4.2.8): just the
    /// group the server wants the client to retry with, no key data.
    KeyShareRetryGroup(u16),
    /// PSK key exchange modes (RFC 8446 §4.2.9).
    PskKeyExchangeModes(Vec<u8>),
    /// ClientHello pre_shared_key (RFC 8446 §4.2.11).
    /// Must be the LAST extension in the ClientHello.
    PreSharedKey {
        identities: Vec<PskIdentity>,
        /// Placeholder binders — filled in after computing the
        /// truncated ClientHello transcript hash.
        binder_lengths: Vec<usize>,
    },
    // Opaque fallthrough so we can round-trip unknown extensions.
    Unknown {
        ty: u16,
        data: Vec<u8>,
    },
}

impl Extension {
    pub fn wire_type(&self) -> u16 {
        match self {
            Extension::ServerName(_) => EXT_SERVER_NAME,
            Extension::SupportedGroups(_) => EXT_SUPPORTED_GROUPS,
            Extension::EcPointFormats(_) => EXT_EC_POINT_FORMATS,
            Extension::SignatureAlgorithms(_) => EXT_SIGNATURE_ALGORITHMS,
            Extension::ExtendedMasterSecret => EXT_EXTENDED_MASTER_SECRET,
            Extension::SessionTicket(_) => EXT_SESSION_TICKET,
            Extension::RenegotiationInfo(_) => EXT_RENEGOTIATION_INFO,
            Extension::SupportedVersions(_) | Extension::SupportedVersionsSingle(_) => {
                EXT_SUPPORTED_VERSIONS
            }
            Extension::KeyShare(_)
            | Extension::KeyShareSingle(_)
            | Extension::KeyShareRetryGroup(_) => EXT_KEY_SHARE,
            Extension::PskKeyExchangeModes(_) => EXT_PSK_KEY_EXCHANGE_MODES,
            Extension::PreSharedKey { .. } => EXT_PRE_SHARED_KEY,
            Extension::Unknown { ty, .. } => *ty,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

#[derive(Clone, Debug)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

pub fn encode_extension(out: &mut ByteWriter, ext: &Extension) {
    let start = out.len();
    match ext {
        Extension::ServerName(name) => {
            out.u16(EXT_SERVER_NAME);
            let len_pos = out.reserve_u16();
            // ServerNameList
            let list_pos = out.reserve_u16();
            // Entry: name_type(1) + HostName(u16-prefixed)
            out.u8(0); // host_name
            out.u16_vec(name.as_bytes());
            out.patch_u16(list_pos);
            out.patch_u16(len_pos);
        }
        Extension::SupportedGroups(groups) => {
            out.u16(EXT_SUPPORTED_GROUPS);
            let len_pos = out.reserve_u16();
            let list_pos = out.reserve_u16();
            for g in groups {
                out.u16(*g);
            }
            out.patch_u16(list_pos);
            out.patch_u16(len_pos);
        }
        Extension::EcPointFormats(formats) => {
            out.u16(EXT_EC_POINT_FORMATS);
            let len_pos = out.reserve_u16();
            out.u8_vec(formats);
            out.patch_u16(len_pos);
        }
        Extension::SignatureAlgorithms(schemes) => {
            out.u16(EXT_SIGNATURE_ALGORITHMS);
            let len_pos = out.reserve_u16();
            let list_pos = out.reserve_u16();
            for s in schemes {
                out.u16(*s);
            }
            out.patch_u16(list_pos);
            out.patch_u16(len_pos);
        }
        Extension::ExtendedMasterSecret => {
            out.u16(EXT_EXTENDED_MASTER_SECRET);
            out.u16(0); // empty body
        }
        Extension::SessionTicket(data) => {
            out.u16(EXT_SESSION_TICKET);
            out.u16(data.len() as u16);
            out.bytes(data);
        }
        Extension::RenegotiationInfo(data) => {
            out.u16(EXT_RENEGOTIATION_INFO);
            let len_pos = out.reserve_u16();
            out.u8_vec(data);
            out.patch_u16(len_pos);
        }
        Extension::SupportedVersions(versions) => {
            out.u16(EXT_SUPPORTED_VERSIONS);
            let len_pos = out.reserve_u16();
            // In ClientHello: u8-prefixed list. (ServerHello uses a
            // single u16, handled in decode_server_hello.)
            assert!(versions.len() * 2 <= u8::MAX as usize);
            out.u8((versions.len() * 2) as u8);
            for v in versions {
                out.u16(*v);
            }
            out.patch_u16(len_pos);
        }
        Extension::KeyShare(entries) => {
            out.u16(EXT_KEY_SHARE);
            let len_pos = out.reserve_u16();
            let list_pos = out.reserve_u16();
            for (i, e) in entries.iter().enumerate() {
                out.u16(e.group);
                out.u16(e.key_exchange.len() as u16);
                // `handshake.key_share`: the first entry's public value, without
                // its length prefix, so byte mutations hit the point itself.
                if i == 0 {
                    out.mark("key_share");
                }
                out.bytes(&e.key_exchange);
                if i == 0 {
                    out.mark_end("key_share");
                }
            }
            out.patch_u16(list_pos);
            out.patch_u16(len_pos);
        }
        Extension::SupportedVersionsSingle(version) => {
            out.u16(EXT_SUPPORTED_VERSIONS);
            out.u16(2); // length
            out.u16(*version);
        }
        Extension::KeyShareSingle(entry) => {
            out.u16(EXT_KEY_SHARE);
            let len_pos = out.reserve_u16();
            out.u16(entry.group);
            out.u16(entry.key_exchange.len() as u16);
            out.mark("key_share");
            out.bytes(&entry.key_exchange);
            out.mark_end("key_share");
            out.patch_u16(len_pos);
        }
        Extension::KeyShareRetryGroup(group) => {
            out.u16(EXT_KEY_SHARE);
            out.u16(2); // length
            out.u16(*group);
        }
        Extension::PskKeyExchangeModes(modes) => {
            out.u16(EXT_PSK_KEY_EXCHANGE_MODES);
            let len_pos = out.reserve_u16();
            out.u8_vec(modes);
            out.patch_u16(len_pos);
        }
        Extension::PreSharedKey {
            identities,
            binder_lengths,
        } => {
            out.u16(EXT_PRE_SHARED_KEY);
            let ext_len_pos = out.reserve_u16();
            // PskIdentity list: u16-length prefixed
            let ids_len_pos = out.reserve_u16();
            for (i, id) in identities.iter().enumerate() {
                out.u16_vec(&id.identity);
                if i == 0 {
                    out.mark("obfuscated_ticket_age");
                }
                out.bytes(&id.obfuscated_ticket_age.to_be_bytes());
                if i == 0 {
                    out.mark_end("obfuscated_ticket_age");
                }
            }
            out.patch_u16(ids_len_pos);
            // Binders list: u16-length prefixed, each is u8-length
            // prefixed HMAC. We write zero placeholders here — the
            // driver patches them after computing the binder HMAC
            // over the truncated ClientHello.
            let binders_len_pos = out.reserve_u16();
            for (i, &blen) in binder_lengths.iter().enumerate() {
                out.u8(blen as u8);
                let indexed_name = format!("psk_binder_{}", i);
                out.mark(&indexed_name);
                if i == 0 {
                    out.mark("psk_binder");
                }
                out.bytes(&vec![0u8; blen]);
                if i == 0 {
                    out.mark_end("psk_binder");
                }
                out.mark_end(&indexed_name);
            }
            out.patch_u16(binders_len_pos);
            out.patch_u16(ext_len_pos);
        }
        Extension::Unknown { ty, data } => {
            out.u16(*ty);
            out.u16_vec(data);
        }
    }
    mark_extension_length_fields(out, start, ext);
}

/// Add flat, stable names for the extension's outer length and any length
/// prefixes nested in its body. `+ext` values are intentionally lowered to an
/// opaque `Unknown`, so this recognizes the wire shape rather than relying on
/// the typed `Extension` variant. Keeping the names flat also lets the existing
/// two-component mutation path (`handshake.<field>`) address them everywhere.
fn mark_extension_length_fields(out: &mut ByteWriter, start: usize, ext: &Extension) {
    let end = out.len();
    if end < start + 4 {
        return;
    }
    let ty = ext.wire_type();
    let Some(ext_name) = crate::schema::extension_name(ty) else {
        return;
    };
    out.mark_range(
        &format!("extension_{ext_name}_length"),
        start + 2..start + 4,
    );

    let body_start = start + 4;
    let body_len = end - body_start;
    let u16_at = |writer: &ByteWriter, offset: usize| -> Option<usize> {
        (offset + 2 <= body_len).then(|| {
            u16::from_be_bytes([
                writer.buf[body_start + offset],
                writer.buf[body_start + offset + 1],
            ]) as usize
        })
    };
    let mark = |writer: &mut ByteWriter, name: &str, offset: usize, width: usize| {
        if offset + width <= body_len {
            writer.mark_range(name, body_start + offset..body_start + offset + width);
        }
    };

    match ty {
        EXT_SERVER_NAME => {
            mark(out, "extension_server_name_list_length", 0, 2);
            // ServerNameList starts with name_type then HostName's u16 length.
            mark(out, "extension_server_name_host_name_length", 3, 2);
        }
        EXT_SUPPORTED_GROUPS => mark(out, "extension_supported_groups_list_length", 0, 2),
        EXT_EC_POINT_FORMATS => mark(out, "extension_ec_point_formats_list_length", 0, 1),
        EXT_SIGNATURE_ALGORITHMS => mark(out, "extension_signature_algorithms_list_length", 0, 2),
        EXT_SIGNATURE_ALGORITHMS_CERT => {
            mark(out, "extension_signature_algorithms_cert_list_length", 0, 2)
        }
        EXT_RENEGOTIATION_INFO => mark(out, "extension_renegotiation_info_info_length", 0, 1),
        EXT_SUPPORTED_VERSIONS => {
            // ClientHello has an u8 vector; ServerHello/HRR has a single u16.
            if body_len != 2 {
                mark(out, "extension_supported_versions_list_length", 0, 1);
            }
        }
        EXT_KEY_SHARE => {
            // ClientHello: u16 list, then group + u16 key. ServerHello: group +
            // u16 key. HRR is only a group and has no inner length.
            let client_list = u16_at(out, 0).is_some_and(|n| n + 2 == body_len);
            if client_list {
                mark(out, "extension_key_share_list_length", 0, 2);
                mark(out, "extension_key_share_key_exchange_length", 4, 2);
            } else if body_len >= 4 {
                mark(out, "extension_key_share_key_exchange_length", 2, 2);
            }
        }
        EXT_PSK_KEY_EXCHANGE_MODES => {
            mark(out, "extension_psk_key_exchange_modes_list_length", 0, 1)
        }
        EXT_PRE_SHARED_KEY => {
            mark(out, "extension_pre_shared_key_identity_list_length", 0, 2);
            mark(out, "extension_pre_shared_key_identity_length", 2, 2);
            if let Some(ids_len) = u16_at(out, 0) {
                let binders = 2 + ids_len;
                mark(
                    out,
                    "extension_pre_shared_key_binder_list_length",
                    binders,
                    2,
                );
                mark(
                    out,
                    "extension_pre_shared_key_binder_length",
                    binders + 2,
                    1,
                );
            }
        }
        EXT_CERTIFICATE_AUTHORITIES => {
            mark(out, "extension_certificate_authorities_list_length", 0, 2);
            mark(
                out,
                "extension_certificate_authorities_first_authority_length",
                2,
                2,
            );
        }
        EXT_COMPRESS_CERTIFICATE => mark(out, "extension_compress_certificate_list_length", 0, 1),
        // use_srtp: profiles<2..2^16-2>, mki<0..255>.
        0x000e => {
            mark(out, "extension_use_srtp_profiles_length", 0, 2);
            if let Some(profiles_len) = u16_at(out, 0) {
                mark(out, "extension_use_srtp_mki_length", 2 + profiles_len, 1);
            }
        }
        // ALPN ProtocolNameList is a u16 vector.
        0x0010 => mark(out, "extension_alpn_list_length", 0, 2),
        _ => {}
    }
}

/// Parse one extension from a cursor positioned at `ext_type`.
/// RFC 6066 3 ServerNameList: `ServerName server_name_list<1..2^16-1>`, each
/// entry `NameType name_type; opaque HostName<1..2^16-1>`. Returns the first
/// host_name (name_type 0) as UTF-8, or `None` if the body does not parse as a
/// well-formed list with a host_name entry.
fn decode_server_name_list(body: &[u8]) -> Option<String> {
    let mut c = ByteCursor::new(body);
    let list = c.u16_vec().ok()?;
    if !c.is_empty() {
        return None;
    }
    let mut lc = ByteCursor::new(list);
    while !lc.is_empty() {
        let name_type = lc.u8().ok()?;
        let host = lc.u16_vec().ok()?;
        if name_type == 0 {
            return String::from_utf8(host.to_vec()).ok();
        }
    }
    None
}

pub fn decode_extension(cursor: &mut ByteCursor) -> Result<Extension, CodecError> {
    let ty = cursor.u16()?;
    let body = cursor.u16_vec()?;
    let mut inner = ByteCursor::new(body);
    let ext = match ty {
        EXT_SERVER_NAME => {
            // RFC 6066 3: ServerNameList; extract the first host_name so a
            // `recv ClientHello { server_name }` matcher can read it. A body plzn
            // cannot parse (a deliberately malformed server_name test) is kept as
            // Unknown, matching the earlier tolerant behaviour.
            match decode_server_name_list(body) {
                Some(name) => Extension::ServerName(name),
                None => Extension::Unknown {
                    ty,
                    data: body.to_vec(),
                },
            }
        }
        EXT_SUPPORTED_GROUPS => {
            let list = inner.u16_vec()?;
            let mut lc = ByteCursor::new(list);
            let mut groups = Vec::new();
            while !lc.is_empty() {
                groups.push(lc.u16()?);
            }
            Extension::SupportedGroups(groups)
        }
        EXT_EC_POINT_FORMATS => {
            let list = inner.u8_vec()?;
            Extension::EcPointFormats(list.to_vec())
        }
        EXT_SIGNATURE_ALGORITHMS => {
            let list = inner.u16_vec()?;
            let mut lc = ByteCursor::new(list);
            let mut schemes = Vec::new();
            while !lc.is_empty() {
                schemes.push(lc.u16()?);
            }
            Extension::SignatureAlgorithms(schemes)
        }
        EXT_EXTENDED_MASTER_SECRET => {
            // Empty body.
            Extension::ExtendedMasterSecret
        }
        EXT_RENEGOTIATION_INFO => {
            let data = inner.u8_vec()?;
            Extension::RenegotiationInfo(data.to_vec())
        }
        EXT_SESSION_TICKET => {
            // RFC 5077 3.2: the body is the ticket itself (empty = "send me one").
            let n = inner.remaining();
            let data = inner.take(n)?;
            Extension::SessionTicket(data.to_vec())
        }
        EXT_SUPPORTED_VERSIONS => {
            // In ServerHello this is a single u16 version. In
            // ClientHello it's a u8-prefixed list. We'll accept
            // either by inspecting the length.
            if inner.remaining() == 2 {
                let v = inner.u16()?;
                Extension::SupportedVersions(vec![v])
            } else {
                let list = inner.u8_vec()?;
                let mut lc = ByteCursor::new(list);
                let mut vs = Vec::new();
                while !lc.is_empty() {
                    vs.push(lc.u16()?);
                }
                Extension::SupportedVersions(vs)
            }
        }
        EXT_KEY_SHARE => decode_key_share_extension(body)?,
        _ => Extension::Unknown {
            ty,
            data: body.to_vec(),
        },
    };
    Ok(ext)
}

/// Decode a `key_share` extension body. Three formats:
///   - HRR: just `u16(group)` (2 bytes, no key data)
///   - ServerHello: `u16(group) + u16_vec(key_exchange)`
///   - ClientHello: `u16_vec(list of group + u16_vec(key))`
///
/// We probe in order: HRR, ServerHello, ClientHello.
fn decode_key_share_extension(body: &[u8]) -> Result<Extension, CodecError> {
    // HRR form: exactly 2 bytes = selected_group.
    if body.len() == 2 {
        let group = u16::from_be_bytes([body[0], body[1]]);
        return Ok(Extension::KeyShare(vec![KeyShareEntry {
            group,
            key_exchange: Vec::new(),
        }]));
    }
    // ServerHello form.
    {
        let mut c = ByteCursor::new(body);
        let result = (|| -> Result<KeyShareEntry, CodecError> {
            let group = c.u16()?;
            let key_exchange = c.u16_vec()?.to_vec();
            if !c.is_empty() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(KeyShareEntry {
                group,
                key_exchange,
            })
        })();
        if let Ok(entry) = result {
            return Ok(Extension::KeyShare(vec![entry]));
        }
    }
    // ClientHello form: u16-prefixed list of entries.
    let mut c = ByteCursor::new(body);
    let list_bytes = c.u16_vec()?;
    c.expect_empty()?;
    let mut lc = ByteCursor::new(list_bytes);
    let mut entries = Vec::new();
    while !lc.is_empty() {
        let group = lc.u16()?;
        let key_exchange = lc.u16_vec()?.to_vec();
        entries.push(KeyShareEntry {
            group,
            key_exchange,
        });
    }
    Ok(Extension::KeyShare(entries))
}

pub fn decode_extensions_block(bytes: &[u8]) -> Result<Vec<Extension>, CodecError> {
    let mut cursor = ByteCursor::new(bytes);
    let mut out = Vec::new();
    while !cursor.is_empty() {
        out.push(decode_extension(&mut cursor)?);
    }
    Ok(out)
}

// ============================================================
//                        ClientHello
// ============================================================

pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

fn checked_len(len: usize, max: usize, field: &'static str) -> Result<usize, CodecError> {
    if len > max {
        Err(CodecError::LengthOverflow(field))
    } else {
        Ok(len)
    }
}

fn extension_encoded_len(ext: &Extension) -> Result<usize, CodecError> {
    let body_len = match ext {
        Extension::ServerName(name) => {
            checked_len(name.len(), u16::MAX as usize, "server_name")?;
            5usize
                .checked_add(name.len())
                .ok_or(CodecError::LengthOverflow("server_name"))?
        }
        Extension::SupportedGroups(groups) | Extension::SignatureAlgorithms(groups) => {
            let list_len = groups
                .len()
                .checked_mul(2)
                .ok_or(CodecError::LengthOverflow("extension list"))?;
            checked_len(list_len, u16::MAX as usize, "extension list")?;
            2usize
                .checked_add(list_len)
                .ok_or(CodecError::LengthOverflow("extension body"))?
        }
        Extension::EcPointFormats(formats) => {
            checked_len(formats.len(), u8::MAX as usize, "ec_point_formats")?;
            1 + formats.len()
        }
        Extension::ExtendedMasterSecret => 0,
        Extension::SessionTicket(ticket) => ticket.len(),
        Extension::RenegotiationInfo(info) => {
            checked_len(info.len(), u8::MAX as usize, "renegotiation_info")?;
            1 + info.len()
        }
        Extension::SupportedVersions(versions) => {
            let list_len = versions
                .len()
                .checked_mul(2)
                .ok_or(CodecError::LengthOverflow("supported_versions"))?;
            checked_len(list_len, u8::MAX as usize, "supported_versions")?;
            1 + list_len
        }
        Extension::KeyShare(entries) => {
            let mut list_len = 0usize;
            for entry in entries {
                checked_len(
                    entry.key_exchange.len(),
                    u16::MAX as usize,
                    "key_share key_exchange",
                )?;
                list_len = list_len
                    .checked_add(4 + entry.key_exchange.len())
                    .ok_or(CodecError::LengthOverflow("key_share list"))?;
            }
            checked_len(list_len, u16::MAX as usize, "key_share list")?;
            2usize
                .checked_add(list_len)
                .ok_or(CodecError::LengthOverflow("key_share extension"))?
        }
        Extension::SupportedVersionsSingle(_) | Extension::KeyShareRetryGroup(_) => 2,
        Extension::KeyShareSingle(entry) => {
            checked_len(
                entry.key_exchange.len(),
                u16::MAX as usize,
                "key_share key_exchange",
            )?;
            4usize
                .checked_add(entry.key_exchange.len())
                .ok_or(CodecError::LengthOverflow("key_share extension"))?
        }
        Extension::PskKeyExchangeModes(modes) => {
            checked_len(modes.len(), u8::MAX as usize, "psk_key_exchange_modes")?;
            1 + modes.len()
        }
        Extension::PreSharedKey {
            identities,
            binder_lengths,
        } => {
            let mut identities_len = 0usize;
            for identity in identities {
                checked_len(
                    identity.identity.len(),
                    u16::MAX as usize,
                    "pre_shared_key identity",
                )?;
                identities_len = identities_len
                    .checked_add(6 + identity.identity.len())
                    .ok_or(CodecError::LengthOverflow("pre_shared_key identities"))?;
            }
            checked_len(
                identities_len,
                u16::MAX as usize,
                "pre_shared_key identities",
            )?;
            let mut binders_len = 0usize;
            for binder_len in binder_lengths {
                checked_len(*binder_len, u8::MAX as usize, "pre_shared_key binder")?;
                binders_len = binders_len
                    .checked_add(1 + *binder_len)
                    .ok_or(CodecError::LengthOverflow("pre_shared_key binders"))?;
            }
            checked_len(binders_len, u16::MAX as usize, "pre_shared_key binders")?;
            4usize
                .checked_add(identities_len)
                .and_then(|len| len.checked_add(binders_len))
                .ok_or(CodecError::LengthOverflow("pre_shared_key extension"))?
        }
        Extension::Unknown { data, .. } => data.len(),
    };
    checked_len(body_len, u16::MAX as usize, "extension body")?;
    body_len
        .checked_add(4)
        .ok_or(CodecError::LengthOverflow("extension"))
}

pub fn validate_client_hello(ch: &ClientHello) -> Result<(), CodecError> {
    checked_len(
        ch.session_id.len(),
        u8::MAX as usize,
        "ClientHello legacy_session_id",
    )?;
    let cipher_suites_len = ch
        .cipher_suites
        .len()
        .checked_mul(2)
        .ok_or(CodecError::LengthOverflow("ClientHello cipher_suites"))?;
    checked_len(
        cipher_suites_len,
        u16::MAX as usize,
        "ClientHello cipher_suites",
    )?;
    checked_len(
        ch.compression_methods.len(),
        u8::MAX as usize,
        "ClientHello compression_methods",
    )?;
    let mut extensions_len = 0usize;
    for extension in &ch.extensions {
        extensions_len = extensions_len
            .checked_add(extension_encoded_len(extension)?)
            .ok_or(CodecError::LengthOverflow("ClientHello extensions"))?;
    }
    checked_len(extensions_len, u16::MAX as usize, "ClientHello extensions")?;
    Ok(())
}

pub fn encode_client_hello_body(ch: &ClientHello) -> Result<Vec<u8>, CodecError> {
    Ok(encode_client_hello_body_mapped(ch)?.bytes)
}

/// Encode a ClientHello body with named field byte-range tracking.
/// Every field name matches the RFC 5246 §7.4.1.2 / RFC 8446
/// §4.1.2 presentation-language field name.
pub fn encode_client_hello_body_mapped(ch: &ClientHello) -> Result<EncodedBody, CodecError> {
    validate_client_hello(ch)?;
    let mut w = ByteWriter::new();
    w.mark("legacy_version");
    w.u16(ch.legacy_version);
    w.mark_end("legacy_version");
    w.mark("random");
    w.bytes(&ch.random);
    w.mark_end("random");
    // T2: each length prefix is also a mapped region (`*_length`), for the
    // length-field fuzzing family.
    w.mark("legacy_session_id");
    w.mark("session_id_length");
    w.u8(ch.session_id.len() as u8);
    w.mark_end("session_id_length");
    w.bytes(&ch.session_id);
    w.mark_end("legacy_session_id");
    // cipher_suites: u16-prefixed list of u16
    w.mark("cipher_suites");
    w.mark("cipher_suites_length");
    let cs_len_pos = w.reserve_u16();
    w.mark_end("cipher_suites_length");
    for cs in &ch.cipher_suites {
        w.u16(*cs);
    }
    w.patch_u16(cs_len_pos);
    w.mark_end("cipher_suites");
    // compression_methods: u8-prefixed list of u8
    w.mark("compression_methods");
    w.mark("compression_methods_length");
    w.u8(ch.compression_methods.len() as u8);
    w.mark_end("compression_methods_length");
    w.bytes(&ch.compression_methods);
    w.mark_end("compression_methods");
    // extensions: u16-prefixed block
    w.mark("extensions");
    w.mark("extensions_length");
    let ext_len_pos = w.reserve_u16();
    w.mark_end("extensions_length");
    for ext in &ch.extensions {
        encode_extension(&mut w, ext);
    }
    w.patch_u16(ext_len_pos);
    w.mark_end("extensions");
    Ok(w.into_encoded_body())
}

/// T2: the body bytes of one extension as it would go on the wire (its
/// `type(2) || length(2)` header stripped) -- what `ext NAME == value`
/// matchers compare against.
pub fn extension_body(ext: &Extension) -> Vec<u8> {
    let mut w = ByteWriter::new();
    encode_extension(&mut w, ext);
    let bytes = w.into_vec();
    if bytes.len() >= 4 {
        bytes[4..].to_vec()
    } else {
        Vec::new()
    }
}

// ============================================================
//                        ServerHello
// ============================================================

pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

pub fn decode_server_hello_body(body: &[u8]) -> Result<ServerHello, CodecError> {
    let mut c = ByteCursor::new(body);
    let legacy_version = c.u16()?;
    let random_bytes = c.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    let session_id = c.u8_vec()?.to_vec();
    let cipher_suite = c.u16()?;
    let compression_method = c.u8()?;
    // Extensions block is optional in very old TLS 1.2 servers but
    // rustls always sends one.
    let extensions = if c.is_empty() {
        Vec::new()
    } else {
        let ext_bytes = c.u16_vec()?;
        decode_extensions_block(ext_bytes)?
    };
    c.expect_empty()?;
    Ok(ServerHello {
        legacy_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        extensions,
    })
}

// ============================================================
//                        Certificate (TLS 1.2)
// ============================================================

pub struct Certificate12 {
    pub entries: Vec<Vec<u8>>, // DER-encoded certs
}

pub fn decode_certificate_12_body(body: &[u8]) -> Result<Certificate12, CodecError> {
    let mut c = ByteCursor::new(body);
    let list = c.u24_vec()?;
    c.expect_empty()?;
    let mut lc = ByteCursor::new(list);
    let mut entries = Vec::new();
    while !lc.is_empty() {
        let cert = lc.u24_vec()?;
        entries.push(cert.to_vec());
    }
    Ok(Certificate12 { entries })
}

/// RFC 7250 replaces the TLS 1.2 Certificate's X.509 certificate_list with a
/// single `ASN.1_subjectPublicKeyInfo<1..2^24-1>` value. There is no outer list
/// length and no second per-entry length.
pub fn decode_raw_public_key_certificate_12_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let spki = c.u24_vec()?.to_vec();
    if spki.is_empty() {
        return Err(CodecError::BadLengthPrefix);
    }
    c.expect_empty()?;
    Ok(spki)
}

// ============================================================
//                     ServerKeyExchange (ECDHE)
// ============================================================

/// Parsed TLS 1.2 ECDHE ServerKeyExchange.
///
/// `signed_params` is the prefix of the message that the server
/// signed — `ECParameters || ECPoint` — which is needed to verify
/// the signature later. We return it as a slice reference internally
/// and then clone it out; no alias games.
pub struct EcdheServerKeyExchange {
    pub named_curve: u16,
    pub public_point: Vec<u8>,
    pub sig_scheme: u16, // SignatureAndHashAlgorithm
    pub signature: Vec<u8>,
    pub signed_params: Vec<u8>,
}

/// Parsed TLS 1.2 DHE ServerKeyExchange (RFC 5246 7.4.3): the group (p, g), the
/// server public value Ys, and the signature over the params.
pub struct DheServerKeyExchange {
    pub dh_p: Vec<u8>,
    pub dh_g: Vec<u8>,
    pub dh_ys: Vec<u8>,
    pub sig_scheme: u16,
    pub signature: Vec<u8>,
    pub signed_params: Vec<u8>,
}

pub fn decode_dhe_server_key_exchange_body(
    body: &[u8],
) -> Result<DheServerKeyExchange, CodecError> {
    let mut c = ByteCursor::new(body);
    let params_start = c.position();
    let dh_p = c.u16_vec()?.to_vec();
    let dh_g = c.u16_vec()?.to_vec();
    let dh_ys = c.u16_vec()?.to_vec();
    let params_end = c.position();
    let signed_params = c.bytes[params_start..params_end].to_vec();
    let sig_scheme = c.u16()?;
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(DheServerKeyExchange {
        dh_p,
        dh_g,
        dh_ys,
        sig_scheme,
        signature,
        signed_params,
    })
}

pub fn decode_dhe_server_key_exchange_body_legacy(
    body: &[u8],
    sig_scheme: u16,
) -> Result<DheServerKeyExchange, CodecError> {
    let mut c = ByteCursor::new(body);
    let params_start = c.position();
    let dh_p = c.u16_vec()?.to_vec();
    let dh_g = c.u16_vec()?.to_vec();
    let dh_ys = c.u16_vec()?.to_vec();
    let params_end = c.position();
    let signed_params = c.bytes[params_start..params_end].to_vec();
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(DheServerKeyExchange {
        dh_p,
        dh_g,
        dh_ys,
        sig_scheme,
        signature,
        signed_params,
    })
}

/// DHE ClientKeyExchange body: `dh_Yc` as a u16-length-prefixed value.
pub fn encode_dhe_client_key_exchange_body(dh_yc: &[u8]) -> Vec<u8> {
    encode_dhe_client_key_exchange_body_mapped(dh_yc).bytes
}

/// DHE ClientKeyExchange body with a field map (`dh_Yc`, the whole
/// length-prefixed value, like `ecdh_Yc` on the ECDHE form).
pub fn encode_dhe_client_key_exchange_body_mapped(dh_yc: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("dh_Yc");
    w.mark("dh_Yc_length");
    let len = w.reserve_u16();
    w.mark_end("dh_Yc_length");
    w.bytes(dh_yc);
    w.patch_u16(len);
    w.mark_end("dh_Yc");
    w.into_encoded_body()
}

/// Parse a DHE ClientKeyExchange body (server receives this): `dh_Yc`.
pub fn decode_dhe_client_key_exchange_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let yc = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(yc)
}

/// Field-mapped DHE ServerKeyExchange body (RFC 5246 7.4.3): `ServerDHParams`
/// (`dh_p`, `dh_g`, `dh_Ys`, each u16-length-prefixed) then the
/// SignatureAndHashAlgorithm and signature. Marks let `send ServerKeyExchange
/// @ ...` mutations target `dh_Ys` or `signature`.
pub fn encode_dhe_server_key_exchange_body_mapped(
    dh_p: &[u8],
    dh_g: &[u8],
    dh_ys: &[u8],
    sig_scheme: u16,
    signature: &[u8],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("dh_p");
    w.mark("dh_p_length");
    w.u16(dh_p.len() as u16);
    w.mark_end("dh_p_length");
    w.bytes(dh_p);
    w.mark_end("dh_p");
    w.mark("dh_g");
    w.mark("dh_g_length");
    w.u16(dh_g.len() as u16);
    w.mark_end("dh_g_length");
    w.bytes(dh_g);
    w.mark_end("dh_g");
    w.mark("dh_Ys");
    w.mark("dh_Ys_length");
    w.u16(dh_ys.len() as u16);
    w.mark_end("dh_Ys_length");
    w.bytes(dh_ys);
    w.mark_end("dh_Ys");
    w.u16(sig_scheme);
    w.mark("signature");
    w.mark("signature_length");
    w.u16(signature.len() as u16);
    w.mark_end("signature_length");
    w.bytes(signature);
    w.mark_end("signature");
    w.into_encoded_body()
}

pub fn encode_dhe_server_key_exchange_body_mapped_legacy(
    dh_p: &[u8],
    dh_g: &[u8],
    dh_ys: &[u8],
    signature: &[u8],
) -> EncodedBody {
    let mut encoded = encode_dhe_server_key_exchange_body_mapped(dh_p, dh_g, dh_ys, 0, signature);
    let params_len = 2 + dh_p.len() + 2 + dh_g.len() + 2 + dh_ys.len();
    encoded.bytes.drain(params_len..params_len + 2);
    for range in encoded.fields.values_mut() {
        if range.start >= params_len + 2 {
            range.start -= 2;
        }
        if range.end >= params_len + 2 {
            range.end -= 2;
        }
    }
    encoded
}

pub fn decode_ecdhe_server_key_exchange_body(
    body: &[u8],
) -> Result<EcdheServerKeyExchange, CodecError> {
    let mut c = ByteCursor::new(body);
    let params_start = c.position();
    let curve_type = c.u8()?;
    if curve_type != 3 {
        // 3 = named_curve; 1 and 2 are obsolete explicit prime/char2.
        return Err(CodecError::MalformedExtension(curve_type as u16));
    }
    let named_curve = c.u16()?;
    let point_slice = c.u8_vec()?;
    let public_point = point_slice.to_vec();
    let params_end = c.position();
    let signed_params = c.bytes[params_start..params_end].to_vec();
    let sig_scheme = c.u16()?;
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(EcdheServerKeyExchange {
        named_curve,
        public_point,
        sig_scheme,
        signature,
        signed_params,
    })
}

/// TLS 1.0/1.1 ServerKeyExchange omits SignatureAndHashAlgorithm; the
/// certificate key type determines the signature algorithm.
pub fn decode_ecdhe_server_key_exchange_body_legacy(
    body: &[u8],
    sig_scheme: u16,
) -> Result<EcdheServerKeyExchange, CodecError> {
    let mut c = ByteCursor::new(body);
    let params_start = c.position();
    let curve_type = c.u8()?;
    if curve_type != 3 {
        return Err(CodecError::MalformedExtension(curve_type as u16));
    }
    let named_curve = c.u16()?;
    let public_point = c.u8_vec()?.to_vec();
    let params_end = c.position();
    let signed_params = c.bytes[params_start..params_end].to_vec();
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(EcdheServerKeyExchange {
        named_curve,
        public_point,
        sig_scheme,
        signature,
        signed_params,
    })
}

// ============================================================
//                     ServerHelloDone
// ============================================================

pub fn decode_server_hello_done_body(body: &[u8]) -> Result<(), CodecError> {
    if !body.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(())
}

// ============================================================
//                     ClientKeyExchange (ECDHE)
// ============================================================

pub fn encode_ecdhe_client_key_exchange_body(public_point: &[u8]) -> Vec<u8> {
    encode_ecdhe_client_key_exchange_body_mapped(public_point).bytes
}

pub fn encode_ecdhe_client_key_exchange_body_mapped(public_point: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("ecdh_Yc");
    w.mark("ecdh_point_length");
    w.u8(public_point.len() as u8);
    w.mark_end("ecdh_point_length");
    // `handshake.ecdh_point`: the point without its length byte (`ecdh_Yc` is
    // the whole length-prefixed field).
    w.mark("ecdh_point");
    w.bytes(public_point);
    w.mark_end("ecdh_point");
    w.mark_end("ecdh_Yc");
    w.into_encoded_body()
}

/// Encode a TLS 1.2 RSA ClientKeyExchange body: the encrypted
/// PreMasterSecret with a u16 length prefix.
pub fn encode_rsa_client_key_exchange_body(encrypted_pms: &[u8]) -> Vec<u8> {
    encode_rsa_client_key_exchange_body_mapped(encrypted_pms).bytes
}

pub fn encode_rsa_client_key_exchange_body_mapped(encrypted_pms: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("encrypted_premaster");
    w.mark("encrypted_premaster_length");
    w.u16(encrypted_pms.len() as u16);
    w.mark_end("encrypted_premaster_length");
    w.bytes(encrypted_pms);
    w.mark_end("encrypted_premaster");
    w.into_encoded_body()
}

/// Parse a TLS 1.2 RSA ClientKeyExchange body (server receives
/// this). Returns the encrypted PMS bytes.
pub fn decode_rsa_client_key_exchange_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let encrypted = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(encrypted)
}

// ============================================================
//                         Finished
// ============================================================

pub fn encode_finished_body(verify_data: &[u8]) -> Vec<u8> {
    encode_finished_body_mapped(verify_data).bytes
}

pub fn encode_finished_body_mapped(verify_data: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("verify_data");
    w.bytes(verify_data);
    w.mark_end("verify_data");
    w.into_encoded_body()
}

pub fn decode_finished_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    Ok(body.to_vec())
}

// ============================================================
//                        KeyUpdate
// ============================================================

pub fn encode_key_update_body(request_update: u8) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("request_update");
    w.u8(request_update);
    w.mark_end("request_update");
    w.into_encoded_body()
}

pub fn decode_key_update_body(body: &[u8]) -> Result<u8, CodecError> {
    if body.len() != 1 || body[0] > KEY_UPDATE_REQUESTED {
        return Err(CodecError::InvalidValue("invalid KeyUpdate body"));
    }
    Ok(body[0])
}

/// KeyUpdate.request_update values (RFC 8446 §4.6.3).
pub const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
pub const KEY_UPDATE_REQUESTED: u8 = 1;

// ============================================================
//                     NewSessionTicket
// ============================================================

/// Decode a TLS 1.2 NewSessionTicket message (RFC 5077 §3.3):
/// `ticket_lifetime_hint(4) || ticket(u16-length-prefixed)`.
/// TLS 1.2 NewSessionTicket (RFC 5077 3.3): `uint32 ticket_lifetime_hint;
/// opaque ticket<0..2^16-1>`. Field marks `lifetime` and `ticket` for
/// overrides and mutations.
pub fn encode_new_session_ticket_body_mapped(lifetime_hint: u32, ticket: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("lifetime");
    w.bytes(&lifetime_hint.to_be_bytes());
    w.mark_end("lifetime");
    w.mark("ticket");
    w.mark("ticket_length");
    w.u16(ticket.len() as u16);
    w.mark_end("ticket_length");
    w.bytes(ticket);
    w.mark_end("ticket");
    w.into_encoded_body()
}

pub fn decode_new_session_ticket_body(body: &[u8]) -> Result<(u32, Vec<u8>), CodecError> {
    let mut c = ByteCursor::new(body);
    let lifetime_hint = {
        let b = [c.u8()?, c.u8()?, c.u8()?, c.u8()?];
        u32::from_be_bytes(b)
    };
    let ticket = c.u16_vec()?.to_vec();
    if c.remaining() != 0 {
        return Err(CodecError::InvalidValue("trailing NewSessionTicket bytes"));
    }
    Ok((lifetime_hint, ticket))
}

/// TLS 1.3 NewSessionTicket (RFC 8446 §4.6.1):
/// ```text
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// }
/// ```
pub struct NewSessionTicket13 {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    /// The ticket's extensions (RFC 8446 4.6.1: only early_data is defined;
    /// clients MUST ignore unknown ones). Kept for `recv NewSessionTicket
    /// { has_ext / lacks_ext }` matchers.
    pub extensions: Vec<Extension>,
}

pub fn decode_new_session_ticket_13_body(body: &[u8]) -> Result<NewSessionTicket13, CodecError> {
    let mut c = ByteCursor::new(body);
    let lifetime = {
        let b = [c.u8()?, c.u8()?, c.u8()?, c.u8()?];
        u32::from_be_bytes(b)
    };
    let age_add = {
        let b = [c.u8()?, c.u8()?, c.u8()?, c.u8()?];
        u32::from_be_bytes(b)
    };
    let nonce = c.u8_vec()?.to_vec();
    let ticket = c.u16_vec()?.to_vec();
    let ext_bytes = c.u16_vec()?;
    let extensions = decode_extensions_block(ext_bytes)?;
    Ok(NewSessionTicket13 {
        ticket_lifetime: lifetime,
        ticket_age_add: age_add,
        ticket_nonce: nonce,
        ticket,
        extensions,
    })
}

/// Encode a TLS 1.3 NewSessionTicket body (RFC 8446 4.6.1), the server side of
/// `decode_new_session_ticket_13_body`. Field-mapped so `send NewSessionTicket
/// @ ...` byte mutations can target `handshake.ticket` etc.
pub fn encode_new_session_ticket_13_body_mapped(nst: &NewSessionTicket13) -> EncodedBody {
    let mut out = ByteWriter::new();
    out.mark("ticket_lifetime");
    out.bytes(&nst.ticket_lifetime.to_be_bytes());
    out.mark_end("ticket_lifetime");
    out.mark("ticket_age_add");
    out.bytes(&nst.ticket_age_add.to_be_bytes());
    out.mark_end("ticket_age_add");
    out.mark("ticket_nonce");
    out.mark("ticket_nonce_length");
    out.u8(nst.ticket_nonce.len() as u8);
    out.mark_end("ticket_nonce_length");
    out.bytes(&nst.ticket_nonce);
    out.mark_end("ticket_nonce");
    out.mark("ticket");
    out.mark("ticket_length");
    out.u16(nst.ticket.len() as u16);
    out.mark_end("ticket_length");
    out.bytes(&nst.ticket);
    out.mark_end("ticket");
    out.mark("extensions_length");
    let len_pos = out.reserve_u16();
    out.mark_end("extensions_length");
    for ext in &nst.extensions {
        encode_extension(&mut out, ext);
    }
    out.patch_u16(len_pos);
    out.into_encoded_body()
}

/// A ClientHello pre_shared_key offer as the SERVER sees it (RFC 8446 4.2.11):
/// the identities and the binders, plus the byte length of the binders list
/// (`2 + sum(1 + len)`), which is what the binder transcript excludes.
pub struct PskOffer {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
    pub binders_len: usize,
}

/// Decode the body of a ClientHello pre_shared_key extension (the bytes the
/// generic extension decoder leaves in `Extension::Unknown`).
pub fn decode_pre_shared_key_offer(data: &[u8]) -> Result<PskOffer, CodecError> {
    let mut c = ByteCursor::new(data);
    let ids_bytes = c.u16_vec()?;
    let mut ic = ByteCursor::new(ids_bytes);
    let mut identities = Vec::new();
    while !ic.is_empty() {
        let identity = ic.u16_vec()?.to_vec();
        let age = {
            let b = [ic.u8()?, ic.u8()?, ic.u8()?, ic.u8()?];
            u32::from_be_bytes(b)
        };
        identities.push(PskIdentity {
            identity,
            obfuscated_ticket_age: age,
        });
    }
    let binders_bytes = c.u16_vec()?;
    let binders_len = 2 + binders_bytes.len();
    let mut bc = ByteCursor::new(binders_bytes);
    let mut binders = Vec::new();
    while !bc.is_empty() {
        binders.push(bc.u8_vec()?.to_vec());
    }
    c.expect_empty()?;
    if identities.is_empty() || identities.len() != binders.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(PskOffer {
        identities,
        binders,
        binders_len,
    })
}

/// Encode the ServerHello pre_shared_key response: the selected identity
/// index (RFC 8446 4.2.11).
pub fn encode_pre_shared_key_selection(selected_identity: u16) -> Extension {
    Extension::Unknown {
        ty: EXT_PRE_SHARED_KEY,
        data: selected_identity.to_be_bytes().to_vec(),
    }
}

/// Decode a ClientHello psk_key_exchange_modes body: the u8-length-prefixed
/// list of modes (RFC 8446 4.2.9).
pub fn decode_psk_key_exchange_modes(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(data);
    let modes = c.u8_vec()?.to_vec();
    c.expect_empty()?;
    Ok(modes)
}

// ============================================================
//                           Alert
// ============================================================

// ============================================================
//            server-side encoders + client-side decoders
// ============================================================

// These mirror the client-side functions above. The server driver
// needs to ENCODE ServerHello/Certificate/SKE/SHD and DECODE
// ClientHello/CKE.

/// Parsed ClientHello (server receives this).
pub struct ClientHelloDecoded {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

pub fn decode_client_hello_body(body: &[u8]) -> Result<ClientHelloDecoded, CodecError> {
    let mut c = ByteCursor::new(body);
    let legacy_version = c.u16()?;
    let random_bytes = c.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);
    let session_id = c.u8_vec()?.to_vec();
    let cs_bytes = c.u16_vec()?;
    let mut cs_cursor = ByteCursor::new(cs_bytes);
    let mut cipher_suites = Vec::new();
    while !cs_cursor.is_empty() {
        cipher_suites.push(cs_cursor.u16()?);
    }
    let compression_methods = c.u8_vec()?.to_vec();
    let extensions = if c.is_empty() {
        Vec::new()
    } else {
        let ext_bytes = c.u16_vec()?;
        decode_extensions_block(ext_bytes)?
    };
    c.expect_empty()?;
    Ok(ClientHelloDecoded {
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

/// Build a ServerHello body.
pub struct ServerHelloBuilder {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<Extension>,
}

pub fn encode_server_hello_body(sh: &ServerHelloBuilder) -> Vec<u8> {
    encode_server_hello_body_mapped(sh).bytes
}

/// ServerHello (or HelloRetryRequest) body with a field map, so byte mutations
/// can target `handshake.random`, `handshake.key_share` (the key_share public
/// value), and the other named fields.
pub fn encode_server_hello_body_mapped(sh: &ServerHelloBuilder) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("legacy_version");
    w.u16(sh.legacy_version);
    w.mark_end("legacy_version");
    w.mark("random");
    w.bytes(&sh.random);
    w.mark_end("random");
    w.mark("legacy_session_id_echo");
    w.mark("session_id_length");
    w.u8(sh.session_id.len() as u8);
    w.mark_end("session_id_length");
    w.bytes(&sh.session_id);
    w.mark_end("legacy_session_id_echo");
    w.mark("cipher_suite");
    w.u16(sh.cipher_suite);
    w.mark_end("cipher_suite");
    w.mark("legacy_compression_method");
    w.u8(sh.compression_method);
    w.mark_end("legacy_compression_method");
    if !sh.extensions.is_empty() {
        w.mark("extensions");
        w.mark("extensions_length");
        let ext_pos = w.reserve_u16();
        w.mark_end("extensions_length");
        for ext in &sh.extensions {
            encode_extension(&mut w, ext);
        }
        w.patch_u16(ext_pos);
        w.mark_end("extensions");
    }
    w.into_encoded_body()
}

/// Build a TLS 1.2 Certificate message body.
pub fn encode_certificate_12_body(cert_ders: &[&[u8]]) -> Vec<u8> {
    encode_certificate_12_body_mapped(cert_ders).bytes
}

/// TLS 1.2 / DTLS Certificate body with a field map: `certificate_list` covers
/// the list contents after the outer u24 length (the region the TLS 1.2
/// client maps), so a byte mutation lands inside a certificate entry.
pub fn encode_certificate_12_body_mapped(cert_ders: &[&[u8]]) -> EncodedBody {
    let mut w = ByteWriter::new();
    let list_len: usize = cert_ders.iter().map(|cert| 3 + cert.len()).sum();
    w.mark("certificate_list_length");
    w.u24(list_len as u32);
    w.mark_end("certificate_list_length");
    w.mark("certificate_list");
    for (i, cert) in cert_ders.iter().enumerate() {
        if i == 0 {
            w.mark("first_certificate_length");
        }
        w.u24(cert.len() as u32);
        if i == 0 {
            w.mark_end("first_certificate_length");
        }
        w.bytes(cert);
    }
    w.mark_end("certificate_list");
    w.into_encoded_body()
}

pub fn encode_raw_public_key_certificate_12_body_mapped(spki: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("certificate_list_length");
    w.mark("first_certificate_length");
    w.u24(spki.len() as u32);
    w.mark_end("first_certificate_length");
    w.mark_end("certificate_list_length");
    w.mark("certificate_list");
    w.bytes(spki);
    w.mark_end("certificate_list");
    w.into_encoded_body()
}

/// Build a TLS 1.2 ECDHE ServerKeyExchange body.
///
/// `signed_params` is `ECParameters || ECPoint` — the bytes the
/// server signs. `sig_scheme` and `signature` are the TLS 1.2
/// SignatureAndHashAlgorithm + signature.
pub fn encode_ecdhe_server_key_exchange_body(
    named_curve: u16,
    public_point: &[u8],
    sig_scheme: u16,
    signature: &[u8],
) -> Vec<u8> {
    let mut w = ByteWriter::new();
    // ECParameters: curve_type = named_curve (3)
    w.u8(3);
    w.u16(named_curve);
    // ECPoint
    w.u8_vec(public_point);
    // SignatureAndHashAlgorithm + signature
    w.u16(sig_scheme);
    w.u16_vec(signature);
    w.into_vec()
}

/// Field-mapped variant of the ECDHE ServerKeyExchange body, so `send
/// ServerKeyExchange @ ...` mutations can target `signature` (client-side
/// ServerKeyExchange signature-verification tests).
pub fn encode_ecdhe_server_key_exchange_body_mapped(
    named_curve: u16,
    public_point: &[u8],
    sig_scheme: u16,
    signature: &[u8],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.u8(3);
    w.u16(named_curve);
    w.mark("ecdh_point_length");
    w.u8(public_point.len() as u8);
    w.mark_end("ecdh_point_length");
    // `handshake.ecdh_point`: the server's public value without its length byte.
    w.mark("ecdh_point");
    w.bytes(public_point);
    w.mark_end("ecdh_point");
    w.u16(sig_scheme);
    w.mark("signature");
    w.mark("signature_length");
    w.u16(signature.len() as u16);
    w.mark_end("signature_length");
    w.bytes(signature);
    w.mark_end("signature");
    w.into_encoded_body()
}

pub fn encode_ecdhe_server_key_exchange_body_mapped_legacy(
    named_curve: u16,
    public_point: &[u8],
    signature: &[u8],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.u8(3);
    w.u16(named_curve);
    w.mark("ecdh_point_length");
    w.u8(public_point.len() as u8);
    w.mark_end("ecdh_point_length");
    w.mark("ecdh_point");
    w.bytes(public_point);
    w.mark_end("ecdh_point");
    w.mark("signature");
    w.mark("signature_length");
    w.u16(signature.len() as u16);
    w.mark_end("signature_length");
    w.bytes(signature);
    w.mark_end("signature");
    w.into_encoded_body()
}

/// ServerHelloDone has an empty body.
pub fn encode_server_hello_done_body() -> Vec<u8> {
    Vec::new()
}

/// Parse a TLS 1.2 ECDHE ClientKeyExchange body (server receives
/// this). Returns the client's EC point.
pub fn decode_ecdhe_client_key_exchange_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let point = c.u8_vec()?.to_vec();
    c.expect_empty()?;
    Ok(point)
}

// ============================================================
//             TLS 1.3 server-side encoders
// ============================================================

/// Build an empty EncryptedExtensions body (RFC 8446 §4.3.1).
pub fn encode_encrypted_extensions_body() -> Vec<u8> {
    encode_encrypted_extensions_body_mapped(&[]).bytes
}

pub fn encode_encrypted_extensions_body_mapped(extensions: &[Extension]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("extensions_length");
    let len = w.reserve_u16();
    w.mark_end("extensions_length");
    for ext in extensions {
        encode_extension(&mut w, ext);
    }
    w.patch_u16(len);
    w.into_encoded_body()
}

/// Build a TLS 1.3 Certificate body (RFC 8446 §4.4.2). Different
/// from TLS 1.2: has a request_context prefix and per-cert
/// extensions.
pub fn encode_certificate_13_body(cert_ders: &[&[u8]]) -> Vec<u8> {
    encode_certificate_13_body_with_leaf_extensions_mapped(cert_ders, &[]).bytes
}

/// Encode a sequence of extensions with no enclosing length prefix.
pub fn encode_extensions_sequence(extensions: &[Extension]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    for ext in extensions {
        encode_extension(&mut w, ext);
    }
    w.into_vec()
}

/// TLS 1.3 Certificate body whose FIRST entry (the end-entity certificate)
/// carries `leaf_extensions` (RFC 8446 4.4.2: OCSP status, SCTs, ... may only
/// accompany the entry they describe); further entries get an empty block.
pub fn encode_certificate_13_body_with_leaf_extensions(
    cert_ders: &[&[u8]],
    leaf_extensions: &[Extension],
) -> Vec<u8> {
    encode_certificate_13_body_with_leaf_extensions_mapped(cert_ders, leaf_extensions).bytes
}

pub fn encode_certificate_13_body_with_leaf_extensions_mapped(
    cert_ders: &[&[u8]],
    leaf_extensions: &[Extension],
) -> EncodedBody {
    let leaf_ext_len = encode_extensions_sequence(leaf_extensions).len();
    let list_len: usize = cert_ders
        .iter()
        .enumerate()
        .map(|(i, cert)| 3 + cert.len() + 2 + if i == 0 { leaf_ext_len } else { 0 })
        .sum();
    let mut w = ByteWriter::new();
    w.mark("request_context_length");
    w.u8(0); // empty request_context (server cert)
    w.mark_end("request_context_length");
    w.mark("certificate_list_length");
    w.u24(list_len as u32);
    w.mark_end("certificate_list_length");
    w.mark("certificate_list");
    for (i, cert) in cert_ders.iter().enumerate() {
        if i == 0 {
            w.mark("first_certificate_length");
        }
        w.u24(cert.len() as u32);
        if i == 0 {
            w.mark_end("first_certificate_length");
        }
        w.bytes(cert);
        if i == 0 {
            w.mark("first_certificate_extensions_length");
            w.u16(leaf_ext_len as u16);
            w.mark_end("first_certificate_extensions_length");
            for ext in leaf_extensions {
                encode_extension(&mut w, ext);
            }
        } else {
            w.u16(0); // empty per-cert extensions
        }
    }
    w.mark_end("certificate_list");
    w.into_encoded_body()
}

/// Build a TLS 1.3 CertificateVerify body (RFC 8446 §4.4.3).
pub fn encode_certificate_verify_13_body(sig_scheme: u16, signature: &[u8]) -> Vec<u8> {
    encode_certificate_verify_13_body_mapped(sig_scheme, signature).bytes
}

// ============================================================
//                  CertificateRequest (TLS 1.2)
// ============================================================

/// RFC 5246 7.4.4 ClientCertificateType values plzn's server advertises.
pub const CLIENT_CERT_TYPE_RSA_SIGN: u8 = 1;
pub const CLIENT_CERT_TYPE_ECDSA_SIGN: u8 = 64;

/// Parsed TLS 1.2 CertificateRequest (RFC 5246 7.4.4):
///
/// ```text
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// }
/// ```
pub struct CertificateRequest12 {
    pub certificate_types: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    /// Each DER-encoded Name, as sent (u16-length-prefixed on the wire).
    pub certificate_authorities: Vec<Vec<u8>>,
}

/// Field-mapped encoder; `certificate_types`, `signature_algorithms` and
/// `certificate_authorities` are mutation targets. The lists are written as
/// given (an empty list is a deliberate violation of the `<1..>` / `<2..>`
/// bounds, for the client-side negatives).
pub fn encode_certificate_request_12_body_mapped(
    certificate_types: &[u8],
    signature_algorithms: &[u16],
    certificate_authorities: &[Vec<u8>],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("certificate_types");
    w.mark("certificate_types_length");
    w.u8(certificate_types.len() as u8);
    w.mark_end("certificate_types_length");
    w.bytes(certificate_types);
    w.mark_end("certificate_types");
    w.mark("signature_algorithms");
    w.mark("signature_algorithms_length");
    let sig_len = w.reserve_u16();
    w.mark_end("signature_algorithms_length");
    for s in signature_algorithms {
        w.u16(*s);
    }
    w.patch_u16(sig_len);
    w.mark_end("signature_algorithms");
    w.mark("certificate_authorities");
    w.mark("certificate_authorities_length");
    let ca_len = w.reserve_u16();
    w.mark_end("certificate_authorities_length");
    for (i, dn) in certificate_authorities.iter().enumerate() {
        if i == 0 {
            w.mark("first_authority_length");
        }
        w.u16(dn.len() as u16);
        if i == 0 {
            w.mark_end("first_authority_length");
        }
        w.bytes(dn);
    }
    w.patch_u16(ca_len);
    w.mark_end("certificate_authorities");
    w.into_encoded_body()
}

pub fn decode_certificate_request_12_body(body: &[u8]) -> Result<CertificateRequest12, CodecError> {
    let mut c = ByteCursor::new(body);
    let certificate_types = c.u8_vec()?.to_vec();
    let sig_bytes = c.u16_vec()?;
    if sig_bytes.len() % 2 != 0 {
        return Err(CodecError::TrailingBytes);
    }
    let signature_algorithms = sig_bytes
        .chunks(2)
        .map(|ch| u16::from_be_bytes([ch[0], ch[1]]))
        .collect();
    let ca_bytes = c.u16_vec()?;
    let mut cac = ByteCursor::new(ca_bytes);
    let mut certificate_authorities = Vec::new();
    while !cac.is_empty() {
        certificate_authorities.push(cac.u16_vec()?.to_vec());
    }
    c.expect_empty()?;
    Ok(CertificateRequest12 {
        certificate_types,
        signature_algorithms,
        certificate_authorities,
    })
}

pub fn decode_certificate_request_legacy_body(
    body: &[u8],
) -> Result<CertificateRequest12, CodecError> {
    let mut c = ByteCursor::new(body);
    let certificate_types = c.u8_vec()?.to_vec();
    let ca_bytes = c.u16_vec()?;
    let mut cac = ByteCursor::new(ca_bytes);
    let mut certificate_authorities = Vec::new();
    while !cac.is_empty() {
        certificate_authorities.push(cac.u16_vec()?.to_vec());
    }
    c.expect_empty()?;
    Ok(CertificateRequest12 {
        certificate_types,
        signature_algorithms: Vec::new(),
        certificate_authorities,
    })
}

pub fn encode_certificate_request_legacy_body_mapped(
    certificate_types: &[u8],
    certificate_authorities: &[Vec<u8>],
) -> EncodedBody {
    let mut encoded =
        encode_certificate_request_12_body_mapped(certificate_types, &[], certificate_authorities);
    let sig_start = 1 + certificate_types.len();
    encoded.bytes.drain(sig_start..sig_start + 2);
    encoded.fields.remove("signature_algorithms");
    encoded.fields.remove("signature_algorithms_length");
    for range in encoded.fields.values_mut() {
        if range.start >= sig_start + 2 {
            range.start -= 2;
        }
        if range.end >= sig_start + 2 {
            range.end -= 2;
        }
    }
    encoded
}

/// Build a TLS 1.2 CertificateVerify body (RFC 5246 §7.4.8). The wire layout
/// (SignatureAndHashAlgorithm + u16-length signature) is identical to TLS 1.3.
pub fn encode_certificate_verify_12_body(sig_scheme: u16, signature: &[u8]) -> Vec<u8> {
    encode_certificate_verify_13_body(sig_scheme, signature)
}

// ============================================================
//                           Alert
// ============================================================

#[derive(Clone, Copy, Debug)]
pub struct Alert {
    pub level: u8,
    pub description: u8,
}

pub fn decode_alert(body: &[u8]) -> Result<Alert, CodecError> {
    if body.len() != 2 {
        return Err(CodecError::UnexpectedEof);
    }
    Ok(Alert {
        level: body[0],
        description: body[1],
    })
}

// ============================================================
//                     TLS 1.3 messages
// ============================================================

/// RFC 8446 §4.3.1 EncryptedExtensions — just a u16-length block of
/// extensions. We parse the inner extension list but don't do
/// anything with it yet.
pub fn decode_encrypted_extensions_body(body: &[u8]) -> Result<Vec<Extension>, CodecError> {
    let mut c = ByteCursor::new(body);
    let ext_bytes = c.u16_vec()?;
    c.expect_empty()?;
    decode_extensions_block(ext_bytes)
}

/// TLS 1.3 Certificate message (RFC 8446 §4.4.2):
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// }
///
/// CertificateEntry ::= { opaque cert_data<1..2^24-1>; Extension extensions<0..2^16-1>; }
/// ```
///
/// Server certificate has an empty request context.
pub struct Certificate13 {
    pub request_context: Vec<u8>,
    pub entries: Vec<Certificate13Entry>,
}

pub struct Certificate13Entry {
    pub cert_data: Vec<u8>,
    pub extensions: Vec<u8>, // raw extension block bytes (we don't parse)
}

pub fn decode_certificate_13_body(body: &[u8]) -> Result<Certificate13, CodecError> {
    let mut c = ByteCursor::new(body);
    let request_context = c.u8_vec()?.to_vec();
    let list_bytes = c.u24_vec()?;
    c.expect_empty()?;
    let mut lc = ByteCursor::new(list_bytes);
    let mut entries = Vec::new();
    while !lc.is_empty() {
        let cert_data = lc.u24_vec()?.to_vec();
        let extensions = lc.u16_vec()?.to_vec();
        entries.push(Certificate13Entry {
            cert_data,
            extensions,
        });
    }
    Ok(Certificate13 {
        request_context,
        entries,
    })
}

/// TLS 1.3 CertificateVerify (RFC 8446 §4.4.3).
///
/// ```text
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// }
/// ```
pub struct CertificateVerify13 {
    pub algorithm: u16,
    pub signature: Vec<u8>,
}

pub fn decode_certificate_verify_13_body(body: &[u8]) -> Result<CertificateVerify13, CodecError> {
    let mut c = ByteCursor::new(body);
    let algorithm = c.u16()?;
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(CertificateVerify13 {
        algorithm,
        signature,
    })
}

pub fn decode_certificate_verify_legacy_body(
    body: &[u8],
    algorithm: u16,
) -> Result<CertificateVerify13, CodecError> {
    let mut c = ByteCursor::new(body);
    let signature = c.u16_vec()?.to_vec();
    c.expect_empty()?;
    Ok(CertificateVerify13 {
        algorithm,
        signature,
    })
}

/// Build the TLS 1.3 signed-input blob for CertificateVerify.
/// RFC 8446 §4.4.3:
///
/// ```text
/// signed_input =
///     0x20 * 64 ||
///     context_string ||
///     0x00 ||
///     Transcript-Hash(...)
/// ```
pub fn tls13_certificate_verify_signed_input(transcript_hash: &[u8]) -> Vec<u8> {
    tls13_cv_signed_input(transcript_hash, b"TLS 1.3, server CertificateVerify")
}

pub fn tls13_client_certificate_verify_signed_input(transcript_hash: &[u8]) -> Vec<u8> {
    tls13_cv_signed_input(transcript_hash, b"TLS 1.3, client CertificateVerify")
}

fn tls13_cv_signed_input(transcript_hash: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + context.len() + 1 + transcript_hash.len());
    out.extend(std::iter::repeat_n(0x20u8, 64));
    out.extend_from_slice(context);
    out.push(0x00);
    out.extend_from_slice(transcript_hash);
    out
}

pub fn encode_certificate_verify_13_body_mapped(algorithm: u16, signature: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("algorithm");
    w.u16(algorithm);
    w.mark_end("algorithm");
    w.mark("signature");
    w.mark("signature_length");
    w.u16(signature.len() as u16);
    w.mark_end("signature_length");
    w.bytes(signature);
    w.mark_end("signature");
    w.into_encoded_body()
}

pub fn encode_certificate_verify_legacy_body_mapped(signature: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("signature");
    w.mark("signature_length");
    w.u16(signature.len() as u16);
    w.mark_end("signature_length");
    w.bytes(signature);
    w.mark_end("signature");
    w.into_encoded_body()
}

/// TLS 1.3 CertificateRequest (RFC 8446 §4.3.2):
///
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     Extension extensions<2..2^16-1>;
/// }
/// ```
///
/// The only extension we send is signature_algorithms (0x000d).
pub fn encode_certificate_request_13_body(
    sig_algs: &[u16],
    cert_authorities: &[Vec<u8>],
) -> EncodedBody {
    encode_certificate_request_13_body_from_extensions(&certificate_request_13_extensions(
        sig_algs,
        cert_authorities,
    ))
}

/// The extensions a TLS 1.3 CertificateRequest carries by default:
/// signature_algorithms (RFC 8446 4.3.2, mandatory) then certificate_authorities
/// (RFC 8446 4.2.4) when any are configured. Returned as a list so
/// `send CertificateRequest { +ext ... }` deltas can edit it before encoding.
pub fn certificate_request_13_extensions(
    sig_algs: &[u16],
    cert_authorities: &[Vec<u8>],
) -> Vec<Extension> {
    let mut extensions = vec![Extension::SignatureAlgorithms(sig_algs.to_vec())];
    // certificate_authorities: DistinguishedName authorities<3..2^16-1>, each
    // DistinguishedName being opaque<1..2^16-1> of DER-encoded Name.
    if !cert_authorities.is_empty() {
        let mut w = ByteWriter::new();
        let auth_list_len = w.reserve_u16();
        for dn in cert_authorities {
            w.u16(dn.len() as u16);
            w.bytes(dn);
        }
        w.patch_u16(auth_list_len);
        extensions.push(Extension::Unknown {
            ty: EXT_CERTIFICATE_AUTHORITIES,
            data: w.into_vec(),
        });
    }
    extensions
}

/// Encode a TLS 1.3 CertificateRequest (RFC 8446 4.3.2) with an empty
/// certificate_request_context and the given extensions.
pub fn encode_certificate_request_13_body_from_extensions(extensions: &[Extension]) -> EncodedBody {
    encode_certificate_request_13_body_with_context(extensions, &[])
}

/// Encode a TLS 1.3 CertificateRequest with an explicit request context.
/// Initial-handshake requests use an empty context; post-handshake requests
/// are required to use a non-empty context (RFC 8446 4.3.2).
pub fn encode_certificate_request_13_body_with_context(
    extensions: &[Extension],
    context: &[u8],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    assert!(context.len() <= u8::MAX as usize);
    w.mark("request_context_length");
    w.u8(context.len() as u8);
    w.mark_end("request_context_length");
    w.bytes(context);
    w.mark("extensions_length");
    let ext_len_pos = w.reserve_u16();
    w.mark_end("extensions_length");
    for ext in extensions {
        encode_extension(&mut w, ext);
    }
    w.patch_u16(ext_len_pos);
    w.into_encoded_body()
}

/// A decoded TLS 1.3 CertificateRequest: context plus its extensions, for
/// `recv CertificateRequest { has_ext / lacks_ext }` matchers.
pub struct CertificateRequest13 {
    pub context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

pub fn decode_certificate_request_13_full(body: &[u8]) -> Result<CertificateRequest13, CodecError> {
    let mut c = ByteCursor::new(body);
    let context = c.u8_vec()?.to_vec();
    let ext_bytes = c.u16_vec()?;
    c.expect_empty()?;
    let extensions = decode_extensions_block(ext_bytes)?;
    Ok(CertificateRequest13 {
        context,
        extensions,
    })
}

pub fn decode_certificate_request_13_body(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut c = ByteCursor::new(body);
    let context = c.u8_vec()?.to_vec();
    // Skip extensions — we don't inspect them for now.
    let _ext_bytes = c.u16_vec()?;
    Ok(context)
}

// ============================================================
//                            tests
// ============================================================

#[cfg(test)]
mod tests {
    #[test]
    fn new_session_ticket_12_round_trip() {
        let enc = encode_new_session_ticket_body_mapped(7200, b"ticket-bytes");
        assert_eq!(enc.field_range("lifetime"), Some(0..4));
        assert_eq!(enc.field_range("ticket"), Some(4..4 + 2 + 12));
        let (lifetime, ticket) = decode_new_session_ticket_body(&enc.bytes).unwrap();
        assert_eq!(lifetime, 7200);
        assert_eq!(ticket, b"ticket-bytes");
        // A zero-length ticket (RFC 5077 3.3) encodes as a 2-byte length of 0.
        let empty = encode_new_session_ticket_body_mapped(0, b"");
        assert_eq!(empty.bytes, vec![0, 0, 0, 0, 0, 0]);
    }

    use super::*;

    #[test]
    fn certificate_request_13_preserves_explicit_context() {
        let extensions = certificate_request_13_extensions(&[0x0804], &[]);
        let encoded = encode_certificate_request_13_body_with_context(&extensions, b"pha-1");
        let decoded = decode_certificate_request_13_full(&encoded.bytes).unwrap();
        assert_eq!(decoded.context, b"pha-1");
        assert_eq!(decoded.extensions.len(), 1);
    }

    #[test]
    fn compressed_certificate_zlib_round_trip() {
        use std::io::Write;
        // Stand-in for a Certificate message body (arbitrary bytes -- decompression is
        // content-agnostic).
        let inner: Vec<u8> = (0..500u32).map(|i| (i % 7) as u8).collect();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&inner).unwrap();
        let compressed = enc.finish().unwrap();

        let mut w = ByteWriter::new();
        w.u16(CERT_COMPRESSION_ZLIB);
        w.u24(inner.len() as u32);
        w.u24_vec(&compressed);
        assert_eq!(decompress_certificate_13(&w.into_vec()).unwrap(), inner);

        // Wrong declared uncompressed_length must be rejected (RFC 8879 4).
        let mut w2 = ByteWriter::new();
        w2.u16(CERT_COMPRESSION_ZLIB);
        w2.u24((inner.len() + 1) as u32);
        w2.u24_vec(&compressed);
        assert!(decompress_certificate_13(&w2.into_vec()).is_err());

        // Unsupported algorithm (brotli) rejected.
        let mut w3 = ByteWriter::new();
        w3.u16(2);
        w3.u24(inner.len() as u32);
        w3.u24_vec(&compressed);
        assert!(decompress_certificate_13(&w3.into_vec()).is_err());

        // Garbage compressed data rejected (not a valid zlib stream).
        let mut w4 = ByteWriter::new();
        w4.u16(CERT_COMPRESSION_ZLIB);
        w4.u24(inner.len() as u32);
        w4.u24_vec(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(decompress_certificate_13(&w4.into_vec()).is_err());

        // encode_compressed_certificate_13 is the inverse of decompress_certificate_13.
        let encoded = encode_compressed_certificate_13(&inner);
        assert_eq!(decompress_certificate_13(&encoded).unwrap(), inner);
    }

    #[test]
    fn key_share_mark_covers_the_public_value_only() {
        // `handshake.key_share` must resolve to the first entry's key_exchange
        // bytes, excluding its u16 length prefix, so a byte mutation lands inside
        // the point (RFC 8446 4.2.8 KeyShareEntry).
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![Extension::KeyShare(vec![
                KeyShareEntry {
                    group: 0x001d,
                    key_exchange: vec![0xAA; 32],
                },
                KeyShareEntry {
                    group: 0x0017,
                    key_exchange: vec![0xBB; 65],
                },
            ])],
        };
        let encoded = encode_client_hello_body_mapped(&ch).unwrap();
        let range = encoded.field_range("key_share").expect("key_share mark");
        assert_eq!(range.len(), 32, "covers the first entry's value");
        assert!(encoded.bytes[range.clone()].iter().all(|b| *b == 0xAA));
        // The byte before the marked region is the low half of its length prefix.
        assert_eq!(encoded.bytes[range.start - 1], 32);
    }

    #[test]
    fn psk_marks_survive_a_non_final_extension_position() {
        // The driver uses these ranges both to patch a valid binder and to
        // target deliberate binder/age faults. In particular, neither may be
        // inferred from the end of ClientHello: the MUST-be-last negative puts
        // another extension after pre_shared_key.
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![
                Extension::PreSharedKey {
                    identities: vec![PskIdentity {
                        identity: b"identity".to_vec(),
                        obfuscated_ticket_age: 0x1234_5678,
                    }],
                    binder_lengths: vec![32],
                },
                Extension::Unknown {
                    ty: 0x0015, // padding
                    data: vec![0; 8],
                },
            ],
        };
        let encoded = encode_client_hello_body_mapped(&ch).unwrap();
        let age = encoded
            .field_range("obfuscated_ticket_age")
            .expect("ticket-age mark");
        let binder = encoded.field_range("psk_binder").expect("binder mark");
        assert_eq!(encoded.field_range("psk_binder_0"), Some(binder.clone()));
        assert_eq!(&encoded.bytes[age], &0x1234_5678u32.to_be_bytes());
        assert_eq!(binder.len(), 32);
        assert!(encoded.bytes[binder.clone()].iter().all(|b| *b == 0));
        assert!(
            binder.end < encoded.bytes.len(),
            "binder is deliberately non-final"
        );
        assert_eq!(
            encoded.fields["extension_pre_shared_key_identity_list_length"].len(),
            2
        );
        assert_eq!(
            encoded.fields["extension_pre_shared_key_binder_list_length"].len(),
            2
        );
        assert_eq!(
            encoded.fields["extension_pre_shared_key_binder_length"].len(),
            1
        );
    }

    #[test]
    fn every_psk_binder_has_an_indexed_field_range() {
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![0x1301, 0x1302],
            compression_methods: vec![0],
            extensions: vec![Extension::PreSharedKey {
                identities: vec![
                    PskIdentity {
                        identity: b"sha256".to_vec(),
                        obfuscated_ticket_age: 0,
                    },
                    PskIdentity {
                        identity: b"sha384".to_vec(),
                        obfuscated_ticket_age: 1,
                    },
                ],
                binder_lengths: vec![32, 48],
            }],
        };
        let encoded = encode_client_hello_body_mapped(&ch).unwrap();
        assert_eq!(encoded.field_range("psk_binder_0").unwrap().len(), 32);
        assert_eq!(encoded.field_range("psk_binder_1").unwrap().len(), 48);
    }

    #[test]
    fn extension_encoders_map_outer_and_nested_lengths() {
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![0x1301],
            compression_methods: vec![0],
            extensions: vec![
                Extension::SignatureAlgorithms(vec![0x0403, 0x0804]),
                Extension::Unknown {
                    ty: 0x0010,
                    data: vec![0, 3, 2, b'h', b'2'],
                },
                Extension::ExtendedMasterSecret,
            ],
        };
        let encoded = encode_client_hello_body_mapped(&ch).unwrap();
        for (name, width) in [
            ("extension_signature_algorithms_length", 2),
            ("extension_signature_algorithms_list_length", 2),
            ("extension_alpn_length", 2),
            ("extension_alpn_list_length", 2),
            ("extension_extended_master_secret_length", 2),
        ] {
            assert_eq!(encoded.fields[name].len(), width, "{name}");
        }
    }

    #[test]
    fn certificate_encoders_map_all_nested_lengths() {
        let cert12 = encode_certificate_12_body_mapped(&[b"leaf", b"issuer"]);
        assert_eq!(cert12.fields["certificate_list_length"], 0..3);
        assert_eq!(cert12.fields["first_certificate_length"], 3..6);

        let cert13 = encode_certificate_13_body_with_leaf_extensions_mapped(
            &[b"leaf"],
            &[Extension::Unknown {
                ty: 0x0015,
                data: vec![0; 4],
            }],
        );
        assert_eq!(cert13.fields["request_context_length"], 0..1);
        assert_eq!(cert13.fields["certificate_list_length"], 1..4);
        assert_eq!(cert13.fields["first_certificate_length"], 4..7);
        assert_eq!(
            cert13.fields["first_certificate_extensions_length"].len(),
            2
        );
        assert_eq!(cert13.fields["extension_padding_length"].len(), 2);
    }

    #[test]
    fn server_hello_key_share_and_ecdh_point_marks() {
        let sh = ServerHelloBuilder {
            legacy_version: 0x0303,
            random: [7u8; 32],
            session_id: Vec::new(),
            cipher_suite: 0x1301,
            compression_method: 0,
            extensions: vec![Extension::KeyShareSingle(KeyShareEntry {
                group: 0x0017,
                key_exchange: vec![0xCC; 65],
            })],
        };
        let encoded = encode_server_hello_body_mapped(&sh);
        let ks = encoded.field_range("key_share").expect("key_share mark");
        assert_eq!(ks.len(), 65);
        assert!(encoded.bytes[ks].iter().all(|b| *b == 0xCC));
        assert_eq!(
            encoded.field_range("random").expect("random mark").len(),
            32
        );

        // TLS 1.2: `handshake.ecdh_point` excludes the u8 length byte, while
        // `ecdh_Yc` (ClientKeyExchange) covers the whole length-prefixed field.
        let cke = encode_ecdhe_client_key_exchange_body_mapped(&[0xDD; 65]);
        let pt = cke.field_range("ecdh_point").expect("ecdh_point mark");
        assert_eq!(pt.len(), 65);
        assert_eq!(cke.field_range("ecdh_Yc").expect("ecdh_Yc mark").len(), 66);
        let ske =
            encode_ecdhe_server_key_exchange_body_mapped(0x0017, &[0xEE; 65], 0x0403, &[1, 2, 3]);
        assert_eq!(
            ske.field_range("ecdh_point").expect("ske point mark").len(),
            65
        );
    }

    #[test]
    fn cert_type_list_round_trip_and_selection() {
        // RFC 7250 client offer: 1-byte length + one byte per type.
        let body = encode_cert_type_list(&[CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509]);
        assert_eq!(body, vec![0x02, CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509]);
        assert_eq!(
            decode_cert_type_list(&body).unwrap(),
            vec![CERT_TYPE_RAW_PUBLIC_KEY, CERT_TYPE_X509]
        );

        // Length-overrun (claims 5, supplies 1) must be rejected, not accepted.
        assert!(decode_cert_type_list(&[0x05, 0x02]).is_err());
        // Empty list is illegal (<1..>).
        assert!(decode_cert_type_list(&[0x00]).is_err());

        // Server selection: exactly one byte, no list prefix.
        assert_eq!(
            decode_cert_type_selection(&[CERT_TYPE_RAW_PUBLIC_KEY]).unwrap(),
            CERT_TYPE_RAW_PUBLIC_KEY
        );
        // A list-shaped body (2 bytes) is NOT a valid selection.
        assert!(decode_cert_type_selection(&[0x01, 0x02]).is_err());
        assert!(decode_cert_type_selection(&[]).is_err());
    }

    #[test]
    fn byte_writer_length_prefix_round_trip() {
        let mut w = ByteWriter::new();
        w.u16(0x1234);
        let pos = w.reserve_u16();
        w.u16(0xaaaa);
        w.u16(0xbbbb);
        w.patch_u16(pos);
        let bytes = w.into_vec();
        // 0x12 0x34 | 0x00 0x04 | 0xaa 0xaa 0xbb 0xbb
        assert_eq!(bytes, vec![0x12, 0x34, 0x00, 0x04, 0xaa, 0xaa, 0xbb, 0xbb]);
    }

    #[test]
    fn byte_cursor_u24_vec() {
        let bytes = [0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
        let mut c = ByteCursor::new(&bytes);
        assert_eq!(c.u24_vec().unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert!(c.is_empty());
    }

    #[test]
    fn handshake_header_round_trip() {
        let body = b"hello";
        let encoded = encode_handshake(HS_CLIENT_HELLO, body);
        // type(1) + length(3) + body
        assert_eq!(encoded[0], HS_CLIENT_HELLO);
        assert_eq!(&encoded[1..4], &[0, 0, 5]);
        assert_eq!(&encoded[4..], body);
    }

    #[test]
    fn client_hello_encoding_shape() {
        let ch = ClientHello {
            legacy_version: PROTOCOL_VERSION_TLS12,
            random: [0x11; 32],
            session_id: vec![],
            cipher_suites: vec![TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            compression_methods: vec![0],
            extensions: vec![
                Extension::SupportedGroups(vec![GROUP_SECP256R1]),
                Extension::EcPointFormats(vec![0]),
                Extension::SignatureAlgorithms(vec![0x0401]),
                Extension::ExtendedMasterSecret,
                Extension::RenegotiationInfo(vec![]),
            ],
        };
        let body = encode_client_hello_body(&ch).unwrap();
        // Round-trip parse extensions out — shape sanity.
        let mut c = ByteCursor::new(&body);
        assert_eq!(c.u16().unwrap(), PROTOCOL_VERSION_TLS12);
        let _ = c.take(32).unwrap();
        let _ = c.u8_vec().unwrap();
        let _ = c.u16_vec().unwrap();
        let _ = c.u8_vec().unwrap();
        let ext_block = c.u16_vec().unwrap();
        let exts = decode_extensions_block(ext_block).unwrap();
        assert_eq!(exts.len(), 5);
    }

    #[test]
    fn client_hello_length_overflows_are_reported() {
        fn hello() -> ClientHello {
            ClientHello {
                legacy_version: PROTOCOL_VERSION_TLS12,
                random: [0; 32],
                session_id: Vec::new(),
                cipher_suites: vec![TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![0],
                extensions: Vec::new(),
            }
        }

        let mut ch = hello();
        ch.cipher_suites = vec![0; 32768];
        assert_eq!(
            validate_client_hello(&ch),
            Err(CodecError::LengthOverflow("ClientHello cipher_suites"))
        );

        let mut ch = hello();
        ch.extensions.push(Extension::Unknown {
            ty: 0x1a1a,
            data: vec![0; u16::MAX as usize + 1],
        });
        assert_eq!(
            validate_client_hello(&ch),
            Err(CodecError::LengthOverflow("extension body"))
        );

        let mut ch = hello();
        ch.extensions.push(Extension::Unknown {
            ty: 0x1a1a,
            data: vec![0; u16::MAX as usize - 3],
        });
        assert_eq!(
            validate_client_hello(&ch),
            Err(CodecError::LengthOverflow("ClientHello extensions"))
        );

        let mut ch = hello();
        ch.session_id = vec![0; u8::MAX as usize + 1];
        assert_eq!(
            validate_client_hello(&ch),
            Err(CodecError::LengthOverflow("ClientHello legacy_session_id"))
        );
    }

    #[test]
    fn server_hello_decode_rejects_trailing_bytes() {
        // Pathological: add an extra byte after a valid ServerHello.
        let mut w = ByteWriter::new();
        w.u16(PROTOCOL_VERSION_TLS12);
        w.bytes(&[0u8; 32]);
        w.u8_vec(&[]);
        w.u16(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        w.u8(0);
        w.u16(0); // empty extensions block
        w.u8(0xff); // stray
        let body = w.into_vec();
        assert!(decode_server_hello_body(&body).is_err());
    }

    #[test]
    fn new_session_ticket_13_encode_decode_round_trip() {
        // RFC 8446 4.6.1: the mapped encoder is the inverse of the decoder,
        // preserving the four scalar/opaque fields and an unknown extension.
        let nst = NewSessionTicket13 {
            ticket_lifetime: 7200,
            ticket_age_add: 0x01020304,
            ticket_nonce: vec![0xaa, 0xbb],
            ticket: b"plzn13-example-ticket".to_vec(),
            extensions: vec![Extension::Unknown {
                ty: 0x002a, // early_data
                data: vec![0x00, 0x00, 0x10, 0x00],
            }],
        };
        let enc = encode_new_session_ticket_13_body_mapped(&nst);
        // The field map covers the four wire fields for byte mutations.
        for f in [
            "ticket_lifetime",
            "ticket_age_add",
            "ticket_nonce",
            "ticket",
        ] {
            assert!(enc.fields.contains_key(f), "missing field range {f}");
        }
        let back = decode_new_session_ticket_13_body(&enc.bytes).unwrap();
        assert_eq!(back.ticket_lifetime, nst.ticket_lifetime);
        assert_eq!(back.ticket_age_add, nst.ticket_age_add);
        assert_eq!(back.ticket_nonce, nst.ticket_nonce);
        assert_eq!(back.ticket, nst.ticket);
        assert_eq!(back.extensions.len(), 1);
    }

    #[test]
    fn key_update_body_round_trip_and_eof() {
        for v in [KEY_UPDATE_NOT_REQUESTED, KEY_UPDATE_REQUESTED] {
            let enc = encode_key_update_body(v);
            assert_eq!(decode_key_update_body(&enc.bytes).unwrap(), v);
        }
        assert!(decode_key_update_body(&[]).is_err());
        assert!(decode_key_update_body(&[0x05]).is_err());
        assert!(decode_key_update_body(&[0, 0]).is_err());
    }

    #[test]
    fn pre_shared_key_offer_decodes_identities_and_binders() {
        // Build a pre_shared_key extension body (what Extension::Unknown holds
        // for EXT_PRE_SHARED_KEY): one identity + one 32-byte binder.
        let identity = b"a-ticket".to_vec();
        let binder = vec![0x11u8; 32];
        let mut ids = ByteWriter::new();
        ids.u16_vec(&identity);
        ids.bytes(&0x00000000u32.to_be_bytes());
        let mut binders = ByteWriter::new();
        binders.u8_vec(&binder);
        let mut body = ByteWriter::new();
        body.u16_vec(&ids.into_vec());
        body.u16_vec(&binders.into_vec());
        let offer = decode_pre_shared_key_offer(&body.into_vec()).unwrap();
        assert_eq!(offer.identities.len(), 1);
        assert_eq!(offer.identities[0].identity, identity);
        assert_eq!(offer.binders, vec![binder]);
        // binders_len is what the binder transcript excludes: 2 (list len) +
        // 1 (per-binder len byte) + 32.
        assert_eq!(offer.binders_len, 2 + 1 + 32);
    }

    #[test]
    fn pre_shared_key_offer_rejects_mismatched_counts() {
        // Two identities but one binder: RFC 8446 4.2.11 requires equal counts.
        let mut ids = ByteWriter::new();
        for id in [b"one".as_slice(), b"two".as_slice()] {
            ids.u16_vec(id);
            ids.bytes(&0u32.to_be_bytes());
        }
        let mut binders = ByteWriter::new();
        binders.u8_vec(&[0x22u8; 32]);
        let mut body = ByteWriter::new();
        body.u16_vec(&ids.into_vec());
        body.u16_vec(&binders.into_vec());
        assert!(decode_pre_shared_key_offer(&body.into_vec()).is_err());
    }
}

#[cfg(test)]
mod certificate_request_12_tests {
    use super::*;

    #[test]
    fn certificate_request_12_round_trips_and_maps_fields() {
        let dn = vec![0x30, 0x00];
        let enc = encode_certificate_request_12_body_mapped(
            &[CLIENT_CERT_TYPE_RSA_SIGN, CLIENT_CERT_TYPE_ECDSA_SIGN],
            &[0x0403, 0x0804],
            std::slice::from_ref(&dn),
        );
        // types: 1-byte length + 2; sigalgs: 2-byte length + 4; CAs: 2 + (2 + 2).
        assert_eq!(
            enc.bytes,
            vec![
                2, 1, 64, 0, 4, 0x04, 0x03, 0x08, 0x04, 0, 4, 0, 2, 0x30, 0x00
            ]
        );
        assert_eq!(enc.fields["certificate_types"], 0..3);
        assert_eq!(enc.fields["signature_algorithms"], 3..9);
        assert_eq!(enc.fields["certificate_authorities"], 9..15);
        let cr = decode_certificate_request_12_body(&enc.bytes).unwrap();
        assert_eq!(cr.certificate_types, vec![1, 64]);
        assert_eq!(cr.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(cr.certificate_authorities, vec![dn]);
        // The deliberate violations encode (empty lists) and a truncated body fails.
        let empty = encode_certificate_request_12_body_mapped(&[], &[], &[]);
        assert_eq!(empty.bytes, vec![0, 0, 0, 0, 0]);
        assert!(decode_certificate_request_12_body(&enc.bytes[..enc.bytes.len() - 1]).is_err());
    }
}

// ============================================================
//   T6: heartbeat (RFC 6520), CertificateStatus (RFC 6066 8),
//   client-side CompressedCertificate (RFC 8879), SSLv2-format
//   CLIENT-HELLO (RFC 5246 E.2)
// ============================================================

/// RFC 6520 5: the heartbeat record content type.
pub const CONTENT_TYPE_HEARTBEAT: u8 = 24;
pub const HEARTBEAT_REQUEST: u8 = 1;
pub const HEARTBEAT_RESPONSE: u8 = 2;
/// RFC 6520 4: a HeartbeatMessage carries at least 16 bytes of padding.
pub const HEARTBEAT_MIN_PADDING: usize = 16;
/// RFC 6066 8: the CertificateStatus handshake type and the ocsp status_type.
pub const HS_CERTIFICATE_STATUS: u8 = 22;
pub const CERT_STATUS_TYPE_OCSP: u8 = 1;

/// A decoded HeartbeatMessage (RFC 6520 4).
pub struct Heartbeat {
    pub msg_type: u8,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

/// Encode a HeartbeatMessage: `type(1) payload_length(2) payload padding`,
/// with `padding_len` zero bytes of padding (RFC 6520 4: at least 16; the
/// receiver discards a message whose padding is shorter) and, when given,
/// a LYING payload_length field (the heartbleed shape, CVE-2014-0160).
/// Fields: `type`, `payload_length`, `payload`, `padding`.
pub fn encode_heartbeat_mapped(
    msg_type: u8,
    payload: &[u8],
    padding_len: usize,
    payload_length_field: Option<u16>,
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("type");
    w.u8(msg_type);
    w.mark_end("type");
    w.mark("payload_length");
    w.u16(payload_length_field.unwrap_or(payload.len() as u16));
    w.mark_end("payload_length");
    w.mark("payload");
    w.bytes(payload);
    w.mark_end("payload");
    w.mark("padding");
    w.bytes(&vec![0u8; padding_len]);
    w.mark_end("padding");
    w.into_encoded_body()
}

/// Decode a HeartbeatMessage. RFC 6520 4: "If the payload_length of a received
/// HeartbeatMessage is too large, the received HeartbeatMessage MUST be
/// discarded silently" -- here that is `BadLengthPrefix`, as is padding
/// shorter than 16 bytes.
pub fn decode_heartbeat(body: &[u8]) -> Result<Heartbeat, CodecError> {
    let mut c = ByteCursor::new(body);
    let msg_type = c.u8()?;
    let payload_length = c.u16()? as usize;
    if payload_length + HEARTBEAT_MIN_PADDING > c.remaining() {
        return Err(CodecError::BadLengthPrefix);
    }
    let payload = c.take(payload_length)?.to_vec();
    let padding = c.remaining_slice().to_vec();
    Ok(Heartbeat {
        msg_type,
        payload,
        padding,
    })
}

/// A decoded CertificateStatus (RFC 6066 8): `status_type(1)` and, for ocsp,
/// an `OCSPResponse` in a u24-length vector.
pub struct CertificateStatus {
    pub status_type: u8,
    pub response: Vec<u8>,
}

pub fn decode_certificate_status_body(body: &[u8]) -> Result<CertificateStatus, CodecError> {
    let mut c = ByteCursor::new(body);
    let status_type = c.u8()?;
    let response = c.u24_vec()?.to_vec();
    c.expect_empty()?;
    Ok(CertificateStatus {
        status_type,
        response,
    })
}

/// Encode a CertificateStatus body (plzn's TLS 1.2 server, `send
/// CertificateStatus`): `status_type(1) response<1..2^24-1>`. Fields:
/// `status_type`, `response`.
pub fn encode_certificate_status_body_mapped(status_type: u8, response: &[u8]) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("status_type");
    w.u8(status_type);
    w.mark_end("status_type");
    w.mark("response");
    w.mark("response_length");
    w.u24(response.len() as u32);
    w.mark_end("response_length");
    w.bytes(response);
    w.mark_end("response");
    w.into_encoded_body()
}

/// Whether `der` is a well-formed, successful OCSPResponse (RFC 6960 4.2.1):
/// `SEQUENCE { responseStatus ENUMERATED successful(0), responseBytes [0]
/// EXPLICIT SEQUENCE { responseType OID id-pkix-ocsp-basic, response OCTET
/// STRING } }`. A syntactic check of the outer shape, not a validation of
/// the response's signature or the certificate it speaks for.
pub fn ocsp_response_is_successful(der: &[u8]) -> bool {
    fn tlv(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
        if b.len() < 2 || b[0] != tag {
            return None;
        }
        let (len, hdr) = if b[1] < 0x80 {
            (b[1] as usize, 2)
        } else {
            let n = (b[1] & 0x7f) as usize;
            if n == 0 || n > 3 || b.len() < 2 + n {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | b[2 + i] as usize;
            }
            (len, 2 + n)
        };
        if b.len() < hdr + len {
            return None;
        }
        Some((&b[hdr..hdr + len], &b[hdr + len..]))
    }
    let Some((outer, rest)) = tlv(der, 0x30) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Some((status, rest)) = tlv(outer, 0x0a) else {
        return false;
    };
    if status != [0] {
        return false;
    }
    let Some((response_bytes, rest)) = tlv(rest, 0xa0) else {
        return false;
    };
    if !rest.is_empty() {
        return false;
    }
    let Some((inner, _)) = tlv(response_bytes, 0x30) else {
        return false;
    };
    let Some((oid, rest)) = tlv(inner, 0x06) else {
        return false;
    };
    // id-pkix-ocsp-basic = 1.3.6.1.5.5.7.48.1.1
    if oid != [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01] {
        return false;
    }
    matches!(tlv(rest, 0x04), Some((basic, _)) if !basic.is_empty())
}

/// Build a CompressedCertificate body (RFC 8879 4) from already-compressed
/// bytes, with the algorithm label and the uncompressed_length field given
/// explicitly (both may lie). Fields: `algorithm`, `uncompressed_length`,
/// `compressed_certificate_message`.
pub fn encode_compressed_certificate_13_mapped(
    algorithm: u16,
    uncompressed_length: u32,
    compressed: &[u8],
) -> EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("algorithm");
    w.u16(algorithm);
    w.mark_end("algorithm");
    w.mark("uncompressed_length");
    w.u24(uncompressed_length & 0x00ff_ffff);
    w.mark_end("uncompressed_length");
    w.mark("compressed_certificate_message");
    w.u24_vec(compressed);
    w.mark_end("compressed_certificate_message");
    w.into_encoded_body()
}

/// The algorithm label of a received CompressedCertificate (its first field),
/// for the `recv CompressedCertificate { algorithm }` matcher.
pub fn compressed_certificate_algorithm(body: &[u8]) -> Result<u16, CodecError> {
    ByteCursor::new(body).u16()
}

/// zlib-compress `data` (RFC 8879 3, RFC 1950).
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("zlib write to Vec");
    enc.finish().expect("zlib finish to Vec")
}

/// A zlib stream that inflates to `mib` MiB of zeros (a decompression bomb),
/// produced in 1 MiB slices so the plaintext never exists in memory at once.
pub fn zlib_bomb(mib: u32) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let slice = vec![0u8; 1 << 20];
    for _ in 0..mib {
        enc.write_all(&slice).expect("zlib write to Vec");
    }
    enc.finish().expect("zlib finish to Vec")
}

/// An SSLv2-format CLIENT-HELLO negotiating TLS (RFC 5246 E.2 / RFC 6101
/// E.2), as a complete SSLv2 record: `0x80 | len_hi, len_lo` then
/// `msg_type(1)=1 version(2) cipher_spec_length(2) session_id_length(2)=0
/// challenge_length(2)=32 cipher_specs(3 each: 0x00 || suite) challenge(32)`.
/// Returns `(record, body)`; the body (everything after the 2-byte header)
/// is what the handshake hash covers, and the challenge is the client
/// random (RFC 5246 E.2: left-padded with zeros to 32 bytes -- here exactly
/// 32, so it IS the random).
///
/// `cipher_specs` is the CIPHER-SPECS list already framed as 3-byte specs
/// (`sslv2_cipher_specs` builds it from TLS suite ids; `cipher_specs:` bytes
/// pass genuine SSLv2 specs such as 0x010080 through).
pub fn encode_sslv2_client_hello(
    version: u16,
    cipher_specs: &[u8],
    challenge: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    let mut body = Vec::with_capacity(9 + cipher_specs.len() + 32);
    body.push(1);
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&(cipher_specs.len() as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(cipher_specs);
    body.extend_from_slice(challenge);
    let len = body.len();
    let mut record = Vec::with_capacity(2 + len);
    record.push(0x80 | ((len >> 8) as u8 & 0x7f));
    record.push((len & 0xff) as u8);
    record.extend_from_slice(&body);
    (record, body)
}

/// TLS suite ids as SSLv2 CIPHER-SPECs (`0x00 || suite`, RFC 5246 E.2).
pub fn sslv2_cipher_specs(cipher_suites: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * cipher_suites.len());
    for cs in cipher_suites {
        out.push(0);
        out.extend_from_slice(&cs.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod t6_tests {
    use super::*;

    #[test]
    fn heartbeat_round_trip_and_heartbleed_shape() {
        let enc = encode_heartbeat_mapped(HEARTBEAT_REQUEST, b"hb", 16, None);
        assert_eq!(&enc.bytes[..5], &[1, 0, 2, b'h', b'b']);
        assert_eq!(enc.bytes.len(), 3 + 2 + 16);
        assert_eq!(enc.fields["payload_length"], 1..3);
        let hb = decode_heartbeat(&enc.bytes).unwrap();
        assert_eq!(hb.msg_type, 1);
        assert_eq!(hb.payload, b"hb");
        assert_eq!(hb.padding.len(), 16);
        // The lying length (heartbleed) is rejected by the decoder.
        let lie = encode_heartbeat_mapped(HEARTBEAT_REQUEST, b"hb", 16, Some(0x4000));
        assert!(decode_heartbeat(&lie.bytes).is_err());
        // Too little padding is rejected too (RFC 6520 4).
        let short = encode_heartbeat_mapped(HEARTBEAT_REQUEST, b"hb", 15, None);
        assert!(decode_heartbeat(&short.bytes).is_err());
    }

    #[test]
    fn certificate_status_and_ocsp_shape() {
        let enc = encode_certificate_status_body_mapped(
            CERT_STATUS_TYPE_OCSP,
            &[0x30, 0x03, 0x0a, 0x01, 0x03],
        );
        let cs = decode_certificate_status_body(&enc.bytes).unwrap();
        assert_eq!(cs.status_type, 1);
        assert_eq!(cs.response.len(), 5);
        // An unsigned `tryLater` response is well-formed, but not successful.
        assert!(!ocsp_response_is_successful(&cs.response));
        // A minimal successful shell: status 0, responseBytes with the basic OID.
        let basic = [0x04, 0x01, 0xaa];
        let mut inner = vec![
            0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
        ];
        inner.extend_from_slice(&basic);
        let mut rb = vec![0x30, inner.len() as u8];
        rb.extend_from_slice(&inner);
        let mut a0 = vec![0xa0, rb.len() as u8];
        a0.extend_from_slice(&rb);
        let mut body = vec![0x0a, 0x01, 0x00];
        body.extend_from_slice(&a0);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        assert!(ocsp_response_is_successful(&der));
    }

    #[test]
    fn compressed_certificate_round_trips_through_the_decoder() {
        let cert_body = encode_certificate_13_body(&[]);
        let z = zlib_compress(&cert_body);
        let enc = encode_compressed_certificate_13_mapped(
            CERT_COMPRESSION_ZLIB,
            cert_body.len() as u32,
            &z,
        );
        assert_eq!(compressed_certificate_algorithm(&enc.bytes).unwrap(), 1);
        assert_eq!(decompress_certificate_13(&enc.bytes).unwrap(), cert_body);
        let lie = encode_compressed_certificate_13_mapped(CERT_COMPRESSION_ZLIB, 10, &z);
        assert!(decompress_certificate_13(&lie.bytes).is_err());
        assert!(zlib_bomb(1).len() < 4096);
    }

    #[test]
    fn sslv2_client_hello_framing() {
        let (rec, body) =
            encode_sslv2_client_hello(0x0303, &sslv2_cipher_specs(&[0x002f, 0x00ff]), &[7u8; 32]);
        assert_eq!(rec.len(), 2 + body.len());
        assert_eq!(rec[0] & 0x80, 0x80);
        assert_eq!(
            ((rec[0] & 0x7f) as usize) << 8 | rec[1] as usize,
            body.len()
        );
        assert_eq!(&body[..9], &[1, 3, 3, 0, 6, 0, 0, 0, 32]);
        assert_eq!(&body[9..15], &[0, 0, 0x2f, 0, 0, 0xff]);
    }
}
