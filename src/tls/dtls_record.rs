// DTLS 1.2 record and handshake framing (RFC 6347).
//
// This is the foundational codec brick of plzn's DTLS support: it encodes and
// decodes the DTLS record header (which, unlike TLS, carries an explicit epoch
// and 48-bit sequence number) and the DTLS handshake message header (which adds
// message_seq, fragment_offset, and fragment_length for reassembly). It is
// self-contained and independently unit-tested; the DTLS driver/record-layer
// that consumes it is a separate, larger piece (see notes/audit/coverage_matrix.md).
//
// Byte layouts (RFC 6347 4.1, 4.2.2):
//
//   DTLSPlaintext / DTLSCiphertext record header (13 bytes):
//     ContentType type;              // 1
//     ProtocolVersion version;       // 2  (DTLS 1.2 = { 254, 253 } = 0xFEFD)
//     uint16 epoch;                  // 2
//     uint48 sequence_number;        // 6
//     uint16 length;                 // 2
//     opaque fragment[length];
//
//   Handshake header (12 bytes):
//     HandshakeType msg_type;        // 1
//     uint24 length;                 // 3  (total message length)
//     uint16 message_seq;            // 2
//     uint24 fragment_offset;        // 3
//     uint24 fragment_length;        // 3
//     opaque fragment[fragment_length];

/// DTLS 1.2 wire version: { 254, 253 }.
pub const DTLS_V12_WIRE: [u8; 2] = [0xFE, 0xFD];

pub const DTLS_RECORD_HEADER_LEN: usize = 13;
pub const DTLS_HANDSHAKE_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsError {
    Short,
    BadLength,
}

/// A parsed DTLS record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsRecordHeader {
    pub content_type: u8,
    pub version: [u8; 2],
    pub epoch: u16,
    /// 48-bit record sequence number (low 48 bits significant).
    pub sequence_number: u64,
    pub length: u16,
}

impl DtlsRecordHeader {
    pub fn new(content_type: u8, epoch: u16, sequence_number: u64, length: u16) -> Self {
        DtlsRecordHeader {
            content_type,
            version: DTLS_V12_WIRE,
            epoch,
            sequence_number: sequence_number & 0x0000_FFFF_FFFF_FFFF,
            length,
        }
    }

    /// The combined 64-bit (epoch << 48 | seq) value used as the AEAD record
    /// sequence in DTLS 1.2, matching the shim/BoGo convention.
    pub fn combined_seq(&self) -> u64 {
        ((self.epoch as u64) << 48) | (self.sequence_number & 0x0000_FFFF_FFFF_FFFF)
    }

    pub fn encode(&self) -> [u8; DTLS_RECORD_HEADER_LEN] {
        let mut out = [0u8; DTLS_RECORD_HEADER_LEN];
        out[0] = self.content_type;
        out[1] = self.version[0];
        out[2] = self.version[1];
        out[3..5].copy_from_slice(&self.epoch.to_be_bytes());
        // 48-bit sequence number, big-endian.
        let seq = self.sequence_number & 0x0000_FFFF_FFFF_FFFF;
        out[5] = (seq >> 40) as u8;
        out[6] = (seq >> 32) as u8;
        out[7] = (seq >> 24) as u8;
        out[8] = (seq >> 16) as u8;
        out[9] = (seq >> 8) as u8;
        out[10] = seq as u8;
        out[11..13].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    /// Parse a record header from the front of `buf`. Does not consume the body.
    pub fn parse(buf: &[u8]) -> Result<DtlsRecordHeader, DtlsError> {
        if buf.len() < DTLS_RECORD_HEADER_LEN {
            return Err(DtlsError::Short);
        }
        let epoch = u16::from_be_bytes([buf[3], buf[4]]);
        let seq = ((buf[5] as u64) << 40)
            | ((buf[6] as u64) << 32)
            | ((buf[7] as u64) << 24)
            | ((buf[8] as u64) << 16)
            | ((buf[9] as u64) << 8)
            | (buf[10] as u64);
        let length = u16::from_be_bytes([buf[11], buf[12]]);
        Ok(DtlsRecordHeader {
            content_type: buf[0],
            version: [buf[1], buf[2]],
            epoch,
            sequence_number: seq,
            length,
        })
    }
}

/// Frame a full DTLS record: header + fragment. `fragment.len()` sets `length`.
pub fn encode_record(
    content_type: u8,
    epoch: u16,
    sequence_number: u64,
    fragment: &[u8],
) -> Vec<u8> {
    let hdr = DtlsRecordHeader::new(content_type, epoch, sequence_number, fragment.len() as u16);
    let mut out = Vec::with_capacity(DTLS_RECORD_HEADER_LEN + fragment.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(fragment);
    out
}

/// Split the first DTLS record out of `buf`, returning (header, fragment,
/// total_consumed). Multiple records may be packed in one datagram.
pub fn parse_record(buf: &[u8]) -> Result<(DtlsRecordHeader, &[u8], usize), DtlsError> {
    let hdr = DtlsRecordHeader::parse(buf)?;
    let body_start = DTLS_RECORD_HEADER_LEN;
    let body_end = body_start + hdr.length as usize;
    if buf.len() < body_end {
        return Err(DtlsError::Short);
    }
    Ok((hdr, &buf[body_start..body_end], body_end))
}

/// A parsed DTLS handshake message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtlsHandshakeHeader {
    pub msg_type: u8,
    pub length: u32, // 24-bit total message length
    pub message_seq: u16,
    pub fragment_offset: u32, // 24-bit
    pub fragment_length: u32, // 24-bit
}

impl DtlsHandshakeHeader {
    /// An unfragmented message: fragment_offset=0, fragment_length=length.
    pub fn whole(msg_type: u8, message_seq: u16, length: u32) -> Self {
        DtlsHandshakeHeader {
            msg_type,
            length,
            message_seq,
            fragment_offset: 0,
            fragment_length: length,
        }
    }

    pub fn encode(&self) -> [u8; DTLS_HANDSHAKE_HEADER_LEN] {
        let mut out = [0u8; DTLS_HANDSHAKE_HEADER_LEN];
        out[0] = self.msg_type;
        put_u24(&mut out[1..4], self.length);
        out[4..6].copy_from_slice(&self.message_seq.to_be_bytes());
        put_u24(&mut out[6..9], self.fragment_offset);
        put_u24(&mut out[9..12], self.fragment_length);
        out
    }

    pub fn parse(buf: &[u8]) -> Result<DtlsHandshakeHeader, DtlsError> {
        if buf.len() < DTLS_HANDSHAKE_HEADER_LEN {
            return Err(DtlsError::Short);
        }
        Ok(DtlsHandshakeHeader {
            msg_type: buf[0],
            length: get_u24(&buf[1..4]),
            message_seq: u16::from_be_bytes([buf[4], buf[5]]),
            fragment_offset: get_u24(&buf[6..9]),
            fragment_length: get_u24(&buf[9..12]),
        })
    }
}

// ============================================================
//                    DTLS 1.2 record protection
// ============================================================
//
// DTLS 1.2 reuses the TLS 1.2 record protection (RFC 6347 4.1.2 defers to RFC
// 5246 / 5288 / 6655 / 7366 / 7905) with the record's explicit
// (epoch << 48 | sequence_number) standing in for the TLS counter in the nonce,
// the AEAD additional data and the CBC / NULL MAC input, and the DTLS wire
// version in place of 0x0303. The families live in `tls::record`; these are the
// DTLS entry points, parametrized by epoch and sequence instead of a counter.

use crate::tls::record::{DirectionKeys, RecordCtx, RecordError};

/// Combined 64-bit record sequence used by DTLS record protection: epoch in the
/// high 16 bits.
pub fn combined_seq(epoch: u16, sequence_number: u64) -> u64 {
    ((epoch as u64) << 48) | (sequence_number & 0x0000_FFFF_FFFF_FFFF)
}

/// The record context for one DTLS record.
pub fn dtls_ctx(epoch: u16, sequence_number: u64) -> RecordCtx {
    RecordCtx {
        seq: combined_seq(epoch, sequence_number),
        version: DTLS_V12_WIRE,
    }
}

/// Seal a DTLS 1.2 record fragment under one direction's keys (any TLS 1.2
/// record family). For explicit-nonce AEADs the body starts with the 8-byte
/// epoch||sequence nonce, exactly as in TLS 1.2 GCM.
pub fn dtls12_seal(
    keys: &DirectionKeys,
    content_type: u8,
    epoch: u16,
    sequence_number: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    keys.seal_with(
        dtls_ctx(epoch, sequence_number),
        content_type,
        plaintext,
        &[],
    )
}

/// `dtls12_seal` with the in-family `record.*` mutations applied (`record.mac`
/// for CBC / NULL). Tag-level mutations (`record.aead_tag`) act on the framed
/// record: see `apply_dtls_record_mutations`.
pub fn dtls12_seal_with_mutations(
    keys: &DirectionKeys,
    content_type: u8,
    epoch: u16,
    sequence_number: u64,
    plaintext: &[u8],
    mutations: &[crate::ir::Mutation],
) -> Result<Vec<u8>, RecordError> {
    keys.seal_with(
        dtls_ctx(epoch, sequence_number),
        content_type,
        plaintext,
        mutations,
    )
}

/// Post-seal `record.*` mutations on a framed DTLS record (13-byte header +
/// body): `record.aead_tag` (the trailing tag), `record.content_type` (byte 0
/// of either header). `plaintext_len` is the payload length before sealing.
pub fn apply_dtls_record_mutations(
    record: &mut [u8],
    plaintext_len: usize,
    keys: &DirectionKeys,
    mutations: &[crate::ir::Mutation],
) -> Result<(), RecordError> {
    crate::tls::mutate::apply_record_mutations(
        record,
        DTLS_RECORD_HEADER_LEN,
        plaintext_len,
        false,
        keys.aead_tag_len(),
        mutations,
    )
    .map_err(|_| RecordError::Codec(crate::tls::codec::CodecError::TrailingBytes))
}

/// Open a DTLS 1.2 record fragment produced by `dtls12_seal`. `epoch` and
/// `sequence_number` come from the record header (they must match the explicit
/// nonce carried in an AEAD body, which is how the peer bound them).
pub fn dtls12_open(
    keys: &DirectionKeys,
    content_type: u8,
    epoch: u16,
    sequence_number: u64,
    body: &[u8],
) -> Result<Vec<u8>, RecordError> {
    if body.len() > (1 << 14) + 2048 {
        return Err(RecordError::RecordTooLarge(body.len()));
    }
    let plaintext = keys.open_with(dtls_ctx(epoch, sequence_number), content_type, body)?;
    if plaintext.len() > 1 << 14 {
        return Err(RecordError::RecordTooLarge(plaintext.len()));
    }
    Ok(plaintext)
}

fn put_u24(out: &mut [u8], v: u32) {
    out[0] = (v >> 16) as u8;
    out[1] = (v >> 8) as u8;
    out[2] = v as u8;
}

fn get_u24(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_header_round_trip() {
        let hdr = DtlsRecordHeader::new(23, 1, 0x0000_0102_0304_0506, 42);
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), DTLS_RECORD_HEADER_LEN);
        assert_eq!(bytes[0], 23);
        assert_eq!(&bytes[1..3], &DTLS_V12_WIRE);
        let parsed = DtlsRecordHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn sequence_is_48_bit_be() {
        let hdr = DtlsRecordHeader::new(22, 0, 0x0000_FFFF_FFFF_FFFF, 0);
        let bytes = hdr.encode();
        assert_eq!(&bytes[5..11], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // A value exceeding 48 bits is masked, not overflowed into the length.
        let hdr2 = DtlsRecordHeader::new(22, 0, 0xFFFF_FFFF_FFFF_FFFF, 7);
        let b2 = hdr2.encode();
        assert_eq!(&b2[5..11], &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(u16::from_be_bytes([b2[11], b2[12]]), 7);
    }

    #[test]
    fn combined_seq_packs_epoch() {
        let hdr = DtlsRecordHeader::new(22, 3, 0x0102_0304_0506, 0);
        assert_eq!(hdr.combined_seq(), (3u64 << 48) | 0x0102_0304_0506);
    }

    #[test]
    fn record_frame_and_parse() {
        let frag = [0xAA, 0xBB, 0xCC];
        let rec = encode_record(22, 0, 5, &frag);
        assert_eq!(rec.len(), DTLS_RECORD_HEADER_LEN + 3);
        let (hdr, body, consumed) = parse_record(&rec).unwrap();
        assert_eq!(hdr.content_type, 22);
        assert_eq!(hdr.sequence_number, 5);
        assert_eq!(body, &frag);
        assert_eq!(consumed, rec.len());
    }

    #[test]
    fn packed_records_parse_sequentially() {
        let mut datagram = encode_record(22, 0, 0, &[0x01]);
        datagram.extend_from_slice(&encode_record(22, 0, 1, &[0x02, 0x03]));
        let (h1, b1, c1) = parse_record(&datagram).unwrap();
        assert_eq!(h1.sequence_number, 0);
        assert_eq!(b1, &[0x01]);
        let (h2, b2, c2) = parse_record(&datagram[c1..]).unwrap();
        assert_eq!(h2.sequence_number, 1);
        assert_eq!(b2, &[0x02, 0x03]);
        assert_eq!(c1 + c2, datagram.len());
    }

    #[test]
    fn short_record_is_detected() {
        assert_eq!(DtlsRecordHeader::parse(&[0u8; 5]), Err(DtlsError::Short));
        // Header present but body truncated.
        let rec = encode_record(22, 0, 0, &[1, 2, 3, 4]);
        assert_eq!(
            parse_record(&rec[..DTLS_RECORD_HEADER_LEN + 2]),
            Err(DtlsError::Short)
        );
    }

    #[test]
    fn handshake_header_round_trip() {
        let hh = DtlsHandshakeHeader {
            msg_type: 1,
            length: 0x0100,
            message_seq: 7,
            fragment_offset: 0x20,
            fragment_length: 0x40,
        };
        let bytes = hh.encode();
        assert_eq!(bytes.len(), DTLS_HANDSHAKE_HEADER_LEN);
        assert_eq!(DtlsHandshakeHeader::parse(&bytes).unwrap(), hh);
    }

    fn direction_keys(suite: u16, etm: bool) -> (DirectionKeys, DirectionKeys) {
        let s = crate::ir::suite_info(suite).expect("suite in catalogue");
        crate::tls::handshake::tls12_direction_keys(s, &[0x5a; 48], &[0x11; 32], &[0x22; 32], etm)
            .expect("keys")
    }

    #[test]
    fn dtls12_aead_round_trip() {
        use crate::tls::crypto::{AeadAlg, AeadKey};
        let key = AeadKey::new(AeadAlg::Aes128Gcm, &[0x11u8; 16]).unwrap();
        let keys = DirectionKeys::new_tls12(key, [0xAA, 0xBB, 0xCC, 0xDD]);
        let pt = b"application data over dtls";
        let body = dtls12_seal(&keys, 23, 1, 7, pt).unwrap();
        // explicit nonce prefix carries epoch+seq.
        assert_eq!(&body[0..8], &combined_seq(1, 7).to_be_bytes());
        let recovered = dtls12_open(&keys, 23, 1, 7, &body).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn dtls12_aead_rejects_tamper() {
        use crate::tls::crypto::{AeadAlg, AeadKey};
        let key = AeadKey::new(AeadAlg::Aes128Gcm, &[0x22u8; 16]).unwrap();
        let keys = DirectionKeys::new_tls12(key, [0; 4]);
        let mut body = dtls12_seal(&keys, 22, 0, 3, b"handshake").unwrap();
        // Flip a ciphertext byte -> AEAD open must fail.
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert!(dtls12_open(&keys, 22, 0, 3, &body).is_err());
    }

    #[test]
    fn dtls12_aead_rejects_wrong_seq() {
        use crate::tls::crypto::{AeadAlg, AeadKey};
        let key = AeadKey::new(AeadAlg::Aes128Gcm, &[0x33u8; 16]).unwrap();
        let keys = DirectionKeys::new_tls12(key, [1, 2, 3, 4]);
        let body = dtls12_seal(&keys, 23, 2, 10, b"x").unwrap();
        // Opening under a different epoch changes the AAD -> tag mismatch.
        assert!(dtls12_open(&keys, 23, 3, 10, &body).is_err());
    }

    /// Every record family plzn implements, over DTLS: seal under epoch||seq,
    /// open with the same context, and reject a flipped trailing byte, a wrong
    /// epoch and a wrong sequence (all three change the AAD / MAC input).
    #[test]
    fn every_family_round_trips_under_epoch_and_sequence() {
        for (suite, etm) in [
            (0xc02b, false), // AES-128-GCM
            (0xc02c, false), // AES-256-GCM-SHA384
            (0xc0ac, false), // AES-128-CCM
            (0xc0ae, false), // AES-128-CCM_8
            (0xc05c, false), // ARIA-128-GCM
            (0xc087, false), // Camellia-256-GCM
            (0xcca9, false), // ChaCha20-Poly1305 (implicit nonce)
            (0xc009, false), // AES-128-CBC-SHA, MAC-then-encrypt
            (0xc009, true),  // ... encrypt-then-MAC
            (0xc024, false), // AES-256-CBC-SHA384
            (0xc024, true),
            (0xc008, false), // 3DES
            (0xc006, false), // NULL-SHA
            (0x00b1, false), // PSK NULL-SHA384
        ] {
            let (w, _) = direction_keys(suite, etm);
            let pt = b"datagram payload";
            let body = dtls12_seal(&w, 23, 1, 0x0001_0203_0405, pt).unwrap();
            assert_eq!(
                dtls12_open(&w, 23, 1, 0x0001_0203_0405, &body).unwrap(),
                pt,
                "suite {:04x}",
                suite
            );
            let mut bad = body.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(
                dtls12_open(&w, 23, 1, 0x0001_0203_0405, &bad).is_err(),
                "suite {:04x} accepted a flipped byte",
                suite
            );
            assert!(
                dtls12_open(&w, 23, 2, 0x0001_0203_0405, &body).is_err(),
                "suite {:04x} ignored the epoch",
                suite
            );
            assert!(
                dtls12_open(&w, 23, 1, 0x0001_0203_0406, &body).is_err(),
                "suite {:04x} ignored the sequence",
                suite
            );
            // The same keys protect TLS records under a different context: the
            // DTLS output is not accepted as a TLS record with the same counter.
            assert!(
                w.open_with(RecordCtx::tls(combined_seq(1, 0x0001_0203_0405)), 23, &body)
                    .is_err()
            );
        }
    }

    #[test]
    fn record_mutations_reach_the_dtls_tag_and_mac() {
        use crate::ir::{Mutation, MutationOp, ResolvedByteTarget};
        let flip = |field: &str| Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["record".into(), field.into()]),
                    index: 0,
                    end: None,
                },
                value: 0x01,
            },
            span: crate::ast::Span::dummy(),
        };
        // AEAD: the tag is mutated on the framed record, after sealing.
        let (w, _) = direction_keys(0xc02b, false);
        let body = dtls12_seal(&w, 23, 1, 5, b"abc").unwrap();
        let mut record = encode_record(23, 1, 5, &body);
        let clean = record.clone();
        apply_dtls_record_mutations(&mut record, 3, &w, &[flip("aead_tag")]).unwrap();
        assert_ne!(clean, record);
        assert!(dtls12_open(&w, 23, 1, 5, &record[DTLS_RECORD_HEADER_LEN..]).is_err());
        // NULL / CBC: the MAC is mutated inside the family, before framing.
        let (w, _) = direction_keys(0xc006, false);
        let macd = dtls12_seal_with_mutations(&w, 23, 1, 5, b"abc", &[flip("mac")]).unwrap();
        assert!(dtls12_open(&w, 23, 1, 5, &macd).is_err());
        let (w, _) = direction_keys(0xc009, true);
        let macd = dtls12_seal_with_mutations(&w, 23, 1, 5, b"abc", &[flip("mac")]).unwrap();
        assert!(dtls12_open(&w, 23, 1, 5, &macd).is_err());
    }

    #[test]
    fn encrypted_record_mutation_starts_after_the_dtls_header() {
        use crate::ir::{Mutation, MutationOp, ResolvedByteTarget};
        let mutation = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["record".into(), "encrypted_record".into()]),
                    index: 0,
                    end: None,
                },
                value: 0xff,
            },
            span: crate::ast::Span::dummy(),
        };
        let (keys, _) = direction_keys(0xc02b, false);
        let sealed = dtls12_seal(&keys, 23, 7, 9, b"payload").unwrap();
        let mut record = encode_record(23, 7, 9, &sealed);
        let clean = record.clone();
        apply_dtls_record_mutations(&mut record, 7, &keys, &[mutation]).unwrap();

        assert_eq!(
            &record[..DTLS_RECORD_HEADER_LEN],
            &clean[..DTLS_RECORD_HEADER_LEN],
            "record.encrypted_record must not corrupt the DTLS epoch/sequence/length header",
        );
        assert_eq!(
            record[DTLS_RECORD_HEADER_LEN],
            clean[DTLS_RECORD_HEADER_LEN] ^ 0xff,
        );
        assert_eq!(
            &record[DTLS_RECORD_HEADER_LEN + 1..],
            &clean[DTLS_RECORD_HEADER_LEN + 1..],
        );
    }

    #[test]
    fn handshake_whole_sets_fragment_to_full() {
        let hh = DtlsHandshakeHeader::whole(1, 0, 300);
        assert_eq!(hh.fragment_offset, 0);
        assert_eq!(hh.fragment_length, 300);
        assert_eq!(hh.length, 300);
        // 24-bit fields survive a value above 16 bits.
        let bytes = hh.encode();
        assert_eq!(get_u24(&bytes[1..4]), 300);
        assert_eq!(get_u24(&bytes[9..12]), 300);
    }
}
