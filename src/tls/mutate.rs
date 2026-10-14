// Byte-level mutation application.
//
// Two entry points, corresponding to the two pipeline phases where
// mutations fire:
//
//   `apply_handshake_mutations` — runs on the encoded handshake
//       body *before* the handshake header is prepended and *before*
//       the record layer seals it. Targets: bare offsets, `handshake.X`
//       field paths.
//
//   `apply_record_mutations` — runs on the complete record wire
//       bytes *after* the record header is prepended and *after*
//       AEAD sealing. Targets: `record.X` field paths.
//
// Both accept a slice of `ir::Mutation`s and modify the bytes in
// place. Negative indices are from the end of the relevant region.

use crate::ir::{Mutation, MutationOp, ResolvedByteTarget};
use crate::tls::codec::EncodedBody;
use std::ops::Range;

#[derive(Debug)]
pub enum MutateError {
    IndexOutOfRange {
        path: String,
        index: i64,
        region_len: usize,
    },
    UnknownField {
        path: String,
    },
    RecordMutationOnHandshake {
        path: String,
    },
    HandshakeMutationOnRecord {
        path: String,
    },
    LengthAdjustmentOutOfRange {
        path: String,
        value: u64,
        delta: i64,
        width: usize,
    },
}

impl std::fmt::Display for MutateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MutateError::IndexOutOfRange {
                path,
                index,
                region_len,
            } => write!(
                f,
                "byte index {} is out of range for {} (region is {} bytes)",
                index, path, region_len
            ),
            MutateError::UnknownField { path } => {
                write!(f, "no field map entry for `{}`", path)
            }
            MutateError::RecordMutationOnHandshake { path } => write!(
                f,
                "`{}` is a record-layer target and cannot be applied at the \
                 handshake body stage; it will be applied post-seal",
                path
            ),
            MutateError::HandshakeMutationOnRecord { path } => write!(
                f,
                "`{}` is a handshake-body target but was routed to the \
                 record-layer stage (driver bug)",
                path
            ),
            MutateError::LengthAdjustmentOutOfRange {
                path,
                value,
                delta,
                width,
            } => write!(
                f,
                "adjusting {}-byte length field `{}` from {} by {:+} overflows its wire representation",
                width, path, value, delta
            ),
        }
    }
}

impl std::error::Error for MutateError {}

/// Apply mutations to an encoded handshake body. Only bare-offset
/// and `handshake.X` mutations are applied here; `record.X`
/// mutations are silently skipped (they'll fire at the record
/// layer instead).
///
/// `encoded` is the `EncodedBody` from the mapped encoder so we
/// can resolve handshake-field paths to byte ranges.
///
/// Returns the mutated bytes. The field map is used for path
/// resolution but not updated — the caller shouldn't need it
/// after this point.
pub fn apply_handshake_mutations(
    mut body: Vec<u8>,
    field_map: &EncodedBody,
    mutations: &[Mutation],
) -> Result<Vec<u8>, MutateError> {
    for m in mutations {
        match &m.op {
            MutationOp::Xor { target, value } => {
                if target.is_record_level() || is_handshake_header_target(target) {
                    continue; // record-level deferred to post-seal; header to post-frame
                }
                let region = resolve_handshake_region(&body, field_map, target)?;
                for idx in resolve_indices(target, region.len())? {
                    body[region.start + idx] ^= *value as u8;
                }
            }
            MutationOp::Set { target, value } => {
                if target.is_record_level() || is_handshake_header_target(target) {
                    continue;
                }
                let region = resolve_handshake_region(&body, field_map, target)?;
                for idx in resolve_indices(target, region.len())? {
                    body[region.start + idx] = *value as u8;
                }
            }
            MutationOp::AdjustLength { path, delta } => {
                if is_handshake_header_path(path) {
                    continue;
                }
                let region = resolve_named_handshake_region(&body, field_map, path)?;
                adjust_big_endian(&mut body[region], path, *delta)?;
            }
            MutationOp::PadPlus(n) => {
                body.extend(std::iter::repeat_n(0u8, *n));
            }
            MutationOp::PadBytes(bytes) => {
                body.extend_from_slice(bytes);
            }
            MutationOp::PadMinus(n) => {
                let new_len = body.len().saturating_sub(*n);
                body.truncate(new_len);
            }
            MutationOp::Truncate(n) => {
                body.truncate(*n);
            }
            // These operate on the framed handshake stream in the record
            // layer. They deliberately do not alter the logical transcript.
            MutationOp::TrailingBytes(_) | MutationOp::OmitPrefix(_) => {}
            // A framing directive, not a body mutation: the DTLS driver applies
            // it at fragmentation time; nothing to do to the body here.
            MutationOp::Reorder(_) => {}
            // Record-layer fragmentation: the record layer splits the framed
            // message; nothing to do to the body.
            MutationOp::Fragment { .. } => {}
            // T2: record-layer controls, applied when the record is written.
            MutationOp::RecordVersion(_)
            | MutationOp::RecordPad(_)
            | MutationOp::Dtls13ShortSequence
            | MutationOp::Dtls13OmitLength
            | MutationOp::Dtls13SetCidBit
            | MutationOp::Dtls13LegacyHeader
            | MutationOp::Plaintext
            | MutationOp::ReplacePlaintext(_)
            | MutationOp::CbcPad(_) => {}
        }
    }
    Ok(body)
}

/// True if the target names the handshake message HEADER, which is not part of
/// the encoded body -- `handshake.msg_type` (the 1-byte type) or
/// `handshake.length` (the 3-byte length). These are applied post-framing by
/// `apply_handshake_header_mutations`, so they are skipped at the body stage.
fn is_handshake_header_target(target: &ResolvedByteTarget) -> bool {
    matches!(
        &target.path,
        Some(parts) if parts.len() == 2 && parts[0] == "handshake"
            && (parts[1] == "msg_type" || parts[1] == "length")
    )
}

/// Apply `handshake.msg_type` / `handshake.length` mutations to the FRAMED
/// handshake message (`type(1) || length(3) || body`). Used to corrupt the
/// handshake header (BoGo WrongMessageType), which the body-stage mutation cannot
/// reach because the header is added by `encode_handshake` afterwards.
pub fn apply_handshake_header_mutations(framed: &mut [u8], mutations: &[Mutation]) {
    for m in mutations {
        if let MutationOp::AdjustLength { path, delta } = &m.op {
            if is_handshake_header_path(path) && framed.len() >= 4 {
                let _ = adjust_big_endian(&mut framed[1..4], path, *delta);
            }
            continue;
        }
        let (target, is_xor, value) = match &m.op {
            MutationOp::Xor { target, value } => (target, true, *value as u8),
            MutationOp::Set { target, value } => (target, false, *value as u8),
            _ => continue,
        };
        if !is_handshake_header_target(target) {
            continue;
        }
        let parts = target.path.as_ref().unwrap();
        // msg_type = byte 0; length = bytes 1..4.
        let region: std::ops::Range<usize> = if parts[1] == "msg_type" { 0..1 } else { 1..4 };
        if framed.len() < region.end {
            continue;
        }
        let Ok(idxs) = target.indices(region.len()) else {
            continue;
        };
        for idx in idxs {
            let pos = region.start + idx;
            if is_xor {
                framed[pos] ^= value;
            } else {
                framed[pos] = value;
            }
        }
    }
}

/// T2: the (one or more) positions a target names within a region.
fn resolve_indices(target: &ResolvedByteTarget, len: usize) -> Result<Vec<usize>, MutateError> {
    target
        .indices(len)
        .map_err(|_| MutateError::IndexOutOfRange {
            path: target.path_str(),
            index: target.index,
            region_len: len,
        })
}

/// T2: apply the `record.<field>` xor / set mutations that name a
/// PRE-encryption region (`record.padding`, `record.plaintext`,
/// `record.inner_type`) to `buf`, which is that region's bytes. Other targets
/// are ignored. Used by the record layer's seal functions.
pub fn apply_pre_encryption_mutations(
    buf: &mut [u8],
    field: &str,
    mutations: &[Mutation],
) -> Result<(), MutateError> {
    for m in mutations {
        let (target, is_xor, value) = match &m.op {
            MutationOp::Xor { target, value } => (target, true, *value as u8),
            MutationOp::Set { target, value } => (target, false, *value as u8),
            _ => continue,
        };
        if !target.is_record_level() || target.field_name() != Some(field) {
            continue;
        }
        for idx in resolve_indices(target, buf.len())? {
            if is_xor {
                buf[idx] ^= value;
            } else {
                buf[idx] = value;
            }
        }
    }
    Ok(())
}

/// T2: true if any mutation names this pre-encryption record region.
pub fn names_record_field(mutations: &[Mutation], field: &str) -> bool {
    mutations.iter().any(|m| match &m.op {
        MutationOp::Xor { target, .. } | MutationOp::Set { target, .. } => {
            target.is_record_level() && target.field_name() == Some(field)
        }
        _ => false,
    })
}

/// Apply mutations to the complete record wire bytes (header +
/// sealed body). Only `record.X` mutations fire here; others are
/// skipped (they already fired at the handshake-body stage).
///
/// `record_bytes` is the full wire output of `write_record`:
/// `header || sealed_body`. `record_header_len` is 5 for TLS and 13 for DTLS;
/// `plaintext_len` is the length of
/// the plaintext that was sealed (needed to compute the position
/// of the AEAD tag). `is_tls13` toggles between the two record-
/// layer framing layouts.
pub fn apply_record_mutations(
    record_bytes: &mut [u8],
    record_header_len: usize,
    plaintext_len: usize,
    is_tls13: bool,
    tag_len: usize,
    mutations: &[Mutation],
) -> Result<(), MutateError> {
    for m in mutations {
        match &m.op {
            MutationOp::Xor { target, value } => {
                if !target.is_record_level() {
                    continue; // already applied pre-seal
                }
                let region = resolve_record_region(
                    record_bytes.len(),
                    record_header_len,
                    plaintext_len,
                    is_tls13,
                    tag_len,
                    target,
                )?;
                if region.is_empty() {
                    continue; // handled elsewhere (e.g. record.mac pre-seal)
                }
                for idx in resolve_indices(target, region.len())? {
                    record_bytes[region.start + idx] ^= *value as u8;
                }
            }
            MutationOp::Set { target, value } => {
                if !target.is_record_level() {
                    continue;
                }
                let region = resolve_record_region(
                    record_bytes.len(),
                    record_header_len,
                    plaintext_len,
                    is_tls13,
                    tag_len,
                    target,
                )?;
                if region.is_empty() {
                    continue;
                }
                for idx in resolve_indices(target, region.len())? {
                    record_bytes[region.start + idx] = *value as u8;
                }
            }
            // pad / truncate don't apply to record-level targets
            _ => continue,
        }
    }
    Ok(())
}

// ---- helpers ----

fn resolve_handshake_region(
    body: &[u8],
    field_map: &EncodedBody,
    target: &ResolvedByteTarget,
) -> Result<Range<usize>, MutateError> {
    match &target.path {
        None => {
            // Bare offset: whole body is the region.
            Ok(0..body.len())
        }
        Some(parts) if parts.len() == 2 && parts[0] == "handshake" => {
            let field_name = &parts[1];
            field_map
                .field_range(field_name)
                .ok_or_else(|| MutateError::UnknownField {
                    path: parts.join("."),
                })
        }
        Some(parts) => Err(MutateError::UnknownField {
            path: parts.join("."),
        }),
    }
}

fn is_handshake_header_path(path: &[String]) -> bool {
    path.len() == 2 && path[0] == "handshake" && path[1] == "length"
}

fn resolve_named_handshake_region(
    body: &[u8],
    field_map: &EncodedBody,
    path: &[String],
) -> Result<Range<usize>, MutateError> {
    if path.len() != 2 || path[0] != "handshake" {
        return Err(MutateError::UnknownField {
            path: path.join("."),
        });
    }
    let region = field_map
        .field_range(&path[1])
        .ok_or_else(|| MutateError::UnknownField {
            path: path.join("."),
        })?;
    if region.end > body.len() {
        return Err(MutateError::UnknownField {
            path: path.join("."),
        });
    }
    Ok(region)
}

fn adjust_big_endian(bytes: &mut [u8], path: &[String], delta: i64) -> Result<(), MutateError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(MutateError::UnknownField {
            path: path.join("."),
        });
    }
    let mut value = 0u64;
    for &byte in bytes.iter() {
        value = (value << 8) | u64::from(byte);
    }
    // TLS-Anvil's `sub(1)` deliberately turns a zero-length extension into
    // 0xffff. Mirror fixed-width wire arithmetic rather than rejecting the
    // underflow; the purpose of this operator is to construct invalid input.
    let modulus = 1i128 << (bytes.len() * 8);
    let adjusted = (i128::from(value) + i128::from(delta)).rem_euclid(modulus) as u64;
    let encoded = adjusted.to_be_bytes();
    let start = encoded.len() - bytes.len();
    bytes.copy_from_slice(&encoded[start..]);
    Ok(())
}

fn resolve_record_region(
    record_len: usize,
    record_header_len: usize,
    plaintext_len: usize,
    is_tls13: bool,
    tag_len: usize,
    target: &ResolvedByteTarget,
) -> Result<Range<usize>, MutateError> {
    let field_name = target
        .field_name()
        .ok_or_else(|| MutateError::UnknownField {
            path: target.path_str(),
        })?;
    // All record-level regions are relative to the full wire record. TLS has a
    // five-byte header; DTLS has a thirteen-byte header. In particular, using
    // the TLS offset for `record.encrypted_record` on DTLS would also corrupt
    // the epoch, sequence number, and record length.
    let hdr = record_header_len;
    let dtls12_header = hdr == crate::tls::dtls_record::DTLS_RECORD_HEADER_LEN;
    match field_name {
        "content_type" => Ok(0..1),
        // Length-preserving header fields, after sealing. TLS and DTLS both
        // carry the version at offset 1..3; epoch and the 48-bit sequence
        // number exist only in the DTLS 1.2 header (RFC 6347 4.1).
        "version" => Ok(1..3),
        "epoch" if dtls12_header => Ok(3..5),
        "sequence_number" if dtls12_header => Ok(5..11),
        "aead_tag" => {
            if tag_len == 0 {
                return Err(MutateError::UnknownField {
                    path: target.path_str(),
                });
            }
            if is_tls13 {
                // TLS 1.3: sealed body is (inner_len + tag_len)
                // where inner_len = plaintext + 1 (content-type byte).
                let tag_start = hdr + (plaintext_len + 1);
                let tag_end =
                    tag_start
                        .checked_add(tag_len)
                        .ok_or_else(|| MutateError::UnknownField {
                            path: target.path_str(),
                        })?;
                if tag_end > record_len {
                    return Err(MutateError::UnknownField {
                        path: target.path_str(),
                    });
                }
                Ok(tag_start..tag_end)
            } else {
                // TLS 1.2 AEAD: the tag is the record's trailer, after the
                // explicit nonce (GCM/CCM) or directly after the ciphertext
                // (ChaCha20-Poly1305 has no explicit nonce); 16 bytes, or 8
                // for CCM_8.
                let tag_start = record_len.checked_sub(tag_len).ok_or_else(|| {
                    MutateError::IndexOutOfRange {
                        path: target.path_str(),
                        index: target.index,
                        region_len: 0,
                    }
                })?;
                Ok(tag_start..record_len)
            }
        }
        "encrypted_record" => {
            // The whole encrypted payload region after the header.
            Ok(hdr..record_len)
        }
        // "mac" is handled pre-encryption in seal_tls12_cbc, not here; the T2
        // pre-encryption regions likewise.
        "mac" | "padding" | "plaintext" | "inner_type" => Ok(0..0),
        _ => Err(MutateError::UnknownField {
            path: target.path_str(),
        }),
    }
}

/// Convert a possibly-negative byte index into an absolute
/// position within a region of `len` bytes. Negative = from end
/// (-1 = last byte). Returns an error on out-of-range.
fn resolve_index(index: i64, len: usize, path: &str) -> Result<usize, MutateError> {
    let abs = if index >= 0 {
        index as usize
    } else {
        let from_end = (-index) as usize;
        if from_end > len {
            return Err(MutateError::IndexOutOfRange {
                path: path.to_string(),
                index,
                region_len: len,
            });
        }
        len - from_end
    };
    if abs >= len {
        return Err(MutateError::IndexOutOfRange {
            path: path.to_string(),
            index,
            region_len: len,
        });
    }
    Ok(abs)
}

/// Public version of `resolve_index` for use by the record layer's
/// pre-encryption MAC mutation hook.
pub fn resolve_index_pub(index: i64, len: usize) -> Result<usize, MutateError> {
    resolve_index(index, len, "record.mac")
}

/// Every position a MAC-region target names (T2: ranges included).
pub fn resolve_target_indices_pub(
    target: &ResolvedByteTarget,
    len: usize,
) -> Result<Vec<usize>, MutateError> {
    resolve_indices(target, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Span;
    use crate::ir::{Mutation, MutationOp, ResolvedByteTarget};
    use crate::tls::codec::EncodedBody;
    use std::collections::HashMap;

    fn dummy_span() -> Span {
        Span::new(0, 0)
    }

    fn make_body(data: &[u8], fields: &[(&str, Range<usize>)]) -> EncodedBody {
        let mut map = HashMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), v.clone());
        }
        EncodedBody {
            bytes: data.to_vec(),
            fields: map,
        }
    }

    #[test]
    fn xor_bare_offset() {
        let body = vec![0x00, 0x11, 0x22, 0x33];
        let enc = make_body(&body, &[]);
        let m = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: None,
                    index: 2,
                    end: None,
                },
                value: 0xff,
            },
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[m]).unwrap();
        assert_eq!(result, vec![0x00, 0x11, 0xdd, 0x33]);
    }

    #[test]
    fn xor_negative_index() {
        let body = vec![0x00, 0x11, 0x22, 0x33];
        let enc = make_body(&body, &[]);
        let m = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: None,
                    index: -1,
                    end: None,
                },
                value: 0x01,
            },
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[m]).unwrap();
        assert_eq!(result, vec![0x00, 0x11, 0x22, 0x32]);
    }

    #[test]
    fn xor_handshake_field_path() {
        let body = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let enc = make_body(&body, &[("verify_data", 1..4)]);
        let m = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["handshake".into(), "verify_data".into()]),
                    index: 0,
                    end: None,
                },
                value: 0xff,
            },
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[m]).unwrap();
        // Only byte at field offset 0 (global offset 1) is mutated.
        assert_eq!(result, vec![0xAA, 0x44, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn pad_plus_appends_zeros() {
        let body = vec![0x01, 0x02];
        let enc = make_body(&body, &[]);
        let m = Mutation {
            op: MutationOp::PadPlus(3),
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[m]).unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn truncate_shortens() {
        let body = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let enc = make_body(&body, &[]);
        let m = Mutation {
            op: MutationOp::Truncate(2),
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[m]).unwrap();
        assert_eq!(result, vec![0x01, 0x02]);
    }

    #[test]
    fn length_adjustment_changes_the_complete_integer_only() {
        let body = vec![0xAA, 0x01, 0x00, 0xBB, 0xCC];
        let enc = make_body(&body, &[("signature_length", 1..3)]);
        let mutation = Mutation {
            op: MutationOp::AdjustLength {
                path: vec!["handshake".into(), "signature_length".into()],
                delta: -1,
            },
            span: dummy_span(),
        };
        let result = apply_handshake_mutations(body, &enc, &[mutation]).unwrap();
        assert_eq!(result, vec![0xAA, 0x00, 0xFF, 0xBB, 0xCC]);
    }

    #[test]
    fn length_adjustment_wraps_at_the_wire_width() {
        let body = vec![0x00, 0x00];
        let enc = make_body(&body, &[("extension_encrypt_then_mac_length", 0..2)]);
        let mutation = Mutation {
            op: MutationOp::AdjustLength {
                path: vec![
                    "handshake".into(),
                    "extension_encrypt_then_mac_length".into(),
                ],
                delta: -1,
            },
            span: dummy_span(),
        };
        assert_eq!(
            apply_handshake_mutations(body, &enc, &[mutation]).unwrap(),
            vec![0xFF, 0xFF]
        );
    }

    #[test]
    fn handshake_header_length_adjustment_is_post_frame() {
        let mutation = Mutation {
            op: MutationOp::AdjustLength {
                path: vec!["handshake".into(), "length".into()],
                delta: -1,
            },
            span: dummy_span(),
        };
        let mut framed = vec![1, 0, 1, 0, 0xAA];
        apply_handshake_header_mutations(&mut framed, &[mutation]);
        assert_eq!(framed, vec![1, 0, 0, 0xFF, 0xAA]);
    }

    #[test]
    fn record_level_skipped_in_handshake_phase() {
        let body = vec![0x01, 0x02, 0x03];
        let enc = make_body(&body, &[]);
        let m = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["record".into(), "aead_tag".into()]),
                    index: 0,
                    end: None,
                },
                value: 0xff,
            },
            span: dummy_span(),
        };
        // record-level mutations are silently skipped.
        let result = apply_handshake_mutations(body.clone(), &enc, &[m]).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn record_aead_tag_tls12() {
        // TLS 1.2 GCM record: header(5) + explicit_nonce(8) + ct(3) + tag(16)
        let plaintext_len = 3;
        let total = 5 + 8 + 3 + 16;
        let mut record = vec![0u8; total];
        // Put recognizable bytes in the tag.
        for i in 0..16 {
            record[5 + 8 + 3 + i] = 0xAA;
        }
        let m = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["record".into(), "aead_tag".into()]),
                    index: 0,
                    end: None,
                },
                value: 0x55,
            },
            span: dummy_span(),
        };
        apply_record_mutations(&mut record, 5, plaintext_len, false, 16, &[m]).unwrap();
        assert_eq!(record[5 + 8 + 3], 0xAA ^ 0x55);
        assert_eq!(record[5 + 8 + 3 + 1], 0xAA); // only index 0 was hit
    }

    #[test]
    fn aead_tag_on_plaintext_record_is_an_error() {
        let mut record = vec![22, 3, 3, 0, 1, 0];
        let mutation = Mutation {
            op: MutationOp::Xor {
                target: ResolvedByteTarget {
                    path: Some(vec!["record".into(), "aead_tag".into()]),
                    index: 0,
                    end: None,
                },
                value: 1,
            },
            span: dummy_span(),
        };
        assert!(apply_record_mutations(&mut record, 5, 1, false, 0, &[mutation]).is_err());
    }

    fn set_record_byte(path: &str, field: &str, index: i64, value: i64) -> Mutation {
        Mutation {
            op: MutationOp::Set {
                target: ResolvedByteTarget {
                    path: Some(vec![path.into(), field.into()]),
                    index,
                    end: None,
                },
                value,
            },
            span: dummy_span(),
        }
    }

    #[test]
    fn dtls_record_header_fields_resolve_to_the_right_offsets() {
        // A DTLS 1.2 record: 13-byte header + 2-byte body. The header is
        // type(1) | version(2) | epoch(2) | sequence_number(6) | length(2).
        let base: Vec<u8> = vec![
            23, // content type
            0xfe, 0xfd, // version
            0x00, 0x01, // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // sequence_number
            0x00, 0x02, // length
            0xAA, 0xBB, // body
        ];

        // record.version at offset 1..3.
        let mut r = base.clone();
        apply_record_mutations(
            &mut r,
            13,
            2,
            false,
            0,
            &[set_record_byte("record", "version", 1, 0xff)],
        )
        .unwrap();
        assert_eq!(&r[1..3], &[0xfe, 0xff]);

        // record.epoch at offset 3..5.
        let mut r = base.clone();
        apply_record_mutations(
            &mut r,
            13,
            2,
            false,
            0,
            &[set_record_byte("record", "epoch", 1, 0x05)],
        )
        .unwrap();
        assert_eq!(&r[3..5], &[0x00, 0x05]);

        // record.sequence_number at offset 5..11 (6 bytes).
        let mut r = base.clone();
        apply_record_mutations(
            &mut r,
            13,
            2,
            false,
            0,
            &[set_record_byte("record", "sequence_number", 0, 0xff)],
        )
        .unwrap();
        assert_eq!(&r[5..11], &[0xff, 0x00, 0x00, 0x00, 0x00, 0x02]);

        // The body and length are untouched by all three.
        assert_eq!(&r[11..], &[0x00, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn dtls_only_header_fields_are_rejected_on_a_tls_record() {
        // epoch and sequence_number exist only in the 13-byte DTLS header, so
        // targeting them on a 5-byte TLS record is an error rather than a
        // silent hit on the wrong bytes.
        let mut r = vec![23, 3, 3, 0, 2, 0xAA, 0xBB];
        assert!(
            apply_record_mutations(
                &mut r,
                5,
                2,
                false,
                0,
                &[set_record_byte("record", "epoch", 0, 0x05)]
            )
            .is_err()
        );
        let mut r = vec![23, 3, 3, 0, 2, 0xAA, 0xBB];
        assert!(
            apply_record_mutations(
                &mut r,
                5,
                2,
                false,
                0,
                &[set_record_byte("record", "sequence_number", 0, 0x05)]
            )
            .is_err()
        );
    }
}
