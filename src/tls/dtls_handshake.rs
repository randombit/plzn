// DTLS 1.2 handshake message fragmentation and reassembly (RFC 6347 4.2.2/4.2.3).
//
// DTLS handshake messages carry a 12-byte header (see dtls_record.rs) and may be
// fragmented across records; the receiver reassembles by message_seq using the
// fragment_offset/fragment_length fields. This module provides:
//   * `fragment_message` -- split one whole handshake message into records that
//     fit an MTU (the transcript hash still covers the WHOLE message once, in
//     DTLS format).
//   * `Reassembler` -- accumulate inbound fragments into complete messages,
//     delivering them in message_seq order.
//
// It is unit-tested in isolation; the DTLS driver drives it.

use crate::tls::dtls_record::{DTLS_HANDSHAKE_HEADER_LEN, DtlsHandshakeHeader};

/// One on-the-wire handshake fragment: its DTLS header plus the fragment bytes.
/// The caller frames each into a Handshake record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFragment {
    pub header: DtlsHandshakeHeader,
    pub body: Vec<u8>,
}

impl HandshakeFragment {
    /// Serialize header + fragment body (goes into a Handshake record fragment).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DTLS_HANDSHAKE_HEADER_LEN + self.body.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Split a whole handshake message (`msg_type` + `body`) into fragments no
/// larger than `max_fragment` body bytes each. `message_seq` is the DTLS
/// handshake sequence number for this message.
pub fn fragment_message(
    msg_type: u8,
    message_seq: u16,
    body: &[u8],
    max_fragment: usize,
) -> Vec<HandshakeFragment> {
    let total = body.len() as u32;
    let step = max_fragment.max(1);
    let mut out = Vec::new();
    let mut offset = 0usize;
    // An empty message still produces one zero-length fragment.
    loop {
        let end = (offset + step).min(body.len());
        let frag = &body[offset..end];
        out.push(HandshakeFragment {
            header: DtlsHandshakeHeader {
                msg_type,
                length: total,
                message_seq,
                fragment_offset: offset as u32,
                fragment_length: frag.len() as u32,
            },
            body: frag.to_vec(),
        });
        offset = end;
        if offset >= body.len() {
            break;
        }
    }
    out
}

/// Pick a fragment size that yields at least two fragments for a message of
/// `len` bytes (so an "incomplete then forge" scheme has something to overlap),
/// clamping the requested `size`.
fn multi_fragment_size(len: usize, requested: usize) -> usize {
    if len >= 2 {
        requested.clamp(1, len - 1)
    } else {
        requested.max(1)
    }
}

/// Build the on-the-wire fragments for a handshake message under a deliberate
/// DTLS fragmentation scheme (RFC 6347 4.2.3), used to exercise a peer's
/// reassembler. The transcript hash still covers the WHOLE message once; only
/// the wire framing deviates. See `ir::DtlsFragScheme`.
pub fn forge_fragments(
    msg_type: u8,
    seq: u16,
    body: &[u8],
    scheme: &crate::ir::DtlsFragScheme,
) -> Vec<HandshakeFragment> {
    use crate::ir::DtlsFragScheme as S;
    let total = body.len() as u32;
    match scheme {
        S::Fragment { size } => fragment_message(msg_type, seq, body, *size),
        S::HeldFragment { size, .. } => fragment_message(msg_type, seq, body, *size),
        S::DuplicateFragment { size } => {
            // Each fragment sent twice: an exact duplicate (harmless retransmit).
            let base = fragment_message(msg_type, seq, body, *size);
            let mut out = Vec::with_capacity(base.len() * 2);
            for f in base {
                out.push(f.clone());
                out.push(f);
            }
            out
        }
        S::ReorderOverlap { size } => {
            // Mirror BoGo's adversarial-but-valid reordering shape: every
            // fragment is duplicated and successive fragments overlap by up to
            // half their body. Reverse the deterministic list so the final
            // bytes arrive first. All overlapping bytes still agree.
            let max = (*size).max(1);
            let advance = max.div_ceil(2);
            let mut out = Vec::new();
            let mut offset = 0usize;
            loop {
                let end = (offset + max).min(body.len());
                let f = HandshakeFragment {
                    header: DtlsHandshakeHeader {
                        msg_type,
                        length: total,
                        message_seq: seq,
                        fragment_offset: offset as u32,
                        fragment_length: (end - offset) as u32,
                    },
                    body: body[offset..end].to_vec(),
                };
                out.push(f.clone());
                out.push(f);
                if end >= body.len() {
                    break;
                }
                offset += advance.min(end - offset);
            }
            out.reverse();
            out
        }
        S::CompleteAndFragments { size } => {
            let mut out = fragment_message(msg_type, seq, body, *size);
            out.push(HandshakeFragment {
                header: DtlsHandshakeHeader::whole(msg_type, seq, total),
                body: body.to_vec(),
            });
            out.reverse();
            out
        }
        S::EmptyFragments => vec![
            HandshakeFragment {
                header: DtlsHandshakeHeader {
                    msg_type,
                    length: total,
                    message_seq: seq,
                    fragment_offset: 0,
                    fragment_length: 0,
                },
                body: Vec::new(),
            },
            HandshakeFragment {
                header: DtlsHandshakeHeader::whole(msg_type, seq, total),
                body: body.to_vec(),
            },
            HandshakeFragment {
                header: DtlsHandshakeHeader {
                    msg_type,
                    length: total,
                    message_seq: seq,
                    fragment_offset: total,
                    fragment_length: 0,
                },
                body: Vec::new(),
            },
        ],
        S::SplitFragmentRecord { .. } => fragment_message(msg_type, seq, body, 60_000),
        S::FutureSequence { delta } | S::FutureSequencePacked { delta } => vec![
            HandshakeFragment {
                header: DtlsHandshakeHeader::whole(msg_type, seq.wrapping_add(*delta), total),
                body: body.to_vec(),
            },
            HandshakeFragment {
                header: DtlsHandshakeHeader::whole(msg_type, seq, total),
                body: body.to_vec(),
            },
        ],
        S::OverlapMismatch { size } => {
            // Split into >=2 fragments so the message is still incomplete when a
            // second copy of the first fragment -- with one byte flipped --
            // arrives: overlapping bytes that disagree (a protocol error).
            let eff = multi_fragment_size(body.len(), *size);
            let base = fragment_message(msg_type, seq, body, eff);
            let mut out = Vec::with_capacity(base.len() + 1);
            if let Some(first) = base.first().cloned() {
                out.push(first.clone());
                let mut bad = first;
                if let Some(b) = bad.body.first_mut() {
                    *b ^= 0xFF;
                }
                out.push(bad);
                out.extend(base.into_iter().skip(1));
            }
            out
        }
        S::TypeMismatch { size } => {
            // The reassembly slot is keyed by message_seq; every fragment for
            // that slot must agree on the handshake type as well as total
            // length. Change a later fragment so the first remains pending.
            let eff = multi_fragment_size(body.len(), *size);
            let mut base = fragment_message(msg_type, seq, body, eff);
            let idx = if base.len() >= 2 { 1 } else { 0 };
            if let Some(f) = base.get_mut(idx) {
                f.header.msg_type = msg_type.wrapping_add(1);
            }
            base
        }
        S::OffsetOverflow => {
            // One fragment whose fragment_offset + fragment_length runs one byte
            // past the declared message length.
            vec![HandshakeFragment {
                header: DtlsHandshakeHeader {
                    msg_type,
                    length: total,
                    message_seq: seq,
                    fragment_offset: 1,
                    fragment_length: total,
                },
                body: body.to_vec(),
            }]
        }
        S::LengthMismatch { size } => {
            // A later fragment for the same message_seq advertises a different
            // total length (inconsistent metadata).
            let eff = multi_fragment_size(body.len(), *size);
            let mut base = fragment_message(msg_type, seq, body, eff);
            let idx = if base.len() >= 2 { 1 } else { 0 };
            if let Some(f) = base.get_mut(idx) {
                f.header.length = total.wrapping_add(1);
            }
            base
        }
        S::FragmentLengthMismatch { size } => {
            let mut base = fragment_message(msg_type, seq, body, (*size).max(1));
            if let Some(first) = base.first_mut() {
                first.header.fragment_length = first.header.fragment_length.wrapping_add(1);
            }
            base
        }
    }
}

/// The DTLS fragmentation scheme, if any, attached to `kind`'s `send` step.
pub fn frag_scheme_for(
    list: &[crate::ir::MessageMutations],
    kind: crate::ir::MessageKind,
) -> Option<&crate::ir::DtlsFragScheme> {
    list.iter()
        .find(|e| e.message == kind)
        .and_then(|e| e.dtls_frag.as_ref())
}

/// Fragment a message for the wire honouring any `send Msg @ <scheme>` in the
/// flow: a DTLS fragmentation scheme (`@ fragment N`, ...) takes precedence, then
/// `@ reorder N` (reverse-order N-byte fragments), else one fragment. Shared by
/// both DTLS roles so fragmentation control is identical on each side.
pub fn build_fragments(
    send_mutations: &[crate::ir::MessageMutations],
    kind: crate::ir::MessageKind,
    msg_type: u8,
    seq: u16,
    body: &[u8],
) -> Vec<HandshakeFragment> {
    if let Some(scheme) = frag_scheme_for(send_mutations, kind) {
        return forge_fragments(msg_type, seq, body, scheme);
    }
    let reorder = crate::tls::driver::collect_mutations(send_mutations, kind)
        .iter()
        .find_map(|m| match m.op {
            crate::ir::MutationOp::Reorder(size) => Some(size),
            _ => None,
        });
    // A conforming peer must reassemble by fragment_offset regardless of arrival
    // order (RFC 6347 4.2.3), so reorder is a cross-library test on any message
    // both peers exchange. 60_000 is effectively "one fragment" for our messages.
    let mut frags = fragment_message(msg_type, seq, body, reorder.unwrap_or(60_000));
    if reorder.is_some() {
        frags.reverse();
    }
    frags
}

/// Encode the fragments that each become a DTLS Handshake record payload,
/// including handshake-header byte mutations. `split_fragment_record` is the
/// one deliberately malformed scheme: it splits a single encoded fragment into
/// two record payloads, so neither record carries an independently complete
/// fragment header/body.
pub fn build_fragment_payloads(
    send_mutations: &[crate::ir::MessageMutations],
    kind: crate::ir::MessageKind,
    msg_type: u8,
    seq: u16,
    body: &[u8],
) -> Vec<Vec<u8>> {
    let mutations = crate::tls::driver::collect_mutations(send_mutations, kind);
    let mut payloads: Vec<Vec<u8>> = build_fragments(send_mutations, kind, msg_type, seq, body)
        .into_iter()
        .map(|f| {
            let mut encoded = f.encode();
            crate::tls::mutate::apply_handshake_header_mutations(&mut encoded, mutations);
            encoded
        })
        .collect();
    if let Some(crate::ir::DtlsFragScheme::SplitFragmentRecord { at }) =
        frag_scheme_for(send_mutations, kind)
    {
        let encoded = payloads.pop().unwrap_or_default();
        let split = (*at).min(encoded.len());
        return vec![encoded[..split].to_vec(), encoded[split..].to_vec()];
    }
    payloads
}

/// The largest handshake message plzn will reassemble, and the total number of
/// bytes it will hold across all in-flight partial messages. These mirror
/// Botan's DTLS reassembly limits (`k_max_handshake_msg_size`,
/// `max_pending_reassembly`) so a peer that floods plzn with future-seq claims
/// cannot exhaust memory or starve the in-sequence message. RFC 6347 gives no
/// hard limit; these are policy, like every real stack applies.
pub const MAX_HANDSHAKE_MSG_SIZE: u32 = 65536;
pub const MAX_PENDING_REASSEMBLY: u64 = 4 * MAX_HANDSHAKE_MSG_SIZE as u64;

/// A reassembly rule was violated by an inbound fragment (RFC 6347 4.2.3). The
/// DTLS drivers turn this into a `TlsError::Dtls("reassembly: ...")` so a flow
/// can observe the rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    /// The declared message length exceeds `MAX_HANDSHAKE_MSG_SIZE`.
    MsgTooLarge { declared: u32 },
    /// A fragment's declared body length disagrees with the bytes present.
    BadFragmentLength { seq: u16 },
    /// fragment_offset + fragment_length runs past the declared message length.
    FragmentPastEnd {
        seq: u16,
        offset: u32,
        fragment_length: u32,
        declared: u32,
    },
    /// A later fragment for the same message_seq advertises a different msg_type
    /// or total length (inconsistent metadata).
    MetadataMismatch { seq: u16 },
    /// Overlapping fragments cover the same byte with different values.
    OverlapMismatch { seq: u16 },
}

impl std::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReassemblyError::MsgTooLarge { declared } => {
                write!(
                    f,
                    "handshake message length {} exceeds the {}-byte maximum",
                    declared, MAX_HANDSHAKE_MSG_SIZE
                )
            }
            ReassemblyError::BadFragmentLength { seq } => {
                write!(
                    f,
                    "fragment for message_seq {} declares a length that does not match its bytes",
                    seq
                )
            }
            ReassemblyError::FragmentPastEnd {
                seq,
                offset,
                fragment_length,
                declared,
            } => write!(
                f,
                "fragment for message_seq {} runs past the message end (offset {} + length {} > {})",
                seq, offset, fragment_length, declared
            ),
            ReassemblyError::MetadataMismatch { seq } => {
                write!(
                    f,
                    "fragment for message_seq {} disagrees with an earlier fragment's type or length",
                    seq
                )
            }
            ReassemblyError::OverlapMismatch { seq } => {
                write!(
                    f,
                    "overlapping fragments for message_seq {} disagree on their bytes",
                    seq
                )
            }
        }
    }
}

/// A message being reassembled. Bytes are stored sparsely (offset -> value) so a
/// header-only fragment claiming a huge length costs nothing until real bytes
/// arrive, and overlapping bytes can be checked for agreement before being
/// committed (RFC 6347 4.2.3 forbids inconsistent overlaps).
struct Partial {
    msg_type: u8,
    length: u32,
    bytes: std::collections::BTreeMap<u32, u8>,
}

impl Partial {
    fn new(msg_type: u8, length: u32) -> Self {
        Partial {
            msg_type,
            length,
            bytes: std::collections::BTreeMap::new(),
        }
    }

    /// Merge one fragment's bytes. The caller has already checked that
    /// `offset + frag.len()` is within `length`. Any overlap whose bytes
    /// disagree with what is already held is rejected without mutating state.
    fn insert(&mut self, offset: u32, frag: &[u8]) -> Result<(), ()> {
        for (i, &b) in frag.iter().enumerate() {
            let pos = offset + i as u32;
            if let Some(&existing) = self.bytes.get(&pos) {
                if existing != b {
                    return Err(());
                }
            }
        }
        for (i, &b) in frag.iter().enumerate() {
            self.bytes.insert(offset + i as u32, b);
        }
        Ok(())
    }

    /// Bytes actually held (bounded by `length`).
    fn charged(&self) -> u64 {
        self.length as u64
    }

    fn complete(&self) -> bool {
        // Every offset in [0, length) is covered: since all keys lie within that
        // range and are distinct, a full count is a full message.
        self.bytes.len() == self.length as usize
    }

    fn assemble(&self) -> Vec<u8> {
        (0..self.length).map(|i| self.bytes[&i]).collect()
    }
}

/// A fully reassembled handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub msg_type: u8,
    pub message_seq: u16,
    pub body: Vec<u8>,
}

/// Reassembles fragments into whole messages, delivered in message_seq order
/// starting from `next_seq`. Out-of-order and duplicate fragments are handled;
/// a fragment for an already-delivered seq is dropped.
pub struct Reassembler {
    next_seq: u16,
    partials: std::collections::BTreeMap<u16, Partial>,
    // Sum of the declared lengths of every partial currently held, so a flood of
    // future-seq claims is bounded (see `MAX_PENDING_REASSEMBLY`).
    pending_charge: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// A record can carry several handshake fragments. Keep every message
    /// released by a fragment, including already buffered later sequences.
    pub fn accept_record(&mut self, bytes: &[u8]) -> Result<Vec<HandshakeMessage>, String> {
        self.accept_record_in_epoch(bytes, true)
    }

    pub(crate) fn accept_record_in_epoch(
        &mut self,
        mut bytes: &[u8],
        allow_finished: bool,
    ) -> Result<Vec<HandshakeMessage>, String> {
        let mut messages = Vec::new();
        while !bytes.is_empty() {
            let header = DtlsHandshakeHeader::parse(bytes).map_err(|e| format!("{e:?}"))?;
            let end = DTLS_HANDSHAKE_HEADER_LEN + header.fragment_length as usize;
            if bytes.len() < end {
                return Err("short DTLS handshake fragment".into());
            }
            let fragment = HandshakeFragment {
                header,
                body: bytes[DTLS_HANDSHAKE_HEADER_LEN..end].to_vec(),
            };
            if allow_finished || fragment.header.msg_type != crate::tls::codec::HS_FINISHED {
                messages.extend(self.accept(&fragment).map_err(|e| e.to_string())?);
            }
            bytes = &bytes[end..];
        }
        Ok(messages)
    }
    pub fn new() -> Self {
        Reassembler {
            next_seq: 0,
            partials: std::collections::BTreeMap::new(),
            pending_charge: 0,
        }
    }

    pub fn with_next_seq(next_seq: u16) -> Self {
        Reassembler {
            next_seq,
            partials: std::collections::BTreeMap::new(),
            pending_charge: 0,
        }
    }

    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// Feed one fragment. Returns any messages that became deliverable (in
    /// order), which may be zero, one, or several (if this fragment unblocked a
    /// run of already-buffered later messages).
    ///
    /// A fragment that violates a reassembly rule (RFC 6347 4.2.3) returns a
    /// `ReassemblyError` and does not change state: overlapping bytes that
    /// disagree, a fragment past the declared end, inconsistent metadata for a
    /// message_seq, or a declared length above policy. Fragments for an
    /// already-delivered seq, and exact / consistent retransmits, are harmless.
    /// A flood of future-seq claims is bounded: once the pending budget is full,
    /// a new future-seq slot is dropped silently, but the in-sequence message
    /// always gets a slot so it can never be starved.
    pub fn accept(
        &mut self,
        frag: &HandshakeFragment,
    ) -> Result<Vec<HandshakeMessage>, ReassemblyError> {
        let h = &frag.header;
        let seq = h.message_seq;

        // Already delivered: a retransmission the sender did not know we had.
        if seq < self.next_seq {
            return Ok(Vec::new());
        }

        // The fragment_length field must describe the bytes actually carried.
        if h.fragment_length as usize != frag.body.len() {
            return Err(ReassemblyError::BadFragmentLength { seq });
        }
        // A message longer than policy allows is rejected up front (no slot).
        if h.length > MAX_HANDSHAKE_MSG_SIZE {
            return Err(ReassemblyError::MsgTooLarge { declared: h.length });
        }
        // A fragment may not claim bytes past the end of the declared message.
        let end = h.fragment_offset as u64 + h.fragment_length as u64;
        if end > h.length as u64 {
            return Err(ReassemblyError::FragmentPastEnd {
                seq,
                offset: h.fragment_offset,
                fragment_length: h.fragment_length,
                declared: h.length,
            });
        }

        match self.partials.get_mut(&seq) {
            Some(p) => {
                // A later fragment must agree with the slot's type and length.
                if p.msg_type != h.msg_type || p.length != h.length {
                    return Err(ReassemblyError::MetadataMismatch { seq });
                }
                p.insert(h.fragment_offset, &frag.body)
                    .map_err(|()| ReassemblyError::OverlapMismatch { seq })?;
            }
            None => {
                // Admission control for a brand-new slot. The in-sequence message
                // (seq == next_seq) always gets a slot; only future-seq slots are
                // subject to the pending budget, so a flood cannot starve it.
                let charge = h.length as u64;
                if seq != self.next_seq
                    && self.pending_charge.saturating_add(charge) > MAX_PENDING_REASSEMBLY
                {
                    return Ok(Vec::new());
                }
                let mut p = Partial::new(h.msg_type, h.length);
                p.insert(h.fragment_offset, &frag.body)
                    .map_err(|()| ReassemblyError::OverlapMismatch { seq })?;
                self.pending_charge = self.pending_charge.saturating_add(p.charged());
                self.partials.insert(seq, p);
            }
        }

        // Deliver as many consecutive completed messages as possible.
        let mut delivered = Vec::new();
        while let Some(p) = self.partials.get(&self.next_seq) {
            if !p.complete() {
                break;
            }
            let p = self.partials.remove(&self.next_seq).unwrap();
            self.pending_charge = self.pending_charge.saturating_sub(p.charged());
            delivered.push(HandshakeMessage {
                msg_type: p.msg_type,
                message_seq: self.next_seq,
                body: p.assemble(),
            });
            self.next_seq = self.next_seq.wrapping_add(1);
        }
        Ok(delivered)
    }
}

/// The bytes that enter the handshake transcript hash for a DTLS message: the
/// 12-byte DTLS handshake header (with fragment_offset=0 and
/// fragment_length=length, i.e. as a single unfragmented message) followed by
/// the whole body. RFC 6347 4.2.6: the hash is computed as if each handshake
/// message had been sent as a single fragment.
pub fn transcript_bytes(msg: &HandshakeMessage) -> Vec<u8> {
    let hdr = DtlsHandshakeHeader::whole(msg.msg_type, msg.message_seq, msg.body.len() as u32);
    let mut out = Vec::with_capacity(DTLS_HANDSHAKE_HEADER_LEN + msg.body.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&msg.body);
    out
}

// ============================================================
//        DTLS cookie-exchange message bodies (RFC 6347 4.2.1)
// ============================================================
//
// The DTLS ClientHello differs from TLS's by an added `cookie` field between the
// session_id and cipher_suites. HelloVerifyRequest carries the cookie the client
// must echo in its second ClientHello.

use crate::tls::codec::{ByteCursor, ByteWriter, CodecError};

/// A DTLS ClientHello body (RFC 6347 4.2.1). `cookie` is empty on the first
/// flight and echoes the HelloVerifyRequest cookie on the second.
#[derive(Clone)]
pub struct DtlsClientHello {
    pub client_version: u16, // DTLS 1.2 = 0xFEFD
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cookie: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<u8>, // pre-encoded extensions block (may be empty)
}

pub fn encode_dtls_client_hello_body(ch: &DtlsClientHello) -> Vec<u8> {
    encode_dtls_client_hello_body_mapped(ch).bytes
}

/// The DTLS ClientHello with a field map (the TLS ClientHello's names plus the
/// RFC 6347 4.2.1 `cookie`), so `send ClientHello @ xor[handshake.<field>, i]`
/// resolves on the DTLS client like it does on the TLS one.
pub fn encode_dtls_client_hello_body_mapped(
    ch: &DtlsClientHello,
) -> crate::tls::codec::EncodedBody {
    let mut w = ByteWriter::new();
    w.mark("legacy_version");
    w.u16(ch.client_version);
    w.mark_end("legacy_version");
    w.mark("random");
    w.bytes(&ch.random);
    w.mark_end("random");
    w.mark("legacy_session_id");
    w.u8_vec(&ch.session_id);
    w.mark_end("legacy_session_id");
    w.mark("cookie");
    w.u8_vec(&ch.cookie); // opaque cookie<0..2^8-1>
    w.mark_end("cookie");
    w.mark("cipher_suites");
    let cs_pos = w.reserve_u16();
    for cs in &ch.cipher_suites {
        w.u16(*cs);
    }
    w.patch_u16(cs_pos);
    w.mark_end("cipher_suites");
    w.mark("compression_methods");
    w.u8_vec(&ch.compression_methods);
    w.mark_end("compression_methods");
    // extensions: u16-prefixed block (already-encoded contents)
    w.mark("extensions");
    w.u16_vec(&ch.extensions);
    w.mark_end("extensions");
    w.into_encoded_body()
}

/// Parsed HelloVerifyRequest (RFC 6347 4.2.1): server_version + cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    pub server_version: u16,
    pub cookie: Vec<u8>,
}

pub fn parse_hello_verify_request(body: &[u8]) -> Result<HelloVerifyRequest, CodecError> {
    let mut c = ByteCursor::new(body);
    let server_version = c.u16()?;
    let cookie = c.u8_vec()?.to_vec();
    Ok(HelloVerifyRequest {
        server_version,
        cookie,
    })
}

/// Encode a HelloVerifyRequest body (RFC 6347 4.2.1): server_version + cookie.
pub fn encode_hello_verify_request(server_version: u16, cookie: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.u16(server_version);
    w.u8_vec(cookie);
    w.into_vec()
}

/// Minimal DTLS ClientHello fields the server driver needs.
#[derive(Debug, Clone)]
pub struct DtlsClientHelloFields {
    pub client_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cookie: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub use_ems: bool,
    /// The client offered encrypt_then_mac (RFC 7366, 0x0016).
    pub use_etm: bool,
    /// The renegotiation_info "renegotiated_connection" value (RFC 5746): the
    /// verify_data bytes after the 1-byte length prefix, `None` if the extension
    /// is absent, empty on the initial handshake.
    pub reneg_info: Option<Vec<u8>>,
}

/// Rewrite a DTLS ClientHello body into TLS ClientHello form by removing the
/// cookie vector that DTLS inserts after session_id (RFC 6347 4.2.1), so the
/// TLS codec's `decode_client_hello_body` -- and with it the `recv ClientHello
/// { ... }` matchers -- can be applied to it unchanged.
pub fn strip_dtls_cookie(body: &[u8]) -> Result<Vec<u8>, CodecError> {
    // version(2) random(32) session_id<0..32> cookie<0..255> ...
    if body.len() < 2 + 32 + 1 {
        return Err(CodecError::UnexpectedEof);
    }
    let sid_len = body[34] as usize;
    let cookie_len_at = 35 + sid_len;
    if body.len() < cookie_len_at + 1 {
        return Err(CodecError::UnexpectedEof);
    }
    let cookie_len = body[cookie_len_at] as usize;
    let rest_at = cookie_len_at + 1 + cookie_len;
    if body.len() < rest_at {
        return Err(CodecError::UnexpectedEof);
    }
    let mut out = Vec::with_capacity(body.len() - 1 - cookie_len);
    out.extend_from_slice(&body[..cookie_len_at]);
    out.extend_from_slice(&body[rest_at..]);
    Ok(out)
}

pub fn parse_dtls_client_hello(body: &[u8]) -> Result<DtlsClientHelloFields, CodecError> {
    let mut c = ByteCursor::new(body);
    let client_version = c.u16()?;
    let random_slice = c.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_slice);
    let session_id = c.u8_vec()?.to_vec();
    let cookie = c.u8_vec()?.to_vec();
    let cs_block = c.u16_vec()?;
    let mut cipher_suites = Vec::new();
    let mut cc = ByteCursor::new(cs_block);
    while cc.remaining() >= 2 {
        cipher_suites.push(cc.u16()?);
    }
    let _compression = c.u8_vec()?;
    // Extensions are optional; scan for extended_master_secret (0x0017) and
    // renegotiation_info (0xff01).
    let mut use_ems = false;
    let mut use_etm = false;
    let mut reneg_info = None;
    if c.remaining() >= 2 {
        let ext_block = c.u16_vec()?;
        let mut ec = ByteCursor::new(ext_block);
        while ec.remaining() >= 4 {
            let ty = ec.u16()?;
            let data = ec.u16_vec()?;
            if ty == 0x0017 {
                use_ems = true;
            } else if ty == 0x0016 {
                use_etm = true;
            } else if ty == 0xff01 {
                let mut dc = ByteCursor::new(data);
                reneg_info = Some(dc.u8_vec()?.to_vec());
            }
        }
    }
    Ok(DtlsClientHelloFields {
        client_version,
        random,
        session_id,
        cookie,
        cipher_suites,
        use_ems,
        use_etm,
        reneg_info,
    })
}

/// Minimal DTLS/TLS 1.2 ServerHello fields the driver needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloFields {
    pub server_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    /// Extension types present, in order (empty when the block is absent).
    pub extensions: Vec<u16>,
}

pub fn parse_server_hello(body: &[u8]) -> Result<ServerHelloFields, CodecError> {
    let mut c = ByteCursor::new(body);
    let server_version = c.u16()?;
    let random_slice = c.take(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_slice);
    let session_id = c.u8_vec()?.to_vec();
    let cipher_suite = c.u16()?;
    let compression_method = c.u8()?;
    let mut extensions = Vec::new();
    if c.remaining() >= 2 {
        let ext_block = c.u16_vec()?;
        let mut ec = ByteCursor::new(ext_block);
        while ec.remaining() >= 4 {
            extensions.push(ec.u16()?);
            let _ = ec.u16_vec()?;
        }
    }
    Ok(ServerHelloFields {
        server_version,
        random,
        session_id,
        cipher_suite,
        compression_method,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_when_small() {
        let frags = fragment_message(1, 0, &[1, 2, 3], 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].header.fragment_offset, 0);
        assert_eq!(frags[0].header.fragment_length, 3);
        assert_eq!(frags[0].header.length, 3);
        assert_eq!(frags[0].body, vec![1, 2, 3]);
    }

    #[test]
    fn empty_message_is_one_zero_fragment() {
        let frags = fragment_message(14, 5, &[], 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].header.length, 0);
        assert_eq!(frags[0].header.fragment_length, 0);
        assert!(frags[0].body.is_empty());
    }

    #[test]
    fn generic_handshake_header_mutations_apply_to_dtls_fragments() {
        use crate::ir::{Mutation, MutationOp, ResolvedByteTarget};
        let mutation = |field: &str, index: i64, value: u8| Mutation {
            op: MutationOp::Set {
                target: ResolvedByteTarget {
                    path: Some(vec!["handshake".into(), field.into()]),
                    index,
                    end: None,
                },
                value: value as i64,
            },
            span: crate::ast::Span::dummy(),
        };
        let mut wire = fragment_message(1, 3, &[1, 2, 3], 100)[0].encode();
        crate::tls::mutate::apply_handshake_header_mutations(
            &mut wire,
            &[mutation("msg_type", 0, 43), mutation("length", 2, 9)],
        );
        let header = DtlsHandshakeHeader::parse(&wire).unwrap();
        assert_eq!(header.msg_type, 43);
        assert_eq!(header.length, 9);
        assert_eq!(header.message_seq, 3);
        assert_eq!(header.fragment_offset, 0);
        assert_eq!(header.fragment_length, 3);
    }

    #[test]
    fn forged_fragment_metadata_covers_type_and_carried_length() {
        let body = [0u8; 40];
        let type_mismatch = forge_fragments(
            1,
            0,
            &body,
            &crate::ir::DtlsFragScheme::TypeMismatch { size: 16 },
        );
        assert_eq!(type_mismatch.len(), 3);
        assert_eq!(type_mismatch[0].header.msg_type, 1);
        assert_eq!(type_mismatch[1].header.msg_type, 2);

        let carried_mismatch = forge_fragments(
            1,
            0,
            &body,
            &crate::ir::DtlsFragScheme::FragmentLengthMismatch { size: 16 },
        );
        assert_eq!(carried_mismatch[0].body.len(), 16);
        assert_eq!(carried_mismatch[0].header.fragment_length, 17);
    }

    #[test]
    fn valid_adversarial_fragment_schemes_preserve_bytes() {
        let body: Vec<u8> = (0..10).collect();
        let reordered = forge_fragments(
            1,
            7,
            &body,
            &crate::ir::DtlsFragScheme::ReorderOverlap { size: 3 },
        );
        assert!(reordered.len() > 4);
        assert!(
            reordered.windows(2).any(|pair| pair[0] == pair[1]),
            "the scheme includes exact duplicates"
        );
        let mut covered = [false; 10];
        for f in &reordered {
            for i in 0..f.body.len() {
                assert_eq!(f.body[i], body[f.header.fragment_offset as usize + i]);
                covered[f.header.fragment_offset as usize + i] = true;
            }
        }
        assert!(covered.into_iter().all(|v| v));

        let mixed = forge_fragments(
            1,
            7,
            &body,
            &crate::ir::DtlsFragScheme::CompleteAndFragments { size: 3 },
        );
        assert!(mixed.iter().any(|f| f.header.fragment_length == 10));

        let empty = forge_fragments(1, 7, &body, &crate::ir::DtlsFragScheme::EmptyFragments);
        assert_eq!(empty.len(), 3);
        assert_eq!(empty[0].header.fragment_length, 0);
        assert_eq!(empty[2].header.fragment_offset, 10);
        assert_eq!(empty[2].header.fragment_length, 0);
    }

    #[test]
    fn split_fragment_record_splits_encoded_header_and_body() {
        let directives = vec![crate::ir::MessageMutations {
            message: crate::ir::MessageKind::ClientHello,
            mutations: Vec::new(),
            dtls_frag: Some(crate::ir::DtlsFragScheme::SplitFragmentRecord { at: 2 }),
        }];
        let payloads = build_fragment_payloads(
            &directives,
            crate::ir::MessageKind::ClientHello,
            1,
            0,
            &[1, 2, 3],
        );
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].len(), 2);
        assert_eq!(payloads[1].len(), DTLS_HANDSHAKE_HEADER_LEN + 3 - 2);
    }

    #[test]
    fn splits_into_mtu_sized_fragments() {
        let body: Vec<u8> = (0..250u32).map(|i| i as u8).collect();
        let frags = fragment_message(11, 2, &body, 100);
        assert_eq!(frags.len(), 3); // 100 + 100 + 50
        assert_eq!(frags[0].header.fragment_offset, 0);
        assert_eq!(frags[1].header.fragment_offset, 100);
        assert_eq!(frags[2].header.fragment_offset, 200);
        assert_eq!(frags[2].header.fragment_length, 50);
        // All fragments report the same total length.
        assert!(frags.iter().all(|f| f.header.length == 250));
    }

    #[test]
    fn reassemble_in_order() {
        let body: Vec<u8> = (0..250u32).map(|i| i as u8).collect();
        let frags = fragment_message(11, 0, &body, 100);
        let mut r = Reassembler::new();
        let mut got = Vec::new();
        for f in &frags {
            got.extend(r.accept(f).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, 11);
        assert_eq!(got[0].body, body);
    }

    #[test]
    fn reassemble_out_of_order_fragments() {
        let body: Vec<u8> = (0..250u32).map(|i| i as u8).collect();
        let mut frags = fragment_message(11, 0, &body, 100);
        frags.reverse(); // deliver last fragment first
        let mut r = Reassembler::new();
        let mut got = Vec::new();
        for f in &frags {
            got.extend(r.accept(f).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, body);
    }

    #[test]
    fn duplicate_fragments_are_harmless() {
        let frags = fragment_message(1, 0, &[9, 9, 9], 100);
        let mut r = Reassembler::new();
        assert_eq!(r.accept(&frags[0]).unwrap().len(), 1);
        // Re-delivering the same (already-delivered) message is dropped.
        assert_eq!(r.accept(&frags[0]).unwrap().len(), 0);
    }

    #[test]
    fn out_of_order_messages_deliver_when_gap_fills() {
        // message_seq 1 arrives before 0; nothing delivered until 0 arrives.
        let m0 = fragment_message(1, 0, &[0xA], 100).remove(0);
        let m1 = fragment_message(2, 1, &[0xB], 100).remove(0);
        let mut r = Reassembler::new();
        assert!(r.accept(&m1).unwrap().is_empty());
        let got = r.accept(&m0).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].message_seq, 0);
        assert_eq!(got[1].message_seq, 1);
    }

    // A raw fragment for a message_seq at a given offset (models Botan's
    // `dtls_hs_record` test helper): declared total `length`, `frag` at `offset`.
    fn frag_at(msg_type: u8, seq: u16, length: u32, offset: u32, frag: &[u8]) -> HandshakeFragment {
        HandshakeFragment {
            header: DtlsHandshakeHeader {
                msg_type,
                length,
                message_seq: seq,
                fragment_offset: offset,
                fragment_length: frag.len() as u32,
            },
            body: frag.to_vec(),
        }
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| i as u8).collect()
    }

    #[test]
    fn empty_handshake_message_is_delivered() {
        // A zero-length message (e.g. ServerHelloDone) completes immediately.
        let mut r = Reassembler::new();
        let got = r.accept(&frag_at(14, 0, 0, 0, &[])).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_type, 14);
        assert!(got[0].body.is_empty());
    }

    #[test]
    fn fragment_past_end_is_rejected() {
        // msg_len=10 but the fragment carries 20 bytes at offset 0.
        let mut r = Reassembler::new();
        let err = r.accept(&frag_at(1, 0, 10, 0, &payload(20))).unwrap_err();
        assert!(matches!(err, ReassemblyError::FragmentPastEnd { .. }));
    }

    #[test]
    fn inconsistent_metadata_is_rejected() {
        let mut r = Reassembler::new();
        r.accept(&frag_at(1, 0, 50, 0, &payload(20))).unwrap();
        // Same message_seq, different msg_type.
        let err = r.accept(&frag_at(11, 0, 50, 20, &payload(10))).unwrap_err();
        assert!(matches!(err, ReassemblyError::MetadataMismatch { .. }));
    }

    #[test]
    fn inconsistent_declared_length_is_rejected() {
        let mut r = Reassembler::new();
        r.accept(&frag_at(1, 0, 50, 0, &payload(20))).unwrap();
        // Same message_seq and type, different total length.
        let err = r.accept(&frag_at(1, 0, 60, 20, &payload(10))).unwrap_err();
        assert!(matches!(err, ReassemblyError::MetadataMismatch { .. }));
    }

    #[test]
    fn inconsistent_overlapping_bytes_are_rejected() {
        let mut r = Reassembler::new();
        let base = payload(50);
        // A partial first fragment leaves the slot incomplete.
        r.accept(&frag_at(11, 0, 50, 0, &base[..30])).unwrap();
        let mut bad = base[..30].to_vec();
        bad[10] ^= 0xFF;
        let err = r.accept(&frag_at(11, 0, 50, 0, &bad)).unwrap_err();
        assert!(matches!(err, ReassemblyError::OverlapMismatch { .. }));
    }

    #[test]
    fn consistent_retransmits_are_tolerated() {
        let mut r = Reassembler::new();
        let p = payload(100);
        assert!(
            r.accept(&frag_at(1, 0, 100, 0, &p[..50]))
                .unwrap()
                .is_empty()
        );
        // Same first half again: harmless, no error, no state change.
        assert!(
            r.accept(&frag_at(1, 0, 100, 0, &p[..50]))
                .unwrap()
                .is_empty()
        );
        let got = r.accept(&frag_at(1, 0, 100, 50, &p[50..])).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn overlapping_agreeing_fragments_reassemble() {
        // RFC 6347 4.2.3 explicitly allows overlapping retransmissions.
        let mut r = Reassembler::new();
        let p = payload(100);
        assert!(
            r.accept(&frag_at(1, 0, 100, 0, &p[..60]))
                .unwrap()
                .is_empty()
        );
        // Overlaps [40, 60) with matching bytes, extends to 100.
        let got = r.accept(&frag_at(1, 0, 100, 40, &p[40..])).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn msg_len_above_policy_max_is_rejected() {
        let mut r = Reassembler::new();
        let err = r
            .accept(&frag_at(1, 0, MAX_HANDSHAKE_MSG_SIZE + 1, 0, &[]))
            .unwrap_err();
        assert!(matches!(err, ReassemblyError::MsgTooLarge { .. }));
    }

    #[test]
    fn bad_fragment_length_field_is_rejected() {
        // The header claims 20 bytes but only 5 are carried.
        let mut r = Reassembler::new();
        let f = HandshakeFragment {
            header: DtlsHandshakeHeader {
                msg_type: 1,
                length: 20,
                message_seq: 0,
                fragment_offset: 0,
                fragment_length: 20,
            },
            body: payload(5),
        };
        assert!(matches!(
            r.accept(&f).unwrap_err(),
            ReassemblyError::BadFragmentLength { .. }
        ));
    }

    #[test]
    fn header_only_future_seq_flood_does_not_block_the_in_sequence_message() {
        // Enough header-only future-seq claims to exhaust the pending budget.
        let mut r = Reassembler::new();
        for seq in 1..=4u16 {
            let f = frag_at(1, seq, MAX_HANDSHAKE_MSG_SIZE, 0, &[]);
            assert!(r.accept(&f).unwrap().is_empty());
        }
        // The legit in-sequence (seq 0) ClientHello must still get through.
        let p = payload(40);
        let got = r.accept(&frag_at(1, 0, 40, 0, &p)).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn tiny_future_seq_fragments_do_not_exhaust_the_budget() {
        // 1-byte fragments at many out-of-order seqs, each claiming max length:
        // once the budget is full further future slots are dropped, but the
        // in-sequence message is never charged against it.
        let mut r = Reassembler::new();
        for seq in 1..=8u16 {
            let f = frag_at(1, seq, MAX_HANDSHAKE_MSG_SIZE, 0, &[0x42]);
            assert!(r.accept(&f).unwrap().is_empty());
        }
        let p = payload(40);
        let got = r.accept(&frag_at(1, 0, 40, 0, &p)).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn many_sparse_fragments_to_one_slot_charge_the_budget_once() {
        // A single future-seq slot fed thousands of 1-byte fragments is charged
        // its declared length once, so it cannot starve the in-sequence message.
        let mut r = Reassembler::new();
        for offset in (0..40000u32).step_by(2) {
            let f = frag_at(11, 1, MAX_HANDSHAKE_MSG_SIZE, offset, &[0x42]);
            assert!(r.accept(&f).unwrap().is_empty());
        }
        let p = payload(40);
        let got = r.accept(&frag_at(1, 0, 40, 0, &p)).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn high_offset_fragment_then_gap_fill_completes() {
        // A fragment at the far end can arrive first; filling the gap completes.
        let mut r = Reassembler::new();
        let p = payload(200);
        assert!(
            r.accept(&frag_at(1, 0, 200, 199, &p[199..]))
                .unwrap()
                .is_empty()
        );
        let got = r.accept(&frag_at(1, 0, 200, 0, &p[..199])).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].body, p);
    }

    #[test]
    fn strip_dtls_cookie_yields_a_tls_client_hello() {
        let ch = DtlsClientHello {
            client_version: 0xfefd,
            random: [7u8; 32],
            session_id: vec![1, 2, 3],
            cookie: vec![0xaa; 20],
            cipher_suites: vec![0xc02b, 0xc02f],
            compression_methods: vec![0],
            extensions: Vec::new(),
        };
        let body = encode_dtls_client_hello_body(&ch);
        let tls = strip_dtls_cookie(&body).unwrap();
        assert_eq!(tls.len(), body.len() - 21);
        let decoded = crate::tls::codec::decode_client_hello_body(&tls).unwrap();
        assert_eq!(decoded.legacy_version, 0xfefd);
        assert_eq!(decoded.random, [7u8; 32]);
        assert_eq!(decoded.session_id, vec![1, 2, 3]);
        assert_eq!(decoded.cipher_suites, vec![0xc02b, 0xc02f]);
        // An empty cookie (CH1) strips to the same layout minus one byte.
        let ch1 = DtlsClientHello {
            cookie: Vec::new(),
            ..ch
        };
        let body1 = encode_dtls_client_hello_body(&ch1);
        assert_eq!(strip_dtls_cookie(&body1).unwrap().len(), body1.len() - 1);
        assert!(strip_dtls_cookie(&body[..10]).is_err());
    }

    #[test]
    fn dtls_client_hello_places_cookie_after_session_id() {
        let ch = DtlsClientHello {
            client_version: 0xFEFD,
            random: [0x11; 32],
            session_id: vec![],
            cookie: vec![0xAA, 0xBB],
            cipher_suites: vec![0x009C],
            compression_methods: vec![0x00],
            extensions: vec![],
        };
        let body = encode_dtls_client_hello_body(&ch);
        // version(2) + random(32) + session_id(1 len=0) + cookie(1 len=2 + 2)
        assert_eq!(&body[0..2], &[0xFE, 0xFD]);
        assert_eq!(body[34], 0x00); // session_id length
        assert_eq!(body[35], 0x02); // cookie length
        assert_eq!(&body[36..38], &[0xAA, 0xBB]);
        // cipher_suites: u16 len then the suite
        assert_eq!(&body[38..40], &[0x00, 0x02]);
        assert_eq!(&body[40..42], &[0x00, 0x9C]);
    }

    #[test]
    fn hello_verify_request_round_trip() {
        let hvr = HelloVerifyRequest {
            server_version: 0xFEFD,
            cookie: vec![1, 2, 3, 4, 5],
        };
        // Encode by hand: version + u8-len cookie.
        let mut body = vec![0xFE, 0xFD, 5];
        body.extend_from_slice(&hvr.cookie);
        let parsed = parse_hello_verify_request(&body).unwrap();
        assert_eq!(parsed, hvr);
    }

    #[test]
    fn server_hello_parse_extracts_suite_and_random() {
        let mut body = vec![0xFE, 0xFD];
        body.extend_from_slice(&[0x22; 32]); // random
        body.push(0); // session_id len 0
        body.extend_from_slice(&[0x00, 0x9C]); // cipher_suite
        body.push(0); // compression
        let sh = parse_server_hello(&body).unwrap();
        assert_eq!(sh.server_version, 0xFEFD);
        assert_eq!(sh.random, [0x22; 32]);
        assert_eq!(sh.cipher_suite, 0x009C);
        assert_eq!(sh.compression_method, 0);
    }

    #[test]
    fn transcript_uses_whole_message_header() {
        let msg = HandshakeMessage {
            msg_type: 1,
            message_seq: 4,
            body: vec![0xDE, 0xAD],
        };
        let t = transcript_bytes(&msg);
        let hdr = DtlsHandshakeHeader::parse(&t[..DTLS_HANDSHAKE_HEADER_LEN]).unwrap();
        assert_eq!(hdr.fragment_offset, 0);
        assert_eq!(hdr.fragment_length, 2);
        assert_eq!(hdr.length, 2);
        assert_eq!(hdr.message_seq, 4);
        assert_eq!(&t[DTLS_HANDSHAKE_HEADER_LEN..], &[0xDE, 0xAD]);
    }
}
