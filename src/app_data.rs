//! Tiny application protocol used between plzn and its shims.
//!
//! A request is exactly the DSL-declared plaintext size. For requests of at
//! least twelve bytes, the first twelve are `PLZN`, the total request size,
//! and the requested reply size (both big-endian u32); the remainder is
//! deterministic random test data. A zero reply size means no answer.

use rand_core::RngCore;

pub const MAGIC: &[u8; 4] = b"PLZN";
pub const HEADER_LEN: usize = 12;
pub const DEFAULT_SIZE: usize = 32;
pub const MAX_SIZE: usize = 1 << 20;

pub fn request(rng: &mut impl RngCore, size: usize, reply_size: Option<usize>) -> Vec<u8> {
    let mut out = vec![0u8; size];
    rng.fill_bytes(&mut out);

    // A sub-header-sized request can only ask for the historical same-size
    // response. Keep it unframed and avoid a partial magic prefix so
    // the incremental responder can recognize it immediately.
    if size < HEADER_LEN {
        if out.first() == Some(&MAGIC[0]) {
            out[0] ^= 0x80;
        }
        return out;
    }

    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4..8].copy_from_slice(&(size as u32).to_be_bytes());
    header[8..12].copy_from_slice(&(reply_size.unwrap_or(0) as u32).to_be_bytes());
    out[..HEADER_LEN].copy_from_slice(&header);
    out
}

/// Incremental parser exported for the standalone rustls shim. The C++ shims
/// use the matching implementation in `shims/common/app_data_protocol.*`.
#[derive(Default)]
pub struct Responder {
    pending: Vec<u8>,
}

impl Responder {
    pub fn receive(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.pending.extend_from_slice(data);
        let mut replies = Vec::new();

        loop {
            if self.pending.is_empty() {
                break;
            }
            let prefix = self.pending.len().min(MAGIC.len());
            if self.pending[..prefix] != MAGIC[..prefix] {
                // Compatibility for callers outside the DSL: retain the old
                // verbatim echo behaviour for an unframed payload.
                replies.push(std::mem::take(&mut self.pending));
                break;
            }
            if self.pending.len() < HEADER_LEN {
                break;
            }

            let request_size = u32::from_be_bytes(self.pending[4..8].try_into().unwrap()) as usize;
            let reply_size = u32::from_be_bytes(self.pending[8..12].try_into().unwrap()) as usize;
            if !(HEADER_LEN..=MAX_SIZE).contains(&request_size) || reply_size > MAX_SIZE {
                replies.push(std::mem::take(&mut self.pending));
                break;
            }
            if self.pending.len() < request_size {
                break;
            }

            let request: Vec<u8> = self.pending.drain(..request_size).collect();
            if reply_size != 0 {
                replies.push(random_reply(&request, reply_size));
            }
        }
        replies
    }
}

fn random_reply(request: &[u8], size: usize) -> Vec<u8> {
    // FNV-1a folds the random request into a seed, then xorshift64 supplies an
    // inexpensive deterministic byte stream. These are test bytes, not keys.
    let mut state = 0xcbf29ce484222325u64;
    for byte in request {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }
    if state == 0 {
        state = 0x9e3779b97f4a7c15;
    }
    let mut out = vec![0u8; size];
    for byte in &mut out {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn request_size_includes_the_header() {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let got = request(&mut rng, 16_385, Some(47));
        assert_eq!(got.len(), 16_385);
        assert_eq!(&got[..4], MAGIC);
        assert_eq!(u32::from_be_bytes(got[4..8].try_into().unwrap()), 16_385);
        assert_eq!(u32::from_be_bytes(got[8..12].try_into().unwrap()), 47);
    }

    #[test]
    fn responder_reassembles_and_honours_reply_lengths() {
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let a = request(&mut rng, 32, Some(19));
        let b = request(&mut rng, 24, Some(7));
        let mut responder = Responder::default();
        assert!(responder.receive(&a[..5]).is_empty());
        let mut rest = a[5..].to_vec();
        rest.extend_from_slice(&b);
        let replies = responder.receive(&rest);
        assert_eq!(replies.iter().map(Vec::len).collect::<Vec<_>>(), [19, 7]);
        assert_ne!(replies[0], vec![0; 19]);
    }

    #[test]
    fn unframed_data_keeps_legacy_echo_behaviour() {
        let mut responder = Responder::default();
        assert_eq!(responder.receive(b"legacy"), [b"legacy".to_vec()]);
    }
}
