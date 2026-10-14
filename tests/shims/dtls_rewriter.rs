//! Outgoing DTLS mutations used only by the reassembly test shim.
//!
//! Keep this byte-level implementation independent of plzn's DTLS codec: it
//! supplies the malformed input used to test that codec and its reassembler.

use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Fragment(usize),
    Duplicate,
    OverlapMismatch,
    OffsetOverflow,
    LengthMismatch,
}

impl Mode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value {
            "duplicate" => Ok(Self::Duplicate),
            "overlap_mismatch" => Ok(Self::OverlapMismatch),
            "offset_overflow" => Ok(Self::OffsetOverflow),
            "length_mismatch" => Ok(Self::LengthMismatch),
            _ => value
                .strip_prefix("fragment:")
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| *n > 0)
                .map(Self::Fragment)
                .ok_or_else(|| io::Error::other(format!("unknown test rewrite mode: {value}"))),
        }
    }
}

pub struct Rewriter {
    mode: Mode,
    sequence_offset: u64,
    forged: bool,
    pub changed: bool,
}

impl Rewriter {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            sequence_offset: 0,
            forged: false,
            changed: false,
        }
    }

    pub fn rewrite(&mut self, mut datagram: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while !datagram.is_empty() {
            if datagram.len() < 13 {
                return Err(io::Error::other("truncated backend DTLS record header"));
            }
            let header = &datagram[..13];
            let length = u16::from_be_bytes([header[11], header[12]]) as usize;
            if datagram.len() < 13 + length {
                return Err(io::Error::other("truncated backend DTLS record body"));
            }
            let body = &datagram[13..13 + length];
            // Authenticated records, including their sequence numbers, must
            // remain byte-identical even after earlier plaintext rewrites.
            if header[3..5] != [0, 0] {
                out.extend_from_slice(&datagram[..13 + length]);
            } else {
                let sequence = header[5..11]
                    .iter()
                    .fold(0u64, |seq, byte| (seq << 8) | u64::from(*byte));
                let pieces = if header[0] == 22
                    && body.len() >= 12
                    && be24(&body[9..12]) as usize == body.len() - 12
                {
                    self.rewrite_fragment(body)
                } else {
                    vec![body.to_vec()]
                };
                self.changed |= pieces.len() != 1 || pieces[0] != body;
                for (i, piece) in pieces.iter().enumerate() {
                    out.extend_from_slice(&header[..5]);
                    let seq = sequence + self.sequence_offset + i as u64;
                    out.extend_from_slice(&seq.to_be_bytes()[2..]);
                    out.extend_from_slice(&(piece.len() as u16).to_be_bytes());
                    out.extend_from_slice(piece);
                }
                self.sequence_offset += pieces.len() as u64 - 1;
            }
            datagram = &datagram[13 + length..];
        }
        Ok(out)
    }

    fn rewrite_fragment(&mut self, fragment: &[u8]) -> Vec<Vec<u8>> {
        let data = &fragment[12..];
        let offset = be24(&fragment[6..9]);
        match self.mode {
            Mode::Fragment(size) if data.len() > size => data
                .chunks(size)
                .enumerate()
                .map(|(i, bytes)| piece(fragment, offset + (i * size) as u32, bytes))
                .collect(),
            Mode::Duplicate => vec![fragment.to_vec(), fragment.to_vec()],
            Mode::OverlapMismatch | Mode::OffsetOverflow | Mode::LengthMismatch
                if !self.forged && data.len() >= 2 =>
            {
                self.forged = true;
                let half = data.len() / 2;
                let first = piece(fragment, offset, &data[..half]);
                let mut second = piece(fragment, offset + half as u32, &data[half..]);
                match self.mode {
                    Mode::OverlapMismatch => {
                        let mut flipped = first.clone();
                        flipped[12] ^= 0xff;
                        vec![first, flipped, second]
                    }
                    Mode::OffsetOverflow => {
                        let past_end = be24(&fragment[1..4]) - data.len() as u32 + 1;
                        vec![piece(fragment, past_end, data)]
                    }
                    Mode::LengthMismatch => {
                        put24(&mut second[1..4], be24(&fragment[1..4]) + 1);
                        vec![first, second]
                    }
                    _ => unreachable!(),
                }
            }
            _ => vec![fragment.to_vec()],
        }
    }
}

fn be24(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]])
}

fn put24(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_be_bytes()[1..]);
}

fn piece(original: &[u8], offset: u32, data: &[u8]) -> Vec<u8> {
    let mut out = original[..12].to_vec();
    put24(&mut out[6..9], offset);
    put24(&mut out[9..12], data.len() as u32);
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(sequence: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, sequence];
        out.extend_from_slice(&((12 + data.len()) as u16).to_be_bytes());
        let mut handshake = vec![2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        put24(&mut handshake[1..4], data.len() as u32);
        put24(&mut handshake[9..12], data.len() as u32);
        out.extend(handshake);
        out.extend_from_slice(data);
        out
    }

    fn records(mut datagram: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while !datagram.is_empty() {
            let length = u16::from_be_bytes([datagram[11], datagram[12]]) as usize;
            out.push(&datagram[..13 + length]);
            datagram = &datagram[13 + length..];
        }
        out
    }

    #[test]
    fn fragments_renumber_following_records_across_datagrams() {
        let mut rewriter = Rewriter::new(Mode::Fragment(3));
        let mut input = record(3, &[1, 2, 3, 4, 5, 6, 7]);
        input.extend(record(4, &[]));
        let out = rewriter.rewrite(&input).unwrap();
        let fragments = records(&out);
        assert_eq!(fragments.len(), 4);
        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment[10], 3 + i as u8);
        }
        for (i, fragment) in fragments[..3].iter().enumerate() {
            assert_eq!(be24(&fragment[19..22]), (3 * i) as u32);
            assert_eq!(be24(&fragment[14..17]), 7);
        }
        assert_eq!(&fragments[0][25..], &[1, 2, 3]);
        assert_eq!(&fragments[2][25..], &[7]);
        assert_eq!(rewriter.rewrite(&record(5, &[9])).unwrap()[10], 7);
        assert!(rewriter.changed);
    }

    #[test]
    fn duplicates_preserve_payload_and_leave_encrypted_records_untouched() {
        let mut rewriter = Rewriter::new(Mode::Duplicate);
        let out = rewriter.rewrite(&record(0, &[1, 2, 3])).unwrap();
        let fragments = records(&out);
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0][10], 0);
        assert_eq!(fragments[1][10], 1);
        assert_eq!(&fragments[0][13..], &fragments[1][13..]);
        let mut encrypted = record(9, &[1, 2]);
        encrypted[4] = 1;
        assert_eq!(rewriter.rewrite(&encrypted).unwrap(), encrypted);
    }

    #[test]
    fn malformed_fragments_are_one_shot() {
        let input = record(0, &[10, 20, 30, 40]);
        let mut overlap = Rewriter::new(Mode::OverlapMismatch);
        let out = overlap.rewrite(&input).unwrap();
        let fragments = records(&out);
        assert_eq!(fragments.len(), 3);
        assert_eq!(be24(&fragments[0][19..22]), 0);
        assert_eq!(be24(&fragments[1][19..22]), 0);
        assert_eq!(be24(&fragments[2][19..22]), 2);
        assert_eq!(fragments[1][25], 10 ^ 0xff);
        let next = overlap.rewrite(&record(1, &[1, 2, 3])).unwrap();
        assert_eq!(records(&next).len(), 1);
        assert_eq!(next[10], 3);

        let out = Rewriter::new(Mode::OffsetOverflow).rewrite(&input).unwrap();
        assert_eq!(be24(&out[19..22]), 1);
        assert_eq!(&out[25..], &[10, 20, 30, 40]);

        let out = Rewriter::new(Mode::LengthMismatch).rewrite(&input).unwrap();
        let fragments = records(&out);
        assert_eq!(fragments.len(), 2);
        assert_eq!(be24(&fragments[0][14..17]), 4);
        assert_eq!(be24(&fragments[1][14..17]), 5);
    }

    #[test]
    fn rejects_invalid_test_modes() {
        assert!(Mode::parse("fragment:0").is_err());
        assert!(Mode::parse("bogus").is_err());
    }
}
