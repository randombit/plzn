// Runner-side DTLS datagram framing over the shim byte-stream transport.
//
// The interop shims carry DTLS datagrams over the (reliable) TCP control
// connection using BoGo's framing (see shims/common/shim_socket.cpp and
// shims/DESIGN.md):
//   'P' + u32be len + len bytes   -- one datagram
//   'T' + u64be nanos / 't'       -- advance clock / completion acknowledgement
//   'E' + u64be nanos / 'e'       -- assert next timeout (MAX means none) / ack
//   'U' + u32be millis / 'u'      -- rescale the live timeout / ack
//   'M' + u32be bytes / 'm'       -- change the live path MTU / ack
//   'C' + u8 command              -- a runtime control command (see `control`)
//   'X'                            -- the UUT's retransmission budget expired
//
// `ShimSocket` implements the SHIM side. This is the RUNNER (plzn) side: plzn
// writes 'P' to hand a datagram to the shim, 'T' to advance the shim's
// virtual clock (to fire retransmission timers deterministically) and 'C' to
// change the shim's state mid-flow. It reads 'P' datagrams, command
// acknowledgements, and the structured terminal-timeout marker back.
//
// This framer is transport-agnostic and unit-tested against MockTransport; the
// DTLS record/handshake layers that sit on top are separate pieces.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

use crate::transport::UutTransport;

/// Commands carried by a 'C' control frame. The shim applies them between
/// datagrams; a shim that does not know a command exits with an error.
pub mod control {
    /// The shim server rotates its DTLS cookie secret: every cookie it issued
    /// before this point stops verifying (RFC 6347 4.2.1, "changing the Secret
    /// value frequently"). A client presenting a stale cookie SHOULD be treated
    /// as one with no cookie (a fresh HelloVerifyRequest).
    pub const ROTATE_COOKIE_SECRET: u8 = 1;
}

pub struct DtlsFramer {
    inner: Box<dyn UutTransport>,
    pending_datagrams: VecDeque<Vec<u8>>,
    stream_bytes: VecDeque<u8>,
    read_deadline: Option<std::time::Instant>,
}

impl DtlsFramer {
    pub fn new(inner: Box<dyn UutTransport>) -> Self {
        DtlsFramer {
            inner,
            pending_datagrams: VecDeque::new(),
            stream_bytes: VecDeque::new(),
            read_deadline: None,
        }
    }

    /// Hand one datagram to the shim ('P' frame).
    pub fn send_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        let mut hdr = [0u8; 5];
        hdr[0] = b'P';
        hdr[1..5].copy_from_slice(&(datagram.len() as u32).to_be_bytes());
        self.inner.write_all(&hdr)?;
        if !datagram.is_empty() {
            self.inner.write_all(datagram)?;
        }
        self.inner.flush()
    }

    /// Advance the shim's DTLS retransmit clock by `nanos` ('T' frame), then
    /// wait for its 't' completion acknowledgement. Retransmitted datagrams
    /// emitted while the command runs are buffered for `recv_datagram`.
    pub fn advance_clock(&mut self, nanos: u64) -> io::Result<()> {
        let mut frame = [0u8; 9];
        frame[0] = b'T';
        frame[1..9].copy_from_slice(&nanos.to_be_bytes());
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        self.wait_for_ack(b't', "advance-clock")
    }

    /// Assert the remaining DTLS retransmission timeout. `None` is encoded as
    /// UINT64_MAX and means no timer may be armed.
    pub fn expect_next_timeout(&mut self, nanos: Option<u64>) -> io::Result<()> {
        let mut frame = [0u8; 9];
        frame[0] = b'E';
        frame[1..9].copy_from_slice(&nanos.unwrap_or(u64::MAX).to_be_bytes());
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        self.wait_for_ack(b'e', "timeout assertion")
    }

    /// Rescale the UUT's live retransmission timeout ('U' frame).
    pub fn set_timeout(&mut self, millis: u32) -> io::Result<()> {
        let mut frame = [0u8; 5];
        frame[0] = b'U';
        frame[1..5].copy_from_slice(&millis.to_be_bytes());
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        self.wait_for_ack(b'u', "timeout update")
    }

    /// Change the live DTLS association's path MTU (`M` frame).
    pub fn set_mtu(&mut self, mtu: u32) -> io::Result<()> {
        let mut frame = [0u8; 5];
        frame[0] = b'M';
        frame[1..5].copy_from_slice(&mtu.to_be_bytes());
        self.inner.write_all(&frame)?;
        self.inner.flush()?;
        self.wait_for_ack(b'm', "MTU update")
    }

    /// Send a runtime control command to the shim ('C' frame).
    pub fn send_control(&mut self, command: u8) -> io::Result<()> {
        self.inner.write_all(&[b'C', command])?;
        self.inner.flush()
    }

    /// Read one datagram the shim sent ('P' frame). Returns Ok(None) on EOF.
    pub fn recv_datagram(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(datagram) = self.pending_datagrams.pop_front() {
            return Ok(Some(datagram));
        }
        match self.read_frame()? {
            Some(Frame::Packet(datagram)) => Ok(Some(datagram)),
            Some(Frame::Timeout) => Err(timeout_error()),
            Some(Frame::Ack(opcode)) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected DTLS control acknowledgement '{}'",
                    opcode as char
                ),
            )),
            None => Ok(None),
        }
    }

    fn wait_for_ack(&mut self, expected: u8, operation: &str) -> io::Result<()> {
        loop {
            match self.read_frame()? {
                Some(Frame::Packet(datagram)) => self.pending_datagrams.push_back(datagram),
                Some(Frame::Ack(opcode)) if opcode == expected => return Ok(()),
                Some(Frame::Ack(opcode)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "expected '{}' acknowledgement for {}, got '{}'",
                            expected as char, operation, opcode as char
                        ),
                    ));
                }
                Some(Frame::Timeout) => return Err(timeout_error()),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("shim closed before acknowledging {}", operation),
                    ));
                }
            }
        }
    }

    fn read_frame(&mut self) -> io::Result<Option<Frame>> {
        let mut opcode = [0u8; 1];
        if !self.read_exact_or_eof(&mut opcode)? {
            return Ok(None);
        }
        if matches!(opcode[0], b't' | b'e' | b'u' | b'm') {
            return Ok(Some(Frame::Ack(opcode[0])));
        }
        if opcode[0] == b'X' {
            return Ok(Some(Frame::Timeout));
        }
        if opcode[0] != b'P' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown DTLS frame opcode {}", opcode[0]),
            ));
        }
        let mut len_bytes = [0u8; 4];
        if !self.read_exact_or_eof(&mut len_bytes)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in datagram length",
            ));
        }
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut buf = vec![0u8; len];
        if len > 0 && !self.read_exact_or_eof(&mut buf)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF in datagram body",
            ));
        }
        Ok(Some(Frame::Packet(buf)))
    }

    /// Fill `buf` exactly. Returns Ok(false) if EOF is hit before any byte is
    /// read (clean end), Err on EOF partway through.
    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let mut filled = 0;
        while filled < buf.len() {
            if let Some(deadline) = self.read_deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DTLS read deadline expired",
                    ));
                }
                self.inner.set_read_timeout(Some(remaining))?;
            }
            let n = self.inner.read(&mut buf[filled..])?;
            if n == 0 {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF mid-frame",
                ));
            }
            filled += n;
        }
        Ok(true)
    }

    /// Bound how long `recv_datagram` waits for the next frame. `None` blocks
    /// forever. Used by the post-flow drain to catch a deferred alert.
    pub fn set_read_timeout(&mut self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    pub fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        self.read_deadline = deadline;
        if deadline.is_none() {
            self.inner
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        }
        Ok(())
    }

    pub fn into_inner(self) -> Box<dyn UutTransport> {
        self.inner
    }
}

// Adapter used by the DTLS 1.3 record layer. Each Write is one packeted-BIO
// datagram. Reads expose the packet contents as a byte stream; every DTLS 1.3
// record emitted by plzn carries a length, so the record codec can recover
// boundaries while still allowing several records in one datagram.
impl Read for DtlsFramer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stream_bytes.is_empty() {
            let Some(datagram) = self.recv_datagram()? else {
                return Ok(0);
            };
            self.stream_bytes.extend(datagram);
        }
        let n = buf.len().min(self.stream_bytes.len());
        for dst in &mut buf[..n] {
            *dst = self.stream_bytes.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for DtlsFramer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_datagram(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl UutTransport for DtlsFramer {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        DtlsFramer::set_read_deadline(self, deadline)
    }
    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }

    fn close_reset(&mut self) -> io::Result<()> {
        self.inner.close_reset()
    }

    fn reset(&mut self) -> io::Result<()> {
        self.inner.reset()
    }

    fn description(&self) -> String {
        format!("dtls://{}", self.inner.description())
    }

    fn set_read_timeout(&mut self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    fn set_write_timeout(&mut self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }

    fn dtls_advance_clock(&mut self, nanos: u64) -> io::Result<()> {
        self.advance_clock(nanos)
    }

    fn dtls_expect_next_timeout(&mut self, nanos: Option<u64>) -> io::Result<()> {
        self.expect_next_timeout(nanos)
    }

    fn dtls_set_timeout(&mut self, millis: u32) -> io::Result<()> {
        self.set_timeout(millis)
    }

    fn dtls_set_mtu(&mut self, mtu: u32) -> io::Result<()> {
        self.set_mtu(mtu)
    }

    fn dtls_recv_datagram(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.stream_bytes.is_empty() {
            return Ok(Some(self.stream_bytes.drain(..).collect()));
        }
        self.recv_datagram()
    }
}

enum Frame {
    Packet(Vec<u8>),
    Ack(u8),
    Timeout,
}

#[derive(Debug)]
struct DtlsTimeoutExpired;

impl std::fmt::Display for DtlsTimeoutExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DTLS retransmission timeout expired")
    }
}

impl std::error::Error for DtlsTimeoutExpired {}

fn timeout_error() -> io::Error {
    io::Error::other(DtlsTimeoutExpired)
}

/// Distinguish the shim's explicit terminal-timeout marker from an ordinary
/// socket read deadline, which may also use `io::ErrorKind::TimedOut`.
pub fn is_timeout_error(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|source| source.downcast_ref::<DtlsTimeoutExpired>())
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MockTransport;

    #[test]
    fn send_datagram_frames_with_p_and_be_len() {
        let mock = MockTransport::new("dtls");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.send_datagram(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let w = mock.written();
        assert_eq!(w[0], b'P');
        assert_eq!(&w[1..5], &[0, 0, 0, 4]);
        assert_eq!(&w[5..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn empty_datagram_has_zero_length_and_no_body() {
        let mock = MockTransport::new("dtls");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.send_datagram(&[]).unwrap();
        assert_eq!(mock.written(), vec![b'P', 0, 0, 0, 0]);
    }

    #[test]
    fn advance_clock_frames_with_t_and_be_nanos() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(b"t");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.advance_clock(0x0102_0304_0506_0708).unwrap();
        let w = mock.written();
        assert_eq!(w[0], b'T');
        assert_eq!(&w[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn timeout_controls_use_bogo_opcodes_and_wait_for_acks() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(b"eu");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.expect_next_timeout(Some(42)).unwrap();
        framer.set_timeout(250).unwrap();
        let w = mock.written();
        assert_eq!(&w[..9], &[b'E', 0, 0, 0, 0, 0, 0, 0, 42]);
        assert_eq!(&w[9..], &[b'U', 0, 0, 0, 250]);
    }

    #[test]
    fn no_timeout_uses_u64_max() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(b"e");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.expect_next_timeout(None).unwrap();
        assert_eq!(&mock.written()[1..9], &u64::MAX.to_be_bytes());
    }

    #[test]
    fn advance_buffers_packets_emitted_before_ack() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(&[b'P', 0, 0, 0, 2, 0xAA, 0xBB, b't']);
        let mut framer = DtlsFramer::new(Box::new(mock));
        framer.advance_clock(1).unwrap();
        assert_eq!(framer.recv_datagram().unwrap(), Some(vec![0xAA, 0xBB]));
    }

    #[test]
    fn terminal_timeout_is_structured_io_error() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(b"X");
        let mut framer = DtlsFramer::new(Box::new(mock));
        let err = framer.advance_clock(1).unwrap_err();
        assert!(is_timeout_error(&err));
    }

    #[test]
    fn send_control_frames_with_c_and_command() {
        let mock = MockTransport::new("dtls");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        framer.send_control(control::ROTATE_COOKIE_SECRET).unwrap();
        assert_eq!(mock.written(), vec![b'C', 1]);
    }

    #[test]
    fn recv_datagram_reads_p_frame() {
        let mock = MockTransport::new("dtls");
        // Simulate the shim sending a 'P' frame of 3 bytes.
        mock.push_incoming(&[b'P', 0, 0, 0, 3, 0xAA, 0xBB, 0xCC]);
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        let dg = framer.recv_datagram().unwrap().unwrap();
        assert_eq!(dg, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn recv_datagram_eof_returns_none() {
        let mock = MockTransport::new("dtls");
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        assert!(framer.recv_datagram().unwrap().is_none());
    }

    #[test]
    fn recv_rejects_unknown_opcode() {
        let mock = MockTransport::new("dtls");
        mock.push_incoming(&[b'X', 0, 0, 0, 0]);
        let mut framer = DtlsFramer::new(Box::new(mock.clone()));
        assert!(framer.recv_datagram().is_err());
    }

    #[test]
    fn round_trip_send_then_readback() {
        // Write a datagram, then read the same bytes back through a fresh framer
        // over the same buffers (outgoing of one side = incoming of the other).
        let mock = MockTransport::new("dtls");
        let mut tx = DtlsFramer::new(Box::new(mock.clone()));
        tx.send_datagram(&[1, 2, 3]).unwrap();
        mock.push_incoming(b"t");
        tx.advance_clock(42).unwrap();
        tx.send_datagram(&[9]).unwrap();

        // Feed what was written back in as incoming, and parse only the 'P'
        // frames (skipping the 'T' would require peeking; here we assert the
        // wire bytes directly instead).
        let w = mock.written();
        // First frame: P/3
        assert_eq!(&w[0..5], &[b'P', 0, 0, 0, 3]);
        assert_eq!(&w[5..8], &[1, 2, 3]);
        // Then T/42
        assert_eq!(w[8], b'T');
        assert_eq!(&w[9..17], &42u64.to_be_bytes());
        // Then P/1
        assert_eq!(&w[17..22], &[b'P', 0, 0, 0, 1]);
        assert_eq!(w[22], 9);
    }
}
