// Transport abstraction: the narrow waist between the runtime (which
// knows TLS and drives a `flow` top-to-bottom) and however we're
// actually talking to the UUT.
//
// Layer: **byte-level**. The runtime owns all TLS framing, record
// construction, encryption, and parsing. The transport's only job is
// to shuttle bytes back and forth and close cleanly. This is what
// lets the DSL do things like `xor[record.aead_tag, $pos] = 0x01` —
// every byte on the wire has to be something we explicitly produced,
// and no layer below us may second-guess it.
//
// Lifecycle: one `UutTransport` per test. A test calls
// `UutFactory::open()` to get a fresh connection, runs its flow,
// then drops it. TLS connections are single-use; reusing them would
// couple tests together. The factory caches nothing by default.
//
// Implementations in this module:
//
//   * `TcpDialFactory` / `TcpTransport` — dials a listening TLS peer
//     on a fixed SocketAddr. Matches the `uut server` case where
//     the harness plays the client and s_server (or equivalent) is
//     already listening on localhost.
//
//   * `MockTransport` — in-memory buffers, for unit-testing the
//     eventual runtime without standing up a real peer. `written()`
//     and `push_incoming()` let a test drive both sides.
//
// Future implementations (not in this wedge):
//
//   * `TcpListenFactory` — `uut client` case; we listen, the UUT
//     dials us.
//   * `InProcessTransport` — same address space as a plzn-aware peer
//     stack for byte-level fidelity + speed. Trade-off noted in
//     `DSL.md §6.3`: memory bugs in the UUT could corrupt us.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ============================== trait ==============================

/// One bidirectional byte pipe to a TLS peer under test.
///
/// Implementations MUST be `Send` so the runtime can move them
/// between threads if needed. We don't require `Sync` because a
/// single connection is only used from one thread at a time.
pub trait UutTransport: Read + Write + Send {
    /// Cleanly close the connection from our side. Further `read` or
    /// `write` calls after `close` may return errors. Dropping also
    /// closes, but `close` gives callers an explicit place to surface
    /// I/O errors that happen at teardown.
    fn close(&mut self) -> io::Result<()>;
    /// T6: abortive close -- send a TCP RST instead of a FIN where the
    /// transport can (SO_LINGER 0); the default is a plain close.
    fn close_reset(&mut self) -> io::Result<()> {
        self.close()
    }

    /// Short human-readable tag for diagnostics. Should name *what*
    /// we're talking to, not *how* — e.g. `tcp://127.0.0.1:4433`
    /// rather than "tcp transport".
    fn description(&self) -> String;

    /// How long a blocking read is allowed to wait for incoming
    /// bytes. `None` = block forever. Default implementations return
    /// `Unsupported`.
    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transport does not support read timeouts",
        ))
    }

    /// Absolute deadline for a composed read operation. Framing adapters also
    /// enforce this between their underlying partial reads.
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        self.set_read_timeout(Some(
            deadline
                .map(|end| {
                    end.saturating_duration_since(std::time::Instant::now())
                        .max(Duration::from_nanos(1))
                })
                .unwrap_or(Duration::from_secs(5)),
        ))
    }

    /// Counterpart to `set_read_timeout` for writes.
    fn set_write_timeout(&mut self, _dur: Option<Duration>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transport does not support write timeouts",
        ))
    }

    /// T1: abortive close (`close reset`): a TCP RST rather than a FIN, so the
    /// peer sees a connection reset with no alert. Transports without a socket
    /// fall back to `close`.
    fn reset(&mut self) -> io::Result<()> {
        self.close()
    }

    /// DTLS packeted-BIO control plane. Stream transports leave these
    /// unsupported; `DtlsFramer` maps them to the P/T/E/U/M protocol.
    fn dtls_advance_clock(&mut self, _nanos: u64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a DTLS transport",
        ))
    }

    fn dtls_expect_next_timeout(&mut self, _nanos: Option<u64>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a DTLS transport",
        ))
    }

    fn dtls_set_timeout(&mut self, _millis: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a DTLS transport",
        ))
    }

    fn dtls_set_mtu(&mut self, _mtu: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a DTLS transport",
        ))
    }

    /// Read one complete datagram from a packeted DTLS transport. This is kept
    /// separate from `Read`, whose byte-stream adapter deliberately hides
    /// packet boundaries from the record codec.
    fn dtls_recv_datagram(&mut self) -> io::Result<Option<Vec<u8>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not a DTLS transport",
        ))
    }
}

/// Factory for fresh `UutTransport`s. The runtime calls `open()`
/// once per test.
pub trait UutFactory: Send + Sync {
    fn open(&self) -> io::Result<Box<dyn UutTransport>>;

    /// Short human-readable tag for diagnostics (mirrors
    /// `UutTransport::description`). The factory's description lands
    /// in suite-level reports before any connection exists.
    fn description(&self) -> String;
}

// =========================== TCP dial impl ==========================

/// Connect-to-localhost style transport. Matches the `uut server`
/// case: something is already listening at `addr` (s_server, nginx,
/// an in-tree UUT-under-test binary) and we dial it at the start of
/// each test.
#[derive(Clone, Debug)]
pub struct TcpDialFactory {
    addr: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    /// Server backend name for per-UUT expect overrides.
    pub peer_name: String,
}

impl TcpDialFactory {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            peer_name: String::new(),
        }
    }

    pub fn with_connect_timeout(mut self, t: Duration) -> Self {
        self.connect_timeout = t;
        self
    }

    pub fn with_read_timeout(mut self, t: Option<Duration>) -> Self {
        self.read_timeout = t;
        self
    }

    pub fn with_write_timeout(mut self, t: Option<Duration>) -> Self {
        self.write_timeout = t;
        self
    }

    pub fn with_peer_name(mut self, name: impl Into<String>) -> Self {
        self.peer_name = name.into();
        self
    }
}

impl UutFactory for TcpDialFactory {
    fn open(&self) -> io::Result<Box<dyn UutTransport>> {
        let stream = TcpStream::connect_timeout(&self.addr, self.connect_timeout)?;
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;
        stream.set_nodelay(true)?;
        Ok(Box::new(TcpTransport {
            stream,
            addr: self.addr,
        }))
    }

    fn description(&self) -> String {
        if self.peer_name.is_empty() {
            format!("tcp://{}", self.addr)
        } else {
            format!("{} ({})", self.peer_name, self.addr)
        }
    }
}

pub struct TcpTransport {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl UutTransport for TcpTransport {
    /// SO_LINGER {on, 0} then close the socket description: the kernel
    /// answers with RST, not FIN (tlsfuzzer's CloseRST). The fd is replaced
    /// by /dev/null via dup2 so the stream's own Drop stays harmless.
    #[cfg(unix)]
    fn close_reset(&mut self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let fd = self.stream.as_raw_fd();
        let l = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: fd is a live socket owned by self.stream; the option struct
        // and its size are the documented SO_LINGER arguments.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &l as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            // Already reset (the descriptor is /dev/null): idempotent.
            if e.raw_os_error() == Some(libc::ENOTSOCK) {
                return Ok(());
            }
            return Err(e);
        }
        let null = std::fs::File::open("/dev/null")?;
        // SAFETY: dup2 atomically closes the socket's open file description
        // held at `fd` (sending the RST) and makes `fd` refer to /dev/null,
        // which the TcpStream's Drop then closes without touching the peer.
        let rc = unsafe { libc::dup2(null.as_raw_fd(), fd) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        // Shutdown::Both maps to a full TCP close (FIN in both
        // directions). Idempotent in the normal case; if the peer
        // already closed we swallow NotConnected.
        match self.stream.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
            // After `close_reset` the descriptor is /dev/null by design (the
            // socket was closed with SO_LINGER 0); a later close is a no-op.
            Err(e) if e.raw_os_error() == Some(libc::ENOTSOCK) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn description(&self) -> String {
        format!("tcp://{}", self.addr)
    }

    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(dur)
    }

    fn reset(&mut self) -> io::Result<()> {
        tcp_reset(&self.stream)
    }
}

/// T1: SO_LINGER with a zero timeout makes the close an abortive one (RST).
#[cfg(unix)]
fn tcp_reset(stream: &TcpStream) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Linger {
        l_onoff: i32,
        l_linger: i32,
    }
    unsafe extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *const std::ffi::c_void,
            len: u32,
        ) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_LINGER: i32 = 13;
    let linger = Linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a well-formed setsockopt(2) call on a socket this process owns,
    // with a pointer to a correctly sized, initialised struct linger.
    let rc = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_LINGER,
            &linger as *const Linger as *const std::ffi::c_void,
            std::mem::size_of::<Linger>() as u32,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    match stream.shutdown(Shutdown::Both) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn tcp_reset(stream: &TcpStream) -> io::Result<()> {
    stream.shutdown(Shutdown::Both)
}

// =========================== TCP listen ============================

impl TcpTransport {
    /// Wrap a pre-accepted TcpStream (from a TcpListener::accept).
    /// Used by TcpListenFactory for the `uut client` path.
    pub fn from_accepted(stream: TcpStream) -> io::Result<Self> {
        let addr = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        Ok(Self { stream, addr })
    }
}

/// Factory for `uut client` mode: listens on a loopback port
/// and accepts one incoming connection per `open()` call.
pub struct TcpListenFactory {
    listener: TcpListener,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    /// Optional backend name folded into `description()` so per-backend `expect
    /// ... if <backend>` overrides can match this factory (e.g. the `openssl
    /// s_client` client runner). Without it the description is just the listener
    /// address and no override matches.
    label: Option<String>,
}

impl TcpListenFactory {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            label: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_timeouts(mut self, read: Option<Duration>, write: Option<Duration>) -> Self {
        self.read_timeout = read;
        self.write_timeout = write;
        self
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

impl UutFactory for TcpListenFactory {
    fn open(&self) -> io::Result<Box<dyn UutTransport>> {
        let (stream, _peer) = self.listener.accept()?;
        stream.set_read_timeout(self.read_timeout)?;
        stream.set_write_timeout(self.write_timeout)?;
        let transport = TcpTransport::from_accepted(stream)?;
        Ok(Box::new(transport))
    }

    fn description(&self) -> String {
        let addr = match self.listener.local_addr() {
            Ok(addr) => format!("tcp-listen://{}", addr),
            Err(_) => "tcp-listen://?".into(),
        };
        match &self.label {
            Some(label) => format!("{} ({})", label, addr),
            None => addr,
        }
    }
}

// ============================== mock ==============================

/// In-memory transport for unit-testing the runtime without a real
/// peer. The test owns the two buffers directly via `Arc<Mutex>`:
///
///   * `incoming` — bytes the transport will hand back from `read`,
///     as if the peer had sent them. Test pushes in, transport pops.
///   * `outgoing` — bytes the runtime wrote to the transport, for the
///     test to inspect afterwards.
///
/// Both are shared via `Arc<Mutex<...>>` so the test can mutate them
/// after handing the transport to the runtime. Closing sets
/// `closed=true`; subsequent reads return 0, writes return BrokenPipe.
#[derive(Clone)]
pub struct MockTransport {
    incoming: Arc<Mutex<Vec<u8>>>,
    outgoing: Arc<Mutex<Vec<u8>>>,
    closed: Arc<Mutex<bool>>,
    tag: String,
}

impl MockTransport {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            incoming: Arc::new(Mutex::new(Vec::new())),
            outgoing: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(Mutex::new(false)),
            tag: tag.into(),
        }
    }

    /// Push bytes that the next `read` call will see.
    pub fn push_incoming(&self, bytes: &[u8]) {
        self.incoming.lock().unwrap().extend_from_slice(bytes);
    }

    /// Snapshot of everything written to the transport so far.
    pub fn written(&self) -> Vec<u8> {
        self.outgoing.lock().unwrap().clone()
    }

    /// Test helper: take (drain) everything written so far.
    pub fn take_written(&self) -> Vec<u8> {
        std::mem::take(&mut *self.outgoing.lock().unwrap())
    }

    pub fn is_closed(&self) -> bool {
        *self.closed.lock().unwrap()
    }
}

impl Read for MockTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if *self.closed.lock().unwrap() {
            return Ok(0);
        }
        let mut inbox = self.incoming.lock().unwrap();
        let n = buf.len().min(inbox.len());
        buf[..n].copy_from_slice(&inbox[..n]);
        inbox.drain(..n);
        Ok(n)
    }
}

impl Write for MockTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if *self.closed.lock().unwrap() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MockTransport is closed",
            ));
        }
        self.outgoing.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl UutTransport for MockTransport {
    fn close(&mut self) -> io::Result<()> {
        *self.closed.lock().unwrap() = true;
        Ok(())
    }

    fn description(&self) -> String {
        format!("mock://{}", self.tag)
    }

    fn set_read_timeout(&mut self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&mut self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

/// Factory wrapping a `MockTransport` so the runtime can request one
/// via `UutFactory::open()`. Each `open()` returns a **clone** —
/// i.e. the Arc-backed buffers are shared with the original, which
/// is what you want in tests.
pub struct MockFactory {
    template: MockTransport,
}

impl MockFactory {
    pub fn new(template: MockTransport) -> Self {
        Self { template }
    }
}

impl UutFactory for MockFactory {
    fn open(&self) -> io::Result<Box<dyn UutTransport>> {
        Ok(Box::new(self.template.clone()))
    }

    fn description(&self) -> String {
        self.template.description()
    }
}

// ============================== tests ==============================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_round_trip() {
        let m = MockTransport::new("unit");
        m.push_incoming(b"hello");

        let mut t: Box<dyn UutTransport> = Box::new(m.clone());
        let mut buf = [0u8; 32];
        let n = t.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        t.write_all(b"world").unwrap();
        assert_eq!(m.written(), b"world");

        t.close().unwrap();
        assert!(m.is_closed());

        // Reads after close return EOF (0).
        let n = t.read(&mut buf).unwrap();
        assert_eq!(n, 0);

        // Writes after close return BrokenPipe.
        let err = t.write_all(b"again").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn mock_factory_shares_buffers() {
        let m = MockTransport::new("shared");
        let f = MockFactory::new(m.clone());

        let mut t = f.open().unwrap();
        t.write_all(b"from runtime").unwrap();
        drop(t);

        assert_eq!(m.written(), b"from runtime");
    }

    #[test]
    fn description_reports_tag() {
        let m = MockTransport::new("unit-42");
        assert_eq!(m.description(), "mock://unit-42");
    }
}
