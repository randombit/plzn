// Integration tests for `plzn::transport`: real TCP sockets, no TLS.
// We spin up a throwaway listener on an ephemeral port, accept one
// connection in a helper thread, and exercise the dialing factory
// against it. This is the minimum needed to convince ourselves the
// trait and the TCP impl hang together end-to-end.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use plzn::transport::{TcpDialFactory, UutFactory, UutTransport};

/// Bind `127.0.0.1:0` to grab an ephemeral port, hand the listener
/// to a worker that runs `serve` on the first accepted connection,
/// and return (addr, join_handle). Each test gets its own listener.
fn spawn_worker<F>(serve: F) -> (SocketAddr, thread::JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        serve(stream);
    });
    (addr, handle)
}

#[test]
fn dial_then_read_then_write_then_close() {
    // Worker: push 13 bytes at us, read back whatever we send, echo
    // it into an mpsc so the test can assert the payload.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let (addr, handle) = spawn_worker(move |mut stream| {
        stream.write_all(b"hello, harness").unwrap();
        let mut echoed = Vec::new();
        // Read until EOF (i.e. until the harness closes its side).
        stream.read_to_end(&mut echoed).unwrap();
        tx.send(echoed).unwrap();
    });

    let factory = TcpDialFactory::new(addr)
        .with_read_timeout(Some(Duration::from_secs(2)))
        .with_write_timeout(Some(Duration::from_secs(2)));
    let mut t: Box<dyn UutTransport> = factory.open().unwrap();

    // Read what the worker sent.
    let mut buf = [0u8; 32];
    let n = t.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello, harness");

    // Write a reply.
    t.write_all(b"ack from harness").unwrap();

    // Close our side — this lets the worker's read_to_end return.
    t.close().unwrap();

    // Worker should see our exact payload.
    let echoed = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(echoed, b"ack from harness");

    handle.join().unwrap();
}

#[test]
fn dial_to_nothing_errors_quickly() {
    // 127.0.0.1 on a port where nothing is listening. We can't bind
    // it first and then free it without race risk, so we bind a
    // throwaway listener to grab a port, immediately drop it, and
    // use that address. On Linux the port will typically be reusable
    // within TIME_WAIT for a Connect attempt, but we don't actually
    // care whether we get ConnectionRefused specifically — we just
    // want to confirm that `open()` fails (any error) within the
    // connect timeout, instead of hanging.
    let throwaway = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = throwaway.local_addr().unwrap();
    drop(throwaway);

    let factory = TcpDialFactory::new(addr).with_connect_timeout(Duration::from_millis(250));

    let start = std::time::Instant::now();
    let result = factory.open();
    let elapsed = start.elapsed();

    assert!(result.is_err(), "expected open() to fail");
    assert!(
        elapsed < Duration::from_secs(2),
        "open() to a dead port took {:?}, should have errored fast",
        elapsed
    );
}

#[test]
fn read_timeout_actually_times_out() {
    // Worker accepts the connection and never writes anything.
    // Our side sets a short read timeout and asserts that `read`
    // returns a timeout error rather than blocking forever.
    let (addr, handle) = spawn_worker(|stream| {
        // Hold the connection open for a beat so the client's read
        // times out against a live socket, not a closed one.
        thread::sleep(Duration::from_millis(500));
        let _ = stream.shutdown(Shutdown::Both);
    });

    let factory = TcpDialFactory::new(addr).with_read_timeout(Some(Duration::from_millis(100)));
    let mut t = factory.open().unwrap();

    let mut buf = [0u8; 8];
    let err = t.read(&mut buf).unwrap_err();
    // std maps SO_RCVTIMEO to either WouldBlock or TimedOut depending
    // on platform. Both are legitimate here.
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "expected WouldBlock or TimedOut, got {:?}",
        err.kind()
    );

    handle.join().unwrap();
}

#[test]
fn description_is_the_peer_address() {
    let (addr, handle) = spawn_worker(|_stream| {});
    let factory = TcpDialFactory::new(addr);
    assert_eq!(factory.description(), format!("tcp://{}", addr));

    let t = factory.open().unwrap();
    assert_eq!(t.description(), format!("tcp://{}", addr));

    handle.join().unwrap();
}
