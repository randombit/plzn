//! Test-only shim which rewrites a real shim's outgoing DTLS datagrams.
//!
//! Backend selection and mutations come from the integration test's environment,
//! never from the public DSL or shim configuration. The backend receives an
//! ordinary config and its stdout, stderr, and exit status remain observable.

mod dtls_rewriter;

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Command, ExitCode, ExitStatus};
use std::time::{Duration, Instant};

use dtls_rewriter::{Mode, Rewriter};

const TIMEOUT: Duration = Duration::from_secs(10);

struct Backend(Child);

impl Backend {
    fn wait(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("test backend did not exit"));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        // Also clean up if setup or forwarding fails before wait().
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--plzn-shim-info"] {
        println!(r#"{{"protocol":"plzn-shim","protocol_version":1,"name":"dtls-test"}}"#);
        return ExitCode::SUCCESS;
    }
    let result = match args.as_slice() {
        [flag, path] if flag == "-config" || flag == "--config" => run(path),
        _ => Err(io::Error::other("usage: dtls_test_shim -config <file>")),
    };
    match result {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from(code as u8),
            None => {
                eprintln!("PLZN-RESULT case=local_error detail=test backend {status}");
                ExitCode::from(10)
            }
        },
        Err(error) => {
            eprintln!("PLZN-RESULT case=local_error detail=DTLS test shim: {error}");
            ExitCode::from(10)
        }
    }
}

fn run(path: &str) -> io::Result<ExitStatus> {
    let backend_path = std::env::var_os("PLZN_TEST_DTLS_BACKEND")
        .ok_or_else(|| io::Error::other("missing PLZN_TEST_DTLS_BACKEND"))?;
    let mode = std::env::var("PLZN_TEST_DTLS_REWRITE").map_err(io::Error::other)?;
    let mut rewriter = Rewriter::new(Mode::parse(&mode)?);
    let mut config: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if config["protocol"] != "dtls" || config["resume_count"].as_u64().unwrap_or(0) != 0 {
        return Err(io::Error::other(
            "test shim requires a single DTLS connection",
        ));
    }
    let host = config["runner"]["host"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing runner host"))?
        .to_owned();
    let port = config["runner"]["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| io::Error::other("invalid runner port"))?;

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    config["runner"] = serde_json::json!({
        "host": "127.0.0.1",
        "port": listener.local_addr()?.port(),
        "ipv6": false,
    });
    let mut config_file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&mut config_file, &config)?;
    config_file.flush()?;
    let mut child = Backend(
        Command::new(backend_path)
            .arg("-config")
            .arg(config_file.path())
            .spawn()?,
    );
    let deadline = Instant::now() + TIMEOUT;
    let mut backend = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(status) = child.0.try_wait()? {
                    return Err(io::Error::other(format!(
                        "test backend exited before connecting: {status}"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other("test backend did not connect"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    };
    let mut runner = TcpStream::connect((host.as_str(), port))?;
    for socket in [&backend, &runner] {
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
    }
    let mut shim_id = [0; 8];
    backend.read_exact(&mut shim_id)?;
    runner.write_all(&shim_id)?;

    let mut from_runner = runner.try_clone()?;
    let mut to_backend = backend.try_clone()?;
    std::thread::scope(|scope| -> io::Result<()> {
        let inbound = scope.spawn(move || {
            let result = io::copy(&mut from_runner, &mut to_backend);
            let _ = to_backend.shutdown(Shutdown::Write);
            result
        });
        let result = forward_rewritten(&mut backend, &mut runner, &mut rewriter);
        let _ = backend.shutdown(Shutdown::Both);
        let _ = runner.shutdown(Shutdown::Both);
        let inbound_result = inbound
            .join()
            .map_err(|_| io::Error::other("test relay thread panicked"))?;
        result?;
        // The runner may close immediately after observing the expected alert.
        if let Err(error) = inbound_result {
            if !matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ) {
                return Err(error);
            }
        }
        Ok(())
    })?;
    let status = child.wait()?;
    if !rewriter.changed {
        return Err(io::Error::other(
            "configured test rewrite was never applied",
        ));
    }
    Ok(status)
}

fn forward_rewritten(
    backend: &mut TcpStream,
    runner: &mut TcpStream,
    rewriter: &mut Rewriter,
) -> io::Result<()> {
    let mut opcode = [0];
    while backend.read(&mut opcode)? != 0 {
        match opcode[0] {
            b'P' => {
                let mut length = [0; 4];
                backend.read_exact(&mut length)?;
                let length = u32::from_be_bytes(length) as usize;
                if length > 1 << 20 {
                    return Err(io::Error::other("oversized backend datagram"));
                }
                let mut packet = vec![0; length];
                backend.read_exact(&mut packet)?;
                let packet = rewriter.rewrite(&packet)?;
                runner.write_all(b"P")?;
                runner.write_all(&(packet.len() as u32).to_be_bytes())?;
                runner.write_all(&packet)?;
            }
            b't' | b'e' | b'u' | b'm' | b'X' => runner.write_all(&opcode)?,
            other => {
                return Err(io::Error::other(format!(
                    "unexpected backend DTLS opcode {other}"
                )));
            }
        }
    }
    Ok(())
}
