//! Controllable test shim.
//!
//! Unlike the Botan/OpenSSL/rustls shims, this is NOT a real TLS library: it
//! dials the runner, reads the peer's first TLS record (so the peer has reached
//! the "waiting for a response" state), then performs exactly one action from
//! its config -- send a specific alert, close cleanly, or crash.
//! These are deterministic failure modes a real library will not reliably
//! produce on demand, so the runner's expectation matcher (`expect
//! alert/close/reset/handshake-fails`) and its crash reporting can be
//! unit-tested through the same shim harness as everything else, replacing the
//! old hand-rolled oracles.
//!
//! The `crash_early` / `exit_early` actions fire before dialing the runner, so
//! the runner's "shim exited before connecting" path is exercised too.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use plzn::shim::ShimConfig;

const OK: u8 = 0;
const LOCAL_ERROR: u8 = 10;
const IO_ERROR: u8 = 11;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--plzn-shim-info") {
        println!(r#"{{"protocol":"plzn-shim","protocol_version":1,"name":"mock"}}"#);
        return ExitCode::SUCCESS;
    }
    let mut args = argv.into_iter();
    let mut cfg_path: Option<String> = None;
    while let Some(a) = args.next() {
        if a == "-config" || a == "--config" {
            cfg_path = args.next();
        }
    }
    let cfg_path = match cfg_path {
        Some(p) => p,
        None => {
            eprintln!("usage: mock_shim -config <file.json> | --plzn-shim-info");
            return ExitCode::from(LOCAL_ERROR);
        }
    };

    let cfg: ShimConfig = match std::fs::read_to_string(&cfg_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            report(LOCAL_ERROR, &format!("config error: {}", e));
            return ExitCode::from(LOCAL_ERROR);
        }
    };

    match run(&cfg) {
        Ok(detail) => {
            report(OK, &detail);
            ExitCode::from(OK)
        }
        Err((case, detail)) => {
            report(case, &detail);
            ExitCode::from(case)
        }
    }
}

fn run(cfg: &ShimConfig) -> Result<String, (u8, String)> {
    // Deaths before dialing: the runner must notice these without waiting out
    // its accept deadline.
    match cfg.mock.action.as_str() {
        "crash_early" => std::process::abort(),
        "exit_early" => return Err((LOCAL_ERROR, "mock: exiting before connecting".into())),
        _ => {}
    }

    // Dial the runner and announce our ShimID (8-byte little-endian), same as
    // the real shims.
    let mut sock = TcpStream::connect((cfg.runner.host.as_str(), cfg.runner.port))
        .map_err(|e| (IO_ERROR, format!("connect: {}", e)))?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| (IO_ERROR, format!("set timeout: {}", e)))?;
    sock.write_all(&cfg.shim_id.to_le_bytes())
        .map_err(|e| (IO_ERROR, format!("write shim id: {}", e)))?;

    // Read the peer's first TLS record (5-byte header + body) so it has
    // definitely moved past sending its ClientHello before we act. Best-effort:
    // if the peer sent nothing we still perform the action.
    let _ = read_one_record(&mut sock);

    match cfg.mock.action.as_str() {
        "alert" => {
            // Plaintext alert record: content_type=21, version=0x0303, length=2.
            let alert = [
                0x15,
                0x03,
                0x03,
                0x00,
                0x02,
                cfg.mock.alert_level,
                cfg.mock.alert_code,
            ];
            sock.write_all(&alert)
                .map_err(|e| (IO_ERROR, format!("write alert: {}", e)))?;
            let _ = sock.shutdown(Shutdown::Both);
            Ok(format!(
                "sent alert level={} description={}",
                cfg.mock.alert_level, cfg.mock.alert_code
            ))
        }
        "close" => {
            // Clean TCP FIN, no alert -> the peer's next read is EOF.
            let _ = sock.shutdown(Shutdown::Both);
            Ok("closed without alert".into())
        }
        // Die by SIGABRT after connecting: what a shim linked against a
        // library with a changed ABI does on its first call into it, and what a
        // genuine crash bug provoked by a test looks like from the runner.
        "crash" => std::process::abort(),
        // A "reset" action (abortive RST) would need SO_LINGER(0), which is
        // unstable in std; add it via socket2 if a matcher test needs it. The
        // `reset` expectation is already covered against the real rustls shim.
        other => Err((LOCAL_ERROR, format!("unknown mock.action {:?}", other))),
    }
}

/// Read one TLS record (5-byte header + declared body). Returns Ok(()) even on a
/// short read -- the peer having sent *something* is enough.
fn read_one_record(sock: &mut TcpStream) -> std::io::Result<()> {
    let mut hdr = [0u8; 5];
    sock.read_exact(&mut hdr)?;
    let body_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut body = vec![0u8; body_len];
    sock.read_exact(&mut body)?;
    Ok(())
}

fn report(case: u8, detail: &str) {
    let name = match case {
        OK => "ok",
        LOCAL_ERROR => "local_error",
        IO_ERROR => "io_error",
        _ => "failure",
    };
    eprintln!("PLZN-RESULT case={} detail={}", name, detail);
}
