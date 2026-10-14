use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;

use plzn::server::certs::{CertBundle, KeyType};
use plzn::tls::server12::{Tls12Server, Tls12ServerConfig};
use plzn::transport::TcpTransport;

fn plzn() -> Command {
    Command::new(env!("CARGO_BIN_EXE_plzn"))
}

#[test]
fn run_and_dial_have_distinct_backend_options() {
    let run = plzn()
        .args(["run", "--addr", "127.0.0.1:4433", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(run.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&run.stderr).contains("plzn run: unknown flag \"--addr\""));

    let dial = plzn()
        .args(["dial", "--shim", "some-shim", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(dial.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&dial.stderr).contains("plzn dial: unknown flag \"--shim\""));

    let pcap = plzn()
        .args(["run", "--pcap", "trace.pcap", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(pcap.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&pcap.stderr).contains("plzn run: unknown flag \"--pcap\""));
}

#[test]
fn dial_requires_a_valid_address() {
    let missing = plzn()
        .args(["dial", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing.stderr)
            .contains("plzn dial: no address selected. Use --addr HOST:PORT.")
    );

    let invalid = plzn()
        .args(["dial", "--addr", "not-an-address", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&invalid.stderr)
            .contains("plzn dial: invalid --addr \"not-an-address\"")
    );

    let no_shim = plzn()
        .args(["run", "missing.plzn"])
        .output()
        .expect("run plzn");
    assert_eq!(no_shim.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&no_shim.stderr)
            .contains("plzn run: no shim selected. Use --shim PATH.")
    );
}

#[test]
fn dial_rejects_client_uuts_without_connecting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let case = dir.path().join("client.plzn");
    std::fs::write(
        &case,
        r#"plzn tls "dial/client-role" {
  chain: [default]
  uut client { versions: [tls12] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    )
    .expect("write case");

    let output = plzn()
        .args(["dial", "--addr", "127.0.0.1:1"])
        .arg(&case)
        .output()
        .expect("run plzn");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("`plzn dial` only supports `uut server`")
    );
}

#[test]
fn dial_runs_a_server_test_and_writes_a_capture() {
    let bundle = CertBundle::generate(KeyType::EcdsaP256).expect("certificate");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let addr = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        let transport = TcpTransport::from_accepted(stream).expect("transport");
        let config = Tls12ServerConfig {
            version: plzn::tls::record::TlsVersion::Tls12,
            cert_der: bundle.cert_der,
            private_key_der: bundle.key_pkcs8_der,
            chains: Vec::new(),
            seed: [0xd1; 32],
            send_overrides: Vec::new(),
            recv_matchers: Vec::new(),
            send_mutations: Vec::new(),
            send_ext_deltas: Vec::new(),
            cipher_suites: Vec::new(),
            groups: Vec::new(),
            signature_schemes: Vec::new(),
            psk: None,
            cert_request_authorities: Vec::new(),
            resumption: None,
            force_resumption: false,
            issue_tickets: false,
            offer_raw_public_key: false,
        };
        let mut server = Tls12Server::new(Box::new(transport), config);
        server.do_handshake().expect("handshake");
        assert_eq!(server.read_app_data().expect("request").len(), 32);
        server.write_app_data(&[0x5a; 32], &[]).expect("response");
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let case = dir.path().join("dial.plzn");
    let capture = dir.path().join("dial.pcap");
    std::fs::write(
        &case,
        r#"plzn tls "dial/tls12-appdata" {
  chain: [default]
  uut server { versions: [tls12] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    )
    .expect("write case");

    let output = plzn()
        .args(["dial", "--addr"])
        .arg(addr.to_string())
        .args(["--pcap"])
        .arg(&capture)
        .arg(&case)
        .output()
        .expect("run plzn");
    server.join().expect("server thread");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("[PASS] dial/tls12-appdata"), "{stdout}");
    assert!(stderr.contains(&format!("[dial] tcp://{addr}")), "{stderr}");
    assert!(capture.metadata().expect("capture metadata").len() > 24);
}
