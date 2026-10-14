//! `recv ... { matchers }` must be enforced by the DTLS drivers exactly as by
//! the TLS drivers. Regression for a bug where both DTLS drivers stored the
//! matchers and never applied them, so a wrong `cipher_suite` or `has_ext`
//! passed silently. Runs the CLI against the Botan shim (DTLS-capable); skipped
//! when the shim is not built.

use plzn::shim::ShimKind;
use std::process::Command;

fn run_case(name: &str, src: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{}.plzn", name));
    std::fs::write(&path, src).expect("write case");
    let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["run", "--shim"])
        .arg(ShimKind::Botan.binary_path().expect("Botan shim path"))
        .arg("-v")
        .arg(&path)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("spawn plzn");
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const CLIENT_SIDE: &str = r#"
plzn tls "dtls-matchers/client-side" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    recv ServerHello { cipher_suite: CIPHER }
    send AppData
    recv AppData
  }
  expect ok
}
"#;

const SERVER_SIDE: &str = r#"
plzn tls "dtls-matchers/server-side" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    recv ClientHello { has_ext: EXT }
    send AppData
    recv AppData
  }
  expect ok
}
"#;

#[test]
fn dtls_client_applies_server_hello_matchers() {
    if ShimKind::Botan.binary_path().is_none() {
        eprintln!("SKIP: botan shim not built");
        return;
    }
    let ok = run_case(
        "sh-right",
        &CLIENT_SIDE.replace("CIPHER", "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    );
    assert!(ok.contains("[PASS]"), "right matcher should pass:\n{}", ok);
    let bad = run_case(
        "sh-wrong",
        &CLIENT_SIDE.replace("CIPHER", "AES_128_GCM_SHA256"),
    );
    assert!(
        bad.contains("[FAIL]"),
        "wrong matcher should fail:\n{}",
        bad
    );
    assert!(
        bad.contains("recv matcher failed: ServerHello.cipher_suite"),
        "failure must name the matcher:\n{}",
        bad
    );
}

#[test]
fn dtls_server_applies_client_hello_matchers() {
    if ShimKind::Botan.binary_path().is_none() {
        eprintln!("SKIP: botan shim not built");
        return;
    }
    // supported_groups is in every ECDHE ClientHello; 0x9999 never is.
    let ok = run_case("ch-right", &SERVER_SIDE.replace("EXT", "supported_groups"));
    assert!(ok.contains("[PASS]"), "right matcher should pass:\n{}", ok);
    let bad = run_case("ch-wrong", &SERVER_SIDE.replace("EXT", "0x9999"));
    assert!(
        bad.contains("[FAIL]"),
        "wrong matcher should fail:\n{}",
        bad
    );
    assert!(
        bad.contains("recv matcher failed: ClientHello.has_ext"),
        "failure must name the matcher:\n{}",
        bad
    );
}

#[test]
fn dtls_server_applies_client_certificate_matchers() {
    if ShimKind::Botan.binary_path().is_none() {
        eprintln!("SKIP: botan shim not built");
        return;
    }
    let source = include_str!("../suite/dtls/dtls12_client_auth_no_cert.plzn");
    let ok = run_case("empty-certificate", source);
    assert!(ok.contains("[PASS]"), "empty certificate flow:\n{ok}");
    for (name, source) in [
        (
            "empty-wrong-count",
            source.replace("entries: 0", "entries: 1"),
        ),
        (
            "nonempty-wrong-count",
            source.replace("client_cert: none", "client_cert: valid"),
        ),
    ] {
        let bad = run_case(name, &source);
        assert!(bad.contains("[FAIL]"), "wrong matcher should fail:\n{bad}");
        assert!(
            bad.contains("recv matcher failed: Certificate.entries"),
            "failure must name the matcher:\n{bad}"
        );
    }
}
