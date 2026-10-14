// Integration test: drive plzn's own TLS stack against real TLS libraries
// through the config-file shims in `shims/`.
//
// This is the payoff of the shim architecture: plzn (the adversarial runner)
// interoperates with a real UUT built from the library under test, coordinated
// entirely by a JSON config file. The shim self-checks its expectations and
// exits non-zero on mismatch; the runner independently classifies the flow.
//
// Each case is skipped (not failed) when the shim binary is absent, so the
// suite stays green on machines that have not built shims/. Build them with:
//   make -C shims botan            (needs PLZN_BOTAN_ROOT or system Botan)
//   make -C shims openssl
//   make -C shims libressl gnutls wolfssl go

use std::path::PathBuf;

use plzn::runtime::{RunError, RunStatus, run, run_sessions};
use plzn::shim::{Credentials, Expectations, ShimConfig, ShimFactory, ShimKind, ShimResultCase};

fn testdata(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("shims")
        .join("testdata")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn lower_source(name: &str, source: &str) -> plzn::ir::Program {
    let tokens = plzn::lex::lex(source).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let errs = plzn::check::check(&file);
    assert!(errs.is_empty(), "{} schema errors: {:?}", name, errs);
    let mut programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    programs.remove(0)
}

const TLS12_SERVER: &str = r#"
plzn tls "shim/tls12-server" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_SERVER: &str = r#"
plzn tls "shim/tls13-server" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData { size: 37, reply: 91 }
    recv AppData
    send AppData { size: 16384, reply: 33 }
    recv AppData
    send AppData { size: 24, reply: none }
    close
  }
  expect ok
}
"#;

// role=server config: plzn plays the client, the shim plays the TLS server.
fn server_config(version: u16) -> ShimConfig {
    ShimConfig {
        role: "server".into(),
        min_version: Some(version),
        max_version: Some(version),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(version),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn run_case(kind: ShimKind, source_name: &str, source: &str, version: u16) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", source_name, kind.label());
        return;
    }
    let program = lower_source(source_name, source);
    let factory = ShimFactory::new(kind, server_config(version)).expect("shim factory");

    let report = run(&program, &factory, [0x21; 32], None);
    let shim = factory.wait_shim().expect("reap shim");

    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner status: {}",
        source_name,
        report.observed
    );
    assert!(
        shim.success,
        "{} shim reported failure (code {:?})",
        source_name, shim.code
    );
    assert!(
        shim.stdout.is_empty(),
        "{} emitted unexpected stdout: {:?}",
        source_name,
        shim.stdout
    );
}

// Multi-cert selection (BoGo certificate-selection / RFC 8446 4.4.2-4.4.3): the shim SERVER holds
// BOTH an RSA cert (cert_file) and an ECDSA cert (second_cert_file) and must select by the
// client's signature_algorithms. plzn advertises exactly ONE scheme via client_signature_schemes,
// so the server must present the matching cert. Verification rides plzn's RFC 8446 4.4.3
// offered-check: had the server presented the OTHER cert, its CertVerify would use a scheme plzn
// did not offer and plzn would reject -- so `expect ok` PROVES selection by the client's sig algs.
const TLS13_MULTICERT: &str = r#"
plzn tls "shim/tls13-multicert-select" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_multicert_select(kind: ShimKind, offer_scheme: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP multicert-select: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("multicert-select", TLS13_MULTICERT);
    // Offer exactly one signature scheme; the server must pick the cert that can sign with it.
    program.client_signature_schemes = Some(vec![offer_scheme]);

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            second_cert_file: testdata("ec_cert.pem"),
            second_key_file: testdata("ec_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "multicert-select runner: {}",
        report.observed
    );
    assert!(shim.success, "multicert-select shim (code {:?})", shim.code);
}

#[test]
fn openssl_shim_tls13_multicert_select_ecdsa() {
    run_multicert_select(ShimKind::OpenSsl, 0x0403, 0xf0); // offer ecdsa_secp256r1_sha256 only
}

#[test]
fn openssl_shim_tls13_multicert_select_rsa() {
    run_multicert_select(ShimKind::OpenSsl, 0x0804, 0xf1); // offer rsa_pss_rsae_sha256 only
}

#[test]
fn botan_shim_tls13_multicert_select_ecdsa() {
    run_multicert_select(ShimKind::Botan, 0x0403, 0xf2);
}

#[test]
fn botan_shim_tls13_multicert_select_rsa() {
    run_multicert_select(ShimKind::Botan, 0x0804, 0xf3);
}

#[test]
fn rustls_shim_tls13_multicert_select_ecdsa() {
    run_multicert_select(ShimKind::Rustls, 0x0403, 0xf4);
}

#[test]
fn rustls_shim_tls13_multicert_select_rsa() {
    run_multicert_select(ShimKind::Rustls, 0x0804, 0xf5);
}

#[test]
fn go_shim_tls13_multicert_select_ecdsa() {
    run_multicert_select(ShimKind::Go, 0x0403, 0xf6);
}

#[test]
fn go_shim_tls13_multicert_select_rsa() {
    run_multicert_select(ShimKind::Go, 0x0804, 0xf7);
}

// ALPN, server selects an UNOFFERED protocol (RFC 7301 3.2): the shim CLIENT advertises
// ["h2","http/1.1"], but plzn's server picks "bogus" in EncryptedExtensions -- a protocol the
// client never offered. RFC 7301: the server "MUST select a protocol from [the client's] list",
// so a conformant client MUST reject the handshake.
const TLS13_CLIENT_REJECT_UNOFFERED_ALPN: &str = r#"
plzn tls "shim/tls13-client-reject-unoffered-alpn" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext alpn = raw "000605626f677573" }
  }
  expect handshake-fails
}
"#;

fn run_client_reject_unoffered_alpn(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-reject-unoffered-alpn: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source(
        "client-reject-unoffered-alpn",
        TLS13_CLIENT_REJECT_UNOFFERED_ALPN,
    );
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        alpn: plzn::shim::AlpnConfig {
            advertise: vec!["h2".into(), "http/1.1".into()],
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-reject-unoffered-alpn runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-reject-unoffered-alpn shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_reject_unoffered_alpn() {
    run_client_reject_unoffered_alpn(ShimKind::Botan, 0x91);
}

#[test]
fn openssl_shim_tls13_client_reject_unoffered_alpn() {
    run_client_reject_unoffered_alpn(ShimKind::OpenSsl, 0x92);
}

#[test]
fn rustls_shim_tls13_client_reject_unoffered_alpn() {
    run_client_reject_unoffered_alpn(ShimKind::Rustls, 0x93);
}

// Structured shim error cases (BoGo-style): the shim reports WHICH failure path it
// took via its exit code, surfaced as ShimOutcome.case, so the runner can assert on
// the failure category rather than only the wire alert. Cross-library.
const STRUCTURED_FLOW: &str = r#"
plzn tls "shim/structured" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_structured_cases(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP structured-cases: {} binary not built", kind.label());
        return;
    }

    // 1. Happy handshake, expectation matches -> Ok.
    {
        let program = lower_source("structured-ok", STRUCTURED_FLOW);
        let factory = ShimFactory::new(kind, server_config(0x0304)).expect("factory");
        let _ = run(&program, &factory, [0x60; 32], None);
        let shim = factory.wait_shim().expect("reap");
        assert_eq!(
            shim.case,
            ShimResultCase::Ok,
            "{}: happy handshake -> Ok",
            kind.label()
        );
    }

    // 2. Handshake completes but the shim's configured expect.version is wrong, so
    //    its self-check fails -> ExpectationMismatch.
    {
        let program = lower_source("structured-mismatch", STRUCTURED_FLOW);
        let mut cfg = server_config(0x0304);
        cfg.expect.version = Some(0x0303); // force TLS 1.3 but expect TLS 1.2
        let factory = ShimFactory::new(kind, cfg).expect("factory");
        let _ = run(&program, &factory, [0x61; 32], None);
        let shim = factory.wait_shim().expect("reap");
        assert_eq!(
            shim.case,
            ShimResultCase::ExpectationMismatch,
            "{}: wrong expect.version -> ExpectationMismatch",
            kind.label()
        );
    }

    // 3. No common version (shim capped at TLS 1.2, plzn offers only TLS 1.3) ->
    //    the handshake fails in the library -> HandshakeFailed.
    {
        let program = lower_source("structured-hsfail", STRUCTURED_FLOW);
        let mut cfg = server_config(0x0304);
        cfg.min_version = Some(0x0303);
        cfg.max_version = Some(0x0303);
        cfg.expect.version = None;
        let factory = ShimFactory::new(kind, cfg).expect("factory");
        let _ = run(&program, &factory, [0x62; 32], None);
        let shim = factory.wait_shim().expect("reap");
        assert_eq!(
            shim.case,
            ShimResultCase::HandshakeFailed,
            "{}: no common version -> HandshakeFailed",
            kind.label()
        );
    }

    // 4. Same no-common-version failure, but now the shim is TOLD to expect the
    //    handshake to fail. It reports Ok (the expectation was met) BUT still carries
    //    the library's reason in `detail`, so the runner learns WHICH failure path was
    //    taken, not just that one was. (This is the BoGo-style per-case granularity.)
    {
        let program = lower_source("structured-expected-fail", STRUCTURED_FLOW);
        let mut cfg = server_config(0x0304);
        cfg.min_version = Some(0x0303);
        cfg.max_version = Some(0x0303);
        cfg.expect.version = None;
        cfg.expect.handshake_error = Some(String::new());
        let factory = ShimFactory::new(kind, cfg).expect("factory");
        let _ = run(&program, &factory, [0x63; 32], None);
        let shim = factory.wait_shim().expect("reap");
        assert_eq!(
            shim.case,
            ShimResultCase::Ok,
            "{}: expected handshake failure -> Ok",
            kind.label()
        );
        let detail = shim.detail.unwrap_or_default();
        assert!(
            !detail.is_empty(),
            "{}: expected-failure detail should carry the reason, got empty",
            kind.label()
        );
    }
}

#[test]
fn botan_shim_structured_error_cases() {
    run_structured_cases(ShimKind::Botan);
}

#[test]
fn openssl_shim_structured_error_cases() {
    run_structured_cases(ShimKind::OpenSsl);
}

#[test]
fn libressl_shim_structured_error_cases() {
    run_structured_cases(ShimKind::LibreSsl);
}

#[test]
fn gnutls_shim_structured_error_cases() {
    run_structured_cases(ShimKind::GnuTls);
}

#[test]
fn wolfssl_shim_structured_error_cases() {
    run_structured_cases(ShimKind::WolfSsl);
}

#[test]
fn go_shim_structured_error_cases() {
    run_structured_cases(ShimKind::Go);
}

// Matcher self-test: a `recv ServerHello { legacy_version: 0x0304 }` matcher against
// a real shim server (which sends the RFC-mandated 0x0303) must surface a clean
// ExpectationMismatch naming both the expected and observed values. This is a
// RUNNER-side assertion (plzn's matcher), so one backend suffices; it replaces the
// old overrides/matcher_mismatch.plzn integration test, which by design could never
// "pass" and so could not live in the pass-asserting shim corpus.
const MATCHER_MISMATCH_FLOW: &str = r#"
plzn tls "shim/matcher-mismatch" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    recv ServerHello { legacy_version: 0x0304 }
    send AppData
    recv AppData
  }
  expect ok
}
"#;

#[test]
fn matcher_mismatch_reports_expected_and_observed() {
    let kind = ShimKind::Botan;
    if kind.binary_path().is_none() {
        eprintln!("SKIP matcher-mismatch: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("matcher-mismatch", MATCHER_MISMATCH_FLOW);
    let factory = ShimFactory::new(kind, server_config(0x0303)).expect("factory");
    let report = run(&program, &factory, [0x66; 32], None);
    let _ = factory.wait_shim();
    assert!(!report.status.is_pass());
    match &report.status {
        RunStatus::Fail(RunError::ExpectationMismatch { observed, .. }) => {
            assert!(
                observed.contains("ServerHello.legacy_version"),
                "observed should name the field: {}",
                observed
            );
            assert!(
                observed.contains("0x0304") && observed.contains("0x0303"),
                "observed should show both expected and observed values: {}",
                observed
            );
        }
        other => panic!("expected an ExpectationMismatch, got: {:?}", other),
    }
}

// TLS 1.3 downgrade sentinel, SERVER side (RFC 8446 4.1.3): a TLS 1.3-capable
// server that negotiates TLS 1.2 MUST set the last 8 bytes of ServerHello.random
// to 44 4F 57 4E 47 52 44 01. Here the shim is 1.3-capable (min 1.2, max 1.3) but
// the plzn client offers only 1.2, so the server negotiates 1.2 and must stamp the
// sentinel; the client asserts it via the random_suffix matcher. Cross-library.
const DOWNGRADE_SENTINEL: &str = r#"
plzn tls "shim/tls12-downgrade-sentinel" {
  rfc 8446 section 4.1.3
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    recv ServerHello {
      random_suffix: [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01]
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_downgrade_sentinel(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP downgrade-sentinel: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls12-downgrade-sentinel", DOWNGRADE_SENTINEL);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303), // 1.3-capable server (1.2 .. 1.3) ...
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0303),
            ..Default::default()
        }, // ... negotiates 1.2
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x63; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{}: server must stamp the downgrade sentinel: {}",
        kind.label(),
        report.observed
    );
    assert!(
        shim.success,
        "{} shim reported failure (code {:?})",
        kind.label(),
        shim.code
    );
}

#[test]
fn botan_shim_tls12_downgrade_sentinel() {
    run_downgrade_sentinel(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls12_downgrade_sentinel() {
    run_downgrade_sentinel(ShimKind::OpenSsl);
}

#[test]
fn rustls_shim_tls12_downgrade_sentinel() {
    run_downgrade_sentinel(ShimKind::Rustls);
}

// Ed25519 server certificate (shim as server). The client advertises the ed25519
// signature scheme; the server signs its CertificateVerify with its Ed25519 key and
// plzn's client verifies it (id-Ed25519 SPKI parse, RFC 8410 + RFC 8032). The cert
// is openssl-generated (checked into testdata).
//
// OpenSSL ONLY: Botan deliberately does not support Ed25519 for certificate
// authentication -- Signature_Scheme::all_available_schemes() has EDDSA_25519
// commented out (botan PR #2958). So this is a genuine library difference: OpenSSL
// accepts an Ed25519 server cert, Botan cannot present one at all. plzn's own client
// verifier DOES support Ed25519 (see crypto::tests::ed25519_round_trip).
const TLS13_ED25519: &str = r#"
plzn tls "shim/tls13-ed25519" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext signature_algorithms = [ed25519]
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_ed25519_case(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP ed25519: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-ed25519", TLS13_ED25519);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("ed25519_cert.pem"),
            key_file: testdata("ed25519_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x2d; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-ed25519 runner status: {}",
        report.observed
    );
    assert!(
        shim.success,
        "tls13-ed25519 shim reported failure (code {:?})",
        shim.code
    );
}

// No botan_shim_tls13_ed25519: Botan does not support Ed25519 certificate auth
// (see the comment above TLS13_ED25519).
#[test]
fn openssl_shim_tls13_ed25519() {
    run_ed25519_case(ShimKind::OpenSsl);
}

// --- client mode: plzn plays the TLS server, the shim plays the client ---

const TLS12_CLIENT: &str = r#"
plzn tls "shim/tls12-client" {
  chain: [ecdsa_p256]
  uut client {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_CLIENT: &str = r#"
plzn tls "shim/tls13-client" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send AppData { size: 37, reply: 91 }
    recv AppData
    send AppData { size: 24, reply: none }
    close
  }
  expect ok
}
"#;

fn client_config(version: u16) -> ShimConfig {
    ShimConfig {
        role: "client".into(),
        min_version: Some(version),
        max_version: Some(version),
        // Client trusts plzn's server cert without checking (test harness).
        expect: Expectations {
            version: Some(version),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn run_client_case(kind: ShimKind, source_name: &str, source: &str, version: u16) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", source_name, kind.label());
        return;
    }
    let mut program = lower_source(source_name, source);
    // plzn is the server here; give it a cert/key to present.
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let factory = ShimFactory::new(kind, client_config(version)).expect("shim factory");
    let report = run(&program, &factory, [0x37; 32], None);
    let shim = factory.wait_shim().expect("reap shim");

    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner status: {}",
        source_name,
        report.observed
    );
    assert!(
        shim.success,
        "{} shim reported failure (code {:?})",
        source_name, shim.code
    );
}

const TLS13_CLIENT_REJECTS_UNOFFERED_SERVER_SIGALG: &str = r#"
plzn tls "shim/tls13-client-rejects-unoffered-server-sigalg" {
  chain: [rsa_2048]
  uut client {
    versions: [tls13]
    verify_prefs: [rsa_pss_rsae_sha256]
  }
  flow handshake {
    recv ClientHello { signature_algorithms: [rsa_pss_rsae_sha256] }
    send CertificateVerify { algorithm: rsa_pss_rsae_sha384 }
    wait 300ms
  }
  expect alert fatal/illegal_parameter
}
"#;

#[test]
fn gnutls_shim_tls13_client_sends_alert_for_unoffered_server_sigalg() {
    let kind = ShimKind::GnuTls;
    if kind.binary_path().is_none() {
        eprintln!("SKIP unoffered server sigalg: GnuTLS shim binary not built");
        return;
    }
    let mut program = lower_source(
        "gnutls-client-unoffered-server-sigalg",
        TLS13_CLIENT_REJECTS_UNOFFERED_SERVER_SIGALG,
    );
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::Rsa2048)
        .expect("RSA certificate");
    program.cert_der = Some(bundle.cert_der);
    program.private_key_der = Some(bundle.key_pkcs8_der);

    let mut cfg = client_config(0x0304);
    cfg.verify_prefs = vec![0x0804];
    cfg.expect.handshake_error = Some(String::new());
    let factory = ShimFactory::new(kind, cfg).expect("GnuTLS shim factory");
    let report = run(&program, &factory, [0x9d; 32], None);
    let shim = factory.wait_shim().expect("reap GnuTLS shim");
    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "runner status: {}",
        report.observed
    );
    assert!(shim.success, "GnuTLS shim outcome: {:?}", shim);
}

const DTLS12_SERVER_SMOKE: &str = r#"
plzn tls "shim/dtls12-server" {
  chain: [rsa_2048]
  uut server {
    versions: [dtls12]
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  flow handshake {
    send AppData { size: 4096, reply: 33 }
    recv AppData
  }
  expect ok
}
"#;

const DTLS12_CLIENT_SMOKE: &str = r#"
plzn tls "shim/dtls12-client" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send AppData { size: 37, reply: 91 }
    recv AppData
  }
  expect ok
}
"#;

fn run_dtls_case(kind: ShimKind, source_name: &str, source: &str, shim_is_server: bool) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", source_name, kind.label());
        return;
    }
    let mut program = lower_source(source_name, source);
    if !shim_is_server {
        let bundle =
            plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
                .expect("cert gen");
        program.cert_der = Some(bundle.cert_der);
        program.private_key_der = Some(bundle.key_pkcs8_der);
    }
    let cfg = ShimConfig {
        role: if shim_is_server { "server" } else { "client" }.into(),
        protocol: "dtls".into(),
        credentials: if shim_is_server {
            Credentials {
                cert_file: testdata("rsa_cert.pem"),
                key_file: testdata("rsa_key.pem"),
                ..Default::default()
            }
        } else {
            Credentials::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x47; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner status: {}",
        source_name,
        report.observed
    );
    assert!(shim.success, "{} shim: {:?}", source_name, shim);
}

// Server-certificate verification (shim as CLIENT): plzn is the server and
// presents a freshly-generated self-signed cert; the shim client is told to
// verify against a trust anchor that did NOT issue that cert, so path validation
// must fail and the client aborts with a fatal alert (unknown_ca /
// bad_certificate). This exercises the shim's CLIENT-side cert verification -- a
// direction the happy `run_client_case` deliberately skips. Cross-library.
const TLS13_CLIENT_REJECT: &str = r#"
plzn tls "shim/tls13-client-reject-untrusted" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {}
  expect handshake-fails
}
"#;

fn run_client_reject_untrusted(kind: ShimKind, version: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-reject-untrusted: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("client-reject-untrusted", TLS13_CLIENT_REJECT);
    // plzn (server) presents a freshly-generated self-signed cert.
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(version),
        max_version: Some(version),
        server_name: "localhost".into(),
        credentials: Credentials {
            // A trust anchor unrelated to plzn's presented cert -> path fails.
            trust_file: testdata("untrusted_client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-reject-untrusted runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-reject-untrusted shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_reject_untrusted() {
    run_client_reject_untrusted(ShimKind::Botan, 0x0304, 0x91);
}

#[test]
fn openssl_shim_tls13_client_reject_untrusted() {
    run_client_reject_untrusted(ShimKind::OpenSsl, 0x0304, 0x92);
}

#[test]
fn rustls_shim_tls13_client_reject_untrusted() {
    run_client_reject_untrusted(ShimKind::Rustls, 0x0304, 0x99);
}

#[test]
fn go_shim_tls13_client_reject_untrusted() {
    run_client_reject_untrusted(ShimKind::Go, 0x0304, 0x9b);
}

// Server hostname verification (shim as CLIENT). plzn presents a cert whose only
// SAN is "plzn-server"; the shim client trusts that exact cert, so the chain is
// valid and the ONLY variable is the requested hostname. Requesting "plzn-server"
// succeeds; requesting "wrong.example.com" must be rejected (bad_certificate),
// isolating hostname verification from chain validation. Cross-library. This also
// guards an OpenSSL shim fix: setting SNI does not enable hostname checking, so
// the shim now calls SSL_set1_host when verifying (previously it silently skipped
// hostname verification -- a client-security false negative).
fn run_client_hostname(kind: ShimKind, requested_host: &str, expect_ok: bool, seed: u8) {
    run_client_hostname_cert(kind, "server_named", requested_host, expect_ok, seed);
}

/// Hostname verification against a specific server cert (`<cert_base>_cert.{der,pem}` +
/// `<cert_base>_key.pkcs8.der`). The shim client trusts the exact leaf, so ONLY hostname matching
/// can cause a rejection. Used for exact-name and wildcard-name (RFC 6125) matching.
fn run_client_hostname_cert(
    kind: ShimKind,
    cert_base: &str,
    requested_host: &str,
    expect_ok: bool,
    seed: u8,
) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-hostname: {} binary not built", kind.label());
        return;
    }
    let source = if expect_ok {
        TLS13_CLIENT
    } else {
        TLS13_CLIENT_REJECT
    };
    let mut program = lower_source("client-hostname", source);
    program.cert_der =
        Some(std::fs::read(testdata(&format!("{}_cert.der", cert_base))).expect("server cert"));
    program.private_key_der =
        Some(std::fs::read(testdata(&format!("{}_key.pkcs8.der", cert_base))).expect("server key"));

    let mut cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: requested_host.into(),
        credentials: Credentials {
            // Trust plzn's exact leaf, so only the hostname can cause rejection.
            trust_file: testdata(&format!("{}_cert.pem", cert_base)),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        ..Default::default()
    };
    if expect_ok {
        cfg.expect.version = Some(0x0304);
    } else {
        cfg.expect.handshake_error = Some(String::new());
    }

    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-hostname ({}) runner: {}",
        requested_host,
        report.observed
    );
    assert!(
        shim.success,
        "client-hostname ({}) shim (code {:?})",
        requested_host, shim.code
    );
}

#[test]
fn botan_shim_tls13_client_hostname_match() {
    run_client_hostname(ShimKind::Botan, "plzn-server", true, 0x93);
}

#[test]
fn openssl_shim_tls13_client_hostname_match() {
    run_client_hostname(ShimKind::OpenSsl, "plzn-server", true, 0x94);
}

#[test]
fn botan_shim_tls13_client_hostname_mismatch() {
    run_client_hostname(ShimKind::Botan, "wrong.example.com", false, 0x95);
}

#[test]
fn openssl_shim_tls13_client_hostname_mismatch() {
    run_client_hostname(ShimKind::OpenSsl, "wrong.example.com", false, 0x96);
}

#[test]
fn rustls_shim_tls13_client_hostname_match() {
    run_client_hostname(ShimKind::Rustls, "plzn-server", true, 0x97);
}

#[test]
fn rustls_shim_tls13_client_hostname_mismatch() {
    run_client_hostname(ShimKind::Rustls, "wrong.example.com", false, 0x98);
}

// Wildcard hostname matching (RFC 6125 6.4.3), shim as CLIENT: plzn presents a cert whose only SAN
// is DNS:*.example.com; the shim client trusts that exact leaf, so only wildcard matching varies.
// A "*" label matches exactly ONE left-most label: foo.example.com matches; the apex example.com
// does NOT (no left label); foo.bar.example.com does NOT (wildcards match one label, not many).
// Botan + OpenSSL only: the rustls shim client uses a NoVerify certificate verifier (no hostname
// checking), like the existing hostname_{match,mismatch} tests.
fn run_client_wildcard(kind: ShimKind, host: &str, expect_ok: bool, seed: u8) {
    run_client_hostname_cert(kind, "server_wildcard", host, expect_ok, seed);
}

#[test]
fn tls13_client_wildcard_match_single_label() {
    run_client_wildcard(ShimKind::Botan, "foo.example.com", true, 0xa0);
    run_client_wildcard(ShimKind::OpenSsl, "foo.example.com", true, 0xa1);
    run_client_wildcard(ShimKind::Rustls, "foo.example.com", true, 0xa9);
}

#[test]
fn tls13_client_wildcard_reject_apex() {
    run_client_wildcard(ShimKind::Botan, "example.com", false, 0xa3);
    run_client_wildcard(ShimKind::OpenSsl, "example.com", false, 0xa4);
    run_client_wildcard(ShimKind::Rustls, "example.com", false, 0xaa);
}

#[test]
fn tls13_client_wildcard_reject_multi_label() {
    run_client_wildcard(ShimKind::Botan, "foo.bar.example.com", false, 0xa6);
    run_client_wildcard(ShimKind::OpenSsl, "foo.bar.example.com", false, 0xa7);
    run_client_wildcard(ShimKind::Rustls, "foo.bar.example.com", false, 0xab);
}

// CN is ignored, SAN is authoritative (RFC 6125 / CA/Browser Forum), shim as CLIENT: the cert has
// CN=cn.example.com but SAN=DNS:san.example.com. A conformant client matches ONLY the SAN and
// ignores the CN entirely (CN-based matching was a historical bypass source). Requesting the SAN
// name succeeds; requesting the CN name is rejected. Botan + OpenSSL (rustls shim uses NoVerify).
fn run_client_cnsan(kind: ShimKind, host: &str, expect_ok: bool, seed: u8) {
    run_client_hostname_cert(kind, "server_cnsan", host, expect_ok, seed);
}

#[test]
fn tls13_client_cnsan_match_san() {
    run_client_cnsan(ShimKind::Botan, "san.example.com", true, 0xb0);
    run_client_cnsan(ShimKind::OpenSsl, "san.example.com", true, 0xb1);
    run_client_cnsan(ShimKind::Rustls, "san.example.com", true, 0xb4);
}

#[test]
fn tls13_client_cnsan_reject_cn() {
    run_client_cnsan(ShimKind::Botan, "cn.example.com", false, 0xb2);
    run_client_cnsan(ShimKind::OpenSsl, "cn.example.com", false, 0xb3);
    run_client_cnsan(ShimKind::Rustls, "cn.example.com", false, 0xb5);
}

// Expired server certificate (shim as CLIENT). plzn presents a cert whose
// validity ended in 2021; the shim client trusts that exact leaf and requests its
// matching SAN ("plzn-server"), so neither the chain nor the hostname can be the
// cause -- the only defect is that the cert is expired. The client must reject
// (certificate_expired). Isolates time-validity checking. Cross-library.
fn run_client_expired(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-expired: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-expired", TLS13_CLIENT_REJECT);
    program.cert_der =
        Some(std::fs::read(testdata("server_expired_cert.der")).expect("expired cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("server_expired_key.pkcs8.der")).expect("expired key"));

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "plzn-server".into(),
        credentials: Credentials {
            // Trust the exact (expired) leaf, so only expiry can fail validation.
            trust_file: testdata("server_expired_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-expired runner: {}",
        report.observed
    );
    assert!(shim.success, "client-expired shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_client_expired_cert() {
    run_client_expired(ShimKind::Botan, 0x97);
}

#[test]
fn openssl_shim_tls13_client_expired_cert() {
    run_client_expired(ShimKind::OpenSsl, 0x98);
}

#[test]
fn rustls_shim_tls13_client_expired_cert() {
    run_client_expired(ShimKind::Rustls, 0x9a);
}

// Multi-cert chain path building (shim as CLIENT). plzn is the server and
// presents leaf + intermediate; the shim client trusts only the ROOT, so it must
// build the path leaf -> intermediate -> root to accept. With the intermediate
// present the handshake completes; omitting it leaves a gap the client cannot
// bridge and the handshake fails. `with_intermediate` toggles the two. The leaf's
// SAN is "plzn-chain", which the client requests. Cross-library.
fn run_client_chain(kind: ShimKind, with_intermediate: bool, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-chain: {} binary not built", kind.label());
        return;
    }
    let source = if with_intermediate {
        TLS13_CLIENT
    } else {
        TLS13_CLIENT_REJECT
    };
    let mut program = lower_source("client-chain", source);
    program.cert_der = Some(std::fs::read(testdata("chain_leaf_cert.der")).expect("leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("chain_leaf_key.pkcs8.der")).expect("leaf key"));
    if with_intermediate {
        program.extra_chain_der =
            vec![std::fs::read(testdata("chain_intermediate_cert.der")).expect("intermediate")];
    }

    let mut cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "plzn-chain".into(),
        credentials: Credentials {
            trust_file: testdata("chain_root.pem"), // trust only the root
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        ..Default::default()
    };
    if with_intermediate {
        cfg.expect.version = Some(0x0304);
    } else {
        cfg.expect.handshake_error = Some(String::new());
    }

    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-chain (intermediate={}) runner: {}",
        with_intermediate,
        report.observed
    );
    assert!(shim.success, "client-chain shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_client_chain_ok() {
    run_client_chain(ShimKind::Botan, true, 0xa3);
}

#[test]
fn openssl_shim_tls13_client_chain_ok() {
    run_client_chain(ShimKind::OpenSsl, true, 0xa4);
}

#[test]
fn rustls_shim_tls13_client_chain_ok() {
    run_client_chain(ShimKind::Rustls, true, 0xc9);
}

#[test]
fn botan_shim_tls13_client_chain_missing_intermediate() {
    run_client_chain(ShimKind::Botan, false, 0xa5);
}

#[test]
fn openssl_shim_tls13_client_chain_missing_intermediate() {
    run_client_chain(ShimKind::OpenSsl, false, 0xa6);
}

#[test]
fn rustls_shim_tls13_client_chain_missing_intermediate() {
    run_client_chain(ShimKind::Rustls, false, 0xca);
}

// Expired intermediate in a chain (shim as CLIENT). plzn presents leaf +
// intermediate, and the shim client trusts the root -- but the intermediate's
// validity ended in 2021, so even though the path chains structurally, validation
// must reject it (an expired CA anywhere in the path invalidates it). This is
// distinct from the expired-LEAF case; it checks intermediate validity.
// Cross-library.
fn run_client_chain_expired_intermediate(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-chain-expired-int: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("client-chain-expired-int", TLS13_CLIENT_REJECT);
    program.cert_der = Some(std::fs::read(testdata("chain_exp_leaf_cert.der")).expect("leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("chain_exp_leaf_key.pkcs8.der")).expect("leaf key"));
    program.extra_chain_der =
        vec![std::fs::read(testdata("chain_exp_intermediate_cert.der")).expect("intermediate")];

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "plzn-chain-exp".into(),
        credentials: Credentials {
            trust_file: testdata("chain_exp_root.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-chain-expired-int runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-chain-expired-int shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_chain_expired_intermediate() {
    run_client_chain_expired_intermediate(ShimKind::Botan, 0xa7);
}

#[test]
fn openssl_shim_tls13_client_chain_expired_intermediate() {
    run_client_chain_expired_intermediate(ShimKind::OpenSsl, 0xa8);
}

#[test]
fn rustls_shim_tls13_client_chain_expired_intermediate() {
    run_client_chain_expired_intermediate(ShimKind::Rustls, 0xce);
}

// Wrong-key-usage intermediate (shim as CLIENT). The intermediate is CA:TRUE but
// its keyUsage is digitalSignature only -- it lacks keyCertSign, so per RFC 5280
// 4.2.1.3 it is not permitted to sign certificates. A leaf signed by it must be
// rejected during path validation even though the chain is otherwise valid and
// trusted to the root. Cross-library.
fn run_client_chain_bad_keyusage(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-chain-bad-ku: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("client-chain-bad-ku", TLS13_CLIENT_REJECT);
    program.cert_der = Some(std::fs::read(testdata("chain_ku_leaf_cert.der")).expect("leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("chain_ku_leaf_key.pkcs8.der")).expect("leaf key"));
    program.extra_chain_der =
        vec![std::fs::read(testdata("chain_ku_intermediate_cert.der")).expect("intermediate")];

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "plzn-ku-leaf".into(),
        credentials: Credentials {
            trust_file: testdata("chain_ku_root.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-chain-bad-ku runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-chain-bad-ku shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_chain_bad_keyusage() {
    run_client_chain_bad_keyusage(ShimKind::Botan, 0xab);
}

#[test]
fn openssl_shim_tls13_client_chain_bad_keyusage() {
    run_client_chain_bad_keyusage(ShimKind::OpenSsl, 0xac);
}
// NOTE: no rustls variant -- rustls (webpki) does NOT enforce keyUsage=keyCertSign on an
// intermediate CA (it ACCEPTS the bad-keyusage chain), unlike Botan + OpenSSL which reject.
// Documented cross-library difference (coverage_matrix.md), so this stays Botan + OpenSSL.

// Name-constraints violation (shim as CLIENT), RFC 5280 4.2.1.10. The intermediate
// carries a critical nameConstraints permitting only DNS:example.com, but the leaf
// it issued has SAN DNS:notallowed.test. The client requests exactly that name (so
// hostname verification passes and cannot be the cause) -- the rejection must come
// from the name-constraints check during path validation. Cross-library.
fn run_client_chain_name_constraint(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-chain-nc: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-chain-nc", TLS13_CLIENT_REJECT);
    program.cert_der = Some(std::fs::read(testdata("chain_nc_leaf_cert.der")).expect("leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("chain_nc_leaf_key.pkcs8.der")).expect("leaf key"));
    program.extra_chain_der =
        vec![std::fs::read(testdata("chain_nc_intermediate_cert.der")).expect("intermediate")];

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "notallowed.test".into(), // matches leaf SAN -> isolates the NC failure
        credentials: Credentials {
            trust_file: testdata("chain_nc_root.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-chain-nc runner: {}",
        report.observed
    );
    assert!(shim.success, "client-chain-nc shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_client_chain_name_constraint() {
    run_client_chain_name_constraint(ShimKind::Botan, 0xad);
}

#[test]
fn openssl_shim_tls13_client_chain_name_constraint() {
    run_client_chain_name_constraint(ShimKind::OpenSsl, 0xae);
}

#[test]
fn rustls_shim_tls13_client_chain_name_constraint() {
    run_client_chain_name_constraint(ShimKind::Rustls, 0xcc);
}

// Wrong extended key usage (shim as CLIENT), RFC 5280 4.2.1.12. plzn's server leaf
// has a critical extendedKeyUsage of clientAuth ONLY -- it is not valid for TLS
// server authentication (serverAuth). The client trusts the issuing root and the
// hostname matches the leaf SAN, so the only defect is the EKU; a conforming
// client must reject the certificate for this purpose. Cross-library.
fn run_client_eku_mismatch(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-eku: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-eku", TLS13_CLIENT_REJECT);
    program.cert_der = Some(std::fs::read(testdata("chain_eku_leaf_cert.der")).expect("leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("chain_eku_leaf_key.pkcs8.der")).expect("leaf key"));

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        server_name: "plzn-eku-leaf".into(),
        credentials: Credentials {
            trust_file: testdata("chain_eku_root.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-eku runner: {}",
        report.observed
    );
    assert!(shim.success, "client-eku shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_client_eku_mismatch() {
    run_client_eku_mismatch(ShimKind::Botan, 0xaf);
}

#[test]
fn openssl_shim_tls13_client_eku_mismatch() {
    run_client_eku_mismatch(ShimKind::OpenSsl, 0xb0);
}

#[test]
fn rustls_shim_tls13_client_eku_mismatch() {
    run_client_eku_mismatch(ShimKind::Rustls, 0xcd);
}

// --- uut{} policy overrides: genuine negotiation-failure tests ---

// The harness offers what its cfg says; the uut{} block pins the shim's own
// policy to something incompatible, so the handshake must fail. Both the runner
// (sees the failure) and the shim (told to expect it) must pass.
const UUT_VERSION_MISMATCH: &str = r#"
plzn tls "uut/version-mismatch" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake until send ClientHello {
    send ClientHello { -ext supported_versions }
  }
  expect handshake-fails
}
"#;

const UUT_CIPHER_MISMATCH: &str = r#"
plzn tls "uut/cipher-mismatch" {
  chain: [default]
  uut server {
    versions: [tls13]
    cipher_suites: [AES_256_GCM_SHA384]
  }
  flow handshake {}
  expect handshake-fails
}
"#;

fn run_uut_case(kind: ShimKind, name: &str, source: &str) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", name, kind.label());
        return;
    }
    let program = lower_source(name, source);
    // Server-mode: shim needs a cert even though the handshake will fail.
    let cfg = ShimConfig::for_program(
        &program,
        Some(&testdata("rsa_cert.pem")),
        Some(&testdata("rsa_key.pem")),
        None,
    )
    .unwrap();
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x55; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim outcome: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner status: {}",
        name,
        report.observed
    );
    assert!(
        shim.success,
        "{} shim reported failure (code {:?})",
        name, shim.code
    );
}

#[test]
fn botan_shim_uut_version_mismatch() {
    run_uut_case(ShimKind::Botan, "uut-ver-botan", UUT_VERSION_MISMATCH);
}

#[test]
fn botan_shim_uut_cipher_mismatch() {
    run_uut_case(ShimKind::Botan, "uut-cipher-botan", UUT_CIPHER_MISMATCH);
}

#[test]
fn openssl_shim_uut_version_mismatch() {
    run_uut_case(ShimKind::OpenSsl, "uut-ver-openssl", UUT_VERSION_MISMATCH);
}

#[test]
fn openssl_shim_uut_cipher_mismatch() {
    run_uut_case(ShimKind::OpenSsl, "uut-cipher-openssl", UUT_CIPHER_MISMATCH);
}

// TLS 1.3 session resumption across two connections. plzn (client) does a full
// handshake, captures the NewSessionTicket, then resumes on a second connection.
// The shims use a fixed session-ticket key, so a fresh shim process on the
// second connection can still decrypt the stateless ticket and resume.
const TLS13_RESUME: &str = r#"
plzn tls "shim/tls13-resume" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  session initial {
    flow handshake {
      send AppData
      recv AppData
      close
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake {
      send AppData
      recv AppData
    }
    expect ok
  }
}
"#;

fn run_resume_case(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP resume: {} binary not built", kind.label());
        return;
    }
    let tokens = plzn::lex::lex(TLS13_RESUME).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    assert!(plzn::check::check(&file).is_empty(), "schema errors");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(programs.len(), 2, "expected initial + resumed programs");

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let reports = run_sessions(&programs, &factory, [0x63; 32], None);

    for r in &reports {
        eprintln!("{}", r);
    }
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(
            matches!(r.status, RunStatus::Pass),
            "resume session '{}' failed: {}",
            r.test_id,
            r.observed
        );
    }
}

// TLS 1.2 session-ticket resumption (RFC 5077), GENUINE, cross-library. The
// initial session advertises support (empty SessionTicket extension) so the
// server issues a NewSessionTicket; plzn captures it transcript-aware (the ticket
// is part of the server Finished MAC, arriving before CCS). The resumed session
// presents the ticket and runs the abbreviated TLS12_RESUMED_CLIENT_PRESET (no
// Certificate/ServerKeyExchange) -- which only completes if the server actually
// resumed (a full-handshake fallback would send Certificate and fail the resumed
// preset). The shims use a fixed ticket key so a fresh process decrypts the
// stateless ticket.
const TLS12_RESUME: &str = r#"
plzn tls "shim/tls12-resume" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  session initial {
    flow handshake {
      close
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake {
      send AppData
      recv AppData
    }
    expect ok
  }
}
"#;

fn run_tls12_resume_case(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls12-resume: {} binary not built", kind.label());
        return;
    }
    let tokens = plzn::lex::lex(TLS12_RESUME).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    assert!(plzn::check::check(&file).is_empty(), "schema errors");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(programs.len(), 2, "expected initial + resumed programs");

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let reports = run_sessions(&programs, &factory, [seed; 32], None);

    for r in &reports {
        eprintln!("{}", r);
    }
    assert_eq!(reports.len(), 2);
    for r in &reports {
        assert!(
            matches!(r.status, RunStatus::Pass),
            "tls12 resume session '{}' failed: {}",
            r.test_id,
            r.observed
        );
    }
}

#[test]
fn botan_shim_tls12_resume() {
    run_tls12_resume_case(ShimKind::Botan, 0x64);
}

#[test]
fn openssl_shim_tls12_resume() {
    run_tls12_resume_case(ShimKind::OpenSsl, 0x65);
}

#[test]
fn rustls_shim_tls12_resume() {
    run_tls12_resume_case(ShimKind::Rustls, 0x66);
}

// Client authentication (happy): the server requires a client certificate; plzn
// presents one (Certificate + CertificateVerify) and the server verifies it
// against a configured trust anchor. Exercises the full TLS 1.3 client-auth flow.
const TLS13_CLIENT_AUTH_OK: &str = r#"
plzn tls "shim/tls13-client-auth" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_client_auth_ok(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-auth: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-auth", TLS13_CLIENT_AUTH_OK);
    // plzn presents a proper end-entity client cert (CA:FALSE + clientAuth EKU) that chains to a
    // separate self-signed CA trust anchor. rustls's WebPkiClientVerifier rejects a self-signed
    // CA:TRUE cert presented as an end-entity (CaUsedAsEndEntity); Botan/OpenSSL accept this chain
    // too, so all three shim servers verify the same way.
    program.cert_der = Some(std::fs::read(testdata("client_ee_cert.der")).expect("client cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("client_ee_key.pkcs8.der")).expect("client key"));

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_ee_ca.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x72; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-auth runner: {}",
        report.observed
    );
    assert!(shim.success, "client-auth shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_client_auth() {
    run_client_auth_ok(ShimKind::Botan);
}

#[test]
fn rustls_shim_tls13_client_auth() {
    run_client_auth_ok(ShimKind::Rustls);
}

#[test]
fn go_shim_tls13_client_auth() {
    run_client_auth_ok(ShimKind::Go);
}

// Client-auth, the OTHER direction: plzn plays the SERVER and requests
// client authentication; the shim is the CLIENT and presents its
// configured certificate. plzn sends the CertificateRequest, receives the
// shim's Certificate + CertificateVerify, and verifies the client's
// signature (RFC 8446 4.4.3) against the presented leaf. Exercises
// send_certificate_request / recv_client_certificate /
// recv_client_certificate_verify in Tls13Server -- the mirror of
// TLS13_CLIENT_AUTH_OK, which only tests plzn's client side.
const TLS13_SERVER_CLIENT_AUTH: &str = r#"
plzn tls "shim/tls13-server-requests-client-auth" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  peer { request_client_cert: true }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_server_client_auth(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP server-client-auth: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("server-client-auth", TLS13_SERVER_CLIENT_AUTH);
    // plzn is the server here; give it a cert/key to present.
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        // The shim client presents this certificate when plzn requests one.
        credentials: Credentials {
            cert_file: testdata("client_cert.pem"),
            key_file: testdata("client_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x5c; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "server-client-auth runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "server-client-auth shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_server_client_auth() {
    run_server_client_auth(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls13_server_client_auth() {
    run_server_client_auth(ShimKind::OpenSsl);
}

#[test]
fn rustls_shim_tls13_server_client_auth() {
    run_server_client_auth(ShimKind::Rustls);
}

// certificate_authorities in the CertificateRequest (RFC 8446 4.2.4, server->client direction):
// plzn plays the SERVER, requests client auth AND advertises a certificate_authorities extension
// in the CertificateRequest (one entry: an empty Name, structurally valid DER). A conformant
// client parses it and still presents its configured cert (the hint is advisory). This exercises
// the CertReq encoder's certificate_authorities path + client tolerance -- the CertReq companion
// to suite/server/tls13_client_certificate_authorities (the ClientHello direction).
fn run_server_client_auth_ca_hint(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP server-client-auth-ca-hint: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("server-client-auth-ca-hint", TLS13_SERVER_CLIENT_AUTH);
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());
    // Advertise one certificate authority (an empty Name = 0x30 0x00, valid DER) in the CertReq.
    program.cert_request_authorities = vec![vec![0x30, 0x00]];

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("client_cert.pem"),
            key_file: testdata("client_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x71; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "server-client-auth-ca-hint runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "server-client-auth-ca-hint shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_server_client_auth_ca_hint() {
    run_server_client_auth_ca_hint(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls13_server_client_auth_ca_hint() {
    run_server_client_auth_ca_hint(ShimKind::OpenSsl);
}

#[test]
fn rustls_shim_tls13_server_client_auth_ca_hint() {
    run_server_client_auth_ca_hint(ShimKind::Rustls);
}

// Client-auth RPK (RFC 7250, client direction): plzn plays the SERVER, requests client
// authentication AND negotiates client_certificate_type=RawPublicKey (cfg offer_rpk). The
// shim CLIENT offers client_certificate_type=[RawPublicKey] and presents a bare
// SubjectPublicKeyInfo instead of an X.509 certificate; plzn selects RawPublicKey in
// EncryptedExtensions, decodes the client's leaf via from_spki_der (from_certificate_entry),
// and verifies the CertificateVerify against it. Depends on the server-side client-auth added
// alongside; the RPK selection rides the existing client-cert-type negotiation.
const TLS13_SERVER_CLIENT_RPK: &str = r#"
plzn tls "shim/tls13-server-requests-client-auth-rpk" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  peer { capabilities: [offer_rpk], request_client_cert: true }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_server_client_auth_rpk(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP server-client-auth-rpk: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("server-client-auth-rpk", TLS13_SERVER_CLIENT_RPK);
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        // Present a RAW public key (RFC 7250) as the client credential, not an X.509 cert.
        raw_public_key: true,
        credentials: Credentials {
            cert_file: testdata("client_cert.pem"),
            key_file: testdata("client_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x6d; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "server-client-auth-rpk runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "server-client-auth-rpk shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_server_client_auth_rpk() {
    run_server_client_auth_rpk(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls13_server_client_auth_rpk() {
    run_server_client_auth_rpk(ShimKind::OpenSsl);
}

#[test]
fn rustls_shim_tls13_server_client_auth_rpk() {
    run_server_client_auth_rpk(ShimKind::Rustls);
}

// RFC 7250 raw public keys (SELECTED): plzn offers server_certificate_type=RawPublicKey
// and the shim server is configured to present a raw public key (a bare
// SubjectPublicKeyInfo) instead of an X.509 certificate. plzn reads the RawPublicKey
// selection from EncryptedExtensions and decodes the leaf via from_spki_der, verifying the
// CertificateVerify against it. This is the RPK-selected case (vs the X.509-fallback
// suite/server/tls13_offer_rpk_x509_fallback where no server enables RPK).
const TLS13_RPK_SELECTED: &str = r#"
plzn tls "shim/tls13-rpk-selected" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [offer_rpk] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_rpk_selected(kind: ShimKind) {
    run_rpk_selected_with_cert(kind, "rsa_cert.pem", "rsa_key.pem");
}

// Same as run_rpk_selected but with a caller-chosen server credential, so the raw public
// key exercises a specific SPKI algorithm (RSA or ECDSA P-256).
fn run_rpk_selected_with_cert(kind: ShimKind, cert: &str, key: &str) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP rpk-selected: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("rpk-selected", TLS13_RPK_SELECTED);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata(cert),
            key_file: testdata(key),
            ..Default::default()
        },
        raw_public_key: true,
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x78; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "rpk-selected runner: {}",
        report.observed
    );
    assert!(shim.success, "rpk-selected shim (code {:?})", shim.code);
}

#[test]
fn openssl_shim_tls13_rpk_selected() {
    run_rpk_selected(ShimKind::OpenSsl);
}

#[test]
fn botan_shim_tls13_rpk_selected() {
    run_rpk_selected(ShimKind::Botan);
}

#[test]
fn rustls_shim_tls13_rpk_selected() {
    run_rpk_selected(ShimKind::Rustls);
}

// RPK with an ECDSA P-256 server key: the raw SubjectPublicKeyInfo carries an
// id-ecPublicKey key (a different from_spki_der branch than RSA) and the server signs its
// CertificateVerify with ecdsa_secp256r1_sha256, which plzn verifies against the raw key.
#[test]
fn openssl_shim_tls13_rpk_selected_ecdsa() {
    run_rpk_selected_with_cert(ShimKind::OpenSsl, "ec_cert.pem", "ec_key.pem");
}

#[test]
fn botan_shim_tls13_rpk_selected_ecdsa() {
    run_rpk_selected_with_cert(ShimKind::Botan, "ec_cert.pem", "ec_key.pem");
}

#[test]
fn rustls_shim_tls13_rpk_selected_ecdsa() {
    run_rpk_selected_with_cert(ShimKind::Rustls, "ec_cert.pem", "ec_key.pem");
}

// RFC 8879 certificate compression (round-trip): plzn advertises compress_certificate
// with zlib (+ext 0x001b = 02 0001), the shim server pre-compresses its Certificate, and
// plzn reads the CompressedCertificate (type 25), zlib-inflates it (decompress_certificate_13)
// and completes the handshake. A server that did NOT compress would send type 11 and plzn's
// decompressor would never run; a plzn that could not parse type 25 would error -- so the
// completing handshake proves a genuine compress/decompress round-trip.
const TLS13_CERT_COMPRESSION: &str = r#"
plzn tls "shim/tls13-cert-compression" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext compress_certificate = raw "020001"
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_cert_compression(kind: ShimKind) {
    run_cert_compression_with_cert(kind, "rsa_cert.pem", "rsa_key.pem");
}

// Same as run_cert_compression but with a caller-chosen server credential, so the
// compressed Certificate carries a specific key type (RSA or ECDSA P-256).
fn run_cert_compression_with_cert(kind: ShimKind, cert: &str, key: &str) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP cert-compression: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("cert-compression", TLS13_CERT_COMPRESSION);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata(cert),
            key_file: testdata(key),
            ..Default::default()
        },
        compress_certificate: true,
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x79; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "cert-compression runner: {}",
        report.observed
    );
    assert!(shim.success, "cert-compression shim (code {:?})", shim.code);
}

#[test]
fn openssl_shim_tls13_cert_compression() {
    run_cert_compression(ShimKind::OpenSsl);
}

#[test]
fn rustls_shim_tls13_cert_compression() {
    run_cert_compression(ShimKind::Rustls);
}

#[test]
fn openssl_shim_tls13_cert_compression_ecdsa() {
    run_cert_compression_with_cert(ShimKind::OpenSsl, "ec_cert.pem", "ec_key.pem");
}

#[test]
fn rustls_shim_tls13_cert_compression_ecdsa() {
    run_cert_compression_with_cert(ShimKind::Rustls, "ec_cert.pem", "ec_key.pem");
}

// Client-auth negative: the server requires a client certificate; plzn engages
// the client-auth flow but presents no cert (empty Certificate, no
// CertificateVerify), so the server must abort.
const TLS13_CLIENT_AUTH_MISSING: &str = r#"
plzn tls "shim/tls13-client-auth-missing" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {}
  expect handshake-fails
}
"#;

fn run_client_auth_missing(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-auth-missing: {} binary not built",
            kind.label()
        );
        return;
    }
    // No client cert on the program: plzn sends an empty Certificate.
    let program = lower_source("client-auth-missing", TLS13_CLIENT_AUTH_MISSING);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            // Trust anchor present so the server actually sends CertificateRequest.
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x74; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-auth-missing runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-auth-missing shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_auth_missing() {
    run_client_auth_missing(ShimKind::Botan);
}

// TLS 1.3 client-auth signature verification (server side). plzn presents a valid,
// trusted client certificate but a CertificateVerify whose signature has one byte
// flipped inside the signature value (so it parses but does not verify). A server
// that verifies client authentication MUST reject. RFC 8446 4.4.3: "If the
// verification fails, the receiver MUST terminate the handshake with a
// "decrypt_error" alert." Security-critical: a server that skipped this check would
// accept unauthenticated clients. The mutation is registered directly on the Program
// (the client-auth preset drives the CertificateVerify send, so a flow `send` step
// would disrupt the flight ordering). Cross-library.
const TLS13_CLIENT_AUTH_BADSIG: &str = r#"
plzn tls "shim/tls13-client-auth-badsig" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {}
  expect handshake-fails
}
"#;

fn run_client_auth_badsig(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-auth-badsig: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-auth-badsig", TLS13_CLIENT_AUTH_BADSIG);
    program.cert_der = Some(std::fs::read(testdata("client_cert.der")).expect("client cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("client_key.pkcs8.der")).expect("client key"));
    // Flip a byte inside the client's CertificateVerify signature value.
    program.send_mutations.push(plzn::ir::MessageMutations {
        message: plzn::ir::MessageKind::CertificateVerify,
        mutations: vec![plzn::ir::Mutation {
            op: plzn::ir::MutationOp::Xor {
                target: plzn::ir::ResolvedByteTarget {
                    path: Some(vec!["handshake".into(), "signature".into()]),
                    index: 20,
                    end: None,
                },
                value: 0xff,
            },
            span: plzn::ast::Span::dummy(),
        }],
        dtls_frag: None,
    });
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x75; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-auth-badsig runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-auth-badsig shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_auth_badsig() {
    run_client_auth_badsig(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls13_client_auth_badsig() {
    run_client_auth_badsig(ShimKind::OpenSsl);
}

// TLS 1.2 client-auth signature verification (server side). plzn presents a valid,
// trusted client certificate but a CertificateVerify whose signature has one byte
// flipped inside the signature value (so it parses but does not verify). RFC 5246
// 7.4.8: the server verifies the client's signature over the handshake transcript; a
// server that verifies client authentication MUST reject an invalid one. Distinct code
// path from the TLS 1.3 badsig test (TLS 1.2 CertificateVerify + rsa_pkcs1_sha256).
// Enabled by wiring send-mutations into the TLS 1.2 client send_client_certificate_verify
// (previously it applied none). Cross-library.
const TLS12_CLIENT_AUTH_BADSIG: &str = r#"
plzn tls "shim/tls12-client-auth-badsig" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {}
  expect handshake-fails
}
"#;

fn run_client_auth_badsig_tls12(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP tls12 client-auth-badsig: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("tls12-client-auth-badsig", TLS12_CLIENT_AUTH_BADSIG);
    program.cert_der = Some(std::fs::read(testdata("client_cert.der")).expect("client cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("client_key.pkcs8.der")).expect("client key"));
    // Flip a byte inside the client's CertificateVerify signature value.
    program.send_mutations.push(plzn::ir::MessageMutations {
        message: plzn::ir::MessageKind::CertificateVerify,
        mutations: vec![plzn::ir::Mutation {
            op: plzn::ir::MutationOp::Xor {
                target: plzn::ir::ResolvedByteTarget {
                    path: Some(vec!["handshake".into(), "signature".into()]),
                    index: 20,
                    end: None,
                },
                value: 0xff,
            },
            span: plzn::ast::Span::dummy(),
        }],
        dtls_frag: None,
    });
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x77; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls12 client-auth-badsig runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "tls12 client-auth-badsig shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls12_client_auth_badsig() {
    run_client_auth_badsig_tls12(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls12_client_auth_badsig() {
    run_client_auth_badsig_tls12(ShimKind::OpenSsl);
}

// TLS 1.3 client-authentication BYPASS (CVE-2026-34582). A malicious client
// completes the handshake up to its own Certificate, then -- instead of sending
// Certificate / CertificateVerify / Finished -- sends application data. A correct
// server that requires client authentication MUST NOT process application data
// before the client's Finished is received and verified; it must abort. (Botan
// <= 3.11.0 served content to unauthenticated clients here; fixed in 3.11.1.)
// Cross-library.
const TLS13_CLIENT_AUTH_BYPASS: &str = r#"
plzn tls "shim/tls13-client-auth-bypass" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake until send Certificate {
    send AppData
    recv AppData
  }
  expect handshake-fails
}
"#;

fn run_client_auth_bypass(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-auth-bypass: {} binary not built", kind.label());
        return;
    }
    // No client cert: the client never intends to authenticate; it tries to skip
    // straight to application data.
    let program = lower_source("client-auth-bypass", TLS13_CLIENT_AUTH_BYPASS);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-auth-bypass runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-auth-bypass shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_auth_bypass() {
    run_client_auth_bypass(ShimKind::Botan, 0xb3);
}

#[test]
fn openssl_shim_tls13_client_auth_bypass() {
    run_client_auth_bypass(ShimKind::OpenSsl, 0xb4);
}

// Client-auth with a client-certificate CHAIN. plzn presents its client leaf
// followed by an intermediate; the server requires a client cert and trusts only
// the client-CA ROOT, so it must build leaf -> intermediate -> root to accept.
// Exercises client-side chain presentation + server-side client-cert path
// building. Cross-library.
const TLS13_CLIENT_AUTH_CHAIN: &str = r#"
plzn tls "shim/tls13-client-auth-chain" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_client_auth_chain(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP client-auth-chain: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("client-auth-chain", TLS13_CLIENT_AUTH_CHAIN);
    program.cert_der =
        Some(std::fs::read(testdata("client_chain_leaf_cert.der")).expect("client leaf"));
    program.private_key_der =
        Some(std::fs::read(testdata("client_chain_leaf_key.pkcs8.der")).expect("client key"));
    program.extra_chain_der =
        vec![std::fs::read(testdata("client_chain_intermediate_cert.der")).expect("client int")];

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_chain_root.pem"), // trust only the client-CA root
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-auth-chain runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-auth-chain shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_auth_chain() {
    run_client_auth_chain(ShimKind::Botan, 0xa9);
}

#[test]
fn openssl_shim_tls13_client_auth_chain() {
    run_client_auth_chain(ShimKind::OpenSsl, 0xaa);
}

// TLS 1.2 client authentication: the server sends a CertificateRequest before
// ServerHelloDone; plzn answers with Certificate + ClientKeyExchange +
// CertificateVerify (ECDSA-SHA256 over the handshake transcript, RFC 5246
// 7.4.8). The server verifies the client cert against its trust anchor and the
// handshake completes with an app-data exchange.
const TLS12_CLIENT_AUTH_OK: &str = r#"
plzn tls "shim/tls12-client-auth" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls12_client_auth_ok(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls12-client-auth: {} binary not built", kind.label());
        return;
    }
    let mut program = lower_source("tls12-client-auth", TLS12_CLIENT_AUTH_OK);
    program.cert_der = Some(std::fs::read(testdata("client_cert.der")).expect("client cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("client_key.pkcs8.der")).expect("client key"));

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x76; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls12-client-auth runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "tls12-client-auth shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls12_client_auth() {
    run_tls12_client_auth_ok(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls12_client_auth() {
    run_tls12_client_auth_ok(ShimKind::OpenSsl);
}

// TLS 1.2 client-auth negative: the server requires a client certificate; plzn
// engages the client-auth flow but presents an empty Certificate (and no
// CertificateVerify), so the server must abort the handshake. The TLS 1.2
// client falls back to the shim test credential when the program carries
// none, so the empty list is requested explicitly.
const TLS12_CLIENT_AUTH_MISSING: &str = r#"
plzn tls "shim/tls12-client-auth-missing" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send Certificate { entries: 0 }
  }
  expect handshake-fails
}
"#;

fn run_tls12_client_auth_missing(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP tls12-client-auth-missing: {} binary not built",
            kind.label()
        );
        return;
    }
    // `send Certificate { entries: 0 }`: plzn sends an empty Certificate.
    let program = lower_source("tls12-client-auth-missing", TLS12_CLIENT_AUTH_MISSING);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            // Trust anchor present so the server actually sends CertificateRequest.
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x78; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls12-client-auth-missing runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "tls12-client-auth-missing shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls12_client_auth_missing() {
    run_tls12_client_auth_missing(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls12_client_auth_missing() {
    run_tls12_client_auth_missing(ShimKind::OpenSsl);
}

// Client-auth with an UNTRUSTED client certificate: plzn presents a valid,
// correctly-signed client Certificate + CertificateVerify, but the leaf is a
// self-signed cert the server does not have in its trust store. The signature
// verifies, yet path validation fails, so the server must abort. This is the
// certificate-verification-failure family (distinct from the missing-cert case,
// which fails earlier on an empty certificate_list). `src` is the .plzn source,
// `seed` keeps the two version variants deterministic and distinct.
fn run_client_auth_untrusted(kind: ShimKind, test_id: &str, src: &str, tls_version: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", test_id, kind.label());
        return;
    }
    let mut program = lower_source(test_id, src);
    // A valid cert+key, but NOT the one in the server's trust_file.
    program.cert_der =
        Some(std::fs::read(testdata("untrusted_client_cert.der")).expect("untrusted cert"));
    program.private_key_der =
        Some(std::fs::read(testdata("untrusted_client_key.pkcs8.der")).expect("untrusted key"));

    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(tls_version),
        max_version: Some(tls_version),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            // Server trusts a DIFFERENT client cert, so the presented one fails.
            trust_file: testdata("client_cert.pem"),
            ..Default::default()
        },
        verify: plzn::shim::VerifyConfig {
            peer: true,
            require_client_cert: true,
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        test_id,
        report.observed
    );
    assert!(shim.success, "{} shim (code {:?})", test_id, shim.code);
}

const TLS13_CLIENT_AUTH_UNTRUSTED: &str = r#"
plzn tls "shim/tls13-client-auth-untrusted" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {}
  expect handshake-fails
}
"#;

const TLS12_CLIENT_AUTH_UNTRUSTED: &str = r#"
plzn tls "shim/tls12-client-auth-untrusted" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {}
  expect handshake-fails
}
"#;

#[test]
fn botan_shim_tls13_client_auth_untrusted() {
    run_client_auth_untrusted(
        ShimKind::Botan,
        "tls13-client-auth-untrusted",
        TLS13_CLIENT_AUTH_UNTRUSTED,
        0x0304,
        0x7a,
    );
}

#[test]
fn openssl_shim_tls13_client_auth_untrusted() {
    run_client_auth_untrusted(
        ShimKind::OpenSsl,
        "tls13-client-auth-untrusted",
        TLS13_CLIENT_AUTH_UNTRUSTED,
        0x0304,
        0x7b,
    );
}

#[test]
fn botan_shim_tls12_client_auth_untrusted() {
    run_client_auth_untrusted(
        ShimKind::Botan,
        "tls12-client-auth-untrusted",
        TLS12_CLIENT_AUTH_UNTRUSTED,
        0x0303,
        0x7c,
    );
}

#[test]
fn openssl_shim_tls12_client_auth_untrusted() {
    run_client_auth_untrusted(
        ShimKind::OpenSsl,
        "tls12-client-auth-untrusted",
        TLS12_CLIENT_AUTH_UNTRUSTED,
        0x0303,
        0x7d,
    );
}

// ALPN negotiation (RFC 7301): plzn advertises ["h2","http/1.1"] in its
// ClientHello; the server is configured to select "h2" and self-checks that it
// negotiated exactly that (`alpn.expect`). The negotiated protocol travels in
// the ServerHello (TLS 1.2) or EncryptedExtensions (TLS 1.3); the handshake and
// app-data exchange must complete either way. Cross-library.
fn run_alpn_ok(kind: ShimKind, test_id: &str, src: &str, tls_version: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", test_id, kind.label());
        return;
    }
    let program = lower_source(test_id, src);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(tls_version),
        max_version: Some(tls_version),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        alpn: plzn::shim::AlpnConfig {
            select: "h2".into(),
            // Server self-checks it negotiated exactly "h2".
            expect: Some("h2".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        test_id,
        report.observed
    );
    // The shim's alpn.expect self-check makes shim.success authoritative for the
    // server having actually negotiated "h2".
    assert!(shim.success, "{} shim (code {:?})", test_id, shim.code);
}

const TLS13_ALPN_OK: &str = r#"
plzn tls "shim/tls13-alpn" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext alpn = ["h2", "http/1.1"]
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS12_ALPN_OK: &str = r#"
plzn tls "shim/tls12-alpn" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      +ext alpn = ["h2", "http/1.1"]
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_alpn() {
    run_alpn_ok(ShimKind::Botan, "tls13-alpn", TLS13_ALPN_OK, 0x0304, 0x81);
}

#[test]
fn openssl_shim_tls13_alpn() {
    run_alpn_ok(ShimKind::OpenSsl, "tls13-alpn", TLS13_ALPN_OK, 0x0304, 0x82);
}

#[test]
fn rustls_shim_tls13_alpn() {
    run_alpn_ok(ShimKind::Rustls, "tls13-alpn", TLS13_ALPN_OK, 0x0304, 0x8a);
}

#[test]
fn go_shim_tls13_alpn() {
    run_alpn_ok(ShimKind::Go, "tls13-alpn", TLS13_ALPN_OK, 0x0304, 0x8e);
}

#[test]
fn botan_shim_tls12_alpn() {
    run_alpn_ok(ShimKind::Botan, "tls12-alpn", TLS12_ALPN_OK, 0x0303, 0x83);
}

#[test]
fn openssl_shim_tls12_alpn() {
    run_alpn_ok(ShimKind::OpenSsl, "tls12-alpn", TLS12_ALPN_OK, 0x0303, 0x84);
}

#[test]
fn rustls_shim_tls12_alpn() {
    run_alpn_ok(ShimKind::Rustls, "tls12-alpn", TLS12_ALPN_OK, 0x0303, 0x8c);
}

// ALPN mismatch / no_application_protocol (RFC 7301 3.2): plzn advertises only
// "h2", but the server requires "http/1.1", which was not offered. With no common
// protocol the server must abort with a fatal no_application_protocol alert. Both
// shims now behave the same (the Botan shim previously selected an unoffered
// protocol unconditionally; fixed to signal the alert like OpenSSL). Cross-library.
fn run_alpn_mismatch(kind: ShimKind, test_id: &str, src: &str, tls_version: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", test_id, kind.label());
        return;
    }
    let program = lower_source(test_id, src);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(tls_version),
        max_version: Some(tls_version),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        alpn: plzn::shim::AlpnConfig {
            // Require a protocol the client does not advertise.
            select: "http/1.1".into(),
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        test_id,
        report.observed
    );
    assert!(shim.success, "{} shim (code {:?})", test_id, shim.code);
}

const TLS13_ALPN_MISMATCH: &str = r#"
plzn tls "shim/tls13-alpn-mismatch" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext alpn = ["h2"]
    }
  }
  expect handshake-fails
}
"#;

const TLS12_ALPN_MISMATCH: &str = r#"
plzn tls "shim/tls12-alpn-mismatch" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      +ext alpn = ["h2"]
    }
  }
  expect handshake-fails
}
"#;

#[test]
fn botan_shim_tls13_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::Botan,
        "tls13-alpn-mismatch",
        TLS13_ALPN_MISMATCH,
        0x0304,
        0x85,
    );
}

#[test]
fn openssl_shim_tls13_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::OpenSsl,
        "tls13-alpn-mismatch",
        TLS13_ALPN_MISMATCH,
        0x0304,
        0x86,
    );
}

#[test]
fn rustls_shim_tls13_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::Rustls,
        "tls13-alpn-mismatch",
        TLS13_ALPN_MISMATCH,
        0x0304,
        0x8b,
    );
}

#[test]
fn botan_shim_tls12_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::Botan,
        "tls12-alpn-mismatch",
        TLS12_ALPN_MISMATCH,
        0x0303,
        0x87,
    );
}

#[test]
fn openssl_shim_tls12_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::OpenSsl,
        "tls12-alpn-mismatch",
        TLS12_ALPN_MISMATCH,
        0x0303,
        0x88,
    );
}

#[test]
fn rustls_shim_tls12_alpn_mismatch() {
    run_alpn_mismatch(
        ShimKind::Rustls,
        "tls12-alpn-mismatch",
        TLS12_ALPN_MISMATCH,
        0x0303,
        0x8d,
    );
}

// SNI (RFC 6066): plzn sends server_name = "example.com" in its ClientHello; the
// server is told (via `expect_server_name`) to require exactly that and
// self-checks the SNI it received. Proves plzn advertises SNI correctly and the
// server extracts it -- for TLS 1.2 (Botan: Session_Summary::server_info()) and
// TLS 1.3, and for OpenSSL (SSL_get_servername). Cross-library. The `shim.success`
// assertion, driven by the shim's self-check, is authoritative here.
fn run_sni_ok(kind: ShimKind, test_id: &str, src: &str, tls_version: u16, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", test_id, kind.label());
        return;
    }
    let program = lower_source(test_id, src);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(tls_version),
        max_version: Some(tls_version),
        // Deliberately do NOT set `server_name`: the shim's only source for
        // "example.com" is then the client's SNI, so the self-check is genuine.
        expect_server_name: Some("example.com".into()),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        test_id,
        report.observed
    );
    assert!(shim.success, "{} shim (code {:?})", test_id, shim.code);
}

const TLS13_SNI_OK: &str = r#"
plzn tls "shim/tls13-sni" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext server_name = "example.com"
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS12_SNI_OK: &str = r#"
plzn tls "shim/tls12-sni" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      +ext server_name = "example.com"
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_sni() {
    run_sni_ok(ShimKind::Botan, "tls13-sni", TLS13_SNI_OK, 0x0304, 0x89);
}

#[test]
fn openssl_shim_tls13_sni() {
    run_sni_ok(ShimKind::OpenSsl, "tls13-sni", TLS13_SNI_OK, 0x0304, 0x8a);
}

#[test]
fn botan_shim_tls12_sni() {
    run_sni_ok(ShimKind::Botan, "tls12-sni", TLS12_SNI_OK, 0x0303, 0x8b);
}

#[test]
fn openssl_shim_tls12_sni() {
    run_sni_ok(ShimKind::OpenSsl, "tls12-sni", TLS12_SNI_OK, 0x0303, 0x8c);
}

#[test]
fn rustls_shim_tls13_sni() {
    run_sni_ok(ShimKind::Rustls, "tls13-sni", TLS13_SNI_OK, 0x0304, 0xe0);
}

#[test]
fn rustls_shim_tls12_sni() {
    run_sni_ok(ShimKind::Rustls, "tls12-sni", TLS12_SNI_OK, 0x0303, 0xe1);
}

#[test]
fn go_shim_tls13_sni() {
    run_sni_ok(ShimKind::Go, "tls13-sni", TLS13_SNI_OK, 0x0304, 0xe2);
}

#[test]
fn go_shim_tls12_sni() {
    run_sni_ok(ShimKind::Go, "tls12-sni", TLS12_SNI_OK, 0x0303, 0xe3);
}

// Server-side signature-algorithm preference (RFC 8446 4.2.3): the client offers
// only rsa_pss_rsae_sha256, but the server is restricted (via `signing_prefs`) to
// rsa_pss_rsae_sha384. The intersection is empty, so the server cannot sign its
// CertificateVerify with a mutually-acceptable scheme and must abort. This
// exercises the SERVER's own sig-alg preference list (distinct from the
// client-driven `suite/server/tls13_sigalg_mismatch`). It also guards the OpenSSL shim
// fix: `signing_prefs` was previously ignored (SSL_CTX_set1_sigalgs_list), which
// would have let this handshake wrongly succeed. Cross-library.
const TLS13_SERVER_SIGALG_PREF: &str = r#"
plzn tls "shim/tls13-server-sigalg-pref" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext signature_algorithms = [rsa_pss_rsae_sha256]
    }
  }
  expect handshake-fails
}
"#;

fn run_server_sigalg_pref(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP tls13-server-sigalg-pref: {} binary not built",
            kind.label()
        );
        return;
    }
    let program = lower_source("tls13-server-sigalg-pref", TLS13_SERVER_SIGALG_PREF);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        // Server will only sign with rsa_pss_rsae_sha384, which the client above
        // does not offer -> no mutually-acceptable signature algorithm.
        signing_prefs: vec![0x0805],
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "server-sigalg-pref runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "server-sigalg-pref shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_server_sigalg_pref() {
    run_server_sigalg_pref(ShimKind::Botan, 0x8d);
}

#[test]
fn openssl_shim_tls13_server_sigalg_pref() {
    run_server_sigalg_pref(ShimKind::OpenSsl, 0x8e);
}

// HelloRetryRequest round-trip (RFC 8446 4.1.4): plzn's first ClientHello carries
// an empty key_share but advertises x25519 in supported_groups, so the server has
// a mutually-supported group but no usable key_share and MUST answer with an HRR
// requesting x25519. plzn retries with the x25519 key_share and the handshake
// completes with an app-data exchange. Exercises the full HRR client flow against
// real servers (previously only covered against the internal harness). Cross-library.
const TLS13_HRR: &str = r#"
plzn tls "shim/tls13-hrr" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [hrr] }
  flow handshake {
    send ClientHello {
      +ext key_share = raw "0000"
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_hrr(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls13-hrr: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-hrr", TLS13_HRR);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-hrr runner: {}",
        report.observed
    );
    assert!(shim.success, "tls13-hrr shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_hrr() {
    run_hrr(ShimKind::Botan, 0x99);
}

#[test]
fn openssl_shim_tls13_hrr() {
    run_hrr(ShimKind::OpenSsl, 0x9a);
}

// TLS 1.3 with TLS_CHACHA20_POLY1305_SHA256 (0x1303). plzn now offers both
// AES-128-GCM and ChaCha20-Poly1305; the shim server is pinned to 0x1303, so it
// must be negotiated and plzn must protect records with the ChaCha20 AEAD (both
// suites share the SHA-256 key schedule, so only the AEAD differs). The shim
// self-checks the negotiated suite (`expect.cipher`). Cross-library.
const TLS13_CHACHA: &str = r#"
plzn tls "shim/tls13-chacha20" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls13_chacha(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls13-chacha20: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-chacha20", TLS13_CHACHA);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        cipher_suites: vec![0x1303], // pin the server to ChaCha20-Poly1305
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            cipher: Some(0x1303),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-chacha20 runner: {}",
        report.observed
    );
    // shim.success reflects the server's self-check that it negotiated 0x1303.
    assert!(shim.success, "tls13-chacha20 shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_chacha20() {
    run_tls13_chacha(ShimKind::Botan, 0x9b);
}

#[test]
fn openssl_shim_tls13_chacha20() {
    run_tls13_chacha(ShimKind::OpenSsl, 0x9c);
}

// TLS 1.3 with TLS_AES_256_GCM_SHA384 (0x1302). This suite uses a SHA-384 key
// schedule, unlike the SHA-256 default. plzn's ClientHello override offers only
// 0x1302; the client learns the suite (and thus the hash) at ServerHello and
// rebuilds its transcript + key schedule under SHA-384 from the raw ClientHello +
// ServerHello bytes. The shim server is pinned to 0x1302 and self-checks it. This
// exercises plzn's deferred-hash path and the AES-256-GCM AEAD. Cross-library.
const TLS13_AES256: &str = r#"
plzn tls "shim/tls13-aes256" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      cipher_suites: [AES_256_GCM_SHA384]
    }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls13_aes256(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls13-aes256: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-aes256", TLS13_AES256);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        cipher_suites: vec![0x1302], // pin the server to AES-256-GCM-SHA384
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0304),
            cipher: Some(0x1302),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-aes256 runner: {}",
        report.observed
    );
    assert!(shim.success, "tls13-aes256 shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_aes256() {
    run_tls13_aes256(ShimKind::Botan, 0x9d);
}

#[test]
fn openssl_shim_tls13_aes256() {
    run_tls13_aes256(ShimKind::OpenSsl, 0x9e);
}

#[test]
fn gnutls_shim_tls13_aes256() {
    run_tls13_aes256(ShimKind::GnuTls, 0x9f);
}

// TLS 1.3 key exchange over secp256r1 (P-256), reached via HelloRetryRequest.
// plzn advertises both x25519 and secp256r1 but sends only an x25519 key_share;
// the shim server is pinned to secp256r1 (`curves`), so it cannot use the x25519
// share and sends an HRR requesting secp256r1. plzn retries with a P-256
// key_share and the handshake completes -- exercising P-256 ECDH in TLS 1.3
// (previously the client only did x25519). Cross-library.
const TLS13_P256: &str = r#"
plzn tls "shim/tls13-p256" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [hrr] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls13_p256(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls13-p256: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-p256", TLS13_P256);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        curves: vec![0x0017], // pin the server to secp256r1 -> forces HRR to P-256
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-p256 runner: {}",
        report.observed
    );
    assert!(shim.success, "tls13-p256 shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_p256() {
    run_tls13_p256(ShimKind::Botan, 0x9f);
}

#[test]
fn openssl_shim_tls13_p256() {
    run_tls13_p256(ShimKind::OpenSsl, 0xa0);
}

// TLS 1.3 key exchange over secp384r1 (P-384), reached via HelloRetryRequest, the
// same way as the P-256 test but with the shim pinned to secp384r1. Confirms
// plzn's P-384 ECDH in TLS 1.3. Cross-library.
const TLS13_P384: &str = r#"
plzn tls "shim/tls13-p384" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { capabilities: [hrr] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls13_p384(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls13-p384: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls13-p384", TLS13_P384);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        curves: vec![0x0018], // pin the server to secp384r1 -> forces HRR to P-384
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls13-p384 runner: {}",
        report.observed
    );
    assert!(shim.success, "tls13-p384 shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_p384() {
    run_tls13_p384(ShimKind::Botan, 0xa1);
}

#[test]
fn openssl_shim_tls13_p384() {
    run_tls13_p384(ShimKind::OpenSsl, 0xa2);
}

// Static-RSA key exchange (TLS_RSA_WITH_AES_128_GCM_SHA256, 0x009C). The client
// offers only the static-RSA suite; the server (RSA cert) decrypts the RSA-
// encrypted premaster and completes. Deprecated but a real test target
// (Bleichenbacher/ROBOT). Required enabling "RSA" in the Botan shim's
// allowed_key_exchange_methods. Cross-library where the library still supports it.
const TLS12_RSA_KEX: &str = r#"
plzn tls "shim/tls12-rsa-kex" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [rsa, aes128_gcm_sha256] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

fn run_tls12_rsa_kex(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP tls12-rsa-kex: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("tls12-rsa-kex", TLS12_RSA_KEX);
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        credentials: Credentials {
            cert_file: testdata("rsa_cert.pem"),
            key_file: testdata("rsa_key.pem"),
            ..Default::default()
        },
        expect: Expectations {
            version: Some(0x0303),
            cipher: Some(0x009C),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "tls12-rsa-kex runner: {}",
        report.observed
    );
    assert!(shim.success, "tls12-rsa-kex shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls12_rsa_kex() {
    run_tls12_rsa_kex(ShimKind::Botan, 0xb1);
}

#[test]
fn openssl_shim_tls12_rsa_kex() {
    run_tls12_rsa_kex(ShimKind::OpenSsl, 0xb2);
}

// TLS 1.3 external PSK: plzn offers a pre-shared key; the shim resolves it
// through its library's external-PSK callback/credential API.
const TLS13_EXT_PSK: &str = r#"
plzn tls "shim/tls13-ext-psk" {
  chain: []
  uut server {
    versions: [tls13]
  }
  psk {
    identity: "Client_identity"
    secret: "6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_EXT_PSK_CLIENT: &str = r#"
plzn tls "shim/tls13-ext-psk-client" {
  chain: []
  uut client {
    versions: [tls13]
  }
  psk {
    identity: "Client_identity"
    secret: "6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS12_PSK_CLIENT: &str = r#"
plzn tls "shim/tls12-psk-client" {
  chain: []
  uut client {
    versions: [tls12]
  }
  peer { capabilities: [psk, aes128_gcm_sha256] }
  psk {
    identity: "plzn-psk-id"
    secret: "6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

// The runner offers the PSK family, while the shim is pinned to a non-default
// member. This catches a shim replacing the explicit list with a broad PSK
// fallback (the OpenSSL regression) and exercises GnuTLS's component-level
// exact single-suite policy.
const TLS12_PSK_SERVER_PINNED: &str = r#"
plzn tls "shim/tls12-psk-server-pinned" {
  chain: []
  psk {
    identity: "plzn-psk-id"
    secret: "6f6c6f6c6f6c6f6c"
  }
  uut server {
    versions: [tls12]
    cipher_suites: [PSK_WITH_AES_256_CBC_SHA384]
  }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const DTLS12_PSK_CLIENT_PINNED: &str = r#"
plzn tls "shim/dtls12-psk-client-pinned" {
  chain: []
  psk {
    identity: "plzn-psk-id"
    secret: "6f6c6f6c6f6c6f6c"
  }
  uut client {
    versions: [dtls12]
    cipher_suites: [PSK_WITH_AES_128_GCM_SHA256]
  }
  peer { capabilities: [psk, aes128_gcm_sha256] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;

const DTLS12_PSK_SERVER_PINNED: &str = r#"
plzn tls "shim/dtls12-psk-server-pinned" {
  chain: []
  psk {
    identity: "plzn-psk-id"
    secret: "6f6c6f6c6f6c6f6c"
  }
  uut server {
    versions: [dtls12]
    cipher_suites: [PSK_WITH_AES_128_GCM_SHA256]
  }
  peer { capabilities: [psk, aes128_gcm_sha256] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;

fn run_psk_program(
    kind: ShimKind,
    source_name: &str,
    source: &str,
    expected_cipher: Option<u16>,
    seed: u8,
) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", source_name, kind.label());
        return;
    }
    let mut program = lower_source(source_name, source);
    // The in-process plzn server currently initializes its certificate slot
    // even for an eventual PSK handshake. Supply one for client-role tests;
    // it stays off the wire once the external PSK is selected.
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der);
    program.private_key_der = Some(bundle.key_pkcs8_der);
    let mut cfg = ShimConfig::for_program(&program, None, None, None).unwrap();
    cfg.expect.cipher = expected_cipher;
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        source_name,
        report.observed
    );
    assert!(shim.success, "{} shim outcome: {:?}", source_name, shim);
}

fn run_ext_psk(kind: ShimKind) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP ext-psk: {} binary not built", kind.label());
        return;
    }
    let program = lower_source("ext-psk", TLS13_EXT_PSK);
    let cfg = ShimConfig::for_program(
        &program,
        Some(&testdata("rsa_cert.pem")),
        Some(&testdata("rsa_key.pem")),
        None,
    )
    .unwrap();
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [0x73; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "ext-psk runner: {}",
        report.observed
    );
    assert!(shim.success, "ext-psk shim (code {:?})", shim.code);
}

#[test]
fn botan_shim_tls13_external_psk() {
    run_ext_psk(ShimKind::Botan);
}

#[test]
fn openssl_shim_tls13_external_psk() {
    run_ext_psk(ShimKind::OpenSsl);
}

#[test]
fn gnutls_shim_tls13_external_psk() {
    run_ext_psk(ShimKind::GnuTls);
}

#[test]
fn gnutls_shim_tls13_external_psk_client() {
    run_psk_program(
        ShimKind::GnuTls,
        "tls13-ext-psk-client-gnutls",
        TLS13_EXT_PSK_CLIENT,
        Some(0x1301),
        0x74,
    );
}

#[test]
fn gnutls_shim_tls12_psk_client() {
    run_psk_program(
        ShimKind::GnuTls,
        "tls12-psk-client-gnutls",
        TLS12_PSK_CLIENT,
        Some(0x00a8),
        0x75,
    );
}

#[test]
fn gnutls_shim_dtls12_psk_client_pinned() {
    run_psk_program(
        ShimKind::GnuTls,
        "dtls12-psk-client-pinned-gnutls",
        DTLS12_PSK_CLIENT_PINNED,
        Some(0x00a8),
        0x76,
    );
}

#[test]
fn gnutls_shim_dtls12_psk_server_pinned() {
    run_psk_program(
        ShimKind::GnuTls,
        "dtls12-psk-server-pinned-gnutls",
        DTLS12_PSK_SERVER_PINNED,
        Some(0x00a8),
        0x79,
    );
}

#[test]
fn gnutls_shim_tls12_psk_server_pinned() {
    run_psk_program(
        ShimKind::GnuTls,
        "tls12-psk-server-pinned-gnutls",
        TLS12_PSK_SERVER_PINNED,
        Some(0x00af),
        0x77,
    );
}

#[test]
fn openssl_shim_tls12_psk_server_pinned() {
    run_psk_program(
        ShimKind::OpenSsl,
        "tls12-psk-server-pinned-openssl",
        TLS12_PSK_SERVER_PINNED,
        Some(0x00af),
        0x78,
    );
}

#[test]
fn botan_shim_tls13_resume() {
    run_resume_case(ShimKind::Botan);
}

#[test]
fn rustls_shim_tls13_resume() {
    run_resume_case(ShimKind::Rustls);
}

#[test]
fn botan_shim_tls12_client() {
    run_client_case(ShimKind::Botan, "tls12-client-botan", TLS12_CLIENT, 0x0303);
}

#[test]
fn botan_shim_tls13_client() {
    run_client_case(ShimKind::Botan, "tls13-client-botan", TLS13_CLIENT, 0x0304);
}

#[test]
fn openssl_shim_tls13_client() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-openssl",
        TLS13_CLIENT,
        0x0304,
    );
}

#[test]
fn gnutls_shim_tls12_client() {
    run_client_case(
        ShimKind::GnuTls,
        "tls12-client-gnutls",
        TLS12_CLIENT,
        0x0303,
    );
}

#[test]
fn gnutls_shim_tls13_client() {
    run_client_case(
        ShimKind::GnuTls,
        "tls13-client-gnutls",
        TLS13_CLIENT,
        0x0304,
    );
}

#[test]
fn gnutls_shim_dtls12_client() {
    run_dtls_case(
        ShimKind::GnuTls,
        "dtls12-client-gnutls",
        DTLS12_CLIENT_SMOKE,
        false,
    );
}

#[test]
fn libressl_shim_tls12_client() {
    run_client_case(
        ShimKind::LibreSsl,
        "tls12-client-libressl",
        TLS12_CLIENT,
        0x0303,
    );
}

#[test]
fn libressl_shim_tls13_client() {
    run_client_case(
        ShimKind::LibreSsl,
        "tls13-client-libressl",
        TLS13_CLIENT,
        0x0304,
    );
}

#[test]
fn libressl_shim_dtls12_client() {
    run_dtls_case(
        ShimKind::LibreSsl,
        "dtls12-client-libressl",
        DTLS12_CLIENT_SMOKE,
        false,
    );
}

#[test]
fn wolfssl_shim_tls12_client() {
    run_client_case(
        ShimKind::WolfSsl,
        "tls12-client-wolfssl",
        TLS12_CLIENT,
        0x0303,
    );
}

#[test]
fn wolfssl_shim_tls13_client() {
    run_client_case(
        ShimKind::WolfSsl,
        "tls13-client-wolfssl",
        TLS13_CLIENT,
        0x0304,
    );
}

// Client-conformance checks (shim as CLIENT, plzn as server): assert required
// properties of the shim client's ClientHello. A conformant TLS 1.3 client pins
// ClientHello.legacy_version to 0x0303 (RFC 8446 4.1.2) and offers only the null
// compression method (RFC 8446 4.1.2 / CRIME mitigation). plzn (server) matches
// those fields via `recv ClientHello { ... }`. Cross-library.
const TLS13_CLIENT_CH_LEGACY_VERSION: &str = r#"
plzn tls "shim/tls13-client-ch-legacy-version" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { legacy_version: 0x0303 }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_CLIENT_CH_NULL_COMPRESSION: &str = r#"
plzn tls "shim/tls13-client-ch-null-compression" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { compression_methods: [0x00] }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_client_ch_legacy_version() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-legacy-version",
        TLS13_CLIENT_CH_LEGACY_VERSION,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_legacy_version() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-legacy-version",
        TLS13_CLIENT_CH_LEGACY_VERSION,
        0x0304,
    );
}

#[test]
fn botan_shim_tls13_client_ch_null_compression() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-null-compression",
        TLS13_CLIENT_CH_NULL_COMPRESSION,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_null_compression() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-null-compression",
        TLS13_CLIENT_CH_NULL_COMPRESSION,
        0x0304,
    );
}

// RFC 8446 9.1: a compliant TLS 1.3 client MUST implement (and offers)
// TLS_AES_128_GCM_SHA256. The matcher's cipher_suites contains-all semantic passes
// iff 0x1301 appears in the offered list. Cross-library.
const TLS13_CLIENT_CH_MANDATORY_SUITE: &str = r#"
plzn tls "shim/tls13-client-ch-mandatory-suite" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { cipher_suites: [AES_128_GCM_SHA256] }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

// RFC 5246 7.4.1.2: a TLS 1.2 ClientHello must include the null compression method
// (and modern clients offer only it). Cross-library.
const TLS12_CLIENT_CH_NULL_COMPRESSION: &str = r#"
plzn tls "shim/tls12-client-ch-null-compression" {
  chain: [ecdsa_p256]
  uut client {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    recv ClientHello { compression_methods: [0x00] }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_client_ch_mandatory_suite() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-mandatory-suite",
        TLS13_CLIENT_CH_MANDATORY_SUITE,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_mandatory_suite() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-mandatory-suite",
        TLS13_CLIENT_CH_MANDATORY_SUITE,
        0x0304,
    );
}

#[test]
fn botan_shim_tls12_client_ch_null_compression() {
    run_client_case(
        ShimKind::Botan,
        "tls12-client-ch-null-compression",
        TLS12_CLIENT_CH_NULL_COMPRESSION,
        0x0303,
    );
}

#[test]
fn openssl_shim_tls12_client_ch_null_compression() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls12-client-ch-null-compression",
        TLS12_CLIENT_CH_NULL_COMPRESSION,
        0x0303,
    );
}

// RFC 8446 4.2.1 / 9.2: a TLS 1.3 ClientHello MUST carry the supported_versions
// (0x002b) and key_share (0x0033) extensions. The new `has_ext` matcher asserts
// each is present in the shim client's ClientHello. Cross-library.
const TLS13_CLIENT_CH_SUPPORTED_VERSIONS: &str = r#"
plzn tls "shim/tls13-client-ch-supported-versions" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { has_ext: supported_versions }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_CLIENT_CH_KEY_SHARE: &str = r#"
plzn tls "shim/tls13-client-ch-key-share" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { has_ext: key_share }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_client_ch_supported_versions() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-supported-versions",
        TLS13_CLIENT_CH_SUPPORTED_VERSIONS,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_supported_versions() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-supported-versions",
        TLS13_CLIENT_CH_SUPPORTED_VERSIONS,
        0x0304,
    );
}

#[test]
fn botan_shim_tls13_client_ch_key_share() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-key-share",
        TLS13_CLIENT_CH_KEY_SHARE,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_key_share() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-key-share",
        TLS13_CLIENT_CH_KEY_SHARE,
        0x0304,
    );
}

// signature_algorithms (0x000d) presence. Mandatory in TLS 1.3 (RFC 8446 9.2);
// modern TLS 1.2 clients send it too so the server can sign the key exchange with
// an acceptable scheme (RFC 5246 7.4.1.4.1). Cross-library.
const TLS13_CLIENT_CH_SIG_ALGS: &str = r#"
plzn tls "shim/tls13-client-ch-sig-algs" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    recv ClientHello { has_ext: signature_algorithms }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS12_CLIENT_CH_SIG_ALGS: &str = r#"
plzn tls "shim/tls12-client-ch-sig-algs" {
  chain: [ecdsa_p256]
  uut client {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    recv ClientHello { has_ext: signature_algorithms }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_client_ch_sig_algs() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-ch-sig-algs",
        TLS13_CLIENT_CH_SIG_ALGS,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_ch_sig_algs() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-ch-sig-algs",
        TLS13_CLIENT_CH_SIG_ALGS,
        0x0304,
    );
}

#[test]
fn botan_shim_tls12_client_ch_sig_algs() {
    run_client_case(
        ShimKind::Botan,
        "tls12-client-ch-sig-algs",
        TLS12_CLIENT_CH_SIG_ALGS,
        0x0303,
    );
}

#[test]
fn openssl_shim_tls12_client_ch_sig_algs() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls12-client-ch-sig-algs",
        TLS12_CLIENT_CH_SIG_ALGS,
        0x0303,
    );
}

// Cooperative server cipher-suite selection (shim as CLIENT). plzn's server is
// pinned (via cfg) to a single TLS 1.3 suite and selects it; the shim client must
// accept and complete, exercising that record path on the client side.
// AES-256-GCM-SHA384 exercises the client's SHA-384 transcript; ChaCha20 exercises
// the ChaCha20 AEAD. Cross-library.
const TLS13_CLIENT_SELECT_AES256: &str = r#"
plzn tls "shim/tls13-client-select-aes256" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  peer { capabilities: [aes256_gcm_sha384] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

const TLS13_CLIENT_SELECT_CHACHA20: &str = r#"
plzn tls "shim/tls13-client-select-chacha20" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  peer { capabilities: [chacha20_poly1305_sha256] }
  flow handshake {
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;

#[test]
fn botan_shim_tls13_client_select_aes256() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-select-aes256",
        TLS13_CLIENT_SELECT_AES256,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_select_aes256() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-select-aes256",
        TLS13_CLIENT_SELECT_AES256,
        0x0304,
    );
}

#[test]
fn botan_shim_tls13_client_select_chacha20() {
    run_client_case(
        ShimKind::Botan,
        "tls13-client-select-chacha20",
        TLS13_CLIENT_SELECT_CHACHA20,
        0x0304,
    );
}

#[test]
fn openssl_shim_tls13_client_select_chacha20() {
    run_client_case(
        ShimKind::OpenSsl,
        "tls13-client-select-chacha20",
        TLS13_CLIENT_SELECT_CHACHA20,
        0x0304,
    );
}

// Adversarial server selection (BoringSSL ServerHelloBogusCipher): plzn's server
// sends a ServerHello naming a cipher suite the client never offered (0xfe00). RFC
// 8446 4.1.3 requires the client to reject a suite it did not offer. The shim
// client must abort. Cross-library.
const TLS13_CLIENT_REJECT_BOGUS_SUITE: &str = r#"
plzn tls "shim/tls13-client-reject-bogus-suite" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send ServerHello { cipher_suite: 0xfe00 }
  }
  expect handshake-fails
}
"#;

fn run_client_reject_bogus_suite(kind: ShimKind, seed: u8) {
    if kind.binary_path().is_none() {
        eprintln!(
            "SKIP client-reject-bogus-suite: {} binary not built",
            kind.label()
        );
        return;
    }
    let mut program = lower_source("client-reject-bogus-suite", TLS13_CLIENT_REJECT_BOGUS_SUITE);
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "client-reject-bogus-suite runner: {}",
        report.observed
    );
    assert!(
        shim.success,
        "client-reject-bogus-suite shim (code {:?})",
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_reject_bogus_suite() {
    run_client_reject_bogus_suite(ShimKind::Botan, 0xb5);
}

#[test]
fn openssl_shim_tls13_client_reject_bogus_suite() {
    run_client_reject_bogus_suite(ShimKind::OpenSsl, 0xb6);
}

// RFC 8446 4.2: an EncryptedExtensions message may only carry extensions valid for it; a
// client "MUST abort the handshake with an 'unsupported_extension' alert" on a disallowed one.
// plzn plays the SERVER and injects supported_versions (0x002b) into EncryptedExtensions --
// supported_versions is a ServerHello/HRR-only extension (RFC 8446 4.2 table), never legal in
// EE -- so a conformant client MUST reject. (record_size_limit was tried first but is a VALID
// EE extension, and OpenSSL accepts it unsolicited -- it enforces per-message validity but not
// "was it offered"; supported_versions fails the per-message check on both.) Alert codes are
// not pinned (unsupported_extension vs illegal_parameter vary), so a generic handshake-fails.
const TLS13_CLIENT_REJECT_UNSOLICITED_EE_EXT: &str = r#"
plzn tls "shim/tls13-client-reject-unsolicited-ee-ext" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext supported_versions = raw "0304" }
  }
  expect handshake-fails
}
"#;

// Generic harness for "plzn (as server) sends a malformed/illegal flight; a conformant shim
// CLIENT must reject." The shim is told to expect a handshake failure; plzn asserts the flow
// fails (expect handshake-fails). Alert codes vary across libraries, so the .plzn source uses a
// generic handshake-fails and this harness does not pin one.
fn run_client_reject_flight(kind: ShimKind, seed: u8, name: &str, source: &str) {
    if kind.binary_path().is_none() {
        eprintln!("SKIP {}: {} binary not built", name, kind.label());
        return;
    }
    let mut program = lower_source(name, source);
    let bundle = plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256)
        .expect("cert gen");
    program.cert_der = Some(bundle.cert_der.clone());
    program.private_key_der = Some(bundle.key_pkcs8_der.clone());

    let cfg = ShimConfig {
        role: "client".into(),
        min_version: Some(0x0304),
        max_version: Some(0x0304),
        expect: Expectations {
            handshake_error: Some(String::new()),
            ..Default::default()
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner: {}",
        name,
        report.observed
    );
    assert!(
        shim.success
            || (shim.case == ShimResultCase::LocalError
                && matches!(
                    report.raw_outcome,
                    plzn::runtime::ObservedOutcome::Alert { .. }
                )),
        "{} shim (code {:?})",
        name,
        shim.code
    );
}

#[test]
fn botan_shim_tls13_client_reject_unsolicited_ee_ext() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xc0,
        "client-reject-unsolicited-ee-ext",
        TLS13_CLIENT_REJECT_UNSOLICITED_EE_EXT,
    );
}

#[test]
fn openssl_shim_tls13_client_reject_unsolicited_ee_ext() {
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xc1,
        "client-reject-unsolicited-ee-ext",
        TLS13_CLIENT_REJECT_UNSOLICITED_EE_EXT,
    );
}

#[test]
fn rustls_shim_tls13_client_reject_unsolicited_ee_ext() {
    run_client_reject_flight(
        ShimKind::Rustls,
        0xc2,
        "client-reject-unsolicited-ee-ext",
        TLS13_CLIENT_REJECT_UNSOLICITED_EE_EXT,
    );
}

// --- Batch of RFC 8446 4.1.3 / 4.2 server-misbehavior conformance checks (client must reject).
//     Each is verified against every buildable shim inside one test fn (skips a missing binary).

// RFC 8446 4.1.3: "legacy_compression_method: A single byte which MUST have the value 0."
const TLS13_CLIENT_REJECT_SH_BAD_COMPRESSION: &str = r#"
plzn tls "shim/tls13-client-reject-sh-bad-compression" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send ServerHello { legacy_compression_method: 0x01 }
  }
  expect handshake-fails
}
"#;

// key_share (0x0033) is a ServerHello/HRR-only extension (RFC 8446 4.2 table); illegal in EE.
const TLS13_CLIENT_REJECT_EE_KEY_SHARE: &str = r#"
plzn tls "shim/tls13-client-reject-ee-key-share" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext key_share = raw "00170001ff" }
  }
  expect handshake-fails
}
"#;

// pre_shared_key (0x0029) is a ServerHello-only extension (RFC 8446 4.2 table); illegal in EE.
const TLS13_CLIENT_REJECT_EE_PSK: &str = r#"
plzn tls "shim/tls13-client-reject-ee-psk" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext pre_shared_key = raw "0000" }
  }
  expect handshake-fails
}
"#;

#[test]
fn tls13_client_reject_sh_bad_compression() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xd0,
        "sh-bad-compression",
        TLS13_CLIENT_REJECT_SH_BAD_COMPRESSION,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xd1,
        "sh-bad-compression",
        TLS13_CLIENT_REJECT_SH_BAD_COMPRESSION,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xd2,
        "sh-bad-compression",
        TLS13_CLIENT_REJECT_SH_BAD_COMPRESSION,
    );
}

#[test]
fn tls13_client_reject_ee_key_share() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xd3,
        "ee-key-share",
        TLS13_CLIENT_REJECT_EE_KEY_SHARE,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xd4,
        "ee-key-share",
        TLS13_CLIENT_REJECT_EE_KEY_SHARE,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xd5,
        "ee-key-share",
        TLS13_CLIENT_REJECT_EE_KEY_SHARE,
    );
}

#[test]
fn tls13_client_reject_ee_psk() {
    run_client_reject_flight(ShimKind::Botan, 0xd6, "ee-psk", TLS13_CLIENT_REJECT_EE_PSK);
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xd7,
        "ee-psk",
        TLS13_CLIENT_REJECT_EE_PSK,
    );
    run_client_reject_flight(ShimKind::Rustls, 0xd8, "ee-psk", TLS13_CLIENT_REJECT_EE_PSK);
}

// certificate_authorities (0x002f) is a ClientHello/CertificateRequest-only extension (RFC 8446
// 4.2 table); illegal in EncryptedExtensions.
const TLS13_CLIENT_REJECT_EE_CERT_AUTHORITIES: &str = r#"
plzn tls "shim/tls13-client-reject-ee-cert-authorities" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext certificate_authorities = raw "0000" }
  }
  expect handshake-fails
}
"#;

#[test]
fn tls13_client_reject_ee_cert_authorities() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xdc,
        "ee-cert-authorities",
        TLS13_CLIENT_REJECT_EE_CERT_AUTHORITIES,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xdd,
        "ee-cert-authorities",
        TLS13_CLIENT_REJECT_EE_CERT_AUTHORITIES,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xde,
        "ee-cert-authorities",
        TLS13_CLIENT_REJECT_EE_CERT_AUTHORITIES,
    );
}

// --- Structural server-message defects (a different class from extension misplacement).

// Trailing bytes after the Certificate structure (RFC 8446 4.4.2); the client must fail to
// decode. The record is sealed under the handshake key, so this is a decode error, not AEAD.
const TLS13_CLIENT_REJECT_CERT_TRAILING: &str = r#"
plzn tls "shim/tls13-client-reject-cert-trailing" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send Certificate @ pad +5
  }
  expect handshake-fails
}
"#;

// Truncated Certificate body -- a structurally invalid handshake message.
const TLS13_CLIENT_REJECT_CERT_TRUNCATED: &str = r#"
plzn tls "shim/tls13-client-reject-cert-truncated" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send Certificate @ truncate 8
  }
  expect handshake-fails
}
"#;

// Corrupted server Finished verify_data (RFC 8446 4.4.4): the client MUST abort. Flipping a
// plaintext byte (the record still opens under the handshake key) makes the Finished check fail.
const TLS13_CLIENT_REJECT_SERVER_FINISHED_CORRUPT: &str = r#"
plzn tls "shim/tls13-client-reject-server-finished-corrupt" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send Finished @ xor[0]=0xff
  }
  expect handshake-fails
}
"#;

// ServerHello selects a key_share group the client never offered (RFC 8446 4.2.8: the server's
// KeyShareEntry "MUST be in the same group as the KeyShareEntry ... offered by the client").
const TLS13_CLIENT_REJECT_SH_UNOFFERED_KEYSHARE: &str = r#"
plzn tls "shim/tls13-client-reject-sh-unoffered-keyshare" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send ServerHello { key_share_group: secp521r1 }
  }
  expect handshake-fails
}
"#;

#[test]
fn tls13_client_reject_cert_trailing() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xe2,
        "cert-trailing",
        TLS13_CLIENT_REJECT_CERT_TRAILING,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xe3,
        "cert-trailing",
        TLS13_CLIENT_REJECT_CERT_TRAILING,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xe4,
        "cert-trailing",
        TLS13_CLIENT_REJECT_CERT_TRAILING,
    );
}

#[test]
fn tls13_client_reject_cert_truncated() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xe5,
        "cert-truncated",
        TLS13_CLIENT_REJECT_CERT_TRUNCATED,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xe6,
        "cert-truncated",
        TLS13_CLIENT_REJECT_CERT_TRUNCATED,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xe7,
        "cert-truncated",
        TLS13_CLIENT_REJECT_CERT_TRUNCATED,
    );
}

#[test]
fn tls13_client_reject_server_finished_corrupt() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xe8,
        "server-finished-corrupt",
        TLS13_CLIENT_REJECT_SERVER_FINISHED_CORRUPT,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xe9,
        "server-finished-corrupt",
        TLS13_CLIENT_REJECT_SERVER_FINISHED_CORRUPT,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xea,
        "server-finished-corrupt",
        TLS13_CLIENT_REJECT_SERVER_FINISHED_CORRUPT,
    );
}

#[test]
fn tls13_client_reject_sh_unoffered_keyshare() {
    run_client_reject_flight(
        ShimKind::Botan,
        0xeb,
        "sh-unoffered-keyshare",
        TLS13_CLIENT_REJECT_SH_UNOFFERED_KEYSHARE,
    );
    run_client_reject_flight(
        ShimKind::OpenSsl,
        0xec,
        "sh-unoffered-keyshare",
        TLS13_CLIENT_REJECT_SH_UNOFFERED_KEYSHARE,
    );
    run_client_reject_flight(
        ShimKind::Rustls,
        0xed,
        "sh-unoffered-keyshare",
        TLS13_CLIENT_REJECT_SH_UNOFFERED_KEYSHARE,
    );
}

// NOTE: two more candidates were probed here and DROPPED as non-uniform (documented as findings
// in notes/audit/coverage_matrix.md, not shipped as tests):
//   - signature_algorithms (0x000d) in EncryptedExtensions: Botan + OpenSSL reject, but rustls
//     ACCEPTS it (its EE handling tolerates a misplaced signature_algorithms).
//   - ServerHello legacy_version=0x0200: Botan rejects (protocol_version), but OpenSSL ACCEPTS
//     it (does not enforce RFC 8446 4.1.3 "MUST be 0x0303" for the ServerHello legacy field).

#[test]
fn botan_shim_tls12_server() {
    run_case(ShimKind::Botan, "tls12-botan", TLS12_SERVER, 0x0303);
}

#[test]
fn botan_shim_tls13_server() {
    run_case(ShimKind::Botan, "tls13-botan", TLS13_SERVER, 0x0304);
}

#[test]
fn openssl_shim_tls12_server() {
    run_case(ShimKind::OpenSsl, "tls12-openssl", TLS12_SERVER, 0x0303);
}

#[test]
fn openssl_shim_tls13_server() {
    run_case(ShimKind::OpenSsl, "tls13-openssl", TLS13_SERVER, 0x0304);
}

#[test]
fn gnutls_shim_tls12_server() {
    run_case(ShimKind::GnuTls, "tls12-gnutls", TLS12_SERVER, 0x0303);
}

#[test]
fn gnutls_shim_tls13_server() {
    run_case(ShimKind::GnuTls, "tls13-gnutls", TLS13_SERVER, 0x0304);
}

#[test]
fn gnutls_shim_dtls12_server() {
    run_dtls_case(
        ShimKind::GnuTls,
        "dtls12-server-gnutls",
        DTLS12_SERVER_SMOKE,
        true,
    );
}

const GNUTLS_TLS12_CBC_SHA2_BAD_MAC: &str = r#"
plzn tls "shim/gnutls-tls12-cbc-sha2-bad-mac" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  matrix { suite in [SUITE] }
  flow handshake {
    send AppData { size: 7 } @ xor[record.mac, -1] = 1
    recv AppData
  }
  expect alert fatal/bad_record_mac
}
"#;

fn run_gnutls_tls12_cbc_sha2_bad_mac(suite: &str, wire: u16, seed: u8) {
    let kind = ShimKind::GnuTls;
    if kind.binary_path().is_none() {
        eprintln!("SKIP gnutls-tls12-cbc-sha2-bad-mac: binary not built");
        return;
    }
    let source = GNUTLS_TLS12_CBC_SHA2_BAD_MAC.replace("SUITE", suite);
    let program = lower_source("gnutls-tls12-cbc-sha2-bad-mac", &source);
    let mut cfg = server_config(0x0303);
    cfg.requires.any_suite = vec![wire];
    cfg.expect.handshake_error = Some(String::new());
    let factory = ShimFactory::new(kind, cfg).expect("shim factory");
    let report = run(&program, &factory, [seed; 32], None);
    let shim = factory.wait_shim().expect("reap shim");
    eprintln!("{}\nshim: {:?}", report, shim);
    assert!(
        matches!(report.status, RunStatus::Pass),
        "{} runner status: {}",
        suite,
        report.observed
    );
    assert!(shim.success, "{} shim outcome: {:?}", suite, shim);
}

#[test]
fn gnutls_shim_tls12_cbc_sha256_bad_mac_alert() {
    run_gnutls_tls12_cbc_sha2_bad_mac("ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc027, 0xd6);
}

#[test]
fn gnutls_shim_tls12_cbc_sha384_bad_mac_alert() {
    run_gnutls_tls12_cbc_sha2_bad_mac("ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xc028, 0xd7);
}

#[test]
fn gnutls_shim_tls12_3des_bad_mac_alert() {
    run_gnutls_tls12_cbc_sha2_bad_mac("ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xc012, 0xd8);
}

#[test]
fn libressl_shim_tls12_server() {
    run_case(ShimKind::LibreSsl, "tls12-libressl", TLS12_SERVER, 0x0303);
}

#[test]
fn libressl_shim_tls13_server() {
    run_case(ShimKind::LibreSsl, "tls13-libressl", TLS13_SERVER, 0x0304);
}

#[test]
fn libressl_shim_dtls12_server() {
    run_dtls_case(
        ShimKind::LibreSsl,
        "dtls12-server-libressl",
        DTLS12_SERVER_SMOKE,
        true,
    );
}

#[test]
fn wolfssl_shim_tls12_server() {
    run_case(ShimKind::WolfSsl, "tls12-wolfssl", TLS12_SERVER, 0x0303);
}

#[test]
fn wolfssl_shim_tls13_server() {
    run_case(ShimKind::WolfSsl, "tls13-wolfssl", TLS13_SERVER, 0x0304);
}

// Go shim: a real subprocess (shims/go), backed only by the standard library's
// crypto/tls package and driven through the same JSON protocol.
#[test]
fn go_shim_tls12_server() {
    run_case(ShimKind::Go, "tls12-go", TLS12_SERVER, 0x0303);
}

#[test]
fn go_shim_tls13_server() {
    run_case(ShimKind::Go, "tls13-go", TLS13_SERVER, 0x0304);
}

#[test]
fn go_shim_tls12_client() {
    run_client_case(ShimKind::Go, "tls12-client-go", TLS12_CLIENT, 0x0303);
}

#[test]
fn go_shim_tls13_client() {
    run_client_case(ShimKind::Go, "tls13-client-go", TLS13_CLIENT, 0x0304);
}

// rustls shim: a real subprocess (`shims/rustls`), driven by the same JSON
// config as the C++ shims.
#[test]
fn rustls_shim_tls12_server() {
    run_case(ShimKind::Rustls, "tls12-rustls", TLS12_SERVER, 0x0303);
}

#[test]
fn rustls_shim_tls13_server() {
    run_case(ShimKind::Rustls, "tls13-rustls", TLS13_SERVER, 0x0304);
}

#[test]
fn rustls_shim_tls12_client() {
    run_client_case(
        ShimKind::Rustls,
        "tls12-client-rustls",
        TLS12_CLIENT,
        0x0303,
    );
}

#[test]
fn rustls_shim_tls13_client() {
    run_client_case(
        ShimKind::Rustls,
        "tls13-client-rustls",
        TLS13_CLIENT,
        0x0304,
    );
}

#[test]
fn rustls_shim_structured_error_cases() {
    run_structured_cases(ShimKind::Rustls);
}

#[test]
fn openssl_shim_tls13_resume() {
    run_resume_case(ShimKind::OpenSsl);
}

#[test]
fn openssl_shim_tls13_client_auth() {
    run_client_auth_ok(ShimKind::OpenSsl);
}

#[test]
fn openssl_shim_tls13_client_auth_missing() {
    run_client_auth_missing(ShimKind::OpenSsl);
}
