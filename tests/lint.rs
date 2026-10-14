// Integration tests: lint every .plzn file under tests/cases/ clean,
// then verify a handful of deliberately-broken inputs produce the
// expected diagnostic categories.

use std::fs;
use std::path::{Path, PathBuf};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_plzn(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(dir).expect("read_dir") {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_plzn(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("plzn") {
            out.push(path);
        }
    }
}

#[test]
fn all_corpus_cases_lint_clean() {
    let mut files = Vec::new();
    collect_plzn(&manifest().join("suite"), &mut files);
    collect_plzn(&manifest().join("tests").join("cases"), &mut files);
    assert!(
        !files.is_empty(),
        "no .plzn files found under suite/ or tests/cases/"
    );
    for path in &files {
        let src = fs::read_to_string(path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let diags = plzn::lint(&name, &src);
        if !diags.is_empty() {
            let rendered: String = diags.iter().map(|d| format!("{}\n", d)).collect();
            panic!("{} failed to lint clean:\n{}", path.display(), rendered);
        }
    }
}

#[test]
fn unknown_uut_version_reports_suggestion() {
    let src = r#"
plzn tls "unknown-cfg" {
  chain: [rsa_2048]
  uut server {
    versions: [tls31],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake {}
  expect ok
}
"#;
    let diags = plzn::lint("snippet", src);
    assert!(!diags.is_empty(), "expected at least one diagnostic");
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("unknown UUT version") && rendered.contains("tls31"),
        "diagnostic should mention the unknown UUT version, got:\n{}",
        rendered
    );
    assert!(
        rendered.contains("did you mean") && rendered.contains("tls12"),
        "diagnostic should suggest tls12 or tls13, got:\n{}",
        rendered
    );
}

#[test]
fn uut_versions_are_required_and_cannot_mix_tls_with_dtls() {
    let missing_role = lint_err(
        r#"
plzn tls "uut/missing-role" {
  chain: [default]
  uut { versions: [tls13] }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        missing_role.contains("expected `client` or `server` after `uut`"),
        "{missing_role}"
    );

    let unknown_role = lint_err(
        r#"
plzn tls "uut/unknown-role" {
  chain: [default]
  uut proxy { versions: [tls13] }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(unknown_role.contains("found `proxy`"), "{unknown_role}");

    let empty = lint_err(
        r#"
plzn tls "versions/empty" {
  chain: [default]
  uut server {
    versions: []
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        empty.contains("must declare at least one version"),
        "{empty}"
    );

    let mixed = lint_err(
        r#"
plzn tls "versions/mixed" {
  chain: [default]
  uut server {
    versions: [tls12, dtls12]
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(mixed.contains("cannot mix TLS and DTLS"), "{mixed}");
}

#[test]
fn legacy_role_and_cfg_lines_point_to_the_uut_migration() {
    let rendered = lint_err(
        r#"
plzn tls "legacy/testing" {
  testing server
  chain: [default]
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("merged into the mandatory UUT block"),
        "{rendered}"
    );

    let rendered = lint_err(
        r#"
plzn tls "legacy/cfg" {
  chain: [default]
  uut server { versions: [tls12] }
  cfg tls12, ecdhe
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("versions"), "{rendered}");
    assert!(rendered.contains("capabilities"), "{rendered}");
}

#[test]
fn unknown_message_reports_suggestion() {
    let src = r#"
plzn tls "unknown-message" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake until send ClientHelo {
    send Finished
  }
  expect alert fatal
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("unknown message") && rendered.contains("ClientHelo"),
        "expected unknown message diagnostic, got:\n{}",
        rendered
    );
    assert!(
        rendered.contains("ClientHello"),
        "expected suggestion of `ClientHello`, got:\n{}",
        rendered
    );
}

#[test]
fn unknown_alert_code_reports_suggestion() {
    let src = r#"
plzn tls "bad-alert" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake {}
  expect alert fatal/decode_err
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("bad alert code") && rendered.contains("decode_err"),
        "expected bad alert code diagnostic, got:\n{}",
        rendered
    );
    assert!(
        rendered.contains("decode_error"),
        "expected suggestion of `decode_error`, got:\n{}",
        rendered
    );
}

#[test]
fn matrix_var_must_be_declared() {
    let src = r#"
plzn tls "bad-matrix-var" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  matrix {
    pos in 0..10
  }
  flow handshake until send Finished {
    send Finished @ xor[$bit] = 0x01
  }
  expect alert fatal/decrypt_error
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("unknown matrix var") && rendered.contains("bit"),
        "expected unknown matrix var diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn bad_byte_path_reports_suggestion() {
    let src = r#"
plzn tls "bad-byte-path" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  matrix {
    pos in 0..15
  }
  flow handshake {
    send AppData { size: 1 } @ xor[record.aed_tag, $pos] = 0x01
  }
  expect alert fatal/bad_record_mac
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("unknown byte path"),
        "expected unknown byte path diagnostic, got:\n{}",
        rendered
    );
    assert!(
        rendered.contains("record.aead_tag"),
        "expected suggestion of `record.aead_tag`, got:\n{}",
        rendered
    );
}

#[test]
fn multi_send_rejected_in_non_anchored_flow() {
    let src = r#"
plzn tls "multi-send-non-anchored" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake {
    send ChangeCipherSpec, Finished
  }
  expect alert fatal/unexpected_message
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("multi-message send is only allowed in anchored"),
        "expected anchored-flow diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn multi_send_rejects_body() {
    let src = r#"
plzn tls "multi-send-with-body" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake until send ClientKeyExchange {
    send ChangeCipherSpec, Finished @ xor[0] = 0xff
  }
  expect alert fatal/unexpected_message
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("multi-message send takes no body"),
        "expected no-body diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn multi_send_rejects_appdata_mix() {
    let src = r#"
plzn tls "multi-send-with-appdata" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake until send ClientKeyExchange {
    send ChangeCipherSpec, AppData
  }
  expect alert fatal/unexpected_message
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("`AppData` cannot appear in a multi-message send"),
        "expected AppData-mix diagnostic, got:\n{}",
        rendered
    );
}

// ---- extension delta grammar and target validation ----

fn lint_ok(src: &str) {
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        diags.is_empty(),
        "expected no diagnostics, got:\n{}",
        rendered
    );
}

fn lint_err(src: &str) -> String {
    let diags = plzn::lint("snippet", src);
    assert!(!diags.is_empty(), "expected a diagnostic");
    diags.iter().map(|d| format!("{}", d)).collect()
}

#[test]
fn client_auth_policy_belongs_to_the_server_role() {
    lint_ok(
        r#"
plzn tls "owner/client-uut" {
  chain: [default]
  uut client {
    versions: [tls13], client_cert: none
  }
  peer { request_client_cert: true }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    lint_ok(
        r#"
plzn tls "owner/server-uut" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );

    let rendered = lint_err(
        r#"
plzn tls "owner/client-cannot-require" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  peer { request_client_cert: true }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("requires `uut client"), "{rendered}");

    let rendered = lint_err(
        r#"
plzn tls "owner/legacy-capability" {
  chain: [default]
  uut client {
    versions: [tls13]
    capabilities: [ecdhe]
  }
  flow handshake {}
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("move it to `peer { capabilities: [...] }`"),
        "{rendered}"
    );
}

#[test]
fn peer_requests_client_auth_without_a_requirement_policy() {
    let source = include_str!("../suite/client/tls13_client_auth_no_cert.plzn");
    lint_ok(source);
    let error = lint_err(&source.replace("request_client_cert", "require_client_cert"));
    assert!(error.contains("unknown peer field `require_client_cert`"));
}

#[test]
fn client_certificate_credential_selector() {
    // `send Certificate { credential: valid | untrusted | none }` picks the
    // testdata credential plzn's own client presents (TLS 1.2 and DTLS).
    lint_ok(
        r#"
plzn tls "cred/tls12-untrusted" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send Certificate { credential: untrusted }
  }
  expect handshake-fails
}
"#,
    );
    lint_ok(
        r#"
plzn tls "cred/dtls-none" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send Certificate { credential: none }
  }
  expect handshake-fails
}
"#,
    );
    // An unknown credential name is a lint error.
    let rendered = lint_err(
        r#"
plzn tls "cred/bad" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send Certificate { credential: bogus }
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("credential"), "{}", rendered);
}

#[test]
fn dtls_session_resumption_lints_clean() {
    // `session` blocks under `versions: [dtls12]` select the abbreviated DTLS presets
    // (both roles); the resumed flow can be anchored and drive flight ops.
    lint_ok(
        r#"
plzn tls "dtls/resume-client-side" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  session initial {
    flow handshake {
      recv ServerHello { has_ext: session_ticket }
      recv NewSessionTicket
      close alert warning/close_notify
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake after recv Finished {
      send ChangeCipherSpec
      send Finished
      hold_flight
      advance_clock 1s
      expect_retransmit
      retransmit_flight
      release_flight
      send AppData
      recv AppData
    }
    expect ok
  }
}
"#,
    );
    lint_ok(
        r#"
plzn tls "dtls/resume-server-side" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  session initial {
    flow handshake {
      recv ClientHello { has_ext: session_ticket }
      send NewSessionTicket { ticket_lifetime: 60 }
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake after recv Finished {
      send AppData
      recv AppData
    }
    expect ok
  }
}
"#,
    );
}

#[test]
fn dtls_structured_paths_resolve_on_mapped_fields() {
    // Every DTLS sender maps its body: a `handshake.<field>` target must name a
    // field that message's encoder produces (schema::handshake_byte_fields).
    lint_ok(
        r#"
plzn tls "dtls/mapped-paths" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello @ xor[handshake.cookie, -1] = 0x01
    send Certificate @ xor[handshake.certificate_list, 8] = 0x01
    send ClientKeyExchange @ xor[handshake.ecdh_point, 1] = 0x01
    send CertificateVerify @ xor[handshake.signature, 0] = 0x01
    send Finished @ xor[handshake.msg_type, 0] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "dtls/unmapped-path" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientKeyExchange @ xor[handshake.verify_data, 0] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("not a field of the ClientKeyExchange body"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "dtls/unmapped-message" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ChangeCipherSpec @ xor[handshake.random, 0] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("bare offsets only"), "{}", rendered);
}

#[test]
fn ext_delta_without_value_is_an_empty_body() {
    // `+ext NAME` (no `= value`) is the empty-body form; the flow must still end
    // in an app-data round trip for `expect ok`.
    lint_ok(
        r#"
plzn tls "ext/empty-value" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      +ext extended_master_secret
      +ext 0x1a1a
    }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn terminal_receive_matcher_satisfies_expect_ok_liveness() {
    lint_ok(
        r#"
plzn tls "liveness/terminal-matcher" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake until recv Certificate {
    recv Certificate { entries: 1 }
  }
  expect ok
}
"#,
    );

    let rendered = lint_err(
        r#"
plzn tls "liveness/empty-recv" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake until recv Certificate {
    recv Certificate
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("must end with an application-data round trip"),
        "expected liveness diagnostic, got:\n{rendered}"
    );
}

#[test]
fn ext_delta_accepts_typed_value_forms() {
    lint_ok(
        r#"
plzn tls "ext/typed-forms" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello {
      +ext status_request = ocsp
      +ext padding = 100
      +ext ec_point_formats = [uncompressed]
      +ext server_certificate_type = [raw_public_key, x509]
      +ext alpn = ["h2"]
      +ext max_fragment_length = 1024
    }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn ext_delta_wrong_value_form_is_reported() {
    let rendered = lint_err(
        r#"
plzn tls "ext/wrong-form" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext status_request = 5 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("does not take an integer"),
        "{}",
        rendered
    );
    assert!(rendered.contains("ocsp"), "{}", rendered);
}

#[test]
fn ext_delta_on_message_no_driver_applies_is_rejected() {
    // A delta on Finished would lint clean and then be silently dropped; lowering
    // rejects it and names the messages that do take deltas for this role.
    let rendered = lint_err(
        r#"
plzn tls "ext/on-finished" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send Finished { +ext 0x1a1a = raw "00" }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("not applied when plzn plays the client"),
        "{}",
        rendered
    );
    assert!(rendered.contains("ClientHello"), "{}", rendered);

    // Server role: EncryptedExtensions takes deltas, ServerHelloDone does not.
    let rendered = lint_err(
        r#"
plzn tls "ext/on-server-hello-done" {
  chain: [default]
  uut client {
    versions: [tls12]
  }
  flow handshake {
    send ServerHelloDone { +ext 0x1a1a = raw "00" }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("not applied when plzn plays the server"),
        "{}",
        rendered
    );
    lint_ok(
        r#"
plzn tls "ext/on-ee" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send EncryptedExtensions { +ext supported_groups = [x25519] }
  }
  expect ok
}
"#,
    );
}

// ---- key shares: the `group` axis and `+ext key_share = [...]` ----

#[test]
fn key_share_list_form_is_client_hello_only() {
    let rendered = lint_err(
        r#"
plzn tls "ks/on-server-hello" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  flow handshake {
    send ServerHello { +ext key_share = [x25519] }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("applies only to the ClientHello"),
        "{}",
        rendered
    );
    lint_ok(
        r#"
plzn tls "ks/on-client-hello" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext key_share = [secp256r1, x25519] }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn key_share_for_x448_is_accepted() {
    lint_ok(
        r#"
plzn tls "ks/x448" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext key_share = [x448] }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    // The first group capability gets the default share.
    lint_ok(
        r#"
plzn tls "ks/cfg-x448-first" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [x448, x25519] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    // Advertising x448 after another implemented group remains fine.
    lint_ok(
        r#"
plzn tls "ks/cfg-x448-second" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [x25519, x448] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn key_share_point_takes_a_symbolic_recipe() {
    lint_ok(
        r#"
plzn tls "ks/point-compressed" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [secp256r1] }
  flow handshake {
    send ClientHello { key_share_point: compressed }
  }
  expect handshake-fails
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "ks/point-typo" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { key_share_point: squashed }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`key_share_point` takes one of"),
        "{}",
        rendered
    );
    assert!(rendered.contains("`compressed`"), "{}", rendered);
    // A number is not a recipe.
    let rendered = lint_err(
        r#"
plzn tls "ks/point-number" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { key_share_point: 1 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("takes a symbolic value"), "{}", rendered);
}

#[test]
fn key_share_byte_path_is_known() {
    lint_ok(
        r#"
plzn tls "ks/point-flip" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [secp256r1] }
  flow handshake {
    send ClientHello @ xor[handshake.key_share, -1] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "ks/point-typo-path" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello @ xor[handshake.key_shair, -1] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("handshake.key_share"), "{}", rendered);
}

#[test]
fn key_share_list_accepts_p521_ffdhe_and_x448() {
    lint_ok(
        r#"
plzn tls "ks/p521-ffdhe" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext key_share = [secp521r1, ffdhe2048, ffdhe3072, x448] }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    lint_ok(
        r#"
plzn tls "ks/cfg-ffdhe-first" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [ffdhe3072, x25519] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    lint_ok(
        r#"
plzn tls "ks/x448-in-list" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext key_share = [secp521r1, x448] }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn key_share_point_bounds_are_named_recipes() {
    lint_ok(
        r#"
plzn tls "ks/ffdhe-one" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [ffdhe2048] }
  flow handshake {
    send ClientHello { key_share_point: one }
  }
  expect handshake-fails
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "ks/ffdhe-bad-bound" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [ffdhe2048] }
  flow handshake {
    send ClientHello { key_share_point: p_minus_2 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("`p_minus_1`"), "{}", rendered);
    assert!(rendered.contains("`one`"), "{}", rendered);
}

// ---- uut policy knobs ----

#[test]
fn uut_policy_knobs_parse() {
    lint_ok(
        r#"
plzn tls "uut/knobs" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
    server_preference: true
    renegotiation: none
    session_tickets: 0
    max_cert_list: 16384
    records_per_traffic_key: 4
    extended_master_secret: require
    encrypt_then_mac: false
    middlebox_compat: true
    signing_prefs: [rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256]
    verify_prefs: [ecdsa_secp256r1_sha256]
    mtu: 1200
    initial_timeout_ms: 250
    min_key_update_interval_ms: 0
    psk_secret: "0a0B0c"
    psk_identity: "other"
    client_cert: untrusted
    renegotiate_after_handshake: true
    half_rtt_data: ["h", "r", "t"]
    alpn_select_from: ["h2", "http/1.1"]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn uut_peer_knob_values_are_checked() {
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-client-cert" {
  chain: [default]
  uut client {
    versions: [tls13]
    client_cert: forged
  }
  peer { request_client_cert: true }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`client_cert` takes one of"),
        "{}",
        rendered
    );
    assert!(rendered.contains("`expired`"), "{}", rendered);
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-psk-secret" {
  chain: [default]
  uut client {
    versions: [tls13]
    psk_secret: "abc"
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("psk_secret"), "{}", rendered);
    assert!(rendered.contains("even number of digits"), "{}", rendered);
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-half-rtt" {
  chain: [default]
  uut server {
    versions: [tls13]
    half_rtt_data: "hrt"
  }
  flow handshake {}
  expect ok
}
"#,
    );
    assert!(rendered.contains("half_rtt_data"), "{}", rendered);
}

#[test]
fn uut_policy_knob_values_are_checked() {
    let rendered = lint_err(
        r#"
plzn tls "uut/conflicting-alpn-selection" {
  chain: [default]
  uut server {
    versions: [tls13]
    alpn_select: "h2"
    alpn_select_from: ["h2", "http/1.1"]
  }
  flow handshake {}
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`alpn_select` and `alpn_select_from` are mutually exclusive"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-reneg" {
  chain: [default]
  uut server {
    versions: [tls12]
    renegotiation: sometimes
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`renegotiation` takes one of"),
        "{}",
        rendered
    );
    assert!(rendered.contains("`both`"), "{}", rendered);
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-ems" {
  chain: [default]
  uut server {
    versions: [tls12]
    extended_master_secret: maybe
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`extended_master_secret` takes one of"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "uut/bad-sigalg" {
  chain: [default]
  uut server {
    versions: [tls12]
    signing_prefs: [rsa_pss_rsae_sha9999]
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("unknown signature scheme"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "uut/unknown-key" {
  chain: [default]
  uut server {
    versions: [tls12]
    tickets: 0
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("unknown uut field `tickets`"),
        "{}",
        rendered
    );
    assert!(rendered.contains("session_tickets"), "{}", rendered);
}

#[test]
fn rfc_section_is_written_bare() {
    // `rfc <n> section <sec>`: a dotted number, or a letter for an appendix.
    let src = r#"
plzn tls "rfc/sections" {
  rfc 8446
  rfc 5246 section 7.4.1.4.1
  rfc 8446 section B.4
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    let refs: Vec<(u32, Option<&str>)> = programs[0]
        .rfc_refs
        .iter()
        .map(|r| (r.number, r.section.as_deref()))
        .collect();
    assert_eq!(
        refs,
        vec![(8446, None), (5246, Some("7.4.1.4.1")), (8446, Some("B.4")),]
    );
    lint_ok(src);
}

#[test]
fn quoted_rfc_section_names_its_replacement() {
    let rendered = lint_err(
        r#"
plzn tls "rfc/quoted" {
  rfc 8446 "§4.1.2"
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("section 4.1.2"), "{}", rendered);
}

#[test]
fn skip_directive_takes_an_optional_reason() {
    let src = r#"
plzn tls "skip/reason" {
  chain: [default]
  skip rustls "does not enforce the record limit"
  skip openssl, botan
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(
        programs[0].skip_backends,
        vec![
            (
                "rustls".to_string(),
                Some("does not enforce the record limit".to_string())
            ),
            ("openssl".to_string(), None),
            ("botan".to_string(), None),
        ]
    );
}

#[test]
fn xfail_directive_lowers_separately_from_skip() {
    let src = r#"
plzn tls "xfail/reason" {
  chain: [default]
  xfail rustls "accepts an invalid record"
  xfail openssl, botan
  skip wolfssl "feature unavailable"
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(
        programs[0].xfail_backends,
        vec![
            (
                "rustls".to_string(),
                Some("accepts an invalid record".to_string())
            ),
            ("openssl".to_string(), None),
            ("botan".to_string(), None),
        ]
    );
    assert_eq!(
        programs[0].skip_backends,
        vec![(
            "wolfssl".to_string(),
            Some("feature unavailable".to_string())
        )]
    );
}

#[test]
fn cipher_family_capabilities_lint() {
    for tok in [
        "ccm",
        "ccm8",
        "aria",
        "camellia",
        "des3",
        "null",
        "sha384",
        "chacha20_poly1305",
        "aes256_gcm_sha384",
        "aes256_cbc_sha",
    ] {
        let src = format!(
            r#"
plzn tls "suites/token-{tok}" {{
  chain: [rsa_2048]
  uut server {{ versions: [tls12] }}
  peer {{ capabilities: [{tok}] }}
  flow handshake {{
    send AppData
    recv AppData
  }}
  expect ok
}}
"#
        );
        lint_ok(&src);
    }
}

// ---- DTLS flight steps, send alert, DTLS uut knobs ----

#[test]
fn dtls_flight_steps_and_knobs_parse() {
    lint_ok(
        r#"
plzn tls "dtls/steps" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
    initial_timeout_ms: 1
    dtls_max_retransmissions: 2
    dtls_max_timeout_ms: 8
    dtls_require_cookie: false
    dtls_epoch0_restart: true
    dtls_max_hello_verify_requests: 4
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after send Finished {
    send HelloRequest
    discard_flight
    expect next_timeout 1s
    set_timeout 250ms
    expect no_timeout
    advance_clock 1ms
    expect_retransmit no_ccs
    recv ClientHello
    hold_flight
    hold_retransmit
    release_flight [1]
    retransmit_flight split [0, 2, 1]
    retransmit_flight
    replay_flight 2
    map_record_sequences multiply 1023
    map_record_sequences xor 255
    map_record_sequences identity
    send alert warning/no_renegotiation
    hvr_flood 24 max_answers 4
    wait 100ms
  }
  assert max_datagram_size 256
  expect close
}
"#,
    );
    lint_ok(
        r#"
plzn tls "dtls/client-steps" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after recv Finished {
    begin_renegotiation
    send ClientHello
    restart
    send ClientHello
  }
  expect ok
}
"#,
    );
}

#[test]
fn dtls_timer_controls_reject_tls_and_fractional_millisecond_updates() {
    let rendered = lint_err(
        r#"
plzn tls "tls/timer-control" {
  chain: [ecdsa_p256]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    expect next_timeout 1us
    expect no_timeout
    set_timeout 1ms
  }
  expect timeout
}
"#,
    );
    assert!(rendered.contains("DTLS step"), "{}", rendered);
    assert!(rendered.contains("DTLS outcome"), "{}", rendered);

    let rendered = lint_err(
        r#"
plzn tls "dtls/fractional-update" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow { set_timeout 1us }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("whole number of milliseconds"),
        "{}",
        rendered
    );
}

#[test]
fn max_datagram_size_assert_needs_dtls() {
    let rendered = lint_err(
        r#"
plzn tls "tls/datagram-size" {
  chain: [ecdsa_p256]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send AppData
    recv AppData
  }
  assert max_datagram_size 256
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("requires `versions: [dtls12]`"),
        "{}",
        rendered
    );
}

#[test]
fn dtls_flight_steps_need_dtls12_version() {
    let rendered = lint_err(
        r#"
plzn tls "dtls/steps-on-tls" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    discard_flight
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("is a DTLS step"), "{}", rendered);
    let rendered = lint_err(
        r#"
plzn tls "dtls/alert-needs-code" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send alert warning
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("needs a code"), "{}", rendered);
}

#[test]
fn dtls_fragmentation_schemes_parse() {
    // The `send Msg @ <scheme>` fragmentation suffixes on the client side.
    lint_ok(
        r#"
plzn tls "dtls/frag-client" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello @ fragment 16
    send ClientKeyExchange @ duplicate_fragment 8
  }
  expect ok
}
"#,
    );
    // Every scheme, plus the two new flight ops, on the server side.
    lint_ok(
        r#"
plzn tls "dtls/frag-server" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow {
    recv ClientHello
    send HelloVerifyRequest
    recv ClientHello
    send ServerHello @ reorder 16
    send Certificate @ fragment 64
    send ServerKeyExchange @ reorder_overlap 3
    send Certificate @ complete_and_fragments 8
    send ServerHelloDone @ empty_fragments
    send ServerHello @ split_fragment_record 12
    send ServerKeyExchange @ overlap_mismatch 8
    send Certificate @ type_mismatch 8
    send ServerHelloDone @ offset_overflow
    send ClientKeyExchange @ fragment_length_mismatch 8
    future_seq_first
    interleave_flight
    interleave_flight split
    header_only_flood 8
    large_length_fragment 16777215
    recv ClientKeyExchange
    recv ChangeCipherSpec
    recv Finished
    send ChangeCipherSpec
    send Finished
  }
  expect ok
}
"#,
    );
    // A scheme and a byte mutation may share the `@` list on one send.
    lint_ok(
        r#"
plzn tls "dtls/frag-and-mutation" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello @ length_mismatch 16, @ xor[0] = 0xff
  }
  expect ok
}
"#,
    );
}

#[test]
fn dtls13_header_ack_and_previous_epoch_controls_parse() {
    lint_ok(
        r#"
plzn tls "dtls13/new-controls" {
  chain: [default]
  uut server { versions: [dtls13] }
  flow handshake until send Finished {
    suppress_ack
    send Finished @ future_sequence_packed 1, dtls13_short_sequence, dtls13_omit_length
    set_mtu 512
    send_ack first outer_epoch 0 overflow_epoch
    expect_ack
    send_previous_epoch Finished
    retransmit_previous_epoch Finished
    send Certificate @ fragment 16 hold_all
    flush_fragment
  }
  expect handshake-fails
}
"#,
    );

    let rendered = lint_err(
        r#"
plzn tls "tls13/dtls-header-control" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake { send AppData @ dtls13_set_cid_bit }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("DTLS 1.3 record-header control"),
        "{}",
        rendered
    );
}

#[test]
fn dtls_fragmentation_scheme_needs_dtls12_version() {
    // A fragmentation suffix on a TLS (non-DTLS) test is rejected.
    let rendered = lint_err(
        r#"
plzn tls "tls/frag" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send ClientHello @ duplicate_fragment 16
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("DTLS-only"), "{}", rendered);
    // The new DTLS flight ops are guarded like every other DTLS step.
    let rendered = lint_err(
        r#"
plzn tls "tls/flood" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow {
    header_only_flood 4
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("is a DTLS step"), "{}", rendered);
    // A scheme cannot be applied to a non-handshake message.
    let rendered = lint_err(
        r#"
plzn tls "dtls/frag-appdata" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after recv Finished {
    send AppData { size: 2 } @ fragment 4
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("cannot be applied to"), "{}", rendered);
}

#[test]
fn large_length_fragment_bounds_and_guard() {
    // The declared length must fit the 24-bit handshake length field.
    let rendered = lint_err(
        r#"
plzn tls "dtls/too-large" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  flow handshake {
    large_length_fragment 16777216
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("24-bit length"), "{}", rendered);
    // Zero is rejected too (a fragment carries one body byte, so length >= 1).
    let rendered = lint_err(
        r#"
plzn tls "dtls/zero" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  flow handshake {
    large_length_fragment 0
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("24-bit length"), "{}", rendered);
    // Like every DTLS flight op, it is rejected on a non-DTLS test.
    let rendered = lint_err(
        r#"
plzn tls "tls/large" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow {
    large_length_fragment 16777215
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("is a DTLS step"), "{}", rendered);
}

#[test]
fn uut_cipher_suites_accept_matrix_variables() {
    let src = r#"
plzn tls "uut/suite-var" {
  chain: [ecdsa_p256]
  matrix {
    suite in [ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256]
  }
  uut client {
    versions: [dtls12]
    cipher_suites: [$suite, ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    recv ClientHello { cipher_suites: [$suite] }
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(programs.len(), 2);
    assert_eq!(
        programs[0].uut.as_ref().unwrap().cipher_suites,
        vec![0xc02b, 0xc02c]
    );
    assert_eq!(
        programs[1].uut.as_ref().unwrap().cipher_suites,
        vec![0xcca9, 0xc02c]
    );
    let rendered = lint_err(
        r#"
plzn tls "uut/suite-var-unbound" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
    cipher_suites: [$nope]
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {}
  expect ok
}
"#,
    );
    assert!(rendered.contains("not a matrix variable"), "{}", rendered);
}

#[test]
fn dtls_matchers_and_overrides_on_the_parsed_messages() {
    // The DTLS client parses (and so matches on) HelloVerifyRequest,
    // Certificate, ServerKeyExchange and CertificateRequest; both DTLS roles
    // take the TLS 1.2 field overrides on the hellos and key exchanges.
    lint_ok(
        r#"
plzn tls "dtls/matchers-server-flight" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
    require_client_cert: true
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello { legacy_version: 0xfeff, random: 0x00 * 32, legacy_session_id: [0x01], compression_methods: [0x00] }
    recv HelloVerifyRequest { cookie_len: 16 }
    recv Certificate { entries: 1 }
    recv ServerKeyExchange { named_group: secp256r1, signature_scheme: ecdsa_secp256r1_sha256 }
    recv CertificateRequest { has_sigalg: 0x0403, has_cert_type: 64 }
    send Certificate { certificate_list: [] }
    send ClientKeyExchange { key_share_point: zero }
    send CertificateVerify @ xor[-1] = 0x01
  }
  expect handshake-fails
}
"#,
    );
    lint_ok(
        r#"
plzn tls "dtls/overrides-client-side" {
  chain: [rsa_2048]
  uut client {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256], request_client_cert: true }
  flow handshake {
    recv ClientHello { has_ext: supported_groups, server_name: "localhost" }
    send ServerHello { cipher_suite: AES_128_GCM_SHA256, legacy_compression_method: 1 }
    send ServerKeyExchange { named_group: secp521r1, key_share_point: zero }
  }
  expect handshake-fails
}
"#,
    );
}

#[test]
fn dtls12_rejects_an_unimplemented_finished_matcher() {
    let rendered = lint_err(
        r#"
plzn tls "dtls/matcher-on-finished" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    recv Finished { verify_data: [0x00] }
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("not applied by the DTLS 1.2 drivers"),
        "{}",
        rendered
    );
    lint_ok(
        r#"
plzn tls "dtls/matcher-on-server-hello" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    recv ServerHello { cipher_suite: ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 }
  }
  expect ok
}
"#,
    );
}

// TLS 1.2 parity syntax: signature-scheme / group NAMES where a u16 is
// expected, contains-all list matchers on the ClientHello, the
// CertificateRequest / Certificate override fields and the PSK kex tokens.
#[test]
fn tls12_parity_syntax_lints_clean() {
    let src = r#"
plzn tls "parity/tls12-server-side" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, secp384r1, rsa_pss_rsae_sha384], request_client_cert: true }
  flow handshake {
    recv ClientHello { supported_groups: [secp384r1, x25519], signature_algorithms: [rsa_pss_rsae_sha384], server_name: "localhost" }
    send ServerKeyExchange { named_group: secp384r1, signature_scheme: rsa_pss_rsae_sha384, key_share_point: zero }
    send CertificateRequest { certificate_types: [rsa_sign, ecdsa_sign], signature_algorithms: [ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256] }
    send Certificate { entries: 0 }
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "parity/tls12-psk-client-side" {
  chain: []
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_psk] }
  psk {
    identity: "id"
    secret: "6f6c6f6c"
  }
  flow handshake {
    recv ServerKeyExchange { named_group: x25519, psk_identity_hint: "id" }
    send ClientKeyExchange { psk_identity: "other" }
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}\n", d)).collect();
    assert!(diags.is_empty(), "expected clean lint, got:\n{}", rendered);
}

#[test]
fn unknown_signature_scheme_name_is_rejected() {
    let src = r#"
plzn tls "parity/bad-scheme-name" {
  chain: [default]
  uut client {
    versions: [tls12]
  }
  flow handshake {
    send ServerKeyExchange { signature_scheme: rsa_pss_sha256 }
    send AppData
    recv AppData
  }
  expect ok
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("rsa_pss_sha256")
            && rendered.contains("is not a signature scheme, named group"),
        "diagnostic should name the bad scheme, got:\n{}",
        rendered
    );
}

// TLS 1.3 client-side matchers on the encrypted server flight and the
// post-handshake ticket (schema `fields_for` entries added 2026-09-05).
#[test]
fn tls13_client_matchers_on_encrypted_flight_lint() {
    lint_ok(
        r#"
plzn tls "lint/tls13-client-matchers" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    recv EncryptedExtensions { lacks_ext: pre_shared_key }
    recv Certificate { entries: 1, leaf_lacks_ext: signed_certificate_timestamp }
    recv NewSessionTicket { max_ticket_lifetime_hours: 168, has_ext: early_data }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

// A `session` block accepts a per-backend `expect ... if` override, the
// server-side `psk_mode` override, and `send NewSessionTicket` overrides.
#[test]
fn session_block_expect_override_and_psk_mode_lint() {
    lint_ok(
        r#"
plzn tls "lint/session-overrides" {
  chain: [default]
  uut client {
    versions: [tls13]
  }
  session initial {
    flow handshake after recv Finished {
      send NewSessionTicket { ticket_lifetime_days: 1 }
      close alert warning/close_notify
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake {
      send ServerHello { psk_mode: psk_ke }
    }
    expect alert fatal/illegal_parameter
    expect alert fatal/missing_extension if rustls
  }
}
"#,
    );
}

// `send alert level/code` is a step in its own right (no close).
#[test]
fn send_alert_step_lint() {
    lint_ok(
        r#"
plzn tls "lint/send-alert" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send alert warning/user_canceled
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

// TLS 1.2 tickets on plzn's server: the `session_ticket` capability, the abbreviated
// resumed server preset, and NewSessionTicket overrides (a zero-length ticket).
#[test]
fn tls12_session_ticket_syntax_lints_clean() {
    lint_ok(
        r#"
plzn tls "lint/tls12-tickets" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, session_ticket] }
  session initial {
    flow handshake {
      send AppData
      recv AppData
      close alert warning/close_notify
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

plzn tls "lint/tls12-nst-override" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, session_ticket] }
  flow {
    recv ClientHello { has_ext: session_ticket }
    send ServerHello { -ext session_ticket }
    send Certificate
    send ServerKeyExchange
    send ServerHelloDone
    recv ClientKeyExchange
    recv ChangeCipherSpec
    recv Finished
    send NewSessionTicket { ticket: "", ticket_lifetime: 0 }
    send ChangeCipherSpec
    send Finished
    send alert warning/user_canceled
    wait 100 ms
  }
  expect ok
}
"#,
    );
}

/// DTLS parity round two: the PSK families, SNI, the server-side Certificate /
/// CertificateRequest / ServerKeyExchange knobs, Finished overrides and `close
/// alert` lint clean over DTLS in both roles.
#[test]
fn dtls_psk_families_sni_and_server_knobs_lint_clean() {
    let src = r#"
plzn tls "parity/dtls12-ecdhe-psk-client-side" {
  chain: []
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_psk, chacha20_poly1305, secp256r1] }
  psk {
    identity: "id"
    secret: "6f6c6f6c"
  }
  flow handshake {
    send ClientHello { +ext server_name = "example.com" }
    recv ServerKeyExchange { named_group: secp256r1, psk_identity_hint: "id" }
    send ClientKeyExchange { psk_identity: "other", key_share_point: zero }
    send Finished { verify_data: 0x00 * 12 }
    send AppData
    recv AppData
    close alert warning/close_notify
  }
  expect ok
}

plzn tls "parity/dtls12-server-side" {
  chain: []
  psk {
    identity: "id"
    secret: "6f6c6f6c"
  }
  uut client {
    versions: [dtls12]
    cipher_suites: [ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256]
  }
  peer { capabilities: [ecdhe_psk] }
  flow handshake {
    recv ClientHello { cipher_suites: [ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256], has_ext: server_name }
    send ServerKeyExchange { psk_identity_hint: "someone-else", key_share_point: truncated }
    send Finished { verify_data: 0x00 * 12 }
    close alert fatal/internal_error
  }
  expect ok
}
"#;
    let diags = plzn::lint("snippet", src);
    let rendered: String = diags.iter().map(|d| format!("{}\n", d)).collect();
    assert!(diags.is_empty(), "expected clean lint, got:\n{}", rendered);
}

// ---- record-layer fragmentation controls (`@ fragment`, `coalesce`,
// `send empty_record`, `flush_fragment`) ----

#[test]
fn fragmentation_controls_lint_clean_on_tls() {
    lint_ok(
        r#"
plzn tls "frag/tls13-client" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  matrix {
    size in [1, 16, 255]
  }
  flow handshake until send ChangeCipherSpec {
    send empty_record handshake
    send ChangeCipherSpec
    send Finished @ fragment $size
    send KeyUpdate { request_update: update_not_requested } @ fragment 3 hold
    send AppData
    flush_fragment
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "frag/tls12-server" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake until send ServerHello {
    coalesce {
      send ServerHello
      send Certificate
      send ServerKeyExchange
      send ServerHelloDone
    }
    recv ClientKeyExchange
    recv ChangeCipherSpec
    recv Finished
    send Finished @ fragment 6 hold
    send ChangeCipherSpec
    flush_fragment
    send empty_record application_data
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn fragment_keyword_means_handshake_fragmentation_over_dtls() {
    // One keyword, two meanings: TLS record-layer records, DTLS handshake
    // fragments. DTLS 1.2 lacks the DTLS 1.3 held-fragment machinery.
    lint_ok(
        r#"
plzn tls "lint/dtls-fragment" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello @ fragment 16
  }
  expect ok
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "lint/dtls-fragment-hold" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    send ClientHello @ fragment 16 hold
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`@ fragment N hold` / `flush_fragment` require DTLS 1.3"),
        "{}",
        rendered
    );
}

#[test]
fn dtls_accepts_explicit_records_but_rejects_stream_record_controls() {
    lint_ok(
        r#"
plzn tls "frag/dtls-records" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake {
    send empty_record handshake
    send record 255 "garbage" @ xor[record.content_type, 0] = 1
  }
  expect handshake-fails
}
"#,
    );
    let rendered = lint_err(
        r#"
plzn tls "frag/dtls-steps" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa] }
  flow handshake until send ClientKeyExchange {
    coalesce {
      send ClientKeyExchange
    }
    flush_fragment
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`coalesce { ... }` is available for TLS and DTLS 1.3 unified records")
            && rendered.contains("`flush_fragment` requires TLS or DTLS 1.3"),
        "expected the two DTLS step diagnostics, got:\n{}",
        rendered
    );
}

#[test]
fn fragment_requires_a_positive_record_size() {
    let rendered = lint_err(
        r#"
plzn tls "frag/zero" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello @ fragment 0
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("fragment N requires a positive record size"),
        "expected the fragment-size diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn empty_record_rejects_an_unknown_content_type() {
    let rendered = lint_err(
        r#"
plzn tls "frag/empty-heartbeat" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send empty_record heartbeat
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`send empty_record` takes `handshake`, `alert`, `change_cipher_spec`"),
        "expected the content-type diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn coalesce_blocks_do_not_nest() {
    let rendered = lint_err(
        r#"
plzn tls "frag/nested" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake until send ServerHello {
    coalesce {
      send ServerHello
      coalesce {
        send Certificate
      }
    }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`coalesce` blocks do not nest"),
        "expected the nesting diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn rotate_cookie_secret_is_a_dtls_step() {
    let rendered = lint_err(
        r#"
plzn tls "dtls/rotate-tls" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    rotate_cookie_secret
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`rotate_cookie_secret` is a DTLS step"),
        "expected the DTLS-only diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn rotate_cookie_secret_needs_uut_server() {
    let rendered = lint_err(
        r#"
plzn tls "dtls/rotate-client" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12],
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake {
    rotate_cookie_secret
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("rotates the shim SERVER's cookie secret"),
        "expected the uut-server diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn shim_reassembly_self_test_controls_are_not_uut_policy() {
    for knob in [
        "dtls_fragment: 16",
        "dtls_fragment_forgery: overlap_mismatch",
    ] {
        let source = r#"
plzn tls "dtls/self-test-control" {
  chain: [rsa_2048]
  uut server {
    versions: [dtls12]
    KNOB
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {}
  expect ok
}
"#
        .replace("KNOB", knob);
        let rendered = lint_err(&source);
        let name = knob.split(':').next().unwrap();
        assert!(
            rendered.contains(&format!("unknown uut field `{name}`")),
            "self-test controls must not be exposed as UUT policy:\n{rendered}"
        );
    }
}

#[test]
fn dtls_client_initiated_renegotiation_lints_clean() {
    // A `uut client` DTLS flow may take a client-initiated renegotiation
    // after the initial Finished: stepped, with a cookie exchange on the
    // renegotiation, or refused with a no_renegotiation warning and
    // application data afterwards.
    lint_ok(
        r#"
plzn tls "dtls/client-reneg-cookie" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
    renegotiate_after_handshake: true
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after send Finished {
    send AppData
    recv AppData
    recv ClientHello { has_ext: renegotiation_info }
    send HelloVerifyRequest
    recv ClientHello { has_ext: renegotiation_info }
    send ServerHello
    send Certificate
    send ServerKeyExchange
    send ServerHelloDone
    recv ClientKeyExchange
    recv ChangeCipherSpec
    recv Finished
    send ChangeCipherSpec
    send Finished
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "dtls/client-reneg-refused" {
  chain: [ecdsa_p256]
  uut client {
    versions: [dtls12]
    renegotiate_after_handshake: true
  }
  peer { capabilities: [ecdhe_ecdsa, aes128_gcm_sha256] }
  flow handshake after send Finished {
    send AppData
    recv AppData
    recv ClientHello { has_ext: renegotiation_info }
    send alert warning/no_renegotiation
    send AppData
    recv AppData
  }
  expect ok
  expect alert fatal/handshake_failure if openssl
}
"#,
    );
}

// T3: CertificateVerify signing controls, typed credentials, composed
// certificate lists, the TLS 1.3 CertificateRequest sigalg matcher.
#[test]
fn certificate_verify_signing_controls_lint_clean() {
    lint_ok(
        r#"
plzn tls "cv/controls" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello { +ext signature_algorithms = [rsa_pkcs1_sha256, rsa_pkcs1_md5, ecdsa_sha224, ecdsa_md5] }
    recv ServerHello
    recv Certificate
    recv ServerKeyExchange
    recv CertificateRequest { signature_algorithms: [rsa_pkcs1_sha256] }
    recv ServerHelloDone
    send Certificate { credential: rsa }
    send ClientKeyExchange
    send CertificateVerify { sign_with: rsa_pkcs1_md5, algorithm: rsa_pkcs1_sha256, salt_length: 20, mgf1_hash: sha384, format: tls11 } @ xor[signature.em, -1] = 0x01, @ set[signature.em, 1] = 0x02
    send ChangeCipherSpec
    send Finished
  }
  expect alert fatal/decrypt_error
}

plzn tls "cv/tls13-composed" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {
    send ClientHello
    recv ServerHello
    recv EncryptedExtensions
    recv CertificateRequest { signature_algorithms: [rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256] }
    recv Certificate
    recv CertificateVerify
    recv Finished
    send Certificate { certificate_list: [ecdsa_p384, empty, rsa_pss] }
    send CertificateVerify { sign_with: ecdsa_brainpoolP256r1tls13_sha256 }
    send Finished
  }
  expect handshake-fails
}
"#,
    );
}

#[test]
fn certificate_verify_controls_reject_bad_values() {
    let err = lint_err(
        r#"
plzn tls "cv/bad-format" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send CertificateVerify { format: tls10 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("`format` takes one of"), "{}", err);
    let err = lint_err(
        r#"
plzn tls "cv/bad-credential" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12], require_client_cert: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send Certificate { credential: dsa }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("`credential` takes one of"), "{}", err);
    let err = lint_err(
        r#"
plzn tls "cv/bad-mgf1" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  flow handshake {
    send CertificateVerify { mgf1_hash: sha3 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("`mgf1_hash` takes one of"), "{}", err);
}

// ---------------------------------------------------------------------------
// T6: new messages and steps (Heartbeat, CertificateStatus,
// CompressedCertificate, post-handshake auth, SSLv2-format ClientHello,
// literal ClientHello, recv alert, close reset, repeat).
// ---------------------------------------------------------------------------

#[test]
fn t6_heartbeat_steps_lint_clean() {
    lint_ok(
        r#"
plzn tls "t6/heartbeat" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send ClientHello { +ext heartbeat = peer_allowed_to_send }
    recv ServerHello { has_ext: heartbeat }
    send Heartbeat "ping" { payload_length: 64 }
    recv Heartbeat { payload: "ping", padding_min: 16 }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn t6_certificate_status_and_compression_lint_clean() {
    lint_ok(
        r#"
plzn tls "t6/ocsp-and-compression" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
    ocsp_stapling: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow {
    send ClientHello { +ext status_request = ocsp }
    recv ServerHello { has_ext: status_request }
    recv Certificate
    recv CertificateStatus { status_type: ocsp }
    recv ServerKeyExchange
    recv ServerHelloDone
    send ClientKeyExchange
    send ChangeCipherSpec
    send Finished
    recv ChangeCipherSpec
    recv Finished
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "t6/compressed-certificate" {
  chain: [default]
  uut server {
    versions: [tls13], require_client_cert: true
  }
  peer { capabilities: [compress_cert] }
  flow handshake until recv CertificateRequest {
    recv CertificateRequest { has_ext: compress_certificate }
    recv Certificate { compressed: 1 }
    recv CertificateVerify
    recv Finished
    send CompressedCertificate { algorithm: zlib, uncompressed_length: 4095 }
    send CertificateVerify
    send Finished
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn t6_post_handshake_auth_and_close_reset_lint_clean() {
    lint_ok(
        r#"
plzn tls "t6/pha" {
  chain: [default]
  uut server {
    versions: [tls13]
    post_handshake_auth: request, require_client_cert: true
  }
  flow handshake {
    send ClientHello { +ext post_handshake_auth }
    recv CertificateRequest { has_ext: compress_certificate }
    send Certificate
    send CertificateVerify
    send Finished
    send AppData
    recv AppData
    close reset
  }
  expect ok
}
"#,
    );
}

#[test]
fn t6_sslv2_format_repeat_and_recv_alert_lint_clean() {
    lint_ok(
        r#"
plzn tls "t6/sslv2-hello" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow {
    send ClientHello { format: sslv2, legacy_version: 0x0300, cipher_specs: [0x01, 0x00, 0x80, 0x00, 0x00, 0x2f] }
    recv ServerHello
    close
  }
  expect handshake-fails
}

plzn tls "t6/repeat-and-recv-alert" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    repeat 3 {
      send AppData
      recv AppData
    }
    send alert warning/close_notify
    recv alert warning/close_notify
    close
  }
  expect ok
}

plzn tls "t6/literal-hello" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow {
    send ClientHello raw "0303" + 0x00 * 32 + "00" + "0002002f" + "0100" + "0000"
    recv ServerHello
    close
  }
  expect ok
}
"#,
    );
}

#[test]
fn t6_recv_alert_rejects_an_unknown_code_and_repeat_needs_a_count() {
    let rendered = lint_err(
        r#"
plzn tls "t6/bad-alert" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    recv alert warning/not_an_alert
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`not_an_alert` is not a valid alert code"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "t6/bad-repeat" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    repeat 0 {
      send AppData
    }
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`repeat N` takes a count from 1 to 100000"),
        "{}",
        rendered
    );
}

// ---- tlsfuzzer kex / curve / cipher port (2026-09-08): key_share_point forms, PKCS#1 paths,
// byte fills, KEM and brainpool groups.

#[test]
fn key_share_point_forms_lint_clean_on_hello_and_cke() {
    lint_ok(
        r#"
plzn tls "lint/ksp-forms" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [ffdhe2048] }
  flow handshake {
    send ClientHello { key_share_point: p }
    recv ServerHello
  }
  expect alert fatal/illegal_parameter
}
plzn tls "lint/ksp-other-group" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [x25519mlkem768] }
  flow handshake {
    send ClientHello { key_share_point: mlkem768 }
    recv ServerHello
  }
  expect alert fatal/illegal_parameter
}
plzn tls "lint/ksp-literal-and-fill" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [x25519] }
  flow handshake {
    send ClientHello { key_share_point: 0x37 * 31 }
    recv ServerHello
  }
  expect alert fatal/illegal_parameter
}
plzn tls "lint/cke-encodings" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, secp256r1] }
  flow handshake {
    send ClientKeyExchange { key_share_point: hybrid }
    send ChangeCipherSpec
    send Finished
  }
  expect alert fatal/illegal_parameter
}
"#,
    );
}

#[test]
fn pkcs1_paths_and_rsa_overrides_lint_clean() {
    lint_ok(
        r#"
plzn tls "lint/pkcs1" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa] }
  flow handshake {
    send ClientKeyExchange { padding_byte: 0x55 } @ set[pkcs1.block_type, 0] = 0x01, @ set[pkcs1.padding, -1] = 0x00
    send ChangeCipherSpec
    send Finished
  }
  expect alert fatal/bad_record_mac
}
plzn tls "lint/rsa-plaintext-and-modulus" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa] }
  flow handshake {
    send ClientKeyExchange { rsa_plaintext: 0xff * 256 }
    send ChangeCipherSpec
    send Finished
  }
  expect alert fatal/bad_record_mac
}
plzn tls "lint/modulus-and-leading-zeros" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [dhe_rsa] }
  flow handshake {
    send ClientKeyExchange { shared_secret_leading_zeros: 1 }
    send ChangeCipherSpec
    send Finished
    recv ChangeCipherSpec
    recv Finished
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#,
    );
}

#[test]
fn pkcs1_path_is_rejected_off_the_client_key_exchange() {
    let err = lint_err(
        r#"
plzn tls "lint/pkcs1-wrong-message" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa] }
  flow handshake {
    send Finished @ set[pkcs1.padding, 0] = 0x01
  }
  expect alert fatal/bad_record_mac
}
"#,
    );
    assert!(err.contains("pkcs1"), "{err}");
}

#[test]
fn kem_and_brainpool_groups_are_capabilities() {
    lint_ok(
        r#"
plzn tls "lint/pq-groups" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [x448mlkem1024] }
  flow handshake {
    recv ServerHello { key_share_group: X448MLKEM1024 }
    send AppData
    recv AppData
  }
  expect ok
}
plzn tls "lint/brainpool-tls12" {
  chain: [rsa_2048]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, brainpoolP384r1] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn t5_decorated_renegotiate_lints_clean() {
    // T5: `renegotiate { ... }` customizes the renegotiation ClientHello,
    // `renegotiate resumed` requests an abbreviated second handshake, and
    // `renegotiate insecure` omits renegotiation_info (RFC 5746 3.5).
    lint_ok(
        r#"
plzn tls "reneg/decorated" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
    renegotiate {
      cipher_suites: [ECDHE_RSA_WITH_AES_128_GCM_SHA256, EMPTY_RENEGOTIATION_INFO_SCSV]
      +ext encrypt_then_mac
    }
  }
  expect alert fatal/handshake_failure
}

plzn tls "reneg/insecure" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello { -ext renegotiation_info }
    send AppData
    recv AppData
    renegotiate insecure
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "reneg/resumed" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [session_id] }
  flow handshake {
    send AppData
    recv AppData
    renegotiate resumed { -ext signature_algorithms }
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "session/cross-version" {
  chain: [rsa_2048]
  uut server { versions: [tls12, tls13] }
  peer { capabilities: [session_ticket] }
  session initial [version: tls12] {
    flow handshake { close }
    expect ok
    assert resumed == false
  }
  session resumed [resumes: initial, version: tls13] {
    flow handshake {
      recv ServerHello { lacks_ext: pre_shared_key }
      send AppData
      recv AppData
    }
    expect ok
    assert resumed == false
  }
}

plzn tls "session/forced-cross-version" {
  chain: [rsa_2048]
  uut client { versions: [tls12, tls13] }
  session initial [version: tls12] {
    flow handshake { close }
    expect ok
  }
  session malicious [resumes: initial, version: tls13, force_resume: true] {
    flow {
      recv ClientHello
      send ServerHello
    }
    expect alert fatal/unsupported_extension
  }
}
"#,
    );
}

#[test]
fn forced_cross_version_resumption_is_narrowly_scoped() {
    let no_source = lint_err(
        r#"
plzn tls "session/no-source" {
  chain: [default]
  uut client { versions: [tls12, tls13] }
  session initial [version: tls12, force_resume: true] {
    flow handshake { close }
    expect ok
  }
}
"#,
    );
    assert!(no_source.contains("requires `resumes:"), "{no_source}");

    let same_version = lint_err(
        r#"
plzn tls "session/same-version" {
  chain: [default]
  uut client { versions: [tls13] }
  session initial {
    flow handshake { close }
    expect ok
  }
  session malicious [resumes: initial, force_resume: true] {
    flow {
      recv ClientHello
      send ServerHello
    }
    expect alert fatal/illegal_parameter
  }
}
"#,
    );
    assert!(
        same_version.contains("only for cross-version"),
        "{same_version}"
    );

    let wrong_role = lint_err(
        r#"
plzn tls "session/wrong-role" {
  chain: [default]
  uut server { versions: [tls12, tls13] }
  session initial [version: tls12] {
    flow handshake { close }
    expect ok
  }
  session malicious [resumes: initial, version: tls13, force_resume: true] {
    flow handshake { close }
    expect ok
  }
}
"#,
    );
    assert!(wrong_role.contains("requires `uut client`"), "{wrong_role}");
}

#[test]
fn t5_stepped_renegotiation_over_tls() {
    // T5: `begin_renegotiation` over TLS drives plzn's TLS 1.2 client's second
    // handshake step by step, with application data and held fragments in
    // between; declarations after it shape the renegotiation only.
    lint_ok(
        r#"
plzn tls "reneg/stepped" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake after recv Finished {
    send AppData
    recv AppData
    begin_renegotiation
    send ClientHello @ fragment 40 hold
    send AppData
    flush_fragment
    recv ServerHello
    recv Certificate
    recv ServerKeyExchange
    recv ServerHelloDone
    send ClientKeyExchange
    send ChangeCipherSpec
    send Finished { verify_data: [0x00] }
    recv ChangeCipherSpec
    recv Finished
  }
  expect alert fatal/decrypt_error
}
"#,
    );
    // TLS 1.3 has no renegotiation (RFC 8446 4.1.2).
    let rendered = lint_err(
        r#"
plzn tls "reneg/stepped-tls13" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData
    begin_renegotiation
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("RFC 8446 4.1.2"), "{}", rendered);
}

// T5: the `session_id` capability (RFC 5246 7.4.1.3 session-ID resumption) and the
// `resumed` ServerHello matcher lint clean in the TLS 1.2 client role, and the
// token is refused elsewhere.
#[test]
fn session_id_resumption_lints_in_the_tls12_client_role() {
    lint_ok(
        r#"
plzn tls "t" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, session_id] }
  session initial {
    flow handshake {
      recv ServerHello { resumed: false }
      close
    }
    expect ok
  }
  session resumed [resumes: initial] {
    flow handshake {
      recv ServerHello { resumed: true }
      send AppData
      recv AppData
    }
    expect ok
  }
}
"#,
    );
    let err = lint_err(
        r#"
plzn tls "t" {
  chain: [default]
  uut server {
    versions: [tls13],
  }
  peer { capabilities: [session_id] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(err.contains("`session_id` capability"), "{err}");
}

// T5: `recv HelloRequest` (TLS 1.2 client), the two shim-server renegotiation
// knobs, and `assert new_session_tickets == N` lint clean.
#[test]
fn hello_request_and_ticket_count_lint_clean() {
    lint_ok(
        r#"
plzn tls "t" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
    hello_request_after_app_data: true, require_client_cert_on_renegotiation: true
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
    recv HelloRequest
    renegotiate
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    lint_ok(
        r#"
plzn tls "t" {
  chain: [default]
  uut server {
    versions: [tls13]
    session_tickets: 2
  }
  flow handshake {
    recv NewSessionTicket
    recv NewSessionTicket
    send AppData
    recv AppData
    wait 150 ms
  }
  assert new_session_tickets == 2
  expect ok
}
"#,
    );
    let err = lint_err(
        r#"
plzn tls "t" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData
  }
  assert bogus_thing == 3
  expect ok
}
"#,
    );
    assert!(
        err.contains("not yet") || err.contains("new_session_tickets"),
        "{err}"
    );
}

#[test]
fn explicit_tls12_dh_parameters_lint_and_are_bounded() {
    lint_ok(
        r#"
plzn tls "dh/explicit" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake {
    send ServerKeyExchange {
      dh_p: [0x17],
      dh_g: p_plus_1,
      dh_Ys: [0x07]
    }
  }
  expect alert fatal/handshake_failure
}
"#,
    );

    let bad_recipe = lint_err(
        r#"
plzn tls "dh/bad-recipe" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake { send ServerKeyExchange { dh_g: beyond_p } }
  expect handshake-fails
}
"#,
    );
    assert!(bad_recipe.contains("p_plus_1"), "{bad_recipe}");

    lint_ok(
        r#"
plzn tls "dh/small-subgroup" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake {
    send ServerKeyExchange { dh_p: rfc5114_2048_256, dh_g: one, dh_Ys: small_order }
  }
  expect alert fatal/handshake_failure
}
"#,
    );
    let bad_prime = lint_err(
        r#"
plzn tls "dh/bad-prime-name" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake { send ServerKeyExchange { dh_p: rfc5114_1024_160 } }
  expect handshake-fails
}
"#,
    );
    assert!(bad_prime.contains("rfc5114_2048_256"), "{bad_prime}");

    let conflicting = lint_err(
        r#"
plzn tls "dh/conflicting-prime" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake { send ServerKeyExchange { dh_p_bits: 2048, dh_p: [0x17] } }
  expect handshake-fails
}
"#,
    );
    assert!(
        conflicting.contains("both `dh_p_bits` and exact `dh_p`"),
        "{conflicting}"
    );

    let oversized = lint_err(
        r#"
plzn tls "dh/oversized-prime" {
  chain: [rsa_2048]
  uut client { versions: [tls12] }
  peer { capabilities: [dhe_rsa] }
  flow handshake { send ServerKeyExchange { dh_p: 0xff * 65536 } }
  expect handshake-fails
}
"#,
    );
    assert!(
        oversized.contains("cannot exceed 65535 bytes"),
        "{oversized}"
    );
}

#[test]
fn dtls_record_header_mutations_and_app_data_records_assert_lint_clean() {
    // The length-preserving DTLS record-header mutations (`record.version`,
    // `record.epoch`, `record.sequence_number`) and the `app_data_records`
    // post-trace assert.
    lint_ok(
        r#"
plzn tls "dtls/header-mutations" {
  rfc 6347 section 4.1.2.7
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
  }
  flow handshake {
    send AppData { reply: none } @ set[record.epoch, 1] = 0x05
    send AppData { reply: none } @ set[record.version, 1] = 0xff
    send AppData { reply: none } @ set[record.sequence_number, 0] = 0xff
    send AppData
    recv AppData
  }
  expect ok
  assert app_data_records == 1
}
"#,
    );
}

#[test]
fn app_data_records_assert_rejects_negative_and_non_integer() {
    let err = lint_err(
        r#"
plzn tls "dtls/bad-assert" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
  assert app_data_records == yes
}
"#,
    );
    assert!(
        err.contains("app_data_records"),
        "expected an app_data_records diagnostic, got:\n{}",
        err
    );
}

#[test]
fn record_length_is_not_a_mutation_target() {
    // `record.length` is deliberately rejected: changing a sealed record's
    // declared length without changing its bytes desynchronizes the datagram
    // packer, and a raw datagram expresses a lying length directly.
    let err = lint_err(
        r#"
plzn tls "dtls/record-length" {
  chain: [ecdsa_p256]
  uut server {
    versions: [dtls12]
  }
  flow handshake {
    send AppData @ add[record.length] = 7
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        err.contains("length field"),
        "expected an unknown-length-field diagnostic, got:\n{}",
        err
    );
}

// ---- tlsfuzzer burn-down, record-layer track (2026-09-08) ----

#[test]
fn record_layer_shaping_syntax_lints_clean_tls12() {
    lint_ok(
        r#"
plzn tls "t2/shaping-tls12" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, cbc] }
  matrix { n in [1, 2, 3] }
  flow handshake until send ClientHello {
    atomic {
      send ClientHello @ fragment 2 hold_all, record_version 0x0301, pad +$n 0xff
      send record 20 raw "01"
      flush_fragment
    }
    recv ServerHello { ext ec_point_formats == [uncompressed], extensions_exactly: [renegotiation_info, ec_point_formats] }
    recv Certificate
    recv ServerKeyExchange { dh_group: [ffdhe2048, ffdhe3072], named_group: [ffdhe2048, ffdhe3072] }
    recv ServerHelloDone
    send ClientKeyExchange @ pad "fa"
    send ChangeCipherSpec
    send Finished @ truncate $n
    recv ChangeCipherSpec
    recv Finished
    send AppData { size: 1 } @ cbc_pad 20, xor[record.padding, -1] = 0x01, set[record.plaintext, -48..-1] = 0x31
    send AppData { size: 1 } @ plaintext = "0f" + 0x0f * 63
    send record 24 "hello"
    recv AppData
    close alert warning/close_notify
  }
  expect alert fatal/bad_record_mac
}
"#,
    );
}

#[test]
fn record_layer_shaping_syntax_lints_clean_tls13() {
    lint_ok(
        r#"
plzn tls "t2/shaping-tls13" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake until send Finished {
    coalesce old_keys {
      send KeyUpdate { request_update: update_not_requested }
      send KeyUpdate { request_update: update_not_requested }
    }
    send Finished @ plaintext, record_pad 30
    send empty_record 0x00 @ record_pad fill
    send AppData { size: 1 } @ set[record.inner_type] = 0
    send AppData { size: 1 } @ fragment 3 hold_old_keys
    flush_fragment
    recv AppData
  }
  expect alert fatal/unexpected_message
}
"#,
    );
}

#[test]
fn atomic_and_coalesce_blocks_do_not_nest() {
    let rendered = lint_err(
        r#"
plzn tls "t2/nested-atomic" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    atomic {
      coalesce { send Finished }
    }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`coalesce` blocks do not nest (nor `atomic` ones)"),
        "expected the nesting diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn ext_matcher_needs_a_comparison() {
    let rendered = lint_err(
        r#"
plzn tls "t2/ext-matcher-form" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake until send ClientHello {
    send ClientHello
    recv ServerHello { ext ec_point_formats [uncompressed] }
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("expected `==` or `:` after the extension name in an `ext` matcher"),
        "expected the ext-matcher diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn recv_appdata_size_and_close_reset_lint_clean() {
    lint_ok(
        r#"
plzn tls "t2/appdata-size" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  matrix { n in [64, 36] }
  flow handshake {
    send AppData
    recv AppData { size: $n }
    recv AppData { size: 36 }
    close reset
  }
  expect ok
}
"#,
    );
}

#[test]
fn recv_appdata_takes_only_size() {
    let rendered = lint_err(
        r#"
plzn tls "t2/appdata-bad-matcher" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send AppData
    recv AppData { size: "long" }
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`recv AppData` takes only `size: N`"),
        "expected the AppData matcher diagnostic, got:\n{}",
        rendered
    );
}

#[test]
fn send_appdata_defaults_and_length_contract_lower() {
    let src = r#"
plzn tls "appdata/length-contract" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake {
    send AppData
    recv AppData
    send AppData { size: 1024, reply: 7 }
    recv AppData
    send AppData { size: 24, reply: none }
    close
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let program = plzn::lower::lower(&file.tests[0]).expect("lower").remove(0);
    let sends: Vec<_> = program
        .steps
        .iter()
        .filter_map(|step| match step {
            plzn::ir::Step::SendAppData {
                size, reply_size, ..
            } => Some((*size, *reply_size)),
            _ => None,
        })
        .collect();
    assert_eq!(sends, [(32, Some(32)), (1024, Some(7)), (24, None)]);
}

#[test]
fn early_data_steps_lower_with_lengths_and_end_marker() {
    let src = r#"
plzn tls "early-data/steps" {
  chain: [default]
  uut server { versions: [tls13], max_early_data: 1024 }
  flow {
    send ClientHello
    send EarlyData { size: 17 }
    recv EarlyData { size: 23 }
    send EndOfEarlyData
    close
  }
  expect ok
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let program = plzn::lower::lower(&file.tests[0]).expect("lower").remove(0);
    assert!(
        program
            .steps
            .iter()
            .any(|step| matches!(step, plzn::ir::Step::SendEarlyData { size: 17, .. }))
    );
    assert!(
        program
            .steps
            .iter()
            .any(|step| matches!(step, plzn::ir::Step::RecvEarlyData { size: Some(23), .. }))
    );
    assert!(program.steps.iter().any(|step| matches!(
        step,
        plzn::ir::Step::HandshakeSteps { steps, .. }
            if steps.contains(&plzn::ir::HandshakeStep::Send(
                plzn::ir::MessageKind::EndOfEarlyData
            ))
    )));
    assert_eq!(
        program.uut.as_ref().and_then(|u| u.max_early_data),
        Some(1024)
    );
}

#[test]
fn client_hello_after_sent_hrr_gets_retry_matchers() {
    let src = r#"
plzn tls "early-data/hrr-retry-matchers" {
  chain: [default]
  uut client { versions: [tls13] }
  flow {
    recv ClientHello { has_ext: early_data }
    send HelloRetryRequest { key_share_group: secp256r1 }
    recv ClientHello { lacks_ext: early_data }
  }
  expect handshake-fails
}
"#;
    let tokens = plzn::lex::lex(src).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let program = plzn::lower::lower(&file.tests[0]).expect("lower").remove(0);
    let configs: Vec<_> = program
        .steps
        .iter()
        .filter_map(|step| match step {
            plzn::ir::Step::HandshakeSteps {
                config: Some(config),
                ..
            } => Some(config.as_ref()),
            _ => None,
        })
        .collect();
    assert!(configs.iter().any(|entry| {
        entry.message == plzn::ir::MessageKind::ClientHello
            && entry.fields.iter().any(|field| field.field == "has_ext")
    }));
    assert!(configs.iter().any(|entry| {
        entry.message == plzn::ir::MessageKind::ClientHelloRetry
            && entry.fields.iter().any(|field| field.field == "lacks_ext")
    }));
}

#[test]
fn early_data_is_tls13_only() {
    let rendered = lint_err(
        r#"
plzn tls "early-data/tls12" {
  chain: [default]
  uut server { versions: [tls12] }
  flow {
    send EarlyData { size: 32 }
    send EndOfEarlyData
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("EarlyData is only defined for TLS 1.3"),
        "{rendered}"
    );
    assert!(
        rendered.contains("EndOfEarlyData is only defined for TLS 1.3"),
        "{rendered}"
    );

    let rendered = lint_err(
        r#"
plzn tls "early-data/client-policy" {
  chain: [default]
  uut client { versions: [tls13], max_early_data: 1024 }
  flow handshake {}
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("configures a UUT server"), "{rendered}");
}

#[test]
fn send_appdata_rejects_literals_and_invalid_length_contracts() {
    let literal = lint_err(
        r#"
plzn tls "appdata/literal" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake { send AppData "old payload" }
  expect handshake-fails
}
"#,
    );
    assert!(
        literal.contains("literal AppData payloads are no longer supported"),
        "{literal}"
    );

    for (body, expected) in [
        (
            "send AppData { size: 24, size: 32 }",
            "duplicate AppData `size` field",
        ),
        (
            "send AppData { reply: 9, reply: 10 }",
            "duplicate AppData `reply` field",
        ),
        (
            "send AppData { size: 1048577 }",
            "AppData size 1048577 out of range",
        ),
        (
            "send AppData { reply: 0 }",
            "AppData reply size 0 out of range",
        ),
        (
            "send AppData { size: 7, reply: none }",
            "shorter than 12 bytes can only use the default same-size reply",
        ),
    ] {
        let source = format!(
            r#"
plzn tls "appdata/invalid" {{
  chain: [default]
  uut server {{ versions: [tls13] }}
  flow handshake {{ {body} }}
  expect handshake-fails
}}
"#
        );
        let rendered = lint_err(&source);
        assert!(
            rendered.contains(expected),
            "expected {expected:?}, got:\n{rendered}"
        );
    }
}

// ---- T1: values, generators, repeats, captures (tlsfuzzer burn-down) ----

#[test]
fn generators_and_numeric_ids_in_typed_lists_lint_clean() {
    lint_ok(
        r#"
plzn tls "gen/all-forms" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  matrix {
    n in [max_fragment_length, 3, 0x10..0x12]
    base in 0x0300..0x0500 step 0x100
  }
  flow {
    send ClientHello {
      cipher_suites: [AES_128_GCM_SHA256, 0x0100..0x0104, ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 * 2]
      +ext supported_groups = [secp256r1, 0x01ff, 11200, $base..$base + 255]
      +ext signature_algorithms = [rsa_pss_rsae_sha256, 0x0904, rsa_pkcs1_sha256 * 2]
      +ext alpn = ["A" * 3, "http/1.1"]
      +ext padding = $n
      +ext each [0x0100..0x0103, $n]
      +ext $n = raw "00"
      +ext key_share = [x25519, 0x0022..0x0023 : 0xab * 32]
    } @ fragment 16384
    recv HelloRetryRequest { key_share_group: secp256r1, has_ext: cookie, lacks_ext: pre_shared_key }
  }
  expect handshake-fails
}
"#,
    );
}

#[test]
fn repeat_capture_and_cross_run_asserts_lint_clean() {
    lint_ok(
        r#"
plzn tls "gen/repeat-capture" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, aes128_gcm_sha256] }
  repeat 3
  flow {
    send ClientHello
    recv ServerHello { random: capture $r, legacy_session_id_echo: capture $sid }
    recv Certificate
    recv ServerKeyExchange { key_share: capture $ks }
    recv ServerHelloDone
    send ClientKeyExchange
    send ChangeCipherSpec
    send Finished
    recv ChangeCipherSpec
    recv Finished
    repeat $repeat {
      send AppData { size: 4 }
      recv AppData { size: 4 }
    }
    send AppData { size: 8 }
    recv AppData { size: 8 }
    send AppData { size: 4 }
    recv AppData
    send alert warning/close_notify
    recv alert warning/close_notify
    close
  }
  expect ok
  assert unique $r, $ks
  assert gcm_nonces_unique
  assert gcm_nonces_monotonic
}

plzn tls "gen/close-reset" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake until recv ServerHello {
    send ClientHello
    recv ServerHello
    close reset
  }
  expect ok
}
"#,
    );
}

#[test]
fn assert_unique_needs_a_capture() {
    let err = lint_err(
        r#"
plzn tls "gen/unique-without-capture" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  repeat 2
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
  assert unique $r
}
"#,
    );
    assert!(err.contains("names nothing the flow captures"), "{}", err);
}

#[test]
fn negotiated_assertions_are_typed_and_version_checked() {
    lint_ok(
        r#"
plzn tls "assert/negotiated" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
  assert negotiated.cipher == AES_128_GCM_SHA256
  assert negotiated.early_data_accepted == false
}
"#,
    );

    let named = lint_err(
        r#"
plzn tls "assert/named-suite" {
  chain: [default]
  uut server { versions: [tls13] }
  flow { close }
  expect close
  assert negotiated.cipher == 0x1301
}
"#,
    );
    assert!(named.contains("write the cipher-suite name"), "{named}");

    let version = lint_err(
        r#"
plzn tls "assert/early-data-version" {
  chain: [default]
  uut server { versions: [tls12] }
  flow { close }
  expect close
  assert negotiated.early_data_accepted == false
}
"#,
    );
    assert!(version.contains("only available for TLS 1.3"), "{version}");
}

#[test]
fn extension_flood_is_bounded_by_the_u16_block() {
    let err = lint_err(
        r#"
plzn tls "gen/too-many-extensions" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake {
    send ClientHello { +ext each 90..16500 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("keep the total under 65279"), "{}", err);
}

#[test]
fn key_share_entry_forms_are_checked() {
    let err = lint_err(
        r#"
plzn tls "gen/key-share-bare-number" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send ClientHello { +ext key_share = [0x0022] }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("give the opaque key"), "{}", err);
    let err = lint_err(
        r#"
plzn tls "gen/app-data-size-only" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData { length: 1 }
  }
  expect ok
}
"#,
    );
    assert!(err.contains("`length`"), "{}", err);
}

/// T1: `"A" * N` is ONE string of N copies (an ALPN name is capped at 255
/// bytes, so 256 copies is rejected), while `["A" * 255] * 2` is two names.
#[test]
fn repeated_string_is_one_string_and_repeated_list_is_entries() {
    let src = r#"
plzn tls "alpn-repeat" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello { +ext alpn = [["A" * 255] * 2, "B" * 8, "http/1.1"] }
    recv ServerHello
    send AppData
    recv AppData
  }
  expect ok
}
"#;
    lint_ok(src);
    let bad = src.replace("\"A\" * 255", "\"A\" * 256");
    let diags = plzn::lint("snippet", &bad);
    let rendered: String = diags.iter().map(|d| format!("{}", d)).collect();
    assert!(
        rendered.contains("ALPN protocol name too long"),
        "a 256-byte repeated string must be one over-long name, got:\n{}",
        rendered
    );
}

// ---------------------------------------------------------------------------
// A: certificate chains -- `chain:` / `client_chain:` header lines and ECDHE capabilities.
// ---------------------------------------------------------------------------

#[test]
fn chain_line_is_required() {
    let rendered = lint_err(
        r#"
plzn tls "chains/missing" {
  uut server {
    versions: [tls13]
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("missing required `chain:` line"),
        "{}",
        rendered
    );
    assert!(rendered.contains("`chain: []`"), "{}", rendered);
    assert!(rendered.contains("`chain: [default]`"), "{}", rendered);
}

#[test]
fn chain_lines_lint_clean() {
    lint_ok(
        r#"
plzn tls "chains/tls13-ecdsa" {
  uut server {
    versions: [tls13]
  }
  chain: [ecdsa_p256]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "chains/ecdhe-follows-the-chain" {
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe] }
  chain: [rsa_2048, ecdsa_p256]
  client_chain: [ecdsa_p256, rsa]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "chains/no-chain-with-psk" {
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [psk] }
  chain: []
  psk {
    identity: "plzn-psk-id"
    secret: "6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "chains/server-holds-two" {
  uut client {
    versions: [tls13]
  }
  chain: [rsa_2048, ecdsa_p256]
  client_chain: []
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn chain_lines_reject_unknown_names_and_contradictions() {
    let rendered = lint_err(
        r#"
plzn tls "chains/unknown" {
  uut server {
    versions: [tls13]
  }
  chain: [ecdsa_p255]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`ecdsa_p255` is not a chain name"),
        "{}",
        rendered
    );
    assert!(
        rendered.contains("ecdsa_p256"),
        "expected a suggestion, got:\n{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "chains/static-rsa-needs-rsa" {
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [rsa] }
  chain: [ecdsa_p256]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("the `rsa` capability (static RSA) needs an rsaEncryption chain"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "chains/ecdsa-needs-ecdsa" {
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_ecdsa] }
  chain: [rsa_pss]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("the `ecdhe_ecdsa` capability needs an ECDSA or Ed25519 chain"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "chains/empty-needs-psk" {
  uut server {
    versions: [tls13]
  }
  chain: []
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(
        rendered.contains("`chain: []` leaves the server no certificate"),
        "{}",
        rendered
    );
    let rendered = lint_err(
        r#"
plzn tls "chains/twice" {
  uut server {
    versions: [tls13]
  }
  chain: [rsa_2048]
  chain: [ecdsa_p256]
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    assert!(rendered.contains("`chain:` given twice"), "{}", rendered);
}

// ---------------------------------------------------------------------------
// D: named constants. A known cipher suite / group / signature scheme /
// extension type / certificate type must be written by name wherever its
// value lands; numeric literals are for unassigned or deliberately unknown
// codepoints. `plzn names` lists every table.
// ---------------------------------------------------------------------------

const NAMED_LITERAL_TAIL: &str =
    "write the name (numeric values are for unassigned or deliberately unknown codepoints)";

#[test]
fn named_forms_lint_clean_in_every_domain() {
    lint_ok(
        r#"
plzn tls "names/ok" {
  chain: [rsa_2048]
  matrix {
    suite in [ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    scheme in [rsa_pss_rsae_sha256, rsa_pkcs1_sha256]
    grp in [x25519, secp256r1]
    ext in [key_share, 0x0a0a]
  }
  uut server {
    versions: [tls12]
    require_client_cert: true
    cipher_suites: [ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0x0a0a, $suite], curves: [x25519, 0x0a0a], signing_prefs: [rsa_pss_rsae_sha256, 0x0a0a]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello {
      cipher_suites: [$suite, EMPTY_RENEGOTIATION_INFO_SCSV, 0x0a0a]
      +ext supported_groups = [$grp, secp384r1, 0x0a0a]
      +ext signature_algorithms = [$scheme, 0x0a0a]
      +ext 0x0a0a = raw ""
      -ext heartbeat
    }
    recv ServerHello { cipher_suite: $suite, has_ext: renegotiation_info, lacks_ext: $ext, extensions_exactly: [renegotiation_info, ec_point_formats] }
    recv Certificate
    recv ServerKeyExchange { named_group: $grp, signature_scheme: $scheme }
    recv CertificateRequest { certificate_types: [rsa_sign, ecdsa_sign, 200], signature_algorithms: [rsa_pss_rsae_sha256] }
    recv ServerHelloDone
    send Certificate
    send ClientKeyExchange
    send CertificateVerify { sign_with: rsa_pkcs1_sha256, algorithm: rsa_pss_rsae_sha256 }
    send ChangeCipherSpec
    send Finished
    recv ChangeCipherSpec
    recv Finished
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#,
    );
}

#[test]
fn numeric_literal_with_a_name_is_rejected_per_domain() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "send ClientHello { cipher_suites: [0xc02f] }",
            "0xc02f",
            "ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            "send ClientHello { cipher_suites: [0x00ff] }",
            "0x00ff",
            "EMPTY_RENEGOTIATION_INFO_SCSV",
        ),
        (
            "recv ServerHello { cipher_suite: 0x1301 }",
            "0x1301",
            "AES_128_GCM_SHA256",
        ),
        (
            "send ClientHello { +ext supported_groups = [0x001d] }",
            "0x001d",
            "x25519",
        ),
        (
            "recv ServerKeyExchange { named_group: 0x0100 }",
            "0x0100",
            "ffdhe2048",
        ),
        (
            "send ClientHello { +ext signature_algorithms = [0x0804] }",
            "0x0804",
            "rsa_pss_rsae_sha256",
        ),
        (
            "recv ServerKeyExchange { signature_scheme: 0x0403 }",
            "0x0403",
            "ecdsa_secp256r1_sha256",
        ),
        (
            "recv ServerHello { has_ext: 0x0033 }",
            "0x0033",
            "key_share",
        ),
        (
            "send ClientHello { +ext 0x000a = raw \"0000\" }",
            "0x000a",
            "supported_groups",
        ),
        (
            "send ClientHello { -ext 0x000d }",
            "0x000d",
            "signature_algorithms",
        ),
        (
            "recv CertificateRequest { certificate_types: [64] }",
            "64",
            "ecdsa_sign",
        ),
    ];
    for (step, lit, name) in cases {
        let src = format!(
            "plzn tls \"names/bad\" {{\n  chain: [rsa_2048]\n  uut server {{ versions: [tls12] }}\n  peer {{ capabilities: [ecdhe_rsa] }}\n  flow handshake {{\n    {}\n  }}\n  expect handshake-fails\n}}\n",
            step
        );
        let rendered = lint_err(&src);
        let want = format!("`{}` is {}; {}", lit, name, NAMED_LITERAL_TAIL);
        assert!(
            rendered.contains(&want),
            "step `{}`:\nwanted: {}\ngot:\n{}",
            step,
            want,
            rendered
        );
    }
}

#[test]
fn matrix_literals_are_checked_with_the_domain_they_flow_into() {
    let rendered = lint_err(
        r#"
plzn tls "names/matrix" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa] }
  matrix { suite in [0xc02f, 0x0a0a] }
  flow handshake {
    send ClientHello { cipher_suites: [$suite] }
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`0xc02f` is ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        "{}",
        rendered
    );
    // Reported once, at the matrix literal, not once per expanded case.
    assert_eq!(rendered.matches("`0xc02f` is").count(), 1, "{}", rendered);
    assert!(
        !rendered.contains("0x0a0a` is"),
        "an unassigned value must pass: {}",
        rendered
    );
    // `uut client|server { cipher_suites: [$suite] }` is a suite position too.
    let rendered = lint_err(
        r#"
plzn tls "names/matrix-uut" {
  chain: [rsa_2048]
  matrix { s in [0xc02b] }
  uut server {
    versions: [tls12]
    cipher_suites: [$s]
  }
  peer { capabilities: [ecdhe_rsa] }
  flow handshake {
    send ClientHello
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        rendered.contains("`0xc02b` is ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        "{}",
        rendered
    );
}

#[test]
fn unassigned_and_grease_values_stay_numeric_and_ranges_are_not_checked() {
    lint_ok(
        r#"
plzn tls "names/unassigned" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  matrix { g in [0x0022..0x0030, 0x0a0a] }
  flow handshake {
    send ClientHello {
      cipher_suites: [0x0a0a, 0x1a1a]
      +ext supported_groups = [x25519, $g, 0x0100..0x0102]
      +ext 0x0a0a = raw ""
      +ext each 0x0100..0x0105
    }
    recv ServerHello { lacks_ext: 0x0a0a }
    recv EncryptedExtensions
    recv Certificate
    recv CertificateVerify
    recv Finished
    send Finished
    send AppData
    recv AppData
    close
  }
  expect ok
}
"#,
    );
}

#[test]
fn matrix_set_names_must_be_known_and_unambiguous() {
    let rendered = lint_err(
        r#"
plzn tls "names/matrix-unknown" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  matrix { s in [AES_128_GCM_SHA256, no_such_thing] }
  flow handshake {
    send ClientHello { cipher_suites: [$s] }
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("`no_such_thing` is not a known TLS version, cipher suite, named group, signature scheme, extension type or certificate type"), "{}", rendered);
}

#[test]
fn uut_versions_accept_a_version_matrix_axis() {
    lint_ok(
        r#"
plzn tls "versions/matrix" {
  chain: [rsa_2048]
  matrix { version in [tls10, tls11, tls12] }
  uut server { versions: [$version] }
  peer { capabilities: [rsa, aes128_cbc_sha] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

#[test]
fn legacy_signature_wire_fields_require_an_explicit_tls12_format() {
    let rendered = lint_err(
        r#"
plzn tls "legacy/sigalg-format" {
  chain: [rsa_2048]
  uut client { versions: [tls10] }
  peer { capabilities: [ecdhe_rsa, aes128_cbc_sha] }
  flow handshake {
    send ServerKeyExchange { signature_scheme: rsa_pkcs1_sha256 }
  }
  expect handshake-fails
}
"#,
    );
    assert!(rendered.contains("add `format: tls12`"), "{}", rendered);
}

#[test]
fn tls13_psk_age_and_mapped_binder_controls_lint_clean() {
    lint_ok(
        r#"
plzn tls "psk/clienthello-controls" {
  chain: []
  uut server { versions: [tls13] }
  matrix { age in [1, 4294967295] }
  psk {
    identity: "Client_identity"
    secret: "6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c6f6c"
  }
  flow handshake {
    send ClientHello {
      obfuscated_ticket_age: $age
      reverse_extensions
    } @ xor[handshake.psk_binder, -1] = 0x01
  }
  expect alert fatal/illegal_parameter
}
"#,
    );
}

#[test]
fn tls13_multiple_external_psk_offers_lint_clean() {
    lint_ok(
        r#"
plzn tls "psk/multiple-identities" {
  chain: []
  uut server { versions: [tls13] }
  psk {
    identity: "known"
    secret: "00010203"
    offer {
      identity: "decoy"
      secret: "10111213"
    }
    offer {
      identity: "known"
      secret: "00010203"
      hash: sha384
    }
  }
  flow handshake {
    recv ServerHello { selected_psk_identity: 1 }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
}

// C: `recv Certificate { leaf_key }` names the presented leaf's key type.
#[test]
fn leaf_key_matcher_lints_clean_and_rejects_unknown_kinds() {
    lint_ok(
        r#"
plzn tls "c/leaf-key" {
  uut server {
    versions: [tls13]
  }
  chain: [ecdsa_p256, rsa_2048]
  flow handshake {
    send ClientHello { +ext signature_algorithms = [rsa_pss_rsae_sha256] }
    recv ServerHello
    recv EncryptedExtensions
    recv Certificate { entries: 1, leaf_key: rsa_2048 }
    recv CertificateVerify
    recv Finished
    send Finished
    send AppData
    recv AppData
  }
  expect ok
}

plzn tls "c/leaf-key-client" {
  chain: [default]
  uut client {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe], request_client_cert: true }
  client_chain: [ecdsa_p256, ecdsa_p384]
  flow handshake {
    recv ClientHello
    send ServerHello
    send Certificate
    send ServerKeyExchange
    send CertificateRequest { signature_algorithms: [ecdsa_secp384r1_sha384] }
    send ServerHelloDone
    recv Certificate { entries: 1, leaf_key: ecdsa_p384 }
    recv ClientKeyExchange
    recv CertificateVerify
    recv ChangeCipherSpec
    recv Finished
    send ChangeCipherSpec
    send Finished
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    let err = lint_err(
        r#"
plzn tls "c/leaf-key-bad" {
  chain: [default]
  uut server {
    versions: [tls13]
  }
  flow handshake {
    recv Certificate { leaf_key: dsa }
  }
  expect handshake-fails
}
"#,
    );
    assert!(err.contains("`leaf_key` takes one of"), "{}", err);
}

#[test]
fn trailing_handshake_prefix_controls_lint_clean() {
    lint_ok(
        r#"
plzn tls "stream/trailing-prefix" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake until send ClientHello {
    send ClientHello @ trailing "1400"
    recv ServerHello
    recv EncryptedExtensions
    recv Certificate
    recv CertificateVerify
    recv Finished
    send Finished @ omit_prefix 2
  }
  expect alert fatal/unexpected_message
}
"#,
    );
}

#[test]
fn trailing_handshake_prefix_controls_reject_invalid_uses() {
    let empty = lint_err(
        r#"
plzn tls "stream/empty-trailer" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake until send ClientHello {
    send ClientHello @ trailing ""
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        empty.contains("trailing requires at least one byte"),
        "{empty}"
    );

    let zero = lint_err(
        r#"
plzn tls "stream/zero-prefix" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake until send ClientHello {
    send ClientHello @ omit_prefix 0
  }
  expect handshake-fails
}
"#,
    );
    assert!(zero.contains("requires a positive byte count"), "{zero}");

    let dtls = lint_err(
        r#"
plzn tls "stream/dtls" {
  chain: [default]
  uut server { versions: [dtls13] }
  flow handshake until send ClientHello {
    send ClientHello @ trailing "14"
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        dtls.contains("TLS stream-handshake boundary controls"),
        "{dtls}"
    );

    let app_data = lint_err(
        r#"
plzn tls "stream/application-data" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake {
    send AppData @ trailing "14"
  }
  expect handshake-fails
}
"#,
    );
    assert!(
        app_data.contains("defined only for TLS handshake messages"),
        "{app_data}"
    );
}
