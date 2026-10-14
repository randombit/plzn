// Unit tests for the matrix DSL LOWERING: a `matrix { ... }` block must expand to
// N Programs (one per cartesian-product binding), with the per-case binding
// carried in each test_id. Executing the cases against a real library is covered
// by shim_corpus::server_corpus_*; here we only assert the expansion is correct.
// Synthetic axes that do not change wire behavior stay inline here rather than
// becoming duplicate conformance cases in `suite/`.

use std::fs;
use std::path::PathBuf;

use plzn::ir::Program;

fn case(name: &str) -> PathBuf {
    // The matrix sweep files were relocated into the conformance corpus; they
    // double as lowering fixtures here.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("suite")
        .join("server")
        .join(name)
}

fn lower_all(path: &PathBuf) -> Vec<Program> {
    let source = fs::read_to_string(path).expect("read .plzn");
    lower_source(&source)
}

fn lower_source(source: &str) -> Vec<Program> {
    let tokens = plzn::lex::lex(source).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let check_errs = plzn::check::check(&file);
    assert!(
        check_errs.is_empty(),
        "schema check errors: {:?}",
        check_errs
    );
    plzn::lower::lower(&file.tests[0]).expect("lower")
}

const TWO_AXIS_SOURCE: &str = r#"
plzn tls "matrix/two-axis" {
  chain: [default]
  uut server { versions: [tls12] }
  matrix {
    byte in [0x00, 0x02]
    bookkeeping in [1, 2, 3]
  }
  flow handshake {
    send ChangeCipherSpec { type: $byte }
  }
  expect alert fatal/{decode_error, unexpected_message}
}
"#;

#[test]
fn suite_axis_uses_names_in_case_ids() {
    let programs = lower_source(
        r#"
plzn tls "matrix/suite-labels" {
  chain: [default]
  uut server { versions: [tls12] }
  matrix {
    suite in [ECDHE_ECDSA_WITH_AES_256_CCM_8]
  }
  flow handshake {
    recv ServerHello { cipher_suite: $suite }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    let ids: Vec<&str> = programs.iter().map(|p| p.test_id.as_str()).collect();
    assert_eq!(
        ids,
        ["matrix/suite-labels[suite=ECDHE_ECDSA_WITH_AES_256_CCM_8]"]
    );
}

#[test]
fn version_axis_selects_driver_and_uut_version() {
    let programs = lower_source(
        r#"
plzn tls "matrix/version" {
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
    assert_eq!(
        programs
            .iter()
            .map(|program| program.test_id.as_str())
            .collect::<Vec<_>>(),
        [
            "matrix/version[version=tls10]",
            "matrix/version[version=tls11]",
            "matrix/version[version=tls12]",
        ]
    );
    assert_eq!(
        programs
            .iter()
            .map(|program| program.uut.as_ref().unwrap().versions.clone())
            .collect::<Vec<_>>(),
        [vec![0x0301], vec![0x0302], vec![0x0303]]
    );
}

#[test]
fn group_axis_uses_names_and_hex_in_case_ids() {
    let programs = lower_source(
        r#"
plzn tls "matrix/group-labels" {
  chain: [default]
  uut server { versions: [tls13] }
  matrix {
    group in [x25519, brainpoolP256r1tls13, brainpoolP384r1tls13,
              X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
              MLKEM512, MLKEM768, MLKEM1024, 0x0a0a]
  }
  flow handshake {
    recv ServerHello { key_share_group: $group }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    );
    let ids: Vec<&str> = programs.iter().map(|p| p.test_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "matrix/group-labels[group=x25519]",
            "matrix/group-labels[group=brainpoolP256r1tls13]",
            "matrix/group-labels[group=brainpoolP384r1tls13]",
            "matrix/group-labels[group=X25519MLKEM768]",
            "matrix/group-labels[group=SecP256r1MLKEM768]",
            "matrix/group-labels[group=SecP384r1MLKEM1024]",
            "matrix/group-labels[group=MLKEM512]",
            "matrix/group-labels[group=MLKEM768]",
            "matrix/group-labels[group=MLKEM1024]",
            "matrix/group-labels[group=0x0a0a]",
        ]
    );
}

#[test]
fn single_axis_ccs_byte_sweep_produces_three_cases() {
    let programs = lower_all(&case("tls12_sweep_ccs_byte.plzn"));
    assert_eq!(
        programs.len(),
        3,
        "expected 3 cases from a 3-value matrix axis, got {}",
        programs.len()
    );

    // Case IDs carry the per-case binding suffix in source order.
    let ids: Vec<&str> = programs.iter().map(|p| p.test_id.as_str()).collect();
    assert_eq!(ids[0], "server/ccs-byte-sweep[byte=0]");
    assert_eq!(ids[1], "server/ccs-byte-sweep[byte=2]");
    assert_eq!(ids[2], "server/ccs-byte-sweep[byte=255]");
}

#[test]
fn signature_scheme_axis_uses_names_and_hex_for_unknown_values() {
    let programs = lower_source(
        r#"
plzn tls "matrix/signature-scheme-labels" {
  chain: [default]
  uut client { versions: [tls13] }
  matrix { scheme in [rsa_pss_rsae_sha512, ecdsa_secp521r1_sha512, 0x0a0a] }
  flow handshake {}
  expect ok
}
"#,
    );
    let ids: Vec<&str> = programs.iter().map(|p| p.test_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "matrix/signature-scheme-labels[scheme=rsa_pss_rsae_sha512]",
            "matrix/signature-scheme-labels[scheme=ecdsa_secp521r1_sha512]",
            "matrix/signature-scheme-labels[scheme=0x0a0a]",
        ]
    );
}

#[test]
fn two_axis_cartesian_product() {
    let programs = lower_source(TWO_AXIS_SOURCE);
    assert_eq!(
        programs.len(),
        6,
        "expected 2 * 3 = 6 cases, got {}",
        programs.len()
    );

    // Source-order cartesian product: for each value of the outer axis, iterate
    // the inner axis.
    let ids: Vec<&str> = programs.iter().map(|p| p.test_id.as_str()).collect();
    assert_eq!(ids[0], "matrix/two-axis[byte=0,bookkeeping=1]");
    assert_eq!(ids[1], "matrix/two-axis[byte=0,bookkeeping=2]");
    assert_eq!(ids[2], "matrix/two-axis[byte=0,bookkeeping=3]");
    assert_eq!(ids[3], "matrix/two-axis[byte=2,bookkeeping=1]");
    assert_eq!(ids[4], "matrix/two-axis[byte=2,bookkeeping=2]");
    assert_eq!(ids[5], "matrix/two-axis[byte=2,bookkeeping=3]");
}

#[test]
fn unused_matrix_var_is_ok_and_still_appears_in_test_id() {
    // `bookkeeping` isn't referenced in any override, but it must still appear in
    // every test_id suffix (an unused matrix var is not a lowering error).
    let programs = lower_source(TWO_AXIS_SOURCE);
    for p in &programs {
        assert!(
            p.test_id.contains("bookkeeping="),
            "expected case id to carry the unused axis, got {}",
            p.test_id
        );
    }
}

#[test]
fn group_axis_pins_supported_groups_and_key_share() {
    // The corpus sweep crosses every TLS 1.3 suite with every key-shareable
    // group, pinning both rather than relying on backend preference.
    let programs = lower_all(&case("tls13_key_share_sweep.plzn"));
    let expected_groups = vec![
        vec![0x001d],
        vec![0x001e],
        vec![0x0017],
        vec![0x0018],
        vec![0x0019],
        vec![0x001f],
        vec![0x0020],
        vec![0x0100],
        vec![0x0101],
        vec![0x0102],
        vec![0x0103],
        vec![0x0104],
        vec![0x11ec],
        vec![0x11ee],
        vec![0x11eb],
        vec![0x11ed],
        vec![0x0200],
        vec![0x0201],
        vec![0x0202],
    ];
    assert_eq!(programs.len(), 5 * expected_groups.len());
    for suite_cases in programs.chunks(expected_groups.len()) {
        let groups: Vec<Vec<u16>> = suite_cases
            .iter()
            .map(|p| p.server_groups.clone())
            .collect();
        assert_eq!(groups, expected_groups);
    }
    for p in &programs {
        assert_eq!(p.key_share_groups, p.server_groups);
        assert!(p.test_id.contains("[suite="), "{}", p.test_id);
        assert!(p.test_id.contains(",group="), "{}", p.test_id);
    }
}

#[test]
fn session_matrix_expands_each_complete_sequence_per_binding() {
    let programs = lower_source(
        r#"
plzn tls "matrix/session-cartesian" {
  chain: [default]
  uut server {
    versions: [tls13]
    cipher_suites: [$suite]
    curves: [$group]
  }
  matrix {
    suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384]
    group in [x25519, secp256r1]
  }
  session initial {
    flow handshake {
      recv NewSessionTicket
      send AppData
      recv AppData
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
"#,
    );

    assert_eq!(programs.len(), 2 * 2 * 2);
    for pair in programs.chunks(2) {
        assert_eq!(pair[0].session_name.as_deref(), Some("initial"));
        assert_eq!(pair[1].session_name.as_deref(), Some("resumed"));
        assert_eq!(pair[1].resumes.as_deref(), Some("initial"));
        let case0 = pair[0].test_id.rsplit_once(':').unwrap().0;
        let case1 = pair[1].test_id.rsplit_once(':').unwrap().0;
        assert_eq!(case0, case1);
        assert_eq!(pair[0].server_suites, pair[1].server_suites);
        assert_eq!(pair[0].server_groups, pair[1].server_groups);
        assert_eq!(pair[0].key_share_groups, pair[1].key_share_groups);
        assert_eq!(
            pair[0].uut.as_ref().unwrap().cipher_suites,
            pair[0].server_suites
        );
        assert_eq!(pair[0].uut.as_ref().unwrap().curves, pair[0].server_groups);
    }
    assert_eq!(
        programs[0].test_id,
        "matrix/session-cartesian[suite=AES_128_GCM_SHA256,group=x25519]:initial"
    );
    assert_eq!(
        programs[7].test_id,
        "matrix/session-cartesian[suite=AES_256_GCM_SHA384,group=secp256r1]:resumed"
    );
}
