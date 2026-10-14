// Unit tests for the runner's expectation MATCHER: that `expect alert/close/
// handshake-fails` classify a peer's outcome correctly, and that a mismatch is
// reported with both the expected and observed values.
//
// These need deterministic failure modes (send exactly THIS alert; close
// without an alert) that a real TLS library will not reliably produce on
// demand. They are driven through the controllable `mock_shim` (ShimKind::Mock)
// via the standard shim harness, so even the matcher unit-tests go through a
// shim rather than a bespoke in-process oracle. `expect ok` is covered by the
// real-library shims elsewhere.

use std::fs;
use std::path::PathBuf;

use plzn::runtime::{RunError, RunReport, RunStatus, run};
use plzn::shim::{MockField, ShimConfig, ShimFactory, ShimKind};

fn case(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("cases")
        .join("negative")
        .join(name)
}

fn lower(path: &PathBuf) -> plzn::ir::Program {
    let source = fs::read_to_string(path).expect("read .plzn");
    lower_source(&source)
}

fn lower_source(source: &str) -> plzn::ir::Program {
    let tokens = plzn::lex::lex(source).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    let check_errs = plzn::check::check(&file);
    assert!(
        check_errs.is_empty(),
        "schema check errors: {:?}",
        check_errs
    );
    let mut programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    assert_eq!(programs.len(), 1, "expected a single lowered program");
    programs.remove(0)
}

/// Run `program` against the mock shim configured to perform one action:
/// `"alert"` (send `level`/`code` then close) or `"close"` (clean FIN, no
/// alert). Returns None if the mock_shim binary isn't built (the test skips).
fn run_mock(
    program: &plzn::ir::Program,
    action: &str,
    level: u8,
    code: u8,
    seed: u8,
) -> Option<RunReport> {
    if ShimKind::Mock.binary_path().is_none() {
        eprintln!("SKIP: mock_shim not built");
        return None;
    }
    let cfg = ShimConfig {
        // The negative .plzn use `uut server`, so plzn is the client and the
        // shim plays the server. The mock shim ignores role; set it for clarity.
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        mock: MockField {
            action: action.into(),
            alert_level: level,
            alert_code: code,
        },
        ..Default::default()
    };
    let factory = ShimFactory::new(ShimKind::Mock, cfg).expect("mock shim factory");
    let report = run(program, &factory, [seed; 32], None);
    let _ = factory.wait_shim();
    Some(report)
}

#[test]
fn alert_handshake_failure_matches_pinned_alert() {
    // mock sends fatal alert 40 = handshake_failure.
    let program = lower(&case("alert_handshake_failure.plzn"));
    let Some(report) = run_mock(&program, "alert", 2, 40, 0x60) else {
        return;
    };
    eprintln!("{}", report);
    assert!(
        report.status.is_pass(),
        "expected pass, got: {:?}",
        report.status
    );
    assert!(report.observed.contains("handshake_failure"));
}

#[test]
fn alert_any_fatal_matches_any_fatal_alert() {
    // A *different* code (decode_error = 50) proves the wildcard form accepts
    // any fatal code.
    let program = lower(&case("alert_any_fatal.plzn"));
    let Some(report) = run_mock(&program, "alert", 2, 50, 0x61) else {
        return;
    };
    eprintln!("{}", report);
    assert!(
        report.status.is_pass(),
        "expected pass, got: {:?}",
        report.status
    );
    assert!(report.observed.contains("decode_error"));
}

#[test]
fn close_without_alert_matches_clean_close() {
    let program = lower(&case("close_without_alert.plzn"));
    let Some(report) = run_mock(&program, "close", 0, 0, 0x62) else {
        return;
    };
    eprintln!("{}", report);
    assert!(
        report.status.is_pass(),
        "expected pass, got: {:?}",
        report.status
    );
    assert!(report.observed.contains("peer closed without alert"));
}

#[test]
fn handshake_fails_wildcard_matches_any_failure() {
    // Wildcard should accept a close *or* an alert. Drive it with a close.
    let program = lower(&case("handshake_fails_wildcard.plzn"));
    let Some(report) = run_mock(&program, "close", 0, 0, 0x63) else {
        return;
    };
    eprintln!("{}", report);
    assert!(
        report.status.is_pass(),
        "expected pass, got: {:?}",
        report.status
    );
}

#[test]
fn alert_expectation_mismatch_reports_expected_and_observed() {
    // Expect fatal/handshake_failure but the mock sends fatal/decode_error.
    // Should fail with an expectation mismatch naming both codes and the step.
    let program = lower(&case("alert_handshake_failure.plzn"));
    let Some(report) = run_mock(&program, "alert", 2, 50, 0x64) else {
        return;
    };
    eprintln!("{}", report);
    match &report.status {
        RunStatus::Fail(RunError::ExpectationMismatch {
            expected,
            observed,
            at_step,
        }) => {
            assert!(
                expected.contains("handshake_failure"),
                "expected should name handshake_failure: {}",
                expected
            );
            assert!(
                observed.contains("decode_error"),
                "observed should name decode_error: {}",
                observed
            );
            assert_eq!(*at_step, Some(0));
        }
        other => panic!("expected ExpectationMismatch, got: {:?}", other),
    }
}

#[test]
fn ok_expectation_on_failing_peer_reports_mismatch() {
    // Drive an `expect ok` handshake against a mock that closes -- the runtime
    // must catch the clean-close and report it as an expectation mismatch, not
    // crash.
    let program = lower_source(
        r#"
        plzn tls "runner/ok-expectation-mismatch" {
          chain: [default]
          uut server { versions: [tls12] }
          flow handshake {
            send AppData
            recv AppData
          }
          expect ok
        }
        "#,
    );
    let Some(report) = run_mock(&program, "close", 0, 0, 0x65) else {
        return;
    };
    eprintln!("{}", report);
    assert!(!report.status.is_pass());
    assert!(report.observed.contains("closed"));
}
