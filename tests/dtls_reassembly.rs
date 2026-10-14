//! Reassembly self-tests: a test-only proxy rewrites a real shim's output.
//! The production shim receives only ordinary TLS-library policy settings.

use std::path::Path;
use std::process::{Command, Output};

use plzn::shim::ShimKind;

fn run_case(backend: &Path, case: &str, mode: &str) -> Output {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases/dtls_reassembly");
    Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["run", "--shim", env!("CARGO_BIN_EXE_dtls_test_shim")])
        .arg(fixtures.join(format!("{case}.plzn")))
        .env("PLZN_TEST_DTLS_BACKEND", backend)
        .env("PLZN_TEST_DTLS_REWRITE", mode)
        .output()
        .expect("run DTLS reassembly self-test")
}

fn run_cases(backend: ShimKind) {
    let Some(backend) = backend.binary_path() else {
        eprintln!("SKIP: DTLS backend shim not built");
        return;
    };
    for (case, mode) in [
        ("shim-forges-overlap-mismatch", "overlap_mismatch"),
        ("shim-forges-offset-overflow", "offset_overflow"),
        ("shim-forges-length-mismatch", "length_mismatch"),
        ("shim-client-forges-overlap-mismatch", "overlap_mismatch"),
        ("shim-fragments-flight", "fragment:48"),
        ("shim-duplicates-fragments", "duplicate"),
        ("shim-client-fragments-flight", "fragment:16"),
    ] {
        let output = run_case(&backend, case, mode);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 tests, 1 passed, 0 failed"),
            "{case} using {}:\n{stdout}\n{stderr}",
            backend.display()
        );
    }
}

#[test]
fn reassembles_and_rejects_rewritten_botan_flights() {
    run_cases(ShimKind::Botan);
}

#[test]
fn reassembles_and_rejects_rewritten_openssl_flights() {
    run_cases(ShimKind::OpenSsl);
}

#[test]
fn a_handshake_without_the_configured_rewrite_cannot_pass() {
    let Some(backend) = ShimKind::OpenSsl
        .binary_path()
        .or_else(|| ShimKind::Botan.binary_path())
    else {
        eprintln!("SKIP: DTLS backend shim not built");
        return;
    };
    // The handshake can succeed, but none of its messages exceeds this size.
    // The proxy's failure must reach the runner instead of hiding a lost test.
    let output = run_case(&backend, "shim-fragments-flight", "fragment:65535");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("configured test rewrite was never applied")
            || stderr.contains("configured test rewrite was never applied"),
        "{stdout}\n{stderr}"
    );
}
