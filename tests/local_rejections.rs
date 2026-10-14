//! These fixtures assert plzn's own rejection paths, not UUT conformance.
//! Real clients supply certificates, PSKs, and signature preferences through
//! ordinary shim policy; no self-test behavior is needed in the shims.

use std::path::Path;
use std::process::Command;

use plzn::shim::ShimKind;

fn run_cases(backend: ShimKind, paths: &[&str], expected_cases: usize) {
    let Some(shim) = backend.binary_path() else {
        eprintln!("SKIP: {} shim not built", backend.label());
        return;
    };
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases/local_rejections");
    let output = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["run", "--json", "--jobs", "4", "--shim"])
        .arg(shim)
        .args(paths.iter().map(|path| fixtures.join(path)))
        .output()
        .expect("run local rejection self-tests");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{}:\n{stdout}\n{stderr}",
        backend.label()
    );

    let records: Vec<serde_json::Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("each output line is JSON"))
        .collect();
    assert_eq!(records.len(), expected_cases + 1, "{stdout}\n{stderr}");
    for case in &records[..expected_cases] {
        assert_eq!(case["type"], "case", "{case}");
        // Unsupported configurations and expected failures must not silently
        // remove coverage of a driver rejection path.
        assert_eq!(case["status"], "pass", "{case}");
        assert_eq!(case["outcome"]["kind"], "local_reject", "{case}");
    }
    let summary = &records[expected_cases];
    assert_eq!(summary["type"], "summary", "{summary}");
    assert_eq!(summary["total"], expected_cases, "{summary}");
    assert_eq!(summary["passed"], expected_cases, "{summary}");
}

#[test]
fn local_rejections_with_botan() {
    run_cases(ShimKind::Botan, &["."], 14);
}

#[test]
fn local_rejections_with_openssl() {
    run_cases(ShimKind::OpenSsl, &["."], 14);
}

#[test]
fn local_rejections_with_rustls() {
    // rustls supports TLS certificate authentication, but not DTLS or external PSKs.
    run_cases(
        ShimKind::Rustls,
        &["tls/client_auth", "tls/tls13_no_signing_scheme.plzn"],
        5,
    );
}

#[test]
fn local_rejections_with_go() {
    // Go additionally cannot configure signature-scheme preferences.
    run_cases(ShimKind::Go, &["tls/client_auth"], 4);
}
