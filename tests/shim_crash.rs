// Crash reporting through the shim harness.
//
// A shim process that dies by signal has told us exactly one thing: it
// crashed. The runner must (a) classify that as a crash rather than as an
// unmapped exit code or a "peer closed" protocol outcome, (b) notice a shim
// that dies before it even connects immediately, instead of waiting out the
// accept deadline, and (c) still hand the caller the outcome afterwards. The
// controllable mock shim provides the three death modes on demand.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use plzn::runtime::run;
use plzn::shim::{MockField, ShimConfig, ShimFactory, ShimKind, ShimResultCase};
use plzn::transport::UutFactory;

fn fixture() -> plzn::ir::Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/cases/negative/handshake_fails_wildcard.plzn");
    let source = fs::read_to_string(&path).expect("read .plzn");
    let tokens = plzn::lex::lex(&source).expect("lex");
    let file = plzn::parse::parse(&tokens).expect("parse");
    assert!(plzn::check::check(&file).is_empty());
    let mut programs = plzn::lower::lower(&file.tests[0]).expect("lower");
    programs.remove(0)
}

fn mock(action: &str) -> Option<ShimFactory> {
    if ShimKind::Mock.binary_path().is_none() {
        eprintln!("SKIP: mock_shim not built");
        return None;
    }
    let cfg = ShimConfig {
        role: "server".into(),
        min_version: Some(0x0303),
        max_version: Some(0x0303),
        mock: MockField {
            action: action.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    Some(ShimFactory::new(ShimKind::Mock, cfg).expect("mock shim factory"))
}

#[test]
fn crash_after_connect_is_classified_as_crash() {
    let Some(factory) = mock("crash") else { return };
    let program = fixture();
    let report = run(&program, &factory, [0x71; 32], None);
    // From the wire, plzn only saw the peer vanish, which satisfies the
    // fixture's `expect handshake-fails`. The shim outcome is what carries the
    // real story, so the CLI prints [CRASH] regardless of the runner verdict.
    assert!(
        report.status.is_pass(),
        "runner verdict: {:?}",
        report.status
    );

    let outcome = factory.wait_shim().expect("outcome");
    assert!(outcome.is_crash(), "outcome: {:?}", outcome);
    assert_eq!(outcome.case, ShimResultCase::Crashed(6)); // SIGABRT
    assert!(!outcome.success);
    assert_eq!(outcome.code, None);
    assert_eq!(outcome.describe_exit(), "killed by signal 6 (SIGABRT)");
}

#[test]
fn exit_before_connect_fails_open_promptly_with_the_reason() {
    let Some(factory) = mock("exit_early") else {
        return;
    };
    let started = Instant::now();
    let err = factory.open().err().expect("open must fail");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "open() waited {:?}; it should return as soon as the shim exits, not at the accept deadline",
        started.elapsed()
    );
    let msg = err.to_string();
    assert!(msg.contains("mock exited before connecting"), "{}", msg);
    assert!(msg.contains("exit code 10 (local_error)"), "{}", msg);
    assert!(msg.contains("mock: exiting before connecting"), "{}", msg);

    // The outcome is still available afterwards, as after a normal run.
    let outcome = factory.wait_shim().expect("outcome after early exit");
    assert_eq!(outcome.case, ShimResultCase::LocalError);
    assert!(!outcome.is_crash());
    assert!(
        factory.wait_shim().is_err(),
        "early outcome is handed back once"
    );
}

#[test]
fn crash_before_connect_fails_open_promptly_as_a_crash() {
    let Some(factory) = mock("crash_early") else {
        return;
    };
    let started = Instant::now();
    let err = factory.open().err().expect("open must fail");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "open() waited {:?}",
        started.elapsed()
    );
    let msg = err.to_string();
    assert!(msg.contains("killed by signal 6 (SIGABRT)"), "{}", msg);

    let outcome = factory.wait_shim().expect("outcome after early crash");
    assert!(outcome.is_crash());
    assert_eq!(outcome.case, ShimResultCase::Crashed(6));
}

// End to end through the CLI: `--shim` points at an identifying script that
// kills itself with SIGSEGV on normal invocation, before connecting.
// The CLI must print one [CRASH] line per case, stop after the breaker's
// limit of consecutive crashes with exit status 2, and keep going (exit 1,
// every case reported) when the breaker is disabled.
#[cfg(unix)]
mod cli {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    const SWEEP: &str = r#"
plzn tls "crash/sweep" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12]
  }
  peer { capabilities: [ecdhe_rsa] }
  matrix {
    pos in [-1, -2, -3, -4, -5]
  }
  flow handshake {
    send Finished @ xor[$pos] = 0xff
  }
  expect handshake-fails
}
"#;

    fn setup() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("segv_shim.sh");
        {
            let mut f = std::fs::File::create(&script).unwrap();
            f.write_all(
                b"#!/bin/sh\nif [ \"$1\" = --plzn-shim-info ]; then\n  echo '{\"protocol\":\"plzn-shim\",\"protocol_version\":1,\"name\":\"botan\"}'\n  exit 0\nfi\nkill -SEGV $$\n",
            )
            .unwrap();
        }
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let case = dir.path().join("sweep.plzn");
        std::fs::write(&case, SWEEP).unwrap();
        (dir, script, case)
    }

    #[test]
    fn cli_reports_each_crash_and_stops_after_the_limit() {
        let (_dir, script, case) = setup();
        let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(["run", "--shim"])
            .arg(&script)
            .arg(&case)
            .env_remove("PLZN_CRASH_LIMIT")
            .output()
            .expect("spawn plzn");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "stdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
        let crash_lines = stdout.lines().filter(|l| l.starts_with("[CRASH]")).count();
        assert_eq!(crash_lines, 3, "stdout:\n{}", stdout);
        assert!(
            stdout
                .contains("[CRASH] crash/sweep[pos=-1] — botan shim killed by signal 11 (SIGSEGV)"),
            "stdout:\n{}",
            stdout
        );
        // The early-exit reason rides on the per-case report ("transport open
        // failed: ..."), which goes to stdout with the rest of the report.
        assert!(
            stdout.contains("botan exited before connecting"),
            "stdout:\n{}",
            stdout
        );
        assert!(
            stderr.contains("crashed on 3 consecutive cases"),
            "stderr:\n{}",
            stderr
        );
        // The summary line is still printed so tooling can parse the partial run.
        assert!(
            stdout.contains("3 tests, 0 passed, 3 failed"),
            "stdout:\n{}",
            stdout
        );
    }

    #[test]
    fn cli_breaker_disabled_reports_every_crash() {
        let (_dir, script, case) = setup();
        let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(["run", "--shim"])
            .arg(&script)
            .arg(&case)
            .env("PLZN_CRASH_LIMIT", "0")
            .output()
            .expect("spawn plzn");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "stdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
        assert_eq!(
            stdout.lines().filter(|l| l.starts_with("[CRASH]")).count(),
            5,
            "stdout:\n{}",
            stdout
        );
        assert!(!stderr.contains("aborting"), "stderr:\n{}", stderr);
        assert!(
            stdout.contains("5 tests, 0 passed, 5 failed"),
            "stdout:\n{}",
            stdout
        );
    }
}
