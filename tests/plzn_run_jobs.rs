//! The parallel runner (`plzn run --jobs N`) must print exactly what the
//! serial runner prints, in the same order: cases are independent, so only
//! the scheduling changes. A mixed set of suite/server files (matrix sweeps,
//! a per-backend skip, a happy path with the end-of-flow probe) run against
//! the rustls shim serially and four-way, and the outputs are compared with
//! the per-run ports and timings stripped.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rustls_shim_built() -> bool {
    root().join("shims/build/rustls_shim").exists()
}

const FILES: &[&str] = &[
    "suite/server/tls12_extended_master_secret.plzn",
    "suite/server/tls13_certificate_request_sigalgs.plzn",
    "suite/server/tls13_empty_key_share_triggers_hrr.plzn",
    "suite/server/tls13_psk_ke.plzn",
    "suite/server/tls13_close_notify.plzn",
    "suite/server/tls13_client_hello_fragmented.plzn",
    "suite/server/tls13_aead_ciphertext_bitflip.plzn",
    "suite/server/tls12_mandatory_client_message_omissions.plzn",
    "suite/server/tls12_reneg_info_nonempty_initial.plzn",
];

/// Drop what legitimately differs between runs: the shim's ephemeral port and
/// every duration.
fn normalize(out: &str) -> String {
    let mut s = String::new();
    for line in out.lines() {
        let mut l = line.to_string();
        // A shim's `PLZN-RESULT ... detail=<text>`: the library's wording for an
        // EXPECTED failure can depend on timing (rustls says "handshake:" or
        // "io:" for the same undecryptable record), so only the case is kept.
        if let Some(i) = l.find(" detail=") {
            if l.starts_with("PLZN-RESULT") {
                l.truncate(i);
            }
        }
        // "(127.0.0.1:PORT)"
        while let Some(i) = l.find("(127.0.0.1:") {
            let j = l[i..].find(')').map(|k| i + k + 1).unwrap_or(l.len());
            l.replace_range(i..j, "(ADDR)");
        }
        // a trailing "(12.3ms)" / "(1.2s)" / "(45µs)", and the summary's "(1.2s) ["
        let trimmed = match l.rfind(" (") {
            Some(i)
                if l.ends_with(')')
                    && l[i + 2..l.len() - 1].chars().all(|c| {
                        c.is_ascii_digit() || c == '.' || c == 'm' || c == 's' || c == 'µ'
                    }) =>
            {
                l[..i].to_string()
            }
            _ => l.clone(),
        };
        let mut t = trimmed;
        if let (Some(i), Some(j)) = (t.find(" ("), t.find(") [")) {
            if i < j && t.starts_with("--- ") {
                t.replace_range(i..j + 1, " (T)");
            }
        }
        s.push_str(&t);
        s.push('\n');
    }
    s
}

fn run(jobs: &str) -> (String, String) {
    let shim = root().join("shims/build/rustls_shim");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_plzn"));
    cmd.current_dir(root())
        .args(["run", "--shim"])
        .arg(shim)
        .args(["--cert", "rsa", "--jobs", jobs]);
    for f in FILES {
        cmd.arg(f);
    }
    let out = cmd.output().expect("spawn plzn");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn parallel_run_prints_the_serial_output_in_order() {
    if !rustls_shim_built() {
        eprintln!("SKIP: rustls_shim not built");
        return;
    }
    let (serial, serial_err) = run("1");
    let (parallel, parallel_err) = run("4");
    assert!(
        serial.contains("0 failed"),
        "serial run had failures:\n{}\n{}",
        serial,
        serial_err
    );
    assert!(
        parallel.contains("0 failed"),
        "parallel run had failures:\n{}\n{}",
        parallel,
        parallel_err
    );
    assert!(
        serial.lines().filter(|l| l.starts_with("[PASS]")).count() >= 8,
        "expected several passing cases:\n{}",
        serial
    );
    assert!(
        serial.contains("[SKIP]"),
        "expected a rustls skip in the set:\n{}",
        serial
    );
    let (a, b) = (normalize(&serial), normalize(&parallel));
    assert_eq!(a, b, "parallel output differs from the serial run");
    // The shims' own stderr is folded into each case and stays in order too.
    assert_eq!(
        normalize(&serial_err),
        normalize(&parallel_err),
        "parallel stderr differs from the serial run"
    );
}
