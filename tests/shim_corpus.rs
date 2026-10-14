// Regression coverage for the conformance corpus (suite/) run against the
// real-library shims via the `plzn` CLI: the whole cross-library corpus --
// happy paths, malformed-message families, crypto-field mutations, ROBOT
// probes, sweeps -- driven from one place rather than by hand.
//
// The full-corpus tests are `#[ignore]`d, so a plain `cargo test` leaves them
// out: they take minutes per backend, and their expectations track the
// current upstream libraries, so they are a gate for a triaged local setup
// (check.sh runs them) rather than for every environment. Run them with
//
//     cargo test --test shim_corpus -- --ignored
//
// The corpus is split by protocol, shim role, and broad scenario kind. Every
// test selects its own certificate chain, so certificate type is deliberately
// not encoded in the directory layout. Each directory is run against every
// fully triaged corpus backend (Botan, OpenSSL, LibreSSL, rustls, Go); GnuTLS
// and wolfSSL are covered by targeted
// interop tests while their full expectation sets are triaged. Skips cleanly
// if a required shim binary has not been built.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Condvar, Mutex, OnceLock};

fn shim_built(rel: &str) -> bool {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel).exists()
}

// Bound how many `plzn run` corpus subprocesses (each spawning shims) run at once. Every corpus
// test in this binary runs concurrently under cargo's test-threads; at high concurrency that
// resource contention caused rare load-induced flakes (see notes/audit/coverage_matrix.md). A
// leak-proof RAII permit caps it. Overridable via PLZN_CORPUS_LIMIT.
static CORPUS_GATE: OnceLock<(Mutex<usize>, Condvar)> = OnceLock::new();

fn corpus_gate() -> &'static (Mutex<usize>, Condvar) {
    CORPUS_GATE.get_or_init(|| {
        // Two directories at a time is enough to keep the machine busy without
        // the load-induced flakes of many parallel corpora.
        let n = std::env::var("PLZN_CORPUS_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2)
            .max(1);
        (Mutex::new(n), Condvar::new())
    })
}

struct CorpusPermit;
impl Drop for CorpusPermit {
    fn drop(&mut self) {
        let (m, cv) = corpus_gate();
        *m.lock().unwrap() += 1;
        cv.notify_one();
    }
}
fn corpus_permit() -> CorpusPermit {
    let (m, cv) = corpus_gate();
    let mut avail = m.lock().unwrap();
    while *avail == 0 {
        avail = cv.wait(avail).unwrap();
    }
    *avail -= 1;
    CorpusPermit
}

/// Absolute path to a corpus directory under the repo-root `suite/` tree.
fn suite_dir(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("suite")
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

const BOTAN_SHIM: &str = "shims/build/botan_shim";
const OPENSSL_SHIM: &str = "shims/build/openssl_shim";
const LIBRESSL_SHIM: &str = "shims/build/libressl_shim";
const BORINGSSL_SHIM: &str = "shims/build/boringssl_shim";
const GNUTLS_SHIM: &str = "shims/build/gnutls_shim";
const WOLFSSL_SHIM: &str = "shims/build/wolfssl_shim";
const GO_SHIM: &str = "shims/build/go_tls_shim";
const RUSTLS_SHIM: &str = "shims/build/rustls_shim";

fn shim_path(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(rel)
        .to_string_lossy()
        .into_owned()
}

/// Run `plzn run --shim <path> <dir>` and assert every case passed (the
/// summary line reports "N passed, 0 failed"). Every test names its own server
/// chain, so corpus execution must not depend on a directory-level `--cert`.
fn run_corpus(shim: &str, dir: &str) {
    run_corpus_paths(shim, &[dir.to_owned()]);
}

fn run_corpus_paths(shim: &str, paths: &[String]) {
    // Held for the subprocess's lifetime; released (RAII) at return.
    let _permit = corpus_permit();
    let plzn = env!("CARGO_BIN_EXE_plzn");
    let mut cmd = Command::new(plzn);
    // The CLI's interactive default deliberately oversubscribes because most
    // cases wait on sockets. A corpus regression test has hundreds of cases
    // and runs alongside other cargo tests, so cap it unless the caller chose
    // an explicit value.
    if std::env::var_os("PLZN_JOBS").is_none() {
        cmd.env("PLZN_JOBS", "16");
    }
    cmd.args(["run", "--shim", shim]);
    let out = cmd.args(paths).output().expect("spawn plzn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{}\n{}", stdout, stderr);
    // The summary line looks like: "--- N tests, N passed, 0 failed (..) [shim-name] ---"
    let summary = stdout
        .lines()
        .find(|l| l.contains("tests,") && l.contains("passed"))
        .unwrap_or("");
    assert!(
        summary.contains("0 failed"),
        "{} against {} had failures: {}",
        paths.join(", "),
        shim,
        summary
    );
    assert!(
        out.status.success(),
        "plzn exited nonzero for {} against {}",
        paths.join(", "),
        shim
    );
}

fn suite_files_with_prefix(dir: &str, prefix: &str) -> Vec<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("suite")
        .join(dir);
    let mut paths: Vec<_> = std::fs::read_dir(root)
        .expect("read suite directory")
        .map(|entry| entry.expect("read suite entry").path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "plzn")
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
        })
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no {prefix}*.plzn files in suite/{dir}");
    paths
}

// suite/server/ -- shim as SERVER. Every test explicitly names its server
// chain. The bulk of the corpus: happy
// paths, malformed-ClientHello / malformed-extension families, Finished and
// record-layer mutations, sig-alg edge cases, ROBOT/Bleichenbacher probes,
// KeyUpdate, negotiation-failure (policy) cases, and combinatorial sweeps. All
// three shims; static-RSA / CBC cases carry `skip rustls`.
#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn server_corpus_botan() {
    if !shim_built(BOTAN_SHIM) {
        eprintln!("SKIP: botan_shim not built");
        return;
    }
    run_corpus(&shim_path(BOTAN_SHIM), &suite_dir("server"));
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn server_corpus_openssl() {
    if !shim_built(OPENSSL_SHIM) {
        eprintln!("SKIP: openssl_shim not built");
        return;
    }
    run_corpus(&shim_path(OPENSSL_SHIM), &suite_dir("server"));
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn server_corpus_libressl() {
    if !shim_built(LIBRESSL_SHIM) {
        eprintln!("SKIP: libressl_shim not built");
        return;
    }
    run_corpus(&shim_path(LIBRESSL_SHIM), &suite_dir("server"));
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn server_corpus_rustls() {
    if !shim_built(RUSTLS_SHIM) {
        eprintln!("SKIP: rustls_shim not built");
        return;
    }
    run_corpus(&shim_path(RUSTLS_SHIM), &suite_dir("server"));
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn server_corpus_go() {
    if !shim_built(GO_SHIM) {
        eprintln!("SKIP: go_tls_shim not built");
        return;
    }
    run_corpus(&shim_path(GO_SHIM), &suite_dir("server"));
}

// suite/dtls/dtls12_* -- shim as SERVER or CLIENT, with each case selecting its
// own certificate/PSK configuration. Botan, OpenSSL and LibreSSL (rustls has
// no DTLS).
#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn dtls12_corpus() {
    let files = suite_files_with_prefix("dtls", "dtls12_");
    if shim_built(BOTAN_SHIM) {
        run_corpus_paths(&shim_path(BOTAN_SHIM), &files);
    }
    if shim_built(OPENSSL_SHIM) {
        run_corpus_paths(&shim_path(OPENSSL_SHIM), &files);
    }
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn dtls12_corpus_libressl() {
    if !shim_built(LIBRESSL_SHIM) {
        eprintln!("SKIP: libressl_shim not built");
        return;
    }
    let files = suite_files_with_prefix("dtls", "dtls12_");
    run_corpus_paths(&shim_path(LIBRESSL_SHIM), &files);
}

// BoringSSL is the oracle for the focused DTLS 1.3 corpus. Keep this separate
// from DTLS 1.2 so a backend without RFC 9147 is not mistaken for a failure.
#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn dtls13_corpus_boringssl() {
    if shim_built(BORINGSSL_SHIM) {
        let files = suite_files_with_prefix("dtls", "dtls13_");
        run_corpus_paths(&shim_path(BORINGSSL_SHIM), &files);
    }
}

// A shim without RFC 9147 must refuse DTLS 1.3 from the explicit 0xFEFC
// version bounds before dialing. In particular, it must not ignore the bound
// and accidentally run the case as DTLS 1.2.
#[test]
fn dtls13_is_skipped_by_backends_without_support() {
    let _permit = corpus_permit();
    let case = suite_dir("dtls/dtls13_basic_connection.plzn");
    let mut shims = vec![
        BOTAN_SHIM,
        OPENSSL_SHIM,
        LIBRESSL_SHIM,
        GNUTLS_SHIM,
        WOLFSSL_SHIM,
        GO_SHIM,
    ]
    .into_iter()
    .filter(|shim| shim_built(shim))
    .map(shim_path)
    .collect::<Vec<_>>();
    if shim_built(RUSTLS_SHIM) {
        shims.push(shim_path(RUSTLS_SHIM));
    }

    for shim in shims {
        let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(["run", "--shim", &shim, &case])
            .output()
            .expect("run DTLS 1.3 unsupported-version probe");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("{}\n{}", stdout, stderr);
        let summary = stdout
            .lines()
            .find(|line| line.contains("tests,") && line.contains("skipped"))
            .unwrap_or("");
        assert!(
            out.status.success() && summary.contains("0 failed") && summary.contains("2 skipped"),
            "{} did not cleanly skip DTLS 1.3: {}",
            shim,
            summary
        );
        assert!(
            stderr.contains("case=unsupported_config"),
            "{} did not classify DTLS 1.3 as unsupported_config",
            shim
        );
    }
}

// suite/client/ -- shim as CLIENT, plzn as server: TLS 1.2 + 1.3 handshake
// and application-data round-trip (both directions of the client record-layer
// AEAD).
#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn client_corpus() {
    if shim_built(BOTAN_SHIM) {
        run_corpus(&shim_path(BOTAN_SHIM), &suite_dir("client"));
    }
    if shim_built(OPENSSL_SHIM) {
        run_corpus(&shim_path(OPENSSL_SHIM), &suite_dir("client"));
    }
    if shim_built(RUSTLS_SHIM) {
        run_corpus(&shim_path(RUSTLS_SHIM), &suite_dir("client"));
    }
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn client_corpus_libressl() {
    if !shim_built(LIBRESSL_SHIM) {
        eprintln!("SKIP: libressl_shim not built");
        return;
    }
    run_corpus(&shim_path(LIBRESSL_SHIM), &suite_dir("client"));
}

#[test]
#[ignore = "full conformance corpus; run with: cargo test --test shim_corpus -- --ignored"]
fn client_corpus_go() {
    if !shim_built(GO_SHIM) {
        eprintln!("SKIP: go_tls_shim not built");
        return;
    }
    run_corpus(&shim_path(GO_SHIM), &suite_dir("client"));
}
