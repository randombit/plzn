use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

// T1: per-run captures (`capture $x`) keyed by test id, grouped by the
// test's repeat group, with the group's cross-run asserts.
type RunCaptures = Vec<(String, Vec<u8>)>;
type CrossRuns =
    std::collections::BTreeMap<String, (Vec<plzn::ir::CrossAssert>, Vec<(String, RunCaptures)>)>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fmt") => fmt_cmd(&args[1..]),
        Some("lint") => lint_cmd(&args[1..]),
        Some("run") => run_cmd(&args[1..]),
        Some("dial") => dial_cmd(&args[1..]),
        Some("diff") => diff_cmd(&args[1..]),
        // D: every name the DSL knows for cipher suites, groups, signature
        // schemes, extension types and certificate types, with its wire value.
        Some("names") => names_cmd(),
        Some("-h") | Some("--help") | None => {
            print_usage();
            ExitCode::from(0)
        }
        Some(other) => {
            eprintln!("plzn: unknown subcommand '{}'", other);
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!("usage:");
    eprintln!("  plzn fmt [--check] <file.plzn|dir>...");
    eprintln!("  plzn lint [--json] <file.plzn|dir>...");
    eprintln!("  plzn run --shim PATH [--json] <file.plzn|dir>...");
    eprintln!("  plzn dial --addr HOST:PORT <file.plzn|dir>...");
    eprintln!("  plzn diff --shim PATH --shim PATH [--mutate] <file.plzn|dir>...");
    eprintln!();
    eprintln!("Use --shim PATH to run any executable implementing the plzn shim protocol.");
    eprintln!("Use `plzn dial` to test an already-running server directly.");
}

#[derive(serde::Serialize)]
struct LintFileRecord {
    schema_version: u32,
    #[serde(rename = "type")]
    record_type: &'static str,
    path: String,
    status: &'static str,
    diagnostics: Vec<plzn::diag::Diag>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct LintSummaryRecord {
    schema_version: u32,
    #[serde(rename = "type")]
    record_type: &'static str,
    files: usize,
    passed: usize,
    failed: usize,
}

fn emit_json<T: serde::Serialize>(command: &str, value: &T) {
    match serde_json::to_string(value) {
        Ok(line) => println!("{}", line),
        Err(error) => eprintln!("plzn {}: cannot encode JSON result: {}", command, error),
    }
}

fn fmt_cmd(args: &[String]) -> ExitCode {
    let mut check = false;
    let mut paths = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            "-h" | "--help" => {
                eprintln!("usage: plzn fmt [--check] <file.plzn|dir>...");
                eprintln!();
                eprintln!("  --check  report files that need formatting without changing them");
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("plzn fmt: unknown flag {:?}", other);
                return ExitCode::from(2);
            }
            _ => paths.push(arg.clone()),
        }
    }

    let mut files = Vec::new();
    for path in &paths {
        let path = std::path::Path::new(path);
        if path.is_dir() {
            collect_plzn_files(path, &mut files);
        } else {
            files.push(path.to_string_lossy().into_owned());
        }
    }
    files.sort();
    files.dedup();
    if files.is_empty() {
        eprintln!("plzn fmt: no .plzn files found");
        return ExitCode::from(2);
    }

    let mut failures = 0usize;
    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("plzn fmt: {}: {}", path, error);
                failures += 1;
                continue;
            }
        };
        let formatted = match plzn::format::format_source(path, &source) {
            Ok(formatted) => formatted,
            Err(errors) => {
                for error in errors {
                    eprintln!("{}", error);
                }
                failures += 1;
                continue;
            }
        };
        if formatted == source {
            continue;
        }
        if check {
            println!("{}: needs formatting", path);
            failures += 1;
        } else if let Err(error) = std::fs::write(path, formatted) {
            eprintln!("plzn fmt: {}: {}", path, error);
            failures += 1;
        } else {
            println!("{}: formatted", path);
        }
    }

    if failures == 0 {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

fn lint_cmd(args: &[String]) -> ExitCode {
    let mut errors_only = false;
    let mut json = false;
    let mut paths: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--errors-only" | "-e" => errors_only = true,
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("usage: plzn lint [--errors-only] [--json] <file.plzn|dir>...");
                eprintln!();
                eprintln!("  --errors-only, -e  suppress successful files in human output");
                eprintln!("  --json             emit NDJSON file and summary records");
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("plzn lint: unknown flag {:?}", other);
                return ExitCode::from(2);
            }
            _ => paths.push(arg.clone()),
        }
    }
    // Expand directories: collect all .plzn files recursively.
    let mut files: Vec<String> = Vec::new();
    for path in &paths {
        let p = std::path::Path::new(path);
        if p.is_dir() {
            collect_plzn_files(p, &mut files);
        } else {
            files.push(path.clone());
        }
    }
    if files.is_empty() {
        eprintln!("plzn lint: no .plzn files found");
        return ExitCode::from(2);
    }
    files.sort();
    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                if json {
                    emit_json(
                        "lint",
                        &LintFileRecord {
                            schema_version: 1,
                            record_type: "file",
                            path: path.clone(),
                            status: "error",
                            diagnostics: vec![],
                            error: Some(e.to_string()),
                        },
                    );
                } else {
                    eprintln!("plzn: {}: {}", path, e);
                }
                err_count += 1;
                continue;
            }
        };
        let diags = plzn::lint(path, &source);
        if !diags.is_empty() {
            if json {
                emit_json(
                    "lint",
                    &LintFileRecord {
                        schema_version: 1,
                        record_type: "file",
                        path: path.clone(),
                        status: "error",
                        diagnostics: diags,
                        error: None,
                    },
                );
            } else {
                for d in &diags {
                    eprintln!("{}", d);
                }
            }
            err_count += 1;
        } else {
            if json {
                emit_json(
                    "lint",
                    &LintFileRecord {
                        schema_version: 1,
                        record_type: "file",
                        path: path.clone(),
                        status: "ok",
                        diagnostics: vec![],
                        error: None,
                    },
                );
            } else if !errors_only {
                println!("{}: ok", path);
            }
            ok_count += 1;
        }
    }
    if json {
        emit_json(
            "lint",
            &LintSummaryRecord {
                schema_version: 1,
                record_type: "summary",
                files: ok_count + err_count,
                passed: ok_count,
                failed: err_count,
            },
        );
    } else if errors_only && err_count == 0 {
        println!("{} files ok", ok_count);
    }
    if err_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

fn run_cmd(args: &[String]) -> ExitCode {
    let mut shim_path: Option<String> = None;
    let mut cert_type: Option<String> = None;
    let mut verbose = false;
    let mut json = false;
    let mut jobs: Option<usize> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shim" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("plzn run: --shim requires an executable path");
                    return ExitCode::from(2);
                }
                shim_path = Some(args[i].clone());
            }
            "--cert" => {
                i += 1;
                if i >= args.len() {
                    eprintln!(
                        "plzn run: --cert requires an argument (rsa, ecdsa, ecdsa-p384, ecdsa-p521, ed25519, rsa-pss)"
                    );
                    return ExitCode::from(2);
                }
                cert_type = Some(args[i].clone());
            }
            "-v" | "--verbose" => verbose = true,
            "--json" => json = true,
            "-j" | "--jobs" => {
                i += 1;
                let n = args
                    .get(i)
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|n| *n >= 1);
                match n {
                    Some(n) => jobs = Some(n),
                    None => {
                        eprintln!("plzn run: --jobs requires a positive integer");
                        return ExitCode::from(2);
                    }
                }
            }
            "-h" | "--help" => {
                eprintln!("usage: plzn run --shim PATH [OPTIONS] <file.plzn|dir>...");
                eprintln!();
                eprintln!("  --shim PATH       executable implementing the plzn shim protocol");
                eprintln!(
                    "  --cert TYPE       what a test's `chain: [default]` is in this run: ecdsa (P-256, the default), rsa, ecdsa-p384, ecdsa-p521, ed25519, rsa-pss"
                );
                eprintln!("  --verbose, -v     show full step-by-step report for passes");
                eprintln!("  --json            emit NDJSON case and summary records");
                eprintln!(
                    "  --jobs N, -j N    run N cases at a time against a shim backend (default: 8 x CPUs -- cases are mostly idle -- or PLZN_JOBS; 1 = serial)"
                );
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("plzn run: unknown flag {:?}", other);
                return ExitCode::from(2);
            }
            other => files.push(other.to_string()),
        }
        i += 1;
    }
    let files = expand_plzn_files(files);
    if files.is_empty() {
        eprintln!("plzn run: no .plzn files found");
        return ExitCode::from(2);
    }
    // Config-file shims drive a real TLS library and dial back to plzn. The
    // executable identifies itself; plzn has no compiled-in backend registry.
    let path = match shim_path.as_deref() {
        Some(path) => path,
        None => {
            eprintln!("plzn run: no shim selected. Use --shim PATH.");
            return ExitCode::from(2);
        }
    };
    let shim = match plzn::shim::ShimSpec::identify(path) {
        Ok(shim) => shim,
        Err(e) => {
            eprintln!("plzn run: cannot identify shim: {}", e);
            return ExitCode::from(2);
        }
    };
    let expectations = match shim.expectations_path() {
        Some(path) => match plzn::shim::ShimExpectationSet::from_path(&path) {
            Ok(set) => set,
            Err(e) => {
                eprintln!("plzn run: {}", e);
                return ExitCode::from(2);
            }
        },
        None => plzn::shim::ShimExpectationSet::default(),
    };
    // Cases are independent (each owns its shim process, port and seed),
    // so they run on a pool: `--jobs`, else PLZN_JOBS, else eight workers
    // per CPU.
    let jobs = jobs
        .or_else(|| std::env::var("PLZN_JOBS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or_else(|| {
            8 * std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        })
        .clamp(1, 512);
    plzn::shim::configure_shim_limit(jobs.max(8));
    run_shim_backend(
        shim,
        expectations,
        &files,
        verbose,
        cert_type.as_deref(),
        jobs,
        json,
    )
}

fn dial_cmd(args: &[String]) -> ExitCode {
    let mut addr: Option<String> = None;
    let mut pcap_path: Option<String> = None;
    let mut verbose = false;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("plzn dial: --addr requires an argument");
                    return ExitCode::from(2);
                }
                addr = Some(args[i].clone());
            }
            "--pcap" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("plzn dial: --pcap requires a file path");
                    return ExitCode::from(2);
                }
                pcap_path = Some(args[i].clone());
            }
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                eprintln!("usage: plzn dial [OPTIONS] <file.plzn|dir>...");
                eprintln!();
                eprintln!("  --addr HOST:PORT  connect to an existing TLS server");
                eprintln!("  --pcap FILE       write pcap capture to FILE");
                eprintln!("  --verbose, -v     show full step-by-step report for passes");
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("plzn dial: unknown flag {:?}", other);
                return ExitCode::from(2);
            }
            other => files.push(other.to_string()),
        }
        i += 1;
    }

    let files = expand_plzn_files(files);
    if files.is_empty() {
        eprintln!("plzn dial: no .plzn files found");
        return ExitCode::from(2);
    }

    let socket_addr: SocketAddr = match addr.as_deref() {
        Some(a) => match a.parse() {
            Ok(sa) => sa,
            Err(_) => {
                eprintln!("plzn dial: invalid --addr {:?}", a);
                return ExitCode::from(2);
            }
        },
        None => {
            eprintln!("plzn dial: no address selected. Use --addr HOST:PORT.");
            return ExitCode::from(2);
        }
    };
    let factory = plzn::transport::TcpDialFactory::new(socket_addr)
        .with_connect_timeout(Duration::from_secs(5))
        .with_read_timeout(Some(Duration::from_secs(5)))
        .with_write_timeout(Some(Duration::from_secs(5)));
    eprintln!("[dial] tcp://{} (user-provided server)", socket_addr);

    let suite_start = Instant::now();
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    let mut cross_runs: CrossRuns = std::collections::BTreeMap::new();

    for path in &files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("plzn: {}: {}", path, e);
                failed += 1;
                total += 1;
                continue;
            }
        };
        // Lex + parse + check + lower.
        let tokens = match plzn::lex::lex(&source) {
            Ok(t) => t,
            Err(errs) => {
                for e in errs {
                    eprintln!("{}", e.into_diag(path, &source));
                }
                failed += 1;
                total += 1;
                continue;
            }
        };
        let file = match plzn::parse::parse(&tokens) {
            Ok(f) => f,
            Err(errs) => {
                for e in errs {
                    eprintln!("{}", e.into_diag(path, &source));
                }
                failed += 1;
                total += 1;
                continue;
            }
        };
        let check_errs = plzn::check::check(&file);
        if !check_errs.is_empty() {
            for e in check_errs {
                eprintln!("{}", e.into_diag(path, &source));
            }
            failed += 1;
            total += 1;
            continue;
        }
        for test in &file.tests {
            let programs = match plzn::lower::lower(test) {
                Ok(p) => p,
                Err(errs) => {
                    for e in errs {
                        eprintln!("{}", e.into_diag(path, &source));
                    }
                    failed += 1;
                    total += 1;
                    continue;
                }
            };
            if programs
                .first()
                .is_some_and(|program| program.subject == plzn::ir::Subject::Client)
            {
                for program in &programs {
                    total += 1;
                    failed += 1;
                    eprintln!(
                        "[FAIL] {} — `plzn dial` only supports `uut server`; use `plzn run \
                         --shim PATH` for `uut client`",
                        program.test_id
                    );
                }
                continue;
            }
            // Multi-session tests: run all sessions as a group.
            let is_multi_session = programs.iter().any(|p| p.session_name.is_some());
            if is_multi_session {
                let sessions_per_case = test.sessions.len();
                for case_programs in programs.chunks(sessions_per_case) {
                    let seed = test_seed_from_id(&case_programs[0].test_id);
                    let reports = plzn::runtime::run_sessions(
                        case_programs,
                        &factory,
                        seed,
                        pcap_path.as_ref().map(|p| std::path::Path::new(p.as_str())),
                    );
                    for (program, report) in case_programs.iter().zip(reports) {
                        record_cross_run(&mut cross_runs, program, &report);
                        total += 1;
                        if verbose || !report.status.is_pass() {
                            print!("{}", report.display_verbose());
                        } else {
                            println!("{}", report.display_compact());
                        }
                        if report.status.is_pass() {
                            passed += 1;
                        } else if report.status.is_skipped() {
                            skipped += 1;
                        } else {
                            failed += 1;
                        }
                    }
                }
                continue;
            }
            for program in &programs {
                total += 1;
                let seed = test_seed_from_id(&program.test_id);
                // Per-case pcap path: append the test_id as a
                // suffix so matrix cases get separate files.
                let case_pcap = pcap_path.as_ref().map(|base| {
                    let base = std::path::Path::new(base);
                    if programs.len() == 1 {
                        base.to_path_buf()
                    } else {
                        // Sanitise the test_id for use as a filename.
                        let safe_id = program
                            .test_id
                            .replace('/', "_")
                            .replace(['[', ']', ',', '='], "_");
                        let stem = base.file_stem().unwrap_or_default().to_string_lossy();
                        let ext = base
                            .extension()
                            .map(|e| e.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "pcap".into());
                        base.with_file_name(format!("{}_{}.{}", stem, safe_id, ext))
                    }
                });
                let report = plzn::runtime::run(program, &factory, seed, case_pcap.as_deref());
                record_cross_run(&mut cross_runs, program, &report);
                if verbose || !report.status.is_pass() {
                    print!("{}", report.display_verbose());
                } else {
                    println!("{}", report.display_compact());
                }
                if report.status.is_pass() {
                    passed += 1;
                } else if report.status.is_skipped() {
                    skipped += 1;
                } else {
                    failed += 1;
                }
            }
        }
    }

    let (assert_total, assert_passed, assert_failed) = evaluate_cross_runs(&cross_runs);
    total += assert_total;
    passed += assert_passed;
    failed += assert_failed;
    let elapsed = suite_start.elapsed();
    if skipped > 0 {
        println!(
            "--- {} tests, {} passed, {} failed, {} skipped ({:.1?}) ---",
            total, passed, failed, skipped, elapsed
        );
    } else {
        println!(
            "--- {} tests, {} passed, {} failed ({:.1?}) ---",
            total, passed, failed, elapsed
        );
    }
    if failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

#[derive(Clone)]
struct DiffSeed {
    case_id: String,
    source_path: String,
    test_source: String,
    flow_open_offset: Option<usize>,
    mutation_eligible: bool,
    program: plzn::ir::Program,
}

struct DiffShim {
    spec: plzn::shim::ShimSpec,
    label: String,
}

#[derive(Clone, serde::Serialize)]
struct DiffObservation {
    backend: String,
    shim_path: String,
    fingerprint: String,
    outcome: plzn::runtime::ObservedOutcome,
    negotiated_cipher_suite: Option<u16>,
    shim_case: String,
    shim_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shim_detail: Option<String>,
}

impl DiffObservation {
    fn is_comparable(&self) -> bool {
        if self.shim_case == "crashed" {
            return true;
        }
        !matches!(
            self.shim_case.as_str(),
            "unsupported_config" | "local_error" | "unknown" | "setup_error" | "wait_error"
        ) && !matches!(
            self.outcome,
            plzn::runtime::ObservedOutcome::Internal { .. }
                | plzn::runtime::ObservedOutcome::Transport { .. }
                | plzn::runtime::ObservedOutcome::Skipped { .. }
        )
    }

    fn is_success(&self) -> bool {
        self.is_comparable() && self.outcome.is_success() && self.shim_case != "crashed"
    }
}

#[derive(Clone, serde::Serialize)]
struct DifferentialRecord {
    schema_version: u32,
    case_id: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation: Option<plzn::discovery::MutationCandidate>,
    comparable_backends: usize,
    divergent: bool,
    mutation_expectation_violated: bool,
    stable: bool,
    score: u32,
    confirmed_runs: usize,
    observations: Vec<DiffObservation>,
}

fn diff_cmd(args: &[String]) -> ExitCode {
    let mut shim_paths = Vec::new();
    let mut paths = Vec::new();
    let mut mutate = false;
    let mut json = false;
    let mut budget = 256usize;
    let mut reruns = 2usize;
    let mut out_dir: Option<std::path::PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--shim" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    eprintln!("plzn diff: --shim requires an executable path");
                    return ExitCode::from(2);
                };
                shim_paths.push(path.clone());
            }
            "--mutate" => mutate = true,
            "--json" => json = true,
            "--budget" => {
                i += 1;
                budget = match args.get(i).and_then(|value| value.parse().ok()) {
                    Some(value) if value > 0 => value,
                    _ => {
                        eprintln!("plzn diff: --budget requires a positive integer");
                        return ExitCode::from(2);
                    }
                };
            }
            "--reruns" => {
                i += 1;
                reruns = match args.get(i).and_then(|value| value.parse().ok()) {
                    Some(value) if value > 0 => value,
                    _ => {
                        eprintln!("plzn diff: --reruns requires a positive integer");
                        return ExitCode::from(2);
                    }
                };
            }
            "--out" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    eprintln!("plzn diff: --out requires a directory");
                    return ExitCode::from(2);
                };
                out_dir = Some(path.into());
            }
            "-h" | "--help" => {
                eprintln!("usage: plzn diff --shim PATH --shim PATH [OPTIONS] <file.plzn|dir>...");
                eprintln!();
                eprintln!("  --shim PATH  compare one identified shim (repeat at least twice)");
                eprintln!("  --mutate     generate deterministic single-mutation candidates");
                eprintln!("  --budget N   maximum generated candidates (default: 256)");
                eprintln!("  --reruns N   total runs used to confirm each difference (default: 2)");
                eprintln!("  --out DIR    finding artifacts (default with --mutate: findings)");
                eprintln!("  --json       emit one JSON object per observed case/candidate");
                return ExitCode::from(0);
            }
            other if other.starts_with('-') => {
                eprintln!("plzn diff: unknown flag {:?}", other);
                return ExitCode::from(2);
            }
            path => paths.push(path.to_string()),
        }
        i += 1;
    }

    if shim_paths.len() < 2 {
        eprintln!("plzn diff: provide at least two --shim PATH arguments");
        return ExitCode::from(2);
    }
    let files = expand_plzn_files(paths);
    if files.is_empty() {
        eprintln!("plzn diff: no .plzn files found");
        return ExitCode::from(2);
    }

    let mut identified = Vec::new();
    for path in shim_paths {
        let shim = match plzn::shim::ShimSpec::identify(&path) {
            Ok(shim) => shim,
            Err(error) => {
                eprintln!("plzn diff: cannot identify shim {}: {}", path, error);
                return ExitCode::from(2);
            }
        };
        identified.push(shim);
    }
    let mut name_counts = std::collections::BTreeMap::new();
    for shim in &identified {
        *name_counts
            .entry(shim.name().to_ascii_lowercase())
            .or_insert(0usize) += 1;
    }
    let shims: Vec<DiffShim> = identified
        .into_iter()
        .map(|spec| {
            let name = spec.name().to_ascii_lowercase();
            let label = if name_counts[&name] > 1 {
                format!("{} ({})", spec.name(), absolute_path(spec.binary()))
            } else {
                spec.name().into()
            };
            DiffShim { spec, label }
        })
        .collect();

    let seeds = match load_diff_seeds(&files) {
        Ok(seeds) => seeds,
        Err(()) => return ExitCode::from(2),
    };
    if seeds.is_empty() {
        eprintln!("plzn diff: no single-connection test cases found");
        return ExitCode::from(2);
    }

    let cert_dir = match tempfile::Builder::new()
        .prefix("plzn-diff-certs-")
        .tempdir()
    {
        Ok(dir) => dir,
        Err(error) => {
            eprintln!("plzn diff: cannot create certificate directory: {}", error);
            return ExitCode::from(2);
        }
    };
    let mut store = ChainStore {
        dir: cert_dir.path().to_path_buf(),
        default: plzn::server::certs::KeyType::EcdsaP256,
        cache: std::collections::HashMap::new(),
        client_cache: std::collections::HashMap::new(),
    };
    let (default_files, _) = match store.get(plzn::server::certs::KeyType::EcdsaP256) {
        Ok(files) => files,
        Err(error) => {
            eprintln!("plzn diff: certificate setup failed: {}", error);
            return ExitCode::from(2);
        }
    };

    let output_dir = out_dir.unwrap_or_else(|| std::path::PathBuf::from("findings"));
    let mut compared = 0usize;
    let mut divergent = 0usize;
    let mut mutation_expectation_violations = 0usize;
    let mut findings = 0usize;
    let mut unstable = 0usize;
    let mut incomplete = 0usize;
    let mut generated = 0usize;
    let mut seen_clusters = std::collections::BTreeSet::new();

    for seed in seeds {
        let mut base_program = seed.program.clone();
        if let Err(error) = resolve_program_chains(&mut base_program, &mut store) {
            eprintln!("plzn diff: {}: chain setup: {}", seed.case_id, error);
            return ExitCode::from(2);
        }
        let base_seed = test_seed_from_id(&seed.case_id);

        if !mutate {
            let observations = observe_all(&shims, &base_program, &default_files, base_seed);
            let record = differential_record(&seed, None, observations, true, 1);
            compared += 1;
            divergent += usize::from(record.divergent);
            mutation_expectation_violations += usize::from(record.mutation_expectation_violated);
            incomplete += usize::from(record.comparable_backends < 2);
            emit_differential_record(&record, json);
            continue;
        }

        if !seed.mutation_eligible {
            if !json {
                println!(
                    "[SKIP] {} — mutation generation requires one unanchored, non-matrix `flow handshake` test",
                    seed.case_id
                );
            }
            continue;
        }
        let baseline = observe_all(&shims, &base_program, &default_files, base_seed);
        let comparable_baseline: Vec<_> = baseline
            .iter()
            .filter(|observation| observation.is_comparable())
            .collect();
        if comparable_baseline.len() < 2
            || !comparable_baseline
                .iter()
                .all(|observation| observation.is_success())
        {
            if !json {
                println!(
                    "[SKIP] {} — unmodified baseline is not a common successful handshake",
                    seed.case_id
                );
                for observation in &baseline {
                    println!(
                        "       {}: {}",
                        observation.backend, observation.fingerprint
                    );
                }
            }
            continue;
        }

        let remaining = budget.saturating_sub(generated);
        for candidate in plzn::discovery::candidates(&base_program, remaining) {
            generated += 1;
            let generated_source = match generate_candidate_source(&seed, &candidate) {
                Ok(source) => source,
                Err(error) => {
                    eprintln!(
                        "plzn diff: cannot generate {}[mutation={}]: {}",
                        seed.case_id, candidate.id, error
                    );
                    return ExitCode::from(2);
                }
            };
            let mut program = match lower_generated_candidate(&generated_source) {
                Ok(program) => program,
                Err(error) => {
                    eprintln!(
                        "plzn diff: generated {}[mutation={}] did not lower: {}",
                        seed.case_id, candidate.id, error
                    );
                    return ExitCode::from(2);
                }
            };
            if let Err(error) = resolve_program_chains(&mut program, &mut store) {
                eprintln!("plzn diff: {}: chain setup: {}", seed.case_id, error);
                return ExitCode::from(2);
            }

            let observations = observe_all(&shims, &program, &default_files, base_seed);
            let is_divergent = observations_diverge(&observations);
            let expectation_violated = mutation_expectation_violated(&candidate, &observations);
            let mut stable = true;
            let mut confirmed_runs = 1usize;
            let expected_vector = observation_vector(&observations);
            if is_divergent || expectation_violated {
                for _ in 1..reruns {
                    let confirmation = observe_all(&shims, &program, &default_files, base_seed);
                    confirmed_runs += 1;
                    if observation_vector(&confirmation) != expected_vector {
                        stable = false;
                        break;
                    }
                }
            }
            let record = differential_record(
                &seed,
                Some(candidate.clone()),
                observations,
                stable,
                confirmed_runs,
            );
            compared += 1;
            divergent += usize::from(record.divergent);
            mutation_expectation_violations += usize::from(record.mutation_expectation_violated);
            unstable +=
                usize::from((record.divergent || record.mutation_expectation_violated) && !stable);
            incomplete += usize::from(record.comparable_backends < 2);

            let cluster = format!(
                "{}:{}:{}",
                seed.case_id,
                candidate.message,
                observation_vector(&record.observations).join("|")
            );
            let novel = (record.divergent || record.mutation_expectation_violated)
                && record.stable
                && seen_clusters.insert(cluster);
            emit_differential_record(&record, json);
            if novel {
                if let Err(error) = write_finding(&output_dir, &record, &generated_source, &shims) {
                    eprintln!("plzn diff: cannot write finding: {}", error);
                    return ExitCode::from(2);
                }
                findings += 1;
            }
            if generated >= budget {
                break;
            }
        }
        if generated >= budget {
            break;
        }
    }

    if !json {
        if mutate {
            println!(
                "--- {} candidates, {} divergent, {} mutation-expectation violations, {} stable finding clusters, {} unstable, {} incomplete ---",
                compared,
                divergent,
                mutation_expectation_violations,
                findings,
                unstable,
                incomplete
            );
            if findings > 0 {
                println!("--- findings written to {} ---", output_dir.display());
            }
        } else {
            println!(
                "--- {} cases, {} divergent, {} incomplete ---",
                compared, divergent, incomplete
            );
        }
    }
    ExitCode::from(0)
}

fn load_diff_seeds(files: &[String]) -> Result<Vec<DiffSeed>, ()> {
    let mut seeds = Vec::new();
    let mut failed = false;
    for path in files {
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("plzn diff: cannot read {}: {}", path, error);
                failed = true;
                continue;
            }
        };
        let tokens = match plzn::lex::lex(&source) {
            Ok(tokens) => tokens,
            Err(errors) => {
                for error in errors {
                    eprintln!("{}", error.into_diag(path, &source));
                }
                failed = true;
                continue;
            }
        };
        let file = match plzn::parse::parse(&tokens) {
            Ok(file) => file,
            Err(errors) => {
                for error in errors {
                    eprintln!("{}", error.into_diag(path, &source));
                }
                failed = true;
                continue;
            }
        };
        let errors = plzn::check::check(&file);
        if !errors.is_empty() {
            for error in errors {
                eprintln!("{}", error.into_diag(path, &source));
            }
            failed = true;
            continue;
        }
        for test in &file.tests {
            let programs = match plzn::lower::lower(test) {
                Ok(programs) => programs,
                Err(errors) => {
                    for error in errors {
                        eprintln!("{}", error.into_diag(path, &source));
                    }
                    failed = true;
                    continue;
                }
            };
            if !test.sessions.is_empty() {
                eprintln!(
                    "plzn diff: skipping {}: session blocks are deferred until stateful discovery",
                    test.name.value
                );
                continue;
            }
            let test_source = source[test.span.start..test.span.end].to_string();
            let flow_open_offset = test.flow.as_ref().and_then(|flow| {
                let relative_start = flow.span.start - test.span.start;
                test_source[relative_start..]
                    .find('{')
                    .map(|offset| relative_start + offset)
            });
            let mutation_eligible = programs.len() == 1
                && test.matrix.is_none()
                && test.repeat.is_none()
                && test
                    .flow
                    .as_ref()
                    .and_then(|flow| flow.preset.as_ref())
                    .is_some_and(|preset| {
                        preset.base.name == "handshake" && preset.anchor.is_none()
                    })
                && programs[0].send_mutations.is_empty()
                && programs[0].steps.iter().all(|step| !matches!(step, plzn::ir::Step::HandshakeSteps { config: Some(config), .. } if !config.mutations.is_empty() || !config.ext_deltas.is_empty()))
                && programs[0].send_ext_deltas.is_empty()
                && matches!(programs[0].expect, plzn::ir::Expectation::Ok);
            for program in programs {
                seeds.push(DiffSeed {
                    case_id: program.test_id.clone(),
                    source_path: path.clone(),
                    test_source: test_source.clone(),
                    flow_open_offset,
                    mutation_eligible,
                    program,
                });
            }
        }
    }
    if failed { Err(()) } else { Ok(seeds) }
}

fn observation_program(program: &plzn::ir::Program) -> plzn::ir::Program {
    let mut program = program.clone();
    program.expect = plzn::ir::Expectation::Any(vec![
        plzn::ir::Expectation::Ok,
        plzn::ir::Expectation::HandshakeFails,
    ]);
    program.expect_overrides.clear();
    program
}

fn observe_all(
    shims: &[DiffShim],
    program: &plzn::ir::Program,
    default_files: &plzn::ir::ChainFiles,
    seed: [u8; 32],
) -> Vec<DiffObservation> {
    // Backends are independent oracles. Run them concurrently so a timeout on
    // one implementation does not multiply a campaign's wall-clock cost by
    // the number of shims, while joining in declaration order keeps vectors
    // and JSON deterministic.
    std::thread::scope(|scope| {
        let handles: Vec<_> = shims
            .iter()
            .map(|shim| scope.spawn(move || observe_one(shim, program, default_files, seed)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("differential backend thread panicked"))
            .collect()
    })
}

fn observe_one(
    shim: &DiffShim,
    program: &plzn::ir::Program,
    default_files: &plzn::ir::ChainFiles,
    seed: [u8; 32],
) -> DiffObservation {
    use plzn::shim::{ShimConfig, ShimFactory, ShimResultCase};
    let observed_program = observation_program(program);
    let config = ShimConfig::for_program(
        &observed_program,
        Some(&default_files.cert_file),
        Some(&default_files.key_file),
        Some(shim.spec.name()),
    );
    let factory = match config.and_then(|config| ShimFactory::from_spec(shim.spec.clone(), config))
    {
        Ok(factory) => factory,
        Err(error) => {
            return DiffObservation {
                backend: shim.label.clone(),
                shim_path: absolute_path(shim.spec.binary()),
                fingerprint: "setup_error".into(),
                outcome: plzn::runtime::ObservedOutcome::Transport {
                    detail: error.to_string(),
                },
                negotiated_cipher_suite: None,
                shim_case: "setup_error".into(),
                shim_exit_code: None,
                shim_detail: Some(error.to_string()),
            };
        }
    };
    let report = plzn::runtime::run(&observed_program, &factory, seed, None);
    let outcome = factory.wait_shim();
    let (shim_case, shim_exit_code, shim_detail, fingerprint) = match outcome {
        Ok(outcome) => {
            let fingerprint = match outcome.case {
                ShimResultCase::UnsupportedConfig => "unsupported".into(),
                ShimResultCase::Crashed(signal) => format!("crash:{signal}"),
                ShimResultCase::LocalError => "shim-local-error".into(),
                ShimResultCase::Unknown(_) => "shim-unknown".into(),
                _ => report.raw_outcome.fingerprint(),
            };
            (
                outcome.case.label().into(),
                outcome.code,
                outcome.detail,
                fingerprint,
            )
        }
        Err(error) => (
            "wait_error".into(),
            None,
            Some(error.to_string()),
            "wait-error".into(),
        ),
    };
    DiffObservation {
        backend: shim.label.clone(),
        shim_path: absolute_path(shim.spec.binary()),
        fingerprint,
        outcome: report.raw_outcome,
        negotiated_cipher_suite: report.negotiated_cipher_suite,
        shim_case,
        shim_exit_code,
        shim_detail,
    }
}

fn differential_record(
    seed: &DiffSeed,
    mutation: Option<plzn::discovery::MutationCandidate>,
    observations: Vec<DiffObservation>,
    stable: bool,
    confirmed_runs: usize,
) -> DifferentialRecord {
    let divergent = observations_diverge(&observations);
    let mutation_expectation_violated = mutation
        .as_ref()
        .is_some_and(|candidate| mutation_expectation_violated(candidate, &observations));
    let score = differential_score(mutation.as_ref(), &observations);
    let comparable_backends = comparable_fingerprints(&observations).len();
    DifferentialRecord {
        schema_version: 1,
        case_id: seed.case_id.clone(),
        source: seed.source_path.clone(),
        mutation,
        comparable_backends,
        divergent,
        mutation_expectation_violated,
        stable,
        score,
        confirmed_runs,
        observations,
    }
}

fn comparable_fingerprints(observations: &[DiffObservation]) -> Vec<&str> {
    observations
        .iter()
        .filter(|observation| observation.is_comparable())
        .map(|observation| observation.fingerprint.as_str())
        .collect()
}

fn observations_diverge(observations: &[DiffObservation]) -> bool {
    let fingerprints = comparable_fingerprints(observations);
    fingerprints.len() >= 2
        && fingerprints
            .iter()
            .skip(1)
            .any(|fingerprint| *fingerprint != fingerprints[0])
}

fn mutation_expectation_violated(
    candidate: &plzn::discovery::MutationCandidate,
    observations: &[DiffObservation],
) -> bool {
    let comparable: Vec<_> = observations
        .iter()
        .filter(|observation| observation.is_comparable())
        .collect();
    if comparable.len() < 2 {
        return false;
    }
    match candidate.validity {
        plzn::discovery::MutationValidity::Preserving => comparable
            .iter()
            .any(|observation| !observation.is_success()),
        plzn::discovery::MutationValidity::Invalid => comparable
            .iter()
            .any(|observation| observation.is_success()),
        plzn::discovery::MutationValidity::Exploratory => false,
    }
}

fn observation_vector(observations: &[DiffObservation]) -> Vec<String> {
    observations
        .iter()
        .map(|observation| format!("{}={}", observation.backend, observation.fingerprint))
        .collect()
}

fn differential_score(
    mutation: Option<&plzn::discovery::MutationCandidate>,
    observations: &[DiffObservation],
) -> u32 {
    let divergent = observations_diverge(observations);
    let expectation_violated =
        mutation.is_some_and(|candidate| mutation_expectation_violated(candidate, observations));
    if !divergent && !expectation_violated {
        return 0;
    }
    let fingerprints = comparable_fingerprints(observations);
    if fingerprints
        .iter()
        .any(|fingerprint| fingerprint.starts_with("crash:"))
    {
        return 1000;
    }
    let successes = observations
        .iter()
        .filter(|observation| observation.is_success())
        .count();
    if successes > 0 && successes < fingerprints.len() {
        return 900;
    }
    if expectation_violated {
        return 850;
    }
    if mutation.is_some_and(|candidate| {
        candidate.validity == plzn::discovery::MutationValidity::Preserving
    }) {
        return 800;
    }
    if fingerprints
        .iter()
        .any(|fingerprint| fingerprint.starts_with("timeout"))
    {
        return 700;
    }
    let has_alert = fingerprints
        .iter()
        .any(|fingerprint| fingerprint.starts_with("alert:"));
    let has_close = fingerprints
        .iter()
        .any(|fingerprint| fingerprint.starts_with("close@") || fingerprint.starts_with("reset@"));
    if has_alert && has_close { 400 } else { 100 }
}

fn emit_differential_record(record: &DifferentialRecord, json: bool) {
    if json {
        match serde_json::to_string(record) {
            Ok(line) => println!("{}", line),
            Err(error) => eprintln!("plzn diff: cannot encode JSON result: {}", error),
        }
        return;
    }
    // Mutation campaigns can contain thousands of agreeing probes. Keep the
    // interactive output focused on findings; the summary still reports how
    // many candidates ran. JSON mode remains a complete event stream.
    if record.mutation.is_some()
        && !record.divergent
        && !record.mutation_expectation_violated
        && record.comparable_backends >= 2
    {
        return;
    }
    let label = if record.comparable_backends < 2 {
        "INCOMPLETE"
    } else if !record.divergent && !record.mutation_expectation_violated {
        "SAME"
    } else if !record.stable {
        "FLAKY"
    } else if record.mutation_expectation_violated && !record.divergent {
        "EXPECTATION"
    } else {
        "DIFF"
    };
    let mutation = record
        .mutation
        .as_ref()
        .map(|candidate| format!("[mutation={}]", candidate.id))
        .unwrap_or_default();
    println!(
        "[{}] {}{} — score {}",
        label, record.case_id, mutation, record.score
    );
    if record.mutation_expectation_violated {
        if let Some(mutation) = &record.mutation {
            println!(
                "       generated mutation expected {}, but at least one backend did not",
                mutation.expected
            );
        }
    }
    if record.divergent
        || record.mutation_expectation_violated
        || record.observations.iter().any(|o| !o.is_comparable())
    {
        for observation in &record.observations {
            println!(
                "       {}: {}",
                observation.backend, observation.fingerprint
            );
        }
    }
}

fn generate_candidate_source(
    seed: &DiffSeed,
    candidate: &plzn::discovery::MutationCandidate,
) -> Result<String, String> {
    let open = seed
        .flow_open_offset
        .ok_or("test has no flow opening brace")?;
    let generated = plzn::discovery::inject_flow_mutation(&seed.test_source, open, candidate)?;
    plzn::format::format_source("generated.plzn", &generated).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn lower_generated_candidate(source: &str) -> Result<plzn::ir::Program, String> {
    let tokens = plzn::lex::lex(source).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| error.into_diag("generated.plzn", source).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    let file = plzn::parse::parse(&tokens).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| error.into_diag("generated.plzn", source).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    let errors = plzn::check::check(&file);
    if !errors.is_empty() {
        return Err(errors
            .into_iter()
            .map(|error| error.into_diag("generated.plzn", source).to_string())
            .collect::<Vec<_>>()
            .join("\n"));
    }
    let test = file
        .tests
        .first()
        .ok_or("generated source contains no test")?;
    let mut programs = plzn::lower::lower(test).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| error.into_diag("generated.plzn", source).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    if programs.len() != 1 {
        return Err("generated source did not lower to exactly one program".into());
    }
    Ok(programs.remove(0))
}

fn write_finding(
    root: &std::path::Path,
    record: &DifferentialRecord,
    source: &str,
    shims: &[DiffShim],
) -> Result<(), String> {
    let mutation = record.mutation.as_ref().ok_or("finding has no mutation")?;
    let slug = plzn::discovery::artifact_slug(&record.case_id, &mutation.id);
    let dir = root.join(slug);
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("creating {}: {}", dir.display(), error))?;
    std::fs::write(dir.join("case.plzn"), source)
        .map_err(|error| format!("writing case.plzn: {}", error))?;
    let json = serde_json::to_string_pretty(record)
        .map_err(|error| format!("encoding result.json: {}", error))?;
    std::fs::write(dir.join("result.json"), format!("{}\n", json))
        .map_err(|error| format!("writing result.json: {}", error))?;

    let plzn_binary =
        std::env::current_exe().map_err(|error| format!("locating plzn executable: {}", error))?;
    let mut repro = format!(
        "#!/bin/sh\nset -eu\nexec {} diff",
        shell_quote(&absolute_path(&plzn_binary))
    );
    for shim in shims {
        repro.push_str(" --shim ");
        repro.push_str(&shell_quote(&absolute_path(shim.spec.binary())));
    }
    repro.push_str(" \"$(dirname \"$0\")/case.plzn\"\n");
    let repro_path = dir.join("repro.sh");
    std::fs::write(&repro_path, repro).map_err(|error| format!("writing repro.sh: {}", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&repro_path)
            .map_err(|error| format!("reading repro.sh metadata: {}", error))?
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&repro_path, permissions)
            .map_err(|error| format!("marking repro.sh executable: {}", error))?;
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn absolute_path(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

/// What one case (a single program, or every session of a multi-session
/// test) produced. Cases run on a worker pool; the main thread prints the
/// results in input order and folds the counts, so the output of a parallel
/// run is byte-identical to a serial one (timings aside).
/// T1 cross-run capture: (repeat group, its asserts, test id, captured values).
type CaseCapture = (
    String,
    Vec<plzn::ir::CrossAssert>,
    String,
    Vec<(String, Vec<u8>)>,
);

#[derive(Clone, serde::Serialize)]
struct MachineStepReport {
    index: usize,
    description: String,
    status: &'static str,
    duration_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct MachineCipherSuite {
    wire: u16,
    hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct MachineCapture {
    name: String,
    value_hex: String,
}

#[derive(Clone, serde::Serialize)]
struct MachineShimOutcome {
    success: bool,
    case: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    exit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    stdout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    stderr: String,
}

impl MachineShimOutcome {
    fn from_result(outcome: &std::io::Result<plzn::shim::ShimOutcome>) -> Self {
        match outcome {
            Ok(outcome) => Self {
                success: outcome.success,
                case: outcome.case.label().to_string(),
                exit_code: outcome.code,
                exit: outcome.describe_exit(),
                detail: outcome.detail.clone(),
                stdout: outcome.stdout.clone(),
                stderr: outcome.stderr.clone(),
            },
            Err(error) => Self {
                success: false,
                case: "wait_error".into(),
                exit_code: None,
                exit: error.to_string(),
                detail: Some(error.to_string()),
                stdout: String::new(),
                stderr: String::new(),
            },
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct MachineRunRecord {
    schema_version: u32,
    #[serde(rename = "type")]
    record_type: &'static str,
    test_id: String,
    backend: String,
    status: String,
    classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uut: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<plzn::runtime::ObservedOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    negotiated_cipher_suite: Option<MachineCipherSuite>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    steps: Vec<MachineStepReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    captures: Vec<MachineCapture>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shim: Option<MachineShimOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn bytes_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

impl MachineRunRecord {
    fn from_report(report: &plzn::runtime::RunReport, backend: &str, status: &str) -> Self {
        let (reason, error) = match &report.status {
            plzn::runtime::RunStatus::Pass => (None, None),
            plzn::runtime::RunStatus::Skipped(reason) => (Some(reason.clone()), None),
            plzn::runtime::RunStatus::Fail(error) => (None, Some(error.to_string())),
        };
        Self {
            schema_version: 1,
            record_type: "case",
            test_id: report.test_id.clone(),
            backend: backend.to_string(),
            status: status.to_string(),
            classification: "test".into(),
            protocol: None,
            version: None,
            uut: None,
            session: None,
            expected: Some(report.expected.clone()),
            observed: Some(report.observed.clone()),
            outcome: Some(report.raw_outcome.clone()),
            peer: Some(report.peer_description.clone()),
            duration_ns: Some(duration_ns(report.total_duration)),
            negotiated_cipher_suite: report.negotiated_cipher_suite.map(|wire| {
                MachineCipherSuite {
                    wire,
                    hex: format!("0x{wire:04x}"),
                    name: plzn::schema::suite_name(wire).map(str::to_string),
                }
            }),
            steps: report
                .steps
                .iter()
                .map(|step| {
                    let (status, error) = match &step.status {
                        plzn::runtime::StepStatus::Ok => ("ok", None),
                        plzn::runtime::StepStatus::Skipped => ("skipped", None),
                        plzn::runtime::StepStatus::Failed(error) => ("failed", Some(error.clone())),
                    };
                    MachineStepReport {
                        index: step.index,
                        description: step.description.clone(),
                        status,
                        duration_ns: duration_ns(step.duration),
                        error,
                    }
                })
                .collect(),
            captures: report
                .captures
                .iter()
                .map(|(name, value)| MachineCapture {
                    name: name.clone(),
                    value_hex: bytes_hex(value),
                })
                .collect(),
            shim: None,
            reason,
            error,
        }
    }

    fn synthetic(
        test_id: &str,
        backend: &str,
        status: &str,
        classification: &str,
        reason: Option<String>,
        error: Option<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            record_type: "case",
            test_id: test_id.to_string(),
            backend: backend.to_string(),
            status: status.to_string(),
            classification: classification.to_string(),
            protocol: None,
            version: None,
            uut: None,
            session: None,
            expected: None,
            observed: None,
            outcome: None,
            peer: None,
            duration_ns: None,
            negotiated_cipher_suite: None,
            steps: vec![],
            captures: vec![],
            shim: None,
            reason,
            error,
        }
    }

    fn attach_program(&mut self, program: &plzn::ir::Program) {
        self.protocol = Some(match program.protocol {
            plzn::ir::Protocol::Tls => "tls",
            plzn::ir::Protocol::Dtls => "dtls",
        });
        self.version = Some(match (program.protocol, program.version) {
            (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls10) => "tls10",
            (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls11) => "tls11",
            (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls12) => "tls12",
            (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls13) => "tls13",
            (plzn::ir::Protocol::Dtls, plzn::tls::record::TlsVersion::Tls12) => "dtls12",
            (plzn::ir::Protocol::Dtls, plzn::tls::record::TlsVersion::Tls13) => "dtls13",
            (plzn::ir::Protocol::Dtls, _) => unreachable!("DTLS has no TLS 1.0/1.1 IR version"),
        });
        self.uut = Some(match program.subject {
            plzn::ir::Subject::Client => "client",
            plzn::ir::Subject::Server => "server",
        });
        self.session = program.session_name.clone();
    }
}

#[derive(serde::Serialize)]
struct MachineRunSummary {
    schema_version: u32,
    #[serde(rename = "type")]
    record_type: &'static str,
    backend: String,
    shim_path: String,
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    xfailed: usize,
    xpassed: usize,
    duration_ns: u64,
    aborted: bool,
}

fn record_cross_run(
    runs: &mut CrossRuns,
    program: &plzn::ir::Program,
    report: &plzn::runtime::RunReport,
) {
    if let Some(group) = &program.repeat_group {
        runs.entry(group.clone())
            .or_insert_with(|| (program.cross_asserts.clone(), vec![]))
            .1
            .push((program.test_id.clone(), report.captures.clone()));
    }
}

struct CrossRunVerdict {
    group: String,
    label: String,
    runs: usize,
    failure: Option<String>,
}

fn cross_run_verdicts(cross_runs: &CrossRuns) -> Vec<CrossRunVerdict> {
    let mut results = Vec::new();
    for (group, (asserts, runs)) in cross_runs {
        for a in asserts {
            match a {
                plzn::ir::CrossAssert::Unique(names) => {
                    let mut verdict: Option<String> = None;
                    for name in names {
                        if verdict.is_some() {
                            break;
                        }
                        let mut seen: std::collections::HashMap<Vec<u8>, String> =
                            std::collections::HashMap::new();
                        let mut count = 0usize;
                        for (id, caps) in runs {
                            if !caps.iter().any(|(n, _)| n == name) && verdict.is_none() {
                                verdict = Some(format!("`${name}` was not captured in {id}"));
                            }
                            for (n, v) in caps {
                                if n == name {
                                    count += 1;
                                    if let Some(first) = seen.insert(v.clone(), id.clone()) {
                                        if verdict.is_none() {
                                            verdict = Some(format!(
                                                "`${}` repeated between {} and {}",
                                                name, first, id
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                        if count < 2 && verdict.is_none() {
                            verdict = Some(format!(
                                "`${}` was captured {} time(s); a uniqueness assert needs at least two runs",
                                name, count
                            ));
                        }
                    }
                    let label = format!(
                        "assert unique {}",
                        names
                            .iter()
                            .map(|n| format!("${}", n))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    results.push(CrossRunVerdict {
                        group: group.clone(),
                        label,
                        runs: runs.len(),
                        failure: verdict,
                    });
                }
            }
        }
    }
    results
}

fn evaluate_cross_runs(cross_runs: &CrossRuns) -> (usize, usize, usize) {
    let (mut total, mut passed, mut failed) = (0, 0, 0);
    // T1: cross-run asserts, one verdict line per (test, assert).
    for verdict in cross_run_verdicts(cross_runs) {
        total += 1;
        match verdict.failure {
            None => {
                println!(
                    "[PASS] {} — {} over {} runs",
                    verdict.group, verdict.label, verdict.runs
                );
                passed += 1;
            }
            Some(why) => {
                println!("[FAIL] {} — {}: {}", verdict.group, verdict.label, why);
                failed += 1;
            }
        }
    }
    (total, passed, failed)
}

#[derive(Default)]
struct CaseResult {
    /// The case's stdout: the report lines, `[SKIP]` / `[CRASH]` lines.
    out: String,
    /// The case's stderr: the shim's own output, spawn failures, diagnostics.
    err: String,
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    /// Expected protocol failures and unexpected passes from `xfail`.
    xfailed: usize,
    xpassed: usize,
    skip_log: Vec<(String, String)>,
    xfail_log: Vec<(String, String)>,
    /// `Some(crashed)` when the case reached a verdict the crash breaker
    /// should see; `None` for cases skipped before any shim ran.
    breaker_event: Option<bool>,
    /// T1: (repeat group, its cross-run asserts, test id, captured values).
    captures: Vec<CaseCapture>,
    /// Structured equivalents of this case's human report lines.
    machine: Vec<MachineRunRecord>,
}

/// A unit of work for the pool.
enum Item {
    /// Decided before any shim ran (a parse / lint / lower error, a
    /// `skip <backend>` directive): printed in order, never scheduled.
    Done(CaseResult),
    /// One shim process serving every session of the test.
    Multi {
        test_name: String,
        programs: Vec<plzn::ir::Program>,
    },
    /// One program, one shim process.
    Single(Box<plzn::ir::Program>),
}

/// Read-only per-run state every worker shares.
struct RunCtx {
    shim: plzn::shim::ShimSpec,
    /// The run default's PEM pair (what `chain: [default]` resolves to), the
    /// legacy arguments of `ShimConfig::for_program`.
    cert_str: String,
    key_str: String,
    verbose: bool,
}

/// A: the run's certificate chains. Each key type is generated (or loaded from
/// shims/testdata) once per run on first use and written as PEM into the run's
/// cert directory; `default` is what `--cert` named.
struct ChainStore {
    dir: std::path::PathBuf,
    default: plzn::server::certs::KeyType,
    cache: std::collections::HashMap<
        plzn::server::certs::KeyType,
        (plzn::ir::ChainFiles, plzn::ir::Chain),
    >,
    client_cache: std::collections::HashMap<plzn::server::certs::KeyType, plzn::ir::Chain>,
}

impl ChainStore {
    fn get(
        &mut self,
        kt: plzn::server::certs::KeyType,
    ) -> Result<(plzn::ir::ChainFiles, plzn::ir::Chain), String> {
        if let Some(e) = self.cache.get(&kt) {
            return Ok(e.clone());
        }
        let bundle = plzn::server::certs::CertBundle::generate(kt)
            .map_err(|e| format!("{} certificate: {}", kt.name(), e))?;
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cert dir {}: {}", self.dir.display(), e))?;
        let cert = self.dir.join(format!("{}_cert.pem", kt.name()));
        let key = self.dir.join(format!("{}_key.pem", kt.name()));
        std::fs::write(&cert, &bundle.cert_pem)
            .map_err(|e| format!("writing {}: {}", cert.display(), e))?;
        std::fs::write(&key, &bundle.key_pem)
            .map_err(|e| format!("writing {}: {}", key.display(), e))?;
        let parsed_key = plzn::tls::crypto::PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der)
            .map_err(|e| format!("parsing {} private key: {e}", kt.name()))?;
        let entry = (
            plzn::ir::ChainFiles {
                key_type: kt,
                cert_file: cert.to_string_lossy().into_owned(),
                key_file: key.to_string_lossy().into_owned(),
            },
            plzn::ir::Chain {
                key_type: kt,
                cert_der: bundle.cert_der,
                key_der: bundle.key_pkcs8_der,
                parsed_key,
            },
        );
        self.cache.insert(kt, entry.clone());
        Ok(entry)
    }

    fn client_chain(
        &mut self,
        key_type: plzn::server::certs::KeyType,
    ) -> Result<plzn::ir::Chain, String> {
        if let Some(chain) = self.client_cache.get(&key_type) {
            return Ok(chain.clone());
        }
        let (cert_der, key_der) = plzn::shim::client_credential_der_for(key_type)
            .ok_or_else(|| format!("missing {:?} client credential fixture", key_type))?;
        let parsed_key = plzn::tls::crypto::PrivateKey::from_pkcs8_der(&key_der)
            .map_err(|e| format!("parsing {:?} client credential key: {e}", key_type))?;
        let chain = plzn::ir::Chain {
            key_type,
            cert_der,
            key_der,
            parsed_key,
        };
        self.client_cache.insert(key_type, chain.clone());
        Ok(chain)
    }
}

/// A: resolve a program's `chain:` / `client_chain:` names for this run. plzn's
/// server holds every server chain (uut client) and the shim gets the
/// client-auth credentials; plzn's client picks from the client credentials
/// (uut server) and the shim gets the server chains as PEM files.
fn resolve_program_chains(
    program: &mut plzn::ir::Program,
    store: &mut ChainStore,
) -> Result<(), String> {
    use plzn::ir::{Chain, ChainFiles, Subject, SuiteFilter};
    use plzn::server::certs::KeyType;
    let mut server_files: Vec<ChainFiles> = Vec::new();
    let mut server_chains: Vec<Chain> = Vec::new();
    for name in &program.chain_names {
        let (files, chain) = if *name == plzn::ir::ChainName::Rsa2048EcdsaSigned {
            let key_type = KeyType::Rsa2048;
            let (cert_file, key_file) =
                plzn::shim::client_credential_files_for(key_type, &store.dir)
                    .map_err(|e| format!("writing CA-issued RSA certificate fixture: {e}"))?;
            let chain = store.client_chain(key_type)?;
            (
                ChainFiles {
                    key_type,
                    cert_file: cert_file.to_string_lossy().into_owned(),
                    key_file: key_file.to_string_lossy().into_owned(),
                },
                chain,
            )
        } else {
            store.get(name.resolve(store.default))?
        };
        server_files.push(files);
        server_chains.push(chain);
    }
    // `client_chain: [default]` is the P-256 client_ee credential, whatever
    // `--cert` says: the client side has no run default.
    let client_types: Vec<KeyType> = program
        .client_chain_names
        .iter()
        .map(|n| n.resolve(KeyType::EcdsaP256))
        .collect();
    if program.protocol == plzn::ir::Protocol::Tls
        && program.version < plzn::tls::record::TlsVersion::Tls12
    {
        if let Some(kind) = server_chains
            .iter()
            .map(|chain| chain.parsed_key.kind())
            .find(|kind| {
                matches!(
                    kind,
                    plzn::tls::crypto::KeyKind::RsaPss | plzn::tls::crypto::KeyKind::Ed25519
                )
            })
        {
            return Err(format!(
                "{} server chain cannot authenticate in TLS 1.0/1.1: those versions have no signature-algorithm negotiation for this key type",
                kind.dsl_name()
            ));
        }
        if let Some(kind) = client_types
            .iter()
            .find(|key_type| matches!(key_type, KeyType::RsaPss | KeyType::Ed25519))
        {
            return Err(format!(
                "{} client chain cannot authenticate in TLS 1.0/1.1: those versions have no signature-algorithm negotiation for this key type",
                kind.name()
            ));
        }
    }
    match program.subject {
        Subject::Client => {
            program.server_chains = server_chains.clone();
            match server_chains.first() {
                Some(c) => {
                    program.cert_der = Some(c.cert_der.clone());
                    program.private_key_der = Some(c.key_der.clone());
                }
                None => {
                    // `chain: []`: the server never presents a certificate, but
                    // its constructors want a key; the run default stands in and
                    // the ChainKeys filter below keeps every certificate suite out.
                    let (_, c) = store.get(store.default)?;
                    program.cert_der = Some(c.cert_der);
                    program.private_key_der = Some(c.key_der);
                }
            }
            program.shim_client_chains = client_types
                .iter()
                .map(|kt| {
                    plzn::shim::client_credential_files_for(*kt, &store.dir).map(|(c, k)| {
                        ChainFiles {
                            key_type: *kt,
                            cert_file: c.to_string_lossy().into_owned(),
                            key_file: k.to_string_lossy().into_owned(),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("writing client certificate fixtures: {e}"))?;
        }
        Subject::Server => {
            program.shim_server_chains = server_files;
            program.client_credentials = client_types
                .iter()
                .map(|kt| store.client_chain(*kt))
                .collect::<Result<Vec<_>, String>>()?;
            // plzn is the client in a client-authentication flow: it answers the
            // server's CertificateRequest with a CA-issued client_ee credential,
            // the ones whose CA the shim server is told to trust.
            if program_presents_client_cert(program) {
                if let Some(c) = program.client_credentials.first() {
                    program.cert_der = Some(c.cert_der.clone());
                    program.private_key_der = Some(c.key_der.clone());
                }
            }
        }
    }
    // `ecdhe` follows the configured chains. With no chain, constrain only
    // plzn's own server selection set: a client must still offer certificate
    // suites to exercise a UUT server's missing-credential rejection.
    if (program.ecdhe_by_chain && !program.chain_names.is_empty())
        || (program.subject == Subject::Client && program.chain_names.is_empty())
    {
        let mask = server_chains.iter().fold(0u8, |m, c| m | c.key_mask());
        program.suite_filters.push(SuiteFilter::ChainKeys(mask));
    }
    // `chain: [default]` cannot be checked fully at lint time. Reject a
    // chain-dependent empty intersection once the run default is known.
    if program.ecdhe_by_chain && !program.chain_names.is_empty() && program.version.is_legacy() {
        let suites = if program.protocol == plzn::ir::Protocol::Dtls {
            plzn::ir::filter_suites_dtls(&program.suite_filters, program.psk.is_some())
        } else {
            plzn::ir::filter_suites_legacy(
                program.version,
                &program.suite_filters,
                program.psk.is_some(),
            )
        };
        if suites.is_empty() {
            return Err("resolved server chains and peer cipher-suite selectors leave no supported suites; correct the chain or selectors".into());
        }
    }
    Ok(())
}

fn skip_result(
    test_id: &str,
    why: String,
    backend: &str,
    cannot_apply: bool,
    program: Option<&plzn::ir::Program>,
) -> CaseResult {
    let line = if cannot_apply {
        format!("[SKIP] {} — {} cannot apply: {}\n", test_id, backend, why)
    } else {
        format!(
            "[SKIP] {} — not applicable to {}: {}\n",
            test_id, backend, why
        )
    };
    let logged = if cannot_apply {
        format!("{} cannot apply {}", backend, why)
    } else {
        why.clone()
    };
    let mut machine = MachineRunRecord::synthetic(
        test_id,
        backend,
        "skip",
        if cannot_apply {
            "unsupported_config"
        } else {
            "not_applicable"
        },
        Some(why),
        None,
    );
    if let Some(program) = program {
        machine.attach_program(program);
    }
    CaseResult {
        out: line,
        total: 1,
        skipped: 1,
        skip_log: vec![(test_id.to_string(), logged)],
        machine: vec![machine],
        ..Default::default()
    }
}

fn setup_failure_result(test_id: &str, backend: &str, error: String) -> CaseResult {
    CaseResult {
        err: format!("[FAIL] {} — {}\n", test_id, error),
        total: 1,
        failed: 1,
        machine: vec![MachineRunRecord::synthetic(
            test_id,
            backend,
            "fail",
            "setup_error",
            None,
            Some(error),
        )],
        ..Default::default()
    }
}

fn shim_verdict_lines(test_id: &str, backend: &str, o: &plzn::shim::ShimOutcome) -> String {
    if o.is_crash() {
        // The shim process died by signal. plzn's own view of the wire only
        // shows the peer vanishing, so name the crash explicitly.
        format!(
            "[CRASH] {} — {} shim {}\n",
            test_id,
            backend,
            o.describe_exit()
        )
    } else if !o.success {
        format!(
            "    shim self-check FAILED: {}{}\n",
            o.case.label(),
            o.detail
                .as_deref()
                .map(|d| format!(" -- {}", d))
                .unwrap_or_default()
        )
    } else {
        String::new()
    }
}

fn xfail_reason(program: &plzn::ir::Program, backend_name: &str) -> Option<String> {
    program
        .xfail_backends
        .iter()
        .find(|(backend, _)| backend.eq_ignore_ascii_case(backend_name))
        .map(|(_, reason)| {
            reason
                .clone()
                .unwrap_or_else(|| format!("`xfail {}` directive (no reason given)", backend_name))
        })
}

/// Apply an xfail annotation only to a completed protocol verdict. Setup
/// failures, unsupported configurations, runtime skips, and shim crashes are
/// deliberately left alone: an implementation xfail must not hide a broken
/// harness or a process crash.
fn apply_xfail(
    result: &mut CaseResult,
    test_id: &str,
    backend: &str,
    reason: Option<String>,
    verdict_completed: bool,
) {
    let Some(reason) = reason else {
        return;
    };
    if !verdict_completed {
        return;
    }
    if result.failed > 0 {
        result.out = result.out.replace("[FAIL]", "[XFAIL]");
        result.xfailed += result.failed;
        result.failed = 0;
        result.out.push_str(&format!(
            "    expected failure on {}: {}\n",
            backend, reason
        ));
        result.xfail_log.push((test_id.to_string(), reason.clone()));
        for report in &mut result.machine {
            if report.status == "fail" {
                report.status = "xfail".into();
                report.reason = Some(reason.clone());
            }
        }
    } else if result.passed > 0 && result.skipped == 0 {
        result.out = result.out.replace("[PASS]", "[XPASS]");
        result.xpassed += result.passed;
        result.passed = 0;
        result.out.push_str(&format!(
            "    unexpected pass on {} (annotated xfail): {}\n",
            backend, reason
        ));
        for report in &mut result.machine {
            if report.status == "pass" {
                report.status = "xpass".into();
                report.reason = Some(reason.clone());
            }
        }
    }
}

/// A shim-local exception after the library has already emitted an alert does
/// not invalidate an alert observed and classified independently by plzn. It
/// remains a failure for close/reset/timeout outcomes, where the local error
/// could itself be why the connection disappeared.
fn shim_outcome_confirms_report(
    report: &plzn::runtime::RunReport,
    outcome: &plzn::shim::ShimOutcome,
) -> bool {
    outcome.success
        || (outcome.case == plzn::shim::ShimResultCase::LocalError
            && matches!(
                report.raw_outcome,
                plzn::runtime::ObservedOutcome::Alert { .. }
            ))
}

/// A multi-session test: ONE shim process serves every session
/// (resume_count = sessions - 1; it dials back per session), so a shim client
/// keeps the ticket it was issued in memory and a shim server sees the
/// resumption attempt. The session state plzn captured (ticket + PSK) crosses
/// sessions via run_sessions.
fn run_multi_case(ctx: &RunCtx, test_name: &str, programs: &[plzn::ir::Program]) -> CaseResult {
    use plzn::shim::{ShimConfig, ShimFactory};
    let backend = ctx.shim.name();
    let mut r = CaseResult::default();
    let mut cfg = match ShimConfig::for_program(
        &programs[0],
        Some(&ctx.cert_str),
        Some(&ctx.key_str),
        Some(backend),
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            return setup_failure_result(test_name, backend, format!("shim configuration: {e}"));
        }
    };
    // A cross-version session sequence deliberately negotiates a different
    // version on later connections. The wire driver asserts each session;
    // the shim's one process-wide self-check cannot name a single version.
    let cross_version = programs
        .iter()
        .any(|program| program.version != programs[0].version);
    if cross_version {
        cfg.expect.version = None;
        cfg.connection_versions = programs
            .iter()
            .map(|program| match (program.protocol, program.version) {
                (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls10) => 0x0301,
                (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls11) => 0x0302,
                (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls12) => 0x0303,
                (plzn::ir::Protocol::Tls, plzn::tls::record::TlsVersion::Tls13) => 0x0304,
                (plzn::ir::Protocol::Dtls, plzn::tls::record::TlsVersion::Tls12) => 0xfefd,
                (plzn::ir::Protocol::Dtls, plzn::tls::record::TlsVersion::Tls13) => 0xfefc,
                (plzn::ir::Protocol::Dtls, _) => {
                    unreachable!("DTLS has no TLS 1.0/1.1 IR version")
                }
            })
            .collect();
    }
    // Participation requirements are version-specific (the TLS 1.2 and TLS
    // 1.3 suite catalogues are disjoint). A process serving a cross-version
    // sequence needs the union, otherwise a shim such as GnuTLS configures
    // itself from only the initial session's cipher families.
    for program in &programs[1..] {
        let session_cfg = match ShimConfig::for_program(
            program,
            Some(&ctx.cert_str),
            Some(&ctx.key_str),
            Some(backend),
        ) {
            Ok(cfg) => cfg,
            Err(e) => {
                return setup_failure_result(
                    test_name,
                    backend,
                    format!("shim configuration: {e}"),
                );
            }
        };
        cfg.requires
            .any_suite
            .extend(session_cfg.requires.any_suite);
        cfg.requires
            .any_group
            .extend(session_cfg.requires.any_group);
        cfg.requires.session_id_resumption |= session_cfg.requires.session_id_resumption;
    }
    cfg.key_material = programs
        .iter()
        .enumerate()
        .flat_map(|(index, program)| plzn::shim::key_material_for_program(program, index as u32))
        .collect();
    cfg.requires.any_suite.sort_unstable();
    cfg.requires.any_suite.dedup();
    cfg.requires.any_group.sort_unstable();
    cfg.requires.any_group.dedup();
    // One config serves every connection of the shim: expect a clean handshake
    // only when every session does, else let the shim accept either outcome
    // and leave the verdict to the runner. T5: a session's per-backend
    // `expect ... if <backend>` override counts too.
    let all_ok = programs.iter().all(|p| {
        let effective = p
            .expect_overrides
            .iter()
            .find(|(b, _)| b.eq_ignore_ascii_case(backend))
            .map(|(_, e)| e)
            .unwrap_or(&p.expect);
        matches!(effective, plzn::ir::Expectation::Ok)
    });
    if !all_ok {
        cfg.expect.handshake_error = None;
        cfg.expect.handshake_abandoned = true;
    }
    // The single shim configuration covers every connection. A later session
    // may intentionally stop once it has observed the resumption decision or
    // EncryptedExtensions, even when the initial ticket-issuing session ran a
    // complete handshake.
    if programs
        .iter()
        .any(|p| !plzn::shim::program_completes_handshake(p))
    {
        cfg.expect.handshake_abandoned = true;
        cfg.expect.version = None;
    }
    // One shim process serves the full session sequence. EarlyData appears
    // only in the resumed program, so aggregate its per-connection intent into
    // the single config; shims apply it only after they have a cached session.
    cfg.early_data_send = programs
        .iter()
        .flat_map(|p| p.steps.iter())
        .find_map(|s| match s {
            plzn::ir::Step::RecvEarlyData { size, .. } => {
                Some(size.unwrap_or(plzn::app_data::DEFAULT_SIZE) as u32)
            }
            _ => None,
        })
        .unwrap_or(0);
    cfg.early_data_expect = programs
        .iter()
        .flat_map(|p| p.steps.iter())
        .find_map(|s| match s {
            plzn::ir::Step::SendEarlyData { size, .. } => Some(*size as u32),
            _ => None,
        })
        .unwrap_or(0);
    if cfg.early_data_send > 0 {
        cfg.expect_early_data_accepted = Some(programs.iter().any(|p| {
            p.send_extension_configurations().any(|entry| {
                entry.message == plzn::ir::MessageKind::EncryptedExtensions
                    && entry.deltas.iter().any(|delta| {
                        matches!(
                            delta,
                            plzn::ir::ExtDeltaOp::Add {
                                wire_type: 0x002a,
                                ..
                            }
                        )
                    })
            })
        }));
    } else if cfg.early_data_expect > 0 {
        // plzn is the 0-RTT client here. A matcher on the server's
        // EncryptedExtensions states whether the test expects acceptance;
        // without one, preserve the historical accepted-by-default behavior.
        cfg.expect_early_data_accepted = Some(
            programs
                .iter()
                .flat_map(|p| p.receive_configurations())
                .find_map(|(message, fields)| {
                    if message != plzn::ir::MessageKind::EncryptedExtensions {
                        return None;
                    }
                    fields.iter().find_map(|field| {
                        let is_early_data =
                            matches!(field.value, plzn::ir::FieldValue::U16(0x002a));
                        match (field.field.as_str(), is_early_data) {
                            ("has_ext", true) => Some(true),
                            ("lacks_ext", true) => Some(false),
                            _ => None,
                        }
                    })
                })
                .unwrap_or(true),
        );
    }
    cfg.connection_early_data = programs
        .iter()
        .map(|program| {
            use plzn::ir::{ExtDeltaOp, FieldValue, MessageKind, Step};
            let send = program
                .steps
                .iter()
                .find_map(|step| match step {
                    Step::RecvEarlyData { size, .. } => {
                        Some(size.unwrap_or(plzn::app_data::DEFAULT_SIZE) as u32)
                    }
                    _ => None,
                })
                .unwrap_or(0);
            let expect = program
                .steps
                .iter()
                .find_map(|step| match step {
                    Step::SendEarlyData { size, .. } => Some(*size as u32),
                    _ => None,
                })
                .unwrap_or(0);
            let accepted = if send > 0 {
                Some(program.send_extension_configurations().any(|entry| {
                    entry.message == MessageKind::EncryptedExtensions
                        && entry.deltas.iter().any(|delta| {
                            matches!(
                                delta,
                                ExtDeltaOp::Add {
                                    wire_type: 0x002a,
                                    ..
                                }
                            )
                        })
                }))
            } else if expect > 0 {
                Some(
                    program
                        .receive_configurations()
                        .filter(|(kind, _)| *kind == MessageKind::EncryptedExtensions)
                        .flat_map(|(_, fields)| fields)
                        .find_map(|field| {
                            if !matches!(field.value, FieldValue::U16(0x002a)) {
                                return None;
                            }
                            match field.field.as_str() {
                                "has_ext" => Some(true),
                                "lacks_ext" => Some(false),
                                _ => None,
                            }
                        })
                        .unwrap_or(true),
                )
            } else {
                None
            };
            plzn::shim::ConnectionEarlyData {
                send,
                expect,
                accepted,
            }
        })
        .collect();
    let factory = match ShimFactory::from_spec_multi(ctx.shim.clone(), cfg, programs.len() as u32) {
        Ok(f) => f,
        Err(e) => {
            return setup_failure_result(test_name, backend, format!("shim spawn setup: {e}"));
        }
    };
    let seed = test_seed_from_id(&programs[0].test_id);
    let reports = plzn::runtime::run_sessions(programs, &factory, seed, None);
    let shim_outcome = factory.wait_shim();
    if let Ok(o) = &shim_outcome {
        r.err.push_str(&o.stderr);
        r.out.push_str(&o.stdout);
        if o.is_unsupported_config() && factory.connected_count() == 0 {
            let why = o
                .detail
                .clone()
                .unwrap_or_else(|| "cannot apply this configuration".into());
            let skip = skip_result(test_name, why, backend, true, programs.first());
            r.out.push_str(&skip.out);
            r.total = 1;
            r.skipped = 1;
            r.skip_log = skip.skip_log;
            r.machine = skip.machine;
            if let Some(record) = r.machine.last_mut() {
                record.shim = Some(MachineShimOutcome::from_result(&shim_outcome));
            }
            return r;
        }
    }
    let shim_ok = shim_outcome
        .as_ref()
        .is_ok_and(|outcome| shim_outcome_confirms_report(&reports[reports.len() - 1], outcome));
    let crashed = shim_outcome.as_ref().map(|o| o.is_crash()).unwrap_or(false);
    for (i, report) in reports.iter().enumerate() {
        r.total += 1;
        let runner_ok = report.status.is_pass();
        // The shim's single verdict covers the whole run; charge it to the
        // last session so the per-session lines stay honest.
        let last = i + 1 == reports.len();
        let this_ok = runner_ok && (!last || (shim_ok && !crashed));
        let mut rendered = if ctx.verbose || !this_ok {
            report.display_verbose()
        } else {
            format!("{}\n", report.display_compact())
        };
        if runner_ok && !this_ok {
            rendered = rendered.replacen("[PASS]", "[FAIL]", 1);
        }
        r.out.push_str(&rendered);
        if last && !shim_ok {
            if let Ok(ref o) = shim_outcome {
                r.out.push_str(&shim_verdict_lines(test_name, backend, o));
            }
        }
        if report.status.is_skipped() {
            r.skipped += 1;
        } else if this_ok {
            r.passed += 1;
        } else {
            r.failed += 1;
        }
        let status = if report.status.is_skipped() {
            "skip"
        } else if this_ok {
            "pass"
        } else if last && crashed {
            "crash"
        } else {
            "fail"
        };
        let mut machine = MachineRunRecord::from_report(report, backend, status);
        machine.attach_program(&programs[i]);
        r.machine.push(machine);
    }
    if let Some(record) = r.machine.last_mut() {
        record.shim = Some(MachineShimOutcome::from_result(&shim_outcome));
    }
    for (program, report) in programs.iter().zip(&reports) {
        if let Some(group) = &program.repeat_group {
            r.captures.push((
                group.clone(),
                program.cross_asserts.clone(),
                program.test_id.clone(),
                report.captures.clone(),
            ));
        }
    }
    apply_xfail(
        &mut r,
        test_name,
        backend,
        xfail_reason(&programs[0], backend),
        reports.iter().all(|report| report.xfail_eligible)
            && shim_outcome.as_ref().is_ok_and(|outcome| {
                !matches!(
                    outcome.case,
                    plzn::shim::ShimResultCase::LocalError
                        | plzn::shim::ShimResultCase::UnsupportedConfig
                        | plzn::shim::ShimResultCase::Crashed(_)
                        | plzn::shim::ShimResultCase::Unknown(_)
                ) && (outcome.case != plzn::shim::ShimResultCase::IoError
                    || reports
                        .iter()
                        .any(|report| !report.status.is_pass() && report.xfail_eligible))
            }),
    );
    r.breaker_event = Some(crashed);
    r
}

fn run_single_case(ctx: &RunCtx, program: &plzn::ir::Program) -> CaseResult {
    use plzn::shim::{ShimConfig, ShimFactory};
    let backend = ctx.shim.name();
    let mut r = CaseResult {
        total: 1,
        ..Default::default()
    };
    let cfg = ShimConfig::for_program(
        program,
        Some(&ctx.cert_str),
        Some(&ctx.key_str),
        Some(backend),
    );
    let factory = match cfg.and_then(|cfg| ShimFactory::from_spec(ctx.shim.clone(), cfg)) {
        Ok(f) => f,
        Err(e) => {
            return setup_failure_result(
                &program.test_id,
                backend,
                format!("shim spawn setup: {e}"),
            );
        }
    };
    let seed = test_seed_from_id(&program.test_id);
    let report = plzn::runtime::run(program, &factory, seed, None);
    let shim_outcome = factory.wait_shim();
    if let Ok(o) = &shim_outcome {
        r.err.push_str(&o.stderr);
        r.out.push_str(&o.stdout);
        // The backend cannot apply a `uut` knob (or the protocol): the shim
        // said so before dialing, so nothing was tested. SKIP with the shim's
        // reason rather than fail -- or, worse, pass.
        if o.is_unsupported_config() && factory.connected_count() == 0 {
            let why = o
                .detail
                .clone()
                .unwrap_or_else(|| "cannot apply this configuration".into());
            let skip = skip_result(&program.test_id, why, backend, true, Some(program));
            r.out.push_str(&skip.out);
            r.skipped = 1;
            r.skip_log = skip.skip_log;
            r.machine = skip.machine;
            if let Some(record) = r.machine.last_mut() {
                record.shim = Some(MachineShimOutcome::from_result(&shim_outcome));
            }
            return r;
        }
    }
    // A runtime SKIP (e.g. the driver has no crypto for the offered group) is
    // not a failure; count it separately and do not hold the shim's outcome
    // against it since the protocol never ran.
    if let plzn::runtime::RunStatus::Skipped(reason) = &report.status {
        r.out.push_str(&format!("{}\n", report.display_compact()));
        r.skip_log.push((program.test_id.clone(), reason.clone()));
        r.skipped = 1;
        let mut machine = MachineRunRecord::from_report(&report, backend, "skip");
        machine.attach_program(program);
        machine.shim = Some(MachineShimOutcome::from_result(&shim_outcome));
        r.machine.push(machine);
        return r;
    }
    let runner_ok = report.status.is_pass();
    let shim_ok = shim_outcome
        .as_ref()
        .is_ok_and(|outcome| shim_outcome_confirms_report(&report, outcome));
    let crashed = shim_outcome.as_ref().map(|o| o.is_crash()).unwrap_or(false);
    // The runner's verdict is only half the story: the shim self-checks its
    // own expectations. A case passes only when both agree, so a runner PASS
    // the shim contradicts is printed as a FAIL rather than a PASS with a
    // stray stderr note.
    let both_ok = runner_ok && shim_ok && !crashed;
    let mut rendered = if ctx.verbose || !both_ok {
        report.display_verbose()
    } else {
        format!("{}\n", report.display_compact())
    };
    if runner_ok && !shim_ok && !crashed {
        rendered = rendered.replacen("[PASS]", "[FAIL]", 1);
    }
    r.out.push_str(&rendered);
    if !shim_ok {
        if let Ok(ref o) = shim_outcome {
            r.out
                .push_str(&shim_verdict_lines(&program.test_id, backend, o));
        }
    }
    if runner_ok && shim_ok {
        r.passed = 1;
    } else {
        r.failed = 1;
    }
    let status = if both_ok {
        "pass"
    } else if crashed {
        "crash"
    } else {
        "fail"
    };
    let mut machine = MachineRunRecord::from_report(&report, backend, status);
    machine.attach_program(program);
    machine.shim = Some(MachineShimOutcome::from_result(&shim_outcome));
    r.machine.push(machine);
    apply_xfail(
        &mut r,
        &program.test_id,
        backend,
        xfail_reason(program, backend),
        report.xfail_eligible
            && shim_outcome.as_ref().is_ok_and(|outcome| {
                !matches!(
                    outcome.case,
                    plzn::shim::ShimResultCase::LocalError
                        | plzn::shim::ShimResultCase::UnsupportedConfig
                        | plzn::shim::ShimResultCase::Crashed(_)
                        | plzn::shim::ShimResultCase::Unknown(_)
                ) && (outcome.case != plzn::shim::ShimResultCase::IoError
                    || (!report.status.is_pass() && report.xfail_eligible))
            }),
    );
    // T1: what this run captured for the test's cross-run asserts
    // (`repeat N` + `assert unique $x`).
    if let Some(group) = &program.repeat_group {
        r.captures.push((
            group.clone(),
            program.cross_asserts.clone(),
            program.test_id.clone(),
            report.captures.clone(),
        ));
    }
    r.breaker_event = Some(crashed);
    r
}

/// Run every file against a config-file shim backend. Each case spawns its
/// own shim process (or one per multi-session test) and the cases run on a
/// pool of `jobs` workers; results are printed in input order. A case passes
/// only when both the runner's expectation and the shim's self-checked
/// expectations pass.
fn run_shim_backend(
    shim: plzn::shim::ShimSpec,
    expectations: plzn::shim::ShimExpectationSet,
    files: &[String],
    verbose: bool,
    cert_type: Option<&str>,
    jobs: usize,
    json: bool,
) -> ExitCode {
    let backend = shim.name().to_string();
    let shim_path = absolute_path(shim.binary());
    if !json {
        if expectations.is_empty() {
            eprintln!("[shim] {} ({})", backend, shim.binary().display());
        } else {
            eprintln!(
                "[shim] {} ({}, {} expectation overrides)",
                backend,
                shim.binary().display(),
                expectations.len()
            );
        }
    }

    // `--cert` names what an explicit `chain: [default]` resolves to in this
    // run. plzn's choice is P-256: the cheapest signature for plzn and for
    // every library (RSA signing was half of plzn's CPU). Tests that depend on
    // a certificate type name it directly.
    let key_type = match cert_type {
        None | Some("ecdsa") | Some("ecdsa-p256") | Some("p256") | Some("default") => {
            plzn::server::certs::KeyType::EcdsaP256
        }
        Some("rsa") | Some("rsa-2048") => plzn::server::certs::KeyType::Rsa2048,
        Some("ecdsa-p384") | Some("p384") => plzn::server::certs::KeyType::EcdsaP384,
        // T3: file-backed bundles (shims/testdata/gen_client_ee.sh).
        Some("ecdsa-p521") | Some("p521") => plzn::server::certs::KeyType::EcdsaP521,
        Some("rsa-pss") => plzn::server::certs::KeyType::RsaPss,
        Some("ed25519") => plzn::server::certs::KeyType::Ed25519,
        Some(other) => {
            eprintln!(
                "plzn run: unknown --cert {:?} (rsa, ecdsa, ecdsa-p384, ecdsa-p521, ed25519, rsa-pss)",
                other
            );
            return ExitCode::from(2);
        }
    };
    // A: chains are generated per key type on first use; `--cert` names what
    // `chain: [default]` resolves to in this run.
    let cert_dir = std::env::temp_dir().join(format!("plzn-shim-certs-{}", std::process::id()));
    let mut store = ChainStore {
        dir: cert_dir.clone(),
        default: key_type,
        cache: std::collections::HashMap::new(),
        client_cache: std::collections::HashMap::new(),
    };
    let (default_files, _) = match store.get(key_type) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("plzn run: cert generation failed: {}", e);
            return ExitCode::from(2);
        }
    };
    let ctx = RunCtx {
        shim,
        cert_str: default_files.cert_file.clone(),
        key_str: default_files.key_file.clone(),
        verbose,
    };
    let suite_start = std::time::Instant::now();

    // Phase 1 (serial, cheap): parse, check and lower every file into work
    // items, deciding what needs no shim at all. Errors keep their place in
    // the output as pre-decided results.
    let mut items: Vec<Item> = Vec::new();
    for path in files {
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                let mut result =
                    setup_failure_result(path, &backend, format!("cannot read source: {e}"));
                result.err = format!("plzn run: cannot read {}: {}\n", path, e);
                items.push(Item::Done(result));
                continue;
            }
        };
        let diag_result = |errs: Vec<String>| {
            let rendered = errs.concat();
            let mut result =
                setup_failure_result(path, &backend, format!("source diagnostics:\n{rendered}"));
            result.err = rendered;
            Item::Done(result)
        };
        let tokens = match plzn::lex::lex(&source) {
            Ok(t) => t,
            Err(errs) => {
                items.push(diag_result(
                    errs.into_iter()
                        .map(|e| format!("{}\n", e.into_diag(path, &source)))
                        .collect(),
                ));
                continue;
            }
        };
        let file = match plzn::parse::parse(&tokens) {
            Ok(f) => f,
            Err(errs) => {
                items.push(diag_result(
                    errs.into_iter()
                        .map(|e| format!("{}\n", e.into_diag(path, &source)))
                        .collect(),
                ));
                continue;
            }
        };
        let check_errs = plzn::check::check(&file);
        if !check_errs.is_empty() {
            items.push(diag_result(
                check_errs
                    .into_iter()
                    .map(|e| format!("{}\n", e.into_diag(path, &source)))
                    .collect(),
            ));
            continue;
        }
        for test in &file.tests {
            let programs = match plzn::lower::lower(test) {
                Ok(p) => p,
                Err(errs) => {
                    items.push(diag_result(
                        errs.into_iter()
                            .map(|e| format!("{}\n", e.into_diag(path, &source)))
                            .collect(),
                    ));
                    continue;
                }
            };
            if programs.iter().any(|p| p.session_name.is_some()) {
                let sessions_per_case = test.sessions.len();
                for mut case_programs in programs
                    .chunks(sessions_per_case)
                    .map(|programs| programs.to_vec())
                {
                    let case_name = case_programs[0]
                        .test_id
                        .rsplit_once(':')
                        .map(|(name, _)| name)
                        .unwrap_or(&test.name.value)
                        .to_string();
                    for program in &mut case_programs {
                        expectations.apply(program, &backend);
                    }
                    if let Some((_, reason)) = case_programs[0]
                        .skip_backends
                        .iter()
                        .find(|(b, _)| b.eq_ignore_ascii_case(&backend))
                    {
                        let why = reason.clone().unwrap_or_else(|| {
                            format!("`skip {}` directive (no reason given)", backend)
                        });
                        items.push(Item::Done(skip_result(
                            &case_name,
                            why,
                            &backend,
                            false,
                            case_programs.first(),
                        )));
                        continue;
                    }
                    let mut failed_chain: Option<String> = None;
                    for program in case_programs.iter_mut() {
                        if let Err(e) = resolve_program_chains(program, &mut store) {
                            failed_chain = Some(e);
                            break;
                        }
                    }
                    if let Some(e) = failed_chain {
                        items.push(Item::Done(setup_failure_result(
                            &case_name,
                            &backend,
                            format!("chain setup: {e}"),
                        )));
                        continue;
                    }
                    items.push(Item::Multi {
                        test_name: case_name,
                        programs: case_programs,
                    });
                }
                continue;
            }
            for mut program in programs {
                expectations.apply(&mut program, &backend);
                // BoGo-style per-backend skip: a test can declare `skip <backend>`
                // for a library it does not apply to (e.g. rustls has no DHE/CBC).
                if let Some((_, reason)) = program
                    .skip_backends
                    .iter()
                    .find(|(b, _)| b.eq_ignore_ascii_case(&backend))
                {
                    let why = reason.clone().unwrap_or_else(|| {
                        format!("`skip {}` directive (no reason given)", backend)
                    });
                    items.push(Item::Done(skip_result(
                        &program.test_id,
                        why,
                        &backend,
                        false,
                        Some(&program),
                    )));
                    continue;
                }
                // A: the chains `chain:` / `client_chain:` name, for this run.
                if let Err(e) = resolve_program_chains(&mut program, &mut store) {
                    items.push(Item::Done(setup_failure_result(
                        &program.test_id,
                        &backend,
                        format!("chain setup: {e}"),
                    )));
                    continue;
                }
                items.push(Item::Single(Box::new(program)));
            }
        }
    }

    // Phase 2: run the shim-backed items on a worker pool and print every
    // result in input order as its turn comes, so a parallel run reads like
    // a serial one. One crash is a per-case result; a crash on every
    // consecutive case is a broken shim or environment, and the breaker stops
    // scheduling instead of printing the same crash hundreds of times.
    let (mut total, mut passed, mut failed, mut skipped, mut xfailed, mut xpassed) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut breaker = plzn::shim::CrashBreaker::from_env();
    // Every skipped case with its reason, printed after the summary (BoGo's
    // UNSUPPORTED report).
    let mut skip_log: Vec<(String, String)> = Vec::new();
    let mut xfail_log: Vec<(String, String)> = Vec::new();
    // T1: (repeat group) -> (its cross-run asserts, per-run captures).
    let mut cross_runs: CrossRuns = std::collections::BTreeMap::new();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let abort = std::sync::atomic::AtomicBool::new(false);
    // Set when the crash breaker trips (distinct from `abort`, which also
    // stops the pool at a normal end of the run).
    let tripped = std::sync::atomic::AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel::<(usize, CaseResult)>();
    let workers = jobs.max(1).min(items.len().max(1));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let (items, ctx, next, abort) = (&items, &ctx, &next, &abort);
            scope.spawn(move || {
                loop {
                    if abort.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= items.len() {
                        break;
                    }
                    let result = match &items[i] {
                        Item::Done(_) => continue,
                        Item::Multi {
                            test_name,
                            programs,
                        } => run_multi_case(ctx, test_name, programs),
                        Item::Single(program) => run_single_case(ctx, program),
                    };
                    if tx.send((i, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut pending: std::collections::HashMap<usize, CaseResult> =
            std::collections::HashMap::new();
        let mut absorb = |r: &CaseResult| {
            if json {
                for record in &r.machine {
                    emit_json("run", record);
                }
            } else {
                eprint!("{}", r.err);
                print!("{}", r.out);
            }
            total += r.total;
            passed += r.passed;
            failed += r.failed;
            skipped += r.skipped;
            xfailed += r.xfailed;
            xpassed += r.xpassed;
            skip_log.extend(r.skip_log.iter().cloned());
            xfail_log.extend(r.xfail_log.iter().cloned());
            for (group, asserts, id, caps) in &r.captures {
                let entry = cross_runs
                    .entry(group.clone())
                    .or_insert_with(|| (asserts.clone(), Vec::new()));
                entry.1.push((id.clone(), caps.clone()));
            }
            if let Some(crashed) = r.breaker_event {
                if breaker.record(crashed) {
                    tripped.store(true, std::sync::atomic::Ordering::Relaxed);
                    abort.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        };
        for (i, item) in items.iter().enumerate() {
            if tripped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            if let Item::Done(r) = item {
                absorb(r);
                continue;
            }
            let result = loop {
                if let Some(r) = pending.remove(&i) {
                    break Some(r);
                }
                match rx.recv() {
                    Ok((j, r)) if j == i => break Some(r),
                    Ok((j, r)) => {
                        pending.insert(j, r);
                    }
                    Err(_) => break None,
                }
            };
            match result {
                Some(r) => absorb(&r),
                None => break,
            }
        }
        // Stop the pool: results still in flight are dropped unprinted.
        abort.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(rx);
    });
    let aborted = tripped.load(std::sync::atomic::Ordering::Relaxed);

    let (assert_total, assert_passed, assert_failed) = if json {
        let mut counts = (0usize, 0usize, 0usize);
        for verdict in cross_run_verdicts(&cross_runs) {
            counts.0 += 1;
            let status = if verdict.failure.is_none() {
                counts.1 += 1;
                "pass"
            } else {
                counts.2 += 1;
                "fail"
            };
            let mut record = MachineRunRecord::synthetic(
                &verdict.group,
                &backend,
                status,
                "cross_run_assertion",
                None,
                verdict.failure,
            );
            record.expected = Some(verdict.label);
            record.observed = Some(format!("{} runs", verdict.runs));
            emit_json("run", &record);
        }
        counts
    } else {
        evaluate_cross_runs(&cross_runs)
    };
    total += assert_total;
    passed += assert_passed;
    failed += assert_failed;

    let _ = std::fs::remove_dir_all(&cert_dir);

    if json {
        emit_json(
            "run",
            &MachineRunSummary {
                schema_version: 1,
                record_type: "summary",
                backend: backend.clone(),
                shim_path,
                total,
                passed,
                failed,
                skipped,
                xfailed,
                xpassed,
                duration_ns: duration_ns(suite_start.elapsed()),
                aborted,
            },
        );
    } else if skipped > 0 || xfailed > 0 || xpassed > 0 {
        println!(
            "--- {} tests, {} passed, {} failed, {} skipped, {} xfailed, {} xpassed ({:.1?}) [{}] ---",
            total,
            passed,
            failed,
            skipped,
            xfailed,
            xpassed,
            suite_start.elapsed(),
            backend
        );
    } else {
        println!(
            "--- {} tests, {} passed, {} failed ({:.1?}) [{}] ---",
            total,
            passed,
            failed,
            suite_start.elapsed(),
            backend
        );
    }
    if !json && !skip_log.is_empty() {
        println!("--- skipped on {} ({}) ---", backend, skip_log.len());
        for (id, why) in &skip_log {
            println!("    {} — {}", id, why);
        }
    }
    if !json && !xfail_log.is_empty() {
        println!("--- xfailed on {} ({}) ---", backend, xfail_log.len());
        for (id, why) in &xfail_log {
            println!("    {} — {}", id, why);
        }
    }
    if aborted {
        if !json {
            eprintln!(
                "plzn run: aborting: the {} shim crashed on {} consecutive cases.\n\
             A crash on every case is the shape of a broken shim binary or environment\n\
             rather than a per-test finding: the library was rebuilt or upgraded after the\n\
             shim was linked (run `make -C shims`), a shared library is missing, or the\n\
             shim itself is broken. A crash that one test provokes shows up as a single\n\
             [CRASH] line instead. PLZN_CRASH_LIMIT=N raises the threshold; 0 disables it.",
                backend,
                breaker.streak()
            );
        }
        return ExitCode::from(2);
    }
    if failed > 0 || xpassed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

fn collect_plzn_files(dir: &std::path::Path, out: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_plzn_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "plzn") {
            out.push(path.to_string_lossy().into_owned());
        }
    }
}

fn expand_plzn_files(paths: Vec<String>) -> Vec<String> {
    let mut files = Vec::new();
    for path in paths {
        let path = std::path::Path::new(&path);
        if path.is_dir() {
            collect_plzn_files(path, &mut files);
        } else {
            files.push(path.to_string_lossy().into_owned());
        }
    }
    files.sort();
    files
}

fn test_seed_from_id(test_id: &str) -> [u8; 32] {
    let digest = plzn::tls::crypto::hash(plzn::tls::crypto::HashAlg::Sha256, test_id.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// True when plzn plays the client in a client-authentication flow (the
/// expanded preset has it send a Certificate in answer to the server's
/// CertificateRequest), so the runner must hand it a cert to present.
fn program_presents_client_cert(program: &plzn::ir::Program) -> bool {
    use plzn::ir::{HandshakeStep, MessageKind, Step, Subject};
    program.subject == Subject::Server
        && (program.steps.iter().any(|s| match s {
            Step::HandshakeSteps { steps, .. } => {
                steps.contains(&HandshakeStep::Send(MessageKind::Certificate))
                    // T6: the RFC 8879 form of the client's Certificate.
                    || steps.contains(&HandshakeStep::Send(MessageKind::CompressedCertificate))
            }
            _ => false,
        })
            // T5: a renegotiation after the shim server's HelloRequest may
            // demand a client certificate the initial handshake did not.
            || program
                .uut
                .as_ref()
                .is_some_and(|u| u.require_client_cert_on_renegotiation))
}

/// `plzn names`: the name tables the named-constant lint enforces.
fn names_cmd() -> ExitCode {
    use plzn::schema::{NameDomain, domain_names};
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for d in [
        NameDomain::Suite,
        NameDomain::Group,
        NameDomain::Sigalg,
        NameDomain::Extension,
        NameDomain::CertType,
    ] {
        // A closed pipe (`plzn names | head`) ends the listing, not the process.
        if writeln!(out, "# {}", d.label()).is_err() {
            return ExitCode::from(0);
        }
        for (name, wire) in domain_names(d) {
            if writeln!(out, "{:<44} 0x{:04x}", name, wire).is_err() {
                return ExitCode::from(0);
            }
        }
        let _ = writeln!(out);
    }
    ExitCode::from(0)
}

#[cfg(test)]
mod chain_resolution_tests {
    use super::{ChainStore, resolve_program_chains};
    use plzn::ir::{Program, SuiteFilter, filter_suites_dtls, filter_suites_tls12};
    use plzn::server::certs::KeyType;

    fn program(role: &str, version: &str, chain: &str, capabilities: &str) -> Program {
        let source = format!(
            "plzn tls \"chains\" {{\nchain: [{chain}]\nuut {role} {{ versions: [{version}] }}\npeer {{ capabilities: [{capabilities}] }}\nflow {{ close }}\nexpect alert fatal/handshake_failure\n}}"
        );
        assert!(plzn::lint("chains", &source).is_empty());
        let file = plzn::parse::parse(&plzn::lex::lex(&source).unwrap()).unwrap();
        plzn::lower::lower(&file.tests[0]).unwrap().remove(0)
    }

    #[test]
    fn no_server_chain_does_not_empty_the_client_offer() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ChainStore {
            dir: dir.path().into(),
            default: KeyType::EcdsaP256,
            cache: Default::default(),
            client_cache: Default::default(),
        };
        for version in ["tls12", "dtls12"] {
            for capabilities in ["", "ecdhe"] {
                let mut p = program("server", version, "", capabilities);
                resolve_program_chains(&mut p, &mut store).unwrap();
                assert!(p.shim_server_chains.is_empty());
                assert!(
                    !p.suite_filters
                        .iter()
                        .any(|f| matches!(f, SuiteFilter::ChainKeys(_)))
                );
                assert!(!filter_suites_tls12(&p.suite_filters, false).is_empty());
                assert!(!filter_suites_dtls(&p.suite_filters, false).is_empty());
            }
            let mut p = program("client", version, "", "ecdhe");
            resolve_program_chains(&mut p, &mut store).unwrap();
            assert!(p.suite_filters.contains(&SuiteFilter::ChainKeys(0)));
            assert!(filter_suites_tls12(&p.suite_filters, false).is_empty());
        }
    }

    #[test]
    fn resolved_default_chain_must_fit_the_requested_cipher_family() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ChainStore {
            dir: dir.path().into(),
            default: KeyType::Rsa2048,
            cache: Default::default(),
            client_cache: Default::default(),
        };
        for role in ["client", "server"] {
            for version in ["tls12", "dtls12"] {
                let mut p = program(role, version, "default", "ecdhe, ccm");
                assert!(
                    resolve_program_chains(&mut p, &mut store)
                        .unwrap_err()
                        .contains("leave no supported suites")
                );
                let mut p = program(role, version, "ecdsa_p256", "ecdhe, ccm");
                resolve_program_chains(&mut p, &mut store).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod xfail_tests {
    #[test]
    fn uniqueness_requires_every_run_and_rejects_duplicates() {
        use plzn::ir::CrossAssert;
        for (values, expected) in [
            (vec![Some(1), Some(2)], (1, 1, 0)),
            (vec![Some(1), Some(1)], (1, 0, 1)),
            (vec![Some(1), Some(2), None], (1, 0, 1)),
        ] {
            let runs = values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    (
                        format!("run{index}"),
                        value
                            .map(|v| vec![("random".to_string(), vec![v])])
                            .unwrap_or_default(),
                    )
                })
                .collect();
            let groups = [(
                "test:session".to_string(),
                (vec![CrossAssert::Unique(vec!["random".into()])], runs),
            )]
            .into_iter()
            .collect();
            assert_eq!(super::evaluate_cross_runs(&groups), expected);
        }
    }
    use super::{CaseResult, MachineRunRecord, apply_xfail};

    #[test]
    fn expected_failure_is_successful_xfail() {
        let mut result = CaseResult {
            out: "[FAIL] test/case — mock\n".into(),
            total: 1,
            failed: 1,
            machine: vec![MachineRunRecord::synthetic(
                "test/case",
                "mock",
                "fail",
                "test",
                None,
                Some("mismatch".into()),
            )],
            ..Default::default()
        };
        apply_xfail(
            &mut result,
            "test/case",
            "mock",
            Some("known defect".into()),
            true,
        );
        assert_eq!(result.failed, 0);
        assert_eq!(result.xfailed, 1);
        assert!(result.out.contains("[XFAIL] test/case"));
        assert!(
            result
                .out
                .contains("expected failure on mock: known defect")
        );
        assert_eq!(result.machine[0].status, "xfail");
        assert_eq!(result.machine[0].reason.as_deref(), Some("known defect"));
    }

    #[test]
    fn unexpected_pass_is_a_failing_xpass() {
        let mut result = CaseResult {
            out: "[PASS] test/case — mock\n".into(),
            total: 1,
            passed: 1,
            ..Default::default()
        };
        apply_xfail(
            &mut result,
            "test/case",
            "mock",
            Some("known defect".into()),
            true,
        );
        assert_eq!(result.passed, 0);
        assert_eq!(result.xpassed, 1);
        assert!(result.out.contains("[XPASS] test/case"));
    }

    #[test]
    fn xfail_does_not_hide_an_incomplete_verdict() {
        let mut result = CaseResult {
            out: "[FAIL] test/case — shim crashed\n".into(),
            total: 1,
            failed: 1,
            ..Default::default()
        };
        apply_xfail(
            &mut result,
            "test/case",
            "mock",
            Some("known defect".into()),
            false,
        );
        assert_eq!(result.failed, 1);
        assert_eq!(result.xfailed, 0);
        assert!(result.out.contains("[FAIL]"));
    }
}

#[cfg(test)]
mod machine_report_tests {
    use std::time::Duration;

    use super::MachineRunRecord;
    use plzn::runtime::{ObservedOutcome, RunError, RunReport, RunStatus, StepReport, StepStatus};

    #[test]
    fn case_json_keeps_structured_wire_and_step_details() {
        let report = RunReport {
            test_id: "report/structured".into(),
            status: RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "ok".into(),
                observed: "fatal illegal_parameter".into(),
                at_step: Some(2),
            }),
            steps: vec![StepReport {
                index: 2,
                description: "recv Finished".into(),
                status: StepStatus::Failed("fatal illegal_parameter".into()),
                duration: Duration::from_micros(7),
            }],
            total_duration: Duration::from_micros(11),
            negotiated_cipher_suite: Some(0x1301),
            peer_description: "127.0.0.1:443".into(),
            expected: "ok".into(),
            observed: "fatal illegal_parameter".into(),
            raw_outcome: ObservedOutcome::Alert {
                level: 2,
                description: 47,
                at_step: 2,
            },
            captures: vec![("random".into(), vec![0x01, 0xab])],
            xfail_eligible: true,
        };

        let value =
            serde_json::to_value(MachineRunRecord::from_report(&report, "mock", "fail")).unwrap();
        assert_eq!(value["type"], "case");
        assert_eq!(value["outcome"]["kind"], "alert");
        assert_eq!(value["outcome"]["description"], 47);
        assert_eq!(value["negotiated_cipher_suite"]["wire"], 0x1301);
        assert_eq!(
            value["negotiated_cipher_suite"]["name"],
            "AES_128_GCM_SHA256"
        );
        assert_eq!(value["steps"][0]["duration_ns"], 7_000);
        assert_eq!(value["steps"][0]["status"], "failed");
        assert_eq!(value["captures"][0]["value_hex"], "01ab");
    }
}

#[cfg(test)]
mod differential_tests {
    use super::{
        DiffObservation, differential_score, mutation_expectation_violated, observation_vector,
        observations_diverge,
    };
    use plzn::discovery::{MutationCandidate, MutationValidity};
    use plzn::runtime::ObservedOutcome;

    fn observation(
        backend: &str,
        fingerprint: &str,
        outcome: ObservedOutcome,
        shim_case: &str,
    ) -> DiffObservation {
        DiffObservation {
            backend: backend.into(),
            shim_path: format!("/tmp/{backend}-shim"),
            fingerprint: fingerprint.into(),
            outcome,
            negotiated_cipher_suite: None,
            shim_case: shim_case.into(),
            shim_exit_code: Some(0),
            shim_detail: None,
        }
    }

    #[test]
    fn accept_reject_split_has_high_priority() {
        let observations = vec![
            observation("a", "success", ObservedOutcome::Success, "ok"),
            observation(
                "b",
                "alert:2:50@0",
                ObservedOutcome::Alert {
                    level: 2,
                    description: 50,
                    at_step: 0,
                },
                "handshake_failed",
            ),
        ];
        assert!(observations_diverge(&observations));
        assert_eq!(differential_score(None, &observations), 900);
    }

    #[test]
    fn preserving_mutation_rejection_is_an_expectation_violation() {
        let observations = vec![
            observation(
                "a",
                "alert:2:10@0",
                ObservedOutcome::Alert {
                    level: 2,
                    description: 10,
                    at_step: 0,
                },
                "handshake_failed",
            ),
            observation(
                "b",
                "alert:2:50@0",
                ObservedOutcome::Alert {
                    level: 2,
                    description: 50,
                    at_step: 0,
                },
                "handshake_failed",
            ),
        ];
        let mutation = MutationCandidate {
            id: "finished-fragment-1".into(),
            message: "Finished".into(),
            syntax: "fragment 1".into(),
            validity: MutationValidity::Preserving,
            expected: "accept",
        };
        assert!(mutation_expectation_violated(&mutation, &observations));
        assert_eq!(differential_score(Some(&mutation), &observations), 850);
    }

    #[test]
    fn consensus_acceptance_of_invalid_mutation_is_still_interesting() {
        let observations = vec![
            observation("a", "success", ObservedOutcome::Success, "ok"),
            observation("b", "success", ObservedOutcome::Success, "ok"),
        ];
        let mutation = MutationCandidate {
            id: "finished-length-plus-1".into(),
            message: "Finished".into(),
            syntax: "add[handshake.length] = 1".into(),
            validity: MutationValidity::Invalid,
            expected: "reject",
        };
        assert!(!observations_diverge(&observations));
        assert!(mutation_expectation_violated(&mutation, &observations));
        assert_eq!(differential_score(Some(&mutation), &observations), 850);
    }

    #[test]
    fn unsupported_backend_does_not_create_a_difference() {
        let observations = vec![
            observation(
                "a",
                "unsupported",
                ObservedOutcome::Skipped {
                    reason: "no feature".into(),
                },
                "unsupported_config",
            ),
            observation("b", "success", ObservedOutcome::Success, "ok"),
        ];
        assert!(!observations_diverge(&observations));
        assert_eq!(differential_score(None, &observations), 0);
    }

    #[test]
    fn observation_vector_is_stable_and_ordered() {
        let observations = vec![
            observation("openssl", "success", ObservedOutcome::Success, "ok"),
            observation(
                "rustls",
                "close@2",
                ObservedOutcome::Close { at_step: 2 },
                "io_error",
            ),
        ];
        assert_eq!(
            observation_vector(&observations),
            ["openssl=success", "rustls=close@2"]
        );
    }

    #[test]
    fn raw_alert_json_is_numeric_and_schema_tagged() {
        let value = serde_json::to_value(ObservedOutcome::Alert {
            level: 2,
            description: 47,
            at_step: 3,
        })
        .unwrap();
        assert_eq!(value["kind"], "alert");
        assert_eq!(value["description"], 47);
        assert_eq!(value["at_step"], 3);
    }
}
