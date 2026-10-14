//! Corpus-wide invariants that keep `suite/` an inventory of protocol scenarios
//! rather than a home for parser fixtures or repeated smoke tests.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

fn plzn_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read suite directory") {
        let path = entry.expect("read suite entry").path();
        if path.is_dir() {
            plzn_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "plzn") {
            out.push(path);
        }
    }
}

/// Ignore presentation-only differences while preserving every string byte and
/// every executable token. RFC references and comments document a scenario but
/// do not make two otherwise identical scenarios distinct coverage.
fn canonical_body(source: &str, span: plzn::ast::Span) -> String {
    let test = &source[span.start..span.end];
    let open = test.find('{').expect("test has opening brace");
    let close = test.rfind('}').expect("test has closing brace");
    let body = &test[open + 1..close];

    let mut without_comments = String::with_capacity(body.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut in_comment = false;
    for ch in body.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
                without_comments.push(ch);
            }
            continue;
        }
        if in_string {
            without_comments.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '#' {
            in_comment = true;
        } else {
            without_comments.push(ch);
            if ch == '"' {
                in_string = true;
            }
        }
    }

    let executable = without_comments
        .lines()
        .filter(|line| !line.trim_start().starts_with("rfc "))
        .collect::<Vec<_>>()
        .join("\n");

    let mut canonical = String::with_capacity(executable.len());
    in_string = false;
    escaped = false;
    for ch in executable.chars() {
        if in_string {
            canonical.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            canonical.push(ch);
        } else if !ch.is_whitespace() {
            canonical.push(ch);
        }
    }
    canonical
}

#[test]
fn suite_has_unique_ids_and_no_identical_scenarios() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suite");
    let mut paths = Vec::new();
    plzn_files(&root, &mut paths);
    paths.sort();

    let mut ids: HashMap<String, PathBuf> = HashMap::new();
    let mut scenarios: HashMap<String, (String, PathBuf)> = HashMap::new();
    let mut duplicate_ids = Vec::new();
    let mut duplicate_scenarios = Vec::new();

    for path in paths {
        let source = fs::read_to_string(&path).expect("read suite file");
        let tokens = plzn::lex::lex(&source).expect("lex suite file");
        let file = plzn::parse::parse(&tokens).expect("parse suite file");
        for test in file.tests {
            let id = test.name.value.clone();
            if let Some(old_path) = ids.insert(id.clone(), path.clone()) {
                duplicate_ids.push(format!(
                    "{id}: {} and {}",
                    old_path.display(),
                    path.display()
                ));
            }

            let body = canonical_body(&source, test.span);
            if let Some((old_id, old_path)) = scenarios.insert(body, (id.clone(), path.clone())) {
                duplicate_scenarios.push(format!(
                    "{old_id} ({}) == {id} ({})",
                    old_path.display(),
                    path.display()
                ));
            }
        }
    }

    assert!(
        duplicate_ids.is_empty(),
        "duplicate suite test ids:\n{}",
        duplicate_ids.join("\n")
    );
    assert!(
        duplicate_scenarios.is_empty(),
        "identical suite scenarios (comments, RFC references, formatting, and ids ignored):\n{}",
        duplicate_scenarios.join("\n")
    );
}

#[test]
fn suite_names_describe_behavior_in_canonical_namespaces() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suite");
    let mut paths = Vec::new();
    plzn_files(&root, &mut paths);

    let mut errors = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(&root)
            .expect("suite path below suite root");
        let directory = relative
            .components()
            .next()
            .expect("suite file has role directory")
            .as_os_str()
            .to_string_lossy();
        let expected_prefixes: &[&str] = match directory.as_ref() {
            "client" => &["client/"],
            "server" => &["server/"],
            "dtls" => &["dtls12/", "dtls13/"],
            other => {
                errors.push(format!(
                    "{}: unexpected suite role directory `{other}`",
                    relative.display()
                ));
                continue;
            }
        };

        let stem = path
            .file_stem()
            .expect("suite filename has stem")
            .to_string_lossy();
        let provenance_labels = ["tlsfuzzer", "bogo", "botan_msg", "ported"];
        let has_provenance_label = provenance_labels.iter().any(|label| {
            stem == *label
                || stem.starts_with(&format!("{label}_"))
                || stem.ends_with(&format!("_{label}"))
                || stem.contains(&format!("_{label}_"))
        });
        if has_provenance_label || stem.ends_with("_rustls") {
            errors.push(format!(
                "{}: filename encodes source provenance instead of wire behavior",
                relative.display()
            ));
        }
        if !stem
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            errors.push(format!(
                "{}: filename must use lowercase snake_case",
                relative.display()
            ));
        }

        let source = fs::read_to_string(&path).expect("read suite file");
        let tokens = plzn::lex::lex(&source).expect("lex suite file");
        let file = plzn::parse::parse(&tokens).expect("parse suite file");
        for test in file.tests {
            let id = &test.name.value;
            if !expected_prefixes
                .iter()
                .any(|prefix| id.starts_with(prefix))
            {
                errors.push(format!(
                    "{}: test id `{id}` must start with one of {}",
                    relative.display(),
                    expected_prefixes.join(", ")
                ));
            }
            if id
                .split(['/', '-', '_'])
                .any(|part| matches!(part, "tlsfuzzer" | "bogo" | "botan" | "ported"))
            {
                errors.push(format!(
                    "{}: test id `{id}` encodes source provenance instead of wire behavior",
                    relative.display()
                ));
            }
        }
    }

    assert!(
        errors.is_empty(),
        "suite naming invariants failed:\n{}",
        errors.join("\n")
    );
}

#[test]
fn suite_expectations_use_precise_outcomes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suite");
    let mut paths = Vec::new();
    plzn_files(&root, &mut paths);

    let mut found = BTreeSet::new();
    let mut wildcard_overrides = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path).expect("read suite file");
        let tokens = plzn::lex::lex(&source).expect("lex suite file");
        let file = plzn::parse::parse(&tokens).expect("parse suite file");
        for test in file.tests {
            if let Some(expect) = &test.expect {
                if matches!(expect.kind, plzn::ast::ExpectKind::HandshakeFails) {
                    found.insert(test.name.value.clone());
                }
                for override_ in &expect.overrides {
                    if matches!(override_.kind, plzn::ast::ExpectKind::HandshakeFails) {
                        wildcard_overrides.push(format!(
                            "{} (`{}` override)",
                            test.name.value, override_.uut.name
                        ));
                    }
                }
            }
            for session in &test.sessions {
                if matches!(session.expect.kind, plzn::ast::ExpectKind::HandshakeFails) {
                    wildcard_overrides.push(format!(
                        "{} (session `{}`)",
                        test.name.value, session.name.name
                    ));
                }
                for override_ in &session.expect.overrides {
                    if matches!(override_.kind, plzn::ast::ExpectKind::HandshakeFails) {
                        wildcard_overrides.push(format!(
                            "{} (session `{}`, `{}` override)",
                            test.name.value, session.name.name, override_.uut.name
                        ));
                    }
                }
            }
        }
    }

    assert!(
        found.is_empty(),
        "generic `expect handshake-fails` cases must use a precise outcome or xfail: {found:?}"
    );
    assert!(
        wildcard_overrides.is_empty(),
        "backend/session wildcard expectations must use a precise outcome or xfail:\n{}",
        wildcard_overrides.join("\n")
    );
}

#[test]
fn mandatory_message_omission_matrices_are_complete() {
    // One entry for every message that is mandatory on the selected full,
    // certificate-authenticated handshake path in each supported protocol and
    // direction. Conditional Certificate/CertificateVerify entries explicitly
    // select client authentication in their scenarios.
    let required = BTreeSet::from([
        "client/tls12-mandatory-server-message-omissions/server-hello",
        "client/tls12-mandatory-server-message-omissions/certificate",
        "client/tls12-mandatory-server-message-omissions/server-key-exchange",
        "client/tls12-mandatory-server-message-omissions/server-hello-done",
        "client/tls12-mandatory-server-message-omissions/change-cipher-spec",
        "client/tls12-mandatory-server-message-omissions/finished",
        "server/tls12-mandatory-client-message-omissions/client-hello",
        "server/tls12-mandatory-client-message-omissions/certificate-after-certificate-request",
        "server/tls12-mandatory-client-message-omissions/client-key-exchange",
        "server/tls12-mandatory-client-message-omissions/certificate-verify-after-client-certificate",
        "server/tls12-mandatory-client-message-omissions/change-cipher-spec",
        "server/tls12-mandatory-client-message-omissions/finished",
        "client/tls13-mandatory-server-message-omissions/server-hello",
        "client/tls13-mandatory-server-message-omissions/encrypted-extensions",
        "client/tls13-mandatory-server-message-omissions/certificate",
        "client/tls13-mandatory-server-message-omissions/certificate-verify",
        "client/tls13-mandatory-server-message-omissions/finished",
        "server/tls13-mandatory-client-message-omissions/client-hello",
        "server/tls13-mandatory-client-message-omissions/certificate-after-certificate-request",
        "server/tls13-mandatory-client-message-omissions/certificate-verify-after-client-certificate",
        "server/tls13-mandatory-client-message-omissions/finished",
        "dtls12/mandatory-server-message-omissions/server-hello",
        "dtls12/mandatory-server-message-omissions/certificate",
        "dtls12/mandatory-server-message-omissions/server-key-exchange",
        "dtls12/mandatory-server-message-omissions/server-hello-done",
        "dtls12/mandatory-server-message-omissions/change-cipher-spec",
        "dtls12/mandatory-server-message-omissions/finished",
        "dtls12/mandatory-client-message-omissions/initial-client-hello",
        "dtls12/mandatory-client-message-omissions/certificate-after-certificate-request",
        "dtls12/mandatory-client-message-omissions/client-key-exchange",
        "dtls12/mandatory-client-message-omissions/certificate-verify-after-client-certificate",
        "dtls12/mandatory-client-message-omissions/change-cipher-spec",
        "dtls12/mandatory-client-message-omissions/finished",
        "dtls13/mandatory-server-message-omissions/server-hello",
        "dtls13/mandatory-server-message-omissions/encrypted-extensions",
        "dtls13/mandatory-server-message-omissions/certificate",
        "dtls13/mandatory-server-message-omissions/certificate-verify",
        "dtls13/mandatory-server-message-omissions/finished",
        "dtls13/mandatory-client-message-omissions/initial-client-hello",
        "dtls13/mandatory-client-message-omissions/certificate-after-certificate-request",
        "dtls13/mandatory-client-message-omissions/certificate-verify-after-client-certificate",
        "dtls13/mandatory-client-message-omissions/finished",
    ])
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suite");
    let mut paths = Vec::new();
    plzn_files(&root, &mut paths);

    let mut found = BTreeSet::new();
    for path in paths {
        let source = fs::read_to_string(&path).expect("read suite file");
        let tokens = plzn::lex::lex(&source).expect("lex suite file");
        let file = plzn::parse::parse(&tokens).expect("parse suite file");
        found.extend(file.tests.into_iter().filter_map(|test| {
            let id = test.name.value;
            id.contains("mandatory-")
                .then_some(id)
                .filter(|id| id.contains("message-omissions/"))
        }));
    }

    assert_eq!(
        found, required,
        "mandatory-message omission coverage changed; keep every supported protocol/direction matrix systematic"
    );
}

#[test]
fn dtls12_stale_flight_matrix_covers_both_roles_and_every_flight() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("suite/dtls/dtls12_stale_flights_after_progress.plzn");
    let source = fs::read_to_string(path).expect("read DTLS 1.2 stale-flight matrix");
    let tokens = plzn::lex::lex(&source).expect("lex DTLS 1.2 stale-flight matrix");
    let file = plzn::parse::parse(&tokens).expect("parse DTLS 1.2 stale-flight matrix");
    let actual = file
        .tests
        .into_iter()
        .map(|test| test.name.value)
        .collect::<BTreeSet<_>>();

    let required = BTreeSet::from([
        "dtls12/server-ignores-stale-initial-client-hello-after-cookie-exchange".to_owned(),
        "dtls12/client-ignores-stale-hello-verify-request-after-server-flight".to_owned(),
        "dtls12/server-ignores-stale-cookie-client-hello-after-finished".to_owned(),
        "dtls12/client-ignores-stale-server-handshake-after-server-finished".to_owned(),
        "dtls12/server-ignores-stale-client-finished-after-application-data".to_owned(),
        "dtls12/client-ignores-stale-server-finished-after-application-data".to_owned(),
    ]);

    assert_eq!(
        actual, required,
        "DTLS 1.2 stale-flight coverage must retain one case for every full-handshake flight across both roles"
    );
}

#[test]
fn tls13_signature_scheme_and_certificate_constraint_matrices_are_complete() {
    // Every TLS 1.3 CertificateVerify scheme for which plzn has a signing key.
    // Ed448 and the RFC 8734 brainpool schemes are not listed because plzn does
    // not yet have corresponding signing credentials. Add them here when those
    // key types become available so the corpus cannot silently stay thinner
    // than the implementation.
    let required_scheme_cases = BTreeSet::from([
        "client/tls13-server-certificate-verify-scheme/rsa-pss-rsae[scheme=rsa_pss_rsae_sha256]",
        "client/tls13-server-certificate-verify-scheme/rsa-pss-rsae[scheme=rsa_pss_rsae_sha384]",
        "client/tls13-server-certificate-verify-scheme/rsa-pss-rsae[scheme=rsa_pss_rsae_sha512]",
        "client/tls13-server-certificate-verify-scheme/rsa-pss-pss[scheme=rsa_pss_pss_sha256]",
        "client/tls13-server-certificate-verify-scheme/rsa-pss-pss[scheme=rsa_pss_pss_sha384]",
        "client/tls13-server-certificate-verify-scheme/rsa-pss-pss[scheme=rsa_pss_pss_sha512]",
        "client/tls13-server-certificate-verify-scheme/ecdsa-p256",
        "client/tls13-server-certificate-verify-scheme/ecdsa-p384",
        "client/tls13-server-certificate-verify-scheme/ecdsa-p521",
        "client/tls13-server-certificate-verify-scheme/ed25519",
    ])
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("suite/client");
    let scheme_path = root.join("tls13_server_certificate_verify_scheme_sweep.plzn");
    let source = fs::read_to_string(scheme_path).expect("read TLS 1.3 signature sweep");
    let tokens = plzn::lex::lex(&source).expect("lex TLS 1.3 signature sweep");
    let file = plzn::parse::parse(&tokens).expect("parse TLS 1.3 signature sweep");
    assert!(
        plzn::check::check(&file).is_empty(),
        "TLS 1.3 signature sweep must check cleanly"
    );
    let all_scheme_cases = file
        .tests
        .iter()
        .flat_map(|test| plzn::lower::lower(test).expect("lower TLS 1.3 signature sweep"))
        .map(|program| program.test_id)
        .collect::<BTreeSet<_>>();
    assert!(
        all_scheme_cases.contains("client/tls13-server-certificate-verify-scheme/unoffered"),
        "keep the negative in which the server signs with a scheme the client did not offer"
    );
    let actual_scheme_cases = all_scheme_cases
        .into_iter()
        .filter(|id| !id.ends_with("/unoffered"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_scheme_cases, required_scheme_cases,
        "TLS 1.3 server CertificateVerify sweep must cover every scheme plzn can sign"
    );

    let client_signing_path = root.join("tls13_client_certificate_verify_scheme_sweep.plzn");
    let source =
        fs::read_to_string(client_signing_path).expect("read TLS 1.3 client signature sweep");
    let tokens = plzn::lex::lex(&source).expect("lex TLS 1.3 client signature sweep");
    let file = plzn::parse::parse(&tokens).expect("parse TLS 1.3 client signature sweep");
    assert!(
        plzn::check::check(&file).is_empty(),
        "TLS 1.3 client signature sweep must check cleanly"
    );
    let actual_client_signing_cases = file
        .tests
        .iter()
        .flat_map(|test| plzn::lower::lower(test).expect("lower TLS 1.3 client signature sweep"))
        .map(|program| program.test_id)
        .collect::<BTreeSet<_>>();
    let required_client_signing_cases = required_scheme_cases
        .iter()
        .map(|id| id.replacen("server-certificate", "client-certificate", 1))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_client_signing_cases, required_client_signing_cases,
        "TLS 1.3 client CertificateVerify sweep must cover every scheme plzn can verify"
    );

    let constraint_path = root.join("tls13_client_certificate_signature_algorithms_cert.plzn");
    let source = fs::read_to_string(constraint_path)
        .expect("read TLS 1.3 certificate signature constraint cases");
    let tokens = plzn::lex::lex(&source).expect("lex certificate signature constraint cases");
    let file = plzn::parse::parse(&tokens).expect("parse certificate signature constraint cases");
    let constraint_ids = file
        .tests
        .into_iter()
        .map(|test| test.name.value)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        constraint_ids,
        BTreeSet::from([
            "client/tls13-client-certificate-signature-algorithms-cert/independent-lists"
                .to_owned(),
            "client/tls13-client-certificate-signature-algorithms-cert/excludes-certificate"
                .to_owned(),
            "client/tls13-client-certificate-signature-algorithms-cert/absent-falls-back"
                .to_owned(),
        ]),
        "keep the positive, explicit-exclusion, and absent-extension fallback constraints together"
    );

    let server_constraint_path =
        root.join("../server/tls13_server_certificate_signature_algorithms_cert.plzn");
    let source = fs::read_to_string(server_constraint_path)
        .expect("read server certificate signature constraint cases");
    let tokens = plzn::lex::lex(&source).expect("lex server certificate signature constraints");
    let file = plzn::parse::parse(&tokens).expect("parse server certificate signature constraints");
    let server_constraint_ids = file
        .tests
        .into_iter()
        .map(|test| test.name.value)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        server_constraint_ids,
        BTreeSet::from([
            "server/tls13-server-certificate-signature-algorithms-cert/independent-lists"
                .to_owned(),
            "server/tls13-server-certificate-signature-algorithms-cert/excludes-certificate"
                .to_owned(),
            "server/tls13-server-certificate-signature-algorithms-cert/absent-falls-back"
                .to_owned(),
        ]),
        "keep signature_algorithms_cert cross-constraints in both endpoint directions"
    );
}
