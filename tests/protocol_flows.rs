//! Protocol selection is shared by every consumer of the TLS DSL.

use plzn::{format::format_source, lex::lex, parse::parse};
use std::process::Command;

const TLS: &str = r#"plzn tls "tls/selected" {
  chain: [default]
  uut server { versions: [tls13] }
  skip mock "protocol selection fixture"
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;

// Includes nested declarations, non-TLS punctuation, overflowing integers,
// Unicode, and braces in comments and escaped strings. None is TLS input.
const FOREIGN: &str = r#"plzn quic "quic/ignored" {
  ~unsupported => syntax ? | % ; 🦀
  number: 99999999999999999999999999999999999999999999999
  nested { plzn tls "also-ignored" { invalid } }
  "an escaped quote: \" } and backslash: \\"
  # } plzn tls "comment" {
}
plzn http "http/ignored" { request { method: GET; } }
"#;

#[test]
fn mixed_protocols_select_only_tls_and_preserve_spans() {
    let second = TLS.replace("tls/selected", "tls/second");
    let source = format!("{FOREIGN}{TLS}{FOREIGN}{second}{FOREIGN}");
    let file = parse(&lex(&source).unwrap()).unwrap();
    assert_eq!(
        file.tests
            .iter()
            .map(|test| test.name.value.as_str())
            .collect::<Vec<_>>(),
        ["tls/selected", "tls/second"]
    );
    for (test, declaration) in file.tests.iter().zip([TLS, second.as_str()]) {
        assert_eq!(
            &source[test.span.start..test.span.end],
            declaration.trim_end()
        );
    }
    assert!(plzn::lint("mixed.plzn", &source).is_empty());
}

#[test]
fn foreign_only_files_are_empty_tls_programs() {
    assert!(parse(&lex(FOREIGN).unwrap()).unwrap().tests.is_empty());
    assert!(plzn::lint("foreign.plzn", FOREIGN).is_empty());
    // Selection is exact, case-sensitive, and extensible to unknown protocols.
    for protocol in [
        "http",
        "quic",
        "tls13",
        "tls-extra",
        "TLS",
        "future_protocol",
    ] {
        let source = format!("plzn {protocol} \"ignored\" {{ ?; }}");
        assert!(parse(&lex(&source).unwrap()).unwrap().tests.is_empty());
    }
}

#[test]
fn tls_headers_accept_horizontal_whitespace() {
    let source = TLS.replacen("plzn tls", "plzn\t tls", 1);
    assert_eq!(parse(&lex(&source).unwrap()).unwrap().tests.len(), 1);
}

#[test]
fn tls_errors_keep_original_locations_after_foreign_flows() {
    for (body, category) in [("  ?", "lex error"), ("  unsupported", "parse error")] {
        let source = format!("{FOREIGN}plzn tls \"bad\" {{\n{body}\n}}\n");
        let diags = plzn::lint("mixed.plzn", &source);
        assert_eq!(diags.len(), 1, "{diags:?}");
        assert_eq!(diags[0].category, category);
        assert_eq!(diags[0].line, FOREIGN.lines().count() + 2);
        assert_eq!(diags[0].col, 3);
        assert_eq!(diags[0].excerpt, body);
    }
}

#[test]
fn foreign_declarations_cannot_hide_inside_tls_flows() {
    let source = TLS.replace("  expect ok", "  plzn http \"nested\" {}\n  expect ok");
    assert!(!plzn::lint("nested.plzn", &source).is_empty());
}

#[test]
fn legacy_test_headers_are_rejected() {
    let source = TLS.replacen("plzn tls", "test", 1);
    let errors = parse(&lex(&source).unwrap()).unwrap_err();
    assert_eq!(errors[0].message, "expected `plzn tls`");
}

#[test]
fn malformed_tls_headers_recover_to_the_next_declaration() {
    let source = "plzn tls 123 {}\nplzn http \"ignored\" { ? }\nplzn tls 456 {}";
    let errors = parse(&lex(source).unwrap()).unwrap_err();
    assert_eq!(errors.len(), 2);
    assert!(
        errors
            .iter()
            .all(|error| error.message.contains("expected string"))
    );
}

#[test]
fn foreign_envelopes_must_be_delimited() {
    for source in [
        "plzn http {}",
        "plzn http \"name\"",
        "plzn http \"name\" { nested {}",
    ] {
        assert!(!plzn::lint("bad.plzn", source).is_empty());
    }
}

#[test]
fn formatting_preserves_foreign_bytes_in_mixed_files() {
    let foreign = format!(" \t{}", FOREIGN.replace('\n', "  \r\n"));
    let unformatted_tls = TLS.replace("  ", "        ");
    let source = format!("{foreign}{unformatted_tls}{foreign}");
    let formatted = format_source("mixed.plzn", &source).unwrap();
    assert_eq!(formatted, format!("{foreign}{TLS}{foreign}"));
    assert_eq!(format_source("mixed.plzn", &formatted).unwrap(), formatted);

    let foreign_only = format!("\r\n{foreign}\r\n  \t");
    assert_eq!(
        format_source("foreign.plzn", &foreign_only).unwrap(),
        foreign_only
    );
}

#[test]
fn formatting_preserves_shared_lines_and_tracks_tls_indentation() {
    let source =
        "plzn http \"other\" {?;} plzn tls \"tls\" {\nexpect close\n} plzn quic \"other\" {~;}";
    let formatted = format_source("mixed.plzn", source).unwrap();
    assert_eq!(formatted, source.replace("\nexpect", "\n  expect"));
    assert_eq!(format_source("mixed.plzn", &formatted).unwrap(), formatted);
}

#[test]
fn cli_run_and_lint_ignore_foreign_flows_across_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("foreign.plzn"), FOREIGN).unwrap();
    std::fs::write(
        dir.path().join("mixed.plzn"),
        format!("{FOREIGN}{TLS}{FOREIGN}"),
    )
    .unwrap();

    let lint = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .arg("lint")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(lint.status.success(), "{lint:?}");

    let run = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["run", "--json", "--shim", env!("CARGO_BIN_EXE_mock_shim")])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    let records: Vec<serde_json::Value> = String::from_utf8(run.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["test_id"], "tls/selected");
    assert_eq!(records[1]["total"], 1);
}

#[test]
fn cli_foreign_only_run_dial_and_fmt_do_no_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign.plzn");
    let source = format!(" \t{FOREIGN}\r\n\r\n");
    std::fs::write(&path, &source).unwrap();
    for args in [
        vec!["run", "--shim", env!("CARGO_BIN_EXE_mock_shim")],
        vec!["dial", "--addr", "127.0.0.1:1"],
        vec!["fmt", "--check"],
        vec!["fmt"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(&args)
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), source);
}
