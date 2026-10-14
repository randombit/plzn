use std::process::Command;

fn records(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("each output line is JSON"))
        .collect()
}

#[test]
fn lint_json_reports_each_file_and_a_summary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = dir.path().join("valid.plzn");
    let invalid = dir.path().join("invalid.plzn");
    std::fs::write(
        &valid,
        r#"plzn tls "report/json-lint" {
  chain: [default]
  uut server { versions: [tls12] }
  flow handshake {}
  expect close
}
"#,
    )
    .unwrap();
    std::fs::write(&invalid, "this is not plzn\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["lint", "--json"])
        .arg(&valid)
        .arg(&invalid)
        .output()
        .expect("run plzn lint");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);

    let records = records(&output.stdout);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["schema_version"], 1);
    assert_eq!(records[0]["type"], "file");
    assert_eq!(records[0]["status"], "error");
    assert!(!records[0]["diagnostics"].as_array().unwrap().is_empty());
    assert_eq!(records[1]["status"], "ok");
    assert_eq!(records[2]["type"], "summary");
    assert_eq!(records[2]["files"], 2);
    assert_eq!(records[2]["passed"], 1);
    assert_eq!(records[2]["failed"], 1);
}

#[test]
fn run_json_is_a_clean_case_and_summary_stream() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("skip.plzn");
    std::fs::write(
        &source,
        r#"plzn tls "report/json-run" {
  chain: [default]
  uut server { versions: [tls12] }
  skip mock "reporting fixture"
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["run", "--json", "--shim", env!("CARGO_BIN_EXE_mock_shim")])
        .arg(&source)
        .output()
        .expect("run plzn run");
    assert!(output.status.success(), "{:?}", output);
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);

    let records = records(&output.stdout);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["schema_version"], 1);
    assert_eq!(records[0]["type"], "case");
    assert_eq!(records[0]["test_id"], "report/json-run");
    assert_eq!(records[0]["backend"], "mock");
    assert_eq!(records[0]["status"], "skip");
    assert_eq!(records[0]["classification"], "not_applicable");
    assert_eq!(records[0]["reason"], "reporting fixture");
    assert_eq!(records[1]["type"], "summary");
    assert_eq!(records[1]["total"], 1);
    assert_eq!(records[1]["skipped"], 1);
    assert_eq!(records[1]["failed"], 0);
    assert_eq!(records[1]["aborted"], false);
}
