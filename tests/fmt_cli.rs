use std::process::Command;

#[test]
fn fmt_formats_directories_and_check_is_read_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested).unwrap();
    let case = nested.join("case.plzn");
    std::fs::write(
        &case,
        "plzn tls \"fmt/cli\" {  \r\n      chain: [default]\r\n uut server { versions: [tls12] }\r\n flow {\r\n        send AppData\r\n }\r\n expect close\r\n}\r\n\r\n",
    )
    .unwrap();

    let check = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["fmt", "--check"])
        .arg(dir.path())
        .output()
        .expect("run plzn fmt --check");
    assert_eq!(check.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&check.stdout).contains("case.plzn: needs formatting"));

    let run = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .arg("fmt")
        .arg(dir.path())
        .output()
        .expect("run plzn fmt");
    assert!(run.status.success());
    assert_eq!(
        std::fs::read_to_string(&case).unwrap(),
        concat!(
            "plzn tls \"fmt/cli\" {\n",
            "  chain: [default]\n",
            "  uut server { versions: [tls12] }\n",
            "  flow {\n",
            "    send AppData\n",
            "  }\n",
            "  expect close\n",
            "}\n",
        )
    );

    let clean = Command::new(env!("CARGO_BIN_EXE_plzn"))
        .args(["fmt", "--check"])
        .arg(dir.path())
        .output()
        .expect("rerun plzn fmt --check");
    assert!(clean.status.success());
    assert!(clean.stdout.is_empty());
}
