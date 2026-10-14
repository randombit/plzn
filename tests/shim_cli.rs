//! External-shim CLI protocol and expectation-sidecar coverage.

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[test]
    fn path_shim_identifies_itself_and_loads_relative_expectations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let shim = dir.path().join("project_shim");
        std::fs::write(
            &shim,
            r#"#!/bin/sh
if [ "$1" = --plzn-shim-info ]; then
  echo '{"protocol":"plzn-shim","protocol_version":1,"name":"project-tls","expectations":"expectations.json"}'
  exit 0
fi
echo 'the sidecar skip should prevent shim execution' >&2
exit 99
"#,
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join("expectations.json"),
            r#"{
  "schema_version": 1,
  "overrides": {
    "external/sidecar": { "skip": "known project configuration gap" }
  }
}"#,
        )
        .unwrap();
        let case = dir.path().join("case.plzn");
        std::fs::write(
            &case,
            r#"plzn tls "external/sidecar" {
  chain: [default]
  uut server { versions: [tls12] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        )
        .unwrap();

        let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(["run", "--shim"])
            .arg(&shim)
            .arg(&case)
            .output()
            .expect("run plzn");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            stderr.contains("[shim] project-tls") && stderr.contains("1 expectation overrides"),
            "stderr:\n{stderr}"
        );
        assert!(
            stdout.contains(
                "[SKIP] external/sidecar — not applicable to project-tls: known project configuration gap"
            ),
            "stdout:\n{stdout}"
        );
    }

    #[test]
    fn old_server_name_selector_is_rejected() {
        let out = Command::new(env!("CARGO_BIN_EXE_plzn"))
            .args(["run", "--server", "botan", "missing.plzn"])
            .output()
            .expect("run plzn");
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("unknown flag \"--server\""));
    }
}
