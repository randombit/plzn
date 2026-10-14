use std::path::Path;
#[cfg(unix)]
use std::process::Command;

use plzn::server::certs::{CertBundle, KeyType};
use plzn::shim::ShimConfig;

const KEY_TYPES: [KeyType; 6] = [
    KeyType::EcdsaP256,
    KeyType::EcdsaP384,
    KeyType::EcdsaP521,
    KeyType::Ed25519,
    KeyType::Rsa2048,
    KeyType::RsaPss,
];

fn program(subject: &str, policy: &str) -> plzn::ir::Program {
    let peer = if subject == "client" {
        "peer { request_client_cert: true }"
    } else {
        ""
    };
    let source = format!(
        "plzn tls \"portable\" {{\n\
         rfc 8446 section 4.3.2\n\
         chain: [default]\n\
         uut {subject} {{ versions: [tls13], {policy} }}\n\
         {peer}\n\
         flow handshake {{\nsend AppData\nrecv AppData\n}}\n\
         expect ok\n}}\n"
    );
    let diagnostics = plzn::lint("portable", &source);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let file = plzn::parse::parse(&plzn::lex::lex(&source).unwrap()).unwrap();
    plzn::lower::lower(&file.tests[0]).unwrap().remove(0)
}

#[test]
fn all_builtin_credentials_have_matching_pem_and_der() {
    let dir = tempfile::tempdir().unwrap();
    let anchors = plzn::tls::client_auth::default_trust_anchors();
    assert_eq!(anchors.len(), 4);
    for kt in KEY_TYPES {
        let bundle = CertBundle::generate(kt).unwrap();
        assert!(!bundle.cert_der.is_empty());
        plzn::tls::crypto::PrivateKey::from_pkcs8_der(&bundle.key_pkcs8_der).unwrap();

        let (cert, key) = plzn::shim::client_credential_der_for(kt).unwrap();
        plzn::tls::client_auth::verify_client_chain(&[&cert], &anchors).unwrap();
        plzn::tls::crypto::PrivateKey::from_pkcs8_der(&key).unwrap();
        let (cert_file, key_file) =
            plzn::shim::client_credential_files_for(kt, dir.path()).unwrap();
        assert!(cert_file.starts_with(dir.path()));
        assert!(key_file.starts_with(dir.path()));
        assert_eq!(
            plzn::tls::client_auth::pem_certificates(&std::fs::read(cert_file).unwrap()),
            vec![cert],
        );
        let key_pem = std::fs::read(key_file).unwrap();
        let pem_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .unwrap()
            .unwrap();
        assert_eq!(pem_key.secret_der(), key);
    }
    assert_eq!(
        plzn::shim::test_client_credential_der(),
        plzn::tls::dtls_kex::default_client_credential(),
    );
    for name in [
        "valid",
        "rsa",
        "rsa_pss",
        "ecdsa_p384",
        "ecdsa_p521",
        "ed25519",
        "untrusted",
    ] {
        assert!(
            plzn::tls::dtls_kex::named_client_credential(name).is_some(),
            "{name}"
        );
    }
    assert!(plzn::tls::dtls_kex::named_client_credential("none").is_none());
}

#[test]
fn shim_fixture_files_live_until_the_last_config_is_dropped() {
    for choice in ["valid", "expired", "untrusted"] {
        let program = program("client", &format!("client_cert: {choice}"));
        let cfg = ShimConfig::for_program(&program, None, None, None).unwrap();
        let dir = cfg.fixture_dir.as_ref().unwrap().path().to_owned();
        let cert = cfg.credentials.cert_file.clone();
        let key = cfg.credentials.key_file.clone();
        assert!(Path::new(&cert).starts_with(&dir));
        assert!(Path::new(&key).starts_with(&dir));
        assert!(
            !plzn::tls::client_auth::pem_certificates(&std::fs::read(&cert).unwrap()).is_empty()
        );
        assert!(!std::fs::read(&key).unwrap().is_empty());
        assert!(
            serde_json::to_value(&cfg)
                .unwrap()
                .get("fixture_dir")
                .is_none()
        );
        let second_session = cfg.for_connection(1);
        drop(cfg);
        assert!(Path::new(&cert).is_file());
        drop(second_session);
        assert!(!dir.exists());
    }
}

#[test]
fn shim_trust_roots_and_default_client_credentials_are_materialized() {
    let server = program("server", "require_client_cert: true");
    let cfg = ShimConfig::for_program(&server, None, None, None).unwrap();
    assert!(Path::new(&cfg.credentials.trust_file).is_file());
    assert!(
        !plzn::tls::client_auth::pem_certificates(
            &std::fs::read(&cfg.credentials.trust_file).unwrap()
        )
        .is_empty()
    );

    let client = program("client", "");
    let cfg = ShimConfig::for_program(&client, None, None, None).unwrap();
    assert!(Path::new(&cfg.credentials.cert_file).is_file());
    assert!(Path::new(&cfg.credentials.key_file).is_file());

    let no_cert = program("client", "client_cert: none");
    let cfg = ShimConfig::for_program(&no_cert, None, None, None).unwrap();
    assert!(cfg.credentials.cert_file.is_empty());
    assert!(cfg.fixture_dir.is_none());
}

#[test]
fn client_fixture_write_errors_are_not_missing_credentials() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(plzn::shim::client_credential_files_for(KeyType::Rsa2048, file.path()).is_err());
}

#[cfg(unix)]
#[test]
fn boringssl_requires_an_explicit_complete_checkout_even_if_already_built() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Makefile"),
        include_str!("../shims/Makefile"),
    )
    .unwrap();
    std::fs::create_dir(dir.path().join("build")).unwrap();
    std::fs::write(dir.path().join("build/boringssl_shim"), b"already built").unwrap();
    for target in ["boringssl", "build/boringssl_shim"] {
        let out = Command::new("make")
            .current_dir(dir.path())
            .args([target, "PLZN_BORINGSSL_ROOT="])
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("requires PLZN_BORINGSSL_ROOT"));
    }
    let root = dir.path().join("explicit-checkout");
    let make = || {
        Command::new("make")
            .current_dir(dir.path())
            .arg("boringssl-config")
            .arg(format!("PLZN_BORINGSSL_ROOT={}", root.display()))
            .output()
            .unwrap()
    };
    assert!(!make().status.success());
    for name in [
        "include/openssl/ssl.h",
        "build/libssl.a",
        "build/libcrypto.a",
    ] {
        let file = root.join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, []).unwrap();
    }
    assert!(make().status.success());
}
