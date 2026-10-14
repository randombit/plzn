//! A supplied DSL option must affect the program/wire or produce a diagnostic.

use plzn::ir::Program;
use plzn::runtime::RunStatus;
use plzn::tls::codec::{
    ClientHelloDecoded, Extension, decode_client_hello_body, decode_server_hello_body,
};
use plzn::transport::{MockFactory, MockTransport};

fn source(version: &str, header: &str, steps: &str) -> String {
    format!(
        "plzn tls \"consumption\" {{\nchain: [ecdsa_p256]\nuut server {{ versions: [{version}] }}\n{header}\nflow {{\n{steps}\nclose\n}}\nexpect ok\n}}\n"
    )
}

fn program(source: &str) -> Program {
    let diags = plzn::lint("consumption", source);
    assert!(diags.is_empty(), "{diags:?}\n{source}");
    let ast = plzn::parse::parse(&plzn::lex::lex(source).unwrap()).unwrap();
    plzn::lower::lower(&ast.tests[0]).unwrap().remove(0)
}

fn rejected(source: &str, expected: &str) {
    let diags = plzn::lint("consumption", source);
    let rendered = diags
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        rendered.contains(expected),
        "expected {expected:?}, got {rendered:?}\n{source}"
    );
}

#[test]
fn only_single_send_heartbeat_accepts_inline_payloads() {
    for step in [
        "send ClientHello \"ignored\"",
        "send ClientHello $unused",
        "send ClientHello [1, 2]",
        "send ClientHello zeros 2",
        "recv ServerHello \"ignored\"",
        "recv AppData \"ignored\"",
        "send EarlyData \"ignored\"",
        "recv EarlyData \"ignored\"",
        "send Heartbeat \"ignored\", ClientHello",
        "send ClientHello \"ignored\", Finished",
        "send KeyUpdate \"ignored\"",
        "recv KeyUpdate \"ignored\"",
    ] {
        rejected(
            &source("tls13", "", step),
            "does not accept an inline payload",
        );
    }
    rejected(
        &source("tls13", "", "send AppData \"ignored\""),
        "literal AppData payloads",
    );
    rejected(
        &source("tls12", "", "send Heartbeat \"one\" { payload: \"two\" }"),
        "cannot combine an inline payload",
    );
    // Keep the supported Heartbeat shorthand and its actual payload.
    let p = program(&source("tls12", "", "send Heartbeat \"hello\""));
    let plzn::ir::Step::HandshakeSteps {
        config: Some(config),
        ..
    } = &p.steps[0]
    else {
        panic!("missing occurrence configuration");
    };
    assert!(config.fields.iter().any(|field| {
        field.field == "payload" && field.value == plzn::ir::FieldValue::Bytes(b"hello".to_vec())
    }));
}

#[test]
fn special_record_sends_reject_dedicated_handshake_fragmentation() {
    for version in ["tls12", "tls13", "dtls12", "dtls13"] {
        for step in [
            "send alert warning/close_notify",
            "send empty_record application_data",
            "send record 23 \"hello\"",
        ] {
            for suffix in [
                "duplicate_fragment 8",
                "record_version 0x0303, duplicate_fragment 8",
            ] {
                rejected(
                    &source(version, "", &format!("{step} @ {suffix}")),
                    "DTLS handshake fragmentation plans are not supported",
                );
            }
            // Keep valid sends and TLS record-version modifiers accepted.
            program(&source(version, "", step));
            if version.starts_with("tls") {
                program(&source(
                    version,
                    "",
                    &format!("{step} @ record_version 0x0303"),
                ));
            }
        }
    }
    for version in ["dtls12", "dtls13"] {
        rejected(
            &source(version, "", "send Heartbeat @ duplicate_fragment 8"),
            "fragmentation scheme cannot be applied to `Heartbeat`",
        );
        rejected(
            &source(version, "", "send Heartbeat @ fragment 8"),
            "defined only for handshake messages over DTLS",
        );
    }
}

#[test]
fn generated_key_share_duplication_is_rejected() {
    rejected(
        &source(
            "tls13",
            "",
            "send ClientHello {\n+ext dup key_share = [x25519]\n}",
        ),
        "does not support generated share lists",
    );
    rejected(
        &source(
            "tls13",
            "",
            "send ClientHello {\n+ext dup key_share = []\n}",
        ),
        "does not support generated share lists",
    );
    rejected(
        &source("tls13", "", "send ClientHello {\n+ext dup each [0x0a0a]\n}"),
        "already appends each entry",
    );
    program(&source(
        "tls13",
        "",
        "send ClientHello {\n+ext key_share = [x25519]\n}",
    ));
}

fn client_hello_bytes(version: &str, header: &str, fields: &str) -> Vec<u8> {
    let p = program(&source(
        version,
        header,
        &format!("send ClientHello {{ {fields} }}"),
    ));
    let transport = MockTransport::new("consumption");
    let report = plzn::runtime::run(&p, &MockFactory::new(transport.clone()), [7; 32], None);
    assert!(matches!(report.status, RunStatus::Pass), "{report:?}");
    transport.written()
}

fn client_hello(version: &str, header: &str, fields: &str) -> ClientHelloDecoded {
    let bytes = client_hello_bytes(version, header, fields);
    let body = if version.starts_with("dtls") {
        assert_eq!(bytes[0], b'P');
        let datagram_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
        let datagram = &bytes[5..5 + datagram_len];
        assert_eq!(datagram[0], 22); // epoch-zero handshake record
        assert_eq!(datagram[13], 1); // ClientHello
        plzn::tls::dtls_handshake::strip_dtls_cookie(&datagram[25..]).unwrap()
    } else {
        assert_eq!(bytes[0], 22);
        assert_eq!(bytes[5], 1);
        let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        bytes[9..5 + record_len].to_vec()
    };
    decode_client_hello_body(&body).unwrap()
}

#[test]
fn signature_capabilities_change_the_actual_client_offer() {
    let header = "peer { capabilities: [ecdsa_secp384r1_sha384, ecdsa_secp256r1_sha256] }";
    for version in ["tls12", "tls13", "dtls12", "dtls13"] {
        let hello = client_hello(version, header, "");
        let schemes = hello
            .extensions
            .iter()
            .find_map(|extension| match extension {
                Extension::SignatureAlgorithms(schemes) => Some(schemes.as_slice()),
                _ => None,
            });
        assert_eq!(schemes, Some([0x0503, 0x0403].as_slice()), "{version}");
    }
}

#[test]
fn unimplemented_server_signature_preferences_are_rejected() {
    for version in ["tls13", "dtls12", "dtls13"] {
        let s = source(
            version,
            "peer { capabilities: [ecdsa_secp256r1_sha256] }",
            "",
        )
        .replace("uut server", "uut client");
        rejected(&s, "does not implement signature preferences");
    }
    let s = source(
        "tls12",
        "peer { capabilities: [ecdsa_secp256r1_sha256] }",
        "",
    )
    .replace("uut server", "uut client");
    assert_eq!(program(&s).client_signature_schemes, Some(vec![0x0403]));
}

#[test]
fn empty_cipher_selector_intersections_are_rejected() {
    rejected(
        &source("tls12", "matrix { suite in [0x0a0a] }", "send ClientHello"),
        "leave no supported suites",
    );
    for (version, selectors) in [
        ("tls13", "cbc"),
        ("dtls13", "cbc"),
        ("tls12", "gcm, cbc"),
        ("dtls12", "gcm, cbc"),
        ("tls12", "ecdhe_rsa, ccm"),
    ] {
        rejected(
            &source(
                version,
                &format!("peer {{ capabilities: [{selectors}] }}"),
                "send ClientHello",
            ),
            "leave no supported suites",
        );
    }
    for version in ["tls12", "tls13"] {
        let hello = client_hello(version, "peer { capabilities: [aes128_gcm_sha256] }", "");
        let suites: Vec<_> = hello
            .cipher_suites
            .iter()
            .filter_map(|wire| plzn::ir::suite_info(*wire))
            .collect();
        assert!(!suites.is_empty());
        assert!(
            suites
                .iter()
                .all(|suite| suite.cipher == plzn::ir::BulkCipher::Aes128Gcm)
        );
    }
}

#[test]
fn tls13_server_cipher_filters_change_the_actual_selection() {
    let cert =
        plzn::server::certs::CertBundle::generate(plzn::server::certs::KeyType::EcdsaP256).unwrap();
    for version in ["tls13", "dtls13"] {
        let s = source(
            version,
            "peer { capabilities: [gcm, sha384] }",
            "recv ClientHello\nsend ServerHello",
        )
        .replace("uut server", "uut client");
        let mut p = program(&s);
        assert_eq!(p.server_suites, [0x1302]);
        p.cert_der = Some(cert.cert_der.clone());
        p.private_key_der = Some(cert.key_pkcs8_der.clone());
        let transport = MockTransport::new("server cipher selection");
        transport.push_incoming(&client_hello_bytes(
            version,
            "peer { capabilities: [gcm] }",
            "",
        ));
        let report = plzn::runtime::run(&p, &MockFactory::new(transport.clone()), [9; 32], None);
        assert!(matches!(report.status, RunStatus::Pass), "{report:?}");
        let bytes = transport.written();
        let body = if version == "dtls13" {
            assert_eq!(bytes[0], b'P');
            let datagram_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
            let datagram = &bytes[5..5 + datagram_len];
            assert_eq!(datagram[13], 2); // ServerHello
            let record_len = u16::from_be_bytes([datagram[11], datagram[12]]) as usize;
            &datagram[25..13 + record_len]
        } else {
            assert_eq!(bytes[5], 2); // ServerHello
            let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            &bytes[9..5 + record_len]
        };
        assert_eq!(decode_server_hello_body(body).unwrap().cipher_suite, 0x1302);
    }
}

#[test]
fn hello_fields_are_checked_against_the_selected_protocol() {
    for version in ["tls12", "tls13"] {
        rejected(
            &source(version, "", "send ClientHello { cookie: [1, 2] }"),
            "ClientHello.cookie` requires DTLS",
        );
    }
    for version in ["tls12", "dtls12"] {
        rejected(
            &source(version, "", "send ClientHello { key_share_point: x25519 }"),
            "ClientHello.key_share_point` requires TLS 1.3",
        );
    }
    rejected(
        &source("tls12", "", "renegotiate { cookie: [1, 2] }"),
        "ClientHello.cookie` requires DTLS",
    );
    for version in ["dtls12", "dtls13"] {
        program(&source(version, "", "send ClientHello { cookie: [1, 2] }"));
    }
}

#[test]
fn duplicate_configuration_cannot_replace_earlier_work() {
    for (header, diagnostic) in [
        ("repeat 2\nrepeat 3", "duplicate test-level `repeat`"),
        (
            "matrix { x in [1] }\nmatrix { y in [2] }",
            "more than one `matrix`",
        ),
        (
            "psk {\nidentity: \"one\"\nsecret: \"01\"\n}\npsk {\nidentity: \"two\"\nsecret: \"02\"\n}",
            "more than one `psk`",
        ),
        (
            "peer { capabilities: [cbc], capabilities: [gcm] }",
            "duplicate `capabilities`",
        ),
        (
            "peer { request_client_cert: false, request_client_cert: false }",
            "duplicate `request_client_cert`",
        ),
        (
            "psk {\nidentity: \"one\"\nidentity: \"two\"\nsecret: \"01\"\n}",
            "duplicate `identity`",
        ),
        (
            "psk {\nidentity: \"one\"\nsecret: \"01\"\nsecret: \"02\"\n}",
            "duplicate `secret`",
        ),
        (
            "psk {\nidentity: \"one\"\nsecret: \"01\"\noffer {\nidentity: \"one\"\nsecret: \"01\"\nhash: sha256\nhash: sha384\n}\n}",
            "duplicate `hash`",
        ),
    ] {
        rejected(&source("tls13", header, ""), diagnostic);
    }
    for fields in [
        "versions: [tls12], versions: [tls13]",
        "versions: [tls13], verify_peer: true, verify_peer: false",
        "versions: [tls13], cipher_suites: [], cipher_suites: []",
    ] {
        let s = source("tls13", "", "").replace("versions: [tls13]", fields);
        rejected(&s, "duplicate");
    }
}
