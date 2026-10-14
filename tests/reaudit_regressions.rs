use plzn::ir::{MessageKind, Program, Step};
use plzn::tls::codec::{CONTENT_TYPE_APP_DATA, CONTENT_TYPE_HANDSHAKE, encode_handshake};
use plzn::tls::record::{RecordError, RecordLayer, TlsVersion};
use plzn::transport::MockTransport;

const HEADER: &str = "plzn tls \"reaudit\" {\nchain: [default]\nuut server { versions: [tls13] }\n";

fn programs(body: &str) -> Vec<Program> {
    let source = format!("{HEADER}{body}\n}}\n");
    let diagnostics = plzn::lint("reaudit", &source);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let file = plzn::parse::parse(&plzn::lex::lex(&source).unwrap()).unwrap();
    plzn::lower::lower(&file.tests[0]).unwrap()
}

#[test]
fn key_update_matchers_belong_to_each_receive() {
    let program = programs("flow handshake {\nrecv KeyUpdate { request_update: update_requested }\nrecv KeyUpdate { request_update: update_not_requested }\nclose\n}\nexpect ok").remove(0);
    let matchers: Vec<_> = program
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::RecvKeyUpdate { matchers, .. } => Some(&matchers[0].value),
            _ => None,
        })
        .collect();
    assert_eq!(matchers.len(), 2);
    assert_ne!(matchers[0], matchers[1]);
}

#[test]
fn preset_declarations_merge_without_empty_shadowing() {
    let program = programs("flow handshake {\nrecv ServerHello\nrecv ServerHello { cipher_suite: TLS_AES_128_GCM_SHA256 }\nclose\n}\nexpect ok").remove(0);
    let lists: Vec<_> = program
        .recv_matchers
        .iter()
        .filter(|m| m.message == MessageKind::ServerHello)
        .collect();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].fields.len(), 1);
}

#[test]
fn explicit_receives_keep_distinct_fields_and_do_not_configure_the_prefix() {
    let program = programs("flow {\nrecv ServerHello { cipher_suite: TLS_AES_128_GCM_SHA256 }\nrecv ServerHello { cipher_suite: TLS_AES_256_GCM_SHA384 }\n}\nexpect handshake-fails").remove(0);
    assert!(program.recv_matchers.is_empty());
    let configs: Vec<_> = program
        .steps
        .iter()
        .filter_map(|step| match step {
            Step::HandshakeSteps {
                config: Some(config),
                ..
            } => Some(config),
            _ => None,
        })
        .collect();
    assert_eq!(configs.len(), 2);
    assert_ne!(configs[0].fields[0].value, configs[1].fields[0].value);
}

#[test]
fn sessions_are_checked_and_cannot_silently_replace_top_level_work() {
    for body in [
        "session first {\nflow { recv KeyUpdate { nonexistent: 1 } }\nexpect handshake-fails\n}",
        "session first [resumes: missing] {\nflow { close }\nexpect ok\n}",
        "session first [resumes: first] {\nflow { close }\nexpect ok\n}",
        "session first {\nflow { close }\nexpect ok\n}\nsession first {\nflow { close }\nexpect ok\n}",
        "flow { close }\nflow { close }\nexpect ok",
        "flow { close }\nexpect ok\nsession first {\nflow { close }\nexpect ok\n}",
        "session first {\nflow { close }\nflow { close }\nexpect ok\n}",
    ] {
        assert!(
            !plzn::lint("reaudit", &format!("{HEADER}{body}\n}}\n")).is_empty(),
            "accepted {body}"
        );
    }
}

#[test]
fn unsupported_special_message_modifiers_fail_lint() {
    for statement in [
        "send AppData { +ext server_name = \"example.test\" }",
        "recv AppData { ext server_name == \"example.test\" }",
        "send Renegotiation @ truncate 1",
        "recv KeyUpdate { ext server_name == \"example.test\" }",
    ] {
        let source = format!("{HEADER}flow handshake {{\n{statement}\nclose\n}}\nexpect ok\n}}\n");
        assert!(
            !plzn::lint("reaudit", &source).is_empty(),
            "accepted {statement}"
        );
    }
}

#[test]
fn duplicate_client_hello_does_not_silently_drop_new_fields() {
    let source = format!(
        "{HEADER}flow {{\nsend ClientHello\nsend ClientHello {{ cipher_suites: [TLS_AES_128_GCM_SHA256] }}\n}}\nexpect handshake-fails\n}}\n"
    );
    let diagnostics = plzn::lint("reaudit", &source);
    assert!(
        format!("{diagnostics:?}").contains("replays CH1"),
        "{diagnostics:?}"
    );
}

#[test]
fn cross_run_groups_include_the_session_identity() {
    let session = |name| {
        format!(
            "session {name} {{\nflow handshake {{\nrecv ServerHello {{ random: capture $random }}\nclose\n}}\nexpect ok\nassert unique $random\n}}\n"
        )
    };
    let programs = programs(&format!(
        "repeat 2\n{}{}",
        session("first"),
        session("second")
    ));
    assert_eq!(programs.len(), 4);
    assert_eq!(programs[0].repeat_group, programs[2].repeat_group);
    assert_ne!(programs[0].repeat_group, programs[1].repeat_group);
}

#[test]
fn session_pcaps_do_not_overwrite_each_other() {
    let programs = programs(
        "session first {\nflow { close }\nexpect ok\n}\nsession second {\nflow { close }\nexpect ok\n}",
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trace.pcap");
    let factory = plzn::transport::MockFactory::new(MockTransport::new("session captures"));
    let reports = plzn::runtime::run_sessions(&programs, &factory, [0; 32], Some(&path));
    assert_eq!(reports.len(), 2);
    assert!(!path.exists());
    let captures: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(captures.len(), 2);
}

fn ticket() -> Vec<u8> {
    encode_handshake(4, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 42, 0, 0])
}

fn records(input: &[(u8, Vec<u8>)]) -> RecordLayer {
    let transport = MockTransport::new("reaudit");
    let mut writer = RecordLayer::new(Box::new(transport.clone()), TlsVersion::Tls13);
    for (ct, bytes) in input {
        writer.write_record(*ct, bytes).unwrap();
    }
    transport.push_incoming(&transport.take_written());
    RecordLayer::new(Box::new(transport), TlsVersion::Tls13)
}

#[test]
fn coalesced_and_fragmented_tickets_are_counted_per_message() {
    let ticket = ticket();
    let stream = [ticket.as_slice(), ticket.as_slice()].concat();
    for split in 1..stream.len() {
        let mut reader = records(&[
            (CONTENT_TYPE_HANDSHAKE, stream[..split].to_vec()),
            (CONTENT_TYPE_HANDSHAKE, stream[split..].to_vec()),
            (CONTENT_TYPE_APP_DATA, b"reply".to_vec()),
        ]);
        assert_eq!(reader.read_app_data().unwrap(), b"reply");
        assert_eq!(reader.swallowed_nst_count(), 2);
        assert_eq!(reader.take_swallowed_nst(), Some(ticket.clone()));
        assert_eq!(reader.take_swallowed_nst(), Some(ticket.clone()));
        assert_eq!(reader.take_swallowed_nst(), None);
    }
}

#[test]
fn partial_ticket_left_by_explicit_receive_is_reassembled() {
    let ticket = ticket();
    let mut reader = records(&[
        (
            CONTENT_TYPE_HANDSHAKE,
            [ticket.as_slice(), &ticket[..2]].concat(),
        ),
        (CONTENT_TYPE_HANDSHAKE, ticket[2..].to_vec()),
        (CONTENT_TYPE_APP_DATA, b"reply".to_vec()),
    ]);
    assert_eq!(reader.read_handshake_bytes(ticket.len()).unwrap(), ticket);
    assert_eq!(reader.read_app_data().unwrap(), b"reply");
    assert_eq!(reader.swallowed_nst_count(), 1);
}

#[test]
fn drain_does_not_stop_after_a_ticket_before_an_alert() {
    let mut reader = records(&[(CONTENT_TYPE_HANDSHAKE, ticket()), (21, vec![2, 47])]);
    assert!(matches!(
        reader.probe(100),
        Err(RecordError::RemoteAlert {
            description: 47,
            ..
        })
    ));
    assert_eq!(reader.swallowed_nst_count(), 1);
}

#[test]
fn unknown_buffered_handshake_is_an_error_not_a_panic() {
    let mut reader = records(&[(
        CONTENT_TYPE_HANDSHAKE,
        [ticket(), encode_handshake(11, &[])].concat(),
    )]);
    assert!(reader.read_app_data().is_err());
}

#[test]
fn dtls_reassembly_returns_every_fragment_and_complete_message() {
    use plzn::tls::dtls_handshake::{Reassembler, fragment_message};
    let fragments = fragment_message(20, 0, &[7; 12], 4);
    let next = fragment_message(4, 1, b"ticket", 99).remove(0);
    let mut reassembler = Reassembler::new();
    assert!(
        reassembler
            .accept_record(&next.encode())
            .unwrap()
            .is_empty()
    );
    let wire: Vec<_> = fragments.iter().rev().flat_map(|f| f.encode()).collect();
    let messages = reassembler.accept_record(&wire).unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].body, [7; 12]);
    assert_eq!(messages[1].body, b"ticket");
}
