//! Typed mutation candidates and reproducible source generation for
//! differential discovery campaigns.

use serde::Serialize;

use crate::ir::{MessageKind, Program, Protocol, Subject};
use crate::tls::record::TlsVersion;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationValidity {
    Preserving,
    Invalid,
    Exploratory,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MutationCandidate {
    pub id: String,
    pub message: String,
    pub syntax: String,
    pub validity: MutationValidity,
    pub expected: &'static str,
}

impl MutationCandidate {
    fn new(
        message: MessageKind,
        suffix: &str,
        syntax: &str,
        validity: MutationValidity,
        expected: &'static str,
    ) -> Self {
        Self {
            id: format!("{}-{suffix}", snake_case(message.name())),
            message: message.name().into(),
            syntax: syntax.into(),
            validity,
            expected,
        }
    }

    pub fn flow_line(&self) -> String {
        format!("send {} @ {}", self.message, self.syntax)
    }
}

/// Enumerate deterministic, single-operation mutations for the messages the
/// lowering pass says this concrete program sends. Structural and
/// validity-preserving probes come before arbitrary content corruption.
pub fn candidates(program: &Program, budget: usize) -> Vec<MutationCandidate> {
    let mut out = Vec::new();
    for &message in &program.mutation_messages {
        if !is_discovery_target(program, message) {
            continue;
        }
        let mut push = |suffix, syntax, validity, expected| {
            if out.len() < budget {
                out.push(MutationCandidate::new(
                    message, suffix, syntax, validity, expected,
                ));
            }
        };

        push(
            "fragment-1",
            "fragment 1",
            MutationValidity::Preserving,
            "accept",
        );
        if program.protocol == Protocol::Dtls {
            push(
                "duplicate-fragment-1",
                "duplicate_fragment 1",
                MutationValidity::Preserving,
                "accept",
            );
            push(
                "reorder-overlap-8",
                "reorder_overlap 8",
                MutationValidity::Preserving,
                "accept",
            );
        }
        if program.version == TlsVersion::Tls13 && uses_tls13_ciphertext(message) {
            push(
                "record-pad-1",
                "record_pad 1",
                MutationValidity::Preserving,
                "accept",
            );
            if program.protocol == Protocol::Dtls {
                push(
                    "dtls13-short-sequence",
                    "dtls13_short_sequence",
                    MutationValidity::Preserving,
                    "accept",
                );
                push(
                    "dtls13-omit-length",
                    "dtls13_omit_length",
                    MutationValidity::Preserving,
                    "accept",
                );
            }
        }
        push(
            "length-plus-1",
            "add[handshake.length] = 1",
            MutationValidity::Invalid,
            "reject",
        );
        push(
            "length-minus-1",
            "sub[handshake.length] = 1",
            MutationValidity::Invalid,
            "reject",
        );
        if has_nonempty_body(message) {
            push(
                "xor-last",
                "xor[-1] = 1",
                MutationValidity::Exploratory,
                "compare",
            );
        }
        push(
            "pad-plus-1",
            "pad +1 0xff",
            MutationValidity::Invalid,
            "reject",
        );
        if has_nonempty_body(message) {
            push("pad-minus-1", "pad -1", MutationValidity::Invalid, "reject");
        }
        if program.protocol == Protocol::Dtls
            && program.version == TlsVersion::Tls13
            && uses_tls13_ciphertext(message)
        {
            push(
                "dtls13-set-cid-bit",
                "dtls13_set_cid_bit",
                MutationValidity::Invalid,
                "reject",
            );
            push(
                "dtls13-legacy-header",
                "dtls13_legacy_header",
                MutationValidity::Invalid,
                "reject",
            );
        }
        if program.protocol == Protocol::Tls {
            push(
                "trailing-byte",
                "trailing \"00\"",
                MutationValidity::Invalid,
                "reject",
            );
            push(
                "record-version-ffff",
                "record_version 0xffff",
                MutationValidity::Exploratory,
                "compare",
            );
        }
        if out.len() >= budget {
            break;
        }
    }
    out
}

/// Insert a generated `send Message @ mutation` override immediately after
/// the opening brace of an unanchored `flow handshake` block. The caller
/// reparses and formats the result, so every artifact exercises the ordinary
/// DSL pipeline rather than a discovery-only IR shortcut.
pub fn inject_flow_mutation(
    test_source: &str,
    flow_open_offset: usize,
    candidate: &MutationCandidate,
) -> Result<String, String> {
    if flow_open_offset >= test_source.len() || !test_source[flow_open_offset..].starts_with('{') {
        return Err("flow opening brace offset does not point at `{`".into());
    }
    let mut generated = String::with_capacity(test_source.len() + candidate.syntax.len() + 32);
    generated.push_str(&test_source[..=flow_open_offset]);
    generated.push('\n');
    generated.push_str("    ");
    generated.push_str(&candidate.flow_line());
    generated.push('\n');
    let rest = &test_source[flow_open_offset + 1..];
    let rest = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))
        .unwrap_or(rest);
    generated.push_str(rest);
    Ok(generated)
}

pub fn artifact_slug(test_id: &str, mutation_id: &str) -> String {
    format!("{test_id}-{mutation_id}")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn is_discovery_target(program: &Program, message: MessageKind) -> bool {
    if matches!(
        message,
        MessageKind::ChangeCipherSpec
            | MessageKind::Alert
            | MessageKind::AppData
            | MessageKind::EarlyData
            | MessageKind::Heartbeat
            // These are explicit post-handshake steps, not message overrides;
            // inserting another one would duplicate rather than mutate them.
            | MessageKind::KeyUpdate
            | MessageKind::HelloRequest
            | MessageKind::NewSessionTicket
            // Both ClientHello occurrences have the same surface syntax. Do
            // not claim to target CH2 until occurrence selectors exist.
            | MessageKind::ClientHelloRetry
    ) {
        return false;
    }
    // The DTLS 1.2 client uses the same MessageKind for its cookie-less and
    // cookie-bearing ClientHellos; one override currently mutates both.
    !(program.protocol == Protocol::Dtls
        && program.version == TlsVersion::Tls12
        && program.subject == Subject::Server
        && message == MessageKind::ClientHello)
}

fn uses_tls13_ciphertext(message: MessageKind) -> bool {
    !matches!(
        message,
        MessageKind::ClientHello
            | MessageKind::ClientHelloRetry
            | MessageKind::ServerHello
            | MessageKind::HelloRetryRequest
    )
}

fn has_nonempty_body(message: MessageKind) -> bool {
    !matches!(
        message,
        MessageKind::ServerHelloDone | MessageKind::HelloRequest | MessageKind::EndOfEarlyData
    )
}

fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index != 0 {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower_one(source: &str) -> (crate::ast::Test, Program) {
        let tokens = crate::lex::lex(source).unwrap();
        let file = crate::parse::parse(&tokens).unwrap();
        assert!(crate::check::check(&file).is_empty());
        let test = file.tests[0].clone();
        let program = crate::lower::lower(&test).unwrap().remove(0);
        (test, program)
    }

    #[test]
    fn tls13_server_seed_has_typed_candidates_in_priority_order() {
        let source = r#"plzn tls "seed" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;
        let (_, program) = lower_one(source);
        let got = candidates(&program, 100);
        assert_eq!(got[0].id, "client-hello-fragment-1");
        assert_eq!(got[0].validity, MutationValidity::Preserving);
        assert!(got.iter().any(|c| c.id == "finished-length-plus-1"));
        assert!(got.iter().any(|c| c.id == "finished-record-pad-1"));
    }

    #[test]
    fn generated_source_uses_the_normal_parser_and_lowerer() {
        let source = r#"plzn tls "seed" {
  chain: [default]
  uut server { versions: [tls12] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}"#;
        let (test, program) = lower_one(source);
        let candidate = candidates(&program, 100)
            .into_iter()
            .find(|candidate| candidate.id == "finished-length-plus-1")
            .unwrap();
        let flow = test.flow.unwrap();
        let relative_start = flow.span.start - test.span.start;
        let open = relative_start + source[relative_start..].find('{').unwrap();
        let generated = inject_flow_mutation(source, open, &candidate).unwrap();
        assert!(
            generated.find(&candidate.flow_line()).unwrap()
                < generated.find("send AppData").unwrap()
        );
        let (_, generated_program) = lower_one(&generated);
        assert!(generated_program.send_mutations.iter().any(|entry| {
            entry.message == MessageKind::Finished && !entry.mutations.is_empty()
        }));
    }

    #[test]
    fn dtls13_candidates_cover_valid_and_invalid_unified_headers() {
        let source = r#"plzn tls "seed" {
  chain: [default]
  uut server { versions: [dtls13] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#;
        let (_, program) = lower_one(source);
        let got = candidates(&program, 100);
        assert!(got.iter().any(|c| c.id == "finished-dtls13-short-sequence"));
        assert!(got.iter().any(|c| c.id == "finished-dtls13-omit-length"));
        assert!(got.iter().any(|c| c.id == "finished-dtls13-set-cid-bit"));
        assert!(got.iter().any(|c| c.id == "finished-dtls13-legacy-header"));
    }

    #[test]
    fn retry_client_hello_waits_for_occurrence_selectors() {
        let source = r#"plzn tls "seed" {
  chain: [default]
  uut server { versions: [tls13] }
  flow handshake { close }
  expect ok
}"#;
        let (_, program) = lower_one(source);
        assert!(!is_discovery_target(
            &program,
            MessageKind::ClientHelloRetry
        ));
    }

    #[test]
    fn dtls12_cookie_client_hellos_wait_for_occurrence_selectors() {
        let source = r#"plzn tls "seed" {
  chain: [default]
  uut server { versions: [dtls12] }
  flow handshake {}
  expect ok
}"#;
        let (_, program) = lower_one(source);
        assert!(
            candidates(&program, 100)
                .iter()
                .all(|candidate| candidate.message != "ClientHello")
        );
    }
}
