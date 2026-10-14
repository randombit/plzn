// Schema-checker: walks an AST `File` and flags identifiers the wedge
// schema doesn't recognise. Collects all errors, never bails early.
//
// Error philosophy (DSL.md §3.11 / STRESS_TEST.md §3.2): every error
// carries the offending span, a one-line reason, and — where we have a
// plausible close match — one or more "did you mean?" suggestions.

use crate::ast::*;
use crate::diag::{Diag, suggestions};
use crate::schema;

#[derive(Clone, Debug)]
pub struct CheckError {
    pub span: Span,
    pub category: String,
    pub message: String,
    pub suggestions: Vec<String>,
}

impl CheckError {
    pub fn into_diag(self, source_name: &str, source: &str) -> Diag {
        Diag::new(
            source_name,
            source,
            self.span,
            &self.category,
            self.message,
            self.suggestions,
        )
    }
}

pub fn check(file: &File) -> Vec<CheckError> {
    let mut errs = Vec::new();
    for t in &file.tests {
        check_test(t, &mut errs);
    }
    errs
}

fn check_test(t: &Test, errs: &mut Vec<CheckError>) {
    // Matrix variables are the only binding form; gather them to
    // validate `$var` references later.
    let mut matrix_vars: Vec<&str> = t
        .matrix
        .as_ref()
        .map(|m| m.axes.iter().map(|a| a.var.name.as_str()).collect())
        .unwrap_or_default();
    // T1: `repeat N` binds `$repeat` (the repetition index).
    if t.repeat.is_some() {
        matrix_vars.push("repeat");
    }

    // Require the execution-defining headers on every test. In particular,
    // `chain:` must say explicitly whether the server has no certificate, a
    // run-specific default, or one or more named chains.
    let mut has_chain = false;
    for h in &t.header {
        match h {
            HeaderLine::Rfc { .. } => {}
            HeaderLine::Skip { .. } | HeaderLine::Xfail { .. } => {}
            // A: chain names come from a fixed vocabulary.
            HeaderLine::Chain { client, names, .. } => {
                if !client {
                    has_chain = true;
                }
                for n in names {
                    if !schema::is_chain_name(&n.name) {
                        let sug = suggestions(&n.name, schema::CHAIN_NAMES);
                        errs.push(CheckError {
                            span: n.span,
                            category: "unknown chain".into(),
                            message: format!(
                                "`{}` is not a chain name (default, rsa_2048, rsa_pss, ecdsa_p256, ecdsa_p384, ecdsa_p521, ed25519)",
                                n.name
                            ),
                            suggestions: sug,
                        });
                    }
                }
            }
        }
    }
    if t.uut.is_none() {
        errs.push(CheckError {
            span: t.name.span,
            category: "missing header".into(),
            message: "test has no `uut` block".into(),
            suggestions: vec![],
        });
    }
    if !has_chain {
        errs.push(CheckError {
            span: t.name.span,
            category: "missing header".into(),
            message: "missing required `chain:` line; use `chain: []` for no server certificate, `chain: [default]` for the run-specific default, or name the required certificate chain(s)".into(),
            suggestions: vec![],
        });
    }

    if let Some(m) = &t.matrix {
        check_matrix(m, errs);
    }
    if let Some(uut) = &t.uut {
        check_uut_config(uut, &matrix_vars, errs);
    }
    if let Some(peer) = &t.peer {
        check_peer_config(peer, errs);
        if peer.request_client_cert
            && t.uut
                .as_ref()
                .is_some_and(|uut| uut.role != UutRole::Client)
        {
            errs.push(CheckError {
                span: peer.span,
                category: "peer policy on wrong role".into(),
                message: "`peer.request_client_cert` configures plzn's server and therefore requires `uut client { ... }`".into(),
                suggestions: vec![],
            });
        }
    }
    if let Some(uut) = &t.uut {
        if (uut.require_client_cert || uut.request_client_cert) && uut.role == UutRole::Client {
            errs.push(CheckError {
                span: uut.span,
                category: "UUT policy on wrong role".into(),
                message: "`require_client_cert` and `request_client_cert` configure a UUT server; use `peer { request_client_cert: true }` inside a `uut client` test".into(),
                suggestions: vec![],
            });
        }
        if uut.max_early_data.is_some() && uut.role == UutRole::Client {
            errs.push(CheckError {
                span: uut.span,
                category: "UUT policy on wrong role".into(),
                message: "`max_early_data` configures a UUT server's ticket and acceptance limit; a UUT client sends 0-RTT when the flow contains `recv EarlyData`".into(),
                suggestions: vec![],
            });
        }
    }
    if let Some(flow) = &t.flow {
        check_flow(flow, &matrix_vars, errs);
    }
    if let Some(e) = &t.expect {
        check_expect(e, errs);
    }
    for a in &t.asserts {
        check_assert(a, errs);
    }
    if !t.sessions.is_empty() {
        if t.flow.is_some() || t.expect.is_some() || !t.asserts.is_empty() {
            errs.push(CheckError {
                span: t.span,
                category: "mixed session scopes".into(),
                message: "a test with sessions must put its flow, expect and assertions inside the sessions".into(),
                suggestions: vec![],
            });
        }
        let mut names = std::collections::HashSet::new();
        for session in &t.sessions {
            if let Some(source) = &session.resumes {
                if !names.contains(&source.name) {
                    errs.push(CheckError {
                        span: source.span,
                        category: "invalid resumed session".into(),
                        message: format!("`{}` must name an earlier session", source.name),
                        suggestions: vec![],
                    });
                }
            }
            if !names.insert(session.name.name.clone()) {
                errs.push(CheckError {
                    span: session.name.span,
                    category: "duplicate session".into(),
                    message: format!("duplicate session `{}`", session.name.name),
                    suggestions: vec![],
                });
            }
            check_flow(&session.flow, &matrix_vars, errs);
            check_expect(&session.expect, errs);
            for assertion in &session.asserts {
                check_assert(assertion, errs);
            }
        }
    }
}

fn check_uut_config(uut: &UutBlock, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    if uut.versions.is_empty() {
        errs.push(CheckError {
            span: uut.span,
            category: "missing UUT versions".into(),
            message: "`uut` must declare at least one version, for example `versions: [tls12]`"
                .into(),
            suggestions: vec![],
        });
    }

    let mut saw_tls = false;
    let mut saw_dtls = false;
    let mut seen = std::collections::HashSet::new();
    for version in &uut.versions {
        let VersionRef::Name(version) = version else {
            let VersionRef::Var(var) = version else {
                unreachable!()
            };
            if !matrix_vars.contains(&var.name.as_str()) {
                errs.push(CheckError {
                    span: var.span,
                    category: "unknown matrix var".into(),
                    message: format!("`${}` is not a matrix variable in this test", var.name),
                    suggestions: suggestions(&var.name, matrix_vars),
                });
            }
            continue;
        };
        match version.name.as_str() {
            "tls10" | "tls11" | "tls12" | "tls13" => saw_tls = true,
            "dtls12" | "dtls13" => saw_dtls = true,
            _ => {
                let sug = suggestions(&version.name, schema::VERSIONS);
                errs.push(CheckError {
                    span: version.span,
                    category: "unknown UUT version".into(),
                    message: format!("`{}` is not a supported UUT version", version.name),
                    suggestions: sug,
                });
            }
        }
        if !seen.insert(version.name.as_str()) {
            errs.push(CheckError {
                span: version.span,
                category: "duplicate UUT version".into(),
                message: format!("`{}` appears more than once in `versions`", version.name),
                suggestions: vec![],
            });
        }
    }
    if saw_tls && saw_dtls {
        errs.push(CheckError {
            span: uut.span,
            category: "mixed transport protocols".into(),
            message: "one test cannot mix TLS and DTLS versions in `uut.versions`".into(),
            suggestions: vec![],
        });
    }
    if uut.max_early_data.is_some()
        && !uut.versions.iter().any(|v| {
            matches!(v, VersionRef::Name(id) if id.name == "tls13")
                || matches!(v, VersionRef::Var(_))
        })
    {
        errs.push(CheckError {
            span: uut.span,
            category: "TLS 1.3-only UUT policy".into(),
            message: "`max_early_data` requires `tls13` in `uut.versions`".into(),
            suggestions: vec![],
        });
    }
    if uut.alpn_select.is_some() && !uut.alpn_select_from.is_empty() {
        errs.push(CheckError {
            span: uut.span,
            category: "conflicting UUT policy".into(),
            message: "`alpn_select` and `alpn_select_from` are mutually exclusive".into(),
            suggestions: vec![],
        });
    }
    for (field, types) in [
        ("server_certificate_types", &uut.server_certificate_types),
        ("client_certificate_types", &uut.client_certificate_types),
    ] {
        let mut seen = std::collections::HashSet::new();
        for cert_type in types {
            if schema::cert_type_value(&cert_type.name).is_none() || cert_type.name == "openpgp" {
                errs.push(CheckError {
                    span: cert_type.span,
                    category: "unknown certificate type".into(),
                    message: format!(
                        "`{}` is not a supported RFC 7250 certificate type",
                        cert_type.name
                    ),
                    suggestions: suggestions(&cert_type.name, &["x509", "raw_public_key"]),
                });
            }
            if !seen.insert(cert_type.name.as_str()) {
                errs.push(CheckError {
                    span: cert_type.span,
                    category: "duplicate certificate type".into(),
                    message: format!("`{}` appears more than once in `{}`", cert_type.name, field),
                    suggestions: vec![],
                });
            }
        }
    }
    if uut.raw_public_key
        && (!uut.server_certificate_types.is_empty() || !uut.client_certificate_types.is_empty())
    {
        errs.push(CheckError {
            span: uut.span,
            category: "conflicting UUT policy".into(),
            message: "`raw_public_key` is shorthand for both certificate-type lists and cannot be combined with them".into(),
            suggestions: vec![],
        });
    }
}

fn check_peer_config(peer: &PeerBlock, errs: &mut Vec<CheckError>) {
    for tok in &peer.capabilities {
        if !schema::is_peer_capability(&tok.name) {
            let cands = schema::peer_capability_candidates();
            let sug = suggestions(&tok.name, &cands);
            errs.push(CheckError {
                span: tok.span,
                category: "unknown peer capability".into(),
                message: format!("`{}` is not a known peer capability", tok.name),
                suggestions: sug,
            });
        } else if schema::VERSIONS.contains(&tok.name.as_str()) {
            errs.push(CheckError {
                span: tok.span,
                category: "misplaced UUT version".into(),
                message: format!(
                    "put `{}` in `uut.versions`, not `peer.capabilities`",
                    tok.name
                ),
                suggestions: vec![],
            });
        }
    }
}

fn check_matrix(m: &Matrix, errs: &mut Vec<CheckError>) {
    for axis in &m.axes {
        if let MatrixValues::Named { name, .. } = &axis.values {
            if !schema::is_matrix_named_set(&name.name) {
                errs.push(CheckError {
                    span: name.span,
                    category: "unknown matrix set".into(),
                    message: format!("`{}` is not a known matrix set", name.name),
                    suggestions: vec![],
                });
            }
        }
    }
}

fn check_ext_delta(d: &ExtDelta, errs: &mut Vec<CheckError>) {
    let target = match d {
        ExtDelta::Add { target, .. } => target,
        ExtDelta::Remove { target, .. } => target,
        // Reverse has no target to schema-check; T1: `each` ranges are numeric.
        ExtDelta::Reverse { .. } | ExtDelta::AddEach { .. } => return,
    };
    // Only validate named targets; wire-numeric is opaque by design.
    if let ExtTarget::Named(name) = target {
        if !schema::is_extension(&name.name) {
            let cands: Vec<&str> = schema::EXTENSIONS.to_vec();
            let sug = suggestions(&name.name, &cands);
            errs.push(CheckError {
                span: name.span,
                category: "unknown extension".into(),
                message: format!("`{}` is not a known TLS extension", name.name),
                suggestions: sug,
            });
        }
    }
}

fn check_flow(flow: &Flow, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    if let Some(p) = &flow.preset {
        if p.base.name != "handshake" {
            errs.push(CheckError {
                span: p.base.span,
                category: "unknown preset".into(),
                message: format!(
                    "`{}` is not a known flow preset (only `handshake` is in v1)",
                    p.base.name
                ),
                suggestions: vec![],
            });
        }
        if let Some(a) = &p.anchor {
            if !schema::is_message(&a.msg.name) {
                let sug = suggestions(&a.msg.name, schema::MESSAGES);
                errs.push(CheckError {
                    span: a.msg.span,
                    category: "unknown message".into(),
                    message: format!("`{}` is not a known TLS message", a.msg.name),
                    suggestions: sug,
                });
            }
        }
    }
    for s in &flow.steps {
        check_step(s, matrix_vars, errs);
    }
}

fn check_step(s: &Step, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    match s {
        Step::Send {
            msgs,
            overrides,
            mutations,
            ext_deltas,
            ..
        } => {
            for m in msgs {
                check_message_ref(m, errs);
            }
            if let Some(first_msg) = msgs.first() {
                for ov in overrides {
                    check_field_override(&first_msg.name.name, ov, matrix_vars, errs);
                }
            }
            for mu in mutations {
                check_mutation(mu, matrix_vars, errs);
            }
            for d in ext_deltas {
                check_ext_delta(d, errs);
            }
        }
        Step::Recv {
            msgs,
            matchers,
            ext_matchers,
            ..
        } => {
            for m in msgs {
                check_message_ref(m, errs);
            }
            if let Some(first_msg) = msgs.first() {
                for ov in matchers {
                    check_field_override(&first_msg.name.name, ov, matrix_vars, errs);
                }
            }
            // T2: `ext NAME == value` matchers name a known extension.
            for em in ext_matchers {
                if let ExtTarget::Named(name) = &em.target {
                    if !schema::is_extension(&name.name) {
                        let cands: Vec<&str> = schema::EXTENSIONS.to_vec();
                        let sug = suggestions(&name.name, &cands);
                        errs.push(CheckError {
                            span: name.span,
                            category: "unknown extension".into(),
                            message: format!("`{}` is not a known TLS extension", name.name),
                            suggestions: sug,
                        });
                    }
                }
            }
        }
        // T1: repeat blocks recurse; `recv alert` checks its alert spec.
        Step::Repeat { count, steps, .. } => {
            check_int_or_var(count, matrix_vars, errs);
            for inner in steps {
                check_step(inner, matrix_vars, errs);
            }
        }
        Step::RecvAlert { alert, .. } => check_alert_spec(alert, errs),
        Step::SendRaw { .. } => {}
        Step::SendAlert { mutations, .. }
        | Step::SendEmptyRecord { mutations, .. }
        | Step::SendRecord { mutations, .. } => {
            for mu in mutations {
                check_mutation(mu, matrix_vars, errs);
            }
        }
        // Lowering validates the alert level/code of `send alert` and the DTLS
        // flight steps carry no names to check.
        Step::Dtls { .. }
        | Step::CoalesceBegin { .. }
        | Step::AtomicBegin { .. }
        | Step::AtomicEnd { .. }
        | Step::CoalesceEnd { .. }
        | Step::FlushFragment { .. } => {}
        Step::Close { alert, .. } => {
            if let Some(a) = alert {
                check_alert_spec(a, errs);
            }
        }
        Step::Wait { .. }
        | Step::AdvanceClock { .. }
        | Step::ExpectNextTimeout { .. }
        | Step::ExpectNoTimeout { .. }
        | Step::SetTimeout { .. }
        | Step::ExpectRetransmit { .. }
        | Step::RotateCookieSecret { .. }
        | Step::ResendFlight { .. }
        | Step::Renegotiate { .. } => {} // nothing to schema-check
    }
}

fn check_message_ref(m: &MessageRef, errs: &mut Vec<CheckError>) {
    if !schema::is_message(&m.name.name) {
        let sug = suggestions(&m.name.name, schema::MESSAGES);
        errs.push(CheckError {
            span: m.name.span,
            category: "unknown message".into(),
            message: format!("`{}` is not a known TLS message", m.name.name),
            suggestions: sug,
        });
    }
}

fn check_field_override(
    msg_name: &str,
    ov: &FieldOverride,
    matrix_vars: &[&str],
    errs: &mut Vec<CheckError>,
) {
    let allowed = schema::field_names_for(msg_name);
    if !allowed.is_empty() && !allowed.iter().any(|n| *n == ov.field.name) {
        errs.push(CheckError {
            span: ov.field.span,
            category: "unknown field".into(),
            message: format!("`{}` is not a known field of `{}`", ov.field.name, msg_name),
            suggestions: suggestions(&ov.field.name, &allowed),
        });
    }
    check_field_value(&ov.value, matrix_vars, errs);
}

fn check_field_value(v: &FieldValue, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    match v {
        FieldValue::Int(_)
        | FieldValue::Str(_)
        | FieldValue::File(_)
        | FieldValue::Empty
        | FieldValue::Capture(_) => {}
        // T1 generators: the counts and bounds may be matrix variables.
        FieldValue::Range { lo, hi, .. } => {
            check_int_or_var(lo, matrix_vars, errs);
            check_int_or_var(hi, matrix_vars, errs);
        }
        FieldValue::Repeat { item, count, .. } => {
            check_int_or_var(count, matrix_vars, errs);
            check_field_value(item, matrix_vars, errs);
        }
        FieldValue::Entry { key, value, .. } => {
            check_field_value(key, matrix_vars, errs);
            check_field_value(value, matrix_vars, errs);
        }
        FieldValue::Ident(id) => {
            if !schema::is_field_value_ident(&id.name) {
                // Not fatal — may be a user-defined label. Leave as warning.
                // For the wedge we simply don't error here.
            }
        }
        FieldValue::List(items) => {
            for it in items {
                check_field_value(it, matrix_vars, errs);
            }
        }
        FieldValue::MatrixVar(id) => {
            if !matrix_vars.contains(&id.name.as_str()) {
                errs.push(CheckError {
                    span: id.span,
                    category: "unknown matrix var".into(),
                    message: format!("`${}` is not a matrix variable in this test", id.name),
                    suggestions: suggestions(&id.name, matrix_vars),
                });
            }
        }
    }
}

fn check_mutation(mu: &Mutation, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    match &mu.op {
        MutationOp::Xor { target, value } | MutationOp::Set { target, value } => {
            check_byte_target(target, matrix_vars, errs);
            check_mut_value(value, matrix_vars, errs);
        }
        MutationOp::Add { target, value } | MutationOp::Sub { target, value } => {
            let parts: Vec<&str> = target.parts.iter().map(|p| p.name.as_str()).collect();
            if !schema::is_length_path(&parts) {
                let candidates = schema::length_path_candidates();
                let refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
                errs.push(CheckError {
                    span: target.span,
                    category: "unknown length field".into(),
                    message: format!("`{}` is not a named integer length field", parts.join(".")),
                    suggestions: suggestions(&parts.join("."), &refs),
                });
            }
            check_mut_value(value, matrix_vars, errs);
        }
        MutationOp::Fragment { n, .. }
        | MutationOp::PadPlus { n, .. }
        | MutationOp::PadMinus { n }
        | MutationOp::Truncate { n }
        | MutationOp::OmitPrefix { n } => check_mut_value(n, matrix_vars, errs),
        // T2: value ranges are checked at lowering.
        MutationOp::PadBytes { .. }
        | MutationOp::TrailingBytes { .. }
        | MutationOp::RecordVersion { .. }
        | MutationOp::RecordPad { .. }
        | MutationOp::Dtls13ShortSequence
        | MutationOp::Dtls13OmitLength
        | MutationOp::Dtls13SetCidBit
        | MutationOp::Dtls13LegacyHeader
        | MutationOp::Plaintext { .. }
        | MutationOp::CbcPad { .. }
        | MutationOp::Reorder { .. } => {}
    }
}

fn check_byte_target(t: &ByteTarget, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    if let Some(p) = &t.path {
        let parts: Vec<&str> = p.parts.iter().map(|i| i.name.as_str()).collect();
        if !schema::is_byte_path(&parts) {
            let cands = schema::byte_path_candidates();
            let cands_ref: Vec<&str> = cands.iter().map(|s| s.as_str()).collect();
            errs.push(CheckError {
                span: p.span,
                category: "unknown byte path".into(),
                message: format!(
                    "`{}` is not a known structured byte target",
                    parts.join(".")
                ),
                suggestions: suggestions(&parts.join("."), &cands_ref),
            });
        }
    }
    match &t.index {
        ByteIndex::Single(v) => check_int_or_var(v, matrix_vars, errs),
        ByteIndex::Range { lo, hi } => {
            check_int_or_var(lo, matrix_vars, errs);
            check_int_or_var(hi, matrix_vars, errs);
        }
    }
}

fn check_int_or_var(v: &IntOrVar, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    if let IntOrVar::Var(id) | IntOrVar::VarOffset { var: id, .. } = v {
        if !matrix_vars.contains(&id.name.as_str()) {
            errs.push(CheckError {
                span: id.span,
                category: "unknown matrix var".into(),
                message: format!("`${}` is not a matrix variable in this test", id.name),
                suggestions: suggestions(&id.name, matrix_vars),
            });
        }
    }
}

fn check_mut_value(v: &MutValue, matrix_vars: &[&str], errs: &mut Vec<CheckError>) {
    if let MutValue::Var(id) = v {
        if !matrix_vars.contains(&id.name.as_str()) {
            errs.push(CheckError {
                span: id.span,
                category: "unknown matrix var".into(),
                message: format!("`${}` is not a matrix variable in this test", id.name),
                suggestions: suggestions(&id.name, matrix_vars),
            });
        }
    }
}

fn check_alert_spec(a: &AlertSpec, errs: &mut Vec<CheckError>) {
    if !schema::is_alert_level(&a.level.name) {
        errs.push(CheckError {
            span: a.level.span,
            category: "bad alert level".into(),
            message: format!("`{}` is not a valid alert level", a.level.name),
            suggestions: suggestions(&a.level.name, &schema::alert_level_name_list()),
        });
    }
    if let Some(code) = &a.code {
        if !schema::is_alert_code(&code.name) {
            errs.push(CheckError {
                span: code.span,
                category: "bad alert code".into(),
                message: format!("`{}` is not a valid alert code", code.name),
                suggestions: suggestions(&code.name, &schema::alert_code_name_list()),
            });
        }
    }
}

fn check_expect(e: &Expect, errs: &mut Vec<CheckError>) {
    fn check_kind(kind: &ExpectKind, errs: &mut Vec<CheckError>) {
        match kind {
            ExpectKind::Any(alternatives) => {
                for alternative in alternatives {
                    check_kind(alternative, errs);
                }
            }
            ExpectKind::Alert { level, codes } | ExpectKind::Reject { level, codes } => {
                if !schema::is_alert_level(&level.name) {
                    errs.push(CheckError {
                        span: level.span,
                        category: "bad alert level".into(),
                        message: format!("`{}` is not a valid alert level", level.name),
                        suggestions: suggestions(&level.name, &schema::alert_level_name_list()),
                    });
                }
                for c in codes {
                    if !schema::is_alert_code(&c.name) {
                        errs.push(CheckError {
                            span: c.span,
                            category: "bad alert code".into(),
                            message: format!("`{}` is not a valid alert code", c.name),
                            suggestions: suggestions(&c.name, &schema::alert_code_name_list()),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    check_kind(&e.kind, errs);
}

fn check_assert(a: &AssertLine, errs: &mut Vec<CheckError>) {
    match &a.kind {
        AssertKind::Named(id) => {
            if !schema::is_named_assert(&id.name) {
                errs.push(CheckError {
                    span: id.span,
                    category: "unknown named assert".into(),
                    message: format!("`{}` is not a known named assert", id.name),
                    suggestions: suggestions(&id.name, schema::NAMED_ASSERTS),
                });
            }
        }
        AssertKind::Eq { .. } => {
            // No schema check on free-form path-equality asserts in the wedge.
        }
        AssertKind::MaxDatagramSize(_) => {}
        // T1: `assert unique $x` -- lowering checks the names are captured.
        AssertKind::Unique(_) => {}
    }
}
