// AST → IR lowering.
//
// Accepts a parsed `ast::Test` and emits an `ir::Program` with
// preset/matrix/override machinery resolved. For this wedge we
// Semantic failures become `LowerError`s with source spans so the caller can
// render clean diagnostics.
//
// Lowering errors are collected rather than failed-fast, the same
// philosophy as the schema checker — one lint/lower pass should
// surface every problem in a test file.

use crate::ast::{self, AssertKind, ExpectKind, HeaderLine, MessageRef, Span, Test, UutRole};
use crate::diag::Diag;
use crate::ir::{
    self, AlertLevel, Expectation, FieldOverride, FieldValue, MessageKind, MessageOverrides,
    MutationOp, Program, ResolvedByteTarget, RfcRef, Step, Subject,
};
use crate::schema::{self, FieldType};
use crate::tls::record::TlsVersion;

#[derive(Clone, Debug)]
pub struct LowerError {
    pub span: Span,
    pub message: String,
}

impl LowerError {
    pub fn into_diag(self, source_name: &str, source: &str) -> Diag {
        Diag::from_simple(source_name, source, self.span, "lower error", self.message)
    }
}

/// A concrete assignment of matrix variables to integer values.
/// Stored as a Vec so iteration order matches the source-order of
/// axes in the `matrix { ... }` block, which keeps case-suffix
/// formatting stable and deterministic.
type Binding = Vec<(String, i64)>;

type ExporterParams = (Vec<u8>, Option<Vec<u8>>, usize);

fn lookup_binding(b: &[(String, i64)], name: &str) -> Option<i64> {
    b.iter()
        .find_map(|(n, v)| if *n == name { Some(*v) } else { None })
}

fn expectation_kind_contains_timeout(kind: &ExpectKind) -> bool {
    match kind {
        ExpectKind::Timeout => true,
        ExpectKind::Any(alternatives) => alternatives.iter().any(expectation_kind_contains_timeout),
        _ => false,
    }
}

fn lower_expect_kind(kind: &ExpectKind, errors: &mut Vec<LowerError>) -> Option<Expectation> {
    match kind {
        ExpectKind::Ok => Some(Expectation::Ok),
        ExpectKind::Close => Some(Expectation::Close),
        ExpectKind::Reset => Some(Expectation::Reset),
        ExpectKind::HandshakeFails => Some(Expectation::HandshakeFails),
        ExpectKind::Timeout => Some(Expectation::Timeout),
        ExpectKind::Any(alternatives) => {
            let lowered: Vec<_> = alternatives
                .iter()
                .filter_map(|alternative| lower_expect_kind(alternative, errors))
                .collect();
            (lowered.len() == alternatives.len()).then_some(Expectation::Any(lowered))
        }
        ExpectKind::Alert { level, codes } | ExpectKind::Reject { level, codes } => {
            let alert_level = match level.name.as_str() {
                "warning" => AlertLevel::Warning,
                "fatal" => AlertLevel::Fatal,
                other => {
                    errors.push(LowerError {
                        span: level.span,
                        message: format!(
                            "alert level must be `warning` or `fatal`, got `{}`",
                            other
                        ),
                    });
                    return None;
                }
            };
            let mut code_values: Vec<u8> = Vec::new();
            for c in codes {
                match schema::alert_code_value(&c.name) {
                    Some(v) => code_values.push(v),
                    None => errors.push(LowerError {
                        span: c.span,
                        message: format!("unknown alert code `{}`", c.name),
                    }),
                }
            }
            Some(match kind {
                ExpectKind::Reject { .. } => Expectation::Reject {
                    level: alert_level,
                    codes: code_values,
                },
                _ => Expectation::Alert {
                    level: alert_level,
                    codes: code_values,
                },
            })
        }
    }
}

fn format_case_suffix(binding: &[(String, i64)]) -> String {
    if binding.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = binding
        .iter()
        .map(|(name, value)| {
            let rendered = match name.as_str() {
                "suite" => format_named_wire_value(*value, schema::suite_name),
                "group" => format_named_wire_value(*value, schema::group_name),
                "scheme" => format_named_wire_value(*value, schema::sigalg_name),
                "version" => version_name_for_wire(*value)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("0x{value:04x}")),
                "grease" => u16::try_from(*value)
                    .map(|wire| format!("0x{wire:04x}"))
                    .unwrap_or_else(|_| value.to_string()),
                _ => value.to_string(),
            };
            format!("{name}={rendered}")
        })
        .collect();
    format!("[{}]", parts.join(","))
}

fn format_named_wire_value(value: i64, name_for_wire: fn(u16) -> Option<&'static str>) -> String {
    match u16::try_from(value) {
        Ok(wire) => name_for_wire(wire)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("0x{wire:04x}")),
        Err(_) => value.to_string(),
    }
}

fn version_name_for_wire(value: i64) -> Option<&'static str> {
    match value {
        0x0301 => Some("tls10"),
        0x0302 => Some("tls11"),
        0x0303 => Some("tls12"),
        0x0304 => Some("tls13"),
        0xfefd => Some("dtls12"),
        0xfefc => Some("dtls13"),
        _ => None,
    }
}

/// Enumerate every concrete binding produced by the test's matrix
/// block, as the cartesian product of the axes' value lists. A
/// test with no matrix produces one empty binding. A test with
/// a `matrix { pos in [1, 2]  bit in [0x01, 0x80] }` produces
/// four bindings.
fn enumerate_matrix_bindings(test: &Test) -> Result<Vec<Binding>, Vec<LowerError>> {
    let mut errors: Vec<LowerError> = Vec::new();
    let mut axes: Vec<(String, Vec<i64>)> = Vec::new();
    let no_axes: Vec<ast::MatrixAxis> = Vec::new();
    let matrix_axes = match &test.matrix {
        Some(m) => &m.axes,
        None => &no_axes,
    };
    for axis in matrix_axes {
        match &axis.values {
            ast::MatrixValues::Range { lo, hi, step, .. } => {
                if lo.value > hi.value {
                    errors.push(LowerError {
                        span: axis.span,
                        message: format!(
                            "matrix range `{}..{}` is empty; lo must be <= hi",
                            lo.value, hi.value
                        ),
                    });
                    continue;
                }
                let st = step.map(|s| s.value).unwrap_or(1).max(1) as usize;
                let values: Vec<i64> = (lo.value..=hi.value).step_by(st).collect();
                axes.push((axis.var.name.clone(), values));
            }
            ast::MatrixValues::List { items, .. } => {
                // T1: `[a, b, lo..hi]` -- ranges expand inclusively.
                let mut values: Vec<i64> = Vec::new();
                for it in items {
                    match it {
                        ast::MatrixItem::Int(i) => values.push(i.value),
                        ast::MatrixItem::Range { lo, hi } => values.extend(lo.value..=hi.value),
                        // D: a name resolved against every table; it must be
                        // unambiguous (`ed25519` is a scheme, `x25519` a group).
                        ast::MatrixItem::Name(id) => match resolve_matrix_name(&id.name) {
                            Ok(v) => values.push(v),
                            Err(msg) => errors.push(LowerError {
                                span: id.span,
                                message: msg,
                            }),
                        },
                    }
                }
                axes.push((axis.var.name.clone(), values));
            }
            ast::MatrixValues::Named { name, arg, span } => {
                match (name.name.as_str(), arg.as_ref().map(|a| a.name.as_str())) {
                    ("cipher_suites", Some(v @ ("tls10" | "tls11" | "tls12"))) => {
                        let version = match v {
                            "tls10" => crate::tls::record::TlsVersion::Tls10,
                            "tls11" => crate::tls::record::TlsVersion::Tls11,
                            _ => crate::tls::record::TlsVersion::Tls12,
                        };
                        let values: Vec<i64> = ir::ALL_SUITES
                            .iter()
                            .filter(|s| ir::suite_supports_version(s, version))
                            .map(|s| s.wire as i64)
                            .collect();
                        axes.push((axis.var.name.clone(), values));
                    }
                    ("cipher_suites", Some("tls13")) => {
                        let values: Vec<i64> = ir::ALL_SUITES
                            .iter()
                            .filter(|s| s.version == crate::tls::record::TlsVersion::Tls13)
                            .map(|s| s.wire as i64)
                            .collect();
                        axes.push((axis.var.name.clone(), values));
                    }
                    ("cert_models", None) => {
                        // 0 = ecdsa-p256, 1 = rsa-2048
                        axes.push((axis.var.name.clone(), vec![0, 1]));
                    }
                    ("grease", None) => {
                        axes.push((
                            axis.var.name.clone(),
                            schema::GREASE_VALUES.iter().map(|v| *v as i64).collect(),
                        ));
                    }
                    // The groups EVERY backend implements (x25519, secp256r1,
                    // secp384r1), so a sweep runs three-library. plzn can also
                    // key-share secp521r1 and ffdhe2048/3072, but rustls's ring
                    // provider has neither, and a matrix cannot skip one value per
                    // backend; those get their own `skip rustls` cases. A `group`
                    // axis pins supported_groups and the key share to one group.
                    ("groups", Some("tls13")) => {
                        axes.push((axis.var.name.clone(), vec![0x001d, 0x0017, 0x0018]));
                    }
                    ("groups", Some("tls10" | "tls11" | "tls12")) => {
                        axes.push((axis.var.name.clone(), vec![0x001d, 0x0017]));
                    }
                    (other, _) => {
                        errors.push(LowerError {
                            span: *span,
                            message: format!(
                                "unknown matrix catalogue `{}`; supported: \
                                 `cipher_suites(tls10|tls11|tls12|tls13)`, \
                                 `cert_models()`, `groups(tls10|tls11|tls12|tls13)`, `grease`",
                                other
                            ),
                        });
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    // T1: `repeat N` is an implicit last axis `$repeat` in 0..N, so every
    // repetition is its own program (its own test id, hence its own seed).
    if let Some(n) = &test.repeat {
        axes.push(("repeat".to_string(), (0..n.value).collect()));
    }
    // Cartesian product across axes, keeping source-order so the
    // resulting case suffix reads the same way the test was written.
    let mut out: Vec<Binding> = vec![Vec::new()];
    for (name, values) in axes {
        let mut next: Vec<Binding> = Vec::new();
        for b in &out {
            for v in &values {
                let mut b2 = b.clone();
                b2.push((name.clone(), *v));
                next.push(b2);
            }
        }
        out = next;
    }
    Ok(out)
}

/// Lower a single test. Matrix tests produce one `Program` per
/// case; tests without a matrix produce a single-element Vec.
/// Errors are collected across all cases and deduplicated — a
/// structural error (like "unsupported expect") would otherwise
/// get reported N times, once per binding.
pub fn lower(test: &Test) -> Result<Vec<Program>, Vec<LowerError>> {
    // D: a known cipher suite / group / scheme / extension type written as a
    // number is a lint error wherever it appears; the rest of lowering still
    // runs so every other diagnostic is reported alongside.
    let audit = audit_named_literals(test);
    let lowered = lower_inner(test);
    if audit.is_empty() {
        return lowered;
    }
    let mut errors = audit;
    if let Err(more) = lowered {
        errors.extend(more);
    }
    Err(errors)
}

fn lower_inner(test: &Test) -> Result<Vec<Program>, Vec<LowerError>> {
    // Multi-session tests: each session block produces one Program.
    if !test.sessions.is_empty() {
        return lower_sessions(test);
    }
    let bindings = enumerate_matrix_bindings(test)?;
    let mut programs: Vec<Program> = Vec::new();
    let mut errors: Vec<LowerError> = Vec::new();
    let mut seen_errors: std::collections::HashSet<(usize, usize, String)> =
        std::collections::HashSet::new();
    for binding in &bindings {
        match lower_with_binding(test, binding, false) {
            Ok(p) => programs.push(p),
            Err(errs) => {
                for e in errs {
                    let key = (e.span.start, e.span.end, e.message.clone());
                    if seen_errors.insert(key) {
                        errors.push(e);
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(programs)
}

fn lower_sessions(test: &Test) -> Result<Vec<Program>, Vec<LowerError>> {
    let mut programs = Vec::new();
    let mut errors = Vec::new();
    let bindings = enumerate_matrix_bindings(test)?;
    let mut seen_errors: std::collections::HashSet<(usize, usize, String)> =
        std::collections::HashSet::new();
    // Sessions that a later session resumes: their initial handshake must
    // advertise psk_key_exchange_modes so the server issues a ticket.
    let resumed_targets: std::collections::HashSet<String> = test
        .sessions
        .iter()
        .filter_map(|s| s.resumes.as_ref().map(|r| r.name.clone()))
        .collect();
    let default_version = test
        .uut
        .as_ref()
        .and_then(|uut| uut.versions.first())
        .and_then(|v| match v {
            ast::VersionRef::Name(id) => Some(id.name.as_str()),
            ast::VersionRef::Var(_) => None,
        });
    // Keep each matrix point's complete session sequence adjacent. The runners
    // split this flat result into chunks of `test.sessions.len()` and launch a
    // fresh shim for every point, so tickets and cached shim sessions cannot
    // leak from one suite/group combination into another.
    for binding in &bindings {
        for sess in &test.sessions {
            if sess.force_resume {
                let Some(source_name) = sess.resumes.as_ref() else {
                    errors.push(LowerError {
                        span: sess.span,
                        message: "`force_resume: true` requires `resumes: <session>`".into(),
                    });
                    continue;
                };
                let Some(source) = test
                    .sessions
                    .iter()
                    .find(|candidate| candidate.name.name == source_name.name)
                else {
                    errors.push(LowerError {
                        span: source_name.span,
                        message: format!("unknown resumed session `{}`", source_name.name),
                    });
                    continue;
                };
                let source_version = source
                    .version
                    .as_ref()
                    .map(|v| v.name.as_str())
                    .or(default_version);
                let target_version = sess
                    .version
                    .as_ref()
                    .map(|v| v.name.as_str())
                    .or(default_version);
                if source_version == target_version {
                    errors.push(LowerError {
                        span: sess.span,
                        message: "`force_resume: true` is only for cross-version resumption".into(),
                    });
                    continue;
                }
                if !test
                    .uut
                    .as_ref()
                    .is_some_and(|uut| uut.role == ast::UutRole::Client)
                {
                    errors.push(LowerError {
                        span: sess.span,
                        message: "`force_resume: true` requires `uut client`; plzn's server is the peer that makes the false resumption claim".into(),
                    });
                    continue;
                }
            }
            let mut session_uut = test.uut.clone();
            if let Some(wanted) = &sess.version {
                let Some(uut) = session_uut.as_mut() else {
                    errors.push(LowerError {
                        span: wanted.span,
                        message: "a session version requires the test's `uut client|server` block"
                            .into(),
                    });
                    continue;
                };
                let Some(index) = uut
                    .versions
                    .iter()
                    .position(|v| matches!(v, ast::VersionRef::Name(id) if id.name == wanted.name))
                else {
                    errors.push(LowerError {
                        span: wanted.span,
                        message: format!(
                            "session version `{}` is not enabled by the test's `uut.versions`",
                            wanted.name
                        ),
                    });
                    continue;
                };
                uut.versions.swap(0, index);
            }
            let synthetic = ast::Test {
                name: test.name.clone(),
                header: test.header.clone(),
                matrix: None,
                psk: test.psk.clone(),
                uut: session_uut,
                peer: test.peer.clone(),
                sessions: Vec::new(),
                flow: Some(sess.flow.clone()),
                expect: Some(sess.expect.clone()),
                asserts: sess.asserts.clone(),
                repeat: None,
                span: sess.span,
            };
            match lower_with_binding(&synthetic, binding, sess.resumes.is_some()) {
                Ok(mut p) => {
                    p.test_id = format!("{}:{}", p.test_id, sess.name.name);
                    p.session_name = Some(sess.name.name.clone());
                    if let Some(group) = &mut p.repeat_group {
                        group.push(':');
                        group.push_str(&sess.name.name);
                    }
                    p.resumes = sess.resumes.as_ref().map(|r| r.name.clone());
                    p.force_resumption = sess.force_resume;
                    p.advertise_psk_modes |= resumed_targets.contains(&sess.name.name);
                    programs.push(p);
                }
                Err(errs) => {
                    for e in errs {
                        let key = (e.span.start, e.span.end, e.message.clone());
                        if seen_errors.insert(key) {
                            errors.push(e);
                        }
                    }
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(programs)
}

fn lower_with_binding(
    test: &Test,
    binding: &[(String, i64)],
    resumes: bool,
) -> Result<Program, Vec<LowerError>> {
    let mut errors: Vec<LowerError> = Vec::new();

    // Header: version + subject + kex type + rfc refs.
    let mut version: Option<TlsVersion> = None;
    let mut protocol = ir::Protocol::Tls;
    let mut rfc_refs: Vec<RfcRef> = Vec::new();
    let mut suite_filters: Vec<ir::SuiteFilter> = Vec::new();
    // The `psk_ke` capability makes a resuming TLS 1.3 client offer PSK-only.
    let mut resume_psk_ke = false;
    // `uut client` server-selection capability sets, collected
    // from peer capability selectors (see ir::Program::server_suites).
    let mut server_suites: Vec<u16> = Vec::new();
    let mut server_groups: Vec<u16> = Vec::new();
    let mut server_sigalgs: Vec<u16> = Vec::new();
    let mut first_group_span: Option<Span> = None;
    let mut session_ticket = false;
    let mut resume_by_session_id = false; // T5: `session_id` capability
    let mut hrr = false;
    let mut second_hrr = false;
    let mut offer_rpk = false;
    let mut compress_cert = false;
    let mut skip_backends: Vec<(String, Option<String>)> = Vec::new();
    let mut xfail_backends: Vec<(String, Option<String>)> = Vec::new();
    // A: `chain:` / `client_chain:` as written. `chain:` is mandatory; the
    // Option lets us diagnose an omitted line after processing the header.
    let mut chain_names: Option<(Vec<ir::ChainName>, Span)> = None;
    let mut client_chain_names: Option<Vec<ir::ChainName>> = None;
    let mut ecdhe_by_chain = false;

    for h in &test.header {
        match h {
            // A: the chain lists; the schema check vetted the names.
            HeaderLine::Chain {
                client,
                names,
                span,
            } => {
                let mut list = Vec::new();
                for n in names {
                    match ir::ChainName::parse(&n.name) {
                        Some(c) => list.push(c),
                        None => errors.push(LowerError {
                            span: n.span,
                            message: format!("unknown chain `{}`", n.name),
                        }),
                    }
                }
                if *client {
                    if client_chain_names.replace(list).is_some() {
                        errors.push(LowerError {
                            span: *span,
                            message: "`client_chain:` given twice".into(),
                        });
                    }
                } else if chain_names.replace((list, *span)).is_some() {
                    errors.push(LowerError {
                        span: *span,
                        message: "`chain:` given twice".into(),
                    });
                }
            }
            HeaderLine::Skip {
                backends, reason, ..
            } => {
                for b in backends {
                    skip_backends.push((b.name.clone(), reason.as_ref().map(|r| r.value.clone())));
                }
            }
            HeaderLine::Xfail {
                backends, reason, ..
            } => {
                for b in backends {
                    xfail_backends.push((b.name.clone(), reason.as_ref().map(|r| r.value.clone())));
                }
            }
            HeaderLine::Rfc {
                number, section, ..
            } => {
                rfc_refs.push(RfcRef {
                    number: *number,
                    section: section.as_ref().map(|s| s.text.clone()),
                });
            }
        }
    }

    let uut = match test.uut.as_ref() {
        Some(u) => u,
        None => {
            errors.push(LowerError {
                span: test.name.span,
                message: "test has no `uut` block".into(),
            });
            return Err(errors);
        }
    };
    let subject = match uut.role {
        UutRole::Server => Subject::Server,
        UutRole::Client => Subject::Client,
    };
    let mut resolved_uut_versions = Vec::new();
    for entry in &uut.versions {
        match resolve_version_ref(entry, binding) {
            Ok(wire) if matches!(wire, 0x0301..=0x0304 | 0xfefc | 0xfefd) => {
                if resolved_uut_versions.contains(&wire) {
                    errors.push(LowerError {
                        span: entry.span(),
                        message: format!(
                            "version `{}` appears more than once after matrix expansion",
                            version_name_for_wire(i64::from(wire)).unwrap_or("unknown")
                        ),
                    });
                } else {
                    resolved_uut_versions.push(wire);
                }
            }
            Ok(wire) => errors.push(LowerError {
                span: entry.span(),
                message: format!("matrix value 0x{wire:04x} is not a supported TLS/DTLS version"),
            }),
            Err(error) => errors.push(error),
        }
    }
    if resolved_uut_versions.iter().any(|v| *v >= 0xf000)
        && resolved_uut_versions.iter().any(|v| *v < 0xf000)
    {
        errors.push(LowerError {
            span: uut.span,
            message: "one test cannot mix TLS and DTLS versions after matrix expansion".into(),
        });
    }

    // The first enabled version selects plzn's peer driver. Every listed TLS
    // version is passed to the shim below, allowing a scenario to exercise a
    // peer with a wider cross-version range.
    if let Some(primary) = uut.versions.first() {
        let primary_wire = resolved_uut_versions.first().copied();
        match primary_wire {
            Some(0x0301) => version = Some(TlsVersion::Tls10),
            Some(0x0302) => version = Some(TlsVersion::Tls11),
            Some(0x0303) => version = Some(TlsVersion::Tls12),
            Some(0x0304) => version = Some(TlsVersion::Tls13),
            Some(0xfefd) => {
                version = Some(TlsVersion::Tls12);
                protocol = ir::Protocol::Dtls;
            }
            Some(0xfefc) => {
                version = Some(TlsVersion::Tls13);
                protocol = ir::Protocol::Dtls;
            }
            Some(wire) => errors.push(LowerError {
                span: primary.span(),
                message: format!("matrix value 0x{wire:04x} is not a supported TLS/DTLS version"),
            }),
            None => {}
        }
    }

    for tok in test
        .peer
        .as_ref()
        .into_iter()
        .flat_map(|peer| &peer.capabilities)
    {
        match tok.name.as_str() {
            // Key exchange predicates.
            "rsa" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::Rsa)),
            "ecdhe_rsa" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::EcdheRsa)),
            "ecdhe_ecdsa" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::EcdheEcdsa)),
            "dhe_rsa" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::DheRsa)),
            "ecdhe" => {
                suite_filters.push(ir::SuiteFilter::Ecdhe);
                ecdhe_by_chain = true;
            }
            "psk" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::Psk)),
            "ecdhe_psk" => suite_filters.push(ir::SuiteFilter::Kex(ir::KexType::EcdhePsk)),
            "psk_ke" => resume_psk_ke = true,
            "psk_dhe_ke" => resume_psk_ke = false,
            // Cipher predicates.
            "aead" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Aead)),
            "gcm" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Gcm)),
            "cbc" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Cbc)),
            "aes128_cbc_sha" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes128Cbc));
                suite_filters.push(ir::SuiteFilter::Mac(crate::tls::crypto::HashAlg::Sha1));
            }
            "aes256_cbc_sha" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes256Cbc));
                suite_filters.push(ir::SuiteFilter::Mac(crate::tls::crypto::HashAlg::Sha1));
            }
            "aes128_gcm_sha256" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes128Gcm))
            }
            "aes256_gcm_sha384" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes256Gcm))
            }
            "chacha20_poly1305" | "chacha20_poly1305_sha256" => {
                suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::ChaCha))
            }
            "aes128_ccm_sha256" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes128Ccm))
            }
            "aes128_ccm_8_sha256" => {
                suite_filters.push(ir::SuiteFilter::Cipher(ir::BulkCipher::Aes128Ccm8))
            }
            "ccm" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Ccm)),
            "ccm8" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Ccm8)),
            "aria" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Aria)),
            "camellia" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Camellia)),
            "des3" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::TripleDes)),
            "null" => suite_filters.push(ir::SuiteFilter::Mode(ir::CipherMode::Null)),
            "sha384" => {
                suite_filters.push(ir::SuiteFilter::Prf(crate::tls::crypto::HashAlg::Sha384))
            }
            "session_ticket" => session_ticket = true,
            "session_id" => resume_by_session_id = true,
            "hrr" => hrr = true,
            "second_hrr" => {
                second_hrr = true;
                hrr = true;
            }
            "offer_rpk" => offer_rpk = true,
            "compress_cert" => compress_cert = true,
            _ => {}
        }
        if let Some(w) = schema::tls13_suite_wire_value(tok.name.as_str()) {
            if !server_suites.contains(&w) {
                server_suites.push(w);
            }
        }
        if let Some(w) = schema::group_wire_value(tok.name.as_str()) {
            if !server_groups.contains(&w) {
                if server_groups.is_empty() {
                    first_group_span = Some(tok.span);
                }
                server_groups.push(w);
            }
        }
        if let Some(w) = schema::sigalg_wire_value(tok.name.as_str()) {
            if !server_sigalgs.contains(&w) {
                server_sigalgs.push(w);
            }
        }
    }

    let version = match version {
        Some(v) => v,
        None => {
            errors.push(LowerError {
                span: test.name.span,
                message: "`uut.versions` must declare a TLS or DTLS version".into(),
            });
            return Err(errors);
        }
    };
    // A full legacy cipher-suite matrix may carry both certificate chains and
    // PSK material. At an exact suite point, expose the PSK only for a PSK
    // suite so preset selection follows that suite's actual handshake shape.
    let case_has_psk = test.psk.is_some()
        && (version == TlsVersion::Tls13
            || binding
                .iter()
                .find(|(name, _)| name == "suite")
                .and_then(|(_, wire)| u16::try_from(*wire).ok())
                .and_then(ir::suite_info)
                .is_none_or(|suite| suite.kex.is_psk()));

    if protocol == ir::Protocol::Tls && version < TlsVersion::Tls12 {
        for (which, names) in [
            (
                "chain",
                chain_names.as_ref().map(|(names, _)| names.as_slice()),
            ),
            ("client_chain", client_chain_names.as_deref()),
        ] {
            if let Some(name) = names.and_then(|names| {
                names
                    .iter()
                    .find(|name| matches!(name, ir::ChainName::RsaPss | ir::ChainName::Ed25519))
            }) {
                errors.push(LowerError {
                    span: uut.span,
                    message: format!(
                        "`{which}: [{}]` cannot authenticate in TLS 1.0/1.1: those versions have no signature-algorithm negotiation for this key type",
                        name.name()
                    ),
                });
            }
        }
    }

    if uut.key_update && version != TlsVersion::Tls13 {
        errors.push(LowerError {
            span: uut.span,
            message: "`uut.key_update` requires TLS 1.3 or DTLS 1.3".into(),
        });
    }
    if !server_sigalgs.is_empty()
        && subject == Subject::Client
        && (!version.is_legacy() || protocol != ir::Protocol::Tls)
    {
        errors.push(LowerError {
            span: test.peer.as_ref().unwrap().span,
            message: "signature-scheme peer capabilities are supported with `uut server` or a TLS 1.0-1.2 `uut client`; this plzn server driver does not implement signature preferences".into(),
        });
    }
    if test.psk.as_ref().is_some_and(|psk| !psk.offers.is_empty())
        && (version != TlsVersion::Tls13 || subject != Subject::Server)
    {
        errors.push(LowerError {
            span: test.psk.as_ref().unwrap().span,
            message: "PSK `offer { ... }` blocks require a TLS 1.3/DTLS 1.3 `uut server` test"
                .into(),
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // Client authentication is owned by the server. When the UUT is the
    // server, its exact UUT policy drives both the shim and the preset. When
    // the UUT is the client, plzn's peer-server policy is declared separately.
    let client_auth_handshake = match subject {
        Subject::Server => uut.require_client_cert || uut.request_client_cert,
        Subject::Client => test
            .peer
            .as_ref()
            .is_some_and(|peer| peer.request_client_cert),
    };

    // `uut server` + TLS 1.3: the first capability group gets the key share, so it
    // must be one plzn can generate (some groups can only be advertised).
    if subject == Subject::Server && version == TlsVersion::Tls13 {
        if let Some(&first) = server_groups.first() {
            if !ir::CLIENT_KEY_SHARE_GROUPS.contains(&first) {
                return Err(vec![LowerError {
                    span: first_group_span.unwrap_or(test.name.span),
                    message: format!(
                        "plzn's client cannot generate a key share for `{}`; list an \
                         implemented group first (x25519, x448, secp256r1, secp384r1, secp521r1, \
                         brainpoolP256r1tls13, brainpoolP384r1tls13, ffdhe2048, ffdhe3072, \
                         ffdhe4096, ffdhe6144, ffdhe8192, \
                         mlkem512/768/1024, x25519mlkem768, x448mlkem1024, secp256r1mlkem768, \
                         secp384r1mlkem1024) or use `+ext key_share = [...]` to choose \
                         the shared groups",
                        schema_group_name(first)
                    ),
                }]);
            }
        }
    }

    // Matrix is handled by the caller (`lower`) which enumerates
    // bindings and calls us once per case. Nothing to validate
    // here beyond what `enumerate_matrix_bindings` already did.

    // Flow
    let flow = match test.flow.as_ref() {
        Some(f) => f,
        None => {
            errors.push(LowerError {
                span: test.name.span,
                message: "test has no `flow` block".into(),
            });
            return Err(errors);
        }
    };

    // T5: `session_id` is a legacy-TLS client-side resumption capability.
    if resume_by_session_id
        && (!version.is_legacy() || subject != Subject::Server || protocol != ir::Protocol::Tls)
    {
        errors.push(LowerError {
            span: test.name.span,
            message: "the `session_id` capability applies to plzn's TLS 1.0-1.2 client".into(),
        });
        return Err(errors);
    }

    let mut steps: Vec<Step> = Vec::new();
    let mut mutation_messages: Vec<MessageKind> = Vec::new();
    let mut expanded_preset: Option<Vec<ir::HandshakeStep>> = None;

    match &flow.preset {
        Some(p) if p.base.name == "handshake" => {
            // Select the right preset based on (version, subject, kex).
            let has_rsa_kex = suite_filters
                .iter()
                .any(|f| matches!(f, ir::SuiteFilter::Kex(ir::KexType::Rsa)));
            let full_preset = if protocol == ir::Protocol::Dtls && version == TlsVersion::Tls12 {
                // One preset for PSK and ECDHE (see ir::DTLS12_PRESET); the server
                // view (uut client) has its own; the server-owned policy
                // selects the client-authentication variants.
                match (subject, client_auth_handshake) {
                    // A session that `resumes` an earlier one runs the RFC 5077
                    // abbreviated flight (both roles).
                    (Subject::Server, _) if resumes => ir::DTLS12_RESUMED_CLIENT_PRESET,
                    (Subject::Client, _) if resumes => ir::DTLS12_RESUMED_SERVER_PRESET,
                    (Subject::Server, true) => ir::DTLS12_CLIENT_AUTH_PRESET,
                    (Subject::Server, false) => ir::DTLS12_PRESET,
                    (Subject::Client, true) => ir::DTLS12_CLIENT_AUTH_SERVER_PRESET,
                    (Subject::Client, false) => ir::DTLS12_SERVER_PRESET,
                }
            } else if version.is_legacy() {
                let has_ecdhe_psk = suite_filters
                    .iter()
                    .any(|f| matches!(f, ir::SuiteFilter::Kex(ir::KexType::EcdhePsk)));
                match (subject, has_rsa_kex) {
                    // A resuming session runs the abbreviated (ticket) handshake;
                    // its PSK/master-secret comes from the prior session at runtime.
                    (Subject::Server, _) if resumes => ir::TLS12_RESUMED_CLIENT_PRESET,
                    // plzn's server resuming from a ticket it issued: the
                    // abbreviated flight (server CCS + Finished first).
                    (Subject::Client, _) if resumes => ir::TLS12_RESUMED_SERVER_PRESET,
                    // A `psk { }` block selects the RFC 4279 / RFC 5489 flows: no
                    // Certificate, and (plain PSK) an optional ServerKeyExchange.
                    (Subject::Server, _) if case_has_psk && has_ecdhe_psk => {
                        ir::TLS12_ECDHE_PSK_CLIENT_PRESET
                    }
                    (Subject::Server, _) if case_has_psk => ir::TLS12_PSK_CLIENT_PRESET,
                    (Subject::Client, _) if case_has_psk => ir::TLS12_PSK_SERVER_PRESET,
                    (Subject::Server, _) if client_auth_handshake => {
                        ir::TLS12_CLIENT_AUTH_CLIENT_PRESET
                    }
                    (Subject::Client, _) if client_auth_handshake => {
                        ir::TLS12_CLIENT_AUTH_SERVER_PRESET
                    }
                    (Subject::Server, false) => ir::TLS12_ECDHE_CLIENT_PRESET,
                    (Subject::Server, true) => ir::TLS12_RSA_CLIENT_PRESET,
                    (Subject::Client, false) => ir::TLS12_ECDHE_SERVER_PRESET,
                    (Subject::Client, true) => ir::TLS12_RSA_SERVER_PRESET,
                }
            } else {
                // TLS 1.3 — select based on mode flags.
                match subject {
                    // A resuming session gets its PSK from the prior session's
                    // ticket at runtime (not a declared `psk`), so select the
                    // abbreviated PSK preset when either is present.
                    Subject::Server if case_has_psk || resumes => ir::TLS13_PSK_CLIENT_PRESET,
                    Subject::Server if hrr => ir::TLS13_HRR_CLIENT_PRESET,
                    Subject::Server if client_auth_handshake => ir::TLS13_CLIENT_AUTH_CLIENT_PRESET,
                    Subject::Server => ir::TLS13_CLIENT_PRESET,
                    // A resuming session on the server side: the abbreviated
                    // PSK flow (no Certificate / CertificateVerify).
                    Subject::Client if resumes => ir::TLS13_PSK_SERVER_PRESET,
                    Subject::Client if second_hrr => ir::TLS13_SECOND_HRR_SERVER_PRESET,
                    Subject::Client if hrr => ir::TLS13_HRR_SERVER_PRESET,
                    Subject::Client if client_auth_handshake => ir::TLS13_CLIENT_AUTH_SERVER_PRESET,
                    Subject::Client => ir::TLS13_SERVER_PRESET,
                }
            };
            let psk12 = version.is_legacy() && protocol == ir::Protocol::Tls && case_has_psk;
            expanded_preset = Some(full_preset.to_vec());
            for preset_step in full_preset {
                if let ir::HandshakeStep::Send(kind) = preset_step {
                    if !mutation_messages.contains(kind) {
                        mutation_messages.push(*kind);
                    }
                }
            }
            match &p.anchor {
                None if hrr || client_auth_handshake || psk12 => {
                    // HRR and client-auth flows expand into individual steps
                    // because the built-in do_handshake() drives neither the HRR
                    // nor the CertificateRequest/Certificate/CertificateVerify
                    // exchange; running the preset step-by-step does.
                    steps.push(Step::HandshakeSteps {
                        steps: full_preset.to_vec(),
                        config: None,
                        span: flow.span,
                    });
                }
                None => {
                    // No anchor: full handshake as one step.
                    steps.push(Step::Handshake { span: flow.span });
                }
                Some(anchor) => {
                    // Expand the preset and truncate at the anchor.
                    let target_name = anchor.msg.name.as_str();
                    let target_is_send = matches!(anchor.verb, ast::AnchorVerb::Send);
                    let is_until = matches!(anchor.when, ast::AnchorWhen::Until);

                    // Find the anchor step in the preset.
                    let pos = full_preset.iter().position(|hs| {
                        hs.message_name() == target_name && hs.is_send() == target_is_send
                    });
                    let pos = match pos {
                        Some(p) => p,
                        None => {
                            errors.push(LowerError {
                                span: anchor.span,
                                message: format!(
                                    "`{} {}` doesn't appear in the {} handshake preset",
                                    if target_is_send { "send" } else { "recv" },
                                    target_name,
                                    match version {
                                        TlsVersion::Tls10 => "TLS 1.0",
                                        TlsVersion::Tls11 => "TLS 1.1",
                                        TlsVersion::Tls12 => "TLS 1.2",
                                        TlsVersion::Tls13 => "TLS 1.3",
                                    }
                                ),
                            });
                            return Err(errors);
                        }
                    };
                    // `until send X` = everything before X (exclusive).
                    // `after send X` = everything through X (inclusive).
                    let end = if is_until { pos } else { pos + 1 };
                    let prefix: Vec<ir::HandshakeStep> = full_preset[..end].to_vec();
                    if !prefix.is_empty() {
                        steps.push(Step::HandshakeSteps {
                            steps: prefix,
                            config: None,
                            span: flow.span,
                        });
                    }
                }
            }
        }
        Some(p) => {
            errors.push(LowerError {
                span: p.span,
                message: format!(
                    "unknown flow preset `{}`; only `handshake` is supported",
                    p.base.name
                ),
            });
        }
        None => {
            // Bare `flow { ... }`: no handshake prefix, the body
            // steps are the entire flow.
        }
    }
    let mut send_overrides: Vec<MessageOverrides> = Vec::new();
    let mut recv_matchers: Vec<MessageOverrides> = Vec::new();
    let mut send_mutations: Vec<ir::MessageMutations> = Vec::new();
    let mut send_ext_deltas: Vec<ir::MessageExtDeltas> = Vec::new();
    // T5: the list lengths when a TLS `begin_renegotiation` step was lowered;
    // everything pushed after it belongs to the renegotiation phase and is
    // split off into `Program::reneg_*` below.
    let mut reneg_boundary: Option<(usize, usize, usize)> = None;

    // When there's an anchor or no preset at all, inline
    // `send/recv <handshake-msg>` must push HandshakeSteps
    // (the preset was truncated or absent, so the message won't
    // be sent otherwise). Only the full-preset non-anchored case
    // treats inline sends as overrides.
    let is_anchored = match &flow.preset {
        Some(p) => p.anchor.is_some(),
        None => true,
    };
    // T2: once the flow has received a HelloRetryRequest, a `send ClientHello`
    // is the retry hello; its overrides / mutations / deltas lower under
    // `MessageKind::ClientHelloRetry` so the TLS 1.3 client applies them to
    // CH2 rather than CH1.
    let mut after_hrr = false;

    // T1: `repeat N { ... }` blocks are unrolled here (N may be a matrix
    // variable), so the loop below sees only plain steps.
    let flow_steps: Vec<ast::Step> = {
        let mut v = Vec::new();
        if let Err(e) = unroll_repeats(&flow.steps, binding, &mut v) {
            errors.push(e);
            return Err(errors);
        }
        v
    };
    for step in &flow_steps {
        match step {
            ast::Step::Repeat { span, .. } => {
                errors.push(LowerError {
                    span: *span,
                    message: "internal: repeat block survived unrolling".into(),
                });
            }
            // T1: `recv alert level/code` and `close reset`.
            ast::Step::RecvAlert { alert, span } => match lower_alert_spec(alert) {
                Ok((level, code)) => steps.push(Step::RecvAlert {
                    level,
                    code,
                    span: *span,
                }),
                Err(e) => errors.push(e),
            },
            ast::Step::Send {
                msgs,
                overrides,
                mutations,
                ext_deltas,
                dtls_frag,
                span,
            } => {
                if let Some(message) = msgs.iter().find(|message| {
                    message.payload.is_some()
                        && !(msgs.len() == 1 && message.name.name == "Heartbeat")
                }) {
                    errors.push(LowerError {
                        span: message.name.span,
                        message: if message.name.name == "AppData" {
                            "literal AppData payloads are no longer supported; use `send AppData` or `send AppData { size: N, reply: M }`".into()
                        } else {
                            format!("`send {}` does not accept an inline payload; use supported fields inside its message body (inline text is only supported on a single `send Heartbeat`)", message.name.name)
                        },
                    });
                    continue;
                }
                // Multi-send: `send X, Y, Z` is sugar for sequential
                // sends of handshake messages. Only valid in anchored
                // flows (otherwise the preset already orders them).
                // Bodies/mutations/ext-deltas are rejected — they
                // would be ambiguous about which message they bind to.
                if msgs.len() > 1 {
                    if !overrides.is_empty()
                        || !mutations.is_empty()
                        || !ext_deltas.is_empty()
                        || dtls_frag.is_some()
                    {
                        errors.push(LowerError {
                            span: *span,
                            message: "multi-message send takes no body, mutations, \
                                      or `+ext` deltas; send messages individually \
                                      to attach overrides"
                                .into(),
                        });
                        continue;
                    }
                    if !is_anchored {
                        errors.push(LowerError {
                            span: *span,
                            message: "multi-message send is only allowed in anchored \
                                      flows (`flow handshake until ...` / `after ...`)"
                                .into(),
                        });
                        continue;
                    }
                    let mut kinds: Vec<MessageKind> = Vec::with_capacity(msgs.len());
                    let mut had_error = false;
                    for m in msgs {
                        let name = m.name.name.as_str();
                        if name == "AppData" || name == "KeyUpdate" {
                            errors.push(LowerError {
                                span: m.name.span,
                                message: format!(
                                    "`{}` cannot appear in a multi-message send; \
                                     send it on its own line",
                                    name
                                ),
                            });
                            had_error = true;
                            continue;
                        }
                        match MessageKind::from_name(name) {
                            Some(k) => kinds.push(k),
                            None => {
                                errors.push(LowerError {
                                    span: m.name.span,
                                    message: format!("`{}` is not a recognised TLS message", name),
                                });
                                had_error = true;
                            }
                        }
                    }
                    if had_error {
                        continue;
                    }
                    for message in kinds {
                        steps.push(Step::HandshakeSteps {
                            steps: vec![ir::HandshakeStep::Send(message)],
                            config: Some(Box::new(ir::MessageConfig {
                                message,
                                send: true,
                                fields: vec![],
                                mutations: vec![],
                                ext_deltas: vec![],
                            })),
                            span: *span,
                        });
                    }
                    continue;
                }
                let msg_name = msgs[0].name.name.as_str();
                let list_start = (
                    send_overrides.len(),
                    send_mutations.len(),
                    send_ext_deltas.len(),
                );
                if !ext_deltas.is_empty()
                    && matches!(
                        msg_name,
                        "AppData" | "EarlyData" | "Renegotiation" | "KeyUpdate" | "Heartbeat"
                    )
                {
                    errors.push(LowerError {
                        span: *span,
                        message: format!("`{msg_name}` does not support extension deltas"),
                    });
                    continue;
                }
                // A DTLS fragmentation scheme (`@ fragment N`, ...) is DTLS-only
                // and applies only to handshake messages plzn emits.
                if dtls_frag.is_some() {
                    if protocol != ir::Protocol::Dtls {
                        errors.push(LowerError {
                            span: *span,
                            message: "a `@ fragment` / `@ overlap_mismatch` / ... scheme is DTLS-only; the test needs `versions: [dtls12]`".into(),
                        });
                        continue;
                    }
                    if matches!(
                        msg_name,
                        "AppData" | "Renegotiation" | "KeyUpdate" | "Heartbeat"
                    ) {
                        errors.push(LowerError {
                            span: *span,
                            message: format!(
                                "a DTLS fragmentation scheme cannot be applied to `{}`",
                                msg_name
                            ),
                        });
                        continue;
                    }
                }
                if msg_name == "EarlyData" {
                    if version != TlsVersion::Tls13 || protocol != ir::Protocol::Tls {
                        errors.push(LowerError {
                            span: *span,
                            message: "EarlyData is only defined for TLS 1.3".into(),
                        });
                        continue;
                    }
                    let lowered_mutations = match lower_mutations(mutations, binding) {
                        Ok(muts) => muts,
                        Err(errs) => {
                            errors.extend(errs);
                            continue;
                        }
                    };
                    if let Some(message) =
                        t2_unsupported_mutation(&lowered_mutations, version, protocol, false)
                    {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    match lower_early_data_size(overrides, binding, *span, true) {
                        Ok(size) => steps.push(Step::SendEarlyData {
                            size: size.unwrap_or(crate::app_data::DEFAULT_SIZE),
                            mutations: lowered_mutations,
                            span: *span,
                        }),
                        Err(e) => errors.push(e),
                    }
                    continue;
                }
                if msg_name == "EndOfEarlyData"
                    && (version != TlsVersion::Tls13 || protocol != ir::Protocol::Tls)
                {
                    errors.push(LowerError {
                        span: *span,
                        message: "EndOfEarlyData is only defined for TLS 1.3".into(),
                    });
                    continue;
                }
                if msg_name == "AppData" {
                    let lowered_mutations = if !mutations.is_empty() {
                        match lower_mutations(mutations, binding) {
                            Ok(muts) => muts,
                            Err(errs) => {
                                errors.extend(errs);
                                continue;
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    if protocol == ir::Protocol::Dtls
                        && lowered_mutations
                            .iter()
                            .any(|m| matches!(m.op, MutationOp::Fragment { .. }))
                    {
                        errors.push(LowerError {
                            span: *span,
                            message: "`@ fragment N` cannot be applied to application data over DTLS: there it \
                                      fragments handshake messages (the TLS record-layer split is not \
                                      available under `versions: [dtls12]`)"
                                .into(),
                        });
                        continue;
                    }
                    if let Some(message) =
                        t2_unsupported_mutation(&lowered_mutations, version, protocol, false)
                    {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    match lower_send_app_data(
                        &msgs[0],
                        overrides,
                        lowered_mutations,
                        *span,
                        binding,
                    ) {
                        Ok(s) => steps.push(s),
                        Err(e) => errors.push(e),
                    }
                    continue;
                }
                if msg_name == "Renegotiation" {
                    if !mutations.is_empty() {
                        errors.push(LowerError {
                            span: *span,
                            message: "mutations on `send Renegotiation` are not implemented".into(),
                        });
                        continue;
                    }
                    // Post-handshake renegotiation attempt: replay the initial
                    // ClientHello as an encrypted record. RFC 8446 4.1.2 forbids
                    // a TLS 1.3 server from accepting a ClientHello at this point.
                    // An optional `msg_type` override relabels the replayed message
                    // so other unexpected post-handshake types can be injected.
                    let msg_type = match resolve_renegotiation_msg_type(overrides, binding) {
                        Ok(t) => t,
                        Err(e) => {
                            errors.push(LowerError {
                                span: *span,
                                message: e,
                            });
                            continue;
                        }
                    };
                    steps.push(Step::SendRenegotiation {
                        msg_type,
                        span: *span,
                    });
                    continue;
                }
                if msg_name == "KeyUpdate" {
                    // KeyUpdate is a post-handshake message with a
                    // single enum field: request_update.
                    let request_update = if overrides.is_empty() {
                        1 // default: update_requested
                    } else {
                        match resolve_key_update_request(overrides) {
                            Ok(v) => v,
                            Err(e) => {
                                errors.push(LowerError {
                                    span: *span,
                                    message: e,
                                });
                                continue;
                            }
                        }
                    };
                    // `send KeyUpdate ... @ fragment 3 hold` etc.: byte and
                    // record mutations ride along to the TLS 1.3 drivers.
                    let ku_mutations = if mutations.is_empty() {
                        Vec::new()
                    } else {
                        match lower_mutations(mutations, binding) {
                            Ok(m) => m,
                            Err(errs) => {
                                errors.extend(errs);
                                continue;
                            }
                        }
                    };
                    if let Some(message) =
                        t2_unsupported_mutation(&ku_mutations, version, protocol, true)
                    {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    steps.push(Step::SendKeyUpdate {
                        request_update,
                        mutations: ku_mutations,
                        span: *span,
                    });
                    continue;
                }
                // T6: a heartbeat record (RFC 6520) is never in a preset, so
                // `send Heartbeat` is always its own step, like KeyUpdate; the
                // `send Heartbeat "text"` payload form joins the overrides.
                if msg_name == "Heartbeat" {
                    let mut hb_overrides: Vec<ast::FieldOverride> = overrides.clone();
                    if let Some(p) = &msgs[0].payload {
                        if let Some(field) =
                            overrides.iter().find(|field| field.field.name == "payload")
                        {
                            errors.push(LowerError {
                                span: field.span,
                                message: "`send Heartbeat` cannot combine an inline payload with a `payload:` field".into(),
                            });
                            continue;
                        }
                        // T1 made the payload a value; a heartbeat takes a string.
                        let ast::FieldValue::Str(text) = p else {
                            errors.push(LowerError {
                                span: *span,
                                message: "`send Heartbeat` takes a string payload".into(),
                            });
                            continue;
                        };
                        hb_overrides.push(ast::FieldOverride {
                            field: ast::Ident {
                                name: "payload".into(),
                                span: text.span,
                            },
                            value: ast::FieldValue::Str(text.clone()),
                            span: text.span,
                        });
                    }
                    match lower_overrides(msg_name, &hb_overrides, binding, false) {
                        Ok(fields) => {
                            if !fields.is_empty() {
                                send_overrides.push(MessageOverrides {
                                    message: MessageKind::Heartbeat,
                                    fields,
                                });
                            }
                        }
                        Err(errs) => {
                            errors.extend(errs);
                            continue;
                        }
                    }
                    if !mutations.is_empty() {
                        match lower_mutations(mutations, binding) {
                            Ok(m) => {
                                if let Some(message) =
                                    t2_unsupported_mutation(&m, version, protocol, false)
                                {
                                    errors.push(LowerError {
                                        span: *span,
                                        message,
                                    });
                                    continue;
                                }
                                send_mutations.push(ir::MessageMutations {
                                    message: MessageKind::Heartbeat,
                                    mutations: m,
                                    dtls_frag: None,
                                });
                            }
                            Err(errs) => {
                                errors.extend(errs);
                                continue;
                            }
                        }
                    }
                    steps.push(Step::HandshakeSteps {
                        steps: vec![ir::HandshakeStep::Send(MessageKind::Heartbeat)],
                        config: Some(Box::new(take_send_config(
                            MessageKind::Heartbeat,
                            list_start,
                            &mut send_overrides,
                            &mut send_mutations,
                            &mut send_ext_deltas,
                        ))),
                        span: *span,
                    });
                    continue;
                }
                // T6: a CompressedCertificate replaces the preset Certificate,
                // so it only makes sense where that send is spelled out
                // (`flow handshake until send Certificate { ... }`).
                if msg_name == "CompressedCertificate" && !is_anchored {
                    errors.push(LowerError {
                        span: *span,
                        message: "`send CompressedCertificate` needs an anchored or explicit flow \
                                  (`flow handshake until send Certificate { ... }`), where it \
                                  takes the place of the preset's `send Certificate`"
                            .into(),
                    });
                    continue;
                }
                // Handshake message: collect field overrides AND
                // byte mutations as separate preset-target lists.
                let kind = match MessageKind::from_name(msg_name) {
                    Some(k) => k,
                    None => {
                        errors.push(LowerError {
                            span: msgs[0].name.span,
                            message: format!("`{}` is not a recognised TLS message", msg_name),
                        });
                        continue;
                    }
                };
                // T2: the post-HRR ClientHello binds its lists separately.
                let list_kind = if after_hrr && kind == MessageKind::ClientHello {
                    MessageKind::ClientHelloRetry
                } else {
                    kind
                };
                let post_handshake_send = (kind == MessageKind::NewSessionTicket
                    && version == TlsVersion::Tls13)
                    || (kind == MessageKind::HelloRequest
                        && version.is_legacy()
                        && protocol == ir::Protocol::Tls
                        && subject == Subject::Client);
                if !(is_anchored
                    || post_handshake_send
                    || expanded_preset
                        .as_ref()
                        .is_some_and(|preset| preset.contains(&ir::HandshakeStep::Send(kind)))
                    || (version.is_legacy()
                        && subject == Subject::Client
                        && kind == MessageKind::NewSessionTicket))
                {
                    errors.push(LowerError {
                        span: *span,
                        message: format!(
                            "`send {msg_name}` does not occur in this role's expanded handshake flow"
                        ),
                    });
                    continue;
                }
                if !overrides.is_empty() {
                    if let Err(error) =
                        validate_hello_field_context(list_kind, overrides, version, protocol)
                    {
                        errors.push(error);
                        continue;
                    }
                    if let Err(message) =
                        send_overrides_supported_on(subject, version, protocol, list_kind)
                    {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    if protocol == ir::Protocol::Tls && version < TlsVersion::Tls12 {
                        let wire_only_field = match kind {
                            MessageKind::ServerKeyExchange => Some("signature_scheme"),
                            MessageKind::CertificateRequest => Some("signature_algorithms"),
                            MessageKind::CertificateVerify => Some("algorithm"),
                            _ => None,
                        };
                        if let Some(field) = wire_only_field {
                            if overrides.iter().any(|o| o.field.name == field)
                                && !overrides.iter().any(|o| {
                                    o.field.name == "format"
                                        && matches!(&o.value, ast::FieldValue::Ident(id) if id.name == "tls12")
                                })
                            {
                                errors.push(LowerError {
                                    span: overrides
                                        .iter()
                                        .find(|o| o.field.name == field)
                                        .map_or(*span, |o| o.span),
                                    message: format!(
                                        "`{msg_name}.{field}` has no wire field in TLS 1.0/1.1; add `format: tls12` to deliberately send the TLS 1.2 message form"
                                    ),
                                });
                                continue;
                            }
                        }
                    }
                }
                match lower_overrides(msg_name, overrides, binding, false) {
                    Ok(fields) => {
                        if !fields.is_empty() {
                            send_overrides.push(MessageOverrides {
                                message: list_kind,
                                fields,
                            });
                        }
                    }
                    Err(errs) => errors.extend(errs),
                }
                if !mutations.is_empty() || dtls_frag.is_some() {
                    let mut muts = if !mutations.is_empty() {
                        match lower_mutations(mutations, binding) {
                            Ok(m) => m,
                            Err(errs) => {
                                errors.extend(errs);
                                continue;
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    // `pkcs1.*` addresses the PKCS#1 v1.5 encoded premaster of a
                    // static-RSA ClientKeyExchange before encryption; no other
                    // message has that region.
                    if msg_name != "ClientKeyExchange" {
                        if let Some(bad) = muts.iter().find_map(|m| match &m.op {
                            MutationOp::Xor { target, .. } | MutationOp::Set { target, .. }
                                if matches!(&target.path, Some(p) if p.first().map(String::as_str) == Some("pkcs1")) =>
                            {
                                Some(target.path_str())
                            }
                            _ => None,
                        }) {
                            errors.push(LowerError {
                                span: *span,
                                message: format!(
                                    "`{}`: the `pkcs1.*` mutation paths apply to the static-RSA \
                                     ClientKeyExchange only (the encoded premaster before encryption), \
                                     not to `{}`",
                                    bad, msg_name
                                ),
                            });
                            continue;
                        }
                    }
                    let mut frag = match dtls_frag {
                        Some(f) => match lower_dtls_frag(f) {
                            Ok(s) => Some(s),
                            Err(e) => {
                                errors.push(e);
                                continue;
                            }
                        },
                        None => None,
                    };
                    // `@ fragment N` is one keyword with a per-protocol meaning:
                    // over TLS the record layer splits the framed message into
                    // N-byte records (a MutationOp the TLS drivers apply); over
                    // DTLS it is handshake-layer fragmentation (a DtlsFragScheme
                    // the DTLS drivers apply). `hold` (with `flush_fragment`)
                    // exists only for TLS record boundaries.
                    if protocol == ir::Protocol::Dtls {
                        let mut rest = Vec::with_capacity(muts.len());
                        let mut bad: Option<&'static str> = None;
                        for m in muts.drain(..) {
                            match m.op {
                                MutationOp::Fragment { size, hold } => {
                                    if frag.is_some() {
                                        bad = Some(
                                            "a send step may carry only one DTLS fragmentation scheme",
                                        );
                                    } else if hold.holds() {
                                        if version == TlsVersion::Tls13 {
                                            frag = Some(ir::DtlsFragScheme::HeldFragment {
                                                size,
                                                hold,
                                            });
                                        } else {
                                            bad = Some(
                                                "`@ fragment N hold` / `flush_fragment` require DTLS 1.3; \
                                                        DTLS 1.2 uses flight-level loss controls",
                                            );
                                        }
                                    } else {
                                        frag = Some(ir::DtlsFragScheme::Fragment { size });
                                    }
                                }
                                _ => rest.push(m),
                            }
                        }
                        if let Some(message) = bad {
                            errors.push(LowerError {
                                span: *span,
                                message: message.into(),
                            });
                            continue;
                        }
                        muts = rest;
                    }
                    // A structured target must name a field the selected
                    // message's mapped encoder produces. Checking this for TLS
                    // as well as DTLS keeps mistakes at lint time with a span.
                    if let Some(message) = unmapped_handshake_field(msg_name, &muts) {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    // T2: record-layer mutation ops have version / protocol
                    // requirements the runtime cannot report cleanly.
                    if let Some(message) = t2_unsupported_mutation(&muts, version, protocol, true) {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                        continue;
                    }
                    send_mutations.push(ir::MessageMutations {
                        message: list_kind,
                        mutations: muts,
                        dtls_frag: frag,
                    });
                }
                if !ext_deltas.is_empty() {
                    // Only messages whose driver consults the delta list may carry
                    // one; anything else would lint clean and then silently send
                    // the unmodified message.
                    if let Err(message) =
                        ext_deltas_supported_on(subject, version, protocol, list_kind)
                    {
                        errors.push(LowerError {
                            span: *span,
                            message,
                        });
                    } else {
                        match lower_ext_deltas(
                            ext_deltas, subject, version, protocol, kind, binding,
                        ) {
                            Ok(ops) => {
                                send_ext_deltas.push(ir::MessageExtDeltas {
                                    message: list_kind,
                                    deltas: ops,
                                });
                            }
                            Err(errs) => errors.extend(errs),
                        }
                    }
                }
                // In anchored flows, inline sends must push an actual
                // step — the truncated preset won't include this send.
                if is_anchored || post_handshake_send {
                    steps.push(Step::HandshakeSteps {
                        steps: vec![ir::HandshakeStep::Send(kind)],
                        config: Some(Box::new(take_send_config(
                            list_kind,
                            list_start,
                            &mut send_overrides,
                            &mut send_mutations,
                            &mut send_ext_deltas,
                        ))),
                        span: *span,
                    });
                }
                // The server-facing counterpart of the recv-HRR case below:
                // after plzn sends an HRR, a following `recv ClientHello`
                // describes CH2 and needs its own matcher list.
                if kind == MessageKind::HelloRetryRequest {
                    after_hrr = true;
                }
            }
            ast::Step::Recv {
                msgs,
                matchers,
                ext_matchers,
                span,
            } => {
                if let Some(message) = msgs.iter().find(|message| message.payload.is_some()) {
                    errors.push(LowerError {
                        span: message.name.span,
                        message: format!("`recv {}` does not accept an inline payload; use receive matchers inside its message body", message.name.name),
                    });
                    continue;
                }
                if msgs.len() != 1 {
                    errors.push(LowerError {
                        span: *span,
                        message: "only single-message recvs are supported in v1".into(),
                    });
                    continue;
                }
                let msg_name = msgs[0].name.name.as_str();
                if !ext_matchers.is_empty()
                    && !matches!(
                        msg_name,
                        "ServerHello" | "HelloRetryRequest" | "EncryptedExtensions" | "ClientHello"
                    )
                {
                    errors.push(LowerError {
                        span: *span,
                        message: format!("`{msg_name}` does not support extension body matchers"),
                    });
                    continue;
                }
                if msg_name == "EarlyData" {
                    if version != TlsVersion::Tls13 || protocol != ir::Protocol::Tls {
                        errors.push(LowerError {
                            span: *span,
                            message: "EarlyData is only defined for TLS 1.3".into(),
                        });
                        continue;
                    }
                    match lower_early_data_size(matchers, binding, *span, false) {
                        Ok(size) => steps.push(Step::RecvEarlyData { size, span: *span }),
                        Err(e) => errors.push(e),
                    }
                    continue;
                }
                if msg_name == "EndOfEarlyData"
                    && (version != TlsVersion::Tls13 || protocol != ir::Protocol::Tls)
                {
                    errors.push(LowerError {
                        span: *span,
                        message: "EndOfEarlyData is only defined for TLS 1.3".into(),
                    });
                    continue;
                }
                if msg_name == "AppData" {
                    // T1: `recv AppData { size: N }` -- the record's plaintext length.
                    let mut size: Option<usize> = None;
                    let mut bad = false;
                    for m in matchers {
                        if m.field.name != "size" {
                            errors.push(LowerError {
                                span: m.field.span,
                                message: format!(
                                    "AppData takes only a `size` matcher, not `{}`",
                                    m.field.name
                                ),
                            });
                            bad = true;
                            continue;
                        }
                        match extract_int(&m.value, binding, m.span) {
                            Ok(n) if (0..=(1 << 20)).contains(&n) => size = Some(n as usize),
                            Ok(n) => {
                                errors.push(LowerError {
                                    span: m.span,
                                    message: format!("AppData size {} out of range", n),
                                });
                                bad = true;
                            }
                            Err(_) => {
                                errors.push(LowerError {
                                    span: m.span,
                                    message: "`recv AppData` takes only `size: N` (a non-negative integer or matrix variable)".into(),
                                });
                                bad = true;
                            }
                        }
                    }
                    if bad {
                        continue;
                    }
                    steps.push(Step::RecvAppData { size, span: *span });
                    continue;
                }
                if msg_name == "Exporter" {
                    match lower_exporter(matchers, binding, *span) {
                        Ok((label, context, length)) => steps.push(Step::RecvExporter {
                            label,
                            context,
                            length,
                            span: *span,
                        }),
                        Err(e) => errors.push(e),
                    }
                    continue;
                }
                if msg_name == "TLSUnique" {
                    if !version.is_legacy() || protocol != ir::Protocol::Tls {
                        errors.push(LowerError {
                            span: *span,
                            message: "TLSUnique is defined only for TLS 1.0 through TLS 1.2".into(),
                        });
                    } else {
                        let unavailable = match matchers.as_slice() {
                            [] => Some(false),
                            [field]
                                if field.field.name == "unavailable"
                                    && matches!(&field.value, ast::FieldValue::Ident(v) if v.name == "true") =>
                            {
                                Some(true)
                            }
                            _ => None,
                        };
                        if let Some(unavailable) = unavailable {
                            steps.push(Step::RecvTlsUnique {
                                unavailable,
                                span: *span,
                            });
                        } else {
                            errors.push(LowerError {
                                span: *span,
                                message: "TLSUnique takes only `unavailable: true`".into(),
                            });
                        }
                    }
                    continue;
                }
                if msg_name == "KeyUpdate" {
                    match lower_overrides(msg_name, matchers, binding, true) {
                        Ok(matchers) => steps.push(Step::RecvKeyUpdate {
                            matchers,
                            span: *span,
                        }),
                        Err(errs) => errors.extend(errs),
                    }
                    continue;
                }
                // T6: `recv Heartbeat { ... }` reads a heartbeat record (never
                // in a preset: always its own step); `recv CertificateStatus`
                // must be an explicit step, since the preset would otherwise
                // absorb a stapled status silently and a missing one would
                // never fail.
                if msg_name == "Heartbeat" {
                    let fields = match lower_overrides(msg_name, matchers, binding, true) {
                        Ok(fields) => fields,
                        Err(errs) => {
                            errors.extend(errs);
                            continue;
                        }
                    };
                    steps.push(Step::HandshakeSteps {
                        steps: vec![ir::HandshakeStep::Recv(MessageKind::Heartbeat)],
                        config: Some(Box::new(ir::MessageConfig {
                            message: MessageKind::Heartbeat,
                            send: false,
                            fields,
                            mutations: vec![],
                            ext_deltas: vec![],
                        })),
                        span: *span,
                    });
                    continue;
                }
                if msg_name == "CertificateStatus" && !is_anchored {
                    errors.push(LowerError {
                        span: *span,
                        message: "`recv CertificateStatus` needs an anchored or explicit flow \
                                  (`flow handshake until recv ServerKeyExchange { ... }` or a bare \
                                  `flow { ... }`), so that a missing status message fails the step"
                            .into(),
                    });
                    continue;
                }
                let kind = match MessageKind::from_name(msg_name) {
                    Some(k) => k,
                    None => {
                        errors.push(LowerError {
                            span: msgs[0].name.span,
                            message: format!("`{}` is not a recognised TLS message", msg_name),
                        });
                        continue;
                    }
                };
                // The dedicated DTLS 1.2 drivers apply matchers on the messages they parse
                // (the DTLS client: ServerHello, HelloVerifyRequest, Certificate,
                // ServerKeyExchange, CertificateRequest; the DTLS server:
                // ClientHello); anything else would be stored and never checked.
                if protocol == ir::Protocol::Dtls
                    && version == TlsVersion::Tls12
                    && !matchers.is_empty()
                    && !matches!(
                        kind,
                        MessageKind::ServerHello
                            | MessageKind::ClientHello
                            | MessageKind::HelloVerifyRequest
                            | MessageKind::Certificate
                            | MessageKind::ServerKeyExchange
                            | MessageKind::CertificateRequest
                            | MessageKind::CertificateStatus
                    )
                {
                    errors.push(LowerError {
                        span: msgs[0].name.span,
                        message: format!(
                            "`recv {} {{ ... }}` matchers are not applied by the DTLS 1.2 drivers; \
                             DTLS 1.2 supports matchers on ServerHello, HelloVerifyRequest, \
                             Certificate, ServerKeyExchange, CertificateRequest and \
                             CertificateStatus (uut server) and ClientHello (uut client)",
                            msg_name
                        ),
                    });
                    continue;
                }
                if kind == MessageKind::HelloRetryRequest {
                    after_hrr = true;
                }
                let list_kind = if after_hrr && kind == MessageKind::ClientHello {
                    MessageKind::ClientHelloRetry
                } else {
                    kind
                };
                let post_handshake = kind == MessageKind::HelloRequest
                    || (kind == MessageKind::NewSessionTicket && version == TlsVersion::Tls13);
                if !(is_anchored
                    || post_handshake
                    || expanded_preset
                        .as_ref()
                        .is_some_and(|preset| preset.contains(&ir::HandshakeStep::Recv(kind)))
                    || (protocol == ir::Protocol::Dtls
                        && version == TlsVersion::Tls12
                        && subject == Subject::Server
                        && matches!(
                            kind,
                            MessageKind::Certificate | MessageKind::ServerKeyExchange
                        ))
                    || (version.is_legacy()
                        && subject == Subject::Server
                        && kind == MessageKind::NewSessionTicket))
                {
                    errors.push(LowerError {
                        span: *span,
                        message: format!(
                            "`recv {msg_name}` does not occur in this role's expanded handshake flow"
                        ),
                    });
                    continue;
                }
                let mut fields = match lower_overrides(msg_name, matchers, binding, true) {
                    Ok(fields) => fields,
                    Err(errs) => {
                        errors.extend(errs);
                        Vec::new()
                    }
                };
                // T2: `ext NAME == value` body matchers, applied by the hello
                // receivers (ServerHello / HelloRetryRequest / EncryptedExtensions
                // when plzn is the client, ClientHello when it is the server).
                if !ext_matchers.is_empty()
                    && !matches!(
                        kind,
                        MessageKind::ServerHello
                            | MessageKind::HelloRetryRequest
                            | MessageKind::EncryptedExtensions
                            | MessageKind::ClientHello
                    )
                {
                    errors.push(LowerError {
                        span: *span,
                        message: format!(
                            "`ext NAME == value` matchers apply to ServerHello, HelloRetryRequest, \
                             EncryptedExtensions and ClientHello, not `{}`",
                            msg_name
                        ),
                    });
                    continue;
                }
                for em in ext_matchers {
                    match lower_ext_matcher(em, binding) {
                        Ok(f) => fields.push(f),
                        Err(e) => errors.push(e),
                    }
                }
                // A post-handshake message never belongs to the base preset,
                // so it executes even in a non-anchored flow (like `recv
                // KeyUpdate` above): HelloRequest (RFC 5246 7.4.1.1, the
                // server asking for a renegotiation) always, and a TLS 1.3
                // NewSessionTicket (RFC 8446 4.6.1, post-handshake) so an
                // explicit `recv NewSessionTicket` reads and counts one.
                if is_anchored || post_handshake {
                    steps.push(Step::HandshakeSteps {
                        steps: vec![ir::HandshakeStep::Recv(kind)],
                        config: Some(Box::new(ir::MessageConfig {
                            message: list_kind,
                            send: false,
                            fields,
                            mutations: vec![],
                            ext_deltas: vec![],
                        })),
                        span: *span,
                    });
                } else {
                    recv_matchers.push(MessageOverrides {
                        message: list_kind,
                        fields,
                    });
                }
            }
            ast::Step::Close { alert, reset, span } => {
                let alert_bytes = match alert {
                    None => None,
                    Some(spec) => {
                        let level = match spec.level.name.as_str() {
                            "warning" => 1u8,
                            "fatal" => 2u8,
                            other => {
                                errors.push(LowerError {
                                    span: spec.level.span,
                                    message: format!(
                                        "alert level must be `warning` or `fatal`, got `{}`",
                                        other
                                    ),
                                });
                                continue;
                            }
                        };
                        // A bare `close alert warning` with no code defaults to close_notify (0).
                        let code = match &spec.code {
                            None => 0u8,
                            Some(c) => match schema::alert_code_value(&c.name) {
                                Some(v) => v,
                                None => {
                                    errors.push(LowerError {
                                        span: c.span,
                                        message: format!("unknown alert code `{}`", c.name),
                                    });
                                    continue;
                                }
                            },
                        };
                        Some([level, code])
                    }
                };
                steps.push(Step::Close {
                    alert: alert_bytes,
                    reset: *reset,
                    span: *span,
                });
            }
            ast::Step::SendRaw { hex, span } => {
                steps.push(Step::SendRaw {
                    data: hex.clone(),
                    span: *span,
                });
            }
            ast::Step::Wait { millis, span } => {
                steps.push(Step::Wait {
                    millis: *millis,
                    span: *span,
                });
            }
            ast::Step::AdvanceClock { nanos, span } => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message: "`advance_clock` is a DTLS step; the test needs a DTLS version"
                            .into(),
                    });
                    continue;
                }
                steps.push(Step::AdvanceClock {
                    nanos: *nanos,
                    span: *span,
                });
            }
            ast::Step::ExpectNextTimeout { nanos, span } => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message:
                            "`expect next_timeout` is a DTLS step; the test needs a DTLS version"
                                .into(),
                    });
                    continue;
                }
                steps.push(Step::ExpectNextTimeout {
                    nanos: *nanos,
                    span: *span,
                });
            }
            ast::Step::ExpectNoTimeout { span } => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message:
                            "`expect no_timeout` is a DTLS step; the test needs a DTLS version"
                                .into(),
                    });
                    continue;
                }
                steps.push(Step::ExpectNoTimeout { span: *span });
            }
            ast::Step::SetTimeout { millis, span } => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message: "`set_timeout` is a DTLS step; the test needs a DTLS version"
                            .into(),
                    });
                    continue;
                }
                steps.push(Step::SetTimeout {
                    millis: *millis,
                    span: *span,
                });
            }
            ast::Step::ExpectRetransmit { span } => {
                steps.push(Step::ExpectRetransmit { span: *span });
            }
            ast::Step::RotateCookieSecret { span } => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message:
                            "`rotate_cookie_secret` is a DTLS step; the test needs `versions: [dtls12]`"
                                .into(),
                    });
                    continue;
                }
                if subject != Subject::Server {
                    errors.push(LowerError {
                        span: *span,
                        message: "`rotate_cookie_secret` rotates the shim SERVER's cookie secret; it needs `uut server`".into(),
                    });
                    continue;
                }
                steps.push(Step::RotateCookieSecret { span: *span });
            }
            ast::Step::ResendFlight { span } => {
                steps.push(Step::ResendFlight { span: *span });
            }
            ast::Step::Renegotiate {
                resumed,
                insecure,
                overrides,
                ext_deltas,
                span,
            } => {
                let customized = *insecure || !overrides.is_empty() || !ext_deltas.is_empty();
                let supports_customization = protocol == ir::Protocol::Tls
                    && version.is_legacy()
                    && subject == Subject::Server;
                if customized && !supports_customization {
                    errors.push(LowerError {
                        span: *span,
                        message: "`renegotiate insecure { ... }` customization is implemented only for plzn's TLS 1.0-1.2 client (`uut server`)".into(),
                    });
                    continue;
                }
                if *resumed
                    && (protocol != ir::Protocol::Tls
                        || !version.is_legacy()
                        || subject != Subject::Server)
                {
                    errors.push(LowerError {
                        span: *span,
                        message: "`renegotiate resumed` is implemented for plzn's TLS 1.0-1.2 client (`uut server`)"
                            .into(),
                    });
                    continue;
                }
                // T5: the block customizes the renegotiation ClientHello only.
                if let Err(error) = validate_hello_field_context(
                    MessageKind::ClientHello,
                    overrides,
                    version,
                    protocol,
                ) {
                    errors.push(error);
                    continue;
                }
                let reneg_overrides =
                    match lower_overrides("ClientHello", overrides, binding, false) {
                        Ok(f) => f,
                        Err(errs) => {
                            errors.extend(errs);
                            continue;
                        }
                    };
                let reneg_deltas = if ext_deltas.is_empty() {
                    Vec::new()
                } else {
                    match lower_ext_deltas(
                        ext_deltas,
                        subject,
                        version,
                        protocol,
                        MessageKind::ClientHello,
                        binding,
                    ) {
                        Ok(ops) => ops,
                        Err(errs) => {
                            errors.extend(errs);
                            continue;
                        }
                    }
                };
                steps.push(Step::Renegotiate {
                    resumed: *resumed,
                    insecure: *insecure,
                    overrides: reneg_overrides,
                    ext_deltas: reneg_deltas,
                    span: *span,
                });
            }
            ast::Step::Dtls { op, span } => {
                // T5: `begin_renegotiation` is one keyword with a per-protocol
                // meaning; over TLS it starts plzn's legacy client's stepped
                // renegotiation and marks the override boundary.
                if protocol != ir::Protocol::Dtls && *op == ir::DtlsOp::BeginRenegotiation {
                    if subject != Subject::Server || !version.is_legacy() {
                        errors.push(LowerError {
                            span: *span,
                        message: "`begin_renegotiation` over TLS drives plzn's TLS 1.0-1.2 client (`uut server`); RFC 8446 4.1.2 has no renegotiation".into(),
                        });
                        continue;
                    }
                    reneg_boundary.get_or_insert((
                        send_overrides.len(),
                        send_mutations.len(),
                        send_ext_deltas.len(),
                    ));
                    steps.push(Step::BeginRenegotiation { span: *span });
                    continue;
                }
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message: format!(
                            "`{}` is a DTLS step; the test needs `versions: [dtls12]`",
                            op.keyword()
                        ),
                    });
                    continue;
                }
                steps.push(Step::Dtls {
                    op: op.clone(),
                    span: *span,
                });
            }
            ast::Step::CoalesceBegin { mode, span } => {
                if protocol == ir::Protocol::Dtls && version != TlsVersion::Tls13 {
                    errors.push(LowerError {
                        span: *span,
                        message: "`coalesce { ... }` is available for TLS and DTLS 1.3 unified records, but not DTLS 1.2 flights".into(),
                    });
                    continue;
                }
                steps.push(Step::CoalesceBegin {
                    mode: *mode,
                    span: *span,
                });
            }
            // T2: `atomic { ... }` is a TLS stream-write boundary. `send record`
            // below is also useful for DTLS: each call emits one protected DTLS
            // record in its own datagram.
            ast::Step::AtomicBegin { span } => {
                if protocol == ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: *span,
                        message: "`atomic { ... }` is a TLS record-layer step; over DTLS the flight ops (`hold_flight`, `release_flight`) control datagram boundaries".into(),
                    });
                    continue;
                }
                steps.push(Step::AtomicBegin { span: *span });
            }
            ast::Step::AtomicEnd { span } => {
                if protocol == ir::Protocol::Dtls {
                    continue; // reported at the block's opening
                }
                steps.push(Step::AtomicEnd { span: *span });
            }
            ast::Step::SendRecord {
                content_type,
                data,
                mutations,
                span,
            } => {
                if !(0..=255).contains(&content_type.value) {
                    errors.push(LowerError {
                        span: content_type.span,
                        message: format!(
                            "record content type {} out of range (0..255)",
                            content_type.value
                        ),
                    });
                    continue;
                }
                let mutations = match lower_mutations(mutations, binding) {
                    Ok(m) => m,
                    Err(errs) => {
                        errors.extend(errs);
                        continue;
                    }
                };
                if let Some(message) = t2_unsupported_mutation(&mutations, version, protocol, false)
                {
                    errors.push(LowerError {
                        span: *span,
                        message,
                    });
                    continue;
                }
                steps.push(Step::SendRecord {
                    content_type: content_type.value as u8,
                    data: data.clone(),
                    mutations,
                    span: *span,
                });
            }
            ast::Step::CoalesceEnd { span } => {
                if protocol == ir::Protocol::Dtls {
                    continue; // reported at the block's opening
                }
                steps.push(Step::CoalesceEnd { span: *span });
            }
            ast::Step::SendEmptyRecord {
                content_type,
                mutations,
                span,
            } => {
                // RFC 5246 6.2.1 ContentType values, or a numeric type (T2).
                let ct = match content_type {
                    ast::ContentTypeSpec::Numeric(n) => {
                        if !(0..=255).contains(&n.value) {
                            errors.push(LowerError {
                                span: n.span,
                                message: format!(
                                    "record content type {} out of range (0..255)",
                                    n.value
                                ),
                            });
                            continue;
                        }
                        n.value as u8
                    }
                    ast::ContentTypeSpec::Named(content_type) => match content_type.name.as_str() {
                        "change_cipher_spec" => 20u8,
                        "alert" => 21u8,
                        "handshake" => 22u8,
                        "application_data" => 23u8,
                        other => {
                            errors.push(LowerError {
                                span: content_type.span,
                                message: format!(
                                    "`send empty_record` takes `handshake`, `alert`, `change_cipher_spec`, \
                                     `application_data` or a numeric type, got `{}`",
                                    other
                                ),
                            });
                            continue;
                        }
                    },
                };
                let mutations = match lower_mutations(mutations, binding) {
                    Ok(m) => m,
                    Err(errs) => {
                        errors.extend(errs);
                        continue;
                    }
                };
                if let Some(message) = t2_unsupported_mutation(&mutations, version, protocol, false)
                {
                    errors.push(LowerError {
                        span: *span,
                        message,
                    });
                    continue;
                }
                steps.push(Step::SendEmptyRecord {
                    content_type: ct,
                    mutations,
                    span: *span,
                });
            }
            ast::Step::FlushFragment { span } => {
                if protocol == ir::Protocol::Dtls && version != TlsVersion::Tls13 {
                    errors.push(LowerError {
                        span: *span,
                        message: "`flush_fragment` requires TLS or DTLS 1.3; not available under `versions: [dtls12]`".into(),
                    });
                    continue;
                }
                steps.push(Step::FlushFragment { span: *span });
            }
            ast::Step::SendAlert {
                alert,
                mutations,
                span,
            } => {
                let level = match alert.level.name.as_str() {
                    "warning" => 1u8,
                    "fatal" => 2u8,
                    other => {
                        errors.push(LowerError {
                            span: alert.level.span,
                            message: format!(
                                "alert level must be `warning` or `fatal`, got `{}`",
                                other
                            ),
                        });
                        continue;
                    }
                };
                let code = match &alert.code {
                    None => {
                        errors.push(LowerError {
                            span: alert.span,
                            message:
                                "`send alert` needs a code: `send alert warning/no_renegotiation`"
                                    .into(),
                        });
                        continue;
                    }
                    Some(c) => match schema::alert_code_value(&c.name) {
                        Some(v) => v,
                        None => {
                            errors.push(LowerError {
                                span: c.span,
                                message: format!("unknown alert code `{}`", c.name),
                            });
                            continue;
                        }
                    },
                };
                let mutations = match lower_mutations(mutations, binding) {
                    Ok(m) => m,
                    Err(errs) => {
                        errors.extend(errs);
                        continue;
                    }
                };
                if let Some(message) = t2_unsupported_mutation(&mutations, version, protocol, false)
                {
                    errors.push(LowerError {
                        span: *span,
                        message,
                    });
                    continue;
                }
                steps.push(Step::SendAlert {
                    level,
                    code,
                    mutations,
                    span: *span,
                });
            }
        }
    }

    // Assertions are lowered below (see the `asserts` block before the Program
    // is built).

    // Expect
    let ast_expect = match test.expect.as_ref() {
        None => {
            errors.push(LowerError {
                span: test.name.span,
                message: "test has no `expect` clause".into(),
            });
            return Err(errors);
        }
        Some(e) => e,
    };
    let expect = match lower_expect_kind(&ast_expect.kind, &mut errors) {
        Some(e) => e,
        None => return Err(errors),
    };
    let mut expect_overrides: Vec<(String, Expectation)> = Vec::new();
    for ov in &ast_expect.overrides {
        if let Some(e) = lower_expect_kind(&ov.kind, &mut errors) {
            expect_overrides.push((ov.uut.name.clone(), e));
        }
    }
    if protocol != ir::Protocol::Dtls {
        if expect.contains_timeout() {
            errors.push(LowerError {
                span: ast_expect.span,
                message: "`expect timeout` is a DTLS outcome; the test needs a DTLS version".into(),
            });
        }
        for ov in &ast_expect.overrides {
            if expectation_kind_contains_timeout(&ov.kind) {
                errors.push(LowerError {
                    span: ov.uut.span,
                    message: "`expect timeout` is a DTLS outcome; the test needs a DTLS version"
                        .into(),
                });
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // server_name: derive from a `server_name(...)` extension if
    // one was declared, otherwise default to "localhost" for the
    // wedge. (+ext lines are rejected above as not-yet-honoured,
    // so today this always resolves to "localhost".)
    let server_name = "localhost".to_string();

    // Enforce: if any expectation (default or override) is `ok`, the flow must
    // end with an operation that proves the claimed property. A terminal,
    // explicit receive matcher is sufficient for a conformance check that is
    // intentionally bounded before the handshake completes; an empty recv is
    // not, because it asserts only that some message arrived.
    // DTLS liveness is proven by handshake completion (the client verifies the
    // server Finished) plus the shim self-check, so a DTLS `flow handshake {}`
    // need not exchange app-data (explicit DTLS AppData steps are supported).
    let any_expects_ok = expect.accepts_success()
        && subject == Subject::Server // only for `uut server` (harness = client)
        && protocol != ir::Protocol::Dtls;
    if any_expects_ok {
        let has_send_appdata = steps.iter().any(|s| matches!(s, Step::SendAppData { .. }));
        let ends_with_recv_appdata = matches!(steps.last(), Some(Step::RecvAppData { .. }));
        let ends_with_key_material = matches!(
            steps.last(),
            Some(Step::RecvExporter { .. } | Step::RecvTlsUnique { .. })
        );
        let ends_with_receive_matcher = matches!(
            steps.last(),
            Some(Step::HandshakeSteps {
                config: Some(config),
                ..
            }) if !config.send && !config.fields.is_empty()
        );
        let ends_with_appdata =
            (has_send_appdata && ends_with_recv_appdata) || ends_with_key_material;
        let ends_with_close_or_probe = matches!(
            steps.last(),
            Some(Step::Close { .. } | Step::Wait { .. } | Step::RecvAlert { .. })
        );
        if !ends_with_appdata
            && !ends_with_receive_matcher
            && !ends_with_close_or_probe
            && !steps.is_empty()
        {
            errors.push(LowerError {
                span: test
                    .expect
                    .as_ref()
                    .map(|e| e.span)
                    .unwrap_or(test.name.span),
                message: "flow with `expect ok` must end with an application-data round trip, \
                          a receive matcher, `recv Exporter`, or `recv TLSUnique` to prove the \
                          claimed property"
                    .into(),
            });
            return Err(errors);
        }
    }

    // T5: split the renegotiation-phase declarations off (see `reneg_boundary`).
    let (reneg_send_overrides, reneg_send_mutations, reneg_send_ext_deltas) = match reneg_boundary {
        Some((a, b, c)) => (
            send_overrides.split_off(a),
            send_mutations.split_off(b),
            send_ext_deltas.split_off(c),
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    // Matrix `sigalg` axis: pin the offered signature_algorithms to the single bound
    // scheme (IANA wire value) by replacing the ClientHello extension. Lets a matrix
    // sweep one signature scheme per case (BoGo addSignatureAlgorithmTests style).
    for (name, value) in binding {
        if name == "sigalg" {
            let scheme = *value as u16;
            let body = vec![0x00, 0x02, (scheme >> 8) as u8, (scheme & 0xff) as u8];
            send_ext_deltas.push(ir::MessageExtDeltas {
                message: MessageKind::ClientHello,
                deltas: vec![ir::ExtDeltaOp::Add {
                    wire_type: 0x000d,
                    body,
                    dup: false,
                }],
            });
            for step in &mut steps {
                if let Step::HandshakeSteps {
                    config: Some(config),
                    ..
                } = step
                {
                    if config.send && config.message == MessageKind::ClientHello {
                        config
                            .ext_deltas
                            .insert(0, send_ext_deltas.last().unwrap().clone());
                        // Collectors require one list per kind.
                        merge_message_lists(
                            &mut Vec::new(),
                            &mut Vec::new(),
                            &mut config.ext_deltas,
                        );
                    }
                }
            }
        }
    }

    // Post-trace asserts include DTLS sequence-number/MTU checks and TLS 1.2
    // explicit-nonce checks. The general `assert <path> == <value>` form is
    // parsed equality assertions are intentionally a small, typed set.
    let mut asserts: Vec<ir::Assert> = Vec::new();
    let mut cross_asserts: Vec<ir::CrossAssert> = Vec::new();
    for a in &test.asserts {
        match &a.kind {
            AssertKind::MaxDatagramSize(n) => {
                if protocol != ir::Protocol::Dtls {
                    errors.push(LowerError {
                        span: a.span,
                        message: "`assert max_datagram_size N` requires `versions: [dtls12]`"
                            .into(),
                    });
                } else {
                    asserts.push(ir::Assert::MaxDatagramSize(n.value as u32));
                }
            }
            AssertKind::Named(name) if name.name == "no_duplicate_record_seqnums" => {
                asserts.push(ir::Assert::NoDuplicateRecordSeqnums);
            }
            // T1: TLS 1.2 explicit AEAD nonce asserts and cross-run uniqueness.
            AssertKind::Named(name) if name.name == "gcm_nonces_unique" => {
                asserts.push(ir::Assert::GcmNoncesUnique);
            }
            AssertKind::Named(name) if name.name == "gcm_nonces_monotonic" => {
                asserts.push(ir::Assert::GcmNoncesMonotonic);
            }
            AssertKind::Unique(vars) => {
                let captured: Vec<String> = flow_steps
                    .iter()
                    .flat_map(|st| match st {
                        ast::Step::Recv { matchers, .. } => matchers
                            .iter()
                            .filter_map(|m| match &m.value {
                                ast::FieldValue::Capture(id) => Some(id.name.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>(),
                        _ => Vec::new(),
                    })
                    .collect();
                for v in vars {
                    if !captured.contains(&v.name) {
                        errors.push(LowerError {
                            span: v.span,
                            message: format!(
                                "`assert unique ${}` names nothing the flow captures; add `capture ${}` to a `recv` matcher",
                                v.name, v.name
                            ),
                        });
                    }
                }
                cross_asserts.push(ir::CrossAssert::Unique(
                    vars.iter().map(|v| v.name.clone()).collect(),
                ));
            }
            AssertKind::Named(name) => {
                errors.push(LowerError {
                    span: a.span,
                    message: format!("unknown assert `{}`", name.name),
                });
            }
            // T5: `assert new_session_tickets == N` (tlsfuzzer count-tickets).
            AssertKind::Eq { path, value }
                if path.parts.len() == 1 && path.parts[0].name == "new_session_tickets" =>
            {
                match value {
                    ast::FieldValue::Int(n) if n.value >= 0 => {
                        asserts.push(ir::Assert::NewSessionTickets(n.value as u32))
                    }
                    _ => errors.push(LowerError {
                        span: a.span,
                        message: "`assert new_session_tickets == N` takes a non-negative count"
                            .into(),
                    }),
                }
            }
            // `assert app_data_records == N`: the application-data records the
            // endpoint received over the flow (a duplicate the peer answered
            // twice shows up as one too many).
            AssertKind::Eq { path, value }
                if path.parts.len() == 1 && path.parts[0].name == "app_data_records" =>
            {
                match value {
                    ast::FieldValue::Int(n) if n.value >= 0 && n.value <= u32::MAX as i64 => {
                        asserts.push(ir::Assert::AppDataRecords(n.value as u32))
                    }
                    _ => errors.push(LowerError {
                        span: a.span,
                        message: "`assert app_data_records == N` takes a non-negative count".into(),
                    }),
                }
            }
            AssertKind::Eq { path, value }
                if path.parts.len() == 1 && path.parts[0].name == "resumed" =>
            {
                match value {
                    ast::FieldValue::Ident(v) if v.name == "true" => {
                        asserts.push(ir::Assert::Resumed(true))
                    }
                    ast::FieldValue::Ident(v) if v.name == "false" => {
                        asserts.push(ir::Assert::Resumed(false))
                    }
                    _ => errors.push(LowerError {
                        span: a.span,
                        message: "`assert resumed == VALUE` takes `true` or `false`".into(),
                    }),
                }
            }
            AssertKind::Eq { path, value }
                if path.parts.len() == 2
                    && path.parts[0].name == "negotiated"
                    && path.parts[1].name == "cipher" =>
            {
                let suite = match value {
                    ast::FieldValue::Ident(name) => schema::suite_wire_value(&name.name).ok_or_else(
                        || LowerError {
                            span: name.span,
                            message: format!("`{}` is not a named cipher suite", name.name),
                        },
                    ),
                    ast::FieldValue::Int(n) => {
                        range_u16(n.value, n.span).and_then(|wire| {
                            if let Some(name) = schema::suite_name(wire) {
                                Err(LowerError {
                                    span: n.span,
                                    message: format!(
                                        "`0x{wire:04x}` is {name}; write the cipher-suite name"
                                    ),
                                })
                            } else {
                                Ok(wire)
                            }
                        })
                    }
                    ast::FieldValue::MatrixVar(_) => {
                        extract_int(value, binding, a.span).and_then(|n| range_u16(n, a.span))
                    }
                    _ => Err(LowerError {
                        span: a.span,
                        message: "`assert negotiated.cipher == VALUE` takes a cipher-suite name, unknown u16 wire value, or matrix variable".into(),
                    }),
                };
                match suite {
                    Ok(suite) => asserts.push(ir::Assert::NegotiatedCipher(suite)),
                    Err(error) => errors.push(error),
                }
            }
            AssertKind::Eq { path, value }
                if path.parts.len() == 2
                    && path.parts[0].name == "negotiated"
                    && path.parts[1].name == "early_data_accepted" =>
            {
                if version != TlsVersion::Tls13 || protocol != ir::Protocol::Tls {
                    errors.push(LowerError {
                        span: a.span,
                        message: "`negotiated.early_data_accepted` is only available for TLS 1.3"
                            .into(),
                    });
                } else {
                    match value {
                        ast::FieldValue::Ident(v) if v.name == "true" => {
                            asserts.push(ir::Assert::EarlyDataAccepted(true))
                        }
                        ast::FieldValue::Ident(v) if v.name == "false" => {
                            asserts.push(ir::Assert::EarlyDataAccepted(false))
                        }
                        _ => errors.push(LowerError {
                            span: a.span,
                            message: "`assert negotiated.early_data_accepted == VALUE` takes `true` or `false`".into(),
                        }),
                    }
                }
            }
            AssertKind::Eq { .. } => {
                errors.push(LowerError {
                    span: a.span,
                    message: "unsupported equality assertion; available paths are `new_session_tickets`, `resumed`, `negotiated.cipher`, and `negotiated.early_data_accepted`".into(),
                });
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    // `uut client|server { cipher_suites: [$suite] }`: matrix variables resolve per point.

    let uut_suites: Vec<u16> = match test.uut.as_ref() {
        Some(u) => u
            .cipher_suites
            .iter()
            .map(|v| resolve_int_or_var(v, binding).map(|i| i as u16))
            .collect::<Result<Vec<u16>, LowerError>>()
            .map_err(|e| vec![e])?,

        None => Vec::new(),
    };
    let uut_curves: Vec<u16> = match test.uut.as_ref() {
        Some(u) => u
            .curves
            .iter()
            .map(|v| resolve_int_or_var(v, binding).map(|i| i as u16))
            .collect::<Result<Vec<u16>, LowerError>>()
            .map_err(|e| vec![e])?,
        None => Vec::new(),
    };

    // A: the chain list is mandatory. A test must explicitly request no chain,
    // the run-specific default, or every concrete chain it depends upon.
    let has_kex = |k: ir::KexType| {
        suite_filters
            .iter()
            .any(|f| matches!(f, ir::SuiteFilter::Kex(x) if *x == k))
    };
    let wants_rsa_kex = has_kex(ir::KexType::Rsa);
    let wants_rsa_sig = has_kex(ir::KexType::EcdheRsa) || has_kex(ir::KexType::DheRsa);
    let wants_ecdsa_sig = has_kex(ir::KexType::EcdheEcdsa);
    let wants_psk = has_kex(ir::KexType::Psk) || has_kex(ir::KexType::EcdhePsk) || case_has_psk;
    let mut mutation_suite_filters = suite_filters.clone();
    if let Some((_, suite)) = binding.iter().find(|(name, _)| name == "suite") {
        mutation_suite_filters.push(ir::SuiteFilter::Exact(*suite as u16));
    }
    // A selector must not turn into the driver's broad default offer when
    // its intersection is empty. TLS 1.3 negotiates authentication separately
    // from suites, matching the endpoint's treatment of key-exchange filters.
    let peer_suite_filters: Vec<_> = mutation_suite_filters
        .iter()
        .copied()
        .filter(|filter| version != TlsVersion::Tls13 || !matches!(filter, ir::SuiteFilter::Kex(_)))
        .collect();
    let peer_suites = if version == TlsVersion::Tls13 {
        ir::filter_suites(version, &peer_suite_filters)
    } else if protocol == ir::Protocol::Dtls {
        ir::filter_suites_dtls(&peer_suite_filters, wants_psk)
    } else {
        ir::filter_suites_legacy(version, &peer_suite_filters, wants_psk)
    };
    if !peer_suite_filters.is_empty() && peer_suites.is_empty() {
        errors.push(LowerError {
            span: test.peer.as_ref().map_or(test.name.span, |peer| peer.span),
            message: "peer cipher-suite selectors leave no supported suites for this protocol; remove or correct the conflicting selectors".into(),
        });
    }
    let mutation_suites = if version == TlsVersion::Tls13 {
        ir::filter_suites(version, &mutation_suite_filters)
    } else if protocol == ir::Protocol::Dtls {
        ir::filter_suites_dtls(&mutation_suite_filters, wants_psk)
    } else {
        ir::filter_suites_legacy(version, &mutation_suite_filters, wants_psk)
    };
    let step_mutations = steps
        .iter()
        .filter_map(|step| match step {
            Step::HandshakeSteps {
                config: Some(config),
                ..
            } if config.send => Some(config.mutations.as_slice()),
            _ => None,
        })
        .flatten();
    for message in send_mutations
        .iter()
        .chain(reneg_send_mutations.iter())
        .chain(step_mutations)
    {
        for mutation in &message.mutations {
            let target_field = match &mutation.op {
                MutationOp::Xor { target, .. } | MutationOp::Set { target, .. } => target
                    .path
                    .as_ref()
                    .and_then(|path| path.first().zip(path.get(1)))
                    .and_then(|(root, field)| (root == "record").then_some(field.as_str())),
                _ => None,
            };
            let valid_for_all = match target_field {
                Some("mac") => mutation_suites
                    .iter()
                    .all(|suite| ir::suite_info(*suite).is_some_and(|info| info.mac.is_some())),
                Some("padding") => mutation_suites
                    .iter()
                    .all(|suite| ir::suite_info(*suite).is_some_and(|info| info.cipher.is_cbc())),
                _ => true,
            };
            if !valid_for_all || mutation_suites.is_empty() {
                if let Some(field @ ("mac" | "padding")) = target_field {
                    errors.push(LowerError {
                        span: mutation.span,
                        message: format!(
                            "`record.{field}` requires the test's negotiated suite set to contain only legacy TLS {} suites",
                            if field == "mac" { "MAC-bearing" } else { "CBC" }
                        ),
                    });
                }
            }
        }
    }
    let (chain_names, chain_span) = match chain_names {
        Some(value) => value,
        None => {
            return Err(vec![LowerError {
                span: test.name.span,
                message: "missing required `chain:` line; use `chain: []` for no server certificate, `chain: [default]` for the run-specific default, or name the required certificate chain(s)".into(),
            }]);
        }
    };
    {
        let span = chain_span;
        let any = ir::CHAIN_RSA | ir::CHAIN_ECDSA | ir::CHAIN_RSA_PSS;
        let mask = chain_names
            .iter()
            .fold(0u8, |m, c| m | c.key_mask().unwrap_or(any));
        let listed = || {
            if chain_names.is_empty() {
                "`chain: []` (no chain)".to_string()
            } else {
                format!(
                    "`chain: [{}]`",
                    chain_names
                        .iter()
                        .map(|c| c.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        };
        if wants_rsa_kex && mask & ir::CHAIN_RSA == 0 {
            errors.push(LowerError {
                span,
                message: format!("the `rsa` capability (static RSA) needs an rsaEncryption chain (`rsa_2048`); {} cannot serve it", listed()),
            });
        }
        if wants_rsa_sig && mask & (ir::CHAIN_RSA | ir::CHAIN_RSA_PSS) == 0 {
            errors.push(LowerError {
                span,
                message: format!("the `ecdhe_rsa` / `dhe_rsa` capabilities need an RSA chain (`rsa_2048` or `rsa_pss`); {} cannot serve them", listed()),
            });
        }
        if wants_ecdsa_sig && mask & ir::CHAIN_ECDSA == 0 {
            errors.push(LowerError {
                span,
                message: format!(
                    "the `ecdhe_ecdsa` capability needs an ECDSA or Ed25519 chain; {} cannot serve it",
                    listed()
                ),
            });
        }
        if chain_names.is_empty() && !wants_psk && !resumes && expect.accepts_success() {
            errors.push(LowerError {
                span,
                message: "`chain: []` leaves the server no certificate: use it with a `psk { }` block, a PSK kex token, or a non-`ok` expectation".into(),
            });
        }
    }
    let client_chain_names = client_chain_names.unwrap_or_else(|| vec![ir::ChainName::Default]);
    if !errors.is_empty() {
        return Err(errors);
    }

    for step in &steps {
        let kind = match step {
            Step::HandshakeSteps { steps, .. } => {
                for handshake_step in steps {
                    if let ir::HandshakeStep::Send(kind) = handshake_step {
                        if !mutation_messages.contains(kind) {
                            mutation_messages.push(*kind);
                        }
                    }
                }
                None
            }
            Step::SendKeyUpdate { .. } => Some(MessageKind::KeyUpdate),
            Step::SendEarlyData { .. } => Some(MessageKind::EarlyData),
            Step::SendAlert { .. } => Some(MessageKind::Alert),
            _ => None,
        };
        if let Some(kind) = kind {
            if !mutation_messages.contains(&kind) {
                mutation_messages.push(kind);
            }
        }
    }

    // TLS 1.3's pre-HRR duplicate-hello path deliberately replays CH1 and
    // retains its transcript. Only its record-field edits are implemented.
    // Do not accept occurrence-bound modifiers that this path cannot execute.
    if version == TlsVersion::Tls13 && protocol == ir::Protocol::Tls && subject == Subject::Server {
        let mut sent_hello = false;
        for step in &steps {
            if let Step::HandshakeSteps {
                config: Some(config),
                ..
            } = step
            {
                let unsupported_replay_modifier = !config.fields.is_empty()
                    || !config.ext_deltas.is_empty()
                    || config.mutations.iter().any(|entry| {
                        entry.dtls_frag.is_some()
                            || entry.mutations.iter().any(|mutation| match &mutation.op {
                                MutationOp::RecordVersion(_) => false,
                                MutationOp::Xor { target, .. } | MutationOp::Set { target, .. } => {
                                    !target.is_record_level()
                                }
                                _ => true,
                            })
                    });
                if sent_hello
                    && config.send
                    && config.message == MessageKind::ClientHello
                    && unsupported_replay_modifier
                {
                    errors.push(LowerError { span: step.span(), message: "a repeated TLS 1.3 ClientHello replays CH1; field, extension and handshake modifiers on that replay are not implemented".into() });
                }
            }
            match step {
                Step::Handshake { .. } => sent_hello = true,
                Step::HandshakeSteps { steps, .. }
                    if steps.contains(&ir::HandshakeStep::Send(MessageKind::ClientHello)) =>
                {
                    sent_hello = true
                }
                _ => {}
            }
        }
    }
    for declarations in [&send_overrides, &recv_matchers] {
        for (index, declaration) in declarations.iter().enumerate() {
            for prior in &declarations[..index] {
                if prior.message == declaration.message {
                    for field in &declaration.fields {
                        if prior
                            .fields
                            .iter()
                            .any(|p| p.field == field.field && p.value != field.value)
                        {
                            errors.push(LowerError { span: flow.span, message: format!("conflicting preset declarations for {:?}.{}; use an explicit flow for occurrence-specific values", declaration.message, field.field) });
                        }
                    }
                }
            }
        }
    }
    for (index, declaration) in send_mutations.iter().enumerate() {
        if declaration.dtls_frag.is_some()
            && send_mutations[..index]
                .iter()
                .any(|prior| prior.message == declaration.message && prior.dtls_frag.is_some())
        {
            errors.push(LowerError {
                span: flow.span,
                message: format!(
                    "multiple fragmentation schemes for preset message {:?}",
                    declaration.message
                ),
            });
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    merge_message_lists(
        &mut send_overrides,
        &mut send_mutations,
        &mut send_ext_deltas,
    );
    merge_message_lists(&mut recv_matchers, &mut Vec::new(), &mut Vec::new());
    Ok(Program {
        test_id: format!("{}{}", test.name.value, format_case_suffix(binding)),
        test_id_span: test.name.span,
        version,
        protocol,
        subject,
        server_name,
        // TLS 1.3 server selection must consume general cipher/hash filters
        // too, not just named suites. The validated set includes a `suite`
        // matrix pin; legacy drivers read `suite_filters` directly.
        server_suites: if version == TlsVersion::Tls13 && !peer_suite_filters.is_empty() {
            peer_suites
        } else {
            match binding.iter().find(|(n, _)| n == "suite") {
                Some((_, w)) => vec![*w as u16],
                None => server_suites,
            }
        },
        server_groups: match binding.iter().find(|(n, _)| n == "group") {
            Some((_, g)) => vec![*g as u16],
            None => server_groups.clone(),
        },
        key_share_groups: binding
            .iter()
            .find(|(n, _)| n == "group")
            .map(|(_, g)| vec![*g as u16])
            .unwrap_or_default(),
        force_hrr: hrr,
        steps,
        mutation_messages,
        expect,
        expect_overrides,
        rfc_refs,
        send_overrides,
        recv_matchers,
        send_mutations,
        send_ext_deltas,
        reneg_send_overrides,
        reneg_send_mutations,
        reneg_send_ext_deltas,
        // Cert/key are populated by the runtime (from a CertBundle)
        // before execution, not at lowering time. Lowering doesn't
        // know which cert type the server will generate.
        cert_der: None,
        private_key_der: None,
        chain_names,
        client_chain_names,
        ecdhe_by_chain,
        server_chains: Vec::new(),
        client_credentials: Vec::new(),
        shim_server_chains: Vec::new(),
        shim_client_chains: Vec::new(),
        extra_chain_der: Vec::new(),
        session_name: None,
        resumes: None,
        force_resumption: false,
        advertise_psk_modes: session_ticket,
        resume_by_session_id,
        resume_psk_ke,
        offer_raw_public_key: offer_rpk,
        server_compress_certificate: compress_cert,
        cert_request_authorities: Vec::new(),
        // Clients advertise these schemes; the legacy server uses them as
        // signing preferences. Unsupported server roles were rejected above.
        client_signature_schemes: if !server_sigalgs.is_empty() {
            Some(server_sigalgs.clone())
        } else {
            None
        },
        skip_backends,
        xfail_backends,
        asserts,
        // T1: every repetition (and matrix point) of a test with cross-run
        // asserts belongs to the group named by the test and its non-repeat
        // binding, so `assert unique` compares the right programs.
        repeat_group: if cross_asserts.is_empty() {
            None
        } else {
            let non_repeat: Vec<(String, i64)> = binding
                .iter()
                .filter(|(n, _)| n != "repeat")
                .cloned()
                .collect();
            Some(format!(
                "{}{}",
                test.name.value,
                format_case_suffix(&non_repeat)
            ))
        },
        cross_asserts,
        psk: case_has_psk
            .then_some(test.psk.as_ref())
            .flatten()
            .map(|p| ir::PskConfig {
                identity: p.identity.value.as_bytes().to_vec(),
                secret: p.secret.clone(),
                offers: p
                    .offers
                    .iter()
                    .map(|offer| ir::PskOfferConfig {
                        identity: offer.identity.value.as_bytes().to_vec(),
                        secret: offer.secret.clone(),
                        hash: if offer.hash.name == "sha384" {
                            crate::tls::crypto::HashAlg::Sha384
                        } else {
                            crate::tls::crypto::HashAlg::Sha256
                        },
                        is_external: true,
                        obfuscated_ticket_age: 0,
                    })
                    .collect(),
                ke_only: false,
                is_external: true,
                obfuscated_ticket_age: 0,
                cipher_suite: None,
                max_early_data_size: 0,
            }),
        uut: test.uut.as_ref().map(|u| ir::UutConfig {
            versions: resolved_uut_versions.clone(),
            cipher_suites: uut_suites,
            curves: uut_curves,
            require_client_cert: u.require_client_cert,
            request_client_cert: u.request_client_cert,
            verify_peer: u.verify_peer,
            alpn_advertise: u.alpn_advertise.clone(),
            alpn_select: u.alpn_select.clone(),
            alpn_select_from: u.alpn_select_from.clone(),
            expect_alpn: u.expect_alpn.clone(),
            alpn_decline: u.alpn_decline,
            srtp_profiles: u.srtp_profiles.clone(),
            expect_srtp_profile: u.expect_srtp_profile,
            signing_prefs: u.signing_prefs.clone(),
            verify_prefs: u.verify_prefs.clone(),
            server_preference: u.server_preference,
            renegotiation: u.renegotiation.clone(),
            session_tickets: u.session_tickets,
            max_early_data: u.max_early_data,
            max_cert_list: u.max_cert_list,
            record_size_limit: u.record_size_limit,
            records_per_traffic_key: u.records_per_traffic_key,
            key_update: u.key_update,
            extended_master_secret: u.extended_master_secret.clone(),
            encrypt_then_mac: u.encrypt_then_mac,
            middlebox_compat: u.middlebox_compat,
            compress_certificate: u.compress_certificate,
            raw_public_key: u.raw_public_key,
            server_certificate_types: if u.raw_public_key {
                vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY]
            } else {
                u.server_certificate_types
                    .iter()
                    .filter_map(|t| crate::schema::cert_type_value(&t.name))
                    .collect()
            },
            client_certificate_types: if u.raw_public_key {
                vec![crate::tls::codec::CERT_TYPE_RAW_PUBLIC_KEY]
            } else {
                u.client_certificate_types
                    .iter()
                    .filter_map(|t| crate::schema::cert_type_value(&t.name))
                    .collect()
            },
            mtu: u.mtu,
            initial_timeout_ms: u.initial_timeout_ms,
            dtls_max_retransmissions: u.dtls_max_retransmissions,
            dtls_max_timeout_ms: u.dtls_max_timeout_ms,
            dtls_require_cookie: u.dtls_require_cookie,
            dtls_epoch0_restart: u.dtls_epoch0_restart,
            dtls_max_hello_verify_requests: u.dtls_max_hello_verify_requests,
            min_key_update_interval_ms: u.min_key_update_interval_ms,
            psk_secret: u.psk_secret.clone(),
            psk_identity: u.psk_identity.clone(),
            client_cert: u.client_cert.clone(),
            renegotiate_after_handshake: u.renegotiate_after_handshake,
            hello_request_after_app_data: u.hello_request_after_app_data,
            require_client_cert_on_renegotiation: u.require_client_cert_on_renegotiation,
            half_rtt_data: u.half_rtt_data.clone(),
            ocsp_stapling: u.ocsp_stapling,
            post_handshake_auth: u.post_handshake_auth.clone(),
        }),
        suite_filters: {
            // If the matrix binds a `suite` variable, pin the
            // offered suite list to exactly that wire value.
            // If it binds `cert`, filter to cert-compatible kex.
            let mut sf = suite_filters;
            for (name, value) in binding {
                match name.as_str() {
                    "suite" => sf.push(ir::SuiteFilter::Exact(*value as u16)),
                    "cert" => match *value {
                        0 => sf.push(ir::SuiteFilter::Kex(ir::KexType::EcdheEcdsa)),
                        1 => sf.push(ir::SuiteFilter::Kex(ir::KexType::EcdheRsa)),
                        _ => {}
                    },
                    _ => {}
                }
            }
            sf
        },
    })
}

fn resolve_renegotiation_msg_type(
    overrides: &[ast::FieldOverride],
    binding: &[(String, i64)],
) -> Result<Option<u8>, String> {
    if let Some(ov) = overrides.first() {
        if ov.field.name == "msg_type" {
            let n = extract_int(&ov.value, binding, ov.span).map_err(|e| e.message)?;
            if !(0..=255).contains(&n) {
                return Err(format!("msg_type {} out of range (0..255)", n));
            }
            return Ok(Some(n as u8));
        }
        return Err(format!("unknown Renegotiation field `{}`", ov.field.name));
    }
    Ok(None)
}

fn resolve_key_update_request(overrides: &[ast::FieldOverride]) -> Result<u8, String> {
    for ov in overrides {
        if ov.field.name == "request_update" {
            return match &ov.value {
                ast::FieldValue::Ident(s) => match s.name.as_str() {
                    "update_requested" => Ok(1),
                    "update_not_requested" => Ok(0),
                    other => Err(format!(
                        "unknown request_update value `{}`; expected \
                         `update_requested` or `update_not_requested`",
                        other
                    )),
                },
                ast::FieldValue::Int(n) => Ok(n.value as u8),
                _ => Err("request_update must be an enum constant or integer".into()),
            };
        }
    }
    Err("KeyUpdate requires a `request_update` field".into())
}

fn lower_send_app_data(
    msg: &MessageRef,
    overrides: &[ast::FieldOverride],
    mutations: Vec<ir::Mutation>,
    span: Span,
    binding: &[(String, i64)],
) -> Result<Step, LowerError> {
    if msg.payload.is_some() {
        return Err(LowerError {
            span,
            message: "literal AppData payloads are no longer supported; use `send AppData` or `send AppData { size: N, reply: M }`".into(),
        });
    }

    let mut size = crate::app_data::DEFAULT_SIZE;
    let mut reply_size = None;
    let mut reply_was_set = false;
    let mut size_was_set = false;
    for field in overrides {
        match field.field.name.as_str() {
            "size" if size_was_set => {
                return Err(LowerError {
                    span: field.span,
                    message: "duplicate AppData `size` field".into(),
                });
            }
            "size" => match extract_int(&field.value, binding, field.span) {
                Ok(n) if (0..=crate::app_data::MAX_SIZE as i64).contains(&n) => {
                    size = n as usize;
                    size_was_set = true;
                }
                Ok(n) => {
                    return Err(LowerError {
                        span: field.span,
                        message: format!("AppData size {} out of range", n),
                    });
                }
                Err(_) => {
                    return Err(LowerError {
                        span: field.span,
                        message: "AppData `size` must be a non-negative integer or matrix variable"
                            .into(),
                    });
                }
            },
            "reply" if reply_was_set => {
                return Err(LowerError {
                    span: field.span,
                    message: "duplicate AppData `reply` field".into(),
                });
            }
            "reply" => {
                reply_was_set = true;
                if matches!(&field.value, ast::FieldValue::Ident(v) if v.name == "none") {
                    reply_size = None;
                    continue;
                }
                match extract_int(&field.value, binding, field.span) {
                    Ok(n) if (1..=crate::app_data::MAX_SIZE as i64).contains(&n) => {
                        reply_size = Some(n as usize);
                    }
                    Ok(n) => {
                        return Err(LowerError {
                            span: field.span,
                            message: format!(
                                "AppData reply size {} out of range (1..={}) or use `none`",
                                n,
                                crate::app_data::MAX_SIZE
                            ),
                        });
                    }
                    Err(_) => {
                        return Err(LowerError {
                            span: field.span,
                            message: "AppData `reply` must be a positive integer, matrix variable, or `none`".into(),
                        });
                    }
                }
            }
            other => {
                return Err(LowerError {
                    span: field.field.span,
                    message: format!(
                        "send AppData takes only `size` and `reply`, not `{}`",
                        other
                    ),
                });
            }
        }
    }
    if !reply_was_set {
        reply_size = (size != 0).then_some(size);
    }
    if size != 0 && size < crate::app_data::HEADER_LEN && reply_size != Some(size) {
        return Err(LowerError {
            span,
            message: format!(
                "AppData shorter than {} bytes can only use the default same-size reply",
                crate::app_data::HEADER_LEN
            ),
        });
    }
    Ok(Step::SendAppData {
        size,
        reply_size,
        mutations,
        span,
    })
}

fn lower_exporter(
    fields: &[ast::FieldOverride],
    binding: &[(String, i64)],
    span: Span,
) -> Result<ExporterParams, LowerError> {
    let mut label = None;
    let mut context = None;
    let mut context_seen = false;
    let mut length = 32usize;
    let mut length_seen = false;
    for field in fields {
        match field.field.name.as_str() {
            "label" if label.is_none() => match &field.value {
                ast::FieldValue::Str(s) => label = Some(s.value.as_bytes().to_vec()),
                _ => {
                    return Err(LowerError {
                        span: field.span,
                        message: "Exporter `label` must be a string".into(),
                    });
                }
            },
            "context" if !context_seen => {
                context_seen = true;
                match &field.value {
                    ast::FieldValue::Str(s) => context = Some(s.value.as_bytes().to_vec()),
                    ast::FieldValue::Ident(v) if v.name == "none" => context = None,
                    _ => {
                        return Err(LowerError {
                            span: field.span,
                            message: "Exporter `context` must be a string or `none`".into(),
                        });
                    }
                }
            }
            "length" if !length_seen => {
                length_seen = true;
                match extract_int(&field.value, binding, field.span) {
                    Ok(n) if (1..=65535).contains(&n) => length = n as usize,
                    Ok(n) => {
                        return Err(LowerError {
                            span: field.span,
                            message: format!("Exporter length {} out of range (1..=65535)", n),
                        });
                    }
                    Err(_) => {
                        return Err(LowerError {
                            span: field.span,
                            message:
                                "Exporter `length` must be a positive integer or matrix variable"
                                    .into(),
                        });
                    }
                }
            }
            "label" | "context" | "length" => {
                return Err(LowerError {
                    span: field.span,
                    message: format!("duplicate Exporter `{}` field", field.field.name),
                });
            }
            other => {
                return Err(LowerError {
                    span: field.span,
                    message: format!(
                        "Exporter takes only `label`, `context`, and `length`, not `{}`",
                        other
                    ),
                });
            }
        }
    }
    let label = label.ok_or_else(|| LowerError {
        span,
        message: "Exporter requires a `label` string".into(),
    })?;
    if matches!(
        label.as_slice(),
        b"client finished" | b"server finished" | b"master secret" | b"key expansion"
    ) {
        return Err(LowerError {
            span,
            message: "Exporter label collides with a TLS PRF label reserved by RFC 5705".into(),
        });
    }
    Ok((label, context, length))
}

fn lower_early_data_size(
    fields: &[ast::FieldOverride],
    binding: &[(String, i64)],
    span: Span,
    sending: bool,
) -> Result<Option<usize>, LowerError> {
    let mut size = None;
    for field in fields {
        if field.field.name != "size" {
            return Err(LowerError {
                span: field.field.span,
                message: format!(
                    "{} EarlyData takes only `size`, not `{}`",
                    if sending { "send" } else { "recv" },
                    field.field.name
                ),
            });
        }
        if size.is_some() {
            return Err(LowerError {
                span: field.span,
                message: "duplicate EarlyData `size` field".into(),
            });
        }
        match extract_int(&field.value, binding, field.span) {
            Ok(n) if (0..=crate::app_data::MAX_SIZE as i64).contains(&n) => size = Some(n as usize),
            Ok(n) => {
                return Err(LowerError {
                    span: field.span,
                    message: format!("EarlyData size {} out of range", n),
                });
            }
            Err(_) => {
                return Err(LowerError {
                    span: field.span,
                    message: "EarlyData `size` must be a non-negative integer or matrix variable"
                        .into(),
                });
            }
        }
    }
    if sending && size == Some(0) {
        return Err(LowerError {
            span,
            message: "send EarlyData size must be positive".into(),
        });
    }
    Ok(size)
}

// ============================================================
//        T1: the shared value grammar (lists and generators)
// ============================================================

/// One resolved element of a list-valued expression: ranges, repeats and
/// nested lists are already expanded; names stay names for the consumer's
/// lookup table; `key : value` entries keep both sides.
#[derive(Clone, Debug)]
enum Item {
    Int(i64, Span),
    Name(String, Span),
    Str(String, Span),
    Entry {
        key: Vec<Item>,
        value: Vec<Item>,
        span: Span,
    },
}

/// Expand a value expression into flat items. Bounds: a range spans at most
/// 65536 values and a repeat produces at most 2^24 items.
fn flatten_value(
    v: &ast::FieldValue,
    binding: &[(String, i64)],
    out: &mut Vec<Item>,
) -> Result<(), LowerError> {
    match v {
        ast::FieldValue::Int(i) => out.push(Item::Int(i.value, i.span)),
        ast::FieldValue::Ident(id) => out.push(Item::Name(id.name.clone(), id.span)),
        ast::FieldValue::Str(lit) => out.push(Item::Str(lit.value.clone(), lit.span)),
        ast::FieldValue::Empty => {}
        // T4's `file "path"`: the file's bytes as items.
        ast::FieldValue::File(p) => {
            let bytes = std::fs::read(&p.value).map_err(|e| LowerError {
                span: p.span,
                message: format!("cannot read `{}`: {}", p.value, e),
            })?;
            for b in bytes {
                out.push(Item::Int(i64::from(b), p.span));
            }
        }
        ast::FieldValue::List(items) => {
            for it in items {
                flatten_value(it, binding, out)?;
            }
        }
        ast::FieldValue::MatrixVar(id) => {
            let n = lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("`${}` is not a matrix variable in this test", id.name),
            })?;
            out.push(Item::Int(n, id.span));
        }
        ast::FieldValue::Range {
            lo,
            hi,
            span: rspan,
        } => {
            let lo = resolve_int_or_var(lo, binding)?;
            let hi = resolve_int_or_var(hi, binding)?;
            if lo > hi {
                return Err(LowerError {
                    span: *rspan,
                    message: format!("range `{}..{}` is empty; lo must be <= hi", lo, hi),
                });
            }
            if hi - lo > 65536 {
                return Err(LowerError {
                    span: *rspan,
                    message: format!("range `{}..{}` spans more than 65536 values", lo, hi),
                });
            }
            for x in lo..=hi {
                out.push(Item::Int(x, *rspan));
            }
        }
        ast::FieldValue::Repeat {
            item,
            count,
            span: rspan,
        } => {
            let n = resolve_int_or_var(count, binding)?;
            if n < 0 {
                return Err(LowerError {
                    span: *rspan,
                    message: format!("repeat count {} is negative", n),
                });
            }
            // `"A" * N` is ONE string of N copies (a payload, a 255-byte ALPN
            // name); `["A"] * N` is N entries.
            if let ast::FieldValue::Str(st) = &**item {
                if (st.value.len() as i64).saturating_mul(n) > (1 << 24) {
                    return Err(LowerError {
                        span: *rspan,
                        message: "repeat expands to more than 2^24 bytes".into(),
                    });
                }
                out.push(Item::Str(st.value.repeat(n as usize), st.span));
                return Ok(());
            }
            let mut one = Vec::new();
            flatten_value(item, binding, &mut one)?;
            if (one.len() as i64).saturating_mul(n) > (1 << 24) {
                return Err(LowerError {
                    span: *rspan,
                    message: "repeat expands to more than 2^24 items".into(),
                });
            }
            for _ in 0..n {
                out.extend(one.iter().cloned());
            }
        }
        ast::FieldValue::Entry {
            key,
            value,
            span: espan,
        } => {
            let mut k = Vec::new();
            flatten_value(key, binding, &mut k)?;
            let mut val = Vec::new();
            flatten_value(value, binding, &mut val)?;
            out.push(Item::Entry {
                key: k,
                value: val,
                span: *espan,
            });
        }
        ast::FieldValue::Capture(id) => {
            return Err(LowerError {
                span: id.span,
                message: "`capture $name` is only valid as the whole value of a `recv` matcher"
                    .into(),
            });
        }
    }
    Ok(())
}

/// Items as bytes: numbers are single bytes, strings their UTF-8 bytes.
fn items_to_bytes(items: &[Item], span: Span) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Item::Int(v, sp) => out.push(range_u8(*v, *sp)?),
            Item::Str(st, _) => out.extend_from_slice(st.as_bytes()),
            Item::Name(n, sp) => {
                return Err(LowerError {
                    span: *sp,
                    message: format!(
                        "`{}` is not a byte value; byte lists take numbers and strings",
                        n
                    ),
                });
            }
            Item::Entry { span: sp, .. } => {
                return Err(LowerError {
                    span: *sp,
                    message: "a `key : value` entry is not a byte value".into(),
                });
            }
        }
    }
    let _ = span;
    Ok(out)
}

/// Items as u16 wire values: numbers as-is (range-checked), names through
/// `lookup`.
fn items_to_u16s(
    items: &[Item],
    lookup: &dyn Fn(&str) -> Option<u16>,
    what: &str,
    hint: &str,
) -> Result<Vec<u16>, LowerError> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Item::Int(v, sp) => out.push(range_u16(*v, *sp)?),
            Item::Name(n, sp) => match lookup(n) {
                Some(w) => out.push(w),
                None => {
                    return Err(LowerError {
                        span: *sp,
                        message: format!("unknown {} `{}`; {}", what, n, hint),
                    });
                }
            },
            Item::Str(_, sp) => {
                return Err(LowerError {
                    span: *sp,
                    message: format!("a string is not a {}; {}", what, hint),
                });
            }
            Item::Entry { span: sp, .. } => {
                return Err(LowerError {
                    span: *sp,
                    message: format!("a `key : value` entry is not a {}", what),
                });
            }
        }
    }
    Ok(out)
}

fn items_to_u8s(
    items: &[Item],
    lookup: &dyn Fn(&str) -> Option<u8>,
    what: &str,
    hint: &str,
) -> Result<Vec<u8>, LowerError> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Item::Int(v, sp) => out.push(range_u8(*v, *sp)?),
            Item::Name(n, sp) => match lookup(n) {
                Some(w) => out.push(w),
                None => {
                    return Err(LowerError {
                        span: *sp,
                        message: format!("unknown {} `{}`; {}", what, n, hint),
                    });
                }
            },
            Item::Str(_, sp) => {
                return Err(LowerError {
                    span: *sp,
                    message: format!("a string is not a {}; {}", what, hint),
                });
            }
            Item::Entry { span: sp, .. } => {
                return Err(LowerError {
                    span: *sp,
                    message: format!("a `key : value` entry is not a {}", what),
                });
            }
        }
    }
    Ok(out)
}

fn items_to_strs(items: &[Item], what: &str) -> Result<Vec<ast::StrLit>, LowerError> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Item::Str(st, sp) => out.push(ast::StrLit {
                value: st.clone(),
                span: *sp,
            }),
            Item::Int(_, sp) | Item::Name(_, sp) | Item::Entry { span: sp, .. } => {
                return Err(LowerError {
                    span: *sp,
                    message: format!("{} takes a list of strings", what),
                });
            }
        }
    }
    Ok(out)
}

/// Unroll `repeat N { ... }` blocks (recursively) into a flat step list.
fn unroll_repeats(
    steps: &[ast::Step],
    binding: &[(String, i64)],
    out: &mut Vec<ast::Step>,
) -> Result<(), LowerError> {
    for st in steps {
        if let ast::Step::Repeat {
            count,
            steps: inner,
            span,
        } = st
        {
            let n = resolve_int_or_var(count, binding)?;
            if !(0..=4096).contains(&n) {
                return Err(LowerError {
                    span: *span,
                    message: format!("repeat count {} out of range (0..4096)", n),
                });
            }
            for _ in 0..n {
                unroll_repeats(inner, binding, out)?;
            }
        } else {
            out.push(st.clone());
        }
    }
    Ok(())
}

/// `level/code` of an alert spec as bytes; the code may be omitted.
fn lower_alert_spec(spec: &ast::AlertSpec) -> Result<(u8, Option<u8>), LowerError> {
    let level = match spec.level.name.as_str() {
        "warning" => 1u8,
        "fatal" => 2u8,
        other => {
            return Err(LowerError {
                span: spec.level.span,
                message: format!("alert level must be `warning` or `fatal`, got `{}`", other),
            });
        }
    };
    let code = match &spec.code {
        None => None,
        Some(c) => match schema::alert_code_value(&c.name) {
            Some(v) => Some(v),
            None => {
                return Err(LowerError {
                    span: c.span,
                    message: format!("unknown alert code `{}`", c.name),
                });
            }
        },
    };
    Ok((level, code))
}

/// Lower a list of AST `FieldOverride`s (used for both `send X
/// { ... }` overrides and `recv X { ... }` matchers — they share
/// the same grammar) against the schema's type table for
/// `msg_name`. Each entry is range-checked and width-coerced.
///
/// `binding` is the current matrix case's variable assignment;
/// `$var` references in field values resolve against it.
fn lower_overrides(
    msg_name: &str,
    overrides: &[ast::FieldOverride],
    binding: &[(String, i64)],
    matcher: bool,
) -> Result<Vec<FieldOverride>, Vec<LowerError>> {
    let mut errors: Vec<LowerError> = Vec::new();
    let mut out: Vec<FieldOverride> = Vec::new();
    for o in overrides {
        let field_type = match schema::field_type(msg_name, &o.field.name) {
            Some(t) => t,
            None => {
                errors.push(LowerError {
                    span: o.field.span,
                    message: format!(
                        "`{}.{}` is not a registered field (see schema::fields_for)",
                        msg_name, o.field.name
                    ),
                });
                continue;
            }
        };
        // T2: `extensions_exactly: [renegotiation_info, ec_point_formats]` --
        // extension NAMES (or wire values) rather than group / sigalg names.
        if matcher && o.field.name == "extensions_exactly" {
            match lower_ext_type_list(&o.value, o.span, binding) {
                Ok(list) => out.push(FieldOverride {
                    field: o.field.name.clone(),
                    value: FieldValue::U16List(list),
                    span: o.span,
                }),
                Err(e) => errors.push(e),
            }
            continue;
        }
        // T2: an any-of matcher on a u16 field (`named_group: [ffdhe2048,
        // ffdhe3072]`) lowers to the list; the driver accepts any member.
        let field_type = if matcher
            && field_type == FieldType::U16
            && matches!(o.value, ast::FieldValue::List(_))
        {
            FieldType::U16List
        } else if o.field.name == "dh_p" && matches!(o.value, ast::FieldValue::Ident(_)) {
            // A named prime (`dh_p: rfc5114_2048_256`) next to the exact bytes.
            FieldType::Enum
        } else {
            field_type
        };
        match resolve_field_value(field_type, &o.value, o.span, binding) {
            Ok(value) => {
                if matcher && matches!(o.field.name.as_str(), "dh_p" | "dh_g" | "dh_Ys") {
                    errors.push(LowerError {
                        span: o.span,
                        message: format!(
                            "`ServerKeyExchange.{}` is a send-only explicit-DH parameter; use `dh_group` to match a known group",
                            o.field.name
                        ),
                    });
                    continue;
                }
                if matches!(o.field.name.as_str(), "dh_p" | "dh_g" | "dh_Ys")
                    && matches!(&value, FieldValue::Bytes(bytes) if bytes.len() > u16::MAX as usize)
                {
                    errors.push(LowerError {
                        span: o.span,
                        message: format!(
                            "`ServerKeyExchange.{}` is a u16-length-prefixed value and cannot exceed 65535 bytes",
                            o.field.name
                        ),
                    });
                    continue;
                }
                if let Some(msg) = validate_enum_override(&o.field.name, &value) {
                    errors.push(LowerError {
                        span: o.span,
                        message: msg,
                    });
                    continue;
                }
                out.push(FieldOverride {
                    field: o.field.name.clone(),
                    value,
                    span: o.span,
                })
            }
            Err(e) => errors.push(e),
        }
    }
    if !matcher
        && msg_name == "ServerKeyExchange"
        && out.iter().any(|o| o.field == "dh_p_bits")
        && out.iter().any(|o| o.field == "dh_p")
    {
        errors.push(LowerError {
            span: overrides
                .iter()
                .find(|o| o.field.name == "dh_p")
                .map(|o| o.span)
                .expect("dh_p override was found above"),
            message: "`ServerKeyExchange` cannot set both `dh_p_bits` and exact `dh_p`".into(),
        });
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// T2: `[renegotiation_info, 0x000b]` -> extension wire types.
fn lower_ext_type_list(
    v: &ast::FieldValue,
    span: Span,
    binding: &[(String, i64)],
) -> Result<Vec<u16>, LowerError> {
    let items = match v {
        ast::FieldValue::List(items) => items.as_slice(),
        ast::FieldValue::Empty => &[],
        _ => {
            return Err(LowerError {
                span,
                message: "`extensions_exactly` takes a list of extension names or wire types"
                    .into(),
            });
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match it {
            ast::FieldValue::Ident(id) => match schema::extension_wire_type(&id.name) {
                Some(w) => out.push(w),
                None => {
                    return Err(LowerError {
                        span: id.span,
                        message: format!("`{}` is not a known TLS extension", id.name),
                    });
                }
            },
            other => {
                let n = extract_int(other, binding, span)?;
                out.push(range_u16(n, span)?);
            }
        }
    }
    Ok(out)
}

/// T2: `ext NAME == value` -> a `FieldOverride { field: "ext" }` whose bytes
/// are `type(2) || expected body`, the body encoded by the same typed encoders
/// as `+ext NAME = value`.
fn lower_ext_matcher(
    em: &ast::ExtMatcher,
    binding: &[(String, i64)],
) -> Result<FieldOverride, LowerError> {
    let wire = match &em.target {
        ast::ExtTarget::Wire(w, _) => *w,
        ast::ExtTarget::Named(n) => {
            schema::extension_wire_type(&n.name).ok_or_else(|| LowerError {
                span: n.span,
                message: format!("`{}` is not a known TLS extension", n.name),
            })?
        }
        // T1: `ext $id == ...` -- the matrix variable holds the wire type.
        ast::ExtTarget::Var(v) => lookup_binding(binding, &v.name)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| LowerError {
                span: v.span,
                message: format!(
                    "`${}` is not bound to an extension type (0..0xffff)",
                    v.name
                ),
            })?,
    };
    let body = encode_ext_body(&em.target, &em.value, em.span, binding)?;
    let mut bytes = wire.to_be_bytes().to_vec();
    bytes.extend_from_slice(&body);
    Ok(FieldOverride {
        field: "ext".into(),
        value: FieldValue::Bytes(bytes),
        span: em.span,
    })
}

/// Move declarations off the preset lists and onto their executable occurrence.
fn take_send_config(
    message: MessageKind,
    start: (usize, usize, usize),
    fields: &mut Vec<MessageOverrides>,
    mutations: &mut Vec<ir::MessageMutations>,
    deltas: &mut Vec<ir::MessageExtDeltas>,
) -> ir::MessageConfig {
    ir::MessageConfig {
        message,
        send: true,
        fields: fields
            .split_off(start.0)
            .into_iter()
            .flat_map(|m| m.fields)
            .collect(),
        mutations: mutations.split_off(start.1),
        ext_deltas: deltas.split_off(start.2),
    }
}

fn merge_message_lists(
    fields: &mut Vec<MessageOverrides>,
    mutations: &mut Vec<ir::MessageMutations>,
    deltas: &mut Vec<ir::MessageExtDeltas>,
) {
    let mut merged: Vec<MessageOverrides> = vec![];
    for entry in fields.drain(..) {
        if let Some(prior) = merged.iter_mut().find(|m| m.message == entry.message) {
            prior.fields.extend(entry.fields);
        } else {
            merged.push(entry);
        }
    }
    *fields = merged;
    let mut merged: Vec<ir::MessageMutations> = vec![];
    for entry in mutations.drain(..) {
        if let Some(prior) = merged.iter_mut().find(|m| m.message == entry.message) {
            prior.mutations.extend(entry.mutations);
            if entry.dtls_frag.is_some() {
                prior.dtls_frag = entry.dtls_frag;
            }
        } else {
            merged.push(entry);
        }
    }
    *mutations = merged;
    let mut merged: Vec<ir::MessageExtDeltas> = vec![];
    for entry in deltas.drain(..) {
        if let Some(prior) = merged.iter_mut().find(|m| m.message == entry.message) {
            prior.deltas.extend(entry.deltas);
        } else {
            merged.push(entry);
        }
    }
    *deltas = merged;
}

/// These fields are consumed outside the shared ClientHello override handler;
/// reject other protocol cells instead of letting its no-op arms swallow them.
fn validate_hello_field_context(
    kind: MessageKind,
    overrides: &[ast::FieldOverride],
    version: TlsVersion,
    protocol: ir::Protocol,
) -> Result<(), LowerError> {
    if !matches!(
        kind,
        MessageKind::ClientHello | MessageKind::ClientHelloRetry
    ) {
        return Ok(());
    }
    for field in overrides {
        let required = match field.field.name.as_str() {
            "cookie" if protocol != ir::Protocol::Dtls => "DTLS",
            "key_share_point" if version != TlsVersion::Tls13 => "TLS 1.3 or DTLS 1.3",
            _ => continue,
        };
        return Err(LowerError {
            span: field.span,
            message: format!(
                "`ClientHello.{}` requires {required}; this driver does not consume that field",
                field.field.name
            ),
        });
    }
    Ok(())
}

/// Refuse field overrides in driver cells that do not consume them.
fn send_overrides_supported_on(
    subject: Subject,
    version: TlsVersion,
    protocol: ir::Protocol,
    kind: MessageKind,
) -> Result<(), String> {
    let unsupported = match kind {
        MessageKind::Alert => true,
        MessageKind::Finished
            if subject == Subject::Client
                && !(protocol == ir::Protocol::Dtls && version == TlsVersion::Tls12) =>
        {
            true
        }
        MessageKind::CertificateRequest
            if version == TlsVersion::Tls13 && subject == Subject::Client =>
        {
            true
        }
        _ => false,
    };
    if unsupported {
        Err(format!(
            "`send {} {{ ... }}` field overrides are not implemented by this {} {} {} driver",
            kind.name(),
            match protocol {
                ir::Protocol::Tls => "TLS",
                ir::Protocol::Dtls => "DTLS",
            },
            match version {
                TlsVersion::Tls10 => "1.0",
                TlsVersion::Tls11 => "1.1",
                TlsVersion::Tls12 => "1.2",
                TlsVersion::Tls13 => "1.3",
            },
            match subject {
                Subject::Server => "client",
                Subject::Client => "server",
            }
        ))
    } else {
        Ok(())
    }
}

/// T2: the record-layer mutation ops the drivers of this version / protocol
/// cannot apply -- reported at lint time rather than as a runtime error.
fn t2_unsupported_mutation(
    muts: &[ir::Mutation],
    version: TlsVersion,
    protocol: ir::Protocol,
    handshake_payload: bool,
) -> Option<String> {
    let dtls = protocol == ir::Protocol::Dtls;
    for m in muts {
        let what: Option<(&str, &str)> = match &m.op {
            MutationOp::Fragment { .. } if dtls && !handshake_payload => {
                Some(("fragment", "defined only for handshake messages over DTLS"))
            }
            MutationOp::TrailingBytes(_) | MutationOp::OmitPrefix(_) if !handshake_payload => {
                Some((
                    "trailing/omit_prefix",
                    "defined only for TLS handshake messages",
                ))
            }
            MutationOp::RecordVersion(_) if dtls => {
                Some(("record_version", "a TLS record-layer control"))
            }
            MutationOp::RecordPad(_) if dtls && version != TlsVersion::Tls13 => {
                Some(("record_pad", "a TLS/DTLS 1.3 record-layer control"))
            }
            MutationOp::RecordPad(_) if version != TlsVersion::Tls13 => Some((
                "record_pad",
                "TLS 1.3 record padding (RFC 8446 5.4); the test needs `uut client|server { versions: [tls13] }`",
            )),
            MutationOp::Dtls13ShortSequence
            | MutationOp::Dtls13OmitLength
            | MutationOp::Dtls13SetCidBit
            | MutationOp::Dtls13LegacyHeader
                if !dtls || version != TlsVersion::Tls13 =>
            {
                Some((
                    "dtls13_* header control",
                    "a DTLS 1.3 record-header control; the test needs `uut client|server { versions: [dtls13] }`",
                ))
            }
            MutationOp::Plaintext | MutationOp::ReplacePlaintext(_)
                if dtls && version != TlsVersion::Tls13 =>
            {
                Some(("plaintext", "a TLS/DTLS 1.3 record-layer control"))
            }
            MutationOp::CbcPad(_) if dtls => Some(("cbc_pad", "a TLS record-layer control")),
            MutationOp::CbcPad(_) if !version.is_legacy() => Some((
                "cbc_pad",
                "CBC padding control (legacy TLS block-cipher suites); the test needs a TLS 1.0-1.2 version",
            )),
            MutationOp::Fragment { hold, .. } if hold.holds() && dtls => {
                Some(("fragment ... hold", "a TLS record-layer control"))
            }
            MutationOp::TrailingBytes(_) | MutationOp::OmitPrefix(_) if dtls => Some((
                "trailing/omit_prefix",
                "TLS stream-handshake boundary controls",
            )),
            MutationOp::Xor { target, .. } | MutationOp::Set { target, .. }
                if target.is_record_level() =>
            {
                match target.field_name() {
                    Some("inner_type") if version != TlsVersion::Tls13 => Some((
                        "record.inner_type",
                        "the TLS 1.3 inner content type; the test needs `uut client|server { versions: [tls13] }`",
                    )),
                    Some("padding") if !version.is_legacy() || dtls => Some((
                        "record.padding",
                        "legacy TLS CBC padding; the test needs a TLS 1.0-1.2 version",
                    )),
                    Some("plaintext") if dtls && version != TlsVersion::Tls13 => {
                        Some(("record.plaintext", "a TLS/DTLS 1.3 record-layer target"))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some((op, why)) = what {
            return Some(format!("`@ {}` is {}", op, why));
        }
    }
    None
}

/// Per-field vocabulary for enum-valued overrides, checked at lint time so a
/// typo does not surface as a runtime error.
fn validate_enum_override(field: &str, value: &FieldValue) -> Option<String> {
    let FieldValue::Ident(name) = value else {
        return None;
    };
    let allowed: &[&str] = match field {
        // T4: also `p`, `all_ones`, `empty`, `hybrid`, a group name (a valid
        // share of that group under this entry's id) or a byte list.
        "key_share_point" => {
            if schema::group_wire_value(name).is_some() {
                return None;
            }
            &[
                "compressed",
                "zero",
                "truncated",
                "padded",
                "one",
                "p_minus_1",
                "p",
                "all_ones",
                "empty",
                "hybrid",
                "xy",
            ]
        }
        "dh_p" => &["rfc5114_2048_256"],
        "dh_g" | "dh_Ys" => &[
            "zero",
            "one",
            "two",
            "p_minus_1",
            "p",
            "p_plus_1",
            "small_order",
        ],
        "psk_mode" => &["psk_ke", "psk_dhe_ke"],
        // T3: typed client credentials (shims/testdata/client_ee_<type>, all
        // issued by client_ee_ca), the CertificateVerify signing knobs.
        // C: `recv Certificate { leaf_key }` -- the presented leaf's key type.
        "leaf_key" => &[
            "rsa",
            "rsa_2048",
            "rsa_pss",
            "ecdsa_p256",
            "ecdsa_p384",
            "ecdsa_p521",
            "ed25519",
        ],
        "certificate_type" => &["x509", "raw_public_key"],
        "credential" => &[
            "valid",
            "rsa",
            "rsa_pss",
            "ecdsa_p256",
            "ecdsa_p384",
            "ecdsa_p521",
            "ed25519",
            "untrusted",
            "none",
        ],
        "mgf1_hash" => &["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        // `format`: CertificateVerify (T3: tls11 / tls12) and ClientHello (T6: sslv2).
        "format" => &["tls11", "tls12", "sslv2"],
        // T6: Heartbeat.type, CertificateStatus.status_type.
        "type" => &["request", "response"],
        "status_type" => &["ocsp"],
        _ => return None,
    };
    if allowed.contains(&name.as_str()) {
        None
    } else {
        Some(format!(
            "`{}` takes one of {}, not `{}`",
            field,
            allowed
                .iter()
                .map(|a| format!("`{}`", a))
                .collect::<Vec<_>>()
                .join(", "),
            name
        ))
    }
}

/// Extract an integer value from an AST `FieldValue`, resolving
/// `$var` references against the current matrix binding. Returns
/// a LowerError if the value is neither an integer literal nor a
/// bound matrix variable.
fn extract_int(
    v: &ast::FieldValue,
    binding: &[(String, i64)],
    span: Span,
) -> Result<i64, LowerError> {
    match v {
        ast::FieldValue::Int(i) => Ok(i.value),
        ast::FieldValue::MatrixVar(id) => {
            lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("`${}` is not a matrix variable in this test", id.name),
            })
        }
        _ => Err(LowerError {
            span,
            message: "expected an integer literal or matrix variable reference".into(),
        }),
    }
}

fn resolve_field_value(
    expected: FieldType,
    v: &ast::FieldValue,
    span: Span,
    binding: &[(String, i64)],
) -> Result<FieldValue, LowerError> {
    match (expected, v) {
        (FieldType::U16, ast::FieldValue::Int(_))
        | (FieldType::U16, ast::FieldValue::MatrixVar(_)) => {
            let n = extract_int(v, binding, span)?;
            range_u16(n, span).map(FieldValue::U16)
        }
        // A signature-scheme or group NAME where a u16 is expected
        // (`signature_scheme: rsa_pss_rsae_sha256`, `named_group: secp384r1`).
        (FieldType::U16, ast::FieldValue::Ident(s)) => {
            named_u16(&s.name, span).map(FieldValue::U16)
        }
        (FieldType::U8, ast::FieldValue::Int(_))
        | (FieldType::U8, ast::FieldValue::MatrixVar(_)) => {
            let n = extract_int(v, binding, span)?;
            range_u8(n, span).map(FieldValue::U8)
        }
        // T6: 32-bit fields (u24 wire lengths such as uncompressed_length).
        (FieldType::U32, ast::FieldValue::Int(_))
        | (FieldType::U32, ast::FieldValue::MatrixVar(_)) => {
            let n = extract_int(v, binding, span)?;
            if !(0..=u32::MAX as i64).contains(&n) {
                return Err(LowerError {
                    span,
                    message: format!("value {} out of range for u32 field", n),
                });
            }
            Ok(FieldValue::U32(n as u32))
        }
        // T1: `capture $name` records the peer's value instead of matching it.
        (_, ast::FieldValue::Capture(id)) => Ok(FieldValue::Capture(id.name.clone())),
        // T1: lists, ranges, repeats and strings all go through the shared
        // value grammar (`flatten_value`); names resolve as schemes/groups.
        (
            FieldType::U16List,
            ast::FieldValue::List(_)
            | ast::FieldValue::Empty
            | ast::FieldValue::Range { .. }
            | ast::FieldValue::Repeat { .. },
        ) => {
            let mut items = Vec::new();
            flatten_value(v, binding, &mut items)?;
            // D: any table's name (`cipher_suites: [AES_128_GCM_SHA256]`,
            // `extensions_exactly: [key_share]`); the tables are disjoint.
            let lookup = |n: &str| {
                schema::sigalg_wire_value(n)
                    .or_else(|| schema::group_wire_value(n))
                    .or_else(|| schema::version_wire_value(n))
                    .or_else(|| schema::suite_wire_value(n))
                    .or_else(|| schema::extension_wire_type(n))
            };
            items_to_u16s(
                &items,
                &lookup,
                "signature scheme, named group, protocol version, cipher suite, or extension",
                "use a schema name (e.g. rsa_pss_rsae_sha256, secp384r1, tls13) or a wire value",
            )
            .map(FieldValue::U16List)
        }
        (
            FieldType::U8List,
            ast::FieldValue::List(_)
            | ast::FieldValue::Empty
            | ast::FieldValue::Range { .. }
            | ast::FieldValue::Repeat { .. },
        ) => {
            let mut items = Vec::new();
            flatten_value(v, binding, &mut items)?;
            // D: ClientCertificateType names (`certificate_types: [rsa_sign, ecdsa_sign]`).
            items_to_u8s(
                &items,
                &schema::cert_type_wire_value,
                "byte value",
                "use numbers 0..255 (or a certificate type name: rsa_sign, ecdsa_sign, ...)",
            )
            .map(FieldValue::U8List)
        }
        // An empty-list literal `[]` on a Bytes field means zero bytes -- e.g.
        // `extensions: []` (ClientHello with an empty extensions block) or
        // T3: a list of NAMES on a bytes field (`certificate_list: [rsa, empty,
        // rsa]`): the driver composes the bytes from the named parts.
        (FieldType::Bytes, ast::FieldValue::List(items))
            if !items.is_empty()
                && items
                    .iter()
                    .all(|it| matches!(it, ast::FieldValue::Ident(_))) =>
        {
            let names = items
                .iter()
                .map(|it| match it {
                    ast::FieldValue::Ident(s) => s.name.clone(),
                    _ => unreachable!(),
                })
                .collect();
            Ok(FieldValue::IdentList(names))
        }
        // T4: `encrypted_premaster: modulus` -- a symbolic ciphertext the
        // driver resolves against the server key (its modulus n).
        (FieldType::Bytes, ast::FieldValue::Ident(s)) if s.name == "modulus" => {
            Ok(FieldValue::Ident(s.name.clone()))
        }
        // T4: `file "path"` -- the file's bytes, read at lowering time
        // (relative to the working directory).
        (FieldType::Bytes, ast::FieldValue::File(p)) => std::fs::read(&p.value)
            .map(FieldValue::Bytes)
            .map_err(|e| LowerError {
                span: p.span,
                message: format!("cannot read `{}`: {}", p.value, e),
            }),
        // `verify_data: []` (a zero-length Finished); strings are their UTF-8
        // bytes; `"A" * N`, `zeros N`, `[0x01, 0x00] * 512` expand.
        (
            FieldType::Bytes,
            ast::FieldValue::List(_)
            | ast::FieldValue::Empty
            | ast::FieldValue::Str(_)
            | ast::FieldValue::Range { .. }
            | ast::FieldValue::Repeat { .. },
        ) => {
            let mut items = Vec::new();
            flatten_value(v, binding, &mut items)?;
            items_to_bytes(&items, span).map(FieldValue::Bytes)
        }
        // Symbolic enum values (`key_share_point: compressed`); the driver
        // interprets the name, lower_overrides validates it per field.
        (FieldType::Enum, ast::FieldValue::Ident(s)) => Ok(FieldValue::Ident(s.name.clone())),
        // T4: `key_share_point: [0x04, ...]` / `[]` -- literal share bytes.
        // lower_overrides keeps the other enum fields symbolic.
        // T1's generators on a symbolic-or-bytes field (`key_share_point: 0x37 * 31`).
        (FieldType::Enum, ast::FieldValue::Repeat { .. } | ast::FieldValue::Range { .. }) => {
            let mut items = Vec::new();
            flatten_value(v, binding, &mut items)?;
            items_to_bytes(&items, span).map(FieldValue::Bytes)
        }
        (FieldType::Enum, ast::FieldValue::List(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let n = extract_int(it, binding, span)?;
                out.push(range_u8(n, span)?);
            }
            Ok(FieldValue::Bytes(out))
        }
        (FieldType::Enum, ast::FieldValue::Empty) => Ok(FieldValue::Bytes(Vec::new())),
        (FieldType::Enum, _) => Err(LowerError {
            span,
            message:
                "this field takes a symbolic value (a bare name), not a number, string or list"
                    .into(),
        }),
        (t, _) => Err(LowerError {
            span,
            message: format!(
                "cannot coerce field value to {:?}; check the declared field type",
                t
            ),
        }),
    }
}

/// Resolve a signature-scheme or named-group name to its wire value, for the
/// u16 fields that accept either form.
fn named_u16(name: &str, span: Span) -> Result<u16, LowerError> {
    schema::sigalg_wire_value(name)
        .or_else(|| schema::group_wire_value(name))
        .or_else(|| schema::version_wire_value(name))
        // D: cipher-suite names (`cipher_suite: AES_128_GCM_SHA256`).
        .or_else(|| schema::suite_wire_value(name))
        // T6: RFC 8879 7.3 certificate compression algorithm names.
        .or(match name {
            "zlib" => Some(1),
            "brotli" => Some(2),
            "zstd" => Some(3),
            _ => None,
        })
        // T2: extension names too (`has_ext: renegotiation_info`).
        .or_else(|| schema::extension_wire_type(name))
        .ok_or_else(|| LowerError {
            span,
            message: format!(
                "`{}` is not a signature scheme, named group, protocol version, cipher suite, or extension name; use a name from the schema \
                 (e.g. rsa_pss_rsae_sha256, secp384r1, tls13, key_share) or a wire value",
                name
            ),
        })
}

fn range_u16(v: i64, span: Span) -> Result<u16, LowerError> {
    if !(0..=u16::MAX as i64).contains(&v) {
        return Err(LowerError {
            span,
            message: format!("value {} out of range for u16 field", v),
        });
    }
    Ok(v as u16)
}

fn range_u8(v: i64, span: Span) -> Result<u8, LowerError> {
    if !(0..=u8::MAX as i64).contains(&v) {
        return Err(LowerError {
            span,
            message: format!("value {} out of range for u8 field", v),
        });
    }
    Ok(v as u8)
}

// ============================================================
//                     mutation lowering
// ============================================================

/// Lower a list of AST `Mutation`s to IR `Mutation`s, resolving
/// any `$var` references from the current matrix binding and
/// converting symbolic field paths to string vectors.
/// Resolve AST extension deltas into encoded IR ops. Handles
/// the named-extension typed forms (`server_name = "host"`,
/// `supported_groups = [...]`) and the universal `raw "hex"`
/// escape hatch.
fn lower_ext_deltas(
    deltas: &[ast::ExtDelta],
    subject: Subject,
    version: TlsVersion,
    protocol: ir::Protocol,
    kind: MessageKind,
    binding: &[(String, i64)],
) -> Result<Vec<ir::ExtDeltaOp>, Vec<LowerError>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for d in deltas {
        match d {
            ast::ExtDelta::Remove { target, span: _ } => {
                match resolve_ext_target(target, binding) {
                    Ok(wt) => out.push(ir::ExtDeltaOp::Remove { wire_type: wt }),
                    Err(e) => errors.push(e),
                }
            }
            // T1: `+ext each <types> [= value]`: one extension per listed type.
            ast::ExtDelta::AddEach { types, value, span } => {
                let mut items = Vec::new();
                if let Err(e) = flatten_value(types, binding, &mut items) {
                    errors.push(e);
                    continue;
                }
                let wire_types = match items_to_u16s(
                    &items,
                    &|_| None,
                    "extension type",
                    "use wire values 0..0xffff",
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                let value = match resolve_ext_var(value, binding) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                let body = match encode_ext_body(
                    &ast::ExtTarget::Wire(0, *span),
                    &value,
                    *span,
                    binding,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                for wt in wire_types {
                    out.push(ir::ExtDeltaOp::Add {
                        wire_type: wt,
                        body: body.clone(),
                        dup: true,
                    });
                }
                let added: usize = out
                    .iter()
                    .map(|op| match op {
                        ir::ExtDeltaOp::Add { body, .. } => 4 + body.len(),
                        _ => 0,
                    })
                    .sum();
                if added > 65535 - 256 {
                    errors.push(LowerError {
                        span: *span,
                        message: format!(
                            "the extension deltas add {} bytes; the extension block is a u16 length and the \
                             hello's own extensions need about 256 bytes, so keep the total under 65279",
                            added
                        ),
                    });
                }
            }
            ast::ExtDelta::Add {
                target,
                value,
                dup,
                span,
            } => {
                let value = match resolve_ext_var(value, binding) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                let value = &value;
                // `+ext key_share = [g, ...]` is not an encoding: the client must
                // generate a private key per group, so it lowers to a driver op
                // (T1: `group : bytes` entries ride along verbatim).
                if let (ast::ExtTarget::Named(n), ast::ExtValue::List(items, _)) = (target, value) {
                    if n.name == "key_share" {
                        if *dup {
                            errors.push(LowerError {
                                span: *span,
                                message: "`+ext dup key_share` does not support generated share lists; remove `dup`".into(),
                            });
                            continue;
                        }
                        match lower_key_share_entries(
                            items, subject, version, protocol, kind, *span, binding,
                        ) {
                            Ok(op) => out.push(op),
                            Err(e) => errors.push(e),
                        }
                        continue;
                    }
                }
                let wt = match resolve_ext_target(target, binding) {
                    Ok(w) => w,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                let body = match encode_ext_body(target, value, *span, binding) {
                    Ok(b) => b,
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                };
                out.push(ir::ExtDeltaOp::Add {
                    wire_type: wt,
                    body,
                    dup: *dup,
                });
            }
            ast::ExtDelta::Reverse { span: _ } => {
                out.push(ir::ExtDeltaOp::Reverse);
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(out)
}

/// T1: `+ext padding = $i` -- a matrix variable as the typed integer value.
fn resolve_ext_var(
    value: &ast::ExtValue,
    binding: &[(String, i64)],
) -> Result<ast::ExtValue, LowerError> {
    match value {
        ast::ExtValue::Var(id) => {
            let n = lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("`${}` is not a matrix variable in this test", id.name),
            })?;
            Ok(ast::ExtValue::Int(ast::IntLit {
                value: n,
                span: id.span,
            }))
        }
        other => Ok(other.clone()),
    }
}

/// T1: the entries of an explicit `+ext key_share = [...]`: names generate real
/// shares (the pre-existing `KeyShareGroups` op when nothing else is listed),
/// `group : bytes` entries (the group side may be a range or list) carry
/// opaque keys verbatim, and `[]` is an empty key_share extension.
fn lower_key_share_entries(
    items: &[ast::FieldValue],
    subject: Subject,
    version: TlsVersion,
    _protocol: ir::Protocol,
    kind: MessageKind,
    span: Span,
    binding: &[(String, i64)],
) -> Result<ir::ExtDeltaOp, LowerError> {
    let on_client_hello = subject == Subject::Server
        && version == TlsVersion::Tls13
        && kind == MessageKind::ClientHello;
    if !on_client_hello {
        return Err(LowerError {
            span,
            message: "`+ext key_share = [...]` generates the client's key shares, so it \
                      applies only to the ClientHello of a TLS 1.3 `uut server` test; \
                      a server's HelloRetryRequest form is `key_share = secp256r1`"
                .into(),
        });
    }
    let mut flat = Vec::new();
    flatten_value(&ast::FieldValue::List(items.to_vec()), binding, &mut flat)?;
    if flat.is_empty() {
        return Ok(ir::ExtDeltaOp::Add {
            wire_type: 0x0033,
            body: vec![0, 0],
            dup: false,
        });
    }
    let mut entries: Vec<ir::KeyShareEntrySpec> = Vec::new();
    let mut generated: Vec<u16> = Vec::new();
    for it in &flat {
        match it {
            Item::Name(name, sp) => {
                let wire = schema::group_wire_value(name).ok_or_else(|| LowerError {
                    span: *sp,
                    message: format!("unknown group `{}`; try x25519, secp256r1, secp384r1", name),
                })?;
                if !ir::CLIENT_KEY_SHARE_GROUPS.contains(&wire) {
                    return Err(LowerError {
                        span: *sp,
                        message: format!(
                            "plzn's client cannot generate a key share for `{}`; implemented: \
                             x25519, x448, secp256r1, secp384r1, secp521r1, ffdhe2048, ffdhe3072, \
                             ffdhe4096, ffdhe6144, ffdhe8192, \
                             x448mlkem1024 -- \
                             give an opaque key instead: `{} : 0xab * 32`",
                            name, name
                        ),
                    });
                }
                generated.push(wire);
                entries.push(ir::KeyShareEntrySpec::Generate(wire));
            }
            Item::Int(v, sp) => {
                let wire = u16::try_from(*v).map_err(|_| LowerError {
                    span: *sp,
                    message: format!("key-share group 0x{:x} does not fit in u16", v),
                })?;
                if !ir::CLIENT_KEY_SHARE_GROUPS.contains(&wire) {
                    return Err(LowerError {
                        span: *sp,
                        message: format!(
                            "plzn cannot generate a key share for group 0x{:04x}; give the opaque key: `0x{:04x} : 0xab * 32`",
                            wire, wire
                        ),
                    });
                }
                // Matrix variables are resolved to integers before this
                // helper sees them. Preserve the named-group semantics so
                // `+ext key_share = [$group, $group]` can sweep duplicates.
                generated.push(wire);
                entries.push(ir::KeyShareEntrySpec::Generate(wire));
            }
            Item::Str(_, sp) => {
                return Err(LowerError {
                    span: *sp,
                    message: "a key_share entry is a group name or `group : bytes`".into(),
                });
            }
            Item::Entry {
                key,
                value,
                span: esp,
            } => {
                let lookup = |n: &str| schema::group_wire_value(n);
                let groups =
                    items_to_u16s(key, &lookup, "group", "use a group name or wire value")?;
                let bytes = items_to_bytes(value, *esp)?;
                if bytes.len() > 0xffff {
                    return Err(LowerError {
                        span: *esp,
                        message: "a key_share entry's key exceeds 65535 bytes".into(),
                    });
                }
                for g in groups {
                    entries.push(ir::KeyShareEntrySpec::Raw {
                        group: g,
                        key: bytes.clone(),
                    });
                }
            }
        }
    }
    let raw_count = entries
        .iter()
        .filter(|e| matches!(e, ir::KeyShareEntrySpec::Raw { .. }))
        .count();
    if raw_count == 0 {
        // A group listed twice offers two generated KeyShareEntry values for it
        // (T4: the RFC 8446 4.2.8 "MUST NOT" the peer has to reject; the driver
        // draws the second share from its own sub-seed).
        return Ok(ir::ExtDeltaOp::KeyShareGroups(generated));
    }
    Ok(ir::ExtDeltaOp::KeyShareEntries(entries))
}

/// Schema name for a group wire value, for diagnostics.
fn schema_group_name(wire: u16) -> String {
    for name in schema::GROUPS {
        if schema::group_wire_value(name) == Some(wire) {
            return (*name).to_string();
        }
    }
    format!("0x{:04x}", wire)
}

fn resolve_ext_target(
    target: &ast::ExtTarget,
    binding: &[(String, i64)],
) -> Result<u16, LowerError> {
    match target {
        ast::ExtTarget::Named(name) => {
            schema::extension_wire_type(&name.name).ok_or_else(|| LowerError {
                span: name.span,
                message: format!("unknown extension `{}`", name.name),
            })
        }
        ast::ExtTarget::Wire(n, _) => Ok(*n),
        // T1: `+ext $id` -- a matrix variable holding the wire type.
        ast::ExtTarget::Var(id) => {
            let n = lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("`${}` is not a matrix variable in this test", id.name),
            })?;
            range_u16(n, id.span)
        }
    }
}

/// Which messages the drivers apply `+ext` / `-ext` / `reverse_extensions` to.
/// A delta on any other message would be accepted and then silently dropped, so
/// lowering rejects it with the supported list.
fn ext_deltas_supported_on(
    subject: Subject,
    version: TlsVersion,
    _protocol: ir::Protocol,
    kind: MessageKind,
) -> Result<(), String> {
    let tls13 = version == TlsVersion::Tls13;
    let (ok, role, supported) = match subject {
        // plzn plays the client.
        Subject::Server => (
            match kind {
                MessageKind::ClientHello | MessageKind::ClientHelloRetry => true,
                MessageKind::Certificate => tls13,
                _ => false,
            },
            "client",
            "ClientHello (TLS and DTLS), Certificate (TLS 1.3 client authentication)",
        ),
        // plzn plays the server.
        Subject::Client => (
            match kind {
                MessageKind::ServerHello => true,
                MessageKind::HelloRetryRequest
                | MessageKind::EncryptedExtensions
                | MessageKind::CertificateRequest
                | MessageKind::Certificate
                | MessageKind::NewSessionTicket => tls13,
                _ => false,
            },
            "server",
            "ServerHello (TLS and DTLS); HelloRetryRequest, EncryptedExtensions, \
             CertificateRequest, Certificate, NewSessionTicket (TLS 1.3)",
        ),
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "extension deltas on `{:?}` are not applied when plzn plays the {}; \
             `+ext` / `-ext` / `reverse_extensions` work on: {}",
            kind, role, supported
        ))
    }
}

/// Encode a u16-length-prefixed list of u16 values: names through `lookup`,
/// numbers as-is (T1: the items come from the shared value grammar).
fn u16_named_list(
    items: &[Item],
    lookup: fn(&str) -> Option<u16>,
    what: &str,
    hint: &str,
) -> Result<Vec<u8>, LowerError> {
    let values = items_to_u16s(items, &lookup, what, hint)?;
    let mut list = Vec::with_capacity(values.len() * 2);
    for w in values {
        list.extend_from_slice(&w.to_be_bytes());
    }
    let mut body = (list.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    Ok(body)
}

/// Encode a u8-length-prefixed list of u8 values: names through `lookup`,
/// numbers as-is.
fn u8_named_list(
    items: &[Item],
    lookup: fn(&str) -> Option<u8>,
    what: &str,
    hint: &str,
) -> Result<Vec<u8>, LowerError> {
    let list = items_to_u8s(items, &lookup, what, hint)?;
    let mut body = vec![list.len() as u8];
    body.extend_from_slice(&list);
    Ok(body)
}

fn named_u8(
    ident: &ast::Ident,
    lookup: fn(&str) -> Option<u8>,
    what: &str,
    hint: &str,
) -> Result<Vec<u8>, LowerError> {
    lookup(&ident.name)
        .map(|v| vec![v])
        .ok_or_else(|| LowerError {
            span: ident.span,
            message: format!("unknown {} `{}`; {}", what, ident.name, hint),
        })
}

fn alpn_body(items: &[ast::StrLit]) -> Result<Vec<u8>, LowerError> {
    let mut list = Vec::new();
    for s in items {
        let proto = s.value.as_bytes();
        if proto.len() > 255 {
            return Err(LowerError {
                span: s.span,
                message: "ALPN protocol name too long (max 255 bytes)".into(),
            });
        }
        list.push(proto.len() as u8);
        list.extend_from_slice(proto);
    }
    let mut body = (list.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&list);
    Ok(body)
}

/// The typed value forms each named extension accepts, for the error message
/// when a test uses the wrong one.
fn ext_accepted_forms(name: &str) -> &'static str {
    match name {
        "server_name" => "\"hostname\"",
        "application_layer_protocol_negotiation" | "alpn" => "[\"h2\", \"http/1.1\"] or \"h2\"",
        "supported_versions" => "[tls12, tls13] (ClientHello) or tls13 / $version (ServerHello)",
        "supported_groups" => "[x25519, secp256r1, ...]",
        "key_share" => {
            "[x25519, secp256r1] (ClientHello: generate real shares for these groups) or secp256r1 (a server's HelloRetryRequest retry group)"
        }
        "signature_algorithms" | "signature_algorithms_cert" => {
            "[rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, ...]"
        }
        "max_fragment_length" => "512 | 1024 | 2048 | 4096",
        "record_size_limit" => "an integer 64..=65535",
        "padding" => "an integer (number of zero bytes)",
        "ec_point_formats" => {
            "[uncompressed, ansix962_compressed_prime, ansix962_compressed_char2]"
        }
        "psk_key_exchange_modes" => "[psk_ke, psk_dhe_ke]",
        "client_certificate_type" | "server_certificate_type" => {
            "[raw_public_key, x509] (ClientHello) or x509 (server selection)"
        }
        "status_request" => "ocsp",
        "heartbeat" => "peer_allowed_to_send | peer_not_allowed_to_send",
        "use_srtp" => "[srtp_aes128_cm_hmac_sha1_80, srtp_aead_aes_128_gcm, ...]",
        "compress_certificate" => "[zlib, brotli, zstd]",
        "early_data" => "an integer (NewSessionTicket max_early_data_size)",
        _ => "no typed encoder",
    }
}

fn ext_value_form(v: &ast::ExtValue) -> &'static str {
    match v {
        ast::ExtValue::Raw(..) => "raw bytes",
        ast::ExtValue::Str(_) => "a string",
        ast::ExtValue::List(..) => "a list",
        ast::ExtValue::Int(_) => "an integer",
        ast::ExtValue::Ident(_) => "a name",
        ast::ExtValue::Var(_) => "a matrix variable",
        ast::ExtValue::Empty(_) => "no value",
    }
}

/// Encode the body of a `+ext NAME = value` delta.
///
/// `raw "HEX"` and the bare `+ext NAME` (empty body) forms apply to any target.
/// Named extensions with a typed encoder accept the symbolic forms listed in
/// `ext_accepted_forms`; the value form selects between the ClientHello list
/// shape and the server's single-value shape where an extension has both.
fn encode_ext_body(
    target: &ast::ExtTarget,
    value: &ast::ExtValue,
    span: Span,
    binding: &[(String, i64)],
) -> Result<Vec<u8>, LowerError> {
    use ast::ExtValue as V;
    match value {
        V::Raw(bytes, _) => return Ok(bytes.clone()),
        V::Empty(_) => return Ok(Vec::new()),
        _ => {}
    }
    let ext_name = match target {
        ast::ExtTarget::Named(n) => n.name.as_str(),
        ast::ExtTarget::Wire(_, _) | ast::ExtTarget::Var(_) => {
            // T1: a numeric type has no typed encoder, so its body is any
            // bytes value of the shared grammar: `zeros N`, a list of bytes /
            // repeats, or a string (tlsfuzzer's "extension #80 of N bytes").
            return match value {
                V::List(items, _) => {
                    let mut flat = Vec::new();
                    flatten_value(&ast::FieldValue::List(items.clone()), binding, &mut flat)?;
                    items_to_bytes(&flat, span)
                }
                V::Str(s) => Ok(s.value.as_bytes().to_vec()),
                _ => Err(LowerError {
                    span,
                    message: "a numeric extension type takes `raw \"HEX\"`, a bytes value (`zeros N`, `[0x01 * 8]`, a string) or no value (empty body)".into(),
                }),
            };
        }
    };
    // T1: list values arrive as the shared value grammar; expand generators
    // once, then each typed encoder interprets names/numbers/strings.
    let items: Vec<Item> = match value {
        V::List(items, _) => {
            let mut flat = Vec::new();
            flatten_value(&ast::FieldValue::List(items.clone()), binding, &mut flat)?;
            flat
        }
        _ => Vec::new(),
    };
    const GROUP_HINT: &str = "try x25519, secp256r1, secp384r1";
    const SIGALG_HINT: &str =
        "try e.g. rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256, rsa_pkcs1_sha256";
    match (ext_name, value) {
        ("server_name", V::Str(s)) => {
            let host = s.value.as_bytes();
            let mut body = Vec::new();
            let entry_len = 1 + 2 + host.len();
            body.extend_from_slice(&(entry_len as u16).to_be_bytes());
            body.push(0); // name_type = host_name
            body.extend_from_slice(&(host.len() as u16).to_be_bytes());
            body.extend_from_slice(host);
            Ok(body)
        }
        ("application_layer_protocol_negotiation" | "alpn", V::List(..)) => {
            alpn_body(&items_to_strs(&items, "alpn")?)
        }
        ("application_layer_protocol_negotiation" | "alpn", V::Str(s)) => {
            alpn_body(std::slice::from_ref(s))
        }
        ("supported_versions", V::List(..)) => {
            let wires = items_to_u16s(
                &items,
                &schema::version_wire_value,
                "version",
                "try tls10, tls11, tls12, tls13",
            )?;
            if wires.len() > 127 {
                return Err(LowerError {
                    span,
                    message: "supported_versions takes at most 127 entries".into(),
                });
            }
            let mut body = vec![(wires.len() * 2) as u8];
            for w in wires {
                body.extend_from_slice(&w.to_be_bytes());
            }
            Ok(body)
        }
        ("supported_versions", V::Ident(id)) => schema::version_wire_value(&id.name)
            .map(|w| w.to_be_bytes().to_vec())
            .ok_or_else(|| LowerError {
                span: id.span,
                message: format!(
                    "unknown version `{}`; try tls10, tls11, tls12, tls13",
                    id.name
                ),
            }),
        ("supported_versions", V::Int(n)) => Ok(range_u16(n.value, n.span)?.to_be_bytes().to_vec()),
        ("supported_groups", V::List(..)) => {
            u16_named_list(&items, schema::group_wire_value, "group", GROUP_HINT)
        }
        ("key_share", V::Ident(id)) => schema::group_wire_value(&id.name)
            .map(|w| w.to_be_bytes().to_vec())
            .ok_or_else(|| LowerError {
                span: id.span,
                message: format!("unknown group `{}`; {}", id.name, GROUP_HINT),
            }),
        ("signature_algorithms" | "signature_algorithms_cert", V::List(..)) => u16_named_list(
            &items,
            schema::sigalg_wire_value,
            "signature algorithm",
            SIGALG_HINT,
        ),
        ("max_fragment_length", V::Int(n)) => schema::max_fragment_length_code(n.value)
            .map(|c| vec![c])
            .ok_or_else(|| LowerError {
                span: n.span,
                message: format!(
                    "max_fragment_length must be 512, 1024, 2048 or 4096, not {}",
                    n.value
                ),
            }),
        ("record_size_limit", V::Int(n)) => {
            if (64..=65535).contains(&n.value) {
                Ok((n.value as u16).to_be_bytes().to_vec())
            } else {
                Err(LowerError {
                    span: n.span,
                    message: format!("record_size_limit must be 64..=65535, not {}", n.value),
                })
            }
        }
        ("padding", V::Int(n)) => {
            if (0..=65535).contains(&n.value) {
                Ok(vec![0u8; n.value as usize])
            } else {
                Err(LowerError {
                    span: n.span,
                    message: format!("padding length must be 0..=65535, not {}", n.value),
                })
            }
        }
        ("ec_point_formats", V::List(..)) => u8_named_list(
            &items,
            schema::ec_point_format_value,
            "point format",
            "try uncompressed, ansix962_compressed_prime, ansix962_compressed_char2",
        ),
        ("psk_key_exchange_modes", V::List(..)) => u8_named_list(
            &items,
            schema::psk_mode_value,
            "PSK mode",
            "try psk_ke, psk_dhe_ke",
        ),
        ("client_certificate_type" | "server_certificate_type", V::List(..)) => u8_named_list(
            &items,
            schema::cert_type_value,
            "certificate type",
            "try x509, raw_public_key",
        ),
        ("client_certificate_type" | "server_certificate_type", V::Ident(id)) => named_u8(
            id,
            schema::cert_type_value,
            "certificate type",
            "try x509, raw_public_key",
        ),
        ("status_request", V::Ident(id)) if id.name == "ocsp" => {
            // CertificateStatusRequest: status_type=ocsp(1), empty responder_id_list,
            // empty request_extensions (RFC 6066 8).
            Ok(vec![0x01, 0x00, 0x00, 0x00, 0x00])
        }
        ("heartbeat", V::Ident(id)) => named_u8(
            id,
            schema::heartbeat_mode_value,
            "heartbeat mode",
            "try peer_allowed_to_send, peer_not_allowed_to_send",
        ),
        ("use_srtp", V::List(..)) => {
            // SRTPProtectionProfiles<2..2^16-1> then an empty srtp_mki (RFC 5764 4.1.1).
            let mut body = u16_named_list(
                &items,
                schema::srtp_profile_value,
                "SRTP profile",
                "try srtp_aes128_cm_hmac_sha1_80, srtp_aead_aes_128_gcm",
            )?;
            body.push(0);
            Ok(body)
        }
        ("compress_certificate", V::List(..)) => {
            // CertificateCompressionAlgorithm algorithms<2..2^8-2> (RFC 8879 3).
            let list = u16_named_list(
                &items,
                schema::cert_compression_value,
                "compression algorithm",
                "try zlib, brotli, zstd",
            )?;
            if list.len() > 2 + 254 {
                return Err(LowerError {
                    span,
                    message: "compress_certificate takes at most 127 algorithms".into(),
                });
            }
            let mut body = vec![(list.len() - 2) as u8];
            body.extend_from_slice(&list[2..]);
            Ok(body)
        }
        ("early_data", V::Int(n)) => {
            if (0..=u32::MAX as i64).contains(&n.value) {
                Ok((n.value as u32).to_be_bytes().to_vec())
            } else {
                Err(LowerError {
                    span: n.span,
                    message: format!(
                        "early_data max_early_data_size must fit in u32, not {}",
                        n.value
                    ),
                })
            }
        }
        (other, v) => {
            let accepted = ext_accepted_forms(other);
            let message = if accepted == "no typed encoder" {
                format!(
                    "extension `{}` has no typed encoder; use `raw \"HEX\"` or `+ext {}` for an empty body",
                    other, other
                )
            } else {
                format!(
                    "extension `{}` does not take {}; it accepts {} (or `raw \"HEX\"`)",
                    other,
                    ext_value_form(v),
                    accepted
                )
            };
            Err(LowerError { span, message })
        }
    }
}

/// Lower a `send Msg @ <scheme>` DTLS fragmentation suffix. The size-bearing
/// schemes require a positive fragment size (as `reorder` does).
/// Over DTLS every sender routes through a mapped encoder, so a
/// `handshake.<field>` byte target on `msg_name` must name a field that
/// encoder produces (`schema::handshake_byte_fields`); the framing targets
/// `msg_type` / `length` apply to any handshake message.
fn unmapped_handshake_field(msg_name: &str, muts: &[ir::Mutation]) -> Option<String> {
    let mapped = schema::handshake_byte_fields(msg_name);
    for m in muts {
        let target = match &m.op {
            MutationOp::Xor { target, .. } | MutationOp::Set { target, .. } => target,
            _ => continue,
        };
        if !target.is_handshake_field() {
            continue;
        }
        let Some(field) = target.field_name() else {
            continue;
        };
        if matches!(field, "msg_type" | "length") || mapped.contains(&field) {
            continue;
        }
        let list = if mapped.is_empty() {
            "none (this message takes bare offsets only)".to_string()
        } else {
            mapped
                .iter()
                .map(|f| format!("`handshake.{}`", f))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Some(format!(
            "`handshake.{}` is not a field of the {} body; its mapped fields are {}",
            field, msg_name, list
        ));
    }
    None
}

fn lower_dtls_frag(frag: &ast::DtlsFrag) -> Result<ir::DtlsFragScheme, LowerError> {
    fn positive(n: &ast::IntLit, what: &str) -> Result<usize, LowerError> {
        if n.value <= 0 {
            return Err(LowerError {
                span: n.span,
                message: format!("`{}` requires a positive fragment size", what),
            });
        }
        Ok(n.value as usize)
    }
    Ok(match frag {
        ast::DtlsFrag::Fragment { n } => ir::DtlsFragScheme::Fragment {
            size: positive(n, "fragment")?,
        },
        ast::DtlsFrag::DuplicateFragment { n } => ir::DtlsFragScheme::DuplicateFragment {
            size: positive(n, "duplicate_fragment")?,
        },
        ast::DtlsFrag::ReorderOverlap { n } => ir::DtlsFragScheme::ReorderOverlap {
            size: positive(n, "reorder_overlap")?,
        },
        ast::DtlsFrag::CompleteAndFragments { n } => ir::DtlsFragScheme::CompleteAndFragments {
            size: positive(n, "complete_and_fragments")?,
        },
        ast::DtlsFrag::EmptyFragments { .. } => ir::DtlsFragScheme::EmptyFragments,
        ast::DtlsFrag::SplitFragmentRecord { n } => ir::DtlsFragScheme::SplitFragmentRecord {
            at: positive(n, "split_fragment_record")?,
        },
        ast::DtlsFrag::OverlapMismatch { n } => ir::DtlsFragScheme::OverlapMismatch {
            size: positive(n, "overlap_mismatch")?,
        },
        ast::DtlsFrag::TypeMismatch { n } => ir::DtlsFragScheme::TypeMismatch {
            size: positive(n, "type_mismatch")?,
        },
        ast::DtlsFrag::LengthMismatch { n } => ir::DtlsFragScheme::LengthMismatch {
            size: positive(n, "length_mismatch")?,
        },
        ast::DtlsFrag::FragmentLengthMismatch { n } => ir::DtlsFragScheme::FragmentLengthMismatch {
            size: positive(n, "fragment_length_mismatch")?,
        },
        ast::DtlsFrag::FutureSequence { n } | ast::DtlsFrag::FutureSequencePacked { n } => {
            if !(1..=u16::MAX as i64).contains(&n.value) {
                return Err(LowerError {
                    span: n.span,
                    message: "`future_sequence` requires a delta in 1..=65535".into(),
                });
            }
            match frag {
                ast::DtlsFrag::FutureSequence { .. } => ir::DtlsFragScheme::FutureSequence {
                    delta: n.value as u16,
                },
                ast::DtlsFrag::FutureSequencePacked { .. } => {
                    ir::DtlsFragScheme::FutureSequencePacked {
                        delta: n.value as u16,
                    }
                }
                _ => unreachable!(),
            }
        }
        ast::DtlsFrag::OffsetOverflow { .. } => ir::DtlsFragScheme::OffsetOverflow,
    })
}

fn lower_mutations(
    mutations: &[ast::Mutation],
    binding: &[(String, i64)],
) -> Result<Vec<ir::Mutation>, Vec<LowerError>> {
    let mut errors: Vec<LowerError> = Vec::new();
    let mut out: Vec<ir::Mutation> = Vec::new();
    for m in mutations {
        match lower_one_mutation(m, binding) {
            Ok(ir_mut) => out.push(ir_mut),
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn lower_one_mutation(
    m: &ast::Mutation,
    binding: &[(String, i64)],
) -> Result<ir::Mutation, LowerError> {
    let span = m.span;
    let op = match &m.op {
        ast::MutationOp::Xor { target, value } => {
            let resolved_target = resolve_byte_target(target, binding)?;
            let val = resolve_mut_value(value, binding, span)?;
            MutationOp::Xor {
                target: resolved_target,
                value: val,
            }
        }
        ast::MutationOp::Set { target, value } => {
            let resolved_target = resolve_byte_target(target, binding)?;
            let val = resolve_mut_value(value, binding, span)?;
            MutationOp::Set {
                target: resolved_target,
                value: val,
            }
        }
        ast::MutationOp::Add { target, value } | ast::MutationOp::Sub { target, value } => {
            let amount = resolve_mut_value(value, binding, span)?;
            if amount < 0 {
                return Err(LowerError {
                    span,
                    message: "add/sub length adjustments require a non-negative integer".into(),
                });
            }
            let path = target.parts.iter().map(|part| part.name.clone()).collect();
            let delta = if matches!(&m.op, ast::MutationOp::Sub { .. }) {
                -amount
            } else {
                amount
            };
            MutationOp::AdjustLength { path, delta }
        }
        ast::MutationOp::PadPlus { n, byte } => {
            let n = resolve_mut_value(n, binding, span)?;
            if n < 0 {
                return Err(LowerError {
                    span,
                    message: "pad +N requires a non-negative integer".into(),
                });
            }
            match byte {
                None => MutationOp::PadPlus(n as usize),
                Some(b) => {
                    let b = range_u8(b.value, b.span)?;
                    MutationOp::PadBytes(vec![b; n as usize])
                }
            }
        }
        ast::MutationOp::PadBytes { bytes, .. } => MutationOp::PadBytes(bytes.clone()),
        ast::MutationOp::RecordVersion { v } => {
            MutationOp::RecordVersion(range_u16(v.value, v.span)?)
        }
        ast::MutationOp::RecordPad { n, .. } => match n {
            None => MutationOp::RecordPad(None),
            Some(n) => {
                if n.value < 0 || n.value > (1 << 14) + 256 {
                    return Err(LowerError {
                        span: n.span,
                        message: "record_pad N takes 0..=16640 bytes of padding (or `fill`)".into(),
                    });
                }
                MutationOp::RecordPad(Some(n.value as usize))
            }
        },
        ast::MutationOp::Dtls13ShortSequence => MutationOp::Dtls13ShortSequence,
        ast::MutationOp::Dtls13OmitLength => MutationOp::Dtls13OmitLength,
        ast::MutationOp::Dtls13SetCidBit => MutationOp::Dtls13SetCidBit,
        ast::MutationOp::Dtls13LegacyHeader => MutationOp::Dtls13LegacyHeader,
        ast::MutationOp::Plaintext { replace, .. } => match replace {
            None => MutationOp::Plaintext,
            Some(bytes) => MutationOp::ReplacePlaintext(bytes.clone()),
        },
        ast::MutationOp::CbcPad { n } => {
            if !(1..=256).contains(&n.value) {
                return Err(LowerError {
                    span: n.span,
                    message:
                        "cbc_pad N takes 1..=256 (the padding length including its length byte)"
                            .into(),
                });
            }
            MutationOp::CbcPad(n.value as usize)
        }
        ast::MutationOp::PadMinus { n } => {
            let n = resolve_mut_value(n, binding, span)?;
            if n < 0 {
                return Err(LowerError {
                    span,
                    message: "pad -N requires a non-negative integer".into(),
                });
            }
            MutationOp::PadMinus(n as usize)
        }
        ast::MutationOp::Truncate { n } => {
            let n = resolve_mut_value(n, binding, span)?;
            if n < 0 {
                return Err(LowerError {
                    span,
                    message: "truncate N requires a non-negative integer".into(),
                });
            }
            MutationOp::Truncate(n as usize)
        }
        ast::MutationOp::TrailingBytes { bytes, .. } => {
            if bytes.is_empty() {
                return Err(LowerError {
                    span,
                    message: "trailing requires at least one byte".into(),
                });
            }
            MutationOp::TrailingBytes(bytes.clone())
        }
        ast::MutationOp::OmitPrefix { n } => {
            let n = resolve_mut_value(n, binding, span)?;
            if n <= 0 {
                return Err(LowerError {
                    span,
                    message: "omit_prefix N requires a positive byte count".into(),
                });
            }
            MutationOp::OmitPrefix(n as usize)
        }
        ast::MutationOp::Reorder { n } => {
            if n.value <= 0 {
                return Err(LowerError {
                    span: n.span,
                    message: "reorder N requires a positive fragment size".into(),
                });
            }
            MutationOp::Reorder(n.value as usize)
        }
        ast::MutationOp::Fragment { n, hold } => {
            let size = resolve_mut_value(n, binding, span)?;
            if size <= 0 {
                return Err(LowerError {
                    span,
                    message: "fragment N requires a positive record size".into(),
                });
            }
            MutationOp::Fragment {
                size: size as usize,
                hold: *hold,
            }
        }
    };
    Ok(ir::Mutation { op, span })
}

fn resolve_byte_target(
    target: &ast::ByteTarget,
    binding: &[(String, i64)],
) -> Result<ResolvedByteTarget, LowerError> {
    let path = target
        .path
        .as_ref()
        .map(|fp| fp.parts.iter().map(|p| p.name.clone()).collect::<Vec<_>>());
    let (index, end) = match &target.index {
        ast::ByteIndex::Single(v) => (resolve_int_or_var(v, binding)?, None),
        // T2: `lo..hi`, inclusive at both ends (as matrix ranges are).
        ast::ByteIndex::Range { lo, hi } => (
            resolve_int_or_var(lo, binding)?,
            Some(resolve_int_or_var(hi, binding)?),
        ),
    };
    Ok(ResolvedByteTarget { path, index, end })
}

fn resolve_int_or_var(v: &ast::IntOrVar, binding: &[(String, i64)]) -> Result<i64, LowerError> {
    match v {
        ast::IntOrVar::Int(i) => Ok(i.value),
        ast::IntOrVar::Var(id) => lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
            span: id.span,
            message: format!("`${}` is not a matrix variable in this test", id.name),
        }),
        // T1: `$var + N`.
        ast::IntOrVar::VarOffset { var, offset } => lookup_binding(binding, &var.name)
            .map(|v| v + offset)
            .ok_or_else(|| LowerError {
                span: var.span,
                message: format!("`${}` is not a matrix variable in this test", var.name),
            }),
    }
}

fn resolve_version_ref(
    version: &ast::VersionRef,
    binding: &[(String, i64)],
) -> Result<u16, LowerError> {
    match version {
        ast::VersionRef::Name(id) => {
            schema::version_wire_value(&id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("unknown UUT version `{}`", id.name),
            })
        }
        ast::VersionRef::Var(id) => {
            let value = lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
                span: id.span,
                message: format!("`${}` is not a matrix variable in this test", id.name),
            })?;
            u16::try_from(value).map_err(|_| LowerError {
                span: id.span,
                message: format!("matrix version value {value} does not fit on the wire"),
            })
        }
    }
}

fn resolve_mut_value(
    v: &ast::MutValue,
    binding: &[(String, i64)],
    span: Span,
) -> Result<i64, LowerError> {
    match v {
        ast::MutValue::Int(i) => Ok(i.value),
        ast::MutValue::Var(id) => lookup_binding(binding, &id.name).ok_or_else(|| LowerError {
            span: id.span,
            message: format!("`${}` is not a matrix variable in this test", id.name),
        }),
        ast::MutValue::Hex(bytes) => {
            if bytes.len() == 1 {
                Ok(bytes[0] as i64)
            } else {
                Err(LowerError {
                    span,
                    message: "multi-byte hex values in mutations are not yet supported; \
                              use a single-byte xor/set value"
                        .into(),
                })
            }
        }
    }
}

// ======================= Named-constant lint (track D) =======================
//
// A known cipher suite, named group, signature scheme, extension type or
// client certificate type must be written by name; a numeric literal is for
// unassigned, reserved or GREASE codepoints. The audit walks the AST once,
// independent of matrix expansion, and reports each literal once at its own
// span: field overrides and matchers, `+ext` / `-ext` targets and typed
// bodies, `ext NAME == value` matchers, `uut client|server { cipher_suites / curves /
// signing_prefs / verify_prefs }`, and the matrix lists whose variable flows
// into one of those positions (`matrix { suite in [0xc02f] }` with
// `cipher_suites: [$suite]`). Ranges are not checked.

use crate::schema::NameDomain;

fn audit_named_literals(test: &Test) -> Vec<LowerError> {
    let mut errors = Vec::new();
    let mut vars: Vec<(String, NameDomain)> = Vec::new();
    let mut flows: Vec<&ast::Flow> = Vec::new();
    if let Some(f) = &test.flow {
        flows.push(f);
    }
    for s in &test.sessions {
        flows.push(&s.flow);
    }
    for f in flows {
        for st in &f.steps {
            audit_step(st, &mut errors, &mut vars);
        }
    }
    if let Some(u) = &test.uut {
        for (d, lit) in &u.numeric_literals {
            audit_literal(*d, lit.value, lit.span, &mut errors);
        }
        // Numeric suite literals are in `numeric_literals` (the parser resolves
        // names into the same list, so the values alone cannot tell them apart).
        for v in &u.cipher_suites {
            if let ast::IntOrVar::Var(id) | ast::IntOrVar::VarOffset { var: id, .. } = v {
                note_var(&mut vars, &id.name, NameDomain::Suite);
            }
        }
        for v in &u.curves {
            if let ast::IntOrVar::Var(id) | ast::IntOrVar::VarOffset { var: id, .. } = v {
                note_var(&mut vars, &id.name, NameDomain::Group);
            }
        }
    }
    if let Some(m) = &test.matrix {
        for axis in &m.axes {
            let Some((_, d)) = vars.iter().find(|(n, _)| *n == axis.var.name) else {
                continue;
            };
            if let ast::MatrixValues::List { items, .. } = &axis.values {
                for it in items {
                    if let ast::MatrixItem::Int(lit) = it {
                        audit_literal(*d, lit.value, lit.span, &mut errors);
                    }
                }
            }
        }
    }
    errors
}

fn note_var(vars: &mut Vec<(String, NameDomain)>, name: &str, d: NameDomain) {
    if !vars.iter().any(|(n, _)| n == name) {
        vars.push((name.to_string(), d));
    }
}

fn audit_literal(d: NameDomain, value: i64, span: Span, errors: &mut Vec<LowerError>) {
    if let Some(name) = schema::domain_name(d, value) {
        errors.push(LowerError {
            span,
            message: schema::named_literal_message(d, value, name),
        });
    }
}

fn audit_step(
    step: &ast::Step,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    match step {
        ast::Step::Send {
            msgs,
            overrides,
            ext_deltas,
            ..
        } => {
            let msg = msgs.first().map(|m| m.name.name.as_str()).unwrap_or("");
            for o in overrides {
                audit_field(msg, o, errors, vars);
            }
            for d in ext_deltas {
                audit_ext_delta(d, errors, vars);
            }
        }
        ast::Step::Recv {
            msgs,
            matchers,
            ext_matchers,
            ..
        } => {
            let msg = msgs.first().map(|m| m.name.name.as_str()).unwrap_or("");
            for o in matchers {
                audit_field(msg, o, errors, vars);
            }
            for em in ext_matchers {
                audit_ext_target(&em.target, errors, vars);
                if let ast::ExtTarget::Named(n) = &em.target {
                    if let Some(d) = schema::extension_body_domain(&n.name) {
                        audit_ext_value(d, &em.value, errors, vars);
                    }
                }
            }
        }
        ast::Step::Renegotiate {
            overrides,
            ext_deltas,
            ..
        } => {
            for o in overrides {
                audit_field("ClientHello", o, errors, vars);
            }
            for d in ext_deltas {
                audit_ext_delta(d, errors, vars);
            }
        }
        ast::Step::Repeat { steps, .. } => {
            for st in steps {
                audit_step(st, errors, vars);
            }
        }
        _ => {}
    }
}

fn audit_field(
    msg: &str,
    o: &ast::FieldOverride,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    if let Some(d) = schema::field_domain(msg, &o.field.name) {
        audit_value(d, &o.value, errors, vars);
    }
}

fn audit_value(
    d: NameDomain,
    v: &ast::FieldValue,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    match v {
        ast::FieldValue::Int(lit) => audit_literal(d, lit.value, lit.span, errors),
        ast::FieldValue::List(items) => {
            for it in items {
                audit_value(d, it, errors, vars);
            }
        }
        ast::FieldValue::Repeat { item, .. } => audit_value(d, item, errors, vars),
        // `group : bytes` key_share entries: the key is the named position.
        ast::FieldValue::Entry { key, .. } => audit_value(d, key, errors, vars),
        ast::FieldValue::MatrixVar(id) => note_var(vars, &id.name, d),
        _ => {}
    }
}

fn audit_ext_target(
    t: &ast::ExtTarget,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    match t {
        ast::ExtTarget::Wire(w, span) => {
            audit_literal(NameDomain::Extension, i64::from(*w), *span, errors)
        }
        ast::ExtTarget::Var(id) => note_var(vars, &id.name, NameDomain::Extension),
        ast::ExtTarget::Named(_) => {}
    }
}

fn audit_ext_value(
    d: NameDomain,
    v: &ast::ExtValue,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    match v {
        ast::ExtValue::List(items, _) => {
            for it in items {
                audit_value(d, it, errors, vars);
            }
        }
        ast::ExtValue::Int(lit) => audit_literal(d, lit.value, lit.span, errors),
        ast::ExtValue::Var(id) => note_var(vars, &id.name, d),
        _ => {}
    }
}

fn audit_ext_delta(
    delta: &ast::ExtDelta,
    errors: &mut Vec<LowerError>,
    vars: &mut Vec<(String, NameDomain)>,
) {
    match delta {
        ast::ExtDelta::Add { target, value, .. } => {
            audit_ext_target(target, errors, vars);
            if let ast::ExtTarget::Named(n) = target {
                if let Some(d) = schema::extension_body_domain(&n.name) {
                    audit_ext_value(d, value, errors, vars);
                }
            }
        }
        ast::ExtDelta::Remove { target, .. } => audit_ext_target(target, errors, vars),
        ast::ExtDelta::AddEach { types, .. } => {
            audit_value(NameDomain::Extension, types, errors, vars)
        }
        ast::ExtDelta::Reverse { .. } => {}
    }
}

/// A name in a matrix set, resolved against every table; exactly one table
/// must know it.
fn resolve_matrix_name(name: &str) -> Result<i64, String> {
    if let Some(wire) = schema::version_wire_value(name) {
        return Ok(i64::from(wire));
    }
    const DOMAINS: [NameDomain; 5] = [
        NameDomain::Suite,
        NameDomain::Group,
        NameDomain::Sigalg,
        NameDomain::Extension,
        NameDomain::CertType,
    ];
    let hits: Vec<(NameDomain, u16)> = DOMAINS
        .iter()
        .filter_map(|d| schema::domain_wire_value(*d, name).map(|w| (*d, w)))
        .collect();
    match hits.as_slice() {
        [(_, w)] => Ok(i64::from(*w)),
        [] => Err(format!(
            "`{}` is not a known TLS version, cipher suite, named group, signature scheme, extension type or certificate type (see `plzn names`)",
            name
        )),
        many => Err(format!(
            "`{}` is ambiguous in a matrix set: {}",
            name,
            many.iter()
                .map(|(d, w)| format!("{} 0x{:04x}", d.label(), w))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod ext_encoder_tests {
    use super::{encode_ext_body, format_case_suffix, resolve_matrix_name};
    use crate::ast::{ExtTarget, ExtValue, Ident, IntLit, Span, StrLit};

    fn ident(name: &str) -> Ident {
        Ident {
            name: name.into(),
            span: Span::dummy(),
        }
    }

    fn named(name: &str) -> ExtTarget {
        ExtTarget::Named(ident(name))
    }

    fn ident_list(names: &[&str]) -> ExtValue {
        ExtValue::List(
            names
                .iter()
                .map(|n| crate::ast::FieldValue::Ident(ident(n)))
                .collect(),
            Span::dummy(),
        )
    }

    fn int(v: i64) -> ExtValue {
        ExtValue::Int(IntLit {
            value: v,
            span: Span::dummy(),
        })
    }

    fn name(v: &str) -> ExtValue {
        ExtValue::Ident(ident(v))
    }

    fn enc(ext: &str, value: &ExtValue) -> Vec<u8> {
        encode_ext_body(&named(ext), value, Span::dummy(), &[]).expect("encodes")
    }

    fn enc_err(ext: &str, value: &ExtValue) -> String {
        encode_ext_body(&named(ext), value, Span::dummy(), &[])
            .unwrap_err()
            .message
    }

    #[test]
    fn empty_value_is_an_empty_body_for_any_target() {
        assert_eq!(
            enc("extended_master_secret", &ExtValue::Empty(Span::dummy())),
            Vec::<u8>::new()
        );
        let wire = ExtTarget::Wire(0x1a1a, Span::dummy());
        assert_eq!(
            encode_ext_body(&wire, &ExtValue::Empty(Span::dummy()), Span::dummy(), &[]).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn typed_single_value_encoders() {
        // RFC 6066 4: MaxFragmentLength 2^9 = code 1 ... 2^12 = code 4.
        assert_eq!(enc("max_fragment_length", &int(512)), vec![1]);
        assert_eq!(enc("max_fragment_length", &int(4096)), vec![4]);
        assert!(enc_err("max_fragment_length", &int(300)).contains("512, 1024, 2048 or 4096"));
        // RFC 8449: u16 limit.
        assert_eq!(enc("record_size_limit", &int(16385)), vec![0x40, 0x01]);
        assert!(enc_err("record_size_limit", &int(10)).contains("64..=65535"));
        // RFC 7685: N zero bytes.
        assert_eq!(enc("padding", &int(3)), vec![0, 0, 0]);
        // RFC 6066 8: status_type=ocsp, empty responder ids + request extensions.
        assert_eq!(enc("status_request", &name("ocsp")), vec![1, 0, 0, 0, 0]);
        // RFC 6520 2.
        assert_eq!(enc("heartbeat", &name("peer_not_allowed_to_send")), vec![2]);
        // RFC 8446 4.2.1 ServerHello form: a single u16.
        assert_eq!(enc("supported_versions", &name("tls13")), vec![0x03, 0x04]);
        // RFC 8446 4.2.8 HelloRetryRequest form: just the group.
        assert_eq!(enc("key_share", &name("secp256r1")), vec![0x00, 0x17]);
        // RFC 7250 server selection: one CertificateType byte.
        assert_eq!(
            enc("server_certificate_type", &name("raw_public_key")),
            vec![2]
        );
        // RFC 8446 4.2.10 NewSessionTicket form: u32 max_early_data_size.
        assert_eq!(enc("early_data", &int(1024)), vec![0, 0, 4, 0]);
    }

    #[test]
    fn typed_list_encoders() {
        // RFC 8422 5.1.2: u8-length-prefixed ECPointFormat list.
        assert_eq!(
            enc("ec_point_formats", &ident_list(&["uncompressed"])),
            vec![1, 0]
        );
        // RFC 8446 4.2.9: u8-length-prefixed PskKeyExchangeMode list.
        assert_eq!(
            enc(
                "psk_key_exchange_modes",
                &ident_list(&["psk_ke", "psk_dhe_ke"])
            ),
            vec![2, 0, 1]
        );
        // RFC 7250 ClientHello form: u8-length-prefixed CertificateType list.
        assert_eq!(
            enc(
                "server_certificate_type",
                &ident_list(&["raw_public_key", "x509"])
            ),
            vec![2, 2, 0]
        );
        // RFC 5764 4.1.1: u16-length-prefixed profiles then an empty MKI.
        assert_eq!(
            enc(
                "use_srtp",
                &ident_list(&["srtp_aes128_cm_hmac_sha1_80", "srtp_aead_aes_128_gcm"])
            ),
            vec![0, 4, 0, 1, 0, 7, 0]
        );
        // RFC 8879 3: u8-length-prefixed u16 algorithm list.
        assert_eq!(
            enc("compress_certificate", &ident_list(&["zlib", "brotli"])),
            vec![4, 0, 1, 0, 2]
        );
        // ALPN single-protocol convenience (the server's selection).
        let h2 = ExtValue::Str(StrLit {
            value: "h2".into(),
            span: Span::dummy(),
        });
        assert_eq!(enc("alpn", &h2), vec![0, 3, 2, b'h', b'2']);
    }

    #[test]
    fn wrong_value_form_names_the_accepted_forms() {
        let msg = enc_err("status_request", &int(1));
        assert!(msg.contains("does not take an integer"), "{}", msg);
        assert!(msg.contains("ocsp"), "{}", msg);
        let msg = enc_err("cookie", &int(1));
        assert!(msg.contains("no typed encoder"), "{}", msg);
        let msg = enc_err("ec_point_formats", &ident_list(&["bogus"]));
        assert!(msg.contains("unknown point format `bogus`"), "{}", msg);
    }

    #[test]
    fn signature_algorithms_encodes_u16_length_prefixed_list() {
        // RFC 8446 §4.2.3: SignatureSchemeList is a u16-length-prefixed
        // vector of u16 SignatureScheme values.
        let body = encode_ext_body(
            &named("signature_algorithms"),
            &ident_list(&["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256"]),
            Span::dummy(),
            &[],
        )
        .expect("encodes");
        assert_eq!(body, vec![0x00, 0x04, 0x08, 0x04, 0x04, 0x03]);
    }

    #[test]
    fn signature_algorithms_legacy_md5_codepoint() {
        let body = encode_ext_body(
            &named("signature_algorithms"),
            &ident_list(&["rsa_pkcs1_md5"]),
            Span::dummy(),
            &[],
        )
        .expect("encodes");
        assert_eq!(body, vec![0x00, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn signature_algorithms_cert_shares_the_encoder() {
        let body = encode_ext_body(
            &named("signature_algorithms_cert"),
            &ident_list(&["ed25519"]),
            Span::dummy(),
            &[],
        )
        .expect("encodes");
        assert_eq!(body, vec![0x00, 0x02, 0x08, 0x07]);
    }

    #[test]
    fn grease_matrix_values_are_reported_as_wire_hex() {
        assert_eq!(
            format_case_suffix(&[("grease".into(), 0x0a0a)]),
            "[grease=0x0a0a]"
        );
        assert_eq!(
            format_case_suffix(&[("suite".into(), 0x0a0a)]),
            "[suite=0x0a0a]"
        );
        assert_eq!(
            format_case_suffix(&[("version".into(), 0x0301)]),
            "[version=tls10]"
        );
        assert_eq!(resolve_matrix_name("tls11").unwrap(), 0x0302);
    }

    #[test]
    fn supported_versions_accepts_a_numeric_server_selection() {
        assert_eq!(enc("supported_versions", &int(0x1a1a)), vec![0x1a, 0x1a]);
    }

    #[test]
    fn unknown_signature_algorithm_is_rejected() {
        let err = encode_ext_body(
            &named("signature_algorithms"),
            &ident_list(&["rsa_pkcs1_sha999"]),
            Span::dummy(),
            &[],
        )
        .unwrap_err();
        assert!(err.message.contains("unknown signature algorithm"));
    }
}
