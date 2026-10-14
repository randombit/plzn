// IR executor. Takes an `ir::Program` and a `UutFactory`, opens a
// transport, walks the Program step by step, drives the TLS client
// via the `TlsClient` trait, and produces a `RunReport` describing
// what happened.
//
// Failure semantics — the core of this module:
//
//   1. Steps run until one errors (or all complete successfully).
//   2. The first error is classified into a `FailureKind`:
//      Alert / CleanClose / Reset / Timeout / Io / Internal.
//   3. The program's terminal `Expectation` is matched against
//      (success or failure classification). Mismatch -> FAIL.
//   4. The `RunReport` carries both the DSL-style "expected" text
//      and a human-readable "observed" text so the reader never
//      has to guess which side of the mismatch was wrong.
//
// This is what turns a negative test like `expect alert fatal/
// handshake_failure` into a pass/fail: we don't need the peer to
// cooperate with our step list — any failure mid-flow is caught,
// classified, and matched against the expectation.

use std::collections::VecDeque;
use std::fmt;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;

use crate::ir::{AlertLevel, Expectation, Program, Step};
use crate::schema;
use crate::tls::driver::{TlsEndpoint, TlsError, make_endpoint};
use crate::tls::record::RecordError;
use crate::transport::UutFactory;

// ============================================================
//                   reports + status types
// ============================================================

#[derive(Debug)]
pub struct RunReport {
    pub test_id: String,
    pub status: RunStatus,
    pub steps: Vec<StepReport>,
    pub total_duration: Duration,
    pub negotiated_cipher_suite: Option<u16>,
    pub peer_description: String,
    pub expected: String,
    pub observed: String,
    /// Expectation-independent wire/runtime result. Differential discovery
    /// compares this value rather than PASS/FAIL, since a test expectation can
    /// legitimately vary by backend.
    pub raw_outcome: ObservedOutcome,
    /// T1: the values `capture $name` matchers recorded, for cross-run asserts.
    pub captures: Vec<(String, Vec<u8>)>,
    /// A failed protocol assertion may be expected; harness failures may not.
    pub xfail_eligible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObservedOutcome {
    Success,
    Alert {
        level: u8,
        description: u8,
        at_step: usize,
    },
    LocalReject {
        level: u8,
        description: u8,
        at_step: usize,
    },
    Close {
        at_step: usize,
    },
    Reset {
        at_step: usize,
    },
    Timeout {
        at_step: usize,
    },
    Internal {
        detail: String,
        at_step: usize,
    },
    Io {
        detail: String,
        at_step: usize,
    },
    Transport {
        detail: String,
    },
    Skipped {
        reason: String,
    },
}

impl ObservedOutcome {
    /// Stable, deliberately coarse differential bucket. Library prose and
    /// errno wording remain in the JSON observation but do not create a new
    /// finding by themselves.
    pub fn fingerprint(&self) -> String {
        match self {
            ObservedOutcome::Success => "success".into(),
            ObservedOutcome::Alert {
                level,
                description,
                at_step,
            } => format!("alert:{level}:{description}@{at_step}"),
            ObservedOutcome::LocalReject {
                level,
                description,
                at_step,
            } => format!("local_reject:{level}:{description}@{at_step}"),
            ObservedOutcome::Close { at_step } => format!("close@{at_step}"),
            ObservedOutcome::Reset { at_step } => format!("reset@{at_step}"),
            ObservedOutcome::Timeout { at_step } => format!("timeout@{at_step}"),
            ObservedOutcome::Internal { at_step, .. } => format!("internal@{at_step}"),
            ObservedOutcome::Io { at_step, .. } => format!("io@{at_step}"),
            ObservedOutcome::Transport { .. } => "transport".into(),
            ObservedOutcome::Skipped { .. } => "skipped".into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, ObservedOutcome::Success)
    }
}

#[derive(Debug)]
pub enum RunStatus {
    Pass,
    Fail(RunError),
    /// The test's preconditions couldn't be met, so it neither
    /// passed nor failed. Currently raised when a `uut client`
    /// harness-server can't select a cipher suite / group from its
    /// peer capability set that the connecting client also offered.
    /// Counts as non-failing for exit-code purposes.
    Skipped(String),
}

impl RunStatus {
    pub fn is_pass(&self) -> bool {
        matches!(self, RunStatus::Pass)
    }
    pub fn is_skipped(&self) -> bool {
        matches!(self, RunStatus::Skipped(_))
    }
    /// True unless the test actively failed — i.e. a pass or a skip.
    /// Used for exit codes: only real failures are non-zero.
    pub fn is_ok_or_skipped(&self) -> bool {
        matches!(self, RunStatus::Pass | RunStatus::Skipped(_))
    }
}

#[derive(Debug)]
pub struct StepReport {
    pub index: usize,
    pub description: String,
    pub status: StepStatus,
    pub duration: Duration,
}

#[derive(Debug)]
pub enum StepStatus {
    Ok,
    /// Step wasn't reached because an earlier step failed.
    Skipped,
    /// Step errored with the attached human-readable reason.
    Failed(String),
}

#[derive(Debug)]
pub enum RunError {
    /// Couldn't open the transport at all (before any steps ran).
    Transport(String),
    /// Expectation didn't match the observed flow outcome.
    ExpectationMismatch {
        expected: String,
        observed: String,
        /// Index of the step that was executing when the failure
        /// was observed (or `None` if the flow completed cleanly
        /// but the expectation required a failure).
        at_step: Option<usize>,
    },
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Transport(e) => write!(f, "transport error: {}", e),
            RunError::ExpectationMismatch {
                expected,
                observed,
                at_step,
            } => {
                write!(
                    f,
                    "expectation mismatch: expected `{}`, observed `{}`",
                    expected, observed
                )?;
                if let Some(s) = at_step {
                    write!(f, " at step {}", s)?;
                }
                Ok(())
            }
        }
    }
}

// ============================================================
//                      failure classification
// ============================================================

/// Classified outcome of a failed step. The expectation matcher
/// dispatches on this to decide pass/fail.
#[derive(Debug, Clone)]
pub enum FailureKind {
    /// Peer sent an alert record. Level + description are the
    /// RFC wire values.
    Alert { level: u8, description: u8 },
    /// plzn rejected the UUT's input and sent this alert.
    LocalReject { level: u8, description: u8 },
    /// Peer TCP-closed cleanly without sending an alert
    /// (`io::ErrorKind::UnexpectedEof` mid-step).
    CleanClose,
    /// Peer ABORTED the connection without an alert: a TCP reset or a
    /// broken-pipe/aborted close (`ConnectionReset` / `BrokenPipe` /
    /// `ConnectionAborted`). The specific errno is timing-dependent (a reset
    /// races our next read vs write), so all three map here.
    Reset,
    /// The peer exhausted its DTLS retransmission budget.
    Timeout,
    /// Other TLS-internal error (signature verification, finished
    /// mismatch, unexpected message type, etc.).
    Internal(String),
    /// Transport-layer I/O error that isn't a clean close or a reset.
    Io(String),
}

impl FailureKind {
    /// Human-readable description for the observed field in a
    /// report. Intentionally DSL-adjacent (`alert fatal/foo`) so
    /// a test author reads the same vocabulary on both sides of
    /// the expected/observed split.
    pub fn describe(&self) -> String {
        match self {
            FailureKind::Alert { level, description } => {
                let level_name = schema::alert_level_name(*level)
                    .map(String::from)
                    .unwrap_or_else(|| format!("level_{}", level));
                let desc_name = schema::alert_code_name(*description)
                    .map(String::from)
                    .unwrap_or_else(|| format!("code_{}", description));
                format!(
                    "alert {}/{} (level={}, description={})",
                    level_name, desc_name, level, description
                )
            }
            FailureKind::LocalReject { level, description } => {
                let level_name = schema::alert_level_name(*level)
                    .map(String::from)
                    .unwrap_or_else(|| format!("level_{}", level));
                let desc_name = schema::alert_code_name(*description)
                    .map(String::from)
                    .unwrap_or_else(|| format!("code_{}", description));
                format!("reject {}/{} (alert sent by plzn)", level_name, desc_name)
            }
            FailureKind::CleanClose => "peer closed without alert".into(),
            FailureKind::Reset => "peer reset the connection (no alert)".into(),
            FailureKind::Timeout => "DTLS retransmission timeout expired".into(),
            FailureKind::Internal(s) => format!("tls error: {}", s),
            FailureKind::Io(s) => format!("io error: {}", s),
        }
    }
}

fn classify(err: &TlsError) -> FailureKind {
    match err {
        TlsError::Alert { level, description } => FailureKind::Alert {
            level: *level,
            description: *description,
        },
        TlsError::Timeout => FailureKind::Timeout,
        TlsError::Record(RecordError::Io(e)) => {
            if crate::tls::dtls_transport::is_timeout_error(e) {
                FailureKind::Timeout
            } else {
                match e.kind() {
                    ErrorKind::UnexpectedEof => FailureKind::CleanClose,
                    ErrorKind::ConnectionReset
                    | ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionAborted => FailureKind::Reset,
                    _ => FailureKind::Io(format!("{}", e)),
                }
            }
        }
        TlsError::Record(RecordError::RemoteAlert { level, description }) => FailureKind::Alert {
            level: *level,
            description: *description,
        },
        TlsError::Rejected { alert, .. } => FailureKind::LocalReject {
            level: 2,
            description: *alert,
        },
        other => FailureKind::Internal(format!("{}", other)),
    }
}

/// Evaluate post-trace asserts against a completed endpoint. Returns
/// `Some((expected, observed))` describing the first assert that failed, or
/// `None` if all held.
fn eval_asserts(
    asserts: &[crate::ir::Assert],
    client: &dyn TlsEndpoint,
) -> Option<(String, String)> {
    use crate::ir::Assert;
    for assert in asserts {
        match assert {
            Assert::MaxDatagramSize(limit) => {
                let expected = format!("all received datagrams at most {} bytes", limit);
                match client.datagram_size_trace() {
                    None => {
                        return Some((expected, "no datagram-size trace available".to_string()));
                    }
                    Some(sizes) if sizes.is_empty() => {
                        return Some((expected, "no datagrams received".to_string()));
                    }
                    Some(sizes) => {
                        if let Some((index, size)) = sizes
                            .iter()
                            .enumerate()
                            .find(|(_, size)| **size > *limit as usize)
                        {
                            return Some((
                                expected,
                                format!("datagram {} was {} bytes", index + 1, size),
                            ));
                        }
                    }
                }
            }
            Assert::NewSessionTickets(want) => {
                let expected = format!("{} NewSessionTicket message(s)", want);
                match client.new_session_tickets_seen() {
                    None => {
                        return Some((
                            expected,
                            "this endpoint does not count NewSessionTickets".to_string(),
                        ));
                    }
                    Some(got) if got != *want => {
                        return Some((expected, format!("{} received", got)));
                    }
                    Some(_) => {}
                }
            }
            Assert::Resumed(want) => {
                let expected = format!("resumed == {}", want);
                match client.negotiated_resumed() {
                    None => {
                        return Some((
                            expected,
                            "this endpoint does not report resumption state".to_string(),
                        ));
                    }
                    Some(got) if got != *want => {
                        return Some((expected, format!("resumed == {}", got)));
                    }
                    Some(_) => {}
                }
            }
            Assert::NegotiatedCipher(want) => {
                let describe = |suite| {
                    crate::schema::suite_name(suite)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("0x{suite:04x}"))
                };
                let got = client.negotiated_cipher_suite();
                if got != *want {
                    return Some((
                        format!("negotiated.cipher == {}", describe(*want)),
                        format!("negotiated.cipher == {}", describe(got)),
                    ));
                }
            }
            Assert::EarlyDataAccepted(want) => {
                let expected = format!("negotiated.early_data_accepted == {want}");
                match client.negotiated_early_data_accepted() {
                    None => {
                        return Some((
                            expected,
                            "this endpoint does not report early-data state".to_owned(),
                        ));
                    }
                    Some(got) if got != *want => {
                        return Some((
                            expected,
                            format!("negotiated.early_data_accepted == {got}"),
                        ));
                    }
                    Some(_) => {}
                }
            }
            Assert::AppDataRecords(want) => {
                let expected = format!("app_data_records == {want}");
                match client.app_data_records_received() {
                    None => {
                        return Some((
                            expected,
                            "this endpoint does not count application-data records".to_owned(),
                        ));
                    }
                    Some(got) if got != *want => {
                        return Some((expected, format!("app_data_records == {got}")));
                    }
                    Some(_) => {}
                }
            }
            Assert::NoDuplicateRecordSeqnums => {
                let expected = "no duplicate (epoch, sequence_number) records".to_string();
                match client.record_seq_trace() {
                    // Only DTLS keeps this trace; the lowerer should never attach
                    // this assert to a non-DTLS test, but guard anyway.
                    None => {
                        return Some((expected, "no record-sequence trace available".to_string()));
                    }
                    Some(seqs) => {
                        // A completed handshake must have received records; an
                        // empty trace would make the assert vacuously pass.
                        if seqs.is_empty() {
                            return Some((expected, "no records received".to_string()));
                        }
                        let mut seen = std::collections::HashSet::new();
                        for s in &seqs {
                            if !seen.insert(*s) {
                                return Some((
                                    expected,
                                    format!("duplicate record (epoch<<48|seq) = 0x{:012x}", s),
                                ));
                            }
                        }
                    }
                }
            }
            // T1: TLS 1.2 explicit AEAD nonces (RFC 5288 3) of the records the
            // endpoint received: distinct / strictly increasing.
            Assert::GcmNoncesUnique | Assert::GcmNoncesMonotonic => {
                let monotonic = matches!(assert, Assert::GcmNoncesMonotonic);
                let expected = if monotonic {
                    "strictly increasing explicit AEAD nonces".to_string()
                } else {
                    "no repeated explicit AEAD nonce".to_string()
                };
                let Some(nonces) = client.explicit_nonce_trace() else {
                    return Some((expected, "no explicit-nonce trace available".to_string()));
                };
                if nonces.is_empty() {
                    return Some((
                        expected,
                        "no explicit-nonce AEAD records received".to_string(),
                    ));
                }
                let mut seen = std::collections::HashSet::new();
                let mut last: Option<u64> = None;
                for n in &nonces {
                    if !seen.insert(*n) {
                        return Some((expected, format!("explicit nonce 0x{:016x} repeated", n)));
                    }
                    if monotonic {
                        if let Some(prev) = last {
                            if *n <= prev {
                                return Some((
                                    expected,
                                    format!("explicit nonce 0x{:016x} after 0x{:016x}", n, prev),
                                ));
                            }
                        }
                        last = Some(*n);
                    }
                }
            }
        }
    }
    None
}

// ============================================================
//                          executor
// ============================================================

/// Internal bookkeeping as we walk the steps. Kept simple: either
/// every step succeeded, or one step failed and we remember which.
enum Outcome {
    Success,
    Failure {
        at_step: usize,
        failure: FailureKind,
    },
}

/// Execute a lowered Program against a peer reached via `factory`.
/// Returns the report and any captured session state (for resumption).
pub fn run_with_state(
    program: &Program,
    factory: &dyn UutFactory,
    seed: [u8; 32],
    pcap_path: Option<&std::path::Path>,
) -> (RunReport, Option<crate::ir::SessionState>) {
    run_with_session(program, factory, seed, pcap_path, None)
}

/// Run a single program, optionally resuming from a prior session's captured
/// state, and return the report plus any state this session produced. Public so
/// callers can drive a multi-session flow with a different `UutFactory` (e.g. a
/// differently-configured shim) per session.
pub fn run_with_session(
    program: &Program,
    factory: &dyn UutFactory,
    seed: [u8; 32],
    pcap_path: Option<&std::path::Path>,
    prior_session: Option<&crate::ir::SessionState>,
) -> (RunReport, Option<crate::ir::SessionState>) {
    let start = Instant::now();
    let peer_description = factory.description();
    // Select the effective expectation: check per-UUT overrides first.
    let effective_expect = program
        .expect_overrides
        .iter()
        .find(|(uut, _)| {
            peer_description
                .to_lowercase()
                .contains(&uut.to_lowercase())
        })
        .map(|(_, e)| e)
        .unwrap_or(&program.expect);
    let expected = effective_expect.describe();

    if program.resumes.is_some() && prior_session.is_none() {
        let detail = format!(
            "no saved state from session `{}`",
            program.resumes.as_deref().unwrap()
        );
        return (
            RunReport {
                test_id: program.test_id.clone(),
                status: RunStatus::Fail(RunError::Transport(detail.clone())),
                steps: vec![],
                total_duration: start.elapsed(),
                negotiated_cipher_suite: None,
                peer_description,
                expected,
                observed: detail.clone(),
                raw_outcome: ObservedOutcome::Transport { detail },
                captures: vec![],
                xfail_eligible: false,
            },
            None,
        );
    }

    let transport = match factory.open() {
        Ok(t) => t,
        Err(e) => {
            return (
                RunReport {
                    test_id: program.test_id.clone(),
                    status: RunStatus::Fail(RunError::Transport(e.to_string())),
                    steps: Vec::new(),
                    total_duration: start.elapsed(),
                    negotiated_cipher_suite: None,
                    peer_description,
                    expected,
                    observed: format!("transport open failed: {}", e),
                    raw_outcome: ObservedOutcome::Transport {
                        detail: e.to_string(),
                    },
                    captures: Vec::new(),
                    xfail_eligible: false,
                },
                None,
            );
        }
    };

    // Optionally wrap the transport in a pcap capture layer.
    let harness_is_client = program.subject == crate::ir::Subject::Server;
    let transport: Box<dyn crate::transport::UutTransport> = match pcap_path {
        Some(path) => {
            match crate::pcap::CapturingTransport::new(transport, path, harness_is_client) {
                Ok(ct) => Box::new(ct),
                Err(e) => {
                    return (
                        RunReport {
                            test_id: program.test_id.clone(),
                            status: RunStatus::Fail(RunError::Transport(format!(
                                "pcap open failed: {}",
                                e
                            ))),
                            steps: Vec::new(),
                            total_duration: start.elapsed(),
                            negotiated_cipher_suite: None,
                            peer_description,
                            expected,
                            observed: format!("pcap open failed: {}", e),
                            raw_outcome: ObservedOutcome::Transport {
                                detail: format!("pcap open failed: {}", e),
                            },
                            captures: Vec::new(),
                            xfail_eligible: false,
                        },
                        None,
                    );
                }
            }
        }
        None => transport,
    };

    let mut client = make_endpoint(
        program.version,
        program.protocol,
        program.subject,
        &program.server_name,
        transport,
        seed,
        program.send_overrides.clone(),
        program.recv_matchers.clone(),
        program.send_mutations.clone(),
        program.send_ext_deltas.clone(),
        program.cert_der.clone(),
        program.private_key_der.clone(),
        program.extra_chain_der.clone(),
        &program.suite_filters,
        program.server_suites.clone(),
        program.server_groups.clone(),
        program.key_share_groups.clone(),
        program.psk.clone(),
        prior_session,
        program.force_resumption,
        program.advertise_psk_modes && !program.resume_by_session_id,
        program.resume_psk_ke,
        program.offer_raw_public_key,
        program.server_compress_certificate,
        program.cert_request_authorities.clone(),
        program.client_signature_schemes.clone(),
        program.server_chains.clone(),
        program.client_credentials.clone(),
        program.client_chain_names.is_empty(),
        program
            .steps
            .iter()
            .any(|step| matches!(step, Step::SendEarlyData { .. })),
        program.force_hrr,
    );
    // T5: declarations after a TLS `begin_renegotiation` shape the second
    // handshake only; the TLS 1.2 client installs them when it begins.
    client.install_reneg_lists(
        program.reneg_send_overrides.clone(),
        program.reneg_send_mutations.clone(),
        program.reneg_send_ext_deltas.clone(),
    );
    let mut steps: Vec<StepReport> = Vec::with_capacity(program.steps.len());
    let mut outcome = Outcome::Success;
    let mut xfail_eligible = true;
    let mut app_seed = seed;
    for (dst, domain) in app_seed.iter_mut().zip(b"plzn app data rng") {
        *dst ^= *domain;
    }
    let mut app_rng = ChaCha20Rng::from_seed(app_seed);
    let mut expected_replies = VecDeque::new();
    let mut app_buffer = VecDeque::new();
    // Set when the harness-server couldn't satisfy its suite/group capabilities
    // selection against what the client offered — a SKIP, not a failure.
    let mut skip_reason: Option<String> = None;

    for (index, step) in program.steps.iter().enumerate() {
        let step_start = Instant::now();
        let description = step.description();
        let result = execute_step(
            client.as_mut(),
            step,
            &mut app_rng,
            &mut expected_replies,
            &mut app_buffer,
        );
        let duration = step_start.elapsed();
        match result {
            Ok(()) => {
                steps.push(StepReport {
                    index,
                    description,
                    status: StepStatus::Ok,
                    duration,
                });
            }
            Err(TlsError::SelectionUnsatisfiable { reason }) => {
                // Not a failure: the test's preconditions weren't met.
                // Mark this step and any remaining ones as skipped.
                skip_reason = Some(reason);
                steps.push(StepReport {
                    index,
                    description,
                    status: StepStatus::Skipped,
                    duration,
                });
                for (tail_index, tail_step) in program.steps.iter().enumerate().skip(index + 1) {
                    steps.push(StepReport {
                        index: tail_index,
                        description: tail_step.description(),
                        status: StepStatus::Skipped,
                        duration: Duration::ZERO,
                    });
                }
                break;
            }
            Err(err) => {
                // plzn's own endpoint rejected the peer's message: answer with
                // the alert a conformant endpoint sends before closing, so the
                // peer (and its self-check) sees a rejection, not a bare close.
                if let TlsError::Rejected { alert, .. } = &err {
                    let _ = client.send_alert(2, *alert);
                }
                let failure = classify(&err);
                xfail_eligible = protocol_verdict(&err);
                steps.push(StepReport {
                    index,
                    description,
                    status: StepStatus::Failed(failure.describe()),
                    duration,
                });
                // Pad the remaining steps with Skipped so the
                // report reflects what didn't run.
                for (tail_index, tail_step) in program.steps.iter().enumerate().skip(index + 1) {
                    steps.push(StepReport {
                        index: tail_index,
                        description: tail_step.description(),
                        status: StepStatus::Skipped,
                        duration: Duration::ZERO,
                    });
                }
                outcome = Outcome::Failure {
                    at_step: index,
                    failure,
                };
                break;
            }
        }
    }

    // Post-flow drain: if all steps succeeded, probe the socket
    // briefly to catch a deferred alert from the peer. Without
    // this, a test that ends on a send could miss the server's
    // rejection and falsely report success.
    //
    // A warning-level close_notify is a graceful shutdown signal,
    // not a failure — ignore it.
    // After `close reset` (a TCP RST) there is no socket left to probe.
    let ended_with_reset = matches!(program.steps.last(), Some(Step::Close { reset: true, .. }));
    if skip_reason.is_none() && matches!(outcome, Outcome::Success) && !ended_with_reset {
        let deadline = Instant::now() + Duration::from_millis(200);
        let drain = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Ok(());
            }
            match client.probe(remaining.as_millis().max(1) as u64) {
                // Unread replies must not conceal a later alert.
                Err(TlsError::Record(RecordError::UnexpectedContentType {
                    got: crate::tls::codec::CONTENT_TYPE_APP_DATA,
                    ..
                })) => continue,
                result => break result,
            }
        };
        if let Err(err) = drain {
            // Post-handshake handshake records (NewSessionTicket, KeyUpdate) are
            // legitimate TLS 1.3 traffic, not deferred alerts -- the number and
            // timing of tickets is peer-dependent (OpenSSL sends two by default),
            // so seeing one here must not fail an otherwise-successful flow.
            // Likewise an application-data response the flow did not read
            // (a fragmented request, or a large response split across records)
            // is not a rejection, and
            // neither is a ChangeCipherSpec: the peer's final flight arriving
            // after a flow that closed right behind its own Finished (the
            // connection-abort shapes), which is timing, not a verdict.
            let is_post_handshake = (matches!(program.steps.last(), Some(Step::Close { .. }))
                || !crate::shim::program_completes_handshake(program))
                && matches!(
                    &err,
                    TlsError::Record(RecordError::UnexpectedContentType { got, .. })
                        if *got == crate::tls::codec::CONTENT_TYPE_HANDSHAKE
                            || *got == crate::tls::codec::CONTENT_TYPE_APP_DATA
                            || *got == crate::tls::codec::CONTENT_TYPE_CCS
                );
            // A peer that has closed its socket (EOF / RST / broken pipe) after an
            // otherwise-successful flow -- especially one that ended in `close` --
            // is a normal shutdown, not a deferred alert. classify() maps only
            // UnexpectedEof to CleanClose, so match the other close kinds here.
            let is_peer_close = matches!(
                &err,
                TlsError::Record(RecordError::Io(e))
                    if matches!(
                        e.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
                    )
            );
            let failure = classify(&err);
            let is_close_notify = matches!(
                &failure,
                FailureKind::Alert {
                    level: 1,
                    description: 0
                } | FailureKind::CleanClose
            );
            if !is_close_notify && !is_post_handshake && !is_peer_close {
                xfail_eligible = protocol_verdict(&err);
                outcome = Outcome::Failure {
                    at_step: program.steps.len(),
                    failure,
                };
            }
        }
    }

    let raw_outcome = match (&skip_reason, &outcome) {
        (Some(reason), _) => ObservedOutcome::Skipped {
            reason: reason.clone(),
        },
        (None, Outcome::Success) => ObservedOutcome::Success,
        (None, Outcome::Failure { at_step, failure }) => match failure {
            FailureKind::Alert { level, description } => ObservedOutcome::Alert {
                level: *level,
                description: *description,
                at_step: *at_step,
            },
            FailureKind::LocalReject { level, description } => ObservedOutcome::LocalReject {
                level: *level,
                description: *description,
                at_step: *at_step,
            },
            FailureKind::CleanClose => ObservedOutcome::Close { at_step: *at_step },
            FailureKind::Reset => ObservedOutcome::Reset { at_step: *at_step },
            FailureKind::Timeout => ObservedOutcome::Timeout { at_step: *at_step },
            FailureKind::Internal(detail) => ObservedOutcome::Internal {
                detail: detail.clone(),
                at_step: *at_step,
            },
            FailureKind::Io(detail) => ObservedOutcome::Io {
                detail: detail.clone(),
                at_step: *at_step,
            },
        },
    };

    let (mut status, mut observed) = match skip_reason {
        Some(reason) => {
            let observed = format!("skipped: {}", reason);
            (RunStatus::Skipped(reason), observed)
        }
        None => evaluate(effective_expect, &outcome),
    };

    // Post-trace asserts (e.g. no_duplicate_record_seqnums) only make sense on an
    // otherwise-passing run: a failing assert turns Pass into a mismatch.
    if matches!(status, RunStatus::Pass) {
        if let Some((expected_desc, observed_desc)) =
            eval_asserts(&program.asserts, client.as_ref())
        {
            observed = observed_desc.clone();
            status = RunStatus::Fail(RunError::ExpectationMismatch {
                expected: expected_desc,
                observed: observed_desc,
                at_step: None,
            });
        }
    }

    let session_state = client.session_state();
    let negotiated_cipher_suite = client.negotiated_cipher_suite();
    let report = RunReport {
        test_id: program.test_id.clone(),
        status,
        steps,
        total_duration: start.elapsed(),
        negotiated_cipher_suite: (negotiated_cipher_suite != 0).then_some(negotiated_cipher_suite),
        peer_description,
        expected,
        observed,
        raw_outcome,
        captures: client.captures(),
        xfail_eligible,
    };
    (report, session_state)
}

/// Run a sequence of session programs. Each session opens a new
/// TCP connection. Sessions with `resumes` inherit the ticket +
/// master secret from the named prior session.
pub fn run_sessions(
    programs: &[Program],
    factory: &dyn UutFactory,
    seed_base: [u8; 32],
    pcap_path: Option<&std::path::Path>,
) -> Vec<RunReport> {
    let mut states: std::collections::HashMap<String, crate::ir::SessionState> =
        std::collections::HashMap::new();
    let mut reports = Vec::new();
    for program in programs {
        let prior = program.resumes.as_ref().and_then(|name| states.get(name));
        let seed = test_seed_from_id(&program.test_id, seed_base);
        let session_pcap = pcap_path.map(|base| {
            let suffix = test_seed_from_id(&program.test_id, [0u8; 32]);
            let id = u64::from_le_bytes(suffix[..8].try_into().unwrap());
            let stem = base.file_stem().unwrap_or_default().to_string_lossy();
            let ext = base
                .extension()
                .unwrap_or_else(|| std::ffi::OsStr::new("pcap"))
                .to_string_lossy();
            base.with_file_name(format!("{stem}-{id:016x}.{ext}"))
        });
        let (report, state) =
            run_with_session(program, factory, seed, session_pcap.as_deref(), prior);
        if let (Some(name), Some(ss)) = (&program.session_name, state) {
            states.insert(name.clone(), ss);
        }
        reports.push(report);
    }
    reports
}

fn test_seed_from_id(id: &str, base: [u8; 32]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    base.hash(&mut h);
    id.hash(&mut h);
    let v = h.finish();
    let mut seed = base;
    seed[..8].copy_from_slice(&v.to_le_bytes());
    seed
}

/// Run a single program, discarding session state. Convenience
/// wrapper for non-resumption tests.
pub fn run(
    program: &Program,
    factory: &dyn UutFactory,
    seed: [u8; 32],
    pcap_path: Option<&std::path::Path>,
) -> RunReport {
    run_with_state(program, factory, seed, pcap_path).0
}

fn execute_step(
    client: &mut dyn TlsEndpoint,
    step: &Step,
    app_rng: &mut ChaCha20Rng,
    expected_replies: &mut VecDeque<usize>,
    app_buffer: &mut VecDeque<u8>,
) -> Result<(), TlsError> {
    match step {
        Step::Handshake { .. } => client.do_handshake(),
        Step::HandshakeSteps { steps, config, .. } => {
            if let Some(config) = config {
                client.configure_message(config)?;
            }
            let result = steps
                .iter()
                .try_for_each(|step| client.do_handshake_step(step));
            if let Some(config) = config.as_ref().filter(|config| !config.send) {
                let mut cleared = (**config).clone();
                cleared.fields.clear();
                client.configure_message(&cleared)?;
            }
            result
        }
        Step::SendAppData {
            size,
            reply_size,
            mutations,
            ..
        } => {
            let data = crate::app_data::request(app_rng, *size, *reply_size);
            client.write_app_data(&data, mutations)?;
            if let Some(reply) = reply_size {
                expected_replies.push_back(*reply);
            }
            Ok(())
        }
        Step::RecvAppData { size, .. } => {
            let want = (*size).or(expected_replies.pop_front());
            if let Some(want) = want {
                read_exact_app_data(client, want, app_buffer)?;
            } else if app_buffer.is_empty() {
                // A bare receive still asserts that some application data arrives.
                // Keep the historical one-record consumption semantics.
                read_exact_app_data(client, 1, app_buffer)?;
                app_buffer.clear();
            } else {
                app_buffer.clear();
            }
            Ok(())
        }
        Step::RecvExporter {
            label,
            context,
            length,
            ..
        } => {
            let expected = client.export_keying_material(label, context.as_deref(), *length)?;
            let got = read_exact_app_data(client, *length, app_buffer)?;
            if got != expected {
                return Err(TlsError::MatcherFailed {
                    message: "Exporter",
                    field: "keying_material".into(),
                    expected: hex_bytes(&expected),
                    observed: hex_bytes(&got),
                });
            }
            Ok(())
        }
        Step::RecvTlsUnique {
            unavailable: true, ..
        } => {
            if let Ok(value) = client.tls_unique() {
                return Err(TlsError::MatcherFailed {
                    message: "TLSUnique",
                    field: "availability".into(),
                    expected: "unavailable".into(),
                    observed: format!("available ({} bytes)", value.len()),
                });
            }
            let got = read_exact_app_data(client, 1, app_buffer)?;
            if got != [0x01] {
                return Err(TlsError::MatcherFailed {
                    message: "TLSUnique",
                    field: "availability".into(),
                    expected: "unavailable".into(),
                    observed: "UUT exposed a channel binding".into(),
                });
            }
            Ok(())
        }
        Step::RecvTlsUnique { .. } => {
            let expected = client.tls_unique()?;
            let got = read_exact_app_data(client, expected.len(), app_buffer)?;
            if got != expected {
                return Err(TlsError::MatcherFailed {
                    message: "TLSUnique",
                    field: "channel_binding".into(),
                    expected: hex_bytes(&expected),
                    observed: hex_bytes(&got),
                });
            }
            Ok(())
        }
        Step::SendEarlyData {
            size, mutations, ..
        } => {
            let mut data = vec![0u8; *size];
            app_rng.fill_bytes(&mut data);
            client.write_early_data(&data, mutations)
        }
        Step::RecvEarlyData { size, .. } => {
            let got = client.read_early_data()?;
            if let Some(want) = size {
                if got.len() != *want {
                    return Err(TlsError::MatcherFailed {
                        message: "EarlyData",
                        field: "size".into(),
                        expected: format!("{} bytes", want),
                        observed: format!("{} bytes", got.len()),
                    });
                }
            }
            Ok(())
        }
        Step::Close { alert, reset, .. } => match alert {
            Some([level, code]) => client.close_with_alert(*level, *code),
            None if *reset => client.close_reset(),
            None => client.close(),
        },
        Step::RecvAlert { level, code, .. } => client.recv_alert(*level, *code),
        Step::Wait { millis, .. } => client.probe(*millis),
        Step::AdvanceClock { nanos, .. } => client.advance_clock(*nanos),
        Step::ExpectNextTimeout { nanos, .. } => client.expect_next_timeout(Some(*nanos)),
        Step::ExpectNoTimeout { .. } => client.expect_next_timeout(None),
        Step::SetTimeout { millis, .. } => client.set_timeout(*millis),
        Step::ExpectRetransmit { .. } => client.expect_retransmit(),
        Step::RotateCookieSecret { .. } => client.rotate_cookie_secret(),
        Step::ResendFlight { .. } => client.resend_flight(),
        Step::Renegotiate {
            resumed,
            insecure,
            overrides,
            ext_deltas,
            ..
        } => client.renegotiate_with(*resumed, *insecure, overrides, ext_deltas),
        Step::BeginRenegotiation { .. } => client.begin_renegotiation_step(),
        Step::SendRaw { data, .. } => client.write_raw(data),
        Step::SendKeyUpdate {
            request_update,
            mutations,
            ..
        } => client.send_key_update_with(*request_update, mutations),
        Step::RecvKeyUpdate { matchers, .. } => client.recv_key_update_matching(matchers),
        Step::SendRenegotiation { msg_type, .. } => client.send_renegotiation(*msg_type),
        Step::Dtls { op, .. } => client.dtls_op(op),
        Step::SendAlert {
            level,
            code,
            mutations,
            ..
        } => client.send_alert_with(*level, *code, mutations),
        Step::CoalesceBegin { mode, .. } => client.begin_coalesce(*mode),
        Step::CoalesceEnd { .. } => client.end_coalesce(),
        Step::AtomicBegin { .. } => client.begin_atomic(),
        Step::AtomicEnd { .. } => client.end_atomic(),
        Step::SendRecord {
            content_type,
            data,
            mutations,
            ..
        } => client.send_record_with(*content_type, data, mutations),
        Step::SendEmptyRecord {
            content_type,
            mutations,
            ..
        } => client.send_record_with(*content_type, &[], mutations),
        Step::FlushFragment { .. } => client.flush_fragment(),
    }
}

fn protocol_verdict(error: &TlsError) -> bool {
    if let TlsError::Record(RecordError::Io(error)) = error {
        return matches!(
            error.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
                | ErrorKind::ConnectionAborted
        );
    }
    matches!(
        error,
        TlsError::Alert { .. }
            | TlsError::Rejected { .. }
            | TlsError::MatcherFailed { .. }
            | TlsError::FinishedMismatch
            | TlsError::SignatureVerificationFailed
            | TlsError::UnexpectedHandshake { .. }
            | TlsError::ServerChoseUnsupportedSuite(_)
            | TlsError::ServerChoseUnofferedSuite(_)
            | TlsError::ServerChoseUnsupportedSigScheme(_)
            | TlsError::ServerChoseUnsupportedGroup(_)
            | TlsError::ServerChoseUnsharedGroup(_)
            | TlsError::Record(RecordError::RemoteAlert { .. })
            | TlsError::Record(RecordError::UnexpectedContentType { .. })
    ) || matches!(error, TlsError::Dtls(detail) if detail.starts_with("bad record:"))
    // A datagram the peer sent that does not parse as a DTLS record (for
    // example a 7-byte stream-TLS-framed alert over UDP) is the peer's
    // protocol behaviour, not a harness fault.
}

fn read_exact_app_data(
    client: &mut dyn TlsEndpoint,
    length: usize,
    buffered: &mut VecDeque<u8>,
) -> Result<Vec<u8>, TlsError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    client.set_read_deadline(Some(deadline))?;
    let result = (|| {
        while buffered.len() < length {
            let response = if Instant::now() >= deadline {
                Err(TlsError::Record(RecordError::Io(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "application response deadline expired",
                ))))
            } else {
                client.read_app_data()
            };
            match response {
                Ok(bytes) => buffered.extend(bytes),
                Err(TlsError::Record(RecordError::Io(error)))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Err(TlsError::MatcherFailed {
                        message: "AppData",
                        field: "size".into(),
                        expected: format!("{length} bytes"),
                        observed: format!(
                            "{} bytes before the response read deadline",
                            buffered.len()
                        ),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(buffered.drain(..length).collect())
    })();
    let restored = client.set_read_deadline(None);
    result.and_then(|bytes| restored.map(|()| bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ============================================================
//                       expectation matching
// ============================================================

fn evaluate(expect: &Expectation, outcome: &Outcome) -> (RunStatus, String) {
    if let Expectation::Any(alternatives) = expect {
        for alternative in alternatives {
            let result = evaluate(alternative, outcome);
            if matches!(result.0, RunStatus::Pass) {
                return result;
            }
        }
        let (observed, at_step) = match outcome {
            Outcome::Success => ("flow completed cleanly".into(), None),
            Outcome::Failure { at_step, failure } => (failure.describe(), Some(*at_step)),
        };
        return (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: expect.describe(),
                observed: observed.clone(),
                at_step,
            }),
            observed,
        );
    }
    match (expect, outcome) {
        // -------- happy path --------
        (Expectation::Ok, Outcome::Success) => (RunStatus::Pass, "flow completed cleanly".into()),

        // -------- Ok but something failed --------
        (Expectation::Ok, Outcome::Failure { at_step, failure }) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "ok".into(),
                observed: failure.describe(),
                at_step: Some(*at_step),
            }),
            failure.describe(),
        ),

        // -------- local rejection expectations --------
        (
            Expectation::Reject { level, codes },
            Outcome::Failure {
                failure:
                    FailureKind::LocalReject {
                        level: got_level,
                        description: got_desc,
                    },
                ..
            },
        ) if *got_level == level.wire_value() && (codes.is_empty() || codes.contains(got_desc)) => {
            (
                RunStatus::Pass,
                FailureKind::LocalReject {
                    level: *got_level,
                    description: *got_desc,
                }
                .describe(),
            )
        }
        (Expectation::Reject { level, codes }, Outcome::Success) => {
            let expected = describe_reject_expectation(*level, codes);
            (
                RunStatus::Fail(RunError::ExpectationMismatch {
                    expected: expected.clone(),
                    observed: "flow completed cleanly without a local rejection".into(),
                    at_step: None,
                }),
                "flow completed cleanly without a local rejection".into(),
            )
        }
        (Expectation::Reject { level, codes }, Outcome::Failure { at_step, failure }) => {
            let expected = describe_reject_expectation(*level, codes);
            let observed = failure.describe();
            (
                RunStatus::Fail(RunError::ExpectationMismatch {
                    expected,
                    observed: observed.clone(),
                    at_step: Some(*at_step),
                }),
                observed,
            )
        }

        // -------- alert expectations --------
        (
            Expectation::Alert { level, codes },
            Outcome::Failure {
                at_step,
                failure:
                    FailureKind::Alert {
                        level: got_level,
                        description: got_desc,
                    },
            },
        ) => {
            let want_level = level.wire_value();
            let level_ok = *got_level == want_level;
            let code_ok = codes.is_empty() || codes.contains(got_desc);
            if level_ok && code_ok {
                (
                    RunStatus::Pass,
                    FailureKind::Alert {
                        level: *got_level,
                        description: *got_desc,
                    }
                    .describe(),
                )
            } else {
                let observed = FailureKind::Alert {
                    level: *got_level,
                    description: *got_desc,
                }
                .describe();
                (
                    RunStatus::Fail(RunError::ExpectationMismatch {
                        expected: describe_alert_expectation(*level, codes),
                        observed: observed.clone(),
                        at_step: Some(*at_step),
                    }),
                    observed,
                )
            }
        }
        (Expectation::Alert { level, codes }, Outcome::Success) => {
            let expected = describe_alert_expectation(*level, codes);
            (
                RunStatus::Fail(RunError::ExpectationMismatch {
                    expected: expected.clone(),
                    observed: "flow completed cleanly without any alert".into(),
                    at_step: None,
                }),
                "flow completed cleanly without any alert".into(),
            )
        }
        (Expectation::Alert { level, codes }, Outcome::Failure { at_step, failure }) => {
            let expected = describe_alert_expectation(*level, codes);
            let observed = failure.describe();
            (
                RunStatus::Fail(RunError::ExpectationMismatch {
                    expected,
                    observed: observed.clone(),
                    at_step: Some(*at_step),
                }),
                observed,
            )
        }

        // -------- close expectation --------
        (
            Expectation::Close,
            Outcome::Failure {
                at_step: _,
                failure: FailureKind::CleanClose,
            },
        ) => (RunStatus::Pass, "peer closed without alert".into()),
        (Expectation::Close, Outcome::Success) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "close".into(),
                observed: "flow completed cleanly".into(),
                at_step: None,
            }),
            "flow completed cleanly".into(),
        ),
        (Expectation::Close, Outcome::Failure { at_step, failure }) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "close".into(),
                observed: failure.describe(),
                at_step: Some(*at_step),
            }),
            failure.describe(),
        ),

        // -------- reset expectation (abortive close, no alert) --------
        (
            Expectation::Reset,
            Outcome::Failure {
                at_step: _,
                failure: FailureKind::Reset,
            },
        ) => (
            RunStatus::Pass,
            "peer reset the connection (no alert)".into(),
        ),
        (Expectation::Reset, Outcome::Success) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "reset".into(),
                observed: "flow completed cleanly".into(),
                at_step: None,
            }),
            "flow completed cleanly".into(),
        ),
        (Expectation::Reset, Outcome::Failure { at_step, failure }) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "reset".into(),
                observed: failure.describe(),
                at_step: Some(*at_step),
            }),
            failure.describe(),
        ),

        // -------- DTLS timeout expectation --------
        (
            Expectation::Timeout,
            Outcome::Failure {
                failure: FailureKind::Timeout,
                ..
            },
        ) => (
            RunStatus::Pass,
            "DTLS retransmission timeout expired".into(),
        ),
        (Expectation::Timeout, Outcome::Success) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "timeout".into(),
                observed: "flow completed cleanly".into(),
                at_step: None,
            }),
            "flow completed cleanly".into(),
        ),
        (Expectation::Timeout, Outcome::Failure { at_step, failure }) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "timeout".into(),
                observed: failure.describe(),
                at_step: Some(*at_step),
            }),
            failure.describe(),
        ),

        // -------- handshake-fails: wildcard --------
        (
            Expectation::HandshakeFails,
            Outcome::Failure {
                failure:
                    failure @ (FailureKind::Alert { .. }
                    | FailureKind::CleanClose
                    | FailureKind::Reset
                    | FailureKind::Timeout),
                ..
            },
        ) => (RunStatus::Pass, failure.describe()),
        (Expectation::HandshakeFails, Outcome::Failure { at_step, failure }) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "handshake-fails (peer protocol failure)".into(),
                observed: failure.describe(),
                at_step: Some(*at_step),
            }),
            failure.describe(),
        ),
        (Expectation::HandshakeFails, Outcome::Success) => (
            RunStatus::Fail(RunError::ExpectationMismatch {
                expected: "handshake-fails".into(),
                observed: "flow completed cleanly".into(),
                at_step: None,
            }),
            "flow completed cleanly".into(),
        ),
        (Expectation::Any(_), _) => unreachable!("handled above"),
    }
}

fn describe_alert_expectation(level: AlertLevel, codes: &[u8]) -> String {
    if codes.is_empty() {
        format!("alert {}", level.name())
    } else if codes.len() == 1 {
        let name = schema::alert_code_name(codes[0])
            .map(String::from)
            .unwrap_or_else(|| format!("{}", codes[0]));
        format!("alert {}/{}", level.name(), name)
    } else {
        let names: Vec<String> = codes
            .iter()
            .map(|c| {
                schema::alert_code_name(*c)
                    .map(String::from)
                    .unwrap_or_else(|| format!("{}", c))
            })
            .collect();
        format!("alert {}/{{{}}}", level.name(), names.join(","))
    }
}

fn describe_reject_expectation(level: AlertLevel, codes: &[u8]) -> String {
    describe_alert_expectation(level, codes).replacen("alert", "reject", 1)
}

// ============================================================
//                       report rendering
// ============================================================

impl RunReport {
    /// Compact one-line status (default output for passes).
    pub fn display_compact(&self) -> String {
        let label = match &self.status {
            RunStatus::Pass => "PASS",
            RunStatus::Fail(_) => "FAIL",
            RunStatus::Skipped(_) => "SKIP",
        };
        format!(
            "[{}] {} — {} ({:?})",
            label, self.test_id, self.peer_description, self.total_duration
        )
    }

    /// Full verbose report with step-by-step trace.
    pub fn display_verbose(&self) -> String {
        let mut out = String::new();
        use std::fmt::Write;
        let label = match &self.status {
            RunStatus::Pass => "PASS",
            RunStatus::Fail(_) => "FAIL",
            RunStatus::Skipped(_) => "SKIP",
        };
        writeln!(
            out,
            "[{}] {} — {} ({:?})",
            label, self.test_id, self.peer_description, self.total_duration
        )
        .ok();
        if let Some(cs) = self.negotiated_cipher_suite {
            writeln!(out, "       negotiated cipher suite: 0x{:04x}", cs).ok();
        }
        for s in &self.steps {
            let tag = match &s.status {
                StepStatus::Ok => "ok    ",
                StepStatus::Skipped => "skip  ",
                StepStatus::Failed(_) => "FAIL  ",
            };
            writeln!(
                out,
                "  {:>2}. {} {} ({:?})",
                s.index, tag, s.description, s.duration
            )
            .ok();
            if let StepStatus::Failed(msg) = &s.status {
                writeln!(out, "       {}", msg).ok();
            }
        }
        // T1: what `capture $name` matchers recorded.
        for (name, value) in &self.captures {
            let hex: String = value.iter().map(|b| format!("{:02x}", b)).collect();
            writeln!(out, "       captured ${} = {}", name, hex).ok();
        }
        writeln!(out, "       expected: {}", self.expected).ok();
        writeln!(out, "       observed: {}", self.observed).ok();
        if let RunStatus::Fail(RunError::ExpectationMismatch {
            at_step: Some(s), ..
        }) = &self.status
        {
            writeln!(out, "       at step:  {}", s).ok();
        }
        out
    }
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Default Display remains verbose for backwards-compat
        // (integration tests use this format).
        f.write_str(&self.display_verbose())
    }
}

#[cfg(test)]
mod reaudit_tests {
    use super::*;

    #[test]
    fn application_reads_preserve_excess_and_accept_more_than_64_records() {
        use crate::tls::driver::{Tls13Client, Tls13ClientConfig};
        use crate::tls::record::{RecordLayer, TlsVersion};
        let transport = crate::transport::MockTransport::new("application stream");
        let mut writer = RecordLayer::new(Box::new(transport.clone()), TlsVersion::Tls13);
        for _ in 0..128 {
            writer.write_app_data(b"a").unwrap();
        }
        writer.write_app_data(b"bcdef").unwrap();
        transport.push_incoming(&transport.take_written());
        let mut client = Tls13Client::new(
            Box::new(transport),
            Tls13ClientConfig::default_for("localhost", [0; 32]),
        );
        let mut buffered = VecDeque::new();
        assert_eq!(
            read_exact_app_data(&mut client, 129, &mut buffered).unwrap(),
            [vec![b'a'; 128], vec![b'b']].concat()
        );
        assert_eq!(
            read_exact_app_data(&mut client, 4, &mut buffered).unwrap(),
            b"cdef"
        );
        assert!(buffered.is_empty());
    }

    #[test]
    fn local_faults_are_not_xfail_eligible() {
        assert!(!protocol_verdict(&TlsError::Internal("broken harness")));
        assert!(!protocol_verdict(&TlsError::UnknownFieldOverride {
            message: "Finished",
            field: "typo".into()
        }));
        assert!(!protocol_verdict(&TlsError::Record(RecordError::Io(
            std::io::Error::new(ErrorKind::PermissionDenied, "denied")
        ))));
        assert!(!protocol_verdict(&TlsError::Codec(
            crate::tls::codec::CodecError::UnexpectedEof
        )));
        assert!(protocol_verdict(&TlsError::MatcherFailed {
            message: "Finished",
            field: "verify_data".into(),
            expected: "expected".into(),
            observed: "actual".into()
        }));
        // A server choosing what the ClientHello never offered is the peer's
        // protocol violation (e.g. resuming a session whose suite is gone).
        assert!(protocol_verdict(&TlsError::ServerChoseUnofferedSuite(
            0xc014
        )));
        assert!(protocol_verdict(&TlsError::ServerChoseUnsharedGroup(
            0x0017
        )));
    }
}
