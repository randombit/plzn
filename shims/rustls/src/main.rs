//! plzn rustls interop shim.
//!
//! A real subprocess (not the in-memory rustls server) that reads the same JSON
//! config file as the Botan/OpenSSL shims, dials the plzn runner, runs a rustls
//! handshake in the configured role, answers application-data requests,
//! self-checks the configured expectations, and exits with a structured result CASE (the exit
//! code -- mirroring shims/common/plzn_shim.h `ShimResult`) so the runner learns
//! which failure path was taken, not just the wire alert.
//!
//! This is a separate crate under `shims/`: it links the plzn library to reuse
//! `plzn::shim::ShimConfig`, without making rustls a dependency of plzn itself.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::Arc;

use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};

use plzn::app_data::Responder;
use plzn::shim::ShimConfig;

// Result cases, matching shims/common/plzn_shim.h `ShimResult` (value == exit code).
const OK: u8 = 0;
const LOCAL_ERROR: u8 = 10;
const IO_ERROR: u8 = 11;
const HANDSHAKE_FAILED: u8 = 12;
const EXPECTATION_MISMATCH: u8 = 13;
const UNEXPECTED_SUCCESS: u8 = 14;
/// The library cannot apply a configured policy knob; the runner SKIPs the case.
const UNSUPPORTED_CONFIG: u8 = 16;

/// A failure carrying the structured case to report.
struct Fail {
    case: u8,
    detail: String,
}
impl Fail {
    fn new(case: u8, detail: impl Into<String>) -> Self {
        Fail {
            case,
            detail: detail.into(),
        }
    }
}

/// Exit once the parent plzn runner is gone: a runner killed mid-case leaves
/// nothing to read the result, so do not linger.
fn exit_when_orphaned() {
    let parent = std::os::unix::process::parent_id();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if std::os::unix::process::parent_id() != parent {
                std::process::exit(i32::from(IO_ERROR));
            }
        }
    });
}

fn main() -> ExitCode {
    exit_when_orphaned();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "--plzn-shim-info") {
        println!(r#"{{"protocol":"plzn-shim","protocol_version":1,"name":"rustls"}}"#);
        return ExitCode::SUCCESS;
    }
    let mut args = argv.into_iter();
    let mut cfg_path: Option<String> = None;
    while let Some(a) = args.next() {
        if a == "-config" || a == "--config" {
            cfg_path = args.next();
        }
    }
    let cfg_path = match cfg_path {
        Some(p) => p,
        None => {
            eprintln!("usage: rustls_shim -config <file.json> | --plzn-shim-info");
            return ExitCode::from(LOCAL_ERROR);
        }
    };

    // The chain lists (`credentials.chains` / `client_chains`) and the
    // `requires.server_key` list are read from the raw JSON so this shim does
    // not depend on the typed config growing them at the same time.
    let raw_text = std::fs::read_to_string(&cfg_path).unwrap_or_default();
    let _ = CHAINS.set(ChainLists::from_json(&raw_text));
    let cfg: ShimConfig = match std::fs::read_to_string(&cfg_path)
        .map_err(|e| e.to_string())
        .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            report(LOCAL_ERROR, &format!("config error: {}", e));
            return ExitCode::from(LOCAL_ERROR);
        }
    };

    let expect_handshake_failure = cfg.expect.handshake_error.is_some();
    // plzn abandons the handshake on purpose: either outcome is fine.
    let abandoned = cfg.expect.handshake_abandoned;

    match run(&cfg) {
        Ok(()) => {
            if expect_handshake_failure && !abandoned {
                report(
                    UNEXPECTED_SUCCESS,
                    "expected the handshake to fail but it completed",
                );
                return ExitCode::from(UNEXPECTED_SUCCESS);
            }
            report(OK, "");
            ExitCode::from(OK)
        }
        Err(f) => {
            // A handshake/io failure when the test expected one is a pass -- but keep
            // the reason in `detail` so the runner learns WHICH failure path was taken.
            if (expect_handshake_failure || abandoned)
                && (f.case == HANDSHAKE_FAILED || f.case == IO_ERROR)
            {
                report(OK, &f.detail);
                return ExitCode::from(OK);
            }
            report(f.case, &f.detail);
            ExitCode::from(f.case)
        }
    }
}

/// Refuse `uut` knobs rustls has no switch for, before dialing, so the runner
/// SKIPs the case with the reason instead of passing it vacuously.
fn check_policy(cfg: &ShimConfig) -> Result<(), Fail> {
    if cfg.min_version.is_some_and(|v| v < 0x0303) || cfg.max_version.is_some_and(|v| v < 0x0303) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.versions: rustls does not implement TLS 1.0 or TLS 1.1",
        ));
    }
    if !cfg.signing_prefs.is_empty() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.signing_prefs: rustls does not expose signing-scheme preference configuration",
        ));
    }
    for (name, types) in [
        ("server_certificate_types", &cfg.server_certificate_types),
        ("client_certificate_types", &cfg.client_certificate_types),
    ] {
        if !types.is_empty() && types.as_slice() != [0] && types.as_slice() != [2] {
            return Err(Fail::new(
                UNSUPPORTED_CONFIG,
                format!(
                    "uut.{}: rustls only exposes X.509-only or raw-public-key-only configuration",
                    name
                ),
            ));
        }
    }
    if cfg.min_version.unwrap_or(0x0303) <= 0x0303
        && (cfg.server_certificate_types.contains(&2) || cfg.client_certificate_types.contains(&2))
    {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.certificate_types: rustls implements raw public keys only in TLS 1.3",
        ));
    }
    if cfg
        .key_material
        .iter()
        .any(|request| request.kind.starts_with("tls_unique"))
    {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "key_material: rustls does not expose the TLS 1.2 Finished value needed for tls-unique",
        ));
    }
    if let Some(r) = &cfg.renegotiation {
        match r.as_str() {
            "none" => {}
            "client" | "server" | "both" => {
                return Err(Fail::new(
                    UNSUPPORTED_CONFIG,
                    "uut.renegotiation: rustls never renegotiates; only `none` is honoured",
                ));
            }
            other => {
                return Err(Fail::new(
                    LOCAL_ERROR,
                    format!("invalid renegotiation value: {}", other),
                ));
            }
        }
    }
    if let Some(e) = &cfg.extended_master_secret {
        match e.as_str() {
            "require" | "allow" => {}
            "off" => {
                return Err(Fail::new(
                    UNSUPPORTED_CONFIG,
                    "uut.extended_master_secret: rustls always offers extended_master_secret; only require/allow",
                ));
            }
            other => {
                return Err(Fail::new(
                    LOCAL_ERROR,
                    format!("invalid extended_master_secret value: {}", other),
                ));
            }
        }
    }
    if cfg.encrypt_then_mac == Some(true) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.encrypt_then_mac: rustls has no CBC suites, so encrypt_then_mac can never be negotiated",
        ));
    }
    if cfg.middlebox_compat == Some(false) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.middlebox_compat: rustls always sends the TLS 1.3 compatibility ChangeCipherSpec",
        ));
    }
    if cfg.records_per_traffic_key.is_some() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.records_per_traffic_key: rustls has no automatic KeyUpdate policy",
        ));
    }
    if cfg.key_update {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.key_update: manual post-handshake KeyUpdate initiation is not wired in the rustls shim",
        ));
    }
    if cfg.max_cert_list.is_some() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.max_cert_list: rustls exposes no configurable peer certificate-list limit",
        ));
    }
    if cfg.record_size_limit.is_some() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.record_size_limit: rustls exposes no RFC 8449 record-size-limit policy",
        ));
    }
    if cfg.renegotiate_freely {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "renegotiation: rustls never renegotiates (a `renegotiate` step or `uut client { renegotiate_after_handshake }`)",
        ));
    }
    if cfg.renegotiate_after_handshake {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.renegotiate_after_handshake: rustls never renegotiates",
        ));
    }
    // T6: rustls's server never requests post-handshake authentication.
    if cfg.post_handshake_auth.is_some() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.post_handshake_auth: rustls has no server-side post-handshake client authentication (RFC 8446 4.6.2)",
        ));
    }
    if cfg.hello_request_after_app_data {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.hello_request_after_app_data: rustls never renegotiates (no server HelloRequest)",
        ));
    }
    // rustls never rate-limits received KeyUpdates: 0 ("no limit") is its
    // behaviour, any other interval is a knob it lacks.
    if cfg.min_key_update_interval_ms.is_some_and(|ms| ms != 0) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.min_key_update_interval_ms: rustls has no KeyUpdate rate limit (only 0 = no limit is honoured)",
        ));
    }
    if !cfg.half_rtt_data.is_empty() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.half_rtt_data: the rustls shim does not write half-RTT application data",
        ));
    }
    if !cfg.psk.secret_hex.is_empty() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "psk: rustls has no external pre-shared keys (resumption PSKs only)",
        ));
    }
    // `verify_prefs` is honoured by the client's accept-any verifier (its
    // supported_verify_schemes); the WebPKI verifier and the server's client-
    // certificate verifier keep the provider's full list.
    if !cfg.verify_prefs.is_empty() && (cfg.role == "server" || cfg.verify.peer) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "uut.verify_prefs: rustls shim applies it to the client's accept-any verifier only",
        ));
    }
    Ok(())
}

fn group_name(w: u16) -> String {
    match w {
        0x001d => "x25519".into(),
        0x001e => "x448".into(),
        0x0017 => "secp256r1".into(),
        0x0018 => "secp384r1".into(),
        0x0019 => "secp521r1".into(),
        0x0100 => "ffdhe2048".into(),
        0x0101 => "ffdhe3072".into(),
        0x0102 => "ffdhe4096".into(),
        0x0103 => "ffdhe6144".into(),
        0x0104 => "ffdhe8192".into(),
        _ => format!("0x{:04x}", w),
    }
}

fn list_groups(ws: &[u16]) -> String {
    ws.iter()
        .map(|w| group_name(*w))
        .collect::<Vec<_>>()
        .join(", ")
}

fn list_suites(ws: &[u16]) -> String {
    ws.iter()
        .map(|w| format!("0x{:04x}", w))
        .collect::<Vec<_>>()
        .join(", ")
}

fn report(case: u8, detail: &str) {
    let name = match case {
        OK => "ok",
        LOCAL_ERROR => "local_error",
        IO_ERROR => "io_error",
        HANDSHAKE_FAILED => "handshake_failed",
        EXPECTATION_MISMATCH => "expectation_mismatch",
        UNEXPECTED_SUCCESS => "unexpected_success",
        UNSUPPORTED_CONFIG => "unsupported_config",
        _ => "failure",
    };
    eprintln!("PLZN-RESULT case={} detail={}", name, detail);
}

/// rustls protocol-version set from the config's min/max (TLS wire codes).
fn versions(cfg: &ShimConfig) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let lo = cfg.min_version.unwrap_or(0x0303);
    let hi = cfg.max_version.unwrap_or(0x0304);
    let mut v = Vec::new();
    if lo <= 0x0303 && hi >= 0x0303 {
        v.push(&rustls::version::TLS12);
    }
    if lo <= 0x0304 && hi >= 0x0304 {
        v.push(&rustls::version::TLS13);
    }
    v
}

/// Build the crypto provider, restricting cipher suites and key-exchange groups to the config's
/// `cipher_suites` / `curves` when set. This lets the uut policy tests pin the shim to a narrow
/// policy and force a negotiation failure (BoGo NoCommonCurves / cipher-mismatch), the same way
/// the Botan and OpenSSL shims honor these fields.
///
/// A `uut` value the provider does not have (a CBC or static-RSA suite, P-521,
/// FFDHE) is refused rather than silently dropped: the test asked for a policy
/// this library cannot express, so the case SKIPs. Likewise a program whose
/// offer (`requires`) has no suite or group in common with the provider.
fn build_provider(cfg: &ShimConfig) -> Result<Arc<rustls::crypto::CryptoProvider>, Fail> {
    // aws-lc-rs rather than ring: the same suites and curves, plus the ML-KEM
    // groups (X25519MLKEM768, SecP256r1MLKEM768, MLKEM768, MLKEM1024). The
    // shim exposes every group the provider implements, not just its defaults.
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS.to_vec();
    let have_suite = |w: u16| {
        provider
            .cipher_suites
            .iter()
            .any(|cs| u16::from(cs.suite()) == w)
    };
    let have_group = |w: u16| {
        provider
            .kx_groups
            .iter()
            .any(|kx| u16::from(kx.name()) == w)
    };
    let missing: Vec<u16> = cfg
        .cipher_suites
        .iter()
        .copied()
        .filter(|w| !have_suite(*w))
        .collect();
    if !missing.is_empty() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            format!(
                "uut.cipher_suites: rustls (aws-lc-rs) has no {}",
                list_suites(&missing)
            ),
        ));
    }
    let missing: Vec<u16> = cfg
        .curves
        .iter()
        .copied()
        .filter(|w| !have_group(*w))
        .collect();
    if !missing.is_empty() {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            format!(
                "uut.curves: rustls (aws-lc-rs) has no {}",
                list_groups(&missing)
            ),
        ));
    }
    let req = &cfg.requires;
    if !req.any_suite.is_empty() && !req.any_suite.iter().any(|w| have_suite(*w)) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            format!(
                "peer.capabilities: rustls (aws-lc-rs) has none of the offered cipher suites [{}]",
                list_suites(&req.any_suite)
            ),
        ));
    }
    if !req.any_group.is_empty() && !req.any_group.iter().any(|w| have_group(*w)) {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            format!(
                "peer.capabilities: rustls (aws-lc-rs) has none of the offered groups [{}]",
                list_groups(&req.any_group)
            ),
        ));
    }
    if !cfg.cipher_suites.is_empty() {
        provider
            .cipher_suites
            .retain(|cs| cfg.cipher_suites.contains(&u16::from(cs.suite())));
    }
    if !cfg.curves.is_empty() {
        provider
            .kx_groups
            .retain(|kx| cfg.curves.contains(&u16::from(kx.name())));
    }
    Ok(Arc::new(provider))
}

fn run(cfg: &ShimConfig) -> Result<(), Fail> {
    if cfg.protocol == "dtls" {
        // rustls has no DTLS support; report a local error so the runner can skip.
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "protocol: rustls has no DTLS",
        ));
    }
    check_policy(cfg)?;
    // T3 / chains: webpki has no id-RSASSA-PSS SubjectPublicKeyInfo, so a
    // server chain with such a key can be neither verified (plzn's, when we
    // are the client: `requires.server_key` lists what plzn's server MAY
    // present -- refuse only when every option is one) nor served (ours).
    // The aws-lc-rs provider verifies and signs P-521, unlike ring.
    let required = chains().server_keys.clone();
    if !required.is_empty() && required.iter().all(|k| k == "rsa_pss") {
        return Err(Fail::new(
            UNSUPPORTED_CONFIG,
            "chain rsa_pss: rustls (webpki) cannot verify an id-RSASSA-PSS server key",
        ));
    }
    if cfg.role == "server" {
        let served = chains().server.clone();
        let usable = served
            .iter()
            .filter(|c| unsupported_key_kind(&c.key_file).is_none())
            .count();
        if !served.is_empty() && usable == 0 {
            return Err(Fail::new(
                UNSUPPORTED_CONFIG,
                "chain rsa_pss: rustls cannot load an id-RSASSA-PSS private key",
            ));
        }
    }
    // Refuse an inapplicable configuration BEFORE dialing, so the runner sees
    // the unsupported_config exit and SKIPs without waiting on the socket.
    let provider = build_provider(cfg)?;

    let vers = versions(cfg);
    if vers.is_empty() {
        return Err(Fail::new(
            LOCAL_ERROR,
            "no protocol version selected by min/max",
        ));
    }

    // Keep one client session store while rebuilding the ClientConfig for each
    // connection. Cross-version tests pin each connection to a different
    // version, but must retain the ticket/session learned by the prior one.
    let client_session_store: Option<Arc<dyn rustls::client::ClientSessionStore>> =
        (cfg.role != "server").then(|| {
            // Keep rustls's normal cache size. A cache sized merely to this
            // test's connection count can discard the TLS 1.2 session before
            // the next ClientConfig retrieves it.
            Arc::new(rustls::client::ClientSessionMemoryCache::new(256))
                as Arc<dyn rustls::client::ClientSessionStore>
        });
    // rustls deliberately rejects a cached session when either of these Arc
    // identities changes. Cross-version runs need distinct ClientConfigs, so
    // retain the security-policy objects as well as the session store.
    let client_identity = if cfg.role == "server" {
        None
    } else {
        Some(build_client_identity(cfg, provider.clone())?)
    };
    for connection_index in 0..=cfg.resume_count {
        // Dial the runner and announce our ShimID (8-byte little-endian).
        let mut sock = TcpStream::connect((cfg.runner.host.as_str(), cfg.runner.port))
            .map_err(|e| Fail::new(IO_ERROR, format!("connect: {}", e)))?;
        // Every TLS record goes out as soon as it is written: with Nagle on, a
        // flight sent as several small writes stalls on the peer's delayed ACK
        // (~40 ms on Linux) -- see shims/common/shim_socket.cpp.
        let _ = sock.set_nodelay(true);
        sock.write_all(&cfg.shim_id.to_le_bytes())
            .map_err(|e| Fail::new(IO_ERROR, format!("write shim id: {}", e)))?;
        if cfg.role == "server" {
            run_server(
                &cfg.for_connection(connection_index as usize),
                &mut sock,
                provider.clone(),
                &vers,
                connection_index,
            )?;
        } else {
            let connection_cfg = cfg.for_connection(connection_index as usize);
            let connection_vers = versions(&connection_cfg);
            if connection_vers.is_empty() {
                return Err(Fail::new(
                    LOCAL_ERROR,
                    "no protocol version selected for connection",
                ));
            }
            let client_config = Arc::new(build_client_config(
                &connection_cfg,
                provider.clone(),
                &connection_vers,
                client_session_store.clone(),
                client_identity.as_ref().expect("client identity"),
            )?);
            run_client(&connection_cfg, &mut sock, client_config, connection_index)?;
        }
    }
    Ok(())
}

/// RFC 8879 zlib certificate compressor (flate2-backed), for the shim's cert_compressors
/// when the peer advertises compress_certificate.
#[derive(Debug)]
struct ZlibCertCompressor;

impl rustls::compress::CertCompressor for ZlibCertCompressor {
    fn compress(
        &self,
        input: Vec<u8>,
        _level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&input)
            .map_err(|_| rustls::compress::CompressionFailed)?;
        enc.finish()
            .map_err(|_| rustls::compress::CompressionFailed)
    }
    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zlib
    }
}

static ZLIB_CERT_COMPRESSOR: ZlibCertCompressor = ZlibCertCompressor;

/// T6: RFC 8879 zlib certificate DEcompressor (flate2-backed), registered on
/// the server so its CertificateRequest advertises compress_certificate and a
/// client's CompressedCertificate is accepted (the library feature, exposed
/// by default).
#[derive(Debug)]
struct ZlibCertDecompressor;

impl rustls::compress::CertDecompressor for ZlibCertDecompressor {
    fn decompress(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), rustls::compress::DecompressionFailed> {
        use std::io::Read;
        let mut dec = flate2::read::ZlibDecoder::new(input);
        dec.read_exact(output)
            .map_err(|_| rustls::compress::DecompressionFailed)?;
        // RFC 8879 4: the inflated size must be exactly uncompressed_length.
        let mut extra = [0u8; 1];
        match dec.read(&mut extra) {
            Ok(0) => Ok(()),
            _ => Err(rustls::compress::DecompressionFailed),
        }
    }
    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Zlib
    }
}

static ZLIB_CERT_DECOMPRESSOR: ZlibCertDecompressor = ZlibCertDecompressor;

/// A deterministic, stateless ticketer so a fresh shim PROCESS on the resumed connection can
/// recover the session the first process issued (each shim connection is its own process, like the
/// Botan/OpenSSL shims' fixed-key stateless session managers). Test-only: the "ticket" is the
/// session state verbatim -- this is NOT a secure production ticketer, but the harness is trusted
/// and it lets cross-process TLS resumption be exercised against rustls.
#[derive(Debug)]
struct TestTicketer;

impl rustls::server::ProducesTickets for TestTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        86_400
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        Some(plain.to_vec())
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        Some(cipher.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Certificate chains (see shims/DESIGN.md "Certificate chains").
//
// `credentials.chains` is what the shim serves as a server and
// `credentials.client_chains` what it presents as a client; absent lists fall
// back to the legacy cert_file / key_file (+ second_*) pair. Each entry names
// its key type (rsa_2048, rsa_pss, ecdsa_p256, ecdsa_p384, ecdsa_p521,
// ed25519); a missing name is inferred from the certificate's SPKI.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct ChainCfg {
    cert_file: String,
    key_file: String,
    key_type: String,
}

#[derive(Debug, Default)]
struct ChainLists {
    server: Vec<ChainCfg>,
    client: Vec<ChainCfg>,
    /// `requires.server_key`: the key types plzn's server may present.
    server_keys: Vec<String>,
}

static CHAINS: std::sync::OnceLock<ChainLists> = std::sync::OnceLock::new();

fn chains() -> &'static ChainLists {
    CHAINS.get_or_init(ChainLists::default)
}

/// The runner's spelling of a key type: `--cert` names and chain names both
/// map onto rsa_2048 / rsa_pss / ecdsa_p256 / ecdsa_p384 / ecdsa_p521 / ed25519.
fn normalize_key_type(name: &str) -> String {
    let n = name.replace('-', "_");
    match n.as_str() {
        "rsa" | "rsa2048" => "rsa_2048".into(),
        "ecdsa" | "p256" => "ecdsa_p256".into(),
        "p384" => "ecdsa_p384".into(),
        "p521" => "ecdsa_p521".into(),
        _ => n,
    }
}

impl ChainLists {
    fn from_json(text: &str) -> Self {
        let root: serde_json::Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return Self::default(),
        };
        let creds = &root["credentials"];
        let legacy = |first: &str, second: &str| -> Vec<ChainCfg> {
            let mut v = Vec::new();
            let cert = creds[first].as_str().unwrap_or("");
            if !cert.is_empty() {
                v.push(ChainCfg {
                    cert_file: cert.into(),
                    key_file: creds[second].as_str().unwrap_or("").into(),
                    key_type: String::new(),
                });
            }
            let cert2 = creds["second_cert_file"].as_str().unwrap_or("");
            if !cert2.is_empty() {
                v.push(ChainCfg {
                    cert_file: cert2.into(),
                    key_file: creds["second_key_file"].as_str().unwrap_or("").into(),
                    key_type: String::new(),
                });
            }
            v
        };
        let list = |key: &str| -> Option<Vec<ChainCfg>> {
            creds[key].as_array().map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        e.as_object().map(|o| ChainCfg {
                            cert_file: o
                                .get("cert_file")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .into(),
                            key_file: o
                                .get("key_file")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .into(),
                            key_type: normalize_key_type(
                                o.get("key_type").and_then(|v| v.as_str()).unwrap_or(""),
                            ),
                        })
                    })
                    .collect()
            })
        };
        let server = list("chains").unwrap_or_else(|| legacy("cert_file", "key_file"));
        let client = list("client_chains").unwrap_or_else(|| legacy("cert_file", "key_file"));
        let sk = &root["requires"]["server_key"];
        let server_keys = match sk {
            serde_json::Value::String(s) => vec![normalize_key_type(s)],
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str())
                .map(normalize_key_type)
                .collect(),
            _ => Vec::new(),
        };
        ChainLists {
            server,
            client,
            server_keys,
        }
    }
}

/// Infer a chain's key type from the leaf's SubjectPublicKeyInfo (the curve or
/// key OID bytes), when the config carries no name.
fn infer_key_type(leaf: &[u8]) -> String {
    const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    const P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
    const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let has = |pat: &[u8]| leaf.windows(pat.len()).any(|w| w == pat);
    if has(P256) {
        "ecdsa_p256".into()
    } else if has(P384) {
        "ecdsa_p384".into()
    } else if has(P521) {
        "ecdsa_p521".into()
    } else if has(ED25519) {
        "ed25519".into()
    } else if has(RSASSA_PSS) {
        "rsa_pss".into()
    } else if has(RSA) {
        "rsa_2048".into()
    } else {
        String::new()
    }
}

/// Can a key of this type sign the scheme? rustls's signing keys are
/// scheme-bound (a P-256 key signs ecdsa_secp256r1_sha256 only, in either
/// protocol version), so the pairing is exact.
fn scheme_fits(scheme: rustls::SignatureScheme, key_type: &str) -> bool {
    use rustls::SignatureScheme as S;
    match key_type {
        "rsa_2048" => matches!(
            scheme,
            S::RSA_PKCS1_SHA1
                | S::RSA_PKCS1_SHA256
                | S::RSA_PKCS1_SHA384
                | S::RSA_PKCS1_SHA512
                | S::RSA_PSS_SHA256
                | S::RSA_PSS_SHA384
                | S::RSA_PSS_SHA512
        ),
        "ecdsa_p256" => scheme == S::ECDSA_NISTP256_SHA256,
        "ecdsa_p384" => scheme == S::ECDSA_NISTP384_SHA384,
        "ecdsa_p521" => scheme == S::ECDSA_NISTP521_SHA512,
        "ed25519" => scheme == S::ED25519,
        _ => false,
    }
}

/// Every loadable chain in the runner's order; the first one the peer's
/// signature schemes accept is presented, else the first chain (see `pick`).
#[derive(Debug)]
struct ChainResolver {
    chains: Vec<(String, Arc<rustls::sign::CertifiedKey>)>,
    server_tls12: bool,
}

impl ChainResolver {
    fn load(
        provider: &Arc<rustls::crypto::CryptoProvider>,
        cfgs: &[ChainCfg],
        server_tls12: bool,
    ) -> Result<Self, Fail> {
        let mut chains = Vec::new();
        for c in cfgs {
            if unsupported_key_kind(&c.key_file).is_some() {
                continue; // an id-RSASSA-PSS key rustls cannot load: never selected
            }
            let certs = load_certs(&c.cert_file)
                .map_err(|e| Fail::new(LOCAL_ERROR, format!("load cert {}: {}", c.cert_file, e)))?;
            let key = load_key(&c.key_file)
                .map_err(|e| Fail::new(LOCAL_ERROR, format!("load key {}: {}", c.key_file, e)))?;
            let key_type = if c.key_type.is_empty() {
                infer_key_type(certs.first().map(|c| c.as_ref()).unwrap_or(&[]))
            } else {
                c.key_type.clone()
            };
            chains.push((key_type, make_certified_key(provider, certs, key)?));
        }
        Ok(ChainResolver {
            chains,
            server_tls12,
        })
    }

    /// The first chain the peer's schemes accept, else the FIRST chain: rustls
    /// then judges it exactly as it would a lone certificate (a server fails
    /// with its own handshake_failure, a client sends an empty Certificate),
    /// so a multi-chain no-match reads like the single-chain corpus.
    fn pick(&self, schemes: &[rustls::SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.chains
            .iter()
            .find(|(kt, _)| schemes.iter().any(|s| scheme_fits(*s, kt)))
            .or_else(|| self.chains.first())
            .map(|c| c.1.clone())
    }

    fn pick_server(
        &self,
        hello: &rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.chains
            .iter()
            .find(|(key_type, _)| {
                hello
                    .signature_schemes()
                    .iter()
                    .any(|scheme| scheme_fits(*scheme, key_type))
                    && (!self.server_tls12
                        || (hello
                            .cipher_suites()
                            .iter()
                            .any(|suite| tls12_suite_fits_key(*suite, key_type))
                            && tls12_certificate_group_fits(hello.named_groups(), key_type)))
            })
            // Preserve rustls's normal failure path when none of our policy
            // filters can choose a credential.  Returning None here makes the
            // resolver emit access_denied before cipher/sigalg negotiation and
            // changes every unrelated negative test that happens to use an
            // unmatchable ClientHello.
            .or_else(|| self.chains.first())
            .map(|(_, key)| key.clone())
    }
}

fn tls12_suite_fits_key(suite: rustls::CipherSuite, key_type: &str) -> bool {
    use rustls::CipherSuite as C;
    if key_type == "rsa_2048" {
        matches!(
            suite,
            C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        )
    } else if key_type.starts_with("ecdsa_") || key_type == "ed25519" {
        matches!(
            suite,
            C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        )
    } else {
        false
    }
}

fn tls12_certificate_group_fits(groups: Option<&[rustls::NamedGroup]>, key_type: &str) -> bool {
    let Some(groups) = groups else {
        return true;
    };
    let required = match key_type {
        "ecdsa_p256" => rustls::NamedGroup::secp256r1,
        "ecdsa_p384" => rustls::NamedGroup::secp384r1,
        "ecdsa_p521" => rustls::NamedGroup::secp521r1,
        _ => return true,
    };
    groups.contains(&required)
}

impl rustls::server::ResolvesServerCert for ChainResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.pick_server(&client_hello)
    }
}

impl rustls::client::ResolvesClientCert for ChainResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.pick(sigschemes)
    }
    fn has_certs(&self) -> bool {
        !self.chains.is_empty()
    }
}

/// Build a CertifiedKey from a loaded cert chain + private key DER.
fn make_certified_key(
    provider: &Arc<rustls::crypto::CryptoProvider>,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::sign::CertifiedKey>, Fail> {
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("load signing key: {}", e)))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        certs,
        signing_key,
    )))
}

fn run_server(
    cfg: &ShimConfig,
    sock: &mut TcpStream,
    provider: Arc<rustls::crypto::CryptoProvider>,
    vers: &[&'static rustls::SupportedProtocolVersion],
    connection_index: u32,
) -> Result<(), Fail> {
    // Every chain the shim may serve, in the runner's order; the resolver
    // below picks by the ClientHello's signature_algorithms.
    let resolver =
        ChainResolver::load(&provider, &chains().server, cfg.max_version == Some(0x0303))?;
    let (certs, key) = if let Some(first) = chains().server.first() {
        (
            load_certs(&first.cert_file).map_err(|e| {
                Fail::new(LOCAL_ERROR, format!("load cert {}: {}", first.cert_file, e))
            })?,
            Some(load_key(&first.key_file).map_err(|e| {
                Fail::new(LOCAL_ERROR, format!("load key {}: {}", first.key_file, e))
            })?),
        )
    } else {
        (Vec::new(), None)
    };

    let vbuilder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(vers)
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("server versions: {}", e)))?;
    // Require (or, T3, merely request) + verify a client certificate against
    // trust_file when configured: `request_client_cert` sends the
    // CertificateRequest but accepts an empty Certificate (RFC 5246 7.4.6 /
    // RFC 8446 4.4.2), which is rustls's `allow_unauthenticated` verifier.
    let wants_client_cert = cfg.verify.require_client_cert || cfg.verify.request_client_cert;
    let builder = if wants_client_cert && cfg.client_certificate_types.as_slice() == [2] {
        vbuilder.with_client_cert_verifier(Arc::new(RawClientVerifier {
            provider: provider.clone(),
            mandatory: cfg.verify.require_client_cert,
        }))
    } else if wants_client_cert && !cfg.credentials.trust_file.is_empty() {
        let mut roots = rustls::RootCertStore::empty();
        for cert in load_certs(&cfg.credentials.trust_file).map_err(|e| {
            Fail::new(
                LOCAL_ERROR,
                format!("load client trust {}: {}", cfg.credentials.trust_file, e),
            )
        })? {
            roots
                .add(cert)
                .map_err(|e| Fail::new(LOCAL_ERROR, format!("add client-CA anchor: {}", e)))?;
        }
        let vb = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        );
        let vb = if cfg.verify.require_client_cert {
            vb
        } else {
            vb.allow_unauthenticated()
        };
        let verifier = vb
            .build()
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("build client verifier: {}", e)))?;
        vbuilder.with_client_cert_verifier(verifier)
    } else {
        vbuilder.with_no_client_auth()
    };
    let mut sc = if cfg.server_certificate_types.as_slice() == [2] {
        // RFC 7250: present a bare SubjectPublicKeyInfo instead of an X.509 chain when the
        // peer negotiates server_certificate_type=RawPublicKey. The "certificate" entry must
        // be the raw SPKI extracted from the signing key -- NOT the loaded X.509 chain, which
        // rustls would otherwise ship verbatim as the RawPublicKey (a malformed leaf).
        let key =
            key.ok_or_else(|| Fail::new(LOCAL_ERROR, "raw_public_key needs a server chain"))?;
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("load signing key: {}", e)))?;
        let spki = signing_key
            .public_key()
            .ok_or_else(|| Fail::new(LOCAL_ERROR, "signing key exposes no SubjectPublicKeyInfo"))?;
        let rpk_entry = vec![CertificateDer::from(spki.as_ref().to_vec())];
        let ck = Arc::new(rustls::sign::CertifiedKey::new(rpk_entry, signing_key));
        builder.with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(ck),
        ))
    } else if !cfg.credentials.ocsp_file.is_empty() && chains().server.len() == 1 {
        // T6: `uut server { ocsp_stapling }`: staple the runner's OCSP response.
        let key =
            key.ok_or_else(|| Fail::new(LOCAL_ERROR, "ocsp_stapling needs a server chain"))?;
        let ocsp = std::fs::read(&cfg.credentials.ocsp_file).map_err(|e| {
            Fail::new(
                LOCAL_ERROR,
                format!("read ocsp {}: {}", cfg.credentials.ocsp_file, e),
            )
        })?;
        builder
            .with_single_cert_with_ocsp(certs, key, ocsp)
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("server cert: {}", e)))?
    } else {
        // Zero, one or several chains: the resolver answers the ClientHello
        // (none at all is a PSK-only server, or a handshake_failure).
        builder.with_cert_resolver(Arc::new(resolver))
    };
    apply_alpn(&mut sc.alpn_protocols, cfg);
    // T6: accept RFC 8879 compressed client certificates (and so advertise
    // compress_certificate in the CertificateRequest).
    sc.cert_decompressors = vec![&ZLIB_CERT_DECOMPRESSOR];
    // RFC 8879: register the zlib compressor so the server sends a CompressedCertificate
    // when the client advertises compress_certificate.
    if cfg.compress_certificate {
        sc.cert_compressors = vec![&ZLIB_CERT_COMPRESSOR];
    }
    // rustls intentionally accepts 0-RTT only with stateful resumption, so use
    // the process-wide session store when an early-data allowance is set.
    // Other resumption tests retain the deterministic stateless ticketer.
    if cfg.max_early_data.unwrap_or(0) == 0 {
        sc.ticketer = Arc::new(TestTicketer);
    }
    // `uut` policy knobs (see shims/DESIGN.md). ignore_client_order covers cipher
    // suites only: rustls has no server-preference switch for key-exchange groups.
    if let Some(v) = cfg.server_preference {
        sc.ignore_client_order = v;
    }
    // T5: one session cache for the whole process (the config is rebuilt per
    // connection), so a session id issued on an earlier connection of a
    // multi-session run can be resumed by id (RFC 5246 7.4.1.3).
    static SESSION_CACHE: std::sync::OnceLock<Arc<rustls::server::ServerSessionMemoryCache>> =
        std::sync::OnceLock::new();
    sc.session_storage = SESSION_CACHE
        .get_or_init(|| rustls::server::ServerSessionMemoryCache::new(256))
        .clone();
    sc.max_early_data_size = cfg.max_early_data.unwrap_or(0);
    if let Some(n) = cfg.session_tickets {
        sc.send_tls13_tickets = n as usize;
        if n == 0 {
            // No TLS 1.2 session cache either: no resumption at all.
            sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        }
    }
    if let Some(ems) = &cfg.extended_master_secret {
        sc.require_ems = ems == "require";
    }

    let server = rustls::ServerConnection::new(Arc::new(sc))
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("server conn: {}", e)))?;
    let mut conn: rustls::Connection = server.into();

    if let Err(f) = complete_handshake(&mut conn, sock) {
        flush_alert_and_drain(&mut conn, sock);
        return Err(f);
    }
    if connection_index > 0 && cfg.early_data_expect > 0 {
        let mut total = 0usize;
        let mut buf = [0u8; 16 * 1024];
        let accepted = match &mut conn {
            rustls::Connection::Server(server) => {
                if let Some(mut early) = server.early_data() {
                    loop {
                        let n = early
                            .read(&mut buf)
                            .map_err(|e| Fail::new(IO_ERROR, format!("read early data: {}", e)))?;
                        if n == 0 {
                            break;
                        }
                        total += n;
                    }
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        let expected_total = if cfg.expect_early_data_accepted == Some(false) {
            0
        } else {
            cfg.early_data_expect as usize
        };
        if total != expected_total {
            return Err(Fail::new(
                EXPECTATION_MISMATCH,
                format!(
                    "early data length mismatch: got {} expected {}",
                    total, expected_total
                ),
            ));
        }
        if let Some(expected) = cfg.expect_early_data_accepted {
            if accepted != expected {
                return Err(Fail::new(
                    EXPECTATION_MISMATCH,
                    format!(
                        "TLS 1.3 early data was {} unexpectedly",
                        if accepted { "accepted" } else { "rejected" }
                    ),
                ));
            }
        }
    }
    let sni = match &conn {
        rustls::Connection::Server(s) => s.server_name().map(|x| x.to_string()),
        _ => None,
    };
    check_expectations(
        cfg,
        conn.protocol_version(),
        conn.alpn_protocol(),
        sni.as_deref(),
    )?;
    send_key_material(&mut conn, sock, cfg, connection_index)?;
    let r = serve_app_data_until_closed(&mut conn, sock);
    if r.is_err() {
        flush_alert_and_drain(&mut conn, sock);
    }
    r
}

struct ClientIdentity {
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    cert_resolver: Arc<dyn rustls::client::ResolvesClientCert>,
}

#[derive(Debug)]
struct NoClientAuth;

impl rustls::client::ResolvesClientCert for NoClientAuth {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

/// Build the verifier and client-certificate resolver once per process.
/// rustls records their Arc identities in cached sessions and only permits a
/// later ClientConfig to use the session when both identities still match.
fn build_client_identity(
    cfg: &ShimConfig,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ClientIdentity, Fail> {
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if cfg.verify.peer && !cfg.credentials.trust_file.is_empty() {
            let mut roots = rustls::RootCertStore::empty();
            for cert in load_certs(&cfg.credentials.trust_file).map_err(|e| {
                Fail::new(
                    LOCAL_ERROR,
                    format!("load trust {}: {}", cfg.credentials.trust_file, e),
                )
            })? {
                roots
                    .add(cert)
                    .map_err(|e| Fail::new(LOCAL_ERROR, format!("add trust anchor: {}", e)))?;
            }
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("build verifier: {}", e)))?
        } else {
            Arc::new(NoVerify {
                provider: provider.clone(),
                // `uut client { verify_prefs }`: the schemes this client accepts from the
                // server, which rustls also puts in signature_algorithms.
                verify_schemes: cfg
                    .verify_prefs
                    .iter()
                    .map(|w| rustls::SignatureScheme::from(*w))
                    .collect(),
                require_raw_public_key: cfg.server_certificate_types.as_slice() == [2],
            })
        };

    let client_chains = chains().client.clone();
    let cert_resolver: Arc<dyn rustls::client::ResolvesClientCert> = if client_chains.is_empty() {
        Arc::new(NoClientAuth)
    } else if client_chains.len() > 1 && cfg.client_certificate_types.as_slice() != [2] {
        // Several credentials: the CertificateRequest's signature_algorithms
        // pick one; none acceptable -> rustls sends an empty Certificate.
        Arc::new(ChainResolver::load(&provider, &client_chains, false)?)
    } else if cfg.client_certificate_types.as_slice() == [2] {
        // RFC 7250: authenticate with a bare SubjectPublicKeyInfo (from the signing key),
        // NOT the X.509 chain -- and offer client_certificate_type=RawPublicKey.
        let key = load_key(&cfg.credentials.key_file).map_err(|e| {
            Fail::new(
                LOCAL_ERROR,
                format!("load client key {}: {}", cfg.credentials.key_file, e),
            )
        })?;
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("load client signing key: {}", e)))?;
        let spki = signing_key.public_key().ok_or_else(|| {
            Fail::new(
                LOCAL_ERROR,
                "client signing key exposes no SubjectPublicKeyInfo",
            )
        })?;
        let rpk_entry = vec![CertificateDer::from(spki.as_ref().to_vec())];
        let ck = Arc::new(rustls::sign::CertifiedKey::new(rpk_entry, signing_key));
        Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(ck))
    } else {
        let only = &client_chains[0];
        let certs = load_certs(&only.cert_file).map_err(|e| {
            Fail::new(
                LOCAL_ERROR,
                format!("load client cert {}: {}", only.cert_file, e),
            )
        })?;
        let key = load_key(&only.key_file).map_err(|e| {
            Fail::new(
                LOCAL_ERROR,
                format!("load client key {}: {}", only.key_file, e),
            )
        })?;
        let ck = make_certified_key(&provider, certs, key)?;
        Arc::new(rustls::sign::SingleCertAndKey::from(ck))
    };

    Ok(ClientIdentity {
        verifier,
        cert_resolver,
    })
}

/// Build a per-connection client config. Multi-session runs share the session
/// store and identity objects while selecting the requested protocol version.
fn build_client_config(
    cfg: &ShimConfig,
    provider: Arc<rustls::crypto::CryptoProvider>,
    vers: &[&'static rustls::SupportedProtocolVersion],
    session_store: Option<Arc<dyn rustls::client::ClientSessionStore>>,
    identity: &ClientIdentity,
) -> Result<rustls::ClientConfig, Fail> {
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(vers)
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("client versions: {}", e)))?
        .dangerous()
        .with_custom_certificate_verifier(identity.verifier.clone());
    let mut cc = builder.with_client_cert_resolver(identity.cert_resolver.clone());
    // `uut` policy knobs on the client side.
    if cfg.session_tickets == Some(0) {
        cc.resumption = rustls::client::Resumption::disabled();
    } else if let Some(store) = session_store {
        cc.resumption = rustls::client::Resumption::store(store);
    }
    cc.enable_early_data = cfg.early_data_send > 0;
    // RFC 8879: in the client role this knob means accepting (and advertising
    // support for) a compressed server Certificate. The server-side half is
    // configured separately in build_server_config.
    if cfg.compress_certificate {
        cc.cert_decompressors = vec![&ZLIB_CERT_DECOMPRESSOR];
    }
    if let Some(ems) = &cfg.extended_master_secret {
        cc.require_ems = ems == "require";
    }
    apply_alpn(&mut cc.alpn_protocols, cfg);
    Ok(cc)
}

fn run_client(
    cfg: &ShimConfig,
    sock: &mut TcpStream,
    config: Arc<rustls::ClientConfig>,
    connection_index: u32,
) -> Result<(), Fail> {
    let sni = if cfg.server_name.is_empty() {
        "localhost"
    } else {
        cfg.server_name.as_str()
    };
    let name = ServerName::try_from(sni.to_string())
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("server name: {}", e)))?;
    let mut client = rustls::ClientConnection::new(config, name)
        .map_err(|e| Fail::new(LOCAL_ERROR, format!("client conn: {}", e)))?;
    if connection_index > 0 && cfg.early_data_send > 0 {
        let mut early = client.early_data().ok_or_else(|| {
            Fail::new(
                EXPECTATION_MISMATCH,
                "resumed rustls client has no early-data writer",
            )
        })?;
        let data = vec![0x45; cfg.early_data_send as usize];
        early
            .write_all(&data)
            .map_err(|e| Fail::new(IO_ERROR, format!("write early data: {}", e)))?;
    }
    let mut conn: rustls::Connection = client.into();

    if let Err(f) = complete_handshake(&mut conn, sock) {
        flush_alert_and_drain(&mut conn, sock);
        return Err(f);
    }
    if connection_index > 0 {
        if let Some(expected) = cfg.expect_early_data_accepted {
            let accepted = match &conn {
                rustls::Connection::Client(client) => client.is_early_data_accepted(),
                _ => false,
            };
            if accepted != expected {
                return Err(Fail::new(
                    EXPECTATION_MISMATCH,
                    format!(
                        "TLS 1.3 early data was {} unexpectedly",
                        if accepted { "accepted" } else { "rejected" }
                    ),
                ));
            }
        }
    }
    check_expectations(cfg, conn.protocol_version(), conn.alpn_protocol(), None)?;
    send_key_material(&mut conn, sock, cfg, connection_index)?;
    let r = serve_app_data_until_closed(&mut conn, sock);
    if r.is_err() {
        flush_alert_and_drain(&mut conn, sock);
    }
    r
}

fn send_key_material(
    conn: &mut rustls::Connection,
    sock: &mut TcpStream,
    cfg: &ShimConfig,
    connection_index: u32,
) -> Result<(), Fail> {
    for request in cfg
        .key_material
        .iter()
        .filter(|request| request.connection == connection_index)
    {
        if request.kind != "exporter" {
            return Err(Fail::new(
                LOCAL_ERROR,
                format!("unknown key_material kind {}", request.kind),
            ));
        }
        let output = conn
            .export_keying_material(
                vec![0u8; request.length as usize],
                request.label.as_bytes(),
                request.context.as_deref().map(str::as_bytes),
            )
            .map_err(|e| Fail::new(LOCAL_ERROR, format!("export keying material: {e}")))?;
        conn.writer()
            .write_all(&output)
            .map_err(|e| Fail::new(IO_ERROR, format!("queue key material: {e}")))?;
        while conn.wants_write() {
            conn.complete_io(sock)
                .map_err(|e| Fail::new(IO_ERROR, format!("write key material: {e}")))?;
        }
    }
    Ok(())
}

/// After a rustls error the fatal alert is queued in `conn` but not yet on the
/// wire (`complete_io` returns the error before its write phase). Write it,
/// then half-close and drain whatever the peer still has in flight so the
/// kernel closes with a FIN: closing a socket with unread data sends an RST,
/// which can discard the alert before plzn has read it. That race is what
/// made rustls look like it "tears the connection down" instead of alerting.
fn flush_alert_and_drain(conn: &mut rustls::Connection, sock: &mut TcpStream) {
    while conn.wants_write() {
        if conn.write_tls(sock).is_err() {
            break;
        }
    }
    let _ = sock.shutdown(std::net::Shutdown::Write);
    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(300)));
    let mut sink = [0u8; 4096];
    loop {
        match sock.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

fn apply_alpn(target: &mut Vec<Vec<u8>>, cfg: &ShimConfig) {
    if !cfg.alpn.advertise.is_empty() {
        *target = cfg
            .alpn
            .advertise
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    } else if !cfg.alpn.select.is_empty() {
        *target = vec![cfg.alpn.select.as_bytes().to_vec()];
    } else if !cfg.alpn.select_from.is_empty() {
        *target = cfg
            .alpn
            .select_from
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    }
}

fn complete_handshake(conn: &mut rustls::Connection, sock: &mut TcpStream) -> Result<(), Fail> {
    while conn.is_handshaking() {
        let (rd, wr) = conn
            .complete_io(sock)
            .map_err(|e| Fail::new(HANDSHAKE_FAILED, format!("handshake: {}", e)))?;
        if rd == 0 && wr == 0 && conn.is_handshaking() {
            return Err(Fail::new(
                HANDSHAKE_FAILED,
                "handshake stalled (peer closed)",
            ));
        }
    }
    Ok(())
}

/// Answer framed application-data requests until the peer closes (close_notify,
/// or a bare EOF),
/// then send close_notify ourselves. Mirrors the Botan and OpenSSL shims, which
/// keep reading until the peer is done: a flow that renegotiates (or tries to)
/// AFTER its app-data round trip must reach the library, not a shim that hung up
/// right after the first response. rustls's answer to a TLS 1.2 renegotiation attempt
/// -- a fatal unexpected_message from a server, a no_renegotiation warning from a
/// client -- is then what plzn observes.
fn serve_app_data_until_closed(
    conn: &mut rustls::Connection,
    sock: &mut TcpStream,
) -> Result<(), Fail> {
    let mut buf = [0u8; 8192];
    let mut responder = Responder::default();
    loop {
        // Pull records until we have plaintext or the peer is done.
        match conn.reader().read(&mut buf) {
            Ok(0) => break, // close_notify received
            Ok(n) => {
                for reply in responder.receive(&buf[..n]) {
                    conn.writer().write_all(&reply).map_err(|e| {
                        Fail::new(IO_ERROR, format!("application-data response: {}", e))
                    })?;
                }
                conn.complete_io(sock)
                    .map_err(|e| Fail::new(IO_ERROR, format!("flush: {}", e)))?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let (rd, _) = conn.complete_io(sock).map_err(classify_io)?;
                if rd == 0 {
                    break; // peer closed the socket
                }
            }
            // The peer closed the TCP stream without close_notify. The other
            // shims treat a bare EOF after the handshake as the end of the
            // test, not as a failure; do the same.
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(classify_io(e)),
        }
    }
    conn.send_close_notify();
    let _ = conn.complete_io(sock);
    Ok(())
}

fn classify_io(e: std::io::Error) -> Fail {
    Fail::new(IO_ERROR, format!("io: {}", e))
}

fn check_expectations(
    cfg: &ShimConfig,
    version: Option<rustls::ProtocolVersion>,
    alpn: Option<&[u8]>,
    server_name: Option<&str>,
) -> Result<(), Fail> {
    if let Some(want) = cfg.expect.version {
        let got = version.map(u16::from).unwrap_or(0);
        if got != want {
            return Err(Fail::new(
                EXPECTATION_MISMATCH,
                format!("version mismatch: got {:#06x} expected {:#06x}", got, want),
            ));
        }
    }
    if let Some(want) = &cfg.alpn.expect {
        let got = alpn
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .unwrap_or_default();
        if &got != want {
            return Err(Fail::new(
                EXPECTATION_MISMATCH,
                format!("alpn mismatch: got '{}' expected '{}'", got, want),
            ));
        }
    }
    if let Some(want) = &cfg.expect_server_name {
        let got = server_name.unwrap_or("");
        if got != want {
            return Err(Fail::new(
                EXPECTATION_MISMATCH,
                format!("sni mismatch: got '{}' expected '{}'", got, want),
            ));
        }
    }
    Ok(())
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let mut r = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut r).collect()
}

/// The `--cert` name of a PKCS#8 key ring cannot use (its AlgorithmIdentifier
/// says id-RSASSA-PSS or names secp521r1), or None.
fn unsupported_key_kind(path: &str) -> Option<&'static str> {
    let key = load_key(path).ok()?;
    let der = match &key {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        _ => return None,
    };
    let head = &der[..der.len().min(48)];
    const ID_RSASSA_PSS: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    const SECP521R1: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x23];
    // aws-lc-rs loads and signs with P-521 keys (ring did not); an
    // id-RSASSA-PSS PKCS#8 key has no rustls signer.
    let _ = SECP521R1;
    if head
        .windows(ID_RSASSA_PSS.len())
        .any(|w| w == ID_RSASSA_PSS)
    {
        Some("rsa-pss")
    } else {
        None
    }
}

fn load_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let mut r = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut r)?
        .ok_or_else(|| std::io::Error::other("no private key in file"))
}

/// Accept-any server certificate verifier for the test harness (path validation
/// is exercised via the dedicated cert-chain tests, not here).
#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Empty = everything the provider verifies.
    verify_schemes: Vec<rustls::SignatureScheme>,
    require_raw_public_key: bool,
}

impl NoVerify {
    /// With `uut client { verify_prefs }` the server must sign with a scheme this
    /// client advertised (RFC 5246 7.4.3 / RFC 8446 4.4.3); rustls's own
    /// verifier path only checks the provider's full list.
    fn check_advertised(&self, scheme: rustls::SignatureScheme) -> Result<(), rustls::Error> {
        if !self.verify_schemes.is_empty() && !self.verify_schemes.contains(&scheme) {
            return Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        Ok(())
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.check_advertised(dss.scheme)?;
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.check_advertised(dss.scheme)?;
        if self.require_raw_public_key {
            rustls::crypto::verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.provider.signature_verification_algorithms,
            )
        } else {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        if !self.verify_schemes.is_empty() {
            return self.verify_schemes.clone();
        }
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.require_raw_public_key
    }
}

#[derive(Debug)]
struct RawClientVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    mandatory: bool,
}

impl rustls::server::danger::ClientCertVerifier for RawClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "raw public keys are unsupported in TLS 1.2".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}
