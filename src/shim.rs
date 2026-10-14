// Interop-shim backend: drive a real TLS library as the
// unit-under-test via a config-file shim executable.
//
// Unlike `plzn dial --addr`, a shim DIALS
// the runner. So here plzn LISTENS: it binds a loopback port, spawns the shim
// with a JSON config pointing back at that port, accepts the shim's connection,
// strips the 8-byte ShimID prefix, and hands the stream to the runtime through
// the ordinary `UutFactory` seam. The shim plays the TLS role opposite plzn's
// subject (plzn tests a server -> shim is a server, etc.).
//
// The config struct serializes to exactly the JSON keys the shared C++ helper
// lib (shims/common/plzn_shim.h) parses; the two must stay in sync.

use std::io::Write;
use std::io::{self, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::transport::{TcpTransport, UutFactory, UutTransport};

// ------------------------------------------------------------------
// Global cap on concurrently-live shim processes.
//
// The full `cargo test` spawns hundreds of shim processes; at high
// concurrency that resource contention caused rare load-induced test
// flakes (see notes/audit/coverage_matrix.md "Test-suite reliability").
// This gate bounds how many shims are live at once, per process, with a
// leak-proof RAII permit released when the accepted transport is dropped.
// ------------------------------------------------------------------

struct ShimGate {
    available: Mutex<usize>,
    cv: Condvar,
}

static SHIM_GATE: OnceLock<ShimGate> = OnceLock::new();

/// Size the live-shim gate before any shim is spawned (the parallel runner
/// wants at least one slot per worker). `PLZN_SHIM_LIMIT` still wins, and a
/// gate already in use keeps its size.
pub fn configure_shim_limit(n: usize) {
    if std::env::var("PLZN_SHIM_LIMIT").is_ok() {
        return;
    }
    let _ = SHIM_GATE.set(ShimGate {
        available: Mutex::new(n.max(1)),
        cv: Condvar::new(),
    });
}

fn shim_gate() -> &'static ShimGate {
    SHIM_GATE.get_or_init(|| {
        // Bound concurrent shims well below a many-core machine's default
        // test-threads (which is where the contention showed up). Overridable
        // via PLZN_SHIM_LIMIT for tuning.
        let n = std::env::var("PLZN_SHIM_LIMIT")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(8)
            .max(1);
        ShimGate {
            available: Mutex::new(n),
            cv: Condvar::new(),
        }
    })
}

/// RAII permit; releasing (on drop) hands one slot back and wakes a waiter.
struct ShimPermit;

impl Drop for ShimPermit {
    fn drop(&mut self) {
        let gate = shim_gate();
        *gate.available.lock().unwrap() += 1;
        gate.cv.notify_one();
    }
}

fn acquire_shim_permit() -> ShimPermit {
    let gate = shim_gate();
    let mut avail = gate.available.lock().unwrap();
    while *avail == 0 {
        avail = gate.cv.wait(avail).unwrap();
    }
    *avail -= 1;
    ShimPermit
}

/// Wraps an accepted shim transport so its concurrency permit is held for the
/// lifetime of the connection and released (RAII) when the transport is dropped.
struct LimitedTransport {
    inner: Box<dyn UutTransport>,
    _permit: ShimPermit,
}

impl Read for LimitedTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for LimitedTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl UutTransport for LimitedTransport {
    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }
    fn close_reset(&mut self) -> io::Result<()> {
        self.inner.close_reset()
    }
    fn description(&self) -> String {
        self.inner.description()
    }
    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }
    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }
}

// ------------------------------------------------------------------
// Config (serializes to shims/common/plzn_shim.h JSON)
// ------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct RunnerEndpoint {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "is_false")]
    pub ipv6: bool,
}

/// A: one certificate chain for a shim -- PEM files and the key type
/// (`rsa-2048`, `rsa-pss`, `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`,
/// `ed25519`, the `KeyType::name` spellings).
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct ShimChain {
    pub cert_file: String,
    pub key_file: String,
    pub key_type: String,
}

impl From<&crate::ir::ChainFiles> for ShimChain {
    fn from(c: &crate::ir::ChainFiles) -> Self {
        ShimChain {
            cert_file: c.cert_file.clone(),
            key_file: c.key_file.clone(),
            key_type: c.key_type.name().to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Credentials {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cert_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub trust_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ocsp_file: String,
    /// Optional second certificate/key of a DIFFERENT key type (e.g. ECDSA alongside an RSA
    /// cert_file). A server holding both selects by the client's signature_algorithms -- the
    /// multi-cert selection tests. Empty = single cert.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub second_cert_file: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub second_key_file: String,
    // A: every chain a shim SERVER holds (`chain:`), in preference order;
    // `cert_file` / `key_file` are the first one for the single-chain paths and
    // `second_*` the second. An empty list with an empty `cert_file` = no
    // chain at all (`chain: []`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chains: Vec<ShimChain>,
    // A: the client-authentication credentials a shim CLIENT picks from
    // (`client_chain:`), in preference order; `cert_file` / `key_file` are the
    // first one. It should present the one the server's CertificateRequest
    // can take, and an empty Certificate when none fits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub client_chains: Vec<ShimChain>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct VerifyConfig {
    #[serde(skip_serializing_if = "is_false")]
    pub peer: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub require_client_cert: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub request_client_cert: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub fail: bool,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct AlpnConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advertise: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub select: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub select_from: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub decline: bool,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct PskField {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub identity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret_hex: String,
}

impl PskField {
    fn is_empty(&self) -> bool {
        self.secret_hex.is_empty()
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct AppDataConfig {
    /// "echo" | "shim_writes" | "shutdown_only"
    pub mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub send: String,
}

/// A value the shim must derive from its live TLS connection and send as
/// application data. `connection` indexes the initial connection as zero and
/// each resumption after it, so a multi-session test can make different checks.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct KeyMaterialConfig {
    pub connection: u32,
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub length: u32,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Expectations {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resumed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hrr: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_error: Option<String>,
    /// plzn will abandon the handshake on purpose (an anchored flow that
    /// closes after the server's flight, a ROBOT timing probe that stops after
    /// ClientKeyExchange). The shim must accept whatever its library makes of
    /// the abrupt close -- success or a handshake failure -- rather than
    /// self-check against either; only a crash or a local error counts.
    #[serde(skip_serializing_if = "is_false")]
    pub handshake_abandoned: bool,
}

/// What plzn will offer in this program, so a shim can refuse up front when
/// its library supports none of it (BoGo's UNSUPPORTED), and `plzn run` SKIPs
/// the case instead of failing it. Any-of semantics: one common suite (and
/// one common group) is enough to run. An empty list is no constraint.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct Requires {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub any_suite: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub any_group: Vec<u16>,
    /// The flow advances the peer's DTLS retransmit clock (`advance_clock`), so
    /// the shim's library must run its timer on the virtual clock.
    #[serde(skip_serializing_if = "is_false")]
    pub virtual_clock: bool,
    /// The flow changes the timeout of an already-live DTLS channel. Botan has
    /// no public API for this and refuses such cases up front.
    #[serde(skip_serializing_if = "is_false")]
    pub dynamic_timeout: bool,
    /// Stateful TLS 1.2 session-ID resumption, distinct from session tickets.
    #[serde(skip_serializing_if = "is_false")]
    pub session_id_resumption: bool,
    // T3: the key types of the certificates plzn's SERVER may present (from
    // `chain:`), so
    // a shim CLIENT whose library cannot verify that key (rustls's ring
    // provider: P-521, RSA-PSS keys) refuses the case instead of failing it.
    // Every key type plzn's SERVER may present (`chain:`), serialized as a
    // list; the shims read a string or an array here and refuse only when
    // their library can verify none of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub server_key: Vec<String>,
}

impl Requires {
    pub fn is_empty(&self) -> bool {
        self.any_suite.is_empty()
            && self.any_group.is_empty()
            && !self.virtual_clock
            && !self.dynamic_timeout
            && !self.session_id_resumption
            && self.server_key.is_empty()
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ConnectionEarlyData {
    pub send: u32,
    pub expect: u32,
    pub accepted: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ShimConfig {
    /// Owns embedded PEM files materialized by `for_program`. Clones keep them
    /// alive for every session; they are removed when the last owner drops.
    /// Not part of the external shim's JSON protocol.
    #[serde(skip)]
    pub fixture_dir: Option<std::sync::Arc<tempfile::TempDir>>,
    pub role: String,     // "client" | "server"
    pub protocol: String, // "tls" | "dtls"
    pub runner: RunnerEndpoint,
    #[serde(skip_serializing_if = "is_zero_u64")]
    pub shim_id: u64,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub resume_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_version: Option<u16>,
    /// Exact wire version plzn drives on each connection of a multi-session
    /// run. Shim clients pin themselves to the matching entry while retaining
    /// their process-wide session cache; shim servers may leave the full range
    /// enabled because plzn's ClientHello selects the connection version.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connection_versions: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub connection_early_data: Vec<ConnectionEarlyData>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cipher_suites: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub curves: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signing_prefs: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub verify_prefs: Vec<u16>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    /// Server-side SNI expectation: if set, the shim (as server) checks that the
    /// client sent exactly this SNI and fails otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_server_name: Option<String>,
    #[serde(skip_serializing_if = "PskField::is_empty")]
    pub psk: PskField,
    #[serde(skip_serializing_if = "Credentials::is_empty")]
    pub credentials: Credentials,
    #[serde(skip_serializing_if = "VerifyConfig::is_default")]
    pub verify: VerifyConfig,
    #[serde(skip_serializing_if = "AlpnConfig::is_default")]
    pub alpn: AlpnConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub srtp_profiles: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_srtp_profile: Option<u16>,
    pub app_data: AppDataConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_material: Vec<KeyMaterialConfig>,
    #[serde(skip_serializing_if = "Expectations::is_default")]
    pub expect: Expectations,
    /// RFC 7250: server presents a raw public key when the peer negotiates
    /// server_certificate_type=RawPublicKey.
    #[serde(skip_serializing_if = "is_false")]
    pub raw_public_key: bool,
    /// RFC 7250 local preference lists. The names follow the wire extensions:
    /// server type is what the server presents; client type is what the client presents.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub server_certificate_types: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub client_certificate_types: Vec<u8>,
    /// RFC 8879: server compresses its Certificate (zlib) when the peer advertises
    /// compress_certificate.
    #[serde(skip_serializing_if = "is_false")]
    pub compress_certificate: bool,
    /// Accept peer-initiated renegotiation (RFC 5746). Set when a test drives a
    /// renegotiation, so the shim's policy allows it (the library default denies
    /// both client- and server-initiated renegotiation).
    #[serde(skip_serializing_if = "is_false")]
    pub renegotiate_freely: bool,
    /// See [`Requires`]: the suites / groups plzn will offer.
    #[serde(skip_serializing_if = "Requires::is_empty")]
    pub requires: Requires,
    /// Local-policy knobs from the `.plzn` `uut client|server { ... }` block (shims/DESIGN.md,
    /// "Policy controls"). None = the library's capability posture. A shim that
    /// cannot honour a set knob exits `unsupported_config` and the case SKIPs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_preference: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renegotiation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_tickets: Option<u32>,
    /// TLS 1.3 0-RTT policy and per-resumed-connection I/O. The send/expect
    /// sizes are populated from explicit EarlyData flow steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<u32>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub early_data_send: u32,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub early_data_expect: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_early_data_accepted: Option<bool>,
    /// Maximum encoded certificate chain accepted from the peer, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cert_list: Option<u32>,
    /// RFC 8449 receive limit the UUT advertises to its peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_size_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Automatic TLS 1.3 KeyUpdate after this many sent records (Botan policy; 0 = never).
    pub records_per_traffic_key: Option<u32>,
    /// Initiate one post-handshake KeyUpdate before entering the application loop.
    #[serde(skip_serializing_if = "is_false")]
    pub key_update: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_master_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt_then_mac: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middlebox_compat: Option<bool>,
    /// Botan `minimum_key_update_interval_ms`: a peer KeyUpdate arriving sooner
    /// than this after the previous one is rejected. 0 = no rate limit, which
    /// is also what the other libraries do (they accept 0 and refuse the rest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_key_update_interval_ms: Option<u32>,
    /// Client role: start one renegotiation once application data has flowed
    /// (`uut client { renegotiate_after_handshake: true }`).
    #[serde(skip_serializing_if = "is_false")]
    pub renegotiate_after_handshake: bool,
    /// T5, server role: send a HelloRequest once application data has flowed
    /// (`uut server { hello_request_after_app_data: true }`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub hello_request_after_app_data: bool,
    /// T5, server role: the renegotiation after that HelloRequest requires a
    /// client certificate (`uut server { require_client_cert_on_renegotiation: true }`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_client_cert_on_renegotiation: bool,
    /// Server role: half-RTT application records (one per entry), written
    /// after the shim's own Finished and before the client's.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub half_rtt_data: Vec<String>,
    /// T6: server role: request post-handshake client authentication (RFC
    /// 8446 4.6.2) right after the handshake (`uut server { post_handshake_auth }`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_handshake_auth: Option<String>,
    /// DTLS knobs (`uut client|server { mtu, initial_timeout_ms }`), the shim's `dtls` object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtls: Option<DtlsField>,
    /// Only consumed by the mock shim (ShimKind::Mock): the controlled action to
    /// take after reading the peer's first record.
    #[serde(skip_serializing_if = "MockField::is_default")]
    pub mock: MockField,
}

/// Controllable behavior for the mock shim. `action` is one of:
/// `"alert"` (send a fatal/warning alert record with `alert_level`/`alert_code`,
/// then close), `"close"` (clean TCP FIN, no alert), `"crash"` (connect, then
/// abort -- die by SIGABRT), `"crash_early"` (abort before connecting), or
/// `"exit_early"` (report local_error and exit before connecting). Deterministic
/// failure modes a real library will not reliably produce on demand, used to
/// exercise the runner's expectation matcher and its crash reporting.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct MockField {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub action: String,
    #[serde(skip_serializing_if = "is_zero_u8")]
    pub alert_level: u8,
    #[serde(skip_serializing_if = "is_zero_u8")]
    pub alert_code: u8,
}

/// The shim's `dtls` config object: datagram MTU and the initial retransmit
/// timeout (both roles).
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub struct DtlsField {
    pub mtu: u32,
    pub initial_timeout_ms: u32,
    /// Botan `dtls_maximum_retransmissions` (None = the library default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retransmissions: Option<u32>,
    /// Botan `dtls_maximum_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_timeout_ms: Option<u32>,
    /// Botan `dtls_server_require_cookie_exchange` / OpenSSL SSL_OP_COOKIE_EXCHANGE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cookie: Option<bool>,
    /// Botan `allow_dtls_epoch0_restart`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch0_restart: Option<bool>,
    /// Botan `dtls_maximum_hello_verify_requests`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hello_verify_requests: Option<u32>,
}

impl MockField {
    pub fn is_default(&self) -> bool {
        self.action.is_empty()
    }
}

impl ShimConfig {
    fn fixture_path(&mut self, name: &str) -> io::Result<String> {
        if self.fixture_dir.is_none() {
            self.fixture_dir = Some(std::sync::Arc::new(
                tempfile::Builder::new()
                    .prefix("plzn-fixtures-")
                    .tempdir()?,
            ));
        }
        let dir = self
            .fixture_dir
            .as_ref()
            .expect("initialized fixture directory");
        crate::fixtures::write(dir.path(), name).map(|path| path.to_string_lossy().into_owned())
    }

    pub fn for_connection(&self, index: usize) -> Self {
        let mut selected = self.clone();
        if self.role == "client" {
            if let Some(version) = self.connection_versions.get(index) {
                selected.min_version = Some(*version);
                selected.max_version = Some(*version);
            }
        }
        if let Some(early) = self.connection_early_data.get(index) {
            selected.early_data_send = early.send;
            selected.early_data_expect = early.expect;
            selected.expect_early_data_accepted = early.accepted;
        }
        selected
    }
    /// Derive a shim config from a lowered program. The shim plays the TLS role
    /// OPPOSITE the program's subject (plzn testing a server -> shim is a
    /// server, and vice versa). Every version in `uut.versions` is enabled in
    /// the shim; the first is the protocol version plzn drives. For a
    /// shim-as-server, `server_cert`/`server_key` PEM paths must be supplied so
    /// the shim has something to present. Built-in client credentials and
    /// trust roots are written into an owned temporary directory. An I/O
    /// failure is a setup error, never an absent credential or trust anchor.
    pub fn for_program(
        program: &crate::ir::Program,
        server_cert: Option<&str>,
        server_key: Option<&str>,
        backend: Option<&str>,
    ) -> io::Result<Self> {
        use crate::ir::Subject;
        use crate::tls::record::TlsVersion;
        // The expectation the RUNNER will apply on this backend: a per-backend
        // `expect ... if <backend>` override wins over the base expectation, and
        // the shim's self-check must follow the same choice or a legitimate
        // per-library outcome (`expect ok if openssl` on a test the others
        // reject) fails the shim side. Same matching rule as the runtime's
        // (case-insensitive substring of the peer description / backend label).
        let effective_expect = backend
            .and_then(|b| {
                let b = b.to_lowercase();
                program
                    .expect_overrides
                    .iter()
                    .find(|(uut, _)| b.contains(&uut.to_lowercase()))
                    .map(|(_, e)| e)
            })
            .unwrap_or(&program.expect);

        let version: u16 = match program.version {
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 if program.protocol == crate::ir::Protocol::Dtls => 0xfefc,
            TlsVersion::Tls13 => 0x0304,
        };
        // shim role is opposite of the subject-under-test
        let shim_is_server = program.subject == Subject::Server;
        // DTLS negotiates a DTLS wire version (0xFEFD), not the TLS version.
        // Pass that bound to the shims as well: relying on each library's
        // default let OpenSSL accept a DTLS 1.0 ClientHello in a `dtls12` test.
        let is_dtls = program.protocol == crate::ir::Protocol::Dtls;
        let mut enabled_versions: Vec<u16> = program
            .uut
            .as_ref()
            .map(|u| {
                u.versions
                    .iter()
                    .copied()
                    .filter(|v| matches!(v, 0x0301 | 0x0302 | 0x0303 | 0x0304 | 0xfefd | 0xfefc))
                    .collect()
            })
            .unwrap_or_default();
        if enabled_versions.is_empty() {
            enabled_versions.push(if is_dtls {
                match program.version {
                    TlsVersion::Tls12 => 0xfefd,
                    TlsVersion::Tls13 => 0xfefc,
                    _ => unreachable!("DTLS has no TLS 1.0/1.1 IR version"),
                }
            } else {
                version
            });
        }
        // DTLS version numbers run backwards: newer versions are numerically
        // smaller. There is currently only DTLS 1.2 syntax, but keep the bound
        // calculation correct for a future multi-version list.
        let min_version = if is_dtls {
            enabled_versions.iter().copied().max()
        } else {
            enabled_versions.iter().copied().min()
        };
        let max_version = if is_dtls {
            enabled_versions.iter().copied().min()
        } else {
            enabled_versions.iter().copied().max()
        };

        let mut cfg = ShimConfig {
            role: if shim_is_server { "server" } else { "client" }.into(),
            protocol: if is_dtls { "dtls" } else { "tls" }.into(),
            min_version,
            max_version,
            server_name: program.server_name.clone(),
            expect_server_name: None,
            expect: Expectations {
                version: if is_dtls { None } else { Some(version) },
                ..Default::default()
            },
            ..Default::default()
        };
        if shim_is_server {
            // A shim server told to require / request a client certificate --
            // by `uut server { require_client_cert / request_client_cert }` -- verifies plzn's client
            // credential against its issuing CA. Every plzn client (TLS 1.2,
            // TLS 1.3, DTLS) presents the same CA-issued end-entity certificate,
            // shims/testdata/client_ee_cert (see `test_client_credential_der`),
            // so the trust root is always client_ee_ca.pem; a self-signed
            // credential as its own anchor is refused by webpki (rustls).
            let cfg_requires = program_expects_certificate_request(program);
            let wants_client_cert = cfg_requires
                || program.uut.as_ref().is_some_and(|u| {
                    u.require_client_cert
                        || u.request_client_cert
                        || u.require_client_cert_on_renegotiation
                });
            let trust_file = if wants_client_cert {
                cfg.fixture_path("client_ee_ca.pem")?
            } else {
                String::new()
            };
            // A: the chains `chain:` resolved to (the runner wrote the PEMs); a
            // program lowered outside the runner falls back to the caller's pair,
            // and an explicit `chain: []` leaves the shim without a chain.
            let (cert_file, key_file, chains): (String, String, Vec<ShimChain>) =
                if let Some(first) = program.shim_server_chains.first() {
                    (
                        first.cert_file.clone(),
                        first.key_file.clone(),
                        program
                            .shim_server_chains
                            .iter()
                            .map(ShimChain::from)
                            .collect(),
                    )
                } else if program.chain_names.is_empty() {
                    (String::new(), String::new(), Vec::new())
                } else {
                    (
                        server_cert.unwrap_or_default().into(),
                        server_key.unwrap_or_default().into(),
                        Vec::new(),
                    )
                };
            let (second_cert_file, second_key_file) = chains
                .get(1)
                .map(|c| (c.cert_file.clone(), c.key_file.clone()))
                .unwrap_or_default();
            cfg.credentials = Credentials {
                cert_file,
                key_file,
                trust_file,
                second_cert_file,
                second_key_file,
                chains,
                ..Default::default()
            };
            // A post-handshake CertificateRequest (`uut server { post_handshake_auth }`)
            // is the knob's own doing: the flow's `recv CertificateRequest`
            // after Finished must not make the shim request one DURING the
            // handshake as well.
            let pha = program
                .uut
                .as_ref()
                .is_some_and(|u| u.post_handshake_auth.is_some());
            if cfg_requires && !pha {
                // The client-authentication preset shapes the flow (a
                // CertificateRequest is read and answered); whether the shim
                // REQUIRES or merely REQUESTS the certificate is the UUT's
                // policy: an explicit `uut server { request_client_cert: true }`
                // without `require_client_cert` keeps it a request, so an
                // empty Certificate is accepted (RFC 5246 7.4.6).
                let request_only = program
                    .uut
                    .as_ref()
                    .is_some_and(|u| u.request_client_cert && !u.require_client_cert);
                if request_only {
                    cfg.verify.request_client_cert = true;
                } else {
                    cfg.verify.require_client_cert = true;
                }
            }
        } else {
            // plzn's server will send a CertificateRequest: give the shim client
            // a credential to answer with. `uut client { client_cert }` picks which one
            // (plzn's servers verify the chain against `client_trust_anchors`):
            // `valid` (default) is the self-signed test credential plzn trusts,
            // `untrusted` a self-signed one it does not, `expired` a trusted but
            // expired one, and `none` leaves the shim without a certificate, so
            // it answers with an empty Certificate.
            let choice = program.uut.as_ref().and_then(|u| u.client_cert.as_deref());
            if let Some(choice) = choice {
                if let Some((cert, key)) = shim_client_credential_names(choice) {
                    cfg.credentials = Credentials {
                        cert_file: cfg.fixture_path(cert)?,
                        key_file: cfg.fixture_path(key)?,
                        ..Default::default()
                    };
                }
            } else if program_requests_client_auth(program) {
                // A: `client_chain:` -- the CA-issued client_ee credentials by
                // key type (the runner resolved the names); `[]` leaves the shim
                // without one, so it answers with an empty Certificate. A program
                // lowered outside the runner gets the P-256 default.
                let chains: Vec<ShimChain> = if !program.shim_client_chains.is_empty() {
                    program
                        .shim_client_chains
                        .iter()
                        .map(ShimChain::from)
                        .collect()
                } else if program.client_chain_names.is_empty() {
                    Vec::new()
                } else {
                    vec![ShimChain {
                        cert_file: cfg.fixture_path("client_ee_cert.pem")?,
                        key_file: cfg.fixture_path("client_ee_key.pem")?,
                        key_type: crate::server::certs::KeyType::EcdsaP256.name().to_string(),
                    }]
                };
                if let Some(first) = chains.first() {
                    cfg.credentials = Credentials {
                        cert_file: first.cert_file.clone(),
                        key_file: first.key_file.clone(),
                        client_chains: chains.clone(),
                        ..Default::default()
                    };
                }
            }
        }
        // RFC 8879 support is UUT policy. The peer's `compress_cert`
        // capability only controls what plzn offers or sends; it must not
        // silently enable a feature in the shim.
        cfg.compress_certificate = program
            .uut
            .as_ref()
            .is_some_and(|uut| uut.compress_certificate);

        // External PSK: mirror the program's PSK so the shim can complete the
        // PSK handshake plzn is driving.
        if let Some(psk) = &program.psk {
            if psk.is_external {
                cfg.psk = PskField {
                    identity: String::from_utf8_lossy(&psk.identity).into_owned(),
                    secret_hex: psk.secret.iter().map(|b| format!("{:02x}", b)).collect(),
                };
            }
        }
        // `uut client|server { psk_secret / psk_identity }`: the shim's own PSK diverges from
        // the program's (wrong key / unknown identity negatives).
        if let Some(u) = &program.uut {
            if let Some(s) = &u.psk_secret {
                cfg.psk.secret_hex = s.clone();
            }
            if let Some(i) = &u.psk_identity {
                cfg.psk.identity = i.clone();
            }
        }

        // Explicit UUT policy overrides. These are the whole point of the
        // `uut client|server { ... }` block: they let the tested implementation's policy
        // DIFFER from what the harness offers, so a test can drive a genuine
        // negotiation failure (UUT rejects the version/cipher/curve plzn sent).
        if let Some(u) = &program.uut {
            if !u.cipher_suites.is_empty() {
                cfg.cipher_suites = u.cipher_suites.clone();
            }
            if !u.curves.is_empty() {
                cfg.curves = u.curves.clone();
            }
            // OR, not assign: the server policy above set the requirement, and
            // a `uut server { }` block naming other knobs must keep it
            // (otherwise a server with `verify_prefs` sent no CertificateRequest
            // and the client-auth flow passed without authenticating).
            cfg.verify.require_client_cert |= u.require_client_cert;
            cfg.verify.request_client_cert |= u.request_client_cert;
            cfg.verify.peer = u.verify_peer;
            cfg.alpn.advertise = u.alpn_advertise.clone();
            if let Some(a) = &u.alpn_select {
                cfg.alpn.select = a.clone();
            }
            cfg.alpn.select_from = u.alpn_select_from.clone();
            cfg.alpn.expect = u.expect_alpn.clone();
            cfg.alpn.decline = u.alpn_decline;
            cfg.srtp_profiles = u.srtp_profiles.clone();
            cfg.expect_srtp_profile = u.expect_srtp_profile;
            if !u.signing_prefs.is_empty() {
                cfg.signing_prefs = u.signing_prefs.clone();
            }
            if !u.verify_prefs.is_empty() {
                cfg.verify_prefs = u.verify_prefs.clone();
            }
            cfg.server_preference = u.server_preference;
            cfg.renegotiation = u.renegotiation.clone();
            cfg.session_tickets = u.session_tickets;
            cfg.max_early_data = u.max_early_data;
            cfg.max_cert_list = u.max_cert_list;
            cfg.record_size_limit = u.record_size_limit;
            cfg.records_per_traffic_key = u.records_per_traffic_key;
            cfg.key_update = u.key_update;
            cfg.extended_master_secret = u.extended_master_secret.clone();
            cfg.encrypt_then_mac = u.encrypt_then_mac;
            cfg.middlebox_compat = u.middlebox_compat;
            cfg.raw_public_key = u.raw_public_key;
            cfg.server_certificate_types = u.server_certificate_types.clone();
            cfg.client_certificate_types = u.client_certificate_types.clone();
            cfg.min_key_update_interval_ms = u.min_key_update_interval_ms;
            cfg.renegotiate_after_handshake = u.renegotiate_after_handshake;
            cfg.hello_request_after_app_data = u.hello_request_after_app_data;
            cfg.require_client_cert_on_renegotiation = u.require_client_cert_on_renegotiation;
            cfg.half_rtt_data = u.half_rtt_data.clone();
            // T6: post-handshake auth needs the client trust root like any
            // client-auth request; an OCSP staple is generated for the
            // certificate the shim will load.
            cfg.post_handshake_auth = u.post_handshake_auth.clone();
            if u.post_handshake_auth.is_some() && cfg.credentials.trust_file.is_empty() {
                cfg.credentials.trust_file = cfg.fixture_path("client_ee_ca.pem")?;
            }
            if u.ocsp_stapling && shim_is_server {
                match ocsp_staple_for(&cfg.credentials.cert_file, &cfg.credentials.key_file) {
                    Ok(path) => cfg.credentials.ocsp_file = path,
                    Err(e) => eprintln!("plzn: ocsp_stapling: {}", e),
                }
            }
            if u.mtu.is_some()
                || u.initial_timeout_ms.is_some()
                || u.dtls_max_retransmissions.is_some()
                || u.dtls_max_timeout_ms.is_some()
                || u.dtls_require_cookie.is_some()
                || u.dtls_epoch0_restart.is_some()
                || u.dtls_max_hello_verify_requests.is_some()
            {
                cfg.dtls = Some(DtlsField {
                    mtu: u.mtu.unwrap_or(1500),
                    initial_timeout_ms: u.initial_timeout_ms.unwrap_or(400),
                    max_retransmissions: u.dtls_max_retransmissions,
                    max_timeout_ms: u.dtls_max_timeout_ms,
                    require_cookie: u.dtls_require_cookie,
                    epoch0_restart: u.dtls_epoch0_restart,
                    max_hello_verify_requests: u.dtls_max_hello_verify_requests,
                });
            }
        }

        // A test whose expectation is anything other than `ok` is a negative
        // test: plzn deliberately drives the UUT into an alert/close/failure. Tell
        // the shim to expect its handshake (or flow) to fail so it exits 0 when it
        // does, rather than treating the intended failure as an unexpected one.
        // "" means "any failure is acceptable".
        //
        // A WARNING-level alert is the exception: the peer keeps the connection
        // (a no_renegotiation refusal, say), so from the shim's side the flow
        // succeeded and it must self-check for success, not failure.
        let ambiguous_expectation = matches!(effective_expect, crate::ir::Expectation::Any(_));
        let expects_failure = !ambiguous_expectation
            && !matches!(
                effective_expect,
                crate::ir::Expectation::Ok
                    | crate::ir::Expectation::Alert {
                        level: crate::ir::AlertLevel::Warning,
                        ..
                    }
            );
        if expects_failure {
            cfg.expect.handshake_error = Some(String::new());
            // A failing handshake never reaches the version self-check.
            cfg.expect.version = None;
        }
        if ambiguous_expectation {
            cfg.expect.handshake_error = None;
            cfg.expect.handshake_abandoned = true;
            cfg.expect.version = None;
        }
        // An `expect ok` flow that never sends plzn's Finished abandons the
        // handshake on purpose; the library's reaction to the abrupt close is
        // not what is under test, so the shim accepts either outcome.
        if matches!(effective_expect, crate::ir::Expectation::Ok)
            && !program_completes_handshake(program)
        {
            cfg.expect.handshake_abandoned = true;
            cfg.expect.version = None;
        }
        // A test that renegotiates needs the shim (as the peer) to accept the
        // peer-initiated renegotiation -- the library default is to deny it.
        // An explicit `uut client|server { renegotiation }` knob is the test's own statement
        // of the UUT's policy and is left alone.
        let explicit_reneg = program
            .uut
            .as_ref()
            .and_then(|u| u.renegotiation.as_ref())
            .is_some();
        // A stepped renegotiation (`send HelloRequest` on the server side,
        // `begin_renegotiation` on the client side) needs the same permission.
        let renegotiates = program.steps.iter().any(|s| match s {
            crate::ir::Step::Renegotiate { .. } => true,
            crate::ir::Step::BeginRenegotiation { .. } => true,
            crate::ir::Step::Dtls {
                op: crate::ir::DtlsOp::BeginRenegotiation,
                ..
            } => true,
            crate::ir::Step::HandshakeSteps { steps, .. } => steps.contains(
                &crate::ir::HandshakeStep::Send(crate::ir::MessageKind::HelloRequest),
            ),
            _ => false,
        });
        if !explicit_reneg && (renegotiates || cfg.renegotiate_after_handshake) {
            cfg.renegotiate_freely = true;
        }
        cfg.requires = program_requirements(program);
        if !shim_is_server {
            // A: the key types plzn's SERVER may present (`chain:`), so a shim
            // client refuses only when it can verify none of them.
            cfg.requires.server_key = program
                .server_chains
                .iter()
                .map(|c| c.key_type.name().to_string())
                .collect();
        }
        cfg.key_material = key_material_for_program(program, 0);
        Ok(cfg)
    }
}

/// True when the program's flow includes plzn's own Finished (or the whole
/// handshake preset), i.e. plzn intends to complete the handshake.
/// True when plzn's flow finishes its side of the handshake AND observes the
/// peer at least once afterwards. A flow that sends its Finished and closes
/// at once (tlsfuzzer's connection-abort shapes) leaves the peer's
/// post-Finished writes racing plzn's close: whether the library reports a
/// clean handshake or a broken pipe is timing, not a finding, so the shim is
/// not held to a clean success there either.
pub fn program_completes_handshake(program: &crate::ir::Program) -> bool {
    use crate::ir::{HandshakeStep, MessageKind, Step};
    let steps = &program.steps;
    if steps.iter().any(|s| matches!(s, Step::Handshake { .. })) {
        return true;
    }
    let fin = HandshakeStep::Send(MessageKind::Finished);
    let Some(last) = steps
        .iter()
        .rposition(|s| matches!(s, Step::HandshakeSteps { steps, .. } if steps.contains(&fin)))
    else {
        return false;
    };
    let observes = |s: &Step| match s {
        Step::HandshakeSteps { steps, .. } => {
            steps.iter().any(|h| matches!(h, HandshakeStep::Recv(_)))
        }
        Step::RecvAppData { .. }
        | Step::RecvExporter { .. }
        | Step::RecvTlsUnique { .. }
        | Step::RecvAlert { .. }
        | Step::RecvKeyUpdate { .. }
        | Step::Wait { .. }
        | Step::ExpectRetransmit { .. }
        | Step::Renegotiate { .. }
        | Step::BeginRenegotiation { .. }
        | Step::Dtls { .. } => true,
        _ => false,
    };
    // A receive after the Finished inside the same block counts too.
    if let Step::HandshakeSteps { steps: hs, .. } = &steps[last] {
        let pos = hs.iter().rposition(|h| *h == fin).unwrap_or(0);
        if hs[pos + 1..]
            .iter()
            .any(|h| matches!(h, HandshakeStep::Recv(_)))
        {
            return true;
        }
    }
    steps[last + 1..].iter().any(observes)
}

/// The suites and groups plzn will offer (client role) or select from (server
/// role), from the peer capabilities, so a shim can refuse a case its library
/// cannot take part in at all (rustls: CBC, static RSA, DHE, P-521, FFDHE).
fn program_requirements(program: &crate::ir::Program) -> Requires {
    use crate::ir::Subject;
    use crate::tls::record::TlsVersion;
    let any_suite = match (program.version, program.subject) {
        // DTLS: the datagram offer / selection set (Botan's DTLS rule, PSK when
        // the test has a `psk { }` block).
        (TlsVersion::Tls12, _) if program.protocol == crate::ir::Protocol::Dtls => {
            crate::ir::filter_suites_dtls(&program.suite_filters, program.psk.is_some())
        }
        // Client role: what plzn offers; server role: what plzn's server will
        // select from (it honours the same peer capabilities). A `psk { }`
        // block switches both to the pre-shared-key families.
        (TlsVersion::Tls10 | TlsVersion::Tls11 | TlsVersion::Tls12, _) => {
            crate::ir::filter_suites_legacy(
                program.version,
                &program.suite_filters,
                program.psk.is_some(),
            )
        }
        // Key-exchange predicates mean nothing in TLS 1.3 (the client ignores
        // them for its offer too); a `cert` axis must not empty the list.
        (TlsVersion::Tls13, Subject::Server) => {
            let filters13: Vec<crate::ir::SuiteFilter> = program
                .suite_filters
                .iter()
                .filter(|f| !matches!(f, crate::ir::SuiteFilter::Kex(_)))
                .copied()
                .collect();
            crate::ir::filter_suites(TlsVersion::Tls13, &filters13)
        }
        (TlsVersion::Tls13, Subject::Client) => program.server_suites.clone(),
    };
    Requires {
        any_suite,
        // Group capabilities: the UUT's explicit policy wins over the peer's
        // matrix-derived group. This matters for negative tests whose `group`
        // axis is the unsupported value sent by plzn, while `uut.curves`
        // deliberately keeps the implementation on a known-good group.
        // Empty = the driver default set.
        any_group: program
            .uut
            .as_ref()
            .filter(|u| !u.curves.is_empty())
            .map(|u| u.curves.clone())
            .unwrap_or_else(|| program.server_groups.clone()),
        virtual_clock: program.steps.iter().any(|s| {
            matches!(
                s,
                crate::ir::Step::AdvanceClock { .. }
                    | crate::ir::Step::ExpectNextTimeout { .. }
                    | crate::ir::Step::ExpectNoTimeout { .. }
                    | crate::ir::Step::SetTimeout { .. }
            )
        }),
        dynamic_timeout: program
            .steps
            .iter()
            .any(|s| matches!(s, crate::ir::Step::SetTimeout { .. })),
        session_id_resumption: program.resume_by_session_id,
        // A: filled from the program's resolved `chain:` list when the shim is
        // the client (see `for_program`).
        server_key: Vec::new(),
    }
}

/// True when plzn (as client) expects a CertificateRequest from the shim
/// server, i.e. the flow expanded to a client-authentication client preset.
fn program_expects_certificate_request(program: &crate::ir::Program) -> bool {
    use crate::ir::{HandshakeStep, MessageKind, Step};
    program.steps.iter().any(|s| match s {
        Step::HandshakeSteps { steps, .. } => {
            steps.contains(&HandshakeStep::Recv(MessageKind::CertificateRequest))
        }
        _ => false,
    })
}

/// T6: `uut server { ocsp_stapling }`: write a good OCSP response for the PEM
/// certificate/key the shim server loads (see `server::ocsp`) next to the
/// certificate and return its path.
fn ocsp_staple_for(cert_pem_path: &str, key_pem_path: &str) -> Result<String, String> {
    let cert_pem =
        std::fs::read(cert_pem_path).map_err(|e| format!("read {}: {}", cert_pem_path, e))?;
    let key_pem =
        std::fs::read(key_pem_path).map_err(|e| format!("read {}: {}", key_pem_path, e))?;
    let cert_der = crate::tls::client_auth::pem_certificates(&cert_pem)
        .into_iter()
        .next()
        .ok_or_else(|| format!("{}: no certificate", cert_pem_path))?;
    let key_der = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| format!("{}: {}", key_pem_path, e))?
        .ok_or_else(|| format!("{}: no private key", key_pem_path))?
        .secret_der()
        .to_vec();
    let der = crate::server::ocsp::good_response_now(&cert_der, &key_der)?;
    // One file per staple: cases run in parallel must not share (or read a
    // half-written copy of) the same response. The run's cert directory is
    // removed at the end, taking every staple with it.
    static STAPLES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = STAPLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::path::Path::new(cert_pem_path).with_extension(format!("{}.ocsp.der", n));
    std::fs::write(&path, &der).map_err(|e| format!("write {}: {}", path.display(), e))?;
    Ok(path.to_string_lossy().into_owned())
}

/// The client credential plzn's own clients (TLS 1.2, TLS 1.3, DTLS) answer a
/// shim server's CertificateRequest with, as DER `(certificate, PKCS#8 key)`:
/// `shims/testdata/client_ee_{cert,key.pkcs8}.der`, an end-entity certificate
/// issued by `client_ee_ca.pem` (the runner hands a `uut server` program no
/// certificate of its own). Embedded in plzn, independent of the checkout.
pub fn test_client_credential_der() -> Option<(Vec<u8>, Vec<u8>)> {
    client_credential_der_for(crate::server::certs::KeyType::EcdsaP256)
}

/// A: the `client_ee_*` file base of a key type (every one is issued by
/// client_ee_ca; `gen_client_ee.sh` makes them).
fn client_ee_base(kt: crate::server::certs::KeyType) -> &'static str {
    use crate::server::certs::KeyType;
    match kt {
        KeyType::EcdsaP256 => "client_ee",
        KeyType::Rsa2048 => "client_ee_rsa",
        KeyType::RsaPss => "client_ee_rsa_pss",
        KeyType::EcdsaP384 => "client_ee_ecdsa_p384",
        KeyType::EcdsaP521 => "client_ee_ecdsa_p521",
        KeyType::Ed25519 => "client_ee_ed25519",
    }
}

/// A: the CA-issued client credential of a key type as the PEM files a shim
/// client loads (`client_chain:` on the shim side). Write them into the
/// caller-owned directory, which must outlive every shim using these paths.
pub fn client_credential_files_for(
    kt: crate::server::certs::KeyType,
    dir: &std::path::Path,
) -> io::Result<(PathBuf, PathBuf)> {
    let base = client_ee_base(kt);
    Ok((
        crate::fixtures::write(dir, &format!("{base}_cert.pem"))?,
        crate::fixtures::write(dir, &format!("{base}_key.pem"))?,
    ))
}

/// A: the same credential as DER (certificate, PKCS#8 key) for plzn's own
/// client (`client_chain:` on the plzn side).
pub fn client_credential_der_for(kt: crate::server::certs::KeyType) -> Option<(Vec<u8>, Vec<u8>)> {
    let base = client_ee_base(kt);
    let cert = crate::fixtures::read(&format!("{base}_cert.der"))
        .ok()?
        .to_vec();
    let key = crate::fixtures::read(&format!("{base}_key.pkcs8.der"))
        .ok()?
        .to_vec();
    Some((cert, key))
}

fn shim_client_credential_names(choice: &str) -> Option<(&'static str, &'static str)> {
    Some(match choice {
        "valid" => ("client_cert.pem", "client_key.pem"),
        "untrusted" => ("untrusted_client_cert.pem", "untrusted_client_key.pem"),
        "expired" => ("expired_client_cert.pem", "expired_client_key.pem"),
        _ => return None,
    })
}

/// True when plzn (as server) will send a CertificateRequest in this program,
/// i.e. the flow expanded to the client-authentication preset.
fn program_requests_client_auth(program: &crate::ir::Program) -> bool {
    use crate::ir::{HandshakeStep, MessageKind, Step};
    program.steps.iter().any(|s| match s {
        Step::HandshakeSteps { steps, .. } => {
            steps.contains(&HandshakeStep::Send(MessageKind::CertificateRequest))
        }
        _ => false,
    })
}

impl Default for ShimConfig {
    fn default() -> Self {
        ShimConfig {
            fixture_dir: None,
            role: "server".into(),
            protocol: "tls".into(),
            runner: RunnerEndpoint {
                host: "127.0.0.1".into(),
                port: 0,
                ipv6: false,
            },
            shim_id: 0,
            resume_count: 0,
            min_version: None,
            max_version: None,
            connection_versions: Vec::new(),
            connection_early_data: Vec::new(),
            cipher_suites: Vec::new(),
            curves: Vec::new(),
            signing_prefs: Vec::new(),
            verify_prefs: Vec::new(),
            server_name: String::new(),
            expect_server_name: None,
            psk: PskField::default(),
            credentials: Credentials::default(),
            verify: VerifyConfig::default(),
            alpn: AlpnConfig::default(),
            srtp_profiles: Vec::new(),
            expect_srtp_profile: None,
            app_data: AppDataConfig {
                mode: "echo".into(),
                send: String::new(),
            },
            key_material: Vec::new(),
            expect: Expectations::default(),
            raw_public_key: false,
            server_certificate_types: Vec::new(),
            client_certificate_types: Vec::new(),
            compress_certificate: false,
            renegotiate_freely: false,
            requires: Requires::default(),
            server_preference: None,
            renegotiation: None,
            session_tickets: None,
            max_early_data: None,
            early_data_send: 0,
            early_data_expect: 0,
            expect_early_data_accepted: None,
            max_cert_list: None,
            record_size_limit: None,
            records_per_traffic_key: None,
            key_update: false,
            post_handshake_auth: None,
            extended_master_secret: None,
            encrypt_then_mac: None,
            middlebox_compat: None,
            min_key_update_interval_ms: None,
            renegotiate_after_handshake: false,
            hello_request_after_app_data: false,
            require_client_cert_on_renegotiation: false,
            half_rtt_data: Vec::new(),
            dtls: None,
            mock: MockField::default(),
        }
    }
}

pub fn key_material_for_program(
    program: &crate::ir::Program,
    connection: u32,
) -> Vec<KeyMaterialConfig> {
    program
        .steps
        .iter()
        .filter_map(|step| match step {
            crate::ir::Step::RecvExporter {
                label,
                context,
                length,
                ..
            } => Some(KeyMaterialConfig {
                connection,
                kind: "exporter".into(),
                label: String::from_utf8_lossy(label).into_owned(),
                context: context
                    .as_ref()
                    .map(|value| String::from_utf8_lossy(value).into_owned()),
                length: *length as u32,
            }),
            crate::ir::Step::RecvTlsUnique { unavailable, .. } => Some(KeyMaterialConfig {
                connection,
                kind: if *unavailable {
                    "tls_unique_unavailable"
                } else {
                    "tls_unique"
                }
                .into(),
                length: if *unavailable { 1 } else { 12 },
                ..Default::default()
            }),
            _ => None,
        })
        .collect()
}

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

impl Credentials {
    fn is_empty(&self) -> bool {
        self.cert_file.is_empty()
            && self.key_file.is_empty()
            && self.trust_file.is_empty()
            && self.ocsp_file.is_empty()
    }
}
impl VerifyConfig {
    fn is_default(&self) -> bool {
        !self.peer && !self.require_client_cert && !self.request_client_cert && !self.fail
    }
}
impl AlpnConfig {
    fn is_default(&self) -> bool {
        self.advertise.is_empty()
            && self.select.is_empty()
            && self.select_from.is_empty()
            && self.expect.is_none()
            && !self.decline
    }
}
impl Expectations {
    fn is_default(&self) -> bool {
        self.version.is_none()
            && self.cipher.is_none()
            && self.alpn.is_none()
            && self.resumed.is_none()
            && self.hrr.is_none()
            && self.handshake_error.is_none()
            && !self.handshake_abandoned
    }
}

// ------------------------------------------------------------------
// Backend
// ------------------------------------------------------------------

/// Which shim binary to launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShimKind {
    Botan,
    OpenSsl,
    LibreSsl,
    Rustls,
    GnuTls,
    WolfSsl,
    Go,
    /// A controllable test shim (not a real TLS library): it dials the runner,
    /// reads the peer's first record, then performs one configured action
    /// (`mock.action`: send a specific alert, close cleanly, or reset). Used to
    /// unit-test the runner's expectation matcher deterministically.
    Mock,
}

impl ShimKind {
    pub fn label(self) -> &'static str {
        match self {
            ShimKind::Botan => "botan",
            ShimKind::OpenSsl => "openssl",
            ShimKind::LibreSsl => "libressl",
            ShimKind::Rustls => "rustls",
            ShimKind::GnuTls => "gnutls",
            ShimKind::WolfSsl => "wolfssl",
            ShimKind::Go => "go",
            ShimKind::Mock => "mock",
        }
    }

    /// Short backend name matched by a test's `skip <backend>` directive.
    pub fn skip_label(self) -> &'static str {
        match self {
            ShimKind::Botan => "botan",
            ShimKind::OpenSsl => "openssl",
            ShimKind::LibreSsl => "libressl",
            ShimKind::Rustls => "rustls",
            ShimKind::GnuTls => "gnutls",
            ShimKind::WolfSsl => "wolfssl",
            ShimKind::Go => "go",
            ShimKind::Mock => "mock",
        }
    }

    /// Locate the shim binary: env override first, then beside the executable,
    /// then the current directory's development build paths. No build-time
    /// checkout location is retained. The CLI always takes an explicit shim.
    /// Project-provided external shims live under `shims/build/`; only the
    /// in-tree mock used to test the runner itself is a plzn Cargo target.
    pub fn binary_path(self) -> Option<PathBuf> {
        let (env, defaults): (&str, &[&str]) = match self {
            ShimKind::Botan => ("PLZN_BOTAN_SHIM", &["shims/build/botan_shim"]),
            ShimKind::OpenSsl => ("PLZN_OPENSSL_SHIM", &["shims/build/openssl_shim"]),
            ShimKind::LibreSsl => ("PLZN_LIBRESSL_SHIM", &["shims/build/libressl_shim"]),
            ShimKind::GnuTls => ("PLZN_GNUTLS_SHIM", &["shims/build/gnutls_shim"]),
            ShimKind::WolfSsl => ("PLZN_WOLFSSL_SHIM", &["shims/build/wolfssl_shim"]),
            ShimKind::Go => ("PLZN_GO_SHIM", &["shims/build/go_tls_shim"]),
            ShimKind::Rustls => ("PLZN_RUSTLS_SHIM", &["shims/build/rustls_shim"]),
            ShimKind::Mock => (
                "PLZN_MOCK_SHIM",
                &["target/debug/mock_shim", "target/release/mock_shim"],
            ),
        };
        if let Ok(p) = std::env::var(env) {
            let pb = PathBuf::from(p);
            return pb.exists().then_some(pb);
        }
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(PathBuf::from))
        {
            for default in defaults {
                let name = std::path::Path::new(default).file_name()?;
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        let root = std::env::current_dir().ok()?;
        defaults.iter().map(|d| root.join(d)).find(|p| p.is_file())
    }
}

/// Versioned response emitted by a shim for `--plzn-shim-info`.
///
/// `name` is the stable backend identifier used by `expect ... if`, `skip`,
/// and `xfail` as well as in reports. `expectations`, when present, names a
/// JSON sidecar relative to the shim binary (an absolute path is also allowed).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ShimIdentity {
    pub protocol: String,
    pub protocol_version: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expectations: Option<String>,
}

/// An identified, externally supplied shim executable.
#[derive(Clone, Debug)]
pub struct ShimSpec {
    binary: PathBuf,
    identity: ShimIdentity,
}

impl ShimSpec {
    pub const PROTOCOL: &'static str = "plzn-shim";
    pub const PROTOCOL_VERSION: u32 = 1;

    /// Run `binary --plzn-shim-info`, validate the response, and return the
    /// executable plus its stable identity. Identification happens once per
    /// CLI invocation, never once per test case.
    pub fn identify(binary: impl Into<PathBuf>) -> io::Result<Self> {
        let binary = binary.into();
        let mut child = Command::new(&binary)
            .arg("--plzn-shim-info")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("cannot execute shim {}: {}", binary.display(), e),
                )
            })?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{} did not answer --plzn-shim-info within 5s",
                        binary.display()
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "{} rejected --plzn-shim-info ({}): {}",
                binary.display(),
                output.status,
                stderr.trim()
            )));
        }
        let identity: ShimIdentity = serde_json::from_slice(&output.stdout).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} returned invalid shim identity JSON: {}",
                    binary.display(),
                    e
                ),
            )
        })?;
        if identity.protocol != Self::PROTOCOL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} identifies protocol {:?}, expected {:?}",
                    binary.display(),
                    identity.protocol,
                    Self::PROTOCOL
                ),
            ));
        }
        if identity.protocol_version != Self::PROTOCOL_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} uses shim protocol version {}, but plzn supports {}",
                    binary.display(),
                    identity.protocol_version,
                    Self::PROTOCOL_VERSION
                ),
            ));
        }
        if identity.name.is_empty()
            || !identity
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} returned invalid shim name {:?}; use ASCII letters, digits, '.', '-', or '_'",
                    binary.display(),
                    identity.name
                ),
            ));
        }
        Ok(Self { binary, identity })
    }

    /// Compatibility constructor for Rust callers and the interop tests. The
    /// CLI deliberately does not perform this built-in name-to-path lookup.
    pub fn for_kind(kind: ShimKind) -> io::Result<Self> {
        let binary = kind.binary_path().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} shim binary not found", kind.label()),
            )
        })?;
        Ok(Self {
            binary,
            identity: ShimIdentity {
                protocol: Self::PROTOCOL.into(),
                protocol_version: Self::PROTOCOL_VERSION,
                name: kind.label().into(),
                expectations: None,
            },
        })
    }

    pub fn name(&self) -> &str {
        &self.identity.name
    }

    pub fn binary(&self) -> &std::path::Path {
        &self.binary
    }

    pub fn expectations_path(&self) -> Option<PathBuf> {
        self.identity.expectations.as_ref().map(|p| {
            let path = PathBuf::from(p);
            if path.is_absolute() {
                path
            } else {
                self.binary
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(path)
            }
        })
    }
}

/// Per-test policy shipped next to an external shim. A string value is
/// shorthand for `{ "expect": "..." }`.
#[derive(Clone, Debug, Default)]
pub struct ShimTestOverride {
    pub expect: Option<crate::ir::Expectation>,
    pub skip: Option<String>,
    pub xfail: Option<String>,
    pub normal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ShimExpectationSet {
    overrides: std::collections::BTreeMap<String, ShimTestOverride>,
    patterns: Vec<(String, ShimTestOverride)>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawShimTestOverride {
    Expect(String),
    Detailed(RawShimTestOverrideFields),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimTestOverrideFields {
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    skip: Option<String>,
    #[serde(default)]
    xfail: Option<String>,
    /// Clear an in-suite skip/xfail for this backend.
    #[serde(default)]
    normal: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimExpectationSet {
    schema_version: u32,
    #[serde(alias = "tests")]
    overrides: std::collections::BTreeMap<String, RawShimTestOverride>,
    #[serde(default)]
    patterns: Vec<RawShimPatternOverride>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShimPatternOverride {
    pattern: String,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    skip: Option<String>,
    #[serde(default)]
    xfail: Option<String>,
    #[serde(default)]
    normal: bool,
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let (mut star, mut retry_v) = (None, 0);

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry_v = v;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            retry_v += 1;
            v = retry_v;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

impl ShimExpectationSet {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn from_path(path: &std::path::Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot read shim expectations {}: {}", path.display(), e),
            )
        })?;
        Self::from_json(&text).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid shim expectations {}: {}", path.display(), e),
            )
        })
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        let raw: RawShimExpectationSet = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if raw.schema_version != Self::SCHEMA_VERSION {
            return Err(format!(
                "schema_version is {}, but plzn supports {}",
                raw.schema_version,
                Self::SCHEMA_VERSION
            ));
        }
        fn parse_fields(
            label: &str,
            fields: RawShimTestOverrideFields,
        ) -> Result<ShimTestOverride, String> {
            if fields.skip.is_some() && fields.xfail.is_some() {
                return Err(format!("{} cannot specify both skip and xfail", label));
            }
            if fields.normal && (fields.skip.is_some() || fields.xfail.is_some()) {
                return Err(format!(
                    "{} cannot combine normal with skip or xfail",
                    label
                ));
            }
            let expect = fields
                .expect
                .as_deref()
                .map(parse_external_expectation)
                .transpose()
                .map_err(|e| format!("{}: {}", label, e))?;
            Ok(ShimTestOverride {
                expect,
                skip: fields.skip,
                xfail: fields.xfail,
                normal: fields.normal,
            })
        }

        let mut overrides = std::collections::BTreeMap::new();
        for (test_id, entry) in raw.overrides {
            let fields = match entry {
                RawShimTestOverride::Expect(expect) => RawShimTestOverrideFields {
                    expect: Some(expect),
                    skip: None,
                    xfail: None,
                    normal: false,
                },
                RawShimTestOverride::Detailed(fields) => fields,
            };
            let label = format!("override for {:?}", test_id);
            overrides.insert(test_id, parse_fields(&label, fields)?);
        }
        let mut patterns = Vec::new();
        for entry in raw.patterns {
            if entry.pattern.is_empty() {
                return Err("pattern override cannot have an empty pattern".into());
            }
            let label = format!("pattern override for {:?}", entry.pattern);
            let fields = RawShimTestOverrideFields {
                expect: entry.expect,
                skip: entry.skip,
                xfail: entry.xfail,
                normal: entry.normal,
            };
            patterns.push((entry.pattern, parse_fields(&label, fields)?));
        }
        Ok(Self {
            overrides,
            patterns,
        })
    }

    pub fn get(&self, test_id: &str) -> Option<&ShimTestOverride> {
        self.overrides.get(test_id).or_else(|| {
            self.patterns
                .iter()
                .find(|(pattern, _)| wildcard_matches(pattern, test_id))
                .map(|(_, entry)| entry)
        })
    }

    pub fn len(&self) -> usize {
        self.overrides.len() + self.patterns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty() && self.patterns.is_empty()
    }

    /// Apply a sidecar entry with higher precedence than annotations embedded
    /// in the shared suite. Other backends' annotations are left untouched.
    pub fn apply(&self, program: &mut crate::ir::Program, backend: &str) {
        let Some(entry) = self.get(&program.test_id) else {
            return;
        };
        if let Some(expect) = &entry.expect {
            program
                .expect_overrides
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .expect_overrides
                .insert(0, (backend.to_string(), expect.clone()));
        }
        if entry.normal {
            program
                .skip_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .xfail_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
        }
        if let Some(reason) = &entry.skip {
            program
                .skip_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .xfail_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .skip_backends
                .push((backend.to_string(), Some(reason.clone())));
        }
        if let Some(reason) = &entry.xfail {
            program
                .skip_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .xfail_backends
                .retain(|(name, _)| !name.eq_ignore_ascii_case(backend));
            program
                .xfail_backends
                .push((backend.to_string(), Some(reason.clone())));
        }
    }
}

fn parse_external_expectation(text: &str) -> Result<crate::ir::Expectation, String> {
    use crate::ir::{AlertLevel, Expectation};
    let text = text.trim();
    if let Some(body) = text.strip_prefix("any {").and_then(|s| s.strip_suffix('}')) {
        let mut alternatives = Vec::new();
        let mut depth = 0usize;
        let mut start = 0usize;
        for (offset, ch) in body.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or("unbalanced `}` in `any` expectation")?
                }
                ',' if depth == 0 => {
                    alternatives.push(parse_external_expectation(&body[start..offset])?);
                    start = offset + ch.len_utf8();
                }
                _ => {}
            }
        }
        if depth != 0 {
            return Err("unbalanced `{` in `any` expectation".into());
        }
        alternatives.push(parse_external_expectation(&body[start..])?);
        if alternatives.len() < 2 {
            return Err("`any` expectation needs at least two alternatives".into());
        }
        return Ok(Expectation::Any(alternatives));
    }
    match text {
        "ok" => return Ok(Expectation::Ok),
        "close" => return Ok(Expectation::Close),
        "reset" => return Ok(Expectation::Reset),
        "timeout" => return Ok(Expectation::Timeout),
        "handshake-fails" => return Ok(Expectation::HandshakeFails),
        _ => {}
    }
    let (rest, reject) = if let Some(rest) = text.strip_prefix("alert ") {
        (rest, false)
    } else if let Some(rest) = text.strip_prefix("reject ") {
        (rest, true)
    } else {
        return Err(format!("unknown expectation {:?}", text));
    };
    let (level, codes) = match rest.split_once('/') {
        Some((level, codes)) => (level, Some(codes)),
        None => (rest, None),
    };
    let level = match level.trim() {
        "warning" => AlertLevel::Warning,
        "fatal" => AlertLevel::Fatal,
        other => return Err(format!("unknown alert level {:?}", other)),
    };
    let mut parsed = Vec::new();
    if let Some(codes) = codes {
        let codes = codes.trim();
        let codes = codes
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(codes);
        for code in codes.split(',').map(str::trim) {
            if code.is_empty() {
                return Err("alert code set may not be empty".into());
            }
            let value = crate::schema::alert_code_value(code)
                .or_else(|| {
                    code.strip_prefix("0x")
                        .and_then(|v| u8::from_str_radix(v, 16).ok())
                })
                .or_else(|| code.parse::<u8>().ok())
                .ok_or_else(|| format!("unknown alert code {:?}", code))?;
            if !parsed.contains(&value) {
                parsed.push(value);
            }
        }
    }
    Ok(if reject {
        Expectation::Reject {
            level,
            codes: parsed,
        }
    } else {
        Expectation::Alert {
            level,
            codes: parsed,
        }
    })
}

/// A `UutFactory` that spawns a shim per connection and accepts it back.
pub struct ShimFactory {
    name: String,
    binary: PathBuf,
    config: ShimConfig,
    listener: TcpListener,
    port: u16,
    accept_timeout: Duration,
    // Interior mutability: open() is &self but must stash the spawned child so
    // the caller can reap it (and its expectation exit status) after the run.
    child: Mutex<Option<SupervisedChild>>,
    // Keeps the temp config file alive for the process lifetime.
    cfg_file: Mutex<Option<tempfile::NamedTempFile>>,
    // Outcome of a shim that exited before connecting (open() failed early);
    // handed back by wait_shim() so the caller still learns how it ended.
    early_outcome: Mutex<Option<ShimOutcome>>,
    // Multi-session runs: the shim is spawned once with `resume_count` set and
    // dials back once per session, so open() spawns on the first call only and
    // then just accepts the next connection from the same process (a shim
    // CLIENT keeps its session cache in memory, which is what resumption
    // against a real client needs).
    connections: u32,
    opens: Mutex<u32>,
    /// Connections that completed the shim prefix and reached the protocol.
    /// An unsupported_config exit is a SKIP only while this remains zero.
    connected: Mutex<u32>,
}

impl ShimFactory {
    /// `config.runner.port` is overwritten with the bound listener port.
    pub fn new(kind: ShimKind, config: ShimConfig) -> io::Result<Self> {
        Self::from_spec(ShimSpec::for_kind(kind)?, config)
    }

    /// Construct a factory for an executable selected and identified by the
    /// caller (the path-based CLI uses this entry point).
    pub fn from_spec(spec: ShimSpec, mut config: ShimConfig) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        config.runner.host = "127.0.0.1".into();
        config.runner.port = port;
        Ok(ShimFactory {
            name: spec.name().to_string(),
            binary: spec.binary,
            config,
            listener,
            port,
            accept_timeout: Duration::from_secs(10),
            child: Mutex::new(None),
            cfg_file: Mutex::new(None),
            early_outcome: Mutex::new(None),
            connections: 1,
            opens: Mutex::new(0),
            connected: Mutex::new(0),
        })
    }

    /// A factory for a multi-session run: one shim process serving
    /// `connections` successive connections (`resume_count = connections - 1`
    /// in its config). Each `open()` after the first accepts the process's
    /// next dial instead of spawning a new one.
    pub fn new_multi(kind: ShimKind, mut config: ShimConfig, connections: u32) -> io::Result<Self> {
        config.resume_count = connections.saturating_sub(1);
        let mut f = ShimFactory::new(kind, config)?;
        f.connections = connections.max(1);
        Ok(f)
    }

    pub fn from_spec_multi(
        spec: ShimSpec,
        mut config: ShimConfig,
        connections: u32,
    ) -> io::Result<Self> {
        config.resume_count = connections.saturating_sub(1);
        let mut f = ShimFactory::from_spec(spec, config)?;
        f.connections = connections.max(1);
        Ok(f)
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    pub fn connected_count(&self) -> u32 {
        *self.connected.lock().unwrap()
    }

    /// Wait for the spawned shim to exit and return whether it reported success
    /// (exit status 0). The shim self-checks the configured expectations, so a
    /// nonzero status means an expectation mismatch or protocol error on the
    /// UUT side, independent of what the runner's flow concluded.
    pub fn wait_shim(&self) -> io::Result<ShimOutcome> {
        let mut guard = self.child.lock().unwrap();
        match guard.take() {
            Some(mut child) => collect_outcome(&mut child),
            // open() already reaped a shim that exited before connecting.
            None => match self.early_outcome.lock().unwrap().take() {
                Some(outcome) => Ok(outcome),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no shim process was spawned",
                )),
            },
        }
    }

    /// If the spawned shim has already exited, reap it and return how it ended;
    /// None while it is still running (or nothing was spawned).
    fn reap_if_exited(&self) -> io::Result<Option<ShimOutcome>> {
        let mut guard = self.child.lock().unwrap();
        let running = match guard.as_mut() {
            Some(child) => child.try_wait()?.is_none(),
            None => return Ok(None),
        };
        if running {
            return Ok(None);
        }
        let mut child = guard.take().expect("checked above");
        collect_outcome(&mut child).map(Some)
    }
}

/// Extract the `detail=<...>` value from the shim's last `PLZN-RESULT` line.
fn parse_shim_detail(stderr_text: &str) -> Option<String> {
    stderr_text
        .lines()
        .rev()
        .find(|l| l.contains("PLZN-RESULT"))
        .and_then(|l| l.split_once("detail="))
        .map(|(_, d)| d.trim().to_string())
        .filter(|d| !d.is_empty())
}

/// Structured outcome "case" a shim reports via its exit code (see
/// shims/common/plzn_shim.h `ShimResult`). This tells the runner WHICH failure
/// path the UUT took (BoGo-style), complementing the TLS alert plzn observes on
/// the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimResultCase {
    Ok,
    Failure,
    LocalError,
    IoError,
    HandshakeFailed,
    ExpectationMismatch,
    UnexpectedSuccess,
    /// The library cannot apply a configured `uut` policy knob (the `detail`
    /// names it). The runner reports the case as SKIP, never as a pass.
    UnsupportedConfig,
    /// The process died by signal (SIGSEGV, SIGABRT, ...) and never reported a
    /// result. All this says is that the shim crashed; whether that is a
    /// library bug the test provoked or a broken binary/environment is for the
    /// caller to judge from context (see `CrashBreaker`).
    Crashed(i32),
    /// Exit code with no mapped case (e.g. a setup error with an unmapped code).
    Unknown(Option<i32>),
}

impl ShimResultCase {
    fn from_code(code: Option<i32>) -> Self {
        match code {
            Some(0) => ShimResultCase::Ok,
            Some(1) => ShimResultCase::Failure,
            Some(10) => ShimResultCase::LocalError,
            Some(11) => ShimResultCase::IoError,
            Some(12) => ShimResultCase::HandshakeFailed,
            Some(13) => ShimResultCase::ExpectationMismatch,
            Some(14) => ShimResultCase::UnexpectedSuccess,
            Some(16) => ShimResultCase::UnsupportedConfig,
            other => ShimResultCase::Unknown(other),
        }
    }

    /// Classify a wait status: death by signal is a crash (the process never
    /// got to report a result); anything else maps through the exit-code
    /// taxonomy above.
    fn from_status(status: &std::process::ExitStatus) -> Self {
        match exit_signal(status) {
            Some(sig) => ShimResultCase::Crashed(sig),
            None => ShimResultCase::from_code(status.code()),
        }
    }

    /// Canonical lowercase name, matching `shims/common/plzn_shim.h`.
    pub fn label(self) -> &'static str {
        match self {
            ShimResultCase::Ok => "ok",
            ShimResultCase::Failure => "failure",
            ShimResultCase::LocalError => "local_error",
            ShimResultCase::IoError => "io_error",
            ShimResultCase::HandshakeFailed => "handshake_failed",
            ShimResultCase::ExpectationMismatch => "expectation_mismatch",
            ShimResultCase::UnexpectedSuccess => "unexpected_success",
            ShimResultCase::UnsupportedConfig => "unsupported_config",
            ShimResultCase::Crashed(_) => "crashed",
            ShimResultCase::Unknown(_) => "unknown",
        }
    }
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Conventional name for a POSIX signal number, for crash reports.
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => "unknown signal",
    }
}

#[derive(Debug, Clone)]
pub struct ShimOutcome {
    pub success: bool,
    pub code: Option<i32>,
    /// Structured outcome case derived from the shim's exit code.
    pub case: ShimResultCase,
    /// The shim's `detail=` reason from its `PLZN-RESULT` line, if any. Carries the
    /// library's failure reason even when the failure was expected (case == Ok).
    pub detail: Option<String>,
    /// Everything the shim wrote to stderr (its `PLZN-RESULT` line included)
    /// and stdout. The runner prints them next to the case's own report, so the
    /// output of cases run in parallel does not interleave.
    pub stderr: String,
    pub stdout: String,
}

impl ShimOutcome {
    /// The shim's library cannot apply a configured policy knob (SKIP, not FAIL).
    pub fn is_unsupported_config(&self) -> bool {
        self.case == ShimResultCase::UnsupportedConfig
    }

    /// The shim process died by signal rather than exiting with a result code.
    pub fn is_crash(&self) -> bool {
        matches!(self.case, ShimResultCase::Crashed(_))
    }

    /// One line on how the process ended -- `killed by signal 11 (SIGSEGV)` or
    /// `exit code 10 (local_error)` -- followed by the shim's own `detail=`
    /// reason when it managed to report one.
    pub fn describe_exit(&self) -> String {
        let how = match self.case {
            ShimResultCase::Crashed(sig) => {
                format!("killed by signal {} ({})", sig, signal_name(sig))
            }
            _ => match self.code {
                Some(c) => format!("exit code {} ({})", c, self.case.label()),
                None => "unknown exit status".to_string(),
            },
        };
        match &self.detail {
            Some(d) => format!("{}: {}", how, d),
            None => how,
        }
    }
}

/// Stops a run in which the shim crashes on case after case.
///
/// One crash is a result: the case is reported as `[CRASH]` and the run goes
/// on, because a library that dies on a particular flow is exactly what the
/// tests exist to find. A crash on every consecutive case has a different
/// shape -- a shim linked against a library that has since been rebuilt, a
/// missing shared library, a broken shim binary -- and printing hundreds of
/// identical crash lines helps nobody. `record` reports when the streak reaches
/// the limit so the caller can stop and say so. `PLZN_CRASH_LIMIT` sets the
/// limit; 0 disables the breaker.
pub struct CrashBreaker {
    limit: usize,
    streak: usize,
}

impl CrashBreaker {
    pub const DEFAULT_LIMIT: usize = 3;

    pub fn new(limit: usize) -> Self {
        CrashBreaker { limit, streak: 0 }
    }

    pub fn from_env() -> Self {
        let limit = std::env::var("PLZN_CRASH_LIMIT")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_LIMIT);
        Self::new(limit)
    }

    /// Record one case's shim outcome. Returns true when the run should stop.
    pub fn record(&mut self, crashed: bool) -> bool {
        if crashed {
            self.streak += 1;
        } else {
            self.streak = 0;
        }
        self.limit > 0 && self.streak >= self.limit
    }

    pub fn streak(&self) -> usize {
        self.streak
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

/// Drain the shim's stderr (re-emitting it so the CLI display is unchanged),
/// reap the process, and classify how it ended.
fn collect_outcome(child: &mut SupervisedChild) -> io::Result<ShimOutcome> {
    child.wait()
}

/// One supervisor drains both pipes from spawn onwards and owns reaping. Pipe
/// reads are nonblocking: neither a full pipe nor an inherited descendant pipe
/// can prevent enforcing the process deadline. Retain only the last 256 KiB of
/// each stream, including the shim's final structured result line.
struct SupervisedChild {
    outcome: std::sync::Arc<(Mutex<Option<io::Result<ShimOutcome>>>, std::sync::Condvar)>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    finishing: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SupervisedChild {
    fn spawn(mut child: Child, timeout: Duration) -> io::Result<Self> {
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        #[cfg(unix)]
        fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
            let fd = pipe.as_raw_fd();
            // SAFETY: the owned pipe remains open throughout these fcntl calls.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        fn nonblocking(_pipe: &impl Read) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "shim supervision requires nonblocking pipes",
            ))
        }
        if let Err(error) = nonblocking(&stdout).and_then(|()| nonblocking(&stderr)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let outcome = std::sync::Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = outcome.clone();
        let stop = cancel.clone();
        let finishing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finish = finishing.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + timeout;
            let mut exit_deadline = None;
            let mut out = std::collections::VecDeque::new();
            let mut err = std::collections::VecDeque::new();
            let mut timed_out = false;
            let status = loop {
                drain_pipe(&mut stdout, &mut out);
                drain_pipe(&mut stderr, &mut err);
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(error);
                    }
                    Ok(None) => {}
                }
                if finish.load(std::sync::atomic::Ordering::Relaxed) && exit_deadline.is_none() {
                    exit_deadline = Some(Instant::now() + Duration::from_secs(5));
                }
                if Instant::now() >= deadline
                    || exit_deadline.is_some_and(|end| Instant::now() >= end)
                    || stop.load(std::sync::atomic::Ordering::Relaxed)
                {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait();
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            drain_pipe_after_exit(&mut stdout, &mut out);
            drain_pipe_after_exit(&mut stderr, &mut err);
            let stderr = String::from_utf8_lossy(err.make_contiguous()).into_owned();
            let stdout = String::from_utf8_lossy(out.make_contiguous()).into_owned();
            let value = status.map(|status| ShimOutcome {
                success: !timed_out && status.success(),
                code: status.code(),
                case: if timed_out {
                    ShimResultCase::LocalError
                } else {
                    ShimResultCase::from_status(&status)
                },
                detail: if timed_out {
                    Some(format!(
                        "shim supervisor timeout/cancellation after {:?}",
                        timeout
                    ))
                } else {
                    parse_shim_detail(&stderr)
                },
                stderr,
                stdout,
            });
            *result.0.lock().unwrap() = Some(value);
            result.1.notify_all();
        });
        Ok(Self {
            outcome,
            cancel,
            finishing,
        })
    }

    fn try_wait(&mut self) -> io::Result<Option<()>> {
        Ok(self.outcome.0.lock().unwrap().as_ref().map(|_| ()))
    }

    fn wait(&mut self) -> io::Result<ShimOutcome> {
        self.finishing
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut guard = self.outcome.0.lock().unwrap();
        while guard.is_none() {
            guard = self.outcome.1.wait(guard).unwrap();
        }
        guard.take().unwrap()
    }

    fn kill(&mut self) -> io::Result<()> {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Why one bounded `drain_pipe` pass stopped.
#[derive(Debug, PartialEq, Eq)]
enum DrainStop {
    /// EOF, nothing available right now (EAGAIN), or a read error.
    Empty,
    /// The per-pass read bound; the pipe may still hold data.
    Bound,
}

fn drain_pipe(pipe: &mut impl Read, tail: &mut std::collections::VecDeque<u8>) -> DrainStop {
    let mut buffer = [0u8; 8192];
    // Bound work per tick too, so continuous output cannot starve the watchdog.
    for _ in 0..64 {
        match pipe.read(&mut buffer) {
            Ok(0) => return DrainStop::Empty,
            Ok(n) => {
                tail.extend(&buffer[..n]);
                if tail.len() > 256 * 1024 {
                    tail.drain(..tail.len() - 256 * 1024);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return DrainStop::Empty,
        }
    }
    DrainStop::Bound
}

/// Once the child has been reaped, read until EOF or until the pipe is empty.
/// One tick's bound is not enough here: a pipe can hold more than 64 reads'
/// worth (`F_SETPIPE_SZ` allows up to `fs/pipe-max-size`, 1 MiB by default),
/// and the shim's result line is the last thing in it. Seen on CI as a child
/// that exited 0 with no `PLZN-RESULT` line in its retained stderr. A
/// descendant still holding the write end could feed the pipe indefinitely,
/// so this is capped too, far above any pipe capacity.
fn drain_pipe_after_exit(pipe: &mut impl Read, tail: &mut std::collections::VecDeque<u8>) {
    for _ in 0..64 {
        if drain_pipe(pipe, tail) == DrainStop::Empty {
            return;
        }
    }
}

impl UutFactory for ShimFactory {
    fn open(&self) -> io::Result<Box<dyn UutTransport>> {
        // Bound concurrent live shims (RAII permit released when the returned
        // transport drops) to avoid load-induced flakes at high test concurrency.
        let permit = acquire_shim_permit();
        let open_index = {
            let mut n = self.opens.lock().unwrap();
            let i = *n;
            *n += 1;
            i
        };
        // A multi-connection factory spawned its shim on the first open(); the
        // process dials back for each further session, so only accept.
        let reuse_process = self.connections > 1 && open_index > 0 && open_index < self.connections;
        if reuse_process {
            // The shared shim already exited before its first connection (a
            // refused config, a crash): every later session fails the same way
            // at once, and the recorded outcome stays for wait_shim so the run
            // is classified (SKIP for unsupported_config) rather than timed out.
            if let Some(outcome) = self.early_outcome.lock().unwrap().as_ref() {
                return Err(io::Error::other(format!(
                    "{} exited before connecting: {}",
                    self.name,
                    outcome.describe_exit()
                )));
            }
        } else {
            *self.early_outcome.lock().unwrap() = None;
            // Reap any previous shim before spawning the next one. In a per-
            // connection run each connection is its own shim process; the prior
            // one has finished its connection by the time the runtime asks for
            // the next, so waiting here cleans it up rather than leaking a
            // zombie and overwriting its handle.
            if let Some(mut prev) = self.child.lock().unwrap().take() {
                let _ = prev.wait();
            }
            // Write the config to a temp file the child reads.
            let json = serde_json::to_string_pretty(&self.config)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let mut tmp = tempfile::Builder::new()
                .prefix("plzn-shim-")
                .suffix(".json")
                .tempfile()?;
            tmp.write_all(json.as_bytes())?;
            tmp.flush()?;
            let cfg_path = tmp.path().to_path_buf();

            // Spawn the shim; it dials our listener. Capture stderr so wait_shim can
            // parse the shim's structured `PLZN-RESULT ... detail=<reason>` line (the
            // captured text is re-emitted, so the CLI display is unchanged).
            let child = Command::new(&self.binary)
                .arg("-config")
                .arg(&cfg_path)
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let timeout = std::env::var("PLZN_SHIM_TIMEOUT_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|ms| *ms > 0)
                .map(Duration::from_millis)
                .unwrap_or_else(|| Duration::from_secs(60 * u64::from(self.connections)));
            *self.child.lock().unwrap() = Some(SupervisedChild::spawn(child, timeout)?);
            *self.cfg_file.lock().unwrap() = Some(tmp);
        }

        // Accept with a deadline so a shim that dies on a config error does not
        // hang the runner forever.
        self.listener.set_nonblocking(true)?;
        let deadline = Instant::now() + self.accept_timeout;
        let stream = loop {
            match self.listener.accept() {
                Ok((s, _)) => break s,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // A shim that dies before dialing (crash, missing library,
                    // config error) is reported now, not after the deadline.
                    if let Some(outcome) = self.reap_if_exited()? {
                        let msg = format!(
                            "{} exited before connecting: {}",
                            self.name,
                            outcome.describe_exit()
                        );
                        *self.early_outcome.lock().unwrap() = Some(outcome);
                        return Err(io::Error::other(msg));
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "{} did not connect within {:?}",
                                self.name, self.accept_timeout
                            ),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        // Strip the 8-byte little-endian ShimID prefix before the TLS bytes.
        let mut shim_id = [0u8; 8];
        read_exactly(&stream, &mut shim_id)?;
        *self.connected.lock().unwrap() += 1;

        Ok(Box::new(LimitedTransport {
            inner: Box::new(TcpTransport::from_accepted(stream)?),
            _permit: permit,
        }))
    }

    fn description(&self) -> String {
        format!("{} ({})", self.name, self.addr())
    }
}

fn read_exactly(mut stream: &std::net::TcpStream, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "EOF reading ShimID",
            ));
        }
        filled += n;
    }
    Ok(())
}

impl Drop for ShimFactory {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod crash_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn supervisor_drains_both_pipes_and_bounds_retained_output() {
        let child = Command::new("sh").args(["-c", "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2; printf '\\nPLZN-RESULT case=ok detail=drained\\n' >&2"])
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let start = Instant::now();
        let result = SupervisedChild::spawn(child, Duration::from_secs(5))
            .unwrap()
            .wait()
            .unwrap();
        // The retained streams are mostly NUL bytes, so on failure describe
        // them instead of dumping them: this test has failed on CI with the
        // child exiting 0 but no result line in the retained stderr.
        let stderr = result.stderr.as_bytes();
        let summary = format!(
            "after {:?}: code={:?} case={:?} stdout={} bytes stderr={} bytes, stderr tail: {}",
            start.elapsed(),
            result.code,
            result.case,
            result.stdout.len(),
            stderr.len(),
            stderr[stderr.len().saturating_sub(96)..].escape_ascii()
        );
        assert!(result.success, "{summary}");
        assert_eq!(result.detail.as_deref(), Some("drained"), "{summary}");
        assert!(result.stdout.len() <= 256 * 1024, "{summary}");
        assert!(result.stderr.len() <= 256 * 1024, "{summary}");
    }

    // A pipe grown past one drain pass (64 x 8 KiB) with the result line at
    // its end: the post-exit drain must read on to EOF, where one bounded pass
    // stops short. The in-process pipe makes the "everything already written
    // when the child is reaped" state deterministic.
    #[cfg(target_os = "linux")]
    #[test]
    fn post_exit_drain_reads_past_one_pass_of_a_large_pipe() {
        use std::io::Write;
        use std::os::fd::FromRawFd;

        let mut fds = [0; 2];
        // SAFETY: `fds` is a valid two-element out-array; both descriptors are
        // owned by the `File`s below.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: freshly created, unowned descriptors.
        let (mut reader, mut writer) = unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        };
        // SAFETY: plain fcntl calls on open descriptors this test owns.
        if unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, 1 << 20) } < 0 {
            eprintln!("SKIP: cannot grow the pipe to 1 MiB");
            return;
        }
        // SAFETY: as above; the supervisor reads its pipes nonblocking too.
        assert!(unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) } >= 0);

        // Fill the pipe short of its capacity so the writer never blocks, then
        // close it: everything is in the pipe before the first read.
        let zeros = vec![0u8; (1 << 20) - 128];
        writer.write_all(&zeros).unwrap();
        writer
            .write_all(b"\nPLZN-RESULT case=ok detail=drained\n")
            .unwrap();
        drop(writer);

        let mut tail = std::collections::VecDeque::new();
        assert_eq!(drain_pipe(&mut reader, &mut tail), DrainStop::Bound);
        assert_eq!(
            parse_shim_detail(&String::from_utf8_lossy(tail.make_contiguous())),
            None
        );
        drain_pipe_after_exit(&mut reader, &mut tail);
        assert!(tail.len() <= 256 * 1024);
        assert_eq!(
            parse_shim_detail(&String::from_utf8_lossy(tail.make_contiguous())).as_deref(),
            Some("drained")
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_terminates_a_peer_that_never_exits() {
        let child = Command::new("sleep")
            .arg("10")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let result = SupervisedChild::spawn(child, Duration::from_millis(50))
            .unwrap()
            .wait()
            .unwrap();
        assert!(!result.success);
        assert_eq!(result.case, ShimResultCase::LocalError);
        assert!(result.detail.unwrap().contains("timeout"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_does_not_wait_for_descendants_holding_pipes() {
        let child = Command::new("sh")
            .args(["-c", "sleep 1 & exit 0"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        assert!(
            SupervisedChild::spawn(child, Duration::from_secs(2))
                .unwrap()
                .wait()
                .unwrap()
                .success
        );
        assert!(start.elapsed() < Duration::from_millis(800));
    }

    #[cfg(unix)]
    fn status(raw: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(raw)
    }

    #[cfg(unix)]
    #[test]
    fn signal_death_classifies_as_crash() {
        // Raw wait status: low 7 bits = terminating signal, no exit code.
        assert_eq!(
            ShimResultCase::from_status(&status(11)),
            ShimResultCase::Crashed(11)
        );
        assert_eq!(
            ShimResultCase::from_status(&status(6)),
            ShimResultCase::Crashed(6)
        );
        // Normal exit: code in bits 8..16.
        assert_eq!(
            ShimResultCase::from_status(&status(10 << 8)),
            ShimResultCase::LocalError
        );
        assert_eq!(ShimResultCase::from_status(&status(0)), ShimResultCase::Ok);
    }

    /// A multi-session factory whose shim exits before its first connection
    /// (a refused config) must fail every later open() at once and still hand
    /// the recorded outcome to wait_shim(), so the run is SKIPped rather than
    /// timed out session by session (rustls + a DTLS `session` block).
    #[cfg(unix)]
    #[test]
    fn multi_session_factory_keeps_an_early_unsupported_exit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("stub_shim");
        std::fs::write(
            &stub,
            "#!/bin/sh\necho 'PLZN-RESULT case=unsupported_config detail=stub: no DTLS' >&2\nexit 16\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let factory = ShimFactory {
            name: "rustls".into(),
            binary: stub,
            config: ShimConfig::default(),
            listener,
            port,
            accept_timeout: Duration::from_secs(5),
            child: Mutex::new(None),
            cfg_file: Mutex::new(None),
            early_outcome: Mutex::new(None),
            connections: 2,
            opens: Mutex::new(0),
            connected: Mutex::new(0),
        };
        let first = factory.open().err().expect("the stub exits before dialing");
        assert!(
            first.to_string().contains("exited before connecting"),
            "{first}"
        );
        let started = Instant::now();
        let second = factory.open().err().expect("the shared shim is gone");
        assert!(
            second.to_string().contains("exited before connecting"),
            "{second}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the second open must not wait out the accept deadline"
        );
        let outcome = factory
            .wait_shim()
            .expect("the early outcome is kept for wait_shim");
        assert!(outcome.is_unsupported_config());
        assert_eq!(outcome.detail.as_deref(), Some("stub: no DTLS"));
    }

    #[test]
    fn unsupported_config_exit_code_maps_to_its_case() {
        #[cfg(unix)]
        {
            assert_eq!(
                ShimResultCase::from_status(&status(16 << 8)),
                ShimResultCase::UnsupportedConfig
            );
        }
        let o = ShimOutcome {
            success: false,
            code: Some(16),
            case: ShimResultCase::UnsupportedConfig,
            detail: Some("uut.extended_master_secret: only allow/off".into()),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert!(o.is_unsupported_config());
        assert!(!o.is_crash());
        assert_eq!(o.case.label(), "unsupported_config");
    }

    fn lower_one(src: &str) -> crate::ir::Program {
        let tokens = crate::lex::lex(src).expect("lex");
        let file = crate::parse::parse(&tokens).expect("parse");
        crate::lower::lower(&file.tests[0])
            .expect("lower")
            .remove(0)
    }

    #[test]
    fn requires_carries_the_offered_suites_and_groups() {
        let p = lower_one(
            r#"
plzn tls "req/cbc-p521" {
  chain: [rsa_2048]
  uut server {
    versions: [tls12],
  }
  peer { capabilities: [ecdhe_rsa, aes128_cbc_sha, secp521r1] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}

"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("rustls")).unwrap();
        assert_eq!(cfg.requires.any_suite, vec![0xc013]);
        assert_eq!(cfg.requires.any_group, vec![0x0019]);
        assert!(!cfg.expect.handshake_abandoned);
        assert!(cfg.expect.handshake_error.is_none());
    }

    #[test]
    fn explicit_uut_curves_override_a_group_matrix_requirement() {
        let p = lower_one(
            r#"
plzn tls "req/unsupported-offered-group" {
  chain: [default]
  uut server {
    versions: [tls13],
    curves: [secp256r1],
  }
  matrix { group in [0x0001] }
  flow handshake {
    send ClientHello {
      +ext supported_groups = [$group, secp256r1]
    }
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("boringssl")).unwrap();
        assert_eq!(cfg.curves, vec![0x0017]);
        assert_eq!(cfg.requires.any_group, vec![0x0017]);
    }

    #[test]
    fn versions_list_enables_a_range_while_first_selects_the_peer_driver() {
        let p = lower_one(
            r#"
plzn tls "req/tls12-peer-against-12-13-uut" {
  chain: [default]
  uut server {
    versions: [tls12, tls13],
  }
  peer { capabilities: [ecdhe] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        assert_eq!(p.version, crate::tls::record::TlsVersion::Tls12);
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("botan")).unwrap();
        assert_eq!(cfg.min_version, Some(0x0303));
        assert_eq!(cfg.max_version, Some(0x0304));
        assert_eq!(cfg.expect.version, Some(0x0303));
    }

    #[test]
    fn dtls12_pins_the_shim_to_dtls12() {
        let p = lower_one(
            r#"
plzn tls "req/dtls12" {
  chain: [default]
  uut server { versions: [dtls12] }
  flow handshake {}
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("openssl")).unwrap();
        assert_eq!(cfg.min_version, Some(0xfefd));
        assert_eq!(cfg.max_version, Some(0xfefd));
        // DTLS version self-checking remains in the protocol driver; these
        // fields are the policy bound consumed by the library shim.
        assert_eq!(cfg.expect.version, None);
    }

    #[test]
    fn dtls13_pins_the_shim_to_dtls13() {
        let p = lower_one(
            r#"
plzn tls "req/dtls13" {
  chain: [default]
  uut server { versions: [dtls13] }
  flow handshake {}
  expect ok
}
"#,
        );
        assert_eq!(p.version, crate::tls::record::TlsVersion::Tls13);
        assert_eq!(p.protocol, crate::ir::Protocol::Dtls);
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("boringssl")).unwrap();
        assert_eq!(cfg.protocol, "dtls");
        assert_eq!(cfg.min_version, Some(0xfefc));
        assert_eq!(cfg.max_version, Some(0xfefc));
        assert_eq!(cfg.expect.version, None);
    }

    #[test]
    fn abandoned_flow_and_per_backend_override_reach_the_shim() {
        let p = lower_one(
            r#"
plzn tls "req/abandoned" {
  chain: [default]
  uut server {
    versions: [tls12]
  }
  flow handshake after recv ServerHelloDone {
    close
  }
  expect ok
  expect alert fatal/decode_error if botan
}
"#,
        );
        // rustls: base `ok` on a flow without plzn's Finished = abandoned.
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("rustls")).unwrap();
        assert!(cfg.expect.handshake_abandoned);
        assert!(cfg.expect.handshake_error.is_none());
        // botan: the override expects a failure, so the shim does too.
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("botan")).unwrap();
        assert!(!cfg.expect.handshake_abandoned);
        assert_eq!(cfg.expect.handshake_error.as_deref(), Some(""));
        // No backend: the base expectation.
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), None).unwrap();
        assert!(cfg.expect.handshake_abandoned);
    }

    #[test]
    fn client_cert_requirement_survives_a_uut_block() {
        // Client-auth UUT policy plus another UUT knob must still require the
        // certificate (a regression once cleared this while merging).
        let p = lower_one(
            r#"
plzn tls "req/client-cert-with-uut" {
  chain: [default]
  uut server {
    versions: [tls12]
    verify_prefs: [ecdsa_secp256r1_sha256]
    require_client_cert: true
  }
  peer { capabilities: [ecdhe] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("botan")).unwrap();
        assert!(cfg.verify.require_client_cert);
        assert!(!cfg.verify.request_client_cert);
        // An explicit `request_client_cert` is the UUT's policy: request only.
        let p = lower_one(
            r#"
plzn tls "req/client-cert-requested" {
  chain: [default]
  uut server {
    versions: [tls12]
    request_client_cert: true
  }
  peer { capabilities: [ecdhe] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("botan")).unwrap();
        assert!(!cfg.verify.require_client_cert);
        assert!(cfg.verify.request_client_cert);
    }

    #[test]
    fn peer_certificate_compression_offer_does_not_enable_the_uut() {
        let p = lower_one(
            r#"
plzn tls "req/peer-compression-only" {
  chain: [default]
  uut server { versions: [tls13] }
  peer { capabilities: [compress_cert] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("openssl")).unwrap();
        assert!(!cfg.compress_certificate);

        let p = lower_one(
            r#"
plzn tls "req/uut-compression" {
  chain: [default]
  uut server { versions: [tls13], compress_certificate: true }
  peer { capabilities: [compress_cert] }
  flow handshake {
    send AppData
    recv AppData
  }
  expect ok
}
"#,
        );
        let cfg = ShimConfig::for_program(&p, Some("c"), Some("k"), Some("openssl")).unwrap();
        assert!(cfg.compress_certificate);
    }

    #[test]
    fn signal_names() {
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(6), "SIGABRT");
        assert_eq!(signal_name(99), "unknown signal");
    }

    #[test]
    fn describe_exit_names_signal_and_detail() {
        let crash = ShimOutcome {
            success: false,
            code: None,
            case: ShimResultCase::Crashed(11),
            detail: None,
            stderr: String::new(),
            stdout: String::new(),
        };
        assert!(crash.is_crash());
        assert_eq!(crash.describe_exit(), "killed by signal 11 (SIGSEGV)");
        let early = ShimOutcome {
            success: false,
            code: Some(10),
            case: ShimResultCase::LocalError,
            detail: Some("rustls does not support DTLS".into()),
            stderr: String::new(),
            stdout: String::new(),
        };
        assert!(!early.is_crash());
        assert_eq!(
            early.describe_exit(),
            "exit code 10 (local_error): rustls does not support DTLS"
        );
    }

    #[test]
    fn breaker_trips_only_on_consecutive_crashes() {
        let mut b = CrashBreaker::new(3);
        assert!(!b.record(true));
        assert!(!b.record(true));
        assert!(!b.record(false)); // streak reset by a non-crash
        assert_eq!(b.streak(), 0);
        assert!(!b.record(true));
        assert!(!b.record(true));
        assert!(b.record(true)); // third consecutive crash
        assert_eq!(b.streak(), 3);
    }

    #[test]
    fn breaker_limit_zero_never_trips() {
        let mut b = CrashBreaker::new(0);
        for _ in 0..10 {
            assert!(!b.record(true));
        }
        assert_eq!(b.limit(), 0);
    }
}

#[cfg(test)]
mod external_shim_tests {
    use super::*;

    #[test]
    fn expectation_sidecar_accepts_shorthand_and_alert_sets() {
        let set = ShimExpectationSet::from_json(
            r#"{
              "schema_version": 1,
              "overrides": {
                "one": "alert fatal/{unknown_ca,bad_certificate,0x2e}",
                "two": { "expect": "close", "xfail": "known defect" },
                "three": "any { ok, alert fatal/{protocol_version,decode_error}, close }"
              }
            }"#,
        )
        .unwrap();
        assert_eq!(
            set.get("one").unwrap().expect.as_ref().unwrap().describe(),
            "alert fatal/{unknown_ca,bad_certificate,certificate_unknown}"
        );
        assert_eq!(
            set.get("two").unwrap().expect.as_ref().unwrap().describe(),
            "close"
        );
        assert_eq!(
            set.get("two").unwrap().xfail.as_deref(),
            Some("known defect")
        );
        assert_eq!(
            set.get("three")
                .unwrap()
                .expect
                .as_ref()
                .unwrap()
                .describe(),
            "any { ok, alert fatal/{protocol_version,decode_error}, close }"
        );
    }

    #[test]
    fn expectation_sidecar_matches_patterns_after_exact_ids() {
        let set = ShimExpectationSet::from_json(
            r#"{
              "schema_version": 1,
              "overrides": {
                "matrix/case[n=1]": "ok"
              },
              "patterns": [
                { "pattern": "matrix/case*", "expect": "alert fatal" }
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            set.get("matrix/case[n=1]")
                .unwrap()
                .expect
                .as_ref()
                .unwrap()
                .describe(),
            "ok"
        );
        assert_eq!(
            set.get("matrix/case[n=2]")
                .unwrap()
                .expect
                .as_ref()
                .unwrap()
                .describe(),
            "alert fatal"
        );
        assert!(set.get("other/case").is_none());
    }

    #[test]
    fn expectation_sidecar_rejects_ambiguous_disposition() {
        let err = ShimExpectationSet::from_json(
            r#"{
              "schema_version": 1,
              "overrides": { "one": { "skip": "no", "xfail": "broken" } }
            }"#,
        )
        .unwrap_err();
        assert!(err.contains("cannot specify both skip and xfail"), "{err}");
    }

    #[test]
    fn sidecar_expectation_has_backend_precedence_and_reaches_config() {
        let source = r#"
plzn tls "external/expect" {
  chain: [default]
  uut server { versions: [tls12] }
  flow handshake {}
  expect close
  expect reset if project_tls
}
"#;
        let tokens = crate::lex::lex(source).unwrap();
        let file = crate::parse::parse(&tokens).unwrap();
        let mut program = crate::lower::lower(&file.tests[0]).unwrap().remove(0);
        let set = ShimExpectationSet::from_json(
            r#"{
              "schema_version": 1,
              "overrides": {
                "external/expect": "alert fatal/handshake_failure"
              }
            }"#,
        )
        .unwrap();
        set.apply(&mut program, "project_tls");
        assert_eq!(
            program.expect_overrides[0].1.describe(),
            "alert fatal/handshake_failure"
        );
        let cfg = ShimConfig::for_program(&program, Some("cert"), Some("key"), Some("project_tls"))
            .unwrap();
        assert_eq!(cfg.expect.handshake_error.as_deref(), Some(""));
        assert!(cfg.expect.version.is_none());
    }
}
