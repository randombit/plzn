/*
 * Public C++20 interface to libplzn-shim.
 *
 * Include this header and link libplzn-shim.a for configuration parsing,
 * runner transport, result reporting, and the application-data responder.
 */

#ifndef PLZN_SHIM_H_
#define PLZN_SHIM_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace plzn {

/*
 * Self-contained JSON parser for the plzn shim config library.
 *
 * No external dependencies. Supports the JSON subset the shim config needs:
 * objects, arrays, strings (with \" \\ \/ \b \f \n \r \t \uXXXX escapes),
 * numbers (parsed as double and as int64 where integral), booleans, null.
 *
 * This is a test-tooling parser, not a hardened one, but it rejects malformed
 * input with a message + byte offset rather than misparsing it.
 */

class JsonValue;
using JsonArray = std::vector<JsonValue>;
using JsonObject = std::map<std::string, JsonValue>;

enum class JsonType { Null, Bool, Number, String, Array, Object };

/** Thrown on malformed JSON; carries a message and byte offset. */
class JsonError final : public std::runtime_error {
   public:
      JsonError(const std::string& msg, size_t offset) :
            std::runtime_error(msg + " at offset " + std::to_string(offset)), m_offset(offset) {}

      size_t offset() const { return m_offset; }

   private:
      size_t m_offset;
};

/**
 * A parsed JSON value. Copyable. Accessors that assume a type throw JsonError
 * if the actual type does not match, so callers can rely on them after a
 * type() check or accept the exception as a config error.
 */
class JsonValue final {
   public:
      JsonValue() : m_type(JsonType::Null) {}

      static JsonValue parse(const std::string& text);

      JsonType type() const { return m_type; }

      bool is_null() const { return m_type == JsonType::Null; }

      bool is_object() const { return m_type == JsonType::Object; }
      bool is_string() const { return m_type == JsonType::String; }

      bool is_array() const { return m_type == JsonType::Array; }

      bool as_bool() const;
      double as_number() const;
      int64_t as_int() const;
      const std::string& as_string() const;
      const JsonArray& as_array() const;
      const JsonObject& as_object() const;

      /** Object member lookup; nullptr if absent or this is not an object. */
      const JsonValue* find(const std::string& key) const;

      bool contains(const std::string& key) const { return find(key) != nullptr; }

      // Typed member accessors with defaults. They throw JsonError if the member
      // is present but the wrong type; return the default only when absent.
      std::string string_or(const std::string& key, const std::string& def) const;
      int64_t int_or(const std::string& key, int64_t def) const;
      bool bool_or(const std::string& key, bool def) const;

      // Constructors used by the parser.
      static JsonValue make_bool(bool b);
      static JsonValue make_number(double d);
      static JsonValue make_string(std::string s);
      static JsonValue make_array(JsonArray a);
      static JsonValue make_object(JsonObject o);

   private:
      JsonType m_type;
      bool m_bool = false;
      double m_number = 0.0;
      std::string m_string;
      std::shared_ptr<JsonArray> m_array;
      std::shared_ptr<JsonObject> m_object;
};

/*
 * Typed shim configuration for the plzn interop shims.
 *
 * The runner (plzn) writes a JSON config file per test; each shim parses it
 * into this struct via ShimConfig::from_file / from_json. All C++ shims consume
 * the same struct, so the control surface is defined here once. Fields mirror
 * the BoGo flag vocabulary where a direct analogue exists, but are grouped into
 * sub-structs instead of a flat flag list.
 *
 * Wire integers (versions, cipher/curve/sig-alg IDs) are the on-the-wire codes:
 *   TLS 1.0 = 0x0301, TLS 1.1 = 0x0302, TLS 1.2 = 0x0303 = 771,
 *   TLS 1.3 = 0x0304 = 772, DTLS 1.2 = 0xFEFD = 65277.
 */

enum class Role { Client, Server };

enum class Protocol { Tls, Dtls };

/** Where the shim dials back to reach the runner. */
struct RunnerEndpoint {
      std::string host = "127.0.0.1";
      uint16_t port = 0;
      bool ipv6 = false;
};

/** Certificate / key / trust material. Paths to PEM files on disk. */
/** One certificate chain with its private key. `key_type` is the runner's
 * name for the leaf key (rsa_2048, rsa_pss, ecdsa_p256, ecdsa_p384,
 * ecdsa_p521, ed25519); empty when the runner did not say (legacy single
 * cert_file / key_file form), in which case the shim inspects the key. */
struct Chain {
      std::string cert_file;
      std::string key_file;
      std::string key_type;
};

struct Credentials {
      std::string cert_file;    // server cert chain, or client cert (== chains[0] when chains are given)
      std::string key_file;     // private key for cert_file
      std::string trust_file;   // trust anchors for peer verification
      std::string ocsp_file;    // DER OCSP response to staple (server)
      std::string second_cert_file;  // legacy: optional 2nd cert of a different key type
      std::string second_key_file;   // private key for second_cert_file
      // The chains the shim SERVES (server role). Filled from `credentials.chains`
      // when the runner sends it (an explicit empty array = serve no chain, e.g.
      // PSK-only), else derived from cert_file / key_file (+ the legacy second
      // pair), so every shim reads chains only.
      std::vector<Chain> chains;
      // The client-auth credentials the shim PRESENTS (client role), from
      // `credentials.client_chains`; else derived from cert_file / key_file.
      std::vector<Chain> client_chains;
};

/** Normalize a key-type name to the runner's spelling: `--cert` names
 * (rsa, ecdsa, ecdsa-p384, rsa-pss, ...) and the chain names
 * (rsa_2048, ecdsa_p256, ...) both map onto the latter. */
std::string normalize_key_type(std::string_view name);

/** External PSK (TLS 1.3 psk_ke / psk_dhe_ke, or TLS 1.2 PSK suites). */
struct PskConfig {
      std::string identity;
      std::string secret_hex;   // raw PSK bytes, hex-encoded
      bool present = false;
};

/** Peer-verification and client-auth policy. */
struct VerifyConfig {
      bool verify_peer = false;            // require + verify peer cert
      bool require_client_cert = false;    // server: demand a client cert
      bool request_client_cert = false;    // server: request but don't require
      bool fail = false;                   // force verification to fail
      std::optional<std::string> expect_peer_subject_cn;
};

/** ALPN advertisement / selection / expectation. */
struct AlpnConfig {
      std::vector<std::string> advertise;  // client offers these
      std::string select;                  // server selects this
      std::vector<std::string> select_from;  // server-supported protocols, in preference order
      std::optional<std::string> expect;   // assert negotiated protocol
      bool decline = false;                // server declines ALPN
};

enum class AppDataMode {
      Echo,          // answer plzn's framed random-data request (default)
      ShimWrites,    // shim sends app_data_send then closes
      ShutdownOnly,  // shim closes immediately after handshake
};

struct AppDataConfig {
      AppDataMode mode = AppDataMode::Echo;
      std::string send;         // bytes for ShimWrites mode
      bool shim_shuts_down = false;
};

struct KeyMaterialConfig {
      uint32_t connection = 0;
      std::string kind;       // "exporter" | "tls_unique"
      std::string label;
      std::optional<std::string> context;
      uint32_t length = 0;
};

/**
 * Post-handshake assertions the shim self-checks. A mismatch makes the shim
 * exit non-zero with a diagnostic. Absent optionals are not checked.
 */
struct Expectations {
      std::optional<uint16_t> version;                 // negotiated protocol version
      std::optional<uint16_t> cipher;                  // negotiated cipher suite
      std::optional<uint16_t> curve;                   // negotiated group
      std::optional<uint16_t> peer_signature_algorithm;
      std::optional<std::string> alpn;                 // negotiated ALPN
      std::optional<bool> resumed;                     // session was resumed
      std::optional<bool> hrr;                         // HelloRetryRequest occurred
      std::optional<bool> secure_renegotiation;
      std::optional<std::string> peer_subject_cn;
      // If set, the handshake is expected to FAIL and the resulting canonical
      // error code must match this (see ShimResult below). Empty string means
      // "expected to fail with any error".
      std::optional<std::string> handshake_error;
      // plzn abandons the handshake on purpose (closes after the server's
      // flight, or probes and stops). Any outcome of the abrupt close --
      // success or a handshake failure -- is acceptable; do not self-check it.
      bool handshake_abandoned = false;
};

/** The full parsed config. */
struct ConnectionEarlyData {
      uint32_t send = 0;
      uint32_t expect = 0;
      std::optional<bool> accepted;
};

struct ShimConfig {
      Role role = Role::Server;
      Protocol protocol = Protocol::Tls;
      RunnerEndpoint runner;
      uint64_t shim_id = 0;
      uint32_t resume_count = 0;

      std::optional<uint16_t> min_version;
      std::optional<uint16_t> max_version;
      std::vector<uint16_t> connection_versions;
      std::vector<ConnectionEarlyData> connection_early_data;

      /** Pin a shim client to the version plzn selected for this connection. */
      ShimConfig for_connection(uint32_t index) const {
         ShimConfig selected = *this;
         if(!selected.is_server() && index < connection_versions.size()) {
            selected.min_version = connection_versions[index];
            selected.max_version = connection_versions[index];
         }
         if(index < connection_early_data.size()) {
            const auto& early = connection_early_data[index];
            selected.early_data_send = early.send;
            selected.early_data_expect = early.expect;
            selected.expect_early_data_accepted = early.accepted;
         }
         return selected;
      }

      // Cipher/group/sig-alg preference lists. Cipher suites and groups are
      // 16-bit wire IDs; the shim maps them to library-specific selectors.
      std::vector<uint16_t> cipher_suites;
      std::vector<uint16_t> curves;
      std::vector<uint16_t> signing_prefs;     // sig-alg IDs we will sign with
      std::vector<uint16_t> verify_prefs;      // sig-alg IDs we accept from peer

      // What plzn will offer (client role) or select from (server role): the
      // suites and groups its `cfg` line produces. Any-of: the shim refuses the
      // case (unsupported_config) when its library implements none of them, so
      // the runner SKIPs instead of failing on a capability gap.
      std::vector<uint16_t> requires_any_suite;
      std::vector<uint16_t> requires_any_group;

      std::string server_name;                 // SNI to send (client) / expect (server)
      std::optional<std::string> expect_server_name;

      Credentials credentials;
      PskConfig psk;
      VerifyConfig verify;
      AlpnConfig alpn;
      // RFC 5764 DTLS-SRTP policy and post-handshake expectation.
      std::vector<uint16_t> srtp_profiles;
      std::optional<uint16_t> expect_srtp_profile;
      AppDataConfig app_data;
      std::vector<KeyMaterialConfig> key_material;
      Expectations expect;

      // DTLS knobs.
      uint32_t mtu = 1500;
      uint32_t initial_timeout_ms = 400;
      // Botan DTLS policy (unset = the library default): retransmission
      // budget, maximum timer, cookie exchange, epoch-0 restart, bound on
      // HelloVerifyRequests a client answers.
      std::optional<uint32_t> dtls_max_retransmissions;
      std::optional<uint32_t> dtls_max_timeout_ms;
      std::optional<bool> dtls_require_cookie;
      std::optional<bool> dtls_epoch0_restart;
      std::optional<uint32_t> dtls_max_hello_verify_requests;

      // The runner's `requires` block: the flow advances the DTLS retransmit
      // clock, so the library must run its timer on the shim's virtual clock.
      bool requires_virtual_clock = false;
      // The runner will rescale a live DTLS timer (`set_timeout`). Libraries
      // without such an API refuse the case before dialing.
      bool requires_dynamic_timeout = false;
      // T3: the key type of the certificate plzn's SERVER presents (`--cert`
      // name), so a client whose library cannot verify it refuses the case.
      // The key types plzn's SERVER may present (any of them); a shim client
      // refuses the case only when its library can verify none. From
      // `requires.server_key`, a string or an array of strings.
      std::vector<std::string> requires_server_keys;

      // Renegotiation (TLS 1.2).
      bool renegotiate_freely = false;
      uint32_t renegotiate_count = 0;

      // Key update after handshake (TLS 1.3).
      bool key_update = false;

      // RFC 7250 raw public keys: server presents a bare SubjectPublicKeyInfo instead of
      // an X.509 certificate when the peer negotiates server_certificate_type=RawPublicKey.
      bool raw_public_key = false;
      std::vector<uint8_t> server_certificate_types;
      std::vector<uint8_t> client_certificate_types;

      // RFC 8879 certificate compression: server compresses its Certificate (zlib) when the
      // peer advertises the compress_certificate extension.
      bool compress_certificate = false;

      // Session ticket behaviour.
      bool no_ticket = false;

      // Local-policy knobs from the .plzn `uut { ... }` block (shims/DESIGN.md,
      // "Policy controls"). Absent = the library's capability posture. A shim
      // that cannot honour a set knob must call plzn::report_unsupported before
      // dialing, so the runner SKIPs the case instead of passing it vacuously.
      std::optional<bool> server_preference;              // choose suites/groups by our order, not the peer's
      std::optional<std::string> renegotiation;           // "none" | "client" | "server" | "both"
      std::optional<uint32_t> session_tickets;
      std::optional<uint32_t> max_early_data;
      uint32_t early_data_send = 0;
      uint32_t early_data_expect = 0;
      std::optional<bool> expect_early_data_accepted;
      std::optional<uint32_t> max_cert_list;              // maximum encoded peer chain size
      std::optional<uint32_t> record_size_limit;           // RFC 8449 receive limit to advertise
      std::optional<uint32_t> records_per_traffic_key;  // automatic TLS 1.3 KeyUpdate after N records            // tickets per handshake; 0 = no resumption at all
      std::optional<std::string> extended_master_secret;  // "require" | "allow" | "off"
      std::optional<bool> encrypt_then_mac;
      std::optional<bool> middlebox_compat;
      // Botan `minimum_key_update_interval_ms`: a peer KeyUpdate arriving sooner
      // than this after the previous one is rejected; 0 = no rate limit (the
      // other libraries' behaviour, so they honour 0 and refuse the rest).
      std::optional<uint32_t> min_key_update_interval_ms;
      // Client role: start one renegotiation once application data has flowed.
      bool renegotiate_after_handshake = false;
      // T6: server role: request post-handshake client authentication (RFC
      // 8446 4.6.2) as soon as the handshake completes (the client must have
      // offered post_handshake_auth). The OCSP staple lives in
      // credentials.ocsp_file.
      std::string post_handshake_auth;  // "" | "request" | "require"
      // T5, server role: send a HelloRequest once application data has flowed,
      // and require a client certificate on that renegotiation.
      bool hello_request_after_app_data = false;
      bool require_client_cert_on_renegotiation = false;
      // Server role: half-RTT application records (one per entry), written
      // after our Finished and before the client's (TLS 1.3).
      std::vector<std::string> half_rtt_data;

      // The raw parsed JSON, retained so shims can read knobs added to the
      // schema before this struct grows a typed field for them.
      JsonValue raw;

      static ShimConfig from_json(const JsonValue& root);
      static ShimConfig from_file(const std::string& path);

      bool is_server() const { return role == Role::Server; }

      bool is_dtls() const { return protocol == Protocol::Dtls; }

      // plzn always emits explicit DTLS version bounds. DTLS code points count
      // down, so a range containing 1.3 may spell 0xFEFC in either bound.
      // Keep this shared so a DTLS-1.2-only shim cannot silently ignore the
      // unknown bound and negotiate 1.2 instead.
      bool requests_dtls13() const {
         return is_dtls() && (min_version == 0xFEFC || max_version == 0xFEFC);
      }
};

/*
 * Socket helper shared by the plzn shims.
 *
 * A shim dials the runner (which is listening), writes its 8-byte ShimID, then
 * exchanges bytes. For TLS the payload is raw record bytes. For DTLS the runner
 * frames datagrams with one-byte opcodes ('P' packet, 'T' advance-clock, 'E'
 * timer assertion, 'U' timer update, 'C' control command); see DESIGN.md. This class provides the raw byte transport plus the DTLS framing
 * decode/encode shared by the shims.
 *
 * Adapted from Botan's bogo_shim Shim_Socket (same wire protocol).
 */

class ShimSocketError final : public std::runtime_error {
   public:
      explicit ShimSocketError(const std::string& msg) : std::runtime_error(msg) {}
};

/** A DTLS control event read off the framed stream. */
enum class DtlsOpcode {
      Packet,        // a datagram follows in `packet`
      AdvanceClock,  // advance the retransmit clock by `nanos`
      ExpectTimeout, // assert next timeout == `nanos` (UINT64_MAX = none)
      UpdateTimeout, // rescale the live timeout to `millis`
      Control,       // apply the runtime command in `command`
      Eof,           // socket closed
};

/** 'C' frame commands (the runner's `tls::dtls_transport::control`). */
enum class DtlsControl : uint8_t {
      // The server rotates its cookie secret: cookies issued so far stop
      // verifying (RFC 6347 4.2.1). The `rotate_cookie_secret` step.
      RotateCookieSecret = 1,
};

struct DtlsEvent {
      DtlsOpcode opcode;
      std::vector<uint8_t> packet;  // valid when opcode == Packet
      uint64_t nanos = 0;           // valid when opcode == AdvanceClock
      uint32_t millis = 0;          // valid when opcode == UpdateTimeout
      uint8_t command = 0;          // valid when opcode == Control
};

class ShimSocket final {
   public:
      ShimSocket(const std::string& host, uint16_t port, bool ipv6);
      ~ShimSocket();

      ShimSocket(const ShimSocket&) = delete;
      ShimSocket& operator=(const ShimSocket&) = delete;
      ShimSocket(ShimSocket&&) = delete;
      ShimSocket& operator=(ShimSocket&&) = delete;

      /** Write the 8-byte little-endian ShimID; call once, first. */
      void write_shim_id(uint64_t shim_id);

      /**
       * Underlying socket fd. Ownership stays with ShimSocket (it closes on
       * destruction). Used by shims whose library drives its own record IO over
       * an fd (e.g. OpenSSL via SSL_set_fd) after the ShimID has been written.
       */
      int fd() const { return m_socket; }

      // Raw byte IO (TLS payload).
      void write(const uint8_t* buf, size_t len);
      size_t read(uint8_t* buf, size_t len);
      void read_exactly(uint8_t* buf, size_t len);

      // DTLS framing.
      DtlsEvent read_dtls_event();
      void write_dtls_packet(const uint8_t* buf, size_t len);
      void write_dtls_ack(uint8_t opcode);
      void write_dtls_timeout_expired();

   private:
      int m_socket;
};

/*
 * Canonical error taxonomy for the plzn shims.
 *
 * plzn's own TLS stack observes any alert the shim's library emits directly on
 * the wire, so cross-implementation assertions key off the standard TLS alert
 * registry rather than library-specific strings. This module provides the alert
 * name table (RFC 8446 / RFC 5246 alert descriptions) plus a tiny result
 * reporter the shims use to signal pass/fail with a canonical reason.
 *
 * Each shim still maps its own library's error strings to these canonical names
 * (that mapping is library-specific and lives in the shim itself); this header
 * defines the shared vocabulary both mappings target.
 */

/** A failed configured assertion, distinct from local/setup exceptions. */
struct ShimExpectationError : std::runtime_error { using std::runtime_error::runtime_error; };

/** Human-readable name for a TLS alert description code, or "alert_<n>". */
std::string alert_name(uint8_t description);

/** Alert description code for a name, or 255 if unknown. */
uint8_t alert_code(const std::string& name);

/**
 * Structured result "case" a shim exits with, so the runner learns WHICH failure
 * path was taken (BoGo-style) rather than inferring only from the wire alert. The
 * enum value IS the process exit code, so the runner reads it from wait status.
 * plzn still observes the peer's TLS alert directly on the wire; this case
 * complements that with the shim's own classification of the outcome.
 */
enum class ShimResult : int {
   Ok = 0,                    // flow completed and all expectations matched
   Failure = 1,               // generic/unspecified failure (legacy)
   LocalError = 10,           // shim setup / config / internal error (not a protocol outcome)
   IoError = 11,              // socket / transport error
   HandshakeFailed = 12,      // the TLS/DTLS handshake did not complete (library reported an error)
   ExpectationMismatch = 13,  // a configured expectation (version/cipher/alpn/sni/resumed) did not match
   UnexpectedSuccess = 14,    // the flow was expected to fail but it completed
   UnsupportedConfig = 16,    // the library cannot apply a configured policy knob; the runner SKIPs
};

/** Canonical lowercase name for a result case (for the structured stderr line). */
std::string result_case_name(ShimResult result);

/**
 * Report the shim's outcome and exit. Emits a machine-readable line
 * "PLZN-RESULT case=<name> detail=<detail>" to stderr and exits with the case's
 * numeric code, which the runner reads from the child's wait status.
 */
[[noreturn]] void report_result(ShimResult result, const std::string& detail);

// Convenience wrappers. report_success() == Ok; report_failure() == Failure.
[[noreturn]] void report_success();
// Ok, but carrying a detail string -- used when a failure was EXPECTED so the
// runner still learns WHY it failed (the library's error/alert reason), not just
// that the expectation was met.
[[noreturn]] void report_success(const std::string& detail);
[[noreturn]] void report_failure(const std::string& reason);
// The library cannot honour `uut.<knob>` (e.g. a value it has no switch for).
// Exits with UnsupportedConfig so the runner reports the case as SKIP with the
// reason, never as a vacuous pass. Call before dialing the runner.
[[noreturn]] void report_unsupported(const std::string& knob, const std::string& why);

/**
 * Start a background watchdog that exits the shim once its parent (the plzn
 * runner) is gone. A runner killed mid-case leaves nothing to read the result,
 * and a library loop with no live peer could otherwise spin indefinitely.
 * Call once at the start of main().
 */
void exit_when_orphaned();

/** Incremental implementation of plzn's framed application-data protocol. */
class AppDataResponder final {
   public:
      std::vector<std::vector<uint8_t>> receive(const uint8_t* data, size_t size);

   private:
      std::vector<uint8_t> m_pending;
};

}  // namespace plzn

#endif  // PLZN_SHIM_H_
