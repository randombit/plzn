/* wolfSSL interop shim for plzn. */

#include <algorithm>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "plzn_shim.h"

using plzn::ShimConfig;
using plzn::ShimResult;
using plzn::ShimSocket;

namespace {

class WolfSslError final : public std::runtime_error {
   public:
      WolfSslError(const std::string& where, int code) :
            std::runtime_error(where + ": " + describe(code)), m_code(code) {}

      int code() const { return m_code; }

   private:
      static std::string describe(int code) {
         // Unlike wc_ErrorString, this knows the TLS-layer codes as well as
         // wolfCrypt's.
         const char* text = wolfSSL_ERR_reason_error_string(static_cast<unsigned long>(code));
         return std::string(text != nullptr ? text : "unknown error") + " (" +
                std::to_string(code) + ")";
      }

      int m_code;
};

struct ContextDeleter {
      void operator()(WOLFSSL_CTX* p) const {
         if(p != nullptr) {
            wolfSSL_CTX_free(p);
         }
      }
};

struct SessionDeleter {
      void operator()(WOLFSSL* p) const {
         if(p != nullptr) {
            wolfSSL_free(p);
         }
      }
};

using ContextPtr = std::unique_ptr<WOLFSSL_CTX, ContextDeleter>;
using SessionPtr = std::unique_ptr<WOLFSSL, SessionDeleter>;

struct ResumptionDeleter {
      void operator()(WOLFSSL_SESSION* p) const {
         if(p != nullptr) {
            wolfSSL_SESSION_free(p);
         }
      }
};

using ResumptionPtr = std::unique_ptr<WOLFSSL_SESSION, ResumptionDeleter>;

void require_success(int rc, const std::string& where) {
   if(rc != WOLFSSL_SUCCESS) {
      throw WolfSslError(where, rc);
   }
}

#if defined(WOLFSSL_EARLY_DATA) || defined(HAVE_SESSION_TICKET) || \
   defined(HAVE_ENCRYPT_THEN_MAC)
// Some wolfSSL configuration setters follow the native API convention (zero
// means success), while OPENSSL_EXTRA builds make the same functions return
// WOLFSSL_SUCCESS. Accept both documented success values.
void require_config_success(int rc, const std::string& where) {
   if(rc != 0 && rc != WOLFSSL_SUCCESS) {
      throw WolfSslError(where, rc);
   }
}
#endif

bool suite_supported(uint16_t id) {
   const char* name = wolfSSL_get_cipher_name_from_suite(static_cast<unsigned char>(id >> 8),
                                                         static_cast<unsigned char>(id));
   if(name == nullptr || std::strcmp(name, "NONE") == 0 || std::strcmp(name, "None") == 0 ||
      std::strcmp(name, "unknown") == 0) {
      return false;
   }
#ifndef HAVE_AESCCM
   // The lookup table names ciphers known to wolfSSL even when this build did
   // not compile their primitive. Treat those as unavailable during preflight
   // so a matrix point is skipped instead of starting a doomed handshake.
   if(std::strstr(name, "CCM") != nullptr) {
      return false;
   }
#endif
   return true;
}

uint16_t negotiated_version(WOLFSSL* ssl) {
   switch(wolfSSL_GetVersion(ssl)) {
      case WOLFSSL_TLSV1: return 0x0301;
      case WOLFSSL_TLSV1_1: return 0x0302;
      case WOLFSSL_TLSV1_2: return 0x0303;
      case WOLFSSL_TLSV1_3: return 0x0304;
#ifdef WOLFSSL_DTLS
      case WOLFSSL_DTLSV1_2: return 0xFEFD;
#endif
      default: return 0;
   }
}

WOLFSSL_METHOD* method_for(const ShimConfig& cfg);

bool group_supported(const ShimConfig& cfg, uint16_t id) {
   ContextPtr ctx(wolfSSL_CTX_new(method_for(cfg)));
   if(!ctx) {
      return false;
   }
   int group = id;
   return wolfSSL_CTX_set_groups(ctx.get(), &group, 1) == WOLFSSL_SUCCESS;
}

void preflight(const ShimConfig& cfg) {
#if defined(NO_OLD_TLS) || !defined(WOLFSSL_ALLOW_TLSV10)
   if(cfg.min_version == 0x0301 || cfg.max_version == 0x0301) {
      plzn::report_unsupported("versions", "this wolfSSL build was compiled without TLS 1.0");
   }
#endif
#ifdef NO_OLD_TLS
   if(cfg.min_version == 0x0302 || cfg.max_version == 0x0302) {
      plzn::report_unsupported("versions", "this wolfSSL build was compiled without TLS 1.1");
   }
#endif
#ifndef HAVE_KEYING_MATERIAL
   if(std::any_of(cfg.key_material.begin(), cfg.key_material.end(),
                  [](const auto& request) { return request.kind == "exporter"; })) {
      plzn::report_unsupported("key_material", "this wolfSSL build was compiled without key exporters");
   }
#endif
#ifndef WOLFSSL_HAVE_TLS_UNIQUE
   if(std::any_of(cfg.key_material.begin(), cfg.key_material.end(),
                  [](const auto& request) { return request.kind.starts_with("tls_unique"); })) {
      plzn::report_unsupported("key_material", "this wolfSSL build does not expose tls-unique");
   }
#endif
#ifndef WOLFSSL_EARLY_DATA
   if(cfg.max_early_data.value_or(0) > 0) {
      plzn::report_unsupported("max_early_data", "this wolfSSL build was compiled without TLS 1.3 early data");
   }
   if(cfg.early_data_send > 0 || cfg.early_data_expect > 0) {
      plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                          "flow.EarlyData: this wolfSSL build was compiled without TLS 1.3 early data");
   }
#endif
   if(cfg.is_dtls()) {
      if(cfg.requests_dtls13()) {
         plzn::report_unsupported("versions", "the wolfSSL shim does not implement DTLS 1.3");
      }
#ifndef WOLFSSL_DTLS
      plzn::report_unsupported("protocol", "this wolfSSL build was compiled without DTLS");
#else
      plzn::report_unsupported("protocol", "DTLS datagram framing is not wired in the wolfSSL shim yet");
#endif
   }
#ifdef NO_SESSION_CACHE
   if(cfg.resume_count > 0) {
      plzn::report_unsupported("resumption", "this wolfSSL build was compiled without a session cache");
   }
#endif
#ifndef HAVE_SESSION_TICKET
   if(cfg.session_tickets.has_value() || cfg.no_ticket) {
      plzn::report_unsupported("session_tickets", "this wolfSSL build was compiled without session tickets");
   }
#endif
   if(cfg.psk.present) {
#ifdef NO_PSK
      plzn::report_unsupported("psk", "this wolfSSL build was compiled without PSK support");
#else
      plzn::report_unsupported("psk", "PSK credentials are not wired in the wolfSSL shim yet");
#endif
   }
#ifndef HAVE_ALPN
   if(!cfg.alpn.advertise.empty() || !cfg.alpn.select.empty() || !cfg.alpn.select_from.empty() ||
      cfg.alpn.expect.has_value()) {
      plzn::report_unsupported("alpn", "this wolfSSL build was compiled without ALPN");
   }
#endif
#ifndef HAVE_SNI
   if(!cfg.server_name.empty() || cfg.expect_server_name.has_value()) {
      plzn::report_unsupported("server_name", "this wolfSSL build was compiled without SNI");
   }
#endif
   if(!cfg.credentials.ocsp_file.empty()) {
      plzn::report_unsupported("ocsp_stapling", "OCSP stapling is not wired in the wolfSSL shim yet");
   }
   if(cfg.verify.fail || cfg.verify.expect_peer_subject_cn.has_value()) {
      plzn::report_unsupported("verify", "forced verification failure and peer-subject checks are not wired in the wolfSSL shim yet");
   }
   if(cfg.credentials.chains.size() > 1 || cfg.credentials.client_chains.size() > 1) {
      plzn::report_unsupported("credentials", "multi-certificate selection is not wired in the wolfSSL shim yet");
   }
   if(!cfg.signing_prefs.empty() || !cfg.verify_prefs.empty()) {
      plzn::report_unsupported("signature_algorithms", "signature preference controls are not wired in the wolfSSL shim yet");
   }
   if(!cfg.cipher_suites.empty() &&
      std::any_of(cfg.cipher_suites.begin(), cfg.cipher_suites.end(),
                  [](uint16_t id) { return !suite_supported(id); })) {
      plzn::report_unsupported("cipher_suites", "wolfSSL cannot apply one or more requested cipher suites");
   }
   if(!cfg.curves.empty() &&
      std::any_of(cfg.curves.begin(), cfg.curves.end(),
                  [&cfg](uint16_t id) { return !group_supported(cfg, id); })) {
      plzn::report_unsupported("curves", "wolfSSL cannot apply one or more requested groups");
   }
   if(!cfg.requires_any_group.empty() &&
      std::none_of(cfg.requires_any_group.begin(), cfg.requires_any_group.end(),
                   [&cfg](uint16_t id) { return group_supported(cfg, id); })) {
      plzn::report_unsupported("peer.capabilities", "wolfSSL implements none of the required groups");
   }
   if(!cfg.server_certificate_types.empty() || !cfg.client_certificate_types.empty() ||
      cfg.compress_certificate || !cfg.srtp_profiles.empty()) {
      plzn::report_unsupported("extension", "raw public keys, certificate compression, and DTLS-SRTP are not wired in the wolfSSL shim yet");
   }
   if(cfg.requires_virtual_clock || cfg.requires_dynamic_timeout) {
      plzn::report_unsupported("virtual_clock", "DTLS timeout controls are not wired in the wolfSSL shim yet");
   }
   if(!cfg.post_handshake_auth.empty() || !cfg.half_rtt_data.empty() || cfg.key_update ||
      cfg.renegotiate_freely || cfg.renegotiate_count > 0 ||
      cfg.renegotiate_after_handshake || cfg.hello_request_after_app_data ||
      cfg.require_client_cert_on_renegotiation) {
      plzn::report_unsupported("post_handshake", "requested post-handshake control is not wired in the wolfSSL shim yet");
   }
   if(cfg.expect.curve.has_value() || cfg.expect.peer_signature_algorithm.has_value() ||
      cfg.expect.hrr.has_value() || cfg.expect.secure_renegotiation.has_value() ||
      cfg.expect.peer_subject_cn.has_value() || cfg.expect_srtp_profile.has_value()) {
      plzn::report_unsupported("expectations", "one or more requested checks are not wired in the wolfSSL shim yet");
   }
   if(cfg.record_size_limit.has_value()) {
      plzn::report_unsupported("record_size_limit", "this wolfSSL build exposes no RFC 8449 record_size_limit policy");
   }
   if(cfg.server_preference.has_value() || cfg.renegotiation.has_value() ||
      cfg.max_cert_list.has_value() || cfg.records_per_traffic_key.has_value() ||
      cfg.extended_master_secret.has_value() || cfg.middlebox_compat.has_value() ||
      cfg.min_key_update_interval_ms.has_value()) {
      plzn::report_unsupported("uut", "one or more requested policy knobs are not wired in the wolfSSL shim yet");
   }
   if(!cfg.requires_any_suite.empty() &&
      std::none_of(cfg.requires_any_suite.begin(), cfg.requires_any_suite.end(), suite_supported)) {
      plzn::report_unsupported("peer.capabilities", "wolfSSL implements none of the offered cipher suites");
   }
}

WOLFSSL_METHOD* method_for(const ShimConfig& cfg) {
#ifdef WOLFSSL_DTLS
   if(cfg.is_dtls()) {
      return cfg.is_server() ? wolfDTLSv1_2_server_method() : wolfDTLSv1_2_client_method();
   }
#endif
#if !defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_TLSV10)
   if(cfg.min_version == cfg.max_version && cfg.min_version == 0x0301) {
      return cfg.is_server() ? wolfTLSv1_server_method() : wolfTLSv1_client_method();
   }
#endif
#ifndef NO_OLD_TLS
   if(cfg.min_version == cfg.max_version && cfg.min_version == 0x0302) {
      return cfg.is_server() ? wolfTLSv1_1_server_method() : wolfTLSv1_1_client_method();
   }
#endif
   if(cfg.min_version == cfg.max_version && cfg.min_version == 0x0303) {
      return cfg.is_server() ? wolfTLSv1_2_server_method() : wolfTLSv1_2_client_method();
   }
   if(cfg.min_version == cfg.max_version && cfg.min_version == 0x0304) {
      return cfg.is_server() ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method();
   }
   return cfg.is_server() ? wolfSSLv23_server_method() : wolfSSLv23_client_method();
}

#ifdef HAVE_SNI
int accept_any_server_name(WOLFSSL* /*ssl*/, int* /*alert*/, void* /*arg*/) {
   return 0;
}
#endif

ContextPtr make_context(const ShimConfig& cfg) {
   ContextPtr ctx(wolfSSL_CTX_new(method_for(cfg)));
   if(!ctx) {
      throw std::runtime_error("wolfSSL_CTX_new failed");
   }

   if(!cfg.is_dtls()) {
      const uint16_t min = cfg.min_version.value_or(0x0303);
      const int min_version = min >= 0x0304   ? WOLFSSL_TLSV1_3
                              : min >= 0x0303 ? WOLFSSL_TLSV1_2
                              : min >= 0x0302 ? WOLFSSL_TLSV1_1
                                              : WOLFSSL_TLSV1;
      require_success(wolfSSL_CTX_SetMinVersion(ctx.get(), min_version), "set minimum version");
   }

#ifdef WOLFSSL_EARLY_DATA
   if(cfg.max_early_data.has_value()) {
      require_config_success(wolfSSL_CTX_set_max_early_data(ctx.get(), *cfg.max_early_data),
                             "set maximum early data size");
   }
#endif
#ifdef HAVE_SESSION_TICKET
   if(cfg.session_tickets.has_value()) {
      require_config_success(wolfSSL_CTX_set_num_tickets(ctx.get(), *cfg.session_tickets),
                             "set TLS 1.3 session ticket count");
   } else if(cfg.no_ticket) {
      require_config_success(wolfSSL_CTX_set_num_tickets(ctx.get(), 0),
                             "disable TLS 1.3 session tickets");
   }
#endif
#ifdef HAVE_ENCRYPT_THEN_MAC
   if(cfg.encrypt_then_mac.has_value()) {
      require_config_success(
         wolfSSL_CTX_AllowEncryptThenMac(ctx.get(), *cfg.encrypt_then_mac ? 1 : 0),
         "configure encrypt-then-MAC");
   }
#endif

   const auto& chains = cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains;
   if(!chains.empty()) {
      require_success(wolfSSL_CTX_use_certificate_chain_file(ctx.get(), chains[0].cert_file.c_str()),
                      "load certificate chain");
      require_success(wolfSSL_CTX_use_PrivateKey_file(ctx.get(),
                                                      chains[0].key_file.c_str(),
                                                      WOLFSSL_FILETYPE_PEM),
                      "load private key");
   }
   if(!cfg.credentials.trust_file.empty()) {
      require_success(wolfSSL_CTX_load_verify_locations(ctx.get(),
                                                        cfg.credentials.trust_file.c_str(),
                                                        nullptr),
                      "load trust file");
   }

   int verify_mode = WOLFSSL_VERIFY_NONE;
   if(cfg.verify.verify_peer || cfg.verify.require_client_cert || cfg.verify.request_client_cert) {
      verify_mode = WOLFSSL_VERIFY_PEER;
   }
   if(cfg.verify.require_client_cert) {
      verify_mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
   }
   wolfSSL_CTX_set_verify(ctx.get(), verify_mode, nullptr);

   if(!cfg.cipher_suites.empty()) {
      std::string suites;
      for(const uint16_t suite : cfg.cipher_suites) {
         const char* name = wolfSSL_get_cipher_name_iana_from_suite(
            static_cast<unsigned char>(suite >> 8), static_cast<unsigned char>(suite));
         if(name == nullptr) {
            continue;
         }
         if(!suites.empty()) {
            suites += ':';
         }
         suites += name;
      }
      if(suites.empty()) {
         throw std::runtime_error("none of the configured cipher suites is known to wolfSSL");
      }
      require_success(wolfSSL_CTX_set_cipher_list(ctx.get(), suites.c_str()), "set cipher suites");
   }
   if(!cfg.curves.empty()) {
      std::vector<int> groups(cfg.curves.begin(), cfg.curves.end());
      require_success(wolfSSL_CTX_set_groups(ctx.get(), groups.data(), groups.size()),
                      "set key exchange groups");
   }
#ifdef HAVE_SNI
   // A wolfSSL server skips the server_name extension unparsed unless SNI is
   // in use; a servername callback that accepts every name turns parsing on
   // without making the server require a particular name.
   if(cfg.is_server()) {
      wolfSSL_CTX_set_servername_callback(ctx.get(), accept_any_server_name);
   }
#endif
   return ctx;
}

void configure_connection(WOLFSSL* ssl, const ShimConfig& cfg) {
   if(!cfg.is_dtls() && cfg.min_version == cfg.max_version && cfg.min_version.has_value()) {
      const int version = *cfg.min_version >= 0x0304 ? WOLFSSL_TLSV1_3 : WOLFSSL_TLSV1_2;
      require_success(wolfSSL_SetMinVersion(ssl, version),
                      "set connection minimum protocol version");
      require_success(wolfSSL_SetVersion(ssl, version),
                      "set connection maximum protocol version");
   }
#ifdef WOLFSSL_TLS13
   if(!cfg.is_server() && cfg.max_version.value_or(0x0304) >= 0x0304) {
      // wolfSSL's build-dependent default can be a PQ share that plzn did not
      // offer (or a group that would require HRR). Seed one direct share from
      // the UUT policy, then the peer's declared groups, then plzn's defaults.
      // This makes the test configuration -- not wolfSSL's compile-time group
      // order -- determine the initial ClientHello.
      std::vector<uint16_t> candidates = !cfg.curves.empty() ? cfg.curves :
                                           cfg.requires_any_group;
      if(candidates.empty()) {
         candidates = {WOLFSSL_ECC_X25519,
                       WOLFSSL_ECC_SECP256R1,
                       WOLFSSL_ECC_SECP384R1};
      }
      for(const uint16_t group : candidates) {
         if(group_supported(cfg, group) &&
            wolfSSL_UseKeyShare(ssl, static_cast<word16>(group)) == WOLFSSL_SUCCESS) {
            break;
         }
      }
   }
#endif
#ifdef HAVE_SNI
   if(!cfg.is_server() && !cfg.server_name.empty()) {
      require_success(wolfSSL_UseSNI(ssl,
                                     WOLFSSL_SNI_HOST_NAME,
                                     cfg.server_name.data(),
                                     static_cast<unsigned short>(cfg.server_name.size())),
                      "configure SNI");
   }
#endif
   if(!cfg.is_server() && cfg.verify.verify_peer && !cfg.server_name.empty()) {
      require_success(wolfSSL_check_domain_name(ssl, cfg.server_name.c_str()),
                      "configure hostname verification");
   }
#ifdef HAVE_ALPN
   std::string protocols;
   unsigned char option = WOLFSSL_ALPN_CONTINUE_ON_MISMATCH;
   if(cfg.is_server()) {
      if(!cfg.alpn.decline) {
         const auto& selected = cfg.alpn.select_from;
         for(const auto& protocol : selected) {
            if(!protocols.empty()) {
               protocols += ',';
            }
            protocols += protocol;
         }
         if(!cfg.alpn.select.empty()) {
            protocols = protocols.empty() ? cfg.alpn.select : cfg.alpn.select + "," + protocols;
         }
      }
   } else {
      for(const auto& protocol : cfg.alpn.advertise) {
         if(!protocols.empty()) {
            protocols += ',';
         }
         protocols += protocol;
      }
      option = WOLFSSL_ALPN_FAILED_ON_MISMATCH;
   }
   if(!protocols.empty()) {
      require_success(wolfSSL_UseALPN(ssl, protocols.data(), protocols.size(), option),
                      "configure ALPN");
   }
#endif
}

void check_expectations(WOLFSSL* ssl, const ShimConfig& cfg) {
   if(cfg.expect.version.has_value() && negotiated_version(ssl) != *cfg.expect.version) {
      throw plzn::ShimExpectationError("version mismatch: expected " + std::to_string(*cfg.expect.version) +
                               ", got " + std::to_string(negotiated_version(ssl)));
   }
   if(cfg.expect.cipher.has_value()) {
      const uint16_t actual = static_cast<uint16_t>(wolfSSL_get_current_cipher_suite(ssl));
      if(actual != *cfg.expect.cipher) {
         throw plzn::ShimExpectationError("cipher mismatch: expected " + std::to_string(*cfg.expect.cipher) +
                                  ", got " + std::to_string(actual));
      }
   }
   if(cfg.expect.resumed.has_value() && (wolfSSL_session_reused(ssl) != 0) != *cfg.expect.resumed) {
      throw plzn::ShimExpectationError("session-resumption expectation mismatch");
   }
#ifdef HAVE_SNI
   if(cfg.expect_server_name.has_value()) {
      void* name = nullptr;
      const unsigned short size = wolfSSL_SNI_GetRequest(ssl, WOLFSSL_SNI_HOST_NAME, &name);
      const std::string actual = name == nullptr ? "" : std::string(static_cast<char*>(name), size);
      if(actual != *cfg.expect_server_name) {
         throw plzn::ShimExpectationError("SNI mismatch: expected '" + *cfg.expect_server_name + "', got '" + actual + "'");
      }
   }
#endif
#ifdef HAVE_ALPN
   if(cfg.alpn.expect.has_value() || cfg.expect.alpn.has_value()) {
      const auto& expected = cfg.alpn.expect.has_value() ? *cfg.alpn.expect : *cfg.expect.alpn;
      char* selected = nullptr;
      unsigned short size = 0;
      const int rc = wolfSSL_ALPN_GetProtocol(ssl, &selected, &size);
      const std::string actual = rc == WOLFSSL_SUCCESS ? std::string(selected, size) : "";
      if(actual != expected) {
         throw plzn::ShimExpectationError("ALPN mismatch: expected '" + expected + "', got '" + actual + "'");
      }
   }
#endif
}

void write_all(WOLFSSL* ssl, const uint8_t* data, size_t len) {
   size_t sent = 0;
   while(sent < len) {
      const int rc = wolfSSL_write(ssl, data + sent, static_cast<int>(len - sent));
      if(rc <= 0) {
         throw WolfSslError("send application data", wolfSSL_get_error(ssl, rc));
      }
      sent += static_cast<size_t>(rc);
   }
}

void run_connection(const ShimConfig& cfg,
                    WOLFSSL_CTX* ctx,
                    uint32_t connection_index,
                    ResumptionPtr& resumption,
                    std::optional<uint16_t>& resumption_version) {
   ShimSocket socket(cfg.runner.host, cfg.runner.port, cfg.runner.ipv6);
   socket.write_shim_id(cfg.shim_id);
   SessionPtr ssl(wolfSSL_new(ctx));
   if(!ssl) {
      throw std::runtime_error("wolfSSL_new failed");
   }
   configure_connection(ssl.get(), cfg);
#ifndef NO_SESSION_CACHE
   if(!cfg.is_server() && connection_index > 0 &&
      (!resumption_version.has_value() || resumption_version == cfg.min_version)) {
      if(!resumption) {
         throw std::runtime_error("no wolfSSL client session is available to resume");
      }
      // Offering the saved session is best effort: wolfSSL refuses one it
      // cannot resume (without HAVE_SESSION_TICKET, every TLS 1.3 session),
      // and the connection then runs a full handshake.
      (void)wolfSSL_set_session(ssl.get(), resumption.get());
   }
#endif
   require_success(wolfSSL_set_fd(ssl.get(), socket.fd()), "attach socket");

#ifdef WOLFSSL_EARLY_DATA
   if(!cfg.is_server() && connection_index > 0 && cfg.early_data_send > 0) {
      std::vector<uint8_t> early(cfg.early_data_send, 0x45);
      size_t sent = 0;
      while(sent < early.size()) {
         int written = 0;
         const int rc = wolfSSL_write_early_data(ssl.get(),
                                                 early.data() + sent,
                                                 static_cast<int>(early.size() - sent),
                                                 &written);
         if(rc <= 0) {
            throw WolfSslError("send early data", wolfSSL_get_error(ssl.get(), rc));
         }
         const size_t progress = written > 0 ? static_cast<size_t>(written) :
                                               static_cast<size_t>(rc);
         if(progress == 0 || progress > early.size() - sent) {
            throw std::runtime_error("wolfSSL returned an invalid early-data write count");
         }
         sent += progress;
      }
   }

   if(cfg.is_server() && connection_index > 0 && cfg.early_data_expect > 0) {
      std::vector<uint8_t> buf(16 * 1024);
      size_t total = 0;
      do {
         int read = 0;
         const int rc = wolfSSL_read_early_data(
            ssl.get(), buf.data(), static_cast<int>(buf.size()), &read);
         if(rc < 0) {
            throw WolfSslError("receive early data", wolfSSL_get_error(ssl.get(), rc));
         }
         const size_t progress = static_cast<size_t>(read);
         if(progress > buf.size()) {
            throw std::runtime_error("wolfSSL returned an invalid early-data read count");
         }
         total += progress;
      } while(!wolfSSL_is_init_finished(ssl.get()));
      if(total != cfg.early_data_expect) {
         throw plzn::ShimExpectationError("early data length mismatch: got " + std::to_string(total) +
                                  " expected " + std::to_string(cfg.early_data_expect));
      }
   }
#endif

   const int hs = wolfSSL_is_init_finished(ssl.get()) ? WOLFSSL_SUCCESS :
                                                        (cfg.is_server() ? wolfSSL_accept(ssl.get()) :
                                                                           wolfSSL_connect(ssl.get()));
   if(hs != WOLFSSL_SUCCESS) {
      throw WolfSslError("handshake", wolfSSL_get_error(ssl.get(), hs));
   }
   check_expectations(ssl.get(), cfg);
#ifdef WOLFSSL_EARLY_DATA
   if(connection_index > 0 && cfg.expect_early_data_accepted.has_value()) {
      const bool accepted =
         wolfSSL_get_early_data_status(ssl.get()) == WOLFSSL_EARLY_DATA_ACCEPTED;
      if(accepted != *cfg.expect_early_data_accepted) {
         throw plzn::ShimExpectationError(std::string("TLS 1.3 early data was ") +
                                  (accepted ? "accepted" : "rejected") + " unexpectedly");
      }
   }
#endif

   bool session_saved = false;
   const auto save_client_session = [&] {
#ifndef NO_SESSION_CACHE
      if(session_saved || cfg.is_server() || connection_index >= cfg.resume_count) {
         return;
      }
      WOLFSSL_SESSION* saved = wolfSSL_get1_session(ssl.get());
      if(saved == nullptr) {
         throw std::runtime_error("wolfSSL returned no client session state");
      }
      resumption.reset(saved);
      resumption_version = cfg.min_version;
      session_saved = true;
#endif
   };

   for(const auto& request : cfg.key_material) {
      if(request.connection != connection_index) continue;
      std::vector<uint8_t> out(request.length);
      if(request.kind == "exporter") {
#ifdef HAVE_KEYING_MATERIAL
         const unsigned char* context = request.context
            ? reinterpret_cast<const unsigned char*>(request.context->data()) : nullptr;
         const size_t context_len = request.context ? request.context->size() : 0;
         require_success(wolfSSL_export_keying_material(
                            ssl.get(), out.data(), out.size(), request.label.data(),
                            request.label.size(), context, context_len,
                            request.context.has_value()),
                         "export keying material");
#endif
      } else if(request.kind == "tls_unique" || request.kind == "tls_unique_unavailable") {
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
         if(request.kind == "tls_unique_unavailable") {
            throw std::runtime_error("tls-unique unavailability detection is not exposed by wolfSSL");
         }
         const bool resumed = wolfSSL_session_reused(ssl.get()) == 1;
         const bool local_finished_first = resumed == cfg.is_server();
         const size_t n = local_finished_first
            ? wolfSSL_get_finished(ssl.get(), out.data(), out.size())
            : wolfSSL_get_peer_finished(ssl.get(), out.data(), out.size());
         if(n == 0 || n > out.size()) {
            throw std::runtime_error("cannot obtain tls-unique Finished value");
         }
         out.resize(n);
#endif
      } else {
         throw std::runtime_error("unknown key_material kind: " + request.kind);
      }
      write_all(ssl.get(), out.data(), out.size());
   }

   if(cfg.app_data.mode == plzn::AppDataMode::ShimWrites) {
      write_all(ssl.get(), reinterpret_cast<const uint8_t*>(cfg.app_data.send.data()), cfg.app_data.send.size());
      save_client_session();
      (void)wolfSSL_shutdown(ssl.get());
      return;
   }
   if(cfg.app_data.mode == plzn::AppDataMode::ShutdownOnly) {
      save_client_session();
      (void)wolfSSL_shutdown(ssl.get());
      return;
   }

   std::vector<uint8_t> buf(18 * 1024);
   plzn::AppDataResponder app_responder;
   for(;;) {
      const int got = wolfSSL_read(ssl.get(), buf.data(), static_cast<int>(buf.size()));
      if(got > 0) {
         save_client_session();
         for(const auto& reply : app_responder.receive(buf.data(), static_cast<size_t>(got))) {
            write_all(ssl.get(), reply.data(), reply.size());
         }
         continue;
      }
      const int error = wolfSSL_get_error(ssl.get(), got);
      if(error == WOLFSSL_ERROR_ZERO_RETURN || error == WOLFSSL_ERROR_SYSCALL ||
         error == SOCKET_PEER_CLOSED_E) {
         save_client_session();
         (void)wolfSSL_shutdown(ssl.get());
         break;
      }
      if(error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
         continue;
      }
      throw WolfSslError("receive application data", error);
   }
   save_client_session();
}

}  // namespace

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   std::signal(SIGPIPE, SIG_IGN);
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string arg = argv[i];
      if(arg == "--plzn-shim-info") {
         std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"wolfssl"})" << std::endl;
         return 0;
      } else if(arg == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(arg.rfind("-config=", 0) == 0) {
         config_path = arg.substr(8);
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: wolfssl_shim -config <file.json> | --plzn-shim-info" << std::endl;
      return 2;
   }

   ShimConfig cfg;
   try {
      cfg = ShimConfig::from_file(config_path);
   } catch(const std::exception& e) {
      plzn::report_result(ShimResult::LocalError, std::string("config error: ") + e.what());
   }
   require_success(wolfSSL_Init(), "initialize wolfSSL");
   preflight(cfg);
   const bool expect_failure = cfg.expect.handshake_error.has_value();

   try {
      auto ctx = make_context(cfg);
      ResumptionPtr resumption;
      std::optional<uint16_t> resumption_version;
      for(uint32_t i = 0; i <= cfg.resume_count; ++i) {
         const auto connection_cfg = cfg.for_connection(i);
         run_connection(connection_cfg, ctx.get(), i, resumption, resumption_version);
      }
   } catch(const WolfSslError& e) {
      if(expect_failure || cfg.expect.handshake_abandoned) {
         plzn::report_success(e.what());
      }
      plzn::report_result(ShimResult::HandshakeFailed, e.what());
   } catch(const plzn::ShimSocketError& e) {
      if(expect_failure || cfg.expect.handshake_abandoned) {
         plzn::report_success(std::string("socket error: ") + e.what());
      }
      plzn::report_result(ShimResult::IoError, e.what());
   } catch(const plzn::ShimExpectationError& e) {
      plzn::report_result(ShimResult::ExpectationMismatch, e.what());
   } catch(const std::exception& e) {
      plzn::report_result(ShimResult::LocalError, e.what());
   }

   if(expect_failure && !cfg.expect.handshake_abandoned) {
      plzn::report_result(ShimResult::UnexpectedSuccess, "expected the flow to fail but it completed");
   }
   plzn::report_success();
}
