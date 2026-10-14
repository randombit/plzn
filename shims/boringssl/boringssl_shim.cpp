/*
 * plzn BoringSSL interoperability shim.
 *
 * The TLS endpoint is deliberately small, but the DTLS transport is
 * an adaptation of BoringSSL's ssl/test PacketedBio. This keeps the DTLS 1.3
 * oracle on the same timeout and packet framing design used by BoGo, with the
 * deterministic E/U acknowledgements required by plzn's shim protocol.
 */

#include "plzn_shim.h"
#include "packeted_bio.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace plzn;

namespace {

timeval g_clock{};
std::vector<uint8_t> g_psk;
std::string g_psk_identity;
std::string g_verify_hostname;
bool g_force_verify_failure = false;

struct SslCtxDeleter {
   void operator()(SSL_CTX* p) const { SSL_CTX_free(p); }
};
struct SslDeleter {
   void operator()(SSL* p) const { SSL_free(p); }
};
struct SessionDeleter {
   void operator()(SSL_SESSION* p) const { SSL_SESSION_free(p); }
};
struct PkeyDeleter {
   void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct CredentialDeleter {
   void operator()(SSL_CREDENTIAL* p) const { SSL_CREDENTIAL_free(p); }
};
struct CryptoBufferDeleter {
   void operator()(CRYPTO_BUFFER* p) const { CRYPTO_BUFFER_free(p); }
};
struct X509Deleter {
   void operator()(X509* p) const { X509_free(p); }
};
using ContextPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;
using SslPtr = std::unique_ptr<SSL, SslDeleter>;
using SessionPtr = std::unique_ptr<SSL_SESSION, SessionDeleter>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using CredentialPtr = std::unique_ptr<SSL_CREDENTIAL, CredentialDeleter>;
using CryptoBufferPtr = std::unique_ptr<CRYPTO_BUFFER, CryptoBufferDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
SessionPtr g_new_session;

class ShimOutcome final : public std::exception {
   public:
      ShimOutcome(ShimResult result, std::string detail) : m_result(result), m_detail(std::move(detail)) {}
      ShimResult result() const { return m_result; }
      const std::string& detail() const { return m_detail; }
      const char* what() const noexcept override { return m_detail.c_str(); }

   private:
      ShimResult m_result;
      std::string m_detail;
};

std::string errors() {
   std::string out;
   for(unsigned long e = ERR_get_error(); e != 0; e = ERR_get_error()) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof(buf));
      if(!out.empty()) {
         out += "; ";
      }
      out += buf;
   }
   return out;
}

PkeyPtr load_private_key(const std::string& path) {
   BIO* file = BIO_new_file(path.c_str(), "r");
   if(file == nullptr) {
      throw std::runtime_error("cannot open private key: " + errors());
   }
   PkeyPtr key(PEM_read_bio_PrivateKey(file, nullptr, nullptr, nullptr));
   BIO_free(file);
   if(key == nullptr) {
      throw std::runtime_error("cannot load private key: " + errors());
   }
   return key;
}

CredentialPtr make_raw_public_key_credential(const Chain& chain) {
   auto key = load_private_key(chain.key_file);
   CredentialPtr credential(SSL_CREDENTIAL_new_raw_public_key(key.get()));
   if(credential == nullptr) {
      throw std::runtime_error("cannot create raw-public-key credential: " + errors());
   }
   return credential;
}

CredentialPtr make_x509_credential(const Chain& chain) {
   BIO* file = BIO_new_file(chain.cert_file.c_str(), "r");
   if(file == nullptr) {
      throw std::runtime_error("cannot open certificate chain: " + errors());
   }

   std::vector<X509Ptr> certificates;
   while(X509* certificate = PEM_read_bio_X509(file, nullptr, nullptr, nullptr)) {
      certificates.emplace_back(certificate);
   }
   BIO_free(file);
   ERR_clear_error();  // PEM reports end-of-file through the error queue.
   if(certificates.empty()) {
      throw std::runtime_error("certificate chain contains no certificates");
   }

   std::vector<CryptoBufferPtr> buffers;
   std::vector<CRYPTO_BUFFER*> buffer_ptrs;
   for(const auto& certificate : certificates) {
      uint8_t* der = nullptr;
      const int der_len = i2d_X509(certificate.get(), &der);
      if(der_len < 0) {
         throw std::runtime_error("cannot encode certificate: " + errors());
      }
      CryptoBufferPtr buffer(CRYPTO_BUFFER_new(der, static_cast<size_t>(der_len), nullptr));
      OPENSSL_free(der);
      if(buffer == nullptr) {
         throw std::runtime_error("cannot buffer certificate: " + errors());
      }
      buffer_ptrs.push_back(buffer.get());
      buffers.push_back(std::move(buffer));
   }

   auto key = load_private_key(chain.key_file);
   CredentialPtr credential(SSL_CREDENTIAL_new_x509());
   if(credential == nullptr ||
      SSL_CREDENTIAL_set1_cert_chain(credential.get(), buffer_ptrs.data(), buffer_ptrs.size()) != 1 ||
      SSL_CREDENTIAL_set1_private_key(credential.get(), key.get()) != 1) {
      throw std::runtime_error("cannot create X.509 credential: " + errors());
   }
   return credential;
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
   if(hex.size() % 2 != 0) {
      throw std::runtime_error("PSK secret has odd-length hex encoding");
   }
   auto nibble = [](char c) -> int {
      if(c >= '0' && c <= '9') return c - '0';
      if(c >= 'a' && c <= 'f') return c - 'a' + 10;
      if(c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
   };
   std::vector<uint8_t> out;
   out.reserve(hex.size() / 2);
   for(size_t i = 0; i < hex.size(); i += 2) {
      const int hi = nibble(hex[i]);
      const int lo = nibble(hex[i + 1]);
      if(hi < 0 || lo < 0) {
         throw std::runtime_error("PSK secret is not hexadecimal");
      }
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
   }
   return out;
}

std::vector<uint8_t> alpn_wire(const std::vector<std::string>& protocols) {
   std::vector<uint8_t> out;
   for(const auto& protocol : protocols) {
      if(protocol.empty() || protocol.size() > 255) {
         throw std::runtime_error("invalid ALPN protocol length");
      }
      out.push_back(static_cast<uint8_t>(protocol.size()));
      out.insert(out.end(), protocol.begin(), protocol.end());
   }
   return out;
}

int alpn_select(SSL*,
                const uint8_t** out,
                uint8_t* out_len,
                const uint8_t* in,
                unsigned in_len,
                void* arg) {
   const auto* cfg = static_cast<const ShimConfig*>(arg);
   if(cfg->alpn.decline) {
      return SSL_TLSEXT_ERR_NOACK;
   }
   if(cfg->alpn.select.empty() && cfg->alpn.select_from.empty()) {
      if(in_len == 0 || static_cast<unsigned>(in[0]) + 1 > in_len) {
         return SSL_TLSEXT_ERR_NOACK;
      }
      *out = in + 1;
      *out_len = in[0];
      return SSL_TLSEXT_ERR_OK;
   }
   std::vector<std::string> supported = cfg->alpn.select_from;
   if(!cfg->alpn.select.empty()) {
      supported.insert(supported.begin(), cfg->alpn.select);
   }
   for(const auto& want : supported) {
      for(unsigned off = 0; off < in_len;) {
         const unsigned len = in[off++];
         if(off + len > in_len) break;
         if(len == want.size() && std::memcmp(in + off, want.data(), len) == 0) {
            *out = in + off;
            *out_len = static_cast<uint8_t>(len);
            return SSL_TLSEXT_ERR_OK;
         }
         off += len;
      }
   }
   return SSL_TLSEXT_ERR_ALERT_FATAL;
}

unsigned psk_server(SSL*, const char* identity, uint8_t* psk, unsigned max_len) {
   if(identity == nullptr || identity != g_psk_identity || g_psk.size() > max_len) {
      return 0;
   }
   std::memcpy(psk, g_psk.data(), g_psk.size());
   return static_cast<unsigned>(g_psk.size());
}

unsigned psk_client(SSL*,
                    const char*,
                    char* identity,
                    unsigned max_identity_len,
                    uint8_t* psk,
                    unsigned max_psk_len) {
   if(g_psk_identity.size() + 1 > max_identity_len || g_psk.size() > max_psk_len) {
      return 0;
   }
   std::memcpy(identity, g_psk_identity.c_str(), g_psk_identity.size() + 1);
   std::memcpy(psk, g_psk.data(), g_psk.size());
   return static_cast<unsigned>(g_psk.size());
}

int verify_callback(int preverify_ok, X509_STORE_CTX* store) {
   if(!preverify_ok || g_force_verify_failure) {
      return 0;
   }
   if(!g_verify_hostname.empty() && X509_STORE_CTX_get_error_depth(store) == 0) {
      X509* cert = X509_STORE_CTX_get_current_cert(store);
      if(cert == nullptr ||
         X509_check_host(cert, g_verify_hostname.c_str(), g_verify_hostname.size(), 0, nullptr) != 1) {
         X509_STORE_CTX_set_error(store, X509_V_ERR_HOSTNAME_MISMATCH);
         return 0;
      }
   }
   return 1;
}

ssl_verify_result_t raw_public_key_verify(SSL*, uint8_t* out_alert) {
   if(g_force_verify_failure) {
      *out_alert = SSL_AD_BAD_CERTIFICATE;
      return ssl_verify_invalid;
   }
   // The shim's generated raw keys are authenticated out of band by the test
   // configuration. Certificate-path tests continue through verify_callback.
   return ssl_verify_ok;
}

void current_time(const SSL*, timeval* out) {
   *out = g_clock;
}

bool supports_suite(uint16_t id) {
   return SSL_get_cipher_by_value(id) != nullptr;
}

bool supports_group(uint16_t id, bool dtls) {
   ContextPtr ctx(SSL_CTX_new(dtls ? DTLS_method() : TLS_method()));
   const uint16_t group = id;
   return ctx != nullptr && SSL_CTX_set1_group_ids(ctx.get(), &group, 1) == 1;
}

int new_session_callback(SSL*, SSL_SESSION* session) {
   g_new_session.reset(session);
   return 1;  // the callback takes ownership of BoringSSL's session reference
}

void preflight(const ShimConfig& cfg) {
   if(cfg.credentials.chains.size() > 1 || cfg.credentials.client_chains.size() > 1) {
      report_unsupported("credentials", "multiple certificate selection is not wired in the BoringSSL shim yet");
   }
   if(cfg.compress_certificate || !cfg.credentials.ocsp_file.empty()) {
      report_unsupported("credentials", "certificate compression and OCSP stapling are not wired in the BoringSSL shim yet");
   }
   if(cfg.dtls_max_retransmissions || cfg.dtls_max_timeout_ms || cfg.dtls_require_cookie ||
      cfg.dtls_epoch0_restart || cfg.dtls_max_hello_verify_requests) {
      report_unsupported("dtls", "the requested DTLS policy control has no BoringSSL API mapping");
   }
   if(cfg.records_per_traffic_key || cfg.extended_master_secret ||
      cfg.encrypt_then_mac.value_or(false)) {
      report_unsupported("policy", "the requested record/legacy policy control has no BoringSSL API mapping");
   }
   if(cfg.middlebox_compat.value_or(false)) {
      report_unsupported("middlebox_compat", "BoringSSL does not implement TLS 1.3 compatibility-mode CCS records");
   }
   if(cfg.min_key_update_interval_ms.value_or(0) != 0) {
      report_unsupported("min_key_update_interval_ms", "BoringSSL has no KeyUpdate rate-limit control");
   }
   if(cfg.early_data_send || cfg.early_data_expect || cfg.max_early_data ||
      cfg.expect_early_data_accepted) {
      report_unsupported("early_data", "plzn early-data sessions are not wired in the BoringSSL shim yet");
   }
   if(!cfg.post_handshake_auth.empty() || !cfg.half_rtt_data.empty()) {
      report_unsupported("post_handshake", "post-handshake authentication and half-RTT writes are not wired in the BoringSSL shim yet");
   }
   if(cfg.renegotiate_after_handshake || cfg.hello_request_after_app_data ||
      cfg.require_client_cert_on_renegotiation || cfg.renegotiate_count > 0) {
      report_unsupported("renegotiation", "active renegotiation is not wired in the BoringSSL shim yet");
   }
   if((cfg.renegotiate_freely ||
       (cfg.renegotiation.has_value() && *cfg.renegotiation != "none")) &&
      (cfg.is_server() || cfg.is_dtls())) {
      report_unsupported("renegotiation",
                         "BoringSSL only supports receiving server-initiated renegotiation as a TLS client");
   }
   if(cfg.renegotiation.has_value() && *cfg.renegotiation != "none" &&
      *cfg.renegotiation != "server" && *cfg.renegotiation != "both") {
      report_unsupported("renegotiation",
                         "BoringSSL cannot initiate renegotiation");
   }
   if(cfg.psk.present && !cfg.is_dtls() &&
      ((cfg.min_version && *cfg.min_version >= TLS1_3_VERSION) ||
       (cfg.max_version && *cfg.max_version >= TLS1_3_VERSION))) {
      report_unsupported("psk",
                         "BoringSSL's legacy PSK callbacks only support TLS 1.2; its TLS 1.3 API requires RFC 9258 imported identities");
   }
   const auto& chains = cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains;
   if(std::any_of(chains.begin(), chains.end(),
                  [](const Chain& chain) { return chain.key_type == "rsa_pss"; })) {
      report_unsupported("credentials",
                         "BoringSSL cannot load an id-RSASSA-PSS private key through the legacy certificate API");
   }
   if(cfg.session_tickets.has_value() && *cfg.session_tickets > 1) {
      report_unsupported("session_tickets", "BoringSSL does not expose a ticket-count control");
   }
   if(cfg.server_preference.has_value() && !*cfg.server_preference && !cfg.is_dtls() &&
      cfg.max_version && *cfg.max_version >= TLS1_3_VERSION) {
      report_unsupported("server_preference",
                         "BoringSSL does not expose client-order TLS 1.3 cipher selection");
   }
   if(!cfg.requires_any_suite.empty() &&
      std::none_of(cfg.requires_any_suite.begin(), cfg.requires_any_suite.end(), supports_suite)) {
      report_unsupported("cipher_suites", "BoringSSL implements none of the offered cipher suites");
   }
   if(!cfg.requires_any_group.empty() &&
      std::none_of(cfg.requires_any_group.begin(), cfg.requires_any_group.end(),
                   [&](uint16_t id) { return supports_group(id, cfg.is_dtls()); })) {
      report_unsupported("groups", "BoringSSL implements none of the required groups");
   }
}

void configure_ciphers(SSL_CTX* ctx, const ShimConfig& cfg) {
   if(cfg.cipher_suites.empty()) {
      // BoringSSL's `ALL` is a policy list, not every cipher compiled into the
      // library. Explicitly name a required legacy suite first so tests for a
      // disabled-by-default but implemented suite (notably CBC) can run.
      std::string legacy;
      for(uint16_t id : cfg.requires_any_suite) {
         if((id & 0xff00) == 0x1300) continue;
         const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
         if(cipher == nullptr) continue;
         if(!legacy.empty()) legacy += ':';
         legacy += SSL_CIPHER_get_name(cipher);
      }
      if(!legacy.empty()) legacy += ':';
      legacy += "ALL";
      if(SSL_CTX_set_strict_cipher_list(ctx, legacy.c_str()) != 1) {
         throw std::runtime_error("cannot enable BoringSSL's default cipher list: " + errors());
      }
      return;
   }

   std::string legacy;
   std::vector<uint16_t> tls13;
   for(uint16_t id : cfg.cipher_suites) {
      const SSL_CIPHER* cipher = SSL_get_cipher_by_value(id);
      if(cipher == nullptr) continue;
      if((id & 0xff00) == 0x1300) {
         tls13.push_back(id);
      } else {
         if(!legacy.empty()) legacy += ':';
         legacy += SSL_CIPHER_get_name(cipher);
      }
   }
   // Version bounds, rather than an empty legacy cipher list, prevent TLS 1.2
   // when a test asks for TLS-1.3-only suites. BoringSSL rejects `!ALL` as a
   // strict cipher list, before it gets a chance to apply the TLS 1.3 list.
   if(legacy.empty() && !tls13.empty()) legacy = "ALL";
   if(legacy.empty()) {
      report_unsupported("cipher_suites", "BoringSSL implements none of the requested cipher suites");
   }
   if(SSL_CTX_set_strict_cipher_list(ctx, legacy.c_str()) != 1) {
      throw std::runtime_error("cannot apply BoringSSL cipher list: " + errors());
   }
   if(!tls13.empty() && SSL_CTX_set1_tls13_ciphers(ctx, tls13.data(), nullptr, tls13.size()) != 1) {
      throw std::runtime_error("cannot apply BoringSSL TLS 1.3 cipher list: " + errors());
   }
}

void configure_context(SSL_CTX* ctx, const ShimConfig& cfg) {
   if(cfg.record_size_limit.has_value()) {
      report_unsupported("record_size_limit", "BoringSSL exposes no RFC 8449 record_size_limit policy");
   }
   SSL_CTX_set_current_time_cb(ctx, current_time);
   SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
   SSL_CTX_sess_set_new_cb(ctx, new_session_callback);
   configure_ciphers(ctx, cfg);

   if(cfg.server_preference.has_value()) {
      if(*cfg.server_preference) {
         SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      }
   }
   if(cfg.no_ticket || cfg.session_tickets == 0) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
   }
   if(cfg.max_cert_list) {
      SSL_CTX_set_max_cert_list(ctx, *cfg.max_cert_list);
   }
   if(!cfg.srtp_profiles.empty()) {
      std::string profiles;
      for(const uint16_t id : cfg.srtp_profiles) {
         const char* name = nullptr;
         switch(id) {
            case SRTP_AES128_CM_SHA1_80: name = "SRTP_AES128_CM_SHA1_80"; break;
            case SRTP_AES128_CM_SHA1_32: name = "SRTP_AES128_CM_SHA1_32"; break;
            case SRTP_NULL_SHA1_80: name = "SRTP_NULL_SHA1_80"; break;
            case SRTP_NULL_SHA1_32: name = "SRTP_NULL_SHA1_32"; break;
            case SRTP_AEAD_AES_128_GCM: name = "SRTP_AEAD_AES_128_GCM"; break;
            case SRTP_AEAD_AES_256_GCM: name = "SRTP_AEAD_AES_256_GCM"; break;
            default:
               report_unsupported("srtp_profiles", "BoringSSL cannot configure an unknown SRTP profile id");
         }
         if(!profiles.empty()) profiles += ':';
         profiles += name;
      }
      if(SSL_CTX_set_srtp_profiles(ctx, profiles.c_str()) != 1) {
         throw std::runtime_error("cannot apply BoringSSL SRTP profiles: " + errors());
      }
   }

   // As with ciphers, BoringSSL supports a few groups which its default policy
   // does not advertise. A test's `requires.any_group` is permission to enable
   // those groups even when it did not otherwise pin the UUT group list.
   std::vector<uint16_t> groups = cfg.curves;
   if(groups.empty()) {
      for(uint16_t id : cfg.requires_any_group) {
         if(supports_group(id, cfg.is_dtls())) groups.push_back(id);
      }
   }
   // Before TLS 1.3, BoringSSL applies the supported-groups list to both the
   // ECDHE exchange and the peer certificate's EC key. A group-sweep test pins
   // the exchange group, not the certificate curve, so retain the latter in a
   // client offer as well. (TLS 1.3 removed this certificate-key constraint.)
   if(!cfg.is_server() && cfg.max_version == 0x0303) {
      for(const std::string& key_type : cfg.requires_server_keys) {
         const uint16_t cert_group = key_type == "ecdsa_p256" ? 23 :
                                     key_type == "ecdsa_p384" ? 24 :
                                     key_type == "ecdsa_p521" ? 25 : 0;
         if(cert_group != 0 && std::find(groups.begin(), groups.end(), cert_group) == groups.end()) {
            groups.push_back(cert_group);
         }
      }
   }
   if(!groups.empty() &&
      SSL_CTX_set1_group_ids(ctx, groups.data(), groups.size()) != 1) {
      report_unsupported("groups", "BoringSSL cannot apply the requested group list");
   }
   if(!cfg.signing_prefs.empty() &&
      SSL_CTX_set_signing_algorithm_prefs(ctx, cfg.signing_prefs.data(), cfg.signing_prefs.size()) != 1) {
      report_unsupported("signing_prefs", "BoringSSL cannot apply the requested signing algorithms");
   }
   if(!cfg.verify_prefs.empty() &&
      SSL_CTX_set_verify_algorithm_prefs(ctx, cfg.verify_prefs.data(), cfg.verify_prefs.size()) != 1) {
      report_unsupported("verify_prefs", "BoringSSL cannot apply the requested verification algorithms");
   }

   const auto& accepted_peer_types =
      cfg.is_server() ? cfg.client_certificate_types : cfg.server_certificate_types;
   if(!accepted_peer_types.empty() &&
      SSL_CTX_set1_accepted_peer_cert_types(
         ctx, accepted_peer_types.data(), accepted_peer_types.size()) != 1) {
      report_unsupported("certificate_types",
                         "BoringSSL cannot apply the accepted peer certificate types");
   }
   if(!cfg.is_server() && !cfg.client_certificate_types.empty() &&
      SSL_CTX_set1_available_client_cert_types(ctx,
                                               cfg.client_certificate_types.data(),
                                               cfg.client_certificate_types.size()) != 1) {
      report_unsupported("client_certificate_types",
                         "BoringSSL cannot apply the available client certificate types");
   }

   const auto& chains = cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains;
   const auto& local_types =
      cfg.is_server() ? cfg.server_certificate_types : cfg.client_certificate_types;
   if(!chains.empty()) {
      if(local_types.empty()) {
         if(SSL_CTX_use_certificate_chain_file(ctx, chains[0].cert_file.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, chains[0].key_file.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            throw std::runtime_error("cannot load certificate/private key: " + errors());
         }
      } else {
         for(const uint8_t type : local_types) {
            CredentialPtr credential = type == 2 ?
                                          make_raw_public_key_credential(chains[0]) :
                                          make_x509_credential(chains[0]);
            if(SSL_CTX_add1_credential(ctx, credential.get()) != 1) {
               throw std::runtime_error("cannot add certificate credential: " + errors());
            }
         }
      }
   }
   if(!cfg.credentials.trust_file.empty() &&
      SSL_CTX_load_verify_locations(ctx, cfg.credentials.trust_file.c_str(), nullptr) != 1) {
      throw std::runtime_error("cannot load trust anchors: " + errors());
   }

   if(!cfg.alpn.select.empty() || !cfg.alpn.select_from.empty() || cfg.alpn.decline) {
      SSL_CTX_set_alpn_select_cb(ctx, alpn_select, const_cast<ShimConfig*>(&cfg));
   }
}

void configure_connection(SSL* ssl, const ShimConfig& cfg, SSL_SESSION* session) {
   if(cfg.min_version && SSL_set_min_proto_version(ssl, *cfg.min_version) != 1) {
      throw std::runtime_error("cannot set minimum protocol version: " + errors());
   }
   if(cfg.max_version && SSL_set_max_proto_version(ssl, *cfg.max_version) != 1) {
      throw std::runtime_error("cannot set maximum protocol version: " + errors());
   }
   if(cfg.is_dtls()) {
      SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
      if(SSL_set_mtu(ssl, cfg.mtu) != 1) {
         throw std::runtime_error("cannot set DTLS MTU");
      }
      DTLSv1_set_initial_timeout_duration(ssl, cfg.initial_timeout_ms);
   }
   if(!cfg.server_name.empty() && !cfg.is_server() &&
      SSL_set_tlsext_host_name(ssl, cfg.server_name.c_str()) != 1) {
      throw std::runtime_error("cannot set SNI: " + errors());
   }
   if(!cfg.alpn.advertise.empty()) {
      const auto wire = alpn_wire(cfg.alpn.advertise);
      if(SSL_set_alpn_protos(ssl, wire.data(), wire.size()) != 0) {
         throw std::runtime_error("cannot set ALPN offer");
      }
   }
   if(!cfg.is_server()) {
      SSL_enable_ocsp_stapling(ssl);
      if(cfg.renegotiate_freely ||
         (cfg.renegotiation.has_value() &&
          (*cfg.renegotiation == "server" || *cfg.renegotiation == "both"))) {
         SSL_set_renegotiate_mode(ssl, ssl_renegotiate_freely);
      }
   }

   int verify_mode = SSL_VERIFY_NONE;
   if(cfg.verify.verify_peer) verify_mode |= SSL_VERIFY_PEER;
   if(cfg.is_server() && cfg.verify.require_client_cert) {
      verify_mode |= SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
   } else if(cfg.is_server() && cfg.verify.request_client_cert) {
      verify_mode |= SSL_VERIFY_PEER;
   }
   g_force_verify_failure = cfg.verify.fail;
   g_verify_hostname = (!cfg.is_server() && cfg.verify.verify_peer) ? cfg.server_name : "";
   const auto& accepted_peer_types =
      cfg.is_server() ? cfg.client_certificate_types : cfg.server_certificate_types;
   if(std::find(accepted_peer_types.begin(), accepted_peer_types.end(), 2) !=
      accepted_peer_types.end()) {
      SSL_set_custom_verify(ssl, verify_mode | SSL_VERIFY_PEER, raw_public_key_verify);
   } else {
      SSL_set_verify(ssl, verify_mode, verify_callback);
   }

   if(cfg.psk.present) {
      g_psk = hex_decode(cfg.psk.secret_hex);
      g_psk_identity = cfg.psk.identity;
      SSL_set_psk_server_callback(ssl, psk_server);
      SSL_set_psk_client_callback(ssl, psk_client);
   }
   if(session != nullptr && !cfg.is_server() && SSL_set_session(ssl, session) != 1) {
      throw std::runtime_error("cannot offer saved session: " + errors());
   }
}

bool retry(SSL* ssl, int ret, BIO* packeted) {
   const int err = SSL_get_error(ssl, ret);
   if((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
      packeted != nullptr && PacketedBioHasInterrupt(packeted)) {
      if(!PacketedBioHandleInterrupt(packeted)) {
         // A terminal DTLS timeout has already been reported to plzn by the
         // packeted BIO. Let the caller classify the resulting SSL failure;
         // negative-test configuration then turns it into a successful shim
         // self-check instead of an internal shim error.
         return false;
      }
      return true;
   }
   return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
}

int drive_handshake(SSL* ssl, BIO* packeted) {
   for(;;) {
      const int ret = SSL_do_handshake(ssl);
      if(ret == 1) return 1;
      if(!retry(ssl, ret, packeted)) return ret;
   }
}

std::optional<std::string> check_expectations(SSL* ssl, const ShimConfig& cfg) {
   if(cfg.expect.version && SSL_version(ssl) != *cfg.expect.version) {
      return "negotiated version mismatch: got " + std::to_string(SSL_version(ssl));
   }
   const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
   if(cfg.expect.cipher &&
      (cipher == nullptr || SSL_CIPHER_get_protocol_id(cipher) != *cfg.expect.cipher)) {
      return "negotiated cipher suite mismatch";
   }
   if(cfg.expect.curve && SSL_get_curve_id(ssl) != *cfg.expect.curve) {
      return "negotiated group mismatch: got " + std::to_string(SSL_get_curve_id(ssl));
   }
   if(cfg.expect.peer_signature_algorithm &&
      SSL_get_peer_signature_algorithm(ssl) != *cfg.expect.peer_signature_algorithm) {
      return "peer signature algorithm mismatch";
   }
   if(cfg.expect.resumed && static_cast<bool>(SSL_session_reused(ssl)) != *cfg.expect.resumed) {
      return "session resumption mismatch";
   }
   if(cfg.expect.hrr && static_cast<bool>(SSL_used_hello_retry_request(ssl)) != *cfg.expect.hrr) {
      return "HelloRetryRequest expectation mismatch";
   }
   if(cfg.expect.secure_renegotiation &&
      static_cast<bool>(SSL_get_secure_renegotiation_support(ssl)) != *cfg.expect.secure_renegotiation) {
      return "secure renegotiation expectation mismatch";
   }
   const uint8_t* alpn = nullptr;
   unsigned alpn_len = 0;
   SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
   if(cfg.expect.alpn && std::string(reinterpret_cast<const char*>(alpn), alpn_len) != *cfg.expect.alpn) {
      return "negotiated ALPN mismatch";
   }
   if(cfg.expect_server_name && cfg.is_server()) {
      const char* got = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
      if(got == nullptr || got != *cfg.expect_server_name) {
         return "received SNI mismatch";
      }
   }
   if(cfg.expect.peer_subject_cn) {
      X509* peer = SSL_get_peer_certificate(ssl);
      if(peer == nullptr) return "peer certificate missing";
      char cn[256] = {};
      X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, cn, sizeof(cn));
      X509_free(peer);
      if(cn != *cfg.expect.peer_subject_cn) return "peer certificate common-name mismatch";
   }
   if(cfg.expect_srtp_profile) {
      const SRTP_PROTECTION_PROFILE* selected = SSL_get_selected_srtp_profile(ssl);
      const uint16_t got = selected == nullptr ? 0 : static_cast<uint16_t>(selected->id);
      if(got != *cfg.expect_srtp_profile) {
         return "SRTP profile mismatch: got " + std::to_string(got);
      }
   }
   return std::nullopt;
}

void write_all(SSL* ssl, BIO* packeted, const uint8_t* data, size_t len) {
   size_t off = 0;
   while(off < len) {
      const int ret = SSL_write(ssl, data + off, static_cast<int>(len - off));
      if(ret > 0) {
         off += static_cast<size_t>(ret);
      } else if(!retry(ssl, ret, packeted)) {
         throw std::runtime_error("SSL_write failed: " + errors());
      }
   }
}

void flush_post_handshake_tickets(SSL* ssl, BIO* packeted) {
   for(;;) {
      const int ret = SSL_write(ssl, nullptr, 0);
      if(ret >= 0) return;
      if(!retry(ssl, ret, packeted)) {
         throw std::runtime_error("cannot flush post-handshake tickets: " + errors());
      }
   }
}

bool send_key_material(SSL* ssl, BIO* packeted, const ShimConfig& cfg,
                       uint32_t connection_index) {
   for(const auto& request : cfg.key_material) {
      if(request.connection != connection_index) continue;
      std::vector<uint8_t> out(request.length);
      if(request.kind == "exporter") {
         const uint8_t* context = request.context
            ? reinterpret_cast<const uint8_t*>(request.context->data()) : nullptr;
         const size_t context_len = request.context ? request.context->size() : 0;
         if(SSL_export_keying_material(
               ssl, out.data(), out.size(), request.label.data(), request.label.size(),
               context, context_len, request.context.has_value()) != 1) {
            throw std::runtime_error("SSL_export_keying_material failed: " + errors());
         }
      } else if(request.kind == "tls_unique" || request.kind == "tls_unique_unavailable") {
         size_t out_len = 0;
         const bool available = SSL_get_tls_unique(ssl, out.data(), &out_len, out.size());
         if(request.kind == "tls_unique_unavailable") {
            if(available) {
               throw std::runtime_error("tls-unique unexpectedly available");
            }
            out.assign(1, 0x01);
         } else if(!available) {
            throw std::runtime_error("SSL_get_tls_unique failed: " + errors());
         } else {
            out.resize(out_len);
         }
      } else {
         throw std::runtime_error("unknown key_material kind: " + request.kind);
      }
      write_all(ssl, packeted, out.data(), out.size());
   }
   return true;
}

bool application_data(SSL* ssl, BIO* packeted, const ShimConfig& cfg,
                      uint32_t connection_index) {
   if(cfg.key_update && SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED) != 1) {
      throw std::runtime_error("SSL_key_update failed: " + errors());
   }
   if(cfg.app_data.mode == AppDataMode::ShutdownOnly) {
      SSL_shutdown(ssl);
      return true;
   }
   if(cfg.app_data.mode == AppDataMode::ShimWrites) {
      write_all(ssl, packeted,
                reinterpret_cast<const uint8_t*>(cfg.app_data.send.data()), cfg.app_data.send.size());
      SSL_shutdown(ssl);
      return true;
   }

   send_key_material(ssl, packeted, cfg, connection_index);
   AppDataResponder responder;
   std::array<uint8_t, 16384> buf{};
   for(;;) {
      const int ret = SSL_read(ssl, buf.data(), buf.size());
      if(ret > 0) {
         for(const auto& reply : responder.receive(buf.data(), static_cast<size_t>(ret))) {
            write_all(ssl, packeted, reply.data(), reply.size());
         }
         continue;
      }
      const int err = SSL_get_error(ssl, ret);
      if((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) && retry(ssl, ret, packeted)) {
         continue;
      }
      if(err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && ret == 0)) {
         SSL_shutdown(ssl);
         return true;
      }
      return false;
   }
}

SessionPtr run_connection(const ShimConfig& cfg, SSL_CTX* ctx, SSL_SESSION* prior,
                          uint32_t connection_index) {
   g_new_session.reset();
   ShimSocket socket(cfg.runner.host, cfg.runner.port, cfg.runner.ipv6);
   socket.write_shim_id(cfg.shim_id);

   SslPtr ssl(SSL_new(ctx));
   if(!ssl) throw std::runtime_error("SSL_new failed: " + errors());
   configure_connection(ssl.get(), cfg, prior);
   cfg.is_server() ? SSL_set_accept_state(ssl.get()) : SSL_set_connect_state(ssl.get());

   BIO* raw = BIO_new_socket(socket.fd(), BIO_NOCLOSE);
   if(raw == nullptr) throw std::runtime_error("BIO_new_socket failed");
   BIO* packeted_raw = nullptr;
   if(cfg.is_dtls()) {
      auto packeted = PacketedBioCreate(&g_clock, ssl.get());
      if(!packeted) {
         BIO_free(raw);
         throw std::runtime_error("PacketedBioCreate failed");
      }
      packeted_raw = packeted.get();
      BIO_push(packeted.get(), raw);
      SSL_set_bio(ssl.get(), packeted.get(), packeted.get());
      packeted.release();
   } else {
      SSL_set_bio(ssl.get(), raw, raw);
   }

   const int hs = drive_handshake(ssl.get(), packeted_raw);
   if(hs != 1) {
      const std::string reason = "handshake failed: " + errors();
      if(cfg.expect.handshake_error || cfg.expect.handshake_abandoned) {
         throw ShimOutcome(ShimResult::Ok, reason);
      }
      throw ShimOutcome(ShimResult::HandshakeFailed, reason);
   }
   if(const auto mismatch = check_expectations(ssl.get(), cfg)) {
      throw ShimOutcome(ShimResult::ExpectationMismatch, *mismatch);
   }

   if(cfg.is_server() && !cfg.is_dtls() && SSL_version(ssl.get()) == TLS1_3_VERSION) {
      flush_post_handshake_tickets(ssl.get(), packeted_raw);
   }

   if(!application_data(ssl.get(), packeted_raw, cfg, connection_index)) {
      const std::string reason = "record flow failed: " + errors();
      if(cfg.expect.handshake_error || cfg.expect.handshake_abandoned) {
         throw ShimOutcome(ShimResult::Ok, reason);
      }
      throw ShimOutcome(ShimResult::HandshakeFailed, reason);
   }
   if(cfg.expect.handshake_error) {
      throw ShimOutcome(ShimResult::UnexpectedSuccess,
                        "expected the handshake or record flow to fail but it completed");
   }
   if(g_new_session) return std::move(g_new_session);
   return SessionPtr(SSL_get1_session(ssl.get()));
}

}  // namespace

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   std::signal(SIGPIPE, SIG_IGN);
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string arg = argv[i];
      if(arg == "--plzn-shim-info") {
         std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"boringssl","expectations":"boringssl-expectations.json"})"
                   << std::endl;
         return 0;
      }
      if(arg == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(arg.rfind("-config=", 0) == 0) {
         config_path = arg.substr(8);
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: boringssl_shim -config <file.json> | --plzn-shim-info\n";
      return 2;
   }

   try {
      const ShimConfig cfg = ShimConfig::from_file(config_path);
      preflight(cfg);
      gettimeofday(&g_clock, nullptr);
      ContextPtr ctx(SSL_CTX_new(cfg.is_dtls() ? DTLS_method() : TLS_method()));
      if(!ctx) throw std::runtime_error("SSL_CTX_new failed: " + errors());
      configure_context(ctx.get(), cfg);

      SessionPtr session;
      for(uint32_t i = 0; i <= cfg.resume_count; ++i) {
         const auto connection_cfg = cfg.for_connection(i);
         session = run_connection(connection_cfg, ctx.get(), session.get(), i);
      }
      report_success();
   } catch(const ShimOutcome& outcome) {
      report_result(outcome.result(), outcome.detail());
   } catch(const ShimSocketError& e) {
      report_result(ShimResult::IoError, e.what());
   } catch(const std::exception& e) {
      report_result(ShimResult::LocalError, e.what());
   }
}
