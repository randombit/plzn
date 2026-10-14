/*
 * GnuTLS interop shim for plzn.
 *
 * The shim deliberately uses GnuTLS's public session and credential APIs. TLS
 * records travel directly over the runner connection after the 8-byte ShimID;
 * DTLS datagrams use plzn's P framing through custom push/pull callbacks.
 */

#include <gnutls/dtls.h>
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <poll.h>

#include "plzn_shim.h"

using plzn::ShimConfig;
using plzn::ShimResult;
using plzn::ShimSocket;

namespace {

class GnuTlsError final : public std::runtime_error {
   public:
      GnuTlsError(const std::string& where, int code) :
            std::runtime_error(where + ": " + gnutls_strerror(code) + " (" +
                               (gnutls_strerror_name(code) != nullptr ? gnutls_strerror_name(code) : "unknown") + ")"),
            m_code(code) {}

      int code() const { return m_code; }

   private:
      int m_code;
};

void require_ok(int rc, const std::string& where) {
   if(rc < 0) {
      throw GnuTlsError(where, rc);
   }
}

struct CredentialsDeleter {
      void operator()(gnutls_certificate_credentials_st* p) const {
         if(p != nullptr) {
            gnutls_certificate_free_credentials(p);
         }
      }
};

using CredentialsPtr = std::unique_ptr<gnutls_certificate_credentials_st, CredentialsDeleter>;

struct PskClientCredentialsDeleter {
      void operator()(gnutls_psk_client_credentials_st* p) const {
         if(p != nullptr) {
            gnutls_psk_free_client_credentials(p);
         }
      }
};

using PskClientCredentialsPtr =
   std::unique_ptr<gnutls_psk_client_credentials_st, PskClientCredentialsDeleter>;

struct PskServerCredentialsDeleter {
      void operator()(gnutls_psk_server_credentials_st* p) const {
         if(p != nullptr) {
            gnutls_psk_free_server_credentials(p);
         }
      }
};

using PskServerCredentialsPtr =
   std::unique_ptr<gnutls_psk_server_credentials_st, PskServerCredentialsDeleter>;

struct SessionDeleter {
      void operator()(gnutls_session_int* p) const {
         if(p != nullptr) {
            gnutls_deinit(p);
         }
      }
};

using SessionPtr = std::unique_ptr<gnutls_session_int, SessionDeleter>;

class OwnedDatum final {
   public:
      OwnedDatum() = default;
      ~OwnedDatum() {
         if(m_value.data != nullptr) {
            gnutls_memset(m_value.data, 0, m_value.size);
            gnutls_free(m_value.data);
         }
      }

      OwnedDatum(const OwnedDatum&) = delete;
      OwnedDatum& operator=(const OwnedDatum&) = delete;

      gnutls_datum_t* out() { return &m_value; }
      const gnutls_datum_t* get() const { return m_value.data == nullptr ? nullptr : &m_value; }

   private:
      gnutls_datum_t m_value{};
};

struct AntiReplayDeleter {
      void operator()(gnutls_anti_replay_st* p) const {
         if(p != nullptr) {
            gnutls_anti_replay_deinit(p);
         }
      }
};

using AntiReplayPtr = std::unique_ptr<gnutls_anti_replay_st, AntiReplayDeleter>;

int anti_replay_add(void* ptr,
                    time_t /*expiration*/,
                    const gnutls_datum_t* key,
                    const gnutls_datum_t* /*data*/) {
   auto& seen = *static_cast<std::unordered_set<std::string>*>(ptr);
   const std::string encoded(reinterpret_cast<const char*>(key->data), key->size);
   return seen.insert(encoded).second ? GNUTLS_E_SUCCESS : GNUTLS_E_DB_ENTRY_EXISTS;
}

// The server's session-ID cache. GnuTLS keeps none of its own, so without
// these callbacks a server can resume only from a ticket.
using SessionCache = std::unordered_map<std::string, std::string>;

std::string datum_string(const gnutls_datum_t& d) {
   return std::string(reinterpret_cast<const char*>(d.data), d.size);
}

int session_cache_store(void* ptr, gnutls_datum_t key, gnutls_datum_t data) {
   (*static_cast<SessionCache*>(ptr))[datum_string(key)] = datum_string(data);
   return 0;
}

gnutls_datum_t session_cache_retrieve(void* ptr, gnutls_datum_t key) {
   gnutls_datum_t out{nullptr, 0};
   const auto& cache = *static_cast<SessionCache*>(ptr);
   const auto it = cache.find(datum_string(key));
   if(it != cache.end()) {
      out.data = static_cast<unsigned char*>(gnutls_malloc(it->second.size()));
      if(out.data != nullptr) {
         std::memcpy(out.data, it->second.data(), it->second.size());
         out.size = static_cast<unsigned int>(it->second.size());
      }
   }
   return out;
}

int session_cache_remove(void* ptr, gnutls_datum_t key) {
   static_cast<SessionCache*>(ptr)->erase(datum_string(key));
   return 0;
}

// A server that requires or requests a client certificate verifies it against
// the trust list, as every shim server does (docs/USAGE.md). GnuTLS verifies a
// peer chain only through a verify function; gnutls_session_set_verify_cert
// would also fail an absent certificate under GNUTLS_CERT_REQUEST and a raw
// public key, so absence stays governed by the request mode and a raw public
// key has no chain to verify.
int verify_client_certificate(gnutls_session_t session) {
   unsigned int count = 0;
   if(gnutls_certificate_get_peers(session, &count) == nullptr || count == 0) {
      return 0;
   }
   if(gnutls_certificate_type_get2(session, GNUTLS_CTYPE_PEERS) != GNUTLS_CRT_X509) {
      return 0;
   }
   unsigned int status = 0;
   if(gnutls_certificate_verify_peers2(session, &status) < 0 || status != 0) {
      return GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR;
   }
   return 0;
}

std::string group_priority(uint16_t id) {
   switch(id) {
      case 23: return "GROUP-SECP256R1";
      case 24: return "GROUP-SECP384R1";
      case 25: return "GROUP-SECP521R1";
      case 29: return "GROUP-X25519";
      case 30: return "GROUP-X448";
      case 256: return "GROUP-FFDHE2048";
      case 257: return "GROUP-FFDHE3072";
      case 258: return "GROUP-FFDHE4096";
      case 259: return "GROUP-FFDHE6144";
      case 260: return "GROUP-FFDHE8192";
      default: return {};
   }
}

std::string signature_priority(uint16_t id) {
   switch(id) {
      case 0x0201: return "SIGN-RSA-SHA1";
      case 0x0203: return "SIGN-ECDSA-SHA1";
      case 0x0401: return "SIGN-RSA-SHA256";
      case 0x0501: return "SIGN-RSA-SHA384";
      case 0x0601: return "SIGN-RSA-SHA512";
      case 0x0403: return "SIGN-ECDSA-SECP256R1-SHA256";
      case 0x0503: return "SIGN-ECDSA-SECP384R1-SHA384";
      case 0x0603: return "SIGN-ECDSA-SECP521R1-SHA512";
      case 0x0804: return "SIGN-RSA-PSS-RSAE-SHA256";
      case 0x0805: return "SIGN-RSA-PSS-RSAE-SHA384";
      case 0x0806: return "SIGN-RSA-PSS-RSAE-SHA512";
      case 0x0807: return "SIGN-EDDSA-ED25519";
      case 0x0808: return "SIGN-EDDSA-ED448";
      case 0x0809: return "SIGN-RSA-PSS-PSS-SHA256";
      case 0x080A: return "SIGN-RSA-PSS-PSS-SHA384";
      case 0x080B: return "SIGN-RSA-PSS-PSS-SHA512";
      default: return {};
   }
}

struct SuiteAlgorithms {
      bool found = false;
      gnutls_kx_algorithm_t kx = GNUTLS_KX_UNKNOWN;
      gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
      gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;
};

SuiteAlgorithms suite_algorithms(uint16_t wanted) {
   for(size_t i = 0;; ++i) {
      unsigned char id[2] = {0, 0};
      gnutls_kx_algorithm_t kx = GNUTLS_KX_UNKNOWN;
      gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
      gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;
      if(gnutls_cipher_suite_info(i, id, &kx, &cipher, &mac, nullptr) == nullptr) {
         return {};
      }
      if((static_cast<uint16_t>(id[0]) << 8 | id[1]) == wanted) {
         return {true, kx, cipher, mac};
      }
   }
}

void append_priority_component(std::string& priority, const char* component) {
   if(component != nullptr && component[0] != '\0') {
      priority += ":+";
      priority += component;
   }
}

bool priority_enables_suite(const std::string& priority, uint16_t wanted);

std::string priority_for(const ShimConfig& cfg) {
   std::string priority = "NORMAL:-VERS-ALL";
   if(cfg.is_dtls()) {
      priority += ":+VERS-DTLS1.2";
   } else {
      const uint16_t min = cfg.min_version.value_or(0x0303);
      const uint16_t max = cfg.max_version.value_or(0x0304);
      if(min <= 0x0301 && max >= 0x0301) {
         priority += ":+VERS-TLS1.0";
      }
      if(min <= 0x0302 && max >= 0x0302) {
         priority += ":+VERS-TLS1.1";
      }
      if(min <= 0x0303 && max >= 0x0303) {
         priority += ":+VERS-TLS1.2";
      }
      if(min <= 0x0304 && max >= 0x0304) {
         priority += ":+VERS-TLS1.3";
      }
   }

   // NORMAL is a security posture, not the library's capability set: it omits
   // (among others) 3DES, NULL, Camellia-GCM, CCM_8, and the legacy SHA-2 CBC
   // MACs. Tests name suites explicitly, so add every implemented component
   // required by that offer. For a single explicit UUT suite, remove all
   // cipher/MAC/KX components first; this is GnuTLS's component-level spelling
   // of an exact one-suite policy. Multiple arbitrary suites cannot be encoded
   // without also admitting their cross-product and are rejected in preflight.
   const auto& suites = cfg.cipher_suites.empty() ? cfg.requires_any_suite : cfg.cipher_suites;
   if(!cfg.cipher_suites.empty()) {
      priority += ":-CIPHER-ALL:-MAC-ALL:-KX-ALL";
   }
   // `requires.any_suite` is a participation check, not an exact policy. Keep
   // NORMAL when it already supplies any acceptable suite; adding every
   // component from a broad TLS 1.2+1.3 catalogue creates an unusable
   // cross-product (and some GnuTLS versions reject legacy components in a
   // TLS-1.3-only priority altogether). A narrow legacy-only requirement such
   // as 3DES still falls through and has its disabled-by-default components
   // enabled below.
   const bool normal_satisfies_requirement = cfg.cipher_suites.empty() &&
      std::any_of(suites.begin(), suites.end(), [&priority](uint16_t suite) {
         return priority_enables_suite(priority, suite);
      });
   const bool tls12_enabled = cfg.is_dtls() ||
      (cfg.min_version.value_or(0x0303) <= 0x0303 &&
       cfg.max_version.value_or(0x0304) >= 0x0301);
   const bool tls13_enabled = !cfg.is_dtls() &&
      cfg.min_version.value_or(0x0303) <= 0x0304 &&
      cfg.max_version.value_or(0x0304) >= 0x0304;
   for(const uint16_t suite : normal_satisfies_requirement ? std::vector<uint16_t>{} : suites) {
      const bool tls13_suite = suite >= 0x1301 && suite <= 0x1305;
      if((tls13_suite && !tls13_enabled) || (!tls13_suite && !tls12_enabled)) {
         continue;
      }
      const auto algorithms = suite_algorithms(suite);
      if(!algorithms.found) {
         continue;
      }
      append_priority_component(priority, gnutls_cipher_get_name(algorithms.cipher));
      append_priority_component(priority, gnutls_mac_get_name(algorithms.mac));
      append_priority_component(priority, gnutls_kx_get_name(algorithms.kx));
   }
   // TLS 1.3 ciphersuites no longer encode authentication, so their catalogue
   // entries do not carry GNUTLS_KX_PSK. GnuTLS still uses the PSK priority bit
   // to decide whether to process external identities and binders, and the
   // (EC)DHE-PSK bits to decide whether psk_dhe_ke is acceptable.
   if(cfg.psk.present && !cfg.is_dtls() &&
      cfg.max_version.value_or(0x0304) >= 0x0304) {
      append_priority_component(priority, gnutls_kx_get_name(GNUTLS_KX_PSK));
      append_priority_component(priority, gnutls_kx_get_name(GNUTLS_KX_ECDHE_PSK));
      append_priority_component(priority, gnutls_kx_get_name(GNUTLS_KX_DHE_PSK));
   }

   if(!cfg.curves.empty()) {
      priority += ":-GROUP-ALL";
      for(const uint16_t id : cfg.curves) {
         const auto group = group_priority(id);
         if(!group.empty()) {
            priority += ":+" + group;
         }
      }
   }

   // GnuTLS exposes one priority list for both locally-created and verified
   // signatures. preflight() rejects two different lists rather than silently
   // applying only one of them.
   const auto& sigs = cfg.signing_prefs.empty() ? cfg.verify_prefs : cfg.signing_prefs;
   if(!sigs.empty()) {
      priority += ":-SIGN-ALL";
      for(const uint16_t id : sigs) {
         const auto sig = signature_priority(id);
         if(!sig.empty()) {
            priority += ":+" + sig;
         }
      }
   }
   if(cfg.encrypt_then_mac.has_value()) {
      priority += *cfg.encrypt_then_mac ? ":%FORCE_ETM" : ":%NO_ETM";
   }
   const auto append_cert_types = [&](const char* target, const std::vector<uint8_t>& types) {
      for(const auto type : types) {
         priority += type == 2 ? ":+CTYPE-" + std::string(target) + "-RAWPK"
                              : ":+CTYPE-" + std::string(target) + "-X509";
      }
   };
   if(!cfg.server_certificate_types.empty() || !cfg.client_certificate_types.empty()) {
      // The asymmetric lists have asymmetric catch-alls too. Removing the
      // global CTYPE list leaves GnuTLS's TLS 1.2 compatibility check without
      // either role-specific list even after +CTYPE-SRV/CLI additions.
      priority += ":-CTYPE-SRV-ALL:-CTYPE-CLI-ALL";
      const std::vector<uint8_t> default_x509 = {0};
      append_cert_types("SRV", cfg.server_certificate_types.empty()
                                  ? default_x509
                                  : cfg.server_certificate_types);
      append_cert_types("CLI", cfg.client_certificate_types.empty()
                                  ? default_x509
                                  : cfg.client_certificate_types);
   }
   return priority;
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
   if(hex.size() % 2 != 0) {
      throw std::runtime_error("PSK secret has an odd number of hex digits");
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
         throw std::runtime_error("PSK secret contains a non-hex digit");
      }
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
   }
   return out;
}

struct ConnectionState {
      const ShimConfig* cfg = nullptr;
      size_t early_data_received = 0;
};

int psk_server_credentials_cb(gnutls_session_t session,
                              const gnutls_datum_t* username,
                              gnutls_datum_t* key) {
   const auto* state = static_cast<const ConnectionState*>(gnutls_session_get_ptr(session));
   const auto* cfg = state->cfg;
   if(cfg == nullptr || username == nullptr ||
      username->size != cfg->psk.identity.size() ||
      std::memcmp(username->data, cfg->psk.identity.data(), username->size) != 0) {
      return -1;
   }
   try {
      const auto decoded = hex_decode(cfg->psk.secret_hex);
      key->data = static_cast<unsigned char*>(gnutls_malloc(decoded.size()));
      if(key->data == nullptr && !decoded.empty()) {
         return GNUTLS_E_MEMORY_ERROR;
      }
      std::memcpy(key->data, decoded.data(), decoded.size());
      key->size = static_cast<unsigned int>(decoded.size());
      return 0;
   } catch(...) {
      return -1;
   }
}

int receive_early_data_hook(gnutls_session_t session,
                            unsigned int /*htype*/,
                            unsigned /*when*/,
                            unsigned int incoming,
                            const gnutls_datum_t* /*message*/) {
   if(incoming == 0) {
      return GNUTLS_E_SUCCESS;
   }
   auto* state = static_cast<ConnectionState*>(gnutls_session_get_ptr(session));
   std::vector<uint8_t> buf(16 * 1024);
   for(;;) {
      const ssize_t n = gnutls_record_recv_early_data(session, buf.data(), buf.size());
      if(n == 0) {
         return GNUTLS_E_SUCCESS;
      }
      if(n == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE && state->early_data_received > 0) {
         return GNUTLS_E_SUCCESS;
      }
      if(n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
         continue;
      }
      if(n < 0) {
         return static_cast<int>(n);
      }
      state->early_data_received += static_cast<size_t>(n);
   }
}

#if GNUTLS_VERSION_NUMBER >= 0x03080D
gnutls_mac_algorithm_t psk_binder_mac(const ShimConfig& cfg) {
   // A pinned AES-256-GCM TLS 1.3 suite uses SHA-384. The normal plzn external
   // PSK offer, like the OpenSSL shim's find-session callback, uses SHA-256.
   return cfg.cipher_suites.size() == 1 && cfg.cipher_suites[0] == 0x1302
             ? GNUTLS_MAC_SHA384
             : GNUTLS_MAC_SHA256;
}
#endif

bool priority_enables_suite(const std::string& priority, uint16_t wanted) {
   gnutls_priority_t cache = nullptr;
   const char* error = nullptr;
   if(gnutls_priority_init(&cache, priority.c_str(), &error) < 0) {
      return false;
   }
   struct PriorityGuard {
         gnutls_priority_t cache;
         ~PriorityGuard() { gnutls_priority_deinit(cache); }
   } guard{cache};

   for(unsigned int i = 0;; ++i) {
      unsigned int suite_index = 0;
      const int rc = gnutls_priority_get_cipher_suite_index(cache, i, &suite_index);
      if(rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
         return false;
      }
      if(rc < 0) {
         continue;
      }
      unsigned char id[2] = {0, 0};
      const char* name =
         gnutls_cipher_suite_info(suite_index, id, nullptr, nullptr, nullptr, nullptr);
      if(name == nullptr) {
         continue;
      }
      if((static_cast<uint16_t>(id[0]) << 8 | id[1]) == wanted) {
         return true;
      }
   }
}

bool suite_enabled_by_priority(const ShimConfig& cfg, uint16_t wanted) {
   return priority_enables_suite(priority_for(cfg), wanted);
}

bool group_supported(uint16_t id) {
   const std::string token = group_priority(id);
   if(token.empty()) {
      return false;
   }
   return gnutls_group_get_id(token.substr(std::strlen("GROUP-")).c_str()) !=
          GNUTLS_GROUP_INVALID;
}

uint16_t negotiated_suite(gnutls_session_t session) {
   const auto selected_kx = gnutls_kx_get(session);
   const auto selected_cipher = gnutls_cipher_get(session);
   const auto selected_mac = gnutls_mac_get(session);
   const bool selected_tls13 = gnutls_protocol_get_version(session) == GNUTLS_TLS1_3;
   for(size_t i = 0;; ++i) {
      unsigned char id[2] = {0, 0};
      gnutls_kx_algorithm_t kx = GNUTLS_KX_UNKNOWN;
      gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
      gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;
      gnutls_protocol_t version = GNUTLS_VERSION_UNKNOWN;
      const char* name = gnutls_cipher_suite_info(i, id, &kx, &cipher, &mac, &version);
      if(name == nullptr) {
         return 0;
      }
      if((version == GNUTLS_TLS1_3) == selected_tls13 &&
         (selected_tls13 || kx == selected_kx) &&
         cipher == selected_cipher && mac == selected_mac) {
         return static_cast<uint16_t>(id[0]) << 8 | id[1];
      }
   }
}

uint16_t negotiated_version(gnutls_session_t session) {
   switch(gnutls_protocol_get_version(session)) {
      case GNUTLS_TLS1_0: return 0x0301;
      case GNUTLS_TLS1_1: return 0x0302;
      case GNUTLS_TLS1_2: return 0x0303;
      case GNUTLS_TLS1_3: return 0x0304;
      case GNUTLS_DTLS1_2: return 0xFEFD;
      default: return 0;
   }
}

struct DtlsIo {
      ShimSocket* socket = nullptr;
      std::string error;
};

ssize_t dtls_push(gnutls_transport_ptr_t ptr, const void* data, size_t len) {
   auto* io = static_cast<DtlsIo*>(ptr);
   try {
      io->socket->write_dtls_packet(static_cast<const uint8_t*>(data), len);
      return static_cast<ssize_t>(len);
   } catch(const std::exception& e) {
      io->error = e.what();
      errno = EIO;
      return -1;
   }
}

ssize_t dtls_pull(gnutls_transport_ptr_t ptr, void* data, size_t len) {
   auto* io = static_cast<DtlsIo*>(ptr);
   try {
      for(;;) {
         const auto event = io->socket->read_dtls_event();
         if(event.opcode == plzn::DtlsOpcode::Eof) {
            return 0;
         }
         if(event.opcode != plzn::DtlsOpcode::Packet) {
            io->error = "unexpected DTLS timer/control command";
            errno = ENOTSUP;
            return -1;
         }
         const size_t copied = std::min(len, event.packet.size());
         std::memcpy(data, event.packet.data(), copied);
         return static_cast<ssize_t>(copied);
      }
   } catch(const std::exception& e) {
      io->error = e.what();
      errno = EIO;
      return -1;
   }
}

int dtls_pull_timeout(gnutls_transport_ptr_t /*ptr*/, unsigned int /*ms*/) {
   // The runner connection itself is blocking. Reporting readiness makes
   // GnuTLS enter dtls_pull(), which waits for the next framed datagram.
   return 1;
}

int tls_pull_timeout(gnutls_transport_ptr_t ptr, unsigned int ms) {
   const int fd = static_cast<int>(reinterpret_cast<intptr_t>(ptr));
   pollfd descriptor{fd, POLLIN, 0};
   int rc;
   do {
      rc = poll(&descriptor, 1, static_cast<int>(ms));
   } while(rc < 0 && errno == EINTR);
   return rc;
}

CredentialsPtr make_credentials(const ShimConfig& cfg) {
   gnutls_certificate_credentials_t raw = nullptr;
   require_ok(gnutls_certificate_allocate_credentials(&raw), "allocate certificate credentials");
   CredentialsPtr creds(raw);

   const auto& local_types = cfg.is_server() ? cfg.server_certificate_types : cfg.client_certificate_types;
   const bool load_x509 = local_types.empty() ||
                          std::find(local_types.begin(), local_types.end(), 0) != local_types.end();
   const bool load_rawpk =
      std::find(local_types.begin(), local_types.end(), 2) != local_types.end();

   if(cfg.is_server()) {
      // plzn's TLS 1.2 ClientHello does not need to advertise an RFC 7919
      // FFDHE group for classic DHE_RSA suites. Give GnuTLS a standard fallback
      // group for that pre-supported_groups form of negotiation.
      require_ok(gnutls_certificate_set_known_dh_params(creds.get(), GNUTLS_SEC_PARAM_MEDIUM),
                 "configure certificate DH parameters");
   }

   if(!cfg.credentials.trust_file.empty()) {
      require_ok(gnutls_certificate_set_x509_trust_file(
                    creds.get(), cfg.credentials.trust_file.c_str(), GNUTLS_X509_FMT_PEM),
                 "load trust file");
   }

   const auto& chains = cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains;
   for(const auto& chain : chains) {
      if(load_x509) {
         require_ok(gnutls_certificate_set_x509_key_file(creds.get(),
                                                          chain.cert_file.c_str(),
                                                          chain.key_file.c_str(),
                                                          GNUTLS_X509_FMT_PEM),
                    "load certificate/key");
      }

      if(load_rawpk) {
         OwnedDatum cert;
         OwnedDatum key;
         OwnedDatum spki;
         require_ok(gnutls_load_file(chain.cert_file.c_str(), cert.out()), "load certificate for raw public key");
         require_ok(gnutls_load_file(chain.key_file.c_str(), key.out()), "load private key for raw public key");
         gnutls_pubkey_t raw_pubkey = nullptr;
         require_ok(gnutls_pubkey_init(&raw_pubkey), "initialize raw public key");
         const int import_rc = gnutls_pubkey_import_x509_raw(raw_pubkey, cert.get(), GNUTLS_X509_FMT_PEM, 0);
         if(import_rc < 0) {
            gnutls_pubkey_deinit(raw_pubkey);
            require_ok(import_rc, "extract raw public key from certificate");
         }
         const int export_rc = gnutls_pubkey_export2(raw_pubkey, GNUTLS_X509_FMT_PEM, spki.out());
         gnutls_pubkey_deinit(raw_pubkey);
         require_ok(export_rc, "encode raw public key");

         std::vector<unsigned char> terminated_spki(spki.get()->data,
                                                    spki.get()->data + spki.get()->size);
         terminated_spki.push_back(0);
         gnutls_datum_t spki_pem{terminated_spki.data(), spki.get()->size};
         std::vector<unsigned char> terminated_key(key.get()->data,
                                                   key.get()->data + key.get()->size);
         terminated_key.push_back(0);
         gnutls_datum_t key_pem{terminated_key.data(), key.get()->size};
         require_ok(gnutls_certificate_set_rawpk_key_mem(creds.get(),
                                                         &spki_pem,
                                                         &key_pem,
                                                         GNUTLS_X509_FMT_PEM,
                                                         nullptr,
                                                         GNUTLS_KEY_DIGITAL_SIGNATURE,
                                                         nullptr,
                                                         0,
                                                         0),
                    "load raw public key credential");
      }
   }
   return creds;
}

void configure_alpn(gnutls_session_t session, const ShimConfig& cfg) {
   std::vector<std::string> names;
   unsigned flags = 0;
   if(cfg.is_server()) {
      if(cfg.alpn.decline || (cfg.alpn.select.empty() && cfg.alpn.select_from.empty())) {
         return;
      }
      names = cfg.alpn.select_from;
      if(!cfg.alpn.select.empty()) {
         names.insert(names.begin(), cfg.alpn.select);
      }
      flags = GNUTLS_ALPN_SERVER_PRECEDENCE;
   } else {
      names = cfg.alpn.advertise;
   }
   if(names.empty()) {
      return;
   }
   std::vector<gnutls_datum_t> protocols;
   protocols.reserve(names.size());
   for(auto& name : names) {
      protocols.push_back({reinterpret_cast<unsigned char*>(name.data()),
                           static_cast<unsigned int>(name.size())});
   }
   require_ok(gnutls_alpn_set_protocols(session, protocols.data(), protocols.size(), flags),
              "configure ALPN");
}

void check_expectations(gnutls_session_t session, const ShimConfig& cfg) {
   if(cfg.expect.version.has_value() && negotiated_version(session) != *cfg.expect.version) {
      throw plzn::ShimExpectationError("version mismatch: expected " + std::to_string(*cfg.expect.version) +
                               ", got " + std::to_string(negotiated_version(session)));
   }
   if(cfg.expect.cipher.has_value() && negotiated_suite(session) != *cfg.expect.cipher) {
      throw plzn::ShimExpectationError("cipher mismatch: expected " + std::to_string(*cfg.expect.cipher) +
                               ", got " + std::to_string(negotiated_suite(session)));
   }
   if(cfg.expect.resumed.has_value() &&
      (gnutls_session_is_resumed(session) != 0) != *cfg.expect.resumed) {
      throw plzn::ShimExpectationError("session-resumption expectation mismatch");
   }
   if(cfg.alpn.expect.has_value() || cfg.expect.alpn.has_value()) {
      const auto& expected = cfg.alpn.expect.has_value() ? *cfg.alpn.expect : *cfg.expect.alpn;
      gnutls_datum_t selected{};
      const int rc = gnutls_alpn_get_selected_protocol(session, &selected);
      const std::string actual = rc == 0 ? std::string(reinterpret_cast<char*>(selected.data), selected.size) : "";
      if(actual != expected) {
         throw plzn::ShimExpectationError("ALPN mismatch: expected '" + expected + "', got '" + actual + "'");
      }
   }
   if(cfg.expect_server_name.has_value()) {
      char name[256] = {0};
      size_t size = sizeof(name);
      unsigned type = 0;
      const int rc = gnutls_server_name_get(session, name, &size, &type, 0);
      const std::string actual = rc == 0 ? std::string(name, size) : "";
      if(actual != *cfg.expect_server_name) {
         throw plzn::ShimExpectationError("SNI mismatch: expected '" + *cfg.expect_server_name + "', got '" + actual + "'");
      }
   }
}

void run_connection(const ShimConfig& cfg,
                    gnutls_certificate_credentials_t creds,
                    uint32_t connection_index,
                    const gnutls_datum_t* ticket_key,
                    gnutls_anti_replay_t anti_replay,
                    SessionCache& session_cache,
                    std::vector<uint8_t>& client_session_data) {
   ShimSocket socket(cfg.runner.host, cfg.runner.port, cfg.runner.ipv6);
   socket.write_shim_id(cfg.shim_id);

   // Credential objects must outlive the session that refers to them.
   PskClientCredentialsPtr client_psk;
   PskServerCredentialsPtr server_psk;
   std::vector<uint8_t> client_psk_key;
   if(cfg.psk.present) {
      if(cfg.is_server()) {
         gnutls_psk_server_credentials_t raw_psk = nullptr;
#if GNUTLS_VERSION_NUMBER >= 0x03080D
         const int rc = (!cfg.is_dtls() && cfg.max_version.value_or(0x0304) >= 0x0304)
                           ? gnutls_psk_allocate_server_credentials2(&raw_psk, GNUTLS_MAC_UNKNOWN)
                           : gnutls_psk_allocate_server_credentials(&raw_psk);
#else
         const int rc = gnutls_psk_allocate_server_credentials(&raw_psk);
#endif
         require_ok(rc, "allocate server PSK credentials");
         server_psk.reset(raw_psk);
         gnutls_psk_set_server_credentials_function2(server_psk.get(), psk_server_credentials_cb);
         require_ok(gnutls_psk_set_server_known_dh_params(
                       server_psk.get(), GNUTLS_SEC_PARAM_MEDIUM),
                    "configure PSK DH parameters");
      } else {
         gnutls_psk_client_credentials_t raw_psk = nullptr;
#if GNUTLS_VERSION_NUMBER >= 0x03080D
         const int rc = (!cfg.is_dtls() && cfg.max_version.value_or(0x0304) >= 0x0304)
                           ? gnutls_psk_allocate_client_credentials2(&raw_psk, psk_binder_mac(cfg))
                           : gnutls_psk_allocate_client_credentials(&raw_psk);
#else
         const int rc = gnutls_psk_allocate_client_credentials(&raw_psk);
#endif
         require_ok(rc, "allocate client PSK credentials");
         client_psk.reset(raw_psk);
         client_psk_key = hex_decode(cfg.psk.secret_hex);
         gnutls_datum_t identity{
            reinterpret_cast<unsigned char*>(const_cast<char*>(cfg.psk.identity.data())),
            static_cast<unsigned int>(cfg.psk.identity.size())};
         gnutls_datum_t key{client_psk_key.data(), static_cast<unsigned int>(client_psk_key.size())};
         require_ok(gnutls_psk_set_client_credentials2(
                       client_psk.get(), &identity, &key, GNUTLS_PSK_KEY_RAW),
                    "configure client PSK credentials");
      }
   }

   unsigned flags = (cfg.is_server() ? GNUTLS_SERVER : GNUTLS_CLIENT) | GNUTLS_NO_SIGNAL |
                    GNUTLS_ENABLE_RAWPK;
   if(cfg.is_dtls()) {
      flags |= GNUTLS_DATAGRAM;
   }
   if(cfg.no_ticket) {
      flags |= GNUTLS_NO_TICKETS;
   }
   if(cfg.session_tickets == 0) {
      flags |= GNUTLS_NO_TICKETS;
   }
   if(cfg.session_tickets.has_value() && *cfg.session_tickets > 0) {
      flags |= GNUTLS_NO_AUTO_SEND_TICKET;
   }
   if((cfg.is_server() && cfg.max_early_data.value_or(0) > 0) ||
      (!cfg.is_server() && cfg.early_data_send > 0)) {
      flags |= GNUTLS_ENABLE_EARLY_DATA;
   }
   gnutls_session_t raw = nullptr;
   require_ok(gnutls_init(&raw, flags), "initialize session");
   SessionPtr session(raw);
   ConnectionState state{&cfg, 0};
   gnutls_session_set_ptr(session.get(), &state);
   if(cfg.is_server()) {
      gnutls_db_set_retrieve_function(session.get(), session_cache_retrieve);
      gnutls_db_set_store_function(session.get(), session_cache_store);
      gnutls_db_set_remove_function(session.get(), session_cache_remove);
      gnutls_db_set_ptr(session.get(), &session_cache);
   }
   if(cfg.is_server() && ticket_key != nullptr) {
      require_ok(gnutls_session_ticket_enable_server(session.get(), ticket_key),
                 "enable server session tickets");
   } else if(!cfg.is_server() && !cfg.no_ticket && cfg.session_tickets != 0) {
      require_ok(gnutls_session_ticket_enable_client(session.get()),
                 "enable client session tickets");
   }
   if(cfg.is_server() && cfg.max_early_data.value_or(0) > 0) {
      require_ok(gnutls_record_set_max_early_data_size(session.get(), *cfg.max_early_data),
                 "set maximum early data size");
      if(anti_replay != nullptr) {
         gnutls_anti_replay_enable(session.get(), anti_replay);
      }
   }
   if(cfg.is_server() && cfg.early_data_expect > 0) {
      // Read while the buffered early records still exist. GnuTLS 3.8.13
      // removes them while processing EndOfEarlyData, so its documented POST
      // hook (and the documented post-handshake call) reports no data.
      gnutls_handshake_set_hook_function(session.get(),
                                         GNUTLS_HANDSHAKE_END_OF_EARLY_DATA,
                                         GNUTLS_HOOK_PRE,
                                         receive_early_data_hook);
   }
   require_ok(gnutls_credentials_set(session.get(), GNUTLS_CRD_CERTIFICATE, creds),
              "attach certificate credentials");
   if(server_psk) {
      require_ok(gnutls_credentials_set(session.get(), GNUTLS_CRD_PSK, server_psk.get()),
                 "attach server PSK credentials");
   }
   if(client_psk) {
      require_ok(gnutls_credentials_set(session.get(), GNUTLS_CRD_PSK, client_psk.get()),
                 "attach client PSK credentials");
   }

   const std::string priority = priority_for(cfg);
   const char* priority_error = nullptr;
   const int priority_rc = gnutls_priority_set_direct(session.get(), priority.c_str(), &priority_error);
   if(priority_rc < 0) {
      const size_t offset = priority_error == nullptr ? 0 : static_cast<size_t>(priority_error - priority.c_str());
      throw std::runtime_error("GnuTLS priority error at offset " + std::to_string(offset) + " in '" + priority + "'");
   }
   if(cfg.record_size_limit.has_value()) {
      // GnuTLS's API is expressed as application-content bytes. RFC 8449's
      // TLS 1.3 wire value also counts the inner content-type byte.
      const size_t native_limit =
         cfg.min_version == 0x0304 && cfg.max_version == 0x0304
            ? static_cast<size_t>(*cfg.record_size_limit - 1)
            : static_cast<size_t>(*cfg.record_size_limit);
      require_ok(gnutls_record_set_max_recv_size(session.get(), native_limit),
                 "configure record_size_limit");
   }

   if(cfg.is_server() && (cfg.verify.require_client_cert || cfg.verify.request_client_cert)) {
      gnutls_certificate_server_set_request(
         session.get(), cfg.verify.require_client_cert ? GNUTLS_CERT_REQUIRE : GNUTLS_CERT_REQUEST);
   }
   if(!cfg.is_server() && !cfg.server_name.empty()) {
      require_ok(gnutls_server_name_set(session.get(),
                                        GNUTLS_NAME_DNS,
                                        cfg.server_name.data(),
                                        cfg.server_name.size()),
                 "configure SNI");
   }
   if(cfg.verify.verify_peer) {
      gnutls_session_set_verify_cert(session.get(),
                                     cfg.is_server() ? nullptr : cfg.server_name.c_str(),
                                     0);
   } else if(cfg.is_server() &&
             (cfg.verify.require_client_cert || cfg.verify.request_client_cert)) {
      gnutls_session_set_verify_function(session.get(), verify_client_certificate);
   }
   configure_alpn(session.get(), cfg);

   if(!cfg.is_server() && connection_index > 0 && !client_session_data.empty()) {
      require_ok(gnutls_session_set_data(session.get(),
                                         client_session_data.data(),
                                         client_session_data.size()),
                 "restore client session");
      if(cfg.early_data_send > 0 &&
         gnutls_record_get_max_early_data_size(session.get()) < cfg.early_data_send) {
         throw std::runtime_error(
            "restored GnuTLS ticket permits only " +
            std::to_string(gnutls_record_get_max_early_data_size(session.get())) +
            " early-data bytes, need " + std::to_string(cfg.early_data_send));
      }
   }

   DtlsIo dtls_io{&socket, {}};
   if(cfg.is_dtls()) {
      gnutls_transport_set_ptr(session.get(), &dtls_io);
      gnutls_transport_set_push_function(session.get(), dtls_push);
      gnutls_transport_set_pull_function(session.get(), dtls_pull);
      gnutls_transport_set_pull_timeout_function(session.get(), dtls_pull_timeout);
      gnutls_dtls_set_mtu(session.get(), cfg.mtu);
      gnutls_dtls_set_timeouts(session.get(), cfg.initial_timeout_ms, 60000);
   } else {
      gnutls_transport_set_int(session.get(), socket.fd());
      gnutls_transport_set_pull_timeout_function(session.get(), tls_pull_timeout);
   }

   if(!cfg.is_server() && connection_index > 0 && cfg.early_data_send > 0) {
      std::vector<uint8_t> early(cfg.early_data_send, 0x45);
      size_t sent = 0;
      while(sent < early.size()) {
         const ssize_t n =
            gnutls_record_send_early_data(session.get(), early.data() + sent, early.size() - sent);
         if(n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
            continue;
         }
         if(n < 0) {
            throw GnuTlsError("send early data", static_cast<int>(n));
         }
         // GnuTLS 3.8 buffers the complete input but returns zero here (the
         // implementation's buffer-append status), despite the public API
         // documenting a byte count. Treat zero as complete to avoid queuing
         // the same bytes repeatedly until the ticket limit is exhausted.
         sent += n == 0 ? early.size() - sent : static_cast<size_t>(n);
      }
   }

   int rc;
   do {
      // GNUTLS_E_WARNING_ALERT_RECEIVED is non-fatal: the peer's warning alert
      // has been consumed and the handshake is resumed by calling
      // gnutls_handshake() again, the loop gnutls_error_is_fatal() documents.
      rc = gnutls_handshake(session.get());
   } while(rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED ||
           rc == GNUTLS_E_WARNING_ALERT_RECEIVED);
   if(rc < 0) {
      // A handshake parser/validation failure is returned to the caller before
      // GnuTLS necessarily writes its corresponding fatal alert. Send it while
      // the session and socket are alive; ShimSocket's teardown then drains
      // the TCP connection so the alert is not replaced by a close/reset.
      (void)gnutls_alert_send_appropriate(session.get(), rc);
      throw GnuTlsError("handshake", rc);
   }
   check_expectations(session.get(), cfg);

   if(connection_index > 0 && cfg.expect_early_data_accepted.has_value()) {
      const bool accepted =
         (gnutls_session_get_flags(session.get()) & GNUTLS_SFLAGS_EARLY_DATA) != 0;
      if(accepted != *cfg.expect_early_data_accepted) {
         throw plzn::ShimExpectationError(std::string("TLS 1.3 early data was ") +
                                  (accepted ? "accepted" : "rejected") + " unexpectedly");
      }
   }

   if(connection_index > 0 && cfg.is_server() && cfg.early_data_expect > 0 &&
      state.early_data_received !=
         (cfg.expect_early_data_accepted == false ? 0 : cfg.early_data_expect)) {
      const uint32_t expected = cfg.expect_early_data_accepted == false ? 0 : cfg.early_data_expect;
      throw plzn::ShimExpectationError("early data length mismatch: got " +
                               std::to_string(state.early_data_received) +
                                  " expected " + std::to_string(expected));
   }

   if(cfg.is_server() && cfg.session_tickets.value_or(0) > 0) {
      int ticket_rc;
      do {
         ticket_rc = gnutls_session_ticket_send(session.get(), *cfg.session_tickets, 0);
      } while(ticket_rc == GNUTLS_E_AGAIN || ticket_rc == GNUTLS_E_INTERRUPTED);
      require_ok(ticket_rc, "send session tickets");
   }

   bool client_session_saved = false;
   const auto save_client_session = [&] {
      if(client_session_saved || cfg.is_server() || connection_index >= cfg.resume_count) {
         return;
      }
      gnutls_datum_t data{};
      require_ok(gnutls_session_get_data2(session.get(), &data), "save client session");
      if(data.data == nullptr || data.size == 0) {
         throw std::runtime_error("GnuTLS returned empty client session state");
      }
      client_session_data.assign(data.data, data.data + data.size);
      client_session_saved = true;
      gnutls_memset(data.data, 0, data.size);
      gnutls_free(data.data);
   };

   for(const auto& request : cfg.key_material) {
      if(request.connection != connection_index) continue;
      std::vector<uint8_t> out(request.length);
      if(request.kind == "exporter") {
         int export_rc;
         if(request.context.has_value()) {
            export_rc = gnutls_prf_rfc5705(
               session.get(), request.label.size(), request.label.data(),
               request.context->size(), request.context->data(), out.size(),
               reinterpret_cast<char*>(out.data()));
         } else {
            export_rc = gnutls_prf(
               session.get(), request.label.size(), request.label.data(), 0, 0,
               nullptr, out.size(), reinterpret_cast<char*>(out.data()));
         }
         require_ok(export_rc, "export keying material");
      } else if(request.kind == "tls_unique" || request.kind == "tls_unique_unavailable") {
         gnutls_datum_t binding{};
         const int binding_rc = gnutls_session_channel_binding(
            session.get(), GNUTLS_CB_TLS_UNIQUE, &binding);
         if(request.kind == "tls_unique_unavailable") {
            if(binding_rc >= 0) {
               gnutls_free(binding.data);
               throw plzn::ShimExpectationError("tls-unique unexpectedly available");
            }
            out.assign(1, 0x01);
         } else {
            require_ok(binding_rc, "obtain tls-unique channel binding");
            out.assign(binding.data, binding.data + binding.size);
            gnutls_free(binding.data);
         }
      } else {
         throw std::runtime_error("unknown key_material kind: " + request.kind);
      }
      size_t sent = 0;
      while(sent < out.size()) {
         const ssize_t n = gnutls_record_send(session.get(), out.data() + sent,
                                              out.size() - sent);
         if(n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) continue;
         if(n < 0) throw GnuTlsError("send key material", static_cast<int>(n));
         sent += static_cast<size_t>(n);
      }
   }

   if(cfg.app_data.mode == plzn::AppDataMode::ShimWrites) {
      require_ok(static_cast<int>(gnutls_record_send(session.get(),
                                                     cfg.app_data.send.data(),
                                                     cfg.app_data.send.size())),
                 "send application data");
      save_client_session();
      (void)gnutls_bye(session.get(), GNUTLS_SHUT_WR);
      return;
   }
   if(cfg.app_data.mode == plzn::AppDataMode::ShutdownOnly) {
      save_client_session();
      (void)gnutls_bye(session.get(), GNUTLS_SHUT_WR);
      return;
   }

   std::vector<uint8_t> buf(18 * 1024);
   plzn::AppDataResponder app_responder;
   for(;;) {
      const ssize_t got = gnutls_record_recv(session.get(), buf.data(), buf.size());
      if(got == 0) {
         save_client_session();
         (void)gnutls_bye(session.get(), GNUTLS_SHUT_WR);
         break;
      }
      if(got == GNUTLS_E_REHANDSHAKE) {
         int hs;
         do {
            hs = gnutls_handshake(session.get());
         } while(hs == GNUTLS_E_AGAIN || hs == GNUTLS_E_INTERRUPTED);
         require_ok(hs, "renegotiation handshake");
         continue;
      }
      if(got == GNUTLS_E_AGAIN || got == GNUTLS_E_INTERRUPTED ||
         got == GNUTLS_E_WARNING_ALERT_RECEIVED) {
         // A warning alert is reported to the application and the read is
         // simply retried; the library itself places no bound on them.
         continue;
      }
      if(got == GNUTLS_E_PREMATURE_TERMINATION) {
         // plzn's plain `close` ends the transport without close_notify. The
         // application-data exchange already completed, so this is the normal
         // end of that flow rather than a protocol failure.
         break;
      }
      if(got < 0) {
         // Unlike some TLS APIs, gnutls_record_recv() returns the protocol
         // error without automatically putting its mandated fatal alert on
         // the wire. Generate it while the session and transport are alive;
         // ShimSocket's destructor then half-closes and drains the TCP socket
         // so close() cannot replace this alert with an RST.
         (void)gnutls_alert_send_appropriate(session.get(), static_cast<int>(got));
         throw GnuTlsError("receive application data", static_cast<int>(got));
      }
      save_client_session();
      for(const auto& reply : app_responder.receive(buf.data(), static_cast<size_t>(got))) {
         size_t sent = 0;
         while(sent < reply.size()) {
            const ssize_t n = gnutls_record_send(session.get(), reply.data() + sent,
                                                 reply.size() - sent);
            if(n < 0) {
               throw GnuTlsError("send application data response", static_cast<int>(n));
            }
            sent += static_cast<size_t>(n);
         }
      }
   }
   save_client_session();
}

void preflight(const ShimConfig& cfg) {
   if(cfg.requests_dtls13()) {
      plzn::report_unsupported("versions", "GnuTLS does not currently implement DTLS 1.3");
   }
   if(cfg.is_dtls() &&
      (cfg.max_early_data.value_or(0) > 0 || cfg.early_data_send > 0 ||
       cfg.early_data_expect > 0)) {
      plzn::report_unsupported("early_data", "DTLS 1.2 has no TLS 1.3 early data");
   }
   if(!cfg.is_server() && cfg.credentials.client_chains.size() > 1) {
      plzn::report_unsupported(
         "credentials",
         "multi-certificate client selection is not wired through GnuTLS's retrieval callback yet");
   }
   if(cfg.cipher_suites.size() > 1) {
      plzn::report_unsupported(
         "cipher_suites",
         "GnuTLS cannot represent an arbitrary exact multi-suite list without enabling its component cross-product");
   }
   if(cfg.cipher_suites.size() == 1 && !suite_algorithms(cfg.cipher_suites[0]).found) {
      plzn::report_unsupported("cipher_suites", "GnuTLS does not implement the requested cipher suite");
   }
   if(!cfg.credentials.ocsp_file.empty()) {
      plzn::report_unsupported("ocsp_stapling", "OCSP stapling is not wired in the GnuTLS shim yet");
   }
   if(cfg.verify.fail || cfg.verify.expect_peer_subject_cn.has_value()) {
      plzn::report_unsupported("verify", "forced verification failure and peer-subject checks are not wired in the GnuTLS shim yet");
   }
   if((!cfg.signing_prefs.empty() && !cfg.verify_prefs.empty() &&
       cfg.signing_prefs != cfg.verify_prefs) ||
      std::any_of(cfg.signing_prefs.begin(), cfg.signing_prefs.end(),
                  [](uint16_t id) { return signature_priority(id).empty(); }) ||
      std::any_of(cfg.verify_prefs.begin(), cfg.verify_prefs.end(),
                  [](uint16_t id) { return signature_priority(id).empty(); })) {
      plzn::report_unsupported(
         "signature_algorithms",
         "GnuTLS has one signature priority list; both lists must be equal and contain supported schemes");
   }
   if((!cfg.curves.empty() &&
       std::any_of(cfg.curves.begin(), cfg.curves.end(),
                   [](uint16_t id) { return !group_supported(id); })) ||
      (!cfg.requires_any_group.empty() &&
       std::none_of(cfg.requires_any_group.begin(), cfg.requires_any_group.end(), group_supported))) {
      plzn::report_unsupported("groups", "GnuTLS implements none of the required groups");
   }
   if(cfg.requires_virtual_clock || cfg.requires_dynamic_timeout) {
      plzn::report_unsupported("virtual_clock", "GnuTLS exposes its DTLS deadline but not an injectable sub-second clock");
   }
   if(cfg.dtls_max_retransmissions.has_value() || cfg.dtls_max_timeout_ms.has_value() ||
      cfg.dtls_require_cookie.has_value() || cfg.dtls_epoch0_restart.has_value() ||
      cfg.dtls_max_hello_verify_requests.has_value()) {
      plzn::report_unsupported("dtls", "the requested DTLS policy is not wired in the GnuTLS shim yet");
   }
   if(cfg.compress_certificate || !cfg.srtp_profiles.empty()) {
      plzn::report_unsupported("extension", "certificate compression and DTLS-SRTP are not wired in the GnuTLS shim yet");
   }
   // Peer-initiated TLS 1.2 renegotiation needs no special setup: the
   // application loop handles GNUTLS_E_REHANDSHAKE below. The remaining
   // controls require the shim itself to initiate or customize the exchange.
   if(!cfg.post_handshake_auth.empty() || !cfg.half_rtt_data.empty() || cfg.key_update ||
      cfg.renegotiate_count > 0 ||
      cfg.renegotiate_after_handshake || cfg.hello_request_after_app_data ||
      cfg.require_client_cert_on_renegotiation) {
      plzn::report_unsupported("post_handshake", "requested post-handshake control is not wired in the GnuTLS shim yet");
   }
   if(cfg.expect.curve.has_value() || cfg.expect.peer_signature_algorithm.has_value() ||
      cfg.expect.hrr.has_value() || cfg.expect.secure_renegotiation.has_value() ||
      cfg.expect.peer_subject_cn.has_value() || cfg.expect_srtp_profile.has_value()) {
      plzn::report_unsupported("expectations", "one or more requested checks are not wired in the GnuTLS shim yet");
   }
   if(cfg.server_preference.has_value() || cfg.renegotiation.has_value() ||
      cfg.max_cert_list.has_value() ||
      cfg.records_per_traffic_key.has_value() || cfg.extended_master_secret.has_value() ||
      cfg.middlebox_compat.has_value() ||
      cfg.min_key_update_interval_ms.has_value()) {
      plzn::report_unsupported("uut", "one or more requested policy knobs are not wired in the GnuTLS shim yet");
   }
   if(!cfg.requires_any_suite.empty() &&
      std::none_of(cfg.requires_any_suite.begin(), cfg.requires_any_suite.end(),
                   [&cfg](uint16_t id) { return suite_enabled_by_priority(cfg, id); })) {
      plzn::report_unsupported("peer.capabilities", "GnuTLS implements none of the offered cipher suites");
   }
}

}  // namespace

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   std::signal(SIGPIPE, SIG_IGN);
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string arg = argv[i];
      if(arg == "--plzn-shim-info") {
         std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"gnutls"})" << std::endl;
         return 0;
      } else if(arg == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(arg.rfind("-config=", 0) == 0) {
         config_path = arg.substr(8);
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: gnutls_shim -config <file.json> | --plzn-shim-info" << std::endl;
      return 2;
   }

   ShimConfig cfg;
   try {
      cfg = ShimConfig::from_file(config_path);
   } catch(const std::exception& e) {
      plzn::report_result(ShimResult::LocalError, std::string("config error: ") + e.what());
   }

   require_ok(gnutls_global_init(), "initialize GnuTLS");
   if(const char* level = std::getenv("PLZN_GNUTLS_DEBUG")) {
      // GnuTLS's own log, with its gnutls_assert() trail, on stderr: the way
      // to see which internal check failed when the error code alone (such as
      // GNUTLS_E_INTERNAL_ERROR) does not say.
      gnutls_global_set_log_level(std::atoi(level));
      gnutls_global_set_log_function([](int lvl, const char* msg) { std::cerr << "[gnutls " << lvl << "] " << msg; });
   }
   preflight(cfg);
   const bool expect_failure = cfg.expect.handshake_error.has_value();

   try {
      auto creds = make_credentials(cfg);
      OwnedDatum ticket_key;
      // A ticket key whenever a ticket can be used: a later connection, an
      // explicit ticket count, or a renegotiation that resumes within this one.
      // Otherwise none, so a TLS 1.3 server sends no tickets nobody asked for.
      if(cfg.is_server() && !cfg.no_ticket && cfg.session_tickets != 0 &&
         (cfg.resume_count > 0 || cfg.session_tickets.value_or(0) > 0 ||
          cfg.renegotiate_freely || cfg.renegotiate_count > 0)) {
         require_ok(gnutls_session_ticket_key_generate(ticket_key.out()),
                    "generate session ticket key");
      }

      std::unordered_set<std::string> seen_client_hellos;
      AntiReplayPtr anti_replay;
      if(cfg.is_server() && cfg.max_early_data.value_or(0) > 0) {
         gnutls_anti_replay_t raw_anti_replay = nullptr;
         require_ok(gnutls_anti_replay_init(&raw_anti_replay), "initialize anti-replay");
         anti_replay.reset(raw_anti_replay);
         gnutls_anti_replay_set_add_function(anti_replay.get(), anti_replay_add);
         gnutls_anti_replay_set_ptr(anti_replay.get(), &seen_client_hellos);
      }

      SessionCache session_cache;
      std::vector<uint8_t> client_session_data;
      for(uint32_t i = 0; i <= cfg.resume_count; ++i) {
         const auto connection_cfg = cfg.for_connection(i);
         run_connection(connection_cfg,
                        creds.get(),
                        i,
                        ticket_key.get(),
                        anti_replay.get(),
                        session_cache,
                        client_session_data);
      }
   } catch(const GnuTlsError& e) {
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
