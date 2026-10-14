/*
 * plzn LibreSSL interop shim.
 *
 * Wraps LibreSSL's TLS client/server as a unit-under-test driven by the shared
 * JSON config (see ../DESIGN.md, ../common/plzn_shim.h). Derived from the
 * OpenSSL shim; LibreSSL keeps most of the OpenSSL 1.1 SSL API but has none
 * of OpenSSL 3's provider/EVP_MAC/client-hello-callback surface and does not
 * implement PSK, TLS 1.3 resumption or 0-RTT, post-handshake authentication,
 * Ed25519/RSA-PSS certificates, encrypt-then-MAC, extended master secret,
 * RFC 7250 raw public keys, certificate compression, or configurable
 * signature-algorithm lists. A `uut` knob or capability it lacks is refused
 * before dialing so the runner SKIPs the case.
 *
 * Supports both TLS (over the socket fd) and DTLS 1.2 (over a custom datagram
 * BIO that bridges LibreSSL to the shim's P/T datagram framing).
 */

#include "plzn_shim.h"

#include <fstream>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifndef LIBRESSL_VERSION_NUMBER
#error "libressl_shim must be compiled against LibreSSL headers"
#endif

#include <sys/time.h>
#include <time.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>

using namespace plzn;

namespace {

std::string g_fail_reason;

struct ProtocolFailure : std::runtime_error { using std::runtime_error::runtime_error; };

// ---- DTLS virtual clock ----
//
// LibreSSL's DTLS retransmit timer reads the wall clock through gettimeofday()
// (ssl/d1_lib.c dtls1_start_timer / dtls1_get_timeout) and offers no hook for
// another clock. The shim therefore defines gettimeofday itself (below main):
// the dynamic linker resolves libssl's call to the executable's definition,
// because a symbol a shared library references and the executable defines is
// exported and preempts libc's. For a DTLS connection the clock is frozen when
// the shim starts and moves only with the runner's 'T' frames, so a
// retransmission fires exactly when the flow advances the clock past the timer
// (RFC 6347 4.2.4), never on real time; TLS keeps the real clock.
//
// Unlike OpenSSL 3 there is no DTLS_set_timer_cb: the schedule is LibreSSL's
// own (1 s, doubling to 60 s, failing after DTLS1_TMO_ALERT_COUNT = 12
// timeouts), so other `initial_timeout_ms` / `dtls_max_*` values are refused.
struct VirtualClock {
      bool frozen = false;
      int64_t base_us = 0;       // real time captured when frozen
      uint64_t advanced_ns = 0;  // sum of the 'T' frames
};
VirtualClock g_clock;

int64_t real_now_us() {
   timespec ts{};
   ::clock_gettime(CLOCK_REALTIME, &ts);
   return static_cast<int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
}

constexpr uint32_t LIBRESSL_DTLS_INITIAL_TIMEOUT_MS = 1000;
constexpr uint32_t LIBRESSL_DTLS_MAX_TIMEOUT_MS = 60000;
constexpr uint32_t LIBRESSL_DTLS_MAX_RETRANSMISSIONS = DTLS1_TMO_ALERT_COUNT;

enum class DtlsInterruptKind { None, AdvanceClock, ExpectTimeout, UpdateTimeout };

struct DtlsInterrupt {
      DtlsInterruptKind kind = DtlsInterruptKind::None;
      uint64_t value = 0;
};

DtlsInterrupt g_dtls_interrupt;

// ---- DTLS cookies (RFC 6347 4.2.1) ----
//
// Cookie = HMAC-SHA256(secret || generation, client_random || peer identity):
// stateless, bound to the ClientHello's random (the shim reads it off the
// datagrams it hands LibreSSL, since the cookie callback runs before LibreSSL
// has parsed the first ClientHello) and invalidated by a `rotate_cookie_secret`
// step, which bumps the generation. A ClientHello with a cookie that does not
// verify is a fatal handshake_failure in the stateful SSL_accept path
// (SSL_R_COOKIE_MISMATCH); only DTLSv1_listen re-challenges.
uint32_t g_cookie_generation = 0;
std::array<uint8_t, 32> g_client_random{};
std::array<bool, 34> g_client_random_seen{};  // ClientHello bytes [0, 34) covered
int32_t g_client_random_seq = -1;             // message_seq being tracked

std::vector<uint8_t> cookie_for(const uint8_t random[32]) {
   std::string key = "plzn-libressl-shim-cookie-secret";
   key.push_back(static_cast<char>(g_cookie_generation));
   std::vector<uint8_t> data(random, random + 32);
   const std::string identity = "plzn-shim-peer";
   data.insert(data.end(), identity.begin(), identity.end());
   std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
   unsigned int outlen = 0;
   if(HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &outlen) ==
      nullptr) {
      throw std::runtime_error("cookie HMAC failed");
   }
   out.resize(outlen);
   return out;
}

// Track the random of the ClientHello arriving in `dg` (epoch-0 handshake
// records, possibly fragmented) so the cookie callback can bind to it.
void track_client_hello(const std::vector<uint8_t>& dg) {
   size_t off = 0;
   while(off + 13 <= dg.size()) {
      const uint8_t content_type = dg[off];
      const uint16_t epoch = static_cast<uint16_t>((dg[off + 3] << 8) | dg[off + 4]);
      const size_t len = static_cast<size_t>((dg[off + 11] << 8) | dg[off + 12]);
      if(off + 13 + len > dg.size()) {
         return;
      }
      const uint8_t* body = dg.data() + off + 13;
      off += 13 + len;
      if(content_type != 22 || epoch != 0 || len < 12 || body[0] != 1) {
         continue;
      }
      const int32_t seq = (body[4] << 8) | body[5];
      const size_t frag_off = (static_cast<size_t>(body[6]) << 16) | (body[7] << 8) | body[8];
      const size_t frag_len = (static_cast<size_t>(body[9]) << 16) | (body[10] << 8) | body[11];
      if(frag_len != len - 12) {
         continue;
      }
      if(seq != g_client_random_seq) {
         g_client_random_seq = seq;
         g_client_random_seen.fill(false);
      }
      for(size_t i = 0; i < frag_len; ++i) {
         const size_t pos = frag_off + i;
         if(pos >= 34) {
            break;
         }
         if(pos >= 2) {
            g_client_random[pos - 2] = body[12 + i];
         }
         g_client_random_seen[pos] = true;
      }
   }
}

uint32_t g_mtu = 1500;

// Set when the TLS flow fails at any point (handshake or app-data phase). A
// negative test configures expect.handshake_error and passes iff this is set.
bool g_flow_failed = false;
std::string g_expectation_failure;
// The session (with its TLS 1.3 ticket) the previous client connection of this
// process ended with, offered on the next one (multi-session tests).
SSL_SESSION* g_client_session = nullptr;

void note_failure(const std::string& reason) {
   if(!g_flow_failed && g_expectation_failure.empty()) {
      g_expectation_failure = reason;
   }
   if(g_fail_reason.empty()) {
      g_fail_reason = reason;
   }
}

// The last fatal alert this endpoint sent (0 = none). LibreSSL fails some
// paths (e.g. refusing a client-initiated renegotiation) with a fatal alert but
// no queued error, which SSL_get_error then reports as SSL_ERROR_SYSCALL; the
// info callback is the only public view of that alert.
int g_sent_fatal_alert = 0;

void info_cb(const SSL* /*ssl*/, int where, int ret) {
   if((where & SSL_CB_WRITE_ALERT) != 0 && (ret >> 8) == SSL3_AL_FATAL) {
      g_sent_fatal_alert = ret & 0xff;
   }
}

std::string openssl_errors() {
   std::string out;
   unsigned long e = 0;
   while((e = ERR_get_error()) != 0) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof(buf));
      if(!out.empty()) {
         out += "; ";
      }
      out += buf;
   }
   return out;
}

// Map a 16-bit IANA named-group code to the name SSL_CTX_set1_groups_list
// expects. LibreSSL implements the NIST curves, X25519, the RFC 7027
// brainpool curves (TLS 1.2 only) and the X25519MLKEM768 hybrid; no X448,
// FFDHE (RFC 7919) groups, RFC 8734 brainpool TLS 1.3 groups or pure ML-KEM.
// Empty for a group it lacks.
const char* iana_group_to_name(uint16_t id) {
   switch(id) {
      case 0x0017:
         return "P-256";  // secp256r1
      case 0x0018:
         return "P-384";
      case 0x0019:
         return "P-521";
      case 0x001a:
         return "brainpoolP256r1";
      case 0x001b:
         return "brainpoolP384r1";
      case 0x001c:
         return "brainpoolP512r1";
      case 0x001d:
         return "X25519";
      case 0x11ec:
         return "X25519MLKEM768";
      default:
         return "";
   }
}

// The groups the shim exposes when `uut { curves }` is absent: LibreSSL's own
// TLS 1.3 client default (the server default omits P-521, which it still
// implements). Brainpool stays opt-in: LibreSSL would also offer those TLS
// 1.2-only code points in a TLS 1.3 ClientHello.
const char* DEFAULT_GROUPS = "X25519MLKEM768:X25519:P-256:P-384:P-521";
const std::vector<uint16_t> DEFAULT_GROUP_IDS = {0x11ec, 0x001d, 0x0017, 0x0018, 0x0019};

// Whether this build implements a group: parse it on a scratch context, which
// is how the real context would take it.
bool libressl_has_group(uint16_t id, bool dtls) {
   const char* name = iana_group_to_name(id);
   if(name[0] == '\0') {
      return false;
   }
   SSL_CTX* probe = SSL_CTX_new(dtls ? DTLS_method() : TLS_method());
   if(probe == nullptr) {
      return true;  // cannot tell; let the handshake decide
   }
   const bool ok = SSL_CTX_set1_groups_list(probe, name) == 1;
   ERR_clear_error();
   SSL_CTX_free(probe);
   return ok;
}

// Map a 16-bit protocol version code to the library's version constant.
// SSL_set_session switches LibreSSL to the session's version-specific method
// (TLSv1_2_method for a TLS 1.2 session), so offering a TLS 1.2 session on a
// connection limited to TLS 1.3 fails locally before any ClientHello. Offer a
// cached session only when its version is within the connection's range; a
// client that cannot resume it starts a full handshake instead.
bool session_fits_connection(const ShimConfig& cfg, const SSL_SESSION* session) {
   if(cfg.is_dtls()) {
      return true;
   }
   const int version = SSL_SESSION_get_protocol_version(session);
   return (!cfg.min_version.has_value() || version >= *cfg.min_version) &&
          (!cfg.max_version.has_value() || version <= *cfg.max_version);
}

int openssl_version(uint16_t code) {
   switch(code) {
      case 0x0301:
         return TLS1_VERSION;
      case 0x0302:
         return TLS1_1_VERSION;
      case 0x0303:
         return TLS1_2_VERSION;
      case 0x0304:
         return TLS1_3_VERSION;
#ifdef DTLS1_VERSION
      case 0xfeff:
         return DTLS1_VERSION;
#endif
#ifdef DTLS1_2_VERSION
      case 0xfefd:
         return DTLS1_2_VERSION;
#endif
      default:
         return 0;
   }
}

// LibreSSL selects TLS 1.3 suites by name; it implements no TLS 1.3 CCM suites.
const char* tls13_suite_name(uint16_t id) {
   switch(id) {
      case 0x1301:
         return "TLS_AES_128_GCM_SHA256";
      case 0x1302:
         return "TLS_AES_256_GCM_SHA384";
      case 0x1303:
         return "TLS_CHACHA20_POLY1305_SHA256";
      default:
         return nullptr;
   }
}

// Map a 16-bit TLS 1.2 (and DTLS 1.2) cipher-suite ID to its OpenSSL-style
// cipher name (for SSL_CTX_set_cipher_list). Returns nullptr for unmapped IDs;
// a name LibreSSL lacks makes SSL_CTX_set_cipher_list fail -> unsupported.
const char* tls12_cipher_name(uint16_t id) {
   switch(id) {
      case 0xC02F:
         return "ECDHE-RSA-AES128-GCM-SHA256";
      case 0xC02B:
         return "ECDHE-ECDSA-AES128-GCM-SHA256";
      case 0xC030:
         return "ECDHE-RSA-AES256-GCM-SHA384";
      case 0xC02C:
         return "ECDHE-ECDSA-AES256-GCM-SHA384";
      case 0xC013:
         return "ECDHE-RSA-AES128-SHA";
      case 0xC009:
         return "ECDHE-ECDSA-AES128-SHA";
      case 0x009E:
         return "DHE-RSA-AES128-GCM-SHA256";
      case 0x009C:
         return "AES128-GCM-SHA256";
      case 0x00A8:
         return "PSK-AES128-GCM-SHA256";
      case 0x00A9:
         return "PSK-AES256-GCM-SHA384";
      case 0xCCAB:
         return "PSK-CHACHA20-POLY1305";
      case 0xC06A:
         return "PSK-ARIA128-GCM-SHA256";
      case 0xC06B:
         return "PSK-ARIA256-GCM-SHA384";
      case 0xC0A4:
         return "PSK-AES128-CCM";
      case 0xC0A5:
         return "PSK-AES256-CCM";
      case 0xC0A8:
         return "PSK-AES128-CCM8";
      case 0xC0A9:
         return "PSK-AES256-CCM8";
      case 0x008C:
         return "PSK-AES128-CBC-SHA";
      case 0x008D:
         return "PSK-AES256-CBC-SHA";
      case 0x00AE:
         return "PSK-AES128-CBC-SHA256";
      case 0x00AF:
         return "PSK-AES256-CBC-SHA384";
      case 0x008B:
         return "PSK-3DES-EDE-CBC-SHA";
      case 0x002C:
         return "PSK-NULL-SHA";
      case 0x00B0:
         return "PSK-NULL-SHA256";
      case 0x00B1:
         return "PSK-NULL-SHA384";
      // ECDHE_PSK (RFC 5489; the RFC 8442 AEAD ids 0xD001-0xD005 have no
      // OpenSSL names in the usual build and are probed by id instead).
      case 0xC035:
         return "ECDHE-PSK-AES128-CBC-SHA";
      case 0xC036:
         return "ECDHE-PSK-AES256-CBC-SHA";
      case 0xC037:
         return "ECDHE-PSK-AES128-CBC-SHA256";
      case 0xC038:
         return "ECDHE-PSK-AES256-CBC-SHA384";
      case 0xC034:
         return "ECDHE-PSK-3DES-EDE-CBC-SHA";
      case 0xC039:
         return "ECDHE-PSK-NULL-SHA";
      case 0xC03A:
         return "ECDHE-PSK-NULL-SHA256";
      case 0xC03B:
         return "ECDHE-PSK-NULL-SHA384";
      case 0xCCAC:
         return "ECDHE-PSK-CHACHA20-POLY1305";
      case 0x002F:
         return "AES128-SHA";
      case 0x0035:
         return "AES256-SHA";
      case 0x003C:
         return "AES128-SHA256";
      case 0x003D:
         return "AES256-SHA256";
      case 0x0033:
         return "DHE-RSA-AES128-SHA";
      case 0x0039:
         return "DHE-RSA-AES256-SHA";
      case 0x0067:
         return "DHE-RSA-AES128-SHA256";
      case 0x006B:
         return "DHE-RSA-AES256-SHA256";
      case 0x009D:
         return "AES256-GCM-SHA384";
      case 0x009F:
         return "DHE-RSA-AES256-GCM-SHA384";
      case 0xC00A:
         return "ECDHE-ECDSA-AES256-SHA";
      case 0xC014:
         return "ECDHE-RSA-AES256-SHA";
      case 0xC023:
         return "ECDHE-ECDSA-AES128-SHA256";
      case 0xC024:
         return "ECDHE-ECDSA-AES256-SHA384";
      case 0xC027:
         return "ECDHE-RSA-AES128-SHA256";
      case 0xC028:
         return "ECDHE-RSA-AES256-SHA384";
      case 0xCCA8:
         return "ECDHE-RSA-CHACHA20-POLY1305";
      case 0xCCA9:
         return "ECDHE-ECDSA-CHACHA20-POLY1305";
      case 0xCCAA:
         return "DHE-RSA-CHACHA20-POLY1305";
      case 0xC006:
         return "ECDHE-ECDSA-NULL-SHA";
      case 0xC010:
         return "ECDHE-RSA-NULL-SHA";
      case 0x000A:
         return "DES-CBC3-SHA";
      case 0x0016:
         return "DHE-RSA-DES-CBC3-SHA";
      case 0xC008:
         return "ECDHE-ECDSA-DES-CBC3-SHA";
      case 0xC012:
         return "ECDHE-RSA-DES-CBC3-SHA";
      case 0xC050:
         return "ARIA128-GCM-SHA256";
      case 0xC051:
         return "ARIA256-GCM-SHA384";
      case 0xC052:
         return "DHE-RSA-ARIA128-GCM-SHA256";
      case 0xC053:
         return "DHE-RSA-ARIA256-GCM-SHA384";
      case 0xC05C:
         return "ECDHE-ECDSA-ARIA128-GCM-SHA256";
      case 0xC05D:
         return "ECDHE-ECDSA-ARIA256-GCM-SHA384";
      case 0xC060:
         return "ECDHE-ARIA128-GCM-SHA256";
      case 0xC061:
         return "ECDHE-ARIA256-GCM-SHA384";
      case 0xC09C:
         return "AES128-CCM";
      case 0xC09D:
         return "AES256-CCM";
      case 0xC09E:
         return "DHE-RSA-AES128-CCM";
      case 0xC09F:
         return "DHE-RSA-AES256-CCM";
      case 0xC0A0:
         return "AES128-CCM8";
      case 0xC0A1:
         return "AES256-CCM8";
      case 0xC0A2:
         return "DHE-RSA-AES128-CCM8";
      case 0xC0A3:
         return "DHE-RSA-AES256-CCM8";
      case 0xC0AC:
         return "ECDHE-ECDSA-AES128-CCM";
      case 0xC0AD:
         return "ECDHE-ECDSA-AES256-CCM";
      case 0xC0AE:
         return "ECDHE-ECDSA-AES128-CCM8";
      case 0xC0AF:
         return "ECDHE-ECDSA-AES256-CCM8";
      // Camellia-GCM (RFC 6367) has no OpenSSL TLS suites; Camellia-CBC ones
      // exist in OpenSSL but plzn does not implement them.
      default:
         return nullptr;
   }
}

// The default security level (1) refuses the NULL-cipher suites (0-bit
// encryption) and the CCM_8 suites (64-bit tags); everything else plzn
// implements passes at level 1, so the level is lowered only for these.
bool needs_security_level_zero(uint16_t id) {
   switch(id) {
      // NULL cipher
      case 0xC006:
      case 0xC010:
      case 0x002C:
      case 0x00B0:
      case 0x00B1:
      case 0xC039:
      case 0xC03A:
      case 0xC03B:
      // AES-CCM_8
      case 0xC0A0:
      case 0xC0A1:
      case 0xC0A2:
      case 0xC0A3:
      case 0xC0A8:
      case 0xC0A9:
      case 0xC0AE:
      case 0xC0AF:
      case 0xD003:
      case 0x1305:
         return true;
      default:
         return false;
   }
}

// ALPN wire format: series of length-prefixed protocol names.
std::vector<uint8_t> alpn_wire(const std::vector<std::string>& protos) {
   std::vector<uint8_t> out;
   for(const auto& p : protos) {
      out.push_back(static_cast<uint8_t>(p.size()));
      out.insert(out.end(), p.begin(), p.end());
   }
   return out;
}

// Server-side ALPN selection callback.
int alpn_select_cb(SSL* /*ssl*/,
                   const unsigned char** out,
                   unsigned char* outlen,
                   const unsigned char* in,
                   unsigned int inlen,
                   void* arg) {
   const ShimConfig* cfg = static_cast<const ShimConfig*>(arg);
   if(cfg->alpn.decline) {
      return SSL_TLSEXT_ERR_NOACK;
   }
   std::vector<std::string> supported = cfg->alpn.select_from;
   if(!cfg->alpn.select.empty()) {
      supported.insert(supported.begin(), cfg->alpn.select);
   }
   if(!supported.empty()) {
      // Select the first server-preferred protocol present in the client's list.
      for(const std::string& want : supported) {
         unsigned int i = 0;
         while(i < inlen) {
            const unsigned int len = in[i];
            if(i + 1 + len > inlen) {
               break;
            }
            if(len == want.size() && std::memcmp(&in[i + 1], want.data(), len) == 0) {
               *out = &in[i + 1];
               *outlen = static_cast<unsigned char>(len);
               return SSL_TLSEXT_ERR_OK;
            }
            i += 1 + len;
         }
      }
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   // Default: pick the client's first offer.
   if(inlen >= 1) {
      *out = &in[1];
      *outlen = in[0];
      return SSL_TLSEXT_ERR_OK;
   }
   return SSL_TLSEXT_ERR_NOACK;
}

// Fixed session-ticket key so a fresh shim process can decrypt (and resume) a
// ticket issued by a previous one -- otherwise the per-process random key
// makes cross-process resumption impossible. Matches Botan's fixed-key shim.
int ticket_key_cb(SSL* /*s*/,
                  unsigned char key_name[16],
                  unsigned char* iv,
                  EVP_CIPHER_CTX* cctx,
                  HMAC_CTX* hctx,
                  int enc) {
   static const unsigned char kn[16] = {'p', 'l', 'z', 'n', '-', 't', 'k', 't', '-', 'k', 'e', 'y', '0', '0', '0', '1'};
   static const unsigned char aes_key[32] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
   static const unsigned char hmac_key[32] = {
      0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
      0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0};

   if(enc == 1) {
      if(RAND_bytes(iv, 16) <= 0) {
         return -1;
      }
      std::memcpy(key_name, kn, 16);
      if(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1) {
         return -1;
      }
   } else {
      if(std::memcmp(key_name, kn, 16) != 0) {
         return 0;  // unknown key -> no resumption
      }
      if(EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1) {
         return -1;
      }
   }
   if(HMAC_Init_ex(hctx, hmac_key, sizeof(hmac_key), EVP_sha256(), nullptr) != 1) {
      return -1;
   }
   return 1;
}

// DTLS cookie callbacks for the HelloVerifyRequest exchange (RFC 6347 4.2.1):
// stateless HMAC cookies over the ClientHello random (see cookie_for), so a
// corrupted or stale cookie is rejected like Botan's. Enabling the exchange
// also makes LibreSSL send HelloVerifyRequest (parity with the Botan shim).
int dtls_cookie_generate(SSL* /*ssl*/, unsigned char* cookie, unsigned int* cookie_len) {
   const auto c = cookie_for(g_client_random.data());
   std::memcpy(cookie, c.data(), c.size());
   *cookie_len = static_cast<unsigned int>(c.size());
   return 1;
}

int dtls_cookie_verify(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len) {
   // LibreSSL has parsed this ClientHello by now, so its random is the one to
   // bind to (RFC 6347 4.2.1: the second ClientHello MUST repeat the first's).
   unsigned char random[32];
   if(SSL_get_client_random(ssl, random, sizeof(random)) != sizeof(random)) {
      return 0;
   }
   const auto want = cookie_for(random);
   return (cookie_len == want.size() && std::memcmp(cookie, want.data(), want.size()) == 0) ? 1 : 0;
}

// T6: `uut { ocsp_stapling }`: the DER OCSP response the runner wrote for our
// certificate, stapled when the client asks (status_request): TLS 1.2
// CertificateStatus, TLS 1.3 leaf status_request (RFC 6066 8, RFC 8446 4.4.2.1).
static std::vector<uint8_t> g_ocsp_response;

static int ocsp_status_cb(SSL* ssl, void* /*arg*/) {
   if(g_ocsp_response.empty()) {
      return SSL_TLSEXT_ERR_NOACK;
   }
   // The setter takes ownership (LibreSSL frees it with free()), so it must
   // not point into g_ocsp_response.
   if(g_ocsp_response.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   auto* response = static_cast<unsigned char*>(std::malloc(g_ocsp_response.size()));
   if(response == nullptr) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   std::memcpy(response, g_ocsp_response.data(), g_ocsp_response.size());
   if(SSL_set_tlsext_status_ocsp_resp(ssl, response, static_cast<int>(g_ocsp_response.size())) != 1) {
      std::free(response);
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   return SSL_TLSEXT_ERR_OK;
}


// -------------------------------------------------------------------------
// Certificate chains (see shims/DESIGN.md "Certificate chains")
//
// The shim serves `credentials.chains` as a server and presents
// `credentials.client_chains` as a client. LibreSSL keeps exactly two
// certificate slots (RSA and ECC) and picks between them from the peer's
// signature_algorithms on its own. It has no Ed25519 or RSA-PSS (SPKI)
// certificate support and no client-hello or sigalg-inspection callback to
// choose among several chains of one key type, so those are refused
// (unsupported_config).
// -------------------------------------------------------------------------
namespace {

struct ResolvedChain {
      Chain chain;
      std::string key_type;  // rsa_2048 | rsa_pss | ecdsa_p256 | ecdsa_p384 | ecdsa_p521 | ed25519 | ...
};

// The runner's key-type name for a PEM private key ("" if unreadable).
std::string key_type_of_file(const std::string& key_file) {
   FILE* f = std::fopen(key_file.c_str(), "r");
   if(f == nullptr) {
      return "";
   }
   EVP_PKEY* k = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
   std::fclose(f);
   ERR_clear_error();
   if(k == nullptr) {
      return "";
   }
   std::string out;
   switch(EVP_PKEY_base_id(k)) {
      case EVP_PKEY_RSA:
         out = "rsa_2048";
         break;
      case EVP_PKEY_RSA_PSS:
         out = "rsa_pss";
         break;
      case EVP_PKEY_ED25519:
         out = "ed25519";
         break;
      case EVP_PKEY_EC: {
         const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(k);
         const int nid = ec != nullptr ? EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) : NID_undef;
         if(nid == NID_X9_62_prime256v1) {
            out = "ecdsa_p256";
         } else if(nid == NID_secp384r1) {
            out = "ecdsa_p384";
         } else if(nid == NID_secp521r1) {
            out = "ecdsa_p521";
         } else {
            out = "ecdsa";
         }
         break;
      }
      default:
         out = "";
   }
   EVP_PKEY_free(k);
   return out;
}

std::vector<ResolvedChain> resolve_chains(const std::vector<Chain>& chains) {
   std::vector<ResolvedChain> out;
   for(const auto& c : chains) {
      out.push_back({c, c.key_type.empty() ? key_type_of_file(c.key_file) : c.key_type});
   }
   return out;
}

// LibreSSL's certificate slot for a key type ("" = it cannot hold one).
std::string slot_of(const std::string& key_type) {
   if(key_type.rfind("ecdsa", 0) == 0) {
      return "ec";
   }
   if(key_type.rfind("rsa", 0) == 0 && key_type != "rsa_pss") {
      return "rsa";
   }
   return "";
}

// Can a LibreSSL client verify a server certificate with this key type?
bool can_verify_key_type(const std::string& key_type) {
   return key_type.rfind("rsa", 0) == 0 || key_type.rfind("ecdsa", 0) == 0;
}

}  // namespace

// Refuse, before dialing, every capability and `uut` knob LibreSSL lacks, so the
// runner SKIPs the case instead of passing or failing it vacuously.
void refuse_unsupported(const ShimConfig& cfg) {
   if(cfg.requests_dtls13()) {
      report_unsupported("versions", "LibreSSL does not implement DTLS 1.3");
   }
   // LibreSSL's enabled range never goes below TLS 1.2 / DTLS 1.2
   // (ssl_versions.c ssl_enabled_tls_version_range), so a `uut` that enables
   // an older version asks for something it cannot do.
   for(const auto& bound : {cfg.min_version, cfg.max_version}) {
      if(bound.has_value() && (cfg.is_dtls() ? *bound == 0xfeff : *bound < 0x0303)) {
         report_unsupported("versions", "LibreSSL removed TLS 1.0/1.1 and DTLS 1.0");
      }
   }
   if(cfg.psk.present) {
      report_unsupported("psk", "LibreSSL implements no external PSK (TLS 1.2 PSK suites or TLS 1.3 PSK)");
   }
   // A LibreSSL TLS 1.3 server never sends NewSessionTicket, so a multi-session
   // TLS 1.3 run (or one counting tickets) waits for a ticket that never comes.
   if(cfg.is_server() && !cfg.is_dtls()) {
      const bool tls13 = cfg.expect.version == 0x0304 ||
                         std::find(cfg.connection_versions.begin(), cfg.connection_versions.end(), 0x0304) !=
                            cfg.connection_versions.end();
      if(tls13 && (cfg.resume_count > 0 || cfg.session_tickets.value_or(0) > 0)) {
         report_unsupported("session_tickets", "LibreSSL's TLS 1.3 server issues no session tickets");
      }
   }
   if(cfg.record_size_limit.has_value()) {
      report_unsupported("record_size_limit", "LibreSSL does not implement RFC 8449 record_size_limit");
   }
   if(cfg.max_early_data.has_value() || cfg.early_data_send > 0 || cfg.early_data_expect > 0 ||
      cfg.expect_early_data_accepted.has_value() ||
      std::any_of(cfg.connection_early_data.begin(), cfg.connection_early_data.end(), [](const auto& e) {
         return e.send > 0 || e.expect > 0 || e.accepted.has_value();
      })) {
      report_unsupported("early_data", "LibreSSL does not implement TLS 1.3 0-RTT");
   }
   if(!cfg.post_handshake_auth.empty()) {
      report_unsupported("post_handshake_auth", "LibreSSL does not implement post-handshake authentication");
   }
   if(cfg.records_per_traffic_key.has_value()) {
      report_unsupported("records_per_traffic_key", "LibreSSL has no automatic KeyUpdate policy");
   }
   if(cfg.key_update) {
      report_unsupported("key_update", "LibreSSL exposes no API to initiate a TLS 1.3 KeyUpdate");
   }
   if(cfg.min_key_update_interval_ms.has_value() && *cfg.min_key_update_interval_ms != 0) {
      report_unsupported("min_key_update_interval_ms", "LibreSSL has no KeyUpdate rate limit (only 0 = no limit)");
   }
   if(!cfg.half_rtt_data.empty()) {
      report_unsupported("half_rtt_data", "the LibreSSL shim does not write half-RTT application data");
   }
   // LibreSSL implements neither RFC 7627 nor RFC 7366: "off" / false is its
   // only behaviour.
   if(cfg.extended_master_secret.has_value() && *cfg.extended_master_secret != "off") {
      report_unsupported("extended_master_secret", "LibreSSL does not implement extended_master_secret");
   }
   if(cfg.encrypt_then_mac.value_or(false)) {
      report_unsupported("encrypt_then_mac", "LibreSSL does not implement encrypt_then_mac");
   }
   // LibreSSL's TLS 1.3 always runs in middlebox compatibility mode.
   if(cfg.middlebox_compat.has_value() && !*cfg.middlebox_compat) {
      report_unsupported("middlebox_compat", "LibreSSL always uses TLS 1.3 middlebox compatibility mode");
   }
   if(cfg.raw_public_key ||
      std::any_of(cfg.server_certificate_types.begin(), cfg.server_certificate_types.end(),
                  [](uint8_t t) { return t != 0; }) ||
      std::any_of(cfg.client_certificate_types.begin(), cfg.client_certificate_types.end(),
                  [](uint8_t t) { return t != 0; })) {
      report_unsupported("certificate_types", "LibreSSL does not implement RFC 7250 raw public keys");
   }
   if(cfg.compress_certificate) {
      report_unsupported("compress_certificate", "LibreSSL does not implement RFC 8879 certificate compression");
   }
   if(!cfg.signing_prefs.empty() || !cfg.verify_prefs.empty()) {
      report_unsupported("signature_algorithms", "LibreSSL has no API to configure signature algorithm lists");
   }
   if(cfg.server_preference.has_value() && !*cfg.server_preference && cfg.is_server()) {
      // Client preference is LibreSSL's default; nothing to refuse.
   }
   if(cfg.is_dtls()) {
      if(cfg.requires_dynamic_timeout) {
         report_unsupported("set_timeout", "LibreSSL cannot rescale a live DTLS retransmit timer");
      }
      if(cfg.requires_virtual_clock && cfg.initial_timeout_ms != LIBRESSL_DTLS_INITIAL_TIMEOUT_MS) {
         report_unsupported("initial_timeout_ms",
                            "LibreSSL's DTLS retransmit timer always starts at 1000 ms (no DTLS_set_timer_cb)");
      }
      if(cfg.dtls_max_timeout_ms.has_value() && *cfg.dtls_max_timeout_ms != LIBRESSL_DTLS_MAX_TIMEOUT_MS) {
         report_unsupported("dtls_max_timeout_ms", "LibreSSL's DTLS retransmit timer is capped at 60 s");
      }
      if(cfg.dtls_max_retransmissions.has_value() &&
         *cfg.dtls_max_retransmissions != LIBRESSL_DTLS_MAX_RETRANSMISSIONS) {
         report_unsupported("dtls_max_retransmissions", "LibreSSL gives up after a fixed 12 DTLS timeouts");
      }
      if(cfg.dtls_epoch0_restart.has_value()) {
         report_unsupported("dtls_epoch0_restart", "LibreSSL has no epoch-0 restart on an established SSL object");
      }
      if(cfg.dtls_max_hello_verify_requests.has_value()) {
         report_unsupported("dtls_max_hello_verify_requests",
                            "LibreSSL does not bound the HelloVerifyRequests a client answers");
      }
   }

   // Chains: one per slot (RSA, ECC), no Ed25519 / RSA-PSS.
   const auto chains = resolve_chains(cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains);
   std::map<std::string, int> per_slot;
   for(const auto& c : chains) {
      const std::string slot = slot_of(c.key_type);
      if(slot.empty()) {
         report_unsupported("chains", "LibreSSL cannot use a " + c.key_type + " certificate");
      }
      if(++per_slot[slot] > 1) {
         report_unsupported("chains",
                            "LibreSSL holds one " + slot + " certificate per context and has no callback to choose "
                            "among several");
      }
   }
   if(!cfg.is_server() && !cfg.requires_server_keys.empty() &&
      std::none_of(cfg.requires_server_keys.begin(), cfg.requires_server_keys.end(), can_verify_key_type)) {
      report_unsupported("server_key", "LibreSSL cannot verify any of the server's certificate key types");
   }
}

void configure_ctx(SSL_CTX* ctx, const ShimConfig& cfg) {
   refuse_unsupported(cfg);
   SSL_CTX_set_info_callback(ctx, info_cb);

   if(cfg.max_cert_list.has_value()) {
      SSL_CTX_set_max_cert_list(ctx, *cfg.max_cert_list);
   }

   // Session tickets: `uut { session_tickets }`. LibreSSL issues no TLS 1.3
   // tickets at all; 0 also turns off TLS 1.2 tickets and the session cache
   // (no resumption at all).
   if(cfg.session_tickets.has_value() && *cfg.session_tickets == 0) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
      SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
   }

   // Renegotiation (TLS 1.2): an explicit `uut { renegotiation }` wins.
   // LibreSSL's server accepts client-initiated renegotiation by default.
   if(cfg.renegotiation.has_value()) {
      const std::string& r = *cfg.renegotiation;
      if(r != "none" && r != "client" && r != "server" && r != "both") {
         report_result(ShimResult::LocalError, "invalid renegotiation value: " + r);
      }
      if(r == "none") {
         SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_NO_RENEGOTIATION);
         if(r == "client" || r == "both") {
            SSL_CTX_clear_options(ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
            SSL_CTX_set_options(ctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
         } else if(cfg.is_server()) {
            SSL_CTX_set_options(ctx, SSL_OP_NO_CLIENT_RENEGOTIATION);
         }
      }
   } else if(cfg.renegotiate_freely) {
      SSL_CTX_set_options(ctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
   }

   // Server preference covers both cipher suites and groups.
   if(cfg.server_preference.has_value()) {
      if(*cfg.server_preference) {
         SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      }
   }

   // DTLS: the library fragments at `uut { mtu }` (refuse one it will not take).
   if(cfg.is_dtls() && cfg.mtu < 1500) {
      SSL* probe = SSL_new(ctx);
      const bool ok = probe != nullptr && SSL_set_mtu(probe, cfg.mtu) != 0;
      SSL_free(probe);
      if(!ok) {
         report_unsupported("mtu", "below LibreSSL's minimum DTLS MTU (SSL_set_mtu refused " +
                                      std::to_string(cfg.mtu) + ")");
      }
   }
   // DTLS server: perform the HelloVerifyRequest cookie exchange (RFC 6347 4.2.1)
   // during SSL_accept, matching the Botan and OpenSSL shims.
   if(cfg.is_dtls() && cfg.is_server() && cfg.dtls_require_cookie.value_or(true)) {
      SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
      SSL_CTX_set_cookie_generate_cb(ctx, dtls_cookie_generate);
      SSL_CTX_set_cookie_verify_cb(ctx, dtls_cookie_verify);
   }

   if(cfg.min_version.has_value()) {
      const int v = openssl_version(*cfg.min_version);
      if(v != 0) {
         SSL_CTX_set_min_proto_version(ctx, v);
      }
   }
   if(cfg.max_version.has_value()) {
      const int v = openssl_version(*cfg.max_version);
      if(v != 0) {
         SSL_CTX_set_max_proto_version(ctx, v);
      }
   }

   // Certificate chains: at most one per slot (refuse_unsupported checked);
   // LibreSSL picks the slot from the peer's signature_algorithms.
   for(const auto& c : resolve_chains(cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains)) {
      if(SSL_CTX_use_certificate_chain_file(ctx, c.chain.cert_file.c_str()) != 1) {
         throw std::runtime_error("failed to load cert " + c.chain.cert_file + ": " + openssl_errors());
      }
      if(!c.chain.key_file.empty() &&
         SSL_CTX_use_PrivateKey_file(ctx, c.chain.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
         throw std::runtime_error("failed to load key " + c.chain.key_file + ": " + openssl_errors());
      }
   }
   if(!cfg.credentials.trust_file.empty()) {
      if(SSL_CTX_load_verify_locations(ctx, cfg.credentials.trust_file.c_str(), nullptr) != 1) {
         throw std::runtime_error("failed to load trust file: " + openssl_errors());
      }
   }
   // T6: OCSP stapling (server role): staple the configured response.
   if(cfg.is_server() && !cfg.credentials.ocsp_file.empty()) {
      std::ifstream in(cfg.credentials.ocsp_file, std::ios::binary);
      g_ocsp_response.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
      SSL_CTX_set_tlsext_status_cb(ctx, ocsp_status_cb);
      SSL_CTX_set_tlsext_status_arg(ctx, nullptr);
   }

   // NULL-cipher suites need security level 0 (see the OpenSSL shim for why a
   // `requires_any_suite` union lowers it only when every member is weak).
   const bool requires_only_weak =
      !cfg.requires_any_suite.empty() &&
      std::all_of(cfg.requires_any_suite.begin(), cfg.requires_any_suite.end(), needs_security_level_zero);
   if(requires_only_weak ||
      std::any_of(cfg.cipher_suites.begin(), cfg.cipher_suites.end(), needs_security_level_zero)) {
      SSL_CTX_set_security_level(ctx, 0);
   }

   const char* ALL_TLS13_SUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
   if(cfg.cipher_suites.empty()) {
      // Every authenticated, encrypting suite this LibreSSL build implements
      // (LibreSSL's DEFAULT). Anonymous suites, which the OpenSSL shim's
      // security level likewise keeps out, are enabled only when a test names
      // them in `cipher_suites`; NULL-encryption suites also when the peer
      // offers nothing else.
      if(SSL_CTX_set_cipher_list(ctx, requires_only_weak ? "ALL:!aNULL:eNULL" : "ALL:!aNULL:!eNULL") != 1) {
         throw std::runtime_error("failed to set the permissive cipher list: " + openssl_errors());
      }
      if(SSL_CTX_set_ciphersuites(ctx, ALL_TLS13_SUITES) != 1) {
         throw std::runtime_error("failed to set the TLS 1.3 ciphersuites: " + openssl_errors());
      }
   } else {
      std::string tls13_list;
      std::string tls12_list;
      std::string unmapped;
      for(const uint16_t id : cfg.cipher_suites) {
         if(const char* name = tls13_suite_name(id)) {
            tls13_list += (tls13_list.empty() ? "" : ":");
            tls13_list += name;
         } else if(const char* n12 = tls12_cipher_name(id)) {
            tls12_list += (tls12_list.empty() ? "" : ":");
            tls12_list += n12;
         } else {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%s0x%04x", unmapped.empty() ? "" : ", ", id);
            unmapped += buf;
         }
      }
      if(tls13_list.empty() && tls12_list.empty()) {
         report_unsupported("cipher_suites", "LibreSSL has no TLS suite for [" + unmapped + "]");
      }
      // The TLS 1.2 list first: SSL_CTX_set_ciphersuites then merges the
      // TLS 1.3 list in front of the non-TLS 1.3 entries already there. An
      // empty TLS 1.2 list is an error in SSL_CTX_set_cipher_list, so a TLS
      // 1.3-only configuration selects the TLS 1.3 alias (which TLS 1.2 cannot
      // use) and lets the merge replace it.
      if(SSL_CTX_set_cipher_list(ctx, tls12_list.empty() ? "TLSv1.3" : tls12_list.c_str()) != 1) {
         report_unsupported("cipher_suites", "LibreSSL cannot enable [" + tls12_list + "]: " + openssl_errors());
      }
      // An empty TLS 1.3 list is valid and disables TLS 1.3 suites.
      if(SSL_CTX_set_ciphersuites(ctx, tls13_list.c_str()) != 1) {
         report_unsupported("cipher_suites", "LibreSSL cannot enable [" + tls13_list + "]: " + openssl_errors());
      }
   }

   // What plzn will offer: refuse the case when this build has none of the
   // suites it needs, so the runner SKIPs it with the reason.
   if(!cfg.requires_any_suite.empty()) {
      SSL_CTX* probe = SSL_CTX_new(cfg.is_dtls() ? DTLS_method() : TLS_method());
      bool any = false;
      std::string list;
      if(probe != nullptr) {
         SSL_CTX_set_security_level(probe, 0);
         SSL_CTX_set_cipher_list(probe, "ALL:COMPLEMENTOFALL");
         SSL_CTX_set_ciphersuites(probe, ALL_TLS13_SUITES);
         STACK_OF(SSL_CIPHER)* have = SSL_CTX_get_ciphers(probe);
         for(const uint16_t id : cfg.requires_any_suite) {
            for(int i = 0; have != nullptr && i < sk_SSL_CIPHER_num(have); ++i) {
               if(SSL_CIPHER_get_value(sk_SSL_CIPHER_value(have, i)) == id) {
                  any = true;
               }
            }
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%s0x%04x", list.empty() ? "" : ", ", id);
            list += buf;
         }
         SSL_CTX_free(probe);
      } else {
         any = true;  // cannot tell; let the handshake decide
      }
      ERR_clear_error();
      if(!any) {
         report_result(ShimResult::UnsupportedConfig,
                       "peer.capabilities: this LibreSSL build implements none of the offered cipher suites [" +
                          list + "]");
      }
   }

   // Likewise the groups: a `uut { curves }` entry this build lacks, or an
   // offer with no group the shim enables, is a capability gap -> SKIP.
   for(const uint16_t id : cfg.curves) {
      if(!libressl_has_group(id, cfg.is_dtls())) {
         char buf[16];
         std::snprintf(buf, sizeof(buf), "0x%04x", id);
         report_result(ShimResult::UnsupportedConfig, std::string("uut.curves: LibreSSL has no group ") + buf);
      }
   }
   if(!cfg.requires_any_group.empty()) {
      const auto& enabled = cfg.curves.empty() ? DEFAULT_GROUP_IDS : cfg.curves;
      bool any = false;
      std::string list;
      for(const uint16_t id : cfg.requires_any_group) {
         // TLS 1.2 DHE suites ride on the "FFDHE" code points: LibreSSL does
         // DHE with automatic parameters, but not RFC 7919 negotiation.
         any = any || (std::find(enabled.begin(), enabled.end(), id) != enabled.end() &&
                       libressl_has_group(id, cfg.is_dtls()));
         char buf[16];
         std::snprintf(buf, sizeof(buf), "%s0x%04x", list.empty() ? "" : ", ", id);
         list += buf;
      }
      if(!any) {
         report_result(ShimResult::UnsupportedConfig,
                       "peer.capabilities: LibreSSL implements none of the offered key exchange groups [" + list +
                          "]");
      }
   }

   {
      std::string list;
      if(cfg.curves.empty()) {
         list = DEFAULT_GROUPS;
      } else {
         for(const uint16_t id : cfg.curves) {
            list += (list.empty() ? "" : ":");
            list += iana_group_to_name(id);
         }
      }
      if(SSL_CTX_set1_groups_list(ctx, list.c_str()) != 1) {
         throw std::runtime_error("failed to set supported groups " + list + ": " + openssl_errors());
      }
   }

   int verify_mode = SSL_VERIFY_NONE;
   if(cfg.is_server()) {
      if(cfg.verify.require_client_cert) {
         verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      } else if(cfg.verify.request_client_cert) {
         verify_mode = SSL_VERIFY_PEER;
      }
   } else {
      if(cfg.verify.verify_peer) {
         verify_mode = SSL_VERIFY_PEER;
      }
   }
   SSL_CTX_set_verify(ctx, verify_mode, nullptr);

   if(!cfg.srtp_profiles.empty()) {
      std::string profiles;
      for(const uint16_t id : cfg.srtp_profiles) {
         const char* name = nullptr;
         switch(id) {
            case 0x0001: name = "SRTP_AES128_CM_SHA1_80"; break;
            case 0x0002: name = "SRTP_AES128_CM_SHA1_32"; break;
            case 0x0007: name = "SRTP_AEAD_AES_128_GCM"; break;
            case 0x0008: name = "SRTP_AEAD_AES_256_GCM"; break;
            default:
               report_unsupported("srtp_profiles", "LibreSSL does not implement SRTP profile " + std::to_string(id));
         }
         if(!profiles.empty()) {
            profiles += ':';
         }
         profiles += name;
      }
      if(SSL_CTX_set_tlsext_use_srtp(ctx, profiles.c_str()) != 0) {
         report_unsupported("srtp_profiles", "LibreSSL refused SRTP profiles " + profiles + ": " + openssl_errors());
      }
   }

   if(cfg.is_server()) {
      SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, const_cast<ShimConfig*>(&cfg));
      // Enable automatic DH parameters so DHE_RSA suites can be negotiated.
      SSL_CTX_set_dh_auto(ctx, 1);
      // Fixed ticket key for deterministic cross-process resumption.
      SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_cb);
   }
}

void check_expectations(SSL* ssl, const ShimConfig& cfg) {
   const auto& e = cfg.expect;
   if(e.version.has_value()) {
      const uint16_t got = static_cast<uint16_t>(SSL_version(ssl));
      if(got != *e.version) {
         note_failure("version mismatch: got " + std::to_string(got) + " expected " + std::to_string(*e.version));
      }
   }
   if(e.cipher.has_value()) {
      const SSL_CIPHER* c = SSL_get_current_cipher(ssl);
      const uint16_t id = c != nullptr ? static_cast<uint16_t>(SSL_CIPHER_get_value(c)) : 0;
      if(id != *e.cipher) {
         note_failure("cipher mismatch: got " + std::to_string(id) + " expected " + std::to_string(*e.cipher));
      }
   }
   if(cfg.alpn.expect.has_value()) {
      const unsigned char* proto = nullptr;
      unsigned int len = 0;
      SSL_get0_alpn_selected(ssl, &proto, &len);
      const std::string got(reinterpret_cast<const char*>(proto), len);
      if(got != *cfg.alpn.expect) {
         note_failure("alpn mismatch: got '" + got + "' expected '" + *cfg.alpn.expect + "'");
      }
   }
   if(cfg.expect_srtp_profile.has_value()) {
      const SRTP_PROTECTION_PROFILE* selected = SSL_get_selected_srtp_profile(ssl);
      const uint16_t got = selected != nullptr ? static_cast<uint16_t>(selected->id) : 0;
      if(got != *cfg.expect_srtp_profile) {
         note_failure("SRTP profile mismatch: got " + std::to_string(got) + " expected " +
                      std::to_string(*cfg.expect_srtp_profile));
      }
   }
   if(cfg.expect_server_name.has_value()) {
      // On the server, SSL_get_servername returns the SNI the client sent.
      const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
      const std::string got(sni != nullptr ? sni : "");
      if(got != *cfg.expect_server_name) {
         note_failure("sni mismatch: got '" + got + "' expected '" + *cfg.expect_server_name + "'");
      }
   }
   if(e.resumed.has_value()) {
      const bool resumed = SSL_session_reused(ssl) == 1;
      if(resumed != *e.resumed) {
         note_failure(std::string("resumed mismatch: got ") + (resumed ? "true" : "false"));
      }
   }
}

// ---- Custom datagram BIO bridging LibreSSL DTLS to the shim's P/T/C framing ----
//
// LibreSSL DTLS needs a datagram BIO. This one carries each datagram over the
// runner control connection using the shim P/T/C protocol (ShimSocket). A 'T'
// frame advances the frozen clock (g_clock) and makes the read return "retry"
// so the shim can run DTLSv1_handle_timeout against the new time; a 'C' frame
// is applied in place.

bool dtls_trace() {
   static const bool on = ::getenv("PLZN_DTLS_TRACE") != nullptr;
   return on;
}

int dgram_bwrite(BIO* b, const char* data, int len) {
   auto* s = static_cast<ShimSocket*>(BIO_get_data(b));
   BIO_clear_retry_flags(b);
   if(dtls_trace()) {
      std::cerr << "[libressl-bio] bwrite " << len << std::endl;
   }
   s->write_dtls_packet(reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len));
   return len;
}

int dgram_bread(BIO* b, char* data, int len) {
   auto* s = static_cast<ShimSocket*>(BIO_get_data(b));
   BIO_clear_retry_flags(b);
   for(;;) {
      DtlsEvent ev = s->read_dtls_event();
      if(ev.opcode == DtlsOpcode::Eof) {
         if(dtls_trace()) {
            std::cerr << "[libressl-bio] bread EOF" << std::endl;
         }
         return 0;
      }
      if(ev.opcode == DtlsOpcode::AdvanceClock) {
         if(dtls_trace()) {
            std::cerr << "[libressl-bio] defer clock +" << ev.nanos << "ns" << std::endl;
         }
         g_dtls_interrupt = {DtlsInterruptKind::AdvanceClock, ev.nanos};
         BIO_set_retry_read(b);
         return -1;
      }
      if(ev.opcode == DtlsOpcode::ExpectTimeout) {
         g_dtls_interrupt = {DtlsInterruptKind::ExpectTimeout, ev.nanos};
         BIO_set_retry_read(b);
         return -1;
      }
      if(ev.opcode == DtlsOpcode::UpdateTimeout) {
         g_dtls_interrupt = {DtlsInterruptKind::UpdateTimeout, ev.millis};
         BIO_set_retry_read(b);
         return -1;
      }
      if(ev.opcode == DtlsOpcode::Control) {
         if(ev.command == static_cast<uint8_t>(DtlsControl::RotateCookieSecret)) {
            ++g_cookie_generation;
            if(dtls_trace()) {
               std::cerr << "[libressl-bio] cookie secret rotated (generation " << g_cookie_generation << ")"
                         << std::endl;
            }
            continue;
         }
         throw ShimSocketError("unknown DTLS control command " + std::to_string(ev.command));
      }
      track_client_hello(ev.packet);
      const int n = std::min(static_cast<size_t>(len), ev.packet.size());
      std::memcpy(data, ev.packet.data(), static_cast<size_t>(n));
      if(dtls_trace()) {
         std::cerr << "[libressl-bio] bread " << n << " (datagram " << ev.packet.size() << ")" << std::endl;
      }
      return n;
   }
}

long dgram_ctrl(BIO* /*b*/, int cmd, long num, void* /*ptr*/) {
   switch(cmd) {
      case BIO_CTRL_FLUSH:
      case BIO_CTRL_DGRAM_SET_CONNECTED:
      case BIO_CTRL_DGRAM_SET_PEER:
      case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
         return 1;
      case BIO_CTRL_DGRAM_QUERY_MTU:
      case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
         return g_mtu;
      case BIO_CTRL_DGRAM_SET_MTU:
         return num;
      case BIO_CTRL_WPENDING:
      case BIO_CTRL_PENDING:
      case BIO_CTRL_DGRAM_GET_PEER:
      case BIO_CTRL_PUSH:
      case BIO_CTRL_POP:
      default:
         return 0;
   }
}

int dgram_create(BIO* b) {
   BIO_set_init(b, 1);
   return 1;
}

int dgram_destroy(BIO* /*b*/) {
   return 1;
}

BIO_METHOD* plzn_dgram_method() {
   static BIO_METHOD* meth = [] {
      BIO_METHOD* m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "plzn-dgram");
      BIO_meth_set_write(m, dgram_bwrite);
      BIO_meth_set_read(m, dgram_bread);
      BIO_meth_set_ctrl(m, dgram_ctrl);
      BIO_meth_set_create(m, dgram_create);
      BIO_meth_set_destroy(m, dgram_destroy);
      return m;
   }();
   return meth;
}

// The frozen clock makes LibreSSL's own view of the timer exact, so its
// DTLSv1_get_timeout is the semantic remaining time (it already reports a
// timer with under 15 ms left as expired, the same bounded early-fire window
// Botan/BoGo use for a 1 s timer).
void expect_dtls_timeout(SSL* ssl, ShimSocket& socket, uint64_t expected_ns) {
   timeval timeout{};
   const bool has_timeout = DTLSv1_get_timeout(ssl, &timeout) == 1;
   if(expected_ns == UINT64_MAX) {
      if(has_timeout) {
         throw std::runtime_error("expected no DTLS timeout, but one is armed");
      }
      socket.write_dtls_ack('e');
      return;
   }
   if(!has_timeout) {
      throw std::runtime_error("expected an armed DTLS timeout, but got none");
   }
   const uint64_t actual_ns =
      static_cast<uint64_t>(timeout.tv_sec) * 1'000'000'000 + static_cast<uint64_t>(timeout.tv_usec) * 1000;
   if(actual_ns != expected_ns) {
      throw std::runtime_error("DTLS next timeout mismatch: expected " + std::to_string(expected_ns) +
                               "ns, got " + std::to_string(actual_ns) + "ns");
   }
   socket.write_dtls_ack('e');
}

void handle_dtls_interrupt(SSL* ssl, ShimSocket& socket) {
   const DtlsInterrupt op = g_dtls_interrupt;
   g_dtls_interrupt = {};
   switch(op.kind) {
      case DtlsInterruptKind::None:
         return;
      case DtlsInterruptKind::ExpectTimeout:
         expect_dtls_timeout(ssl, socket, op.value);
         return;
      case DtlsInterruptKind::UpdateTimeout:
         // Refused before dialing (requires_dynamic_timeout).
         throw std::runtime_error("LibreSSL cannot rescale a live DTLS retransmit timer");
      case DtlsInterruptKind::AdvanceClock:
         g_clock.advanced_ns += op.value;
         if(dtls_trace()) {
            std::cerr << "[libressl-bio] clock +" << op.value << "ns (virtual " << g_clock.advanced_ns / 1'000'000
                      << " ms)" << std::endl;
         }
         break;
   }

   // DTLSv1_handle_timeout retransmits when the timer expired and fails once
   // LibreSSL's fixed budget (DTLS1_TMO_ALERT_COUNT) is spent.
   const int ret = static_cast<int>(DTLSv1_handle_timeout(ssl));
   if(ret < 0 && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE) {
      socket.write_dtls_timeout_expired();
      g_flow_failed = true;
      throw ProtocolFailure("DTLS retransmission timeout expired: " + openssl_errors());
   }
   socket.write_dtls_ack('t');
}

// Application bytes received so far on this connection (the trigger for
// `renegotiate_after_handshake`).
size_t g_app_bytes_received = 0;

void run_connection(const ShimConfig& cfg, SSL_CTX* ctx, uint32_t connection_index) {
   g_app_bytes_received = 0;
   g_sent_fatal_alert = 0;
   ShimSocket socket(cfg.runner.host, cfg.runner.port, cfg.runner.ipv6);
   socket.write_shim_id(cfg.shim_id);

   SSL* ssl = SSL_new(ctx);
   if(ssl == nullptr) {
      throw std::runtime_error("SSL_new failed: " + openssl_errors());
   }
   if(cfg.min_version.has_value() &&
      SSL_set_min_proto_version(ssl, openssl_version(*cfg.min_version)) != 1) {
      SSL_free(ssl);
      throw std::runtime_error("cannot set connection minimum version: " + openssl_errors());
   }
   if(cfg.max_version.has_value() &&
      SSL_set_max_proto_version(ssl, openssl_version(*cfg.max_version)) != 1) {
      SSL_free(ssl);
      throw std::runtime_error("cannot set connection maximum version: " + openssl_errors());
   }

   if(!cfg.is_server()) {
      if(!cfg.server_name.empty()) {
         SSL_set_tlsext_host_name(ssl, cfg.server_name.c_str());
         // Setting SNI does NOT enable hostname verification -- SSL_VERIFY_PEER
         // only checks the chain. When verifying, also bind the expected name so
         // LibreSSL rejects a certificate whose SAN/CN does not match.
         if(cfg.verify.verify_peer) {
            SSL_set1_host(ssl, cfg.server_name.c_str());
         }
      }
      if(!cfg.alpn.advertise.empty()) {
         const auto wire = alpn_wire(cfg.alpn.advertise);
         SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned int>(wire.size()));
      }
      if(g_client_session != nullptr && session_fits_connection(cfg, g_client_session)) {
         SSL_set_session(ssl, g_client_session);
      }
   }

   if(cfg.is_dtls()) {
      BIO* bio = BIO_new(plzn_dgram_method());
      BIO_set_data(bio, &socket);
      SSL_set_bio(ssl, bio, bio);
      // `uut { mtu }`: the library fragments its handshake flights at this
      // size (checked in configure_ctx); never re-query the BIO for it.
      g_mtu = cfg.mtu;
      SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
      SSL_set_mtu(ssl, cfg.mtu);
      // The retransmit timer runs on the frozen clock (see g_clock).
      g_clock.base_us = real_now_us();
      g_clock.advanced_ns = 0;
      g_clock.frozen = true;
      g_dtls_interrupt = {};
      g_cookie_generation = 0;
      g_client_random_seq = -1;
      g_client_random_seen.fill(false);
   } else {
      SSL_set_fd(ssl, socket.fd());
   }

   // DTLS over a custom (non-socket) BIO drives the handshake as a state
   // machine that yields WANT_READ/WANT_WRITE between flights, so loop rather
   // than calling accept/connect once. Each retry re-enters the BIO, whose read
   // blocks until the next datagram arrives.
   for(;;) {
      // SSL_get_error is only reliable with an empty error queue on entry.
      ERR_clear_error();
      const int hs = cfg.is_server() ? SSL_accept(ssl) : SSL_connect(ssl);
      if(hs == 1) {
         break;
      }
      const int sslerr = SSL_get_error(ssl, hs);
      if(sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
         if(cfg.is_dtls() && g_dtls_interrupt.kind != DtlsInterruptKind::None) {
            handle_dtls_interrupt(ssl, socket);
         }
         continue;
      }
      const std::string err = openssl_errors();
      SSL_free(ssl);
      g_flow_failed = true;
      throw ProtocolFailure("handshake failed: ret=" + std::to_string(hs) + " sslerr=" +
                               std::to_string(sslerr) + " " + err);
   }

   check_expectations(ssl, cfg);
   for(const auto& request : cfg.key_material) {
      if(request.connection != connection_index) continue;
      std::vector<uint8_t> out(request.length);
      if(request.kind == "exporter") {
         const unsigned char* context = request.context
            ? reinterpret_cast<const unsigned char*>(request.context->data()) : nullptr;
         const size_t context_len = request.context ? request.context->size() : 0;
         if(SSL_export_keying_material(
               ssl, out.data(), out.size(), request.label.data(), request.label.size(),
               context, context_len, request.context.has_value()) != 1) {
            SSL_free(ssl);
            throw std::runtime_error("SSL_export_keying_material failed: " + openssl_errors());
         }
      } else if(request.kind == "tls_unique" || request.kind == "tls_unique_unavailable") {
         // LibreSSL has no extended master secret, so tls-unique is
         // unavailable on every resumed connection (RFC 7627 5.4).
         const bool available = SSL_session_reused(ssl) != 1;
         if(request.kind == "tls_unique_unavailable") {
            if(available) {
               SSL_free(ssl);
               throw std::runtime_error("tls-unique unexpectedly available");
            }
            out.assign(1, 0x01);
         } else {
         const bool resumed = SSL_session_reused(ssl) == 1;
         const bool local_finished_first = resumed == cfg.is_server();
         const size_t n = local_finished_first
            ? SSL_get_finished(ssl, out.data(), out.size())
            : SSL_get_peer_finished(ssl, out.data(), out.size());
         if(n == 0 || n > out.size()) {
            SSL_free(ssl);
            throw std::runtime_error("cannot obtain tls-unique Finished value");
         }
         out.resize(n);
         }
      } else {
         SSL_free(ssl);
         throw std::runtime_error("unknown key_material kind: " + request.kind);
      }
      size_t offset = 0;
      while(offset < out.size()) {
         const int n = SSL_write(ssl, out.data() + offset,
                                 static_cast<int>(out.size() - offset));
         if(n <= 0) {
            SSL_free(ssl);
            throw std::runtime_error("writing key material failed: " + openssl_errors());
         }
         offset += static_cast<size_t>(n);
      }
   }

   // Application-data phase.
   if(cfg.app_data.mode == AppDataMode::ShutdownOnly) {
      SSL_shutdown(ssl);
   } else if(cfg.app_data.mode == AppDataMode::ShimWrites) {
      if(!cfg.app_data.send.empty()) {
         SSL_write(ssl, cfg.app_data.send.data(), static_cast<int>(cfg.app_data.send.size()));
      }
      SSL_shutdown(ssl);
   } else {
      // Serve framed random-data requests until the peer closes. A fatal
      // protocol error here (e.g. the runner sent a mutated record that fails
      // AEAD open) is a flow failure a negative test may be asserting, so it is
      // recorded rather than silently swallowed.
      std::vector<uint8_t> buf(16 * 1024);
      AppDataResponder app_responder;
      bool renegotiated = false;
      for(;;) {
         // `uut { renegotiate_after_handshake }`: a client that has completed
         // one application-data round trip starts a renegotiation (TLS 1.2;
         // TLS 1.3 has no renegotiation).
         if(!cfg.is_server() && cfg.renegotiate_after_handshake && !renegotiated && g_app_bytes_received > 0) {
            renegotiated = true;
            if(SSL_renegotiate(ssl) != 1) {
               g_flow_failed = true;
               note_failure("renegotiate_after_handshake: SSL_renegotiate failed: " + openssl_errors());
               break;
            }
            // The renegotiation handshake is driven by the SSL_read below, the
            // way the API intends (SSL_renegotiate(3): "the next SSL_read or
            // SSL_write performs the handshake"): application data the peer
            // sent under the old keys, crossing our ClientHello, is delivered
            // to us (an SSL_do_handshake drive rejects it as an unexpected
            // record), and a refused (no_renegotiation) or failed handshake
            // surfaces as that read's SSL error.
         }
         // T5 `uut { hello_request_after_app_data }`: a server that has received
         // application data sends a HelloRequest (SSL_renegotiate + one
         // SSL_do_handshake pushes it out; the next SSL_read runs the client's
         // renegotiation). `require_client_cert_on_renegotiation` switches the
         // verify mode first, so only the second handshake demands a client
         // certificate (the classic per-resource renegotiation).
         if(cfg.is_server() && cfg.hello_request_after_app_data && !renegotiated && g_app_bytes_received > 0) {
            renegotiated = true;
            if(cfg.require_client_cert_on_renegotiation) {
               SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            }
            if(SSL_renegotiate(ssl) != 1) {
               g_flow_failed = true;
               note_failure("hello_request_after_app_data: SSL_renegotiate failed: " + openssl_errors());
               break;
            }
            (void)SSL_do_handshake(ssl);
         }
         ERR_clear_error();
         errno = 0;
         const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
         const int read_errno = errno;
         if(n <= 0) {
            const int err = SSL_get_error(ssl, n);
            if(dtls_trace()) {
               std::cerr << "[libressl] SSL_read ret=" << n << " err=" << err << std::endl;
            }
            if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
               if(cfg.is_dtls() && g_dtls_interrupt.kind != DtlsInterruptKind::None) {
                  handle_dtls_interrupt(ssl, socket);
               }
               continue;  // DTLS: the virtual clock moved; nothing arrived yet
            }
            if(err == SSL_ERROR_ZERO_RETURN) {
               // Clean close_notify from the peer: answer it (bidirectional
               // shutdown). SSL_free evicts a session that was never shut down
               // from the cache, so without this reply it could not be resumed
               // on the next connection. The peer may already have closed the
               // socket; a failed write here is harmless.
               SSL_shutdown(ssl);
               break;
            }
            if(err == SSL_ERROR_SYSCALL && g_sent_fatal_alert != 0) {
               g_flow_failed = true;
               if(g_fail_reason.empty()) {
                  g_fail_reason = "SSL_read failed after sending fatal alert " + std::to_string(g_sent_fatal_alert);
               }
               break;
            }
            if(err == SSL_ERROR_SYSCALL && n < 0 && read_errno != ECONNRESET && read_errno != EPIPE) {
               // LibreSSL rejects some records (an unknown content type, a
               // stray ChangeCipherSpec) by failing the read with neither an
               // alert nor a queued error; an application sees this
               // SSL_ERROR_SYSCALL as a failed connection.
               g_flow_failed = true;
               if(g_fail_reason.empty()) {
                  g_fail_reason = "SSL_read failed (SSL_ERROR_SYSCALL, errno " + std::to_string(read_errno) + ")";
               }
               break;
            }
            if(err == SSL_ERROR_SYSCALL && n == 0 && ERR_peek_error() == 0) {
               // The runner closed the TCP connection without a close_notify,
               // which it legitimately does at the end of a flow. Treat it as a
               // clean close, as the OpenSSL shim does with
               // SSL_OP_IGNORE_UNEXPECTED_EOF (LibreSSL has no such option):
               // otherwise SSL_free evicts the session (TLS 1.0 rule, relaxed by
               // RFC 5246 7.2.1) and session-ID resumption could never be tested.
               SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
               break;
            }
            if(err == SSL_ERROR_SSL) {
               g_flow_failed = true;  // fatal protocol error (bad_record_mac, ...)
               const std::string errors = openssl_errors();
               if(renegotiated) {
                  note_failure("renegotiate_after_handshake: renegotiation handshake failed: " + errors);
               } else if(g_fail_reason.empty()) {
                  g_fail_reason = "SSL_read failed: " + errors;
               }
            }
            break;
         }
         bool write_failed = false;
         for(const auto& reply : app_responder.receive(buf.data(), static_cast<size_t>(n))) {
            size_t written = 0;
            while(written < reply.size()) {
               const int w = SSL_write(ssl, reply.data() + written,
                                       static_cast<int>(reply.size() - written));
               if(w <= 0) {
                  write_failed = true;
                  break;
               }
               written += static_cast<size_t>(w);
            }
            if(write_failed) break;
         }
         if(write_failed) {
            break;
         }
         g_app_bytes_received += static_cast<size_t>(n);
      }
   }

   if(!cfg.is_server()) {
      // Keep the session this connection ended with (a TLS 1.3 ticket arrives
      // post-handshake, so it is only complete now) for the next connection.
      if(g_client_session != nullptr) {
         SSL_SESSION_free(g_client_session);
      }
      g_client_session = SSL_get1_session(ssl);
   }
   SSL_free(ssl);
}

}  // namespace

// The process-wide clock LibreSSL's DTLS timer reads (see VirtualClock). glibc
// declares gettimeofday with a throw() specification, so the definition must
// be noexcept to match.
extern "C" int gettimeofday(struct timeval* tv, void* /*tz*/) noexcept {
   const int64_t virtual_ns = static_cast<int64_t>(g_clock.advanced_ns);
   const int64_t us = g_clock.frozen ? g_clock.base_us + virtual_ns / 1000 : real_now_us();
   tv->tv_sec = static_cast<time_t>(us / 1000000);
   tv->tv_usec = static_cast<suseconds_t>(us % 1000000);
   return 0;
}

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   // LibreSSL writes to the socket fd directly (no MSG_NOSIGNAL): a close_notify
   // sent after the runner already closed its end must not kill the process.
   std::signal(SIGPIPE, SIG_IGN);
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      if(a == "--plzn-shim-info") {
         std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"libressl","expectations":"libressl-expectations.json"})" << std::endl;
         return 0;
      } else if(a == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(a.rfind("-config=", 0) == 0) {
         config_path = a.substr(std::string("-config=").size());
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: libressl_shim -config <file.json> | --plzn-shim-info" << std::endl;
      return 2;
   }

   ShimConfig cfg;
   try {
      cfg = ShimConfig::from_file(config_path);
   } catch(const std::exception& e) {
      std::cerr << "config error: " << e.what() << std::endl;
      return 2;
   }

   const bool expect_handshake_failure = cfg.expect.handshake_error.has_value();

   const SSL_METHOD* method;
   if(cfg.is_dtls()) {
      method = cfg.is_server() ? DTLS_server_method() : DTLS_client_method();
   } else {
      method = cfg.is_server() ? TLS_server_method() : TLS_client_method();
   }
   SSL_CTX* ctx = SSL_CTX_new(method);
   if(ctx == nullptr) {
      std::cerr << "SSL_CTX_new failed: " << openssl_errors() << std::endl;
      return 2;
   }

   try {
      configure_ctx(ctx, cfg);
      for(uint32_t i = 0; i <= cfg.resume_count; ++i) {
         const auto connection_cfg = cfg.for_connection(i);
         run_connection(connection_cfg, ctx, i);
         if(!g_fail_reason.empty()) {
            break;
         }
      }
   } catch(const ProtocolFailure& e) {
      g_flow_failed = true;
      g_fail_reason = e.what();
   } catch(const ShimSocketError& e) {
      SSL_CTX_free(ctx);
      if(!g_expectation_failure.empty()) report_result(ShimResult::ExpectationMismatch, g_expectation_failure);
      if(expect_handshake_failure || cfg.expect.handshake_abandoned) report_success(e.what());
      report_result(ShimResult::IoError, e.what());
   } catch(const std::exception& e) {
      SSL_CTX_free(ctx);
      report_result(ShimResult::LocalError, e.what());
   }

   SSL_CTX_free(ctx);

   if(!g_expectation_failure.empty()) {
      report_result(ShimResult::ExpectationMismatch, g_expectation_failure);
   }
   if(cfg.expect.handshake_abandoned) {
      // plzn abandons the handshake on purpose: the library's reaction to the
      // abrupt close (a failed flow, or a completed one) is not under test.
      report_success(g_flow_failed ? (g_fail_reason.empty() ? std::string("flow ended by the peer's close") : g_fail_reason)
                                   : std::string());
   }
   if(expect_handshake_failure) {
      if(g_flow_failed) {
         // Report Ok (the failure was expected) but keep the library's reason so
         // the runner learns WHICH failure path was taken, not just that one was.
         report_success(g_fail_reason.empty() ? std::string("flow failed as expected") : g_fail_reason);
      }
      report_result(ShimResult::UnexpectedSuccess, "expected the flow to fail but it completed");
   }
   if(g_flow_failed) {
      // The handshake / record flow failed in the library (not a self-check).
      report_result(ShimResult::HandshakeFailed,
                    g_fail_reason.empty() ? "flow failed unexpectedly" : g_fail_reason);
   }
   if(!g_fail_reason.empty()) {
      // Only note_failure (negotiated-parameter expectation mismatch) reaches here
      // without g_flow_failed.
      report_result(ShimResult::ExpectationMismatch, g_fail_reason);
   }
   report_success();
}
