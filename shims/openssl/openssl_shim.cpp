/*
 * plzn OpenSSL interop shim.
 *
 * Wraps OpenSSL 3.x TLS client/server as a unit-under-test driven by the same
 * JSON config the Botan shim consumes (see ../DESIGN.md, ../common/plzn_shim.h).
 * This is the second consumer of the shared config library, which is the point:
 * one config format, two independent library backends.
 *
 * Supports both TLS (over the socket fd) and DTLS (over a custom datagram BIO
 * that bridges OpenSSL to the shim's P/T datagram framing).
 */

#include "plzn_shim.h"

#include <fstream>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/time.h>
#include <time.h>

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <optional>

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
// The library's error for a failure in the post-handshake application-data
// loop, reported as the detail without ending a multi-session run early.
std::string g_record_error;

struct ProtocolFailure : std::runtime_error { using std::runtime_error::runtime_error; };

// Decoded PSK material, shared with the C-style PSK callbacks (single config
// per process).
std::vector<uint8_t> g_psk;
std::string g_psk_identity;

// ---- DTLS virtual clock ----
//
// OpenSSL's DTLS retransmit timer reads the wall clock through gettimeofday()
// (crypto/time.c, ossl_time_now) and offers no hook for another clock. The
// shim therefore defines gettimeofday itself (below main): the dynamic linker
// resolves libcrypto's call to the executable's definition, because a symbol a
// shared library references and the executable defines is exported and
// preempts libc's. For a DTLS connection the clock is frozen when the shim
// starts and moves only with the runner's 'T' frames, so a retransmission
// fires exactly when the flow advances the clock past the timer (RFC 6347
// 4.2.4), never on real time; TLS keeps the real clock.
struct VirtualClock {
      bool frozen = false;
      int64_t base_us = 0;       // real time captured when frozen
      uint64_t advanced_ns = 0;  // sum of the 'T' frames
      // Live timeout rescaling moves OpenSSL's view of now relative to the
      // runner's logical clock. This is how the shim emulates BoringSSL's
      // DTLSv1_set_initial_timeout_duration API on OpenSSL 3.x.
      int64_t adjustment_ns = 0;
};
VirtualClock g_clock;

int64_t real_now_us() {
   timespec ts{};
   ::clock_gettime(CLOCK_REALTIME, &ts);
   return static_cast<int64_t>(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000;
}

// The retransmit schedule the shim gives OpenSSL through DTLS_set_timer_cb:
// `initial_timeout_ms`, doubling up to `dtls_max_timeout_ms` (60 s by default,
// OpenSSL's own cap), giving up after `dtls_max_retransmissions` timeouts
// (OpenSSL's own budget is 12). OpenSSL treats a timer with 15 ms or less left
// as expired (d1_lib.c dtls1_get_timeout); the callback adds enough slack for
// short timers while preserving Botan/BoGo's bounded early-fire window.
struct DtlsTimer {
      uint32_t initial_ms = 1000;
      uint32_t max_ms = 60000;
      std::optional<uint32_t> max_retransmissions;
      uint64_t duration_ms = 0;
      uint32_t timeouts = 0;
      uint64_t armed_at_logical_ns = 0;
      int64_t deadline_clock_ns = 0;
      // The budget is spent: the flight is not sent again and the next read
      // reports end-of-connection, so the handshake fails the way Botan's does
      // when its channel gives up.
      bool exhausted = false;
};
DtlsTimer g_timer;

uint64_t dtls_timer_slack_ms() {
   // OpenSSL treats <=15 ms as expired. Botan/BoGo expose a bounded early-fire
   // window of min(15ms, initial/2); add only the difference so tiny timers do
   // not fire immediately while ordinary timers retain the BoGo fudge factor.
   const uint64_t semantic_fudge = std::min<uint64_t>(15, g_timer.initial_ms / 2);
   return 15 - semantic_fudge;
}

unsigned int dtls_timer_cb(SSL* /*ssl*/, unsigned int timer_us) {
   if(timer_us == 0) {
      // A fresh timer (first flight, or the first after a stop).
      g_timer.duration_ms = g_timer.initial_ms;
      g_timer.timeouts = 0;
   } else {
      // The timer fired: OpenSSL is about to retransmit and re-arm.
      ++g_timer.timeouts;
      if(g_timer.max_retransmissions.has_value() && g_timer.timeouts > *g_timer.max_retransmissions) {
         g_timer.exhausted = true;
      }
      g_timer.duration_ms = std::min<uint64_t>(g_timer.duration_ms * 2, g_timer.max_ms);
   }
   g_timer.armed_at_logical_ns = g_clock.advanced_ns;
   const uint64_t slack_ms = dtls_timer_slack_ms();
   g_timer.deadline_clock_ns = static_cast<int64_t>(g_clock.advanced_ns) + g_clock.adjustment_ns +
                               static_cast<int64_t>(g_timer.duration_ms + slack_ms) * 1'000'000;
   return static_cast<unsigned int>((g_timer.duration_ms + slack_ms) * 1000);
}

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
// datagrams it hands OpenSSL, since the cookie callback runs before OpenSSL
// has parsed the first ClientHello) and invalidated by a `rotate_cookie_secret`
// step, which bumps the generation. A ClientHello with a cookie that does not
// verify is a fatal handshake_failure in OpenSSL's stateful SSL_accept path
// (SSL_R_COOKIE_MISMATCH); only DTLSv1_listen re-challenges.
uint32_t g_cookie_generation = 0;
std::array<uint8_t, 32> g_client_random{};
std::array<bool, 34> g_client_random_seen{};  // ClientHello bytes [0, 34) covered
int32_t g_client_random_seq = -1;             // message_seq being tracked

std::vector<uint8_t> cookie_for(const uint8_t random[32]) {
   std::string key = "plzn-openssl-shim-cookie-secret";
   key.push_back(static_cast<char>(g_cookie_generation));
   std::vector<uint8_t> data(random, random + 32);
   const std::string identity = "plzn-shim-peer";
   data.insert(data.end(), identity.begin(), identity.end());
   std::vector<uint8_t> out(32);
   size_t outlen = 0;
   if(EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.data(), key.size(), data.data(), data.size(),
                out.data(), out.size(), &outlen) == nullptr) {
      throw std::runtime_error("cookie HMAC failed: " + std::string("EVP_Q_mac"));
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

std::vector<uint8_t> hex_decode(const std::string& hex) {
   std::vector<uint8_t> out;
   auto nibble = [](char c) -> int {
      if(c >= '0' && c <= '9') {
         return c - '0';
      }
      if(c >= 'a' && c <= 'f') {
         return c - 'a' + 10;
      }
      if(c >= 'A' && c <= 'F') {
         return c - 'A' + 10;
      }
      return -1;
   };
   for(size_t i = 0; i + 1 < hex.size(); i += 2) {
      const int hi = nibble(hex[i]);
      const int lo = nibble(hex[i + 1]);
      if(hi < 0 || lo < 0) {
         break;
      }
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
   }
   return out;
}

// TLS 1.3 external PSK (server side): build an SSL_SESSION carrying the PSK when
// the offered identity matches. The cipher fixes the PRF hash (SHA-256 here).
int psk_find_session_cb(SSL* ssl,
                        const unsigned char* identity,
                        size_t identity_len,
                        SSL_SESSION** sess) {
   if(identity_len != g_psk_identity.size() ||
      std::memcmp(identity, g_psk_identity.data(), identity_len) != 0) {
      *sess = nullptr;
      return 1;  // no match, not an error
   }
   const unsigned char tls13_aes128[2] = {0x13, 0x01};  // TLS_AES_128_GCM_SHA256 (SHA-256)
   const SSL_CIPHER* cipher = SSL_CIPHER_find(ssl, tls13_aes128);
   if(cipher == nullptr) {
      return 0;
   }
   SSL_SESSION* s = SSL_SESSION_new();
   if(s == nullptr) {
      return 0;
   }
   if(SSL_SESSION_set1_master_key(s, g_psk.data(), g_psk.size()) != 1 ||
      SSL_SESSION_set_cipher(s, cipher) != 1 ||
      SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION) != 1) {
      SSL_SESSION_free(s);
      return 0;
   }
   *sess = s;
   return 1;
}

unsigned int psk_server_cb(SSL* /*ssl*/, const char* identity, unsigned char* psk, unsigned int max_psk_len) {
   // The shim holds exactly one PSK, for the identity plzn configured: any
   // other identity has no key (OpenSSL then sends unknown_psk_identity,
   // RFC 4279 2), which is what the unknown-identity negatives probe.
   if(identity == nullptr || std::string(identity) != g_psk_identity) {
      return 0;
   }
   if(g_psk.size() > max_psk_len) {
      return 0;
   }
   std::memcpy(psk, g_psk.data(), g_psk.size());
   return static_cast<unsigned int>(g_psk.size());
}

unsigned int psk_client_cb(
   SSL* /*ssl*/, const char* /*hint*/, char* identity, unsigned int max_identity_len, unsigned char* psk, unsigned int max_psk_len) {
   if(g_psk_identity.size() + 1 > max_identity_len || g_psk.size() > max_psk_len) {
      return 0;
   }
   std::memcpy(identity, g_psk_identity.c_str(), g_psk_identity.size() + 1);
   std::memcpy(psk, g_psk.data(), g_psk.size());
   return static_cast<unsigned int>(g_psk.size());
}

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

// Map a 16-bit IANA named-group code (RFC 8446 / 7919 / 7027 / 8734,
// draft-connolly-tls-mlkem, draft-kwiatkowski-tls-ecdhe-mlkem) to the OpenSSL
// group name SSL_CTX_set1_groups_list expects (names work for the provider-
// implemented ML-KEM groups, which have no stable NID). Empty for an unmapped
// code.
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
      case 0x001e:
         return "X448";
      case 0x001f:
         return "brainpoolP256r1tls13";
      case 0x0020:
         return "brainpoolP384r1tls13";
      case 0x0021:
         return "brainpoolP512r1tls13";
      case 0x0100:
         return "ffdhe2048";
      case 0x0101:
         return "ffdhe3072";
      case 0x0102:
         return "ffdhe4096";
      case 0x0103:
         return "ffdhe6144";
      case 0x0104:
         return "ffdhe8192";
      case 0x0200:
         return "MLKEM512";
      case 0x0201:
         return "MLKEM768";
      case 0x0202:
         return "MLKEM1024";
      case 0x11eb:
         return "SecP256r1MLKEM768";
      case 0x11ec:
         return "X25519MLKEM768";
      case 0x11ed:
         return "SecP384r1MLKEM1024";
      case 0x11ee:
         return "X448MLKEM1024";
      default:
         return "";
   }
}

// Whether this build (and its loaded providers) implements a group: parse it
// on a scratch context, which is how the real context would take it.
bool openssl_has_group(uint16_t id, bool dtls) {
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

// Every group beyond OpenSSL's built-in DEFAULT list that the shim exposes when
// `uut { curves }` is absent (RFC 8734 brainpool for TLS 1.3, RFC 7027
// brainpool for TLS 1.2, the pure ML-KEM groups and the remaining hybrids),
// appended as a last tuple after DEFAULT. "?" keeps a name the build lacks
// from failing the parse.
const char* EXTRA_GROUPS_AFTER_DEFAULT =
   "DEFAULT/?brainpoolP256r1tls13:?brainpoolP384r1tls13:?brainpoolP512r1tls13:"
   "?brainpoolP256r1:?brainpoolP384r1:?brainpoolP512r1:"
   "?MLKEM512:?MLKEM768:?MLKEM1024:?SecP256r1MLKEM768:?SecP384r1MLKEM1024:?X448MLKEM1024";

// Map a 16-bit IANA SignatureScheme code (RFC 8446 4.2.3) to the OpenSSL name
// used by SSL_CTX_set1_sigalgs_list. Throws on an unmapped code.
const char* iana_sigalg_to_name(uint16_t id) {
   switch(id) {
      case 0x0201:
         return "RSA+SHA1";
      case 0x0203:
         return "ECDSA+SHA1";
      case 0x0401:
         return "rsa_pkcs1_sha256";
      case 0x0501:
         return "rsa_pkcs1_sha384";
      case 0x0601:
         return "rsa_pkcs1_sha512";
      case 0x0403:
         return "ecdsa_secp256r1_sha256";
      case 0x0503:
         return "ecdsa_secp384r1_sha384";
      case 0x0603:
         return "ecdsa_secp521r1_sha512";
      case 0x0804:
         return "rsa_pss_rsae_sha256";
      case 0x0805:
         return "rsa_pss_rsae_sha384";
      case 0x0806:
         return "rsa_pss_rsae_sha512";
      case 0x0807:
         return "ed25519";
      case 0x0808:
         return "ed448";
      case 0x0809:
         return "rsa_pss_pss_sha256";
      case 0x080A:
         return "rsa_pss_pss_sha384";
      case 0x080B:
         return "rsa_pss_pss_sha512";
      default:
         throw std::runtime_error("unsupported sigalg code 0x" + std::to_string(id));
   }
}

// Map a 16-bit protocol version code to OpenSSL's version constant.
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

// OpenSSL selects TLS 1.3 suites by name, so map the wire IDs we care about.
const char* tls13_suite_name(uint16_t id) {
   switch(id) {
      case 0x1301:
         return "TLS_AES_128_GCM_SHA256";
      case 0x1302:
         return "TLS_AES_256_GCM_SHA384";
      case 0x1303:
         return "TLS_CHACHA20_POLY1305_SHA256";
      case 0x1304:
         return "TLS_AES_128_CCM_SHA256";
      case 0x1305:
         return "TLS_AES_128_CCM_8_SHA256";
      default:
         return nullptr;
   }
}

// Map a 16-bit TLS 1.2 (and DTLS 1.2) cipher-suite ID to its OpenSSL cipher name
// (for SSL_CTX_set_cipher_list). Returns nullptr for unmapped IDs.
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

// OpenSSL's default security level (1) refuses the NULL-cipher suites (0-bit
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
// ticket issued by a previous one -- otherwise OpenSSL's per-process random key
// makes cross-process resumption impossible. Matches Botan's fixed-key shim.
int ticket_key_cb(SSL* /*s*/,
                  unsigned char key_name[16],
                  unsigned char iv[EVP_MAX_IV_LENGTH],
                  EVP_CIPHER_CTX* cctx,
                  EVP_MAC_CTX* hctx,
                  int enc) {
   static const unsigned char kn[16] = {'p', 'l', 'z', 'n', '-', 't', 'k', 't', '-', 'k', 'e', 'y', '0', '0', '0', '1'};
   static const unsigned char aes_key[32] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
   static const unsigned char hmac_key[32] = {
      0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
      0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0};

   char digest[] = "SHA256";
   OSSL_PARAM params[2] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_end(),
   };

   if(enc == 1) {
      if(RAND_bytes(iv, 16) <= 0) {
         return -1;
      }
      std::memcpy(key_name, kn, 16);
      if(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1) {
         return -1;
      }
      if(EVP_MAC_init(hctx, hmac_key, sizeof(hmac_key), params) != 1) {
         return -1;
      }
      return 1;
   } else {
      if(std::memcmp(key_name, kn, 16) != 0) {
         return 0;  // unknown key -> no resumption
      }
      if(EVP_DecryptInit_ex(cctx, EVP_aes_256_cbc(), nullptr, aes_key, iv) != 1) {
         return -1;
      }
      if(EVP_MAC_init(hctx, hmac_key, sizeof(hmac_key), params) != 1) {
         return -1;
      }
      return 1;
   }
}

// DTLS cookie callbacks for the HelloVerifyRequest exchange (RFC 6347 4.2.1):
// stateless HMAC cookies over the ClientHello random (see cookie_for), so a
// corrupted or stale cookie is rejected like Botan's. Enabling the exchange
// also makes OpenSSL send HelloVerifyRequest (parity with the Botan shim).
int dtls_cookie_generate(SSL* /*ssl*/, unsigned char* cookie, unsigned int* cookie_len) {
   const auto c = cookie_for(g_client_random.data());
   std::memcpy(cookie, c.data(), c.size());
   *cookie_len = static_cast<unsigned int>(c.size());
   return 1;
}

int dtls_cookie_verify(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len) {
   // OpenSSL has parsed this ClientHello by now, so its random is the one to
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
#ifdef SSL_set0_tlsext_status_ocsp_resp_ex
   // OpenSSL 3.6+ keeps the server's staples as a stack of parsed responses
   // (one per chain certificate, RFC 8446 4.4.2.1 multi-stapling); the legacy
   // single-buffer setter no longer marks the extension for sending.
   const unsigned char* p = g_ocsp_response.data();
   OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, static_cast<long>(g_ocsp_response.size()));
   if(resp == nullptr) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   STACK_OF(OCSP_RESPONSE)* sk = sk_OCSP_RESPONSE_new_null();
   if(sk == nullptr || sk_OCSP_RESPONSE_push(sk, resp) <= 0) {
      OCSP_RESPONSE_free(resp);
      sk_OCSP_RESPONSE_free(sk);
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   SSL_set0_tlsext_status_ocsp_resp_ex(ssl, sk);
#else
   // OpenSSL 3.5 and earlier use a single DER buffer, including for TLS 1.3.
   // The setter takes ownership, so it must not point into g_ocsp_response.
   if(g_ocsp_response.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   auto* response = static_cast<unsigned char*>(OPENSSL_memdup(g_ocsp_response.data(),
                                                             g_ocsp_response.size()));
   if(response == nullptr) {
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
   if(SSL_set_tlsext_status_ocsp_resp(ssl, response, static_cast<int>(g_ocsp_response.size())) != 1) {
      OPENSSL_free(response);
      return SSL_TLSEXT_ERR_ALERT_FATAL;
   }
#endif
   return SSL_TLSEXT_ERR_OK;
}


// -------------------------------------------------------------------------
// Certificate chains (see shims/DESIGN.md "Certificate chains")
//
// The shim serves `credentials.chains` as a server and presents
// `credentials.client_chains` as a client. An SSL_CTX keeps one certificate
// per key-type slot (RSA, RSA-PSS, ECDSA, Ed25519) and OpenSSL picks the slot
// from the peer's signature_algorithms on its own; two chains that share the
// ECDSA slot (P-256 + P-384) are chosen per connection from the ClientHello
// (server) or the CertificateRequest (client), and two chains in any other
// slot are refused (unsupported_config), since OpenSSL cannot hold them.
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
   if(k == nullptr) {
      return "";
   }
   std::string out;
   switch(EVP_PKEY_get_base_id(k)) {
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
         char name[80] = {0};
         size_t len = 0;
         if(EVP_PKEY_get_group_name(k, name, sizeof(name), &len) == 1) {
            const std::string g(name);
            if(g == "prime256v1" || g == "P-256") {
               out = "ecdsa_p256";
            } else if(g == "secp384r1" || g == "P-384") {
               out = "ecdsa_p384";
            } else if(g == "secp521r1" || g == "P-521") {
               out = "ecdsa_p521";
            } else {
               out = "ecdsa_" + g;
            }
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

// OpenSSL's certificate slot for a key type.
std::string slot_of(const std::string& key_type) {
   if(key_type.rfind("ecdsa", 0) == 0) {
      return "ec";
   }
   return key_type;
}

// Can a key of this type sign the SignatureScheme code point? Under TLS 1.3
// an ECDSA scheme names its curve; under TLS 1.2 any ECDSA hash goes with
// any curve (RFC 5246), and `strict` asks for the 1.3 pairing first.
bool scheme_fits(uint16_t code, const std::string& key_type, bool strict) {
   if(key_type == "rsa_2048") {
      switch(code) {
         case 0x0201:
         case 0x0301:
         case 0x0401:
         case 0x0501:
         case 0x0601:
         case 0x0804:
         case 0x0805:
         case 0x0806:
            return true;
         default:
            return false;
      }
   }
   if(key_type == "rsa_pss") {
      return code == 0x0809 || code == 0x080a || code == 0x080b;
   }
   if(key_type == "ed25519") {
      return code == 0x0807;
   }
   if(key_type.rfind("ecdsa", 0) == 0) {
      const bool ecdsa = code == 0x0203 || code == 0x0303 || code == 0x0403 || code == 0x0503 || code == 0x0603;
      if(!ecdsa) {
         return false;
      }
      if(!strict) {
         return true;
      }
      if(key_type == "ecdsa_p256") {
         return code == 0x0403;
      }
      if(key_type == "ecdsa_p384") {
         return code == 0x0503;
      }
      if(key_type == "ecdsa_p521") {
         return code == 0x0603;
      }
      return true;
   }
   return false;
}

bool certificate_group_fits(const ResolvedChain& chain, const std::vector<uint16_t>& groups, bool constrain) {
   if(!constrain || groups.empty()) {
      return true;
   }
   uint16_t required = 0;
   if(chain.key_type == "ecdsa_p256") {
      required = 0x0017;
   } else if(chain.key_type == "ecdsa_p384") {
      required = 0x0018;
   } else if(chain.key_type == "ecdsa_p521") {
      required = 0x0019;
   } else {
      // RFC 8422's curve-list constraint applies to ECDSA certificates, not
      // RSA or Ed25519 credentials.
      return true;
   }
   return std::find(groups.begin(), groups.end(), required) != groups.end();
}

const ResolvedChain* pick_chain(const std::vector<ResolvedChain>& chains,
                                const std::vector<uint16_t>& codes,
                                bool tls13,
                                const std::vector<uint16_t>& groups = {},
                                bool constrain_groups = false) {
   if(codes.empty()) {
      return chains.empty() ? nullptr : &chains.front();
   }
   // TLS 1.3's ECDSA schemes bind the certificate curve. The same wire code
   // points in TLS 1.2 name only ECDSA + hash, so preserve credential order
   // among all ECDSA curves rather than doing a curve-bound pass first.
   for(const bool strict : {tls13}) {
      for(const auto& c : chains) {
         if(!certificate_group_fits(c, groups, constrain_groups)) {
            continue;
         }
         for(const auto code : codes) {
            if(scheme_fits(code, c.key_type, strict)) {
               return &c;
            }
         }
      }
   }
   return nullptr;
}

// Several ECDSA server chains: chosen per connection from the ClientHello's
// signature_algorithms (the curve-bound TLS 1.3 code points first).
std::vector<ResolvedChain> g_ec_server_chains;
bool g_ec_server_constrain_groups = false;
bool g_ec_server_tls13 = false;
bool g_ec_server_has_other_key_type = false;

int ec_client_hello_cb(SSL* ssl, int* al, void* /*arg*/) {
   const unsigned char* data = nullptr;
   size_t len = 0;
   std::vector<uint16_t> codes;
   if(SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_signature_algorithms, &data, &len) == 1 && len >= 2) {
      const size_t n = (static_cast<size_t>(data[0]) << 8) | data[1];
      for(size_t i = 2; i + 1 < len && i < 2 + n; i += 2) {
         codes.push_back(static_cast<uint16_t>((data[i] << 8) | data[i + 1]));
      }
   }
   std::vector<uint16_t> groups;
   if(g_ec_server_constrain_groups &&
      SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_groups, &data, &len) == 1 && len >= 2) {
      const size_t n = (static_cast<size_t>(data[0]) << 8) | data[1];
      for(size_t i = 2; i + 1 < len && i < 2 + n; i += 2) {
         groups.push_back(static_cast<uint16_t>((data[i] << 8) | data[i + 1]));
      }
   }
   const ResolvedChain* pick =
      pick_chain(g_ec_server_chains, codes, g_ec_server_tls13, groups, g_ec_server_constrain_groups);
   if(pick == nullptr) {
      // This callback exists only to disambiguate several ECDSA chains.  If
      // none fits but another key-type slot is loaded, leave the per-key-type
      // choice to OpenSSL (for example an RSA-only signature-algorithm offer).
      // Returning an error here incorrectly hid an otherwise usable RSA slot.
      if(g_ec_server_has_other_key_type) {
         return SSL_CLIENT_HELLO_SUCCESS;
      }
      if(g_ec_server_constrain_groups && !groups.empty()) {
         *al = SSL_AD_HANDSHAKE_FAILURE;
         return SSL_CLIENT_HELLO_ERROR;
      }
      pick = &g_ec_server_chains.front();  // OpenSSL then fails the handshake on its own
   }
   if(SSL_use_certificate_chain_file(ssl, pick->chain.cert_file.c_str()) != 1 ||
      SSL_use_PrivateKey_file(ssl, pick->chain.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
      *al = SSL_AD_INTERNAL_ERROR;
      return SSL_CLIENT_HELLO_ERROR;
   }
   return SSL_CLIENT_HELLO_SUCCESS;
}

// Several client chains: chosen when the server's CertificateRequest arrives,
// by its signature_algorithms (SSL_get_sigalgs hands back the raw code
// points). Nothing acceptable -> return 0 and OpenSSL sends an empty
// Certificate (RFC 5246 7.4.6 / RFC 8446 4.4.2).
std::vector<ResolvedChain> g_client_chains;

int client_cert_cb(SSL* ssl, X509** x509, EVP_PKEY** pkey) {
   std::vector<uint16_t> codes;
   const int n = SSL_get_sigalgs(ssl, -1, nullptr, nullptr, nullptr, nullptr, nullptr);
   for(int i = 0; i < n; ++i) {
      unsigned char rsig = 0;
      unsigned char rhash = 0;
      if(SSL_get_sigalgs(ssl, i, nullptr, nullptr, nullptr, &rsig, &rhash) > 0) {
         codes.push_back(static_cast<uint16_t>((rhash << 8) | rsig));
      }
   }
   const bool tls13 = SSL_version(ssl) == TLS1_3_VERSION;
   const unsigned char* requested_types = nullptr;
   const long requested_types_len = SSL_get0_certificate_types(ssl, &requested_types);
   std::vector<ResolvedChain> eligible;
   for(const auto& chain : g_client_chains) {
      bool type_ok = requested_types_len <= 0 || tls13;
      for(long i = 0; !type_ok && i < requested_types_len; ++i) {
         const unsigned char cert_type = requested_types[i];
         type_ok = (cert_type == 1 && chain.key_type == "rsa_2048") ||
                   (cert_type == 64 &&
                    (chain.key_type.rfind("ecdsa", 0) == 0 || chain.key_type == "ed25519"));
      }
      if(type_ok) {
         eligible.push_back(chain);
      }
   }
   const ResolvedChain* pick = pick_chain(eligible, codes, tls13);
   if(pick == nullptr) {
      return 0;
   }
   FILE* f = std::fopen(pick->chain.cert_file.c_str(), "r");
   if(f == nullptr) {
      return 0;
   }
   X509* leaf = PEM_read_X509(f, nullptr, nullptr, nullptr);
   STACK_OF(X509)* extra = sk_X509_new_null();
   while(X509* c = PEM_read_X509(f, nullptr, nullptr, nullptr)) {
      sk_X509_push(extra, c);
   }
   ERR_clear_error();  // the end-of-file "no start line" is not an error
   std::fclose(f);
   FILE* kf = std::fopen(pick->chain.key_file.c_str(), "r");
   EVP_PKEY* key = kf ? PEM_read_PrivateKey(kf, nullptr, nullptr, nullptr) : nullptr;
   if(kf) {
      std::fclose(kf);
   }
   if(leaf == nullptr || key == nullptr) {
      X509_free(leaf);
      EVP_PKEY_free(key);
      sk_X509_pop_free(extra, X509_free);
      return 0;
   }
   if(sk_X509_num(extra) > 0) {
      SSL_set1_chain(ssl, extra);
   }
   sk_X509_pop_free(extra, X509_free);
   *x509 = leaf;
   *pkey = key;
   return 1;
}

// A configured RFC 7250 key is the shim's out-of-band trust assertion. Preserve
// normal X.509 verification outcomes, but accept the peer RPK itself without a
// PKIX chain (which, by definition, it cannot have).
int rpk_verify_cb(int preverify_ok, X509_STORE_CTX* store) {
   return X509_STORE_CTX_get0_rpk(store) != nullptr ? 1 : preverify_ok;
}

}  // namespace

void configure_ctx(SSL_CTX* ctx, const ShimConfig& cfg) {
   if(cfg.requests_dtls13()) {
      plzn::report_unsupported("versions", "OpenSSL does not currently implement DTLS 1.3");
   }
   if(cfg.record_size_limit.has_value()) {
      plzn::report_unsupported("record_size_limit", "OpenSSL exposes no RFC 8449 record_size_limit policy");
   }

   // A peer that closes the TCP connection without a close_notify is, since
   // OpenSSL 3.0, reported as a fatal SSL_ERROR_SSL (unexpected EOF). The runner
   // legitimately does that at end of flow, so treat it as a clean close;
   // genuine record failures (bad_record_mac, ...) still surface as errors.
   SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);

   if(cfg.max_cert_list.has_value()) {
      SSL_CTX_set_max_cert_list(ctx, *cfg.max_cert_list);
   }
   if(cfg.max_early_data.has_value()) {
      if(cfg.is_dtls()) {
         plzn::report_unsupported("max_early_data", "DTLS 1.2 has no TLS 1.3 early data");
      }
      SSL_CTX_set_max_early_data(ctx, *cfg.max_early_data);
   }

   // Policy knobs from the .plzn `uut { ... }` block. Values the library has no
   // switch for are refused here, before dialing, so the runner SKIPs the case.
   //
   // Session tickets: `uut { session_tickets }` sets the TLS 1.3 count; 0 also
   // turns off TLS 1.2 tickets and the session cache (no resumption at all).
   // Default: exactly one (Botan issues one; OpenSSL's second ticket otherwise
   // races the runner's close probe).
   if(cfg.session_tickets.has_value()) {
      SSL_CTX_set_num_tickets(ctx, *cfg.session_tickets);
      if(*cfg.session_tickets == 0) {
         SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
         SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
      }
   } else {
      SSL_CTX_set_num_tickets(ctx, 1);
   }

   // Renegotiation: an explicit `uut { renegotiation }` wins; otherwise the legacy
   // renegotiate_freely flag a `renegotiate` step sets. OpenSSL 3.0+ denies
   // client-initiated renegotiation on the server by default.
   if(cfg.renegotiation.has_value()) {
      const std::string& r = *cfg.renegotiation;
      if(r != "none" && r != "client" && r != "server" && r != "both") {
         plzn::report_result(plzn::ShimResult::LocalError, "invalid renegotiation value: " + r);
      }
      if(r == "none") {
         SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_NO_RENEGOTIATION);
#ifdef SSL_OP_ALLOW_CLIENT_RENEGOTIATION
         if(r == "client" || r == "both") {
            SSL_CTX_set_options(ctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
         }
#endif
      }
   } else if(cfg.renegotiate_freely) {
#ifdef SSL_OP_ALLOW_CLIENT_RENEGOTIATION
      SSL_CTX_set_options(ctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
#endif
   }

   // Server preference covers both cipher suites and groups in OpenSSL.
   if(cfg.server_preference.has_value()) {
      if(*cfg.server_preference) {
         SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
      }
   }

   if(cfg.records_per_traffic_key.has_value()) {
      plzn::report_unsupported("records_per_traffic_key",
                               "OpenSSL has no automatic KeyUpdate policy (SSL_key_update is manual)");
   }
   if(cfg.key_update) {
      plzn::report_unsupported("key_update",
                               "manual post-handshake KeyUpdate initiation is not wired in the OpenSSL shim");
   }
   // OpenSSL never rate-limits received KeyUpdates: 0 ("no limit") is its
   // behaviour, any other interval is a knob it lacks.
   if(cfg.min_key_update_interval_ms.has_value() && *cfg.min_key_update_interval_ms != 0) {
      plzn::report_unsupported("min_key_update_interval_ms",
                               "OpenSSL has no KeyUpdate rate limit (only 0 = no limit is honoured)");
   }
   if(!cfg.half_rtt_data.empty()) {
      plzn::report_unsupported("half_rtt_data", "the OpenSSL shim does not write half-RTT application data");
   }
   if(cfg.extended_master_secret.has_value()) {
      const std::string& e = *cfg.extended_master_secret;
      if(e == "off") {
         SSL_CTX_set_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
      } else if(e == "allow") {
         SSL_CTX_clear_options(ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET);
      } else if(e == "require") {
         plzn::report_unsupported("extended_master_secret",
                                  "OpenSSL has no option to require extended_master_secret; only allow/off");
      } else {
         plzn::report_result(plzn::ShimResult::LocalError, "invalid extended_master_secret value: " + e);
      }
   }

   if(cfg.encrypt_then_mac.has_value()) {
      if(*cfg.encrypt_then_mac) {
         SSL_CTX_clear_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
      } else {
         SSL_CTX_set_options(ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
      }
   }

   if(cfg.middlebox_compat.has_value()) {
      if(*cfg.middlebox_compat) {
         SSL_CTX_set_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
      } else {
         SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
      }
   }

   // DTLS policy knobs OpenSSL cannot honour: an established SSL object has no
   // epoch-0 restart, and a client answers HelloVerifyRequests without bound.
   // Refusing them SKIPs the case instead of passing it vacuously. (The
   // retransmit timer knobs and the runner's virtual clock are honoured via
   // DTLS_set_timer_cb and the shim's frozen gettimeofday, see g_clock.)
   if(cfg.is_dtls()) {
      if(cfg.mtu < 1500) {
         // SSL_set_mtu refuses anything under its link minimum less the record
         // overhead; probe it so the case SKIPs with the reason.
         SSL* probe = SSL_new(ctx);
         const bool ok = probe != nullptr && SSL_set_mtu(probe, cfg.mtu) != 0;
         SSL_free(probe);
         if(!ok) {
            report_unsupported("mtu", "below OpenSSL's minimum DTLS MTU (SSL_set_mtu refused " + std::to_string(cfg.mtu) + ")");
         }
      }
      if(cfg.dtls_epoch0_restart.has_value()) {
         report_unsupported("dtls_epoch0_restart", "OpenSSL has no epoch-0 restart on an established SSL object");
      }
      if(cfg.dtls_max_hello_verify_requests.has_value()) {
         report_unsupported("dtls_max_hello_verify_requests", "OpenSSL does not bound the HelloVerifyRequests a client answers");
      }
   }
   // DTLS server: perform the HelloVerifyRequest cookie exchange (RFC 6347 4.2.1)
   // during SSL_accept, matching the Botan shim. This makes the second ClientHello
   // (CH2) exist, which the reorder/retransmit tests fragment and reorder.
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

   // Certificate chains: see the helpers above. One chain per key-type slot
   // goes into the CTX (OpenSSL selects among slots by the peer's
   // signature_algorithms); several ECDSA chains are chosen per connection;
   // several chains in any other slot cannot be held and are refused.
   {
      const auto chains =
         resolve_chains(cfg.is_server() ? cfg.credentials.chains : cfg.credentials.client_chains);
      std::vector<std::string> slots;
      std::map<std::string, std::vector<ResolvedChain>> by_slot;
      for(const auto& c : chains) {
         const std::string slot = slot_of(c.key_type);
         if(by_slot.find(slot) == by_slot.end()) {
            slots.push_back(slot);
         }
         by_slot[slot].push_back(c);
      }
      for(const auto& slot : slots) {
         if(by_slot[slot].size() > 1 && slot != "ec") {
            plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                                "chains: OpenSSL holds one " + slot +
                                   " chain per context, so several " + slot + " chains cannot be served");
         }
      }
      auto load_into_ctx = [&](const ResolvedChain& c) {
         if(SSL_CTX_use_certificate_chain_file(ctx, c.chain.cert_file.c_str()) != 1) {
            throw std::runtime_error("failed to load cert " + c.chain.cert_file + ": " + openssl_errors());
         }
         if(!c.chain.key_file.empty() &&
            SSL_CTX_use_PrivateKey_file(ctx, c.chain.key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            throw std::runtime_error("failed to load key " + c.chain.key_file + ": " + openssl_errors());
         }
      };
      if(cfg.is_server() || chains.size() <= 1) {
         for(const auto& slot : slots) {
            load_into_ctx(by_slot[slot].front());  // the fallback for a multi-ECDSA slot too
         }
         if(cfg.is_server() && by_slot.count("ec") != 0 && by_slot["ec"].size() > 1) {
            g_ec_server_chains = by_slot["ec"];
            g_ec_server_has_other_key_type = by_slot.size() > 1;
            // TLS 1.2's supported_groups constrains both ECDHE and the curve
            // in an ECDSA certificate. TLS 1.3 deliberately removed the
            // latter meaning (RFC 8446 4.2.7).
            g_ec_server_constrain_groups = cfg.is_dtls()
                                                  ? !cfg.requests_dtls13()
                                                  : cfg.max_version.value_or(0x0304) <= 0x0303;
            g_ec_server_tls13 = cfg.is_dtls()
                                   ? cfg.requests_dtls13()
                                   : cfg.min_version.value_or(0x0303) >= 0x0304;
            SSL_CTX_set_client_hello_cb(ctx, ec_client_hello_cb, nullptr);
         }
      } else {
         // Client with several credentials: nothing in the CTX, the
         // CertificateRequest decides.
         g_client_chains = chains;
         SSL_CTX_set_client_cert_cb(ctx, client_cert_cb);
      }
   }
   // RFC 7250: present our public key as a bare SubjectPublicKeyInfo when the peer negotiates
   // {server,client}_certificate_type=RawPublicKey. OpenSSL derives the raw key from the loaded
   // certificate/key; setting our cert type to RPK makes it selectable. Server role sets the
   // server cert type; client role sets the client cert type (offer + present a raw key).
   // OpenSSL sends any configured list, but RFC 7250 4.1 requires a client to omit an
   // extension whose only type is the default X.509, so a client leaves such a list unset.
   const auto offers_list = [&](const std::vector<uint8_t>& types) {
      return !types.empty() &&
             (cfg.is_server() ||
              std::any_of(types.begin(), types.end(), [](uint8_t t) { return t != 0; }));
   };
   if(offers_list(cfg.server_certificate_types) &&
      SSL_CTX_set1_server_cert_type(ctx,
                                    cfg.server_certificate_types.data(),
                                    cfg.server_certificate_types.size()) != 1) {
      throw std::runtime_error("failed to configure server certificate types: " + openssl_errors());
   }
   if(offers_list(cfg.client_certificate_types) &&
      SSL_CTX_set1_client_cert_type(ctx,
                                    cfg.client_certificate_types.data(),
                                    cfg.client_certificate_types.size()) != 1) {
      throw std::runtime_error("failed to configure client certificate types: " + openssl_errors());
   }
   // RFC 8879: pre-compress the server certificate with zlib so it is sent as a
   // CompressedCertificate when the client advertises compress_certificate.
   if(cfg.compress_certificate && cfg.is_server()) {
      if(SSL_CTX_compress_certs(ctx, TLSEXT_comp_cert_zlib) != 1) {
         throw std::runtime_error("failed to compress certs: " + openssl_errors());
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

   // NULL-cipher and CCM_8 suites need security level 0. An explicit UUT list
   // must enable every suite it names. `requires_any_suite`, however, is a
   // union: one supported alternative is enough, so a weak member must not
   // lower the policy when a normal alternative is also available. Otherwise
   // an unconstrained DHE peer silently disables OpenSSL's small-DH check.
   {
      const bool configured_weak =
         std::any_of(cfg.cipher_suites.begin(), cfg.cipher_suites.end(), needs_security_level_zero);
      const bool requires_only_weak =
         !cfg.requires_any_suite.empty() &&
         std::all_of(cfg.requires_any_suite.begin(), cfg.requires_any_suite.end(), needs_security_level_zero);
      const auto requests_sha1_signature = [](const std::vector<uint16_t>& prefs) {
         return std::any_of(prefs.begin(), prefs.end(), [](uint16_t id) {
            return id == 0x0201 || id == 0x0203;
         });
      };
      const bool requests_obsolete_tls = !cfg.is_dtls() &&
         (cfg.min_version.value_or(0x0303) < 0x0303 ||
          cfg.max_version.value_or(0x0304) < 0x0303);
      if(configured_weak || requires_only_weak || requests_obsolete_tls ||
         requests_sha1_signature(cfg.signing_prefs) ||
         requests_sha1_signature(cfg.verify_prefs)) {
         SSL_CTX_set_security_level(ctx, 0);
      }
   }

   if(cfg.cipher_suites.empty()) {
      // Expose everything this OpenSSL build implements (project principle: the
      // shim presents the library's capability, not its default posture).
      // Client preference decides, as with OpenSSL's default list, so peers
      // offering the usual suites still get the usual choice.
      if(SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL") != 1) {
         throw std::runtime_error("failed to set the permissive cipher list: " + openssl_errors());
      }
      if(SSL_CTX_set_ciphersuites(ctx,
                                  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
                                  "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256") != 1) {
         throw std::runtime_error("failed to set the TLS 1.3 ciphersuites: " + openssl_errors());
      }
   } else {
      // TLS 1.3 suites are pinned by name via SSL_CTX_set_ciphersuites; TLS 1.2 /
      // DTLS 1.2 suites are pinned by name via SSL_CTX_set_cipher_list. Mapping the
      // TLS 1.2 IDs (rather than leaving the default list) lets cipher-negotiation
      // tests actually restrict what the server accepts.
      std::string tls13_list;
      std::string tls12_list;
      std::string unmapped;
      for(const uint16_t id : cfg.cipher_suites) {
         if(const char* name = tls13_suite_name(id)) {
            if(!tls13_list.empty()) {
               tls13_list += ":";
            }
            tls13_list += name;
         } else if(const char* n12 = tls12_cipher_name(id)) {
            if(!tls12_list.empty()) {
               tls12_list += ":";
            }
            tls12_list += n12;
         } else {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%s0x%04x", unmapped.empty() ? "" : ", ", id);
            unmapped += buf;
         }
      }
      if(tls13_list.empty() && tls12_list.empty()) {
         plzn::report_unsupported("cipher_suites", "OpenSSL has no TLS suite for [" + unmapped + "]");
      }
      if(!tls13_list.empty()) {
         if(SSL_CTX_set_ciphersuites(ctx, tls13_list.c_str()) != 1) {
            throw std::runtime_error("failed to set TLS 1.3 ciphersuites: " + openssl_errors());
         }
      }
      if(!tls12_list.empty()) {
         if(SSL_CTX_set_cipher_list(ctx, tls12_list.c_str()) != 1) {
            // A name OpenSSL knows but this build lacks (e.g. 3DES without
            // enable-weak-ssl-ciphers) is a capability gap, not a config error.
            plzn::report_unsupported("cipher_suites",
                                     "this OpenSSL build cannot enable [" + tls12_list + "]: " + openssl_errors());
         }
      }
   }

   // What plzn will offer: refuse the case when this build has none of the
   // suites it needs, so the runner SKIPs it with the reason. The context's
   // cipher list is what the library would actually negotiate from.
   if(!cfg.requires_any_suite.empty()) {
      // A scratch context with every suite this build has, so a `uut`
      // restriction on the real context does not masquerade as a gap.
      SSL_CTX* probe = SSL_CTX_new(cfg.is_dtls() ? DTLS_method() : TLS_method());
      bool any = false;
      std::string list;
      if(probe != nullptr) {
         SSL_CTX_set_security_level(probe, 0);
         SSL_CTX_set_cipher_list(probe, "ALL:COMPLEMENTOFALL");
         SSL_CTX_set_ciphersuites(probe,
                                  "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
                                  "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256");
         STACK_OF(SSL_CIPHER)* have = SSL_CTX_get_ciphers(probe);
         for(const uint16_t id : cfg.requires_any_suite) {
            for(int i = 0; have != nullptr && i < sk_SSL_CIPHER_num(have); ++i) {
               if(SSL_CIPHER_get_protocol_id(sk_SSL_CIPHER_value(have, i)) == id) {
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
      if(!any) {
         plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                             "peer.capabilities: this OpenSSL build implements none of the offered cipher suites [" + list + "]");
      }
   }

   // Likewise the groups: a `uut { curves }` entry this build lacks, or an
   // offer with no implemented group at all, is a capability gap -> SKIP.
   for(const uint16_t id : cfg.curves) {
      if(!openssl_has_group(id, cfg.is_dtls())) {
         char buf[16];
         std::snprintf(buf, sizeof(buf), "0x%04x", id);
         plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                             std::string("uut.curves: this OpenSSL build has no group ") + buf);
      }
   }
   if(!cfg.requires_any_group.empty()) {
      bool any = false;
      std::string list;
      for(const uint16_t id : cfg.requires_any_group) {
         any = any || openssl_has_group(id, cfg.is_dtls());
         char buf[16];
         std::snprintf(buf, sizeof(buf), "%s0x%04x", list.empty() ? "" : ", ", id);
         list += buf;
      }
      if(!any) {
         plzn::report_result(plzn::ShimResult::UnsupportedConfig,
                             "peer.capabilities: this OpenSSL build implements none of the offered key exchange groups [" + list + "]");
      }
   }

   if(!cfg.curves.empty()) {
      // Map each configured IANA code to its OpenSSL group name. An unmapped
      // code is a config error (fail loudly rather than silently leaving the
      // default groups, which would let a "no common curve" negotiation-failure
      // test pass). The plain colon list keeps the legacy semantics: the first
      // group is the client's sole predicted key share.
      std::string list;
      for(const uint16_t id : cfg.curves) {
         const char* name = iana_group_to_name(id);
         if(name[0] == '\0') {
            throw std::runtime_error("unsupported group code 0x" + std::to_string(id));
         }
         list += (list.empty() ? "" : ":");
         list += name;
      }
      if(SSL_CTX_set1_groups_list(ctx, list.c_str()) != 1) {
         throw std::runtime_error("failed to set supported groups: " + openssl_errors());
      }
   } else {
      // Expose every group the build has: OpenSSL's DEFAULT (with its key-share
      // predictions intact) plus the brainpool, pure ML-KEM and remaining
      // hybrid groups it leaves out, as a final tuple.
      if(SSL_CTX_set1_groups_list(ctx, EXTRA_GROUPS_AFTER_DEFAULT) != 1) {
         throw std::runtime_error("failed to set the default group list: " + openssl_errors());
      }
   }

   if(!cfg.signing_prefs.empty()) {
      // The signature algorithms this endpoint will sign with. Build the
      // colon-separated name list SSL_CTX_set1_sigalgs_list expects. Without this
      // the shim silently ignored `signing_prefs` and left OpenSSL's defaults,
      // which would let a "no common sigalg" negotiation-failure test pass.
      std::string list;
      for(const uint16_t id : cfg.signing_prefs) {
         if(!list.empty()) {
            list += ":";
         }
         list += iana_sigalg_to_name(id);
      }
      if(SSL_CTX_set1_sigalgs_list(ctx, list.c_str()) != 1) {
         throw std::runtime_error("failed to set signature algorithms: " + openssl_errors());
      }
   }

   if(!cfg.verify_prefs.empty()) {
      // The signature algorithms this endpoint ACCEPTS from its peer. For a
      // client that is the signature_algorithms extension itself
      // (SSL_CTX_set1_sigalgs_list); for a server it is the CertificateRequest's
      // list (SSL_CTX_set1_client_sigalgs_list). A client's signing_prefs share
      // the former single list, so the two can be pinned together on a client
      // only when they agree; when they name different lists OpenSSL has no way
      // to represent both, so the case SKIPs.
      if(!cfg.is_server() && !cfg.signing_prefs.empty() && cfg.signing_prefs != cfg.verify_prefs) {
         plzn::report_unsupported(
            "verify_prefs",
            "OpenSSL keeps a client's signing and verify preferences in one list; they can be pinned together "
            "only when equal");
      }
      std::string list;
      for(const uint16_t id : cfg.verify_prefs) {
         if(!list.empty()) {
            list += ":";
         }
         list += iana_sigalg_to_name(id);
      }
      const int rc = cfg.is_server() ? SSL_CTX_set1_client_sigalgs_list(ctx, list.c_str())
                                     : SSL_CTX_set1_sigalgs_list(ctx, list.c_str());
      if(rc != 1) {
         throw std::runtime_error("failed to set accepted signature algorithms: " + openssl_errors());
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
   const auto& accepted_peer_types =
      cfg.is_server() ? cfg.client_certificate_types : cfg.server_certificate_types;
   const bool accepts_rpk =
      std::find(accepted_peer_types.begin(), accepted_peer_types.end(), 2) !=
      accepted_peer_types.end();
   SSL_CTX_set_verify(ctx, verify_mode, accepts_rpk ? rpk_verify_cb : nullptr);
   if(cfg.is_server()) {
      // OpenSSL refuses to resume (or accept an external PSK) on a server that
      // verifies client certificates unless a session id context is set.
      static const unsigned char sid_ctx[] = "plzn";
      SSL_CTX_set_session_id_context(ctx, sid_ctx, sizeof(sid_ctx) - 1);
   }

   if(!cfg.srtp_profiles.empty()) {
      std::string profiles;
      for(const uint16_t id : cfg.srtp_profiles) {
         const char* name = nullptr;
         switch(id) {
            case 0x0001: name = "SRTP_AES128_CM_SHA1_80"; break;
            case 0x0002: name = "SRTP_AES128_CM_SHA1_32"; break;
            case 0x0005: name = "SRTP_NULL_SHA1_80"; break;
            case 0x0006: name = "SRTP_NULL_SHA1_32"; break;
            case 0x0007: name = "SRTP_AEAD_AES_128_GCM"; break;
            case 0x0008: name = "SRTP_AEAD_AES_256_GCM"; break;
            default:
               plzn::report_unsupported("srtp_profiles", "OpenSSL cannot configure an unknown SRTP profile id");
         }
         if(!profiles.empty()) {
            profiles += ':';
         }
         profiles += name;
      }
      if(SSL_CTX_set_tlsext_use_srtp(ctx, profiles.c_str()) != 0) {
         throw std::runtime_error("failed to set SRTP profiles: " + openssl_errors());
      }
   }

   if(cfg.is_server()) {
      SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, const_cast<ShimConfig*>(&cfg));
      // Enable automatic FFDHE parameters so DHE_RSA suites can be negotiated.
      SSL_CTX_set_dh_auto(ctx, 1);
      // Fixed ticket key for deterministic cross-process resumption.
      SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx, ticket_key_cb);
   }

   if(cfg.psk.present) {
      g_psk = hex_decode(cfg.psk.secret_hex);
      g_psk_identity = cfg.psk.identity;
      if(cfg.is_server()) {
         SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);       // TLS 1.2 / DTLS
         SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);  // TLS 1.3
      } else {
         SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
      }
      // Enable the PSK ciphersuites when the test did not provide an exact
      // list. An explicit cipher_suites list was already installed above and
      // must not be replaced by this broad fallback.
      SSL_CTX_set_security_level(ctx, 0);
      if(cfg.cipher_suites.empty() &&
         SSL_CTX_set_cipher_list(ctx, "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK") != 1) {
         throw std::runtime_error("failed to set PSK cipher list: " + openssl_errors());
      }
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
      const uint16_t id = c != nullptr ? static_cast<uint16_t>(SSL_CIPHER_get_protocol_id(c)) : 0;
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

// ---- Custom datagram BIO bridging OpenSSL DTLS to the shim's P/T/C framing ----
//
// OpenSSL DTLS needs a datagram BIO. This one carries each datagram over the
// runner control connection using the shim P/T/C protocol (ShimSocket). A 'T'
// frame advances the frozen clock (g_clock) and makes the read return
// "retry" so OpenSSL re-checks its retransmit timer against the new time
// (dtls1_read_failed -> dtls1_handle_timeout); a 'C' frame is applied in
// place. When the retransmission budget is spent, writes are swallowed and the
// read reports end-of-connection.

bool dtls_trace() {
   static const bool on = ::getenv("PLZN_DTLS_TRACE") != nullptr;
   return on;
}

int dgram_bwrite(BIO* b, const char* data, int len) {
   auto* s = static_cast<ShimSocket*>(BIO_get_data(b));
   BIO_clear_retry_flags(b);
   if(dtls_trace()) {
      std::cerr << "[openssl-bio] bwrite " << len << (g_timer.exhausted ? " (dropped: budget spent)" : "") << std::endl;
   }
   if(g_timer.exhausted) {
      return len;
   }
   s->write_dtls_packet(reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len));
   return len;
}

int dgram_bread(BIO* b, char* data, int len) {
   auto* s = static_cast<ShimSocket*>(BIO_get_data(b));
   BIO_clear_retry_flags(b);
   if(g_timer.exhausted) {
      if(dtls_trace()) {
         std::cerr << "[openssl-bio] bread: retransmission budget spent, reporting EOF" << std::endl;
      }
      return 0;
   }
   for(;;) {
      DtlsEvent ev = s->read_dtls_event();
      if(ev.opcode == DtlsOpcode::Eof) {
         if(dtls_trace()) {
            std::cerr << "[openssl-bio] bread EOF" << std::endl;
         }
         return 0;
      }
      if(ev.opcode == DtlsOpcode::AdvanceClock) {
         if(dtls_trace()) {
            std::cerr << "[openssl-bio] defer clock +" << ev.nanos << "ns" << std::endl;
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
               std::cerr << "[openssl-bio] cookie secret rotated (generation " << g_cookie_generation << ")"
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
         std::cerr << "[openssl-bio] bread " << n << " (datagram " << ev.packet.size() << ")" << std::endl;
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

uint64_t semantic_timeout_remaining_ns() {
   const uint64_t elapsed_ns = g_clock.advanced_ns - g_timer.armed_at_logical_ns;
   const uint64_t duration_ns = g_timer.duration_ms * 1'000'000;
   return elapsed_ns >= duration_ns ? 0 : duration_ns - elapsed_ns;
}

uint64_t semantic_timeout_reported_ns() {
   const uint64_t remaining_ns = semantic_timeout_remaining_ns();
   const uint64_t fudge_ns = std::min<uint64_t>(15, g_timer.initial_ms / 2) * 1'000'000;
   return remaining_ns <= fudge_ns ? 0 : remaining_ns;
}

// Position OpenSSL's physical clock so its existing absolute deadline has the
// semantic remaining duration. A logically-expired timer is kept one
// microsecond outside OpenSSL's 15 ms early-fire window when `defer_expired`:
// this lets `expect next_timeout 0` run before `advance_clock 0` handles it.
void synchronize_dtls_clock(bool defer_expired) {
   const uint64_t remaining_ns = semantic_timeout_remaining_ns();
   const uint64_t reported_ns = semantic_timeout_reported_ns();
   uint64_t physical_remaining_ns = 0;
   if(reported_ns == 0) {
      physical_remaining_ns = defer_expired ? 15'001'000 : 15'000'000;
   } else {
      physical_remaining_ns = remaining_ns + dtls_timer_slack_ms() * 1'000'000;
   }
   const int64_t target_clock_ns =
      g_timer.deadline_clock_ns - static_cast<int64_t>(physical_remaining_ns);
   g_clock.adjustment_ns = target_clock_ns - static_cast<int64_t>(g_clock.advanced_ns);
}

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

   const uint64_t actual_ns = semantic_timeout_reported_ns();
   if(actual_ns != expected_ns) {
      throw std::runtime_error("DTLS next timeout mismatch: expected " + std::to_string(expected_ns) +
                               "ns, got " + std::to_string(actual_ns) + "ns");
   }
   socket.write_dtls_ack('e');
}

void update_dtls_timeout(SSL* ssl, ShimSocket& socket, uint32_t initial_ms) {
   timeval timeout{};
   const bool timer_is_armed = DTLSv1_get_timeout(ssl, &timeout) == 1;

   g_timer.initial_ms = initial_ms;
   uint64_t duration = initial_ms;
   for(uint32_t i = 0; i < g_timer.timeouts && duration < g_timer.max_ms; ++i) {
      duration = std::min<uint64_t>(duration * 2, g_timer.max_ms);
   }
   g_timer.duration_ms = duration;

   if(timer_is_armed) {
      synchronize_dtls_clock(true);
   }
   socket.write_dtls_ack('u');
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
         update_dtls_timeout(ssl, socket, static_cast<uint32_t>(op.value));
         return;
      case DtlsInterruptKind::AdvanceClock:
         g_clock.advanced_ns += op.value;
         if(dtls_trace()) {
            std::cerr << "[openssl-bio] clock +" << op.value << "ns (virtual " << g_clock.advanced_ns / 1'000'000
                      << " ms)" << std::endl;
         }
         break;
   }

   timeval timeout{};
   if(DTLSv1_get_timeout(ssl, &timeout) == 1) {
      synchronize_dtls_clock(false);
   }
   const int ret = DTLSv1_handle_timeout(ssl);
   if(g_timer.exhausted || (ret < 0 && SSL_get_error(ssl, ret) != SSL_ERROR_WANT_WRITE)) {
      socket.write_dtls_timeout_expired();
      g_flow_failed = true;
      throw ProtocolFailure("DTLS retransmission timeout expired");
   }
   socket.write_dtls_ack('t');
}

// Application bytes received so far on this connection (the trigger for
// `renegotiate_after_handshake`).
size_t g_app_bytes_received = 0;

void run_connection(const ShimConfig& cfg, SSL_CTX* ctx, uint32_t connection_index) {
   g_app_bytes_received = 0;
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
         // OpenSSL rejects a certificate whose SAN/CN does not match.
         if(cfg.verify.verify_peer) {
            SSL_set1_host(ssl, cfg.server_name.c_str());
         }
      }
      if(!cfg.alpn.advertise.empty()) {
         const auto wire = alpn_wire(cfg.alpn.advertise);
         SSL_set_alpn_protos(ssl, wire.data(), static_cast<unsigned int>(wire.size()));
      }
      if(g_client_session != nullptr) {
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
      // The retransmit timer runs on the frozen clock with the configured
      // schedule (see g_clock / g_timer).
      g_clock.base_us = real_now_us();
      g_clock.advanced_ns = 0;
      g_clock.adjustment_ns = 0;
      g_clock.frozen = true;
      g_dtls_interrupt = {};
      g_timer = DtlsTimer{};
      g_timer.initial_ms = cfg.initial_timeout_ms;
      g_timer.max_ms = cfg.dtls_max_timeout_ms.value_or(60000);
      g_timer.max_retransmissions = cfg.dtls_max_retransmissions;
      DTLS_set_timer_cb(ssl, dtls_timer_cb);
      g_cookie_generation = 0;
      g_client_random_seq = -1;
      g_client_random_seen.fill(false);
   } else {
      SSL_set_fd(ssl, socket.fd());
   }

   // 0-RTT is meaningful only on a resumed connection. SSL_write_early_data
   // emits ClientHello + application_data before SSL_connect; the server-side
   // read API consumes those records before SSL_accept completes the handshake.
   if(connection_index > 0 && !cfg.is_dtls() && !cfg.is_server() && cfg.early_data_send > 0) {
      std::vector<uint8_t> early(cfg.early_data_send, 0x45);
      size_t offset = 0;
      while(offset < early.size()) {
         size_t written = 0;
         if(SSL_write_early_data(ssl, early.data() + offset, early.size() - offset, &written) != 1) {
            SSL_free(ssl);
            g_flow_failed = true;
            throw ProtocolFailure("SSL_write_early_data failed: " + openssl_errors());
         }
         offset += written;
      }
   }

   if(connection_index > 0 && !cfg.is_dtls() && cfg.is_server() && cfg.early_data_expect > 0) {
      std::vector<uint8_t> buf(16 * 1024);
      size_t total = 0;
      for(;;) {
         size_t n = 0;
         const int status = SSL_read_early_data(ssl, buf.data(), buf.size(), &n);
         total += n;
         if(status == SSL_READ_EARLY_DATA_SUCCESS) {
            continue;
         }
         if(status == SSL_READ_EARLY_DATA_FINISH) {
            break;
         }
         SSL_free(ssl);
         g_flow_failed = true;
         throw ProtocolFailure("SSL_read_early_data failed: " + openssl_errors());
      }
      const size_t expected_total = cfg.expect_early_data_accepted == false ? 0 : cfg.early_data_expect;
      if(total != expected_total) {
         SSL_free(ssl);
         g_flow_failed = true;
         throw std::runtime_error("early data length mismatch: got " + std::to_string(total) +
                                  " expected " + std::to_string(expected_total));
      }
   }

   // DTLS over a custom (non-socket) BIO drives the handshake as a state
   // machine that yields WANT_READ/WANT_WRITE between flights, so loop rather
   // than calling accept/connect once. Each retry re-enters the BIO, whose read
   // blocks until the next datagram arrives.
   for(;;) {
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
      if(g_timer.exhausted) {
         throw ProtocolFailure("handshake failed: DTLS retransmission budget (" +
                                  std::to_string(*g_timer.max_retransmissions) + ") spent without an answer");
      }
      throw ProtocolFailure("handshake failed: ret=" + std::to_string(hs) + " sslerr=" +
                               std::to_string(sslerr) + " " + err);
   }

   check_expectations(ssl, cfg);
   if(connection_index > 0 && !cfg.is_dtls() && cfg.expect_early_data_accepted.has_value()) {
      const bool accepted = SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED;
      if(accepted != *cfg.expect_early_data_accepted) {
         note_failure(std::string("TLS 1.3 early data was ") +
                      (accepted ? "accepted" : "rejected") + " unexpectedly");
      }
   }

   // T6: `uut { post_handshake_auth }` (RFC 8446 4.6.2): request the client's
   // certificate now that the handshake is done -- the client must have
   // offered post_handshake_auth -- and write the CertificateRequest at once;
   // the SSL_read loop below drives the client's reply. `require_client_cert`
   // makes an empty Certificate fatal (certificate_required).
   if(cfg.is_server() && !cfg.post_handshake_auth.empty()) {
      int mode = SSL_VERIFY_PEER;
      if(cfg.post_handshake_auth == "require") {
         mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
      }
      SSL_set_verify(ssl, mode, nullptr);
      if(SSL_verify_client_post_handshake(ssl) != 1) {
         g_flow_failed = true;
         note_failure("post_handshake_auth: SSL_verify_client_post_handshake failed: " + openssl_errors());
      } else {
         const int r = SSL_do_handshake(ssl);
         if(r != 1) {
            const int e = SSL_get_error(ssl, r);
            if(e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
               g_flow_failed = true;
               note_failure("post_handshake_auth: writing the CertificateRequest failed: " + openssl_errors());
            }
         }
      }
   }

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
         const bool available = !(SSL_session_reused(ssl) == 1 && SSL_get_extms_support(ssl) != 1);
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
         // OpenSSL refuses to renegotiate a TLS 1.3 connection).
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
         const int n = SSL_read(ssl, buf.data(), static_cast<int>(buf.size()));
         if(n <= 0) {
            const int err = SSL_get_error(ssl, n);
            if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
               if(cfg.is_dtls() && g_dtls_interrupt.kind != DtlsInterruptKind::None) {
                  handle_dtls_interrupt(ssl, socket);
               }
               continue;  // DTLS: the virtual clock moved; nothing arrived yet
            }
            if(err == SSL_ERROR_ZERO_RETURN) {
               // Clean close_notify from the peer: answer it (bidirectional
               // shutdown). OpenSSL marks a session it never sent close_notify
               // on as non-resumable (the TLS 1.2 rule, applied to 1.3 too), so
               // without this reply a client would never resume on its next
               // connection. The peer may already have closed the socket; a
               // failed write here is harmless.
               SSL_shutdown(ssl);
               break;
            }
            if(err == SSL_ERROR_SSL) {
               g_flow_failed = true;  // fatal protocol error (bad_record_mac, ...)
               if(g_record_error.empty()) {
                  g_record_error = "read: " + openssl_errors();
               }
               if(renegotiated) {
                  note_failure("renegotiate_after_handshake: renegotiation handshake failed: " + openssl_errors());
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

// The process-wide clock OpenSSL's DTLS timer reads (see VirtualClock). glibc
// declares gettimeofday with a throw() specification, so the definition must
// be noexcept to match.
extern "C" int gettimeofday(struct timeval* tv, void* /*tz*/) noexcept {
   const int64_t virtual_ns = static_cast<int64_t>(g_clock.advanced_ns) + g_clock.adjustment_ns;
   const int64_t us = g_clock.frozen ? g_clock.base_us + virtual_ns / 1000 : real_now_us();
   tv->tv_sec = static_cast<time_t>(us / 1000000);
   tv->tv_usec = static_cast<suseconds_t>(us % 1000000);
   return 0;
}

int main(int argc, char* argv[]) {
   plzn::exit_when_orphaned();
   // OpenSSL writes to the socket fd directly (no MSG_NOSIGNAL): a close_notify
   // sent after the runner already closed its end must not kill the process.
   std::signal(SIGPIPE, SIG_IGN);
   std::string config_path;
   for(int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      if(a == "--plzn-shim-info") {
         std::cout << R"({"protocol":"plzn-shim","protocol_version":1,"name":"openssl"})" << std::endl;
         return 0;
      } else if(a == "-config" && i + 1 < argc) {
         config_path = argv[++i];
      } else if(a.rfind("-config=", 0) == 0) {
         config_path = a.substr(std::string("-config=").size());
      }
   }
   if(config_path.empty()) {
      std::cerr << "usage: openssl_shim -config <file.json> | --plzn-shim-info" << std::endl;
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

   const auto failure_detail = [](const char* fallback) {
      if(!g_fail_reason.empty()) {
         return g_fail_reason;
      }
      return g_record_error.empty() ? std::string(fallback) : g_record_error;
   };
   if(!g_expectation_failure.empty()) {
      report_result(ShimResult::ExpectationMismatch, g_expectation_failure);
   }
   if(cfg.expect.handshake_abandoned) {
      // plzn abandons the handshake on purpose: the library's reaction to the
      // abrupt close (a failed flow, or a completed one) is not under test.
      report_success(g_flow_failed ? failure_detail("flow ended by the peer's close") : std::string());
   }
   if(expect_handshake_failure) {
      if(g_flow_failed) {
         // Report Ok (the failure was expected) but keep the library's reason so
         // the runner learns WHICH failure path was taken, not just that one was.
         report_success(failure_detail("flow failed as expected"));
      }
      report_result(ShimResult::UnexpectedSuccess, "expected the flow to fail but it completed");
   }
   if(g_flow_failed) {
      // The handshake / record flow failed in the library (not a self-check).
      report_result(ShimResult::HandshakeFailed, failure_detail("flow failed unexpectedly"));
   }
   if(!g_fail_reason.empty()) {
      // Only note_failure (negotiated-parameter expectation mismatch) reaches here
      // without g_flow_failed.
      report_result(ShimResult::ExpectationMismatch, g_fail_reason);
   }
   report_success();
}
