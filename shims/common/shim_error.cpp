/*
 * Canonical error taxonomy implementation. See plzn_shim.h.
 */

#include "plzn_shim.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <thread>

#include <unistd.h>

namespace plzn {

namespace {

// TLS alert descriptions (RFC 8446 Section 6, RFC 5246 Section 7.2, RFC 6066).
const std::map<uint8_t, std::string>& alert_table() {
   static const std::map<uint8_t, std::string> t = {
      {0, "close_notify"},
      {10, "unexpected_message"},
      {20, "bad_record_mac"},
      {21, "decryption_failed"},
      {22, "record_overflow"},
      {30, "decompression_failure"},
      {40, "handshake_failure"},
      {41, "no_certificate"},
      {42, "bad_certificate"},
      {43, "unsupported_certificate"},
      {44, "certificate_revoked"},
      {45, "certificate_expired"},
      {46, "certificate_unknown"},
      {47, "illegal_parameter"},
      {48, "unknown_ca"},
      {49, "access_denied"},
      {50, "decode_error"},
      {51, "decrypt_error"},
      {70, "protocol_version"},
      {71, "insufficient_security"},
      {80, "internal_error"},
      {86, "inappropriate_fallback"},
      {90, "user_canceled"},
      {100, "no_renegotiation"},
      {109, "missing_extension"},
      {110, "unsupported_extension"},
      {111, "certificate_unobtainable"},
      {112, "unrecognized_name"},
      {113, "bad_certificate_status_response"},
      {114, "bad_certificate_hash_value"},
      {115, "unknown_psk_identity"},
      {116, "certificate_required"},
      {120, "no_application_protocol"},
   };
   return t;
}

}  // namespace

std::string alert_name(uint8_t description) {
   const auto& t = alert_table();
   auto it = t.find(description);
   if(it != t.end()) {
      return it->second;
   }
   return "alert_" + std::to_string(description);
}

uint8_t alert_code(const std::string& name) {
   for(const auto& [code, n] : alert_table()) {
      if(n == name) {
         return code;
      }
   }
   return 255;
}

std::string result_case_name(ShimResult result) {
   switch(result) {
      case ShimResult::Ok:
         return "ok";
      case ShimResult::Failure:
         return "failure";
      case ShimResult::LocalError:
         return "local_error";
      case ShimResult::IoError:
         return "io_error";
      case ShimResult::HandshakeFailed:
         return "handshake_failed";
      case ShimResult::ExpectationMismatch:
         return "expectation_mismatch";
      case ShimResult::UnexpectedSuccess:
         return "unexpected_success";
      case ShimResult::UnsupportedConfig:
         return "unsupported_config";
   }
   return "unknown";
}

void report_result(ShimResult result, const std::string& detail) {
   std::cerr << "PLZN-RESULT case=" << result_case_name(result) << " detail=" << detail << std::endl;
   std::exit(static_cast<int>(result));
}

void exit_when_orphaned() {
   const pid_t parent = ::getppid();
   std::thread([parent] {
      for(;;) {
         std::this_thread::sleep_for(std::chrono::seconds(1));
         if(::getppid() != parent) {
            std::_Exit(static_cast<int>(ShimResult::IoError));
         }
      }
   }).detach();
}

void report_success() {
   report_result(ShimResult::Ok, "");
}

void report_success(const std::string& detail) {
   report_result(ShimResult::Ok, detail);
}

void report_failure(const std::string& reason) {
   report_result(ShimResult::Failure, reason);
}



void report_unsupported(const std::string& knob, const std::string& why) {
   report_result(ShimResult::UnsupportedConfig, "uut." + knob + ": " + why);
}

}  // namespace plzn
