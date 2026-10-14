/*
 * Unit tests for the shared shim helper library. No external dependency; built
 * and run by `make check`. Exits non-zero on the first failure.
 */

#include "plzn_shim.h"

#include <cstdio>
#include <string>

namespace {

int g_checks = 0;
int g_failures = 0;

void check(bool cond, const char* what) {
   ++g_checks;
   if(!cond) {
      ++g_failures;
      std::fprintf(stderr, "  FAIL: %s\n", what);
   }
}

template <typename F>
void expect_throw(F&& f, const char* what) {
   ++g_checks;
   bool threw = false;
   try {
      f();
   } catch(const std::exception&) {
      threw = true;
   }
   if(!threw) {
      ++g_failures;
      std::fprintf(stderr, "  FAIL (expected throw): %s\n", what);
   }
}

using namespace plzn;

void test_json_scalars() {
   check(JsonValue::parse("true").as_bool() == true, "parse true");
   check(JsonValue::parse("false").as_bool() == false, "parse false");
   check(JsonValue::parse("null").is_null(), "parse null");
   check(JsonValue::parse("42").as_int() == 42, "parse int");
   check(JsonValue::parse("-17").as_int() == -17, "parse negative int");
   check(JsonValue::parse("3.5").as_number() == 3.5, "parse double");
   check(JsonValue::parse("771").as_int() == 771, "parse version int");
   check(JsonValue::parse("  \n 5 \t ").as_int() == 5, "parse with whitespace");
}

void test_json_strings() {
   check(JsonValue::parse("\"hello\"").as_string() == "hello", "parse string");
   check(JsonValue::parse("\"\"").as_string().empty(), "parse empty string");
   check(JsonValue::parse("\"a\\nb\"").as_string() == "a\nb", "parse newline escape");
   check(JsonValue::parse("\"tab\\there\"").as_string() == "tab\there", "parse tab escape");
   check(JsonValue::parse("\"quote\\\"end\"").as_string() == "quote\"end", "parse quote escape");
   check(JsonValue::parse("\"a\\\\b\"").as_string() == "a\\b", "parse backslash escape");
   check(JsonValue::parse("\"\\u0041\"").as_string() == "A", "parse \\u ascii");
   check(JsonValue::parse("\"\\u00e9\"").as_string() == "\xc3\xa9", "parse \\u 2-byte utf8");
   check(JsonValue::parse("\"\\u4e2d\"").as_string() == "\xe4\xb8\xad", "parse \\u 3-byte utf8");
   // Surrogate pair for U+1F600.
   check(JsonValue::parse("\"\\ud83d\\ude00\"").as_string() == "\xf0\x9f\x98\x80", "parse surrogate pair");
}

void test_json_arrays_objects() {
   auto arr = JsonValue::parse("[1, 2, 3]");
   check(arr.is_array() && arr.as_array().size() == 3, "parse array size");
   check(arr.as_array()[1].as_int() == 2, "parse array element");

   auto empty = JsonValue::parse("[]");
   check(empty.is_array() && empty.as_array().empty(), "parse empty array");

   auto obj = JsonValue::parse("{\"a\": 1, \"b\": \"x\"}");
   check(obj.is_object(), "parse object");
   check(obj.find("a") != nullptr && obj.find("a")->as_int() == 1, "object member a");
   check(obj.find("b")->as_string() == "x", "object member b");
   check(obj.find("missing") == nullptr, "object missing member");

   auto nested = JsonValue::parse("{\"outer\": {\"inner\": [true, false]}}");
   check(nested.find("outer")->find("inner")->as_array()[0].as_bool(), "nested access");

   check(JsonValue::parse("{}").as_object().empty(), "parse empty object");
   check(obj.int_or("a", 99) == 1, "int_or present");
   check(obj.int_or("z", 99) == 99, "int_or default");
   check(obj.string_or("b", "def") == "x", "string_or present");
   check(obj.string_or("z", "def") == "def", "string_or default");
}

void test_json_errors() {
   expect_throw([] { JsonValue::parse("{"); }, "unterminated object");
   expect_throw([] { JsonValue::parse("[1, 2"); }, "unterminated array");
   expect_throw([] { JsonValue::parse("\"unterminated"); }, "unterminated string");
   expect_throw([] { JsonValue::parse("tru"); }, "bad literal");
   expect_throw([] { JsonValue::parse("{\"a\": }"); }, "missing value");
   expect_throw([] { JsonValue::parse("[1] [2]"); }, "trailing data");
   expect_throw([] { JsonValue::parse("{\"a\" 1}"); }, "missing colon");
   expect_throw([] { JsonValue::parse(""); }, "empty input");
   // Wrong-type accessors throw.
   expect_throw([] { JsonValue::parse("42").as_string(); }, "int as string");
   expect_throw([] { JsonValue::parse("\"x\"").as_int(); }, "string as int");
}

void test_config_minimal() {
   const std::string js = R"({
      "role": "server",
      "protocol": "tls",
      "runner": { "port": 12345 }
   })";
   ShimConfig c = ShimConfig::from_json(JsonValue::parse(js));
   check(c.is_server(), "role server");
   check(!c.is_dtls(), "protocol tls");
   check(c.runner.port == 12345, "runner port");
   check(c.runner.host == "127.0.0.1", "runner host default");
   check(c.resume_count == 0, "resume_count default");
   check(!c.min_version.has_value(), "min_version absent");
   check(c.connection_versions.empty(), "connection_versions absent");
}

void test_config_full() {
   const std::string js = R"({
      "role": "client",
      "protocol": "dtls",
      "runner": { "host": "::1", "port": 4433, "ipv6": true },
      "shim_id": 7,
      "resume_count": 2,
      "max_early_data": 1024,
      "early_data_send": 32,
      "early_data_expect": 64,
      "expect_early_data_accepted": false,
      "min_version": 771,
      "max_version": 772,
      "connection_versions": [771, 772],
      "connection_early_data": [{"send": 0, "expect": 0, "accepted": null}, {"send": 16, "expect": 48, "accepted": true}],
      "cipher_suites": [4865, 4866],
      "curves": [23, 29],
      "signing_prefs": [1027, 2052],
      "server_name": "example.com",
      "credentials": { "cert_file": "/tmp/c.pem", "key_file": "/tmp/k.pem" },
      "psk": { "identity": "id", "secret_hex": "aabb" },
      "verify": { "peer": true, "require_client_cert": true },
      "alpn": { "advertise": ["h2", "http/1.1"], "select_from": ["h2", "http/1.1"], "expect": "h2" },
      "app_data": { "mode": "shim_writes", "send": "hello" },
      "expect": { "version": 772, "cipher": 4865, "resumed": true, "hrr": false },
      "dtls": { "mtu": 1200, "initial_timeout_ms": 200 }
   })";
   ShimConfig c = ShimConfig::from_json(JsonValue::parse(js));
   check(!c.is_server(), "role client");
   check(c.is_dtls(), "protocol dtls");
   check(c.runner.host == "::1" && c.runner.ipv6, "runner ipv6");
   check(c.shim_id == 7, "shim_id");
   check(c.resume_count == 2, "resume_count");
   check(c.max_early_data == 1024 && c.early_data_send == 32 && c.early_data_expect == 64,
         "early data config");
   check(c.expect_early_data_accepted == false, "early data acceptance expectation");
   check(c.min_version == 771 && c.max_version == 772, "version bounds");
   check(c.connection_versions == std::vector<uint16_t>({771, 772}), "connection versions");
   const auto resumed = c.for_connection(1);
   check(resumed.min_version == 772 && resumed.max_version == 772, "per-connection version");
   check(resumed.early_data_send == 16 && resumed.early_data_expect == 48 && resumed.expect_early_data_accepted == true,
         "per-connection early data");
   check(c.for_connection(0).expect_early_data_accepted == std::nullopt, "initial connection has no early data assertion");
   check(c.cipher_suites.size() == 2 && c.cipher_suites[0] == 4865, "cipher_suites");
   check(c.curves.size() == 2 && c.curves[1] == 29, "curves");
   check(c.signing_prefs.size() == 2 && c.signing_prefs[0] == 1027, "signing_prefs");
   check(c.server_name == "example.com", "server_name");
   check(c.credentials.cert_file == "/tmp/c.pem", "cert_file");
   check(c.psk.present && c.psk.identity == "id" && c.psk.secret_hex == "aabb", "psk");
   check(c.verify.verify_peer && c.verify.require_client_cert, "verify");
   check(c.alpn.advertise.size() == 2 && c.alpn.select_from.size() == 2 &&
            c.alpn.select_from[1] == "http/1.1" && c.alpn.expect == "h2",
         "alpn");
   check(c.app_data.mode == AppDataMode::ShimWrites && c.app_data.send == "hello", "app_data");
   check(c.expect.version == 772 && c.expect.cipher == 4865, "expect codes");
   check(c.expect.resumed == true && c.expect.hrr == false, "expect bools");
   check(c.mtu == 1200 && c.initial_timeout_ms == 200, "dtls knobs");
}

void test_config_errors() {
   expect_throw([] { ShimConfig::from_json(JsonValue::parse("[]")); }, "root not object");
   expect_throw([] { ShimConfig::from_json(JsonValue::parse("{\"role\":\"server\"}")); }, "missing port");
   expect_throw(
      [] { ShimConfig::from_json(JsonValue::parse("{\"role\":\"bogus\",\"runner\":{\"port\":1}}")); },
      "invalid role");
   expect_throw(
      [] { ShimConfig::from_json(JsonValue::parse("{\"protocol\":\"quic\",\"runner\":{\"port\":1}}")); },
      "invalid protocol");
}

void test_dtls13_version_detection() {
   ShimConfig c;
   c.protocol = Protocol::Dtls;
   c.min_version = 0xFEFD;
   c.max_version = 0xFEFD;
   check(!c.requests_dtls13(), "DTLS 1.2 does not request DTLS 1.3");

   c.min_version = 0xFEFC;
   c.max_version = 0xFEFC;
   check(c.requests_dtls13(), "DTLS 1.3 exact bounds are detected");

   c.min_version = 0xFEFD;
   c.max_version = 0xFEFC;
   check(c.requests_dtls13(), "mixed DTLS 1.2/1.3 bounds are detected");

   c.protocol = Protocol::Tls;
   check(!c.requests_dtls13(), "TLS never requests DTLS 1.3");
}

void test_alert_names() {
   check(alert_name(50) == "decode_error", "alert 50");
   check(alert_name(51) == "decrypt_error", "alert 51");
   check(alert_name(40) == "handshake_failure", "alert 40");
   check(alert_name(0) == "close_notify", "alert 0");
   check(alert_name(200) == "alert_200", "unknown alert");
   check(alert_code("decode_error") == 50, "code decode_error");
   check(alert_code("bad_record_mac") == 20, "code bad_record_mac");
   check(alert_code("nonexistent") == 255, "code unknown");
}


void test_app_data_protocol() {
   std::vector<uint8_t> request(32, 0x5a);
   request[0] = 'P';
   request[1] = 'L';
   request[2] = 'Z';
   request[3] = 'N';
   request[4] = 0;
   request[5] = 0;
   request[6] = 0;
   request[7] = 32;
   request[8] = 0;
   request[9] = 0;
   request[10] = 0;
   request[11] = 19;

   AppDataResponder responder;
   check(responder.receive(request.data(), 5).empty(), "app-data request waits for its header/body");
   const auto replies = responder.receive(request.data() + 5, request.size() - 5);
   check(replies.size() == 1 && replies[0].size() == 19, "app-data request controls reply length");

   const std::vector<uint8_t> legacy = {'o', 'l', 'd'};
   const auto echo = responder.receive(legacy.data(), legacy.size());
   check(echo.size() == 1 && echo[0] == legacy, "unframed app-data retains legacy echo");
}

}  // namespace

int main() {
   test_json_scalars();
   test_json_strings();
   test_json_arrays_objects();
   test_json_errors();
   test_config_minimal();
   test_config_full();
   test_config_errors();
   test_dtls13_version_detection();
   test_alert_names();
   test_app_data_protocol();

   std::printf("%d checks, %d failures\n", g_checks, g_failures);
   return g_failures == 0 ? 0 : 1;
}
