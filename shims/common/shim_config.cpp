/*
 * JSON -> ShimConfig deserialization. See plzn_shim.h.
 */

#include "plzn_shim.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace plzn {

namespace {

std::vector<uint16_t> u16_array(const JsonValue& parent, const std::string& key) {
   std::vector<uint16_t> out;
   const JsonValue* v = parent.find(key);
   if(v == nullptr || v->is_null()) {
      return out;
   }
   for(const auto& e : v->as_array()) {
      out.push_back(static_cast<uint16_t>(e.as_int()));
   }
   return out;
}

std::vector<std::string> string_array(const JsonValue& parent, const std::string& key) {
   std::vector<std::string> out;
   const JsonValue* v = parent.find(key);
   if(v == nullptr || v->is_null()) {
      return out;
   }
   for(const auto& e : v->as_array()) {
      out.push_back(e.as_string());
   }
   return out;
}

std::optional<uint16_t> opt_u16(const JsonValue& parent, const std::string& key) {
   const JsonValue* v = parent.find(key);
   if(v == nullptr || v->is_null()) {
      return std::nullopt;
   }
   return static_cast<uint16_t>(v->as_int());
}

std::optional<std::string> opt_string(const JsonValue& parent, const std::string& key) {
   const JsonValue* v = parent.find(key);
   if(v == nullptr || v->is_null()) {
      return std::nullopt;
   }
   return v->as_string();
}

std::optional<bool> opt_bool(const JsonValue& parent, const std::string& key) {
   const JsonValue* v = parent.find(key);
   if(v == nullptr || v->is_null()) {
      return std::nullopt;
   }
   return v->as_bool();
}

}  // namespace

std::string normalize_key_type(std::string_view name) {
   std::string n(name);
   for(auto& ch : n) {
      if(ch == '-') {
         ch = '_';
      }
   }
   if(n == "rsa" || n == "rsa2048") {
      return "rsa_2048";
   }
   if(n == "ecdsa" || n == "p256") {
      return "ecdsa_p256";
   }
   if(n == "p384") {
      return "ecdsa_p384";
   }
   if(n == "p521") {
      return "ecdsa_p521";
   }
   return n;
}

ShimConfig ShimConfig::from_json(const JsonValue& root) {
   if(!root.is_object()) {
      throw std::runtime_error("shim config root must be a JSON object");
   }

   ShimConfig c;
   c.raw = root;

   const std::string role = root.string_or("role", "server");
   if(role == "client") {
      c.role = Role::Client;
   } else if(role == "server") {
      c.role = Role::Server;
   } else {
      throw std::runtime_error("invalid role: " + role);
   }

   const std::string proto = root.string_or("protocol", "tls");
   if(proto == "tls") {
      c.protocol = Protocol::Tls;
   } else if(proto == "dtls") {
      c.protocol = Protocol::Dtls;
   } else {
      throw std::runtime_error("invalid protocol: " + proto);
   }

   if(const JsonValue* r = root.find("runner")) {
      c.runner.host = r->string_or("host", "127.0.0.1");
      c.runner.port = static_cast<uint16_t>(r->int_or("port", 0));
      c.runner.ipv6 = r->bool_or("ipv6", false);
   }
   if(c.runner.port == 0) {
      throw std::runtime_error("shim config: runner.port is required");
   }

   c.shim_id = static_cast<uint64_t>(root.int_or("shim_id", 0));
   c.resume_count = static_cast<uint32_t>(root.int_or("resume_count", 0));

   c.min_version = opt_u16(root, "min_version");
   c.max_version = opt_u16(root, "max_version");
   c.connection_versions = u16_array(root, "connection_versions");
   if(const auto* entries = root.find("connection_early_data")) {
      for(const auto& entry : entries->as_array()) {
         c.connection_early_data.push_back({
            static_cast<uint32_t>(entry.int_or("send", 0)),
            static_cast<uint32_t>(entry.int_or("expect", 0)),
            opt_bool(entry, "accepted")});
      }
   }

   c.cipher_suites = u16_array(root, "cipher_suites");
   c.curves = u16_array(root, "curves");
   c.signing_prefs = u16_array(root, "signing_prefs");
   c.verify_prefs = u16_array(root, "verify_prefs");
   if(const JsonValue* r = root.find("requires")) {
      c.requires_any_suite = u16_array(*r, "any_suite");
      c.requires_any_group = u16_array(*r, "any_group");
   }

   c.server_name = root.string_or("server_name", "");
   c.expect_server_name = opt_string(root, "expect_server_name");

   if(const JsonValue* cr = root.find("credentials")) {
      c.credentials.cert_file = cr->string_or("cert_file", "");
      c.credentials.key_file = cr->string_or("key_file", "");
      c.credentials.trust_file = cr->string_or("trust_file", "");
      c.credentials.ocsp_file = cr->string_or("ocsp_file", "");
      c.credentials.second_cert_file = cr->string_or("second_cert_file", "");
      c.credentials.second_key_file = cr->string_or("second_key_file", "");
      auto chain_list = [&](const char* key, std::vector<Chain>& out) -> bool {
         const JsonValue* arr = cr->find(key);
         if(arr == nullptr || !arr->is_array()) {
            return false;
         }
         for(const auto& e : arr->as_array()) {
            if(!e.is_object()) {
               continue;
            }
            Chain ch;
            ch.cert_file = e.string_or("cert_file", "");
            ch.key_file = e.string_or("key_file", "");
            ch.key_type = normalize_key_type(e.string_or("key_type", ""));
            out.push_back(std::move(ch));
         }
         return true;  // present, possibly empty
      };
      // Server-role chains: the explicit list wins (an empty one means "serve
      // nothing"); else the legacy single (+ second) pair.
      if(!chain_list("chains", c.credentials.chains)) {
         if(!c.credentials.cert_file.empty()) {
            c.credentials.chains.push_back({c.credentials.cert_file, c.credentials.key_file, ""});
         }
         if(!c.credentials.second_cert_file.empty()) {
            c.credentials.chains.push_back({c.credentials.second_cert_file, c.credentials.second_key_file, ""});
         }
      } else if(!c.credentials.chains.empty() && c.credentials.cert_file.empty()) {
         c.credentials.cert_file = c.credentials.chains[0].cert_file;
         c.credentials.key_file = c.credentials.chains[0].key_file;
      }
      // Client-role credentials: same rule.
      if(!chain_list("client_chains", c.credentials.client_chains)) {
         if(!c.credentials.cert_file.empty()) {
            c.credentials.client_chains.push_back({c.credentials.cert_file, c.credentials.key_file, ""});
         }
         if(!c.credentials.second_cert_file.empty()) {
            c.credentials.client_chains.push_back(
               {c.credentials.second_cert_file, c.credentials.second_key_file, ""});
         }
      }
   }

   if(const JsonValue* p = root.find("psk")) {
      c.psk.identity = p->string_or("identity", "");
      c.psk.secret_hex = p->string_or("secret_hex", "");
      c.psk.present = !c.psk.secret_hex.empty();
   }

   if(const JsonValue* v = root.find("verify")) {
      c.verify.verify_peer = v->bool_or("peer", false);
      c.verify.require_client_cert = v->bool_or("require_client_cert", false);
      c.verify.request_client_cert = v->bool_or("request_client_cert", false);
      c.verify.fail = v->bool_or("fail", false);
      c.verify.expect_peer_subject_cn = opt_string(*v, "expect_peer_subject_cn");
   }

   if(const JsonValue* a = root.find("alpn")) {
      c.alpn.advertise = string_array(*a, "advertise");
      c.alpn.select = a->string_or("select", "");
      c.alpn.select_from = string_array(*a, "select_from");
      c.alpn.expect = opt_string(*a, "expect");
      c.alpn.decline = a->bool_or("decline", false);
   }

   c.srtp_profiles = u16_array(root, "srtp_profiles");
   c.expect_srtp_profile = opt_u16(root, "expect_srtp_profile");

   if(const JsonValue* a = root.find("app_data")) {
      const std::string mode = a->string_or("mode", "echo");
      if(mode == "echo") {
         c.app_data.mode = AppDataMode::Echo;
      } else if(mode == "shim_writes") {
         c.app_data.mode = AppDataMode::ShimWrites;
      } else if(mode == "shutdown_only") {
         c.app_data.mode = AppDataMode::ShutdownOnly;
      } else {
         throw std::runtime_error("invalid app_data.mode: " + mode);
      }
      c.app_data.send = a->string_or("send", "");
      c.app_data.shim_shuts_down = a->bool_or("shim_shuts_down", false);
   }
   if(const JsonValue* values = root.find("key_material")) {
      if(!values->is_array()) {
         throw std::runtime_error("key_material must be an array");
      }
      for(const auto& value : values->as_array()) {
         if(!value.is_object()) continue;
         KeyMaterialConfig request;
         request.connection = static_cast<uint32_t>(value.int_or("connection", 0));
         request.kind = value.string_or("kind", "");
         request.label = value.string_or("label", "");
         request.context = opt_string(value, "context");
         request.length = static_cast<uint32_t>(value.int_or("length", 0));
         c.key_material.push_back(std::move(request));
      }
   }

   if(const JsonValue* e = root.find("expect")) {
      c.expect.version = opt_u16(*e, "version");
      c.expect.cipher = opt_u16(*e, "cipher");
      c.expect.curve = opt_u16(*e, "curve");
      c.expect.peer_signature_algorithm = opt_u16(*e, "peer_signature_algorithm");
      c.expect.alpn = opt_string(*e, "alpn");
      c.expect.resumed = opt_bool(*e, "resumed");
      c.expect.hrr = opt_bool(*e, "hrr");
      c.expect.secure_renegotiation = opt_bool(*e, "secure_renegotiation");
      c.expect.peer_subject_cn = opt_string(*e, "peer_subject_cn");
      c.expect.handshake_error = opt_string(*e, "handshake_error");
      c.expect.handshake_abandoned = opt_bool(*e, "handshake_abandoned").value_or(false);
   }

   if(const JsonValue* d = root.find("dtls")) {
      c.mtu = static_cast<uint32_t>(d->int_or("mtu", 1500));
      c.initial_timeout_ms = static_cast<uint32_t>(d->int_or("initial_timeout_ms", 400));
      if(d->find("max_retransmissions") != nullptr) {
         c.dtls_max_retransmissions = static_cast<uint32_t>(d->int_or("max_retransmissions", 0));
      }
      if(d->find("max_timeout_ms") != nullptr) {
         c.dtls_max_timeout_ms = static_cast<uint32_t>(d->int_or("max_timeout_ms", 0));
      }
      c.dtls_require_cookie = opt_bool(*d, "require_cookie");
      c.dtls_epoch0_restart = opt_bool(*d, "epoch0_restart");
      if(d->find("max_hello_verify_requests") != nullptr) {
         c.dtls_max_hello_verify_requests = static_cast<uint32_t>(d->int_or("max_hello_verify_requests", 0));
      }
   }

   c.renegotiate_freely = root.bool_or("renegotiate_freely", false);

   if(const JsonValue* r = root.find("requires")) {
      c.requires_virtual_clock = opt_bool(*r, "virtual_clock").value_or(false);
      c.requires_dynamic_timeout = opt_bool(*r, "dynamic_timeout").value_or(false);
      // T3 / chains: a string or an array of key-type names.
      if(const JsonValue* sk = r->find("server_key")) {
         if(sk->is_array()) {
            for(const auto& e : sk->as_array()) {
               if(e.is_string()) {
                  c.requires_server_keys.push_back(normalize_key_type(e.as_string()));
               }
            }
         } else if(sk->is_string()) {
            c.requires_server_keys.push_back(normalize_key_type(sk->as_string()));
         }
      }
   }
   c.renegotiate_count = static_cast<uint32_t>(root.int_or("renegotiate_count", 0));
   c.key_update = root.bool_or("key_update", false);
   c.raw_public_key = root.bool_or("raw_public_key", false);
   for(const auto value : u16_array(root, "server_certificate_types")) {
      c.server_certificate_types.push_back(static_cast<uint8_t>(value));
   }
   for(const auto value : u16_array(root, "client_certificate_types")) {
      c.client_certificate_types.push_back(static_cast<uint8_t>(value));
   }
   if(c.raw_public_key) {
      c.server_certificate_types = {2};
      c.client_certificate_types = {2};
   }
   c.compress_certificate = root.bool_or("compress_certificate", false);
   c.no_ticket = root.bool_or("no_ticket", false);

   c.server_preference = opt_bool(root, "server_preference");
   c.renegotiation = opt_string(root, "renegotiation");
   if(root.contains("session_tickets")) {
      c.session_tickets = static_cast<uint32_t>(root.int_or("session_tickets", 0));
   }
   if(root.contains("max_early_data")) {
      c.max_early_data = static_cast<uint32_t>(root.int_or("max_early_data", 0));
   }
   c.early_data_send = static_cast<uint32_t>(root.int_or("early_data_send", 0));
   c.early_data_expect = static_cast<uint32_t>(root.int_or("early_data_expect", 0));
   c.expect_early_data_accepted = opt_bool(root, "expect_early_data_accepted");
   if(root.contains("max_cert_list")) {
      c.max_cert_list = static_cast<uint32_t>(root.int_or("max_cert_list", 0));
   }
   if(root.contains("record_size_limit")) {
      c.record_size_limit = static_cast<uint32_t>(root.int_or("record_size_limit", 0));
   }
   if(root.contains("records_per_traffic_key")) {
      c.records_per_traffic_key = static_cast<uint32_t>(root.int_or("records_per_traffic_key", 0));
   }
   c.extended_master_secret = opt_string(root, "extended_master_secret");
   c.encrypt_then_mac = opt_bool(root, "encrypt_then_mac");
   c.middlebox_compat = opt_bool(root, "middlebox_compat");
   if(root.contains("min_key_update_interval_ms")) {
      c.min_key_update_interval_ms = static_cast<uint32_t>(root.int_or("min_key_update_interval_ms", 0));
   }
   c.renegotiate_after_handshake = root.bool_or("renegotiate_after_handshake", false);
   c.post_handshake_auth = root.string_or("post_handshake_auth", "");
   c.hello_request_after_app_data = root.bool_or("hello_request_after_app_data", false);
   c.require_client_cert_on_renegotiation = root.bool_or("require_client_cert_on_renegotiation", false);
   c.half_rtt_data = string_array(root, "half_rtt_data");

   return c;
}

ShimConfig ShimConfig::from_file(const std::string& path) {
   std::ifstream in(path, std::ios::binary);
   if(!in) {
      throw std::runtime_error("cannot open shim config file: " + path);
   }
   std::ostringstream ss;
   ss << in.rdbuf();
   return from_json(JsonValue::parse(ss.str()));
}

}  // namespace plzn
