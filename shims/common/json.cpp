/*
 * Self-contained JSON parser implementation. See plzn_shim.h.
 */

#include "plzn_shim.h"

namespace plzn {

JsonValue JsonValue::make_bool(bool b) {
   JsonValue v;
   v.m_type = JsonType::Bool;
   v.m_bool = b;
   return v;
}

JsonValue JsonValue::make_number(double d) {
   JsonValue v;
   v.m_type = JsonType::Number;
   v.m_number = d;
   return v;
}

JsonValue JsonValue::make_string(std::string s) {
   JsonValue v;
   v.m_type = JsonType::String;
   v.m_string = std::move(s);
   return v;
}

JsonValue JsonValue::make_array(JsonArray a) {
   JsonValue v;
   v.m_type = JsonType::Array;
   v.m_array = std::make_shared<JsonArray>(std::move(a));
   return v;
}

JsonValue JsonValue::make_object(JsonObject o) {
   JsonValue v;
   v.m_type = JsonType::Object;
   v.m_object = std::make_shared<JsonObject>(std::move(o));
   return v;
}

bool JsonValue::as_bool() const {
   if(m_type != JsonType::Bool) {
      throw JsonError("expected bool", 0);
   }
   return m_bool;
}

double JsonValue::as_number() const {
   if(m_type != JsonType::Number) {
      throw JsonError("expected number", 0);
   }
   return m_number;
}

int64_t JsonValue::as_int() const {
   if(m_type != JsonType::Number) {
      throw JsonError("expected integer", 0);
   }
   return static_cast<int64_t>(m_number);
}

const std::string& JsonValue::as_string() const {
   if(m_type != JsonType::String) {
      throw JsonError("expected string", 0);
   }
   return m_string;
}

const JsonArray& JsonValue::as_array() const {
   if(m_type != JsonType::Array) {
      throw JsonError("expected array", 0);
   }
   return *m_array;
}

const JsonObject& JsonValue::as_object() const {
   if(m_type != JsonType::Object) {
      throw JsonError("expected object", 0);
   }
   return *m_object;
}

const JsonValue* JsonValue::find(const std::string& key) const {
   if(m_type != JsonType::Object) {
      return nullptr;
   }
   auto it = m_object->find(key);
   return (it == m_object->end()) ? nullptr : &it->second;
}

std::string JsonValue::string_or(const std::string& key, const std::string& def) const {
   const JsonValue* v = find(key);
   if(v == nullptr || v->is_null()) {
      return def;
   }
   return v->as_string();
}

int64_t JsonValue::int_or(const std::string& key, int64_t def) const {
   const JsonValue* v = find(key);
   if(v == nullptr || v->is_null()) {
      return def;
   }
   return v->as_int();
}

bool JsonValue::bool_or(const std::string& key, bool def) const {
   const JsonValue* v = find(key);
   if(v == nullptr || v->is_null()) {
      return def;
   }
   return v->as_bool();
}

namespace {

class Parser final {
   public:
      explicit Parser(const std::string& text) : m_text(text), m_pos(0) {}

      JsonValue parse() {
         skip_ws();
         JsonValue v = parse_value();
         skip_ws();
         if(m_pos != m_text.size()) {
            throw JsonError("trailing data after JSON value", m_pos);
         }
         return v;
      }

   private:
      const std::string& m_text;
      size_t m_pos;

      [[noreturn]] void fail(const std::string& msg) { throw JsonError(msg, m_pos); }

      char peek() {
         if(m_pos >= m_text.size()) {
            fail("unexpected end of input");
         }
         return m_text[m_pos];
      }

      char next() {
         char c = peek();
         ++m_pos;
         return c;
      }

      void skip_ws() {
         while(m_pos < m_text.size()) {
            char c = m_text[m_pos];
            if(c == ' ' || c == '\t' || c == '\n' || c == '\r') {
               ++m_pos;
            } else {
               break;
            }
         }
      }

      void expect(char c) {
         if(next() != c) {
            fail(std::string("expected '") + c + "'");
         }
      }

      JsonValue parse_value() {
         skip_ws();
         char c = peek();
         switch(c) {
            case '{':
               return parse_object();
            case '[':
               return parse_array();
            case '"':
               return JsonValue::make_string(parse_string());
            case 't':
            case 'f':
               return parse_bool();
            case 'n':
               return parse_null();
            default:
               if(c == '-' || (c >= '0' && c <= '9')) {
                  return parse_number();
               }
               fail("unexpected character");
         }
      }

      JsonValue parse_object() {
         expect('{');
         JsonObject obj;
         skip_ws();
         if(peek() == '}') {
            ++m_pos;
            return JsonValue::make_object(std::move(obj));
         }
         for(;;) {
            skip_ws();
            if(peek() != '"') {
               fail("expected object key string");
            }
            std::string key = parse_string();
            skip_ws();
            expect(':');
            JsonValue val = parse_value();
            obj[key] = std::move(val);
            skip_ws();
            char c = next();
            if(c == ',') {
               continue;
            }
            if(c == '}') {
               break;
            }
            fail("expected ',' or '}' in object");
         }
         return JsonValue::make_object(std::move(obj));
      }

      JsonValue parse_array() {
         expect('[');
         JsonArray arr;
         skip_ws();
         if(peek() == ']') {
            ++m_pos;
            return JsonValue::make_array(std::move(arr));
         }
         for(;;) {
            arr.push_back(parse_value());
            skip_ws();
            char c = next();
            if(c == ',') {
               continue;
            }
            if(c == ']') {
               break;
            }
            fail("expected ',' or ']' in array");
         }
         return JsonValue::make_array(std::move(arr));
      }

      std::string parse_string() {
         expect('"');
         std::string out;
         for(;;) {
            char c = next();
            if(c == '"') {
               break;
            }
            if(c == '\\') {
               char e = next();
               switch(e) {
                  case '"':
                     out.push_back('"');
                     break;
                  case '\\':
                     out.push_back('\\');
                     break;
                  case '/':
                     out.push_back('/');
                     break;
                  case 'b':
                     out.push_back('\b');
                     break;
                  case 'f':
                     out.push_back('\f');
                     break;
                  case 'n':
                     out.push_back('\n');
                     break;
                  case 'r':
                     out.push_back('\r');
                     break;
                  case 't':
                     out.push_back('\t');
                     break;
                  case 'u':
                     out += decode_utf8(parse_hex4());
                     break;
                  default:
                     fail("invalid escape sequence");
               }
            } else {
               out.push_back(c);
            }
         }
         return out;
      }

      uint32_t parse_hex4() {
         uint32_t val = 0;
         for(int i = 0; i < 4; ++i) {
            char c = next();
            val <<= 4;
            if(c >= '0' && c <= '9') {
               val |= static_cast<uint32_t>(c - '0');
            } else if(c >= 'a' && c <= 'f') {
               val |= static_cast<uint32_t>(c - 'a' + 10);
            } else if(c >= 'A' && c <= 'F') {
               val |= static_cast<uint32_t>(c - 'A' + 10);
            } else {
               fail("invalid \\u hex digit");
            }
         }
         return val;
      }

      std::string decode_utf8(uint32_t cp) {
         // Surrogate pairs: if we see a high surrogate, expect \uXXXX low.
         if(cp >= 0xD800 && cp <= 0xDBFF) {
            if(next() != '\\' || next() != 'u') {
               fail("expected low surrogate");
            }
            uint32_t low = parse_hex4();
            if(low < 0xDC00 || low > 0xDFFF) {
               fail("invalid low surrogate");
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
         }
         std::string out;
         if(cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
         } else if(cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
         } else if(cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
         } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
         }
         return out;
      }

      JsonValue parse_number() {
         size_t start = m_pos;
         if(peek() == '-') {
            ++m_pos;
         }
         while(m_pos < m_text.size()) {
            char c = m_text[m_pos];
            if((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
               ++m_pos;
            } else {
               break;
            }
         }
         const std::string num = m_text.substr(start, m_pos - start);
         try {
            size_t consumed = 0;
            double d = std::stod(num, &consumed);
            if(consumed != num.size()) {
               throw JsonError("malformed number", start);
            }
            return JsonValue::make_number(d);
         } catch(const std::invalid_argument&) {
            throw JsonError("malformed number", start);
         } catch(const std::out_of_range&) {
            throw JsonError("number out of range", start);
         }
      }

      JsonValue parse_bool() {
         if(m_text.compare(m_pos, 4, "true") == 0) {
            m_pos += 4;
            return JsonValue::make_bool(true);
         }
         if(m_text.compare(m_pos, 5, "false") == 0) {
            m_pos += 5;
            return JsonValue::make_bool(false);
         }
         fail("invalid literal");
      }

      JsonValue parse_null() {
         if(m_text.compare(m_pos, 4, "null") == 0) {
            m_pos += 4;
            return JsonValue();
         }
         fail("invalid literal");
      }
};

}  // namespace

JsonValue JsonValue::parse(const std::string& text) {
   Parser p(text);
   return p.parse();
}

}  // namespace plzn
