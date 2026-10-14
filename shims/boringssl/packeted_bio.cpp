// Copyright 2014 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "packeted_bio.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <climits>
#include <cstdio>
#include <functional>
#include <utility>
#include <vector>

namespace {

constexpr uint8_t kPacket = 'P';
constexpr uint8_t kAdvanceClock = 'T';
constexpr uint8_t kAdvanceClockAck = 't';
constexpr uint8_t kTimeoutExpired = 'X';
constexpr uint8_t kMtu = 'M';
constexpr uint8_t kMtuAck = 'm';
constexpr uint8_t kExpectTimeout = 'E';
constexpr uint8_t kExpectTimeoutAck = 'e';
constexpr uint8_t kUpdateTimeout = 'U';
constexpr uint8_t kUpdateTimeoutAck = 'u';

struct State {
   State(timeval* clock_in, SSL* ssl_in) : clock(clock_in), ssl(ssl_in) {}
   timeval* clock;
   SSL* ssl;
   std::function<bool()> interrupt;
};

uint32_t load_u32_be(const uint8_t* in) {
   return (static_cast<uint32_t>(in[0]) << 24) |
          (static_cast<uint32_t>(in[1]) << 16) |
          (static_cast<uint32_t>(in[2]) << 8) |
          static_cast<uint32_t>(in[3]);
}

uint64_t load_u64_be(const uint8_t* in) {
   uint64_t value = 0;
   for(size_t i = 0; i != 8; ++i) value = (value << 8) | in[i];
   return value;
}

void store_u32_be(uint8_t* out, uint32_t value) {
   out[0] = static_cast<uint8_t>(value >> 24);
   out[1] = static_cast<uint8_t>(value >> 16);
   out[2] = static_cast<uint8_t>(value >> 8);
   out[3] = static_cast<uint8_t>(value);
}

int method_type() {
   static const int type = BIO_get_new_index() | BIO_TYPE_FILTER;
   return type;
}

State* state(BIO* bio) {
   if(BIO_method_type(bio) != method_type()) return nullptr;
   return static_cast<State*>(BIO_get_data(bio));
}

int read_all(BIO* bio, uint8_t* out, size_t len) {
   while(len != 0) {
      const int chunk = static_cast<int>(std::min(len, static_cast<size_t>(INT_MAX)));
      const int ret = BIO_read(bio, out, chunk);
      if(ret <= 0) return ret;
      out += ret;
      len -= static_cast<size_t>(ret);
   }
   return 1;
}

bool write_byte(BIO* bio, uint8_t byte) {
   return BIO_write(bio, &byte, 1) == 1;
}

int packeted_write_ex(BIO* bio, const char* in, size_t in_len, size_t* written) {
   BIO* next = BIO_next(bio);
   if(next == nullptr || in_len > UINT32_MAX) return 0;
   BIO_clear_retry_flags(bio);

   std::array<uint8_t, 5> header{kPacket, 0, 0, 0, 0};
   store_u32_be(header.data() + 1, static_cast<uint32_t>(in_len));
   if(!BIO_write_all(next, header.data(), header.size()) ||
      !BIO_write_all(next, in, in_len)) {
      BIO_copy_next_retry(bio);
      return 0;
   }
   *written = in_len;
   return 1;
}

int packeted_read(BIO* bio, char* out, int out_len) {
   State* data = state(bio);
   BIO* next = BIO_next(bio);
   if(data == nullptr || next == nullptr) return -1;
   BIO_clear_retry_flags(bio);

   if(data->interrupt) {
      BIO_set_retry_read(bio);
      return -1;
   }

   uint8_t opcode = 0;
   int ret = read_all(next, &opcode, 1);
   if(ret <= 0) {
      BIO_copy_next_retry(bio);
      return ret;
   }

   if(opcode == kPacket) {
      std::array<uint8_t, 4> len_bytes{};
      ret = read_all(next, len_bytes.data(), len_bytes.size());
      if(ret <= 0) {
         BIO_copy_next_retry(bio);
         return ret;
      }
      std::vector<uint8_t> packet(load_u32_be(len_bytes.data()));
      ret = read_all(next, packet.data(), packet.size());
      if(ret <= 0) return ret;
      const int copied = std::min(out_len, static_cast<int>(packet.size()));
      std::copy_n(packet.data(), copied, reinterpret_cast<uint8_t*>(out));
      return copied;
   }

   if(opcode == kAdvanceClock || opcode == kExpectTimeout) {
      std::array<uint8_t, 8> value_bytes{};
      ret = read_all(next, value_bytes.data(), value_bytes.size());
      if(ret <= 0) {
         BIO_copy_next_retry(bio);
         return ret;
      }
      const uint64_t value = load_u64_be(value_bytes.data());
      if(opcode == kAdvanceClock) {
         // Defer the SSL operation until the active SSL_read/handshake call
         // unwinds. Unlike BoGo's one-way timeout command, plzn needs a
         // completion marker: acknowledge only after handle_timeout succeeds,
         // or surface the terminal retransmission-budget expiry as `X`.
         data->interrupt = [bio, next, value] {
            if(PacketedBioAdvanceClock(bio, value / 1000)) {
               return write_byte(next, kAdvanceClockAck);
            }
            write_byte(next, kTimeoutExpired);
            return false;
         };
      } else {
         data->interrupt = [data, next, value] {
            timeval timeout{};
            const bool has_timeout = DTLSv1_get_timeout(data->ssl, &timeout);
            if(value == UINT64_MAX) {
               if(has_timeout) {
                  std::fprintf(stderr, "expected no DTLS timeout, but one is armed\n");
                  return false;
               }
            } else {
               const uint64_t expected_us = value / 1000;
               if(!has_timeout || static_cast<uint64_t>(timeout.tv_sec) != expected_us / 1000000 ||
                  static_cast<uint64_t>(timeout.tv_usec) != expected_us % 1000000) {
                  if(!has_timeout) {
                     std::fprintf(stderr, "expected DTLS timeout %llu us, but no timer is armed\n",
                                  static_cast<unsigned long long>(expected_us));
                  } else {
                     const uint64_t actual_us = static_cast<uint64_t>(timeout.tv_sec) * 1000000 +
                                                static_cast<uint64_t>(timeout.tv_usec);
                     std::fprintf(stderr, "expected DTLS timeout %llu us, got %llu us\n",
                                  static_cast<unsigned long long>(expected_us),
                                  static_cast<unsigned long long>(actual_us));
                  }
                  return false;
               }
            }
            return write_byte(next, kExpectTimeoutAck);
         };
      }
      BIO_set_retry_read(bio);
      return -1;
   }

   if(opcode == kUpdateTimeout || opcode == kMtu) {
      std::array<uint8_t, 4> value_bytes{};
      ret = read_all(next, value_bytes.data(), value_bytes.size());
      if(ret <= 0) {
         BIO_copy_next_retry(bio);
         return ret;
      }
      const uint32_t value = load_u32_be(value_bytes.data());
      if(opcode == kMtu) {
         data->interrupt = [data, next, value] {
            return SSL_set_mtu(data->ssl, value) && write_byte(next, kMtuAck);
         };
      } else {
         data->interrupt = [data, next, value] {
            DTLSv1_set_initial_timeout_duration(data->ssl, value);
            return write_byte(next, kUpdateTimeoutAck);
         };
      }
      BIO_set_retry_read(bio);
      return -1;
   }

   std::fprintf(stderr, "unknown packeted BIO opcode %u\n", opcode);
   return -1;
}

long packeted_ctrl(BIO* bio, int command, long number, void* pointer) {
   BIO* next = BIO_next(bio);
   if(next == nullptr) return 0;
   BIO_clear_retry_flags(bio);
   const long ret = BIO_ctrl(next, command, number, pointer);
   BIO_copy_next_retry(bio);
   return ret;
}

long packeted_callback_ctrl(BIO* bio, int command, BIO_info_cb* callback) {
   BIO* next = BIO_next(bio);
   return next == nullptr ? 0 : BIO_callback_ctrl(next, command, callback);
}

int packeted_free(BIO* bio) {
   delete state(bio);
   return 1;
}

const BIO_METHOD* method() {
   static const BIO_METHOD* value = [] {
      BIO_METHOD* result = BIO_meth_new(method_type(), "plzn packeted bio");
      assert(result != nullptr);
      assert(BIO_meth_set_write_ex(result, packeted_write_ex));
      assert(BIO_meth_set_read(result, packeted_read));
      assert(BIO_meth_set_ctrl(result, packeted_ctrl));
      assert(BIO_meth_set_callback_ctrl(result, packeted_callback_ctrl));
      assert(BIO_meth_set_destroy(result, packeted_free));
      return result;
   }();
   return value;
}

}  // namespace

bssl::UniquePtr<BIO> PacketedBioCreate(timeval* clock, SSL* ssl) {
   bssl::UniquePtr<BIO> bio(BIO_new(method()));
   if(!bio) return nullptr;
   BIO_set_data(bio.get(), new State(clock, ssl));
   BIO_set_init(bio.get(), 1);
   return bio;
}

bool PacketedBioHasInterrupt(BIO* bio) {
   State* data = state(bio);
   return data != nullptr && static_cast<bool>(data->interrupt);
}

bool PacketedBioHandleInterrupt(BIO* bio) {
   State* data = state(bio);
   if(data == nullptr || !data->interrupt) return false;
   return std::exchange(data->interrupt, {})();
}

bool PacketedBioAdvanceClock(BIO* bio, uint64_t microseconds) {
   State* data = state(bio);
   if(data == nullptr) return false;
   data->clock->tv_sec += static_cast<time_t>(microseconds / 1000000);
   data->clock->tv_usec += static_cast<suseconds_t>(microseconds % 1000000);
   if(data->clock->tv_usec >= 1000000) {
      data->clock->tv_usec -= 1000000;
      ++data->clock->tv_sec;
   }
   const int ret = DTLSv1_handle_timeout(data->ssl);
   return ret >= 0 || SSL_get_error(data->ssl, ret) == SSL_ERROR_WANT_WRITE;
}
