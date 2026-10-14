#include "plzn_shim.h"

#include <algorithm>
#include <array>
#include <utility>

namespace plzn {

namespace {

constexpr std::array<uint8_t, 4> Magic = {'P', 'L', 'Z', 'N'};
constexpr size_t HeaderSize = 12;
constexpr size_t MaxSize = 1 << 20;

uint32_t load_be_u32(const uint8_t* p) {
   return (static_cast<uint32_t>(p[0]) << 24) |
          (static_cast<uint32_t>(p[1]) << 16) |
          (static_cast<uint32_t>(p[2]) << 8) |
          static_cast<uint32_t>(p[3]);
}

std::vector<uint8_t> random_reply(const uint8_t* request, size_t request_size, size_t reply_size) {
   uint64_t state = 0xcbf29ce484222325ULL;
   for(size_t i = 0; i != request_size; ++i) {
      state ^= request[i];
      state *= 0x100000001b3ULL;
   }
   if(state == 0) {
      state = 0x9e3779b97f4a7c15ULL;
   }
   std::vector<uint8_t> reply(reply_size);
   for(auto& byte : reply) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      byte = static_cast<uint8_t>(state);
   }
   return reply;
}

}  // namespace

std::vector<std::vector<uint8_t>> AppDataResponder::receive(const uint8_t* data, size_t size) {
   m_pending.insert(m_pending.end(), data, data + size);
   std::vector<std::vector<uint8_t>> replies;

   while(!m_pending.empty()) {
      const size_t prefix = std::min(m_pending.size(), Magic.size());
      if(!std::equal(m_pending.begin(), m_pending.begin() + prefix, Magic.begin())) {
         // Preserve the historical echo behaviour for non-DSL callers.
         replies.push_back(std::move(m_pending));
         m_pending.clear();
         break;
      }
      if(m_pending.size() < HeaderSize) {
         break;
      }

      const size_t request_size = load_be_u32(m_pending.data() + 4);
      const size_t reply_size = load_be_u32(m_pending.data() + 8);
      if(request_size < HeaderSize || request_size > MaxSize || reply_size > MaxSize) {
         replies.push_back(std::move(m_pending));
         m_pending.clear();
         break;
      }
      if(m_pending.size() < request_size) {
         break;
      }
      if(reply_size != 0) {
         replies.push_back(random_reply(m_pending.data(), request_size, reply_size));
      }
      m_pending.erase(m_pending.begin(), m_pending.begin() + request_size);
   }
   return replies;
}

}  // namespace plzn
