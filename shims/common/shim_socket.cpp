/*
 * Socket helper implementation. See plzn_shim.h.
 */

#include "plzn_shim.h"

#include <cstring>
#include <memory>

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace plzn {

namespace {

void store_le64(uint64_t v, uint8_t out[8]) {
   for(int i = 0; i < 8; ++i) {
      out[i] = static_cast<uint8_t>(v >> (8 * i));
   }
}

uint32_t load_be32(const uint8_t in[4]) {
   return (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
          (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
}

uint64_t load_be64(const uint8_t in[8]) {
   uint64_t v = 0;
   for(int i = 0; i < 8; ++i) {
      v = (v << 8) | in[i];
   }
   return v;
}

void store_be32(uint32_t v, uint8_t out[4]) {
   out[0] = static_cast<uint8_t>(v >> 24);
   out[1] = static_cast<uint8_t>(v >> 16);
   out[2] = static_cast<uint8_t>(v >> 8);
   out[3] = static_cast<uint8_t>(v);
}

}  // namespace

ShimSocket::ShimSocket(const std::string& host, uint16_t port, bool ipv6) : m_socket(-1) {
   addrinfo hints{};
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_NUMERICSERV;

   const std::string service = std::to_string(port);

   addrinfo* res = nullptr;
   const int rc = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
   if(rc != 0) {
      throw ShimSocketError("name resolution failed for " + host);
   }
   std::unique_ptr<addrinfo, void (*)(addrinfo*)> res_guard(res, ::freeaddrinfo);

   for(const addrinfo* rp = res; m_socket == -1 && rp != nullptr; rp = rp->ai_next) {
      if((!ipv6 && rp->ai_family != AF_INET) || (ipv6 && rp->ai_family != AF_INET6)) {
         continue;
      }
      m_socket = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if(m_socket == -1) {
         continue;
      }
      if(::connect(m_socket, rp->ai_addr, rp->ai_addrlen) != 0) {
         ::close(m_socket);
         m_socket = -1;
      }
   }

   if(m_socket < 0) {
      throw ShimSocketError("failed to connect to " + host + ":" + service);
   }

   // Send every TLS record as soon as the library emits it. The libraries
   // hand the shim a flight one record at a time (Botan's tls_emit_data is
   // called per record), and with Nagle's algorithm on, the second small
   // segment waits for the peer's ACK -- which Linux delays by up to 40 ms
   // when the peer has nothing to say yet. That cost every Botan handshake
   // two ~40 ms stalls (server flight, then CCS+Finished) and made the shim
   // look 10x slower than OpenSSL, whose BIO coalesces a flight into one
   // write. Not a correctness issue, so a failure to set it is ignored.
   const int one = 1;
   ::setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

ShimSocket::~ShimSocket() {
   if(m_socket >= 0) {
      // Signal end-of-write so pending alert records leave with a FIN, then
      // drain incoming so close() does not trigger an RST that would discard
      // our outgoing alert.
      ::shutdown(m_socket, SHUT_WR);
      char buf[256];
      while(::read(m_socket, buf, sizeof(buf)) > 0) {}
      ::close(m_socket);
      m_socket = -1;
   }
}

void ShimSocket::write_shim_id(uint64_t shim_id) {
   uint8_t id[8];
   store_le64(shim_id, id);
   write(id, sizeof(id));
}

void ShimSocket::write(const uint8_t* buf, size_t len) {
   if(m_socket < 0) {
      throw ShimSocketError("socket bad on write");
   }
   size_t sent_so_far = 0;
   while(sent_so_far != len) {
      const ssize_t sent = ::send(m_socket, buf + sent_so_far, len - sent_so_far, MSG_NOSIGNAL);
      if(sent < 0) {
         if(errno == EPIPE) {
            return;
         }
         throw ShimSocketError(std::string("socket write failed: ") + ::strerror(errno));
      }
      sent_so_far += static_cast<size_t>(sent);
   }
}

size_t ShimSocket::read(uint8_t* buf, size_t len) {
   if(m_socket < 0) {
      throw ShimSocketError("socket bad on read");
   }
   const ssize_t got = ::read(m_socket, buf, len);
   if(got < 0) {
      if(errno == ECONNRESET) {
         return 0;
      }
      throw ShimSocketError(std::string("socket read failed: ") + ::strerror(errno));
   }
   return static_cast<size_t>(got);
}

void ShimSocket::read_exactly(uint8_t* buf, size_t len) {
   while(len > 0) {
      const ssize_t got = ::read(m_socket, buf, len);
      if(got == 0) {
         throw ShimSocketError("socket read EOF");
      }
      if(got < 0) {
         throw ShimSocketError(std::string("socket read failed: ") + ::strerror(errno));
      }
      buf += static_cast<size_t>(got);
      len -= static_cast<size_t>(got);
   }
}

DtlsEvent ShimSocket::read_dtls_event() {
   uint8_t opcode = 0;
   const size_t got = read(&opcode, 1);
   if(got == 0) {
      return DtlsEvent{DtlsOpcode::Eof, {}, 0, 0, 0};
   }

   if(opcode == 'P') {
      uint8_t len_bytes[4];
      read_exactly(len_bytes, sizeof(len_bytes));
      const uint32_t packet_len = load_be32(len_bytes);
      DtlsEvent ev{DtlsOpcode::Packet, std::vector<uint8_t>(packet_len), 0, 0, 0};
      if(packet_len > 0) {
         read_exactly(ev.packet.data(), packet_len);
      }
      return ev;
   }

   if(opcode == 'T') {
      uint8_t nanos_bytes[8];
      read_exactly(nanos_bytes, sizeof(nanos_bytes));
      return DtlsEvent{DtlsOpcode::AdvanceClock, {}, load_be64(nanos_bytes), 0, 0};
   }

   if(opcode == 'E') {
      uint8_t nanos_bytes[8];
      read_exactly(nanos_bytes, sizeof(nanos_bytes));
      return DtlsEvent{DtlsOpcode::ExpectTimeout, {}, load_be64(nanos_bytes), 0, 0};
   }

   if(opcode == 'U') {
      uint8_t millis_bytes[4];
      read_exactly(millis_bytes, sizeof(millis_bytes));
      return DtlsEvent{DtlsOpcode::UpdateTimeout, {}, 0, load_be32(millis_bytes), 0};
   }

   if(opcode == 'C') {
      uint8_t command = 0;
      read_exactly(&command, 1);
      return DtlsEvent{DtlsOpcode::Control, {}, 0, 0, command};
   }

   throw ShimSocketError("unknown DTLS opcode: " + std::to_string(opcode));
}

void ShimSocket::write_dtls_packet(const uint8_t* buf, size_t len) {
   uint8_t hdr[5];
   hdr[0] = 'P';
   store_be32(static_cast<uint32_t>(len), hdr + 1);
   write(hdr, sizeof(hdr));
   if(len > 0) {
      write(buf, len);
   }
}

void ShimSocket::write_dtls_ack(uint8_t opcode) {
   write(&opcode, 1);
}

void ShimSocket::write_dtls_timeout_expired() {
   write_dtls_ack('X');
}

}  // namespace plzn
