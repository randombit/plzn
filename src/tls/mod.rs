// plzn's TLS implementation. Scoped to what a test harness needs:
//
//   * We are the client side (for `uut server`) or the server side
//     (`uut client`). The happy-path first slice only covers the
//     client side; the server side lands when we add `TcpListenFactory`.
//   * No certificate verification. We're talking to an oracle whose
//     output we trust; malformed server behaviour is a separate
//     concern handled by explicit negative tests.
//   * No side-channel / timing resistance. The runtime wants predictable
//     bytes on the wire more than it wants production security.
//   * Session resumption and TLS 1.3 0-RTT are implemented for explicit
//     multi-session flows. This is still a harness stack, not a general TLS
//     implementation; unsupported state-machine branches fail closed.
//
// Layering:
//
//   crypto.rs  - ONLY file importing RustCrypto. Everything else sees
//                plzn-owned wrapper types.
//   codec.rs   - Serialise/parse TLS handshake messages + extensions.
//   record.rs  - Record framing and AEAD/CBC en/decryption.
//   handshake.rs - Key schedule + derived secrets for TLS 1.2 and 1.3.
//   driver.rs  - Step-by-step driver that runs a handshake against a
//                UutTransport.

pub mod chains;
pub mod client_auth;
pub mod codec;
pub mod crypto;
pub mod driver;
pub mod dtls_driver;
pub mod dtls_handshake;
pub mod dtls_kex;
pub mod dtls_record;
pub mod dtls_server;
pub mod dtls_transport;
pub mod handshake;
pub mod kex12;
pub mod mutate;
pub mod record;
pub mod server12;
pub mod server13;
