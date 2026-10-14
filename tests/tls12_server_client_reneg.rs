// Integration test: plzn's Tls12Server accepts a CLIENT-initiated TLS 1.2
// renegotiation (RFC 5246 7.4.1.2, RFC 5746 3.7). No shim client can
// initiate one yet, so the peer is plzn's own Tls12Client, which drives the
// client side of a secure renegotiation (`Tls12Client::renegotiate`).
//
// Two acceptance paths are covered:
//   * unprompted: the ClientHello arrives while the server waits on
//     application data (`read_app_data` runs the second handshake, then
//     returns the data sent under the new keys);
//   * stepped: the flow spells out `recv ClientHello` after the initial
//     Finished (`do_handshake_step` starts the renegotiation).

use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use plzn::ir::{HandshakeStep, MessageKind};
use plzn::server::certs::{CertBundle, KeyType};
use plzn::tls::driver::{Tls12Client, Tls12ClientConfig};
use plzn::tls::server12::{Tls12Server, Tls12ServerConfig};
use plzn::transport::{TcpDialFactory, TcpTransport, UutFactory};

fn server_config(bundle: &CertBundle) -> Tls12ServerConfig {
    Tls12ServerConfig {
        version: plzn::tls::record::TlsVersion::Tls12,
        cert_der: bundle.cert_der.clone(),
        private_key_der: bundle.key_pkcs8_der.clone(),
        chains: Vec::new(),
        seed: [0x5e; 32],
        send_overrides: Vec::new(),
        recv_matchers: Vec::new(),
        send_mutations: Vec::new(),
        send_ext_deltas: Vec::new(),
        cipher_suites: Vec::new(),
        groups: Vec::new(),
        signature_schemes: Vec::new(),
        psk: None,
        cert_request_authorities: Vec::new(),
        resumption: None,
        force_resumption: false,
        issue_tickets: false,
        offer_raw_public_key: false,
    }
}

#[test]
fn tls12_server_negotiates_renegotiation_info_only_when_offered() {
    use plzn::tls::codec::{
        ClientHello, Extension, HS_CLIENT_HELLO, HS_SERVER_HELLO, decode_server_hello_body,
        encode_client_hello_body, encode_handshake,
    };
    use plzn::transport::MockTransport;

    let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
    for (extension, scsv) in [(false, false), (true, false), (false, true), (true, true)] {
        let transport = MockTransport::new("renegotiation-info-negotiation");
        let ch = ClientHello {
            legacy_version: 0x0303,
            random: [0xc1; 32],
            session_id: Vec::new(),
            cipher_suites: if scsv {
                vec![0xc02b, 0x00ff]
            } else {
                vec![0xc02b]
            },
            compression_methods: vec![0],
            extensions: if extension {
                vec![Extension::RenegotiationInfo(Vec::new())]
            } else {
                Vec::new()
            },
        };
        let hello = encode_handshake(
            HS_CLIENT_HELLO,
            &encode_client_hello_body(&ch).expect("valid ClientHello"),
        );
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        transport.push_incoming(&record);
        let mut server = Tls12Server::new(Box::new(transport.clone()), server_config(&bundle));
        server
            .do_handshake_step(&HandshakeStep::Recv(MessageKind::ClientHello))
            .unwrap();
        server
            .do_handshake_step(&HandshakeStep::Send(MessageKind::ServerHello))
            .unwrap();
        let reply = transport.written();
        assert_eq!(reply[5], HS_SERVER_HELLO);
        // Skip the five-byte record header and four-byte handshake header.
        let sh = decode_server_hello_body(&reply[9..]).unwrap();
        assert_eq!(
            sh.extensions
                .iter()
                .any(|e| matches!(e, Extension::RenegotiationInfo(data) if data.is_empty())),
            extension || scsv,
            "extension={extension}, scsv={scsv}",
        );
    }
}

/// plzn's TLS 1.2 client: handshake, one round trip, a client-initiated
/// renegotiation, one more round trip under the new keys. Returns both replies.
fn run_plzn_client(addr: SocketAddr) -> (Vec<u8>, Vec<u8>) {
    let transport = TcpDialFactory::new(addr)
        .with_read_timeout(Some(Duration::from_secs(5)))
        .open()
        .expect("connect");
    let cfg = Tls12ClientConfig::default_for("localhost", [0xc1; 32]);
    let mut client = Tls12Client::new(transport, cfg);
    client.do_handshake().expect("client initial handshake");
    client.write_app_data(b"first", &[]).expect("write first");
    let first = client.read_app_data().expect("read first reply");
    client
        .renegotiate()
        .expect("client-initiated renegotiation");
    client.write_app_data(b"second", &[]).expect("write second");
    let second = client.read_app_data().expect("read second reply");
    client.close().ok();
    (first, second)
}

fn accept(listener: &TcpListener, bundle: &CertBundle) -> Tls12Server {
    let (stream, _peer) = listener.accept().unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_nodelay(true).ok();
    let transport = TcpTransport::from_accepted(stream).unwrap();
    Tls12Server::new(Box::new(transport), server_config(bundle))
}

#[test]
fn tls12_server_accepts_client_initiated_renegotiation() {
    let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = thread::spawn(move || run_plzn_client(addr));

    let mut server = accept(&listener, &bundle);
    server.do_handshake().expect("server initial handshake");
    assert_eq!(server.read_app_data().expect("read first"), b"first");
    server
        .write_app_data(b"reply one", &[])
        .expect("write first reply");
    // The client's renegotiation ClientHello arrives here, while the server
    // waits on application data: the second handshake runs inside this read.
    assert_eq!(
        server.read_app_data().expect("read after renegotiation"),
        b"second"
    );
    server
        .write_app_data(b"reply two", &[])
        .expect("write second reply");
    server.close().ok();

    let (first, second) = client.join().expect("client thread panicked");
    assert_eq!(first, b"reply one");
    assert_eq!(second, b"reply two");
}

#[test]
fn tls12_server_steps_through_client_initiated_renegotiation() {
    use HandshakeStep::{Recv as R, Send as S};
    use MessageKind as MK;

    let bundle = CertBundle::generate(KeyType::EcdsaP256).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = thread::spawn(move || run_plzn_client(addr));

    let mut server = accept(&listener, &bundle);
    server.do_handshake().expect("server initial handshake");
    assert_eq!(server.read_app_data().expect("read first"), b"first");
    server
        .write_app_data(b"reply one", &[])
        .expect("write first reply");
    // An explicit `recv ClientHello` after the completed handshake starts the
    // renegotiation; the rest of the full server flight follows step by step.
    for step in [
        R(MK::ClientHello),
        S(MK::ServerHello),
        S(MK::Certificate),
        S(MK::ServerKeyExchange),
        S(MK::ServerHelloDone),
        R(MK::ClientKeyExchange),
        R(MK::ChangeCipherSpec),
        R(MK::Finished),
        S(MK::ChangeCipherSpec),
        S(MK::Finished),
    ] {
        server
            .do_handshake_step(&step)
            .unwrap_or_else(|e| panic!("renegotiation step {step:?}: {e:?}"));
    }
    assert_eq!(
        server.read_app_data().expect("read after renegotiation"),
        b"second"
    );
    server
        .write_app_data(b"reply two", &[])
        .expect("write second reply");
    server.close().ok();

    let (first, second) = client.join().expect("client thread panicked");
    assert_eq!(first, b"reply one");
    assert_eq!(second, b"reply two");
}
