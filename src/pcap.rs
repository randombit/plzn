// PCAP capture: a UutTransport wrapper that records every byte
// sent/received into a pcap file with synthetic TCP/IP/Ethernet
// headers, openable in Wireshark for offline analysis.
//
// The capture is transparent to the TLS driver — it just sees
// Read + Write as before. All the framing (Ethernet → IPv4 →
// TCP → payload) is synthesised from fixed loopback addresses
// and tracked sequence numbers so Wireshark can reassemble the
// TCP stream and decode the TLS records.
//
// Usage: wrap an existing transport before handing it to the
// driver:
//
//   let transport = factory.open()?;
//   let transport = CapturingTransport::new(transport, &path)?;
//
// The pcap file is flushed on every packet and closed on Drop.

use std::fs::File;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use etherparse::PacketBuilder;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};

use crate::transport::UutTransport;

/// Direction of a captured packet, from the harness's perspective.
#[derive(Clone, Copy)]
enum Dir {
    /// Harness → peer (our write = client-to-server in `uut server`
    /// mode, server-to-client in `uut client` mode).
    Send,
    /// Peer → harness (our read).
    Recv,
}

pub struct CapturingTransport {
    inner: Box<dyn UutTransport>,
    writer: PcapWriter<File>,
    // Synthetic TCP state for realistic Wireshark display.
    // "Client" = port 49152 on 127.0.0.1, "Server" = port 4433
    // on 127.0.0.2. These are arbitrary but stable.
    client_seq: u32,
    server_seq: u32,
    /// True if the harness is the client (uut server).
    /// Affects which direction maps to which TCP endpoint.
    harness_is_client: bool,
}

impl CapturingTransport {
    /// Wrap `inner` and start writing packets to `path`.
    ///
    /// `harness_is_client`: true for `uut server` (harness
    /// dials), false for `uut client` (harness listens). This
    /// determines which synthetic IP:port pair represents the
    /// harness vs the peer in the pcap.
    pub fn new(
        inner: Box<dyn UutTransport>,
        path: &std::path::Path,
        harness_is_client: bool,
    ) -> io::Result<Self> {
        let file = File::create(path)?;
        let header = PcapHeader {
            datalink: pcap_file::DataLink::ETHERNET,
            ..PcapHeader::default()
        };
        let writer = PcapWriter::with_header(file, header).map_err(io::Error::other)?;
        Ok(Self {
            inner,
            writer,
            client_seq: 1000,
            server_seq: 2000,
            harness_is_client,
        })
    }

    fn write_packet(&mut self, dir: Dir, data: &[u8]) {
        // Map direction to TCP endpoints.
        let (src_ip, dst_ip, src_port, dst_port, seq) = match (dir, self.harness_is_client) {
            (Dir::Send, true) | (Dir::Recv, false) => {
                // Client → Server
                let seq = self.client_seq;
                self.client_seq = self.client_seq.wrapping_add(data.len() as u32);
                ([127, 0, 0, 1], [127, 0, 0, 2], 49152u16, 4433u16, seq)
            }
            (Dir::Recv, true) | (Dir::Send, false) => {
                // Server → Client
                let seq = self.server_seq;
                self.server_seq = self.server_seq.wrapping_add(data.len() as u32);
                ([127, 0, 0, 2], [127, 0, 0, 1], 4433u16, 49152u16, seq)
            }
        };

        // Build the full Ethernet/IP/TCP packet.
        let builder = PacketBuilder::ethernet2(
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x01], // src MAC
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x02], // dst MAC
        )
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, seq, 65535);

        let mut packet_bytes = Vec::with_capacity(54 + data.len());
        // etherparse writes headers + payload into the vec.
        if builder.write(&mut packet_bytes, data).is_err() {
            return; // silently skip on serialisation error
        }

        // Timestamp.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);

        let pcap_packet = PcapPacket::new(now, packet_bytes.len() as u32, &packet_bytes);
        // Best-effort write — don't let pcap errors break the test.
        let _ = self.writer.write_packet(&pcap_packet);
    }
}

impl Read for CapturingTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.write_packet(Dir::Recv, &buf[..n]);
        }
        Ok(n)
    }
}

impl Write for CapturingTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        if n > 0 {
            self.write_packet(Dir::Send, &buf[..n]);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl UutTransport for CapturingTransport {
    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }

    fn close_reset(&mut self) -> io::Result<()> {
        self.inner.close_reset()
    }

    fn description(&self) -> String {
        format!("{} + pcap", self.inner.description())
    }

    fn set_read_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    fn set_write_timeout(&mut self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }
}
