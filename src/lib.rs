//! rstun: A lightweight QUIC-based TCP/UDP tunneling library.
//!
//! This crate provides the core building blocks for a client/server tunneling
//! system over QUIC (via quinn). It exposes simple configuration types for
//! defining tunnels and helpers to start client and server components.
//!
//! Binaries rstunc (client) and rstund (server) are provided under src/bin.

mod client;
mod noprotection;
mod pem_util;
mod server;
mod tcp;

mod tunnel_message;
mod udp;
mod util;

use anyhow::{Context, Result};
use byte_pool::BytePool;
pub use client::Client;
pub use client::ClientState;
use log::warn;
use rs_utilities::log_and_bail;
use rustls::crypto::ring::cipher_suite;
use serde::Deserialize;
use serde::Serialize;
pub use server::Server;
use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::{net::SocketAddr, ops::Deref, sync::LazyLock};
pub use tcp::tcp_server::TcpServer;
pub use tcp::{AsyncStream, StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use tunnel_message::LoginInfo;
use udp::udp_server::UdpServer;
pub use udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};

/// Human-readable tunnel direction used in CLI/config strings.
pub const TUNNEL_MODE_IN: &str = "IN";
/// Human-readable tunnel direction used in CLI/config strings.
pub const TUNNEL_MODE_OUT: &str = "OUT";
/// Maximum UDP payload size representable by the tunnel wire format.
pub const UDP_PACKET_SIZE: usize = u16::MAX as usize;

static BUFFER_POOL: LazyLock<BytePool<Vec<u8>>> = LazyLock::new(BytePool::new);

pub(crate) const QUIC_STREAM_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
pub(crate) const QUIC_CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;
pub(crate) const QUIC_SEND_WINDOW: u64 = 64 * 1024 * 1024;
pub(crate) const QUIC_MAX_CONCURRENT_BIDI_STREAMS: u32 = 4096;

/// List of supported TLS cipher suites (as CLI-friendly strings).
///
/// These map to TLS 1.3 cipher suites in rustls. Strings are accepted by
/// [`SelectedCipherSuite`]'s FromStr implementation and by the client binary.
pub const SUPPORTED_CIPHER_SUITE_STRS: &[&str] = &[
    "aes-128-gcm",
    "chacha20-poly1305",
    "aes-256-gcm",
    // the following ciphers don't work at the moement, will look into it later
    // "ecdhe-ecdsa-aes256-gcm",
    // "ecdhe-ecdsa-aes128-gcm",
    // "ecdhe-ecdsa-chacha20-poly1305",
    // "ecdhe-rsa-aes256-gcm",
    // "ecdhe-rsa-aes128-gcm",
    // "ecdhe-rsa-chacha20-poly1305",
];

/// Supported TLS cipher suites used to build rustls/quinn configs.
pub static SUPPORTED_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    cipher_suite::TLS13_AES_128_GCM_SHA256,
    cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS13_AES_256_GCM_SHA384,
];

/// Wrapper type to parse a user-provided cipher suite string into a
/// rustls SupportedCipherSuite.
pub(crate) struct SelectedCipherSuite(rustls::SupportedCipherSuite);

impl std::str::FromStr for SelectedCipherSuite {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20-poly1305" => Ok(SelectedCipherSuite(
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            )),
            "aes-256-gcm" => Ok(SelectedCipherSuite(cipher_suite::TLS13_AES_256_GCM_SHA384)),
            "aes-128-gcm" => Ok(SelectedCipherSuite(cipher_suite::TLS13_AES_128_GCM_SHA256)),
            // "ecdhe-ecdsa-aes256-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            // )),
            // "ecdhe-ecdsa-aes128-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            // )),
            // "ecdhe-ecdsa-chacha20-poly1305" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            // )),
            // "ecdhe-rsa-aes256-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            // )),
            // "ecdhe-rsa-aes128-gcm" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            // )),
            // "ecdhe-rsa-chacha20-poly1305" => Ok(SelectedCipherSuite(
            //     rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            // )),
            _ => Ok(SelectedCipherSuite(
                cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            )),
        }
    }
}

impl Deref for SelectedCipherSuite {
    type Target = rustls::SupportedCipherSuite;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Info about an outbound TCP tunnel (client connects to server, server dials upstream).
#[derive(Debug)]
pub struct TcpTunnelOutInfo {
    conn: quinn::Connection,
    upstream_addr: SocketAddr,
}

/// Info about an inbound TCP tunnel (client accepts local TCP and forwards to server).
#[derive(Debug)]
pub struct TcpTunnelInInfo {
    conn: quinn::Connection,
    tcp_server: TcpServer,
}

/// Info about an outbound UDP tunnel (client connects to server, server sends to upstream).
#[derive(Debug)]
pub struct UdpTunnelOutInfo {
    conn: quinn::Connection,
    upstream_addr: SocketAddr,
}

/// Info about an inbound UDP tunnel (client accepts local UDP and forwards to server).
#[derive(Debug)]
pub struct UdpTunnelInInfo {
    conn: quinn::Connection,
    udp_server: UdpServer,
}

/// Negotiated tunnel role and transport type after authentication.
#[derive(Debug)]
pub enum TunnelType {
    /// TCP OUT mode: server will connect to upstream.
    TcpOut(TcpTunnelOutInfo),
    /// TCP IN mode: server spawns a local TCP listener for the client.
    TcpIn(TcpTunnelInInfo),
    /// UDP OUT mode: server will send/receive datagrams to/from upstream.
    UdpOut(UdpTunnelOutInfo),
    /// UDP IN mode: server spawns a local UDP socket for the client.
    UdpIn(UdpTunnelInInfo),
    /// Channel-based TCP OUT: upstream decided dynamically by the client.
    DynamicUpstreamTcpOut(quinn::Connection),
    /// Channel-based UDP OUT: upstream decided dynamically by the client.
    DynamicUpstreamUdpOut(quinn::Connection),
}

/// Direction of a tunnel: Inbound or Outbound relative to the client.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TunnelMode {
    In,
    Out,
}

impl Display for TunnelMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Out => write!(f, "OUT"),
        }
    }
}

/// Transport type for a tunnel: TCP or UDP.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum UpstreamType {
    Tcp,
    Udp,
}

impl Display for UpstreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

/// Upstream endpoint definition.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// Destination address on the peer side (None means use server default in OUT mode).
    pub upstream_addr: Option<SocketAddr>,
    /// Transport type to use when forwarding to the upstream.
    pub upstream_type: UpstreamType,
}

impl Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.upstream_addr {
            Some(addr) => write!(f, "{}", addr),
            None => write!(f, "PeerDefault"),
        }
    }
}

/// A single tunnel specification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// Direction of the tunnel, relative to the client.
    pub mode: TunnelMode,
    /// Local listen address for NetworkBased tunnels (Some) or None for ChannelBased.
    pub local_server_addr: Option<SocketAddr>,
    /// Upstream config on the server side.
    pub upstream: Upstream,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tunnel {
    /// Tunnel driven by local networking (binds on a local address).
    NetworkBased(TunnelConfig),
    /// Tunnel driven by in-process channels (no local binding).
    ChannelBased(UpstreamType),
}

/// Client-side runtime configuration.
#[derive(Debug, Default, Clone)]
pub struct ClientConfig {
    /// Path to a PEM certificate for server identity (self-signed use-case).
    pub cert_path: String,
    /// Preferred TLS cipher suite string (see SUPPORTED_CIPHER_SUITE_STRS).
    pub cipher: String,
    /// Server address in "host:port".
    pub server_addr: String,
    /// Shared password for authentication.
    pub password: String,
    /// Wait time before retrying a failed connection.
    pub wait_before_retry_ms: u64,
    /// QUIC idle timeout (ms).
    pub quic_timeout_ms: u64,
    /// TCP idle timeout (ms).
    pub tcp_timeout_ms: u64,
    /// UDP idle timeout (ms).
    pub udp_timeout_ms: u64,
    /// Periodic endpoint migration interval (ms); 0 disables.
    pub hop_interval_ms: u64,
    /// Tunnel definitions to start.
    pub tunnels: Vec<TunnelConfig>,
    /// DNS-over-TLS servers (domain names). Takes precedence over dns_servers if non-empty.
    pub dot_servers: Vec<String>,
    /// Plain DNS servers (IP addresses).
    pub dns_servers: Vec<String>,
    /// Number of async worker threads.
    pub workers: usize,
}

/// Server-side runtime configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address for the server (host:port).
    pub addr: String,
    /// Shared password for authentication.
    pub password: String,
    /// Path to certificate PEM.
    pub cert_path: String,
    /// Path to private key PEM.
    pub key_path: String,
    /// QUIC idle timeout (ms).
    pub quic_timeout_ms: u64,
    /// TCP idle timeout (ms).
    pub tcp_timeout_ms: u64,
    /// UDP idle timeout (ms).
    pub udp_timeout_ms: u64,

    /// for TunnelOut only
    pub default_tcp_upstream: Option<SocketAddr>,
    /// for TunnelOut only
    pub default_udp_upstream: Option<SocketAddr>,

    /// 0.0.0.0:3515
    pub dashboard_server: String,
    /// user:password
    pub dashboard_server_credential: String,
}

impl ClientConfig {
    /// Create a ClientConfig by parsing CLI-style mapping strings.
    ///
    /// - tcp_addr_mappings / udp_addr_mappings: comma-separated entries in the form
    ///   MODE^SRC^DEST where MODE is IN|OUT, SRC is [ip:]port, DEST is [ip:]port or ANY
    ///   (ANY means use peer default, only valid in OUT mode).
    /// - dot / dns: comma-separated servers.
    /// - workers: set to 0 to use all logical CPUs.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        server_addr: &str,
        password: &str,
        cert: &str,
        cipher: &str,
        tcp_addr_mappings: &str,
        udp_addr_mappings: &str,
        dot: &str,
        dns: &str,
        workers: usize,
        wait_before_retry_ms: u64,
        mut quic_timeout_ms: u64,
        mut tcp_timeout_ms: u64,
        mut udp_timeout_ms: u64,
        mut hop_interval_ms: u64,
    ) -> Result<ClientConfig> {
        if tcp_addr_mappings.is_empty() && udp_addr_mappings.is_empty() {
            log_and_bail!("must specify either --tcp-mappings or --udp-mappings, or both");
        }

        if quic_timeout_ms == 0 {
            quic_timeout_ms = 30000;
        }
        if tcp_timeout_ms == 0 {
            tcp_timeout_ms = 30000;
        }
        if udp_timeout_ms == 0 {
            udp_timeout_ms = 5000;
        }
        if hop_interval_ms != 0 && hop_interval_ms < 5000 {
            warn!("Endpoint migration interval: {hop_interval_ms} ms is too low and has been forcibly set to 5000 ms to prevent potential network failures due to excessive port or NAT resource exhaustion."
                    );
            hop_interval_ms = 5000;
        }

        let mut config = ClientConfig {
            cert_path: cert.to_string(),
            cipher: cipher.to_string(),
            server_addr: if !server_addr.contains(':') {
                format!("127.0.0.1:{server_addr}")
            } else {
                server_addr.to_string()
            },
            password: password.to_string(),
            workers: if workers > 0 {
                workers
            } else {
                std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
            },
            wait_before_retry_ms,
            quic_timeout_ms,
            tcp_timeout_ms,
            udp_timeout_ms,
            hop_interval_ms,
            dot_servers: dot.split(',').map(|s| s.to_string()).collect(),
            dns_servers: dns.split(',').map(|s| s.to_string()).collect(),
            ..ClientConfig::default()
        };

        parse_addr_mappings(tcp_addr_mappings, UpstreamType::Tcp, &mut config.tunnels)?;
        parse_addr_mappings(udp_addr_mappings, UpstreamType::Udp, &mut config.tunnels)?;

        Ok(config)
    }
}

fn parse_addr_mappings(
    mappings: &str,
    upstream_type: UpstreamType,
    v: &mut Vec<TunnelConfig>,
) -> Result<()> {
    if mappings.is_empty() {
        return Ok(());
    }

    for mapping in mappings.split(',') {
        let parts: Vec<&str> = mapping.split('^').collect();
        if parts.len() != 3 {
            log_and_bail!("Invalid mapping format, expected TYPE^SRC^DEST");
        }

        let tunnel_mode = parts[0];
        if tunnel_mode != "OUT" && tunnel_mode != "IN" {
            log_and_bail!("Invalid tunnel type, expected OUT or IN");
        }

        let parse_addr = |addr: &str| -> Result<Option<SocketAddr>> {
            if addr == "ANY" {
                return Ok(None);
            }

            // Handle port-only case
            let port = addr.parse::<u16>();
            if let Ok(port) = port {
                return Ok(Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port,
                )));
            }

            // Parse full SocketAddr
            Ok(Some(addr.parse().with_context(|| {
                format!("Invalid address format '{addr}', expected IP:PORT or PORT")
            })?))
        };

        let local_server_addr = parse_addr(parts[1])?;
        if local_server_addr.is_none() {
            log_and_bail!("'ANY' is not allowed as local_server_addr");
        }
        let upstream_addr = parse_addr(parts[2])?;

        v.push(TunnelConfig {
            mode: if tunnel_mode == "IN" {
                TunnelMode::In
            } else {
                TunnelMode::Out
            },
            upstream: Upstream {
                upstream_addr,
                upstream_type: upstream_type.clone(),
            },
            local_server_addr,
        });
    }

    Ok(())
}

/// Create a socket address with an unspecified IP and port 0, suitable for binding.
pub fn socket_addr_with_unspecified_ip_port(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

