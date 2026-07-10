//! QUIC-based tunnel server implementation.
//!
//! This module provides the [`Server`] struct, which represents a QUIC-based
//! tunnel server. The server can bind to a specific address, authenticate
//! clients, and serve TCP/UDP tunnels as negotiated by the client.

use crate::tcp::tcp_tunnel::TcpTunnel;
use crate::tcp::{StreamMessage, StreamSender};
use crate::tunnel_message::TunnelMessage;
use crate::udp::udp_server::{UdpMessage, UdpSender};
use crate::udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel};
use crate::{
    noprotection::NoProtectionServerConfig, pem_util, ServerConfig, TcpServer, TcpTunnelInInfo,
    Tunnel, TunnelConfig, TunnelType, UdpTunnelInInfo, UpstreamType, QUIC_CONNECTION_WINDOW,
    QUIC_MAX_CONCURRENT_BIDI_STREAMS, QUIC_SEND_WINDOW, QUIC_STREAM_RECEIVE_WINDOW,
    SUPPORTED_CIPHER_SUITES,
};
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use parking_lot::{Mutex, Once};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::IdleTimeout;
use quinn::VarInt;
use quinn::{Connection, Endpoint, SendStream, TransportConfig};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;

#[derive(Debug, Clone)]
struct ConnectedTcpInSession {
    bound_port: std::net::SocketAddr,
    conn: Connection,
    sender: StreamSender<TcpStream>,
    control: Arc<tokio::sync::Mutex<(quinn::SendStream, quinn::RecvStream)>>,
}

#[derive(Debug, Clone)]
struct ConnectedUdpInSession {
    bound_port: std::net::SocketAddr,
    conn: Connection,
    sender: UdpSender,
    control: Arc<tokio::sync::Mutex<(quinn::SendStream, quinn::RecvStream)>>,
}

#[derive(Debug)]
struct State {
    config: ServerConfig,
    endpoint: Option<Endpoint>,
    tcp_sessions: Vec<ConnectedTcpInSession>,
    udp_sessions: Vec<ConnectedUdpInSession>,
}

impl State {
    pub fn new(config: ServerConfig) -> Self {
        State {
            config,
            endpoint: None,
            tcp_sessions: Vec::new(),
            udp_sessions: Vec::new(),
        }
    }
}

#[derive(Debug)]
/// QUIC-based tunnel server. Binds to an address, authenticates clients, and
/// serves TCP/UDP tunnels as negotiated.
pub struct Server {
    inner_state: Arc<Mutex<State>>,
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock()).$field
    };
}

impl Server {
    /// Create a new server with the given runtime configuration.
    pub fn new(config: ServerConfig) -> Self {
        Server {
            inner_state: Arc::new(Mutex::new(State::new(config))),
        }
    }

    /// Bind the server endpoint and return the actual bound address.
    pub fn bind(&mut self) -> Result<SocketAddr> {
        let mut state = self.inner_state.lock();
        let config = state.config.clone();
        let addr: SocketAddr = config
            .addr
            .parse()
            .context(format!("invalid address: {}", config.addr))?;

        let quinn_server_cfg = Self::load_quinn_server_config(&config)?;
        let endpoint = quinn::Endpoint::server(quinn_server_cfg, addr).inspect_err(|e| {
            error!("failed to bind tunnel server on address: {addr}, err: {e}");
        })?;

        info!(
            "tunnel server is bound on address: {}, idle_timeout: {}",
            endpoint.local_addr()?,
            config.quic_timeout_ms
        );

        let ep = endpoint.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600 * 24)).await;
                match Self::load_quinn_server_config(&config) {
                    Ok(quinn_server_cfg) => {
                        info!("updated quinn server config!");
                        ep.set_server_config(Some(quinn_server_cfg));
                    }
                    Err(e) => {
                        error!("failed to load quinn server config:{e}");
                    }
                }
            }
        });

        state.endpoint = Some(endpoint);
        Ok(addr)
    }

    fn load_quinn_server_config(config: &ServerConfig) -> Result<quinn::ServerConfig> {
        let (certs, key) =
            Self::read_certs_and_key(config.cert_path.as_str(), config.key_path.as_str())
                .context("failed to read certificate or key")?;

        let default_provider = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: SUPPORTED_CIPHER_SUITES.into(),
            ..default_provider
        };

        let tls_server_cfg = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW));
        transport_cfg.receive_window(VarInt::from_u32(QUIC_CONNECTION_WINDOW));
        transport_cfg.send_window(QUIC_SEND_WINDOW);
        transport_cfg
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        transport_cfg.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

        if config.quic_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(config.quic_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg
                .keep_alive_interval(Some(Duration::from_millis(config.quic_timeout_ms * 2 / 3)));
        }
        transport_cfg
            .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS));

        let mut quinn_server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            NoProtectionServerConfig::new(Arc::new(QuicServerConfig::try_from(tls_server_cfg)?)),
        ));
        quinn_server_cfg.transport_config(Arc::new(transport_cfg));

        Ok(quinn_server_cfg)
    }

    pub async fn serve(&self) -> Result<()> {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            loop {
                interval.tick().await;
                Self::clear_expired_sessions(state.clone());
            }
        });

        let endpoint = inner_state!(self, endpoint).take().context("failed")?;
        while let Some(client_conn) = endpoint.accept().await {
            let state = self.inner_state.clone();
            let config = inner_state!(self, config).clone();
            tokio::spawn(async move {
                let client_conn = client_conn.await?;
                let (tun_type, quic_send, quic_recv) = Self::authenticate_connection(&config, client_conn, state.clone()).await?;

                let control = Arc::new(tokio::sync::Mutex::new((quic_send, quic_recv)));

                match tun_type {
                    TunnelType::TcpIn(mut info) => {
                        state.lock().tcp_sessions.push(ConnectedTcpInSession {
                            bound_port: info.bound_port,
                            conn: info.conn.clone(),
                            sender: info.tcp_server.clone_sender(),
                            control: control.clone(),
                        });

                        let mut tcp_receiver = info.tcp_server.take_receiver();

                        TcpTunnel::start_serving(
                            false,
                            &info.conn,
                            &mut tcp_receiver,
                            &mut None,
                            config.tcp_timeout_ms,
                        )
                        .await;

                        info.tcp_server.shutdown().await.ok();
                    }

                    TunnelType::UdpIn(mut info) => {
                        state.lock().udp_sessions.push(ConnectedUdpInSession {
                            bound_port: info.bound_port,
                            conn: info.conn.clone(),
                            sender: info.udp_server.clone_sender(),
                            control: control.clone(),
                        });

                        let mut udp_receiver = info.udp_server.take_receiver();
                        let udp_sender = info.udp_server.clone_sender();

                        UdpTunnel::start_serving(
                            &info.conn,
                            &udp_sender,
                            &mut udp_receiver,
                            config.udp_timeout_ms,
                        )
                        .await;

                        info.udp_server.shutdown().await.ok();
                    }
                }

                Ok::<(), anyhow::Error>(())
            });
        }
        info!("quit!");

        Ok(())
    }

    async fn authenticate_connection(
        config: &ServerConfig,
        conn: quinn::Connection,
        state: Arc<Mutex<State>>,
    ) -> Result<(TunnelType, quinn::SendStream, quinn::RecvStream)> {
        let remote_addr = &conn.remote_address();

        info!("authenticating connection, addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) = conn
            .accept_bi()
            .await
            .context(format!("login request not received in time: {remote_addr}"))?;

        info!("received bi_stream request: {remote_addr}");
        match TunnelMessage::recv(&mut quic_recv).await? {
            TunnelMessage::ReqLogin(login_info) => {
                info!("received ReqLogin request: {remote_addr}");

                Self::check_password(config.password.as_str(), login_info.password.as_str())?;

                let (tunnel_type, preempted) = match login_info.tunnel {
                    Tunnel::NetworkBased(tunnel_config) => {
                        Self::derive_tunnel_type(conn, &mut quic_send, &tunnel_config, config, state)
                            .await?
                    }
                    Tunnel::ChannelBased(_) => {
                        log_and_bail!("only network-based tunneling is supported");
                    }
                };

                if preempted {
                    TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccessPreempted).await?;
                } else {
                    TunnelMessage::send(&mut quic_send, &TunnelMessage::RespSuccess).await?;
                }
                info!("connection authenticated! addr: {remote_addr}");
                Ok((tunnel_type, quic_send, quic_recv))
            }

            _ => {
                log_and_bail!("received unepxected message");
            }
        }
    }

    async fn derive_tunnel_type(
        conn: quinn::Connection,
        quic_send: &mut SendStream,
        tunnel_config: &TunnelConfig,
        _config: &ServerConfig,
        state: Arc<Mutex<State>>,
    ) -> Result<(TunnelType, bool)> {
        let upstream_addr = tunnel_config.upstream.upstream_addr.ok_or_else(|| {
            anyhow::anyhow!("explicit port is required to start inbound tunneling")
        })?;

        if !upstream_addr.ip().is_unspecified() && !upstream_addr.ip().is_loopback() {
            log_and_bail!(
                "only loopback or unspecified IP is allowed for inbound tunelling: {upstream_addr}, or simply specify a port without the IP part"
            );
        }

        let mut preempted = false;
        let mut old_control = None;
        {
            let state = state.lock();
            if let Some(s) = state.tcp_sessions.iter().find(|s| s.bound_port == upstream_addr) {
                old_control = Some(s.control.clone());
            }
            if let Some(s) = state.udp_sessions.iter().find(|s| s.bound_port == upstream_addr) {
                old_control = Some(s.control.clone());
            }
        }

        if let Some(control) = old_control {
            let mut is_alive = false;
            {
                let mut guard = control.lock().await;
                let (old_send, old_recv) = &mut *guard;
                if TunnelMessage::send(old_send, &TunnelMessage::Ping).await.is_ok() {
                    if let Ok(Ok(TunnelMessage::Pong)) = tokio::time::timeout(Duration::from_millis(800), TunnelMessage::recv(old_recv)).await {
                        is_alive = true;
                    }
                }
            }
            if is_alive {
                log_and_bail!("Connection for port {upstream_addr} is still alive! Rejecting connection.");
            } else {
                let mut state = state.lock();
                if let Some(idx) = state.tcp_sessions.iter().position(|s| s.bound_port == upstream_addr) {
                    let sess = state.tcp_sessions.remove(idx);
                    sess.conn.close(quinn::VarInt::from_u32(2), b"preempted");
                }
                if let Some(idx) = state.udp_sessions.iter().position(|s| s.bound_port == upstream_addr) {
                    let sess = state.udp_sessions.remove(idx);
                    sess.conn.close(quinn::VarInt::from_u32(2), b"preempted");
                }
                preempted = true;
            }
        }

        if preempted {
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        }

        let tunnel_type = match tunnel_config.upstream.upstream_type {
            UpstreamType::Tcp => {
                let tcp_server = match TcpServer::bind_and_start(upstream_addr).await {
                    Ok(tcp_server) => tcp_server,
                    Err(e) => {
                        TunnelMessage::send_failure(
                            quic_send,
                            format!("udp server failed to bind at: {upstream_addr}"),
                        )
                        .await?;
                        log_and_bail!("tcp_IN login rejected: {e}");
                    }
                };

                TunnelType::TcpIn(TcpTunnelInInfo {
                    bound_port: upstream_addr,
                    conn,
                    tcp_server,
                })
            }
            UpstreamType::Udp => {
                let udp_server = match UdpServer::bind_and_start(upstream_addr).await {
                    Ok(udp_server) => udp_server,
                    Err(e) => {
                        TunnelMessage::send_failure(
                            quic_send,
                            format!("udp server failed to bind at: {upstream_addr}"),
                        )
                        .await?;
                        log_and_bail!("udp_IN login rejected: {e}");
                    }
                };
                TunnelType::UdpIn(UdpTunnelInInfo {
                    bound_port: upstream_addr,
                    conn,
                    udp_server,
                })
            }
        };

        Ok((tunnel_type, preempted))
    }

    fn clear_expired_sessions(state: Arc<Mutex<State>>) {
        tokio::spawn(async move {
            let mut state = state.lock();
            state.udp_sessions.retain(|sess| {
                if sess.conn.close_reason().is_some() {
                    let sess = sess.clone();
                    tokio::spawn(async move {
                        sess.sender.send(UdpMessage::Quit).await.ok();
                        debug!("dropped udp session: {}", sess.conn.remote_address());
                    });
                    false
                } else {
                    true
                }
            });

            state.tcp_sessions.retain(|sess| {
                if sess.conn.close_reason().is_some() {
                    let sess = sess.clone();
                    tokio::spawn(async move {
                        sess.sender.send(StreamMessage::Quit).await.ok();
                        debug!("dropped tcp session: {}", sess.conn.remote_address());
                    });
                    false
                } else {
                    true
                }
            });
        });
    }

    fn read_certs_and_key(
        cert_path: &str,
        key_path: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let (certs, key) = if cert_path.is_empty() {
            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                info!("will use auto-generated self-signed certificate.");
                warn!("============================= WARNING ==============================");
                warn!("No valid certificate path is provided, a self-signed certificate");
                warn!("for the domain \"localhost\" is generated.");
                warn!("============== Be cautious, this is for TEST only!!! ===============");
            });

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let cert = CertificateDer::from(cert.cert);
            (vec![cert], PrivateKeyDer::Pkcs8(key))
        } else {
            let certs = pem_util::load_certificates_from_pem(cert_path)
                .context(format!("failed to read cert file: {cert_path}"))?;
            let key = pem_util::load_private_key_from_pem(key_path)
                .context(format!("failed to read key file: {key_path}"))?;
            (certs, key)
        };

        Ok((certs, key))
    }

    fn check_password(password1: &str, password2: &str) -> Result<()> {
        if password1 != password2 {
            log_and_bail!("passwords don't match!");
        }
        Ok(())
    }
}
