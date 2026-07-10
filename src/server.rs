//! QUIC-based tunnel server implementation.
//!
//! This module provides the [`Server`] struct, which represents a QUIC-based
//! tunnel server. The server can bind to a specific address, authenticate
//! clients, and serve TCP/UDP tunnels as negotiated by the client.

use crate::tcp::tcp_tunnel::TcpTunnel;
use crate::tunnel_message::{LoginResponse, TunnelMessage};
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
use quinn::{Connection, Endpoint, TransportConfig};
use rs_utilities::log_and_bail;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::time::Duration;

const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    upstream_type: UpstreamType,
    port: u16,
}

impl SessionKey {
    fn new(upstream_type: UpstreamType, addr: SocketAddr) -> Self {
        Self {
            upstream_type,
            port: addr.port(),
        }
    }
}

#[derive(Debug, Clone)]
enum SessionListener {
    Tcp(TcpServer),
    Udp(UdpServer),
}

impl SessionListener {
    async fn shutdown(&self) {
        match self {
            Self::Tcp(server) => {
                let mut server = server.clone();
                server.shutdown().await.ok();
            }
            Self::Udp(server) => {
                let mut server = server.clone();
                server.shutdown().await.ok();
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ConnectedSession {
    id: u64,
    conn: Connection,
    listener: SessionListener,
}

#[derive(Debug)]
struct AuthenticatedTunnel {
    tunnel_type: TunnelType,
    key: SessionKey,
    session_id: u64,
}

struct PreparedTunnel {
    tunnel_type: TunnelType,
    key: SessionKey,
    _key_guard: tokio::sync::OwnedMutexGuard<()>,
}

#[derive(Debug)]
struct State {
    config: ServerConfig,
    endpoint: Option<Endpoint>,
    sessions: HashMap<SessionKey, ConnectedSession>,
    session_locks: HashMap<SessionKey, Weak<tokio::sync::Mutex<()>>>,
    next_session_id: u64,
}

impl State {
    pub fn new(config: ServerConfig) -> Self {
        State {
            config,
            endpoint: None,
            sessions: HashMap::new(),
            session_locks: HashMap::new(),
            next_session_id: 1,
        }
    }
}

#[derive(Debug, Clone)]
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

        let bound_addr = endpoint.local_addr()?;
        info!(
            "tunnel server is bound on address: {}, idle_timeout: {}",
            bound_addr, config.quic_timeout_ms
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
        Ok(bound_addr)
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
        let endpoint = inner_state!(self, endpoint)
            .clone()
            .context("server is not bound")?;
        while let Some(client_conn) = endpoint.accept().await {
            let state = self.inner_state.clone();
            let config = inner_state!(self, config).clone();
            tokio::spawn(async move {
                match client_conn.await {
                    Ok(client_conn) => {
                        if let Err(error) =
                            Self::serve_connection(&config, client_conn, state).await
                        {
                            warn!("client session failed: {error:#}");
                        }
                    }
                    Err(error) => warn!("QUIC handshake failed: {error}"),
                }
            });
        }
        info!("quit!");

        Ok(())
    }

    /// Gracefully stop accepting connections, close active sessions, and drain QUIC.
    pub async fn shutdown(&self) {
        let (endpoint, sessions) = {
            let mut state = self.inner_state.lock();
            (
                state.endpoint.take(),
                state
                    .sessions
                    .drain()
                    .map(|(_, session)| session)
                    .collect::<Vec<_>>(),
            )
        };

        if let Some(endpoint) = &endpoint {
            endpoint.close(quinn::VarInt::from_u32(1), b"server shutting down");
        }

        let mut tasks = tokio::task::JoinSet::new();
        for session in sessions {
            session
                .conn
                .close(quinn::VarInt::from_u32(1), b"server shutting down");
            tasks.spawn(async move {
                session.listener.shutdown().await;
            });
        }
        while tasks.join_next().await.is_some() {}

        if let Some(endpoint) = endpoint {
            tokio::time::timeout(Duration::from_secs(3), endpoint.wait_idle())
                .await
                .ok();
        }
    }

    async fn serve_connection(
        config: &ServerConfig,
        conn: quinn::Connection,
        state: Arc<Mutex<State>>,
    ) -> Result<()> {
        let authenticated =
            Self::authenticate_connection(config, conn.clone(), state.clone()).await?;
        let key = authenticated.key;
        let session_id = authenticated.session_id;

        match authenticated.tunnel_type {
            TunnelType::TcpIn(mut info) => {
                let mut tcp_receiver = info.tcp_server.take_receiver()?;
                let mut pending_request = None;
                tokio::select! {
                    _ = info.conn.closed() => {
                        debug!("TCP session closed: {}", info.conn.remote_address());
                    }
                    _ = TcpTunnel::start_serving(
                        false,
                        &info.conn,
                        &mut tcp_receiver,
                        &mut pending_request,
                        config.tcp_timeout_ms,
                    ) => {}
                }
                info.tcp_server.shutdown().await.ok();
            }
            TunnelType::UdpIn(mut info) => {
                let mut udp_receiver = info.udp_server.take_receiver()?;
                let udp_sender = info.udp_server.clone_sender();
                tokio::select! {
                    _ = info.conn.closed() => {
                        debug!("UDP session closed: {}", info.conn.remote_address());
                    }
                    _ = UdpTunnel::start_serving(
                        &info.conn,
                        &udp_sender,
                        &mut udp_receiver,
                        config.udp_timeout_ms,
                    ) => {}
                }
                info.udp_server.shutdown().await.ok();
            }
        }

        conn.close(quinn::VarInt::from_u32(3), b"session ended");
        Self::remove_session_if_id(&state, key, session_id);
        Ok(())
    }

    async fn authenticate_connection(
        config: &ServerConfig,
        conn: quinn::Connection,
        state: Arc<Mutex<State>>,
    ) -> Result<AuthenticatedTunnel> {
        let remote_addr = &conn.remote_address();

        info!("authenticating connection, addr:{remote_addr}");
        let (mut quic_send, mut quic_recv) =
            tokio::time::timeout(AUTHENTICATION_TIMEOUT, conn.accept_bi())
                .await
                .context(format!("login stream timed out: {remote_addr}"))??;

        info!("received bi_stream request: {remote_addr}");
        let login_message =
            tokio::time::timeout(AUTHENTICATION_TIMEOUT, TunnelMessage::recv(&mut quic_recv))
                .await
                .context(format!("login message timed out: {remote_addr}"))??;
        let login_request = match login_message {
            TunnelMessage::Login(request) => request,
            TunnelMessage::LoginResponse(_) => {
                TunnelMessage::send_rejection(
                    &mut quic_send,
                    "expected a login request".to_string(),
                )
                .await?;
                log_and_bail!("received unexpected message");
            }
        };
        info!("received login request: {remote_addr}");

        if let Err(error) =
            Self::check_password(config.password.as_str(), login_request.password.as_str())
        {
            TunnelMessage::send_rejection(&mut quic_send, error.to_string()).await?;
            return Err(error);
        }

        let prepared = match login_request.tunnel {
            Tunnel::NetworkBased(tunnel_config) => {
                Self::derive_tunnel_type(conn.clone(), &tunnel_config, state.clone()).await
            }
            Tunnel::ChannelBased(_) => {
                Err(anyhow::anyhow!("only network-based tunneling is supported"))
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                TunnelMessage::send_rejection(&mut quic_send, error.to_string()).await?;
                return Err(error);
            }
        };

        let listener = match &prepared.tunnel_type {
            TunnelType::TcpIn(info) => SessionListener::Tcp(info.tcp_server.clone()),
            TunnelType::UdpIn(info) => SessionListener::Udp(info.udp_server.clone()),
        };
        let session_id = {
            let mut state = state.lock();
            let session_id = state.next_session_id;
            state.next_session_id = state.next_session_id.wrapping_add(1).max(1);
            let replaced = state.sessions.insert(
                prepared.key,
                ConnectedSession {
                    id: session_id,
                    conn: conn.clone(),
                    listener: listener.clone(),
                },
            );
            debug_assert!(replaced.is_none());
            session_id
        };

        let response = TunnelMessage::LoginResponse(LoginResponse::Accepted);
        if let Err(error) = TunnelMessage::send(&mut quic_send, &response).await {
            Self::remove_session_if_id(&state, prepared.key, session_id);
            conn.close(quinn::VarInt::from_u32(4), b"login response failed");
            listener.shutdown().await;
            return Err(error);
        }
        info!("connection authenticated! addr: {remote_addr}");

        Ok(AuthenticatedTunnel {
            tunnel_type: prepared.tunnel_type,
            key: prepared.key,
            session_id,
        })
    }

    async fn derive_tunnel_type(
        conn: quinn::Connection,
        tunnel_config: &TunnelConfig,
        state: Arc<Mutex<State>>,
    ) -> Result<PreparedTunnel> {
        let upstream_addr = tunnel_config.upstream.upstream_addr.ok_or_else(|| {
            anyhow::anyhow!("explicit port is required to start inbound tunneling")
        })?;

        if upstream_addr.port() == 0 {
            log_and_bail!("an explicit non-zero port is required for inbound tunneling");
        }

        if !upstream_addr.ip().is_unspecified() && !upstream_addr.ip().is_loopback() {
            log_and_bail!(
                "only loopback or unspecified IP is allowed for inbound tunelling: {upstream_addr}, or simply specify a port without the IP part"
            );
        }

        let key = SessionKey::new(tunnel_config.upstream.upstream_type, upstream_addr);
        let key_lock = Self::session_lock(&state, key);
        let key_guard = key_lock.lock_owned().await;
        let incumbent = { state.lock().sessions.get(&key).cloned() };

        if let Some(incumbent) = incumbent {
            let connection_closed = incumbent.conn.close_reason().is_some();
            if !connection_closed {
                log_and_bail!(
                    "{} port {} is owned by an active client",
                    key.upstream_type,
                    key.port
                );
            }

            Self::remove_session_if_id(&state, key, incumbent.id);
            incumbent
                .conn
                .close(quinn::VarInt::from_u32(2), b"replacing closed session");
            incumbent.listener.shutdown().await;
        }

        let tunnel_type = match tunnel_config.upstream.upstream_type {
            UpstreamType::Tcp => {
                let tcp_server = TcpServer::bind_and_start(upstream_addr)
                    .await
                    .with_context(|| format!("TCP server failed to bind at {upstream_addr}"))?;
                let bound_addr = tcp_server.addr();

                TunnelType::TcpIn(TcpTunnelInInfo {
                    bound_port: bound_addr,
                    conn,
                    tcp_server,
                })
            }
            UpstreamType::Udp => {
                let udp_server = UdpServer::bind_and_start(upstream_addr)
                    .await
                    .with_context(|| format!("UDP server failed to bind at {upstream_addr}"))?;
                let bound_addr = udp_server.addr();
                TunnelType::UdpIn(UdpTunnelInInfo {
                    bound_port: bound_addr,
                    conn,
                    udp_server,
                })
            }
        };

        Ok(PreparedTunnel {
            tunnel_type,
            key,
            _key_guard: key_guard,
        })
    }

    fn session_lock(state: &Arc<Mutex<State>>, key: SessionKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut state = state.lock();
        state
            .session_locks
            .retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = state.session_locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }

        let lock = Arc::new(tokio::sync::Mutex::new(()));
        state.session_locks.insert(key, Arc::downgrade(&lock));
        lock
    }

    fn remove_session_if_id(
        state: &Arc<Mutex<State>>,
        key: SessionKey,
        session_id: u64,
    ) -> Option<ConnectedSession> {
        let mut state = state.lock();
        if state
            .sessions
            .get(&key)
            .is_some_and(|session| session.id == session_id)
        {
            state.sessions.remove(&key)
        } else {
            None
        }
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

#[cfg(test)]
mod tests {
    use super::{Server, SessionKey};
    use crate::{ServerConfig, UpstreamType};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn session_keys_separate_transports_and_serialize_port_aliases() {
        let ipv4 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 8080);
        let ipv6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8080);

        assert_ne!(
            SessionKey::new(UpstreamType::Tcp, ipv4),
            SessionKey::new(UpstreamType::Udp, ipv4)
        );
        assert_eq!(
            SessionKey::new(UpstreamType::Tcp, ipv4),
            SessionKey::new(UpstreamType::Tcp, ipv6)
        );
    }

    #[tokio::test]
    async fn graceful_shutdown_stops_server_without_idle_timeout() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut server = Server::new(ServerConfig {
            addr: "127.0.0.1:0".to_string(),
            password: "test".to_string(),
            cert_path: format!("{manifest_dir}/localhost.crt.pem"),
            key_path: format!("{manifest_dir}/localhost.key.pem"),
            quic_timeout_ms: 30_000,
            ..ServerConfig::default()
        });
        server.bind().unwrap();
        let serving = server.clone();
        let task = tokio::spawn(async move { serving.serve().await });

        tokio::task::yield_now().await;
        server.shutdown().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("server shutdown waited for idle timeout")
            .unwrap()
            .unwrap();
    }
}
