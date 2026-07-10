use crate::{
    noprotection::NoProtectionClientConfig,
    pem_util, socket_addr_with_unspecified_ip_port,
    tcp::{tcp_tunnel::TcpTunnel, AsyncStream, StreamReceiver, StreamRequest},
    tunnel_message::{LoginResponse, TunnelMessage},
    udp::{udp_server::UdpServer, udp_tunnel::UdpTunnel, UdpReceiver, UdpSender},
    ClientConfig, LoginRequest, SelectedCipherSuite, TcpServer, Tunnel, TunnelConfig, UpstreamType,
    QUIC_CONNECTION_WINDOW, QUIC_MAX_CONCURRENT_BIDI_STREAMS, QUIC_SEND_WINDOW,
    QUIC_STREAM_RECEIVE_WINDOW,
};
use ahash::{AHashMap, AHashSet};
use anyhow::{bail, Context, Result};
use backon::ExponentialBuilder;
use backon::Retryable;
use log::{debug, error, info, warn};
use parking_lot::{Mutex, Once};
use quinn::{crypto::rustls::QuicClientConfig, Connection, Endpoint, TransportConfig};
use quinn::{IdleTimeout, VarInt};
use rs_utilities::dns::{self, DNSQueryOrdering, DNSResolverConfig, DNSResolverLookupIpStrategy};
use rs_utilities::log_and_bail;
use rustls::{
    client::danger::ServerCertVerified,
    crypto::{ring::cipher_suite, CryptoProvider},
    RootCertStore, SupportedCipherSuite,
};
use rustls_platform_verifier::{self, BuilderVerifierExt};
use serde::Serialize;
use std::{
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const DEFAULT_SERVER_PORT: u16 = 3515;
const POST_TRAFFIC_DATA_INTERVAL_SECS: u64 = 30;
const LOGIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
static INIT: Once = Once::new();

#[derive(Clone, Serialize, PartialEq)]
/// High-level client state reported during the lifecycle of a tunnel.
pub enum ClientState {
    Idle = 0,
    Connecting,
    Connected,
    LoggingIn,
    Tunneling,
    Stopping,
    Terminated,
}

impl Display for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientState::Idle => write!(f, "Idle"),
            ClientState::Connecting => write!(f, "Connecting"),
            ClientState::Connected => write!(f, "Connected"),
            ClientState::LoggingIn => write!(f, "LoggingIn"),
            ClientState::Tunneling => write!(f, "Tunneling"),
            ClientState::Stopping => write!(f, "Stopping"),
            ClientState::Terminated => write!(f, "Terminated"),
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct TunnelTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dgrams: u64,
    pub tx_dgrams: u64,
}

struct State {
    tcp_servers: AHashMap<SocketAddr, TcpServer>,
    udp_servers: AHashMap<SocketAddr, UdpServer>,
    endpoint: Option<Endpoint>,
    connections: AHashMap<TunnelConfig, Connection>,
    client_state: ClientState,
    total_traffic_data: TunnelTraffic,
    tunnel_tasks: AHashMap<TunnelConfig, ManagedTunnel>,
    next_tunnel_index: usize,
}

struct ManagedTunnel {
    cancel: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl State {
    fn new() -> Self {
        Self {
            tcp_servers: AHashMap::new(),
            udp_servers: AHashMap::new(),
            endpoint: None,
            connections: AHashMap::new(),
            client_state: ClientState::Idle,
            total_traffic_data: TunnelTraffic::default(),
            tunnel_tasks: AHashMap::new(),
            next_tunnel_index: 0,
        }
    }
}

struct LoginConfig {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    quinn_client_cfg: quinn::ClientConfig,
    domain: String,
}

#[derive(Clone)]
/// Client entry point that manages QUIC connection(s) and tunnel serving.
pub struct Client {
    config: ClientConfig,
    inner_state: Arc<Mutex<State>>,
}

macro_rules! inner_state {
    ($self:ident, $field:ident) => {
        (*$self.inner_state.lock()).$field
    };
}

impl Client {
    /// Create a client with the given runtime configuration.
    pub fn new(config: ClientConfig) -> Self {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .unwrap();
        });

        Client {
            config,
            inner_state: Arc::new(Mutex::new(State::new())),
        }
    }

    /// Start the runtime (multi-threaded tokio) and block the current thread until Ctrl-C.
    ///
    /// Spawns tasks to connect and serve all tunnels in [ClientConfig::tunnels].
    pub fn start_tunneling(&mut self) {
        let mut builder = if self.config.workers == 1 {
            tokio::runtime::Builder::new_current_thread()
        } else {
            let mut b = tokio::runtime::Builder::new_multi_thread();
            b.worker_threads(self.config.workers);
            b
        };

        builder.enable_all().build().unwrap().block_on(async {
            self.connect_and_serve_async();
            if let Err(error) = crate::wait_for_shutdown_signal().await {
                error!("shutdown signal handler failed: {error:#}");
            }
            self.stop_async().await;
        });
    }

    /// Start tunneling and reconcile network tunnels received from a config watcher.
    pub fn start_tunneling_with_updates(
        &mut self,
        mut updates: watch::Receiver<Vec<TunnelConfig>>,
    ) {
        let mut builder = if self.config.workers == 1 {
            tokio::runtime::Builder::new_current_thread()
        } else {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(self.config.workers);
            builder
        };

        builder.enable_all().build().unwrap().block_on(async {
            self.connect_and_serve_async();
            let mut updates_open = true;
            let shutdown = crate::wait_for_shutdown_signal();
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    result = &mut shutdown => {
                        if let Err(error) = result {
                            error!("shutdown signal handler failed: {error:#}");
                        }
                        break;
                    }
                    update = updates.changed(), if updates_open => {
                        if update.is_err() {
                            warn!("config watcher stopped; existing tunnels will keep running");
                            updates_open = false;
                            continue;
                        }
                        let tunnels = updates.borrow_and_update().clone();
                        if let Err(error) = self.update_tunnels(tunnels).await {
                            error!("rejected tunnel configuration update: {error:#}");
                        } else {
                            info!("tunnel configuration updated successfully");
                        }
                    }
                }
            }
            self.stop_async().await;
        });
    }

    /// Spawn async tasks for network/channel-based tunnels; does not block.
    pub fn connect_and_serve_async(&mut self) {
        let tunnels = self.config.tunnels.clone();
        if let Err(error) = Self::validate_tunnels(&tunnels) {
            error!("invalid tunnel configuration: {error}");
            return;
        }
        for tunnel_config in tunnels {
            self.spawn_network_tunnel(tunnel_config);
        }

        self.report_traffic_data_in_background();
        if self.config.hop_interval_ms > 0 {
            self.start_migration_task();
        }
    }

    fn spawn_network_tunnel(&mut self, tunnel_config: TunnelConfig) {
        let (cancel, cancel_rx) = watch::channel(false);
        let index = {
            let mut state = self.inner_state.lock();
            let index = state.next_tunnel_index;
            state.next_tunnel_index = state.next_tunnel_index.wrapping_add(1);
            index
        };
        let mut this = self.clone();
        let task_config = tunnel_config.clone();
        let task = tokio::spawn(async move {
            this.connect_and_serve::<TcpStream>(
                index,
                Tunnel::NetworkBased(task_config),
                None,
                None,
                cancel_rx,
            )
            .await;
        });

        let replaced = self
            .inner_state
            .lock()
            .tunnel_tasks
            .insert(tunnel_config, ManagedTunnel { cancel, task });
        debug_assert!(replaced.is_none());
    }

    fn validate_tunnels(tunnels: &[TunnelConfig]) -> Result<()> {
        let mut configs = AHashSet::new();
        let mut ports = AHashSet::new();
        for tunnel in tunnels {
            if !configs.insert(tunnel.clone()) {
                bail!("duplicate tunnel configuration: {tunnel:?}");
            }
            let addr = tunnel
                .upstream
                .upstream_addr
                .context("inbound tunnel requires a server bind address")?;
            if addr.port() == 0 {
                bail!("inbound tunnel requires a non-zero server port");
            }
            if !ports.insert((tunnel.upstream.upstream_type, addr.port())) {
                bail!(
                    "multiple {} tunnels claim server port {}",
                    tunnel.upstream.upstream_type,
                    addr.port()
                );
            }
        }
        Ok(())
    }

    /// Atomically reconcile running network tunnels with a new configuration.
    /// Invalid updates leave the currently running tunnels unchanged.
    pub async fn update_tunnels(&mut self, tunnels: Vec<TunnelConfig>) -> Result<()> {
        Self::validate_tunnels(&tunnels)?;
        let desired: AHashSet<_> = tunnels.iter().cloned().collect();

        let removed = {
            let mut state = self.inner_state.lock();
            let removed_keys: Vec<_> = state
                .tunnel_tasks
                .keys()
                .filter(|config| !desired.contains(*config))
                .cloned()
                .collect();
            removed_keys
                .into_iter()
                .filter_map(|config| state.tunnel_tasks.remove(&config))
                .collect::<Vec<_>>()
        };

        for tunnel in &removed {
            tunnel.cancel.send(true).ok();
        }
        for tunnel in removed {
            tunnel.task.await.ok();
        }

        let running: AHashSet<_> = self
            .inner_state
            .lock()
            .tunnel_tasks
            .keys()
            .cloned()
            .collect();
        self.config.tunnels = tunnels.clone();
        for tunnel in tunnels {
            if !running.contains(&tunnel) {
                self.spawn_network_tunnel(tunnel);
            }
        }
        Ok(())
    }

    /// Connect and serve a channel-based TCP tunnel using an external stream receiver.
    pub fn connect_and_serve_tcp_async<S: AsyncStream>(
        &mut self,
        stream_receiver: StreamReceiver<S>,
    ) {
        let mut this = self.clone();
        let (cancel, cancel_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _cancel = cancel;
            this.connect_and_serve::<S>(
                0,
                Tunnel::ChannelBased(UpstreamType::Tcp),
                Some(stream_receiver),
                None,
                cancel_rx,
            )
            .await;
        });
    }

    /// Connect and serve a channel-based UDP tunnel using the provided sender/receiver.
    pub fn connect_and_serve_udp_async(&mut self, ch: (UdpSender, UdpReceiver)) {
        let mut this = self.clone();
        let (cancel, cancel_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _cancel = cancel;
            this.connect_and_serve::<TcpStream>(
                0,
                Tunnel::ChannelBased(UpstreamType::Udp),
                None,
                Some(ch),
                cancel_rx,
            )
            .await;
        });
    }

    fn start_migration_task(&self) {
        let state = self.inner_state.clone();
        let hop_interval = self.config.hop_interval_ms;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(hop_interval));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                interval.tick().await;

                let endpoint = { state.lock().endpoint.clone() };
                if let Some(endpoint) = endpoint {
                    Self::migrate_endpoint(&endpoint).await.ok();
                }
            }
        });
    }

    async fn migrate_endpoint(endpoint: &Endpoint) -> Result<()> {
        let current_addr = endpoint.local_addr()?;
        let new_addr = socket_addr_with_unspecified_ip_port(current_addr.is_ipv6());
        let socket = std::net::UdpSocket::bind(new_addr)?;
        debug!(
            "endpoint will migrated from {} to {}",
            current_addr,
            socket.local_addr()?,
        );
        endpoint.rebind(socket)?;
        Ok(())
    }

    /// Start a local TCP server for an OUT tunnel and return its handle.
    pub async fn start_tcp_server(&self, addr: SocketAddr) -> Result<TcpServer> {
        let bind_tcp_server = || async { TcpServer::bind_and_start(addr).await };
        let tcp_server = bind_tcp_server
            .retry(
                ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will start tcp server ({addr}) after {dur:?}, err: {err:?}");
            })
            .await?;

        inner_state!(self, tcp_servers).insert(addr, tcp_server.clone());

        Ok(tcp_server)
    }

    /// Start a local UDP server for an OUT tunnel and return its handle.
    pub async fn start_udp_server(&self, addr: SocketAddr) -> Result<UdpServer> {
        // create a local udp server for 'OUT' tunnel
        let bind_udp_server = || async { UdpServer::bind_and_start(addr).await };
        let udp_server = bind_udp_server
            .retry(
                ExponentialBuilder::default()
                    .with_max_delay(Duration::from_secs(10))
                    .with_max_times(10),
            )
            .sleep(tokio::time::sleep)
            .notify(|err: &anyhow::Error, dur: Duration| {
                warn!("will start udp server ({addr}) after {dur:?}, err: {err:?}");
            })
            .await?;

        inner_state!(self, udp_servers).insert(addr, udp_server.clone());
        Ok(udp_server)
    }

    /// Return a clone of the client's configuration.
    pub fn get_config(&self) -> ClientConfig {
        self.config.clone()
    }

    /// Stop the client and shutdown all servers and connections (blocking variant).
    #[allow(clippy::unnecessary_to_owned)]
    pub fn stop(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        {
            let mut state = self.inner_state.lock();
            for tunnel in state.tunnel_tasks.values() {
                tunnel.cancel.send(true).ok();
            }
            state.tunnel_tasks.clear();
            for mut s in state.tcp_servers.values().cloned() {
                tokio::spawn(async move {
                    s.shutdown().await.ok();
                });
            }
            for mut s in state.udp_servers.values().cloned() {
                tokio::spawn(async move {
                    s.shutdown().await.ok();
                });
            }

            for c in state.connections.values().cloned() {
                tokio::spawn(async move {
                    c.close(VarInt::from_u32(1), b"");
                });
            }

            state.tcp_servers.clear();
            state.udp_servers.clear();
            state.connections.clear();
            if let Some(endpoint) = state.endpoint.take() {
                endpoint.close(VarInt::from_u32(1), b"client shutting down");
            }
        }

        std::thread::sleep(Duration::from_secs(3));
    }

    /// Stop the client and shutdown all servers and connections (async variant).
    #[allow(clippy::unnecessary_to_owned)]
    pub async fn stop_async(&self) {
        self.set_and_post_tunnel_state(ClientState::Stopping);

        let tunnel_tasks = {
            let mut state = self.inner_state.lock();
            state
                .tunnel_tasks
                .drain()
                .map(|(_, tunnel)| tunnel)
                .collect::<Vec<_>>()
        };
        for tunnel in &tunnel_tasks {
            tunnel.cancel.send(true).ok();
        }
        for tunnel in tunnel_tasks {
            tunnel.task.await.ok();
        }

        let (tcp_servers, udp_servers, connections, endpoint) = {
            let mut state = self.inner_state.lock();
            (
                state
                    .tcp_servers
                    .drain()
                    .map(|(_, server)| server)
                    .collect::<Vec<_>>(),
                state
                    .udp_servers
                    .drain()
                    .map(|(_, server)| server)
                    .collect::<Vec<_>>(),
                state
                    .connections
                    .drain()
                    .map(|(_, conn)| conn)
                    .collect::<Vec<_>>(),
                state.endpoint.take(),
            )
        };

        for connection in connections {
            connection.close(VarInt::from_u32(1), b"client shutting down");
        }
        if let Some(endpoint) = &endpoint {
            endpoint.close(VarInt::from_u32(1), b"client shutting down");
        }

        let mut tasks = tokio::task::JoinSet::new();
        for mut server in tcp_servers {
            tasks.spawn(async move {
                server.shutdown().await.ok();
            });
        }
        for mut server in udp_servers {
            tasks.spawn(async move {
                server.shutdown().await.ok();
            });
        }

        while tasks.join_next().await.is_some() {}
        if let Some(endpoint) = endpoint {
            tokio::time::timeout(Duration::from_secs(3), endpoint.wait_idle())
                .await
                .ok();
        }
        self.set_and_post_tunnel_state(ClientState::Terminated);
    }

    async fn connect_and_serve<S: AsyncStream>(
        &mut self,
        index: usize,
        tunnel: Tunnel,
        mut stream_receiver: Option<StreamReceiver<S>>,
        mut ch: Option<(UdpSender, UdpReceiver)>,
        mut cancel: watch::Receiver<bool>,
    ) {
        let login_request = LoginRequest {
            password: self.config.password.clone(),
            tunnel: tunnel.clone(),
        };

        let mut pending_network_based_stream = None;
        let mut pending_channel_based_stream = None;
        loop {
            if *cancel.borrow() || self.should_quit() {
                break;
            }
            let connect = || async {
                let login_cfg = self.prepare_login_config().await?;
                let endpoint = { self.inner_state.lock().endpoint.clone() };
                let endpoint = if let Some(endpoint) = endpoint {
                    Self::migrate_endpoint(&endpoint).await?;
                    endpoint
                } else {
                    let mut endpoint = quinn::Endpoint::client(login_cfg.local_addr)?;
                    endpoint.set_default_client_config(login_cfg.quinn_client_cfg);
                    inner_state!(self, endpoint) = Some(endpoint.clone());
                    endpoint
                };

                let conn = self
                    .login(
                        index,
                        &endpoint,
                        &login_request,
                        &login_cfg.remote_addr,
                        login_cfg.domain.as_str(),
                    )
                    .await?;

                Ok(conn)
            };
            let retry = connect
                .retry(
                    ExponentialBuilder::default()
                        .with_max_delay(Duration::from_secs(10))
                        .with_max_times(usize::MAX),
                )
                .when(|_| !self.should_quit())
                .sleep(tokio::time::sleep)
                .notify(|err: &anyhow::Error, dur: Duration| {
                    warn!("will retry after {dur:?}, err: {err:?}");
                });
            let result = tokio::select! {
                _ = cancel.changed() => break,
                result = retry => result,
            };

            if *cancel.borrow() || self.should_quit() {
                break;
            }

            match result {
                Ok(conn) => match &tunnel {
                    Tunnel::NetworkBased(tunnel_config) => {
                        inner_state!(self, connections).insert(tunnel_config.clone(), conn.clone());

                        tokio::select! {
                            _ = cancel.changed() => {
                                conn.close(VarInt::from_u32(5), b"tunnel removed");
                            }
                            _ = self.handle_network_based_tunnel(
                                index,
                                conn.clone(),
                                tunnel_config,
                                &mut pending_network_based_stream,
                            ) => {}
                        }

                        inner_state!(self, connections).remove(tunnel_config);
                    }
                    Tunnel::ChannelBased(upstream_type) => match upstream_type {
                        UpstreamType::Tcp => {
                            self.post_tunnel_log(
                                format!(
                                    "{index}:STREAM_OUT start serving via {}",
                                    conn.remote_address()
                                )
                                .as_str(),
                            );
                            self.set_and_post_tunnel_state(ClientState::Tunneling);

                            let stream_receiver = stream_receiver.as_mut().unwrap();
                            tokio::select! {
                                _ = cancel.changed() => {
                                    conn.close(VarInt::from_u32(5), b"tunnel removed");
                                }
                                _ = TcpTunnel::start_serving(
                                    true,
                                    &conn,
                                    stream_receiver,
                                    &mut pending_channel_based_stream,
                                    self.config.tcp_timeout_ms,
                                ) => {}
                            }
                        }

                        UpstreamType::Udp => {
                            self.post_tunnel_log(
                                format!(
                                    "{index}:UDP_OUT start serving via {}",
                                    conn.remote_address()
                                )
                                .as_str(),
                            );
                            self.set_and_post_tunnel_state(ClientState::Tunneling);

                            let ch = ch.as_mut().unwrap();
                            tokio::select! {
                                _ = cancel.changed() => {
                                    conn.close(VarInt::from_u32(5), b"tunnel removed");
                                }
                                _ = UdpTunnel::start_serving(
                                    &conn,
                                    &ch.0,
                                    &mut ch.1,
                                    self.config.udp_timeout_ms,
                                ) => {}
                            }
                        }
                    },
                },

                Err(e) => {
                    error!("{e}");
                    info!(
                        "[{login_request}] quit after having retried for {} times",
                        usize::MAX
                    );
                    break;
                }
            };

            if *cancel.borrow() || self.should_quit() {
                break;
            }
        }
        self.post_tunnel_log(format!("[{login_request}] quit").as_str());
    }

    async fn handle_network_based_tunnel(
        &mut self,
        index: usize,
        conn: Connection,
        tunnel_config: &TunnelConfig,
        _pending_request: &mut Option<StreamRequest<TcpStream>>,
    ) {
        let upstream_type = &tunnel_config.upstream.upstream_type;
        let local_server_addr = tunnel_config.local_server_addr;

        match upstream_type {
            UpstreamType::Tcp => {
                self.serve_inbound_tcp(index, conn.clone(), local_server_addr)
                    .await
                    .ok();
            }
            UpstreamType::Udp => {
                self.serve_inbound_udp(index, conn.clone(), local_server_addr)
                    .await
                    .ok();
            }
        }

        let stats = conn.stats();
        let data = &mut inner_state!(self, total_traffic_data);
        data.rx_bytes += stats.udp_rx.bytes;
        data.tx_bytes += stats.udp_tx.bytes;
        data.rx_dgrams += stats.udp_rx.datagrams;
        data.tx_dgrams += stats.udp_tx.datagrams;
    }

    async fn prepare_login_config(&self) -> Result<LoginConfig> {
        let mut transport_cfg = TransportConfig::default();
        transport_cfg.stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW));
        transport_cfg.receive_window(VarInt::from_u32(QUIC_CONNECTION_WINDOW));
        transport_cfg.send_window(QUIC_SEND_WINDOW);
        transport_cfg
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        transport_cfg.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
        transport_cfg
            .max_concurrent_bidi_streams(VarInt::from_u32(QUIC_MAX_CONCURRENT_BIDI_STREAMS));

        if self.config.quic_timeout_ms > 0 {
            let timeout = IdleTimeout::from(VarInt::from_u32(self.config.quic_timeout_ms as u32));
            transport_cfg.max_idle_timeout(Some(timeout));
            transport_cfg.keep_alive_interval(Some(Duration::from_millis(
                self.config.quic_timeout_ms * 2 / 3,
            )));
        }

        let (tls_client_cfg, domain) = self.parse_client_config_and_domain()?;
        let mut client_cfg: quinn::ClientConfig = quinn::ClientConfig::new(Arc::new(
            NoProtectionClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_client_cfg)?)),
        ));
        client_cfg.transport_config(Arc::new(transport_cfg));

        let remote_addr = self.parse_server_addr().await?;
        let local_addr = socket_addr_with_unspecified_ip_port(remote_addr.is_ipv6());
        Ok(LoginConfig {
            local_addr,
            remote_addr,
            quinn_client_cfg: client_cfg,
            domain,
        })
    }

    async fn login(
        &self,
        index: usize,
        endpoint: &Endpoint,
        login_request: &LoginRequest,
        remote_addr: &SocketAddr,
        domain: &str,
    ) -> Result<Connection> {
        self.set_and_post_tunnel_state(ClientState::Connecting);
        self.post_tunnel_log(
            format!(
                "{index}:{} connecting, idle_timeout:{}, retry_timeout:{}, cipher:{}, threads:{}",
                login_request.format_with_remote_addr(remote_addr),
                self.config.quic_timeout_ms,
                self.config.wait_before_retry_ms,
                self.config.cipher,
                self.config.workers,
            )
            .as_str(),
        );

        let conn = endpoint.connect(*remote_addr, domain)?.await?;
        let (mut quic_send, mut quic_recv) = conn
            .open_bi()
            .await
            .context("open bidirectional connection failed")?;

        self.set_and_post_tunnel_state(ClientState::Connected);

        self.post_tunnel_log(
            format!(
                "{index}:{} logging in...",
                login_request.format_with_remote_addr(remote_addr)
            )
            .as_str(),
        );

        let login_msg = TunnelMessage::Login(login_request.clone());
        TunnelMessage::send(&mut quic_send, &login_msg).await?;

        let resp =
            tokio::time::timeout(LOGIN_RESPONSE_TIMEOUT, TunnelMessage::recv(&mut quic_recv))
                .await
                .context("login response timed out")??;
        match resp {
            TunnelMessage::LoginResponse(LoginResponse::Accepted) => {}
            TunnelMessage::LoginResponse(LoginResponse::Rejected { reason }) => {
                bail!(
                    "{index}:{} failed to login: {reason}",
                    login_request.format_with_remote_addr(remote_addr)
                )
            }
            TunnelMessage::Login(_) => bail!("server sent a login request instead of a response"),
        }
        self.post_tunnel_log(
            format!(
                "{index}:{} started",
                login_request.format_with_remote_addr(remote_addr)
            )
            .as_str(),
        );

        Ok(conn)
    }

    async fn serve_inbound_tcp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        self.post_tunnel_log(
            format!(
                "{index}:TCP_IN start serving via: {}",
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);
        TcpTunnel::start_accepting(&conn, Some(local_server_addr), self.config.tcp_timeout_ms)
            .await;

        Ok(())
    }

    async fn serve_inbound_udp(
        &mut self,
        index: usize,
        conn: Connection,
        local_server_addr: SocketAddr,
    ) -> Result<()> {
        self.post_tunnel_log(
            format!(
                "{index}:UDP_IN start serving via: {}",
                conn.remote_address()
            )
            .as_str(),
        );

        self.set_and_post_tunnel_state(ClientState::Tunneling);
        UdpTunnel::start_accepting(&conn, Some(local_server_addr), self.config.udp_timeout_ms)
            .await;

        Ok(())
    }

    fn should_quit(&self) -> bool {
        let state = self.get_state();
        state == ClientState::Stopping || state == ClientState::Terminated
    }

    fn report_traffic_data_in_background(&self) {
        let state = self.inner_state.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(POST_TRAFFIC_DATA_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                let mut rx_bytes = 0;
                let mut tx_bytes = 0;
                let mut rx_dgrams = 0;
                let mut tx_dgrams = 0;

                {
                    let connections = &state.lock().connections;
                    for conn in connections.values() {
                        let stats = conn.stats();
                        rx_bytes += stats.udp_rx.bytes;
                        tx_bytes += stats.udp_tx.bytes;
                        rx_dgrams += stats.udp_rx.datagrams;
                        tx_dgrams += stats.udp_tx.datagrams;
                    }
                }

                {
                    let total_traffic_data = &state.lock().total_traffic_data;
                    rx_bytes += total_traffic_data.rx_bytes;
                    tx_bytes += total_traffic_data.tx_bytes;
                    rx_dgrams += total_traffic_data.rx_dgrams;
                    tx_dgrams += total_traffic_data.tx_dgrams;
                }

                let state = state.lock();
                let client_state = state.client_state.clone();
                let _data = TunnelTraffic {
                    rx_bytes,
                    tx_bytes,
                    rx_dgrams,
                    tx_dgrams,
                };

                info!("traffic log, rx_bytes:{rx_bytes}, tx_bytes:{tx_bytes}, rx_dgrams:{rx_dgrams}, tx_dgrams:{tx_dgrams}");

                if client_state == ClientState::Stopping || client_state == ClientState::Terminated
                {
                    break;
                }
            }
        });
    }

    fn get_crypto_provider(&self, cipher: &SupportedCipherSuite) -> Arc<CryptoProvider> {
        let default_provider = rustls::crypto::ring::default_provider();
        let mut cipher_suites = vec![*cipher];
        // Quinn assumes that the cipher suites contain this one
        cipher_suites.push(cipher_suite::TLS13_AES_128_GCM_SHA256);
        Arc::new(rustls::crypto::CryptoProvider {
            cipher_suites,
            ..default_provider
        })
    }

    fn create_client_config_builder(
        &self,
        cipher: &SupportedCipherSuite,
    ) -> std::result::Result<
        rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
        rustls::Error,
    > {
        let cfg_builder =
            rustls::ClientConfig::builder_with_provider(self.get_crypto_provider(cipher))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap();
        Ok(cfg_builder)
    }

    fn parse_client_config_and_domain(&self) -> Result<(rustls::ClientConfig, String)> {
        let cipher = *SelectedCipherSuite::from_str(&self.config.cipher).map_err(|_| {
            rustls::Error::General(format!("invalid cipher: {}", self.config.cipher))
        })?;

        if self.config.cert_path.is_empty() {
            if !Self::is_ip_addr(&self.config.server_addr) {
                let domain = match self.config.server_addr.rfind(':') {
                    Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
                    None => self.config.server_addr.to_string(),
                };

                let client_config = self
                    .create_client_config_builder(&cipher)?
                    .with_platform_verifier()?
                    .with_no_client_auth();

                return Ok((client_config, domain));
            }

            let client_config = self
                .create_client_config_builder(&cipher)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier::new(
                    self.get_crypto_provider(&cipher),
                )))
                .with_no_client_auth();

            static ONCE: Once = Once::new();
            ONCE.call_once(|| {
                warn!(
                    "No certificate is provided for verification, domain \"localhost\" is assumed"
                );
            });
            return Ok((client_config, "localhost".to_string()));
        }

        // when client config provides a certificate
        let certs = pem_util::load_certificates_from_pem(self.config.cert_path.as_str())
            .context("failed to read from cert file")?;
        if certs.is_empty() {
            log_and_bail!(
                "No certificates found in provided file: {}",
                self.config.cert_path
            );
        }
        let mut roots = RootCertStore::empty();
        // save all certificates in the certificate chain to the trust list
        for cert in &certs {
            roots.add(cert.clone()).context(format!(
                "failed to add certificate from file: {}",
                self.config.cert_path
            ))?;
        }

        // for self-signed certificates, generating IP-based TLS certificates is not difficult
        let domain_or_ip = match self.config.server_addr.rfind(':') {
            Some(colon_index) => self.config.server_addr[0..colon_index].to_string(),
            None => self.config.server_addr.to_string(),
        };

        Ok((
            self.create_client_config_builder(&cipher)?
                .with_root_certificates(roots)
                .with_no_client_auth(),
            domain_or_ip,
        ))
    }

    pub fn get_state(&self) -> ClientState {
        inner_state!(self, client_state).clone()
    }

    fn is_ip_addr(addr: &str) -> bool {
        addr.parse::<SocketAddr>().is_ok()
    }

    async fn parse_server_addr(&self) -> Result<SocketAddr> {
        let addr = self.config.server_addr.as_str();
        let sock_addr: Result<SocketAddr> = addr.parse().context("error will be ignored");

        if sock_addr.is_ok() {
            return sock_addr;
        }

        let mut domain = addr;
        let mut port = DEFAULT_SERVER_PORT;
        let pos = addr.rfind(':');
        if let Some(pos) = pos {
            port = addr[(pos + 1)..]
                .parse()
                .with_context(|| format!("invalid address: {}", addr))?;
            domain = &addr[..pos];
        }

        for dot in &self.config.dot_servers {
            if let Ok(ip) = Self::lookup_server_ip(domain, dot, vec![]).await {
                return Ok(SocketAddr::new(ip, port));
            }
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "", self.config.dns_servers.clone()).await {
            return Ok(SocketAddr::new(ip, port));
        }

        if let Ok(ip) = Self::lookup_server_ip(domain, "", vec![]).await {
            return Ok(SocketAddr::new(ip, port));
        }

        bail!("failed to resolve domain: {domain}");
    }

    async fn lookup_server_ip(
        domain: &str,
        dot_server: &str,
        name_servers: Vec<String>,
    ) -> Result<IpAddr> {
        let dns_config = DNSResolverConfig {
            strategy: DNSResolverLookupIpStrategy::Ipv6thenIpv4,
            num_conccurent_reqs: 3,
            ordering: DNSQueryOrdering::QueryStatistics,
        };

        let resolver = if !dot_server.is_empty() {
            dns::resolver2(dot_server, vec![], dns_config)
        } else if !name_servers.is_empty() {
            dns::resolver2("", name_servers, dns_config)
        } else {
            dns::resolver2("", vec![], dns_config)
        };

        let ip = resolver.await.lookup_first(domain).await?;
        info!("resolved {domain} to {ip}");
        Ok(ip)
    }

    fn post_tunnel_log(&self, msg: &str) {
        info!("{msg}");
    }

    fn set_and_post_tunnel_state(&self, client_state: ClientState) {
        let mut state = self.inner_state.lock();
        state.client_state = client_state;
    }

    pub fn set_on_info_listener(&self, callback: impl FnMut(&str) + 'static + Send + Sync) {
        let _ = callback;
    }

    /// Returns true if an info listener has been installed.
    pub fn has_tunnel_info_listener(&self) -> bool {
        false
    }

    /// Enable or disable periodic posting of tunnel info via the listener.
    pub fn set_enable_on_info_report(&self, enable: bool) {
        info!("set_enable_on_info_report, enable:{enable}");
    }
}

#[derive(Debug)]
struct InsecureCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl InsecureCertVerifier {
    pub fn new(crypto: Arc<CryptoProvider>) -> Self {
        Self(crypto)
    }
}

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::prelude::v1::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::prelude::v1::Result<ServerCertVerified, rustls::Error> {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            warn!("======================================= WARNING ======================================");
            warn!("Connecting to a server without verifying its certificate is DANGEROUS!!!");
            warn!("Provide the self-signed certificate for verification or connect with a domain name");
            warn!("======================= Be cautious, this is for TEST only!!! ========================");
        });
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Server, ServerConfig, Upstream};
    use std::net::{Ipv4Addr, SocketAddr};

    fn test_client_config(server_addr: SocketAddr, tunnels: Vec<TunnelConfig>) -> ClientConfig {
        ClientConfig {
            cipher: "aes-128-gcm".to_string(),
            server_addr: server_addr.to_string(),
            password: "integration-secret".to_string(),
            quic_timeout_ms: 3_000,
            tcp_timeout_ms: 3_000,
            udp_timeout_ms: 3_000,
            workers: 1,
            tunnels,
            ..ClientConfig::default()
        }
    }

    async fn reserve_tcp_addr() -> SocketAddr {
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn wait_until_tunnel_accepts(addr: SocketAddr) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpStream::connect(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn wait_until_port_is_released(addr: SocketAddr) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if tokio::net::TcpListener::bind(addr).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    fn tunnel(bind: SocketAddr, destination_port: u16) -> TunnelConfig {
        TunnelConfig {
            upstream: Upstream {
                upstream_addr: Some(bind),
                upstream_type: UpstreamType::Tcp,
            },
            local_server_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), destination_port),
        }
    }

    async fn start_test_server() -> (SocketAddr, JoinHandle<Result<()>>) {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut server = Server::new(ServerConfig {
            addr: "127.0.0.1:0".to_string(),
            password: "integration-secret".to_string(),
            cert_path: format!("{manifest_dir}/localhost.crt.pem"),
            key_path: format!("{manifest_dir}/localhost.key.pem"),
            quic_timeout_ms: 3_000,
            tcp_timeout_ms: 3_000,
            udp_timeout_ms: 3_000,
            ..ServerConfig::default()
        });
        let addr = server.bind().unwrap();
        let task = tokio::spawn(async move { server.serve().await });
        (addr, task)
    }

    async fn create_endpoint(client: &Client) -> Result<(Endpoint, SocketAddr, String)> {
        let login_config = client.prepare_login_config().await?;
        let mut endpoint = Endpoint::client(login_config.local_addr)?;
        endpoint.set_default_client_config(login_config.quinn_client_cfg);
        Ok((endpoint, login_config.remote_addr, login_config.domain))
    }

    #[tokio::test]
    async fn live_duplicate_is_rejected_without_disrupting_owner() {
        let (server_addr, server_task) = start_test_server().await;
        let tunnel_addr = reserve_tcp_addr().await;
        let request = LoginRequest {
            password: "integration-secret".to_string(),
            tunnel: Tunnel::NetworkBased(tunnel(tunnel_addr, 9)),
        };

        let owner = Client::new(test_client_config(server_addr, vec![]));
        let (owner_endpoint, remote_addr, domain) = create_endpoint(&owner).await.unwrap();
        let first = owner
            .login(0, &owner_endpoint, &request, &remote_addr, &domain)
            .await
            .unwrap();

        let competitor = Client::new(test_client_config(server_addr, vec![]));
        let (competitor_endpoint, competitor_remote, competitor_domain) =
            create_endpoint(&competitor).await.unwrap();
        let rejected = competitor
            .login(
                0,
                &competitor_endpoint,
                &request,
                &competitor_remote,
                &competitor_domain,
            )
            .await;
        assert!(rejected.is_err());
        assert!(first.close_reason().is_none());

        first.close(VarInt::from_u32(0), b"test complete");
        owner_endpoint.close(VarInt::from_u32(0), b"test complete");
        competitor_endpoint.close(VarInt::from_u32(0), b"test complete");
        server_task.abort();
    }

    #[tokio::test]
    async fn reconciles_add_update_remove_and_rejects_invalid_updates() {
        let (server_addr, server_task) = start_test_server().await;
        let first_bind = reserve_tcp_addr().await;
        let second_bind = reserve_tcp_addr().await;
        let initial = tunnel(first_bind, 9);
        let updated = tunnel(first_bind, 10);
        let added = tunnel(second_bind, 11);

        let mut client = Client::new(test_client_config(server_addr, vec![initial.clone()]));
        client.connect_and_serve_async();
        assert!(client
            .inner_state
            .lock()
            .tunnel_tasks
            .contains_key(&initial));
        wait_until_tunnel_accepts(first_bind).await;

        client.update_tunnels(vec![updated.clone()]).await.unwrap();
        assert_eq!(client.inner_state.lock().tunnel_tasks.len(), 1);
        assert!(client
            .inner_state
            .lock()
            .tunnel_tasks
            .contains_key(&updated));
        wait_until_tunnel_accepts(first_bind).await;

        client
            .update_tunnels(vec![updated.clone(), added.clone()])
            .await
            .unwrap();
        assert_eq!(client.inner_state.lock().tunnel_tasks.len(), 2);
        wait_until_tunnel_accepts(first_bind).await;
        wait_until_tunnel_accepts(second_bind).await;

        let conflicting = tunnel(second_bind, 12);
        assert!(client
            .update_tunnels(vec![updated.clone(), added.clone(), conflicting])
            .await
            .is_err());
        assert_eq!(client.inner_state.lock().tunnel_tasks.len(), 2);

        client.update_tunnels(vec![added.clone()]).await.unwrap();
        assert_eq!(client.inner_state.lock().tunnel_tasks.len(), 1);
        assert!(client.inner_state.lock().tunnel_tasks.contains_key(&added));
        wait_until_port_is_released(first_bind).await;
        wait_until_tunnel_accepts(second_bind).await;

        client.stop_async().await;

        let restarted = Client::new(test_client_config(server_addr, vec![]));
        let (restart_endpoint, restart_remote, restart_domain) =
            create_endpoint(&restarted).await.unwrap();
        let restart_request = LoginRequest {
            password: "integration-secret".to_string(),
            tunnel: Tunnel::NetworkBased(added),
        };
        let restarted_connection = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(connection) = restarted
                    .login(
                        0,
                        &restart_endpoint,
                        &restart_request,
                        &restart_remote,
                        &restart_domain,
                    )
                    .await
                {
                    break connection;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("clean restart waited for the QUIC idle timeout");
        restarted_connection.close(VarInt::from_u32(0), b"test complete");
        restart_endpoint.close(VarInt::from_u32(0), b"test complete");
        server_task.abort();
    }
}
