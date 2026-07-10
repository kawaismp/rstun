//! UDP tunneling helpers built on top of QUIC bidirectional streams.
//!
//! This module provides the `UdpTunnel` struct, which facilitates the tunneling
//! of UDP packets over a QUIC connection. It allows for bridging between local
//! UDP servers and remote endpoints using QUIC streams.

use crate::tunnel_message::TunnelMessage;
use crate::udp::{configure_udp_socket, UdpMessage, UdpPacket};
use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use ahash::AHashMap;
use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use parking_lot::Mutex as MapMutex;
use quinn::{Connection, RecvStream, SendStream};
use rs_utilities::log_and_bail;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio::{net::UdpSocket, sync::Mutex as AsyncMutex};

#[derive(Clone)]
struct Activity(Arc<MapMutex<Instant>>);

impl Activity {
    fn new() -> Self {
        Self(Arc::new(MapMutex::new(Instant::now())))
    }

    fn touch(&self) {
        *self.0.lock() = Instant::now();
    }

    fn is_expired(&self, timeout: Duration) -> bool {
        self.0.lock().elapsed() >= timeout
    }
}

struct UdpStream {
    sender: AsyncMutex<SendStream>,
    activity: Activity,
}

type TSafeUdpStream = Arc<UdpStream>;
type StreamMap = Arc<MapMutex<AHashMap<SocketAddr, TSafeUdpStream>>>;

const UDP_WRITE_BATCH_BYTES: usize = 64 * 1024;
const UDP_WRITE_BATCH_PACKETS: usize = 64;

pub struct UdpTunnel;

impl UdpTunnel {
    /// Bridge packets between a local UDP server and QUIC streams (OUT mode).
    /// Consumes packets from `udp_receiver` and sends them via QUIC; also
    /// spawns tasks to relay responses back to the local UDP server.
    pub async fn start_serving(
        conn: &quinn::Connection,
        udp_sender: &Sender<UdpMessage>,
        udp_receiver: &mut Receiver<UdpMessage>,
        udp_timeout_ms: u64,
    ) {
        debug!("start serving udp via: {}", conn.remote_address());
        let stream_map = Arc::new(MapMutex::new(AHashMap::new()));
        let mut pending_packet = None;
        let mut write_batch = Vec::with_capacity(UDP_WRITE_BATCH_BYTES);

        loop {
            let packet = match pending_packet.take() {
                Some(packet) => packet,
                None => match udp_receiver.recv().await {
                    Some(UdpMessage::Packet(packet)) => packet,
                    Some(UdpMessage::Quit) | None => break,
                },
            };
            let local_addr = packet.local_addr;
            let quic_send = match UdpTunnel::open_stream(
                conn.clone(),
                udp_sender.clone(),
                local_addr,
                stream_map.clone(),
                udp_timeout_ms,
            )
            .await
            {
                Ok(quic_send) => quic_send,
                Err(e) => {
                    error!("{e}");
                    if conn.close_reason().is_some() {
                        debug!("connection is closed, will quit");
                        break;
                    }
                    continue;
                }
            };

            TunnelMessage::start_udp_batch(&mut write_batch);
            if let Err(e) = TunnelMessage::append_udp_packet(
                &mut write_batch,
                packet.peer_addr,
                &packet.payload,
            ) {
                warn!("failed to encode UDP packet: {e}");
                continue;
            }

            let mut packet_count = 1;
            let mut should_quit = false;
            while write_batch.len() < UDP_WRITE_BATCH_BYTES
                && packet_count < UDP_WRITE_BATCH_PACKETS
            {
                match udp_receiver.try_recv() {
                    Ok(UdpMessage::Packet(packet)) if packet.local_addr == local_addr => {
                        if let Err(e) = TunnelMessage::append_udp_packet(
                            &mut write_batch,
                            packet.peer_addr,
                            &packet.payload,
                        ) {
                            warn!("failed to encode UDP packet: {e}");
                        }
                        packet_count += 1;
                    }
                    Ok(UdpMessage::Packet(packet)) => {
                        pending_packet = Some(packet);
                        break;
                    }
                    Ok(UdpMessage::Quit) => {
                        should_quit = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }

            if let Err(e) = TunnelMessage::finish_udp_batch(&mut write_batch) {
                warn!("failed to finalize UDP batch: {e}");
                continue;
            }
            let payload_len = write_batch.len() - 4;
            let result = {
                let mut quic_send = quic_send.sender.lock().await;
                quic_send.write_all(&write_batch).await
            };

            if let Err(e) = result {
                stream_map.lock().remove(&local_addr);
                warn!("failed to send datagram({payload_len}) through the tunnel, err: {e}");
            } else {
                quic_send.activity.touch();
            }
            if should_quit {
                break;
            }
        }

        info!("udp server quit");
    }

    /// Open (or reuse) a QUIC stream for a specific local UDP socket address.
    async fn open_stream(
        conn: Connection,
        udp_sender: Sender<UdpMessage>,
        local_addr: SocketAddr,
        stream_map: StreamMap,
        udp_timeout_ms: u64,
    ) -> Result<TSafeUdpStream> {
        if let Some(stream) = stream_map.lock().get(&local_addr).cloned() {
            return Ok(stream);
        }

        let (quic_send, mut quic_recv) =
            conn.open_bi().await.context("open_bi failed for udp out")?;

        let quic_send = Arc::new(UdpStream {
            sender: AsyncMutex::new(quic_send),
            activity: Activity::new(),
        });
        stream_map.lock().insert(local_addr, quic_send.clone());

        let stream_map = stream_map.clone();
        let recv_stream = quic_send.clone();
        tokio::spawn(async move {
            debug!(
                "start udp stream: {local_addr}, streams: {}",
                stream_map.lock().len()
            );
            let mut read_batch = Vec::with_capacity(UDP_WRITE_BATCH_BYTES);
            let timeout = Duration::from_millis(udp_timeout_ms);
            'stream: loop {
                match tokio::time::timeout(
                    timeout,
                    TunnelMessage::recv_udp_batch(&mut quic_recv, &mut read_batch),
                )
                .await
                {
                    Ok(Ok(())) => {
                        recv_stream.activity.touch();
                        let mut cursor = 0;
                        loop {
                            let packet_data =
                                match TunnelMessage::decode_udp_packet(&read_batch, &mut cursor) {
                                    Ok(Some((_, packet_data))) => packet_data,
                                    Ok(None) => break,
                                    Err(e) => {
                                        warn!("failed to decode UDP response batch: {e}");
                                        break 'stream;
                                    }
                                };
                            let packet_len = packet_data.len();
                            let mut payload = BUFFER_POOL.alloc_and_fill(packet_len.max(1));
                            payload[..packet_len].copy_from_slice(packet_data);
                            payload.truncate(packet_len);
                            let packet = UdpPacket {
                                payload,
                                local_addr,
                                peer_addr: None,
                            };
                            if udp_sender.send(UdpMessage::Packet(packet)).await.is_err() {
                                break 'stream;
                            }
                        }
                    }
                    Ok(Err(_)) => {
                        // warn!("failed to read for udp, err: {e}");
                        break;
                    }
                    Err(_) if recv_stream.activity.is_expired(timeout) => break,
                    Err(_) => continue,
                }
            }

            let mut streams = stream_map.lock();
            if streams
                .get(&local_addr)
                .is_some_and(|stream| Arc::ptr_eq(stream, &recv_stream))
            {
                streams.remove(&local_addr);
            }
            debug!(
                "dropped udp stream: {local_addr}, streams: {}",
                streams.len()
            );
        });

        Ok(quic_send)
    }

    /// Accept peer QUIC streams and forward them to an upstream UDP endpoint.
    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) {
        let remote_addr = &conn.remote_address();
        info!("start udp stream, {remote_addr} ↔  {upstream_addr:?}");

        loop {
            match conn.accept_bi().await {
                Err(quinn::ConnectionError::TimedOut) => {
                    info!("connection timeout: {remote_addr}");
                    break;
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    debug!("connection closed: {remote_addr}");
                    break;
                }
                Err(e) => {
                    error!("failed to accept_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok((quic_send, quic_recv)) => tokio::spawn(async move {
                    Self::process(quic_send, quic_recv, upstream_addr, udp_timeout_ms).await
                }),
            };
        }

        info!("connection for udp out is dropped");
    }

    /// Process one accepted QUIC pair for UDP bridging.
    async fn process(
        quic_send: SendStream,
        mut quic_recv: RecvStream,
        upstream_addr: Option<SocketAddr>,
        udp_timeout_ms: u64,
    ) -> Result<()> {
        let quic_send = Arc::new(AsyncMutex::new(quic_send));
        let activity = Activity::new();
        let mut udp_socket = None;
        if let Some(upstream_addr) = upstream_addr {
            // pre-create the udp-socket if upstream is specified
            udp_socket = Self::create_peer_socket_and_exchange_data(
                upstream_addr,
                quic_send.clone(),
                activity.clone(),
                udp_timeout_ms,
            )
            .await?;
        }

        let mut read_batch = Vec::with_capacity(UDP_WRITE_BATCH_BYTES);
        let timeout = Duration::from_millis(udp_timeout_ms);
        loop {
            match tokio::time::timeout(
                timeout,
                TunnelMessage::recv_udp_batch(&mut quic_recv, &mut read_batch),
            )
            .await
            {
                Ok(Ok(())) => {
                    activity.touch();
                    let mut cursor = 0;
                    while let Some((peer_addr, packet_data)) =
                        TunnelMessage::decode_udp_packet(&read_batch, &mut cursor)?
                    {
                        match peer_addr {
                            Some(peer_addr) => {
                                if let Some(upstream_addr) = upstream_addr {
                                    warn!("upstream_addr {upstream_addr:?} is specified for the connection, peer_addr {peer_addr} is ignored");
                                } else if udp_socket
                                    .as_ref()
                                    .and_then(|sock| sock.0.peer_addr().ok())
                                    != Some(peer_addr)
                                {
                                    if let Some(udp_socket) = udp_socket {
                                        // shutdown the old socket
                                        udp_socket.1.send(()).ok();
                                    }
                                    udp_socket = Self::create_peer_socket_and_exchange_data(
                                        peer_addr,
                                        quic_send.clone(),
                                        activity.clone(),
                                        udp_timeout_ms,
                                    )
                                    .await?;
                                }
                            }
                            None => {
                                if udp_socket.is_none() {
                                    log_and_bail!("no valid upstream_addr to connect");
                                }
                            }
                        };

                        Self::send_connected_udp(&udp_socket.as_ref().unwrap().0, packet_data)
                            .await?;
                    }
                }
                Ok(Err(e)) => {
                    warn!("failed to read from udp packet from tunnel, err: {e}");
                    break;
                }
                Err(_) if activity.is_expired(timeout) => break,
                Err(_) => continue,
            }
        }

        Ok::<(), anyhow::Error>(())
    }

    async fn send_connected_udp(socket: &UdpSocket, data: &[u8]) -> Result<()> {
        loop {
            match socket.try_send(data) {
                Ok(written) if written == data.len() => return Ok(()),
                Ok(written) => bail!("partial UDP send: {written}/{} bytes", data.len()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    socket.writable().await?;
                }
                Err(e) => return Err(e).context("failed to send datagram through UDP socket"),
            }
        }
    }

    /// Spawn a task to forward datagrams from a connected UDP socket to QUIC.
    fn udp_to_quic(
        udp_socket: Arc<UdpSocket>,
        quic_send: Arc<AsyncMutex<SendStream>>,
        activity: Activity,
        udp_timeout_ms: u64,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        tokio::spawn(async move {
            debug!("start udp stream →  {:?}", udp_socket.peer_addr());
            let mut buf = vec![0u8; UDP_PACKET_SIZE];
            let mut write_batch = Vec::with_capacity(UDP_WRITE_BATCH_BYTES);
            let timeout = Duration::from_millis(udp_timeout_ms);
            loop {
                tokio::select! {
                    biased;

                    _ = &mut shutdown_rx => {
                        break;
                    }

                    result = tokio::time::timeout(
                        timeout,
                        udp_socket.recv(&mut buf)
                    ) => {
                        match result {
                            Ok(Ok(len)) => {
                                activity.touch();
                                TunnelMessage::start_udp_batch(&mut write_batch);
                                if let Err(e) = TunnelMessage::append_udp_packet(
                                    &mut write_batch,
                                    None,
                                    &buf[..len],
                                ) {
                                    warn!("failed to encode UDP response: {e}");
                                    continue;
                                }

                                let mut packet_count = 1;
                                while write_batch.len() < UDP_WRITE_BATCH_BYTES
                                    && packet_count < UDP_WRITE_BATCH_PACKETS
                                {
                                    match udp_socket.try_recv(&mut buf) {
                                        Ok(len) => {
                                            if let Err(e) = TunnelMessage::append_udp_packet(
                                                &mut write_batch,
                                                None,
                                                &buf[..len],
                                            ) {
                                                warn!("failed to encode UDP response: {e}");
                                            }
                                            packet_count += 1;
                                        }
                                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                            break;
                                        }
                                        Err(e) => {
                                            warn!("failed to receive datagrams from upstream, err: {e:?}");
                                            break;
                                        }
                                    }
                                }

                                if TunnelMessage::finish_udp_batch(&mut write_batch).is_err() {
                                    break;
                                }
                                let mut quic_send = quic_send.lock().await;
                                if quic_send.write_all(&write_batch).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Err(e)) => {
                                warn!("failed to receive datagrams from upstream, err: {e:?}");
                                break;
                            }
                            Err(_) if activity.is_expired(timeout) => break,
                            Err(_) => continue,
                        }
                    }
                }
            }
            debug!("dropped udp stream →  {:?}", udp_socket.peer_addr());
        });
    }

    async fn create_peer_socket_and_exchange_data(
        addr: SocketAddr,
        quic_send: Arc<AsyncMutex<SendStream>>,
        activity: Activity,
        udp_timeout_ms: u64,
    ) -> Result<Option<(Arc<UdpSocket>, oneshot::Sender<()>)>> {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        match UdpSocket::bind(local_addr).await {
            Ok(udp_socket) => {
                configure_udp_socket(&udp_socket);
                if let Err(e) = udp_socket.connect(addr).await {
                    log_and_bail!("failed to connect to upstream: {addr}, err: {e}");
                };

                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
                let udp_socket = Arc::new(udp_socket);

                Self::udp_to_quic(
                    udp_socket.clone(),
                    quic_send.clone(),
                    activity,
                    udp_timeout_ms,
                    shutdown_rx,
                );

                Ok(Some((udp_socket, shutdown_tx)))
            }
            Err(e) => {
                log_and_bail!("failed to bind to localhost, err: {e}");
            }
        }
    }
}
