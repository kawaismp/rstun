use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use anyhow::Result;
use log::debug;
use log::error;
use log::info;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;

use crate::udp::{configure_udp_socket, UDP_CHANNEL_CAPACITY};
pub use crate::udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};

#[derive(Debug, Clone)]
/// Lightweight UDP helper that binds a local socket and bridges packets via channels.
pub struct UdpServer(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    active: bool,
    in_udp_sender: UdpSender,
    udp_receiver: Option<UdpReceiver>,
}

impl UdpServer {
    /// Bind to the given address and start the UDP bridging task in background.
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await?;
        configure_udp_socket(&udp_socket);
        let addr = udp_socket.local_addr().unwrap();

        let (in_udp_sender, mut in_udp_receiver) = channel::<UdpMessage>(UDP_CHANNEL_CAPACITY);
        let (out_udp_sender, out_udp_receiver) = channel::<UdpMessage>(UDP_CHANNEL_CAPACITY);

        let state = Arc::new(Mutex::new(State {
            addr,
            active: false,
            in_udp_sender,
            udp_receiver: Some(out_udp_receiver),
        }));
        let state_clone = state.clone();

        // Split socket for concurrent recv/send
        let udp_socket = Arc::new(udp_socket);
        let recv_socket = udp_socket.clone();
        let send_socket = udp_socket.clone();

        // Spawn separate recv task
        let recv_state = state.clone();
        tokio::spawn(async move {
            let mut recv_buffer = vec![0u8; UDP_PACKET_SIZE];
            loop {
                match recv_socket.recv_from(&mut recv_buffer).await {
                    Ok((size, local_addr)) => {
                        let active = recv_state.lock().active;
                        if !active {
                            debug!("drop the packet ({size}) from addr: {local_addr}");
                            continue;
                        }

                        let mut payload = BUFFER_POOL.alloc_and_fill(size.max(1));
                        payload[..size].copy_from_slice(&recv_buffer[..size]);
                        payload.truncate(size);
                        let msg = UdpMessage::Packet(UdpPacket {
                            payload,
                            local_addr,
                            peer_addr: None,
                        });

                        // Apply backpressure instead of silently dropping a burst in userspace.
                        match out_udp_sender.send(msg).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!(
                                    "receiving end of the channel is closed, will quit recv task"
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("failed to read from local udp socket, err: {e}");
                    }
                }
            }
            info!("udp recv task quit: {addr}");
        });

        // Spawn separate send task
        tokio::spawn(async move {
            loop {
                match in_udp_receiver.recv().await {
                    Some(UdpMessage::Packet(p)) => {
                        match send_socket.send_to(&p.payload, p.local_addr).await {
                            Ok(_) => {
                                // succeeded
                            }
                            Err(e) => {
                                error!("failed to send packet to local, err: {e}");
                            }
                        }
                    }
                    Some(UdpMessage::Quit) => {
                        info!("udp send task is requested to quit");
                        break;
                    }
                    None => {
                        // all senders quit
                        info!("udp send task quit");
                        break;
                    }
                }
            }
            info!("udp send task quit: {addr}");
        });

        Ok(Self(state_clone))
    }

    /// Get the bound local address.
    pub fn addr(&self) -> SocketAddr {
        self.0.lock().addr
    }

    /// Ask the UDP server to shut down gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        let udp_sender = self.0.lock().in_udp_sender.clone();
        udp_sender.send(UdpMessage::Quit).await?;
        Ok(())
    }

    /// Mark the server active/inactive. When inactive, inbound packets are dropped.
    pub fn set_active(&mut self, active: bool) {
        self.0.lock().active = active
    }

    /// Take the receiver side of the channel for reading inbound UDP packets (activates server).
    pub fn take_receiver(&mut self) -> UdpReceiver {
        let mut state = self.0.lock();
        state.active = true;
        state.udp_receiver.take().unwrap()
    }

    /// Put back a previously taken receiver (deactivates server).
    pub fn put_receiver(&mut self, udp_receiver: UdpReceiver) {
        let mut state = self.0.lock();
        state.active = false;
        state.udp_receiver = Some(udp_receiver);
    }

    /// Clone the sender used for delivering packets to the local UDP socket.
    pub fn clone_sender(&self) -> UdpSender {
        self.0.lock().in_udp_sender.clone()
    }
}
