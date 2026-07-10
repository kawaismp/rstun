use crate::BUFFER_POOL;
use crate::UDP_PACKET_SIZE;
use anyhow::{Context, Result};
use log::debug;
use log::error;
use log::info;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::channel;
use tokio::sync::watch;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::udp::{configure_udp_socket, UDP_CHANNEL_CAPACITY};
pub use crate::udp::{UdpMessage, UdpPacket, UdpReceiver, UdpSender};

#[derive(Debug, Clone)]
/// Lightweight UDP helper that binds a local socket and bridges packets via channels.
pub struct UdpServer(Arc<Mutex<State>>, Arc<()>);

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    active: bool,
    in_udp_sender: UdpSender,
    udp_receiver: Option<UdpReceiver>,
    terminated: bool,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    shutdown_complete: Arc<Notify>,
    completed: bool,
}

impl UdpServer {
    /// Bind to the given address and start the UDP bridging task in background.
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await?;
        configure_udp_socket(&udp_socket);
        let addr = udp_socket.local_addr().unwrap();

        let (in_udp_sender, mut in_udp_receiver) = channel::<UdpMessage>(UDP_CHANNEL_CAPACITY);
        let (out_udp_sender, out_udp_receiver) = channel::<UdpMessage>(UDP_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let state = Arc::new(Mutex::new(State {
            addr,
            active: false,
            in_udp_sender,
            udp_receiver: Some(out_udp_receiver),
            terminated: false,
            shutdown_tx,
            tasks: Vec::new(),
            shutdown_complete: Arc::new(Notify::new()),
            completed: false,
        }));
        let state_clone = state.clone();

        // Split socket for concurrent recv/send
        let udp_socket = Arc::new(udp_socket);
        let recv_socket = udp_socket.clone();
        let send_socket = udp_socket.clone();

        // Spawn separate recv task
        let recv_state = state.clone();
        let mut recv_shutdown = shutdown_rx.clone();
        let recv_task = tokio::spawn(async move {
            let mut recv_buffer = vec![0u8; UDP_PACKET_SIZE];
            loop {
                let received = tokio::select! {
                    changed = recv_shutdown.changed() => {
                        if changed.is_err() || *recv_shutdown.borrow() {
                            break;
                        }
                        continue;
                    }
                    received = recv_socket.recv_from(&mut recv_buffer) => received,
                };

                match received {
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
        let mut send_shutdown = shutdown_rx;
        let send_task = tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    changed = send_shutdown.changed() => {
                        if changed.is_err() || *send_shutdown.borrow() {
                            break;
                        }
                        continue;
                    }
                    message = in_udp_receiver.recv() => message,
                };

                match message {
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

        state.lock().tasks.extend([recv_task, send_task]);

        Ok(Self(state_clone, Arc::new(())))
    }

    /// Get the bound local address.
    pub fn addr(&self) -> SocketAddr {
        self.0.lock().addr
    }

    /// Ask the UDP server to shut down gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        let (tasks, shutdown_complete, completed) = {
            let mut state = self.0.lock();
            if !state.terminated {
                state.terminated = true;
                state.shutdown_tx.send(true).ok();
            }
            (
                std::mem::take(&mut state.tasks),
                state.shutdown_complete.clone(),
                state.completed,
            )
        };

        if tasks.is_empty() {
            if !completed {
                loop {
                    let notified = shutdown_complete.notified();
                    if self.0.lock().completed {
                        break;
                    }
                    notified.await;
                }
            }
        } else {
            let mut result = Ok(());
            for task in tasks {
                if let Err(error) = task.await {
                    result = Err(error);
                }
            }
            let mut state = self.0.lock();
            state.completed = true;
            state.shutdown_complete.notify_waiters();
            result?;
        }
        Ok(())
    }

    /// Mark the server active/inactive. When inactive, inbound packets are dropped.
    pub fn set_active(&mut self, active: bool) {
        self.0.lock().active = active
    }

    /// Take the receiver side of the channel for reading inbound UDP packets (activates server).
    pub fn take_receiver(&mut self) -> Result<UdpReceiver> {
        let mut state = self.0.lock();
        state.active = true;
        state
            .udp_receiver
            .take()
            .context("UDP receiver has already been taken")
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

impl Drop for UdpServer {
    fn drop(&mut self) {
        if Arc::strong_count(&self.1) == 1 {
            let mut state = self.0.lock();
            if !state.terminated {
                state.terminated = true;
                state.shutdown_tx.send(true).ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UdpServer;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn concurrent_shutdown_waits_until_udp_port_is_released() {
        let mut server = UdpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let addr = server.addr();
        let mut clone = server.clone();

        let (first, second) = tokio::join!(server.shutdown(), clone.shutdown());
        first.unwrap();
        second.unwrap();

        UdpSocket::bind(addr).await.unwrap();
    }

    #[tokio::test]
    async fn dropping_last_handle_releases_udp_port() {
        let server = UdpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let addr = server.addr();
        drop(server);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if UdpSocket::bind(addr).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn taking_udp_receiver_twice_returns_error() {
        let mut server = UdpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let _receiver = server.take_receiver().unwrap();
        assert!(server.take_receiver().is_err());
        server.shutdown().await.unwrap();
    }
}
