use crate::tcp::{StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use anyhow::{Context, Result};
use log::{debug, error, info};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::error::SendTimeoutError;
use tokio::sync::watch;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
/// Lightweight TCP listener that forwards accepted connections to a channel.
pub struct TcpServer {
    state: Arc<Mutex<State>>,
    owners: Arc<()>,
}

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    tcp_sender: StreamSender<TcpStream>,
    tcp_receiver: Option<StreamReceiver<TcpStream>>,
    active: bool,
    terminated: bool,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    shutdown_complete: Arc<Notify>,
    completed: bool,
}

impl TcpServer {
    /// Bind to the given address and start accepting connections in background.
    /// Returns a handle to control the server and obtain the receiver channel.
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let addr = tcp_listener.local_addr().unwrap();

        let (tcp_sender, tcp_receiver) = channel(128);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let state = Arc::new(Mutex::new(State {
            addr,
            tcp_sender: tcp_sender.clone(),
            tcp_receiver: Some(tcp_receiver),
            active: false,
            terminated: false,
            shutdown_tx,
            task: None,
            shutdown_complete: Arc::new(Notify::new()),
            completed: false,
        }));
        let state_clone = state.clone();
        let task_state = state.clone();

        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                    accepted = tcp_listener.accept() => accepted,
                };

                match accepted {
                    Ok((stream, addr)) => {
                        if let Err(e) = stream.set_nodelay(true) {
                            error!("failed to set TCP_NODELAY: {e}");
                        }

                        #[cfg(target_os = "linux")]
                        if let Err(e) = stream.set_quickack(true) {
                            error!("failed to set TCP_QUICKACK: {e}");
                        }

                        {
                            let (terminated, active) = {
                                let state = task_state.lock();
                                (state.terminated, state.active)
                            };

                            if terminated {
                                tcp_sender.send(StreamMessage::Quit).await.ok();
                                break;
                            }

                            if !active {
                                // unless being explicitly requested, always drop the connections because we are not
                                // sure whether the receiver is ready to aceept connections
                                debug!("drop connection: {addr}");
                                continue;
                            }
                        }

                        match tcp_sender
                            .send_timeout(
                                StreamMessage::Request(StreamRequest {
                                    stream,
                                    dst_addr: None,
                                }),
                                Duration::from_millis(300),
                            )
                            .await
                        {
                            Ok(_) => {
                                // succeeded
                            }
                            Err(SendTimeoutError::Timeout(_)) => {
                                debug!("timedout sending the request, drop the stream");
                            }
                            Err(e) => {
                                info!("channel is closed, will quit tcp server, err: {e}");
                                break;
                            }
                        }
                    }

                    Err(e) => {
                        error!("tcp server failed, err: {e}");
                    }
                }
            }
            info!("tcp server quit: {addr}");
        });

        state.lock().task = Some(task);

        Ok(Self {
            state: state_clone,
            owners: Arc::new(()),
        })
    }

    /// Request the server to shutdown gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        let (sender, task, shutdown_complete, completed) = {
            let mut state = self.state.lock();
            let sender = if state.terminated {
                None
            } else {
                state.terminated = true;
                state.shutdown_tx.send(true).ok();
                Some(state.tcp_sender.clone())
            };
            (
                sender,
                state.task.take(),
                state.shutdown_complete.clone(),
                state.completed,
            )
        };

        if let Some(sender) = sender {
            sender
                .send_timeout(StreamMessage::Quit, Duration::from_millis(300))
                .await
                .ok();
        }
        if let Some(task) = task {
            let result = task.await;
            let mut state = self.state.lock();
            state.completed = true;
            state.shutdown_complete.notify_waiters();
            result?;
        } else if !completed {
            loop {
                let notified = shutdown_complete.notified();
                if self.state.lock().completed {
                    break;
                }
                notified.await;
            }
        }
        Ok(())
    }

    /// Get the bound local address.
    pub fn addr(&self) -> SocketAddr {
        self.state.lock().addr
    }

    /// Take the receiver channel for accepted streams (sets server active=true).
    pub fn take_receiver(&mut self) -> Result<StreamReceiver<TcpStream>> {
        let mut state = self.state.lock();
        state.active = true;
        state
            .tcp_receiver
            .take()
            .context("TCP receiver has already been taken")
    }

    /// Put back a previously taken receiver channel (sets server active=false).
    pub fn put_receiver(&mut self, tcp_receiver: StreamReceiver<TcpStream>) {
        let mut state = self.state.lock();
        state.active = false;
        state.tcp_receiver = Some(tcp_receiver);
    }

    /// Clone a sender to receive future stream requests.
    pub fn clone_sender(&self) -> StreamSender<TcpStream> {
        self.state.lock().tcp_sender.clone()
    }
}

impl Drop for TcpServer {
    fn drop(&mut self) {
        if Arc::strong_count(&self.owners) == 1 {
            let mut state = self.state.lock();
            if !state.terminated {
                state.terminated = true;
                state.shutdown_tx.send(true).ok();
                state.tcp_sender.try_send(StreamMessage::Quit).ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TcpServer;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn concurrent_shutdown_waits_until_tcp_port_is_released() {
        let mut server = TcpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let addr = server.addr();
        let mut clone = server.clone();

        let (first, second) = tokio::join!(server.shutdown(), clone.shutdown());
        first.unwrap();
        second.unwrap();

        TcpListener::bind(addr).await.unwrap();
    }

    #[tokio::test]
    async fn dropping_last_handle_releases_tcp_port() {
        let server = TcpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let addr = server.addr();
        drop(server);

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if TcpListener::bind(addr).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn taking_tcp_receiver_twice_returns_error() {
        let mut server = TcpServer::bind_and_start(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
            .await
            .unwrap();
        let _receiver = server.take_receiver().unwrap();
        assert!(server.take_receiver().is_err());
        server.shutdown().await.unwrap();
    }
}
