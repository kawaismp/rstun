use crate::tcp::{StreamMessage, StreamReceiver, StreamRequest, StreamSender};
use anyhow::Result;
use log::{debug, error, info};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::error::SendTimeoutError;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[derive(Debug, Clone)]
/// Lightweight TCP listener that forwards accepted connections to a channel.
pub struct TcpServer {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    addr: SocketAddr,
    tcp_sender: StreamSender<TcpStream>,
    tcp_receiver: Option<StreamReceiver<TcpStream>>,
    active: bool,
    terminated: bool,
}

impl TcpServer {
    /// Bind to the given address and start accepting connections in background.
    /// Returns a handle to control the server and obtain the receiver channel.
    pub async fn bind_and_start(addr: SocketAddr) -> Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let addr = tcp_listener.local_addr().unwrap();

        // Configure socket for performance
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = tcp_listener.as_raw_fd();
            Self::optimize_socket(fd);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let socket = tcp_listener.as_raw_socket();
            Self::optimize_socket_windows(socket);
        }

        let (tcp_sender, tcp_receiver) = channel(128);
        let state = Arc::new(Mutex::new(State {
            addr,
            tcp_sender: tcp_sender.clone(),
            tcp_receiver: Some(tcp_receiver),
            active: false,
            terminated: false,
        }));
        let state_clone = state.clone();

        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((stream, addr)) => {
                        if let Err(e) = stream.set_nodelay(true) {
                            error!("failed to set TCP_NODELAY: {e}");
                        }

                        {
                            let (terminated, active) = {
                                let state = state.lock();
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

        Ok(Self { state: state_clone })
    }

    /// Request the server to shutdown gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        let addr = {
            let mut state = self.state.lock();
            state.terminated = true;
            state.addr
        };
        // initiate a new connection to wake up the accept() loop
        TcpStream::connect(addr).await?;
        Ok(())
    }

    /// Get the bound local address.
    pub fn addr(&self) -> SocketAddr {
        self.state.lock().addr
    }

    /// Take the receiver channel for accepted streams (sets server active=true).
    pub fn take_receiver(&mut self) -> StreamReceiver<TcpStream> {
        let mut state = self.state.lock();
        state.active = true;
        state.tcp_receiver.take().unwrap()
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

    /// Optimize TCP socket for low latency and high throughput
    #[cfg(unix)]
    fn optimize_socket(fd: std::os::unix::prelude::RawFd) {
        use libc::{setsockopt, IPPROTO_TCP, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF, TCP_NODELAY};

        unsafe {
            // Disable Nagle's algorithm for lower latency
            let nodelay: libc::c_int = 1;
            setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_NODELAY,
                &nodelay as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            // Increase socket buffers for better throughput (512KB each)
            let buffer_size: libc::c_int = 524288;
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &buffer_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &buffer_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            // Enable TCP_QUICKACK on Linux for lower latency
            #[cfg(target_os = "linux")]
            {
                let quickack: libc::c_int = 1;
                setsockopt(
                    fd,
                    IPPROTO_TCP,
                    libc::TCP_QUICKACK,
                    &quickack as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    /// Optimize TCP socket for Windows
    #[cfg(windows)]
    fn optimize_socket_windows(socket: std::os::windows::prelude::RawSocket) {
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_TCP, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF, TCP_NODELAY,
        };

        unsafe {
            // Disable Nagle's algorithm
            let nodelay: i32 = 1;
            setsockopt(
                socket as usize,
                IPPROTO_TCP as i32,
                TCP_NODELAY,
                &nodelay as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );

            // Increase socket buffers (512KB each)
            let buffer_size: i32 = 524288;
            setsockopt(
                socket as usize,
                SOL_SOCKET as i32,
                SO_RCVBUF,
                &buffer_size as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
            setsockopt(
                socket as usize,
                SOL_SOCKET as i32,
                SO_SNDBUF,
                &buffer_size as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}
