//! TCP tunneling helpers built on top of QUIC bidirectional streams.
//!
//! This module provides a `TcpTunnel` struct that offers methods to serve and accept TCP
//! connections over QUIC. It bridges accepted streams to QUIC bidirectional streams, allowing
//! for seamless TCP tunneling.
//!
//! # Examples
//!
//! ```rust,ignore
//! use quinn::Connection;
//! use std::net::SocketAddr;
//!
//! async fn example(conn: &Connection, addr: SocketAddr) {
//!     // Serving TCP connections over QUIC.
//!     // TcpTunnel::start_serving::<YourAsyncStreamType>(
//!     //     true,    // tunnel_out: true for OUT mode, false for IN mode
//!     //     conn,
//!     //     &mut your_stream_receiver,
//!     //     &mut None, // no pending request initially
//!     //     5000,      // stream timeout in milliseconds
//!     // ).await;
//!
//!     // Accepting QUIC streams and connecting to upstream TCP endpoint.
//!     // TcpTunnel::start_accepting(
//!     //     conn,
//!     //     Some(addr), // upstream TCP address
//!     //     5000,       // stream timeout in milliseconds
//!     // ).await;
//! }
//! ```

use crate::tcp::StreamMessage;
use crate::tcp::{AsyncStream, StreamReceiver, StreamRequest};
use crate::util::stream_util::StreamUtil;
use log::{debug, error, info};
use std::borrow::BorrowMut;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

pub struct TcpTunnel;

impl TcpTunnel {
    /// Serve outbound or inbound TCP by bridging accepted streams to QUIC.
    ///
    /// - `tunnel_out`: true for OUT mode logs, false for IN mode.
    /// - `pending_request`: used to retry the last request on transient errors.
    pub async fn start_serving<S: AsyncStream>(
        tunnel_out: bool,
        conn: &quinn::Connection,
        stream_receiver: &mut StreamReceiver<S>,
        pending_request: &mut Option<StreamRequest<S>>,
        stream_timeout_ms: u64,
    ) {
        loop {
            let request = match pending_request.take() {
                Some(request) => request,
                None => match stream_receiver.borrow_mut().recv().await {
                    Some(StreamMessage::Request(request)) => request,
                    _ => break,
                },
            };

            match conn.open_bi().await {
                Ok((mut quic_send, quic_recv)) => {
                    if let Err(e) =
                        StreamUtil::write_socket_addr(&mut quic_send, &request.dst_addr, false)
                            .await
                    {
                        error!("failed to send dst addr: {e}");
                        *pending_request = Some(request);
                        continue;
                    }
                    StreamUtil::start_flowing(
                        if tunnel_out { "OUT" } else { "IN" },
                        request.stream,
                        (quic_send, quic_recv),
                        stream_timeout_ms,
                    )
                }
                Err(e) => {
                    error!("failed to open_bi, will retry: {e}");
                    *pending_request = Some(request);
                    break;
                }
            }
        }
        // the tcp server will be reused when tunnel reconnects
    }

    /// Accept peer QUIC streams and connect to the upstream TCP endpoint.
    pub async fn start_accepting(
        conn: &quinn::Connection,
        upstream_addr: Option<SocketAddr>,
        stream_timeout_ms: u64,
    ) {
        let remote_addr = &conn.remote_address();
        info!("start tcp streaming, {remote_addr} ↔  {upstream_addr:?}");

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
                    error!("failed to open accept_bi: {remote_addr}, err: {e}");
                    break;
                }
                Ok((quic_send, mut quic_recv)) => tokio::spawn(async move {
                    let dst_addr = match upstream_addr {
                        Some(dst_addr) => dst_addr,
                        None => {
                            match StreamUtil::read_socket_addr(&mut quic_recv, stream_timeout_ms)
                                .await
                            {
                                Ok(dst_addr) => dst_addr,
                                Err(e) => {
                                    log::error!("failed to read dst address: {e}");
                                    return;
                                }
                            }
                        }
                    };

                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        TcpStream::connect(&dst_addr),
                    )
                    .await
                    {
                        Ok(Ok(request)) => {
                            // Optimize the accepted TCP stream for performance
                            Self::optimize_tcp_stream(&request);
                            StreamUtil::start_flowing(
                                "OUT",
                                request,
                                (quic_send, quic_recv),
                                stream_timeout_ms,
                            )
                        },
                        Ok(Err(e)) => error!("failed to connect to {dst_addr}, err: {e}"),
                        Err(_) => error!("timeout connecting to {dst_addr}"),
                    }
                }),
            };
        }
    }

    /// Optimize TCP stream for low latency and high throughput
    fn optimize_tcp_stream(stream: &TcpStream) {
        // Set TCP_NODELAY to disable Nagle's algorithm
        if let Err(e) = stream.set_nodelay(true) {
            error!("failed to set TCP_NODELAY: {e}");
        }

        #[cfg(unix)]
        {
            use libc::{setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
            let fd = stream.as_raw_fd();
            
            unsafe {
                // Increase socket buffers (512KB each)
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
                        libc::IPPROTO_TCP,
                        libc::TCP_QUICKACK,
                        &quickack as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF};
            
            let socket = stream.as_raw_socket();
            unsafe {
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
}
