//! UDP abstractions used by the tunneling implementation.

pub mod udp_server;
pub mod udp_tunnel;

use byte_pool::Block;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};

pub(crate) const UDP_CHANNEL_CAPACITY: usize = 1024;

/// Increase kernel buffering for burst tolerance. The OS may cap this value
/// according to its global socket-buffer limits.
pub(crate) fn configure_udp_socket(socket: &tokio::net::UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let size: libc::c_int = 4 * 1024 * 1024;
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            };
            if result != 0 {
                log::warn!(
                    "failed to enlarge UDP socket buffer: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    #[cfg(not(unix))]
    let _ = socket;
}

/// Message types used by the UDP server/tunnel tasks.
pub enum UdpMessage {
    /// A datagram with metadata about source/destination.
    Packet(UdpPacket),
    /// Request the receiver to shut down.
    Quit,
}

/// Sender half of the UDP message channel.
pub type UdpSender = Sender<UdpMessage>;
/// Receiver half of the UDP message channel.
pub type UdpReceiver = Receiver<UdpMessage>;

/// UDP datagram payload and addressing info.
pub struct UdpPacket {
    /// Backed by a shared byte pool to reduce allocations.
    pub payload: Block<'static, Vec<u8>>,
    /// Local socket address the packet arrived on or will be sent to.
    pub local_addr: SocketAddr,
    /// Optional peer address (None when not applicable).
    pub peer_addr: Option<SocketAddr>,
}
