//! Serializable messages exchanged over QUIC control/data streams.
//!
//! This module defines the messages used for controlling the tunnel
//! lifecycle and for coordinating per-packet operations between
//! client and server.
use crate::Tunnel;
use anyhow::Result;
use anyhow::{bail, Context};

use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_UDP_BATCH_BYTES: usize = 128 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Control/data messages used during login and per-packet coordination.
pub enum TunnelMessage {
    /// Client → Server: authenticate and declare desired tunnel.
    ReqLogin(LoginInfo),
    /// Server → Client: failure with reason.
    RespFailure(String),
    /// Server ↔ Client: success acknowledgement.
    RespSuccess,
    /// Server → Client: success, but took over an existing connection.
    RespSuccessPreempted,
    /// Server → Client: Are you still alive?
    Ping,
    /// Client → Server: Yes, I am.
    Pong,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Login payload containing password and requested tunnel description.
pub(crate) struct LoginInfo {
    pub password: String,
    pub tunnel: Tunnel,
}

impl LoginInfo {
    /// Format a human-friendly description including the remote address.
    pub fn format_with_remote_addr(&self, remote_addr: &SocketAddr) -> String {
        match &self.tunnel {
            Tunnel::ChannelBased(upstream_type) => {
                format!("{upstream_type}_ChannelBased →  {remote_addr}")
            }
            Tunnel::NetworkBased(cfg) => {
                let upstream = &cfg.upstream;
                let upstream_str = if let Some(upstream) = upstream.upstream_addr {
                    if upstream.ip().is_loopback() {
                        format!("{}:{}", remote_addr.ip(), upstream.port())
                    } else {
                        format!("{upstream}")
                    }
                } else {
                    String::from("PeerDefault")
                };

                format!(
                    "{} →  {} →  {remote_addr} →  {upstream_str}",
                    upstream.upstream_type, cfg.local_server_addr
                )
            }
        }
    }
}

impl Display for LoginInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.tunnel {
            Tunnel::ChannelBased(upstream_type) => {
                f.write_str(format!("{upstream_type}_ChannelBased").as_str())
            }
            Tunnel::NetworkBased(cfg) => {
                f.write_str(format!("{}", cfg.upstream.upstream_type).as_str())
            }
        }
    }
}

impl Display for TunnelMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReqLogin(login_info) => f.write_str(login_info.to_string().as_str()),
            Self::RespFailure(msg) => f.write_str(format!("fail:{msg}").as_str()),
            Self::RespSuccess => f.write_str("succeeded"),
            Self::RespSuccessPreempted => f.write_str("succeeded (preempted old connection)"),
            Self::Ping => f.write_str("ping"),
            Self::Pong => f.write_str("pong"),
        }
    }
}

impl TunnelMessage {
    /// Receive and decode a TunnelMessage from the given QUIC recv stream.
    pub async fn recv(quic_recv: &mut RecvStream) -> Result<TunnelMessage> {
        let msg_len = quic_recv.read_u32().await? as usize;
        let mut msg = vec![0; msg_len];
        quic_recv
            .read_exact(&mut msg)
            .await
            .context("read message failed")?;

        let tun_msg =
            postcard::from_bytes::<TunnelMessage>(&msg).context("deserialize message failed")?;
        Ok(tun_msg)
    }

    /// Encode and send a TunnelMessage via the given QUIC send stream.
    pub async fn send(quic_send: &mut SendStream, msg: &TunnelMessage) -> Result<()> {
        let msg = postcard::to_allocvec(msg).context("serialize message failed")?;
        quic_send.write_u32(msg.len() as u32).await?;
        quic_send.write_all(&msg).await?;
        Ok(())
    }

    /// Convenience to send a failure response and flush.
    pub async fn send_failure(quic_send: &mut SendStream, msg: String) -> Result<()> {
        let msg = TunnelMessage::RespFailure(msg);
        Self::send(quic_send, &msg).await?;
        quic_send.flush().await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }

    /// Start a reusable UDP batch with room for its wire-length prefix.
    pub fn start_udp_batch(output: &mut Vec<u8>) {
        output.clear();
        output.extend_from_slice(&[0; 4]);
    }

    /// Fill in a UDP batch's length prefix before writing it to QUIC.
    pub fn finish_udp_batch(output: &mut [u8]) -> Result<()> {
        let body_len = output
            .len()
            .checked_sub(4)
            .context("UDP batch is missing its length prefix")?;
        let body_len = u32::try_from(body_len).context("UDP batch exceeds 4 GiB")?;
        output[..4].copy_from_slice(&body_len.to_be_bytes());
        Ok(())
    }

    /// Append the optional dynamic destination and payload as one compact UDP frame.
    pub fn append_udp_packet(
        output: &mut Vec<u8>,
        peer_addr: Option<SocketAddr>,
        data: &[u8],
    ) -> Result<()> {
        let msg_len = u16::try_from(data.len()).context("datagram payload exceeds 65535 bytes")?;
        let mut header = [0u8; 21];
        let mut cursor = 1;

        match peer_addr {
            None => header[0] = 0,
            Some(SocketAddr::V4(addr)) => {
                header[0] = 4;
                header[cursor..cursor + 4].copy_from_slice(&addr.ip().octets());
                cursor += 4;
                header[cursor..cursor + 2].copy_from_slice(&addr.port().to_be_bytes());
                cursor += 2;
            }
            Some(SocketAddr::V6(addr)) => {
                header[0] = 6;
                header[cursor..cursor + 16].copy_from_slice(&addr.ip().octets());
                cursor += 16;
                header[cursor..cursor + 2].copy_from_slice(&addr.port().to_be_bytes());
                cursor += 2;
            }
        }

        header[cursor..cursor + 2].copy_from_slice(&msg_len.to_be_bytes());
        cursor += 2;
        output.reserve(cursor + data.len());
        output.extend_from_slice(&header[..cursor]);
        output.extend_from_slice(data);
        Ok(())
    }

    /// Receive one complete UDP batch with two QUIC reads regardless of packet count.
    pub async fn recv_udp_batch(quic_recv: &mut RecvStream, data: &mut Vec<u8>) -> Result<()> {
        let batch_len = quic_recv.read_u32().await? as usize;
        if batch_len > MAX_UDP_BATCH_BYTES {
            bail!("UDP batch too large: {batch_len}");
        }
        data.resize(batch_len, 0);
        quic_recv
            .read_exact(data)
            .await
            .context("read UDP batch failed")?;
        Ok(())
    }

    /// Decode the next packet from an in-memory UDP batch.
    pub fn decode_udp_packet<'a>(
        data: &'a [u8],
        cursor: &mut usize,
    ) -> Result<Option<(Option<SocketAddr>, &'a [u8])>> {
        fn take<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
            let end = cursor
                .checked_add(len)
                .context("UDP frame length overflow")?;
            let value = data.get(*cursor..end).context("truncated UDP frame")?;
            *cursor = end;
            Ok(value)
        }

        if *cursor == data.len() {
            return Ok(None);
        }

        let family = take(data, cursor, 1)?[0];
        let peer_addr = match family {
            0 => None,
            4 => {
                let encoded = take(data, cursor, 6)?;
                Some(SocketAddr::new(
                    Ipv4Addr::new(encoded[0], encoded[1], encoded[2], encoded[3]).into(),
                    u16::from_be_bytes([encoded[4], encoded[5]]),
                ))
            }
            6 => {
                let encoded = take(data, cursor, 18)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&encoded[..16]);
                Some(SocketAddr::new(
                    Ipv6Addr::from(octets).into(),
                    u16::from_be_bytes([encoded[16], encoded[17]]),
                ))
            }
            family => bail!("invalid UDP address family marker: {family}"),
        };

        let encoded_len = take(data, cursor, 2)?;
        let payload_len = u16::from_be_bytes([encoded_len[0], encoded_len[1]]) as usize;
        let payload = take(data, cursor, payload_len)?;
        Ok(Some((peer_addr, payload)))
    }

    /// Validate a response message, returning Ok for RespSuccess else error.
    pub fn handle_message(msg: &TunnelMessage) -> Result<()> {
        match msg {
            TunnelMessage::RespSuccess | TunnelMessage::RespSuccessPreempted => Ok(()),
            TunnelMessage::RespFailure(msg) => bail!(format!("received failure, err: {msg}")),
            _ => bail!("unexpected message type"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TunnelMessage;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn compact_udp_frame_without_peer_address() {
        let mut frame = Vec::new();
        TunnelMessage::append_udp_packet(&mut frame, None, b"abc").unwrap();
        assert_eq!(frame, [0, 0, 3, b'a', b'b', b'c']);

        let mut cursor = 0;
        let (peer, payload) = TunnelMessage::decode_udp_packet(&frame, &mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(peer, None);
        assert_eq!(payload, b"abc");
        assert!(TunnelMessage::decode_udp_packet(&frame, &mut cursor)
            .unwrap()
            .is_none());
    }

    #[test]
    fn compact_udp_frame_with_ipv4_peer_address() {
        let mut frame = Vec::new();
        let peer = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 8080);
        TunnelMessage::append_udp_packet(&mut frame, Some(peer), b"x").unwrap();
        assert_eq!(frame, [4, 192, 0, 2, 1, 0x1f, 0x90, 0, 1, b'x']);

        let mut cursor = 0;
        let (decoded_peer, payload) = TunnelMessage::decode_udp_packet(&frame, &mut cursor)
            .unwrap()
            .unwrap();
        assert_eq!(decoded_peer, Some(peer));
        assert_eq!(payload, b"x");
    }

    #[test]
    fn compact_udp_frame_with_ipv6_peer_address() {
        let mut frame = Vec::new();
        let peer = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 53);
        TunnelMessage::append_udp_packet(&mut frame, Some(peer), b"z").unwrap();
        assert_eq!(frame.len(), 22);
        assert_eq!(frame[0], 6);
        assert_eq!(&frame[1..17], &Ipv6Addr::LOCALHOST.octets());
        assert_eq!(&frame[17..], &[0, 53, 0, 1, b'z']);
    }
}
