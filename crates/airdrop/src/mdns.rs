// SPDX-License-Identifier: GPL-3.0-or-later
//! IPv6 mDNS datagrams with interface, source-address and hop-limit metadata.
use anyhow::{Context, Result, ensure};
use nix::sys::socket::{self, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn6};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{Ipv6Addr, SocketAddrV6},
    os::fd::AsRawFd,
};
use tokio::{io::Interest, net::UdpSocket};

pub(crate) struct Datagram {
    pub len: usize,
    pub source: SocketAddrV6,
    pub interface: u32,
    pub hop_limit: i32,
}
pub(crate) struct Socket {
    io: UdpSocket,
    index: u32,
    address: Ipv6Addr,
}
impl Socket {
    pub fn open(interface: &str, index: u32, address: Ipv6Addr) -> Result<Self> {
        Self::open_port(interface, index, address, 5353)
    }
    fn open_port(interface: &str, index: u32, address: Ipv6Addr, port: u16) -> Result<Self> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.bind_device(Some(interface.as_bytes()))?;
        socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        socket.join_multicast_v6(&"ff02::fb".parse()?, index)?;
        socket.set_multicast_if_v6(index)?;
        socket.set_multicast_hops_v6(255)?;
        socket.set_unicast_hops_v6(255)?;
        socket.set_multicast_loop_v6(false)?;
        socket::setsockopt(&socket, socket::sockopt::Ipv6RecvPacketInfo, &true)?;
        socket::setsockopt(&socket, socket::sockopt::Ipv6RecvHopLimit, &true)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            io: UdpSocket::from_std(socket.into())?,
            index,
            address,
        })
    }
    pub fn interface_index(&self) -> u32 {
        self.index
    }
    pub async fn send(&self, bytes: &[u8], destination: Ipv6Addr) -> Result<()> {
        ensure!(bytes.len() <= 1402, "mDNS datagram exceeds AWDL MTU");
        self.send_to(bytes, SocketAddrV6::new(destination, 5353, 0, self.index))
            .await
    }
    async fn send_to(&self, bytes: &[u8], destination: SocketAddrV6) -> Result<()> {
        let target = SockaddrIn6::from(destination);
        let packet_info = nix::libc::in6_pktinfo {
            ipi6_addr: nix::libc::in6_addr {
                s6_addr: self.address.octets(),
            },
            ipi6_ifindex: self.index,
        };
        loop {
            self.io.writable().await?;
            let result = self.io.try_io(Interest::WRITABLE, || {
                socket::sendmsg(
                    self.io.as_raw_fd(),
                    &[IoSlice::new(bytes)],
                    &[ControlMessage::Ipv6PacketInfo(&packet_info)],
                    MsgFlags::MSG_DONTWAIT,
                    Some(&target),
                )
                .map_err(io::Error::from)
            });
            if !matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
                ensure!(
                    result.context("send IPv6 mDNS datagram")? == bytes.len(),
                    "partial mDNS datagram"
                );
                return Ok(());
            }
        }
    }
    pub async fn receive(&self, bytes: &mut [u8]) -> Result<Option<Datagram>> {
        loop {
            self.io.readable().await?;
            let result = self.io.try_io(Interest::READABLE, || {
                let mut iov = [IoSliceMut::new(bytes)];
                let mut control = nix::cmsg_space!(nix::libc::in6_pktinfo, nix::libc::c_int);
                let message = socket::recvmsg::<SockaddrIn6>(
                    self.io.as_raw_fd(),
                    &mut iov,
                    Some(&mut control),
                    MsgFlags::MSG_DONTWAIT,
                )
                .map_err(io::Error::from)?;
                if message
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                {
                    return Ok(None);
                }
                let (mut interface, mut hop_limit) = (None, None);
                for field in message.cmsgs().map_err(io::Error::from)? {
                    match field {
                        ControlMessageOwned::Ipv6PacketInfo(info) => {
                            interface = Some(info.ipi6_ifindex)
                        }
                        ControlMessageOwned::Ipv6HopLimit(value) => hop_limit = Some(value),
                        _ => (),
                    }
                }
                Ok(message.address.zip(interface).zip(hop_limit).map(
                    |((source, interface), hop_limit)| Datagram {
                        len: message.bytes,
                        source: source.into(),
                        interface,
                        hop_limit,
                    },
                ))
            });
            if !matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock) {
                return result.context("receive IPv6 mDNS datagram");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn udp_preserves_scoped_source_and_receive_metadata_without_raw_sockets() {
        let index = nix::net::if_::if_nametoindex("lo").unwrap();
        let socket = Socket::open_port("lo", index, Ipv6Addr::LOCALHOST, 0).unwrap();
        let port = socket.io.local_addr().unwrap().port();
        let peer = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        socket2::SockRef::from(&peer)
            .set_unicast_hops_v6(255)
            .unwrap();
        let std::net::SocketAddr::V6(target) = peer.local_addr().unwrap() else {
            panic!("IPv6")
        };
        socket.send_to(b"query", target).await.unwrap();
        let mut bytes = [0; 64];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..n], b"query");
        assert_eq!(from.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(from.port(), port);
        peer.send_to(b"answer", from).await.unwrap();
        let packet = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.receive(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..packet.len], b"answer");
        assert_eq!(packet.source.port(), target.port());
        assert_eq!(packet.interface, index);
        assert_eq!(packet.hop_limit, 255);
    }
}
