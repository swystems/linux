// SPDX-License-Identifier: GPL-2.0

//! UDP socket wrapper.
//!
//! This module contains wrappers for a UDP Socket ([`UdpSocket`]).
//! The wrapper is just convenience structs around the generic [`Socket`] type.
//!
//! The API is inspired by the Rust standard library's [`UdpSocket`](https://doc.rust-lang.org/std/net/struct.UdpSocket.html).

use crate::error::Result;
use crate::net::addr::SocketAddr;
use crate::net::socket::flags::{ReceiveFlag, SendFlag};
use crate::net::socket::{SockType, Socket};
use crate::net::{AddressFamily, IpProtocol};

/// A UDP socket.
///
/// Provides an interface to send and receive UDP packets, removing
/// all the socket functionality that is not needed for UDP.
///
/// # Examples
/// ```rust
/// use kernel::net::udp::UdpSocket;
/// use kernel::net::addr::*;
///
/// let socket = UdpSocket::new().unwrap();
/// socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000))).unwrap();
/// let mut buf = [0u8; 1024];
/// while let Ok((len, addr)) = socket.receive(&mut buf, []) {
///     socket.send(&buf[..len], &addr, []).unwrap();
/// }
/// ```
pub struct UdpSocket(pub(crate) Socket);

impl UdpSocket {
    /// Creates a UDP socket.
    /// Returns a [`UdpSocket`] on success.
    pub fn new() -> Result<Self> {
        Ok(Self(Socket::new(
            AddressFamily::Inet,
            SockType::Datagram,
            IpProtocol::Udp,
        )?))
    }

    /// Binds the socket to the given address.
    pub fn bind(&self, address: SocketAddr) -> Result {
        self.0.bind(address)
    }

    /// Returns the socket's local address.
    pub fn sockname(&self) -> Result<SocketAddr> {
        self.0.sockname()
    }

    /// Receives data from another socket.
    /// The given flags are used to modify the behavior of the receive operation.
    /// See [`ReceiveFlag`] for more.
    ///
    /// Returns the number of bytes received and the address of the sender.
    pub fn receive(
        &self,
        buf: &mut [u8],
        flags: impl IntoIterator<Item = ReceiveFlag>,
    ) -> Result<(usize, SocketAddr)> {
        self.0
            .receive_from(buf, flags)
            .map(|(size, addr)| (size, addr.unwrap()))
    }

    /// Sends data to another socket.
    /// The given flags are used to modify the behavior of the send operation.
    /// See [`SendFlag`] for more.
    ///
    /// Returns the number of bytes sent.
    pub fn send(
        &self,
        buf: &[u8],
        address: &SocketAddr,
        flags: impl IntoIterator<Item = SendFlag>,
    ) -> Result<usize> {
        self.0.send_to(buf, &address, flags)
    }
}
