// SPDX-License-Identifier: GPL-2.0

//! TCP socket wrapper.
//!
//! This module contains wrappers for a TCP Socket ([`TcpListener`]) and an active
//! TCP connection ([`TcpStream`]).
//! The wrappers are just convenience structs around the generic [`Socket`] type.
//!
//! The API is inspired by the Rust standard library's [`TcpListener`](https://doc.rust-lang.org/std/net/struct.TcpListener.html) and [`TcpStream`](https://doc.rust-lang.org/std/net/struct.TcpStream.html).

use crate::error::Result;
use crate::net::addr::SocketAddr;
use crate::net::socket::flags::{ReceiveFlag, SendFlag};
use crate::net::socket::{ShutdownCmd, SockType, Socket};
use crate::net::{AddressFamily, IpProtocol};

/// A TCP listener.
/// Wraps the [`Socket`] type to create a TCP-specific interface.
///
/// The wrapper abstracts away the generic Socket methods that a connection-oriented
/// protocol like TCP does not need.
///
/// # Examples
/// ```rust
/// use kernel::net::tcp::TcpListener;
/// use kernel::net::addr::*;
///
/// let listener = TcpListener::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000))).unwrap();
/// while let Ok(stream) = listener.accept() {
///   // ...
/// }
pub struct TcpListener(pub(crate) Socket);

impl TcpListener {
    /// Create a new TCP listener bound to the given address.
    /// The listener will be ready to accept connections.
    pub fn new(address: SocketAddr) -> Result<Self> {
        let socket = Socket::new(AddressFamily::Inet, SockType::Stream, IpProtocol::Tcp)?;
        socket.bind(address)?;
        socket.listen(128)?;
        Ok(Self(socket))
    }
    /// Accepts an incoming connection.
    /// Returns a [`TcpStream`] on success.
    pub fn accept(&self) -> Result<TcpStream> {
        Ok(TcpStream(self.0.accept(true)?))
    }
}

/// A TCP stream.
/// Represents an active TCP connection between two sockets.
///
/// See [`TcpListener`] for an example of how to create a [`TcpStream`].
pub struct TcpStream(pub(crate) Socket);

impl TcpStream {
    /// Receive data from the stream.
    /// The given flags are used to modify the behavior of the receive operation.
    /// See [`ReceiveFlag`] for more.
    ///
    /// Returns the number of bytes received.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::tcp::TcpListener;
    /// use kernel::net::addr::*;
    ///
    /// let listener = TcpListener::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000))).unwrap();
    /// while let Ok(stream) = listener.accept() {
    ///     let mut buf = [0u8; 1024];
    ///     while let Ok(len) = stream.receive(&mut buf, []) {
    ///         // ...
    ///     }
    /// }
    /// ```
    pub fn receive(
        &self,
        buf: &mut [u8],
        flags: impl IntoIterator<Item = ReceiveFlag>,
    ) -> Result<usize> {
        self.0.receive(buf, flags)
    }

    /// Send data to the stream.
    /// The given flags are used to modify the behavior of the send operation.
    /// See [`SendFlag`] for more.
    ///
    /// Returns the number of bytes sent.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::tcp::TcpListener;
    /// use kernel::net::addr::*;
    ///
    /// let listener = TcpListener::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000))).unwrap();
    /// while let Ok(stream) = listener.accept() {
    ///     let mut buf = [0u8; 1024];
    ///     while let Ok(len) = stream.receive(&mut buf, []) {
    ///         stream.send(&buf[..len], [])?;
    ///     }
    /// }
    pub fn send(&self, buf: &[u8], flags: impl IntoIterator<Item = SendFlag>) -> Result<usize> {
        self.0.send(buf, flags)
    }
}

impl Drop for TcpStream {
    /// Shutdown the stream.
    fn drop(&mut self) {
        self.0.shutdown(ShutdownCmd::RdWr).unwrap();
    }
}
