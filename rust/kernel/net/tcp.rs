use crate::{
    error::Result,
    net::{
        addr::SocketAddr,
        socket::{ShutdownCmd, SockType, Socket},
        AddressFamily, IpProtocol,
    },
};

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
    ///     while let Ok(len) = stream.receive(&mut buf) {
    ///         // ...
    ///     }
    /// }
    /// ```
    pub fn receive(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.receive(buf, true)
    }

    /// Send data to the stream.
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
    ///     while let Ok(len) = stream.receive(&mut buf) {
    ///         stream.send(&buf[..len])?;
    ///     }
    /// }
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }
}

impl Drop for TcpStream {
    /// Shutdown the stream.
    fn drop(&mut self) {
        self.0.shutdown(ShutdownCmd::RdWr).unwrap();
    }
}
