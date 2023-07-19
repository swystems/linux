use crate::{
    error::Result,
    net::{
        addr::SocketAddr,
        socket::{ShutdownCmd, SockType, Socket},
        AddressFamily, IpProtocol,
    },
};

pub struct TcpListener(Socket);

impl TcpListener {
    pub fn new(address: SocketAddr) -> Result<Self> {
        let socket = Socket::new(AddressFamily::Inet, SockType::Stream, IpProtocol::Tcp)?;
        socket.bind(address)?;
        socket.listen(128)?;
        Ok(Self(socket))
    }
    pub fn accept(&self) -> Result<TcpStream> {
        Ok(TcpStream(self.0.accept(true)?))
    }
}

pub struct TcpStream(Socket);

impl TcpStream {
    pub fn receive(&self, buf: &mut [u8]) -> Result<usize> {
        self.0.receive(buf, true)
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        self.0.send(buf)
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.0.shutdown(ShutdownCmd::RdWr).unwrap();
    }
}
