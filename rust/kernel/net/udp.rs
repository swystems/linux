use crate::error::Result;
use crate::net::addr::SocketAddr;
use crate::net::socket::Socket;

pub struct UdpSocket(Socket);

impl UdpSocket {
    pub fn new() -> Result<Self> {
        Ok(Self(Socket::new(
            crate::net::AddressFamily::Inet,
            crate::net::socket::SockType::Datagram,
            crate::net::IpProtocol::Udp,
        )?))
    }

    pub fn bind(&self, address: SocketAddr) -> Result {
        self.0.bind(address)
    }

    pub fn sockname(&self) -> Result<SocketAddr> {
        self.0.sockname()
    }

    pub fn peername(&self) -> Result<SocketAddr> {
        self.0.peername()
    }

    pub fn connect(&self, address: &SocketAddr, flags: i32) -> Result {
        self.0.connect(address, flags)
    }

    pub fn receive(&self, buf: &mut [u8], block: bool) -> Result<(usize, SocketAddr)> {
        self.0
            .receive(buf, block)
            .map(|(size, msg)| (size, msg.owned_address().unwrap()))
    }

    pub fn send(&self, buf: &[u8], address: SocketAddr) -> Result<usize> {
        self.0.send_to(buf, address)
    }
}
