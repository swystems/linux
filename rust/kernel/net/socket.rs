use super::*;
use crate::error::{to_result, Result};
use crate::net::addr::*;

pub enum SockType {
    Stream = bindings::sock_type_SOCK_STREAM as isize,
    Datagram = bindings::sock_type_SOCK_DGRAM as isize,
    Raw = bindings::sock_type_SOCK_RAW as isize,
    Rdm = bindings::sock_type_SOCK_RDM as isize,
    Seqpacket = bindings::sock_type_SOCK_SEQPACKET as isize,
    Dccp = bindings::sock_type_SOCK_DCCP as isize,
    Packet = bindings::sock_type_SOCK_PACKET as isize,
}

pub enum ShutdownCmd {
    Rd = bindings::sock_shutdown_cmd_SHUT_RD as isize,
    Wr = bindings::sock_shutdown_cmd_SHUT_WR as isize,
    RdWr = bindings::sock_shutdown_cmd_SHUT_RDWR as isize,
}

pub struct Message(pub(crate) bindings::msghdr, bindings::sockaddr);

impl Message {
    pub fn new_empty() -> Self {
        let mut obj = Self(unsafe { core::mem::zeroed() }, unsafe {
            core::mem::zeroed()
        });
        obj.0.msg_name = &obj.1 as *const _ as _;
        obj
    }
    pub fn from(address: SocketAddr) -> Self {
        let mut msg = Self::new_empty();
        msg.set_address(address);
        msg
    }
    pub(crate) fn set_address(&mut self, address: SocketAddr) {
        let len = address.size();
        self.1 = address.into_raw();
        self.0.msg_name = &self.1 as *const _ as _;
        self.0.msg_namelen = len as _;
    }
    pub fn owned_address(self) -> Option<SocketAddr> {
        if self.0.msg_namelen == 0 {
            None
        } else {
            Some(SocketAddr::from_raw(self.1))
        }
    }
}

#[repr(transparent)]
pub struct Socket(*mut bindings::socket);

impl Socket {
    fn base_new<T>(create_fn: T) -> Result<Self>
    where
        T: (FnOnce(*mut *mut bindings::socket) -> core::ffi::c_int),
    {
        let mut socket_ptr: *mut bindings::socket = core::ptr::null_mut();
        to_result(create_fn(&mut socket_ptr))?;
        Ok(Self { 0: socket_ptr })
    }

    pub fn new(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create(family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    pub fn new_kern(
        ns: &Namespace,
        family: AddressFamily,
        type_: SockType,
        proto: IpProtocol,
    ) -> Result<Self> {
        //Self::new(family, type_, proto)
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create_kern(ns.0.get(), family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    pub fn new_lite(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create_lite(family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    pub fn bind(&self, address: SocketAddr) -> Result {
        to_result(unsafe {
            bindings::kernel_bind(self.0, address.as_ptr() as _, address.size() as i32)
        })
    }

    pub fn listen(&self, backlog: i32) -> Result {
        to_result(unsafe { bindings::kernel_listen(self.0, backlog) })
    }

    pub fn accept(&self, block: bool) -> Result<Socket> {
        let mut new_sock = core::ptr::null_mut();
        let flags: i32 = if block { 0 } else { bindings::O_NONBLOCK as _ };

        to_result(unsafe { bindings::kernel_accept(self.0, &mut new_sock, flags as _) })?;

        Ok(Self { 0: new_sock })
    }

    pub fn sockname(&self) -> Result<SocketAddr> {
        let mut addr = unsafe { core::mem::zeroed::<bindings::sockaddr>() };
        unsafe { to_result(bindings::kernel_getsockname(self.0, &mut addr)) }
            .map(|_| SocketAddr::from_raw(addr))
    }

    pub fn peername(&self) -> Result<SocketAddr> {
        let mut addr = unsafe { core::mem::zeroed::<bindings::sockaddr>() };
        unsafe { to_result(bindings::kernel_getpeername(self.0, &mut addr)) }
            .map(|_| SocketAddr::from_raw(addr))
    }

    pub fn connect(&self, address: &SocketAddr, flags: i32) -> Result {
        unsafe {
            to_result(bindings::kernel_connect(
                self.0,
                address.as_ptr() as _,
                address.size() as _,
                flags,
            ))
        }
    }

    pub fn shutdown(&self, how: ShutdownCmd) -> Result {
        unsafe { to_result(bindings::kernel_sock_shutdown(self.0, how as _)) }
    }

    pub fn receive(&self, bytes: &mut [u8], block: bool) -> Result<(usize, Message)> {
        let mut message: Message = Message::new_empty();
        let mut vec = bindings::kvec {
            iov_base: bytes.as_mut_ptr() as _,
            iov_len: bytes.len() as _,
        };
        let flags: i32 = if block {
            0
        } else {
            bindings::MSG_DONTWAIT as _
        };
        let size = unsafe {
            bindings::kernel_recvmsg(
                self.0,
                &mut message.0,
                &mut vec,
                1,
                bytes.len() as _,
                flags as _,
            )
        };
        to_result(size)?;
        Ok((size as _, message))
    }

    pub fn send_msg(&self, bytes: &[u8], message: Message) -> Result<usize> {
        let mut vec = bindings::kvec {
            iov_base: bytes.as_ptr() as _,
            iov_len: bytes.len() as _,
        };
        let size = unsafe {
            bindings::kernel_sendmsg(
                self.0,
                &message.0 as *const _ as _,
                &mut vec,
                1,
                bytes.len() as _,
            )
        };
        to_result(size)?;
        Ok(size as _)
    }

    pub fn send(&self, bytes: &[u8]) -> Result<usize> {
        self.send_msg(bytes, Message::new_empty())
    }

    pub fn send_to(&self, bytes: &[u8], address: SocketAddr) -> Result<usize> {
        self.send_msg(bytes, Message::from(address))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            bindings::sock_release(self.0);
        }
    }
}
//
// pub struct TcpSocket(Socket);
//
// impl TcpSocket {
//     pub fn new() -> Result<Self> {
//         Ok(Self(Socket::new(
//             AddressFamily::Inet,
//             SockType::Stream,
//             IpProtocol::Tcp,
//         )?))
//     }
//
//     pub fn new_kern(ns: &Namespace) -> Result<Self> {
//         Ok(Self(Socket::new_kern(
//             ns,
//             AddressFamily::Inet,
//             SockType::Stream,
//             IpProtocol::Tcp,
//         )?))
//     }
//
//     pub fn new_lite() -> Result<Self> {
//         Ok(Self(Socket::new_lite(
//             AddressFamily::Inet,
//             SockType::Stream,
//             IpProtocol::Tcp,
//         )?))
//     }
//
//     pub fn create_and_listen(address: SocketAddr, backlog: i32) -> Result<Self> {
//         let socket = Self::new()?;
//         socket.bind(address)?;
//         socket.listen(backlog)?;
//         Ok(socket)
//     }
//
//     pub fn bind(&self, address: SocketAddr) -> Result {
//         self.0.bind(address)
//     }
//
//     pub fn listen(&self, backlog: i32) -> Result {
//         self.0.listen(backlog)
//     }
//
//     pub fn accept(&self, block: bool) -> Result<Self> {
//         Ok(Self(self.0.accept(block)?))
//     }
//
//     pub fn sockname(&self) -> Result<SocketAddr> {
//         self.0.sockname()
//     }
//
//     pub fn peername<T: GenericSocketAddr>(&self) -> Result<T> {
//         self.0.peername()
//     }
//
//     pub fn connect<T: GenericSocketAddr>(&self, address: &mut T, flags: i32) -> Result {
//         self.0.connect(address, flags)
//     }
//
//     pub fn shutdown(&self, how: ShutdownCmd) -> Result {
//         self.0.shutdown(how)
//     }
//
//     pub fn receive(&self, bytes: &mut [u8], block: bool) -> Result<usize> {
//         let (size, _) = self.0.receive(bytes, block)?;
//         Ok(size)
//     }
//
//     pub fn send(&self, bytes: &[u8]) -> Result<usize> {
//         self.0.send(bytes)
//     }
// }
//
// pub struct UdpSocket(Socket);
//
// impl UdpSocket {
//     pub fn new() -> Result<Self> {
//         Ok(Self(Socket::new(
//             AddressFamily::Inet,
//             SockType::Datagram,
//             IpProtocol::Udp,
//         )?))
//     }
//
//     pub fn new_kern(ns: &Namespace) -> Result<Self> {
//         Ok(Self(Socket::new_kern(
//             ns,
//             AddressFamily::Inet,
//             SockType::Datagram,
//             IpProtocol::Udp,
//         )?))
//     }
//
//     pub fn new_lite() -> Result<Self> {
//         Ok(Self(Socket::new_lite(
//             AddressFamily::Inet,
//             SockType::Datagram,
//             IpProtocol::Udp,
//         )?))
//     }
//
//     pub fn create_and_bind(address: SocketAddr) -> Result<Self> {
//         let socket = Self::new()?;
//         socket.bind(address)?;
//         Ok(socket)
//     }
//
//     pub fn bind(&self, address: SocketAddr) -> Result {
//         self.0.bind(address)
//     }
//
//     pub fn sockname(&self) -> Result<SocketAddr> {
//         self.0.sockname()
//     }
//
//     pub fn peername<T: GenericSocketAddr>(&self) -> Result<T> {
//         self.0.peername()
//     }
//
//     pub fn connect<T: GenericSocketAddr>(&self, address: &mut T, flags: i32) -> Result {
//         self.0.connect(address, flags)
//     }
//
//     pub fn send_to<T: GenericSocketAddr>(&self, bytes: &[u8], address: T) -> Result<usize> {
//         self.0.send_to(bytes, address)
//     }
//
//     pub fn receive_from<T: GenericSocketAddr>(
//         &self,
//         bytes: &mut [u8],
//         block: bool,
//     ) -> Result<(usize, T)> {
//         let (size, message) = self.0.receive(bytes, block)?;
//         Ok((size, message.address::<T>().unwrap().clone()))
//     }
// }
