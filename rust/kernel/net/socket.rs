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

    pub fn receive_from(
        &self,
        bytes: &mut [u8],
        block: bool,
    ) -> Result<(usize, Option<SocketAddr>)> {
        let mut addr: bindings::sockaddr = unsafe { core::mem::zeroed() };
        let mut msg: bindings::msghdr = unsafe { core::mem::zeroed() };
        msg.msg_name = &addr as *const _ as _;

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
                &mut msg as *mut _ as _,
                &mut vec,
                1,
                bytes.len() as _,
                flags as _,
            )
        };
        to_result(size)?;
        let address = if msg.msg_namelen > 0 {
            Some(SocketAddr::from_raw(addr))
        } else {
            None
        };
        Ok((size as _, address))
    }

    pub fn receive(&self, bytes: &mut [u8], block: bool) -> Result<usize> {
        let (size, _) = self.receive_from(bytes, block)?;
        Ok(size)
    }

    pub(crate) fn send_msg(&self, bytes: &[u8], message: bindings::msghdr) -> Result<usize> {
        let mut vec = bindings::kvec {
            iov_base: bytes.as_ptr() as _,
            iov_len: bytes.len() as _,
        };
        let size = unsafe {
            bindings::kernel_sendmsg(
                self.0,
                &message as *const _ as _,
                &mut vec,
                1,
                bytes.len() as _,
            )
        };
        to_result(size)?;
        Ok(size as _)
    }

    pub fn send(&self, bytes: &[u8]) -> Result<usize> {
        self.send_msg(bytes, unsafe { core::mem::zeroed() })
    }

    pub fn send_to(&self, bytes: &[u8], address: &SocketAddr) -> Result<usize> {
        let mut message: bindings::msghdr = unsafe { core::mem::zeroed() };
        message.msg_name = address.as_ptr() as _;
        message.msg_namelen = address.size() as _;
        self.send_msg(bytes, message)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            bindings::sock_release(self.0);
        }
    }
}
