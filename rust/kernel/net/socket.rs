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
pub struct Message(bindings::msghdr);

impl Message {
    pub fn new<T: SocketAddr>(address: &T, flags: u32) -> Self {
        let mut message = bindings::msghdr::default();
        message.msg_name = address as *const _ as _;
        message.msg_namelen = T::size() as _;
        message.msg_flags = flags;
        Self { 0: message }
    }
    pub fn default() -> Self {
        Self {
            0: bindings::msghdr::default(),
        }
    }
    pub const fn address<T: SocketAddr>(&self) -> Option<&T> {
        if self.0.msg_namelen == 0 {
            None
        } else {
            Some(unsafe { &*(self.0.msg_name as *const _ as *const T) })
        }
    }
    pub const fn flags(&self) -> u32 {
        self.0.msg_flags as _
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        if !self.0.msg_control.is_null() {
            unsafe {
                bindings::kfree(self.0.msg_control as _);
            }
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

    pub fn bind<T: SocketAddr>(&self, address: &T) -> Result {
        to_result(unsafe {
            bindings::kernel_bind(self.0, address as *const _ as _, T::size() as i32)
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

    pub fn sockname<T: SocketAddr>(&self) -> Result<T> {
        let mut addr: T = unsafe { core::mem::zeroed() };
        unsafe {
            to_result(bindings::kernel_getsockname(
                self.0,
                &mut addr as *mut _ as _,
            ))
        }
        .map(|_| addr)
    }

    pub fn peername<T: SocketAddr>(&self) -> Result<T> {
        let mut addr: T = unsafe { core::mem::zeroed() };
        unsafe {
            to_result(bindings::kernel_getpeername(
                self.0,
                &mut addr as *mut _ as _,
            ))
        }
        .map(|_| addr)
    }

    pub fn connect<T: SocketAddr>(&self, address: &mut T, flags: i32) -> Result {
        unsafe {
            to_result(bindings::kernel_connect(
                self.0,
                address as *mut _ as _,
                T::size() as _,
                flags,
            ))
        }
    }

    pub fn shutdown(&self, how: ShutdownCmd) -> Result {
        unsafe { to_result(bindings::kernel_sock_shutdown(self.0, how as _)) }
    }

    pub fn receive(&self, bytes: &mut [u8], block: bool) -> Result<(usize, Message)> {
        let mut message: Message = unsafe { core::mem::zeroed() };
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

    pub fn send(&self, bytes: &[u8], message: Option<Message>) -> Result<usize> {
        let mut vec = bindings::kvec {
            iov_base: bytes.as_ptr() as _,
            iov_len: bytes.len() as _,
        };
        let size = unsafe {
            bindings::kernel_sendmsg(
                self.0,
                &message.unwrap_or(Message::default()).0 as *const _ as _,
                &mut vec,
                1,
                bytes.len() as _,
            )
        };
        to_result(size)?;
        Ok(size as _)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            bindings::sock_release(self.0);
        }
    }
}
