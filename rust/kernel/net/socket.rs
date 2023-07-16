use crate::error::{to_result, Result};
use super::*;
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


#[repr(transparent)]
pub struct Socket(*mut bindings::socket);

impl Socket {
    fn base_new<T>(create_fn: T) -> Result<Self>
        where T: (FnOnce(*mut *mut bindings::socket) -> core::ffi::c_int) {
        let mut socket_ptr: *mut bindings::socket = core::ptr::null_mut();
        to_result(create_fn(&mut socket_ptr))?;
        Ok(Self { 0: socket_ptr })
    }

    pub fn new(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create(family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    pub fn new_kern(ns: &Namespace, family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
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

    pub fn bind(&self, address: &mut SocketAddr) -> Result {
        to_result(unsafe { bindings::kernel_bind(self.0, address.ptr(), address.size() as i32) })
    }

    pub fn listen(&self, backlog: i32) -> Result {
        to_result(unsafe { bindings::kernel_listen(self.0, backlog) })
    }

    pub fn accept(&self, block: bool) -> Result<Socket> {
        let mut new_sock = core::ptr::null_mut();
        let flags: i32 = if block { 0 } else { bindings::O_NONBLOCK as _ };

        to_result(unsafe {
            bindings::kernel_accept(self.0, &mut new_sock, flags as _)
        })?;

        Ok(Self { 0: new_sock })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            bindings::sock_release(self.0);
        }
    }
}