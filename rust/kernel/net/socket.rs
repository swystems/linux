// SPDX-License-Identifier: GPL-2.0

//! Socket API.
//!
//! This module contains the Socket layer kernel APIs that have been wrapped for usage by Rust code
//! in the kernel.
//!
//! C header: [`include/linux/socket.h`](../../../../include/linux/socket.h)
//!
//! This API is inspired by the Rust std::net Socket API, but is not a direct port.
//! The main difference is that the Rust std::net API is designed for user-space, while this API
//! is designed for kernel-space.
//! Rust net API: <https://doc.rust-lang.org/std/net/index.html>

use super::*;
use crate::error::{to_result, Result};
use crate::net::addr::*;
use core::cmp::max;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use flags::*;

pub mod flags;
pub mod opts;

/// The socket type.
pub enum SockType {
    /// Stream socket (e.g. TCP)
    Stream = bindings::sock_type_SOCK_STREAM as isize,
    /// Connectionless socket (e.g. UDP)
    Datagram = bindings::sock_type_SOCK_DGRAM as isize,
    /// Raw socket
    Raw = bindings::sock_type_SOCK_RAW as isize,
    /// Reliably-delivered message
    Rdm = bindings::sock_type_SOCK_RDM as isize,
    /// Sequenced packet stream
    Seqpacket = bindings::sock_type_SOCK_SEQPACKET as isize,
    /// Datagram Congestion Control Protocol socket
    Dccp = bindings::sock_type_SOCK_DCCP as isize,
    /// Packet socket
    Packet = bindings::sock_type_SOCK_PACKET as isize,
}

/// The socket shutdown command.
pub enum ShutdownCmd {
    /// Disallow further receive operations.
    Rd = bindings::sock_shutdown_cmd_SHUT_RD as isize,
    /// Disallow further send operations.
    Wr = bindings::sock_shutdown_cmd_SHUT_WR as isize,
    /// Disallow further send and receive operations.
    RdWr = bindings::sock_shutdown_cmd_SHUT_RDWR as isize,
}

/// A generic socket.
/// Wraps a `struct socket` from the kernel.
/// See `include/linux/socket.h`.
///
/// The wrapper offers high-level methods for common operations on the socket.
/// More fine-grained control is possible by using the C bindings directly.
///
/// # Example
/// A simple TCP echo server:
/// ```rust
/// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
/// use kernel::net::{AddressFamily, init_ns, IpProtocol};
/// use kernel::net::socket::{Socket, SockType};
///
/// let socket = Socket::new_kern(
///     init_ns(),
///     AddressFamily::Inet,
///     SockType::Stream,
///     IpProtocol::Tcp,
/// )?;
/// socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000)))?;
/// socket.listen(10)?;
/// while let Ok(peer) = socket.accept(true) {
///     let mut buf = [0u8; 1024];
///     peer.receive(&mut buf, [])?;
///     peer.send(&buf, [])?;
/// }
/// ```
/// A simple UDP echo server:
/// ```rust
/// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
/// use kernel::net::{AddressFamily, init_ns, IpProtocol};
/// use kernel::net::socket::{Socket, SockType};
///
/// let socket = Socket::new_kern(init_ns(), AddressFamily::Inet, SockType::Datagram, IpProtocol::Udp)?;///
/// socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000)))?;
/// let mut buf = [0u8; 1024];
/// while let Ok((len, sender_opt)) = socket.receive_from(&mut buf, []) {
///     let sender: SocketAddr = sender_opt.expect("Sender address is always available for UDP");
///     socket.send_to(&buf[..len], &sender, [])?;
/// }
/// ```
///
/// # Invariants
///
/// The socket pointer is valid for the lifetime of the wrapper.
#[repr(transparent)]
pub struct Socket(*mut bindings::socket);

impl Socket {
    /// Private utility function to create a new socket by calling a function.
    /// The function is generic over the creation function.
    ///
    /// # Arguments
    /// * `create_fn`: A function that initiates the socket given as parameter.
    ///                The function must return 0 on success and a negative error code on failure.
    fn base_new<T>(create_fn: T) -> Result<Self>
    where
        T: (FnOnce(*mut *mut bindings::socket) -> core::ffi::c_int),
    {
        let mut socket_ptr: *mut bindings::socket = core::ptr::null_mut();
        to_result(create_fn(&mut socket_ptr))?;
        Ok(Self { 0: socket_ptr })
    }

    /// Create a new socket.
    /// Wraps the `sock_create` function.
    ///
    /// # Arguments
    /// * `family`: The [address family](AddressFamily).
    /// * `type_`: The [socket type](SockType).
    /// * `proto`: The [IP protocol](IpProtocol).
    pub fn new(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create(family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    /// Create a new socket in a specific namespace.
    /// Wraps the `sock_create_kern` function.
    ///
    /// # Arguments
    /// * `ns`: The [namespace](Namespace) to create the socket in.
    /// * `family`: The [address family](AddressFamily).
    /// * `type_`: The [socket type](SockType).
    /// * `proto`: The [IP protocol](IpProtocol).
    pub fn new_kern(
        ns: &Namespace,
        family: AddressFamily,
        type_: SockType,
        proto: IpProtocol,
    ) -> Result<Self> {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create_kern(ns.0.get(), family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    /// Creates a new "lite" socket.
    /// Wraps the `sock_create_lite` function.
    /// This is a lighter version of `sock_create` that does not perform any sanity check.
    ///
    /// # Arguments
    /// * `family`: The [address family](AddressFamily).
    /// * `type_`: The [socket type](SockType).
    /// * `proto`: The [IP protocol](IpProtocol).
    pub fn new_lite(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create_lite(family as _, type_ as _, proto as _, socket_ptr)
        })
    }

    /// Binds the socket to a specific address.
    /// Wraps the `kernel_bind` function.
    ///
    /// # Arguments
    /// * `address`: The [socket address](SocketAddr) to bind to.
    pub fn bind(&self, address: SocketAddr) -> Result {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        to_result(unsafe {
            bindings::kernel_bind(self.0, address.as_ptr() as _, address.size() as i32)
        })
    }

    /// Connects the socket to a specific address.
    /// Wraps the `kernel_connect` function.
    /// The socket must be a connection-oriented socket.
    /// If the socket is not bound, it will be bound to a random local address.
    ///
    /// # Arguments
    /// * `backlog`: The maximum number of pending connections.
    ///
    /// # Example
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
    /// use kernel::net::{AddressFamily, init_ns, IpProtocol};
    /// use kernel::net::socket::{Socket, SockType};
    ///
    /// let socket = Socket::new_kern(init_ns(), AddressFamily::Inet, SockType::Stream, IpProtocol::Tcp)?;
    /// socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOOPBACK, 8000)))?;
    /// socket.listen(10)?;
    pub fn listen(&self, backlog: i32) -> Result {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        to_result(unsafe { bindings::kernel_listen(self.0, backlog) })
    }

    /// Accepts a connection on a socket.
    /// Wraps the `kernel_accept` function.
    ///
    /// # Arguments
    /// * `block`: Whether to block until a connection is available.
    pub fn accept(&self, block: bool) -> Result<Socket> {
        let mut new_sock = core::ptr::null_mut();
        let flags: i32 = if block { 0 } else { bindings::O_NONBLOCK as _ };

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        to_result(unsafe { bindings::kernel_accept(self.0, &mut new_sock, flags as _) })?;

        Ok(Self { 0: new_sock })
    }

    /// Returns the address the socket is bound to.
    /// Wraps the `kernel_getsockname` function.
    pub fn sockname(&self) -> Result<SocketAddr> {
        // SAFETY: A zero-initialized address is a valid input for `kernel_getsockname`.
        let mut addr: SocketAddrStorage = unsafe { core::mem::zeroed() };

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe {
            to_result(bindings::kernel_getsockname(
                self.0,
                &mut addr as *mut _ as _,
            ))
        }
        .map(|_| SocketAddr::from_raw(addr))
    }

    /// Returns the address the socket is connected to.
    /// Wraps the `kernel_getpeername` function.
    ///
    /// The socket must be connected.
    pub fn peername(&self) -> Result<SocketAddr> {
        // SAFETY: A zero-initialized address is a valid input for `kernel_getpeername`.
        let mut addr: SocketAddrStorage = unsafe { core::mem::zeroed() };

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe {
            to_result(bindings::kernel_getpeername(
                self.0,
                &mut addr as *mut _ as _,
            ))
        }
        .map(|_| SocketAddr::from_raw(addr))
    }

    /// Connects the socket to a specific address.
    /// Wraps the `kernel_connect` function.
    ///
    /// # Arguments
    /// * `address`: The address to connect to.
    /// * `flags`: The flags to use for the connection.
    pub fn connect(&self, address: &SocketAddr, flags: i32) -> Result {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe {
            to_result(bindings::kernel_connect(
                self.0,
                address.as_ptr() as _,
                address.size() as _,
                flags,
            ))
        }
    }

    /// Shuts down the socket.
    /// Wraps the `kernel_sock_shutdown` function.
    ///
    /// # Arguments
    /// * `how`: The shutdown command.
    pub fn shutdown(&self, how: ShutdownCmd) -> Result {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe { to_result(bindings::kernel_sock_shutdown(self.0, how as _)) }
    }

    /// Receives data from a remote socket and returns the bytes read and the sender address.
    /// Wraps the `kernel_recvmsg` function.
    /// Used by connectionless sockets to retrieve the sender of the message.
    /// If the socket is connection-oriented, the sender address will be `None`.
    /// The function abstracts the usage of the `struct msghdr` type.
    ///
    /// # Arguments
    /// * `bytes`: The buffer to read the data into.
    /// * `flags`: The flags to use for the receive operation.
    ///            See the [flags module](flags) for more.
    pub fn receive_from(
        &self,
        bytes: &mut [u8],
        flags: impl IntoIterator<Item = ReceiveFlag>,
    ) -> Result<(usize, Option<SocketAddr>)> {
        // SAFETY: An uninitialized address is a valid field value for `msghdr`.
        let addr: SocketAddrStorage = unsafe { core::mem::zeroed() };

        // SAFETY: An uninitialized msghdr is a valid input for `kernel_recvmsg`.
        let mut msg: bindings::msghdr = unsafe { core::mem::zeroed() };

        msg.msg_name = &addr as *const _ as _;

        let mut vec = bindings::kvec {
            iov_base: bytes.as_mut_ptr() as _,
            iov_len: bytes.len() as _,
        };

        // SAFETY: FFI call; the socket address is valid for the lifetime of the wrapper.
        let size = unsafe {
            bindings::kernel_recvmsg(
                self.0,
                &mut msg as *mut _ as _,
                &mut vec,
                1,
                bytes.len() as _,
                flags_value(flags) as _,
            )
        };
        to_result(size)?;

        // If the socket is connection-oriented, the `kernel_recvmsg` function
        // will not fill the address field, nor the length field.
        let address = if msg.msg_namelen > 0 {
            Some(SocketAddr::from_raw(addr))
        } else {
            None
        };
        Ok((size as _, address))
    }

    /// Receives data from a remote socket and returns only the bytes read.
    /// Wraps the `kernel_recvmsg` function.
    /// Used by connection-oriented sockets, where the sender address is the connected peer.
    pub fn receive(
        &self,
        bytes: &mut [u8],
        flags: impl IntoIterator<Item = ReceiveFlag>,
    ) -> Result<usize> {
        let (size, _) = self.receive_from(bytes, flags)?;
        Ok(size)
    }

    /// Sends a message to a remote socket.
    /// Wraps the `kernel_sendmsg` function.
    /// Crate-public to allow its usage only in the kernel crate, as modules are not supposed
    /// to use bindings.
    ///
    /// # Arguments
    /// * `bytes`: The buffer to send.
    /// * `message`: The raw `msghdr` to use.
    /// * `flags`: The flags to use for the send operation.
    ///            See the [flags module](flags) for more.
    pub(crate) fn send_msg(
        &self,
        bytes: &[u8],
        mut message: bindings::msghdr,
        flags: impl IntoIterator<Item = SendFlag>,
    ) -> Result<usize> {
        let mut vec = bindings::kvec {
            iov_base: bytes.as_ptr() as _,
            iov_len: bytes.len() as _,
        };
        message.msg_flags = flags_value(flags) as _;

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
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

    /// Sends a message to a remote socket and returns the bytes sent.
    /// Wraps the `kernel_sendmsg` function.
    /// Used by connection-oriented sockets, as they don't need to specify the destination address.
    pub fn send(&self, bytes: &[u8], flags: impl IntoIterator<Item = SendFlag>) -> Result<usize> {
        // SAFETY: An uninitialized msghdr is a valid input for `kernel_sendmsg`.
        self.send_msg(bytes, unsafe { core::mem::zeroed() }, flags)
    }

    /// Sends a message to a specific remote socket address and returns the bytes sent.
    /// Wraps the `kernel_sendmsg` function.
    /// Used by connectionless sockets, as they need to specify the destination address.
    ///
    /// # Arguments
    /// * `bytes`: The buffer to send.
    /// * `address`: The address to send the message to.
    /// * `flags`: The flags to use for the send operation.
    ///            See the [flags module](flags) for more.
    pub fn send_to(
        &self,
        bytes: &[u8],
        address: &SocketAddr,
        flags: impl IntoIterator<Item = SendFlag>,
    ) -> Result<usize> {
        // SAFETY: An uninitialized msghdr is a valid input for `kernel_sendmsg`.
        let mut message: bindings::msghdr = unsafe { core::mem::zeroed() };
        message.msg_name = address.as_ptr() as _;
        message.msg_namelen = address.size() as _;
        self.send_msg(bytes, message, flags)
    }

    /// Sets an option on the socket.
    /// Wraps the `sock_setsockopt` function.
    /// The generic type `T` is used as the type of the value to set.
    ///
    /// # Arguments
    /// * `option`: The [Options](opts::Options) to set. Automatically implies both the level
    /// and the name of the option.
    /// * `value`: The value to set.
    ///
    /// # Safety
    /// The caller must ensure that the generic type `T` matches the type of the option.
    /// The type of each option is specified in the [options module](opts).
    pub fn set_option<T>(&self, option: opts::Options, value: T) -> Result
    where
        T: Sized,
    {
        let value_ptr = SockPtr::new(&value);
        let min_size = core::mem::size_of::<core::ffi::c_int>();
        let size = max(core::mem::size_of::<T>(), min_size);

        // SAFETY: FFI call;
        // the address is valid for the lifetime of the wrapper;
        // the size is at least the size of an integer;
        // the level and name of the option are valid.
        to_result(unsafe {
            bindings::sock_setsockopt(
                self.0,
                option.as_level() as _,
                option.to_value() as _,
                value_ptr.to_raw() as _,
                size as _,
            )
        })
    }

    /// Gets an option from the socket.
    /// Wraps the `sock_getsockopt` function.
    /// The generic type `T` is used as the type of the value to get.
    ///
    /// # Arguments
    /// * `option`: The [Options](opts::Options) to get. Automatically implies both the level
    /// and the name of the option.
    /// * `value`: The value to get.
    ///
    /// # Safety
    /// The caller must ensure that the generic type `T` matches the type of the option.
    /// The type of each option is specified in the [options module](opts).
    ///
    /// TODO: The functions `sk_getsockopt` and `sock_getsockopt` are not exported by the kernel.
    /// Find a way to retrieve the socket options without using those functions.
    pub fn get_option<T>(&self, option: opts::Options) -> Result<T>
    where
        T: Sized,
    {
        let value = MaybeUninit::<T>::uninit();
        let value_ptr = SockPtr::new_from_ptr(value.as_ptr() as _);

        let min_size = core::mem::size_of::<core::ffi::c_int>();
        let size = max(core::mem::size_of::<T>(), min_size);
        let size_ptr = SockPtr::new(&size);

        // SAFETY: FFI call;
        // the address is valid for the lifetime of the wrapper;
        // the size is at least the size of an integer;
        // the level and name of the option are valid.
        to_result(unsafe {
            bindings::sk_getsockopt(
                (*self.0).sk,
                option.as_level() as _,
                option.to_value() as _,
                value_ptr.to_raw() as _,
                size_ptr.to_raw() as _,
            )
        })?;
        Ok(unsafe { value.assume_init() })
    }

    /// Consumes the socket and returns the underlying pointer.
    ///
    /// # Safety
    /// The caller must ensure that the pointer is not used after the socket is dropped.
    pub unsafe fn into_inner(self) -> *mut bindings::socket {
        self.0
    }

    /// Returns the underlying pointer.
    /// The pointer is valid for the lifetime of the wrapper.
    ///
    /// # Safety
    /// The caller must ensure that the pointer is not used after the socket is dropped.
    pub unsafe fn as_inner(&self) -> *mut bindings::socket {
        self.0
    }
}

impl Drop for Socket {
    /// Closes and releases the socket.
    /// Wraps the `sock_release` function.
    fn drop(&mut self) {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe {
            bindings::sock_release(self.0);
        }
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct SockPtr<'a>(bindings::sockptr_t, PhantomData<&'a ()>);

impl<'a> SockPtr<'a> {
    fn new<'b: 'a, T>(value: &'b T) -> Self
    where
        T: Sized,
    {
        let bf = bindings::__BindgenBitfieldUnit::<[u8; 1usize]>::new([1; 1usize]);
        let sockptr = bindings::sockptr_t {
            __bindgen_anon_1: bindings::sockptr_t__bindgen_ty_1 {
                kernel: value as *const T as _,
            },
            _bitfield_align_1: [0; 0],
            _bitfield_1: bf,
            __bindgen_padding_0: [0; 7],
        };
        SockPtr(sockptr, PhantomData)
    }

    fn new_from_ptr<T>(value: *const T) -> Self
    where
        T: Sized,
    {
        let bf = bindings::__BindgenBitfieldUnit::<[u8; 1usize]>::new([1; 1usize]);
        let sockptr = bindings::sockptr_t {
            __bindgen_anon_1: bindings::sockptr_t__bindgen_ty_1 { kernel: value as _ },
            _bitfield_align_1: [0; 0],
            _bitfield_1: bf,
            __bindgen_padding_0: [0; 7],
        };
        SockPtr(sockptr, PhantomData)
    }

    fn to_raw(self) -> bindings::sockptr_t {
        self.0
    }
}
