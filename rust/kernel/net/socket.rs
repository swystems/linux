pub mod opts;

use super::*;
use crate::error::{to_result, Result};
use crate::net::addr::*;

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
///     peer.receive(&mut buf, true)?;
///     peer.send(&buf)?;
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
/// while let Ok((len, sender_opt)) = socket.receive_from(&mut buf, true) {
///     let sender: SocketAddr = sender_opt.expect("Sender address is always available for UDP");
///     socket.send_to(&buf[..len], &sender)?;
/// }
/// ```
///
/// # Safety
/// The socket pointer must be valid for the lifetime of the wrapper.
#[repr(transparent)]
pub struct Socket(*mut bindings::socket);

impl Socket {
    /// Private utility function to create a new socket.
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
        let mut addr = unsafe { core::mem::zeroed::<bindings::sockaddr>() };

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe { to_result(bindings::kernel_getsockname(self.0, &mut addr)) }
            .map(|_| SocketAddr::from_raw(addr))
    }

    /// Returns the address the socket is connected to.
    /// Wraps the `kernel_getpeername` function.
    /// The socket must be connected.
    pub fn peername(&self) -> Result<SocketAddr> {
        // SAFETY: A zero-initialized address is a valid input for `kernel_getpeername`.
        let mut addr = unsafe { core::mem::zeroed::<bindings::sockaddr>() };

        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe { to_result(bindings::kernel_getpeername(self.0, &mut addr)) }
            .map(|_| SocketAddr::from_raw(addr))
    }

    /// Connects the socket to a specific address.
    /// Wraps the `kernel_connect` function.
    /// The socket must be a connection-oriented socket.
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
    /// * `block`: Whether to block until data is available.
    pub fn receive_from(
        &self,
        bytes: &mut [u8],
        block: bool,
    ) -> Result<(usize, Option<SocketAddr>)> {
        // SAFETY: An uninitialized address is a valid field value for `msghdr`.
        let addr: bindings::sockaddr = unsafe { core::mem::zeroed() };

        // SAFETY: An uninitialized msghdr is a valid input for `kernel_recvmsg`.
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

        // SAFETY: FFI call; the socket address is valid for the lifetime of the wrapper.
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
    pub fn receive(&self, bytes: &mut [u8], block: bool) -> Result<usize> {
        let (size, _) = self.receive_from(bytes, block)?;
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
    pub(crate) fn send_msg(&self, bytes: &[u8], message: bindings::msghdr) -> Result<usize> {
        let mut vec = bindings::kvec {
            iov_base: bytes.as_ptr() as _,
            iov_len: bytes.len() as _,
        };

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
    pub fn send(&self, bytes: &[u8]) -> Result<usize> {
        // SAFETY: An uninitialized msghdr is a valid input for `kernel_sendmsg`.
        self.send_msg(bytes, unsafe { core::mem::zeroed() })
    }

    /// Sends a message to a specific remote socket address and returns the bytes sent.
    /// Wraps the `kernel_sendmsg` function.
    /// Used by connectionless sockets, as they need to specify the destination address.
    ///
    /// # Arguments
    /// * `bytes`: The buffer to send.
    /// * `address`: The address to send the message to.
    pub fn send_to(&self, bytes: &[u8], address: &SocketAddr) -> Result<usize> {
        // SAFETY: An uninitialized msghdr is a valid input for `kernel_sendmsg`.
        let mut message: bindings::msghdr = unsafe { core::mem::zeroed() };
        message.msg_name = address.as_ptr() as _;
        message.msg_namelen = address.size() as _;
        self.send_msg(bytes, message)
    }

    /// Sets an option on the socket.
    /// Wraps the `sock_setsockopt` function.
    /// The generic type `T` is used as the type of the value to set.
    ///
    /// # Arguments
    /// * `level`: The [Level](opts::Level) of the option.
    /// * `option`: The [Options](opts::Options) to set.
    /// * `value`: The value to set.
    ///
    /// # Safety
    /// The caller must ensure that the generic type `T` matches the type of the option.
    /// The list of types for each enum is in the [options file](opts).
    pub fn set_option<T>(&self, level: opts::Level, option: opts::Options, value: T) -> Result
    where
        T: Sized,
    {
        let value_ptr = &value as *const T as *mut T;
        let bf = bindings::__BindgenBitfieldUnit::<[u8; 1usize]>::new([1; 1usize]);
        let sockptr = bindings::sockptr_t {
            __bindgen_anon_1: bindings::sockptr_t__bindgen_ty_1 {
                kernel: value_ptr as _,
            },
            _bitfield_align_1: [0; 0],
            _bitfield_1: bf,
            __bindgen_padding_0: [0; 7],
        };
        let value_size = core::mem::size_of::<T>();

        // SAFETY: FFI call;
        //         The address is valid for the lifetime of the wrapper;
        //         The generic type matches the option.
        unsafe {
            to_result(bindings::sock_setsockopt(
                self.0,
                level as _,
                option.to_value() as _,
                sockptr,
                value_size as _,
            ))
        }
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
