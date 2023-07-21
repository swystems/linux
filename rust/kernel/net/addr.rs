use crate::net::AddressFamily;
use core::fmt::Display;

/// An IPv4 address.
/// Wraps a `struct in_addr`.
#[repr(transparent)]
pub struct Ipv4Addr(pub(crate) bindings::in_addr);

impl Ipv4Addr {
    /// Create a new IPv4 address from four octets.
    /// The bytes do not need to be in network order.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr(bindings::in_addr {
            s_addr: u32::from_ne_bytes([a.to_be(), b.to_be(), c.to_be(), d.to_be()]),
        })
    }

    /// Create a new IPv4 address from an array of octets.
    /// The bytes do not need to be in network order.
    pub const fn from(octets: [u8; 4]) -> Self {
        Self::new(octets[0], octets[1], octets[2], octets[3])
    }

    /// Get the octets of the address.
    /// The bytes are in network order.
    pub fn octets(&self) -> &[u8; 4] {
        // SAFETY: `s_addr` is a 32-bit integer, which is 4 bytes.
        unsafe { &*(&self.0.s_addr as *const _ as *const [u8; 4]) }
    }

    /// The "any" address: 0.0.0.0
    /// Used to accept any incoming message.
    pub const ANY: Self = Self::new(0, 0, 0, 0);

    /// The broadcast address: 255.255.255.255
    /// Used to send a message to all hosts on the network.
    pub const BROADCAST: Self = Self::new(255, 255, 255, 255);

    /// "None" address; can be used as return value to indicate an error.
    pub const NONE: Self = Self::new(255, 255, 255, 255);

    /// A dummy address: 192.0.0.8
    /// Used as ICMP reply source if no address is set.
    pub const DUMMY: Self = Self::new(192, 0, 0, 8);

    /// The loopback address: 127.0.0.1
    /// Used to send a message to the local host.
    pub const LOOPBACK: Self = Self::new(127, 0, 0, 1);
}

impl Display for Ipv4Addr {
    /// Display the address as a string.
    /// The bytes are in network order.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::Ipv4Addr;
    ///
    /// let addr = Ipv4Addr::new(192, 168, 0, 1);
    /// assert_eq!(format!("{}", addr), "192.168.0.1");
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let octets = self.octets();
        write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    }
}

/// An IPv6 address.
/// Wraps a `struct in6_addr`.
#[repr(transparent)]
pub struct Ipv6Addr(pub(crate) bindings::in6_addr);

impl Ipv6Addr {
    /// Create a new IPv6 address from eight 16-bit integers.
    /// The integers do not need to be in network order.
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self::from([
            a.to_be(),
            b.to_be(),
            c.to_be(),
            d.to_be(),
            e.to_be(),
            f.to_be(),
            g.to_be(),
            h.to_be(),
        ])
    }

    /// Create a new IPv6 address from an array of 16-bit integers.
    /// The integers do not need to be in network order.
    pub const fn from(octets: [u16; 8]) -> Self {
        Ipv6Addr(bindings::in6_addr {
            in6_u: bindings::in6_addr__bindgen_ty_1 { u6_addr16: octets },
        })
    }

    /// Get the octets of the address.
    /// The bytes are in network order.
    pub fn octets(&self) -> &[u16; 8] {
        unsafe { &self.0.in6_u.u6_addr16 as _ }
    }

    /// The "any" address: ::
    /// Used to accept any incoming message.
    pub const ANY: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 0);

    /// The loopback address: ::1
    /// Used to send a message to the local host.
    pub const LOOPBACK: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 1);
}

impl Display for Ipv6Addr {
    /// Display the address as a string.
    /// The bytes are in network order.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::Ipv6Addr;
    ///
    /// let addr = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334);
    /// assert_eq!(format!("{}", addr), "2001:db8:85a3:0:0:8a2e:370:7334");
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let octets = self.octets();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]
        )
    }
}

/// A generic Socket Address. Acts like a `struct sockaddr`.
/// The purpose of this enum is to be used as a generic parameter for functions that can take any type of address.
pub enum SocketAddr {
    /// An IPv4 address.
    V4(SocketAddrV4),
    /// An IPv6 address.
    V6(SocketAddrV6),
}

impl SocketAddr {
    /// Returns the size in bytes of the concrete address contained.
    /// Used in the kernel functions that take a parameter with the size of the socket address.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
    /// assert_eq!(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80)).size(),
    ///           core::mem::size_of::<SocketAddrV4>());
    pub fn size(&self) -> usize {
        match self {
            SocketAddr::V4(_) => SocketAddrV4::size(),
            SocketAddr::V6(_) => SocketAddrV6::size(),
        }
    }

    /// Returns the address family of the concrete address contained.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
    /// use kernel::net::AddressFamily;
    /// assert_eq!(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80)).family(),
    ///          AddressFamily::Inet);
    /// ```
    pub fn family(&self) -> AddressFamily {
        match self {
            SocketAddr::V4(_) => AddressFamily::Inet,
            SocketAddr::V6(_) => AddressFamily::Inet6,
        }
    }

    /// Consumes the object and returns the concrete address contained.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it does not check if the address family of the contained address matches the type parameter.
    /// The function must be called with the correct type parameter.
    pub unsafe fn into_addr<T: GenericSocketAddr>(self) -> T {
        // SAFETY: The function is called with the correct type parameter.
        unsafe { core::ptr::read(self.as_ptr() as *const T) }
    }

    /// Tries to convert the object into the concrete address contained.
    /// Returns `None` if the address family of the contained address does not match the type parameter.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddrV4};
    /// let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80));
    /// assert_eq!(addr.try_into::<SocketAddrV4>(), Some(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80)));
    pub fn try_into<T: GenericSocketAddr>(self) -> Option<T> {
        if self.family() as isize == T::family() as isize {
            // SAFETY: The address family of the contained address matches the type parameter, so
            // the address structure must be the same.
            unsafe { Some(self.into_addr()) }
        } else {
            None
        }
    }

    /// Returns a pointer to the C `struct sockaddr` contained.
    /// Used in the kernel functions that take a pointer to a socket address.
    pub(crate) fn as_ptr(&self) -> *const bindings::sockaddr {
        match self {
            SocketAddr::V4(addr) => addr as *const _ as _,
            SocketAddr::V6(addr) => addr as *const _ as _,
        }
    }

    /// Creates a `SocketAddr` from a C `struct sockaddr`.
    /// The function consumes the `struct sockaddr`.
    /// Used in the kernel functions that return a socket address.
    ///
    /// # Panics
    /// Panics if the address family of the `struct sockaddr` is invalid.
    /// This should never happen.
    /// If it does, it is likely because of an invalid pointer.
    pub(crate) fn from_raw(sockaddr: bindings::sockaddr) -> Self {
        match sockaddr.sa_family as u32 {
            bindings::AF_INET => SocketAddr::V4(unsafe {
                core::ptr::read(&sockaddr as *const _ as *const SocketAddrV4)
            }),
            bindings::AF_INET6 => SocketAddr::V6(unsafe {
                core::ptr::read(&sockaddr as *const _ as *const SocketAddrV6)
            }),
            _ => panic!("Invalid address family"),
        }
    }
}

/// Generic trait for socket addresses.
///
/// The purpose of this trait is:
/// - To force all socket addresses to have a size and an address family.
/// - To allow the conversion of a `SocketAddr` into a concrete address.
pub trait GenericSocketAddr: Copy {
    /// Returns the size in bytes of the concrete address.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::bindings;
    /// use kernel::net::addr::{GenericSocketAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    /// assert_eq!(SocketAddrV4::size(), core::mem::size_of::<bindings::sockaddr_in>());
    /// ```
    fn size() -> usize
    where
        Self: Sized,
    {
        core::mem::size_of::<Self>()
    }

    /// Returns the address family of the concrete address.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use kernel::net::addr::{GenericSocketAddr, SocketAddrV4};
    /// use kernel::net::AddressFamily;
    /// assert_eq!(SocketAddrV4::family(), AddressFamily::Inet);
    /// ```
    fn family() -> AddressFamily;
}

/// Trait for socket addresses that contain an IP address and a port.
///
/// This trait is implemented by [SocketAddrV4] and [SocketAddrV6].
pub trait SocketAddressInfo<T> {
    /// Returns a reference to the IP address contained.
    /// The type of the IP address is the type parameter of the trait.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddressInfo, SocketAddrV4};
    /// let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80);
    /// assert_eq!(addr.address(), &Ipv4Addr::new(192, 168, 0, 1));
    /// ```
    fn address(&self) -> &T;

    /// Returns the port contained. The port is in network byte order.
    ///
    /// # Examples
    /// ```rust
    /// use kernel::net::addr::{Ipv4Addr, SocketAddr, SocketAddressInfo, SocketAddrV4};
    /// let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80);
    /// assert_eq!(addr.port(), 80);
    /// ```
    fn port(&self) -> u16;
}

/// IPv4 socket address.
/// Wraps a C `struct sockaddr_in`.
///
/// # Examples
/// ```rust
/// use kernel::bindings;
/// use kernel::net::addr::{GenericSocketAddr, Ipv4Addr, SocketAddr, SocketAddressInfo, SocketAddrV4};
/// let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 80);
/// assert_eq!(addr.address(), &Ipv4Addr::new(192, 168, 0, 1));
/// assert_eq!(SocketAddrV4::size(), core::mem::size_of::<bindings::sockaddr_in>());
/// ```
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct SocketAddrV4(pub(crate) bindings::sockaddr_in);

impl SocketAddrV4 {
    /// Creates a new IPv4 socket address from an IP address and a port.
    /// The port does not need to be in network byte order.
    pub fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self(bindings::sockaddr_in {
            sin_family: bindings::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: addr.0,
            __pad: [0; 8],
        })
    }
}

impl GenericSocketAddr for SocketAddrV4 {
    /// Returns the family of the address.
    ///
    /// # Invariants
    /// The family is always [AddressFamily::Inet].
    fn family() -> AddressFamily {
        AddressFamily::Inet
    }
}

impl SocketAddressInfo<Ipv4Addr> for SocketAddrV4 {
    /// Returns a reference to the IP address contained.
    /// The type of the IP address is [Ipv4Addr].
    fn address(&self) -> &Ipv4Addr {
        // SAFETY: The [Ipv4Addr] is a transparent representation of the C `struct in_addr`,
        // which is the type of `sin_addr`. Therefore, the conversion is safe.
        unsafe { &*(&self.0.sin_addr as *const _ as *const Ipv4Addr) }
    }

    /// Returns the port contained. The port is in network byte order.
    fn port(&self) -> u16 {
        self.0.sin_port.to_be()
    }
}

/// IPv6 socket address.
/// Wraps a C `struct sockaddr_in6`.
///
/// # Examples
/// ```rust
/// use kernel::bindings;
/// use kernel::net::addr::{GenericSocketAddr, Ipv6Addr, SocketAddr, SocketAddressInfo, SocketAddrV6};
///
/// let addr = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 80, 0, 0);
/// assert_eq!(addr.address(), &Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
/// assert_eq!(SocketAddrV6::size(), core::mem::size_of::<bindings::sockaddr_in6>());
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct SocketAddrV6(pub(crate) bindings::sockaddr_in6);

impl SocketAddrV6 {
    /// Creates a new IPv6 socket address from an IP address, a port, a flowinfo and a scope_id.
    /// The port does not need to be in network byte order.
    pub fn new(addr: Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> Self {
        Self(bindings::sockaddr_in6 {
            sin6_family: bindings::AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: flowinfo,
            sin6_addr: addr.0,
            sin6_scope_id: scope_id,
        })
    }
}

impl GenericSocketAddr for SocketAddrV6 {
    /// Returns the family of the address.
    ///
    /// # Invariants
    /// The family is always [AddressFamily::Inet6].
    fn family() -> AddressFamily {
        AddressFamily::Inet6
    }
}

impl SocketAddressInfo<Ipv6Addr> for SocketAddrV6 {
    /// Returns a reference to the IP address contained.
    /// The type of the IP address is [Ipv6Addr].
    fn address(&self) -> &Ipv6Addr {
        // SAFETY: The [Ipv6Addr] is a transparent representation of the C `struct in6_addr`,
        // which is the type of `sin6_addr`. Therefore, the conversion is safe.
        unsafe { &*(&self.0.sin6_addr as *const _ as *const Ipv6Addr) }
    }

    /// Returns the port contained. The port is in network byte order.
    fn port(&self) -> u16 {
        self.0.sin6_port.to_be()
    }
}
