use crate::net::AddressFamily;
use core::fmt::Display;

#[repr(transparent)]
pub struct Ipv4Addr(pub(crate) bindings::in_addr);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr(bindings::in_addr {
            s_addr: u32::from_ne_bytes([a.to_be(), b.to_be(), c.to_be(), d.to_be()]),
        })
    }
    pub const fn from(octets: [u8; 4]) -> Self {
        Self::new(octets[0], octets[1], octets[2], octets[3])
    }
    pub fn octets(&self) -> &[u8; 4] {
        unsafe { &*(&self.0.s_addr as *const _ as *const [u8; 4]) }
    }

    pub const ANY: Self = Self::new(0, 0, 0, 0);
    pub const BROADCAST: Self = Self::new(255, 255, 255, 255);
    pub const NONE: Self = Self::new(255, 255, 255, 255);
    pub const DUMMY: Self = Self::new(192, 0, 0, 8);
    pub const LOOPBACK: Self = Self::new(127, 0, 0, 1);
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let octets = self.octets();
        write!(f, "{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    }
}

#[repr(transparent)]
pub struct Ipv6Addr(pub(crate) bindings::in6_addr);

impl Ipv6Addr {
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self::from([a, b, c, d, e, f, g, h])
    }
    pub const fn from(octets: [u16; 8]) -> Self {
        Ipv6Addr(bindings::in6_addr {
            in6_u: bindings::in6_addr__bindgen_ty_1 { u6_addr16: octets },
        })
    }
    pub fn octets(&self) -> &[u16; 8] {
        unsafe { &self.0.in6_u.u6_addr16 as _ }
    }

    pub const ANY: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 0);
    pub const LOOPBACK: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 1);
}

impl Display for Ipv6Addr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let octets = self.octets();
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]
        )
    }
}

pub enum SocketAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl SocketAddr {
    pub fn size(&self) -> usize {
        match self {
            SocketAddr::V4(_) => SocketAddrV4::size(),
            SocketAddr::V6(_) => SocketAddrV6::size(),
        }
    }
    pub fn family(&self) -> AddressFamily {
        match self {
            SocketAddr::V4(_) => AddressFamily::Inet,
            SocketAddr::V6(_) => AddressFamily::Inet6,
        }
    }
    pub fn into_addr<T: GenericSocketAddr>(self) -> T {
        unsafe { core::ptr::read(self.as_ptr() as *const T) }
    }
    pub fn try_into<T: GenericSocketAddr>(self) -> Option<T> {
        if self.family() as isize == T::family() as isize {
            Some(self.into_addr())
        } else {
            None
        }
    }
}

impl SocketAddr {
    pub(crate) fn as_ptr_mut(&mut self) -> *mut bindings::sockaddr {
        self.as_ptr() as _
    }
    pub(crate) fn as_ptr(&self) -> *const bindings::sockaddr {
        match self {
            SocketAddr::V4(addr) => addr as *const _ as _,
            SocketAddr::V6(addr) => addr as *const _ as _,
        }
    }
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

pub trait GenericSocketAddr: Copy {
    fn size() -> usize
    where
        Self: Sized,
    {
        core::mem::size_of::<Self>()
    }
    fn family() -> AddressFamily;
}

pub trait SocketAddressInfo<T> {
    fn address(&self) -> &T;
    fn port(&self) -> u16;
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct SocketAddrV4(pub(crate) bindings::sockaddr_in);

impl SocketAddrV4 {
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
    fn family() -> AddressFamily {
        AddressFamily::Inet
    }
}

impl SocketAddressInfo<Ipv4Addr> for SocketAddrV4 {
    fn address(&self) -> &Ipv4Addr {
        unsafe { &*(&self.0.sin_addr as *const _ as *const Ipv4Addr) }
    }

    fn port(&self) -> u16 {
        self.0.sin_port.to_be()
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct SocketAddrV6(pub(crate) bindings::sockaddr_in6);

impl SocketAddrV6 {
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
    fn family() -> AddressFamily {
        AddressFamily::Inet6
    }
}

impl SocketAddressInfo<Ipv6Addr> for SocketAddrV6 {
    fn address(&self) -> &Ipv6Addr {
        unsafe { &*(&self.0.sin6_addr as *const _ as *const Ipv6Addr) }
    }

    fn port(&self) -> u16 {
        self.0.sin6_port.to_be()
    }
}
