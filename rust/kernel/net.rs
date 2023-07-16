use core::cell::UnsafeCell;

pub mod socket;
pub mod addr;

pub enum AddressFamily {
    Unspec = bindings::AF_UNSPEC as isize,
    Unix = bindings::AF_UNIX as isize,
    Inet = bindings::AF_INET as isize,
    Ax25 = bindings::AF_AX25 as isize,
    Ipx = bindings::AF_IPX as isize,
    Appletalk = bindings::AF_APPLETALK as isize,
    Netrom = bindings::AF_NETROM as isize,
    Bridge = bindings::AF_BRIDGE as isize,
    Atmpvc = bindings::AF_ATMPVC as isize,
    X25 = bindings::AF_X25 as isize,
    Inet6 = bindings::AF_INET6 as isize,
    Rose = bindings::AF_ROSE as isize,
    Decnet = bindings::AF_DECnet as isize,
    Netbeui = bindings::AF_NETBEUI as isize,
    Security = bindings::AF_SECURITY as isize,
    Key = bindings::AF_KEY as isize,
    Netlink = bindings::AF_NETLINK as isize,
    Packet = bindings::AF_PACKET as isize,
    Ash = bindings::AF_ASH as isize,
    Econet = bindings::AF_ECONET as isize,
    Atmsvc = bindings::AF_ATMSVC as isize,
    Rds = bindings::AF_RDS as isize,
    Sna = bindings::AF_SNA as isize,
    Irda = bindings::AF_IRDA as isize,
    Pppox = bindings::AF_PPPOX as isize,
    Wanpipe = bindings::AF_WANPIPE as isize,
    Llc = bindings::AF_LLC as isize,
    Ib = bindings::AF_IB as isize,
    Mpls = bindings::AF_MPLS as isize,
    Can = bindings::AF_CAN as isize,
    Tipc = bindings::AF_TIPC as isize,
    Bluetooth = bindings::AF_BLUETOOTH as isize,
    Iucv = bindings::AF_IUCV as isize,
    Rxrpc = bindings::AF_RXRPC as isize,
    Isdn = bindings::AF_ISDN as isize,
    Phonet = bindings::AF_PHONET as isize,
    Ieee802154 = bindings::AF_IEEE802154 as isize,
    Caif = bindings::AF_CAIF as isize,
    Alg = bindings::AF_ALG as isize,
    Nfc = bindings::AF_NFC as isize,
    Vsock = bindings::AF_VSOCK as isize,
    Kcm = bindings::AF_KCM as isize,
    Qipcrtr = bindings::AF_QIPCRTR as isize,
    Smc = bindings::AF_SMC as isize,
    Xdp = bindings::AF_XDP as isize,
    Mctp = bindings::AF_MCTP as isize,
    Max = bindings::AF_MAX as isize,
}

pub enum IpProtocol {
    // TODO: implement the rest of the protocols
    Ip = bindings::IPPROTO_IP as isize,
    Icmp = bindings::IPPROTO_ICMP as isize,
    Tcp = bindings::IPPROTO_TCP as isize,
    Udp = bindings::IPPROTO_UDP as isize,
    Ipv6 = bindings::IPPROTO_IPV6 as isize,
    Raw = bindings::IPPROTO_RAW as isize,
}

/// Wraps the kernel's `struct net`.
#[repr(transparent)]
pub struct Namespace(UnsafeCell<bindings::net>);

/// Returns the network namespace for the `init` process.
pub fn init_ns() -> &'static Namespace {
    unsafe { &*core::ptr::addr_of!(bindings::init_net).cast() }
}