// SPDX-License-Identifier: GPL-2.0

//! Network subsystem.
//!
//! This module contains the kernel APIs related to networking that have been ported or wrapped for
//! usage by Rust code in the kernel.
//!
//! C header: [`include/linux/net.h`](../../../../include/linux/net.h)

use core::cell::UnsafeCell;

pub mod addr;
pub mod dev;
pub mod eth;
pub mod ip;
pub mod skb;
pub mod socket;
pub mod tcp;
pub mod udp;

/// The address family.
///
/// See [`man 7 address families`](https://man7.org/linux/man-pages/man7/address_families.7.html) for more information.
pub enum AddressFamily {
    /// Unspecified address family.
    Unspec = bindings::AF_UNSPEC as isize,
    /// Local to host (pipes and file-domain).
    Unix = bindings::AF_UNIX as isize,
    /// Internetwork: UDP, TCP, etc.
    Inet = bindings::AF_INET as isize,
    /// Amateur radio AX.25.
    Ax25 = bindings::AF_AX25 as isize,
    /// IPX.
    Ipx = bindings::AF_IPX as isize,
    /// Appletalk DDP.
    Appletalk = bindings::AF_APPLETALK as isize,
    /// AX.25 packet layer protocol.
    Netrom = bindings::AF_NETROM as isize,
    /// Bridge link.
    Bridge = bindings::AF_BRIDGE as isize,
    /// ATM PVCs.
    Atmpvc = bindings::AF_ATMPVC as isize,
    /// X.25 (ISO-8208).
    X25 = bindings::AF_X25 as isize,
    /// IPv6.
    Inet6 = bindings::AF_INET6 as isize,
    /// ROSE protocol.
    Rose = bindings::AF_ROSE as isize,
    /// DECnet protocol.
    Decnet = bindings::AF_DECnet as isize,
    /// 802.2LLC project.
    Netbeui = bindings::AF_NETBEUI as isize,
    /// Firewall hooks.
    Security = bindings::AF_SECURITY as isize,
    /// Key management protocol.
    Key = bindings::AF_KEY as isize,
    /// Netlink.
    Netlink = bindings::AF_NETLINK as isize,
    /// Low-level packet interface.
    Packet = bindings::AF_PACKET as isize,
    /// Acorn Econet protocol.
    Econet = bindings::AF_ECONET as isize,
    /// ATM SVCs.
    Atmsvc = bindings::AF_ATMSVC as isize,
    /// RDS sockets.
    Rds = bindings::AF_RDS as isize,
    /// IRDA sockets.
    Irda = bindings::AF_IRDA as isize,
    /// Generic PPP.
    Pppox = bindings::AF_PPPOX as isize,
    /// Legacy WAN networks protocol.
    Wanpipe = bindings::AF_WANPIPE as isize,
    /// LLC protocol.
    Llc = bindings::AF_LLC as isize,
    /// Infiniband.
    Ib = bindings::AF_IB as isize,
    /// Multiprotocol label switching.
    Mpls = bindings::AF_MPLS as isize,
    /// Controller Area Network.
    Can = bindings::AF_CAN as isize,
    /// TIPC sockets.
    Tipc = bindings::AF_TIPC as isize,
    /// Bluetooth sockets.
    Bluetooth = bindings::AF_BLUETOOTH as isize,
    /// IUCV sockets.
    Iucv = bindings::AF_IUCV as isize,
    /// RxRPC sockets.
    Rxrpc = bindings::AF_RXRPC as isize,
    /// Modular ISDN protocol.
    Isdn = bindings::AF_ISDN as isize,
    /// Nokia cellular modem interface.
    Phonet = bindings::AF_PHONET as isize,
    /// IEEE 802.15.4 sockets.
    Ieee802154 = bindings::AF_IEEE802154 as isize,
    /// CAIF sockets.
    Caif = bindings::AF_CAIF as isize,
    /// Kernel crypto API
    Alg = bindings::AF_ALG as isize,
    /// VMware VSockets.
    Vsock = bindings::AF_VSOCK as isize,
    /// KCM sockets.
    Kcm = bindings::AF_KCM as isize,
    /// Qualcomm IPC router protocol.
    Qipcrtr = bindings::AF_QIPCRTR as isize,
    /// SMC sockets.
    Smc = bindings::AF_SMC as isize,
    /// Express Data Path sockets.
    Xdp = bindings::AF_XDP as isize,
}

/// Network namespace.
///
/// Wraps `struct net` from `include/net/net_namespace.h`.
#[repr(transparent)]
pub struct Namespace(UnsafeCell<bindings::net>);

/// The global network namespace.
pub fn init_ns() -> &'static Namespace {
    unsafe { &*core::ptr::addr_of!(bindings::init_net).cast() }
}
