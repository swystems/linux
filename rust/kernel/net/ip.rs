// SPDX-License-Identifier: GPL-2.0

//! IP protocol definitions.
//!
//! This module contains the kernel structures and functions related to IP protocols.
//!
//! C header: [`include/linux/in.h`](../../../../include/linux/in.h)
//! C header: [`include/linux/ip.h`](../../../../include/linux/ip.h)
//! C header: [`include/uapi/linux/ip.h`](../../../../include/uapi/linux/ip.h)

/// The Ip protocol.
///
/// See `include/uapi/linux/in.h` for more information.
pub enum IpProtocol {
    // TODO: implement the rest of the protocols
    /// Unspecified protocol.
    Ip = bindings::IPPROTO_IP as isize,
    /// Internet Control Message Protocol.
    Icmp = bindings::IPPROTO_ICMP as isize,
    /// Transmission Control Protocol.
    Tcp = bindings::IPPROTO_TCP as isize,
    /// User Datagram Protocol.
    Udp = bindings::IPPROTO_UDP as isize,
    /// IPv6-in-IPv4 tunnelling.
    Ipv6 = bindings::IPPROTO_IPV6 as isize,
    /// Raw IP packets.
    Raw = bindings::IPPROTO_RAW as isize,
}
