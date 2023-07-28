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

impl From<isize> for IpProtocol {
    fn from(value: isize) -> Self {
        let val: u32 = value as u32;
        match val {
            bindings::IPPROTO_IP => IpProtocol::Ip,
            bindings::IPPROTO_ICMP => IpProtocol::Icmp,
            bindings::IPPROTO_TCP => IpProtocol::Tcp,
            bindings::IPPROTO_UDP => IpProtocol::Udp,
            bindings::IPPROTO_IPV6 => IpProtocol::Ipv6,
            bindings::IPPROTO_RAW => IpProtocol::Raw,
            _ => panic!("Unknown IP protocol: {}", value),
        }
    }
}

impl From<IpProtocol> for isize {
    fn from(value: IpProtocol) -> Self {
        value as _
    }
}

/// IP header.
#[repr(transparent)]
#[derive(Default, Copy, Clone)]
pub struct IpHeader(pub(crate) bindings::iphdr);

impl IpHeader {
    /// Create a new IP header.
    pub fn new(
        ihl: u8,
        version: u8,
        tos: u8,
        tot_len: u16,
        id: u16,
        frag_off: u16,
        ttl: u8,
        protocol: u8,
        check: u16,
        saddr: u32,
        daddr: u32,
    ) -> Self {
        Self(bindings::iphdr {
            _bitfield_align_1: [0; 0],
            _bitfield_1: bindings::iphdr::new_bitfield_1(ihl, version),
            tos,
            tot_len,
            id,
            frag_off,
            ttl,
            protocol,
            check,
            __bindgen_anon_1: bindings::iphdr__bindgen_ty_1 {
                addrs: bindings::iphdr__bindgen_ty_1__bindgen_ty_2 { saddr, daddr },
            },
        })
    }

    /// Returns the length of the IP header in bytes.
    ///
    /// # Note
    /// The IHL field is actually the first 4 bits of the first byte of the IP header.
    pub fn ihl(&self) -> u8 {
        self.0.ihl()
    }

    /// Sets the length of the IP header in bytes.
    ///
    /// # Note
    /// The IHL field is actually 4-bit long.
    pub fn set_ihl(&mut self, ihl: u8) {
        self.0.set_ihl(ihl);
    }

    /// Returns the IP version.
    ///
    /// # Note
    /// The version field is actually the last 4 bits of the first byte of the IP header.
    pub fn version(&self) -> u8 {
        self.0.version()
    }

    /// Sets the IP version.
    ///
    /// # Note
    /// The version field is actually 4-bit long.
    pub fn set_version(&mut self, version: u8) {
        self.0.set_version(version);
    }

    /// Returns the type of service.
    pub fn tos(&self) -> u8 {
        self.0.tos
    }

    /// Sets the type of service.
    pub fn set_tos(&mut self, tos: u8) {
        self.0.tos = tos;
    }

    /// Returns the total length of the IP packet in bytes.
    pub fn tot_len(&self) -> u16 {
        self.0.tot_len
    }

    /// Sets the total length of the IP packet in bytes.
    pub fn set_tot_len(&mut self, tot_len: u16) {
        self.0.tot_len = tot_len;
    }

    /// Returns the identification of the IP packet.
    pub fn id(&self) -> u16 {
        self.0.id
    }

    /// Sets the identification of the IP packet.
    pub fn set_id(&mut self, id: u16) {
        self.0.id = id;
    }

    /// Returns the fragment offset.
    pub fn frag_off(&self) -> u16 {
        self.0.frag_off
    }

    /// Sets the fragment offset.
    pub fn set_frag_off(&mut self, frag_off: u16) {
        self.0.frag_off = frag_off;
    }

    /// Returns the time to live.
    pub fn ttl(&self) -> u8 {
        self.0.ttl
    }

    /// Sets the time to live.
    pub fn set_ttl(&mut self, ttl: u8) {
        self.0.ttl = ttl;
    }

    /// Returns the protocol.
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.0.protocol as isize)
    }

    /// Sets the protocol.
    pub fn set_protocol(&mut self, protocol: IpProtocol) {
        self.0.protocol = protocol as _;
    }

    /// Returns the checksum.
    pub fn check(&self) -> u16 {
        self.0.check
    }

    /// Sets the checksum.
    pub fn set_check(&mut self, check: u16) {
        self.0.check = check;
    }

    /// Returns the source address.
    pub fn saddr(&self) -> u32 {
        // SAFETY: Both the structs in the union have the same layout.
        unsafe { self.0.__bindgen_anon_1.addrs.saddr }
    }

    /// Sets the source address.
    pub fn set_saddr(&mut self, saddr: u32) {
        self.0.__bindgen_anon_1.addrs.saddr = saddr;
    }

    /// Returns the destination address.
    pub fn daddr(&self) -> u32 {
        // SAFETY: Both the structs in the union have the same layout.
        unsafe { self.0.__bindgen_anon_1.addrs.daddr }
    }

    /// Sets the destination address.
    pub fn set_daddr(&mut self, daddr: u32) {
        self.0.__bindgen_anon_1.addrs.daddr = daddr;
    }
}

impl From<bindings::iphdr> for IpHeader {
    fn from(header: bindings::iphdr) -> Self {
        Self(header)
    }
}
