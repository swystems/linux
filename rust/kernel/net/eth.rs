// SPDX-License-Identifier: GPL-2.0

//! Ethernet IEEE 802.3 interface.
//!
//! C header: [`include/uapi/linux/if_ether.h`](../../../../include/uapi/linux/if_ether.h)

use crate::bindings;

/// Octets in one ethernet hardware address.
pub const ALEN: u32 = bindings::ETH_ALEN;

/// Octets in the ethernet type header field.
pub const TLEN: u32 = bindings::ETH_TLEN;

/// Octets in ethernet header.
pub const HLEN: u32 = bindings::ETH_HLEN;

/// Min octets in ethernet frame sans FCS.
pub const ZLEN: u32 = bindings::ETH_ZLEN;

/// Max octets in payload
pub const DATA_LEN: u32 = bindings::ETH_DATA_LEN;

/// Max octets in frame sans FCS
pub const FRAME_LEN: u32 = bindings::ETH_FRAME_LEN;

/// Octets in the FCS
pub const FCS_LEN: u32 = bindings::ETH_FCS_LEN;

/// Min IPv4 MTU (RFC791)
pub const MIN_MTU: u32 = bindings::ETH_MIN_MTU;

/// Max IPv4 MTU (RFC791)
pub const MAX_MTU: u32 = bindings::ETH_MAX_MTU;

/// Max value of the protocol field for Ethernet 802.3
pub const P_802_3_MIN: u32 = bindings::ETH_P_802_3_MIN;

/// Ethernet address
type EthAddress = [u8; ALEN as usize];

/// Ethernet frame header
#[derive(Default, Copy, Clone)]
#[repr(transparent)]
pub struct EthHeader(pub(crate) bindings::ethhdr);

impl EthHeader {
    /// Create a new Ethernet frame header
    pub fn new(dest: EthAddress, source: EthAddress, protocol: EthProtocol) -> Self {
        Self(bindings::ethhdr {
            h_dest: dest as _,
            h_source: source as _,
            h_proto: protocol as u16,
        })
    }

    /// Get the destination address
    pub fn dest(&self) -> EthAddress {
        self.0.h_dest as _
    }

    /// Set the destination address
    pub fn set_dest(&mut self, dest: EthAddress) {
        self.0.h_dest = dest as _;
    }

    /// Get the source address
    pub fn source(&self) -> EthAddress {
        self.0.h_source as _
    }

    /// Set the source address
    pub fn set_source(&mut self, source: EthAddress) {
        self.0.h_source = source as _;
    }

    /// Get the protocol
    pub fn protocol(&self) -> EthProtocol {
        EthProtocol::from(self.0.h_proto as isize)
    }

    /// Set the protocol
    pub fn set_protocol(&mut self, protocol: EthProtocol) {
        self.0.h_proto = protocol as _;
    }
}

impl From<bindings::ethhdr> for EthHeader {
    fn from(value: bindings::ethhdr) -> Self {
        Self(value)
    }
}

/// Ethernet protocol
pub enum EthProtocol {
    /// Ethernet Loopback packet
    Loop = bindings::ETH_P_LOOP as isize,
    /// Xerox PUP packet
    Pup = bindings::ETH_P_PUP as isize,
    /// Xerox PUP Addr Trans packet
    Pupat = bindings::ETH_P_PUPAT as isize,
    /// TSN (IEEE 1722) packet
    Tsn = bindings::ETH_P_TSN as isize,
    /// ERSPAN version 2 (type III)
    Erspan2 = bindings::ETH_P_ERSPAN2 as isize,
    /// Internet Protocol packet
    Ip = bindings::ETH_P_IP as isize,
    /// CCITT X.25
    X25 = bindings::ETH_P_X25 as isize,
    /// Address Resolution packet
    Arp = bindings::ETH_P_ARP as isize,
    /// G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ]
    Bpq = bindings::ETH_P_BPQ as isize,
    /// Xerox IEEE802.3 PUP packet
    IeeePup = bindings::ETH_P_IEEEPUP as isize,
    /// Xerox IEEE802.3 PUP Addr Trans packet
    IeeePupat = bindings::ETH_P_IEEEPUPAT as isize,
    /// B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
    Batman = bindings::ETH_P_BATMAN as isize,
    /// DEC Assigned proto
    Dec = bindings::ETH_P_DEC as isize,
    /// DEC DNA Dump/Load
    DnaDL = bindings::ETH_P_DNA_DL as isize,
    /// DEC DNA Remote Console
    DnaRC = bindings::ETH_P_DNA_RC as isize,
    /// DEC DNA Routing
    DnaRT = bindings::ETH_P_DNA_RT as isize,
    /// DEC LAT
    Lat = bindings::ETH_P_LAT as isize,
    /// DEC Diagnostics
    Diag = bindings::ETH_P_DIAG as isize,
    /// DEC Customer use
    Cust = bindings::ETH_P_CUST as isize,
    /// DEC Systems Comms Arch
    Sca = bindings::ETH_P_SCA as isize,
    /// Trans Ether Bridging
    Teb = bindings::ETH_P_TEB as isize,
    /// Reverse Addr Res packet
    Rarp = bindings::ETH_P_RARP as isize,
    /// Appletalk DDP
    Atalk = bindings::ETH_P_ATALK as isize,
    /// Appletalk AARP
    Aarp = bindings::ETH_P_AARP as isize,
    /// 802.1Q VLAN Extended Header
    P8021q = bindings::ETH_P_8021Q as isize,
    /// ERSPAN type II
    Erspan = bindings::ETH_P_ERSPAN as isize,
    /// IPX over DIX
    Ipx = bindings::ETH_P_IPX as isize,
    /// IPv6 over bluebook
    Ipv6 = bindings::ETH_P_IPV6 as isize,
    /// IEEE Pause frames. See 802.3 31B
    Pause = bindings::ETH_P_PAUSE as isize,
    /// Slow Protocol. See 802.3ad 43B
    Slow = bindings::ETH_P_SLOW as isize,
    /// Web-cache coordination protocol
    Wccp = bindings::ETH_P_WCCP as isize,
    /// MPLS Unicast traffic
    MplsUc = bindings::ETH_P_MPLS_UC as isize,
    /// MPLS Multicast traffic
    MplsMc = bindings::ETH_P_MPLS_MC as isize,
    /// MultiProtocol Over ATM
    AtmmPoA = bindings::ETH_P_ATMMPOA as isize,
    /// PPPoE discovery messages
    PppDisc = bindings::ETH_P_PPP_DISC as isize,
    /// PPPoE session messages
    PppSes = bindings::ETH_P_PPP_SES as isize,
    /// HPNA, wlan link local tunnel
    LinkCtl = bindings::ETH_P_LINK_CTL as isize,
    /// Frame-based ATM Transport over Ethernet
    AtmFate = bindings::ETH_P_ATMFATE as isize,
    /// Port Access Entity (IEEE 802.1X)
    Pae = bindings::ETH_P_PAE as isize,
    /// PROFINET
    Profinet = bindings::ETH_P_PROFINET as isize,
    /// Multiple proprietary protocols
    Realtek = bindings::ETH_P_REALTEK as isize,
    /// ATA over Ethernet
    Aoe = bindings::ETH_P_AOE as isize,
    /// EtherCAT
    Ethercat = bindings::ETH_P_ETHERCAT as isize,
    /// 802.1ad Service VLAN
    P8021AD = bindings::ETH_P_8021AD as isize,
    /// 802.1 Local Experimental 1.
    P802EX1 = bindings::ETH_P_802_EX1 as isize,
    /// 802.11 Preauthentication
    Preauth = bindings::ETH_P_PREAUTH as isize,
    /// TIPC
    Tipc = bindings::ETH_P_TIPC as isize,
    /// Link Layer Discovery Protocol
    Lldp = bindings::ETH_P_LLDP as isize,
    /// Media Redundancy Protocol
    Mrp = bindings::ETH_P_MRP as isize,
    /// 802.1ae MACsec
    Macsec = bindings::ETH_P_MACSEC as isize,
    /// 802.1ah Backbone Service Tag
    P8021AH = bindings::ETH_P_8021AH as isize,
    /// 802.1Q MVRP
    Mvrp = bindings::ETH_P_MVRP as isize,
    /// IEEE 1588 Timesync
    P1588 = bindings::ETH_P_1588 as isize,
    /// NCSI protocol
    Ncsi = bindings::ETH_P_NCSI as isize,
    /// IEC 62439-3 PRP/HSRv0
    Prp = bindings::ETH_P_PRP as isize,
    /// Connectivity Fault Management
    Cfm = bindings::ETH_P_CFM as isize,
    /// Fibre Channel over Ethernet
    Fcoe = bindings::ETH_P_FCOE as isize,
    /// Infiniband over Ethernet
    Iboe = bindings::ETH_P_IBOE as isize,
    /// TDLS
    Tdls = bindings::ETH_P_TDLS as isize,
    /// FCoE Initialization Protocol
    Fip = bindings::ETH_P_FIP as isize,
    /// IEEE 802.21 Media Independent Handover Protocol
    P80221 = bindings::ETH_P_80221 as isize,
    /// IEC 62439-3 HSRv1
    Hsr = bindings::ETH_P_HSR as isize,
    /// Network Service Header
    Nsh = bindings::ETH_P_NSH as isize,
    /// Ethernet loopback packet, per IEEE 802.3
    Loopback = bindings::ETH_P_LOOPBACK as isize,
    /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    Qinq1 = bindings::ETH_P_QINQ1 as isize,
    /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    Qinq2 = bindings::ETH_P_QINQ2 as isize,
    /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
    Qinq3 = bindings::ETH_P_QINQ3 as isize,
    /// Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
    Edsa = bindings::ETH_P_EDSA as isize,
    /// Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ]
    Dsa8021q = bindings::ETH_P_DSA_8021Q as isize,
    /// A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ]
    DsaA5psw = bindings::ETH_P_DSA_A5PSW as isize,
    /// ForCES inter-FE LFB type
    Ife = bindings::ETH_P_IFE as isize,
    /// IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
    AfIucv = bindings::ETH_P_AF_IUCV as isize,
}

impl From<EthProtocol> for isize {
    fn from(proto: EthProtocol) -> isize {
        proto as isize
    }
}

impl From<isize> for EthProtocol {
    fn from(proto: isize) -> EthProtocol {
        let val: u32 = proto as u32;
        match val {
            bindings::ETH_P_LOOP => EthProtocol::Loop,
            bindings::ETH_P_PUP => EthProtocol::Pup,
            bindings::ETH_P_PUPAT => EthProtocol::Pupat,
            bindings::ETH_P_TSN => EthProtocol::Tsn,
            bindings::ETH_P_ERSPAN2 => EthProtocol::Erspan2,
            bindings::ETH_P_IP => EthProtocol::Ip,
            bindings::ETH_P_X25 => EthProtocol::X25,
            bindings::ETH_P_ARP => EthProtocol::Arp,
            bindings::ETH_P_BPQ => EthProtocol::Bpq,
            bindings::ETH_P_IEEEPUP => EthProtocol::IeeePup,
            bindings::ETH_P_IEEEPUPAT => EthProtocol::IeeePupat,
            bindings::ETH_P_BATMAN => EthProtocol::Batman,
            bindings::ETH_P_DEC => EthProtocol::Dec,
            bindings::ETH_P_DNA_DL => EthProtocol::DnaDL,
            bindings::ETH_P_DNA_RC => EthProtocol::DnaRC,
            bindings::ETH_P_DNA_RT => EthProtocol::DnaRT,
            bindings::ETH_P_LAT => EthProtocol::Lat,
            bindings::ETH_P_DIAG => EthProtocol::Diag,
            bindings::ETH_P_CUST => EthProtocol::Cust,
            bindings::ETH_P_SCA => EthProtocol::Sca,
            bindings::ETH_P_TEB => EthProtocol::Teb,
            bindings::ETH_P_RARP => EthProtocol::Rarp,
            bindings::ETH_P_ATALK => EthProtocol::Atalk,
            bindings::ETH_P_AARP => EthProtocol::Aarp,
            bindings::ETH_P_8021Q => EthProtocol::P8021q,
            bindings::ETH_P_ERSPAN => EthProtocol::Erspan,
            bindings::ETH_P_IPX => EthProtocol::Ipx,
            bindings::ETH_P_IPV6 => EthProtocol::Ipv6,
            bindings::ETH_P_PAUSE => EthProtocol::Pause,
            bindings::ETH_P_SLOW => EthProtocol::Slow,
            bindings::ETH_P_WCCP => EthProtocol::Wccp,
            bindings::ETH_P_MPLS_UC => EthProtocol::MplsUc,
            bindings::ETH_P_MPLS_MC => EthProtocol::MplsMc,
            bindings::ETH_P_ATMMPOA => EthProtocol::AtmmPoA,
            bindings::ETH_P_PPP_DISC => EthProtocol::PppDisc,
            bindings::ETH_P_PPP_SES => EthProtocol::PppSes,
            bindings::ETH_P_LINK_CTL => EthProtocol::LinkCtl,
            bindings::ETH_P_ATMFATE => EthProtocol::AtmFate,
            bindings::ETH_P_PAE => EthProtocol::Pae,
            bindings::ETH_P_PROFINET => EthProtocol::Profinet,
            bindings::ETH_P_REALTEK => EthProtocol::Realtek,
            bindings::ETH_P_AOE => EthProtocol::Aoe,
            bindings::ETH_P_ETHERCAT => EthProtocol::Ethercat,
            bindings::ETH_P_8021AD => EthProtocol::P8021AD,
            bindings::ETH_P_802_EX1 => EthProtocol::P802EX1,
            bindings::ETH_P_PREAUTH => EthProtocol::Preauth,
            bindings::ETH_P_TIPC => EthProtocol::Tipc,
            bindings::ETH_P_LLDP => EthProtocol::Lldp,
            bindings::ETH_P_MRP => EthProtocol::Mrp,
            bindings::ETH_P_MACSEC => EthProtocol::Macsec,
            bindings::ETH_P_8021AH => EthProtocol::P8021AH,
            bindings::ETH_P_MVRP => EthProtocol::Mvrp,
            bindings::ETH_P_1588 => EthProtocol::P1588,
            bindings::ETH_P_NCSI => EthProtocol::Ncsi,
            bindings::ETH_P_PRP => EthProtocol::Prp,
            bindings::ETH_P_CFM => EthProtocol::Cfm,
            bindings::ETH_P_FCOE => EthProtocol::Fcoe,
            bindings::ETH_P_IBOE => EthProtocol::Iboe,
            bindings::ETH_P_TDLS => EthProtocol::Tdls,
            bindings::ETH_P_FIP => EthProtocol::Fip,
            bindings::ETH_P_80221 => EthProtocol::P80221,
            bindings::ETH_P_HSR => EthProtocol::Hsr,
            bindings::ETH_P_NSH => EthProtocol::Nsh,
            bindings::ETH_P_LOOPBACK => EthProtocol::Loopback,
            bindings::ETH_P_QINQ1 => EthProtocol::Qinq1,
            bindings::ETH_P_QINQ2 => EthProtocol::Qinq2,
            bindings::ETH_P_QINQ3 => EthProtocol::Qinq3,
            bindings::ETH_P_EDSA => EthProtocol::Edsa,
            bindings::ETH_P_DSA_8021Q => EthProtocol::Dsa8021q,
            bindings::ETH_P_DSA_A5PSW => EthProtocol::DsaA5psw,
            bindings::ETH_P_IFE => EthProtocol::Ife,
            bindings::ETH_P_AF_IUCV => EthProtocol::AfIucv,
            _ => panic!("Unknown Ethernet 802.3 protocol: {}", proto),
        }
    }
}
