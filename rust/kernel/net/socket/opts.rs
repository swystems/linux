// SPDX-License-Identifier: GPL-2.0

//! Socket options.
//!
//! This module contains the types related to socket options.
//! It is meant to be used together with the [`Socket`](kernel::net::socket::Socket) type.
//!
//! Currently, only a subset of the socket options are supported, because some of them
//! require specific structures, that must be ported to Rust before they can be used.

use kernel::bindings;

/// Options level to retrieve and set socket options.
/// See `man 7 socket` for more information.
pub enum OptionsLevel {
    /// IP level socket options.
    /// See `man 7 ip` for more information.
    Ip = bindings::IPPROTO_IP as isize,

    /// Socket level socket options.
    /// See `man 7 socket` for more information.
    Socket = bindings::SOL_SOCKET as isize,

    /// IPv6 level socket options.
    /// See `man 7 ipv6` for more information.
    Ipv6 = bindings::IPPROTO_IPV6 as isize,

    /// Raw level socket options.
    /// See `man 7 raw` for more information.
    Raw = bindings::IPPROTO_RAW as isize,

    /// TCP level socket options.
    /// See `man 7 tcp` for more information.
    Tcp = bindings::IPPROTO_TCP as isize,
}

/// IP-level socket options.
///
/// Only the options with a Rust-wrapped struct are implemented.
pub enum IpOptions {
    /// Join a multicast group.
    ///
    /// C value type: `struct ip_mreqn`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AddMembership = bindings::IP_ADD_MEMBERSHIP as isize,

    /// Join a multicast group and receive only from a source.
    ///
    /// C value type: `struct ip_mreq_source`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AddSourceMembership = bindings::IP_ADD_SOURCE_MEMBERSHIP as isize,

    /// Don't reserve a port when binding with port number `0`.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    BindAddressNoPort = bindings::IP_BIND_ADDRESS_NO_PORT as isize,

    /// Stops receiving multicast data from a specific source
    ///
    /// C value type: `struct ip_mreq_source`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    BlockSource = bindings::IP_BLOCK_SOURCE as isize,

    /// Leave a multicast group.
    ///
    /// C value type: `struct ip_mreqn`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    DropMembership = bindings::IP_DROP_MEMBERSHIP as isize,

    /// Stop receiving data that comes from a specific source in a specific group.
    ///
    /// C value type: `struct ip_mreq_source`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    DropSourceMembership = bindings::IP_DROP_SOURCE_MEMBERSHIP as isize,

    /// Allow binding to a non-local non-yet-existing address.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    FreeBind = bindings::IP_FREEBIND as isize,

    /// Receive the IP Header in front of the user data. Only valid with raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    Header = bindings::IP_HDRINCL as isize,

    /// Full-state multicast filtering API.
    ///
    /// C value type: `struct ip_msfilter`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    MsFilter = bindings::IP_MSFILTER as isize,

    /// Retrieve the path MTU of the socket. Read-only.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    Mtu = bindings::IP_MTU as isize,

    /// Set or retrieve Path MTU discovery settings.
    ///
    /// C value type: `int` macros
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    MtuDiscover = bindings::IP_MTU_DISCOVER as isize,

    /// Modify delivery policy of messages.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    MulticastAll = bindings::IP_MULTICAST_ALL as isize,

    /// Set the interface for outgoing multicast packets.
    ///
    /// C value type: `struct in_addr`
    ///
    /// Rust value type: [Ipv4Addr](kernel::net::addr::Ipv4Addr)
    MulticastIf = bindings::IP_MULTICAST_IF as isize,

    /// Set or read whether multicast packets are looped back to the local socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    MulticastLoop = bindings::IP_MULTICAST_LOOP as isize,

    /// Set or read the TTL of multicast packets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u8`
    MulticastTtl = bindings::IP_MULTICAST_TTL as isize,

    /// Sets whether the reassembly is disabled in the netfilter layer.
    /// Only valid with raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    NoDefrag = bindings::IP_NODEFRAG as isize,

    /// Set or read the IP options to be sent in very packet on the socket.
    ///
    /// C value type: `*void`
    ///
    /// Rust value type: unimplemented (?)
    #[non_exhaustive]
    Options = bindings::IP_OPTIONS as isize,

    /// Enable receiving the security context with the packet.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    PassSec = bindings::IP_PASSSEC as isize,

    /// Enable extended reliable error message passing.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RecvErr = bindings::IP_RECVERR as isize,

    /// Pass all IP Router Alert enabled messages to this socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RouterAlert = bindings::IP_ROUTER_ALERT as isize,

    /// Set or receive TOS field sent with every packet.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u8`
    IpTos = bindings::IP_TOS as isize,

    /// Set transparent proxying.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    IpTransparent = bindings::IP_TRANSPARENT as isize,

    /// Set or receive TTL field sent with every packet.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u8`
    IpTtl = bindings::IP_TTL as isize,

    /// Unblock a previously blocked source.
    ///
    /// C value type: `struct ip_mreq_source`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    UnblockSource = bindings::IP_UNBLOCK_SOURCE as isize,
}

/// Socket-level options.
///
/// See `man 7 socket` for more information.
pub enum SocketOptions {
    /// Get whether the socket is accepting connections. Read-only.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    AcceptConn = bindings::SO_ACCEPTCONN as isize,

    /// Attach a filter to the socket.
    ///
    /// C value type: `struct sock_fprog`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AttachFilter = bindings::SO_ATTACH_FILTER as isize,

    /// Attach a eBPF program to the socket.
    ///
    /// C value type: `struct sock_fprog`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AttachBpf = bindings::SO_ATTACH_BPF as isize,

    /// Attach a BPF program to the socket.
    ///
    /// C value type: `struct sock_fprog`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AttachReusePortCBPF = bindings::SO_ATTACH_REUSEPORT_CBPF as isize,

    /// Attach a eBPF program to the socket.
    ///
    /// C value type: `struct sock_fprog`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AttachReusePortEBPF = bindings::SO_ATTACH_REUSEPORT_EBPF as isize,

    /// Bind the socket to a specific network device.
    /// If the string passed has a length of 0, the socket is unbound.
    ///
    /// C value type: `char *`
    ///
    /// Rust value type: `&str`
    BindToDevice = bindings::SO_BINDTODEVICE as isize,

    /// Set or get the broadcast flag. Only valid on datagram sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    Broadcast = bindings::SO_BROADCAST as isize,

    /// Enable BSD bug-to-bug compatibility.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    BsdCompatible = bindings::SO_BSDCOMPAT as isize,

    /// Enable socket debugging.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    Debug = bindings::SO_DEBUG as isize,

    /// Remove classic BPF or eBPF program from the socket.
    /// The argument is ignored.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    DetachFilter = bindings::SO_DETACH_FILTER as isize,

    /// Get the domain of the socket. Read-only.
    ///
    /// C value type: `int` macros (e.g. `AF_INET`)
    ///
    /// Rust value type: [AddressFamily](kernel::net::AddressFamily)
    Domain = bindings::SO_DOMAIN as isize,

    /// Get and clear the pending socket error. Read-only.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: [Error](kernel::error::Error) (?)
    #[non_exhaustive]
    Error = bindings::SO_ERROR as isize,

    /// Only send packets to directly connected peers.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    DontRoute = bindings::SO_DONTROUTE as isize,

    /// Set or get the CPU affinity of a socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    IncomingCpu = bindings::SO_INCOMING_CPU as isize,

    /// Retrieve the NAPI ID associated with the last packet received on this socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    IncomingNapiId = bindings::SO_INCOMING_NAPI_ID as isize,

    /// Enable keep-alive packets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    KeepAlive = bindings::SO_KEEPALIVE as isize,

    /// Set or get the linger time of a socket.
    ///
    /// C value type: `struct linger`
    ///
    /// Rust value type: [Linger]
    Linger = bindings::SO_LINGER as isize,

    /// Prevent changing the filters attached to the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    LockFilter = bindings::SO_LOCK_FILTER as isize,

    /// Set or get the mark of a socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    Mark = bindings::SO_MARK as isize,

    /// Set whether out-of-band data is placed into the data stream.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    OobInline = bindings::SO_OOBINLINE as isize,

    /// Enable the receiving of SCM_CREDENTIALS messages.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    PassCred = bindings::SO_PASSCRED as isize,

    /// Enable the receiving of SCM_SECURITY messages.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    PassSec = bindings::SO_PASSSEC as isize,

    /// Set the peek offset for MSG_PEEK messages.
    /// Only valid on UNIX sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    PeekOff = bindings::SO_PEEK_OFF as isize,

    /// Return the credentials of the peer connected to the socket. Read-only.
    ///
    /// C value type: `struct ucred *`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    PeerCredentials = bindings::SO_PEERCRED as isize,

    /// Return the security context of the peer connected to the socket. Read-only.
    ///
    /// C value type: `char *`
    ///
    /// Rust value type: unimplemented (?)
    #[non_exhaustive]
    PeerSecurity = bindings::SO_PEERSEC as isize,

    /// Set or get the protocol-defined priority for packets sent on the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u8`
    Priority = bindings::SO_PRIORITY as isize,

    /// Retrieve the socket protocol. Read-only.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: [IpProtocol](kernel::net::ip::IpProtocol)
    Protocol = bindings::SO_PROTOCOL as isize,

    /// Set or get maximum socket receive buffer.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    RcvBuf = bindings::SO_RCVBUF as isize,

    /// Set or get maximum socket receive buffer.
    /// This option can only be used by processes with the `CAP_NET_ADMIN` capability.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    RcvBufForce = bindings::SO_RCVBUFFORCE as isize,

    /// Set or get the minimum number of bytes to process for socket receive operations.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    RecvLowLatency = bindings::SO_RCVLOWAT as isize,

    /// Set or get the minimum number of bytes to process for socket send operations.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    SendLowLatency = bindings::SO_SNDLOWAT as isize,

    /// Set or get the receive timeout value.
    ///
    /// C value type: `struct timeval`
    ///
    /// Rust value type: unimplemented
    ///
    /// TODO: Understand how to use the _NEW/_OLD values
    #[non_exhaustive]
    RecvTimeo = bindings::SO_RCVTIMEO_NEW as isize,

    /// Set or get the send timeout value.
    ///
    /// C value type: `struct timeval`
    ///
    /// Rust value type: unimplemented
    ///
    /// TODO: Understand how to use the _NEW/_OLD values
    #[non_exhaustive]
    SendTimeo = bindings::SO_SNDTIMEO_NEW as isize,

    /// Bind should allow reuse of local addresses.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    ReuseAddr = bindings::SO_REUSEADDR as isize,

    /// Allow multiple sockets to be bound to identical socket address.
    /// Must be set on each socket before calling `bind`.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    ReusePort = bindings::SO_REUSEPORT as isize,

    /// Set whether the number of dropped packets should be received from the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RxQOvfl = bindings::SO_RXQ_OVFL as isize,

    /// Set or get maximum socket send buffer.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    SndBuf = bindings::SO_SNDBUF as isize,

    /// Set or get maximum socket send buffer.
    /// This option can only be used by processes with the `CAP_NET_ADMIN` capability.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    SndBufForce = bindings::SO_SNDBUFFORCE as isize,

    /// Set the receiving of the timestamp control message.
    /// The message is a `struct timeval`.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    ///
    /// TODO: Understand how to use the _NEW/_OLD values
    Timestamp = bindings::SO_TIMESTAMP_NEW as isize,

    /// Set the receiving of the timestamp control message.
    /// The message is a `struct timespec`.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    ///
    /// TODO: Understand how to use the _NEW/_OLD values
    TimestampNs = bindings::SO_TIMESTAMPNS_NEW as isize,

    /// Get the socket type (e.g. `SOCK_STREAM`). Read-only.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: [SockType](kernel::net::socket::SockType)
    Type = bindings::SO_TYPE as isize,

    /// Set or get time in microseconds to busy poll on a blocking receive.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    BusyPoll = bindings::SO_BUSY_POLL as isize,
}

/// IPv6-level socket options.
///
/// See `man 7 ipv6` for more information.
pub enum Ipv6Options {
    /// Modify the address family used by the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: [AddressFamily](kernel::net::AddressFamily)
    AddrForm = bindings::IPV6_ADDRFORM as isize,

    /// Join a multicast group.
    ///
    /// C value type: `struct ipv6_mreq`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    AddMembership = bindings::IPV6_ADD_MEMBERSHIP as isize,

    /// Leave a multicast group.
    ///
    /// C value type: `struct ipv6_mreq`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    DropMembership = bindings::IPV6_DROP_MEMBERSHIP as isize,

    /// Set or get the MTU of the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    Mtu = bindings::IPV6_MTU as isize,

    /// Set or retrieve Path MTU discovery settings.
    ///
    /// C value type: `int` macros
    ///
    /// Rust value type: unimplemented
    MtuDiscover = bindings::IPV6_MTU_DISCOVER as isize,

    /// Set or get the multicast hop limit.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32` (-1 to 255)
    MulticastHops = bindings::IPV6_MULTICAST_HOPS as isize,

    /// Set or get the multicast interface.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    MulticastInterface = bindings::IPV6_MULTICAST_IF as isize,

    /// Set or read whether multicast packets are looped back to the local socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    MulticastLoop = bindings::IPV6_MULTICAST_LOOP as isize,

    /// Set or get whether IPV6_PKTINFO messages on receive.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RecvPktInfo = bindings::IPV6_RECVPKTINFO as isize,

    /// Set or get whether IPV6_RTHDR messages are delivered to the socket.
    /// IPV6_RTHDR messages carry routing data.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RouteHdr = bindings::IPV6_RTHDR as isize,

    /// Set or get whether IPV6_AUTHHDR messages are delivered to the socket.
    /// IPV6_AUTHHDR messages carry authentication data.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    AuthHdr = bindings::IPV6_AUTHHDR as isize,

    /// Set or get whether IPV6_DSTOPTS messages are delivered to the socket.
    /// IPV6_DSTOPTS messages carry destination options.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    DestOptions = bindings::IPV6_DSTOPTS as isize,

    /// Set or get whether IPV6_HOPOPTS messages are delivered to the socket.
    /// IPV6_HOPOPTS messages carry hop options.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    HopOptions = bindings::IPV6_HOPOPTS as isize,

    /// Set or get whether IPV6_FLOWINFO messages are delivered to the socket.
    /// IPV6_FLOWINFO messages carry the flow ID.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    FlowInfo = bindings::IPV6_FLOWINFO as isize,

    /// Set or get whether IPV6_HOPLIMIT messages are delivered to the socket.
    /// IPV6_HOPLIMIT messages carry the hop count of the packet.
    /// Only valid for datagram and raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    HopLimit = bindings::IPV6_HOPLIMIT as isize,

    /// Enable extended reliable error message passing.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RecvErr = bindings::IPV6_RECVERR as isize,

    /// Pass all Router Alert enabled messages to this socket.
    /// Only valid for raw sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    RouterAlert = bindings::IPV6_ROUTER_ALERT as isize,

    /// Set or get the unicast hop limit for the socket.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32` (-1 to 255)
    UnicastHops = bindings::IPV6_UNICAST_HOPS as isize,

    /// Set whether the socket can only send and receive IPv6 packets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    V6Only = bindings::IPV6_V6ONLY as isize,
}

/// Raw socket options.
///
/// All the datagram-only [IpOptions] are also valid for raw sockets.
///
/// See `man 7 raw` for more information.
pub enum RawOptions {
    /// Enable a filter for IPPROTO_ICMP raw sockets.
    /// The filter has a bit set for each ICMP type to be filtered out.
    ///
    /// C value type: `struct icmp_filter`
    ///
    /// Rust value type: `IcmpFilter`
    #[non_exhaustive]
    Filter = bindings::ICMPV6_FILTER as isize,
}

/// TCP socket options.
///
/// Many [IpOptions] are also valid for TCP sockets.
///
/// See `man 7 tcp` for more information.
pub enum TcpOptions {
    /// Set or get the congestion control algorithm to be used.
    ///
    /// C value type: `char *`
    ///
    /// Rust value type: `&str` (?)
    Congestion = bindings::TCP_CONGESTION as isize,

    /// If true, don't send partial frames.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    Cork = bindings::TCP_CORK as isize,

    /// Allow a listener to be awakened only when data arrives.
    /// The value is the time to wait for data in milliseconds.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    DeferAccept = bindings::TCP_DEFER_ACCEPT as isize,

    /// Collect information about this socket.
    ///
    /// C value type: `struct tcp_info`
    ///
    /// Rust value type: unimplemented
    #[non_exhaustive]
    Info = bindings::TCP_INFO as isize,

    /// Set or get maximum number of keepalive probes to send.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    KeepCount = bindings::TCP_KEEPCNT as isize,

    /// Set or get the time in seconds to idle before sending keepalive probes.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    KeepIdle = bindings::TCP_KEEPIDLE as isize,

    /// Set or get the time in seconds between keepalive probes.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    KeepInterval = bindings::TCP_KEEPINTVL as isize,

    /// Set or get the lifetime or orphaned FIN_WAIT2 sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    Linger2 = bindings::TCP_LINGER2 as isize,

    /// Set or get the maximum segment size for outgoing TCP packets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `i32`
    MaxSeg = bindings::TCP_MAXSEG as isize,

    /// If true, Nagle algorithm is disabled, i.e. segments are send as soon as possible.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    NoDelay = bindings::TCP_NODELAY as isize,

    /// Set or get whether QuickAck mode is on.
    /// If true, ACKs are sent immediately, rather than delayed.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool`
    QuickAck = bindings::TCP_QUICKACK as isize,

    /// Set or get the number of SYN retransmits before the connection is dropped.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u8` (0 to 255)
    SynCount = bindings::TCP_SYNCNT as isize,

    /// Set or get how long sent packets can remain unacknowledged before timing out.
    /// The value is in milliseconds; 0 means to use the system default.
    ///
    /// C value type: `unsigned int`
    ///
    /// Rust value type: `u32`
    UserTimeout = bindings::TCP_USER_TIMEOUT as isize,

    /// Set or get the maximum window size for TCP sockets.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    WindowClamp = bindings::TCP_WINDOW_CLAMP as isize,

    /// Enable Fast Open on the listener socket (RFC 7413).
    /// The value is the maximum length of pending SYNs.
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `u32`
    FastOpen = bindings::TCP_FASTOPEN as isize,

    /// Enable Fast Open on the client socket (RFC 7413).
    ///
    /// C value type: `int`
    ///
    /// Rust value type: `bool` (?)
    FastOpenConnect = bindings::TCP_FASTOPEN_CONNECT as isize,
}

/// Socket options wrapper to enforce correct usage.
///
/// The Rust-wrapped functions to set and get socket options accept only this type,
/// which is then used to retrieve the level and the actual option value.
/// This way, it is impossible to set an option with the wrong level.
pub enum Options {
    /// IP socket options.
    IpOptions(IpOptions),
    /// Socket options.
    SocketOptions(SocketOptions),
    /// IPv6 socket options.
    Ipv6Options(Ipv6Options),
    /// Raw socket options.
    RawOptions(RawOptions),
    /// TCP socket options.
    TcpOptions(TcpOptions),
}

impl Options {
    /// Get the value of the option, transforming the enum into the correct int value.
    ///
    /// # Example
    /// ```
    /// use kernel::bindings;
    /// use kernel::net::socket::opts::{Options, IpOptions};
    /// let opt = Options::IpOptions(IpOptions::AddMembership);
    /// assert_eq!(opt.to_value(), IpOptions::AddMembership as isize);
    /// assert_eq!(opt.to_value(), bindings::IP_ADD_MEMBERSHIP as isize);
    /// ```
    pub fn to_value(self) -> isize {
        match self {
            Options::IpOptions(opt) => opt as isize,
            Options::SocketOptions(opt) => opt as isize,
            Options::Ipv6Options(opt) => opt as isize,
            Options::RawOptions(opt) => opt as isize,
            Options::TcpOptions(opt) => opt as isize,
        }
    }

    /// Get the level of the option.
    /// This is used to determine what level to pass to get and set functions.
    ///
    /// # Example
    /// ```
    /// use kernel::net::socket::opts::{Options, OptionsLevel, IpOptions};
    /// let opt = Options::IpOptions(IpOptions::AddMembership);
    /// assert_eq!(opt.as_level(), OptionsLevel::Ip);
    /// ```
    pub fn as_level(&self) -> OptionsLevel {
        match self {
            Options::IpOptions(_) => OptionsLevel::Ip,
            Options::SocketOptions(_) => OptionsLevel::Socket,
            Options::Ipv6Options(_) => OptionsLevel::Ipv6,
            Options::RawOptions(_) => OptionsLevel::Raw,
            Options::TcpOptions(_) => OptionsLevel::Tcp,
        }
    }
}

/// Linger structure to set and get the [SocketOptions::Linger] option.
/// This is a wrapper around the C struct `linger`.
#[repr(transparent)]
pub struct Linger(bindings::linger);

impl Linger {
    /// Create a "on" Linger object with the given linger time.
    /// This is equivalent to `linger { l_onoff: 1, l_linger: linger_time }`.
    /// The linger time is in seconds.
    ///
    /// # Example
    /// ```
    /// use kernel::net::socket::opts::Linger;
    /// let linger = Linger::on(10);
    /// assert!(linger.is_on());
    /// assert_eq!(linger.linger_time(), 10);
    pub fn on(linger: i32) -> Self {
        Linger(bindings::linger {
            l_onoff: 1 as _,
            l_linger: linger as _,
        })
    }

    /// Create an "off" Linger object.
    /// This is equivalent to `linger { l_onoff: 0, l_linger: 0 }`.
    ///
    /// # Example
    /// ```
    /// use kernel::net::socket::opts::Linger;
    /// let linger = Linger::off();
    /// assert!(!linger.is_on());
    pub fn off() -> Self {
        Linger(bindings::linger {
            l_onoff: 0 as _,
            l_linger: 0 as _,
        })
    }

    /// Get whether the linger option is on.
    ///
    /// # Example
    /// ```
    /// use kernel::net::socket::opts::Linger;
    /// let linger = Linger::on(10);
    /// assert!(linger.is_on());
    /// ```
    ///
    /// ```
    /// use kernel::net::socket::opts::Linger;
    /// let linger = Linger::off();
    /// assert!(!linger.is_on());
    /// ```
    pub fn is_on(&self) -> bool {
        self.0.l_onoff != 0
    }

    /// Get the linger time in seconds.
    /// If the linger option is off, this will return 0.
    ///
    /// # Example
    /// ```
    /// use kernel::net::socket::opts::Linger;
    /// let linger = Linger::on(10);
    /// assert_eq!(linger.linger_time(), 10);
    /// ```
    pub fn linger_time(&self) -> i32 {
        self.0.l_linger as _
    }
}
