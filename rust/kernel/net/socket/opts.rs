use kernel::bindings;

pub enum Level {
    Ip = bindings::IPPROTO_IP as isize,
    Socket = bindings::SOL_SOCKET as isize,
    Ipv6 = bindings::IPPROTO_IPV6 as isize,
    Icmpv6 = bindings::IPPROTO_ICMPV6 as isize,
    Tcp = bindings::IPPROTO_TCP as isize,
}

pub enum IpOptions {
    HeaderInclude = bindings::IP_HDRINCL as isize,
    Options = bindings::IP_OPTIONS as isize,
    RecvOpts = bindings::IP_RECVOPTS as isize,
    Tos = bindings::IP_TOS as isize,
    Ttl = bindings::IP_TTL as isize,
    MulticastInterface = bindings::IP_MULTICAST_IF as isize,
    MulticastTtl = bindings::IP_MULTICAST_TTL as isize,
    MulticastLoop = bindings::IP_MULTICAST_LOOP as isize,
    AddMembership = bindings::IP_ADD_MEMBERSHIP as isize,
    DropMembership = bindings::IP_DROP_MEMBERSHIP as isize,
    AddSourceMembership = bindings::IP_ADD_SOURCE_MEMBERSHIP as isize,
    DropSourceMembership = bindings::IP_DROP_SOURCE_MEMBERSHIP as isize,
    BlockSource = bindings::IP_BLOCK_SOURCE as isize,
    UnblockSource = bindings::IP_UNBLOCK_SOURCE as isize,
}

pub enum SocketOptions {
    AcceptConn = bindings::SO_ACCEPTCONN as isize,
    BindToDevice = bindings::SO_BINDTODEVICE as isize,
    Broadcast = bindings::SO_BROADCAST as isize,
    BsdComp = bindings::SO_BSDCOMPAT as isize,
    Debug = bindings::SO_DEBUG as isize,
    Domain = bindings::SO_DOMAIN as isize,
    Error = bindings::SO_ERROR as isize,
    DontRoute = bindings::SO_DONTROUTE as isize,
    IncomingCpu = bindings::SO_INCOMING_CPU as isize,
    KeepAlive = bindings::SO_KEEPALIVE as isize,
    Linger = bindings::SO_LINGER as isize,
    LockFilter = bindings::SO_LOCK_FILTER as isize,
    Mark = bindings::SO_MARK as isize,
    OobInline = bindings::SO_OOBINLINE as isize,
    PassCred = bindings::SO_PASSCRED as isize,
    PassSec = bindings::SO_PASSSEC as isize,
    PeekOff = bindings::SO_PEEK_OFF as isize,
    PeerCredentials = bindings::SO_PEERCRED as isize,
    Priority = bindings::SO_PRIORITY as isize,
    Protocol = bindings::SO_PROTOCOL as isize,
    RcvBuf = bindings::SO_RCVBUF as isize,
    ReuseAddr = bindings::SO_REUSEADDR as isize,
    ReusePort = bindings::SO_REUSEPORT as isize,
    SndBuf = bindings::SO_SNDBUF as isize,
    Type = bindings::SO_TYPE as isize,
    BusyPoll = bindings::SO_BUSY_POLL as isize,
}

pub enum Ipv6Options {
    Checksum = bindings::IPV6_CHECKSUM as isize,
    DontFragment = bindings::IPV6_DONTFRAG as isize,
    NextHop = bindings::IPV6_NEXTHOP as isize,
    PathMtu = bindings::IPV6_PATHMTU as isize,
    RecvHopLimit = bindings::IPV6_RECVHOPLIMIT as isize,
    RecvHopOpts = bindings::IPV6_RECVHOPOPTS as isize,
    RecvPacketInfo = bindings::IPV6_RECVPKTINFO as isize,
    RecvPathMtu = bindings::IPV6_RECVPATHMTU as isize,
    RecvTclass = bindings::IPV6_RECVTCLASS as isize,
    UnicastHopLimit = bindings::IPV6_UNICAST_HOPS as isize,
    V6Only = bindings::IPV6_V6ONLY as isize,
    MulticastInterface = bindings::IPV6_MULTICAST_IF as isize,
    MulticastHopLimit = bindings::IPV6_MULTICAST_HOPS as isize,
    MulticastLoop = bindings::IPV6_MULTICAST_LOOP as isize,
    JoinGroup = bindings::MCAST_JOIN_GROUP as isize,
    LeaveGroup = bindings::MCAST_LEAVE_GROUP as isize,
    BlockSource = bindings::MCAST_BLOCK_SOURCE as isize,
    UnblockSource = bindings::MCAST_UNBLOCK_SOURCE as isize,
    JoinSourceGroup = bindings::MCAST_JOIN_SOURCE_GROUP as isize,
    LeaveSourceGroup = bindings::MCAST_LEAVE_SOURCE_GROUP as isize,
}

pub enum Icmpv6Options {
    Filter = bindings::ICMPV6_FILTER as isize,
}

pub enum TcpOptions {
    MaxSeg = bindings::TCP_MAXSEG as isize,
    NoDelay = bindings::TCP_NODELAY as isize,
}

pub enum Options {
    IpOptions(IpOptions),
    SocketOptions(SocketOptions),
    Ipv6Options(Ipv6Options),
    Icmpv6Options(Icmpv6Options),
    TcpOptions(TcpOptions),
}

impl Options {
    pub fn to_value(self) -> isize {
        match self {
            Options::IpOptions(opt) => opt as isize,
            Options::SocketOptions(opt) => opt as isize,
            Options::Ipv6Options(opt) => opt as isize,
            Options::Icmpv6Options(opt) => opt as isize,
            Options::TcpOptions(opt) => opt as isize,
        }
    }
}

#[repr(transparent)]
pub struct Linger(bindings::linger);

impl Linger {
    pub fn on(linger: i32) -> Self {
        Linger(bindings::linger {
            l_onoff: 1 as _,
            l_linger: linger as _,
        })
    }
    pub fn off() -> Self {
        Linger(bindings::linger {
            l_onoff: 0 as _,
            l_linger: 0 as _,
        })
    }
}
