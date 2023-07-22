// SPDX-License-Identifier: GPL-2.0

//! Socket-related flags and utilities.

use crate::bindings;

/// Generic socket flag trait.
///
/// This trait is implemented by all socket flags.
pub trait Flag {
    /// Get the value of the flag.
    fn to_value(self) -> isize;
}

/// Socket send operation flags.
///
/// See <https://linux.die.net/man/2/sendmsg> for more.
pub enum SendFlag {
    /// Got a successful reply.
    ///
    /// Only valid for datagram and raw sockets.
    /// Only valid for IPv4 and IPv6.
    Confirm = bindings::MSG_CONFIRM as isize,

    /// Don't use a gateway to send out the packet.
    DontRoute = bindings::MSG_DONTROUTE as isize,

    /// Enables nonblocking operation.
    ///
    /// If the operation would block, return immediately with an error.
    DontWait = bindings::MSG_DONTWAIT as isize,

    /// Terminates a record.
    EOR = bindings::MSG_EOR as isize,

    /// More data will be sent.
    ///
    /// Only valid for TCP and UDP sockets.
    More = bindings::MSG_MORE as isize,

    /// Don't send SIGPIPE error if the socket is shut down.
    NoSignal = bindings::MSG_NOSIGNAL as isize,

    /// Send out-of-band data on supported sockets.
    OOB = bindings::MSG_OOB as isize,
}

impl Flag for SendFlag {
    fn to_value(self) -> isize {
        self as isize
    }
}

/// Socket receive operation flags.
///
/// See <https://linux.die.net/man/2/recvmsg> for more.
pub enum ReceiveFlag {
    /// Enables nonblocking operation.
    ///
    /// If the operation would block, return immediately with an error.
    DontWait = bindings::MSG_DONTWAIT as isize,

    /// Specifies that queued errors should be received from the socket error queue.
    ErrQueue = bindings::MSG_ERRQUEUE as isize,

    /// Enables out-of-band reception.
    OOB = bindings::MSG_OOB as isize,

    /// Peeks at an incoming message.
    ///
    /// The data is treated as unread and the next recv() or similar function shall still return this data.
    Peek = bindings::MSG_PEEK as isize,

    /// Returns the real length of the packet, even when it was longer than the passed buffer.
    ///
    /// Only valid for raw, datagram, netlink and UNIX datagram sockets.
    Trunc = bindings::MSG_TRUNC as isize,

    /// Waits for the full request to be satisfied.
    WaitAll = bindings::MSG_WAITALL as isize,
}
impl Flag for ReceiveFlag {
    fn to_value(self) -> isize {
        self as isize
    }
}

/// Compute the value of a set of flags by bitwise ORing them together.
///
/// This is useful when passing flags to the kernel.
///
/// # Example
/// ```
/// use kernel::net::socket::flags::{SendFlag, flags_value};
///
/// let flags = vec![SendFlag::Confirm, SendFlag::DontRoute];
/// let value = flags_value(flags);
/// assert_eq!(value, SendFlag::Confirm as isize | SendFlag::DontRoute as isize);
pub(crate) fn flags_value<T>(flags: T) -> isize
where
    T: IntoIterator,
    T::Item: Flag,
{
    let mut value: isize = 0;
    for flag in flags {
        value |= flag.to_value();
    }
    value
}
