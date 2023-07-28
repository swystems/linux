// SPDX-License-Identifier: GPL-2.0

//! Socket buffer
//!
//! The socket buffer is the fundamental data structure used throughout the
//! networking code. It is used to store packets as they are moved between the
//! various protocols and interfaces. It is also used to store packets queued
//! for transmission, packets received from the network, and various other
//! information the kernel needs to process packets.
//!
//! The Rust port of the socket buffer is a wrapper around the C implementation, which
//! aims to provide a safe(r) memory management.
//!
//! C header: [`include/linux/skbuff.h`](../../../../include/linux/skbuff.h)
//!
//! Reference: <https://www.kernel.org/doc/html/latest/networking/skbuff.html>

use crate::bindings;

#[repr(transparent)]
pub struct SkBuff(pub(crate) *mut bindings::sk_buff);

impl SkBuff {}
