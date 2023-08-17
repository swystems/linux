// SPDX-License-Identifier: GPL-2.0

//! Rust minimal sample.

use core::str::FromStr;
use kernel::prelude::*;
use kernel::net::socket::*;
use kernel::net::ip::IpProtocol;
use kernel::net::addr::{SocketAddr};
use kernel::net::AddressFamily;
use kernel::flag_set;

module! {
    type: RustSocket,
    name: "rust_socket",
    author: "Rust for Linux Contributors",
    description: "Rust sockets support sample",
    license: "GPL",
}

struct RustSocket {}

impl kernel::Module for RustSocket {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let sock = Socket::new(AddressFamily::Inet, SockType::Datagram, IpProtocol::Udp)?;
        let addr = "0.0.0.0:8000";
        sock.bind(SocketAddr::from_str(addr)?)?;

        sock.set_option::<opts::sock::ReuseAddr>(true)?;

        assert_eq!(sock.sockname()?, SocketAddr::from_str(addr)?);

        let mut buf = [0; 1024];
        while let Ok((bytes, msghdr)) = sock.receive_msg(&mut buf, flag_set!()) {
            if bytes == 0 {
                break;
            }
            pr_info!("Received {} bytes from {}", bytes, msghdr.address().unwrap());
            if msghdr.flags().contains(flags::MessageFlag::Trunc) {
                pr_info!("The message was truncated");
            }
        }
        Ok(Self{})
    }
}