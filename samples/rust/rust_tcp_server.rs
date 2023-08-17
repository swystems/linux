// SPDX-License-Identifier: GPL-2.0

//! Rust echo server sample.

use core::str::FromStr;
use kernel::prelude::*;
use kernel::net::tcp::TcpListener;
use kernel::net::addr::SocketAddr;
use kernel::flag_set;

module! {
    type: RustTcpServer,
    name: "rust_tcp_server",
    author: "Rust for Linux Contributors",
    license: "GPL",
}

struct RustTcpServer {}

impl kernel::Module for RustTcpServer {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        let listener = TcpListener::new(SocketAddr::from_str("0.0.0.0:8000")?)?;
        while let Ok(stream) = listener.accept() {
            let mut buf = [0; 1024];
            while let Ok(size) = stream.receive(&mut buf, flag_set!()) {
                if size == 0 {
                    break;
                }
                stream.send(&buf[..size], flag_set!())?;
            }
        }
        Ok(Self {})
    }
}
