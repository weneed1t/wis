//! #Wis – Secure P2P Mesh Networking Toolkit
//!
//! A pure Rust library for building **protocol‑agnostic**, **highly configurable** secure
//! communication in unreliable and reliable network environments (TCP, UDP, BLE, or any
//! byte‑stream / datagram transport).
//!
//! ## Core philosophy
//! - **You control the transport** – this crate does **not** send or receive data over
//!   physical devices. It implements only the protocol logic, making it fully
//!   cross‑platform and portable.
//! - **No external dependencies** – everything is written in safe, platform‑independent
//!   Rust. No `std::net`, no async runtime, no FFI.
//! - **Uncompromising safety** – the codebase contains >2× more tests than production
//!   code. Indexing and unwrapping are strictly forbidden (Clippy lints deny them).
//!
//! ## What it does
//! * **Packet framing & fragmentation** – split arbitrary byte streams into packets and
//!   reassemble them, even across unreliable channels.
//! * **Pluggable cryptography** – any stream cipher + authentication tag (AEAD‑like) can
//!   be integrated via simple traits (`EncWis`, `Noncer`, `Cfcser`, …).
//! * **Flexible key exchange** – support for arbitrary handshake protocols (`HandMaker`).
//! * **Intelligent queues** – handle out‑of‑order, duplicate, lost, or concatenated
//!   packets (UDP / TCP‑like behaviours) with minimal overhead.
//! * **Traffic obfuscation** – insert randomised “trash” fields, fake packets, and
//!   variable lengths to resist DPI and traffic analysis.
//! * **Time‑To‑Live (TTL)** – multi‑hop packet lifetime control.
//! * **Minimal wire overhead** – as low as 18 bytes (16‑byte authentication tag, 1‑byte
//!   counter, 1‑byte control flags).
//!
//! ## What it does **not** do
//! - Physical transmission (send/receive over sockets, Bluetooth, etc.).
//! - Provide a default crypto backend – you must supply your own (or use the provided
//!   test stubs).
//! - Handle threading or async I/O – all structures are synchronous and agnostic to
//!   concurrency models.
//!
//! ## Example use cases
//! - Censorship‑resistant mesh networks
//! - Low‑latency P2P communication over unreliable links (e.g., LoRa, Wi‑Fi mesh)
//! - Protocol obfuscation for embedded devices
//! - Educational / research prototypes for secure transport protocols
//!
//! ## Status
//! ~80% complete – core logic is implemented and heavily tested; remaining work
//! focuses on API polishing and final integration.
//!
//! For detailed API documentation, start with [`WsConnection`] and [`PackTopology`].

#![forbid(unsafe_code)]
//-----#![deny(clippy::all)]
#![deny(clippy::unwrap_used)]
//#![deny(clippy::expect_used)]
#![allow(clippy::empty_docs)]
#![allow(clippy::type_complexity)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::empty_line_after_doc_comments)]

pub mod t0pology;
pub mod t1dumps_struct;
pub mod t1fields; //(crypt,ttl,len,chc,ctr,head,nonce,id,idc)utils
//pub mod __t2proc_fields;
pub mod wacross;

mod t1queue_tcpudp;
pub mod t3poc_files;
pub mod t4algo_param;
pub mod t5_2_connect_data;
pub mod t5_connect_data;
pub mod w1utils;
pub mod wt1types; //utils //topology

pub mod t0_grouper;
pub mod t0_parsel;

#[cfg(feature = "wisdel")]
pub mod wisdel;

pub use crate::t1queue_tcpudp::recv_queue::{
    WSRecvQueueCtrs, WSTcpLike as TcpPackageSplitter, WSUdpLike,
    WSWaitQueue as UnconfirmedQueuePackets,
};

pub mod murmur3;
pub mod private_core {
    pub use crate::{t0pology as PackageFields, t1fields as PacketsProcessingFields};
}
/*
delete this in prod dapgp

cargo test &&

rustup component add clippy
cargo clippy --fix
cargo fix --allow-dirty
cargo clippy --fix --allow-dirty --broken-code

git add . &&
git commit -S -m "dev" &&
git push origin main

cargo fix --allow-dirty
cargo clippy --fix --all --allow-dirty
git rm -r --cached t.txt


cargo +nightly fmt
rustup toolchain install nightly
rustup run nightly cargo fmt


cargo clippy --fix  --allow-dirty &&
cargo fix --allow-dirty &&
cargo clippy --fix --allow-dirty --broken-code &&
cargo clippy --fix --all --allow-dirty &&
rustup run nightly cargo fmt &&
cargo fmt


if a have crush
rustup component add rust-analyzer

?

[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0%2FMIT-blue.svg)](LICENSE)


*/
