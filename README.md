# Wis
# <img src="wis_logo.svg" width="128" height="128"> Wis
**Secure, protocol‑agnostic toolkit for building P2P mesh networks over unreliable and reliable transports.**



## Overview

Wisleess2 is a **pure Rust** library that implements all the logic required to build secure, flexible, and censorship‑resistant communication protocols. It does **not** handle physical data transmission (sockets, Bluetooth, etc.) – you provide the byte transport, and Wisleess2 takes care of the rest.

The crate is:
- **Cross‑platform** – no platform‑specific code, no external dependencies.
- **Highly configurable** – plug your own crypto, key exchange, nonce generation, CRC, and traffic obfuscation.
- **Memory‑safe** – `#![forbid(unsafe_code)]` and strict Clippy lints (no indexing, no unwrapping).
- **Extensively tested** – test code is more than twice the size of production code.

## Key features

- **Packet framing & fragmentation** – split byte streams into packets and reassemble them, even when the underlying channel reorders, duplicates, or loses data.
- **Pluggable cryptography** – support for any stream cipher + authentication tag (AEAD‑like) via simple traits (`EncWis`, `Noncer`, `Cfcser`, `Randomer`, `Thrasher`).
- **Flexible key exchange** – implement arbitrary handshake protocols with the `HandMaker` trait.
- **Intelligent queues**:
  - `WSUdpLike` – reorder out‑of‑order packets and detect gaps.
  - `WSWaitQueue` – track unconfirmed packets with configurable timeouts and resend logic.
  - `WSRecvQueueCtrs` – batch acknowledgements (fback) to minimise overhead.
  - `WSTcpLike` – reconstruct packet boundaries from a continuous byte stream (TCP‑style).
- **Traffic obfuscation**:
  - Insert randomised “trash” (user) fields at fixed positions.
  - Send fake data and fake fback packets with configurable probabilities.
  - Randomise packet lengths to resist DPI.
- **Header integrity** – optional CRC32‑like checksums (pluggable algorithm) for unreliable channels.
- **Time‑To‑Live (TTL)** – multi‑hop packet lifetime control with custom hop cost (positive or negative).
- **Connection multiplexing** – separate sessions via `IdConnect` field.
- **Minimal overhead** – as low as **18 bytes** (16‑byte authentication tag + 1‑byte counter + 1‑byte control flags). The exact size depends on your topology configuration.
- **No heap allocations in hot paths** – many operations use stack‑allocated buffers.

## Architecture overview

The library is built around several core concepts:

- **`PackTopology`** – describes the layout of a packet header: positions and lengths of all fields (counter, IDs, length, CRC, nonce, TTL, user fields, etc.).  
- **`GroupTopology`** – a set of interchangeable topologies selected by a “tricky byte”, allowing dynamic packet shapes.
- **`WsConnectParam`** – static connection parameters (MTU, timeouts, queue sizes, fake traffic probabilities, etc.).
- **`WsConnection`** – the main connection state machine (counters, queues, crypto, handshake, file splitting).
- **`WSFileSplitter`** – splits large files into chunks and reassembles them from arbitrary slices.
- **Traits** – all algorithms (encryption, nonce generation, CRC, random, user field generation, handshake) are injected via traits, making the library crypto‑agnostic.

## Requirements

- Rust **1.70** or later (edition 2021)
- No `std::net`, no async runtime, no external crates – pure `core` + `alloc`.

## Status

The library is **~80% complete**. Core functionality is implemented and heavily tested. Remaining work focuses on:
- API polishing
- Final integration of the handshake machinery
- Additional stress tests and documentation examples