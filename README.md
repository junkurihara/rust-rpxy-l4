# rpxy-l4: A reverse proxy for the layer-4 (TCP+UDP) with protocol multiplexer, written in Rust

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/rust-rpxy-l4/actions/workflows/ci.yml/badge.svg)
![Container Build](https://github.com/junkurihara/rust-rpxy-l4/actions/workflows/docker.yml/badge.svg)
![Release](https://github.com/junkurihara/rust-rpxy-l4/actions/workflows/release.yml/badge.svg)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jqtype/rpxy-l4)](https://hub.docker.com/r/jqtype/rpxy-l4)

> **WIP project, early stage of development.** This project just started from the owner's personal interest and research activity. Not recommended for production use yet.

## Introduction

`rpxy-l4` is an L4 reverse proxy supporting both TCP and UDP protocols, which is designed on the same philosophy as [`rpxy`](https://github.com/junkurihara/rust-rpxy) (HTTP reverse proxy). It is written in Rust and aims to provide a high-performance and easy-to-use reverse proxy for layer-4 protocols.

## Features

- **Basic L4 reverse proxy feature**: `rpxy-l4` can forward TCP and UDP packets to the backend server.
- **Protocol multiplexing**: `rpxy-l4` can multiplex multiple protocols over TCP/UDP on the same port, which means `rpxy-l4` routes specific protocols to their corresponding backend servers. Currently, it supports the following protocols:
  - TCP: HTTP (cleartext), TLS, SSH
  - UDP: QUIC (IETF [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)), WireGuard
- **Load balancing**: `rpxy-l4` can distribute incoming connections to multiple backend servers based on the several simple load balancing algorithms.
- **Protocol sanitization**: `rpxy-l4` can sanitize the incoming packets to prevent protocol over TCP/UDP mismatching between the client and the backend server by leveraging the protocol multiplexer feature. (Simply drops packets that do not match the expected protocol by disallowing the default route.)
- **TLS/QUIC forwarder**: `rpxy-l4` can forward TLS/IETF QUIC streams to appropriate backend servers based on the ServerName Indication (SNI) and Application Layer Protocol Negotiation (ALPN) values.
<!-- - [TODO:] **TLS/QUIC Encrypted Client Hello (ECH) proxy**: `rpxy-l4` works as a proxy to serve TLS/QUIC streams with IETF-Draft Encrypted Client Hello. In other words, `rpxy-l4` hosts ECH private keys and decrypts the ECH-encrypted Client Hello to route the stream to the appropriate backend server. -->

## Installation

You can build an executable binary yourself by checking out this Git repository.

```bash
# Cloning the git repository
% git clone https://github.com/junkurihara/rust-rpxy-l4
% cd rust-rpxy-l4

# Build
% cargo build --release
```

Then you have an executive binary `rust-rpxy/target/release/rpxy-l4`.

## Usage

`rpxy-l4` always refers to a configuration file in TOML format, e.g., `config.toml`. You can find an example of the configuration file, `config.example.toml`, in this repository.

You can run `rpxy-l4` with a configuration file like

```bash
% ./target/release/rpxy-l4 --config config.toml
```

`rpxy-l4` always tracks the change of `config.toml` in the real-time manner and apply the change immediately without restarting the process.

## Basic configuration

> [!NOTE]
> A configuration example can be found at [./config.example.toml](./config.example.toml). Another toml file, [./config.spec.toml](./config.spec.toml), is a specification of the configuration file including **unimplemented features**.

### 1. First step: The fundamental TCP/UDP reverse proxy scenario

The following is an example of the basic configuration for the TCP/UDP reverse proxy scenario.

```toml
# Listen port, must be set
listen_port = 8448

# Default targets for TCP connections. [default: empty]
# Format: ["<ip>:<port>", "<ip>:<port>", ...]
tcp_target = ["192.168.0.2:8000"]

# Default targets for UDP connections. [default: empty]
# Format: ["<ip>:<port>", "<ip>:<port>", ...]
udp_target = ["192.168.0.3:4000"]
```

The above configuration works as the following manner.

- Forwards TCP packets received on port `8448` to the backend server `192.168.0.2:8000`;
- Forwards UDP packets received on port `8448` to the backend server `192.168.0.3:4000`.

> [!IMPORTANT]
> For the UDP reverse proxy, `rpxy-l4` manages the pseudo connection for each client based on its socket address (IP address + port number) to save the memory usage and preserve the connection state for protocol multiplexing. The pseudo connection is automatically removed after the idle lifetime (default: 30 seconds) since the last packet received from the client. We recommend setting the `udp_idle_lifetime` value in the configuration file to adjust the idle lifetime according to your use case.
>
> ```toml
> # Udp connection idle lifetime in seconds [default: 30]
> udp_idle_lifetime = 30
> ```

### 2. Load balancing

`rpxy-l4` allows you to distribute incoming TCP/UDP packets to multiple backend servers based on the several simple load balancing algorithms. For the multiple TCP/UDP targets, you can set the load balancing algorithm as follows.

```toml
# Default targets for TCP connections. [default: empty]
tcp_target = ["192.168.0.2:8000", "192.168.0.3:8000"]

# Load balancing method for default targets [default: none]
tcp_load_balance = "source_ip" # source_ip, source_socket, random, or none

# Default targets for UDP connections. [default: empty]
udp_target = ["192.168.0.2:4000", "192.168.0.3:4000"]

# (Optional) Load balancing method for default targets [default: none]
udp_load_balance = "source_socket"
```

Currently, `rpxy-l4` supports the following load balancing algorithms:

- `source_ip`: based on source IP hash
- `source_socket`: based on source IP and port hash
- `random`: random selection
- `none`: always use the first target [default]

### 3. Second step: Protocol multiplexing

TBD!

#### 3.1. Example of TLS/QUIC multiplexer with SNI/ALPN

#### 3.2. Example of WireGuard multiplexer

#### 3.3. Passing through only the expected protocols (protocol sanitization)

TBD!

## Containerization

The container, docker, image is available at Docker Hub and Github Container Registry.

- Docker Hub: [jqtype/rpxy-l4](https://hub.docker.com/r/jqtype/rpxy-l4)
- Github Container Registry: [ghcr.io/junkurihara/rust-rpxy-l4](https://ghcr.io/junkurihara/rust-rpxy-l4)

The detailed configuration of the container can be found at [./docker](./docker) directory.

## Caveats

TBD!

## Credits

`rpxy-4` cannot be built without the following projects and inspirations:

- [`sslh`](https://github.com/yrutschle/sslh): `rpxy-l4` is strongly inspired by `sslh` for its protocol multiplexer feature.
- [`tokio`](https://github.com/tokio-rs/tokio): Great async runtime for Rust.

## License

`rpxy` is free, open-source software licensed under MIT License.

You can open issues for bugs you've found or features you think are missing. You can also submit pull requests to this repository.

Contributors are more than welcome!
