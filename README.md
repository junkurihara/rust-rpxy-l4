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
# Listen port, must be set
listen_port = 8448

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

Here are examples/use-cases of the protocol multiplexing scenario over TCP/UDP. For protocol multiplexing, you need to set a `[protocol.<service_name>]` filed in the configuration file as follows.

```toml
listen_port = 8448
...

# Set for each multiplexed service
[protocol."http_service"]
...
```

Currently, `rpxy-l4` supports the following protocols for multiplexing:

- TCP: HTTP (cleartext), TLS, SSH
- UDP: QUIC (IETF [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)), WireGuard

#### 3.1. Example of TLS/QUIC multiplexer with SNI/ALPN

`rpxy-l4` can detect and multiplex TLS/QUIC streams by probing the TLS ClientHello message and IETF QUIC Initial packet (containing ClientHello). The following example demonstrates the scenario that any TLS/QUIC is forwarded to the appropriate backend that are different from the default targets.

```toml
listen_port = 8448
tcp_target = ["192.168.0.2:8000"]
udp_target = ["192.168.0.3:4000"]

# TLS
[protocol."tls_service"]
# Name of protocol tls|ssh|http|wireguard|quic
protocol = "tls"

# Target for connections detected as TLS.
target = ["192.168.0.5:443"]

# (Optional) Load balancing method specific to this connections [default: none]
load_balance = "source_ip"

#####################
# IETF QUIC
[protocol."quic_service"]
# Name of protocol tls|ssh|http|wireguard|quic
protocol = "quic"

# Target for connections detected as QUIC.
target = ["192.168.0.6:443"]

# Load balancing method for QUIC connections [default: none]
load_balance = "source_socket"

# Idle lifetime for QUIC connections in seconds [default: 30]
idle_lifetime = 30
```

> [!NOTE]
> Since IETF-QUIC is a UDP-based protocol, the `idle_lifetime` field is available for `protocol="quic"` to adjust the idle lifetime of the pseudo connection only valid for QUIC streams.

Additionally, you can set the `tls_alpn` and `tls_sni` fields for the case where `protocol="tls"` or `protocol="quic"`. These are additional filters for the TLS/QUIC multiplexer to route the stream to the appropriate backend server based on the Application Layer Protocol Negotiation (ALPN) and Server Name Indication (SNI) values. This means that only streams with the specified ALPN and SNI values are forwarded to the target.

```toml
[protocol."tls_service"]
protocol = "tls"
target = ["192.168.0.5:443"]
load_balance = "source_ip"

# (Optional) SNI-based routing for TLS/QUIC connections.
# If specified, only TLS/QUIC connections matched to the given SNI(s) are forwarded to the target.
# Format: ["<server_name>", "<server_name>", ...]
server_names = ["example.com", "example.org"]

# (Optional) ALPN-based routing for TLS/QUIC connections.
# If specified, only TLS/QUIC connections matched to the given ALPN(s) are forwarded to the target.
# Format: ["<alpn>", "<alpn>", ...]
alpns = ["h2", "http/1.1"]

```

> [!NOTE]
> If both `server_names` and `alpns` are specified, the proxy forwards connections that match simultaneously both of them.

#### 3.2. Example of WireGuard multiplexer

`rpxy-l4` can detect and multiplex WireGuard packets by probing the initial handshake packet. The following example demonstrates the scenario that any WireGuard packets are forwarded to the appropriate backend that are different from the default targets as well.

```toml
[protocols."wireguard_service"]
protocol = "wireguard"
target = ["192.168.0.10:51820"]
load_balance = "none"
# longer than the keepalive interval of the wireguard tunnel
idle_lifetime = 30
```

> [!NOTE]
> As well as QUIC, WireGuard is a UDP-based protocol. The `idle_lifetime` field is available for `protocol="wireguard"`. You should adjust the value according to your WireGuard configuration, especially the keep-alive interval.

#### 3.3. Passing through only the expected protocols (protocol sanitization)

This is somewhat a security feature to prevent protocol over TCP/UDP mismatching between the client and the backend server. *By ignoring the default routes*, i.e., removing `tcp_target` and `udp_target` on the top level, and set only specific protocol multiplexers, `rpxy-l4` simply handles packets matching the expected protocols and drops the others.

## Containerization

The container, docker, image is available at Docker Hub and Github Container Registry.

- Docker Hub: [jqtype/rpxy-l4](https://hub.docker.com/r/jqtype/rpxy-l4)
- Github Container Registry: [ghcr.io/junkurihara/rust-rpxy-l4](https://ghcr.io/junkurihara/rust-rpxy-l4)

The detailed configuration of the container can be found at [./docker](./docker) directory.

## Caveats

### `UDP` pseudo connection management

As mentioned earlier, `rpxy-l4` manages pseudo connections for UDP packets from each clients based on the socket address. Also, `rpxy-l4` identifies specific protocols by probing their initial/handshake packets. These means that if the idle lifetime of pseudo connections is too short and the client sends packets in a long interval, the pseudo connection would be removed even during the communication. Then, the subsequent packets from the client, i.e., NOT the initial/handshake packets, are *routed not to the protocol-specific target but to the default target (or dropped if there is no default target)*. To avoid this, you should set the `idle_lifetime` value of UDP-based protocol multiplexer to be longer than the interval of the client's packet sending.

### Others

TBD!

## Credits

`rpxy-4` cannot be built without the following projects and inspirations:

- [`sslh`](https://github.com/yrutschle/sslh): `rpxy-l4` is strongly inspired by `sslh` for its protocol multiplexer feature.
- [`tokio`](https://github.com/tokio-rs/tokio): Great async runtime for Rust.
- [`RustCrypto`](https://github.com/RustCrypto): Pure Rust implementations of various cryptographic algorithms, used in `rpxy-l4` for TLS/QUIC cryptographic operations.

## License

`rpxy-l4` is free, open-source software licensed under MIT License.

You can open issues for bugs you've found or features you think are missing. You can also submit pull requests to this repository.

Contributors are more than welcome!
