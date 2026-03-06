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
  - TCP: HTTP (cleartext), TLS, SSH, Socks5
  - UDP: QUIC (IETF QUIC[^quic]), WireGuard
- **Load balancing**: `rpxy-l4` can distribute incoming connections to multiple backend servers based on the several simple load balancing algorithms.
- **Protocol sanitization**: `rpxy-l4` can sanitize the incoming packets to prevent protocol over TCP/UDP mismatching between the client and the backend server by leveraging the protocol multiplexer feature. (Simply drops packets that do not match the expected protocol by disallowing the default route.)
- **TLS/QUIC forwarder**: `rpxy-l4` can forward TLS/IETF QUIC streams to appropriate backend servers based on the ServerName Indication (SNI) and Application Layer Protocol Negotiation (ALPN) values.
- **HAProxy PROXY protocol support**: `rpxy-l4` supports outbound PROXY protocol (prepend header to backend connections, global/per-protocol) and inbound PROXY protocol (parse header from trusted upstream proxies) for TCP. (Requires the `proxy-protocol` Cargo feature, enabled by default.)
- **[Experimental] TLS Encrypted Client Hello (ECH) proxy**: `rpxy-l4` works as a proxy[^ech_proxy] to serve TLS/QUIC streams with IETF-Draft Encrypted Client Hello. In other words, `rpxy-l4` hosts ECH private keys and decrypts the ECH-encrypted Client Hello to route the stream to the appropriate backend server.

[^quic]: Not Google QUIC. Both QUIC v1 ([RFC9000](https://datatracker.ietf.org/doc/html/rfc9000), [RFC9001](https://datatracker.ietf.org/doc/html/rfc9001)) and QUIC v2 ([RFC9369](https://datatracker.ietf.org/doc/html/rfc9369)) are supported.

[^ech_proxy]: Client facing server in the context of [ECH Split Mode](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-3)

## Installation

### Building from Source

You can build an executable binary yourself by checking out this Git repository.

```bash
# Cloning the git repository
% git clone https://github.com/junkurihara/rust-rpxy-l4
% cd rust-rpxy-l4

# Build
% cargo build --release
```

Then you have an executive binary `rust-rpxy-l4/target/release/rpxy-l4`.

To build without the PROXY protocol feature:

```bash
% cargo build --release --no-default-features
```

### Package Installation for Linux (RPM/DEB)

You can find the Jenkins CI/CD build scripts for `rpxy-l4` in the [./.build](./.build) directory.

Prebuilt packages for Linux RPM and DEB are available at [https://rpxy.gamerboy59.dev](https://rpxy.gamerboy59.dev), provided by [@Gamerboy59](https://github.com/Gamerboy59).

## Usage

`rpxy-l4` always refers to a configuration file in TOML format, e.g., `config.toml`. You can find an example of the configuration file, `config.example.toml`, in this repository.

You can run `rpxy-l4` with a configuration file like

```bash
% ./target/release/rpxy-l4 --config config.toml
```

`rpxy-l4` always tracks the change of `config.toml` in the real-time manner and apply the change immediately without restarting the process.

Full command line options are as follows:

```bash
% ./target/release/rpxy-l4 --help
Usage: rpxy-l4 [OPTIONS] --config <FILE>

Options:
  -c, --config <FILE>      Configuration file path like ./config.toml
  -l, --log-dir <LOG_DIR>  Directory for log files. If not specified, logs are printed to stdout.
  -h, --help               Print help
  -V, --version            Print version
```

If you set `--log-dir=<log_dir>`, the log files are created in the specified directory. Otherwise, the log is printed to stdout.

- `${log_dir}/access.log` for access log
- `${log_dir}/rpxy-l4.log` for system and error log

## Basic configuration

> [!NOTE]
> A configuration example can be found at [./config.example.toml](./config.example.toml). Another toml file, [./config.spec.toml](./config.spec.toml), is a specification of the configuration file including **unimplemented features**.

### 1. First step: The fundamental TCP/UDP reverse proxy scenario

The following is an example of the basic configuration for the TCP/UDP reverse proxy scenario.

```toml
# Listen port, must be set
listen_port = 8448

# Default targets for TCP connections. [default: empty]
# Format: ["<ip|domain_name>:<port>", "<ip|domain_name>:<port>", ...]
tcp_target = ["192.168.0.2:8000"]

# Default targets for UDP connections. [default: empty]
# Format: ["<ip|domain_name>:<port>", "<ip|domain_name>:<port>", ...]
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

### 2. Second step: Load balancing

`rpxy-l4` allows you to distribute incoming TCP/UDP packets to multiple backend servers based on the several simple load balancing algorithms. For the multiple TCP/UDP targets, you can set the load balancing algorithm as follows.

```toml
# Listen port, must be set
listen_port = 8448

# Default targets for TCP connections. [default: empty]
# Format: ["<ip|domain_name>:<port>", "<ip|domain_name>:<port>", ...]
tcp_target = ["192.168.0.2:8000", "192.168.0.3:8000"]

# Load balancing method for default targets [default: none]
tcp_load_balance = "source_ip" # source_ip, source_socket, random, or none

# Default targets for UDP connections. [default: empty]
# Format: ["<ip|domain_name>:<port>", "<ip|domain_name>:<port>", ...]
udp_target = ["192.168.0.2:4000", "192.168.0.3:4000"]

# (Optional) Load balancing method for default targets [default: none]
udp_load_balance = "source_socket"
```

Currently, `rpxy-l4` supports the following load balancing algorithms:

- `source_ip`: based on source IP hash
- `source_socket`: based on source IP and port hash
- `random`: random selection
- `none`: always use the first target [default]

### 3. Third step: Protocol multiplexing

Here are examples/use-cases of the protocol multiplexing scenario over TCP/UDP. For protocol multiplexing, you need to set a `[protocol.<service_name>]` filed in the configuration file as follows.

```toml
listen_port = 8448
...

# Set for each multiplexed service
[protocol."http_service"]
...
```

Currently, `rpxy-l4` supports the following protocols for multiplexing:

- TCP: HTTP (cleartext), TLS, SSH, Socks5
- UDP: QUIC (IETF [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)), WireGuard

#### 3.1. Example of TLS/QUIC multiplexer with SNI/ALPN

`rpxy-l4` can detect and multiplex TLS/QUIC streams by probing the TLS ClientHello message and IETF QUIC Initial packet (containing ClientHello). The following example demonstrates the scenario that any TLS/QUIC is forwarded to the appropriate backend that are different from the default targets.

```toml
listen_port = 8448
tcp_target = ["192.168.0.2:8000"]
udp_target = ["192.168.0.3:4000"]

# TLS
[protocol."tls_service"]
# Name of protocol tls|ssh|socks5|http|wireguard|quic
protocol = "tls"

# Target for connections detected as TLS.
target = ["192.168.0.5:443"]

# (Optional) Load balancing method specific to this connections [default: none]
load_balance = "source_ip"

#####################
# IETF QUIC
[protocol."quic_service"]
# Name of protocol tls|ssh|socks5|http|wireguard|quic
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
[protocol."wireguard_service"]
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

### 4. PROXY protocol (preserving client IP)

`rpxy-l4` supports [HAProxy PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) (v1 and v2) for TCP connections. This enables client IP preservation when `rpxy-l4` sits in a proxy chain.

> [!NOTE]
> This feature requires the `proxy-protocol` Cargo feature, which is enabled by default. To build without it, use `cargo build --release --no-default-features`.

> [!IMPORTANT]
> The PROXY protocol is only supported for TCP connections, and UDP connections are not supported due to the stateless nature of UDP, meaning that the concept of a "connection" does not exist in the same way as TCP. Typically, for UDP-based protocols, the concept of `stream` is used the overlaid protocol, e.g., QUIC stream or WireGuard session, and it does not fit well with the connection-oriented design of the PROXY protocol.

> [!WARNING]
> Enabling inbound PROXY protocol may cause service disruption and security risks if not configured properly. Make sure to set `tcp_trusted_proxies` to only accept PROXY headers from trusted sources, and be aware that all incoming TCP connections are expected to start with a valid PROXY header when `tcp_recv_proxy_protocol` is enabled.

#### 4.1. Outbound: Sending PROXY header to backend servers

Prepend a PROXY protocol header to connections toward backend servers, so backends can see the original client IP.

**Global setting** — applies to all TCP backend connections:

```toml
listen_port = 8448
tcp_target = ["192.168.0.2:8000"]

# Prepend PROXY protocol v2 header to all TCP backend connections
tcp_send_proxy_protocol = "v2"  # "v1", "v2", or omit/"none" to disable
```

**Per-protocol override** — each protocol entry can override the global setting:

```toml
tcp_send_proxy_protocol = "v2"  # global default

[protocols."tls_1"]
protocol = "tls"
target = ["192.168.0.5:443"]
send_proxy_protocol = "v1"  # override: use v1 for this protocol

[protocols."http_1"]
protocol = "http"
target = ["192.168.0.6:80"]
send_proxy_protocol = "none"  # override: disable for this protocol
```

#### 4.2. Inbound: Parsing PROXY header from upstream proxies

When `rpxy-l4` sits behind a load balancer or proxy (e.g., AWS NLB, HAProxy) that sends PROXY protocol, enable inbound parsing to extract the original client IP from the header.

```toml
listen_port = 8448
tcp_target = ["192.168.0.2:8000"]

# Expect inbound PROXY header on every TCP connection
tcp_recv_proxy_protocol = true

# Trusted sources allowed to send PROXY headers (required when recv is enabled)
tcp_trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
```

- `tcp_recv_proxy_protocol = true` requires **all** incoming TCP connections to start with a PROXY header. Connections without a valid header are rejected.
- `tcp_trusted_proxies` is **mandatory** when recv is enabled. Connections from untrusted source IPs are rejected. If this field is missing or empty, startup validation fails.
- Both v1 and v2 headers are auto-detected — no version configuration is needed.
- LOCAL (v2) / UNKNOWN (v1) commands (e.g., health checks) are accepted without modifying the source address.

#### 4.3. End-to-end client IP preservation

When both inbound and outbound are enabled, `rpxy-l4` achieves end-to-end client IP preservation through a proxy chain:

```text
Client → [LB with PROXY protocol] → rpxy-l4 (inbound parse → outbound send) → Backend
```

The inbound parser extracts the original client IP, and the outbound encoder forwards it to the backend. No special configuration is needed beyond enabling both.

### 5. Advanced: Experimental features

#### 5.1. TLS Encrypted Client Hello (ECH) proxy

See [./examples/README.md](./examples/README.md) for the ECH proxy configuration and client and backend server examples.

## Containerization

The container, docker, image is available at Docker Hub and Github Container Registry.

- Docker Hub: [jqtype/rpxy-l4](https://hub.docker.com/r/jqtype/rpxy-l4)
- Github Container Registry: [ghcr.io/junkurihara/rust-rpxy-l4](https://ghcr.io/junkurihara/rust-rpxy-l4)

The detailed configuration of the container can be found at [./docker](./docker) directory.

## Caveats

### `UDP` pseudo connection management

As mentioned earlier, `rpxy-l4` manages pseudo connections for UDP packets from each clients based on the socket address. Also, `rpxy-l4` identifies specific protocols by probing their initial/handshake packets. These means that if the idle lifetime of pseudo connections is too short and the client sends packets in a long interval, the pseudo connection would be removed even during the communication. Then, the subsequent packets from the client, i.e., NOT the initial/handshake packets, are *routed not to the protocol-specific target but to the default target (or dropped if there is no default target)*. To avoid this, you should set the `idle_lifetime` value of UDP-based protocol multiplexer to be longer than the interval of the client's packet sending.

### Encrypted Client Hello (ECH) proxy

#### Reduced functionality

*Currently we do not fully implement the function of client facing server described in the [IETF draft](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-7.1).* It works as the following *simplified and reduced* manner, which is different from the draft:

- If no matching configuration with the given ECH is found, it just forwards the client hello to the backend server as it is.
- `rpxy-l4` does not support the retry mechanisms of client facing server, i.e., it currently has no state about ECH request, and doesn't handle, forward or emit the `HelloRetryRequest` message to the client.

#### No ECH over QUIC

ECH proxy function is limited only to the TLS protocol, and ECH over QUIC is not supported yet.

### Others

TBD!

## Credits

`rpxy-l4` cannot be built without the following projects and inspirations:

- [`sslh`](https://github.com/yrutschle/sslh): `rpxy-l4` is strongly inspired by `sslh` for its protocol multiplexer feature.
- [`tokio`](https://github.com/tokio-rs/tokio): Great async runtime for Rust.
- [`RustCrypto`](https://github.com/RustCrypto): Pure Rust implementations of various cryptographic algorithms, used in `rpxy-l4` for TLS/QUIC cryptographic operations.

## License

`rpxy-l4` is free, open-source software licensed under MIT License.

You can open issues for bugs you've found or features you think are missing. You can also submit pull requests to this repository.

Contributors are more than welcome!
