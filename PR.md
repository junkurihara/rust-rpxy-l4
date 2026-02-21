Feature Description
Currently, it appears that the original client IP address is not preserved after traffic forwarding.

We would like to request support for HAProxy Proxy Protocol to preserve the client’s original IP address. Proxy Protocol allows the upstream server to receive the real client IP instead of the proxy’s IP.

Reference:
https://www.haproxy.com/blog/use-the-proxy-protocol-to-preserve-a-clients-ip-address
Below is a clear description of Proxy Protocol v1 and v2, several examples, and Rust libraries that implement parsers/encoders.

Support for Proxy Protocol can be added to rpxy via two configuration options:
1️⃣ Listening Side (Inbound)

accept_proxy_protocol = true
If disabled (default), the server behaves as it does today and reads raw TCP without expecting a Proxy header.

This is useful when rpxy is deployed behind HAProxy, AWS NLB, or another L4 proxy that sends Proxy Protocol.

2️⃣ Forwarding Side (Outbound)

send_proxy_protocol = "v2" 
or
send_proxy_protocol = "v1"
⸻
Please see the details

Details
📌 Proxy Protocol Versions
Proxy Protocol v1 (Text Format)

This version is human-readable ASCII text sent at the start of a TCP connection:

PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n

•	TCP4 = IPv4 over TCP
•	TCP6 = IPv6 over TCP
•	UNKNOWN = client didn’t send the header
Example (IPv4):

PROXY TCP4 203.0.113.10 10.0.0.5 56789 443

Interpreted as:
• Source IP: 203.0.113.10
• Destination IP: 10.0.0.5
• Source Port: 56789
• Destination Port: 443

Example (IPv6):

PROXY TCP6 2001:db8::1 2001:db8::2 34567 443

This header is always terminated with \r\n.

⸻

Proxy Protocol v2 (Binary Format)

v2 is a binary header (not text) that includes the same address info and can also carry additional TLVs (type–length–value fields), such as SSL info, application layer metadata, connection IDs, etc.

The binary header starts with a fixed magic sequence followed by fields indicating:
• protocol version and command
• address family (IPv4/IPv6/UNIX)
• transport protocol (STREAM/DGRAM)
• source/dest addresses + ports
• optional TLVs

Because it’s binary, it is more space-efficient and extensible.

High-level structure (not exact bytes):

<version/command> <fam/proto> <TLVs...>

⸻

🧪 Examples

v1 Example

Client → HAProxy adds header and forwards:

PROXY TCP4 192.0.2.1 10.1.1.100 52345 443\r\n
<actual TLS/HTTP data follows>

Backend sees:
• real client: 192.0.2.1
• real port: 52345

⸻

v2 Example with TLVs (simplified)

The HAProxy PROXY v2 header might contain:
• client IP
• destination IP
• source/dest ports
• custom TLVs (e.g., SSL info, connection metadata)

The header parses into structured info, including optional TLVs for connection attributes beyond IP/port.

⸻

🦀 Rust Libraries Supporting Proxy Protocol

Rust has multiple crates that can help encode/decode Proxy Protocol. Here are the main ones:

✅ ppp

A dedicated parser for both v1 and v2 headers in Rust.
• Supports parsing Proxy Protocol headers in streaming contexts
• Can detect partial headers
• Implements Text (v1) and Binary (v2) version parsing

Add to Cargo.toml:

ppp = "2.0"

Usage includes parsing or generating both v1 and v2 formats.

⸻
Motivation
Preserving the original client IP is essential for many use cases, including:
• Accurate logging and auditing
• Geolocation-based features
• Security monitoring and abuse prevention
• Rate limiting per real client IP

Without Proxy Protocol support, backend services only see the proxy’s IP address, which limits visibility and control.
Alternatives considered
Have you considered any alternatives or workarounds?
(Please describe what you tried, e.g., configuration changes, external tools, or client-side modifications.)

Your contribution
Would you be willing to:


Submit a Pull Request implementing this feature

Sponsor the development (via GitHub Sponsors / other)
Important notes
Features that cause compatibility issues or are out of project scope may be declined.
This project is maintained on a best-effort basis. Requests without contributions (PR or sponsorship) may not be prioritized.
This project is primarily driven by the code owner's personal interests, not by commercial demand or contractual obligations.