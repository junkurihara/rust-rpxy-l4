# Examples for the backend server and client of Encrypted Client Hello

## Start backend server

```bash
cargo run --package rpxy-l4-examples --bin tlsserver-mio -- --certs ./examples/server.crt --key ./examples/server.key --verbose http
```

This simply hosts a TLS server working as the backend server in the context of [ECH Split Mode](https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-3).

> [!NOTE]
> The above server certificate and key are self-signed for the common name `localhost`. This means that you will get an error as `untrusted certificate` or `unknown CA` when you try to connect to it without `--cafile server.crt` option in the client.

## Start client

```bash
cargo run --package rpxy-l4-examples --bin ech-client -- --host localhost --cafile ./examples/server.crt localhost localhost
```

This will connect to the backend server by cloaking the target hostname `localhost:443` (the backend server) with the public hostname `localhost:8448` (the client facing server, i.e., `rpxy-l4`), and tries to send HTTP request with host header `localhost`.

## Start rxpy-l4 with ECH configuration

Before you run the above command, make sure that you have started the backend server and `rxpy-l4` with the following ECH configuration:

```toml
listen_port = 8448

[protocols."tls_ech"]
protocol = "tls"
target = ["1.1.1.1:53"] # default target to which the packet is sent when ECH decryption fails (no matching ECH config)
load_balance = "source_ip"
server_names = ["localhost"]

# Static ECH configuration embedded in the client source code
[protocols."tls_ech".ech]
ech_config_list = "ADz+DQA4ugAgACA9U8FCH7vKOFXVCCcAdpUUSfu3rzlooRNflhOXyV0uTwAEAAEAAQAJbG9jYWxob3N0AAA"
private_keys = ["KwyvZOuPlflYlcmJbwhA24HMWUvxXXyan/oh9cJ6lNw"]
# Acceptable private server names obtained from decrypted ECH Client Hello Inner, where port is optional.
# When port is not specified, it is the same as the listen port (i.e., forward as it is).
private_server_names = ["localhost:443"]
```
