//! **Test code based on [Rustls Examples](https://github.com/rustls/rustls/tree/main/examples)**
//! Using static keys and ech config for testing
//! - secret key: "KwyvZOuPlflYlcmJbwhA24HMWUvxXXyan/oh9cJ6lNw"
//! - ech config list (base64): ADz+DQA4ugAgACA9U8FCH7vKOFXVCCcAdpUUSfu3rzlooRNflhOXyV0uTwAEAAEAAQAJbG9jYWxob3N0AAA
//!
//! `cargo run --package rpxy-l4-examples --bin ech-client -- --host localhost localhost www.defo.ie`
//!
//! ============================================================================
//! This is a simple example demonstrating how to use Encrypted Client Hello (ECH) with
//! rustls and hickory-dns.
//!
//! Note that `unwrap()` is used to deal with networking errors; this is not something
//! that is sensible outside of example code.
//!
//! Example usage:
//! ```
//! cargo run --package rustls-examples --bin ech-client -- --host defo.ie defo.ie www.defo.ie
//! ```
//!
//! This will perform a DNS-over-HTTPS lookup for the defo.ie ECH config, using it to determine
//! the plaintext SNI to send to the server. The protected encrypted SNI will be "www.defo.ie".
//! An HTTP request for Host: defo.ie will be made once the handshake completes. You should
//! observe output that contains:
//! ```
//!   <p>SSL_ECH_OUTER_SNI: cover.defo.ie <br />
//!   SSL_ECH_INNER_SNI: www.defo.ie <br />
//!   SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
//!   </p>
//! ```

// use std::fs;
use std::io::{BufReader, Read, Write, stdout};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;

use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use clap::Parser;
// use hickory_resolver::Resolver;
// use hickory_resolver::config::{ResolverConfig, ResolverOpts};
// use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
// use hickory_resolver::proto::rr::{RData, RecordType};
use log::trace;
use rustls::RootCertStore;
use rustls::client::{EchConfig, EchGreaseConfig, EchStatus};
use rustls::crypto::aws_lc_rs;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName};

const ECH_CONFIG: &str = "ADz+DQA4ugAgACA9U8FCH7vKOFXVCCcAdpUUSfu3rzlooRNflhOXyV0uTwAEAAEAAQAJbG9jYWxob3N0AAA";
const LOCAL_SOCK: &str = "127.0.0.1:8448";

fn main() {
  let args = Args::parse();

  let static_ech_config = EchConfigListBytes::from(BASE64_STANDARD_NO_PAD.decode(ECH_CONFIG).unwrap());

  // // Find raw ECH configs using DNS-over-HTTPS with Hickory DNS.
  // let resolver_config = if args.use_cloudflare_dns {
  //   ResolverConfig::cloudflare_https()
  // } else {
  //   ResolverConfig::google_https()
  // };
  // let resolver = Resolver::new(resolver_config, ResolverOpts::default()).unwrap();
  // let server_ech_config = match args.grease {
  //   true => None, // Force the use of the GREASE ext by skipping ECH config lookup
  //   false => match args.ech_config {
  //     Some(path) => Some(read_ech(&path)),
  //     None => lookup_ech_configs(&resolver, &args.outer_hostname, args.port),
  //   },
  // };
  let server_ech_config = Some(static_ech_config.clone());

  // NOTE: we defer setting up env_logger and setting the trace default filter level until
  //       after doing the DNS-over-HTTPS lookup above - we don't want to muddy the output
  //       with the rustls debug logs from the lookup.
  env_logger::Builder::new().parse_filters("trace").init();

  let ech_mode = match server_ech_config {
    Some(ech_config_list) => EchConfig::new(ech_config_list, ALL_SUPPORTED_SUITES).unwrap().into(),
    None => {
      let (public_key, _) = GREASE_HPKE_SUITE.generate_key_pair().unwrap();
      EchGreaseConfig::new(GREASE_HPKE_SUITE, public_key).into()
    }
  };

  let root_store = match args.cafile {
    Some(file) => {
      let mut root_store = RootCertStore::empty();
      root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(file)
          .expect("Cannot open CA file")
          .map(|result| result.unwrap()),
      );
      root_store
    }
    None => RootCertStore {
      roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    },
  };

  // Construct a rustls client config with a custom provider, and ECH enabled.
  let mut config = rustls::ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
    .with_ech(ech_mode)
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  // Allow using SSLKEYLOGFILE.
  config.key_log = Arc::new(rustls::KeyLogFile::new());
  let config = Arc::new(config);

  // The "inner" SNI that we're really trying to reach.
  let server_name: ServerName<'static> = args.inner_hostname.clone().try_into().unwrap();

  for i in 0..args.num_reqs {
    trace!("\nRequest {} of {}", i + 1, args.num_reqs);
    let mut conn = rustls::ClientConnection::new(config.clone(), server_name.clone()).unwrap();
    // The "outer" server that we're connecting to.
    // let sock_addr = (args.outer_hostname.as_str(), args.port)
    //   .to_socket_addrs()
    //   .unwrap()
    //   .next()
    //   .unwrap();
    let sock_addr: std::net::SocketAddr = LOCAL_SOCK.parse().unwrap();
    let mut sock = TcpStream::connect(sock_addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let request = format!(
      "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
      args.path,
      args.host.as_ref().unwrap_or(&args.inner_hostname),
    );
    dbg!(&request);
    let res = tls.write_all(request.as_bytes());
    if let Err(e) = res {
      eprintln!("Error writing to socket: {:#?}", e);
      return;
    }
    assert!(!tls.conn.is_handshaking());
    assert_eq!(
      tls.conn.ech_status(),
      match args.grease {
        true => EchStatus::Grease,
        false => EchStatus::Accepted,
      }
    );
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
  }
}

/// Connects to the TLS server at hostname:PORT.  The default PORT
/// is 443. If an ECH config can be fetched for hostname using
/// DNS-over-HTTPS, ECH is enabled. Otherwise, a placeholder ECH
/// extension is sent for anti-ossification testing.
///
/// Example:
///   ech-client --host defo.ie defo.ie www.defo.ie
#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
  /// Connect to this TCP port.
  #[clap(short, long, default_value = "443")]
  port: u16,

  /// Read root certificates from this file.
  ///
  /// If --cafile is not supplied, a built-in set of CA certificates
  /// are used from the webpki-roots crate.
  #[clap(long)]
  cafile: Option<String>,

  /// HTTP GET this PATH.
  #[clap(long, default_value = "ech-check.php")]
  path: String,

  /// HTTP HOST to use for GET request (defaults to value of inner-hostname).
  #[clap(long)]
  host: Option<String>,

  /// Use Google DNS for the DNS-over-HTTPS lookup (default).
  #[clap(long, group = "dns")]
  use_google_dns: bool,
  /// Use Cloudflare DNS for the DNS-over-HTTPS lookup.
  #[clap(long, group = "dns")]
  use_cloudflare_dns: bool,

  /// Skip looking up an ECH config and send a GREASE placeholder.
  #[clap(long)]
  grease: bool,

  /// Skip looking up an ECH config and read it from the provided file (in binary TLS encoding).
  #[clap(long)]
  ech_config: Option<String>,

  /// Number of requests to make.
  #[clap(long, default_value = "1")]
  num_reqs: usize,

  /// Outer hostname.
  outer_hostname: String,

  /// Inner hostname.
  inner_hostname: String,
}

// // TODO(@cpu): consider upstreaming to hickory-dns
// fn lookup_ech_configs(resolver: &Resolver, domain: &str, port: u16) -> Option<EchConfigListBytes<'static>> {
//   // For non-standard ports, lookup the ECHConfig using port-prefix naming
//   // See: https://datatracker.ietf.org/doc/html/rfc9460#section-9.1
//   let qname_to_lookup = match port {
//     443 => domain.to_owned(),
//     port => format!("_{port}._https.{domain}"),
//   };

//   resolver
//     .lookup(qname_to_lookup, RecordType::HTTPS)
//     .ok()?
//     .record_iter()
//     .find_map(|r| match r.data() {
//       RData::HTTPS(svcb) => svcb.svc_params().iter().find_map(|sp| match sp {
//         (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(e)) => Some(e.clone().0),
//         _ => None,
//       }),
//       _ => None,
//     })
//     .map(Into::into)
// }

// fn read_ech(path: &str) -> EchConfigListBytes<'static> {
//   let file = fs::File::open(path).unwrap_or_else(|_| panic!("Cannot open ECH file: {path}"));
//   let mut reader = BufReader::new(file);
//   let mut bytes = Vec::new();
//   reader
//     .read_to_end(&mut bytes)
//     .unwrap_or_else(|_| panic!("Cannot read ECH file: {path}"));
//   bytes.into()
// }

/// A HPKE suite to use for GREASE ECH.
///
/// A real implementation should vary this suite across all of the suites that are supported.
static GREASE_HPKE_SUITE: &dyn Hpke = aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
