#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod log;

use crate::{config::parse_opts, log::*};
use config::{ConfigToml, ConfigTomlReloader};
use hot_reload::{ReloaderReceiver, ReloaderService};
use rpxy_l4_lib::*;
use std::sync::Arc;

/// Delay in seconds to watch the config file
const CONFIG_WATCH_DELAY_SECS: u32 = 15;
/// Listen on v4 address
const LISTEN_ON_V4: &str = "0.0.0.0";
/// Listen on v6 address
const LISTEN_ON_V6: &str = "[::]";

fn main() {
  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("rpxy-l4");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    let Ok(parsed_opts) = parse_opts() else {
      error!("Invalid toml file");
      std::process::exit(1);
    };
    init_logger(parsed_opts.log_dir_path.as_deref());

    info!("Starting rpxy for layer 4");

    // config service watches the service config file.
    // if the base service config file is updated, the  entrypoint will be restarted.
    let (config_service, config_rx) = ReloaderService::<ConfigTomlReloader, ConfigToml, String>::new(
      &parsed_opts.config_file_path,
      CONFIG_WATCH_DELAY_SECS,
      false,
    )
    .await
    .unwrap();

    tokio::select! {
      config_res = config_service.start() => {
        if let Err(e) = config_res {
          error!("config reloader service exited: {e}");
          std::process::exit(1);
        }
      }
      res = entrypoint(config_rx, runtime.handle().clone()) => {
        if let Err(e) = res {
          error!("Service exited: {e}");
          std::process::exit(1);
        }
      }
    }
    std::process::exit(0);
  });
}

/// Entrypoint for the service
async fn entrypoint(
  mut config_rx: ReloaderReceiver<ConfigToml, String>,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(), anyhow::Error> {
  // Initial loading
  config_rx.changed().await?;
  let config_toml = config_rx
    .borrow()
    .clone()
    .ok_or(anyhow::anyhow!("Something wrong in config reloader receiver"))?;

  let mut proxy_service = ProxyService::try_new(&config_toml, runtime_handle.clone())?;

  // Continuous monitoring
  loop {
    // Notifier for proxy service termination
    let cancel_token = tokio_util::sync::CancellationToken::new();

    tokio::select! {
      res = proxy_service.start(cancel_token.child_token()) => {
        if let Err(ref e) = res {
          error!("Proxy service stopped: {e}");
        } else {
          error!("Proxy service exited");
        }
        return res.map_err(|e| anyhow::anyhow!(e));
      }
      _ = config_rx.changed() => {
        let Some(new_config_toml) = config_rx.borrow().clone() else {
          error!("Something wrong in config reloader receiver");
          return Err(anyhow::anyhow!("Something wrong in config reloader receiver"));
        };
        match ProxyService::try_new(&new_config_toml, runtime_handle.clone()) {
          Ok(new_proxy_service) => {
            info!("Configuration reloaded");
            proxy_service = new_proxy_service;
          }
          Err(e) => {
            error!("Failed to create a new proxy service: {e}");
          }
        }

        // Kill the previous proxy service
        info!("Terminate all spawned services and force to re-bind TCP/UDP sockets");
        cancel_token.cancel();
      }
    }
  }
}

/* ---------------------------------------------------------- */
#[derive(Debug)]
/// Proxy service struct
struct ProxyService {
  runtime_handle: tokio::runtime::Handle,
  listen_port: u16,
  listen_ipv6: bool,
  tcp_backlog: Option<u32>,
  tcp_max_connections: Option<u32>,
  udp_max_connections: Option<u32>,
  tcp_proxy_mux: Arc<TcpDestinationMux>,
  udp_proxy_mux: Arc<UdpDestinationMux>,
}

impl ProxyService {
  /// Create a new proxy service
  fn try_new(config_toml: &ConfigToml, runtime_handle: tokio::runtime::Handle) -> Result<Self, anyhow::Error> {
    let config = Config::try_from(config_toml.clone())?;
    let (tcp_proxy_mux, udp_proxy_mux) = build_multiplexers(&config)?;

    let res = Self {
      runtime_handle,
      listen_port: config.listen_port,
      listen_ipv6: config.listen_ipv6,
      tcp_backlog: config.tcp_backlog,
      tcp_max_connections: config.tcp_max_connections,
      udp_max_connections: config.udp_max_connections,
      tcp_proxy_mux: Arc::new(tcp_proxy_mux),
      udp_proxy_mux: Arc::new(udp_proxy_mux),
    };
    debug!("Service configuration: {:#?}", res);
    Ok(res)
  }

  /// Start the proxy service
  async fn start(&self, cancel_token: tokio_util::sync::CancellationToken) -> Result<(), anyhow::Error> {
    let mut join_handles = Vec::new();

    let listen_on_v4 = format!("{LISTEN_ON_V4}:{}", self.listen_port).parse()?;
    let listen_on_v6 = format!("{LISTEN_ON_V6}:{}", self.listen_port).parse()?;
    /* -------------------------- Tcp -------------------------- */
    if !self.tcp_proxy_mux.is_empty() {
      // connection count will be shared among all TCP proxies
      let tcp_conn_count = TcpConnectionCount::default();
      let tcp_proxy_v4 = self
        .tcp_builder()
        .listen_on(listen_on_v4)
        .connection_count(tcp_conn_count.clone())
        .build()?;
      let tcp_proxy_v4_handle = self.runtime_handle.spawn({
        let cancel_token = cancel_token.child_token();
        async move {
          if let Err(e) = tcp_proxy_v4.start(cancel_token).await {
            error!("TCPv4 proxy stopped: {e}");
          }
        }
      });
      join_handles.push(tcp_proxy_v4_handle);

      if self.listen_ipv6 {
        let tcp_proxy_v6 = self
          .tcp_builder()
          .listen_on(listen_on_v6)
          .connection_count(tcp_conn_count)
          .build()?;
        let tcp_proxy_v6_handle = self.runtime_handle.spawn({
          let cancel_token = cancel_token.child_token();
          async move {
            if let Err(e) = tcp_proxy_v6.start(cancel_token).await {
              error!("TCPv6 proxy stopped: {e}");
            }
          }
        });
        join_handles.push(tcp_proxy_v6_handle);
      }
    }

    /* -------------------------- Udp -------------------------- */
    if !self.udp_proxy_mux.is_empty() {
      // connection count will be shared among all UDP proxies
      let udp_conn_count = UdpConnectionCount::<std::net::SocketAddr>::default();
      let udp_proxy_v4 = self
        .udp_builder()
        .listen_on(listen_on_v4)
        .connection_count(udp_conn_count.clone())
        .build()?;
      let udp_proxy_v4_handle = self.runtime_handle.spawn({
        let cancel_token = cancel_token.child_token();
        async move {
          if let Err(e) = udp_proxy_v4.start(cancel_token).await {
            error!("UDPv4 proxy stopped: {e}");
          }
        }
      });
      join_handles.push(udp_proxy_v4_handle);

      if self.listen_ipv6 {
        let udp_proxy_v6 = self
          .udp_builder()
          .listen_on(listen_on_v6)
          .connection_count(udp_conn_count)
          .build()?;
        let udp_proxy_v6_handle = self.runtime_handle.spawn({
          let cancel_token = cancel_token.child_token();
          async move {
            if let Err(e) = udp_proxy_v6.start(cancel_token).await {
              error!("UDPv6 proxy stopped: {e}");
            }
          }
        });
        join_handles.push(udp_proxy_v6_handle);
      }
    }

    if join_handles.is_empty() {
      error!("No proxy service is configured");
      return Err(anyhow::anyhow!("No proxy service is configured"));
    }

    let _ = futures::future::select_all(join_handles.into_iter()).await;
    // Kill all spawned services
    cancel_token.cancel();
    Ok(())
  }

  /// Create a TCP proxy builder common for v4 and v6
  fn tcp_builder(&self) -> TcpProxyBuilder {
    let mut tcp_proxy_builder = TcpProxyBuilder::default();
    tcp_proxy_builder
      .destination_mux(self.tcp_proxy_mux.clone())
      .runtime_handle(self.runtime_handle.clone());
    if let Some(tcp_backlog) = self.tcp_backlog {
      tcp_proxy_builder.backlog(tcp_backlog);
    }
    if let Some(tcp_max_connections) = self.tcp_max_connections {
      tcp_proxy_builder.max_connections(tcp_max_connections as usize);
    }
    tcp_proxy_builder
  }

  /// Create a UDP proxy builder common for v4 and v6
  fn udp_builder(&self) -> UdpProxyBuilder {
    let mut udp_proxy_builder = UdpProxyBuilder::default();
    udp_proxy_builder
      .destination_mux(self.udp_proxy_mux.clone())
      .runtime_handle(self.runtime_handle.clone());
    if let Some(udp_max_connections) = self.udp_max_connections {
      udp_proxy_builder.max_connections(udp_max_connections as usize);
    }
    udp_proxy_builder
  }
}
