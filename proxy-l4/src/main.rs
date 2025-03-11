mod config;
mod log;

use crate::{config::parse_opts, log::*};
use config::{ConfigToml, ConfigTomlReloader};
use hot_reload::ReloaderService;
use rpxy_l4_lib::*;
use std::sync::Arc;

/// Delay in seconds to watch the config file
const CONFIG_WATCH_DELAY_SECS: u32 = 15;

fn main() {
  init_logger();

  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("rpxy-l4");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    info!("Starting rpxy for layer 4");

    let Ok(parsed_opts) = parse_opts() else {
      error!("Invalid toml file");
      std::process::exit(1);
    };

    // config service watches the service config file.
    // if the base service config file is updated, the  entrypoint will be restarted.
    let (config_service, config_rx) = ReloaderService::<ConfigTomlReloader, ConfigToml, String>::new(
      &parsed_opts.config_file_path,
      CONFIG_WATCH_DELAY_SECS,
      false,
    )
    .await
    .unwrap();

    let config = ConfigToml::new(&parsed_opts.config_file_path).unwrap();
    println!("{:#?}", config);

    /* -------------------------------------- */
    let dst_any = &["192.168.122.4:53".parse().unwrap()];
    let dst_ssh = &["192.168.50.253:59978".parse().unwrap()];
    let dst_tls = &["8.8.4.4:853".parse().unwrap()];
    let dst_http = &["1.1.1.1:80".parse().unwrap()];
    let listen_on_v6 = "[::1]:50444".parse().unwrap();
    let listen_on_v4 = "127.0.0.1:50444".parse().unwrap();
    let tcp_proxy_mux = TcpDestinationMuxBuilder::default()
      .dst_any(dst_any, None)
      .dst_ssh(dst_ssh, None)
      .dst_http(dst_http, None)
      .dst_tls(dst_tls, None, None, None)
      .build()
      .unwrap();

    // connection count will be shared among all TCP proxies
    let tcp_conn_count = TcpConnectionCount::default();
    let tcp_proxy_v6 = TcpProxyBuilder::default()
      .listen_on(listen_on_v6)
      .destination_mux(Arc::new(tcp_proxy_mux.clone()))
      .runtime_handle(runtime.handle().clone())
      .connection_count(tcp_conn_count.clone())
      .build()
      .unwrap();
    let tcp_proxy_v4 = TcpProxyBuilder::default()
      .listen_on(listen_on_v4)
      .destination_mux(Arc::new(tcp_proxy_mux))
      .runtime_handle(runtime.handle().clone())
      .connection_count(tcp_conn_count)
      .build()
      .unwrap();

    /* -------------------------------------- */
    let udp_proxy_mux = UdpDestinationMuxBuilder::default()
      // .dst_any("127.0.0.1:4433".parse().unwrap())
      .dst_wireguard(&["192.168.50.253:52280".parse().unwrap()], None, Some(30))
      // .dst_any("8.8.8.8:53".parse().unwrap())
      .dst_any(&["8.8.8.8:53".parse().unwrap()], None, Some(5))
      .dst_quic(&["127.0.0.1:4433".parse().unwrap()], None, Some(30), None, None)
      .build()
      .unwrap();
    // connection count will be shared among all UDP proxies
    let udp_conn_count = UdpConnectionCount::<std::net::SocketAddr>::default();
    let udp_proxy_v6 = UdpProxyBuilder::default()
      .listen_on(listen_on_v6)
      .destination_mux(Arc::new(udp_proxy_mux.clone()))
      .runtime_handle(runtime.handle().clone())
      .connection_count(udp_conn_count.clone())
      .build()
      .unwrap();
    let udp_proxy_v4 = UdpProxyBuilder::default()
      .listen_on(listen_on_v4)
      .destination_mux(Arc::new(udp_proxy_mux))
      .runtime_handle(runtime.handle().clone())
      .connection_count(udp_conn_count)
      .build()
      .unwrap();

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // tokio::spawn({
    //   let cancel_token = cancel_token.clone();
    //   async move {
    //     tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
    //     cancel_token.cancel();
    //   }
    // });

    tokio::select! {
      res = tcp_proxy_v6.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("TCPv6 proxy stopped: {}", e);
        }
      }
      res = tcp_proxy_v4.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("TCPv4 proxy stopped: {}", e);
        }
      }
      res = udp_proxy_v6.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("UDPv6 proxy stopped: {}", e);
        }
      }
      res = udp_proxy_v4.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("UDPv4 proxy stopped: {}", e);
        }
      }
    }

    // let tcp_handle = tokio::spawn(async move { start_tcp_proxy().await });
    // let udp_handle = tokio::spawn(async move { start_udp_proxy().await });
    // tokio::select! {
    //   _ = tcp_handle => {
    //     error!("TCP proxy stopped");
    //   }
    //   _ = udp_handle => {
    //     error!("UDP proxy stopped");
    //   }
    // }
  });
}
