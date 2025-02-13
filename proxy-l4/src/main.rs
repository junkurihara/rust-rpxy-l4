mod config;
mod log;

use crate::log::*;
use rpxy_l4_lib::*;
use std::sync::Arc;

// Proof of concept
fn main() {
  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("rpxy-layer-4");
  let runtime = runtime_builder.build().unwrap();

  init_logger();

  runtime.block_on(async {
    info!("Starting rpxy for layer 4");

    let dst_any = "192.168.122.4:53".parse().unwrap();
    let dst_ssh = "192.168.50.253:59978".parse().unwrap();
    let dst_tls = "8.8.4.4:853".parse().unwrap();
    let dst_http = "1.1.1.1:80".parse().unwrap();
    let listen_on_v6 = "[::1]:50444".parse().unwrap();
    let listen_on_v4 = "127.0.0.1:50444".parse().unwrap();
    let tcp_proxy_mux = TcpDestinationMuxBuilder::default()
      .dst_any(dst_any)
      .dst_ssh(dst_ssh)
      .dst_tls(dst_tls)
      .dst_http(dst_http)
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

    let udp_proxy_mux = UdpDestinationMuxBuilder::default()
      // .dst_any("127.0.0.1:4433".parse().unwrap())
      .dst_wireguard_with_custom_lifetime("192.168.50.253:52280".parse().unwrap(), 30)
      // .dst_any("8.8.8.8:53".parse().unwrap())
      .dst_any_with_custom_lifetime("[2001:4860:4860::8888]:53".parse().unwrap(), 5)
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
