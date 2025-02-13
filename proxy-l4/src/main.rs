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
    let listen_on = "[::1]:50444".parse().unwrap();
    let tcp_proxy_mux = TcpDestinationMuxBuilder::default()
      .dst_any(dst_any)
      .dst_ssh(dst_ssh)
      .dst_tls(dst_tls)
      .dst_http(dst_http)
      .build()
      .unwrap();
    let tcp_proxy = TcpProxyBuilder::default()
      .listen_on(listen_on)
      .destination_mux(Arc::new(tcp_proxy_mux))
      .runtime_handle(runtime.handle().clone())
      .build()
      .unwrap();

    let udp_proxy_mux = UdpDestinationMuxBuilder::default()
      // .dst_any("127.0.0.1:4433".parse().unwrap())
      .dst_wireguard("192.168.50.253:52280".parse().unwrap())
      // .dst_any("8.8.8.8:53".parse().unwrap())
      .dst_any("[2001:4860:4860::8888]:53".parse().unwrap())
      .build()
      .unwrap();
    let udp_proxy = UdpProxyBuilder::default()
      .listen_on("[::1]:50444".parse().unwrap())
      .destination_mux(Arc::new(udp_proxy_mux))
      .runtime_handle(runtime.handle().clone())
      .build()
      .unwrap();

    let cancel_token = tokio_util::sync::CancellationToken::new();

    tokio::select! {
      res = tcp_proxy.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("TCP proxy stopped: {}", e);
        }
      }
      res = udp_proxy.start(cancel_token.child_token()) => {
        if let Err(e) = res {
          error!("UDP proxy stopped: {}", e);
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
