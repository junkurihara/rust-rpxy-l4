mod config;
mod log;
mod proxy;

use crate::{log::*, proxy::*};
use std::sync::Arc;
// use tokio::{
// io::copy_bidirectional,
// net::{TcpStream, UdpSocket},
// sync::mpsc,
// };

// Proof of concept
fn main() {
  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("rpxy-layer-4");
  let runtime = runtime_builder.build().unwrap();
  init_logger();

  runtime.block_on(async {
    info!("Starting rpxy layer 4");

    let write_on_any = "192.168.122.4:53".parse().unwrap();
    let write_on_ssh = "150.95.211.62:59978".parse().unwrap();
    let listen_on = "127.0.0.1:50444".parse().unwrap();
    let tcp_proxy_mux = TcpProxyMuxBuilder::default()
      .write_on_any(write_on_any)
      .write_on_ssh(write_on_ssh)
      .build()
      .unwrap();
    let tcp_proxy = TcpProxyBuilder::default()
      .listen_on(listen_on)
      .write_on_mux(Arc::new(tcp_proxy_mux))
      .runtime_handle(runtime.handle().clone())
      .build()
      .unwrap();

    let cancel_token = tokio_util::sync::CancellationToken::new();

    let _ = tcp_proxy.start(cancel_token.child_token()).await;

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

// async fn start_tcp_proxy() {
//   let listen_on = "127.0.0.1:50553".parse().unwrap();
//   let write_on = "192.168.50.184:59978";
//   let tcp_socket = bind_tcp_socket(&listen_on).unwrap();
//   let tcp_listener = tcp_socket.listen(1024).unwrap();

//   loop {
//     let (mut incoming_stream, src_addr) = match tcp_listener.accept().await {
//       Err(e) => {
//         // error!("Error in TCP listener: {}", e);
//         println!("Error in TCP listener: {e}");
//         continue;
//       }
//       Ok(res) => res,
//     };
//     tokio::spawn(async move {
//       let mut buf = vec![0u8; 4];
//       let res = tokio::time::timeout(tokio::time::Duration::from_millis(100), incoming_stream.peek(&mut buf))
//         .await
//         .unwrap()
//         .unwrap();
//       if res == 0 {
//         println!("No data received");
//         return;
//       }
//       if buf.eq(b"SSH-") {
//         println!("SSH connection detected");
//       }

//       // let (mut incoming_readable, mut incoming_writable) = incoming_stream.into_split();
//       println!("Accepted TCP connection from: {src_addr}");
//       let mut outgoing_stream = TcpStream::connect(write_on).await.unwrap();
//       copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await.unwrap();
//     });

//     // let self_clone = self.clone();
//     // self.globals.runtime_handle.spawn(async move {
//     //   if let Err(e) = self_clone.serve_tcp_query(stream, src_addr).await {
//     //     error!("Failed to handle TCP query: {}", e);
//     //   }
//     // });
//   }
// }

// async fn start_udp_proxy() {
//   let incoming_listen_on = "127.0.0.1:50553".parse().unwrap();
//   let outgoing_listen_on = "127.0.0.1:50054".parse().unwrap();
//   let write_on: SocketAddr = "127.0.0.1:50053".parse().unwrap();
//   let incoming_udp_socket = UdpSocket::from_std(bind_udp_socket(&incoming_listen_on).unwrap()).unwrap();
//   let incoming_socket_tx = Arc::new(incoming_udp_socket);
//   let incoming_socket_rx = incoming_socket_tx.clone();
//   let outgoing_udp_socket = UdpSocket::from_std(bind_udp_socket(&outgoing_listen_on).unwrap()).unwrap();
//   let outgoing_socket_tx = Arc::new(outgoing_udp_socket);
//   let outgoing_socket_rx = outgoing_socket_tx.clone();

//   // setup a channel for sending out responses
//   let (channel_tx, channel_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(UDP_CHANNEL_CAPACITY);

//   // create sender thread that sends out response given through channel
//   tokio::spawn(udp_responder_service(incoming_socket_tx, channel_rx));

//   // Setup buffer
//   let mut udp_buf = vec![0u8; UDP_BUFFER_SIZE];

//   loop {
//     let (buf_size, src_addr) = match incoming_socket_rx.recv_from(&mut udp_buf).await {
//       Err(e) => {
//         println!("Error in UDP listener: {e}");
//         continue;
//       }
//       Ok(res) => res,
//     };
//     println!("received {} bytes from {}", buf_size, src_addr);

//     let rx_packet_buf = udp_buf[..buf_size].to_vec();

//     let outgoing_socket_tx_clone = outgoing_socket_tx.clone();
//     let outgoing_socket_rx_clone = outgoing_socket_rx.clone();
//     let channel_tx_clone = channel_tx.clone();
//     tokio::spawn(async move {
//       let mut outgoing_udp_buf = vec![0u8; UDP_BUFFER_SIZE];
//       // forward the packet to upstream
//       let x = outgoing_socket_tx_clone.send_to(rx_packet_buf.as_slice(), write_on);
//       let y = outgoing_socket_rx_clone.recv_from(&mut outgoing_udp_buf);
//       if let Ok((_, (buf_size, _))) = tokio::try_join!(x, y) {
//         let response = outgoing_udp_buf[..buf_size].to_vec();
//         channel_tx_clone.send((response, src_addr)).await.unwrap();
//       };
//     });
//   }
// }

// /// Send response to source client
// async fn udp_responder_service(
//   incoming_socket_tx: Arc<UdpSocket>,
//   mut channel_rx: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
// ) {
//   let service = async {
//     loop {
//       let (bytes, addr) = match channel_rx.recv().await {
//         None => {
//           println!("udp channel_receiver.recv()");
//           continue;
//         }
//         Some(res) => res,
//       };
//       match &incoming_socket_tx.send_to(&bytes, addr).await {
//         Ok(len) => {
//           println!("send_to source with response of {:?} bytes", len);
//         }
//         Err(e) => {
//           println!("send_to error: {:?}", e);
//         }
//       };
//     }
//   };

//   service.await;
// }
