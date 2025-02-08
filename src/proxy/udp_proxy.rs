use std::net::SocketAddr;

/* ---------------------------------------------------------- */
#[derive(Debug, Clone, derive_builder::Builder)]
/// Single Udp proxy struct
pub struct UdpProxy {
  /// Bound socket address to listen on, exposed to the client
  listen_on: SocketAddr,
  // /// Socket address to write on, the actual destination routed for protocol types
  // write_on_mux: Arc<UdpProxyMux>,
  /// Tokio runtime handle
  runtime_handle: tokio::runtime::Handle,
}

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
