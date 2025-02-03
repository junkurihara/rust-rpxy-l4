mod socket;

use socket::bind_tcp_socket;
use tokio::{io::copy_bidirectional, net::TcpStream};

// Proof of concept
fn main() {
  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("http-proxy-auth");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    println!("Starting rpxy-l4");
    start_proxy().await;
  });
}

async fn start_proxy() {
  let listen_on = "127.0.0.1:50553".parse().unwrap();
  let write_on = "127.0.0.1:50053";
  let tcp_socket = bind_tcp_socket(&listen_on).unwrap();
  let tcp_listener = tcp_socket.listen(1024).unwrap();

  loop {
    let (mut incoming_stream, src_addr) = match tcp_listener.accept().await {
      Err(e) => {
        // error!("Error in TCP listener: {}", e);
        println!("Error in TCP listener: {e}");
        continue;
      }
      Ok(res) => res,
    };
    tokio::spawn(async move {
      // let (mut incoming_readable, mut incoming_writable) = incoming_stream.into_split();
      println!("Accepted TCP connection from: {src_addr}");
      let mut outgoing_stream = TcpStream::connect(write_on).await.unwrap();
      copy_bidirectional(&mut incoming_stream, &mut outgoing_stream).await.unwrap();
    });

    // let self_clone = self.clone();
    // self.globals.runtime_handle.spawn(async move {
    //   if let Err(e) = self_clone.serve_tcp_query(stream, src_addr).await {
    //     error!("Failed to handle TCP query: {}", e);
    //   }
    // });
  }
}
