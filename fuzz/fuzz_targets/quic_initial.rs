#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // One UDP datagram; the parser itself splits coalesced packets inside it.
  // AEAD authentication gates everything after header protection, which quic_frames covers.
  let _ = rpxy_l4_quic_tls::probe_quic_initial_packets(&[data.to_vec()]);
});
