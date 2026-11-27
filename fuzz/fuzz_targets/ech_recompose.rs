#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // ClientHelloOuter records and a decrypted EncodedClientHelloInner: reconstruction after ECH
  // decryption, its postconditions, and the write-back read back by the TLS probe.
  rpxy_l4_quic_tls::fuzzing::probe_ech_recomposition(data);
});
