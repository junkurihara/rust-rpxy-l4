#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // Decrypted Initial payload: frame extraction, CRYPTO reassembly, and inner ClientHello parsing.
  rpxy_l4_quic_tls::fuzzing::probe_quic_unprotected_payload(data);
});
