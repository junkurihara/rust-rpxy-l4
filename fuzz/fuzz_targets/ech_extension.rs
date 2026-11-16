#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // ECH extension body as carried in a ClientHello extension.
  rpxy_l4_quic_tls::fuzzing::probe_ech_extension(data);
});
