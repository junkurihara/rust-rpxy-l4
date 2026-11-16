#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  // Production TCP detection uses the budgeted entry. A budget equal to the input length never
  // rejects a ClientHello whose body is fully present, so the body and extension parsers receive
  // the same inputs as with the unbudgeted entry while the budget check is also exercised.
  let mut buf = data;
  let _ = rpxy_l4_quic_tls::probe_tls_handshake_with_max_probe_bytes(&mut buf, data.len());
});
