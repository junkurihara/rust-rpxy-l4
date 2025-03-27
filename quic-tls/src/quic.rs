use crate::{
  client_hello::{TlsClientHelloInfo, probe_tls_client_hello_body, probe_tls_client_hello_header},
  error::TlsProbeFailure,
  trace::*,
};
use anyhow::anyhow;

const QUIC_VERSION_LEN: usize = 4;

/* ---------------------------------------------------- */
/// Is QUIC initial packets contained?
/// We consider initial packets only since only communication initiated from the client is expected.
/// Version negotiation packet is sent by the server as a response to the client
pub fn probe_quic_initial_packets(udp_datagrams: &[Vec<u8>]) -> Result<TlsClientHelloInfo, TlsProbeFailure> {
  if udp_datagrams.is_empty() || udp_datagrams.iter().any(|p| p.is_empty()) {
    return Err(TlsProbeFailure::Failure);
  }

  // Check if the packets contain QUIC initial packets, and unprotect the header and payload.
  let unprotected = udp_datagrams.iter().flat_map(|p| probe_quic_packets(p)).collect::<Vec<_>>();
  if unprotected.is_empty() {
    return Err(TlsProbeFailure::Failure);
  }

  // Check if all unprotected packets contains the same version, SCID, DCID, and Token.
  let version = unprotected[0].version;
  let scid = unprotected[0].scid.clone();
  let dcid = unprotected[0].dcid.clone();
  let token = unprotected[0].token.clone();
  if unprotected
    .iter()
    .any(|p| p.version != version || p.scid != scid || p.dcid != dcid || p.token != token)
  {
    return Err(TlsProbeFailure::Failure);
  }

  // Filter only the initial packets
  let unprotected = unprotected
    .into_iter()
    .filter(|p| matches!(p.packet_type, QuicCoalesceablePacketType::Initial))
    .collect::<Vec<_>>();

  probe_quic_unprotected_frames(&unprotected)
}

// /* ---------------------------------------------------- */
// /// Check if the buffer contains a QUIC version negotiation packet.
// fn is_quic_version_negotiation_packet(buf: &[u8]) -> bool {
//   // header(1), version(4), DCID length(1), SCID length(1)
//   if buf.len() < 7 {
//     return false;
//   }
//   // Packet header byte: 0b1xxx_xxxx
//   if buf[0] & 0x80 == 0 {
//     return false;
//   }
//   // Version: 0x00000000
//   if !buf[1..5].eq(&[0x00, 0x00, 0x00, 0x00]) {
//     return false;
//   }
//   let mut ptr = 5;
//   let Ok((_dcid, _scid)) = dcid_scid(buf, &mut ptr) else {
//     return false;
//   };

//   // Supported versions, each 4 bytes
//   let remained = buf.len() - ptr;
//   if remained % 4 != 0 {
//     return false;
//   }

//   true
// }

/* ---------------------------------------------------- */
#[allow(unused)]
#[derive(Debug)]
/// Parsed and unprotected QUIC packet
struct QuicPacket {
  version: QuicVersion,
  packet_type: QuicCoalesceablePacketType,
  dcid: Vec<u8>,
  scid: Vec<u8>,
  token: Vec<u8>,
  header: Vec<u8>,
  packet_number: Vec<u8>,
  payload: Vec<u8>,
}

#[derive(Eq, PartialEq, Clone, Copy, Hash, Debug)]
/// QUIC version
enum QuicVersion {
  V1,
  V2,
}
impl std::fmt::Display for QuicVersion {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      QuicVersion::V1 => write!(f, "QUICv1"),
      QuicVersion::V2 => write!(f, "QUICv2"),
    }
  }
}

/// Check QUIC version
fn quic_version(buf: &[u8]) -> Option<QuicVersion> {
  match buf {
    [0x00, 0x00, 0x00, 0x01] => Some(QuicVersion::V1),
    [0x6b, 0x33, 0x43, 0xcf] => Some(QuicVersion::V2),
    _ => None,
  }
}

#[derive(Debug, PartialEq, Eq)]
/// Quic coalesceable packet types
/// Ommitted: Short header packet types, etc
enum QuicCoalesceablePacketType {
  Initial,
  Handshake,
  ZeroRTT,
}
impl std::fmt::Display for QuicCoalesceablePacketType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      QuicCoalesceablePacketType::Initial => write!(f, "Initial"),
      QuicCoalesceablePacketType::Handshake => write!(f, "Handshake"),
      QuicCoalesceablePacketType::ZeroRTT => write!(f, "0-RTT"),
    }
  }
}

// Check if the first byte of the packet is a coalesceable packet type
fn quick_coalesceable_packet_type(first_byte: &u8, version: &QuicVersion) -> Option<QuicCoalesceablePacketType> {
  match version {
    QuicVersion::V1 => match first_byte & 0xf0 {
      0xc0 => Some(QuicCoalesceablePacketType::Initial),
      0xd0 => Some(QuicCoalesceablePacketType::ZeroRTT),
      0xe0 => Some(QuicCoalesceablePacketType::Handshake),
      _ => None,
    },
    QuicVersion::V2 => match first_byte & 0xf0 {
      0xd0 => Some(QuicCoalesceablePacketType::Initial),
      0xe0 => Some(QuicCoalesceablePacketType::ZeroRTT),
      0xf0 => Some(QuicCoalesceablePacketType::Handshake),
      _ => None,
    },
  }
}

/// Check if the buffer contains a QUIC packet with TLS ClientHello.
/// https://www.rfc-editor.org/rfc/rfc9000.html (v1)
/// https://www.rfc-editor.org/rfc/rfc9001.html (QUIC-TLS)
/// https://www.rfc-editor.org/rfc/rfc9369.html (v2)
/// https://quic.xargs.org
/// - First checks if the buffer contains QUIC (coalsceable) packets.
/// - Then derive the header protection key and decrypt the packet.
///
/// We also have to consider coalescing packets in a single UDP datagram.
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-coalescing-packets
fn probe_quic_packets(udp_datagram: &[u8]) -> Vec<QuicPacket> {
  let mut contained_quic_packets = Vec::new();
  let mut ptr = 0;

  while ptr < udp_datagram.len() {
    // header(1), version(4), DCID length(1), SCID length(1)
    if udp_datagram[ptr..].len() < 7 {
      break;
    }

    // Packet header byte and version
    let packet_type_byte = udp_datagram[ptr];
    ptr += 1;
    // Version
    let Some(version) = quic_version(&udp_datagram[ptr..ptr + QUIC_VERSION_LEN]) else {
      debug!("Not a QUIC initial packet, possibly short header or padding, finish to parse");
      break;
    };
    ptr += QUIC_VERSION_LEN;
    // 0b1100_[0000] (version 1) 0b1101_[0000] (version 2) - Long header for initial packet type
    // with protected packet number field length ([0000])
    // omitting the protected part.
    let Some(packet_type) = quick_coalesceable_packet_type(&packet_type_byte, &version) else {
      debug!("Not a QUIC initial packet, possibly short header or padding, finish to parse");
      break;
    };
    debug!("QUIC Version: {}, Packet Type: {}", version, packet_type);

    // DCID and SCID
    let Ok((dcid, scid)) = dcid_scid(udp_datagram, &mut ptr) else {
      break;
    };

    // Token length
    let Ok(token_len) = variable_length_int(udp_datagram, &mut ptr) else {
      break;
    };
    ptr += token_len;
    if ptr >= udp_datagram.len() {
      break;
    }

    let token = udp_datagram[ptr - token_len..ptr].to_vec();
    debug!("Token: {:x?}", &token);
    // Payload length
    let Ok(payload_len) = variable_length_int(udp_datagram, &mut ptr) else {
      break;
    };

    if ptr + payload_len > udp_datagram.len() {
      debug!("Buffer too short for payload");
      break;
    }
    debug!("Payload: {:x?}", &udp_datagram[ptr..ptr + payload_len]);

    // So far, the buffer is consistent with a QUIC coalseable packet.
    // Now, try to decrypt the packet and check if it is a TLS ClientHello.
    let Ok(unprotected_result) = unprotect(&version, udp_datagram, &dcid, ptr, payload_len) else {
      debug!("invalid to unprotect payload, just continue to parse the next packet");
      ptr += payload_len;
      continue;
    };
    debug!(
      "Decrypted quic packet payload ({}): {:x?}",
      packet_type, unprotected_result.payload
    );

    let quic_packet = QuicPacket {
      version,
      packet_type,
      dcid,
      scid,
      token,
      header: unprotected_result.header,
      packet_number: unprotected_result.packet_number,
      payload: unprotected_result.payload,
    };
    contained_quic_packets.push(quic_packet);

    ptr += payload_len;
  }

  contained_quic_packets
}

/* ---------------------------------------------------- */
/// Extract CRYPTO frame from unprotected QUIC initial packet.
/// Reassemble the CRYPTO frames and check if it is a TLS ClientHello.
fn probe_quic_unprotected_frames(unprotected_payloads: &[QuicPacket]) -> Result<TlsClientHelloInfo, TlsProbeFailure> {
  // We have to consider crypto frames split into multiple packets.
  // reassemble the crypto frames and check if it is a TLS ClientHello!!

  // Parse QUIC frames of the unprotected payload in initial packet.
  let crypto_frames = match unprotected_payloads
    .iter()
    .map(|packet| extract_quic_crypto_frames(&packet.payload))
    .collect::<Result<Vec<_>, _>>()
  {
    Err(e) => {
      error!("Failed to parse QUIC frames: {:?}", e);
      return Err(TlsProbeFailure::Failure);
    }
    Ok(crypto_frames) => {
      debug!("Parsed QUIC frames: {:?}", crypto_frames);
      crypto_frames
    }
  };
  let flatten_crypto_frames = crypto_frames.into_iter().flatten().collect::<Vec<_>>();

  // Reassemble the crypto frames
  let Ok(reassemble_res) = reassemble_crypto_frames(&flatten_crypto_frames) else {
    error!("Failed to reassemble crypto frames");
    return Err(TlsProbeFailure::Failure);
  };
  let expected_client_hello = match reassemble_res {
    ReassembleResult::MissingFrames => {
      debug!("Missing frames to reassemble the QUIC crypto frames");
      return Err(TlsProbeFailure::PollNext);
    }
    ReassembleResult::CompleteFromGivenFrames(content) => content,
  };

  // Check client hello header
  let pos = 0;
  probe_tls_client_hello_header(&expected_client_hello, pos)?;

  // Check client hello body
  let Some(body_probe_res) = probe_tls_client_hello_body(&expected_client_hello, 3, 2) else {
    return Err(TlsProbeFailure::Failure);
  };

  Ok(body_probe_res)
}

/* ---------------------------------------------------- */
#[derive(Debug, Clone)]
/// Struct for CRYPTO Frame, type 0x06
struct CryptoFrame<'a> {
  frame_offset: usize,
  crypto_data_len: usize,
  crypto_data: &'a [u8],
}

/// Reassemble result
enum ReassembleResult {
  /// Reassembled crypto frames from given frames, maybe incomplete by checking the content
  CompleteFromGivenFrames(Vec<u8>),
  /// Some frames are missing to reassemble the content
  MissingFrames,
}

/// Reassemble CYRPTO frames
fn reassemble_crypto_frames(crypto_frames: &[CryptoFrame]) -> Result<ReassembleResult, anyhow::Error> {
  // First sort the crypto frames by frame_offset
  let mut sorted = crypto_frames.to_vec();
  sorted.sort_by_key(|f| f.frame_offset);

  let mut reassembled = Vec::new();
  let mut offset = 0;
  for frame in sorted {
    if frame.frame_offset > offset {
      return Ok(ReassembleResult::MissingFrames);
    }
    if frame.frame_offset < offset {
      return Err(anyhow!("Overlapping crypto frames! Invalid QUIC packet"));
    }
    reassembled.extend_from_slice(frame.crypto_data);
    offset += frame.crypto_data_len;
  }

  Ok(ReassembleResult::CompleteFromGivenFrames(reassembled))
}

/// Extract CRYPTO frames from QUIC unprotected payload of the initial packet.
/// https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2
/// Initial packet can contain CRYPTO (0x06), ACK (0x02, 0x03), PING (0x01), PADDING (0x00), and CONNECTION_CLOSE (only 0x1c).
fn extract_quic_crypto_frames(buf: &[u8]) -> Result<Vec<CryptoFrame<'_>>, anyhow::Error> {
  let mut ptr = 0;
  let mut crypto_frames = Vec::new();
  while ptr < buf.len() {
    let frame_type = buf[ptr];
    ptr += 1;
    match frame_type {
      0x06 => {
        let crypto_frame = parse_crypto_frame(buf, &mut ptr)?;
        crypto_frames.push(crypto_frame);
      }
      0x02 | 0x03 => parse_ack_frame(frame_type, buf, &mut ptr)?,
      0x1c => parse_cc_frame(buf, &mut ptr)?,
      0x01 => continue, // PING frame
      0x00 => continue, // PADDING frame
      _ => return Err(anyhow!("Prohibited frame type in initial packets: {:x}", frame_type)),
    }
  }
  Ok(crypto_frames)
}

// parse crypto frame
fn parse_crypto_frame<'a>(buf: &'a [u8], ptr: &mut usize) -> Result<CryptoFrame<'a>, anyhow::Error> {
  let frame_offset = variable_length_int(buf, ptr)?;
  let crypto_data_len = variable_length_int(buf, ptr)?;
  if *ptr + crypto_data_len > buf.len() {
    return Err(anyhow!("Buffer too short"));
  }
  let crypto_data = &buf[*ptr..*ptr + crypto_data_len];
  *ptr += crypto_data_len;

  let crypto_frame = CryptoFrame {
    frame_offset,
    crypto_data_len,
    crypto_data,
  };
  Ok(crypto_frame)
}

// parse ack frame
fn parse_ack_frame(ack_type: u8, buf: &[u8], ptr: &mut usize) -> Result<(), anyhow::Error> {
  let _largest_ack = variable_length_int(buf, ptr)?;
  let _ack_delay = variable_length_int(buf, ptr)?;
  let _ack_range_count = variable_length_int(buf, ptr)?;
  let _first_ack_range = variable_length_int(buf, ptr)?;
  for _ in 0.._ack_range_count {
    let _gap = variable_length_int(buf, ptr)?;
    let _ack_range_length = variable_length_int(buf, ptr)?;
  }
  if ack_type == 0x03 {
    let _ect01_count = variable_length_int(buf, ptr)?;
    let _ect02_count = variable_length_int(buf, ptr)?;
    let _ecn_ce_count = variable_length_int(buf, ptr)?;
  }
  Ok(())
}

// parse connection close frame
fn parse_cc_frame(buf: &[u8], ptr: &mut usize) -> Result<(), anyhow::Error> {
  let _error_code = variable_length_int(buf, ptr)?;
  if *ptr >= buf.len() {
    return Err(anyhow!("Buffer too short"));
  }
  let _frame_type = buf[*ptr];
  *ptr += 1;
  let reason_phrase_len = variable_length_int(buf, ptr)?;
  if *ptr + reason_phrase_len > buf.len() {
    return Err(anyhow!("Buffer too short"));
  }
  let _reason_phrase = &buf[*ptr..*ptr + reason_phrase_len];
  *ptr += reason_phrase_len;
  Ok(())
}

/* ---------------------------------------------------- */
use aes::{
  Aes128,
  cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use aes_gcm::{
  Aes128Gcm, Key, Nonce,
  aead::{Aead, Payload},
};
use std::{collections::HashMap, sync::LazyLock};
/// QUIC protection parameters struct
struct QuicProtectionParams<'a> {
  initial_salt: &'a [u8],
  client_in: &'a [u8],
  quic_key: &'a [u8],
  quic_iv: &'a [u8],
  quic_hp: &'a [u8],
}
/// QUIC protection parameters
static QUIC_PROTECTION_PARAMS: LazyLock<HashMap<QuicVersion, QuicProtectionParams>> = LazyLock::new(|| {
  let mut map = HashMap::new();
  map.insert(
    QuicVersion::V1,
    QuicProtectionParams {
      initial_salt: hex_literal::hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a").as_slice(),
      client_in: b"\0 \x0Ftls13 client in\0",
      quic_key: b"\0\x10\x0Etls13 quic key\0",
      quic_iv: b"\0\x0C\rtls13 quic iv\0",
      quic_hp: b"\0\x10\rtls13 quic hp\0",
    },
  );
  map.insert(
    QuicVersion::V2,
    QuicProtectionParams {
      initial_salt: hex_literal::hex!("0dede3def700a6db819381be6e269dcbf9bd2ed9").as_slice(),
      client_in: b"\0 \x0Ftls13 client in\0",
      quic_key: b"\0\x10\x10tls13 quicv2 key\0",
      quic_iv: b"\0\x0C\x0Ftls13 quicv2 iv\0",
      quic_hp: b"\0\x10\x0Ftls13 quicv2 hp\0",
    },
  );
  map
});

/// Unprotection result
struct UnprotectionResult {
  packet_number: Vec<u8>,
  header: Vec<u8>,
  payload: Vec<u8>,
}

/// Unprotect header and payload, returning the decrypted payload, i.e., expected ClientHello contained in Crypto Frame.
fn unprotect(
  version: &QuicVersion,
  buf: &[u8],
  dcid: &[u8],
  pn_offset: usize,
  payload_len: usize,
) -> Result<UnprotectionResult, anyhow::Error> {
  // Try to decrypt the protected fields
  let Ok(protection_values) = derive_initial_protection_values(version, dcid) else {
    return Err(anyhow!("Failed to derive protection values"));
  };

  // Generate mask for header protection
  let sampled_part = &buf[pn_offset + 4..pn_offset + 20];
  let mut mask = GenericArray::clone_from_slice(sampled_part);
  let hp_key = GenericArray::from_slice(protection_values.hp.as_slice());
  let cipher = Aes128::new(hp_key);
  cipher.encrypt_block(&mut mask);
  debug!("Header protection mask: {:x?}", mask);

  // Unprotect header protection
  // header protected first byte (2 LSBs (reserved fields are always unset, ignored))
  // For the initial packet, AES_128_GCM is used, and hence mask is derived by AES_ECB
  let plain_first_byte = buf[0] ^ (mask[0] & 0x0f);
  let pn_length = (plain_first_byte & 0x0f) as usize + 1;
  if payload_len < pn_length || pn_offset + pn_length > buf.len() {
    return Err(anyhow!("Payload length too short"));
  }
  debug!("Packet number length: {}", pn_length);
  let packet_number = &buf[pn_offset..pn_offset + pn_length]
    .iter()
    .zip(mask[1..pn_length + 1].iter())
    .map(|(a, b)| a ^ b)
    .collect::<Vec<u8>>();
  debug!("Packet number: {:x?}", packet_number);

  // Unprotect packet protection part
  let encrypted_payload_offset = pn_offset + pn_length;
  let encrypted_payload_length = payload_len - pn_length;
  let mut unprotected_header = buf[..encrypted_payload_offset].to_vec();
  unprotected_header[0] = plain_first_byte;
  unprotected_header[pn_offset..].copy_from_slice(packet_number);
  debug!("unprotected_header: {:x?}", unprotected_header);

  let encrypted_part = &buf[encrypted_payload_offset..encrypted_payload_offset + encrypted_payload_length];
  debug!("encrypted_part: {:x?}", encrypted_part);
  let payload = Payload {
    aad: unprotected_header.as_ref(),
    msg: encrypted_part,
  };
  let key = Key::<Aes128Gcm>::from_slice(protection_values.key.as_slice());
  let nonce = build_nonce(&protection_values.iv, packet_number);
  let nonce = Nonce::from_slice(nonce.as_slice());
  // let nonce = Nonce::from_slice(protection_values.iv.as_slice());
  let cipher = Aes128Gcm::new(key);
  let Ok(decrypted) = cipher.decrypt(nonce, payload) else {
    error!("Failed to decrypt");
    return Err(anyhow!("Failed to decrypt"));
  };

  Ok(UnprotectionResult {
    packet_number: packet_number.to_vec(),
    header: unprotected_header,
    payload: decrypted,
  })
}

/* ---------------------------------------------------- */
/// Build nonce for AES-GCM from IV and packet number.
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-sample-packet-number-decodi
/// NOTE: Since we are "stateless" for the quic connection, and the packet number is not tracked,
/// we have to assume that the largest packet number acknowledged is 0.
fn build_nonce(iv: &[u8], pn: &[u8]) -> [u8; 12] {
  let largest_pn: usize = 0;
  let pn_int = pn.iter().fold(0, |acc, &b| (acc << 8) + b as usize);
  let expected_pn = largest_pn + 1;
  let pn_win = 1 << (pn.len() * 8);
  // let pn_hwin = pn_win / 2;
  let pn_mask = pn_win - 1;

  let candidate_pn = (expected_pn & !pn_mask) | pn_int;
  let candidate_pn_buf = candidate_pn.to_be_bytes();
  debug!("Candidate packet number: {:x?}", candidate_pn_buf);

  let mut nonce = [0u8; 12];
  nonce.copy_from_slice(iv);
  nonce[12 - candidate_pn_buf.len()..]
    .iter_mut()
    .zip(&candidate_pn_buf)
    .for_each(|(a, b)| *a ^= b);

  nonce
}

/* ---------------------------------------------------- */
fn dcid_scid(buf: &[u8], ptr: &mut usize) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
  // DCID length
  let dcid_len = buf[*ptr] as usize;
  *ptr += 1 + dcid_len;
  if *ptr >= buf.len() {
    return Err(anyhow!("Buffer too short"));
  }
  let dcid = buf[*ptr - dcid_len..*ptr].to_vec();
  debug!("DCID: {:x?}", dcid);

  // SCID length
  let scid_len = buf[*ptr] as usize;
  *ptr += 1 + scid_len;
  if *ptr >= buf.len() {
    return Err(anyhow!("Buffer too short"));
  }
  let scid = buf[*ptr - scid_len..*ptr].to_vec();
  debug!("SCID: {:x?}", scid);

  Ok((dcid, scid))
}

/* ---------------------------------------------------- */
/// Packet protection values
struct ProtectionValues {
  key: [u8; 16],
  iv: [u8; 12],
  hp: [u8; 16],
}

/// Packet protection key derivation
/// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
#[inline]
fn derive_initial_protection_values(version: &QuicVersion, dcid: &[u8]) -> Result<ProtectionValues, anyhow::Error> {
  let params = QUIC_PROTECTION_PARAMS
    .get(version)
    .ok_or_else(|| anyhow!("Invalid QUIC version"))?;
  let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(params.initial_salt), dcid);
  let mut client_secret = [0u8; 32];
  if let Err(e) = hk.expand(params.client_in, &mut client_secret) {
    error!("Failed to derive client secret: {:?}", e);
    return Err(anyhow!("Failed to derive client secret"));
  }

  // Client specific key derivation below
  let Ok(hk) = hkdf::Hkdf::<sha2::Sha256>::from_prk(&client_secret) else {
    return Err(anyhow!("Failed to derive HKDF from PRK"));
  };
  let mut client_key = [0u8; 16];
  let mut client_iv = [0u8; 12];
  let mut client_hp = [0u8; 16];

  if let Err(e) = hk.expand(params.quic_key, &mut client_key) {
    error!("Failed to derive client key: {:?}", e);
    return Err(anyhow!("Failed to derive client key"));
  }
  if let Err(e) = hk.expand(params.quic_iv, &mut client_iv) {
    error!("Failed to derive client IV: {:?}", e);
    return Err(anyhow!("Failed to derive client IV"));
  }
  if let Err(e) = hk.expand(params.quic_hp, &mut client_hp) {
    error!("Failed to derive client HP: {:?}", e);
    return Err(anyhow!("Failed to derive client HP"));
  }
  Ok(ProtectionValues {
    key: client_key,
    iv: client_iv,
    hp: client_hp,
  })
}

/* ---------------------------------------------------- */

/// Variable-length integer encoding
/// https://www.rfc-editor.org/rfc/rfc9000.html#integer-encoding
#[inline]
fn variable_length_int(buf: &[u8], pos: &mut usize) -> Result<usize, anyhow::Error> {
  let two_msb = buf[*pos] >> 6;
  let len = 1 << two_msb;
  if *pos + len > buf.len() {
    debug!("buffer too short as variable-length integer");
    return Err(anyhow!("Buffer too short"));
  }
  let mut val = (buf[*pos] as usize) & 0x3f;
  *pos += 1;
  for _ in 1..len {
    val = (val << 8) + (buf[*pos] as usize);
    *pos += 1;
  }

  Ok(val)
}

/* ---------------------------------------------------- */

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_encoding_crypto_params() {
    const CLIENT_IN: &[u8] = hex_literal::hex!("00200f746c73313320636c69656e7420696e00").as_slice();
    const QUIC_KEY_V1: &[u8] = hex_literal::hex!("00100e746c7331332071756963206b657900").as_slice();
    const QUIC_IV_V1: &[u8] = hex_literal::hex!("000c0d746c733133207175696320697600").as_slice();
    const QUIC_HP_V1: &[u8] = hex_literal::hex!("00100d746c733133207175696320687000").as_slice();
    const QUIC_KEY_V2: &[u8] = hex_literal::hex!("001010746c73313320717569637632206b657900").as_slice();
    const QUIC_IV_V2: &[u8] = hex_literal::hex!("000c0f746c7331332071756963763220697600").as_slice();
    const QUIC_HP_V2: &[u8] = hex_literal::hex!("00100f746c7331332071756963763220687000").as_slice();
    let params = QUIC_PROTECTION_PARAMS.get(&QuicVersion::V1).unwrap();
    assert_eq!(params.client_in, CLIENT_IN);
    assert_eq!(params.quic_key, QUIC_KEY_V1);
    assert_eq!(params.quic_iv, QUIC_IV_V1);
    assert_eq!(params.quic_hp, QUIC_HP_V1);
    let params = QUIC_PROTECTION_PARAMS.get(&QuicVersion::V2).unwrap();
    assert_eq!(params.client_in, CLIENT_IN);
    assert_eq!(params.quic_key, QUIC_KEY_V2);
    assert_eq!(params.quic_iv, QUIC_IV_V2);
    assert_eq!(params.quic_hp, QUIC_HP_V2);
  }
  #[test]
  fn test_derive_initial_secret_v1() {
    let dcid = hex_literal::hex!("8394c8f03e515708");
    let protection_values = derive_initial_protection_values(&QuicVersion::V1, &dcid).unwrap();

    assert_eq!(protection_values.key, hex_literal::hex!("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(protection_values.iv, hex_literal::hex!("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(protection_values.hp, hex_literal::hex!("9f50449e04a0e810283a1e9933adedd2"));

    let dcid = hex_literal::hex!("0001020304050607");

    //ckey: b14b918124fda5c8d79847602fa3520b
    //civ: ddbc15dea80925a55686a7df
    //chp: 6df4e9d737cdf714711d7c617ee82981
    let protection_values = derive_initial_protection_values(&QuicVersion::V1, &dcid).unwrap();
    assert_eq!(protection_values.key, hex_literal::hex!("b14b918124fda5c8d79847602fa3520b"));
    assert_eq!(protection_values.iv, hex_literal::hex!("ddbc15dea80925a55686a7df"));
    assert_eq!(protection_values.hp, hex_literal::hex!("6df4e9d737cdf714711d7c617ee82981"));
  }

  #[test]
  fn test_derive_initial_secret_v2() {
    let dcid = hex_literal::hex!("8394c8f03e515708");
    let protection_values = derive_initial_protection_values(&QuicVersion::V2, &dcid).unwrap();

    assert_eq!(protection_values.key, hex_literal::hex!("8b1a0bc121284290a29e0971b5cd045d"));
    assert_eq!(protection_values.iv, hex_literal::hex!("91f73e2351d8fa91660e909f"));
    assert_eq!(protection_values.hp, hex_literal::hex!("45b95e15235d6f45a6b19cbcb0294ba9"));
  }

  #[test]
  fn test_variable_length_int() {
    let buf = hex_literal::hex!("c2197c5eff14e88c");
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 151_288_809_941_952_652);
    assert_eq!(pos, 8);

    let buf = hex_literal::hex!("9d7f3e7d");
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 494_878_333);

    let buf = hex_literal::hex!("7bbd");
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 15_293);

    let buf = hex_literal::hex!("25");
    let mut pos = 0;
    let val = variable_length_int(&buf, &mut pos).unwrap();
    assert_eq!(val, 37);
  }

  #[test]
  fn test_decrypt_v1() {
    use aes_gcm::{
      Aes128Gcm, Key, KeyInit, Nonce,
      aead::{Aead, Payload},
    };
    let plaintext = [
      0x06, 0x00, 0x40, 0xee, 0x01, 0x00, 0x00, 0xea, 0x03, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
      0x1e, 0x1f, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0xbb, 0x00, 0x00, 0x00, 0x18, 0x00,
      0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e,
      0x6e, 0x65, 0x74, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x0b, 0x00,
      0x09, 0x08, 0x70, 0x69, 0x6e, 0x67, 0x2f, 0x31, 0x2e, 0x30, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04,
      0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
      0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
      0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54, 0x00, 0x2d, 0x00, 0x02,
      0x01, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x39, 0x00, 0x31, 0x03, 0x04, 0x80, 0x00, 0xff, 0xf7, 0x04,
      0x04, 0x80, 0xa0, 0x00, 0x00, 0x05, 0x04, 0x80, 0x10, 0x00, 0x00, 0x06, 0x04, 0x80, 0x10, 0x00, 0x00, 0x07, 0x04, 0x80,
      0x10, 0x00, 0x00, 0x08, 0x01, 0x0a, 0x09, 0x01, 0x0a, 0x0a, 0x01, 0x03, 0x0b, 0x01, 0x19, 0x0f, 0x05, 0x63, 0x5f, 0x63,
      0x69, 0x64,
    ];
    let unprotected_header = [
      0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x05, 0x63, 0x5f, 0x63, 0x69, 0x64,
      0x00, 0x41, 0x03, 0x00,
    ];
    let ciphertext = [
      0x1c, 0x36, 0xa7, 0xed, 0x78, 0x71, 0x6b, 0xe9, 0x71, 0x1b, 0xa4, 0x98, 0xb7, 0xed, 0x86, 0x84, 0x43, 0xbb, 0x2e, 0x0c,
      0x51, 0x4d, 0x4d, 0x84, 0x8e, 0xad, 0xcc, 0x7a, 0x00, 0xd2, 0x5c, 0xe9, 0xf9, 0xaf, 0xa4, 0x83, 0x97, 0x80, 0x88, 0xde,
      0x83, 0x6b, 0xe6, 0x8c, 0x0b, 0x32, 0xa2, 0x45, 0x95, 0xd7, 0x81, 0x3e, 0xa5, 0x41, 0x4a, 0x91, 0x99, 0x32, 0x9a, 0x6d,
      0x9f, 0x7f, 0x76, 0x0d, 0xd8, 0xbb, 0x24, 0x9b, 0xf3, 0xf5, 0x3d, 0x9a, 0x77, 0xfb, 0xb7, 0xb3, 0x95, 0xb8, 0xd6, 0x6d,
      0x78, 0x79, 0xa5, 0x1f, 0xe5, 0x9e, 0xf9, 0x60, 0x1f, 0x79, 0x99, 0x8e, 0xb3, 0x56, 0x8e, 0x1f, 0xdc, 0x78, 0x9f, 0x64,
      0x0a, 0xca, 0xb3, 0x85, 0x8a, 0x82, 0xef, 0x29, 0x30, 0xfa, 0x5c, 0xe1, 0x4b, 0x5b, 0x9e, 0xa0, 0xbd, 0xb2, 0x9f, 0x45,
      0x72, 0xda, 0x85, 0xaa, 0x3d, 0xef, 0x39, 0xb7, 0xef, 0xaf, 0xff, 0xa0, 0x74, 0xb9, 0x26, 0x70, 0x70, 0xd5, 0x0b, 0x5d,
      0x07, 0x84, 0x2e, 0x49, 0xbb, 0xa3, 0xbc, 0x78, 0x7f, 0xf2, 0x95, 0xd6, 0xae, 0x3b, 0x51, 0x43, 0x05, 0xf1, 0x02, 0xaf,
      0xe5, 0xa0, 0x47, 0xb3, 0xfb, 0x4c, 0x99, 0xeb, 0x92, 0xa2, 0x74, 0xd2, 0x44, 0xd6, 0x04, 0x92, 0xc0, 0xe2, 0xe6, 0xe2,
      0x12, 0xce, 0xf0, 0xf9, 0xe3, 0xf6, 0x2e, 0xfd, 0x09, 0x55, 0xe7, 0x1c, 0x76, 0x8a, 0xa6, 0xbb, 0x3c, 0xd8, 0x0b, 0xbb,
      0x37, 0x55, 0xc8, 0xb7, 0xeb, 0xee, 0x32, 0x71, 0x2f, 0x40, 0xf2, 0x24, 0x51, 0x19, 0x48, 0x70, 0x21, 0xb4, 0xb8, 0x4e,
      0x15, 0x65, 0xe3, 0xca, 0x31, 0x96, 0x7a, 0xc8, 0x60, 0x4d, 0x40, 0x32, 0x17, 0x0d, 0xec, 0x28, 0x0a, 0xee, 0xfa, 0x09,
      0x5d, 0x08, 0xb3, 0xb7, 0x24, 0x1e, 0xf6, 0x64, 0x6a, 0x6c, 0x86, 0xe5, 0xc6, 0x2c, 0xe0, 0x8b, 0xe0, 0x99,
    ];
    let key = [
      0xb1, 0x4b, 0x91, 0x81, 0x24, 0xfd, 0xa5, 0xc8, 0xd7, 0x98, 0x47, 0x60, 0x2f, 0xa3, 0x52, 0x0b,
    ];
    let iv = [0xdd, 0xbc, 0x15, 0xde, 0xa8, 0x09, 0x25, 0xa5, 0x56, 0x86, 0xa7, 0xdf];

    let key = Key::<Aes128Gcm>::from_slice(key.as_slice());
    let iv = Nonce::from_slice(iv.as_slice());
    let cipher = Aes128Gcm::new(key);
    let decrypted = cipher
      .decrypt(
        iv,
        Payload {
          aad: unprotected_header.as_ref(),
          msg: ciphertext.as_ref(),
        },
      )
      .unwrap();

    assert_eq!(decrypted, plaintext);
  }

  #[test]
  fn test_probe_v1() {
    let quic_packet = hex_literal::hex!(
      "
      c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
      d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
      1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
      8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
      30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
      457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
      4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
      4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
      485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
      059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
      7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
      9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
      be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
      68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
      c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
      f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
      291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
      25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
      14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
      ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
      e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
      c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
      203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
      cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
      fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
      a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
      90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
      162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
      40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
      6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
      8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
      be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
      54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
      760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
      f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
      056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
      7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
      e221af44860018ab0856972e194cd934
      "
    );
    let unprotected_payload = hex_literal::hex!(
      "
      060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
      04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
      616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
      04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
      baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
      0d0010000e0403050306030203080408 050806002d00020101001c0002400100
      3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
      75300901100f088394c8f03e51570806 048000ffff
      "
    );
    let unprotected_header = hex_literal::hex!("c300000001088394c8f03e5157080000449e00000002");
    let res = probe_quic_packets(&quic_packet);
    assert_eq!(res[0].version, QuicVersion::V1);
    assert_eq!(res[0].packet_type, QuicCoalesceablePacketType::Initial);
    assert_eq!(res[0].header, unprotected_header);
    assert_eq!(res[0].packet_number, hex_literal::hex!("00000002"));
    assert!(res[0].payload.starts_with(&unprotected_payload));
  }

  #[test]
  fn test_probe_v2() {
    let quic_packet = hex_literal::hex!(
      "
      d76b3343cf088394c8f03e5157080000 449ea0c95e82ffe67b6abcdb4298b485
      dd04de806071bf03dceebfa162e75d6c 96058bdbfb127cdfcbf903388e99ad04
      9f9a3dd4425ae4d0992cfff18ecf0fdb 5a842d09747052f17ac2053d21f57c5d
      250f2c4f0e0202b70785b7946e992e58 a59ac52dea6774d4f03b55545243cf1a
      12834e3f249a78d395e0d18f4d766004 f1a2674802a747eaa901c3f10cda5500
      cb9122faa9f1df66c392079a1b40f0de 1c6054196a11cbea40afb6ef5253cd68
      18f6625efce3b6def6ba7e4b37a40f77 32e093daa7d52190935b8da58976ff33
      12ae50b187c1433c0f028edcc4c2838b 6a9bfc226ca4b4530e7a4ccee1bfa2a3
      d396ae5a3fb512384b2fdd851f784a65 e03f2c4fbe11a53c7777c023462239dd
      6f7521a3f6c7d5dd3ec9b3f233773d4b 46d23cc375eb198c63301c21801f6520
      bcfb7966fc49b393f0061d974a2706df 8c4a9449f11d7f3d2dcbb90c6b877045
      636e7c0c0fe4eb0f697545460c806910 d2c355f1d253bc9d2452aaa549e27a1f
      ac7cf4ed77f322e8fa894b6a83810a34 b361901751a6f5eb65a0326e07de7c12
      16ccce2d0193f958bb3850a833f7ae43 2b65bc5a53975c155aa4bcb4f7b2c4e5
      4df16efaf6ddea94e2c50b4cd1dfe060 17e0e9d02900cffe1935e0491d77ffb4
      fdf85290fdd893d577b1131a610ef6a5 c32b2ee0293617a37cbb08b847741c3b
      8017c25ca9052ca1079d8b78aebd4787 6d330a30f6a8c6d61dd1ab5589329de7
      14d19d61370f8149748c72f132f0fc99 f34d766c6938597040d8f9e2bb522ff9
      9c63a344d6a2ae8aa8e51b7b90a4a806 105fcbca31506c446151adfeceb51b91
      abfe43960977c87471cf9ad4074d30e1 0d6a7f03c63bd5d4317f68ff325ba3bd
      80bf4dc8b52a0ba031758022eb025cdd 770b44d6d6cf0670f4e990b22347a7db
      848265e3e5eb72dfe8299ad7481a4083 22cac55786e52f633b2fb6b614eaed18
      d703dd84045a274ae8bfa73379661388 d6991fe39b0d93debb41700b41f90a15
      c4d526250235ddcd6776fc77bc97e7a4 17ebcb31600d01e57f32162a8560cacc
      7e27a096d37a1a86952ec71bd89a3e9a 30a2a26162984d7740f81193e8238e61
      f6b5b984d4d3dfa033c1bb7e4f0037fe bf406d91c0dccf32acf423cfa1e70710
      10d3f270121b493ce85054ef58bada42 310138fe081adb04e2bd901f2f13458b
      3d6758158197107c14ebb193230cd115 7380aa79cae1374a7c1e5bbcb80ee23e
      06ebfde206bfb0fcbc0edc4ebec30966 1bdd908d532eb0c6adc38b7ca7331dce
      8dfce39ab71e7c32d318d136b6100671 a1ae6a6600e3899f31f0eed19e3417d1
      34b90c9058f8632c798d4490da498730 7cba922d61c39805d072b589bd52fdf1
      e86215c2d54e6670e07383a27bbffb5a ddf47d66aa85a0c6f9f32e59d85a44dd
      5d3b22dc2be80919b490437ae4f36a0a e55edf1d0b5cb4e9a3ecabee93dfc6e3
      8d209d0fa6536d27a5d6fbb17641cde2 7525d61093f1b28072d111b2b4ae5f89
      d5974ee12e5cf7d5da4d6a31123041f3 3e61407e76cffcdcfd7e19ba58cf4b53
      6f4c4938ae79324dc402894b44faf8af bab35282ab659d13c93f70412e85cb19
      9a37ddec600545473cfb5a05e08d0b20 9973b2172b4d21fb69745a262ccde96b
      a18b2faa745b6fe189cf772a9f84cbfc
      "
    );
    let unprotected_payload = hex_literal::hex!(
      "
      060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
      04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
      616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
      04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
      baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
      0d0010000e0403050306030203080408 050806002d00020101001c0002400100
      3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
      75300901100f088394c8f03e51570806 048000ffff
      "
    );
    let unprotected_header = hex_literal::hex!("d36b3343cf088394c8f03e5157080000449e00000002");
    let res = probe_quic_packets(&quic_packet);
    assert_eq!(res[0].version, QuicVersion::V2);
    assert_eq!(res[0].packet_type, QuicCoalesceablePacketType::Initial);
    assert_eq!(res[0].header, unprotected_header);
    assert_eq!(res[0].packet_number, hex_literal::hex!("00000002"));
    assert!(res[0].payload.starts_with(&unprotected_payload));
  }

  #[test]
  fn test_pn() {
    let largest_pn: usize = 0xa82f30ea;
    let truncated_pn = [0x9b, 0x32];
    let truncated_pn_int = truncated_pn.iter().fold(0, |acc, &b| (acc << 8) + b as usize);
    let expected_pn = largest_pn + 1;
    let pn_win = 1 << (truncated_pn.len() * 8);
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    println!("pn_win: {:x?}, pn_hwin: {:x?}, pn_mask: {:x?}", pn_win, pn_hwin, pn_mask);
    println!("!pn_mask: {:x?}", !pn_mask);

    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn_int;
    println!("candidate_pn: {:x?}", candidate_pn);
    let candidate_pn_buf = candidate_pn.to_be_bytes();
    println!("candidate_pn_bu: {:x?}", candidate_pn_buf);
  }
}
