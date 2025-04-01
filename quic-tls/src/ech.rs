use crate::{client_hello::TlsClientHello, error::TlsClientHelloError, serialize::compose};
use bytes::Bytes;

/// Build aad from incoming TLS ClientHello for ECH decryption
/// As indicated in https://www.ietf.org/archive/id/draft-ietf-tls-esni-24.html#section-5.2,
/// the aad is serialized TLS ClientHello which matches the ClientHelloOuter except that the payload field of the "encrypted_client_hello" is replaced with a byte string of the same length but whose contents are zeros.
pub(crate) fn build_aad(client_hello: &TlsClientHello) -> Result<Bytes, TlsClientHelloError> {
  let mut cloned = client_hello.clone();
  cloned.fill_ech_payload_with_zeros();
  let aad = compose(cloned)?.freeze();
  Ok(aad)
}

///////////////////////////////////
// TODO: REMOVE LATER, JUST FOR PROOF OF CONCEPT
use crate::{ech_config::EchConfigList, ech_extension::ClientHelloOuter, serialize::parse};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use hpke::{Deserializable, Kem, OpModeR, aead::Aead, aead::AesGcm128, kdf::HkdfSha256, kdf::Kdf, kem::X25519HkdfSha256};
pub(crate) fn decrypt_ech(client_hello: &TlsClientHello) {
  let Some(outer) = client_hello.get_ech_outer() else {
    return;
  };

  let aad = build_aad(client_hello).unwrap();
  println!("AAD: {:?}", aad.clone().to_vec());

  const ECH_SECRET_KEY: &str = "pLNPBNTitfdij7QQznqFbnNxPyorRN2ZARSWWpYOBDY";
  // const ECH_PUBLIC_KEY: &str = "rY0SPwP8yflbYTUHTNcX/RWC/oy+qAi2ZcM62nwLVXU";
  const ECH_CONFIG_LIST: &str =
    "AE3+DQBJAAAgACCtjRI/A/zJ+VthNQdM1xf9FYL+jL6oCLZlwzrafAtVdQAEAAEAAQAabXktcHVibGljLW5hbWUuZXhhbXBsZS5jb20AAA";

  let sk_bytes = BASE64_STANDARD_NO_PAD.decode(ECH_SECRET_KEY).unwrap();
  let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&sk_bytes).unwrap();
  let config_list_bytes = BASE64_STANDARD_NO_PAD.decode(ECH_CONFIG_LIST).unwrap();
  let deser_config_list: EchConfigList = parse(&mut config_list_bytes.as_slice()).unwrap();
  let ech_config = deser_config_list.into_iter().next().unwrap();
  let config_bytes = compose(&ech_config).unwrap().freeze();

  let enc_clone = outer.enc.clone();
  println!("enc: {:?}", enc_clone.clone().to_vec());
  println!("sk: {:?}", BASE64_STANDARD_NO_PAD.decode(ECH_SECRET_KEY).unwrap());
  let payload_clone = outer.payload.clone();
  let encapped_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc_clone).unwrap();
  let mut info = bytes::BytesMut::new();
  info.extend_from_slice(b"tls ech\0");
  info.extend_from_slice(&config_bytes);
  let mut ctx: hpke::aead::AeadCtxR<AesGcm128, HkdfSha256, X25519HkdfSha256> =
    hpke::setup_receiver(&OpModeR::Base, &sk, &encapped_key, &info).unwrap();

  let encoded_client_hello_inner = ctx.open(&payload_clone, &aad).unwrap();
  println!("encoded_client_hello_inner: {:x?}", encoded_client_hello_inner);

  let client_hello_inner: TlsClientHello = parse(&mut encoded_client_hello_inner.as_slice()).unwrap();
  println!("client_hello_inner: {:#?}", client_hello_inner);

  // ///////////////////////////////////
}
