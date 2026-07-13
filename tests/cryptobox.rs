
mod common;
#[allow(unused)]
use hex_literal::hex;
#[cfg(all(feature = "rustcrypto-secretbox"))]
use ies::{Ies, ies_types::EciesSodiumX255192};
#[allow(unused)]
use x25519_dalek::{PublicKey, StaticSecret};

//
// Example  - crypto_secretbox hasn't been updated to use Array
// 
#[test]
#[allow(non_snake_case, unused)]
#[cfg(all(feature = "rustcrypto-secretbox"))]
fn nacl_sample_1 ()
{
    let pkRm = hex!("24a9378a8a88e6b0f3ec10ee111ac7275334728dd416ad7c650050fdc15daa1a");
    let skRm = hex!("8886278a5ad880c6a1c3a8523ebdc3510cb8bb969e8a573684f9f1f474aedc10");
    let key = hex!("c9940f375b49873d5bf2692c0b82efeae6e680d87004302eaacd4789d68ccf94");
    let plaintext = b"Message";
    let ciphertext = hex!("3448d7f6242993174930f95ea61f9c53b6fc657f1a6bdac68e29692d6d7fa76bb00a296f14f37d29524f6cfc3272a1e3d53fdb6dfdb513");

    let pkRm2 = PublicKey::from(pkRm);
    let skRm2 = StaticSecret::from(skRm);
    assert! ( pkRm2 == PublicKey::from(&skRm2));
   
    let decryptor = EciesSodiumX255192::from_key_decap(skRm2);

    let result = decryptor.open(ciphertext.as_ref()).unwrap();
    assert!( result == plaintext);

}




#[test]
#[allow(non_snake_case, unused)]
#[cfg(all(feature = "rustcrypto-secretbox"))]
fn nacl_sample_2 ()
{
    let pkSm = hex!("0f198520f26d05cb81127d057ac4f21fa389e9d4cb6e20ed7bd162e9d32f9603");
    let skSm = hex!("b468a31dcb7aa57428c6431290ee6bcfc16ea39d4ed85aff19dc8b0ac2b03ea2");
    let pkRm = hex!("08886442c7c60da6eef2a88cd11abac11bbf3badde3c8a602908cb516c99513b");
    let skRm = hex!("1a75a1ead5d1a5c108115d2f3a542fd23ad89297af96b2d3f67960ed29da4033");

    let plaintext = b"Message";
    let pkRm2 = PublicKey::from(pkRm);
    let skRm2 = StaticSecret::from(skRm);

    let encryptor = EciesSodiumX255192::from_key_encap(pkRm2);
    let encrypted_result = encryptor.seal_deterministic(&skRm.into(), plaintext.as_slice()).unwrap();

    let decryptor = EciesSodiumX255192::from_key_decap(skRm2);
    let decrypted_result = decryptor.open(encrypted_result.as_ref()).unwrap();
    assert!( decrypted_result == plaintext);
}
