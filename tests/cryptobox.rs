
mod common;
use aead::consts::{U24, U56};
//use common::PredictableRng;

//use aead::{AeadCore, AeadInOut, KeyInit, KeySizeUser};
use crypto_secretbox::XSalsa20Poly1305;
use hex_literal::hex;

use kems::{kem_with_kdf::{CombinerAllPubKeys, KemWithKdf}};
use kems::{eckem::SeedAsScalar};
use kdfs::misc::CryptoBoxKdf;

use kems::{x25519kem::X25519Capsulator};
use ies::{IesWithDerivedIv, Ies};

//use typenum::{U24, U56};
use x25519_dalek::{PublicKey, StaticSecret};

// Ecies which uses a wrapped version of XSalsa20Poly1305 so that we can implement the new RustCrypto AEAD traits
//type EciesSodiumX255192      = IesWithDerivedIv<X25519Capsulator<EcCombinerAllPubKeys<CryptoBoxKdf<blake2::Blake2b::<U24>>>, U56,SeedAsScalar>, XSalsa20Poly1305Wrapper>;
type EciesSodiumX255192      = IesWithDerivedIv<KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, CryptoBoxKdf<blake2::Blake2b::<U24>>, U56>, XSalsa20Poly1305Wrapper>;

struct XSalsa20Poly1305Wrapper ( XSalsa20Poly1305 );

impl aead::AeadCore for XSalsa20Poly1305Wrapper {
    type NonceSize = <XSalsa20Poly1305 as crypto_secretbox::AeadCore>::NonceSize;
    type TagSize = <XSalsa20Poly1305 as crypto_secretbox::AeadCore>::TagSize;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix; 
}
impl aead::KeySizeUser for XSalsa20Poly1305Wrapper
{
    type KeySize = <XSalsa20Poly1305 as crypto_secretbox::KeySizeUser>::KeySize;
}

impl aead::KeyInit for XSalsa20Poly1305Wrapper
{
    fn new(key: &aead::Key<Self>) -> Self {
        let key = generic_array_old::GenericArray::from_slice(&key);
        let encryptor = <XSalsa20Poly1305 as crypto_secretbox::KeyInit>::new(key);
        Self(encryptor)
    }
}
impl aead::AeadInOut for XSalsa20Poly1305Wrapper {
    fn decrypt_in_place(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut dyn aead::Buffer,
        ) -> aead::Result<()> {
        let nonce = generic_array_old::GenericArray::from_slice(&nonce);
        //let nonce = &nonce.from().unwrap();
        let mut buffer2 = buffer.as_ref().to_vec();

        <XSalsa20Poly1305 as crypto_secretbox::AeadInPlace>::decrypt_in_place(&self.0, nonce, associated_data, &mut buffer2).map_err(|_e|aead::Error)?;
        buffer.truncate(0);
        buffer.extend_from_slice(&buffer2).unwrap();
        Ok(())
    }
    fn decrypt_inout_detached(
            &self,
            _nonce: &aead::Nonce<Self>,
            _associated_data: &[u8],
            _buffer: cipher::InOutBuf<'_, '_, u8>,
            _tag: &aead::Tag<Self>,
        ) -> aead::Result<()> {
        todo!()
    }
    fn encrypt_in_place(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut dyn aead::Buffer,
        ) -> aead::Result<()> {
        let nonce = generic_array_old::GenericArray::from_slice(&nonce);
        let mut buffer2 = buffer.as_ref().to_vec();
        <XSalsa20Poly1305 as crypto_secretbox::AeadInPlace>::encrypt_in_place(&self.0, nonce, associated_data, &mut buffer2).map_err(|_e|aead::Error)?;
        buffer.truncate(0);
        buffer.extend_from_slice(&buffer2).unwrap();
        Ok(())
    }
    fn encrypt_inout_detached(
            &self,
            _nonce: &aead::Nonce<Self>,
            _associated_data: &[u8],
            _buffer: cipher::InOutBuf<'_, '_, u8>,
        ) -> aead::Result<aead::Tag<Self>> {
        todo!()
    }
}


//
// Example  - crypto_secretbox hasn't been updated to use Array
// 
#[test]
#[allow(non_snake_case, unused)]
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
   
    //let decryptor = EciesDecryptionSodiumX25519::new(skRm2);
    let decryptor = EciesSodiumX255192::from_key_decap(skRm2);

    let result = decryptor.open(ciphertext.as_ref()).unwrap();
    assert!( result == plaintext);

}




#[test]
#[allow(non_snake_case, unused)]
fn nacl_sample_2 ()
{
    let pkSm = hex!("0f198520f26d05cb81127d057ac4f21fa389e9d4cb6e20ed7bd162e9d32f9603");
    let skSm = hex!("b468a31dcb7aa57428c6431290ee6bcfc16ea39d4ed85aff19dc8b0ac2b03ea2");
    let pkRm = hex!("08886442c7c60da6eef2a88cd11abac11bbf3badde3c8a602908cb516c99513b");
    let skRm = hex!("1a75a1ead5d1a5c108115d2f3a542fd23ad89297af96b2d3f67960ed29da4033");

    //let key = hex!("c9940f375b49873d5bf2692c0b82efeae6e680d87004302eaacd4789d68ccf94");
    let plaintext = b"Message";
    let pkRm2 = PublicKey::from(pkRm);
    let skRm2 = StaticSecret::from(skRm);


    // let encryptor = EciesEncryptionSodiumX25519::default();
    //let mut pred_rng = PredictableRng::new(&skSm);
    
    //let encrypted_result = encryptor.seal2(&mut pred_rng, &pkRm2, plaintext.as_slice()).unwrap();
    // println! ( "encrypted_result={:X?}", encrypted_result);


    let encryptor = EciesSodiumX255192::from_key_encap(pkRm2);
    //let encrypted_result = encryptor.seal(&mut pred_rng, plaintext.as_slice()).unwrap();
    let encrypted_result = encryptor.seal_deterministic(&skRm.into(), plaintext.as_slice()).unwrap();

   

    // let decryptor = EciesDecryptionSodiumX25519::new(skRm2.clone());
    // let decrypted_result = decryptor.try_open2(encrypted_result.as_ref()).unwrap();
    // assert!( decrypted_result == plaintext);
    

    let decryptor = EciesSodiumX255192::from_key_decap(skRm2);
    let decrypted_result = decryptor.open(encrypted_result.as_ref()).unwrap();
    assert!( decrypted_result == plaintext);
}
