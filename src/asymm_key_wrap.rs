//!
//! This struct combines a KEM with a symmetric key encryption such that the originator
//! is able to select the key to be transported. 
//! This mechanisms is used by JWE, CMS and other formats
//! 
//! 

// use std::marker::PhantomData;
// use aead::{consts::U16, Error, KeyInit};
// use aes_kw::Kek;
// use cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser};
// use kem::{Decapsulator, EncappedKey, Encapsulator};
// use rand_core::{CryptoRng, RngCore};
// use crate::Capsulator;


// pub struct AsymmKeyWrapUsingEncapsulatorAndAesKw<EK: EncappedKey, E, A>
//     where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt
// {
//     encap: E,
//     phantom: PhantomData<EK>,
//     phantom2: PhantomData<A>
// }



// impl<EK: EncappedKey, E, A> AsymmKeyWrapUsingEncapsulatorAndAesKw<EK, E,A> 
// where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
//     E: Capsulator,
// {
//     pub fn new_wrapper ( encap: E::Encapsulator ) -> AsymmKeyWrapUsingEncapsulatorAndAesKw<EK, E::Encapsulator, A>
//     {
//         AsymmKeyWrapUsingEncapsulatorAndAesKw{encap, phantom: PhantomData, phantom2: PhantomData }
//     }
//     pub fn new_unwrapper ( encap: E::Decapsulator ) -> AsymmKeyWrapUsingEncapsulatorAndAesKw<EK, E::Decapsulator, A>
//     {
//         AsymmKeyWrapUsingEncapsulatorAndAesKw{encap, phantom: PhantomData, phantom2: PhantomData }
//     }
// }

// impl<EK: EncappedKey, E, A> AsymmKeyWrapUsingEncapsulatorAndAesKw<EK, E,A> 
// where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt
// {
//     pub fn unwrap_from_components ( self, encapsulated_key: &[u8], encrypted_key: &[u8] ) -> Result<Vec<u8>, Error> 
//     where E: Decapsulator<EK>
//     {
//         let typed_encapsulated_key = EK::from_bytes(encapsulated_key.into()).map_err(|_v|aead::Error)?;
//         let derived_key = self.encap.try_decap(&typed_encapsulated_key).map_err(|_v|aead::Error)?;
//         let decryptor = Kek::<A>::try_from(derived_key.as_bytes()).map_err(|_v|aead::Error)?;
//         decryptor.unwrap_vec(encrypted_key).map_err(|_v|aead::Error)
//     }
    
//     pub fn wrap_from_components<R: CryptoRng + RngCore> ( self, csprng: &mut R, recip_pubkey: &<EK as EncappedKey>::RecipientPublicKey, key_to_wrap: &[u8] )
//       -> Result<(EK, Vec<u8>), kem::Error>
//     where E: Encapsulator<EK>
//     {
//         let (ek, ss) = E::try_encap(&self.encap, csprng, recip_pubkey).unwrap();
//         let encryptor = Kek::<A>::try_from(ss.as_bytes()).unwrap();
//         let wrapped_key = encryptor.wrap_vec(&key_to_wrap).unwrap();
//         Ok((ek, wrapped_key))
//     }
// }
