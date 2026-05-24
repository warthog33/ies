//!
//! Integrated Encryption Scheme, also known as hybrid encryption in ISO 18033-2
//! 
//! Two types of IES are implemented
//!  - SimpleIes - A basic structure defined in ISO 18033-2 which is composed of a Key Encapsulation Mechanism (KEM) and an Authentication Encryption with Associated Data (AEAD) algorithm.
//!  - Hpke - Implementation of the hybrid public key encryption algorithm specified in RFC 9180. Is composed of a Key Encapsulation Mechanism (KEM), Key Derivation Function (KDF) 
//!         and an Authenticated Encryption with Associated Data (AEAD) algorithm
//! 
//! For each type there are a number of common variants depending upon the KEM, KDF and AEAD algorithm used. 
//! Types for many of these variants have been created. As these types use a concrete reference to an implementation they
//! are gated by configuration features.
//! 
//! # Example 
//! The following example requires features rustcrypto-sha2 and rustcrypto-aes
//! ```
//! use p256::{SecretKey, elliptic_curve::Generate};
//! use kems::OsRng;
//! use ies::ies_types::EciesStandardX963SHA256AESGCM;
//! use ies::Ies;
//! 
//! let recipient_secret_key = SecretKey::generate();
//! let recipient_public_key = recipient_secret_key.public_key();
//! let plaintext_message = b"Hello World!";
//! 
//! let encryptor = EciesStandardX963SHA256AESGCM::from_key_encap(recipient_public_key);
//! let ciphertext = encryptor.seal ( &mut OsRng, plaintext_message.as_ref()).unwrap();
//! 
//! let decryptor = EciesStandardX963SHA256AESGCM::from_key_decap(recipient_secret_key);
//! let recovered_plaintext = decryptor.open ( ciphertext.as_ref() );
//! assert! ( recovered_plaintext.unwrap() == plaintext_message );
//! ```

use std::{marker::PhantomData, ops::{Add, Rem, Sub}};
use std::array::TryFromSliceError;

use aead::{consts::{U8,U16}, Aead, KeyInit, Payload, Tag, Nonce};
use aes_kw::AesKw;
use cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeySizeUser, typenum::{Zero, Unsigned}};
//use elliptic_curve::rand_core::{CryptoRng, RngCore};
//use generic_array::{GenericArray, ArrayLength};

use kdfs::hybrid_array::ArraySize;
use kems::{Decapsulate, Encapsulate, EncapsulateDeterministic2, EncapsulateWithKeyWrapDeterministic};
use kems::{Capsulator, DecapsulateWithKeyWrap, EncapsulateWithKeyWrap, FromKey, GenerateCapsulatorFromSeed, SetKdf, generic_array::typenum::{NonZero, Sum}};
use kems::generic_array::{GenericArray, ArrayLength};
//use typenum::{NonZero, Sum, Unsigned, Zero, U8};
use kems::{CryptoRngCore,CryptoRng,RngCore};
//use rand::CryptoRng;


pub mod ies_types;
pub mod encrypt_then_mac;
pub mod hash_encrypt;
pub mod asymm_key_wrap;

#[derive(Debug)]
pub enum Error 
{
    AeadError,
    KemError,
    KeyError,
    LenError,
    TryFromSliceError,
    EllipticCurveError,
}
impl From<aead::Error> for Error {
    fn from(_err: aead::Error) -> Error {
        return Error::AeadError;
    }
}
// impl From<kem::Error> for Error {
//     fn from(_err: kem::Error) -> Error {
//         return Error::KemError;
//     }
// }
impl From<TryFromSliceError> for Error {
    fn from(_value: TryFromSliceError) -> Self {
        return Error::TryFromSliceError;
    }
}
// impl From<elliptic_curve::Error> for Error {
//     fn from(_value: elliptic_curve::Error) -> Self {
//         return Error::EllipticCurveError;
//     }
// }


#[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-sha2", feature="rustcrypto-hmac", feature="rustcrypto-cbc"))]
pub mod rfc7518 
{
    use aes::{Aes128, Aes192, Aes256};
    use sha2::{Sha256, Sha512, Sha384};
    use hmac::Hmac;
    use cipher::inout::block_padding::Pkcs7;
    use crate::encrypt_then_mac::EncryptThenMac;

    pub type A128CbcHS256 = EncryptThenMac<cbc::Encryptor<Aes128>, cbc::Decryptor<Aes128>, Hmac<Sha256>, Pkcs7>;
    pub type A192CbcHS384 = EncryptThenMac<cbc::Encryptor<Aes192>, cbc::Decryptor<Aes192>, Hmac<Sha384>, Pkcs7>;
    pub type A256CbcHS512 = EncryptThenMac<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Hmac<Sha512>, Pkcs7>;
}

pub mod cms
{
    #[allow(unused)]
    use aead::consts::U12;
    // Used in CMS, openssl uses is
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    use aes::{Aes128, Aes192, Aes256};
    #[allow(unused)]
    use const_oid::db::rfc5911::{ID_AES_128_CBC, ID_AES_192_CBC, ID_AES_256_CBC, DES_EDE_3_CBC};
    #[allow(unused)]
    use const_oid::{ObjectIdentifier, AssociatedOid};
    //use der::oid::{db::rfc5911::{ID_AES_128_CBC, ID_AES_192_CBC, ID_AES_256_CBC, DES_EDE_3_CBC}, AssociatedOid, ObjectIdentifier};
    #[allow(unused)]
    use crate::encrypt_then_mac::EncryptNoMac;
    #[allow(unused)]
    use cipher::inout::block_padding::Pkcs7;

    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    pub type A128CbcNoMac = EncryptNoMac<cbc::Encryptor<Aes128>, cbc::Decryptor<Aes128>, Pkcs7>;
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    impl AssociatedOid for A128CbcNoMac { const OID: ObjectIdentifier = ID_AES_128_CBC; }
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    pub type A192CbcNoMac = EncryptNoMac<cbc::Encryptor<Aes192>, cbc::Decryptor<Aes192>, Pkcs7>;
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    impl AssociatedOid for A192CbcNoMac { const OID: ObjectIdentifier = ID_AES_192_CBC; }
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    pub type A256CbcNoMac = EncryptNoMac<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Pkcs7>;
    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    impl AssociatedOid for A256CbcNoMac { const OID: ObjectIdentifier = ID_AES_256_CBC; }
    #[cfg(all(feature = "rustcrypto-des"))]
    pub type TdesCbcNoMac = EncryptNoMac<cbc::Encryptor<des::TdesEde3>, cbc::Decryptor<des::TdesEde3>, Pkcs7>;
    #[cfg(all(feature = "rustcrypto-des"))]
    impl AssociatedOid for TdesCbcNoMac { const OID: ObjectIdentifier = DES_EDE_3_CBC; }

    #[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-cbc"))]
    pub type A128Gcm = aes_gcm::AesGcm<Aes128, U12>;
    //impl AssociatedOid for A128Gcm { const OID: ObjectIdentifier = ID_AES_128_GCM }; // Can't do this becauase the trait and type are outside this crate

    //pub type A128OfbNoMac = EncryptNoMac<ofb::Encryptor<Aes128, ofb::Decryptor<Aes128>, Pkcs7>;
    pub const ID_AES_128_OFB: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.3");
    pub const ID_AES_128_OFB_NEW: spki_new::ObjectIdentifier = spki_new::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.3");

    //pub const DH_SINGLE_PASS_STD_DH_SHA256KDF_SCHEME_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.1");
    //pub const DH_SINGLE_PASS_STD_DH_SHA512KDF_SCHEME_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.11.3");
    pub const KDF_FOR_ML_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");
    pub const KDF_FOR_ML_KEM_NEW: spki_new::ObjectIdentifier = spki_new::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.28");
    pub const OID_ML_KEM_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");

    
} 



pub trait Ies<C: Capsulator> 
{
    type Encryptor: FromKey<Key = C::Encapsulator>;
    type Decryptor: FromKey<Key = C::Decapsulator>;

    fn generate ( rng: &mut impl CryptoRngCore ) -> (Self::Encryptor, Self::Decryptor) 
    {
        let (encapsulator, decapsulator) = C::generate(rng);
        (Self::Encryptor::from_key(encapsulator), Self::Decryptor::from_key(decapsulator))
    }
    fn from_key_decap ( private: <C::Decapsulator as FromKey>::Key ) -> Self::Decryptor
    where <C as Capsulator>::Decapsulator: FromKey,
    {
        Self::Decryptor::from_key(C::Decapsulator::from_key(private))
    }
    fn from_key_encap (key: <C::Encapsulator as FromKey>::Key) -> Self::Encryptor
    where <C as Capsulator>::Encapsulator: FromKey
    {
        //return SimpleIes{ encapsulator: EncapOrDecap::Encap(C::Encapsulator::from_key(key)), phantom1: PhantomData, iv: Array::default()}
        Self::Encryptor::from_key(C::Encapsulator::from_key(key))
    }
    fn from_encapsulator (encapsulator: C::Encapsulator) -> Self::Encryptor
    {
        //return SimpleIes{ encapsulator: EncapOrDecap::Encap(encapsulator), phantom1: PhantomData, iv: Array::default() }
        //SimpleIesEncryptor::from_key(encapsulator)
        Self::Encryptor::from_key(encapsulator)
    }
    fn from_decapsulator (decapsulator: C::Decapsulator) -> Self::Decryptor
    {
        //return SimpleIes{ encapsulator: EncapOrDecap::Decap(encapsulator), phantom1: PhantomData, iv: Array::default() }
        Self::Decryptor::from_key(decapsulator)
    }
}
    


///
/// Basic IES which uses a key encapsulation mechanism and a single key derivation function to output 
/// an encryption key
/// Used by Apples ECIES algorithm
///
pub struct SimpleIes <C: Capsulator, A: Aead + KeyInit > 
{
    //encapsulator: EncapOrDecap<C>,
    phantom: PhantomData<C>,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    //iv: Vec<u8>
    //iv: Array<u8, A::NonceSize>,
} 

impl<C: Capsulator, A: Aead + KeyInit> Ies<C> for SimpleIes<C,A> 
where <C as Capsulator>::Decapsulator: FromKey,
    <C as Capsulator>::Encapsulator: FromKey
{
    type Decryptor = SimpleIesDecryptor<C,A>;
    type Encryptor = SimpleIesEncryptor<C,A>;
}


// impl<C, A> SimpleIes<C,A>
// where A: Aead + KeyInit,
// C: Capsulator,
// {
    
//     // pub fn from_key_decap ( private: <C::Decapsulator as FromKey>::Key) -> SimpleIesDecryptor<C, A>

//     // //where <C as Capsulator>::Decapsulator: PrivateKeyInit<T>
//     // //where <C as Capsulator>::Decapsulator: From<T>
//     // where <C as Capsulator>::Decapsulator: FromKey
//     // {
//     //     //return SimpleIes{ encapsulator: EncapOrDecap::Decap(C::Decapsulator::from_key(private)), phantom1: PhantomData, iv: Array::default() }
//     //     SimpleIesDecryptor::from_key(C::Decapsulator::from_key(private))
//     // }

//     //pub fn from_key_encap (key: <C::Encapsulator as FromKey>::Key) -> SimpleIes<C, A>
//     // pub fn from_key_encap (key: <C::Encapsulator as FromKey>::Key) -> SimpleIesEncryptor<C, A>
//     // where <C as Capsulator>::Encapsulator: FromKey
//     // {
//     //     //return SimpleIes{ encapsulator: EncapOrDecap::Encap(C::Encapsulator::from_key(key)), phantom1: PhantomData, iv: Array::default()}
//     //     SimpleIesEncryptor::from_key(C::Encapsulator::from_key(key))
//     // }
//     // pub fn new_encryptor () -> SimpleIes<C, A, EK>
//     // where <C as Capsulator>::Encapsulator: Default
//     // {
//     //     return SimpleIes{ encapsulator: EncapOrDecap::encap(C::new_encapsulator()), phantom1: PhantomData, phantom2: PhantomData, iv: Vec::new()}
//     // }
//     // pub fn from_encapsulator (encapsulator: C::Encapsulator) -> SimpleIesEncryptor<C, A>
//     // {
//     //     //return SimpleIes{ encapsulator: EncapOrDecap::Encap(encapsulator), phantom1: PhantomData, iv: Array::default() }
//     //     SimpleIesEncryptor::from_key(encapsulator)
//     // }

//     //pub fn from_decapsulator (encapsulator: C::Decapsulator) -> SimpleIes<C, A>
//     // pub fn from_decapsulator (decapsulator: C::Decapsulator) -> SimpleIesDecryptor<C, A>
//     // {
//     //     //return SimpleIes{ encapsulator: EncapOrDecap::Decap(encapsulator), phantom1: PhantomData, iv: Array::default() }
//     //     SimpleIesDecryptor::from_key(decapsulator)
//     // }
// }


pub struct SimpleIesEncryptor <C: Capsulator, A: Aead + KeyInit > 
{
    encapsulator: C::Encapsulator,
    iv: Array<u8, A::NonceSize>,
} 

impl<C: Capsulator, A: Aead+KeyInit> FromKey for SimpleIesEncryptor<C,A>
{
    type Key = C::Encapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { encapsulator: key, iv: Array::default()}
    }
}

impl <C: Capsulator, A> SimpleIesEncryptor<C, A> 
where A: Aead + KeyInit,
{
    pub fn set_iv (&mut self, iv: Array<u8, A::NonceSize>) { 
        self.iv = iv;
    }
}
///
/// 
/// 
impl <C: Capsulator, A> SimpleIesEncryptor<C, A> 
    where A: Aead + KeyInit,
    //Error: From<<<C as Capsulator>::Encapsulator as Encapsulate<GenericArray<u8, <C as Capsulator>::CiphertextSize>, Array<u8, <A as aead::KeySizeUser>::KeySize>>>::Error>
{

    pub fn seal_detached_encapsulated_key <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>), Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate(csprng).map_err(|_f|Error::KemError)?;
        let encryptor = A::new(&shared_secret);
        // it would be preferable to use one of the in-place aead functions, however the in-place functions assume ciphertext len = plaintext len
        // this is not the case with CBC Encrypt + CBC MAC which is a common AEAD used in CMS and JWE. encrypt works with vectors and therefore 
        // allows for different input and output sizes.
        return Ok((encapsulated_key, encryptor.encrypt(&self.iv, pt)?))
    }

    pub fn seal_detached_encapsulated_key_deterministic <'msg, 'aad> (
        &self,
        //seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        seed: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>), Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>,
        C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate_deterministic(seed).map_err(|_f|Error::KemError)?;
        let encryptor = A::new(&shared_secret);
        // it would be preferable to use one of the in-place aead functions, however the in-place functions assume ciphertext len = plaintext len
        // this is not the case with CBC Encrypt + CBC MAC which is a common AEAD used in CMS and JWE. encrypt works with vectors and therefore 
        // allows for different input and output sizes.
        return Ok((encapsulated_key, encryptor.encrypt(&self.iv, pt)?))
    }


    ///
    /// Encrypts the provided msg with authentication of the optional authenticated data field
    /// Returns a single vector containing the encapsulated key, enciphered payload and tag
    /// 
    pub fn seal <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>
    {
        let ( encapsulated_key, ct ) = self.seal_detached_encapsulated_key(csprng, pt)?;
        Ok ( [encapsulated_key.as_slice(), ct.as_slice()].concat())
    }

    pub fn seal_deterministic <'msg, 'aad> (
        &self,
        seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>,
        C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>
    {
        let ( encapsulated_key, ct ) = self.seal_detached_encapsulated_key_deterministic(seed, pt)?;
        Ok ( [encapsulated_key.as_slice(), ct.as_slice()].concat())
    }

    ///
    /// Encrypted the provided msg with authenication of the optical authenticated data field
    /// Returns the encapsulated key, enciphered payload and tag as separate fields.
    pub fn seal_detached <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        plaintext_payload_and_aad: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>, Tag<A>), Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>
    {
        let (ek, mut ct) = self.seal_detached_encapsulated_key(csprng, plaintext_payload_and_aad)?;
        let tag = ct.split_off(ct.len()-A::TagSize::USIZE);
        Ok((ek,ct,tag.as_slice().try_into().map_err(|_f|Error::LenError)?))
    }
    
    pub fn seal_detached_deterministic <'msg, 'aad> (
        &self,
        //seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        seed: &[u8],
        plaintext_payload_and_aad: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>, Tag<A>), Error> 
    where C: Capsulator<SharedKeySize = A::KeySize>,
        C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>
    {
        let (ek, mut ct) = self.seal_detached_encapsulated_key_deterministic(seed, plaintext_payload_and_aad)?;
        let tag = ct.split_off(ct.len()-A::TagSize::USIZE);
        Ok((ek,ct,tag.as_slice().try_into().map_err(|_f|Error::LenError)?))
    }
}


pub struct SimpleIesDecryptor <C: Capsulator, A: Aead + KeyInit > 
{
    decapsulator: C::Decapsulator,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    //iv: Vec<u8>
    iv: Array<u8, A::NonceSize>,
} 

impl<C: Capsulator, A: Aead+KeyInit> FromKey for SimpleIesDecryptor<C,A>
{
    type Key = C::Decapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { decapsulator: key, phantom1: PhantomData, iv: Array::default()}
    }
}

impl <C: Capsulator, A> SimpleIesDecryptor<C, A> 
where A: Aead + KeyInit,
{
    pub fn set_iv (&mut self, iv: Array<u8, A::NonceSize>) { 
        self.iv = iv;
    }
}

///
///
/// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
/// 
impl <'msg, 'aad, C: Capsulator, A> SimpleIesDecryptor<C, A> 
where A: Aead + KeyInit,
    C: Capsulator<SharedKeySize = A::KeySize>
{
    pub fn open_detached_encapsulated_key(
        &self, 
        encapped_key: &GenericArray<u8, C::CiphertextSize>,
        encrypted_payload_and_tag: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>
    {
        let shared_secret = self.decapsulator.decapsulate(encapped_key).map_err(|_|Error::KemError)?;
        let encryptor = A::new(&shared_secret);
        Ok(encryptor.decrypt(&self.iv, encrypted_payload_and_tag)?)
    }
    pub fn open(
        &self, 
        encrypted_msg: impl Into<Payload<'msg, 'aad>>,    
    ) -> Result<Vec<u8>, Error>
    {
        let encrypted_msg_as_payload: Payload = encrypted_msg.into();
        let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(C::CiphertextSize::USIZE).ok_or(Error::LenError)?;
        self.open_detached_encapsulated_key(GenericArray::from_slice(encapped_key_bytes), Payload{msg:&ciphertext, aad: encrypted_msg_as_payload.aad})
    }

    pub fn try_open_detached(
        &self, 
        encapped_key: &GenericArray<u8, C::CiphertextSize>,
        encrypted_payload: impl Into<Payload<'msg, 'aad>>,
        //tag: &Array::<u8, A::TagSize>
        tag: &Tag<A>,
    ) -> Result<Vec<u8>, Error>
    {
        let payload = encrypted_payload.into();
        //let mut ct_and_tag = payload.msg.to_vec();
        //ct_and_tag.extend(tag);
        let ct_and_tag = [payload.msg, tag].concat();
        return self.open_detached_encapsulated_key ( encapped_key, Payload { msg: &ct_and_tag, aad: &payload.aad});
    }



}

///
/// Implementation of the Open trait, which imports an ephemeral public key and derives a symmetric session key from the ephemeral key
/// and the recipients private key.
/// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
/// 
impl <'msg, 'aad, C: Capsulator, A> SimpleIes<C, A> 
where A: Aead + KeyInit,
    <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
    <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    //EK: EncappedKey,
    //C: Decapsulator<EK>,
{
    
    
}










pub struct IesWithKeyWrap <C: Capsulator, KW, A: Aead + KeyInit> 
{
    phantom: PhantomData<C>,
    phantom1: PhantomData<A>,
    phantom3: PhantomData<KW>,
} 



impl<C: Capsulator, KW, A: Aead + KeyInit> Ies<C> for IesWithKeyWrap<C,KW,A> 
{
    type Decryptor = IesDecryptorWithKeyWrap<C,KW,A>;
    type Encryptor = IesEncryptorWithKeyWrap<C,KW,A>;
}


impl<C: Capsulator, KW, A: Aead + KeyInit> IesWithKeyWrap<C,KW,A> 
where C: GenerateCapsulatorFromSeed
{
    pub fn derive_from_seed(seed: &Array::<u8, <C as GenerateCapsulatorFromSeed>::SeedSize>) -> ( <Self as Ies<C>>::Encryptor, <Self as Ies<C>>::Decryptor )
    {
        let (encapsulator, decapsulator) = C::derive_from_seed(&seed);
        (IesEncryptorWithKeyWrap::<C,KW,A>{encapsulator, phantom1: PhantomData, phantom3: PhantomData},
            IesDecryptorWithKeyWrap::<C,KW,A>{decapsulator, phantom1: PhantomData, phantom3: PhantomData})
    }
}

// impl<C, A, KW> IesWithKeyWrap<C, KW,A>
// where A: Aead + KeyInit,
// C: Capsulator,
// {
    
//     // pub fn new_from_encapsulator (encapsulator: C::Encapsulator) -> IesEncryptorWithKeyWrap<C,KW,A>
//     // {
//     //     //Self { encapsulator: EncapOrDecap::Encap(encapsulator), phantom1: PhantomData, phantom3: PhantomData }
//     //     IesEncryptorWithKeyWrap::from_key(encapsulator)
//     // }
//     // pub fn new_from_decapsulator (decapsulator: C::Decapsulator) -> IesDecryptorWithKeyWrap<C,KW,A>
//     // {
//     //     //return IesWithKeyWrap{ encapsulator: EncapOrDecap::Decap(encapsulator), phantom1: PhantomData, phantom3: PhantomData }
//     //     IesDecryptorWithKeyWrap::from_key(decapsulator)
//     // }
// }


pub struct IesEncryptorWithKeyWrap <C: Capsulator, KW, A: Aead + KeyInit> 
{
    encapsulator: C::Encapsulator,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    phantom3: PhantomData<KW>,
    //iv: Vec<u8>
} 



impl<C: Capsulator, A: Aead+KeyInit, KW> FromKey for IesEncryptorWithKeyWrap<C, KW, A> 
{
    type Key = C::Encapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { encapsulator: key, phantom1: PhantomData, phantom3: PhantomData}
    }
}

impl<C: Capsulator, A: Aead+KeyInit, KW> SetKdf for IesEncryptorWithKeyWrap<C, KW, A>
where C::Encapsulator: SetKdf
{
    type Kdf = <C::Encapsulator as SetKdf>::Kdf;
    fn set_kdf(&mut self, kdf: Self::Kdf )
    {
        self.encapsulator.set_kdf(kdf);
    }
}

impl <C, A, KW> IesEncryptorWithKeyWrap<C, KW, A> 
where A: Aead + KeyInit,
    C: Capsulator,
    KW: KeyInit + BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
        <A as aead::AeadCore>::TagSize: ArrayLength, //<u8>,
        <A as cipher::KeySizeUser>::KeySize: NonZero,
        <A as cipher::KeySizeUser>::KeySize: Add<U8>,
        <A as cipher::KeySizeUser>::KeySize: Rem<U8>,
        <<A as cipher::KeySizeUser>::KeySize as Add<U8>>::Output: ArraySize,
        <<A as cipher::KeySizeUser>::KeySize as Rem<U8>>::Output: Zero,
        // <A as cipher::KeySizeUser>::KeySize: Sub<A::KeySize>,
        // <<A as cipher::KeySizeUser>::KeySize as Sub>::Output: ArraySize,
        C: Capsulator<SharedKeySize = KW::KeySize>,

        C::Encapsulator: EncapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize, LK=A::KeySize>,
    //C::Encapsulator: Encapsulator<EK>,
{
    pub fn seal_detached_encapsulated_key <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Array<u8, A::NonceSize>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, 
        Array::<u8, <C::Encapsulator as EncapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        Vec<u8>), Error> 
    {
        // let (encapsulated_key, derived_key) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        // let key_encryptor = AesKw::<KW>::new(&derived_key);
        // let wrapped_cek = key_encryptor.wrap_fixed_key(&content_encryption_key); //.map_err(|_v|aead::Error)?;
        let (encapsulated_key, wrapped_cek) = self.encapsulator.encapsulate_and_wrap(csprng, content_encryption_key).unwrap();
        let data_encryptor = A::new(content_encryption_key);

        let enciphered_data = data_encryptor.encrypt(&nonce, pt)?;
        Ok ((encapsulated_key, wrapped_cek, enciphered_data))
    }


    pub fn seal_detached <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        //nonce: &Array<u8, A::NonceSize>,
        nonce: &Nonce<A>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, 
        //Array::<u8, Sum<A::KeySize, U8>>,
        Array::<u8, <C::Encapsulator as EncapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        Vec<u8>, 
        //Array<u8, A::TagSize>), Error> 
        Tag<A>), Error>
    {
        //let EncapOrDecap::Encap(encapsulator) = &self.encapsulator else { panic! ( "wrong types")};
        let (encapsulated_key, wrapped_cek, mut enciphered_data) = self.seal_detached_encapsulated_key(csprng, content_encryption_key, pt, nonce)?;

        // let tag = enciphered_data.split_off(enciphered_data.len() - A::TagSize::USIZE);
        // Ok ((encapsulated_key, wrapped_cek, enciphered_data, Array::try_from(&tag)?))

        let tag = enciphered_data.drain((enciphered_data.len() - A::TagSize::USIZE)..);
        let tag2 = Array::from_iter(tag);
        Ok ((encapsulated_key, wrapped_cek, enciphered_data, tag2))



        //let tag = Array::try_from(&enciphered_data[enciphered_data.len() - A::TagSize::USIZE..]).unwrap();

        //enciphered_data.truncate(ct.len()-A::TagSize::USIZE);
        
    }


    
    

    // pub fn seal_detached_deterministic <'msg, 'aad> (
    //     &self,
    //     //seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
    //     seed: &[u8],
    //     content_encryption_key: &Array<u8, A::KeySize>,
    //     pt: impl Into<Payload<'msg, 'aad>>,
    //     //nonce: &Array<u8, A::NonceSize>,
    //     nonce: &Nonce<A>,
    // ) -> Result<(GenericArray<u8, C::CiphertextSize>, 
    //     //Array::<u8, Sum<A::KeySize, U8>>,
    //     Array::<u8, <C::Encapsulator as EncapsulateWithKeyWrapDeterministic<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
    //     Vec<u8>, 
    //     //Array<u8, A::TagSize>), Error>
    //     Tag<A>), Error>

    // where C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>,
    //     //C: Capsulator<SharedKeySize = A::KeySize>,
    //     //<C as Capsulator>::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, <C as Capsulator>::CiphertextSize>, Array<u8, <KW as KeySizeUser>::KeySize>>
    //     // C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>
    // {
    //     //let EncapOrDecap::Encap(encapsulator) = &self.encapsulator else { panic! ( "wrong types")};
    //     let (encapsulated_key, wrapped_cek, mut enciphered_data) = self.seal_detached_encapsulated_key_deterministic(seed, content_encryption_key, pt, nonce)?;

    //     // let tag = enciphered_data.split_off(enciphered_data.len() - A::TagSize::USIZE);
    //     // Ok ((encapsulated_key, wrapped_cek, enciphered_data, Array::try_from(&tag)?))

    //     let tag = enciphered_data.drain((enciphered_data.len() - A::TagSize::USIZE)..);
    //     let tag2 = Array::from_iter(tag);
    //     Ok ((encapsulated_key, wrapped_cek, enciphered_data, tag2))



    //     //let tag = Array::try_from(&enciphered_data[enciphered_data.len() - A::TagSize::USIZE..]).unwrap();

    //     //enciphered_data.truncate(ct.len()-A::TagSize::USIZE);
        
    // }


    ///
    /// Function which encrypts a ciphertext and returns a blob to be transferred to the recipient.
    /// The blob contains the encapsulated key, wrapped cek, enciphered data and tag 
    /// 
    pub fn seal <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Array<u8, A::NonceSize>,
    ) -> Result<Vec<u8>, Error> 
    {
        //let EncapOrDecap::Encap(encapsulator) = &self.encapsulator else { panic! ( "wrong types")};
        let (encapsulated_key, wrapped_cek, enciphered_data) = self.seal_detached_encapsulated_key(csprng, content_encryption_key, pt, nonce)?;

        //enciphered_data.truncate(ct.len()-A::TagSize::USIZE);
        Ok ([encapsulated_key.as_slice(), wrapped_cek.as_slice(), enciphered_data.as_slice()].concat())
    }

}




impl <C, A, KW> IesEncryptorWithKeyWrap<C, KW, A> 
where A: Aead + KeyInit,
    C: Capsulator,
    KW: KeyInit + BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
        <A as aead::AeadCore>::TagSize: ArrayLength, //u8>,
        <A as cipher::KeySizeUser>::KeySize: NonZero,
        <A as cipher::KeySizeUser>::KeySize: Add<U8>,
        <A as cipher::KeySizeUser>::KeySize: Rem<U8>,
        <<A as cipher::KeySizeUser>::KeySize as Add<U8>>::Output: ArraySize,
        <<A as cipher::KeySizeUser>::KeySize as Rem<U8>>::Output: Zero,
        // <A as cipher::KeySizeUser>::KeySize: Sub<A::KeySize>,
        // <<A as cipher::KeySizeUser>::KeySize as Sub>::Output: ArraySize,
        C: Capsulator<SharedKeySize = KW::KeySize>,

        C::Encapsulator: EncapsulateWithKeyWrapDeterministic<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize, LK=A::KeySize>,
        //<<C as Capsulator>::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, <C as Capsulator>::CiphertextSize>, Array<u8, <KW as aead::KeySizeUser>::KeySize>>>::Error: std::fmt::Debug,
    //C::Encapsulator: Encapsulator<EK>,
{

    pub fn seal_detached_encapsulated_key_deterministic <'msg, 'aad> (
        &self,
        //seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        seed: &[u8],
        content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Array<u8, A::NonceSize>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, 
        Array::<u8, <C::Encapsulator as EncapsulateWithKeyWrapDeterministic<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        Vec<u8>), Error> 
    where C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>
    {
        // let (encapsulated_key, derived_key) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        // let key_encryptor = AesKw::<KW>::new(&derived_key);
        // let wrapped_cek = key_encryptor.wrap_fixed_key(&content_encryption_key); //.map_err(|_v|aead::Error)?;
        let Ok((encapsulated_key, wrapped_cek)) = self.encapsulator.encapsulate_and_wrap_deterministic(seed, content_encryption_key) 
        else 
        {
            return Err(Error::AeadError)
        };
        let data_encryptor = A::new(content_encryption_key);

        let enciphered_data = data_encryptor.encrypt(&nonce, pt)?;
        Ok ((encapsulated_key, wrapped_cek, enciphered_data))
    }
}


pub struct IesDecryptorWithKeyWrap <C: Capsulator, KW, A: Aead + KeyInit> 
{
    decapsulator: C::Decapsulator,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    phantom3: PhantomData<KW>,
    //iv: Vec<u8>
} 


impl<C: Capsulator, A: Aead+KeyInit, KW> FromKey for IesDecryptorWithKeyWrap<C, KW, A> 
{
    type Key = C::Decapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { decapsulator: key, phantom1: PhantomData, phantom3: PhantomData}
    }
}


impl<C: Capsulator, A: Aead+KeyInit, KW> SetKdf for IesDecryptorWithKeyWrap<C, KW, A> 
where C::Decapsulator: SetKdf
{
    type Kdf = <C::Decapsulator as SetKdf>::Kdf;
    fn set_kdf(&mut self, kdf: Self::Kdf )
    {
        self.decapsulator.set_kdf(kdf);
    }
}

///
/// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
/// 
impl <'msg, 'aad, C, A, KW> IesDecryptorWithKeyWrap<C, KW, A> 
where A: Aead + KeyInit,
    C: Capsulator,
     KW: KeyInit + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>, //+ BlockEncrypt + BlockDecrypt,
            //A::KeySize: Add<U8>,
            //<A::KeySize as Add<U8>>::Output: ArraySize,
            //A::KeySize: NonZero, 
            //A::KeySize: Rem<U8>,
            //<<A as cipher::KeySizeUser>::KeySize as Rem<U8>>::Output: Zero,
            // <C as Capsulator>::SharedKeySize: Sub<KW::KeySize>,
            // <<C as Capsulator>::SharedKeySize as Sub<<KW as KeySizeUser>::KeySize>>::Output: ArraySize,
            C: Capsulator<SharedKeySize = KW::KeySize>,
            //<C as Capsulator>::CiphertextSize: ArraySize,
            C::Decapsulator: DecapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize, LK=A::KeySize>,
{
    ///
    /// Opening of a payload where the encapped_key and encrypted_key are separate fields, but the tag is embedded into the ct
    /// 
    pub fn open_semi_detached(
        &self, 
        encapped_key: &GenericArray<u8, C::CiphertextSize>,
        //encrypted_key: &Array::<u8, Sum::<A::KeySize, U8>>,
        encrypted_key: &Array<u8, <C::Decapsulator as DecapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        ct: impl Into<Payload<'msg, 'aad>>,
        //tag: &Array::<u8, A::TagSize>,
        //nonce: &Array::<u8, A::NonceSize>
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error>
   
    {
        // let derived_key = self.decapsulator.decapsulate(&encapped_key).map_err(|_|Error::KemError)?;
        // let decryptor = AesKw::<KW>::new(&derived_key);
        // let shared_secret: Array<u8, A::KeySize> = decryptor.unwrap_fixed_key(&encrypted_key).map_err(|_v|aead::Error)?;
        //let encrypted_key2 = Array::try_from(encrypted_key.as_slice()).unwrap();
        //println! ( "expected len={} provided len={}", encrypted_key2.len(), encrypted_key.len());
        let shared_secret = self.decapsulator.decapsulate_and_unwrap(encapped_key, encrypted_key).map_err(|_|Error::AeadError)?;
        let encryptor = A::new(&shared_secret);
        //let encryptor = A::new_from_slice(shared_secret.as_slice()).unwrap();
        
        Ok(encryptor.decrypt(&nonce, ct)?)
    }

    /// 
    /// Opening of a payload where each field is a separate parameter
    ///  
    pub fn open_detached(
        &self, 
        encapped_key: &GenericArray<u8, C::CiphertextSize>,
        //encrypted_key: &Array::<u8, Sum::<A::KeySize, U8>>,
        encrypted_key: &Array<u8, <C::Decapsulator as DecapsulateWithKeyWrap<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        ct: impl Into<Payload<'msg, 'aad>>,
        //tag: &Array::<u8, A::TagSize>,
        tag: &Tag<A>,
        //nonce: &Array::<u8, A::NonceSize>
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error>
   
    {
        let payload = ct.into();
        self.open_semi_detached(encapped_key, encrypted_key, Payload{ msg: &[payload.msg, tag].concat(), aad: &payload.aad}, nonce)
    }
    
    ///
    /// Opening of a payload where the encapsulated key, encrypted key, ciphertext and tag are passed in through a single parameter
    /// 
    pub fn open(
        &self, 
        ct: impl Into<Payload<'msg, 'aad>>,
        //nonce: &Array::<u8, A::NonceSize>
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error>
    {
        let payload = ct.into();
        let (encapsulated_key, rem) = payload.msg.split_at(C::CiphertextSize::USIZE);
        let (encrypted_key, rem) = rem.split_at(KW::KeySize::USIZE);
        let (encrypted_msg, tag) = rem.split_at(rem.len() - A::TagSize::USIZE);
        self.open_detached(GenericArray::from_slice(encapsulated_key), &Array::try_from(encrypted_key)?, Payload { msg: encrypted_msg, aad: payload.aad}, &Array::try_from(tag)?, nonce)
    }
       
}



pub struct IesWithDerivedIv<C: Capsulator, A: Aead + KeyInit> ( PhantomData<C>, PhantomData<A>);
//impl<C: Capsulator,A: Aead+KeyInit> IesInit<C, IesEncryptorWithDerivedIv<C,A>, IesDecapsulatorWithDerivedIv<C,A>> for IesWithDerivedIv<C,A> {}

impl<C: Capsulator, A: Aead + KeyInit> Ies<C> for IesWithDerivedIv<C,A> 
{
    type Decryptor = IesDecryptorWithDerivedIv<C,A>;
    type Encryptor = IesEncryptorWithDerivedIv<C,A>;
}

// impl<C: Capsulator,A: Aead+KeyInit> IesWithDerivedIv<C,A> {
//     pub fn from_key_decap ( key: <C::Decapsulator as FromKey>::Key) -> IesDecapsulatorWithDerivedIv<C,A>
//         where <C as Capsulator>::Decapsulator: FromKey,
//     {
//         let decapsulator = C::Decapsulator::from_key(key);
//         IesDecapsulatorWithDerivedIv::<C,A>::from_key(decapsulator)
//     }
//     pub fn from_key_encap ( key: <C::Encapsulator as FromKey>::Key) -> IesEncryptorWithDerivedIv<C,A>
//         where <C as Capsulator>::Encapsulator: FromKey,
//     {
//         let decapsulator = C::Encapsulator::from_key(key);
//         IesEncryptorWithDerivedIv::<C,A>::from_key(decapsulator)
//     }
// }











pub struct IesEncryptorWithDerivedIv <C: Capsulator, A: Aead + KeyInit> 
{
    encapsulator: C::Encapsulator,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    //iv: Vec<u8>
} 

//impl<C: Capsulator, A: Aead + KeyInit> From<GenericArray<u8, C::Decapsulator::

impl<C: Capsulator, A: Aead+KeyInit> FromKey for IesEncryptorWithDerivedIv<C,A>
{
    type Key = C::Encapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { encapsulator: key, phantom1: PhantomData}
    }
}

impl<C: Capsulator, A: Aead + KeyInit> IesEncryptorWithDerivedIv<C, A>
{
    ///
    /// Function which returns the encapsulated key and encrypted data in two separate values
    /// The encrypted data includes the authentication tag
    /// 
    pub fn seal_semi_detached <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>), Error> 
    where <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
        <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize 
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        let (shared_secret_key, shared_secret_nonce) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(shared_secret_key);
        
        let nonce = &Array::try_from ( shared_secret_nonce.as_slice() )?;

        Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?))
    }

    ///
    /// Function which combines all data into a single return buffer
    /// 
    pub fn seal <'msg, 'aad, R: CryptoRng + RngCore> (
        &self,
        csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
        <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize 
    {
        let ( encapsulated_key, encrypted_data ) = self.seal_semi_detached(csprng, pt)?;
        // let mut full_message = encapsulated_key.to_vec();
        // full_message.append(&mut ct);
        return Ok ([encapsulated_key.as_slice(), encrypted_data.as_slice()].concat());
    }

    pub fn seal_semi_detached_deterministic <'msg, 'aad> (
        &self,
        seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        //content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        //nonce: &Array<u8, A::NonceSize>,
    ) -> Result<(GenericArray<u8, C::CiphertextSize>, 
        //Array::<u8, <C::Encapsulator as EncapsulateWithKeyWrapDeterministic<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::LW>,
        Vec<u8>), Error> 
    where C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>,
        <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
        <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize
    {
        // let (encapsulated_key, derived_key) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        // let key_encryptor = AesKw::<KW>::new(&derived_key);
        // let wrapped_cek = key_encryptor.wrap_fixed_key(&content_encryption_key); //.map_err(|_v|aead::Error)?;
        let Ok((encapsulated_key, shared_secret)) = self.encapsulator.encapsulate_deterministic(seed) 
        else 
        {
            return Err(Error::AeadError)
        };
        let (shared_secret_key, shared_secret_nonce) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(shared_secret_key);
        
        let nonce = &Array::try_from ( shared_secret_nonce.as_slice() )?;

        Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?))
    }

    pub fn seal_deterministic <'msg, 'aad> (
        &self,
        seed: &Array<u8, <C::Encapsulator as EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>>::SeedSize>,
        //content_encryption_key: &Array<u8, A::KeySize>,
        pt: impl Into<Payload<'msg, 'aad>>,
        //nonce: &Array<u8, A::NonceSize>,
    ) -> Result<Vec<u8>, Error> 
    where C::Encapsulator: EncapsulateDeterministic2<GenericArray<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>>,
        <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
        <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize
    {
        // let (encapsulated_key, derived_key) = self.encapsulator.encapsulate(csprng).map_err(|_|Error::KemError)?;
        // let key_encryptor = AesKw::<KW>::new(&derived_key);
        // let wrapped_cek = key_encryptor.wrap_fixed_key(&content_encryption_key); //.map_err(|_v|aead::Error)?;
        let Ok((encapsulated_key, encrypted_data)) = self.seal_semi_detached_deterministic(seed, pt) 
        else 
        {
            return Err(Error::AeadError)
        };
        Ok([encapsulated_key.as_slice(), encrypted_data.as_slice()].concat())
    }


}

pub struct IesDecryptorWithDerivedIv <C: Capsulator, A: Aead + KeyInit> 
{
    decapsulator: C::Decapsulator,
    phantom1: PhantomData<A>,
    //phantom2: PhantomData<EK>,
    //iv: Vec<u8>
} 

impl<C: Capsulator, A: Aead+KeyInit> FromKey for IesDecryptorWithDerivedIv<C,A>
{
    type Key = C::Decapsulator;
    fn from_key(key: Self::Key) -> Self {
        Self { decapsulator: key, phantom1: PhantomData}
    }
}

impl<C: Capsulator, A: Aead + KeyInit> IesDecryptorWithDerivedIv<C, A>
where <C as Capsulator>::SharedKeySize: Sub<A::KeySize>,
    <<C as Capsulator>::SharedKeySize as Sub<<A as KeySizeUser>::KeySize>>::Output: ArraySize,
    C: Capsulator<SharedKeySize=Sum<A::KeySize, A::NonceSize>>,
        A::KeySize: Add<A::NonceSize>,
        Sum<A::KeySize, A::NonceSize>: ArraySize,
        Sum<A::KeySize, A::NonceSize>: Sub<A::KeySize>,
{
    ///
    /// Open a payload where the encapsulated key and encrypted data are separate parameters
    /// The authentication tag is appended to the encrypted data
    /// 
    pub fn open_semi_detached<'msg, 'aad>(
        &self, 
        encapped_key: &GenericArray<u8, C::CiphertextSize>,
        ct: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>

    {
        let shared_secret = self.decapsulator.decapsulate(encapped_key).map_err(|_|Error::KemError)?;
        let ( key, nonce ) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(key);
        Ok(encryptor.decrypt(nonce.as_slice().try_into()?, ct)?)
    }
    /// 
    /// Open a payload where the encrypted_msg contains both the encapsulated key and the enciphered data
    ///
    pub fn open<'msg, 'aad>(
        &self, 
        encrypted_msg: impl Into<Payload<'msg, 'aad>>,    
    ) -> Result<Vec<u8>, Error>
    {
        let encrypted_msg_as_payload: Payload = encrypted_msg.into();
        let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(C::CiphertextSize::USIZE).ok_or(Error::LenError)?;
        return self.open_semi_detached(GenericArray::from_slice(encapped_key_bytes), Payload{msg:ciphertext, aad: encrypted_msg_as_payload.aad})
    }
}




//
// Trait used to create an encapsulator passing in a kdf structure
// 
// pub trait EncapsulatorInit<K> {
//     fn new (kdf: K) -> Self;
// }

//
// Trait used for decapsulators and auth encapsulators which need a private key to be specified 
// during creation
// 
// pub trait PrivateKeyInit<P> {
//     fn new(private_key: P) -> Self;
// }

// pub trait EncodePublicKey<P> {
//     type EncodedLen: ArrayLength<u8>;
//     fn encode(public_key: &P) -> GenericArray<u8, Self::EncodedLen>;
// }
// pub trait DecodePublicKey<P> {
//     fn decode(encoded_bytes: &[u8]) -> Result<P, Error>;
// }

//
// Trait used for types which support both Encapsulation and Decapsulation.
// Default implementations are provided for new_encapsulator and new_decapsulator
// 
// pub trait Capsulator{
//     type SecretKey;
//     type Encapsulator;
//     type Decapsulator;
//     type EncappedKey: EncappedKey;
    
//     fn new_encapsulator () -> Self::Encapsulator
//     where Self::Encapsulator: Default
//     {
//         return Self::Encapsulator::default();
//     }
//     fn new_decapsulator (priv_key: Self::SecretKey) -> Self::Decapsulator
//     where Self::Decapsulator: PrivateKeyInit<Self::SecretKey>
//     {
//         return Self::Decapsulator::new(priv_key);
//     }    
// }

// pub trait DecapsulatorWithKeyWrap<EK: EncappedKey>: Decapsulator<EK> {
//     /// Attempt to decapsulate the given encapsulated key. Returns the shared secret on success, or
//     /// an error if something went wrong.
//     fn try_decap_with_key_wrap<A,L>(&self, encapped_key: &EK, encrypted_key: impl AsRef<[u8]>) -> Result<GenericArray<u8,L>, Error> // kem::SharedSecret<EK>
//     where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
//         L: ArrayLength<u8>
//     {
//         //let typed_encapsulated_key = EK::from_bytes(encapsulated_key.into()).map_err(|_v|aead::Error)?;
//         let derived_key = self.try_decap(&encapped_key)?;
//         let decryptor = Kek::<A>::try_from(derived_key.as_bytes()).map_err(|_v|aead::Error)?;
//         let ss_vec = decryptor.unwrap_vec(encrypted_key.as_ref()).map_err(|_v|aead::Error)?;
//         let ss_ga = GenericArray::clone_from_slice(ss_vec.as_ref()); //.map_err(|_v|aead::Error)?;
//         Ok(ss_ga)
//     }
// }

// pub trait EncapsulatorWithKeyWrap<EK: EncappedKey>: Encapsulator<EK> {
//     /// Attempt to decapsulate the given encapsulated key. Returns the shared secret on success, or
//     /// an error if something went wrong.
//     /// 
//     fn try_encap_with_key_wrap<A, L: ArrayLength<u8>, R: CryptoRng + RngCore>(
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &EK::RecipientPublicKey,
//         cek: &[u8],
//     ) -> Result<(EK, GenericArray<u8,L>), Error>

//     where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
//     // fn try_encap_with_key_wrap<A,L>(&self, encapped_key: &EK, encrypted_key: impl AsRef<[u8]>) -> Result<GenericArray<u8,L>, Error> // kem::SharedSecret<EK>
//     // where A: KeyInit + BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + BlockDecrypt,
//     //     L: ArrayLength<u8>
//     {
//         //let typed_encapsulated_key = EK::from_bytes(encapsulated_key.into()).map_err(|_v|aead::Error)?;
//         let (encapped_key, derived_key) = self.try_encap(csprng, recip_pubkey)?;
//         let encryptor = Kek::<A>::try_from(derived_key.as_bytes()).map_err(|_v|aead::Error)?;
//         let ss_vec = encryptor.wrap_vec(cek).map_err(|_v|aead::Error)?;
//         let ss_ga = GenericArray::clone_from_slice(ss_vec.as_ref()); //.map_err(|_v|aead::Error)?;
//         Ok((encapped_key, ss_ga))
//     }
// }

//
// Trait used for types which support both Authenticated Encapsulation and Authenticated Decapsulation.
// Default implementations are provided for new_auth_encapsulator and new_auth_decapsulator
// 
// pub trait AuthCapsulator{
//     type AuthSecretKey;
//     type AuthEncapsulator: PrivateKeyInit<Self::AuthSecretKey>;
//     type AuthDecapsulator: PrivateKeyInit<Self::AuthSecretKey>;
    
//     fn new_auth_encapsulator (priv_key: Self::AuthSecretKey) -> Self::AuthEncapsulator
//     {
//         return Self::AuthEncapsulator::new(priv_key);
//     }
//     fn new_auth_decapsulator (priv_key: Self::AuthSecretKey) -> Self::AuthDecapsulator
//     {
//         return Self::AuthDecapsulator::new(priv_key);
//     }
// }



//
// pub trait Seal <C: Capsulator, LCT, LK> {
//     fn try_seal <'msg, 'aad, R: CryptoRng + RngCore> (
//         &self,
//         csprng: &mut R,
//         pt: impl Into<Payload<'msg, 'aad>>
//     ) -> Result<(GenericArray<u8, C::CiphertextSize>, Vec<u8>), Error>;

//     fn seal2 <'msg, 'aad, R: CryptoRng + RngCore> (
//         &self,
//         csprng: &mut R,
//         pt: impl Into<Payload<'msg, 'aad>>
//     ) -> Result<Vec<u8>, Error> 
//     {
//         let ( encapsulated_key, mut ct ) = self.try_seal(csprng, pt)?;
//         let mut full_message = encapsulated_key.to_vec();
//         full_message.append(&mut ct);
//         return Ok (full_message);
//     }
// }


// pub trait Open <'msg, 'aad, C: Capsulator> {
//     fn try_open(
//         &self, 
//         //encapped_key: &EK,
//         encapped_key: &GenericArray<u8, C::CiphertextSize>,
//         //ct: &[u8],        
//         ct: impl Into<Payload<'msg, 'aad>>,
//     ) -> Result<Vec<u8>, Error>;

//     fn try_open2(
//         &self, 
//         //encrypted_msg: &'msg [u8],
//         encrypted_msg: impl Into<Payload<'msg, 'aad>>,    
//     ) -> Result<Vec<u8>, Error>
//     {
//         let encrypted_msg_as_payload: Payload = encrypted_msg.into();
        
//         let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(C::CiphertextSize::USIZE).ok_or(Error::LenError)?;

//         //return self.try_open(&EK::from_bytes(encapped_key_bytes.into())?, Payload{msg:&ciphertext, aad: encrypted_msg_as_payload.aad})
//         return self.try_open(GenericArray::from_slice(encapped_key_bytes), Payload{msg:&ciphertext, aad: encrypted_msg_as_payload.aad})
//     }
// }

//pub mod kems;



// impl<D: Digest> Kdf for CryptoBoxKdf<D> {
//     //fn derive_self_secret_others_into( &self, secret:&[u8], other_data: &[&[u8]], out: &mut [u8]) -> Result<(), digest::InvalidBufferSize> 
//     fn derive_self_secrets_others_into<'c,'b> ( &mut self, secret: impl IntoIterator<Item=&'c[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone, out: &mut [u8]) -> Result<(), digest::InvalidBufferSize>
//     {
//         let input = GenericArray::<u8, U16>::default();
//         //let secret2 = GenericArray::<u8, U32>::from_slice(secret);
//         let secret2 = iter_to_generic_array::<U32>(secret);
//         let h = salsa20::hsalsa::<U10> ( &secret2, &input);

//         //println! ( "new_secret = {:02X}", h);

//         //blake2::Blake2b::<U24>
//         let mut hasher = D::new();
//         other_data.into_iter().for_each(|v| hasher.update(v));

//         let hashed_other = hasher.finalize();
//         println!( "int_nonce = {:02X?}", hashed_other);

//         //let res2 = GenericArray::from_slice(&res[0..16]);

//         //let h2 = salsa20::hsalsa::<U10> ( &h, &res2);
//         //println! ( "nonce = {:02X?}", h2);
//         out[0..32].copy_from_slice(h.as_slice());
//         out[32..56].copy_from_slice(&hashed_other[0..24]);
//         Ok(())
//     }
// }


//impl<D: Digest> KdfWithContext for CryptoBoxKdf<D> {
//     type OutputSize = U56;

//     #[cfg(not(feature = "iter_based"))]
//     fn derive_from_self_secrets_others(&self, secret: &[&[u8]], others: &[&[u8]]) -> GenericArray<u8, <Self as KdfWithContext>::OutputSize> 
//     { 
//         let mut result = GenericArray::default();
//         println! ( "raw_secret = {:02X?}", secret);
//         println! ( "others = {:02X?}", others);

//         let input = GenericArray::<u8, U16>::default();
//         let secret2 = GenericArray::<u8, U32>::from_slice(secret[0]);
//         let h = salsa20::hsalsa::<U10> ( secret2, &input);

//         //println! ( "new_secret = {:02X}", h);

//         //blake2::Blake2b::<U24>
//         let mut hasher = D::new();
//         for other in others {
//             hasher.update(other);
//         }
//         let hashed_other = hasher.finalize();
//         println!( "int_nonce = {:02X?}", hashed_other);

//         //let res2 = GenericArray::from_slice(&res[0..16]);

//         //let h2 = salsa20::hsalsa::<U10> ( &h, &res2);
//         //println! ( "nonce = {:02X?}", h2);
//         result[0..32].copy_from_slice(h.as_slice());
//         result[32..56].copy_from_slice(&hashed_other[0..24]);

//         println! ( "key+nonce={:02X?}", result);

//         return result;
//     }

//     #[cfg(feature = "iter_based")]
//     fn derive_from_self_secrets_others<'a,'b, F, G> ( &'a self, secret : F, other_data: G) -> GenericArray<u8,Self::OutputSize>
//     where   F: IntoIterator<Item=&'a[u8]> + Clone, <F as IntoIterator>::IntoIter: Clone,
//             G: IntoIterator<Item=&'a[u8]> + Clone, <G as IntoIterator>::IntoIter: Clone {
//     //fn derive_from_self_secrets_others<'a,'b> ( &self, secret : impl IntoIterator<Item=&'a[u8]> + Clone, other_data: impl IntoIterator<Item=&'b[u8]> + Clone) -> GenericArray<u8,Self::OutputSize> {
//         use key_derivation::iso11770_6::iter_to_generic_array;

        
//         let mut result = GenericArray::default();
//         //println! ( "raw_secret = {:02X?}", secret);
//         //println! ( "others = {:02X?}", others);

//         let input = GenericArray::<u8, U16>::default();
//         //let secret2 = GenericArray::<u8, U32>::from_slice(secret[0]);
//         let secret2 = iter_to_generic_array(secret);
//         let h = salsa20::hsalsa::<U10> ( &secret2, &input);

//         //println! ( "new_secret = {:02X}", h);

//         //blake2::Blake2b::<U24>
//         let mut hasher = D::new();
//         other_data.into_iter().for_each(|v|hasher.update(v));
        
//         let hashed_other = hasher.finalize();
//         println!( "int_nonce = {:02X?}", hashed_other);

//         //let res2 = GenericArray::from_slice(&res[0..16]);

//         //let h2 = salsa20::hsalsa::<U10> ( &h, &res2);
//         //println! ( "nonce = {:02X?}", h2);
//         result[0..32].copy_from_slice(h.as_slice());
//         result[32..56].copy_from_slice(&hashed_other[0..24]);

//         println! ( "key+nonce={:02X?}", result);

//         return result;
//     }
// }



// ///
// /// Basic IES which uses a key encapsulation mechanism and a single key derivation function to output 
// /// an encryption key
// /// Used by Apples ECIES algorithm
// ///
// pub struct SimpleIes <C, A: Aead + KeyInit, EK > 
// {
//     encapsulator: C,
//     phantom1: PhantomData<A>,
//     phantom2: PhantomData<EK>,
//     iv: Vec<u8>
// } 


// ///
// /// new function for SimpleIes which takes no parameters
// /// this function is designed for encryption operations
// /// 
// impl <C, A, EK> SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
// {
//     // pub fn new2 () -> Self where C: Default { 
//     //     Self{encapsulator: C::default(), phantom1: PhantomData, phantom2: PhantomData, iv: Vec::new()}
//     // }
//     pub fn new_with_encapsulator (encapsulator: C) -> Self {
//         Self{ encapsulator, phantom1: PhantomData, phantom2: PhantomData, iv: Vec::new()}
//     }    
// }

// ///
// /// new function for SimpleIes which takes no parameters
// /// this function is designed for encryption operations
// /// 
// impl <C, A, EK> Default for SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     C: Default,
// {
//     fn default () -> Self  { 
//         return Self::new_with_encapsulator(C::default());
//     }
   
// }

// ///
// /// new function for SimpleIes which accepts a private key as a parameter
// /// this function is designed for decryption operations
// /// 
// impl <C, S, A, EK> PrivateKeyInit<S> for SimpleIes<C, A, EK > 
// where A: Aead + KeyInit,
//     C: PrivateKeyInit<S>,
// {
//     fn new (private: S) -> Self { 
//         //Self{encapsulator: C::new(private), phantom1: PhantomData, phantom2: PhantomData}
//         return Self::new_with_encapsulator(C::new(private));
//     }
// }


// impl <C, A, EK> SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     //C: Default,
//     //EK: EncappedKey,
//     //C: Encapsulator<EK>,
// {
//     pub fn set_iv (&mut self, iv: &[u8]) { 
//         self.iv.extend(iv);
//     }
// }
// ///
// /// Implementation of the Seal trait, which creates a random ephemeral key and derives a symmetric session key from the ephemeral key
// /// and the recipients public key.
// /// The session key is used to encrypt the passed data and optional additional authentication data. The public ephemeral
// /// key and the encrypted data are returned so they can be sent to the receipient.
// /// 
// impl <C, A, EK> Seal<EK> for SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     EK: EncappedKey,
//     C: Encapsulator<EK>,
// {
//     fn try_seal <'msg, 'aad, R: CryptoRng + RngCore> (
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &EK::RecipientPublicKey,
//         //pt: &[u8],
//         pt: impl Into<Payload<'msg, 'aad>>,
//     ) -> Result<(EK, Vec<u8>), Error> 
//     {
//         let (encapsulated_key, shared_secret) = self.encapsulator.try_encap(csprng, recip_pubkey)?;
//         let encryptor = A::new_from_slice(&shared_secret.as_bytes()[0..A::KeySize::USIZE]).map_err ( |_err| return Error::AeadError)?;
        
//         let nonce = if self.iv.len() > 0 { GenericArray::<u8, A::NonceSize>::from_slice ( &self.iv ) }
//             else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE { &GenericArray::<u8, A::NonceSize>::default() }
//             else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE { GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]) }
//             else { return Err(Error::AeadError) };

//         // if self.iv.len() > 0 {
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( &self.iv );
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?));
//         // }
//         // if EK::SharedSecretSize::USIZE == A::KeySize::USIZE {
//         //     // No nonce provided, use zeros
//         //     let nonce = GenericArray::<u8, A::NonceSize>::default();
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?));
//         // } else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE {
//         //     // Nonce provided as second part of shared secret
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]);
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?))
//         // }
//         // else {
//         //     return Err(Error::AeadError)
//         // }
//         return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?))

//     }
// }


// impl <C, A, EK> SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     EK: EncappedKey,
//     C: Encapsulator<EK>,
// {
//     pub fn try_seal_detached <'msg, 'aad, R: CryptoRng + RngCore> (
//         &self,
//         csprng: &mut R,
//         recip_pubkey: &EK::RecipientPublicKey,
//         //pt: &[u8],
//         pt: impl Into<Payload<'msg, 'aad>>,
//         //iv: &[u8],
//     ) -> Result<(EK, Vec<u8>, GenericArray<u8, A::TagSize>), Error> 
    
//     {
//         let (ek, mut ct) = self.try_seal(csprng, recip_pubkey, pt)?;
//         let tag = GenericArray::from_slice(&ct[ct.len() - A::TagSize::USIZE..]).clone();
//         ct.truncate(ct.len()-A::TagSize::USIZE);
//         return Ok ((ek, ct, tag));


//         // let (encapsulated_key, shared_secret) = self.encapsulator.try_encap(csprng, recip_pubkey)?;
//         // let encryptor = A::new_from_slice(&shared_secret.as_bytes()[0..A::KeySize::USIZE]).map_err ( |_err| return Error::AeadError)?;
        
//         // if iv.len() > 0 {
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( iv );
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?));
//         // }
//         // else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE {
//         //     // No nonce provided, use zeros
//         //     let nonce = GenericArray::<u8, A::NonceSize>::default();
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?));
//         // } else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE {
//         //     // Nonce provided as second part of shared secret
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]);
//         //     return Ok((encapsulated_key, encryptor.encrypt(&nonce, pt)?))
//         // }
//         // else {
//         //     return Err(Error::AeadError)
//         // }

//     }
// }

// ///
// /// Implementation of the Open trait, which imports an ephemeral public key and derives a symmetric session key from the ephemeral key
// /// and the recipients private key.
// /// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
// /// 
// impl <'msg, 'aad, C, A, EK> Open<'msg, 'aad, EK> for SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     EK: EncappedKey,
//     C: Decapsulator<EK>,
// {
//     fn try_open(
//         &self, 
//         encapped_key: &EK,
//         ct: impl Into<Payload<'msg, 'aad>>,
//     ) -> Result<Vec<u8>, Error>
//     {
//         let shared_secret = self.encapsulator.try_decap(encapped_key)?;
    
//         let encryptor = A::new_from_slice(&shared_secret.as_bytes()[0..A::KeySize::USIZE]).map_err ( |_err| return Error::AeadError)?;

//         let nonce = if self.iv.len() > 0 { GenericArray::<u8, A::NonceSize>::from_slice ( &self.iv ) }
//             else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE { &GenericArray::<u8, A::NonceSize>::default() }
//             else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE { GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]) }
//             else { return Err(Error::AeadError) };
        
//         // if EK::SharedSecretSize::USIZE == A::KeySize::USIZE {
//         //     // No nonce provided, use zeros
//         //     let nonce = GenericArray::<u8, A::NonceSize>::default();
//         //     return Ok(encryptor.decrypt(&nonce, ct)?);
//         // } else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE {
//         //     // Nonce provided as second part of derived shared secret
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]);
//         //     return Ok(encryptor.decrypt(&nonce, ct)?);
//         // }
//         // else {
//         //     return Err(Error::AeadError)
//         // }
//         return Ok(encryptor.decrypt(&nonce, ct)?); 
//     }
    
// }

// ///
// /// Implementation of the Open trait, which imports an ephemeral public key and derives a symmetric session key from the ephemeral key
// /// and the recipients private key.
// /// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
// /// 
// impl <'msg, 'aad, C, A, EK> SimpleIes<C, A, EK> 
// where A: Aead + KeyInit,
//     EK: EncappedKey,
//     C: Decapsulator<EK>,
// {
//     pub fn try_open_detached(
//         &self, 
//         encapped_key: &EK,
//         ct: impl Into<Payload<'msg, 'aad>>,
//         tag: &[u8]
//     ) -> Result<Vec<u8>, Error>
//     {
//         let payload = ct.into();
//         let mut ct_and_tag = payload.msg.to_vec();
//         ct_and_tag.extend(tag);
//         return self.try_open ( encapped_key, Payload { msg: &ct_and_tag, aad: &payload.aad});
//         // let shared_secret = self.encapsulator.try_decap(encapped_key)?;
    
//         // let encryptor = A::new_from_slice(&shared_secret.as_bytes()[0..A::KeySize::USIZE]).map_err ( |_err| return Error::AeadError)?;

//         // if iv.len() > 0 {
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice(iv);
//         //     return Ok(encryptor.decrypt(&nonce, ct)?);
//         // }
//         // else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE {
//         //     // No nonce provided, use zeros
//         //     let nonce = GenericArray::<u8, A::NonceSize>::default();
//         //     return Ok(encryptor.decrypt(&nonce, ct)?);
//         // } else if EK::SharedSecretSize::USIZE == A::KeySize::USIZE + A::NonceSize::USIZE {
//         //     // Nonce provided as second part of derived shared secret
//         //     let nonce = GenericArray::<u8, A::NonceSize>::from_slice ( &shared_secret.as_bytes()[A::KeySize::USIZE..]);
//         //     return Ok(encryptor.decrypt(&nonce, ct)?);
//         // }
//         // else {
//         //     return Err(Error::AeadError)
//         // }
//     }
    
// }








// pub struct SimpleIes <C, A: Aead + KeyInit, EK > 
// {
//     encapsulator: PhantomData<C>,
//     phantom1: PhantomData<A>,
//     phantom2: PhantomData<EK>,
//     //iv: Vec<u8>
// } 




// enum EncapOrDecap<C: Capsulator>{
//     Encap(C::Encapsulator),
//     Decap(C::Decapsulator),
// }



// trait IesInit<C: Capsulator, E, D>
// {
//     //     fn from_bytes_decap ( private_bytes: &GenericArray<u8, D::EncodedSize>) -> D
//     // where <C as Capsulator>::Decapsulator: EncodedSizeUser2
//     // {
//     //     return SimpleIes{ encapsulator: EncapOrDecap::Decap(C::Decapsulator::from_bytes(private_bytes)), phantom1: PhantomData, iv: Array::default() }
//     // }

//     // fn from_key_decap ( key: <C::Decapsulator as FromKey>::Key) -> D
//     // //where <C as Capsulator>::Decapsulator: PrivateKeyInit<T>
//     // //where <C as Capsulator>::Decapsulator: From<T>
//     // where <C as Capsulator>::Decapsulator: FromKey,
//     //     D: FromKey
//     // {
//     //     let decapsulator = C::Decapsulator::from_key(key);
//     //     D::from_key(decapsulator)
//     // }

//     // pub fn from_key_encap (key: <C::Encapsulator as FromKey>::Key) -> SimpleIes<C, A>
//     // where <C as Capsulator>::Encapsulator: FromKey
//     // {
//     //     return SimpleIes{ encapsulator: EncapOrDecap::Encap(C::Encapsulator::from_key(key)), phantom1: PhantomData, iv: Array::default()}
//     // }
//     // // pub fn new_encryptor () -> SimpleIes<C, A, EK>
//     // // where <C as Capsulator>::Encapsulator: Default
//     // // {
//     // //     return SimpleIes{ encapsulator: EncapOrDecap::encap(C::new_encapsulator()), phantom1: PhantomData, phantom2: PhantomData, iv: Vec::new()}
//     // // }
//     // pub fn from_encapsulator (encapsulator: C::Encapsulator) -> SimpleIes<C, A>
//     // {
//     //     return SimpleIes{ encapsulator: EncapOrDecap::Encap(encapsulator), phantom1: PhantomData, iv: Array::default() }
//     // }

//     // pub fn from_decapsulator (encapsulator: C::Decapsulator) -> SimpleIes<C, A>
//     // {
//     //     return SimpleIes{ encapsulator: EncapOrDecap::Decap(encapsulator), phantom1: PhantomData, iv: Array::default() }
//     // }
// }







//
// new function for SimpleIes which accepts a private key as a parameter
// this function is designed for decryption operations
// 
// impl <C, A, KW> FromKey for IesWithKeyWrap<C, KW, A> 
// where A: Aead + KeyInit,
//     C: Capsulator,
//     C::Decapsulator: FromKey,
// {
//     type Key = <C::Decapsulator as FromKey>::Key;
//     fn from_key (private: Self::Key) -> Self { 
//         //Self{encapsulator: C::new(private), phantom1: PhantomData, phantom2: PhantomData}
//         return Self::new_from_decapsulator(C::Decapsulator::from_key(private));
//     }
// }
