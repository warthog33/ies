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
//! let ciphertext = encryptor.seal ( plaintext_message.as_ref()).unwrap();
//! 
//! let decryptor = EciesStandardX963SHA256AESGCM::from_key_decap(recipient_secret_key);
//! let recovered_plaintext = decryptor.open ( ciphertext.as_ref() ).unwrap();
//! assert! ( recovered_plaintext == plaintext_message );
//! ```

use std::{marker::PhantomData, ops::{Add, Sub}};
use std::array::TryFromSliceError;

use aead::{consts::{U16}, Aead, KeyInit, Payload, Tag, Nonce};
use aes_kw::AesKw;
use cipher::{Array, BlockCipherDecrypt, BlockSizeUser, KeySizeUser, typenum::{Diff, Sum, Unsigned}};

use kdfs::hybrid_array::ArraySize;
use kems::{EncapsulateDeterministic, EncapsulateWithKeyWrap, EncapsulateWithKeyWrapDeterministic, FromKey, SetKdf, TryDecapsulateWithKeyWrap, WrappedCek};
use kem::{Ciphertext, Encapsulate, FromSeed, InvalidKey, Kem, Key, TryDecapsulate, TryKeyInit};


pub mod ies_types;
pub mod encrypt_then_mac;
pub mod hash_encrypt;

#[cfg(all(feature = "rustcrypto-secretbox"))]
pub mod cryptobox;

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

    pub const ID_AES_128_OFB_NEW: spki_new::ObjectIdentifier = spki_new::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.3");
    
} 


///
/// Trait which includes a variety of functions to generate and initiate ies-based ciphers
/// 
pub trait Ies<C: Kem> 
{
    //type Encryptor: FromKey<Key = C::EncapsulationKey>;
    type Encryptor: From<C::EncapsulationKey>;
    /// The type of the decryptor for this IES implementation.
    //type Decryptor: FromKey<Key = C::DecapsulationKey>;
    type Decryptor: From<C::DecapsulationKey>;

    fn generate () -> (Self::Encryptor, Self::Decryptor) 
    {
        let (decapsulator, encapsulator, ) = <C as Kem>::generate_keypair();
        //(Self::Encryptor::from_key(encapsulator), Self::Decryptor::from_key(decapsulator))
        (Self::Encryptor::from(encapsulator), Self::Decryptor::from(decapsulator))
    }
    fn from_key_decap ( private: <C::DecapsulationKey as FromKey>::Key ) -> Self::Decryptor
    where C::DecapsulationKey: FromKey,
    {
        //Self::Decryptor::from_key(C::DecapsulationKey::from_key(private))
        Self::Decryptor::from(C::DecapsulationKey::from_key(private))
    }
    fn from_key_encap (key: <C::EncapsulationKey as FromKey>::Key) -> Self::Encryptor
    where C::EncapsulationKey: FromKey
    {
        Self::Encryptor::from(C::EncapsulationKey::from_key(key))
    }
    fn from_bytes_decap ( private_bytes: &Key<C::DecapsulationKey> ) -> Self::Decryptor
    where C::DecapsulationKey: KeySizeUser + KeyInit,
    {
        //Self::Decryptor::from_key(<<C as Kem>::DecapsulationKey as KeyInit>::new(private_bytes))
        Self::Decryptor::from(<<C as Kem>::DecapsulationKey as KeyInit>::new(private_bytes))
    }
    fn from_bytes_encap (public_bytes: &Key<C::EncapsulationKey>) -> Self::Encryptor
    where C::EncapsulationKey: KeyInit,
    {
        Self::Encryptor::from(<C::EncapsulationKey as KeyInit>::new(public_bytes))
    }
    fn try_from_bytes_encap (public_bytes: &Key<C::EncapsulationKey>) -> Result<Self::Encryptor, InvalidKey>
    where C::EncapsulationKey: TryKeyInit,
    {
        Ok(Self::Encryptor::from(<C::EncapsulationKey as TryKeyInit>::new(public_bytes)?))
    }
    fn try_from_slice_encap (public_bytes: &[u8]) -> Result<Self::Encryptor, InvalidKey>
    where C::EncapsulationKey: TryKeyInit
    {
        let key = C::EncapsulationKey::new_from_slice(public_bytes)?;
        Ok(Self::Encryptor::from(key))
    }
    fn try_from_slice_decap (public_bytes: &[u8]) -> Result<Self::Decryptor, std::array::TryFromSliceError>
    where C::DecapsulationKey: TryKeyInit
    {
        let key = C::DecapsulationKey::new_from_slice(public_bytes).unwrap();
        //Ok(Self::Decryptor::from_key(key))
        Ok(Self::Decryptor::from(key))
    }

    fn from_encapsulator (encapsulator: C::EncapsulationKey) -> Self::Encryptor
    {
        Self::Encryptor::from(encapsulator)
    }
    fn from_decapsulator (decapsulator: C::DecapsulationKey) -> Self::Decryptor
    {
        //Self::Decryptor::from_key(decapsulator)
        Self::Decryptor::from(decapsulator)
    }
}
    


///
/// Basic IES which uses a key encapsulation mechanism and a single key derivation function to output 
/// an encryption key
/// Used by Apples ECIES algorithm
///
pub struct SimpleIes <C: Kem, A: Aead + KeyInit > 
{
    phantom: PhantomData<C>,
    phantom1: PhantomData<A>,
} 

impl<C: Kem, A: Aead + KeyInit> Ies<C> for SimpleIes<C,A> 
where C::DecapsulationKey: FromKey,
    C::EncapsulationKey: FromKey,
{
    type Decryptor = SimpleIesDecryptor<C::DecapsulationKey,A>;
    type Encryptor = SimpleIesEncryptor<C::EncapsulationKey,A>;
}


///
/// Implementation of an encryption mechanisms whereby the output
/// of the KEM is used as the content encrpytion key. The IV can be 
/// explicitly set, otherwise it defaults to all zeros
/// 
pub struct SimpleIesEncryptor <EK, A: Aead + KeyInit > 
{
    pub encapsulator: EK,
    iv: Nonce<A>,
} 

// impl<EK, A: Aead+KeyInit> FromKey for SimpleIesEncryptor<EK, A>
// {
//     type Key = EK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { encapsulator: key, iv: Array::default()}
//     }
// }
impl<EK, A: Aead+KeyInit> From<EK> for SimpleIesEncryptor<EK,A>
{
    fn from(key: EK) -> Self {
        Self { encapsulator: key, iv: Nonce::<A>::default()}
    }
}

impl <EK, A> SimpleIesEncryptor<EK, A> 
where A: Aead + KeyInit,
{
    pub fn set_iv (&mut self, iv: Nonce<A>) { 
        self.iv = iv;
    }
}

impl <EK, A> SetKdf for SimpleIesEncryptor<EK, A> 
where A: Aead + KeyInit,
    EK: SetKdf,
{
    type Kdf = EK::Kdf;
    fn set_kdf (&mut self, kdf: Self::Kdf ) { 
        self.encapsulator.set_kdf(kdf);
    }
}
///
/// 
/// 
impl <EK, A> SimpleIesEncryptor<EK, A> 
    where A: Aead + KeyInit,
{
    pub fn seal_detached_encapsulated_key <'msg, 'aad> (
        &self,
        //csprng: &mut R,
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>), Error> 
    where EK: Encapsulate,
        EK::Kem: Kem<SharedKeySize = A::KeySize>
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate(); //.map_err(|_f|Error::KemError)?;
        let encryptor = A::new(&shared_secret);
        // it would be preferable to use one of the in-place aead functions, however the in-place functions assume ciphertext len = plaintext len
        // this is not the case with CBC Encrypt + CBC MAC which is a common AEAD used in CMS and JWE. encrypt works with vectors and therefore 
        // allows for different input and output sizes.
        return Ok((encapsulated_key, encryptor.encrypt(&self.iv, pt)?))
    }

    pub fn seal_detached_encapsulated_key_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>), Error> 
    where EK: EncapsulateDeterministic,
        EK::Kem: Kem<SharedKeySize = A::KeySize>,
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate_deterministic(seed); //.map_err(|_f|Error::KemError)?;
        let encryptor = A::new(&shared_secret.as_slice().try_into().unwrap());
        // it would be preferable to use one of the in-place aead functions, however the in-place functions assume ciphertext len = plaintext len
        // this is not the case with CBC Encrypt + CBC MAC which is a common AEAD used in CMS and JWE. encrypt works with vectors and therefore 
        // allows for different input and output sizes.
        return Ok((encapsulated_key.as_slice().try_into().unwrap(), encryptor.encrypt(&self.iv, pt)?))
    }


    ///
    /// Encrypts the provided msg with authentication of the optional authenticated data field
    /// Returns a single vector containing the encapsulated key, enciphered payload and tag
    /// 
    pub fn seal <'msg, 'aad> (
        &self,
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where EK: Encapsulate, 
        EK::Kem: Kem<SharedKeySize = A::KeySize>
    {
        let ( encapsulated_key, ct ) = self.seal_detached_encapsulated_key(pt)?;
        Ok ( [encapsulated_key.as_slice(), ct.as_slice()].concat())
    }

    pub fn seal_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where EK: EncapsulateDeterministic,
        EK::Kem: Kem<SharedKeySize = A::KeySize>,
    {
        let ( encapsulated_key, ct ) = self.seal_detached_encapsulated_key_deterministic(seed, pt)?;
        Ok ( [encapsulated_key.as_slice(), ct.as_slice()].concat())
    }

    ///
    /// Encrypted the provided msg with authenication of the optical authenticated data field
    /// Returns the encapsulated key, enciphered payload and tag as separate fields.
    pub fn seal_detached <'msg, 'aad> (
        &self,
        //csprng: &mut R,
        plaintext_payload_and_aad: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>, Tag<A>), Error> 
    where EK: Encapsulate,
        EK::Kem: Kem<SharedKeySize = A::KeySize>
    {
        let (ek, mut ct) = self.seal_detached_encapsulated_key(plaintext_payload_and_aad)?;
        let tag = ct.split_off(ct.len()-A::TagSize::USIZE);
        Ok((ek,ct,tag.as_slice().try_into().map_err(|_f|Error::LenError)?))
    }
    
    pub fn seal_detached_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        plaintext_payload_and_aad: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>, Tag<A>), Error> 
    where EK: EncapsulateDeterministic,
        EK::Kem: Kem<SharedKeySize = A::KeySize>
    {
        let (ek, mut ct) = self.seal_detached_encapsulated_key_deterministic(seed, plaintext_payload_and_aad)?;
        let tag = ct.split_off(ct.len()-A::TagSize::USIZE);
        Ok((ek,ct,tag.as_slice().try_into().map_err(|_f|Error::LenError)?))
    }
}


//pub struct SimpleIesDecryptor <C: Kem, A: Aead + KeyInit > 
pub struct SimpleIesDecryptor <DK, A: Aead + KeyInit > 
{
    //pub decapsulator: C::DecapsulationKey,
    pub decapsulator: DK,
    iv: Nonce<A>,
} 

//impl<C: Kem, A: Aead+KeyInit> FromKey for SimpleIesDecryptor<C,A>
// impl<DK, A: Aead+KeyInit> FromKey for SimpleIesDecryptor<DK,A>
// {
//     type Key = DK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { decapsulator: key, iv: Array::default()}
//     }
// }
impl<DK, A: Aead+KeyInit> From<DK> for SimpleIesDecryptor<DK,A>
{
    fn from(key: DK) -> Self {
        Self { decapsulator: key, iv: Nonce::<A>::default()}
    }
}


//impl <C: Kem, A> SimpleIesDecryptor<C, A> 
impl <DK, A> SimpleIesDecryptor<DK, A> 
where A: Aead + KeyInit,
{
    pub fn set_iv (&mut self, iv: Nonce<A>) { 
        self.iv = iv;
    }
}

//impl <C: Kem, A> SetKdf for SimpleIesDecryptor<C, A> 
impl <DK, A> SetKdf for SimpleIesDecryptor<DK, A> 
where A: Aead + KeyInit,
    DK: SetKdf,
{
    type Kdf = <DK as SetKdf>::Kdf;
    fn set_kdf (&mut self, kdf: Self::Kdf ) { 
        self.decapsulator.set_kdf(kdf);
    }
}

///
///
/// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
/// 
//impl <'msg, 'aad, C: Kem + Kem, A> SimpleIesDecryptor<C, A> 
impl <'msg, 'aad, DK, A> SimpleIesDecryptor<DK, A> 
where A: Aead + KeyInit,
    //C: Kem<SharedKeySize = A::KeySize> + Kem
    DK: TryDecapsulate,
    DK::Kem: Kem<SharedKeySize = A::KeySize> + Kem
{
    pub fn open_detached_encapsulated_key(
        &self, 
        //encapped_key: &Array<u8, C::CiphertextSize>,
        encapped_key: &Ciphertext<DK::Kem>,
        encrypted_payload_and_tag: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>
    {
        let shared_secret = self.decapsulator.try_decapsulate(encapped_key.as_slice().try_into().unwrap()).map_err(|_|Error::KemError)?;
        let encryptor = A::new(&shared_secret);
        Ok(encryptor.decrypt(&self.iv, encrypted_payload_and_tag)?)
    }
    pub fn open(
        &self, 
        encrypted_msg: impl Into<Payload<'msg, 'aad>>,    
    ) -> Result<Vec<u8>, Error>
    {
        let encrypted_msg_as_payload: Payload = encrypted_msg.into();
        //let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(C::CiphertextSize::USIZE).ok_or(Error::LenError)?;
        let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(<DK::Kem as Kem>::CiphertextSize::USIZE).ok_or(Error::LenError)?;
        self.open_detached_encapsulated_key(encapped_key_bytes.try_into().unwrap(), Payload{msg:&ciphertext, aad: encrypted_msg_as_payload.aad})
    }

    pub fn try_open_detached(
        &self, 
        //encapped_key: &Array<u8, C::CiphertextSize>,
        encapped_key: &Ciphertext<DK::Kem>,
        encrypted_payload: impl Into<Payload<'msg, 'aad>>,
        tag: &Tag<A>,
    ) -> Result<Vec<u8>, Error>
    {
        let payload = encrypted_payload.into();
        let ct_and_tag = [payload.msg, tag].concat();
        return self.open_detached_encapsulated_key ( encapped_key, Payload { msg: &ct_and_tag, aad: &payload.aad});
    }
}





///
/// Similar to SimpleIes, but with the additional of a seapraate key wrapping
/// step. This allows for the encapsulating end to explicitly select a payload encryption
/// key, allowing for multiple recipients
///
pub struct IesWithKeyWrap <C: Kem, KW, A: Aead + KeyInit> 
{
    phantom1: PhantomData<C>,
    phantom2: PhantomData<A>,
    phantom3: PhantomData<KW>,
} 

impl<C: Kem, KW, A: Aead + KeyInit> Ies<C> for IesWithKeyWrap<C,KW,A> 
{
    //type Decryptor = IesDecryptorWithKeyWrap<C,KW,A>;
    type Decryptor = IesDecryptorWithKeyWrap<C::DecapsulationKey,KW,A>;
    type Encryptor = IesEncryptorWithKeyWrap<C::EncapsulationKey,KW,A>;
}

// Generate an encryptor and decryptor for a secret seed
impl<C: Kem, KW, A: Aead + KeyInit> IesWithKeyWrap<C,KW,A> 
where C: Kem + FromSeed,    
{
    pub fn derive_from_seed(seed: &Array::<u8, <C as FromSeed>::SeedSize>) -> 
        Result<(<Self as Ies<C>>::Encryptor, <Self as Ies<C>>::Decryptor ), ()>
    {
        let (decapsulator, encapsulator ) = C::from_seed(seed); //.map_err(|_|())?;
        Ok((IesEncryptorWithKeyWrap::<C::EncapsulationKey,KW,A>{encapsulator, phantom1: PhantomData, phantom2: PhantomData},
            IesDecryptorWithKeyWrap::<C::DecapsulationKey,KW,A>{decapsulator, phantom1: PhantomData, phantom2: PhantomData}))
    }
}


pub struct IesEncryptorWithKeyWrap <EK, KW, A: Aead + KeyInit> 
{
    encapsulator: EK,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<KW>,
} 



// impl<EK, A: Aead+KeyInit, KW> FromKey for IesEncryptorWithKeyWrap<EK, KW, A> 
// {
//     type Key = EK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { encapsulator: key, phantom1: PhantomData, phantom2: PhantomData}
//     }
// }
impl<EK, A: Aead+KeyInit, KW> From<EK> for IesEncryptorWithKeyWrap<EK, KW, A> 
{
    fn from(key: EK) -> Self {
        Self { encapsulator: key, phantom1: PhantomData, phantom2: PhantomData}
    }
}


impl<EK, A: Aead+KeyInit, KW> SetKdf for IesEncryptorWithKeyWrap<EK, KW, A>
where EK: SetKdf
{
    type Kdf = EK::Kdf;
    fn set_kdf(&mut self, kdf: Self::Kdf )
    {
        self.encapsulator.set_kdf(kdf);
    }
}

impl <EK, A, KW> IesEncryptorWithKeyWrap<EK, KW, A> 
where A: Aead + KeyInit,
    //C: Kem,
    EK: EncapsulateWithKeyWrap<AesKw<KW>, A::KeySize, CekSize=A::KeySize>,
    //C::EncapsulationKey: EncapsulateWithKeyWrap<AesKw<KW>, A::KeySize, CekSize=A::KeySize>,
{
    pub fn seal_detached_encapsulated_key <'msg, 'aad> (
        &self,
        //csprng: &mut R,
        content_encryption_key: &Key<A>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Nonce<A>,
    ) -> Result<(Ciphertext<EK::Kem>, 
        //Array::<u8, <C::EncapsulationKey as EncapsulateWithKeyWrap<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        Array::<u8, <EK as WrappedCek<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        Vec<u8>), Error> 
    {
        let (encapsulated_key, wrapped_cek) = self.encapsulator.encapsulate_and_wrap(content_encryption_key).map_err(|_|Error::KemError)?;
        let data_encryptor = A::new(content_encryption_key);

        let enciphered_data = data_encryptor.encrypt(&nonce, pt)?;
        Ok ((encapsulated_key, wrapped_cek, enciphered_data))
    }

    /// Encapsulate and encrypt payload using the provided content encryption key
    pub fn seal_detached <'msg, 'aad> (
        &self,
        content_encryption_key: &Key<A>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Nonce<A>,
    ) -> Result<(Ciphertext<EK::Kem>, 
        Array::<u8, <EK as WrappedCek<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        Vec<u8>, 
        Tag<A>), Error>
    {
        let (encapsulated_key, wrapped_cek, mut enciphered_data) = self.seal_detached_encapsulated_key(content_encryption_key, pt, nonce)?;

        let tag = enciphered_data.drain((enciphered_data.len() - A::TagSize::USIZE)..);
        let tag2 = Array::from_iter(tag);
        Ok ((encapsulated_key, wrapped_cek, enciphered_data, tag2))
    }

    ///
    /// Function which encrypts a ciphertext and returns a blob to be transferred to the recipient.
    /// The blob contains the encapsulated key, wrapped cek, enciphered data and tag 
    /// 
    pub fn seal <'msg, 'aad> (
        &self,
        content_encryption_key: &Key<A>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error> 
    {
        let (encapsulated_key, wrapped_cek, enciphered_data) = self.seal_detached_encapsulated_key(content_encryption_key, pt, nonce)?;
        Ok ([encapsulated_key.as_slice(), wrapped_cek.as_slice(), enciphered_data.as_slice()].concat())
    }

}




impl <EK, A, KW> IesEncryptorWithKeyWrap<EK, KW, A> 
where A: Aead + KeyInit,
    EK: EncapsulateWithKeyWrapDeterministic<AesKw<KW>, A::KeySize, CekSize=A::KeySize>,
{
    pub fn seal_detached_encapsulated_key_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        content_encryption_key: &Key<A>,
        pt: impl Into<Payload<'msg, 'aad>>,
        nonce: &Nonce<A>,
    ) -> Result<(
        Ciphertext<EK::Kem>,
        //Array<u8, C::CiphertextSize>, 
        Array::<u8, <EK as WrappedCek<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        Vec<u8>), Error> 
    where EK: EncapsulateDeterministic
    {
        let (encapsulated_key, wrapped_cek) = self.encapsulator.encapsulate_and_wrap_deterministic(seed, content_encryption_key).map_err(|_|Error::KemError)?;
        let data_encryptor = A::new(content_encryption_key);
        let enciphered_data = data_encryptor.encrypt(&nonce, pt)?;
        Ok ((encapsulated_key, wrapped_cek, enciphered_data))
    }
}


//pub struct IesDecryptorWithKeyWrap <C: Kem, KW, A: Aead + KeyInit> 
pub struct IesDecryptorWithKeyWrap <DK, KW, A: Aead + KeyInit> 
{
    //decapsulator: C::DecapsulationKey,
    decapsulator: DK,
    phantom1: PhantomData<A>,
    phantom2: PhantomData<KW>,
} 


//impl<C: Kem, A: Aead+KeyInit, KW> FromKey for IesDecryptorWithKeyWrap<C, KW, A> 
// impl<DK, A: Aead+KeyInit, KW> FromKey for IesDecryptorWithKeyWrap<DK, KW, A> 
// {
//     type Key = DK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { decapsulator: key, phantom1: PhantomData, phantom2: PhantomData}
//     }
// }
impl<DK, A: Aead+KeyInit, KW> From<DK> for IesDecryptorWithKeyWrap<DK, KW, A> 
{
    fn from(key: DK) -> Self {
        Self { decapsulator: key, phantom1: PhantomData, phantom2: PhantomData}
    }
}

//impl<C: Kem, A: Aead+KeyInit, KW> SetKdf for IesDecryptorWithKeyWrap<C, KW, A> 
impl<DK, A: Aead+KeyInit, KW> SetKdf for IesDecryptorWithKeyWrap<DK, KW, A> 
//where C::DecapsulationKey: SetKdf
where DK: SetKdf
{
    type Kdf = <DK as SetKdf>::Kdf;
    fn set_kdf(&mut self, kdf: Self::Kdf )
    {
        self.decapsulator.set_kdf(kdf);
    }
}

///
/// The session key is used to decrypt the passed data and optional additional authentication data. Decrypted data is returned or an error.
/// 
//impl <'msg, 'aad, C, A, KW> IesDecryptorWithKeyWrap<C, KW, A> 
impl <'msg, 'aad, DK, A, KW> IesDecryptorWithKeyWrap<DK, KW, A> 
where A: Aead + KeyInit,
    //C: Kem,
    KW: KeyInit + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
    //C: Kem<SharedKeySize = KW::KeySize>,
    DK: TryDecapsulateWithKeyWrap<AesKw<KW>, A::KeySize, CekSize = A::KeySize>,
    DK::Kem: Kem<SharedKeySize = KW::KeySize>,
    //C::DecapsulationKey: TryDecapsulateWithKeyWrap<AesKw<KW>, A::KeySize, CekSize=A::KeySize>,
{
    ///
    /// Opening of a payload where the encapped_key and encrypted_key are separate fields, but the tag is embedded into the ct
    /// 
    pub fn open_semi_detached(
        &self, 
        //encapped_key: &Array<u8, C::CiphertextSize>,
        encapped_key: &Ciphertext<DK::Kem>,
        //encrypted_key: &Array<u8, <C::DecapsulationKey as TryDecapsulateWithKeyWrap<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        encrypted_key: &Array<u8, <DK as WrappedCek<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        ct: impl Into<Payload<'msg, 'aad>>,
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error>
   
    {
        let shared_secret = self.decapsulator.decapsulate_and_unwrap(encapped_key, encrypted_key).map_err(|_|Error::AeadError)?;
        let encryptor = A::new(&shared_secret);
        Ok(encryptor.decrypt(&nonce, ct)?)
    }

    /// 
    /// Opening of a payload where each field is a separate parameter
    ///  
    pub fn open_detached(
        &self, 
        //encapped_key: &Array<u8, C::CiphertextSize>,
        encapped_key: &Ciphertext<DK::Kem>,
        //encrypted_key: &Array<u8, <C::DecapsulationKey as TryDecapsulateWithKeyWrap<Array<u8, C::CiphertextSize>, Array<u8, C::SharedKeySize>, AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        //encrypted_key: &Array<u8, <C::DecapsulationKey as TryDecapsulateWithKeyWrap<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        encrypted_key: &Array<u8, <DK as WrappedCek<AesKw<KW>, A::KeySize>>::WrappedCekSize>,
        ct: impl Into<Payload<'msg, 'aad>>,
        tag: &Tag<A>,
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
        nonce: &Nonce<A>,
    ) -> Result<Vec<u8>, Error>
    {
        let payload = ct.into();
        //let (encapsulated_key, rem) = payload.msg.split_at(C::CiphertextSize::USIZE);
        let (encapsulated_key, rem) = payload.msg.split_at(<DK::Kem as Kem>::CiphertextSize::USIZE);
        let (encrypted_key, rem) = rem.split_at(KW::KeySize::USIZE);
        let encrypted_key = Array::slice_as_array(encrypted_key).unwrap();
        let (encrypted_msg, tag) = rem.split_at(rem.len() - A::TagSize::USIZE);
        let tag = Array::slice_as_array(tag).unwrap();
        self.open_detached(Array::slice_as_array(encapsulated_key).unwrap(), encrypted_key, Payload { msg: encrypted_msg, aad: payload.aad}, tag, nonce)
    }
       
}


/// Implementaiton of an IES where the shared secret is used for both symmetric encryption key and the IV
pub struct IesWithDerivedIv<C: Kem, A: Aead + KeyInit> ( PhantomData<C>, PhantomData<A>);

impl<C: Kem, A: Aead + KeyInit> Ies<C> for IesWithDerivedIv<C,A> 
{
    type Decryptor = IesDecryptorWithDerivedIv<C::DecapsulationKey,A>;
    type Encryptor = IesEncryptorWithDerivedIv<C::EncapsulationKey,A>;
}


pub struct IesEncryptorWithDerivedIv <EK, A: Aead + KeyInit> 
{
    encapsulator: EK,
    phantom1: PhantomData<A>,
} 

// impl<EK, A: Aead+KeyInit> FromKey for IesEncryptorWithDerivedIv<EK,A>
// {
//     type Key = EK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { encapsulator: key, phantom1: PhantomData}
//     }
// }
impl<EK, A: Aead+KeyInit> From<EK> for IesEncryptorWithDerivedIv<EK,A>
{
    fn from(key: EK) -> Self {
        Self { encapsulator: key, phantom1: PhantomData}
    }
}

impl<EK, A: Aead + KeyInit> IesEncryptorWithDerivedIv<EK, A>
{
    ///
    /// Function which returns the encapsulated key and encrypted data in two separate values
    /// The encrypted data includes the authentication tag
    /// 
    pub fn seal_semi_detached <'msg, 'aad> (
        &self,
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>), Error> 
    where EK: Encapsulate,
        <EK::Kem as Kem>::SharedKeySize: Sub<A::KeySize, Output=A::NonceSize>,
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate();
        let (shared_secret_key, nonce) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(shared_secret_key);
        
        Ok((encapsulated_key, encryptor.encrypt(nonce, pt)?))
    }

    ///
    /// Function which combines all data into a single return buffer
    /// 
    pub fn seal <'msg, 'aad> (
        &self,
        pt: impl Into<Payload<'msg, 'aad>>
    ) -> Result<Vec<u8>, Error> 
    where EK: Encapsulate,
        <EK::Kem as Kem>::SharedKeySize: Sub<A::KeySize, Output=A::NonceSize>,
    {
        let ( encapsulated_key, encrypted_data ) = self.seal_semi_detached(pt)?;
        Ok ([encapsulated_key.as_slice(), encrypted_data.as_slice()].concat())
    }

    pub fn seal_semi_detached_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<(Ciphertext<EK::Kem>, Vec<u8>), Error> 
    where EK: EncapsulateDeterministic,
        <EK::Kem as Kem>::SharedKeySize: Sub<A::KeySize, Output=A::NonceSize>
    {
        let (encapsulated_key, shared_secret) = self.encapsulator.encapsulate_deterministic(seed);
        
        let (shared_secret_key, nonce) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(shared_secret_key);
        Ok((encapsulated_key, encryptor.encrypt(nonce, pt)?))
    }

    pub fn seal_deterministic <'msg, 'aad> (
        &self,
        seed: &[u8],
        pt: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error> 
    where EK: EncapsulateDeterministic,
        <EK::Kem as Kem>::SharedKeySize: Sub<A::KeySize, Output=A::NonceSize>
    {
        let (encapsulated_key, encrypted_data) = self.seal_semi_detached_deterministic(seed, pt)?; 
        Ok([encapsulated_key.as_slice(), encrypted_data.as_slice()].concat())
    }


}


/// Integrated encryption scheme where both the encryption key and IV are extracted from the shared secret
//pub struct IesDecryptorWithDerivedIv <C: Kem, A: Aead + KeyInit> 
pub struct IesDecryptorWithDerivedIv <DK, A: Aead + KeyInit> 
{
    //decapsulator: C::DecapsulationKey,
    decapsulator: DK,
    phantom: PhantomData<A>,
} 

//impl<C: Kem, A: Aead+KeyInit> FromKey for IesDecryptorWithDerivedIv<C,A>
// impl<DK, A: Aead+KeyInit> FromKey for IesDecryptorWithDerivedIv<DK,A>
// {
//     //type Key = C::DecapsulationKey;
//     type Key = DK;
//     fn from_key(key: Self::Key) -> Self {
//         Self { decapsulator: key, phantom: PhantomData}
//     }
// }

impl<DK, A: Aead+KeyInit> From<DK> for IesDecryptorWithDerivedIv<DK,A>
{
    //type Key = C::DecapsulationKey;
    fn from(key: DK) -> Self {
        Self { decapsulator: key, phantom: PhantomData}
    }
}

//impl<C: Kem, A: Aead + KeyInit> IesDecryptorWithDerivedIv<C, A>
impl<DK, A: Aead + KeyInit> IesDecryptorWithDerivedIv<DK, A>
//where C: Kem<SharedKeySize=Sum<A::KeySize, A::NonceSize>>,
where DK: TryDecapsulate,
    DK::Kem: Kem<SharedKeySize=Sum<A::KeySize, A::NonceSize>>,
    <DK::Kem as Kem>::SharedKeySize: Sub<A::KeySize>,
    Diff<<DK::Kem as Kem>::SharedKeySize, A::KeySize>: ArraySize,
    A::KeySize: Add<A::NonceSize>,
    Sum<A::KeySize, A::NonceSize>: ArraySize + Sub<A::KeySize, Output=A::NonceSize>,

{
    ///
    /// Open a payload where the encapsulated key and encrypted data are separate parameters
    /// The authentication tag is appended to the encrypted data
    /// 
    pub fn open_semi_detached<'msg, 'aad>(
        &self, 
        encapped_key: &Ciphertext<DK::Kem>,
        ct: impl Into<Payload<'msg, 'aad>>,
    ) -> Result<Vec<u8>, Error>

    {
        let shared_secret = self.decapsulator.try_decapsulate(encapped_key).map_err(|_|Error::KemError)?;
        let ( key, nonce ) = shared_secret.split_ref::<A::KeySize>();
        let encryptor = A::new(key);
        Ok(encryptor.decrypt(nonce, ct)?)
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
        let (encapped_key_bytes, ciphertext) = encrypted_msg_as_payload.msg.split_at_checked(<DK::Kem as Kem>::CiphertextSize::USIZE).ok_or(Error::LenError)?;
        self.open_semi_detached(encapped_key_bytes.try_into().unwrap(), Payload{msg:ciphertext, aad: encrypted_msg_as_payload.aad})
    }
}


