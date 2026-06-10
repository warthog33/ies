#[allow(unused)]
use super::SimpleIes;
#[allow(unused)]
use crate::IesWithDerivedIv;
#[allow(unused)]
use crate::IesWithKeyWrap;

// #[cfg(all(feature = "rustcrypto-alternate"))]
// use crypto_secretbox::XSalsa20Poly1305;
//use kdfs::misc::CryptoBoxKdf;


#[allow(unused)]
use kdfs::nistsp800_56::ConcatKdf;
#[allow(unused)]
use kems::eckem::{EcUncompressedEncoder, EcdhKemUncompressed, EcdhKem, EcRawEncoder};
#[allow(unused)]
use kems::kem_with_kdf::{CombinerEphemOnly, CombinerNoKeys, JwaKdf, KemWithKdf};
#[cfg(feature="rustcrypto-rsa")]
use kems::rsakem::{Oaep2, RsaKem};
// #[cfg(feature="rustcrypto-x25519")]
// use kems::x25519kem::{X25519Capsulator};

#[cfg(all(feature = "rustcrypto-rsa"))]
use rsa::Pkcs1v15Encrypt;
#[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-sha2", feature="rustcrypto-hmac", feature="rustcrypto-cbc"))]
use crate::rfc7518::A128CbcHS256;
#[allow(unused)]
use crate::hash_encrypt::HashEncryption;
#[allow(unused)]
use kems::generic_array::typenum::consts::*;

pub type X963Kdf<H> = kdfs::ansi_x9_63::X963Kdf<H>;

#[cfg(feature = "rustcrypto-aes")]
use aes_gcm::{AesGcm,Aes256Gcm,aes::{Aes128, Aes256}};
#[cfg(feature = "rustcrypto-sha1")]
use sha1::Sha1;
#[cfg(feature = "rustcrypto-sha2")]
use sha2::{Sha224, Sha256, Sha384, Sha512};
#[cfg(all(feature = "rustcrypto-sm2"))]
use sm2::Sm2;
#[allow(unused)]
use kems::eckem::SeedAsScalar;


/// Implementation of Apple's eciesEncryptionStandardX963SHA1AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-1 implementation and AES-128 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha1", feature="rustcrypto-aes"))]
pub type EciesStandardX963SHA1AESGCM<C>           = SimpleIes<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha1>, U16>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardX963SHA224AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-256 implementation and AES-128 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardX963SHA224AESGCM<C>           = SimpleIes<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha224>, U16>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardX963SHA256AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-256 implementation and AES-128 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardX963SHA256AESGCM<C>           = SimpleIes<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha256>, U16>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardX963SHA384AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-384 implementation and AES-256 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardX963SHA384AESGCM<C>           = SimpleIes<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha384>, U32>, AesGcm<Aes256,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardX963SHA512AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-384 implementation and AES-256 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardX963SHA512AESGCM<C>           = SimpleIes<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha512>, U32>, AesGcm<Aes256,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardVariableIVX963SHA224AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-224 implementation and AES-128 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardVariableIVX963SHA224AESGCM<C>           = IesWithDerivedIv<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha224>, U32>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardVariableIVX963SHA256AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-256 implementation and AES-128 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardVariableIVX963SHA256AESGCM<C>           = IesWithDerivedIv<KemWithKdf<EcdhKemUncompressed<C,SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha256>, U32>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardVariableIVX963SHA384AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-384 implementation and AES-256 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardVariableIVX963SHA384AESGCM<C>           = IesWithDerivedIv<KemWithKdf<EcdhKemUncompressed<C, SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha384>, U48>, AesGcm<Aes256,U16,U16>>;

/// Implementation of Apple's eciesEncryptionStandardVariableIVX963SHA512AESGCM elliptic curve decryption algorithm
/// Key derivation uses X9.63 kdf with rust-cryptos native SHA-512 implementation and AES-256 GCM is used for authenticated encryption. The AES nonce is zero.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type EciesStandardVariableIVX963SHA512AESGCM<C>           = IesWithDerivedIv<KemWithKdf<EcdhKemUncompressed<C, SeedAsScalar>, CombinerEphemOnly, X963Kdf<Sha512>, U48>, AesGcm<Aes256,U16,U16>>;

/// Implementation of Apple's rsaEncryptionOAEPSHA1AESGCM cipher
/// The method uses RSA OAEP to encrypt an ephemeral AES-128 key. SHA-1 is used for both hashing and the mask generation function. The IV used in AES GCM is 16 bytes of zeros.
/// Note that to be compatible with the Apple implementation the DER encoded public key needs to be used as the Additional Authentication Data to the AES GCM function.
#[cfg(all(feature = "rustcrypto-sha1", feature="rustcrypto-aes"))]
pub type RsaOAEPSHA1AESGCM<M> = SimpleIes<RsaKem<M, U16, Oaep2<sha1::Sha1,sha1::Sha1>>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's rsaEncryptionOAEPSHA1AESGCM cipher
/// The method uses RSA OAEP to encrypt an ephemeral AES-128 key. SHA-224 is used for both hashing and the mask generation function. The IV used in AES GCM is 16 bytes of zeros.
/// Note that to be compatible with the Apple implementation the DER encoded public key needs to be used as the Additional Authentication Data to the AES GCM function.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type RsaOAEPSHA224AESGCM<M> = SimpleIes<RsaKem<M, U16, Oaep2<sha2::Sha224,sha2::Sha224>>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's rsaEncryptionOAEPSHA1AESGCM elliptic curve decryption algorithm
/// The method uses RSA OAEP to encrypt an ephemeral AES-128 key. SHA-256 is used for both hashing and the mask generation function. The IV used in AES GCM is 16 bytes of zeros. 
/// Note that to be compatible with the Apple implementation the DER encoded public key needs to be used as the Additional Authentication Data to the AES GCM function.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type RsaOAEPSHA256AESGCM<M> = SimpleIes<RsaKem<M, U16, Oaep2<sha2::Sha256,sha2::Sha256>>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's rsaEncryptionOAEPSHA1AESGCM elliptic curve decryption algorithm
/// The method uses RSA OAEP to encrypt an ephemeral AES-128 key. SHA-384 is used for both hashing and the mask generation function. The IV used in AES GCM is 16 bytes of zeros 
/// Note that to be compatible with the Apple implementation the DER encoded public key needs to be used as the Additional Authentication Data to the AES GCM function.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type RsaOAEPSHA384AESGCM<M> = SimpleIes<RsaKem<M, U16, Oaep2<sha2::Sha384,sha2::Sha384>>, AesGcm<Aes128,U16,U16>>;

/// Implementation of Apple's rsaEncryptionOAEPSHA512AESGCM elliptic curve decryption algorithm
/// The method uses RSA OAEP to encrypt an ephemeral AES-128 key. SHA-512 is used for both hashing and the mask generation function. The IV used in AES GCM is 16 bytes of zeros 
/// Note that to be compatible with the Apple implementation the DER encoded public key needs to be used as the Additional Authentication Data to the AES GCM function.
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-aes"))]
pub type RsaOAEPSHA512AESGCM<M> = SimpleIes<RsaKem<M, U16, Oaep2<sha2::Sha512,sha2::Sha512>>, AesGcm<Aes128,U16,U16>>;

/// Ecies cryptor using the cryptbox algorithm from libsodium. Uses X25519 curve with XSala20 encryption and Poly1305 MACing
//#[cfg(all(feature = "rustcrypto-x25519", feature = "rustcrypto-blake2"))]
// pub type EciesSodiumX25519      = SimpleIes<KemWithKdf<X25519Capsulator<SeedAsScalar>, CombinerEphemOnly, CryptoBoxKdf<blake2::Blake2b::<U24>>, U56>, XSalsa20Poly1305>;
//type EciesSodiumX255192      = IesWithDerivedIv<KemWithKdf::<X25519Capsulator<SeedAsScalar>, kems::kem_with_kdf::CombinerAllPubKeys, CryptoBoxKdf<blake2::Blake2b::<U24>>, U56>, XSalsa20Poly1305Wrapper>;


/// Ecies encryptor using the EC encryption mechanism from GM/T 0003, which uses SM2 curve with SM3 hash function
#[cfg(all(feature = "rustcrypto-sm2", feature="rustcrypto-sm3"))]
pub type EciesSm2          = SimpleIes<EcdhKem<Sm2, EcUncompressedEncoder<Sm2>, kems::eckem::SeedAsScalar, EcRawEncoder<Sm2>>, HashEncryption<sm3::Sm3, U64>>;

/// Ecies encryptor using the JWE encryption mechanism with AesCbcHs128 encryption
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-cbc", feature="rustcrypto-hmac"))]
//pub type EciesJweA128CbcHs256<'a,C> = SimpleIes::<EcdhKemUncompressed::<C,kems::eckem::EcCombinerJwa<'a,Sha256>,U32, kems::eckem::SeedAsScalar>, A128CbcHS256>;
pub type EciesJweA128CbcHs256<'a,C> = SimpleIes::<KemWithKdf<EcdhKemUncompressed::<C,kems::eckem::SeedAsScalar>, CombinerNoKeys, JwaKdf<'a,ConcatKdf<Sha256>,true>, U32>, A128CbcHS256>;

/// Ecies encryptor using the JWE encryption mechanism with AesKw128 and AesCbcHs128 encryption
#[cfg(all(feature = "rustcrypto-sha2", feature="rustcrypto-cbc", feature="rustcrypto-hmac"))]
//pub type EciesA256KwJweA128CbcHs256<'a,C> = IesWithKeyWrap::<EcdhKemUncompressed::<C,kems::eckem::EcCombinerJwa<'a,Sha256>,U32, kems::eckem::SeedAsScalar>, Aes256, A128CbcHS256>;
pub type EciesA256KwJweA128CbcHs256<'a,C> = IesWithKeyWrap::<KemWithKdf<EcdhKemUncompressed::<C,kems::eckem::SeedAsScalar>, CombinerNoKeys, JwaKdf<'a,ConcatKdf<Sha256>,true>, U32>, Aes256, A128CbcHS256>;

/// RSA hybrid encryption as used by JWE when "alg"=RSA-OAEP and "enc"=A256GCM. 
/// RSA-OEAP (with SHA-1) is used to encrypt a content encryption key. The CEK is used to encrypt the payload using Aes in GCM mode
/// The generic parameter L is the size of the RSA modulus
#[cfg(all(feature = "rustcrypto-rsa", feature="rustcrypto-sha1", feature="rustcrypto-aes"))]
pub type RsaesOaepJweA256Gcm<L> = SimpleIes::<RsaKem<L, U32, Oaep2<sha1::Sha1,sha1::Sha1>>, Aes256Gcm>;

/// RSA hybrid encryption as used by JWE when "alg"=RSA-OAEP-256 and "enc"=A256GCM.
/// RSA-OEAP to encrypt a content encryption key. The CEK is used to encrypt the payload using Aes
/// The generic parameter L is the size of the RSA modulus
#[cfg(all(feature = "rustcrypto-sha2"))]
pub type RsaesOaep256IesJweA256Gcm<L> = SimpleIes::<RsaKem<L, U32, Oaep2<Sha256,Sha256>>, Aes256Gcm>;

/// RSA hybrid encryption as used by JWE when "alg"=RSAES-PKCS1-v1_5 and "enc"=A128CBC-HS256. 
/// RSA-PKCS#1 v1.5 is used to encrypt a content encryption key. The CEK is used to encrypt the payload using Aes
/// The generic parameter L is the size of the RSA modulus
#[cfg(all(feature = "rustcrypto-rsa", feature="rustcrypto-aes", feature="rustcrypto-hmac", feature="rustcrypto-sha2", feature="rustcrypto-cbc"))]
pub type RsaesPkcs15IesJweA128CbcHS256<L> = SimpleIes::<RsaKem<L, U32, Pkcs1v15Encrypt>, A128CbcHS256>;