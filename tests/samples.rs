

use aes::Aes128;
use aead::Generate;
use aes_gcm::{KeyInit};
use aes_gcm::aead::{Aead,Payload};
use ctr::Ctr64BE;
use ctr::cipher::{KeyIvInit,StreamCipher};
use elliptic_curve::sec1::FromSec1Point;
use elliptic_curve::{PrimeField,Scalar};
use elliptic_curve::consts::*;
use elliptic_curve::ecdh::diffie_hellman;
use elliptic_curve::point::{AffineCoordinates,DecompactPoint};
use elliptic_curve::ff::FromUniformBytes;
use ies::{Ies};
use ies::ies_types::{EcdhKemP256EmvCmac128, EciesCompactX963SHA256AESGCM, EciesSm2, EciesStandardVariableIVX963SHA512AESGCM, X963Kdf};
use ies::ies_types::{RsaOAEPSHA224AESGCM, RsaOAEPSHA256AESGCM,RsaOAEPSHA384AESGCM,RsaOAEPSHA512AESGCM,RsaesPkcs15IesJweA128CbcHS256};
use ies::ies_types::{RsaOAEPSHA1AESGCM, EciesStandardVariableIVX963SHA384AESGCM, EciesStandardX963SHA384AESGCM, EciesStandardX963SHA512AESGCM};
use ies::ies_types::{EciesStandardVariableIVX963SHA256AESGCM, EciesStandardX963SHA256AESGCM,EciesStandardVariableIVX963SHA224AESGCM, EciesStandardX963SHA1AESGCM}; 
use hex_literal::hex;
use kdfs::Kdf;
use kdfs::hybrid_array::Array;
use kdfs::emv::{EmvCmacAes128,EmvSessionKeyType,EmvCommonSessionKdf};

use kem::{Kem, Decapsulate, Decapsulator, Encapsulate, KeyExport};
use kems::rsakem::{RsaDecapsulator, RsaRaw};
use kems::{OsRng, RngCore, KemExtensions,FromKey,EncapsulateDeterministic};
use kems::iso18033_2::{EciesKemCompressedKdf1, EciesKemUncompressedKdf1, RsaKemKdf1, RsaKemKdf2};
use kems::kem_with_kdf::{CombinerCiphertext, KemWithKdf};
use kems::eckem::*;

use rsa::pkcs1::{DecodeRsaPrivateKey,EncodeRsaPublicKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

use p192::NistP192;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use sha1::Sha1;
use sha2::Sha256;

pub mod common;



#[test]
#[allow(non_snake_case, unused)]
fn test_iso18033_c_2_2() {
    //Group=ECModp-Group:
    let p = hex!("fffffffffffffffffffffffffffffffeffffffffffffffff");
    let a = hex!("fffffffffffffffffffffffffffffffefffffffffffffffc");
    let b = hex!("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
    let mu = hex!("ffffffffffffffffffffffff99def836146bc9b1b4d22831");
    let nu = hex!("01");
    let g_x = hex!("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
    let g_y = hex!("07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

    // Public Key
    let h_x = hex!("1cbc74a41b4e84a1509f935e2328a0bb06104d8dbb8d2130");
    let h_y = hex!("7b2ab1f10d76fde1ea046a4ad5fb903734190151bb30cec2");
    //Private Key
    let x = hex!("b67048c28d2d26a73f713d5ebb994ac92588464e7fe7d3f3");

    // Encrypt
    let r = hex!("083d4ac64f1960a9836a84f91ca211a185814fa43a2c8f21");
    let _r_prime = hex!("083d4ac64f1960a9836a84f91ca211a185814fa43a2c8f21");
    let _g_tilde_x = hex!("ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df");
    let _g_tilde_y = hex!("047b2e07dd2ffb89359945f3d22ca8757874be2536e0f924");
    let _h_tilde_x = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let _h_tilde_y = hex!("0cae66e42ae0dd8857ab670c6397c93c1769f9a5f5b9d36d");
    let _peh = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let _z = hex!("04ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df047b2e07dd2ffb89\
        359945f3d22ca8757874be2536e0f924");
    let c0 = hex!("04ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df047b2e07dd2ffb8\
        9359945f3d22ca8757874be2536e0f924");
    let k = hex!("9a709adeb6c7590ccfc7d594670dd2d74fcdda3f8622f2dbcf0f0c02966d5d9002\
        db578c989bf4a5cc896d2a11d74e0c51efc1f8ee784897ab9b865a7232b5661b7cac\
        87cf4150bdf23b015d7b525b797cf6d533e9f6ad49a4c6de5e7089724c9cadf0adf1\
        3ee51b41be6713653fc1cb2c95a1d1b771cc7429189861d7a829f3");
    
    let encoded_point = p192::Sec1Point::from_affine_coordinates(&h_x.into(), &h_y.into(), false);
    let encap_key = elliptic_curve::PublicKey::<NistP192>::from_sec1_point(&encoded_point).unwrap();
    let encapsulator = EciesKemUncompressedKdf1::<NistP192,Sha1,U128>::from_public_key(encap_key);
    let (c0_calc, k_calc ) = encapsulator.encapsulate_deterministic(&r);
    assert_eq! ( c0_calc, c0);
    assert_eq! ( k_calc, k );
    
    // Decapsulate
    let decapsulator = EciesKemUncompressedKdf1::<NistP192,Sha1,U128>::try_from_slice_decap(&x).unwrap();
    
    let k_calc2 = decapsulator.decapsulate(&c0_calc);
    assert! ( k_calc2 == k);

}

#[test]
#[allow(non_snake_case)]
fn test_iso_18033_2_c_2_3 () {
    //Group=ECModp-Group:
    let _p = hex!("fffffffffffffffffffffffffffffffeffffffffffffffff");
    let _a = hex!("fffffffffffffffffffffffffffffffefffffffffffffffc");
    let _b = hex!("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1");
    let _mu = hex!("ffffffffffffffffffffffff99def836146bc9b1b4d22831");
    let _nu = hex!("01");
    let _g_x = hex!("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012");
    let _g_y = hex!("07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

    //Public Key
    let h_x = hex!("1cbc74a41b4e84a1509f935e2328a0bb06104d8dbb8d2130");
    let _h_y = hex!("7b2ab1f10d76fde1ea046a4ad5fb903734190151bb30cec2");
    //-----
    //Private Key
    let x = hex!("b67048c28d2d26a73f713d5ebb994ac92588464e7fe7d3f3");
    //Encoding format = compressed_fmt
    let r = hex!("083d4ac64f1960a9836a84f91ca211a185814fa43a2c8f21");
    let _r_prime = hex!("083d4ac64f1960a9836a84f91ca211a185814fa43a2c8f21");
    let _g_tilde_x = hex!("ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df");
    let _g_tilde_y = hex!("047b2e07dd2ffb89359945f3d22ca8757874be2536e0f924");
    let _h_tilde_x = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let _h_tilde_y = hex!("0cae66e42ae0dd8857ab670c6397c93c1769f9a5f5b9d36d");
    let _peh = hex!("cdec12c4cf1cb733a2a691ad945e124535e5fc10c70203b5");
    let _z = hex!("02ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df");
    let c0 = hex!("02ccc9ea07b8b71d25646b22b0e251362a3fa9e993042315df");
    let k = hex!("8fbe0903fac2fa05df02278fe162708fb432f3cbf9bb14138d22be1d279f74bfb9\
        4f0843a153b708fcc8d9446c76f00e4ccabef85228195f732f4aedc5e48efcf2968c\
        3a46f2df6f2afcbdf5ef79c958f233c6d208f3a7496e08f505d1c792b314b45ff647\
        237b0aa186d0cdbab47a00fb4065d62cfc18f8a8d12c78ecbee3fd");

    // Encapsulate
    let encapsulator = EciesKemCompressedKdf1::<NistP192,Sha1,U128>::try_from_bytes_encap(&(&[[2u8].as_slice(), &h_x].concat().try_into().unwrap())).unwrap(); //new(kdf);
    
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&r);
    assert! ( c0_calc.as_slice() == &c0);
    assert! ( k_calc == k );

    // Decapsulate
    let decapsulator = EciesKemCompressedKdf1::<NistP192,Sha1,U128>::try_from_slice_decap(&x).unwrap();
    let k_calc2 = decapsulator.decapsulate(&c0_calc);
    assert! ( k_calc2 == k);

}

// #[test]
// fn test_iso_18033_2_c_2_4() {
//     //Group=ECGF2-Group:
//     let _p = hex!("0800000000000000000000000000000000000000c9");
//     let _a = hex!("01");
//     let _b = hex!("020a601907b8c953ca1481eb10512f78744a3205fd");
//     let _mu = hex!("040000000000000000000292fe77e70c12a4234c33");
//     let _nu = hex!("01");
//     let _g_x = hex!("03f0eba16286a2d57ea0991168d4994637e8343e36");
//     let _g_y = hex!("d51fbc6c71a0094fa2cdd545b11c5c0c797324f1");
//     //-----
//     //Public Key
//     let h_x = hex!("03d401df33470c1eb3611ed1b9fd4dd12ffb48cbc1");
//     let h_y = hex!("057b470f90c82a900cc4daa27567d15b05d8bdbcb0");
//     //-----
//     //Private Key
//     let x = hex!("028d2d26a73f713d3f9d0d5b8ce30d76f4d151c933");
//     //Encoding format = uncompressed_fmt
//     let r = hex!("a9836a84a1583f601a2f9b2b2432a0aff42c8541");
//     let _r_prime = hex!("a9836a84a1583f601a2f9b2b2432a0aff42c8541");
//     let _g_tilde_x = hex!("0619b155dea55122f456a0b4741093a244893c91df");
//     let _g_tilde_y = hex!("03c75545c65707dd31d9a1a583aba4f107c0c2af51");
//     let _h_tilde_x = hex!("93c4a6f28021e71e1af8c9da440ab0317e12febd");
//     let _h_tilde_y = hex!("048d83cad5c3da366af4b7da10f5e13ec45eb1d65d");
//     let _peh = hex!("0093c4a6f28021e71e1af8c9da440ab0317e12febd");
//     let _z = hex!("040619b155dea55122f456a0b4741093a244893c91df03c75545c65707dd31d9a1\
//         a583aba4f107c0c2af51");
//     let _c0 = hex!("040619b155dea55122f456a0b4741093a244893c91df03c75545c65707dd31d9a\
//          1a583aba4f107c0c2af51");
//     let k = hex!("970d1027a42bb88402797cadc8b0822849218339f25189a624c1c7881a09814ede\
//         d59a9baafafd2ceb516d43b7c6594d1db583ac478bec07bfe37cc3d216a9a2929658\
//         fae29a7023e266abbdecff6ccecd19bd1f8e51d4db6329af82cae0c07ee093eb3188\
//         3c57511800057e60407d7d67210ba7366ae3b8b6877a9e81ecb774");

//     let mut ctx = BigNumContext::new().unwrap();

//     // Rust openssl doesn't expose interface to create group from binary fields
//     //let group = ec_group_from_components(&p, &a, &b, &g_x, &g_y, &nu, &mu);
//     let group2 = EcGroup::from_curve_name(openssl::nid::Nid::SECT163R2).unwrap();
    
//     let mut h = EcPoint::new(&group2).unwrap();
//     h.set_affine_coordinates_gfp(&group2, &BigNum::from_slice(&h_x).unwrap(), 
//         &BigNum::from_slice(&h_y).unwrap(), &mut ctx).unwrap();
    
//     let (c0, k_send) = ecies_kem_encrypt_openssl ( &h, &r, &group2, 128, PointConversionForm::UNCOMPRESSED, kdf1_sha1).unwrap();
//     assert! ( k_send == k );

//     let k_rec = ecies_kem_decrypt_openssl(&x, &c0, &group2, 128, kdf1_sha1).unwrap();
//     assert! ( k_rec == k);




// }

// #[test]
// fn test_iso_18033_2_c_2_5 () {
//     // -------------
//     // ECIES-KEM
//     // -------------
//     // Kdf=Kdf1(Hash=Sha1())
//     // Keylen=128
//     // CofactorMode=0
//     // OldCofactorMode=0
//     // CheckMode=0
//     // SingleHashMode=0
//     // -----
//     // Group=ECGF2-Group:
//     let _p = hex!("0800000000000000000000000000000000000000c9");
//     let _a = hex!("01");
//     let _b = hex!("020a601907b8c953ca1481eb10512f78744a3205fd");
//     let _mu = hex!("040000000000000000000292fe77e70c12a4234c33"); //n, order
//     let _nu = hex!("01");
//     //let cofactor = 2
//     let _g_x = hex!("03f0eba16286a2d57ea0991168d4994637e8343e36");
//     let _g_y = hex!("d51fbc6c71a0094fa2cdd545b11c5c0c797324f1");
//     // Public Key
//     let h_x = hex!("03d401df33470c1eb3611ed1b9fd4dd12ffb48cbc1");
//     let h_y = hex!("057b470f90c82a900cc4daa27567d15b05d8bdbcb0");
//     //Private Key
//     let x = hex!("028d2d26a73f713d3f9d0d5b8ce30d76f4d151c933");
//     // Trace for ECIES-KEM encrypt
//     // -------------------------------
//     // Encoding format = compressed_fmt
//     let r = hex!("a9836a84a1583f601a2f9b2b2432a0aff42c8541");
//     let _r_prime = hex!("a9836a84a1583f601a2f9b2b2432a0aff42c8541");
//     let _g_tilde_x = hex!("0619b155dea55122f456a0b4741093a244893c91df");
//     let _g_tilde_y = hex!("03c75545c65707dd31d9a1a583aba4f107c0c2af51");
//     let _h_tilde_x = hex!("93c4a6f28021e71e1af8c9da440ab0317e12febd");
//     let _h_tilde_y = hex!("048d83cad5c3da366af4b7da10f5e13ec45eb1d65d");
//     let _peh = hex!("0093c4a6f28021e71e1af8c9da440ab0317e12febd");
//     let _z = hex!("030619b155dea55122f456a0b4741093a244893c91df");
//     let _c0 = hex!("030619b155dea55122f456a0b4741093a244893c91df");
//     let k = hex!("dc66d10d56868d338b147186fdac210c351150862f94ff3ffcf4fc34b96c2117f1\
//         2e8cf39527419a96066ce00fd856b1742f3ec1865614d901b87ea7b89102417f9b62\
//         775e5806870e73db128fe00a0edd3efe21d93e84a4ae9609ade5838c96da784104db\
//         20170f74b430acde310785d4b66edd09d37f9f32c54ae44442c41f");

//     let mut ctx = BigNumContext::new().unwrap();

//     // No functions exposed by openssl to create a binary field from components, instead use premade curves
//     let group = EcGroup::from_curve_name(openssl::nid::Nid::SECT163R2).unwrap();
    
//     let mut h = EcPoint::new(&group).unwrap();
//     h.set_affine_coordinates_gfp(&group, &BigNum::from_slice(&h_x).unwrap(), 
//         &BigNum::from_slice(&h_y).unwrap(), &mut ctx).unwrap();
    
//     let (c0, k_send) = ecies_kem_encrypt_openssl ( &h, &r, &group, 128, PointConversionForm::COMPRESSED, kdf1_sha1).unwrap();
//     assert! ( k_send == k );

//     let k_recv = ecies_kem_decrypt_openssl(&x, &c0, &group, 128, kdf1_sha1).unwrap();
//     assert! ( k_recv == k);

// }

// a) Generate a random number r ∈ [0 . . n).
// b) Set R = I2OSP (r, L(n)).
// c) Set C0 = RSATransform (R, e, n).
// d) ComputeK=KDF(R,KeyLen).
// e) Output the ciphertext C0 and the secret key K.
// fn encrypt_rsa_kem<K> ( n: &str, e: u32, r: &[u8], keylen: usize, kdf: K ) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> 
//     where K: FnOnce (&[u8], &[u8], usize )->Result<Vec<u8>,ErrorStack>
// {
//     let pubkey = openssl::rsa::Rsa::from_public_components(BigNum::from_dec_str(n).unwrap(), BigNum::from_u32(e).unwrap()).unwrap();
//     let mut c0 = Vec::<u8>::new();
//     c0.resize(pubkey.n().num_bytes() as usize, 0);
//     let result = pubkey.public_encrypt(r, &mut c0, Padding::NONE )?;
//     c0.truncate(result);
//     let k = (kdf)(r, &[0u8;0], keylen)?;
//     return Ok((c0,k));
// }

// // a) Set R = RSATransform(C0, d, n); note that this step may fail. 
// // b) ComputeK=KDF(R,KeyLen).
// // c) Output the secret key K.
// fn decrypt_rsa_kem<K> ( n: &str, e: u32, d: &str, c0: &[u8], keylen:usize, kdf:K ) -> Result<Vec<u8>, ErrorStack>
//     where K: FnOnce (&[u8], &[u8], usize )->Result<Vec<u8>,ErrorStack>
// {
//     let privkey = RsaPrivateKeyBuilder::new(BigNum::from_dec_str(n)?, BigNum::from_u32(e)?, BigNum::from_dec_str(d)?)?.build();
//     let mut r = vec![0u8;privkey.n().num_bytes() as usize];
//     let r_len = privkey.private_decrypt(c0, &mut r, Padding::NONE)?;

//     r.truncate(r_len);
//     let k = (kdf)(&r, &[0u8;0], keylen);

//     return k;
// }

#[test]
fn test_iso_18033_2_c_6_1 () {
    // -------------
    // RSA-KEM
    // -------------
    // Kdf=Kdf1(Hash=Sha1())
    // keylen=128
    // -----
    // Public Key
    
    let _n = "58881133325026912517619364310092848849666407571798023374905464783262\
        38537107326596800820237597139824869184990638749556269785797065508097\
        452399642780486933";
    let e = 65537u64;
    //-----
    //Private Key
    let n = "58881133325026912517619364310092848849666407571798023374905464783262\
        38537107326596800820237597139824869184990638749556269785797065508097\
        452399642780486933";
    let d = "32023135558599481863153745244741739956797835803921402370443497280464\
        79396037520308981353808895461806395564474639124525446044708705259675\
        840210989546479265";
    // -------------------------------
    // Trace for RSA-KEM encrypt
    // -------------------------------
    let r = hex!("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741\
        52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    let c0 = hex!("4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ff\
         cf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0");
    let k = hex!("5f8de105b5e96b2e490ddecbd147dd1def7e3b8e0e6a26eb7b956ccb8b3bdc1ca9\
        75bc57c3989e8fbad31a224655d800c46954840ff32052cdf0d640562bdfadfa263c\
        fccf3c52b29f2af4a1869959bc77f854cf15bd7a25192985a842dbff8e13efee5b7e\
        7e55bbe4d389647c686a9a9ab3fb889b2d7767d3837eea4e0a2f04");

    let n_2 = rsa::BoxedUint::from_str_radix_vartime(n, 10).unwrap();
    let e_2 = rsa::BoxedUint::from_words([e;1]);
    let pubkey = rsa::RsaPublicKey::new (n_2.clone(),e_2.clone()).unwrap();

    
    let encapsulator2 = RsaKemKdf1::<U64, U128, Sha1>::from_public_key(pubkey);
    let (c0_calc2, k_calc2 ) = encapsulator2.encapsulate_deterministic(&r);
    assert! ( k_calc2 == k );
    assert! ( c0_calc2.as_slice() == &c0 );
    
    let d_2 = rsa::BoxedUint::from_str_radix_vartime(d, 10).unwrap();
    let priv_key = rsa::RsaPrivateKey::from_components(n_2, e_2, d_2, [].to_vec()).unwrap();
    let decapsulator = RsaKemKdf1::<U64, U128, Sha1>::from_private_key(priv_key);

    let k_calc2 = decapsulator.decapsulate(&c0_calc2);
    assert_eq! ( k_calc2.as_slice(), k );
}
#[test]

fn test_rsa_kem () {
    
    let mut rng = rand::rng();
    let key = rsa::RsaPrivateKey::new(&mut rng, 1024).expect("failed to generate a key");
    
    let encapsulator = <::kems::iso18033_2::RsaKemKdf1::<U128, U16, Sha256> as Kem>::EncapsulationKey::from_key(key.to_public_key());
    let (c0_send, k_send )= encapsulator.encapsulate();

    let decapsulator = ::kems::iso18033_2::RsaKemKdf1::<U128, U16, Sha256>::from_private_key(key);
    let k_recv = decapsulator.decapsulate(&c0_send);

    assert! ( k_send == k_recv);
}

#[test]
fn test_iso_18033_2_c_6_2 () {
    // -------------
    // RSA-KEM
    // -------------
    // Kdf=Kdf2(Hash=Sha1())
    //let keylen=128;
    // -----
    // Public Key
    let _n = "58881133325026912517619364310092848849666407571798023374905464783262\
        38537107326596800820237597139824869184990638749556269785797065508097\
        452399642780486933";
    let e = 65537u64;
    // -----
    // Private Key
    let n = "58881133325026912517619364310092848849666407571798023374905464783262\
        38537107326596800820237597139824869184990638749556269785797065508097\
        452399642780486933";
    let d = "32023135558599481863153745244741739956797835803921402370443497280464\
        79396037520308981353808895461806395564474639124525446044708705259675\
        840210989546479265";
    // -------------------------------
    // Trace for RSA-KEM encrypt
    // -------------------------------
    let r = hex!("032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741\
        52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    let c0 = hex!("4603e5324cab9cef8365c817052d954d44447b1667099edc69942d32cd594e4ff\
        cf268ae3836e2c35744aaa53ae201fe499806b67dedaa26bf72ecbd117a6fc0");
    let k = hex!("0e6a26eb7b956ccb8b3bdc1ca975bc57c3989e8fbad31a224655d800c46954840f
        f32052cdf0d640562bdfadfa263cfccf3c52b29f2af4a1869959bc77f854cf15bd7a
        25192985a842dbff8e13efee5b7e7e55bbe4d389647c686a9a9ab3fb889b2d7767d3
        837eea4e0a2f04b53ca8f50fb31225c1be2d0126c8c7a4753b0807");

    
    // Encapsulate using RustCrypto KEM traits
    let n_2 = rsa::BoxedUint::from_str_radix_vartime(n, 10).unwrap();
    let e_2 = rsa::BoxedUint::from_words([e;1]);
    let pubkey = rsa::RsaPublicKey::new (n_2.clone(),e_2.clone()).unwrap();
    let encapsulator = RsaKemKdf2::<U64, U128, Sha1>::from_public_key(pubkey);
    
    let (c0_calc, k_calc) = encapsulator.encapsulate_deterministic(&r);
    assert! ( k_calc.as_slice() == k );
    assert! ( c0_calc.as_slice() == &c0 );

    let d_2 = rsa::BoxedUint::from_str_radix_vartime(d, 10).unwrap();
    let priv_key = rsa::RsaPrivateKey::from_components(n_2, e_2, d_2, [].to_vec()).unwrap();
    let decapsulator = RsaKemKdf2::<U64, U128, Sha1>::from_private_key(priv_key);
    let k_calc2 = decapsulator.decapsulate(&c0_calc);
    assert_eq! ( k_calc2.as_slice(), k );

}












#[test]
fn test_emvco_blinded_diffie_helman() {
    
    let terminal_secret_key = p256::SecretKey::generate();
    let terminal_public_key = terminal_secret_key.public_key();

    let card_static_secret_key = p256::SecretKey::generate();
    let card_static_public_key = card_static_secret_key.public_key();

    let card_static_secret_scalar = card_static_secret_key.as_scalar_value();
    
    let mut rand = [0u8; 64];
    OsRng.fill_bytes(&mut rand);
    let r = p256::Scalar::from_uniform_bytes(&rand); //::random(&mut rand::rngs::OsRng);
    let card_static_secret_scalar2 = p256::Scalar::from(card_static_secret_scalar);
    let blinded_secret_key: p256::Scalar = r * card_static_secret_scalar2;
    let blinded_secret_as_bytes = blinded_secret_key.as_ref().to_bytes();

    let encapsulator = KemWithKdf::<EcdhKemUncompressed::<_>, CombinerCiphertext, EmvCmacAes128, U16>::from_public_key(terminal_public_key); //new(kdf);
    let (c0_calc, k_send ) = encapsulator.encapsulate_deterministic(&blinded_secret_as_bytes);

    let decapsulator = KemWithKdf::<EcdhKemUncompressed::<_>, CombinerCiphertext, EmvCmacAes128, U16>::from_private_key(terminal_secret_key);
    let k_recv = decapsulator.decapsulate(&c0_calc);
    assert! ( k_recv == k_send );

    let session_key_confidentiality = EmvCommonSessionKdf::<Aes128>::derive_session_key(&k_recv, EmvSessionKeyType::SessionKeyConfidentiality);

    // Validate blinding factor as per EMV spec
    let mut r_as_bytes = r.to_bytes().as_slice().to_vec();
    // todo, put in CMC (Card Message Counter)
    let mut encryptor = <ctr::Ctr64LE::<Aes128> as KeyIvInit>::new(&session_key_confidentiality.0.into(), &[0;16].into());
    encryptor.apply_keystream ( &mut r_as_bytes );

    //decrypt
    let mut decryptor = <ctr::Ctr64LE::<Aes128> as KeyIvInit>::new(&session_key_confidentiality.0.into(), &[0;16].into());
    decryptor.apply_keystream ( &mut r_as_bytes );

    let r_prime_as_ga = Array::try_from(&r_as_bytes).unwrap();
    let r_prime = p256::Scalar::from_repr(r_prime_as_ga).unwrap();

    let blinded_public_key_prime = *card_static_public_key.as_affine() * r_prime;
    
    let blinded_public_key = elliptic_curve::PublicKey::<NistP256>::from_sec1_bytes(&c0_calc).unwrap();
        
    assert! ( &blinded_public_key_prime.to_affine() == blinded_public_key.as_affine() );
}


#[test]
#[allow(non_snake_case)]
fn test_emvco_book_e_we_6_1_p256 ()
{
    let dK = hex!("7D6FD7D5B428CF88A1A8B0F2A6A0DC563B6882CBCB09DB8C63E05E78B008C2E7");
    let QK = /*dK·G(x)*/ hex!("B3B037BB4E599B3E7392332CE9DEC1D388EF551C9B8FDE20D5ABAE5B8464707E");
    
    let _QC_x = hex!( "43CA1837F6B4321CA70262902037EFCE790DC583828AEA628FFAAEFC08618658");
    let r = hex! ( "8C5AE5C30D3164A755D101C50646F405A06761562EC0CCF940D2B6E67CE2F1F8");
    let PC_x = /*r·QC(x)*/ hex!("D4D37071C5EC5AC817FE5B7500E623A1323DEC9241DE35099834FB0618A062EC");

    let dC = hex!("9CCCF19E58228AED9CEEB7D48F69D3B37EE56F416D642E13D5F46FC9D198E08F");
    let KD = /*AES-CMAC (V) [Z]*/ hex!("602A2FC322991249E47991E4B6952D38");


    // Card side, uses card key and random number to create ephemeral key
    let dC_card = Scalar::<NistP256>::from_repr(dC.into()).unwrap();
    let r_card = Scalar::<NistP256>::from_repr(r.into()).unwrap();
    let dC_r = (dC_card * r_card).to_bytes();
    
    let encapsulator = EcdhKemP256EmvCmac128::try_from_bytes_encap(&QK.into()).unwrap();

    let (c0_calc, k_send ) = encapsulator.encapsulate_deterministic(&dC_r);
    assert_eq! ( c0_calc, PC_x);
    assert_eq! ( k_send.0, KD);

    // Terminal side, decapsulates key 
    let decapsulator = EcdhKemP256EmvCmac128::try_from_slice_decap(&dK).unwrap();
    
    let k_recv = decapsulator.decapsulate(&c0_calc);
    assert! ( k_recv == KD );

    // Derive sub keys
    let C1 = hex!("01010054334A325957773DA5A5A50180");
    let SKC = /*AES (KD) [C1]*/ hex!("88655CFD79DF9E9DDDEAF9EC0C538DC5");
    let C2 = hex!("02010054334A325957773DA5A5A50180");
    let SKI = /*AES (KD) [C2]*/ hex!("642373F56192B09B132C7E024164D3A7");
    let C3 = hex!("03010054334A325957773DA5A5A50180");
    let SKR = /*AES (KD) [C3]*/ hex!("55042AA8CF1F193EC435A449493C177D");

    let SKC2: Array<u8, U16> = EmvCommonSessionKdf::<Aes128>::derive_secret_other(&k_recv, &C1);
    assert_eq! ( &SKC2, &SKC);
    let SKI2: Array<u8, U16> = EmvCommonSessionKdf::<Aes128>::derive_secret_other(&k_recv, &C2);
    assert! ( SKI2 == SKI);
    let SKR2: Array<u8, U16> = EmvCommonSessionKdf::<Aes128>::derive_secret_other(&k_recv, &C3);
    assert! ( SKR2 == SKR);
    

    // Validate blinding factor as per EMV spec
    let R = hex!("8C5AE5C30D3164A755D101C50646F405A06761562EC0CCF940D2B6E67CE2F1F8");
    let _CMC = hex!("8000");
    let SV = hex!("80000000000000000000000000000000");
    let SKC = hex!("88655CFD79DF9E9DDDEAF9EC0C538DC5");
    let E_R = hex!("4A7653A86A6AE421DB875BF695F31C8631C1EDB721EBFCBB3057C87DB03EEA7A");
    let Rprime = hex!("8C5AE5C30D3164A755D101C50646F405A06761562EC0CCF940D2B6E67CE2F1F8");
    let QC_x = hex!("43CA1837F6B4321CA70262902037EFCE790DC583828AEA628FFAAEFC08618658");
    let PC_x = /*r'·QC(x) = PC(x)*/ hex!("D4D37071C5EC5AC817FE5B7500E623A1323DEC9241DE35099834FB0618A062EC");

    // Create encrypted blinding factor
    let mut encryptor = <Ctr64BE::<Aes128> as KeyIvInit>::new(&SKC.into(), &SV.into());
    
    let mut E_R_sender = R;
    encryptor.apply_keystream ( &mut E_R_sender );
    assert! ( E_R_sender == E_R);

    // Decrypt blinding factor
    let mut decryptor = <Ctr64BE::<Aes128> as KeyIvInit>::new(&SKC.into(), &SV.into());
    let mut r_recv =  E_R_sender;
    decryptor.apply_keystream ( &mut r_recv);
    assert ! ( r_recv == Rprime );
    
    // Validate blinding factor and static card key
    let r_prime = p256::Scalar::from_repr(r_recv.into()).unwrap();

    let QC2: p256::PublicKey = p256::AffinePoint::decompact ( &QC_x.into() ).unwrap().try_into().unwrap();


    let PC_recv = *QC2.as_affine() * r_prime;
    assert! ( PC_recv.to_affine().x() == PC_x );
}



#[test]
#[allow(non_snake_case)]
fn apple_sample_1 ()
{
    let pkrm=hex!("04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a88 18a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd");
    let skrm=hex!("3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38");
    //eciesEncryptionCofactorVariableIVX963SHA224AESGCM
    //let output = hex!("04a46e0c 283e2e69 edea41bd a2a21ddb bf1cda9d 402c5208 23a76c14 74ffab28 87fce80b 3ff945d2 0acb7baa a160efed 0fac7bbf 17c01178 dc8eb1aa 1e5096e3 1ec7a95b fc6abfde f03e5c4c 57adfa0c ea46f259 039e03cb fd9ccb8e 62");
    //eciesEncryptionStandardX963SHA256AESGCM
    let output1 = hex!("04a520ba 543c3a6b 2c7c2cff 47171be2 30f4f933 0cf30777 482e6fcf 8fdf05eb dfb80b75 0f33eec7 a1828a6c 87f3915e 831eb00d 700822a3 6d3a0b99 4a91bcdf 91103d53 0feb9a4d 41985f34 b2d23d62 ee32a11e 303c5327 20c72ff4 a2");
    //eciesEncryptionStandardVariableIVX963SHA256AESGCM
    let output = hex!("04c86b15 1febdaaa 1eea2459 c4921637 d6d600dd 38cef370 c4ea1f4e 5ceccd17 511ba5bf 1eda15a0 e32a5441 3b3efc9e 0c02d456 8684d322 04fa5071 ebe438b0 0dcfcd96 7e53ace8 9ef73ae6 23370c6f a4932ddb a55990c8 05fbe59a 22");
    // eciesEncryptionCofactorX963SHA256AESGCM
    //let output = hex!("04f6a946 e2fdf61f 124aca40 2255ed54 64b507d2 2423177e f7a2fa5d 5c8fbb65 f3992465 227ca161 a0c03e08 3e148e0a ddad9b4a 7788a7d4 34cdd967 c4447508 7262fe12 eee62974 25c69501 d2551802 277468b4 68569018 0a426f11 a4");
    // eciesEncryptionX963SHA1AESGCM
    let output2 = hex!("041b9b1a 9a13e4fd acfccd73 740d1fe3 945ef296 d79f6087 c7e08511 a78e196e 1514f983 ed9f5e26 8651c485 17fd189e 8163ba5d eb11aceb e70c6e60 4921c9a9 9b07e822 8de4a5ff 0ea4b438 fa2b3a7a 1d1f5421 aefec28b 99b000e0 c7");
    // eciesEncryptionStandardVariabelIVX963SHA224AESGCM
    let output3 = hex!("04cc41ed 60b10a7d fcf4940a 901ca445 31047085 93275441 634ff9bb 98dee629 3f90d3d4 47ca85e0 66ca8d29 5eee9608 0a59e117 2e2c3ab7 1dcb1ea2 92573f7a 0c150d7f a37b29a2 b85ba5b1 44409379 23db7d99 7434913c f4fab996 ff");
    let c0 = &output[0..65];
    let ct = &output[65..93];
    //let tag = &output[93..93];

    // let skrm2 = elliptic_curve::SecretKey::<NistP256>::from_bytes ( &skrm.into() ).unwrap();
    // let pkrm3 = skrm2.public_key().to_sec1_bytes();
    // assert!( &pkrm3.to_vec() == &pkrm);
    
    let decapsulator = KemWithKdf::<EcdhKemUncompressed::<NistP256>, CombinerCiphertext, X963Kdf<Sha256>, U32>::try_from_slice_decap(&skrm).unwrap();
    assert_eq!(decapsulator.encapsulation_key().to_bytes(), pkrm);

    //let c0_ga = Array::<u8, U65>::from_slice(c0).try_into().unwrap();
    let ss_key_recv = decapsulator.decapsulate(&c0.try_into().unwrap());

    let (aes_key, aes_nonce) = ss_key_recv.split_ref::<U16>();

    let decryptor = aes_gcm::AesGcm::<Aes128, U16, U16>::new(aes_key);
    let result = decryptor.decrypt ( &aes_nonce, ct ).unwrap();
    assert_eq! ( &result, &b"Hello World!");

    //let decryptor = EciesStandardVariableIVX963SHA256AESGCM::from_key_decap(skrm2.clone());
    let decryptor = EciesStandardVariableIVX963SHA256AESGCM::<NistP256>::try_from_slice_decap(&skrm).unwrap();
    let result = decryptor.open_semi_detached(&c0.try_into().unwrap(), ct);
    assert! ( &result.unwrap() == &b"Hello World!");

    let result2 = decryptor.open(output.as_ref());
    assert! ( &result2.unwrap() == &b"Hello World!");

    //let dd3 = EciesStandardX963SHA256AESGCM::from_key_decap(skrm2.clone());
    let dd3 = EciesStandardX963SHA256AESGCM::<NistP256>::try_from_slice_decap(&skrm).unwrap();
    let (c01, ct1) = output1.split_at(65);

    let result = dd3.open_detached_encapsulated_key(&c01.try_into().unwrap(), ct1);
    assert! ( &result.unwrap() == &b"Hello World!");

    let result = dd3.open(output1.as_ref());
    assert! ( &result.unwrap() == &b"Hello World!");

    let dd4 = EciesStandardX963SHA1AESGCM::<NistP256>::try_from_slice_decap(&skrm).unwrap();
    let result = dd4.open(output2.as_ref());
    assert! ( &result.unwrap() == &b"Hello World!");
    
    let dd5 = EciesStandardVariableIVX963SHA224AESGCM::<NistP256>::try_from_slice_decap(&skrm).unwrap();
    let result = dd5.open(output3.as_ref());
    assert! ( &result.unwrap() == &b"Hello World!");

}


#[test]
#[allow(non_snake_case)]
fn apple_sample_2 ()
{
    //.di=di_SHA256,
    //.curve=&ccec_cp_256,
    //.mac_length = 16,
    //.key_length = 16,

    let dec_priv_key = hex!("5abf13dbd59e0c5872bd9e72b4e17c5c9e6fe956b51aca389ad43ff5594c82b3");
    //QeCAVSx = 230951e9f774dae7c7938fcfe407a54981bda3b6b79bb37d82823f9b4ae065d5
    //QeCAVSy = 4b30c7314c1b96b0554e26e95d641408df645349a14090cd672ae9cc5829a3c4
    let eph_priv_key = hex!("1ffe7e4cbbb59f069806ebbcd18f66bc42ac3cfc9b8d0d61c7a50e94f71cf6b5");
    //QsIUTx = 895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d
    //QsIUTy = aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
    let Z = hex!("fa17d1d5717a75202a3e02ea665322f3566407d631c93a06ba278ba68a2f2c45");
    //KDF(Z,04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451daebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab
    //    ) = 864c47a851501ade4b749f1c4dbf02d4
    let message = hex!("f04e8860e6b86552cfa933c387");
    // Encrypted message = e658d7f2ebafe7e3cef9bcbbb5
    // Mac Tag = 19dee0db 770eb72b 4143a9df 85e98a63
    let cipher =       hex!("04895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d aebf853151e56f3ed04b1e68bacb39c4c8e140c10cfca6e419478b07946abdab e658d7f2ebafe7e3cef9bcbbb5 19dee0db770eb72b4143a9df85e98a63");
    let compact_cipher = hex!("895ce51cabc5cc0f857504bc684106290335538298b9de9c4759a8b3945f451d e3730a7db1f52354858c1457f147e901c84e3ee0a78367411743a285cb");
    //.options=ECIES_EXPORT_PUB_STANDARD+ECIES_EPH_PUBKEY_IN_SHAREDINFO1,
    //.sharedInfo1="",
    //.sharedInfo2="",

    let dec_priv_key2 = elliptic_curve::SecretKey::<NistP256>::from_bytes ( &dec_priv_key.into() ).unwrap();
    let eph_priv_key2 = elliptic_curve::SecretKey::<NistP256>::from_bytes ( &eph_priv_key.into() ).unwrap();

    let z = diffie_hellman ( dec_priv_key2.to_nonzero_scalar(), eph_priv_key2.public_key().as_affine());
    assert_eq!(z.raw_secret_bytes(), &Z);
    
    let decapsulator = KemWithKdf::<EcdhKemUncompressed::<NistP256>, CombinerCiphertext, X963Kdf<Sha256>, U16>::try_from_slice_decap(&dec_priv_key).unwrap();
    let key = decapsulator.decapsulate(&cipher[0..65].try_into().unwrap());

    let aes_cipher = aes_gcm::AesGcm::<Aes128, U16, U16>::new(&key);
    let encrypted = aes_cipher.encrypt ( &Array::default()/*empty nonce*/, message.as_ref() ).unwrap();
    assert_eq! ( encrypted.as_slice(), &cipher[65..]);

    let encapsulator = EciesStandardX963SHA256AESGCM::<NistP256>::try_from_slice_encap(&decapsulator.encapsulation_key().to_bytes()).unwrap();
    let calc_cipher = encapsulator.seal_deterministic(&eph_priv_key, message.as_ref()).unwrap();
    assert! ( &calc_cipher == &cipher);

    let decapsulator = EciesStandardX963SHA256AESGCM::<NistP256>::try_from_slice_decap(&dec_priv_key).unwrap();
    let calc_plaintext = decapsulator.open(cipher.as_ref()).unwrap();
    assert! ( &calc_plaintext == &message);

    let decapsulator = EciesCompactX963SHA256AESGCM::<NistP256>::try_from_slice_decap(&dec_priv_key).unwrap();
    let plaintext3 = decapsulator.open(compact_cipher.as_ref()).unwrap();
    assert! ( &plaintext3 == &message);

}

#[test]
#[allow(non_snake_case)]
fn apple_sample_3_p521_ivx ()
{
    let pkRm = hex!("0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84
    ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580
    e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b
    57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64");

    let skRm = hex!("01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c2
    7196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b24628
    47");
    let skEm = hex!("014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354
    15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e37
    4b");

    let plaintext = b"Hello World!";
    let ciphertext = hex!("04018cf6 02ad5f32 b8821e59 0ac59ed2 5e271c0c 86377973 35daef74 bc7c85f9 a49f91e5 aad4aae4 ed682cc0 e2c72cbe a3052dba 3782a085 47696fb5 7278bcd2 53b5ea01 e3c21bb8 01bd29d6 8ee37fb6 e8fd8444 6068a1c0 bbbda3d1 d6a54335 63316f6e 48933234 b1470fba 4faba708 53b6b082 4ef16bd8 d9a12330 5227edf7 13465776 f42e725a 1ba72ca8 a7a6ff8a d130e4fc 9fc300ce 9f9ca0a4 45013da4 1b");

    let decapsulator = EciesStandardVariableIVX963SHA512AESGCM::<NistP521>::try_from_slice_decap(&skRm).unwrap();
    let calc_plaintext = decapsulator.open(ciphertext.as_ref()).unwrap();
    assert! ( calc_plaintext == plaintext);

    let encapsulator = EciesStandardVariableIVX963SHA512AESGCM::<NistP521>::try_from_bytes_encap(&pkRm.into()).unwrap();
    let calc_ciphertext2 = encapsulator.seal_deterministic(&skEm, plaintext.as_ref()).unwrap();
    //assert_eq!(calc_ciphertext2, &ciphertext); // doesn't seem to use skEm as the raw randomness directly converted to a key

    let calc_plaintext2 = decapsulator.open(calc_ciphertext2.as_ref()).unwrap();
    assert! ( calc_plaintext2 == plaintext);


}

#[test]
#[allow(non_snake_case)]
fn apple_sample_3_p521_sha512 ()
{
    
    let pkRm = hex!("0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84
    ba0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa6837580
    e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f64704f464b
    57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f66d2451ec64");

    let skRm = hex!("01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c2
    7196a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b24628
    47");
    let skEm = hex!("014784c692da35df6ecde98ee43ac425dbdd0969c0c72b42f2e708ab9d5354
    15a8569bdacfcc0a114c85b8e3f26acf4d68115f8c91a66178cdbd03b7bcc5291e37
    4b");

    let plaintext = b"Hello World!";
    let ciphertext = hex!("04006c8e 4e4e128d 5ab93058 79da0aec 588ec4e8 8db4c1ec 1e140892 053d5948 7043a26c f038d3b5 c8169641 a275b3e8 60567b63 fa59c9c8 5fcda888 3f23c97c 18d0c501 59240d08 32f9386b 1d145385 2a8662a0 31bc8b28 b96fcd76 8bcc2b99 a2b16b12 1073c074 382c45d4 c0c25098 d1b3340b c5ca30f0 ec0b5e39 387f4708 fdbe18ed bf2b9bdd 7f3906eb d2fd72c3 a2e1b425 bbec7a89 54dd51ae fe074f5c 2b");

    // SHA384 Variable IV
    let ciphertext2 = hex!("04011d6f 2f012224 7b72adaf b3f881dd d56790f7 cdc0c1af 828e7661 abe4fb0a 75a6de87 66d85c39 e6e8461f 1aaeb2fd e672751b bdbe95e9 150ddea7 c3d48150 ca58d801 cc306643 5cd8268f b459d22f 4a79c9b6 e88e68be 78971729 cc3cb84a 9d8f0669 4e38ad13 842a58ab 963af000 7177f172 52e44ad9 b16bf6cf efdb08f8 f4e62598 7cab7138 17358823 9102a09f cba5dcd9 33094294 31b378d3 de5ed5cb ea");
    //eciesEncryptionStandardX963SHA512AESGCM
    // eciesEncryptionStandardX963SHA384AESGCM
    let ciphertext3 = hex!("0401cca9 b11bbab1 5ca99d47 f4190e37 a819cb69 7d27a407 da3cd911 c7cdf8b6 c92d5f62 3af9405b 52c821a7 51c51e67 4c46a63d ca71c738 daef3ee6 b7beb6f8 f2720100 687eeef2 2292b517 75fc890c 306a7a80 32ad94ec 8a55e433 49c410b0 f6816994 05203590 e6d70f93 f7eedfa0 efc28cbd 770d84e2 374f7926 a4ced01f bf662ee8 07b9603c 149730fd 62233c63 f4f3a422 18d9f5e6 e3bfc077 c9f63082 12");

    // eciesEncryptionCofactorX963SHA384AESGCM
    let ciphertext4 = hex!("04013ba6 9eeccf44 016a33dc 2fdd5bb5 8d5807b0 0c0df5ae c3e1c0ea 00ff3a97 a7c1a8bf 1eac9496 b9bb95d1 531172f9 f8dbb5b0 bfc38dcc 017d6a4a fb6d87e9 18847800 8761a949 a5c3ae42 96f8e449 293c5b10 d22c602a 798ef70f 5d95c626 5173f2ba 43089586 f32eaec8 78888fcd 3ef8f94d f4a0a932 bbb94f84 cb1abe1e f845ac26 c6741263 89c83b01 2b241a22 a86faae0 da4bad04 231c8213 19994e72 d6");

    //let dec_priv_key2 = elliptic_curve::SecretKey::<NistP521>::from_slice(&skRm).unwrap();
    //let decapsulator = EciesStandardX963SHA512AESGCM::from_key_decap(dec_priv_key2.clone());
    let decapsulator = EciesStandardX963SHA512AESGCM::<NistP521>::try_from_slice_decap(&skRm).unwrap();
    let calc_plaintext = decapsulator.open(ciphertext.as_ref()).unwrap();
    assert! ( calc_plaintext == plaintext);

    //let mut pred_rng = PredictableRng::new(&skEm);
        
    let pkRm3 = elliptic_curve::PublicKey::<NistP521>::from_sec1_bytes(pkRm.as_ref()).unwrap();
    let encapsulator = EciesStandardX963SHA512AESGCM::from_key_encap(pkRm3);
    //let calc_ciphertext2 = encapsulator.seal(&mut pred_rng, plaintext.as_ref()).unwrap();
    let calc_ciphertext2 = encapsulator.seal_deterministic(&skEm, plaintext.as_ref()).unwrap();

    let calc_plaintext2 = decapsulator.open(calc_ciphertext2.as_ref()).unwrap();
    assert! ( calc_plaintext2 == plaintext);

    let decapsulator2 = EciesStandardVariableIVX963SHA384AESGCM::<NistP521>::try_from_slice_decap(&skRm).unwrap();
    let calc_plaintext3 = decapsulator2.open(ciphertext2.as_ref()).unwrap();
    assert! ( calc_plaintext3 == plaintext );

    let decapsulator4 = EciesStandardX963SHA384AESGCM::<NistP521>::try_from_slice_decap(&skRm).unwrap();
    let calc_plaintext4 = decapsulator4.open(ciphertext3.as_ref()).unwrap();
    assert! ( calc_plaintext4 == plaintext );

    let decapsulator4 = EciesStandardX963SHA384AESGCM::<NistP521>::try_from_slice_decap(&skRm).unwrap();
    let calc_plaintext4 = decapsulator4.open(ciphertext4.as_ref()).unwrap();
    assert! ( calc_plaintext4 == plaintext );

}


#[test]
fn apple_sample_3_rsa_2048_sha1() {
    let priv_key = hex!( "308204a3 02010002 82010100 b0a5c91a 39f39a3c a80dc22d eb0c7549 93b4a960 c8a553e3 b1446e96 a41e6dc3 dc2f4b18 85965be3 92010735 7fa2b1c7 5f519fac a176b435 7fb724aa d6609975 705b9e80 2dcbc473 059679eb acb1b9de bc10641f a0871d90 799e6637 afb1f3a7 925f8192 ff6575f5 47f41af2 58dc1478 bb5067ec 67d1d534 c50da7ca bd210552 60109d13 12008323 a3477275 061cfa0b 4c3e7699 145ef160 12d0182a e04131b0 2877fd00 ccff9c3d 2acaef0f ef13a0a8 efd2b685 7dea81d0 b13c8e80 971afae2 350c2ec8 d14fe27a 9b171eb5 ada636a1 14acc88d f2a2f70f 025e0751 25c03181 48bbe801 e53f0d55 063e11e1 6ee9e242 3b8c9732 3c019878 7af11deb 7eb9c8a5 02030100 01028201 003475d7 c6712576 4dc33eea c7064219 e6f2f5b9 43a3f2ed 79f66033 538b83f9 e72bd1e3 c4718fd8 d439bd12 6e01ecc8 4d447292 300b779c 473319a9 cb0e857b ad93e3b1 abb16e0d 7677575b f7f0be8b 4ba9a058 8bc7f9b8 7efa8f5f 1df490ad a2bb669f ad8f298b a17f6ff0 3cbec505 5361959c 7769d1b8 36c6baaa 751c3bdd 3f3d8ec1 b5cca103 2157754b 83c96c2e 9f376154 baf56de9 93308c30 ec591637 5ecf7247 fe2e4793 795ebf66 56e0a350 953891e7 ce45b75e 3910d1c6 9fc930c6 c435fe8f ccdd6bc6 5f49fae6 7080e555 a4c4d48f 487a301b a39acf6f f4c2e7fd 7aaebcf4 e0a25e8a 59cad7ed 2610be27 f061487c 630e3dda e36b973d a173ba2f 95028181 00eb8015 4e6f6ed7 d923bf88 8db4365b 0aa02c92 d5f3009c 0e7505a4 e2ffba28 abc18749 8cea26e6 68b077a8 0d553359 881128de 0d49ae0f e327e3ef 9da95438 850e225a 00562600 8ca90249 ae8ed7ee 558ed4bc 04a41340 083c672b d682149e 17794311 eb630ff9 64363d5b 55aa9d94 e1e37ce7 f1a42934 d881e70e 5e79cfad 5f028181 00c00638 a85d4b35 f5cc164c 09cb916a 11addd5a c14cc9ed 14230a5e 5576d23d 2eaa66cf 83f4a8bb 142cf97e 2502929e 612255b6 88345f53 f8f09303 cda2e357 7483e208 b827b626 8c768142 e410102f 90d2134a 10fd1bfb 882b0f16 aa69d6ca c4215e4c 5a77b98e dda1f50f 3985807f 89138fb5 69fdb45c 66729e51 fdd44404 7b028181 00ca1b5e 2db64c76 4a0ff7ec 855047e5 d234ac8c 47b908a8 e56f60ac a573ba9b f4eb5de3 ad5fb68a bf05d36b 122630af 81aad85b d9238692 73ec641d dc3cd9de b7b1eda1 37f0b724 79930237 a1eb4d3d 6987eee2 7d49228c 2d854935 c21e58fb 6441d961 a3959cbb f758e547 6139cf8b 5a61156d 29602d4d 01125aed 65ff3c50 19028180 23224045 95e447f8 34223441 6a8cada2 947436c1 bd6208cd b1679940 fbdf95b0 2f1f6682 9746340c 89fa1039 8751fa46 7d78bf50 067d16a9 2aa34b83 d974cd30 955ccb09 9ec27625 271d9976 8ef5d72e 2131c450 7d6f1c43 9ad544e9 633a1899 701d87cc d9b10ad1 c46b4920 d62b5faa 5df8e251 8548f5cb 0cd7a8da cf76ae77 02818044 69575f7d e42cd330 b88c60aa 77c6233c 9c6dd7e3 6c79cfe6 f99e4ba3 903da28c 94ee07bc eb07aa32 ff8991b6 4df737b8 575e217f 9b16c23e 90e4f30c 8419c48e 8ef82992 4230c24f 99238ea7 cb86af83 ac21ee5f 2575273c a6d2f922 5c90a1cb 146735b3 5ea436f6 d4ee0f6f 5f482352 d3fcc6dd 1a75bca9 8cfc5c23 af8c16");
    let ciphertext = hex!("085b5918 90bf487f 5dba887d a2289800 740857b6 d94ff4f1 4bf0cb2e c30c335d d1c43b0e 00f37682 bc7036dc c914b700 2cb017e6 3d070961 93dba95e fae47c03 95ed82ce 539b0bf4 405d7564 da940e16 035304fe aee598d7 e0b56525 d603fa28 da0384c4 132804dc 7d43a1aa 6bd83d45 e835ad5b af07537d 3be24e7f 789c12f8 b904802a 204d0d94 8e20c08f d46165a9 ad311a14 bab3b677 4202e6da bd96787e 7c77ac1e 939fda66 5d3be379 0f20b424 94b897cc c6508c27 292279f4 1b63bc81 5229b5bc 6a039105 336a58b0 aedb1d55 f7d0bb36 06f8ab21 a390f77d 25a42aff 9747f038 06b51787 6e250af8 4002c83d 59fdb914 c8966b9f babb43df e37ad993 f47eb26f 85c62725 9b138b15 d4be1033 dd84357b b49eb2e8 93ef405b");
    let plaintext = b"Hello World!";

    let rsa_priv = RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap();
    let rsa_pub = rsa_priv.to_public_key().to_pkcs1_der().unwrap();
    
    let decryptor = RsaOAEPSHA1AESGCM::<U256>::from_key_decap(rsa_priv.clone());
    let result = decryptor.open ( Payload{msg: ciphertext.as_ref(), aad: rsa_pub.as_bytes()} ).unwrap();
    assert_eq!(result, plaintext);
    

    let encryptor = RsaOAEPSHA1AESGCM::<U256>::from_key_encap(rsa_priv.to_public_key());
    let ciphertext2 = encryptor.seal ( Payload { msg: plaintext.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    
    let plaintext2 = decryptor.open ( Payload{msg: ciphertext2.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    assert! ( &plaintext2 == &plaintext);
}


#[test]
#[allow(non_snake_case)]
fn apple_sample_3_rsa_2048_sha512() {
    let priv_key = hex!( "308204a3 02010002 82010100 b0a5c91a 39f39a3c a80dc22d eb0c7549 93b4a960 c8a553e3 b1446e96 a41e6dc3 dc2f4b18 85965be3 92010735 7fa2b1c7 5f519fac a176b435 7fb724aa d6609975 705b9e80 2dcbc473 059679eb acb1b9de bc10641f a0871d90 799e6637 afb1f3a7 925f8192 ff6575f5 47f41af2 58dc1478 bb5067ec 67d1d534 c50da7ca bd210552 60109d13 12008323 a3477275 061cfa0b 4c3e7699 145ef160 12d0182a e04131b0 2877fd00 ccff9c3d 2acaef0f ef13a0a8 efd2b685 7dea81d0 b13c8e80 971afae2 350c2ec8 d14fe27a 9b171eb5 ada636a1 14acc88d f2a2f70f 025e0751 25c03181 48bbe801 e53f0d55 063e11e1 6ee9e242 3b8c9732 3c019878 7af11deb 7eb9c8a5 02030100 01028201 003475d7 c6712576 4dc33eea c7064219 e6f2f5b9 43a3f2ed 79f66033 538b83f9 e72bd1e3 c4718fd8 d439bd12 6e01ecc8 4d447292 300b779c 473319a9 cb0e857b ad93e3b1 abb16e0d 7677575b f7f0be8b 4ba9a058 8bc7f9b8 7efa8f5f 1df490ad a2bb669f ad8f298b a17f6ff0 3cbec505 5361959c 7769d1b8 36c6baaa 751c3bdd 3f3d8ec1 b5cca103 2157754b 83c96c2e 9f376154 baf56de9 93308c30 ec591637 5ecf7247 fe2e4793 795ebf66 56e0a350 953891e7 ce45b75e 3910d1c6 9fc930c6 c435fe8f ccdd6bc6 5f49fae6 7080e555 a4c4d48f 487a301b a39acf6f f4c2e7fd 7aaebcf4 e0a25e8a 59cad7ed 2610be27 f061487c 630e3dda e36b973d a173ba2f 95028181 00eb8015 4e6f6ed7 d923bf88 8db4365b 0aa02c92 d5f3009c 0e7505a4 e2ffba28 abc18749 8cea26e6 68b077a8 0d553359 881128de 0d49ae0f e327e3ef 9da95438 850e225a 00562600 8ca90249 ae8ed7ee 558ed4bc 04a41340 083c672b d682149e 17794311 eb630ff9 64363d5b 55aa9d94 e1e37ce7 f1a42934 d881e70e 5e79cfad 5f028181 00c00638 a85d4b35 f5cc164c 09cb916a 11addd5a c14cc9ed 14230a5e 5576d23d 2eaa66cf 83f4a8bb 142cf97e 2502929e 612255b6 88345f53 f8f09303 cda2e357 7483e208 b827b626 8c768142 e410102f 90d2134a 10fd1bfb 882b0f16 aa69d6ca c4215e4c 5a77b98e dda1f50f 3985807f 89138fb5 69fdb45c 66729e51 fdd44404 7b028181 00ca1b5e 2db64c76 4a0ff7ec 855047e5 d234ac8c 47b908a8 e56f60ac a573ba9b f4eb5de3 ad5fb68a bf05d36b 122630af 81aad85b d9238692 73ec641d dc3cd9de b7b1eda1 37f0b724 79930237 a1eb4d3d 6987eee2 7d49228c 2d854935 c21e58fb 6441d961 a3959cbb f758e547 6139cf8b 5a61156d 29602d4d 01125aed 65ff3c50 19028180 23224045 95e447f8 34223441 6a8cada2 947436c1 bd6208cd b1679940 fbdf95b0 2f1f6682 9746340c 89fa1039 8751fa46 7d78bf50 067d16a9 2aa34b83 d974cd30 955ccb09 9ec27625 271d9976 8ef5d72e 2131c450 7d6f1c43 9ad544e9 633a1899 701d87cc d9b10ad1 c46b4920 d62b5faa 5df8e251 8548f5cb 0cd7a8da cf76ae77 02818044 69575f7d e42cd330 b88c60aa 77c6233c 9c6dd7e3 6c79cfe6 f99e4ba3 903da28c 94ee07bc eb07aa32 ff8991b6 4df737b8 575e217f 9b16c23e 90e4f30c 8419c48e 8ef82992 4230c24f 99238ea7 cb86af83 ac21ee5f 2575273c a6d2f922 5c90a1cb 146735b3 5ea436f6 d4ee0f6f 5f482352 d3fcc6dd 1a75bca9 8cfc5c23 af8c16");
    //let ciphertext2 = hex!("0d20b5d4 456d81ef ea1e418e 76f13a95 ae51bc4c 5f7fc5bf 15d5ffef 53ca1688 f198bf91 5ebb9625 9f2f4a34 ca5b6fb9 e77f1611 26810471 9d7ee6f9 e2df1759 f3f9dc6b 2db77c74 0e9b7f7d 0bd11687 4fd06b8d 605ca4b3 b43f8d8f a197ac77 1cafd73d b7602074 2419ec11 f74fb166 256d42e7 594228e8 8d4fc61f ce987831 f8ce0f86 8a721f04 49d2f127 36092d9e c0df3e80 2a94a52a 92cdb14c f0b54e83 1bd5fbf7 34909d2d da89358f dfdd5dcf d055604a 8e5f274b 9e9e1b19 94be670f 7bc36f06 5063e324 928f8878 12fbb567 84607cc0 0c37309b 3880a293 f65bbfb7 ebb2635f 04642341 f3857bf3 09958648 d7122dad 2f9394f4 b26e0814 937fcd2d 48762f47 450b7e76 b9d74f82 367945fa 8e1a5781 bb9fe237 f156c4cc");
    let ciphertext = hex!("44197d09 2b22c5ab 18621f64 e0348142 a0ccd74c 3c6fe7a0 b6f880d1 62704aba 4cbdc93d fb6f7fbc d0468507 f122404c af74f4ff 3eaf7d0f 14d0e9b8 01428db5 385adf6e 013a14f8 18988575 4f6669c0 ec13cd7a 5b9d89c9 f96c2154 ad41775d e15d32dc fb90ac3d bcccfa06 c95dd957 f3dbffd7 a65015ca 7843a4b0 9bd4668c 60eb3434 215cb860 ed033af1 24061ddb c2b63ce3 4dafb889 a3c403c6 1c291694 a62993e2 1ddd221f 3b641d44 1a452a02 5db889cc a6f73538 fb1dcee9 a27ff35e 7217e0a7 efca5e69 a6a4b894 475eb36f f344a773 325b323a 149d9cd3 f9225710 6ff973cc 593751d8 43521a03 7e191165 11bf0412 bf373b0d 57b9344a 8233dd43 aeecc4bd 1facc3dd cf29c061 91d564ca f12f188a 0d9028bf 60e200ee");
    let plaintext1 = b"Hello World!";
    // let plaintext = "Some text, including emojis 😀 🖖 and greek letters Φ Θ"; 
    // let plaintext_ba = plaintext.as_bytes();

    let rsa_priv = RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap();
    let rsa_pub = rsa_priv.to_public_key().to_pkcs1_der().unwrap();
   
    let decryptor = RsaOAEPSHA512AESGCM::<U256>::from_key_decap(rsa_priv.clone());
    let result = decryptor.open ( Payload{msg: ciphertext.as_ref(), aad: rsa_pub.as_bytes()} ).unwrap();
    
    assert_eq! ( &result, plaintext1);

    let encryptor = RsaOAEPSHA512AESGCM::<U256>::from_key_encap(rsa_priv.to_public_key());
    let ciphertext2 = encryptor.seal ( Payload { msg: plaintext1, aad: rsa_pub.as_bytes()}).unwrap();

    let plaintext2 = decryptor.open ( Payload{msg: ciphertext2.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    assert_eq!(plaintext2, plaintext1);


}


#[test]
fn apple_sample_3_rsa_2048_sha224() {
    let priv_key = hex!( "308204a3 02010002 82010100 b0a5c91a 39f39a3c a80dc22d eb0c7549 93b4a960 c8a553e3 b1446e96 a41e6dc3 dc2f4b18 85965be3 92010735 7fa2b1c7 5f519fac a176b435 7fb724aa d6609975 705b9e80 2dcbc473 059679eb acb1b9de bc10641f a0871d90 799e6637 afb1f3a7 925f8192 ff6575f5 47f41af2 58dc1478 bb5067ec 67d1d534 c50da7ca bd210552 60109d13 12008323 a3477275 061cfa0b 4c3e7699 145ef160 12d0182a e04131b0 2877fd00 ccff9c3d 2acaef0f ef13a0a8 efd2b685 7dea81d0 b13c8e80 971afae2 350c2ec8 d14fe27a 9b171eb5 ada636a1 14acc88d f2a2f70f 025e0751 25c03181 48bbe801 e53f0d55 063e11e1 6ee9e242 3b8c9732 3c019878 7af11deb 7eb9c8a5 02030100 01028201 003475d7 c6712576 4dc33eea c7064219 e6f2f5b9 43a3f2ed 79f66033 538b83f9 e72bd1e3 c4718fd8 d439bd12 6e01ecc8 4d447292 300b779c 473319a9 cb0e857b ad93e3b1 abb16e0d 7677575b f7f0be8b 4ba9a058 8bc7f9b8 7efa8f5f 1df490ad a2bb669f ad8f298b a17f6ff0 3cbec505 5361959c 7769d1b8 36c6baaa 751c3bdd 3f3d8ec1 b5cca103 2157754b 83c96c2e 9f376154 baf56de9 93308c30 ec591637 5ecf7247 fe2e4793 795ebf66 56e0a350 953891e7 ce45b75e 3910d1c6 9fc930c6 c435fe8f ccdd6bc6 5f49fae6 7080e555 a4c4d48f 487a301b a39acf6f f4c2e7fd 7aaebcf4 e0a25e8a 59cad7ed 2610be27 f061487c 630e3dda e36b973d a173ba2f 95028181 00eb8015 4e6f6ed7 d923bf88 8db4365b 0aa02c92 d5f3009c 0e7505a4 e2ffba28 abc18749 8cea26e6 68b077a8 0d553359 881128de 0d49ae0f e327e3ef 9da95438 850e225a 00562600 8ca90249 ae8ed7ee 558ed4bc 04a41340 083c672b d682149e 17794311 eb630ff9 64363d5b 55aa9d94 e1e37ce7 f1a42934 d881e70e 5e79cfad 5f028181 00c00638 a85d4b35 f5cc164c 09cb916a 11addd5a c14cc9ed 14230a5e 5576d23d 2eaa66cf 83f4a8bb 142cf97e 2502929e 612255b6 88345f53 f8f09303 cda2e357 7483e208 b827b626 8c768142 e410102f 90d2134a 10fd1bfb 882b0f16 aa69d6ca c4215e4c 5a77b98e dda1f50f 3985807f 89138fb5 69fdb45c 66729e51 fdd44404 7b028181 00ca1b5e 2db64c76 4a0ff7ec 855047e5 d234ac8c 47b908a8 e56f60ac a573ba9b f4eb5de3 ad5fb68a bf05d36b 122630af 81aad85b d9238692 73ec641d dc3cd9de b7b1eda1 37f0b724 79930237 a1eb4d3d 6987eee2 7d49228c 2d854935 c21e58fb 6441d961 a3959cbb f758e547 6139cf8b 5a61156d 29602d4d 01125aed 65ff3c50 19028180 23224045 95e447f8 34223441 6a8cada2 947436c1 bd6208cd b1679940 fbdf95b0 2f1f6682 9746340c 89fa1039 8751fa46 7d78bf50 067d16a9 2aa34b83 d974cd30 955ccb09 9ec27625 271d9976 8ef5d72e 2131c450 7d6f1c43 9ad544e9 633a1899 701d87cc d9b10ad1 c46b4920 d62b5faa 5df8e251 8548f5cb 0cd7a8da cf76ae77 02818044 69575f7d e42cd330 b88c60aa 77c6233c 9c6dd7e3 6c79cfe6 f99e4ba3 903da28c 94ee07bc eb07aa32 ff8991b6 4df737b8 575e217f 9b16c23e 90e4f30c 8419c48e 8ef82992 4230c24f 99238ea7 cb86af83 ac21ee5f 2575273c a6d2f922 5c90a1cb 146735b3 5ea436f6 d4ee0f6f 5f482352 d3fcc6dd 1a75bca9 8cfc5c23 af8c16");
    let ciphertext = hex!("272b08d3 e56c6f44 a34f08b5 54d123f2 c05f2804 20838533 42787dcc 271e3c0f 720013a3 40fa3773 5e472fc3 6f57c8d1 98f12304 35dd3d5c 3d94625f 0bab24d9 b48b5668 dfe74e33 5de48a32 1bc53116 f0ba62f8 5d361854 84c9dd80 45e3cded 9860206d 0ebe05d1 aa121a8f b97c374f 03885df4 f071baac 3eef8b4e 10c9f5e9 e145e5c6 e85132e6 e948ee87 c2bce732 b433f3ae 7b132822 4cd5fa02 b1a50525 8eb003b9 183c8709 3abef083 be56e65b d7ac1140 f3b02c2c abd57584 499fc2bf 541d32c5 2041ac80 d1c005c9 03ba52bb 1e1ddfe6 4032be62 377c81cf f66601d6 3228d87f 170045c6 eb65df88 ff753873 e8fc07cd 251d3de9 88d01dfe 7b5dff44 bbfaaf73 213beb6b 14e04bc3 f3dc4e1e 2af0c5fc 4251c141 45635a95 b22a6bf0 21f9e595 6c05068a 5e4a4921 f5cf2ded 72d06195 b2f0d1f0 f4b3ce88 4e88bd16 627329a5 fbe1ef08 161acbf1 b8");
    let plaintext = "Some text, including emojis 😀 🖖 and greek letters Φ Θ";
    let plaintext_ba = plaintext.as_bytes();

    let rsa_priv = RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap();
    let rsa_pub = rsa_priv.to_public_key().to_pkcs1_der().unwrap();
   
    let decryptor = RsaOAEPSHA224AESGCM::<U256>::from_key_decap(rsa_priv.clone());
    let plaintext2 = decryptor.open ( Payload{msg: ciphertext.as_ref(), aad: rsa_pub.as_bytes()} );
    assert! ( &plaintext2.unwrap() == plaintext_ba);

    let encryptor = RsaOAEPSHA224AESGCM::<U256>::from_key_encap(rsa_priv.to_public_key());
    let ciphertext2 = encryptor.seal ( Payload { msg: plaintext_ba, aad: rsa_pub.as_bytes()}).unwrap();

    let plaintext3 = decryptor.open ( Payload{msg: ciphertext2.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    assert_eq!(plaintext3, plaintext_ba);
}



#[test]
fn apple_sample_4_rsa_2048_sha256() {
    let priv_key = hex!( "308204a3 02010002 82010100 b0a5c91a 39f39a3c a80dc22d eb0c7549 93b4a960 c8a553e3 b1446e96 a41e6dc3 dc2f4b18 85965be3 92010735 7fa2b1c7 5f519fac a176b435 7fb724aa d6609975 705b9e80 2dcbc473 059679eb acb1b9de bc10641f a0871d90 799e6637 afb1f3a7 925f8192 ff6575f5 47f41af2 58dc1478 bb5067ec 67d1d534 c50da7ca bd210552 60109d13 12008323 a3477275 061cfa0b 4c3e7699 145ef160 12d0182a e04131b0 2877fd00 ccff9c3d 2acaef0f ef13a0a8 efd2b685 7dea81d0 b13c8e80 971afae2 350c2ec8 d14fe27a 9b171eb5 ada636a1 14acc88d f2a2f70f 025e0751 25c03181 48bbe801 e53f0d55 063e11e1 6ee9e242 3b8c9732 3c019878 7af11deb 7eb9c8a5 02030100 01028201 003475d7 c6712576 4dc33eea c7064219 e6f2f5b9 43a3f2ed 79f66033 538b83f9 e72bd1e3 c4718fd8 d439bd12 6e01ecc8 4d447292 300b779c 473319a9 cb0e857b ad93e3b1 abb16e0d 7677575b f7f0be8b 4ba9a058 8bc7f9b8 7efa8f5f 1df490ad a2bb669f ad8f298b a17f6ff0 3cbec505 5361959c 7769d1b8 36c6baaa 751c3bdd 3f3d8ec1 b5cca103 2157754b 83c96c2e 9f376154 baf56de9 93308c30 ec591637 5ecf7247 fe2e4793 795ebf66 56e0a350 953891e7 ce45b75e 3910d1c6 9fc930c6 c435fe8f ccdd6bc6 5f49fae6 7080e555 a4c4d48f 487a301b a39acf6f f4c2e7fd 7aaebcf4 e0a25e8a 59cad7ed 2610be27 f061487c 630e3dda e36b973d a173ba2f 95028181 00eb8015 4e6f6ed7 d923bf88 8db4365b 0aa02c92 d5f3009c 0e7505a4 e2ffba28 abc18749 8cea26e6 68b077a8 0d553359 881128de 0d49ae0f e327e3ef 9da95438 850e225a 00562600 8ca90249 ae8ed7ee 558ed4bc 04a41340 083c672b d682149e 17794311 eb630ff9 64363d5b 55aa9d94 e1e37ce7 f1a42934 d881e70e 5e79cfad 5f028181 00c00638 a85d4b35 f5cc164c 09cb916a 11addd5a c14cc9ed 14230a5e 5576d23d 2eaa66cf 83f4a8bb 142cf97e 2502929e 612255b6 88345f53 f8f09303 cda2e357 7483e208 b827b626 8c768142 e410102f 90d2134a 10fd1bfb 882b0f16 aa69d6ca c4215e4c 5a77b98e dda1f50f 3985807f 89138fb5 69fdb45c 66729e51 fdd44404 7b028181 00ca1b5e 2db64c76 4a0ff7ec 855047e5 d234ac8c 47b908a8 e56f60ac a573ba9b f4eb5de3 ad5fb68a bf05d36b 122630af 81aad85b d9238692 73ec641d dc3cd9de b7b1eda1 37f0b724 79930237 a1eb4d3d 6987eee2 7d49228c 2d854935 c21e58fb 6441d961 a3959cbb f758e547 6139cf8b 5a61156d 29602d4d 01125aed 65ff3c50 19028180 23224045 95e447f8 34223441 6a8cada2 947436c1 bd6208cd b1679940 fbdf95b0 2f1f6682 9746340c 89fa1039 8751fa46 7d78bf50 067d16a9 2aa34b83 d974cd30 955ccb09 9ec27625 271d9976 8ef5d72e 2131c450 7d6f1c43 9ad544e9 633a1899 701d87cc d9b10ad1 c46b4920 d62b5faa 5df8e251 8548f5cb 0cd7a8da cf76ae77 02818044 69575f7d e42cd330 b88c60aa 77c6233c 9c6dd7e3 6c79cfe6 f99e4ba3 903da28c 94ee07bc eb07aa32 ff8991b6 4df737b8 575e217f 9b16c23e 90e4f30c 8419c48e 8ef82992 4230c24f 99238ea7 cb86af83 ac21ee5f 2575273c a6d2f922 5c90a1cb 146735b3 5ea436f6 d4ee0f6f 5f482352 d3fcc6dd 1a75bca9 8cfc5c23 af8c16");
    let ciphertext = hex!("27c95dad f3ffb7a8 5efaeb75 52243400 d9269b17 4ac925a6 6cb6478e 63306d00 f45e4a07 e57ed4fb d5ed2088 367bd62a 4890a892 8b37f81f aa2ea311 f0f9d460 2a220c02 ae76736b e6699e59 6e72d669 e17833c7 bf4379db 41987699 ffb1720b a50a9ad8 862d719c 6442b39d c7637aac 32682e31 47929a4a 1723e6e3 675ad623 42187c49 d1d4c5c5 db8e8ec3 bc4a1b4b f1c65701 b17af842 dd9a0f2f 20d96731 b462dc8c bdc18174 75efa5a6 f717e5f8 ef146b72 4890bccb 3fe3c209 3ed2c234 f3079e85 d4315d6f 7e591b83 b6f77cf2 fb8c4bbf c75ae76c 5f956a77 5bec62d7 d0dd21b8 0736c540 20e381e3 97aa5f4f 8a096e21 9f225305 522666cf 74b0dafc b3ace378 2cfaf755 e46cd2ca c7d6f229 0983ff6a 6ecdafdd 7ab40e31 0790fb2e 921fef3e a5265614 2703f35b f57613c2 9cc76636 f1b4f356 b50fce14 594b64e1 a7a01503 de369eeb 33f05a3a 6c");
    let plaintext = "Some text, including emojis 😀 🖖 and greek letters Φ Θ";
    let plaintext_ba = plaintext.as_bytes();

    let rsa_priv = RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap();
    let rsa_pub = rsa_priv.to_public_key().to_pkcs1_der().unwrap();
   
    let decryptor = RsaOAEPSHA256AESGCM::<U256>::from_key_decap(rsa_priv.clone());
    let result = decryptor.open ( Payload{msg: ciphertext.as_ref(), aad: rsa_pub.as_bytes()} );
    assert! ( &result.unwrap() == plaintext_ba);

    let encryptor = RsaOAEPSHA256AESGCM::<U256>::from_key_encap(rsa_priv.to_public_key());
    let ciphertext2 = encryptor.seal ( Payload { msg: plaintext_ba, aad: rsa_pub.as_bytes()}).unwrap();

    let plaintext2 = decryptor.open ( Payload{msg: ciphertext2.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    assert_eq!(plaintext2, plaintext_ba);
}

#[test]
fn apple_sample_5_rsa_2048_sha384() {
    let priv_key = hex!( "308204a3 02010002 82010100 b0a5c91a 39f39a3c a80dc22d eb0c7549 93b4a960 c8a553e3 b1446e96 a41e6dc3 dc2f4b18 85965be3 92010735 7fa2b1c7 5f519fac a176b435 7fb724aa d6609975 705b9e80 2dcbc473 059679eb acb1b9de bc10641f a0871d90 799e6637 afb1f3a7 925f8192 ff6575f5 47f41af2 58dc1478 bb5067ec 67d1d534 c50da7ca bd210552 60109d13 12008323 a3477275 061cfa0b 4c3e7699 145ef160 12d0182a e04131b0 2877fd00 ccff9c3d 2acaef0f ef13a0a8 efd2b685 7dea81d0 b13c8e80 971afae2 350c2ec8 d14fe27a 9b171eb5 ada636a1 14acc88d f2a2f70f 025e0751 25c03181 48bbe801 e53f0d55 063e11e1 6ee9e242 3b8c9732 3c019878 7af11deb 7eb9c8a5 02030100 01028201 003475d7 c6712576 4dc33eea c7064219 e6f2f5b9 43a3f2ed 79f66033 538b83f9 e72bd1e3 c4718fd8 d439bd12 6e01ecc8 4d447292 300b779c 473319a9 cb0e857b ad93e3b1 abb16e0d 7677575b f7f0be8b 4ba9a058 8bc7f9b8 7efa8f5f 1df490ad a2bb669f ad8f298b a17f6ff0 3cbec505 5361959c 7769d1b8 36c6baaa 751c3bdd 3f3d8ec1 b5cca103 2157754b 83c96c2e 9f376154 baf56de9 93308c30 ec591637 5ecf7247 fe2e4793 795ebf66 56e0a350 953891e7 ce45b75e 3910d1c6 9fc930c6 c435fe8f ccdd6bc6 5f49fae6 7080e555 a4c4d48f 487a301b a39acf6f f4c2e7fd 7aaebcf4 e0a25e8a 59cad7ed 2610be27 f061487c 630e3dda e36b973d a173ba2f 95028181 00eb8015 4e6f6ed7 d923bf88 8db4365b 0aa02c92 d5f3009c 0e7505a4 e2ffba28 abc18749 8cea26e6 68b077a8 0d553359 881128de 0d49ae0f e327e3ef 9da95438 850e225a 00562600 8ca90249 ae8ed7ee 558ed4bc 04a41340 083c672b d682149e 17794311 eb630ff9 64363d5b 55aa9d94 e1e37ce7 f1a42934 d881e70e 5e79cfad 5f028181 00c00638 a85d4b35 f5cc164c 09cb916a 11addd5a c14cc9ed 14230a5e 5576d23d 2eaa66cf 83f4a8bb 142cf97e 2502929e 612255b6 88345f53 f8f09303 cda2e357 7483e208 b827b626 8c768142 e410102f 90d2134a 10fd1bfb 882b0f16 aa69d6ca c4215e4c 5a77b98e dda1f50f 3985807f 89138fb5 69fdb45c 66729e51 fdd44404 7b028181 00ca1b5e 2db64c76 4a0ff7ec 855047e5 d234ac8c 47b908a8 e56f60ac a573ba9b f4eb5de3 ad5fb68a bf05d36b 122630af 81aad85b d9238692 73ec641d dc3cd9de b7b1eda1 37f0b724 79930237 a1eb4d3d 6987eee2 7d49228c 2d854935 c21e58fb 6441d961 a3959cbb f758e547 6139cf8b 5a61156d 29602d4d 01125aed 65ff3c50 19028180 23224045 95e447f8 34223441 6a8cada2 947436c1 bd6208cd b1679940 fbdf95b0 2f1f6682 9746340c 89fa1039 8751fa46 7d78bf50 067d16a9 2aa34b83 d974cd30 955ccb09 9ec27625 271d9976 8ef5d72e 2131c450 7d6f1c43 9ad544e9 633a1899 701d87cc d9b10ad1 c46b4920 d62b5faa 5df8e251 8548f5cb 0cd7a8da cf76ae77 02818044 69575f7d e42cd330 b88c60aa 77c6233c 9c6dd7e3 6c79cfe6 f99e4ba3 903da28c 94ee07bc eb07aa32 ff8991b6 4df737b8 575e217f 9b16c23e 90e4f30c 8419c48e 8ef82992 4230c24f 99238ea7 cb86af83 ac21ee5f 2575273c a6d2f922 5c90a1cb 146735b3 5ea436f6 d4ee0f6f 5f482352 d3fcc6dd 1a75bca9 8cfc5c23 af8c16");
    let ciphertext = hex!("574dcebf a7a7827b 8e7a073a a9d1eede 6cec5ec5 5ab4406a ffc30108 4001269c eddd2161 4ecd9131 03d81fdd a8733100 1e021d2a 230586ca 2cc9c126 ebcea2bb fac9fc49 9a437f8f c285385b 5da0b393 86f8f9e8 63b4d948 e73ccfab 793b0dac e4d8a530 84066004 a646a46f 1640b6b2 918134a9 c71f9ce1 213bcc4a 13229ac1 b34f4113 83977d06 f8fa626e 779d2879 e5c9ded3 7d821c05 26850fb1 d952be75 9524fb8a 0ac34fbe a1721108 7d47614c 8788ea92 5158eaec 78b64167 07096c60 96a818bb 283922f8 4c4fd976 0a9b38be a54c6170 8177b419 90319fa1 d5bdc981 2af2e185 ef2e7466 3e067d7b 2ce35ac7 f3ea1f21 1bdb66ce 8fd8388e 178337ba a0856a2b bb399373 20caf39d 22b96ea6 8bbaa3f2 c7ff9772 d644f0cc 984d1b53 3031438b 89e3e1fa acb25fea af534e59 eefc2e47 6e729db1 4c70e251 5138fd33 dc681fcd 748195c3 8bdb0b14 7e");
    let plaintext = "Some text, including emojis 😀 🖖 and greek letters Φ Θ";
    let plaintext_ba = plaintext.as_bytes();

    let rsa_priv = RsaPrivateKey::from_pkcs1_der(&priv_key).unwrap();
    let rsa_pub = rsa_priv.to_public_key().to_pkcs1_der().unwrap();
   
    let decryptor = RsaOAEPSHA384AESGCM::<U256>::from_key_decap(rsa_priv.clone());
    let plaintext2 = decryptor.open ( Payload{msg: ciphertext.as_ref(), aad: rsa_pub.as_bytes()} );
    assert! ( &plaintext2.unwrap() == plaintext_ba);

    let encryptor = RsaOAEPSHA384AESGCM::<U256>::from_key_encap(rsa_priv.to_public_key());
    let ciphertext2 = encryptor.seal ( Payload { msg: plaintext_ba, aad: rsa_pub.as_bytes()}).unwrap();

    let plaintext3 = decryptor.open ( Payload{msg: ciphertext2.as_ref(), aad: rsa_pub.as_bytes()}).unwrap();
    assert_eq! ( plaintext3, plaintext_ba);
}



///
/// 
/// openssl pkeyutl -encap -pubin -kemop RSASVE -inkey rsa_priv.pem -out encap_out.bin -secret secret.bin
/// 
#[test]
fn openssl_encap_rsa () {

    let rsa_priv = "-----BEGIN PRIVATE KEY-----\n\
        MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAPVQnf4ggADiq0bt\n\
        zDmPU/mSxrVl4oW3Ioa0kTDIPrH7NDFUqSxipEtIff47MTTYcMKtHMnzEXBr/eB5\n\
        Ll8DduZQS6H6EyUiEVSFazfD3Ca3sB8jaNlEoUbHkUnV9GNxLcvOfUa7WjXxlYbG\n\
        N50kwixfsA8o8O7mFPJ8kyHXa2CzAgMBAAECgYA+iHhdyWcX0rAaeo+utIyReArT\n\
        Ps+Jim9wqyK/rqvcrs5VLOGbAOIklqwXXHtkny/PUFWgXSe64qxqxjk92yI5f8Io\n\
        Z/HPgvwEoy/b9plX++u+dZj5iePd2Q21vvPvENg6hVHh8XhitEiW5D/QnnaNCpxp\n\
        zzzZE2wdrL0BJvONYQJBAP8BX6oEkzdHospjZboLj2zSnPGEHEqrlE1Mh4y101DI\n\
        njI7cj/PAM15kFZKKeyOp6o2TGI6Fdt6i/PS8J/XaHkCQQD2RZFCci7puO+PIq5L\n\
        z1NTwdvJwuqY+A+h5x44DlLCCrdJYTGhewXfQTZTI3f3NdMWe958sKb1f8/rHo7g\n\
        hx+LAkAFcooQn7hlXepkWGs75jNSJ82ieyf/kFrCq/fZUakJ+L8oY4y1QD7MJOSo\n\
        cz0iCIocYLyQ/Jyq65tBwifRwlBBAkBemAgcoqk8Yym5LBQQ0HjsQhk/HVxpF1dB\n\
        0/l6hJ3rJJyUVf3vTcbKo0zPkF8jGIyVJU0nTd9Diy183Ub6HUzTAkBBl5zIcObJ\n\
        CXb2OjqwawsES1k+uDoBQrP7SYZxgQ+/Car4wWNe5m+nvZtjKL6Hy8hJTPU0JzKu\n\
        5PU3t7smZHqk\n\
        -----END PRIVATE KEY-----";

    let encapped_key = hex!("50 62 03 ac 64 20 ef 33  4f 36 f7 df 04 52 be a7
    98 45 78 ac af 59 ff f1  34 a3 bb 3c 10 a3 e7 7e
    69 77 8c a8 e0 c2 88 ab  9d 06 6f b2 30 9e da c1
    3f e5 55 e4 07 05 da 91  4d d3 a2 53 45 7e ae 3a
    77 47 14 bd 09 10 0c d4  f6 fd c8 88 79 20 86 e6
    9f 42 03 85 9b 18 a5 91  f2 76 1d 81 84 58 47 dd
    b7 f6 da fb 76 cd 2d 3c  e7 7c 66 fb 90 5f 73 09 
    cc b8 25 90 bb 8c cd 0e  f0 f7 70 e3 60 e8 d7 45 ");

    let key = hex!("aa a2 be 22 4e 1c 3e 17  b2 72 73 37 f2 f3 01 7e
      b9 3f 26 1c 43 78 de f4  01 33 7b b9 ca c2 4b da
      b3 ba a8 e3 61 e0 b5 cc  5e 73 88 a7 fa 35 40 63
      21 7e 3c e8 b2 ef f0 7c  75 39 24 f9 68 28 c3 39
      c4 ae 31 d5 36 c6 f4 68  c4 19 e5 7b 5f d3 cd 4f
      84 24 61 cc 70 d1 85 db  ce 3c 38 ea 9f 2f 98 d8
      0e 40 b9 76 b6 5a cc 16  e8 b1 97 a0 d0 34 8e 04
      2a d2 1b 50 86 d9 c6 da  04 8e c1 ff 0d 0d 97 3e");

    let rsa_priv2 = rsa::RsaPrivateKey::from_pkcs8_pem(rsa_priv).unwrap();

    let decapsulator = RsaDecapsulator::<U128, U128, RsaRaw>::from_key(rsa_priv2);
    let shared_secret = decapsulator.decapsulate(&encapped_key.as_slice().try_into().unwrap());
    assert_eq!( shared_secret, key);
}



#[test]
fn test_ec_ml_kem ()
{
    let (decapsulator, encapsulator) = EcdhKem::<NistP256, EcCompressedEncoder<NistP256>>::generate_keypair();
    let (ek, ss) = encapsulator.encapsulate();
    let ss2 = decapsulator.decapsulate(&ek);
    assert_eq! ( ss, ss2);
}

#[test]
fn test_apple_full ()
{
    let (encryptor, decryptor) = EciesStandardX963SHA256AESGCM::<NistP256>::generate();

    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}

#[test]
fn test_apple_2 ()
{
    let (encryptor, decryptor) = EciesStandardVariableIVX963SHA256AESGCM::<NistP384>::generate();

    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}


#[test]
fn test_apple_3 ()
{
    let (encryptor, decryptor) = EciesStandardX963SHA512AESGCM::<NistP521>::generate();
    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}


#[test]
fn test_apple_4 ()
{
    let (encryptor, decryptor) = RsaOAEPSHA256AESGCM::<U256>::generate();
    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}


#[test]
fn test_sm2_5 ()
{
    let (encryptor, decryptor) = EciesSm2::generate();
    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}


#[test]
fn test_pkcs15 ()
{
    let (encryptor, decryptor) = RsaesPkcs15IesJweA128CbcHS256::<U256>::generate();
    let ciphertext = encryptor.seal ( b"Hello World".as_slice()).unwrap();
    let plaintext = decryptor.open ( ciphertext.as_slice()).unwrap();
    assert_eq! ( plaintext, b"Hello World");
}