use aead::consts::{U16, U24, U32, U128, U256, U384};
use aead::{AeadInOut, KeyInit, Payload};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use base64::Engine;
use cipher::{BlockModeDecrypt, InOutBuf, KeyIvInit, StreamCipher};
use cipher::block_padding::{Iso7816, Pkcs7};
use cms::authenveloped_data::AuthEnvelopedData;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{OriginatorIdentifierOrKey, RecipientIdentifier, RecipientInfo};
use cms::enveloped_data::{RecipientInfo::Kari, EnvelopedData, OriginatorIdentifierOrKey::OriginatorKey,RecipientInfo::Ktri};
use cms::cert::x509::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned,SubjectPublicKeyInfo};
use cms::kemri::{CmsOriForKemOtherInfo, ID_ORI_KEM, KemRecipientInfo};
use cms::signed_data::SignedData;
use const_oid::AssociatedOid;
use const_oid::db::rfc5911::{DES_EDE_3_CBC, ID_AES_128_GCM, ID_AES_192_WRAP, ID_AES_256_WRAP, ID_AES_256_CBC, ID_AES_256_GCM, ID_CT_AUTH_ENVELOPED_DATA, ID_DATA, ID_ENVELOPED_DATA, ID_SIGNED_DATA, ID_AES_128_WRAP, ID_AES_128_CBC};
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, ID_MGF_1, ID_RSAES_OAEP, ID_SHA_256};
use const_oid::db::rfc9688::{ID_KDF_KDF_3, RSA_ENCRYPTION};
use const_oid::db::rfc5753::{DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME, DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME};
use const_oid::db::fips203::ID_ALG_ML_KEM_512;
use der::{Choice, Decode, Encode, Sequence};
use der::asn1::{Any, AnyRef, BitString, OctetString, OctetStringRef, SetOfVec};
use des::TdesEde3;
use hex_literal::hex;
use ies::{SimpleIes, Ies, IesWithKeyWrap};
use ies::cms::{A128CbcNoMac, A256CbcNoMac, ID_AES_128_OFB_NEW, TdesCbcNoMac};
use ies::encrypt_then_mac::{EncryptNoMac, StreamNoMac};
use kdfs::rfc8619::{HkdfSha256, ID_ALG_HKDF_WITH_SHA256};
use kdfs::{InitSalt};
use kdfs::Kdf;
use kdfs::ansi_x9_63::X963Kdf;
use kdfs::ansi_x9_44::X944Kdf3;
use kdfs::misc::PassThroughKdf;
use kdfs::hybrid_array::Array;
use kdfs::rfc5869_hkdf::Hkdf;
use kem::{TryDecapsulate, Decapsulator, Kem, KeyExport, TryKeyInit};
use kems::{KemExtensions, SetKdf,};
use kems::draft_ietf_lamps_pq_composite_kem::{HybridKemMlKem768P256Sha3_256, ID_MLKEM768_ECDH_P256_SHA3_256};
use kems::rfc9936::MlKem512Hkdf256;
use kems::kem_with_kdf::{CombinerNoKeys, KemWithKdf};
use kems::rsakem::{RsaOrigKem,RsaPkcs15Kem,RsaOaepKem,ID_KEM_RSA};
use kems::rfc5753::{DhSinglePassStdDhSha384KdfScheme, DhSinglePassStdDhSha512KdfScheme,DhSinglePassStdDhSha256KdfScheme};
use kems::eckem::{EcdhKem, EcUncompressedEncoder};
use ml_kem::{MlKem512, MlKem768, ml_kem_512};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use rsa::traits::PublicKeyParts;
use rsa::pkcs1::{DecodeRsaPrivateKey, RsaOaepParams};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey,PrivateKeyInfoRef};
use sha1::Sha1;
use sha2::{Sha256,Sha512};
use x509_cert_new::ext::pkix::SubjectKeyIdentifier;

mod common;

///
/// Struct used as additional information in the derivation process used for ECIES
/// 
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EccCmsSharedInfo { //}::= SEQUENCE {
    key_info:       AlgorithmIdentifier<Any>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional="true")]
    entity_uinfo:   Option<OctetString>, // [0] EXPLICIT OCTET STRING OPTIONAL,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    supp_pub_info:  OctetString, // [2] EXPLICIT OCTET STRING  
}

// GCMParameters ::= SEQUENCE {
//     aes-nonce        OCTET STRING, -- recommended size is 12 octets
//     aes-ICVlen       AES-GCM-ICVlen DEFAULT 12 }

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct GcmParams {
    aes_nonce: OctetString,
    aes_icv_len: u8,
}

// ML-KEM-PrivateKey ::= CHOICE {
//   seed [0] IMPLICIT OCTET STRING (SIZE (64)),
//   expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)),
//   both SEQUENCE {
//     seed OCTET STRING (SIZE (64)),
//     expandedKey OCTET STRING (SIZE (1632 | 2400 | 3168)) } }
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum MlKemPrivateKeyChoice {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Seed(OctetString),
    ExpandedKey(OctetString),
    //both(Any),
}


/// Sample script created from openssl using ECDH with P-256 and KDF with Sha256
/// 
/// openssl ecparam -name prime256v1 -genkey -noout -out p256-priv.pem
/// openssl pkey -in p256-priv.pem -pubout -out p256-pub.pem
/// openssl req -new -sha256 -key p256-priv.pem -out p256-crt.pem -days 360 -x509
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip p256-pub.pem -outform pem -aes192-wrap -aes256 -keyopt ecdh_kdf_md:sha256
#[test]
fn test_cms_p256_decrypt()
{
    let priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
        MHcCAQEEIIAeR+r0C/MJx1xE9GUqBTFaCLl+9HeZrjKA1/jUC+D3oAoGCCqGSM49\n\
        AwEHoUQDQgAElRlvqDFGAdt8Lnp5LSlpli5oARWQPm85pro3s+wWAHbdh49IW+rb\n\
        k5tyDD2vz0/ifJjQbSSXsV13TSSVK73hDg==\n\
        -----END EC PRIVATE KEY-----";

    let cms = "-----BEGIN CMS-----\
        MIIBVgYJKoZIhvcNAQcDoIIBRzCCAUMCAQIxgf+hgfwCAQOgUaFPMAkGByqGSM49\
        AgEDQgAE4M09qF7rXFI6UcYIFaFVB4GQ9dXnmiEdhQrRgY9DIPG3CgGQlkzXWasJ\
        uPHOVQIAOqHrRbnifUGl7JbbPi8ivjAVBgYrgQQBCwEwCwYJYIZIAWUDBAEZMIGM\
        MIGJMF0wRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNV\
        BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZAIUaWv5adMNlXvGhj8G3lrf5xNV\
        a6sEKJtYjXan32oBMVDYjFwgE4Y2F70a88FacnAYDgjKVBLuvLAiOC4temYwPAYJ\
        KoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQGYf4veCjarvc/UlLGkQZL4AQMrOgaoto\
        veqbWy8Y3knjNQ==\
        -----END CMS-----";

    let recip_priv = p256::SecretKey::from_sec1_pem(priv_key_pem).unwrap();
    let recip_pub = recip_priv.public_key();

    // Decode CMS structure
    let content_info  = ContentInfo::from_der(pem::parse(cms).unwrap().contents()).unwrap();
    assert_eq! ( content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();

    let iv = enveloped_data.encrypted_content.content_enc_alg.parameters.unwrap().decode_as::<OctetString>().unwrap();
    let ciphertext = enveloped_data.encrypted_content.encrypted_content.unwrap();
    
    
    // Handle recipient info
    assert! ( enveloped_data.recip_infos.0.len() == 1);
    let Kari(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    assert_eq! ( recip.key_enc_alg.oid, DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME );
    assert_eq! ( recip.key_enc_alg.oid, DhSinglePassStdDhSha256KdfScheme::<NistP256,U24>::OID);
    let kem_params = recip.key_enc_alg.parameters.as_ref().unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq! ( kem_params, AlgorithmIdentifierOwned{ oid: ID_AES_192_WRAP, parameters: None });
    
    // Handle originator fields
    let OriginatorKey(orig) = &recip.originator else { panic!("Unhandled")};
    assert! ( orig.algorithm.oid == ID_EC_PUBLIC_KEY);
    let _sender_pub = elliptic_curve::PublicKey::<NistP256>::from_sec1_bytes(orig.public_key.raw_bytes()).unwrap();
    let encapsulated_key: Array<u8, _> = Array::try_from(orig.public_key.raw_bytes()).unwrap();
    
    // Handle recipient encrypted keys
    assert! ( recip.recipient_enc_keys.len() == 1);
    let enc_key = &recip.recipient_enc_keys.get(0).unwrap().enc_key;
        
    assert! ( enveloped_data.encrypted_content.content_enc_alg.oid == ID_AES_256_CBC);
    let ecc_shared_info = EccCmsSharedInfo{ key_info: AlgorithmIdentifierOwned { oid: ID_AES_192_WRAP, parameters: None }, 
            entity_uinfo:recip.ukm.clone(), supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap() };
    
    // Recover content encryption key
    let kdf2 = X963Kdf::new_with_salt(&ecc_shared_info.to_der().unwrap());
    let mut decapsulator = DhSinglePassStdDhSha256KdfScheme::from_private_key(recip_priv.clone());
    decapsulator.set_kdf(kdf2.clone());
    
    let shared_secret: Array<u8, U24> = decapsulator.try_decapsulate(&encapsulated_key).unwrap();
    let kek = aes_kw::KwAes192::new(&shared_secret);
    let cek = kek.unwrap_fixed_key(&Array::try_from(enc_key.as_bytes()).unwrap()).unwrap();
    // Decrypt content
    let decryptor = cbc::Decryptor::<Aes256>::new(&cek, &Array::try_from(iv.as_bytes()).unwrap());
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();
    assert! ( plaintext == b"Hello World\r\n" );

    // Using Ies 
    type IesCmsP256AesKwAesCbc256 = IesWithKeyWrap::<DhSinglePassStdDhSha256KdfScheme<NistP256,U24>, Aes192, A256CbcNoMac>;
    
    let mut decryptor2 = IesCmsP256AesKwAesCbc256::from_key_decap(recip_priv.clone());
    decryptor2.set_kdf(kdf2.clone());
    let plaintext2 = decryptor2.open_detached(&encapsulated_key, enc_key.as_bytes().try_into().unwrap(), ciphertext.as_bytes(), &[].into(), &iv.as_bytes().try_into().unwrap()).unwrap();
    assert_eq!(plaintext2, plaintext);

    // Rewrap 
    let mut encryptor3 = IesCmsP256AesKwAesCbc256::from_key_encap(recip_pub);
    encryptor3.set_kdf(kdf2.clone());
    let (encapped_key_3, ciphertext_4, encrypted_cek_4, tag4) = encryptor3.seal_detached( &cek, plaintext.as_ref(), iv.as_bytes().try_into().unwrap() ).unwrap();

    // Re-unwrap using AsymmKeyWrap
    let mut decryptor4 = IesCmsP256AesKwAesCbc256::from_key_decap(recip_priv.clone());
    decryptor4.set_kdf(kdf2.clone());
    let plaintext4 = decryptor4.open_detached(&encapped_key_3, ciphertext_4.as_slice().try_into().unwrap(), encrypted_cek_4.as_slice(), &tag4, &iv.as_bytes().try_into().unwrap()).unwrap();
    
    assert_eq!(plaintext4, plaintext);
    
}


/// Sample script created from openssl using ECDH with P-38456 and KDF with Sha384
/// 
/// openssl ecparam -name secp384r1 -genkey -noout -out p384-priv.pem
/// openssl pkey -in p384-priv.pem -pubout -out p384-pub.pem
/// openssl req -new -sha256 -key p384-priv.pem -out p384-crt.pem -days 360 -x509
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip p384-crt.pem -outform pem -aes192-wrap -aes256 -keyopt ecdh_kdf_md:sha384
#[test]
fn test_cms_p384_decrypt2()
{
    let priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
        MIGkAgEBBDBBY/PX1sR/mbezT4Vw3LLyyIS63A7D8+p8jT1xU9qe3dumZmyRaaza\n\
        anjFedHQ+2agBwYFK4EEACKhZANiAASPVbmpoBxS0oayBlOXSInsxT4r+/UtAHqs\n\
        pFlnScici4b4KTy9PzZUT3bI4rPTNYvgq+/h1YiAuxVSposTxzuyIcZaYWVVKtNA\n\
        4edKoVeCxNkRDeCsQ3yDJduaLKbuk6M=\n\
        -----END EC PRIVATE KEY-----";

    let cms = "-----BEGIN CMS-----\n\
        MIIBeAYJKoZIhvcNAQcDoIIBaTCCAWUCAQIxggEgoYIBHAIBA6BxoW8wCQYHKoZI\n\
        zj0CAQNiAASz/jMrWU9qGYYRncnLZD/Gl+3byubQs3U7aL+pZGFuLWi5DHq5OQ1B\n\
        EFnN0S3aJW0GhWmYAmXBMyFq6w/hIW9WpWsG34sH8q3+anksoKvlctwoaG6ClRXq\n\
        9HScLUcr/bUwFQYGK4EEAQsCMAsGCWCGSAFlAwQBGTCBjDCBiTBdMEUxCzAJBgNV\n\
        BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n\
        aWRnaXRzIFB0eSBMdGQCFAJXwqzHf1bY7OqgKoLEZKWTd7iUBCisECLAHG8+5uM4\n\
        dFLlDlM7vJJ/7WsuV7pu9nyZta/AZAI0xDifyhkAMDwGCSqGSIb3DQEHATAdBglg\n\
        hkgBZQMEASoEENKfnAmlAeJkgyXbj3xVAFaAEKt5ab7ouSd0SGi2ifEHq4M=\n\
        -----END CMS-----";

    let recip_priv = p384::SecretKey::from_sec1_pem(priv_key_pem).unwrap();
    let recip_pub = recip_priv.public_key();

    let content_info  = ContentInfo::from_der(pem::parse(cms).unwrap().contents()).unwrap();
    assert_eq!(content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();

    assert! ( enveloped_data.recip_infos.0.len() == 1);
    let Kari(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    assert_eq! ( recip.key_enc_alg.oid, DH_SINGLE_PASS_STD_DH_SHA_384_KDF_SCHEME);
    assert_eq! ( recip.key_enc_alg.oid, DhSinglePassStdDhSha384KdfScheme::<NistP384, U24>::OID);
    let enc_params = recip.key_enc_alg.parameters.as_ref().unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq! ( enc_params, AlgorithmIdentifierOwned{oid: ID_AES_192_WRAP, parameters: None});
    
    assert! ( recip.recipient_enc_keys.len() == 1);
    let enc_key = &recip.recipient_enc_keys.get(0).unwrap().enc_key;
    
    let OriginatorKey(orig) = &recip.originator else { panic!("Unhandled")};
    assert! ( orig.algorithm.oid == ID_EC_PUBLIC_KEY);
    let _sender_pub = p384::PublicKey::from_sec1_bytes(orig.public_key.raw_bytes()).unwrap();
    
    let ecc_shared_info = EccCmsSharedInfo{ key_info: AlgorithmIdentifierOwned { oid: ID_AES_192_WRAP, parameters: None }, entity_uinfo: recip.ukm.clone(), 
        supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap() };
    
    // Recover cek
    let kdf2 = X963Kdf::new_with_salt(&ecc_shared_info.to_der().unwrap());
    let mut decap = DhSinglePassStdDhSha384KdfScheme::from_private_key(recip_priv.clone());
    decap.set_kdf(kdf2.clone());
    let encapped_key = Array::try_from(orig.public_key.raw_bytes()).unwrap();
    let shared_secret = decap.try_decapsulate(&encapped_key).unwrap();
    let kek = aes_kw::KwAes192::new(&shared_secret);
    let cek = kek.unwrap_fixed_key(enc_key.as_bytes().try_into().unwrap()).unwrap();

    // Decrypt content
    let encrypted_content = &enveloped_data.encrypted_content;
    assert! ( encrypted_content.content_enc_alg.oid == ID_AES_256_CBC);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let ciphertext = encrypted_content.encrypted_content.as_ref().unwrap();
    
    let decryptor = cbc::Decryptor::<Aes256>::new(&cek, iv.as_bytes().try_into().unwrap());
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();
    assert! ( plaintext == b"Hello World\r\n" );

    // Using Ies 
    type IesCmsP384AesKwAesCbc256 = IesWithKeyWrap::<DhSinglePassStdDhSha384KdfScheme<NistP384,U24>, Aes192, A256CbcNoMac>;

    let mut decryptor2 = IesCmsP384AesKwAesCbc256::from_key_decap(recip_priv.clone());
    decryptor2.set_kdf(kdf2.clone());
    let plaintext2 = decryptor2.open_detached(&encapped_key, enc_key.as_bytes().try_into().unwrap(), ciphertext.as_bytes(), &[].into(), &iv.as_bytes().try_into().unwrap()).unwrap();
    assert_eq!(plaintext2, plaintext);

    // Encrypt with random data 
    let mut encryptor3 = IesCmsP384AesKwAesCbc256::from_key_encap(recip_pub);
    encryptor3.set_kdf(kdf2.clone());
    let (encapped_key_3, ciphertext_4, encrypted_cek_4, tag4) = encryptor3.seal_detached(&cek, plaintext.as_ref(), iv.as_bytes().try_into().unwrap() ).unwrap();

    // Decrypt
    let mut decryptor4 = IesCmsP384AesKwAesCbc256::from_key_decap(recip_priv.clone());
    decryptor4.set_kdf(kdf2.clone());
    let plaintext4 = decryptor4.open_detached(&encapped_key_3, ciphertext_4.as_slice().try_into().unwrap(), encrypted_cek_4.as_slice(), &tag4, &iv.as_bytes().try_into().unwrap()).unwrap();
    
    assert_eq!(plaintext4, plaintext);
}




/// Sample script created from openssl using ECDH with P-256 and KDF with Sha256
/// 
/// openssl ecparam -name prime256v1 -genkey -noout -out p256-priv.pem
/// openssl pkey -in p256-priv.pem -pubout -out p256-pub.pem
/// openssl req -new -sha256 -key p256-priv.pem -out p256-crt.pem -days 360 -x509
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip p256-pub.pem -outform pem -aes192-wrap -aes256 -keyopt ecdh_kdf_md:sha256

#[test]
fn test_cms_p256_decrypt_gcm() -> Result<(), pem::PemError>
{
    let priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
        MHcCAQEEIGvNx9z0Ks90NxEP8kGsSM24p2hpXOVp4RYcX8eoy1J+oAoGCCqGSM49\n\
        AwEHoUQDQgAE1v5Sf5sYMG4ziVOk5mk8RWyjYtXrtCU6nRC8v/FhniuAahtu6Qtc\n\
        J6u1mCbfqy+RQh9GAYba4NwipEz4TDwZ6Q==\n\
        -----END EC PRIVATE KEY-----";

    let cms = "-----BEGIN CMS-----\n\
        MIIBVgYLKoZIhvcNAQkQARegggFFMIIBQQIBADGB7aGB6gIBA6BRoU8wCQYHKoZI\n\
        zj0CAQNCAATBvPS7d+aWb3csGXVE8tEUEW4thIlGNFc3givH6FEVFphRE6Z3TVuO\n\
        zIx3xGOrZJ2YchpoNhLmQvGYiaLwsNNpMBUGBiuBBAELATALBglghkgBZQMEARkw\n\
        ezB5MF0wRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNV\n\
        BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZAIUa387gJugMF99WtCUflM7iLrh\n\
        8cQEGJfXKJUBrIfT4Ax+LN3FLIzlwKxQOta86jA6BgkqhkiG9w0BBwEwHgYJYIZI\n\
        AWUDBAEGMBEEDOQ55BMf6c72aytJpwIBEIANB7j+/PngW9mW2+3dbAQQVC1W6F9Z\n\
        C74ir4QqU0gcjA==\n\
        -----END CMS-----";

    let plaintext = b"Hello World\r\n";

    let recip_private = elliptic_curve::SecretKey::<NistP256>::from_sec1_pem(priv_key_pem).unwrap();
    let recip_public = recip_private.public_key();

    let content_info  = ContentInfo::from_der(pem::parse(cms).unwrap().contents()).unwrap();
    assert! ( content_info.content_type == ID_CT_AUTH_ENVELOPED_DATA);
    let auth_enveloped_data = content_info.content.decode_as::<AuthEnvelopedData>().unwrap();

    assert_eq! ( auth_enveloped_data.version, CmsVersion::V0);
    let mac = &auth_enveloped_data.mac;    

    // Handling of recipient infos
    assert_eq! ( auth_enveloped_data.recip_infos.0.len(), 1);
    let RecipientInfo::Kari(recip_info) = auth_enveloped_data.recip_infos.0.get(0).unwrap() else { panic! ( "unhandled enum")};
    assert_eq! ( recip_info.version, CmsVersion::V3);
    assert_eq! ( recip_info.key_enc_alg.oid, DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME);
    assert_eq! ( recip_info.key_enc_alg.oid, DhSinglePassStdDhSha256KdfScheme::<NistP256,U24>::OID);
    let key_enc_params = recip_info.key_enc_alg.parameters.as_ref().unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq! ( key_enc_params, AlgorithmIdentifierOwned{ oid: ID_AES_192_WRAP, parameters: None});

    assert_eq! ( recip_info.recipient_enc_keys.len(), 1);
    let wrapped_key = &recip_info.recipient_enc_keys.get(0).unwrap().enc_key;

    let OriginatorIdentifierOrKey::OriginatorKey(originator_key) = &recip_info.originator else { panic!("Unhandled enum")};
    assert_eq! ( originator_key.algorithm, AlgorithmIdentifier{oid: ID_EC_PUBLIC_KEY, parameters: None});
    let encapsulated_key = Array::try_from(originator_key.public_key.raw_bytes()).unwrap();
    
    let ecc_shared_info = EccCmsSharedInfo{ 
        key_info: key_enc_params, //AlgorithmIdentifierOwned { oid: ID_AES_192_WRAP, parameters: None }, 
        entity_uinfo: recip_info.ukm.clone(), 
        supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap() };
    
    // Recover CEK
    let kdf2 = X963Kdf::<Sha256>::new_with_salt(&ecc_shared_info.to_der().unwrap());
    let mut decapsulator = DhSinglePassStdDhSha256KdfScheme::from_private_key(recip_private.clone());
    decapsulator.set_kdf(kdf2.clone());
    
    let shared_secret = decapsulator.try_decapsulate(&encapsulated_key).unwrap();
    let kek = KwAes192::new(&shared_secret);
    let cek = kek.unwrap_fixed_key(wrapped_key.as_bytes().try_into().unwrap()).unwrap();
        
    // Handling of encrypted content
    let auth_encrypted_content = &auth_enveloped_data.auth_encrypted_content_info;
    assert_eq! ( auth_encrypted_content.content_type, ID_DATA);
    assert_eq! ( auth_encrypted_content.content_enc_alg.oid, ID_AES_128_GCM);
    let iv_params = auth_encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<GcmParams>().unwrap();

    let nonce = iv_params.aes_nonce.as_bytes().try_into().unwrap();
    let ciphertext = auth_encrypted_content.encrypted_content.as_ref().unwrap();

    let decryptor = Aes128Gcm::new(&cek);// AesGcm::<Aes128,U12>::new(&cek);
    let mut buffer = ciphertext.as_bytes().to_vec();
    decryptor.decrypt_inout_detached(iv_params.aes_nonce.as_bytes().try_into().unwrap(), &[], buffer.as_mut_slice().into(), &mac.as_bytes().try_into().unwrap()).unwrap();
    assert! ( buffer == plaintext );

    // Use Ies instead
    type IesCmsP256AesKwAesGcm128 = IesWithKeyWrap::<DhSinglePassStdDhSha256KdfScheme<NistP256,U24>, Aes192, Aes128Gcm>;

    let mut decryptor4= IesCmsP256AesKwAesGcm128::from_key_decap(recip_private);
    decryptor4.set_kdf(kdf2.clone());

    let plaintext4 = decryptor4.open_detached(&encapsulated_key, wrapped_key.as_bytes().try_into().unwrap(), ciphertext.as_bytes(), mac.as_bytes().try_into().unwrap(), nonce).unwrap();
    assert_eq! ( plaintext4, plaintext );

    // Reencrypt and redecrypt
    let mut encryptor5 = IesCmsP256AesKwAesGcm128::from_key_encap(recip_public);
    encryptor5.set_kdf(kdf2);

    let (encapped_key5, wrapped_cek2, ciphertext5, tag5) = encryptor5.seal_detached(&cek, plaintext.as_slice(), nonce).unwrap();
    let plaintext5 = decryptor4.open_detached(&encapped_key5, &wrapped_cek2, ciphertext5.as_slice(), &tag5, nonce).unwrap();
    assert_eq!( plaintext5, plaintext );

    Ok(())
}







// Sample script created from openssl using ECDH with P-521 and KDF with Sha512
/// 
/// openssl ecparam -name secp521r1 -genkey -noout -out p521-priv.pem 
/// openssl req -new -sha256 -key p521-priv.pem -out p521-crt.pem -days 360 -x509
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip p521-crt.pem -outform pem -aes192-wrap -aes256 -keyopt ecdh_kdf_md:sha512
#[test]
fn test_cms_p521_decrypt()
{
    let priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
        MIHcAgEBBEIBkhOXGSwq5jr6oWLpf8shQFlKz/FljkFwumuptlsvUDaH40UY9/aS\n\
        ZbwycpnF5LV83SRId4d9vR0p0BQfoL9zKMWgBwYFK4EEACOhgYkDgYYABAG9Nhq0\n\
        ApGchdlPW9LYgbNJv8Ri4DbVIJEik+/YLVBoXK8ZUDtlCF+REVO1yoBA0Vaq6UX+\n\
        7S5tv1WAZHDRuVNT/wDaou0hyDhbrszEOAUeyAOqA75QCWMjZLLz74fAEp/Sl7jv\n\
        9iOgq1LO5di8hqedfb/lEIjMHsqmFIgjpcSehjXt6Q==\n\
        -----END EC PRIVATE KEY-----";

    let cms = "-----BEGIN CMS-----\n\
        MIIBnwYJKoZIhvcNAQcDoIIBkDCCAYwCAQIxggFHoYIBQwIBA6CBl6GBlDAJBgcq\n\
        hkjOPQIBA4GGAAQAFN1n987tSM0YttEE0+Glp5IbY3+vC/6Gwl/78Kb9iCWcWrhV\n\
        4xA2E1t9gohfjV/uysU2K1eVh7jf8lZZUvM91AUByXsr9pMVW4ifNOylt/3Ml2go\n\
        RwBX8DC6vJyERRW9kcwA+pJGfVtB/RUpjnY/cP9WxGis+LcCN9E3oGe2a1NpZn8w\n\
        FQYGK4EEAQsDMAsGCWCGSAFlAwQBGTCBjDCBiTBdMEUxCzAJBgNVBAYTAkFVMRMw\n\
        EQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0\n\
        eSBMdGQCFF49+A4N5AsvNgVRwerDdWERyLYfBCh5B1btSA4qn1L2H04qibvuUlLl\n\
        yKN/e+MQxh+FGEdKyI4MtHwer+xrMDwGCSqGSIb3DQEHATAdBglghkgBZQMEASoE\n\
        ENKFSBszpSeFV31NwX8olj+AEKdrgJWE4cHYVo+T0oAdciw=\n\
        -----END CMS-----";

    let recipient_private = elliptic_curve::SecretKey::<NistP521>::from_sec1_pem(priv_key_pem).unwrap();
    let recipient_public = recipient_private.public_key();
   
    let content_info  = ContentInfo::from_der(pem::parse(cms).unwrap().contents()).unwrap();
    assert_eq! ( content_info.content_type, ID_ENVELOPED_DATA );
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();

    assert_eq! ( enveloped_data.recip_infos.0.len(), 1);
    let Kari(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled case")};
    let OriginatorKey(orig) = &recip.originator else { panic!("Unhandled case")};
    let wrapped_key = &recip.recipient_enc_keys.get(0).as_ref().unwrap().enc_key;
    let wrapped_key = wrapped_key.as_bytes().try_into().unwrap();
    
    assert_eq! ( recip.key_enc_alg.oid, DH_SINGLE_PASS_STD_DH_SHA_512_KDF_SCHEME );
    assert_eq! ( recip.key_enc_alg.oid, DhSinglePassStdDhSha512KdfScheme::<NistP521, U24>::OID );
    
    let enc_parameters = recip.key_enc_alg.parameters.as_ref().unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq! ( enc_parameters, AlgorithmIdentifierOwned{oid: ID_AES_192_WRAP, parameters: None} );
    assert_eq! ( orig.algorithm, AlgorithmIdentifier{oid: ID_EC_PUBLIC_KEY, parameters: None});
    assert_eq! ( recip.recipient_enc_keys.len(), 1);
    
    let ecc_shared_info = EccCmsSharedInfo{  
        key_info: enc_parameters, //AlgorithmIdentifierOwned { oid: ID_AES_192_WRAP, parameters: None }, 
        entity_uinfo: recip.ukm.clone(), 
        supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap() };

    // Using discrete primitives
    let kdf2 = X963Kdf::<Sha512>::new_with_salt(&ecc_shared_info.to_der().unwrap());
    let mut decapsulator = DhSinglePassStdDhSha512KdfScheme::from_private_key(recipient_private.clone());
    decapsulator.set_kdf(kdf2.clone());
    let encapsulated_key = Array::try_from(orig.public_key.raw_bytes()).unwrap();

    let kek= decapsulator.try_decapsulate(&encapsulated_key).unwrap();
    let kek = KwAes192::new(&kek);
    let cek = kek.unwrap_fixed_key(wrapped_key).unwrap();

    // Decrypt 
    assert! ( enveloped_data.encrypted_content.content_enc_alg.oid == ID_AES_256_CBC);
    let iv = enveloped_data.encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let iv = iv.as_bytes().try_into().unwrap();
    let ciphertext = enveloped_data.encrypted_content.encrypted_content.unwrap();
    
    let decryptor = cbc::Decryptor::<Aes256>::new(&cek, iv);
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();

    assert! ( plaintext == b"Hello World\r\n" );

    // Using IES struct
    type IesCmsP521AesKw192A256Cbc = IesWithKeyWrap::<DhSinglePassStdDhSha512KdfScheme<NistP521, U24>, Aes192, A256CbcNoMac>;

    let mut decryptor4 = IesCmsP521AesKw192A256Cbc::from_key_decap(recipient_private);
    decryptor4.set_kdf(kdf2.clone());
    let plaintext4 = decryptor4.open_detached(&encapsulated_key, wrapped_key, ciphertext.as_bytes(), &[].into(), &iv).unwrap();
    assert_eq! ( plaintext, plaintext4);

    let mut encryptor5 = IesCmsP521AesKw192A256Cbc::from_key_encap(recipient_public);
    encryptor5.set_kdf(kdf2);
    let (encapsulated_key5, wrapped_key5, ciphertext5, _) = encryptor5.seal_detached(&cek, plaintext.as_slice(), &iv).unwrap();

    let plaintext5 = decryptor4.open_detached(&encapsulated_key5, &wrapped_key5, ciphertext5.as_slice(), &[].into(), &iv).unwrap();

    assert_eq!( plaintext5, plaintext );
}



// Sample script created from openssl using ECDH with P-521 and KDF with Sha512
/// 
/// openssl ecparam -name secp384r1 -genkey -noout -out p384-priv.pem 
/// openssl req -new -sha384 -key p384-priv.pem -out p384-crt.pem -days 360 -x509
/// openssl ecparam -name secp384r1 -genkey -noout -out p384-priv-2.pem 
/// openssl req -new -sha384 -key p384-priv-2.pem -out p384-crt-2.pem -days 360 -x509
/// 
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip p384-crt.pem -outform pem -aes192-wrap -aes256 -keyopt ecdh_kdf_md:sha512 -originator p384-2-priv.pem
//
#[test]
fn test_cms_p384_decrypt() -> Result<(), common::Error>
{
    let priv_key_pem = "-----BEGIN EC PRIVATE KEY-----\n\
        MHcCAQEEIGvNx9z0Ks90NxEP8kGsSM24p2hpXOVp4RYcX8eoy1J+oAoGCCqGSM49\n\
        AwEHoUQDQgAE1v5Sf5sYMG4ziVOk5mk8RWyjYtXrtCU6nRC8v/FhniuAahtu6Qtc\n\
        J6u1mCbfqy+RQh9GAYba4NwipEz4TDwZ6Q==\n\
        -----END EC PRIVATE KEY-----";

    let cms = "-----BEGIN CMS-----\n\
        MIIBVgYLKoZIhvcNAQkQARegggFFMIIBQQIBADGB7aGB6gIBA6BRoU8wCQYHKoZI\n\
        zj0CAQNCAATBvPS7d+aWb3csGXVE8tEUEW4thIlGNFc3givH6FEVFphRE6Z3TVuO\n\
        zIx3xGOrZJ2YchpoNhLmQvGYiaLwsNNpMBUGBiuBBAELATALBglghkgBZQMEARkw\n\
        ezB5MF0wRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNV\n\
        BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZAIUa387gJugMF99WtCUflM7iLrh\n\
        8cQEGJfXKJUBrIfT4Ax+LN3FLIzlwKxQOta86jA6BgkqhkiG9w0BBwEwHgYJYIZI\n\
        AWUDBAEGMBEEDOQ55BMf6c72aytJpwIBEIANB7j+/PngW9mW2+3dbAQQVC1W6F9Z\n\
        C74ir4QqU0gcjA==\n\
        -----END CMS-----";
    let plaintext = b"Hello World\r\n";

    let priv_p256 = elliptic_curve::SecretKey::<NistP256>::from_sec1_pem(priv_key_pem).unwrap();

    let content_info  = ContentInfo::from_der(pem::parse(cms)?.contents()).unwrap();
    assert_eq! ( content_info.content_type, ID_CT_AUTH_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<AuthEnvelopedData>().unwrap();

    let mac = enveloped_data.mac.as_bytes().try_into().unwrap();

    assert_eq! ( enveloped_data.recip_infos.0.len(), 1);
    let Kari(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    assert_eq! ( recip.key_enc_alg.oid, DH_SINGLE_PASS_STD_DH_SHA_256_KDF_SCHEME  );
    assert_eq! ( recip.key_enc_alg.oid, DhSinglePassStdDhSha256KdfScheme::<NistP256, U24>::OID  );
    let key_enc_parameters = recip.key_enc_alg.parameters.as_ref().unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq! ( key_enc_parameters, AlgorithmIdentifier{oid: ID_AES_192_WRAP, parameters: None});

    // Handle originator fields
    let OriginatorIdentifierOrKey::OriginatorKey(orig) = &recip.originator else { panic!("Unhandled")};
    assert_eq! ( orig.algorithm, AlgorithmIdentifier{oid: ID_EC_PUBLIC_KEY, parameters: None});
    let encapped_key = Array::try_from(orig.public_key.raw_bytes()).unwrap();
    
    assert_eq! ( recip.recipient_enc_keys.len(), 1);
    let wrapped_cek = &recip.recipient_enc_keys.get(0).as_ref().unwrap().enc_key; // { Some(RecipientEncryptedKey { rid: _, enc_key: v}) => v, _ => panic!("Unhdnaled")};
           
    let ecc_shared_info = EccCmsSharedInfo{ 
        key_info: key_enc_parameters, //AlgorithmIdentifierOwned { oid: ID_AES_192_WRAP, parameters: None }, 
        entity_uinfo: recip.ukm.clone(), 
        supp_pub_info: OctetString::new(192u32.to_be_bytes()).unwrap() };
   
    let kdf2 = X963Kdf::new_with_salt(&ecc_shared_info.to_der().unwrap());
    let mut decapsulator = DhSinglePassStdDhSha256KdfScheme::from_private_key(priv_p256.clone());
    decapsulator.set_kdf(kdf2.clone());
    
    let shared_secret = decapsulator.try_decapsulate(&encapped_key).unwrap();
    let kek = KwAes192::new(&shared_secret);
    let cek = kek.unwrap_fixed_key(wrapped_cek.as_bytes().try_into().unwrap()).unwrap();
    
    // Encrypted content struct
    assert_eq! ( enveloped_data.auth_encrypted_content_info.content_enc_alg.oid, ID_AES_128_GCM);
    let gcm_params = enveloped_data.auth_encrypted_content_info.content_enc_alg.parameters.unwrap().decode_as::<GcmParams>().unwrap();
    assert_eq! ( gcm_params.aes_icv_len, 16); // Not sure what this length represents, its different to the nonce value
    let nonce = gcm_params.aes_nonce.as_bytes().try_into().unwrap();

    let ciphertext = enveloped_data.auth_encrypted_content_info.encrypted_content.unwrap();
    
    let mut buf = ciphertext.as_bytes().to_vec();
    let decryptor = Aes128Gcm::new(&cek);
    decryptor.decrypt_inout_detached(nonce, &[], buf.as_mut_slice().into(), &mac).unwrap();
    assert! ( buf == plaintext );

    // Using IES struct
    type IesCmsP256AesKw192AesGcm128 = IesWithKeyWrap::<DhSinglePassStdDhSha256KdfScheme<NistP256, U24>, Aes192, Aes128Gcm>;
    
    let mut decryptor4 = IesCmsP256AesKw192AesGcm128::from_key_decap(priv_p256);
    decryptor4.set_kdf(kdf2);

    let plaintext4 = decryptor4.open_detached(&encapped_key, wrapped_cek.as_bytes().try_into().unwrap(), ciphertext.as_bytes(), &mac, &gcm_params.aes_nonce.as_bytes().try_into().unwrap())?;

    assert! ( plaintext4 == plaintext);
    Ok(())
}






/// Sample script created from openssl using RSA 
/// 
/// openssl genrsa -out rsa-priv.pem 1024
/// openssl req -new -x509 -key rsa-priv.pem -out rsa-cert.pem -days 360
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip rsa-cert.pem -outform pem -aes192-wrap -aes256
/// 
#[test]
fn test_cms_rsa_pkcs15_dncrypt() -> Result<(), common::Error>
{
    let rsa_priv_pem = "-----BEGIN PRIVATE KEY-----\n\
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
    let ciphertext = "-----BEGIN CMS-----\n\
        MIIBTgYJKoZIhvcNAQcDoIIBPzCCATsCAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG\n\
        EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk\n\
        Z2l0cyBQdHkgTHRkAhRSyORjFCUux2W8OQKdMaxd64mroDANBgkqhkiG9w0BAQEF\n\
        AASBgFzQRdbLOfFBqmF4VlMSAYKpz6gHW/OWt+haUNmt07ieqtWeJDgIyGpoXWQt\n\
        Y/WhfitD2XWF3Ytn7T98QNdIQTqrVO6mTKgxnSWbs+4Po8S/rRLNtlJuv4KCzTYq\n\
        LMffBSv5xs2f9chxGgXS19Y9XkR+4p9xstpndVG3QeB2zd00MDwGCSqGSIb3DQEH\n\
        ATAdBglghkgBZQMEASoEEL6teOxOYo12clwesnWdXkaAEBowhoPLs/i0ji9BYALd\n\
        HMw=\n\
        -----END CMS-----";

    let rsa_priv = rsa::RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem)?;
    let cms_pem = pem::parse(ciphertext)?;
    let content_info = ContentInfo::from_der(cms_pem.contents()).unwrap();
    //let enveloped_data = EnvelopedData::from_der(&der::Encode::to_der(&content_info.content).unwrap()).unwrap();
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();
    let Ktri(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    let iv = enveloped_data.encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let ciphertext = enveloped_data.encrypted_content.encrypted_content.unwrap();

    assert_eq! ( enveloped_data.recip_infos.0.len(), 1 );
    assert_eq! ( recip.key_enc_alg, AlgorithmIdentifierOwned{ oid: RSA_ENCRYPTION, parameters: Some(Any::null()) });
    assert_eq! ( recip.key_enc_alg.oid, RsaPkcs15Kem::<U128, U32>::OID);
    assert_eq! ( enveloped_data.encrypted_content.content_enc_alg.oid, ID_AES_256_CBC);
    
    let decapsulator = RsaPkcs15Kem::<U128, U32>::from_private_key(rsa_priv.clone());
    let encapsulated_cek = Array::<u8,U128>::try_from(recip.enc_key.as_bytes()).unwrap();
    let cek = decapsulator.try_decapsulate(&encapsulated_cek).unwrap();
        
    let decryptor = cbc::Decryptor::<Aes256>::new(&cek, iv.as_bytes().try_into().unwrap());
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();
    assert! ( plaintext == b"Hello World\r\n" );

    // Using IES struct
    let mut decryptor4 = SimpleIes::<RsaPkcs15Kem<U128,U32>, A256CbcNoMac>::from_key_decap(rsa_priv);
    decryptor4.set_iv(iv.as_bytes().try_into().unwrap());
    let c0 = Array::try_from(recip.enc_key.as_bytes()).unwrap();
    let result4 = decryptor4.try_open_detached(&c0, ciphertext.as_bytes(), &[].into())?;
    assert! ( result4 == b"Hello World\r\n" );

    Ok(())
}


/// Sample script created from openssl using RSA 
/// 
/// openssl genrsa -out rsa-priv.pem 1024
/// openssl req -new -x509 -key rsa-priv.pem -out rsa-cert.pem -days 360
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip rsa-cert.pem -outform pem -aes192-wrap -aes256 -keyopt rsa_padding_mode:oaep
/// 
#[test]
fn test_cms_rsa_oaep_dncrypt() -> Result<(), common::Error>
{
   
    let rsa_priv_pem = "-----BEGIN PRIVATE KEY-----\n\
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
    let ciphertext = "-----BEGIN CMS-----\n\
        MIIBTgYJKoZIhvcNAQcDoIIBPzCCATsCAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG\n\
        EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk\n\
        Z2l0cyBQdHkgTHRkAhRSyORjFCUux2W8OQKdMaxd64mroDANBgkqhkiG9w0BAQcw\n\
        AASBgLK0mCf5eKfbWG01QpFIeobjUi09nh6/6hvgYJlG1WOahbLfhFrMLXXKmdNr\n\
        QOmd4MjxnBr69bTLmI4NAvx5j0meP6bqcQULZt/zoHZCpJwsOE/eTgxwCK+O3kBS\n\
        PdoBjf0tXuionTWKLtwMrTJIGVHN61rOxUQkJ1cUfTCO/gbQMDwGCSqGSIb3DQEH\n\
        ATAdBglghkgBZQMEASoEEC55WHDb5wzUAJQPzF0OQT+AEIHTGUHpodaUbBg4p22X\n\
        Nnc=\n\
        -----END CMS-----";
    let rsa_priv = rsa::RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem)?;
    let cms_pem = pem::parse(ciphertext)?;
    let content_info = ContentInfo::from_der(cms_pem.contents()).unwrap();
    assert_eq! (content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();

    // Parse recipient infos
    assert_eq! ( enveloped_data.recip_infos.0.len(), 1 );
    let Ktri(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    assert_eq! ( recip.version, CmsVersion::V0);
    let _rid = &recip.rid;
    //assert_eq! ( recip.key_enc_alg, AlgorithmIdentifierOwned{ oid: ID_RSAES_OAEP, parameters: Some(Any::encode_from(&pkcs1_new::RsaOaepParams::default()).unwrap()) });
    assert_eq! ( recip.key_enc_alg.oid, ID_RSAES_OAEP);
    assert_eq! ( recip.key_enc_alg.oid, RsaOaepKem::<U128,U32,Sha1,Sha1>::OID);
    assert_eq! ( recip.key_enc_alg.parameters.as_ref().unwrap().decode_as::<RsaOaepParams>().unwrap(), RsaOaepParams::default() );
    
    //assert_eq! ( recip.key_enc_alg, AlgorithmIdentifierOwned{ oid: ID_RSAES_OAEP, parameters: Some(Any::encode_from(&rsa::pkcs1::RsaOaepParams::default()).unwrap()) });
    let encapsulated_key = Array::<u8, U128>::try_from(recip.enc_key.as_bytes()).unwrap();
    
    // Parse encrypted content block
    let encrypted_content = enveloped_data.encrypted_content;
    assert_eq! ( encrypted_content.content_enc_alg.oid, ID_AES_256_CBC);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let ciphertext = encrypted_content.encrypted_content.unwrap();

    // Recover encryption key
    let decapsulator = RsaOaepKem::<U128,U32,Sha1,Sha1>::from_private_key(rsa_priv.clone());
    let cek = decapsulator.try_decapsulate(&encapsulated_key).unwrap();
    // Recover plaintext 
    let decryptor = cbc::Decryptor::<Aes256>::new(&cek, iv.as_bytes().try_into().unwrap());
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();
    assert! ( plaintext == b"Hello World\r\n" );

    // Using IES struct
    let mut decryptor4 = SimpleIes::<RsaOaepKem<U128,U32,Sha1,Sha1>, A256CbcNoMac>::from_key_decap(rsa_priv);
    decryptor4.set_iv(iv.as_bytes().try_into().unwrap());
    let c0 = Array::try_from(recip.enc_key.as_bytes()).unwrap();
    let result4 = decryptor4.try_open_detached(&c0, ciphertext.as_bytes(), &[].into())?;
    assert! ( result4 == b"Hello World\r\n" );

    Ok(())

}



/// Sample script created from openssl using RSA 
/// 
/// openssl genrsa -out rsa-priv.pem 1024
/// openssl req -new -x509 -key rsa-priv.pem -out rsa-cert.pem -days 360
///
/// echo "Hello World" > plaintext
/// openssl smime -encrypt -in plaintext -out ciphertext -outform pem rsa-cert.pem
/// 
#[test]
fn test_cms_rsa_pkcs7_decrypt() -> Result<(), common::Error>
{
    let rsa_priv_pem = "-----BEGIN PRIVATE KEY-----\n\
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
    let ciphertext = "-----BEGIN PKCS7-----\n\
        MIIBRQYJKoZIhvcNAQcDoIIBNjCCATICAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG\n\
        EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk\n\
        Z2l0cyBQdHkgTHRkAhRSyORjFCUux2W8OQKdMaxd64mroDANBgkqhkiG9w0BAQEF\n\
        AASBgLsj4JDniavFJfkxIiasfw1S0pQbRuoKoQWzHp9zIfQP0gamwM+/Ty0EtoUf\n\
        iEeQk1ISCsr+VLXc+l49lwqNUPQl1deIh7Zxz+XG6hJ1g736fzLO0ap8aM0YmRnc\n\
        UeuYBqi4nPYDzEb0msuHQHDB3dsn/xYX9A2ApZLz/fsCeuv1MDMGCSqGSIb3DQEH\n\
        ATAUBggqhkiG9w0DBwQI18vPlJzDh+mAEDEqUE0GZxAKpCT3MBVBjxQ=\n\
        -----END PKCS7-----";

    let rsa_priv = rsa::RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem)?;
    let cms_pem = pem::parse(ciphertext)?;
    let content_info = ContentInfo::from_der(cms_pem.contents()).unwrap();
    //let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(&content_info.content.to_der()?)?;
    assert_eq! ( content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();
    assert_eq! ( enveloped_data.version, CmsVersion::V0);
    assert_eq! ( enveloped_data.recip_infos.0.len(), 1 );

    // Parse recipient info
    let Ktri(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled")};
    assert_eq! ( recip.version, CmsVersion::V0);
    assert_eq! ( recip.key_enc_alg, AlgorithmIdentifierOwned{ oid: RSA_ENCRYPTION, parameters: Some(Any::null()) });
    assert_eq! ( recip.key_enc_alg.oid, RsaPkcs15Kem::<U128,U24>::OID);
    let encapsulated_key = Array::try_from(recip.enc_key.as_bytes()).unwrap();
    
    // Parse encrypted content
    let encrypted_content = enveloped_data.encrypted_content;
    assert_eq! ( encrypted_content.content_enc_alg.oid, DES_EDE_3_CBC);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let ciphertext = encrypted_content.encrypted_content.unwrap();
    
    // Recover key
    let decapsulator = <RsaPkcs15Kem::<U128,U24> as Kem>::DecapsulationKey::from(rsa_priv.clone());
    let cek = decapsulator.try_decapsulate(&encapsulated_key).unwrap();
    
    // Decrypt content
    let decryptor = cbc::Decryptor::<TdesEde3>::new(&cek, iv.as_bytes().try_into().unwrap());
    let plaintext = decryptor.decrypt_padded_vec::<Pkcs7>(ciphertext.as_bytes()).unwrap();
    assert! ( plaintext == b"Hello World\r\n" );

    // Using ies
    let mut decryptor4 = SimpleIes::<RsaPkcs15Kem::<U128,U24>, TdesCbcNoMac>::from_key_decap(rsa_priv);
    decryptor4.set_iv(iv.as_bytes().try_into().unwrap());
    let result4 = decryptor4.try_open_detached(&encapsulated_key, ciphertext.as_bytes(), &[].into())?;
    assert! ( result4 == b"Hello World\r\n" );

    Ok(())
}




/// Sample script created from openssl using RSA 
/// 
/// openssl genrsa -out rsa-priv.pem 1024
/// openssl req -new -x509 -key rsa-priv.pem -out rsa-cert.pem -days 360
///
/// echo "Hello World" > plaintext
/// openssl cms -encrypt -in plaintext -out ciphertext  -recip rsa-cert.pem -keyopt rsa_padding_mode:oaep -outform pem -aes192-wrap -aes-128-ofb
/// 
#[test]
fn test_cms_rsa_oaep_decrypt() -> Result<(), common::Error>
{
    let rsa_priv_pem = "-----BEGIN PRIVATE KEY-----\n\
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
    let ciphertext = "-----BEGIN CMS-----\n\
        MIIBSwYJKoZIhvcNAQcDoIIBPDCCATgCAQAxgfcwgfQCAQAwXTBFMQswCQYDVQQG\n\
        EwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lk\n\
        Z2l0cyBQdHkgTHRkAhRT5EVqSz/2b7fI38DA8unhp1TqQjANBgkqhkiG9w0BAQcw\n\
        AASBgGfh+ck1krO0TAhrvbqmZNhyYvowBe9Wfvsn2sUiDHhjBVTFBBOSp9dYY5aJ\n\
        sG0NiYS1d7DBtnBGCQaJBPj8dA2bxyeWaAEkxv9Lbkg2sVVIDaPcciKM1F55HXE4\n\
        B9SBornksr8rBvKNAi30aG7vr2t6yGZPbyblW6GB50NunQVcMDkGCSqGSIb3DQEH\n\
        ATAdBglghkgBZQMEAQMEEPobVuQltT/IJJNml98YueOADX9R8kebQ1HyHFLyKuA=\n\
        -----END CMS-----";

    let rsa_priv = rsa::RsaPrivateKey::from_pkcs8_pem(&rsa_priv_pem)?;
    let cms_pem = pem::parse(ciphertext)?;

    let content_info = ContentInfo::from_der(cms_pem.contents()).unwrap();
    assert_eq! ( content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();
    
    // Recover content encryption key
    assert! ( enveloped_data.recip_infos.0.len() == 1 );
    let Ktri(recip) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("unhandled match")};
    assert! ( recip.key_enc_alg == AlgorithmIdentifierOwned{ oid: ID_RSAES_OAEP, parameters: Some(Any::encode_from(&[0u8;0]).unwrap()) });
    assert_eq! ( recip.key_enc_alg.oid, RsaOaepKem::<U128,U16,Sha1,Sha1>::OID );

    let decapsulator = RsaOaepKem::<U128,U16,Sha1,Sha1>::from_private_key(rsa_priv.clone());
    let encapped_key = Array::<u8,U128>::try_from(recip.enc_key.as_bytes()).unwrap();
    let cek = decapsulator.try_decapsulate(&encapped_key).unwrap();

    // Recover plaintext
    let encrypted_content = &enveloped_data.encrypted_content;
    assert_eq! ( encrypted_content.content_enc_alg.oid, ID_AES_128_OFB_NEW ); //);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    let ciphertext = encrypted_content.encrypted_content.as_ref().unwrap();
    
    let mut decryptor = ofb::Ofb::<Aes128>::new_from_slices(&cek, &iv.as_bytes())?;
    let mut buf = ciphertext.as_bytes().to_vec();
    decryptor.apply_keystream (&mut buf);
    assert! ( buf == b"Hello World\r\n" );

    // Using IES
    let mut decryptor4 = SimpleIes::<RsaOaepKem::<U128,U16,Sha1,Sha1>, StreamNoMac<ofb::Ofb<Aes128>>>::from_key_decap(rsa_priv);
    decryptor4.set_iv(iv.as_bytes().try_into().unwrap());
    let result4 = decryptor4.try_open_detached(&encapped_key, ciphertext.as_bytes(), &[].into())?;
    assert! ( result4 == b"Hello World\r\n" );

    Ok(())
}





// KEMRecipientInfo ::= SEQUENCE {
//        version CMSVersion,  -- always set to 0
//        rid RecipientIdentifier,
//        kem KEMAlgorithmIdentifier,
//        kemct OCTET STRING,
//        kdf KeyDerivationAlgorithmIdentifier,
//        kekLength INTEGER (1..65535),
//        ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
//        wrap KeyEncryptionAlgorithmIdentifier,
//        encryptedKey EncryptedKey }
//#[cfg(all(feature = "rustcrypto"))]
// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
// struct KEMRecipientInfo {
//     pub version: CmsVersion,
//     pub rid: RecipientIdentifier,
//     pub kem: AlgorithmIdentifierOwned, //KemAlgorithmIdentifier,
//     pub kemct: OctetString,
//     pub kdf: AlgorithmIdentifierOwned, //KeyDerivationAlgorithmIdentifier
//     pub kek_length: u16,
//     #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional="true")]
//     pub ukm: Option<OctetString>, //UserKeyingMaterial,
//     pub wrap: AlgorithmIdentifierOwned, //KeyEncryptionAlgorithmIdentifier,
//     pub encrypted_key: EncryptedKey
// }



// #[cfg(all(feature = "rustcrypto"))]
// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
// struct MlKemPublicKey {
//     pub alg: AlgorithmIdentifierOwned,
//     pub pub_key: BitString,
// }


// #[derive(Choice, Debug)]
// pub enum Time {
//     #[asn1(type = "UTCTime", context_specific="0", tag_mode="IMPLICIT")]
//     UtcTime(UtcTime),

//     #[asn1(type = "GeneralizedTime")]
//     GeneralTime(GeneralizedTime),
// }
// #[cfg(all(feature = "rustcrypto"))]
// #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
// struct MlKemPrivateKey {
//     //pub alg: AlgorithmIdentifierOwned,
//     pub version: CmsVersion,
//     pub alg: AlgorithmIdentifierOwned,
//     //pub private_key: MlKeyPrivateKey,
//     //#[asn1(tag_mode="IMPLICIT")]
//     pub priv_key: OctetString,
//     //pub priv_key: MlKeyPrivateKey2,
// }

///
/// Sample from draft-ietf-lamps-cms-kyber-13, now RFC9936
/// 
#[test]
fn test_cms_ml_kem_512() -> Result<(), common::Error>
{
    let bob_public_pem = "-----BEGIN PUBLIC KEY-----\n\
        MIIDMjALBglghkgBZQMEBAEDggMhADmVgV5ZfRBDVc8pqlMzyTJRhp1bzb5IcST2\n\
        Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHmvG+QsOSb\n\
        aTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbWf/mqvJdQ\n\
        Pyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lAk0Frg7gS\n\
        Tmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8XSCVcuD8\n\
        dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoEZM5BqLtE\n\
        wtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRrevpsRZMl\n\
        JqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5JPSQpaxU\n\
        lfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6tnVUAAUH\n\
        gVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10zgGocjicy\n\
        r5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyekb7U7oR3l\n\
        y0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oXthQzzRr4\n\
        D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPMFgCQPmUp\n\
        NWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGmgx1bVMC3\n\
        kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9huqtxp6PT\n\
        UZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2NoPwS/eg\n\
        nMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3guBw7xZoG\n\
        WhttY7Js\n\
        -----END PUBLIC KEY-----";

    let bob_private_pem = "-----BEGIN PRIVATE KEY-----\n\
        MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ\n\
        GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\n\
        -----END PRIVATE KEY-----";

    // Bob's ML-KEM-512 public key has the following key identifier:
    let bob_key_id = hex!("599788C37AED400EE405D1B2A3366AB17D824A51");
    
    // Alice generates a shared secret and ciphertext using Bob's ML-KEM-512 public key:
    // Shared secret:
    let shared_secret = hex!("7DF12D412AE299A24FDE6D7C3BB8E3194C80AD3C733DCF2775E09FE8BEDB86D8");

    // Ciphertext:
    let encapped_key = hex!("
        3EA40FC6CA090E2C8AF76E2727AB38E0652D9515986FE186827FE84E596E421B
        85FD459CC78997372C9DE31D191B39C1D5A3EB6DDB56AADEDE765CC390FDBBC2
        F88CB175681D4201B81CCDFCB24FEF13AF2F5A1ABCF8D8AF384F02A010A6E919
        F1987A5E9B1C0E2D3F07F58A9FA539CE86CC149910A1692C0CA4CE0ECE4EEED2
        E6699CB976332452DE4A2EB5CA61F7B081330C34798EF712A24E59C33CEA1F1F
        9E6D4FBF3743A38467430011336F62D870792B866BEFCD1D1B365BED1952673D
        3A5B0C20B386B4EFD1CF63FD376BD47CCC46AC4DD8EC66B047C4C95ACFF1CFD0
        28A419B002FDA1B617CBA61D2E91CFE8FFFBCB8FFD4D5F6AD8B158C219E36DC5
        1405DC0C0B234979AC658E72BDDF1B6773B96B2AE3E4D07BE86048040C016743
        6FA839E7529B00CC9AB55A2F25DB63CC9F557594E691C11E553D4A3EBC760F5F
        19E5FE144838B4C7D1591DA9B5D467494FD9CAC52CC5504060399DBDB72298EB
        9A4C017B00786FDC7D9D7AA57ADBB8B61C34DE1E288B2AB728171DCE143CD169
        53F984C1AED559E56BAA0CE658D32CCE42F4407504CD7A579AD0EF9B77135EAA
        39B6F93A3A2E5997807F06361C83F4E67F8E3F9CF68316011514F5D85A181CEA
        D714CD4940E4EBAC01D66528DA32F89CEA0428E8EBCADCF8AA188C9F62E85B19
        57655B7FE2B8D7973B7A7226B66D93BF7B232F3DCF653C84B4ECF1A9920DB194
        9AD750B546A5552A20E54909719B8C0C07056FCB7E574AD2A32EC95001DDE844
        81BE77D039ED5BF74262ECF3981F1B00D3366A9C2E061C47E241A061C6249560
        D2B8446A480C38C28BA989D9F68ADC4BBAF2A20B47E4923128C72342D597FDA2
        59DE0B83C2056D6B77E799B319324AA50B1D659C2A56029B7453C5F3BA5243D9
        FA749D917C40D9D101E453BC8B10E42A7C089323C026F783E100B9FA6E701442
        4DA6FA3792BC957EE8219D016B773F28FEDCC962A485ABAFFEC023281971E29A
        A689839ECFD2619E92287CD230DB26A2507CC500EB1C7A5293B5FE917AE29BF1
        AD350124F8A311635214B411DB9F67D3B85BD715018537EA45B41F41B4C66051");

    // Alice encodes the CMSORIforKEMOtherInfo:
    let other_info = hex!("3010300B0609608648016503040105020110");
    // Alice derives the key-encryption key from the shared secret and
    // CMSORIforKEMOtherInfo using HKDF with SHA-256:
    let key = hex!("CF453A3E2BAE0A78701B8206C185A008");
    //  Alice randomly generates a 128-bit content-encryption key:
    let cek = hex!("C5153005588269A0A59F3C01943FDD56");
    //    Alice uses AES-128-KEYWRAP to encrypt the content-encryption key with
    //    the key-encryption key:
    let encrypted_cek = hex!("C050E4392F9C14DD0AC2220203F317D701F94F9DD92778F5");

    //    Alice encrypts the padded content using AES-128-GCM with the content-
    //    encryption key and encodes the AuthEnvelopedData (using
    //    KEMRecipientInfo) and ContentInfo, and then sends the result to Bob.
    //    The Base64-encoded result is:
    let cms = "-----BEGIN CMS-----\n\
        MIID4gYLKoZIhvcNAQkQARegggPRMIIDzQIBADGCA3ikggN0BgsqhkiG9w0BCRAN\n\
        AzCCA2MCAQCAFFmXiMN67UAO5AXRsqM2arF9gkpRMAsGCWCGSAFlAwQEAQSCAwA+\n\
        pA/GygkOLIr3bicnqzjgZS2VFZhv4YaCf+hOWW5CG4X9RZzHiZc3LJ3jHRkbOcHV\n\
        o+tt21aq3t52XMOQ/bvC+IyxdWgdQgG4HM38sk/vE68vWhq8+NivOE8CoBCm6Rnx\n\
        mHpemxwOLT8H9YqfpTnOhswUmRChaSwMpM4Ozk7u0uZpnLl2MyRS3koutcph97CB\n\
        Mww0eY73EqJOWcM86h8fnm1PvzdDo4RnQwARM29i2HB5K4Zr780dGzZb7RlSZz06\n\
        Wwwgs4a079HPY/03a9R8zEasTdjsZrBHxMlaz/HP0CikGbAC/aG2F8umHS6Rz+j/\n\
        +8uP/U1fatixWMIZ423FFAXcDAsjSXmsZY5yvd8bZ3O5ayrj5NB76GBIBAwBZ0Nv\n\
        qDnnUpsAzJq1Wi8l22PMn1V1lOaRwR5VPUo+vHYPXxnl/hRIOLTH0VkdqbXUZ0lP\n\
        2crFLMVQQGA5nb23IpjrmkwBewB4b9x9nXqletu4thw03h4oiyq3KBcdzhQ80WlT\n\
        +YTBrtVZ5WuqDOZY0yzOQvRAdQTNelea0O+bdxNeqjm2+To6LlmXgH8GNhyD9OZ/\n\
        jj+c9oMWARUU9dhaGBzq1xTNSUDk66wB1mUo2jL4nOoEKOjrytz4qhiMn2LoWxlX\n\
        ZVt/4rjXlzt6cia2bZO/eyMvPc9lPIS07PGpkg2xlJrXULVGpVUqIOVJCXGbjAwH\n\
        BW/LfldK0qMuyVAB3ehEgb530DntW/dCYuzzmB8bANM2apwuBhxH4kGgYcYklWDS\n\
        uERqSAw4woupidn2itxLuvKiC0fkkjEoxyNC1Zf9olneC4PCBW1rd+eZsxkySqUL\n\
        HWWcKlYCm3RTxfO6UkPZ+nSdkXxA2dEB5FO8ixDkKnwIkyPAJveD4QC5+m5wFEJN\n\
        pvo3kryVfughnQFrdz8o/tzJYqSFq6/+wCMoGXHimqaJg57P0mGekih80jDbJqJQ\n\
        fMUA6xx6UpO1/pF64pvxrTUBJPijEWNSFLQR259n07hb1xUBhTfqRbQfQbTGYFEw\n\
        DQYLKoZIhvcNAQkQAxwCARAwCwYJYIZIAWUDBAEFBBjAUOQ5L5wU3QrCIgID8xfX\n\
        AflPndknePUwOgYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBBjARBAxcpXRouBvwO42n\n\
        GGwCARCADZTIaJqZ0sOOGS+muggEEFzxeGxXx0ArVPyTwwpKRTM=\n\
        -----END CMS-----";

    let plaintext = b"Hello, world!";

    // Parse public key
    let recipient_public = pem::parse(bob_public_pem)?;
    let recipient_public = SubjectPublicKeyInfo::<Any, BitString>::from_der(recipient_public.contents()).unwrap();
    assert_eq!( recipient_public.algorithm, AlgorithmIdentifier{oid:ID_ALG_ML_KEM_512, parameters: None});
    assert_eq!( recipient_public.subject_public_key.as_bytes().unwrap().len(), 800);
    let recipient_public = ml_kem::array::Array::try_from(recipient_public.subject_public_key.as_bytes().unwrap()).unwrap();
    //let recipient_public = <ml_kem::kem::Kem<MlKem512Params> as KemCore>::EncapsulationKey::from_bytes(&recipient_public);
    let recipient_public = ml_kem_512::EncapsulationKey::new(&recipient_public).unwrap();

    // Parse private key
    let recipient_private = pem::parse(bob_private_pem)?;
    let recipient_private = PrivateKeyInfoRef::from_der(recipient_private.contents()).unwrap();
    assert_eq!(recipient_private.algorithm, AlgorithmIdentifier{oid:ID_ALG_ML_KEM_512, parameters: None});
    let recipient_private_choice = MlKemPrivateKeyChoice::from_der(recipient_private.private_key.as_bytes()).unwrap();
    let MlKemPrivateKeyChoice::Seed(recipient_private_seed) = recipient_private_choice else { panic!("bb")};
    //let (recipient_private, recipient_public2) = MlKem512::generate_deterministic(&recipient_private_seed.as_bytes()[..32].try_into().unwrap(), &recipient_private_seed.as_bytes()[32..].try_into().unwrap());
    let recipient_private = ml_kem_512::DecapsulationKey::from_seed(recipient_private_seed.as_bytes().try_into().unwrap());
    let recipient_public2 = recipient_private.encapsulation_key();

    assert_eq!( &recipient_public, recipient_public2);

    // Parse CMS structure
    let content_info = ContentInfo::from_der(pem::parse(cms)?.contents())?;
    assert_eq! ( content_info.content_type, ID_CT_AUTH_ENVELOPED_DATA);
    let auth_enveloped_data = content_info.content.decode_as::<AuthEnvelopedData>().unwrap();

    
    let RecipientInfo::Ori(recip) = auth_enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled case")};
    let kem_recip_info = recip.ori_value.decode_as::<KemRecipientInfo>().unwrap();

    assert_eq!( kem_recip_info.version, CmsVersion::V0);
    assert_eq!( kem_recip_info.rid, RecipientIdentifier::SubjectKeyIdentifier(x509_cert_new::ext::pkix::SubjectKeyIdentifier(OctetString::new(bob_key_id).unwrap())));
    assert_eq!( kem_recip_info.kem, AlgorithmIdentifier{oid: ID_ALG_ML_KEM_512, parameters: None});
    assert_eq!( kem_recip_info.kem.oid, MlKem512::OID);
    assert_eq!( kem_recip_info.kem_ct.as_bytes(), &encapped_key);
    assert_eq!( kem_recip_info.kdf, AlgorithmIdentifier{oid: ID_ALG_HKDF_WITH_SHA256, parameters: None});
    assert_eq!( kem_recip_info.kdf.oid, HkdfSha256::OID);
    assert_eq!( kem_recip_info.kek_length, 16);
    assert_eq!( kem_recip_info.ukm, None);
    assert_eq!( kem_recip_info.wrap, AlgorithmIdentifier{oid: ID_AES_128_WRAP, parameters: None});
    assert_eq!( kem_recip_info.encrypted_key.as_bytes(), encrypted_cek);

    let ori = CmsOriForKemOtherInfo{wrap: kem_recip_info.wrap, 
        kek_length: kem_recip_info.kek_length, ukm: kem_recip_info.ukm};
    assert_eq!( ori.to_der().unwrap(), other_info);

    
    // Using vanilla ML-KEM functions    
    // Recover KEK
    use ml_kem::kem::Decapsulate;
    let shared_secret_calc = recipient_private.decapsulate(&kem_recip_info.kem_ct.as_bytes().try_into().unwrap());
    assert_eq! ( shared_secret_calc, shared_secret);

    let kek = Hkdf::<Sha256>::derive_secret_other(&shared_secret, &other_info);
    assert_eq! (kek, key);
    // Recover CEK
    let kek2 = KwAes128::new(&kek);
    let mut cek2 = Array::<u8,U16>::default(); //[0u8; 16];
    kek2.unwrap_key(kem_recip_info.encrypted_key.as_bytes(), &mut cek2)?;
    assert_eq! ( cek2, cek);

    // Decrypt payload
    let auth_encrypted_content = auth_enveloped_data.auth_encrypted_content_info;
    assert_eq!( auth_encrypted_content.content_type, ID_DATA);
    assert_eq!( auth_encrypted_content.content_enc_alg.oid, ID_AES_128_GCM );

    let iv_params = auth_encrypted_content.content_enc_alg.parameters.unwrap().decode_as::<GcmParams>().unwrap();
    let ciphertext = auth_encrypted_content.encrypted_content.unwrap();

    let decryptor = Aes128Gcm::new(&cek2);
    let mut buf = ciphertext.as_bytes().to_vec();
    decryptor.decrypt_inout_detached(iv_params.aes_nonce.as_bytes().try_into().unwrap(), &[], 
        InOutBuf::from(buf.as_mut_slice()),  auth_enveloped_data.mac.as_bytes().try_into().unwrap()).unwrap();
    assert_eq!( buf, plaintext);
    
    // Repeat using Ies
    let (_, mut decryptor4) = IesWithKeyWrap::<MlKem512Hkdf256<U16>, Aes128, Aes128Gcm>::derive_from_seed(recipient_private_seed.as_bytes().try_into().unwrap()).unwrap();
    decryptor4.set_kdf(Hkdf::<Sha256>::new_with_add_info(&other_info));
    
    let encapsulated_key2 = Array::try_from(kem_recip_info.kem_ct.as_bytes()).unwrap();
    let plaintext4 = decryptor4.open_detached(&encapsulated_key2, 
        kem_recip_info.encrypted_key.as_bytes().try_into().unwrap(), ciphertext.as_bytes().as_ref(), 
        auth_enveloped_data.mac.as_bytes().try_into().unwrap(), &iv_params.aes_nonce.as_bytes().try_into().unwrap()).unwrap();
    assert_eq! ( plaintext4, plaintext);

    Ok(())
}




/// https://datatracker.ietf.org/doc/rfc9690/
#[test]
fn test_rfc_9690_d_1() 
{
    let bob_pub = "-----BEGIN PUBLIC KEY-----\n\
      MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA3ocW14cxncPJ47fnEjBZ\n\
      AyfC2lqapL3ET4jvV6C7gGeVrRQxWPDwl+cFYBBR2ej3j3/0ecDmu+XuVi2+s5JH\n\
      Keeza+itfuhsz3yifgeEpeK8T+SusHhn20/NBLhYKbh3kiAcCgQ56dpDrDvDcLqq\n\
      vS3jg/VO+OPnZbofoHOOevt8Q/roahJe1PlIyQ4udWB8zZezJ4mLLfbOA9YVaYXx\n\
      2AHHZJevo3nmRnlgJXo6mE00E/6qkhjDHKSMdl2WG6mO9TCDZc9qY3cAJDU6Ir0v\n\
      SH7qUl8/vN13y4UOFkn8hM4kmZ6bJqbZt5NbjHtY4uQ0VMW3RyESzhrO02mrp39a\n\
      uLNnH3EXdXaV1tk75H3qC7zJaeGWMJyQfOE3YfEGRKn8fxubji716D8UecAxAzFy\n\
      FL6m1JiOyV5acAiOpxN14qRYZdHnXOM9DqGIGpoeY1UuD4Mo05osOqOUpBJHA9fS\n\
      whSZG7VNf+vgNWTLNYSYLI04KiMdulnvU6ds+QPz+KKtAgMBAAE=\n\
      -----END PUBLIC KEY-----";

     //let bob_priv = "-----BEGIN RSA PRIVATE KEY-----\n\
    let bob_priv = "-----BEGIN PRIVATE KEY-----\n\
      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\n\
      -----END PRIVATE KEY-----";

    let random = hex!("9c126102a5c1c0354672a3c2f19fc9ddea988f815e1da812c7bd4f8eb082bdd1
      4f85a7f7c2f1af11d5333e0d6bcb375bf855f208da72ba27e6fb0655f2825aa6
      2b93b1f9bbd3491fed58f0380fa0de36430e3a144d569600bd362609be5b9481
      0875990b614e406fa6dff500043cbca95968faba61f795096a7fb3687a51078c
      4ca2cb663366b0bea0cd9cccac72a25f3f4ed03deb68b4453bba44b943f4367b
      67d6cd10c8ace53f545aac50968fc3c6ecc80f3224b64e37038504e2d2c0e2b2
      9d45e46c62826d96331360e4c17ea3ef89a9efc5fac99eda830e81450b6534dc
      0bdf042b8f3b706649c631fe51fc2445cc8d447203ec2f41f79cdfea16de1ce6
      abdfdc1e2ef2e5d5d8a65e645f397240ef5a26f5e4ff715de782e30ecf477293
      e89e13171405909a8e04dd31d21d0c57935fc1ceea8e1033e31e1bc8c56da0f3
      d79510f3f380ff58e5a61d361f2f18e99fbae5663172e8cd1f21deaddc5bbbea
      060d55f1842b93d1a9c888d0bf85d0af9947fe51acf940c7e7577eb79cabecb3");

    let ciphertext = hex!("c071fc273af8e7bdb152e06bf73310361074154a43abcf3c93c13499d2065344
      3eed9ef5d3c0685e4aa76a6854815bb97691ff9f8dac15eea7d74f452bf350a6
      46163d68288e978cbf7a73089ee52712f9a4f49e06ace7bbc85ab14d4e336c97
      c5728a2654138c7b26e8835c6b0a9fbed26495c4eadf745a2933be283f6a88b1
      6695fc06666873cfb6d36718ef3376cefc100c3941f3c494944078325807a559
      186b95ccabf3714cfaf79f83bd30537fdd9aed5a4cdcbd8bd0486faed73e9d48
      6b3087d6c806546b6e2671575c98461e441f65542bd95de26d0f53a64e7848d7
      31d9608d053e8d345546602d86236ffe3704c98ad59144f3089e5e6d527b5497
      ba103c79d62e80d0235410b06f71a7d9bd1c38000f910d6312ea2f20a3557535
      ad01b3093fb5f7ee507080d0f77d48c9c3b3796f6b7dd3786085fb895123f04c
      a1f1c1be22c747a8dface32370fb0d570783e27dbb7e74fca94ee39676fde3d8
      a9553d878224736e37e191dab953c7e228c07ad5ca3122421c14debd072a9ab6");

    let shared_secret = hex!("3cf82ec41b54ed4d37402bbd8f805a52");

    let cms_ori = hex!("3010300b0609608648016503040105020110");

    let enveloped_data = "MIICXAYJKoZIhvcNAQcDoIICTTCCAkkCAQMxggIEpIICAAYLKoZIhvcNAQkQDQMw\
      ggHvAgEAgBSe62fJuVp01E0vFjlmgOgBtcuknDAJBgcogYxxAgIEBIIBgMBx/Cc6\
      +Oe9sVLga/czEDYQdBVKQ6vPPJPBNJnSBlNEPu2e9dPAaF5Kp2poVIFbuXaR/5+N\
      rBXup9dPRSvzUKZGFj1oKI6XjL96cwie5ScS+aT0ngas57vIWrFNTjNsl8VyiiZU\
      E4x7JuiDXGsKn77SZJXE6t90Wikzvig/aoixZpX8BmZoc8+202cY7zN2zvwQDDlB\
      88SUlEB4MlgHpVkYa5XMq/NxTPr3n4O9MFN/3ZrtWkzcvYvQSG+u1z6dSGswh9bI\
      BlRrbiZxV1yYRh5EH2VUK9ld4m0PU6ZOeEjXMdlgjQU+jTRVRmAthiNv/jcEyYrV\
      kUTzCJ5ebVJ7VJe6EDx51i6A0CNUELBvcafZvRw4AA+RDWMS6i8go1V1Na0Bswk/\
      tffuUHCA0Pd9SMnDs3lva33TeGCF+4lRI/BMofHBviLHR6jfrOMjcPsNVweD4n27\
      fnT8qU7jlnb949ipVT2HgiRzbjfhkdq5U8fiKMB61coxIkIcFN69ByqatjAbBgor\
      gQUQhkgJLAECMA0GCWCGSAFlAwQCAQUAAgEQMAsGCWCGSAFlAwQBBQQYKHguXT15\
      SnYWuGP7z8cZt48S3gjPKG4JMDwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEEgM\
      yv66vvrO263eyviId4GAEMbKZdt73Xaw834vq2Jktm0=";

    let kek = hex!("e6dc9d62ff2b469bef604c617b018718");
    let cek = hex!("77f2a84640304be7bd42670a84a1258b");

    let bob_pub = rsa::RsaPublicKey::from_public_key_pem(bob_pub).unwrap();

    // Validate the randomness and ciphertext match using raw RSA functions
    let randomness2 = rsa::BoxedUint::from_be_slice_vartime(&random);
    let ciphertext2 = rsa::hazmat::rsa_encrypt(&bob_pub,&randomness2).unwrap();
    assert_eq!(ciphertext.as_slice(), &ciphertext2.to_be_bytes()[..]);

    let bob_prv = pem::parse(bob_priv).unwrap();
    let bob_prv = rsa::RsaPrivateKey::from_pkcs1_der(bob_prv.contents()).unwrap();
    assert_eq!(bob_prv.as_public_key(), &bob_pub);
    
    let enveloped_data = base64::engine::general_purpose::STANDARD.decode(enveloped_data).unwrap();

    let content_info = ContentInfo::from_der(&enveloped_data).unwrap();
    assert_eq!( content_info.content_type, ID_ENVELOPED_DATA);
    let enveloped_data = content_info.content.decode_as::<EnvelopedData>().unwrap();
    
    assert_eq!(enveloped_data.version, CmsVersion::V3);
    assert_eq!(enveloped_data.originator_info, None);
    assert_eq!(enveloped_data.unprotected_attrs, None);

    assert_eq!(enveloped_data.recip_infos.0.len(), 1);
    let RecipientInfo::Ori(recip_info) = enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("not an ori")};
    assert_eq!(recip_info.ori_type, ID_ORI_KEM); //1.2.840.113549.1.9.16.13.3
    let kem_recip_info = recip_info.ori_value.decode_as::<KemRecipientInfo>().unwrap();
    assert_eq!(kem_recip_info.version, CmsVersion::V0);
    assert_eq!(kem_recip_info.kek_length, 16);
    assert_eq!(kem_recip_info.kem, AlgorithmIdentifier{oid: ID_KEM_RSA, parameters: None });
    assert_eq!(kem_recip_info.kem.oid, RsaOrigKem::<U384, U16, X944Kdf3::<Sha256>>::OID);
    assert_eq!(kem_recip_info.kdf.oid, ID_KDF_KDF_3);
    let kdf_params = kem_recip_info.kdf.parameters.unwrap().decode_as::<AlgorithmIdentifierOwned>().unwrap();
    assert_eq!( kdf_params, AlgorithmIdentifier{oid: ID_SHA_256, parameters: Some(Any::null())});

    assert_eq!(kem_recip_info.wrap, AlgorithmIdentifier{oid: ID_AES_128_WRAP, parameters:None});
    assert_eq!(kem_recip_info.ukm, None);
    let encrypted_key = kem_recip_info.encrypted_key.as_bytes();
    let kem_ct = kem_recip_info.kem_ct.as_bytes();
    assert_eq!(kem_ct, ciphertext);

    // Recover CEK
    let ori = CmsOriForKemOtherInfo{wrap: kem_recip_info.wrap, kek_length: kem_recip_info.kek_length, ukm: kem_recip_info.ukm};
    assert_eq!( ori.to_der().unwrap(), cms_ori);    

    let decapsulator = RsaOrigKem::<U384, U16, X944Kdf3::<Sha256>>::from_private_key(bob_prv.clone());
    let k_calc2 = decapsulator.try_decapsulate(&Array::try_from(kem_ct).unwrap()).unwrap();
    let k_calc3 = ml_kem::kem::TryDecapsulate::try_decapsulate(&decapsulator, &Array::try_from(kem_ct).unwrap()).unwrap(); // use different traits
    assert_eq!(k_calc2.as_slice(), k_calc3.as_slice());

    assert_eq!(k_calc2, shared_secret);
    let kek2 = X944Kdf3::<Sha256>::derive_secret_other(&shared_secret, &cms_ori);
    assert_eq!(kek2, kek);

    // Repeat with double kdf version
    type KemRsaX944Kdf3Sha256X944Kdf3Sha256 = KemWithKdf::<KemWithKdf::<RsaOrigKem::<U384, U384, PassThroughKdf>, CombinerNoKeys, X944Kdf3::<Sha256>, U16>, CombinerNoKeys, X944Kdf3::<Sha256>, U16>;

    let kdf4 = X944Kdf3::<Sha256>::new_with_salt(&cms_ori);
    let mut decapsulator = KemRsaX944Kdf3Sha256X944Kdf3Sha256::from_private_key(bob_prv.clone());
    decapsulator.set_kdf(kdf4.clone());

    let kek3 = decapsulator.try_decapsulate(&Array::try_from(kem_ct).unwrap()).unwrap();
    assert_eq!(kek3, kek);

    let decryptor = KwAes128::new(&kek2);
    let cek2 = decryptor.unwrap_fixed_key::<U16>(&Array::try_from(encrypted_key).unwrap()).unwrap();

    assert_eq!(cek2, cek);

    // Decrypt payload
    let encrypted_content = enveloped_data.encrypted_content;
    assert_eq!(encrypted_content.content_type, ID_DATA);
    assert_eq!(encrypted_content.content_enc_alg.oid, ID_AES_128_CBC);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    assert_eq!(iv.as_bytes(), &hex!("480CCAFEBABEFACEDBADDECAF8887781"));
    
    let mut encrypted_field = encrypted_content.encrypted_content.as_ref().unwrap().clone().into_bytes();
    
    let decryptor2 = cbc::Decryptor::<Aes128>::new_from_slices(&cek2, iv.as_bytes()).unwrap();
    let plaintext = decryptor2.decrypt_padded::<Pkcs7>(&mut encrypted_field).unwrap();
    assert_eq!(plaintext, b"Hello, world!");

    // Using IES
    type IesKemRsaX944Kdf3Sha256X944Kdf3Sha256AesKwAes128Gcm = IesWithKeyWrap<KemRsaX944Kdf3Sha256X944Kdf3Sha256, Aes128, A128CbcNoMac>;

    let mut decryptor3 = IesKemRsaX944Kdf3Sha256X944Kdf3Sha256AesKwAes128Gcm::from_key_decap(bob_prv);
    decryptor3.set_kdf(kdf4);

    let plaintext2 = decryptor3.open_semi_detached(
        &kem_ct.try_into().unwrap(),
        &Array::try_from(encrypted_key).unwrap(),
        Payload{msg:&encrypted_content.encrypted_content.unwrap().as_bytes(), aad:&[]},
        iv.as_bytes().try_into().unwrap(),
    ).unwrap();

    assert_eq!(plaintext2, b"Hello, world!");
}







/// Test from Nexo Card Security Spec 4.0
/// 9.4.3.1 RSA Example
#[test]

fn test_rsa_kb ()
{
    let kb = "-----BEGIN KTKDH_2Pass PEM File-----\n\
        MIIEzAYJKoZIhvcNAQcCoIIEvTCCBLkCAQExDzANBglghkgBZQMEAgEFADCCAocG\n\
        CSqGSIb3DQEHA6CCAngwggJ0AgEAMYIBrjCCAaoCAQAwVDA8MQswCQYDVQQGEwJC\n\
        RTENMAsGA1UEChMEbmV4bzEeMBwGA1UEAxMVTmltYnVzMjAwMS1TTjAwMDAwODUx\n\
        AhQKmu4+t8wvqHNuvrSbnVuDsqngEjBLBgkqhkiG9w0BAQcwPqAPMA0GCWCGSAFl\n\
        AwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAog0wCwYJKoZIhvcN\n\
        AQEJBIIBACATn1nMKjQAyiEofB9j0/582KqvfuF76uglYMq68+VMA2UTtNHy6aCt\n\
        x1bFL2yMUoQ/m9Z7CHnAK1mKD37e6PtowzFGQylGMzroQ1Ceb6M7o8gqXZ9f2yPm\n\
        GC0OX9etqtLBX2UQ98SNSYMpx2LAAA2QbBrw2BcVxHd8DEwDdCSiVJ4qLwKLpAyu\n\
        vezTiIIe/ATFLX78xxr9vbz8Q4rWy0qj/nPkIM9fo6KQdJ1V8OuFHrGuBg81SNnb\n\
        1+3dzMtjlS6dlNp0JMNA7K543yetS9xJeKVnZtD1pZ5jvdcUissI42lKwdCg4P8P\n\
        h/41V4MpoLq3rUcKDAVvy/wdQPPj0sMwgbwGCSqGSIb3DQEHATAUBggqhkiG9w0D\n\
        BwQIonu0bRwwbgmAgZj/0EAX6bII1Wkph39TH3At6vdAKRYhcZbzW4lcdn829Ehl\n\
        AWJd8lGGlrl2aV4o8MkGL0jiTFOUAg5meZDzkPv5O6qkWgUh16nKTEimhstcjpQ0\n\
        fZ2Vpv0evwqia39hFQIr4iQc8TWEmlc88I4Z6hCv661ts7R/DPMtX+wetyhaC4dH\n\
        w0agWWOMs55S7FdGvL7ECIQlUdgPgTGCAhYwggISAgEBMFowQjELMAkGA1UEBhMC\n\
        QkUxDTALBgNVBAoTBG5leG8xJDAiBgNVBAMTG25leG8tS2V5SW5qZWN0aW9uU2Vy\n\
        dmVyLVRNMQIUCV0Roz+UTgA0ejlZZgPTGj6rbqkwDQYJYIZIAWUDBAIBBQCggY4w\n\
        GAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHAzAfBgkqhkiG9w0BBwExEgQQQjAwMTZL\n\
        MVREMDBOMDAwMDAgBgoqhkiG9w0BCRkDMRIEEFNnViDTEghQZ9aUMfrWrCEwLwYJ\n\
        KoZIhvcNAQkEMSIEIKuta5Wej8QlL+U3ao7X2sfhmUFKQdbFtwW0brNdwinuMA0G\n\
        CSqGSIb3DQEBCwUABIIBAAzBMaYR5ZZpdaCi7iCoL9TcxNlcTNV7yg3z3KbOy1Qi\n\
        iylSZcPcuNGKNrYZhwhZBLMCU1BLCPl7/zko5R6TAvu5HY7KOTz5D9tBgsoFVm55\n\
        Je9O7cMg6jAaEYrfEDUFD6Bdk/7Wkh4JsIOMfbzrHMLXWybUT9nO8WVE/65m/cfx\n\
        fI6LkTbAzQqzO0fRO6WNkDUiBReu/AnUMzG+DZvWdxnA4RABlYvnb1h9TZBI+Az3\n\
        OQpTR9y1ne83KZLOdF4csYWbx9CVx0MeQCgebq/iDrpiQagVohcUlxHLsV91W5dN\n\
        0FCrJnD+u3zmQRET2Upv2z3fE+7Dg29B2S3yxcgrUvg=\n\
        -----END KTKDH_2Pass PEM File-----";

let rsa_enc_mod = hex!("E0A258BA99AB65A891B3A643A022DA73C2A7E742EDF3676F6E5222A1D171
        2714AB63E4B864A897DC03F2F6DC479CE059CE03558735F4E9007B7F60D4
        6040D5F861545EAA3E78E8A74B52575EF6FA4C2DC2C61104409E572D9856
        DF15471DA5C27BDDC68C32C98F10ACE63AFDED242B8727A55CAD9C2BEDBC
        C50ABCB943943FE8E20ACC151253C161C71B0A972B45173F72642D9A1420
        EF208DF64FEDE0576C40FC182BEAAE4DA1D0FC2877866FB87AD6361781B1
        9821A1DE1362949843884B6B7E11F7E6337E31496771347A109EB31BB181
        BAA43330CD2018CAAF90E5A74E84796D19F36DF019682E6A0EFA2D82D1A9
        9A8D034A0F41D653FD76124A018FD6C1");
    let rsa_enc_pub_exp = hex!("010001");
    let rsa_enc_priv_exp = hex!("57612F6C9E9C1A7640FF05DCE66CC857215018D863213C8A0EFAEA37D1F5
        D702E64C7C4AF1F4D6E5A1AFA0313DB61B5B3394FE6F13210A85C2846111
        1BC3FCB79A7CAC3A4304DB53402C6E8A253E65E5A30F52CD39A99E35C13D
        8197904B4B10650876D45069313A8657247964069EDBFB230AF3097DD903
        860E502D2CC97D360A2C003EFD6DBD2598DA389D6FD4F7095EE3DD1AF0A7
        65DC54AC1DB7901109C88BB446008E152CED91C557AFC3CA4EDD075C91FA
        7498CB58D308373AC951327334321D15A300F38766BABE26EE7527D4FD50
        18584121C5EA570C813BAFE7A3AE9D594E57E9BB34D6708A2C9095A0EA05
        2075D6A71414FFAC6FD60037B7561AF1");

    let rsa_enc_priv = rsa::RsaPrivateKey::from_components(rsa::BoxedUint::from_be_slice(&rsa_enc_mod, 2048).unwrap(), rsa::BoxedUint::from_be_slice(&rsa_enc_pub_exp, 257).unwrap(), rsa::BoxedUint::from_be_slice(&rsa_enc_priv_exp,2048).unwrap(), [].to_vec()).unwrap();
    let rsa_enc_pub = rsa_enc_priv.as_public_key();

    assert_eq!( rsa_enc_pub.n_bytes().as_ref(), rsa_enc_mod);
    assert_eq!( rsa_enc_pub.e_bytes().as_ref(), rsa_enc_pub_exp);
        
    let content_info  = ContentInfo::from_der(pem::parse(kb).unwrap().contents()).unwrap();
    assert_eq!(content_info.content_type, ID_SIGNED_DATA);
    
    let signed_data = content_info.content.decode_as::<SignedData>().unwrap();
    assert_eq!( signed_data.version, CmsVersion::V1);
    assert_eq!( signed_data.crls, None);
    assert_eq!( signed_data.certificates, None);
    assert_eq!( signed_data.digest_algorithms, SetOfVec::try_from(vec![AlgorithmIdentifierOwned{oid: ID_SHA_256, parameters: Some(Any::null())}]).unwrap() );
    let signer_infos = signed_data.signer_infos;
    assert_eq!( signer_infos.0.len(), 1);
    let signer_info = signer_infos.0.get(0).unwrap();

    assert_eq!( signer_info.version, CmsVersion::V1);
    assert_eq!( signer_info.unsigned_attrs, None);
    assert_eq!( signer_info.digest_alg, AlgorithmIdentifierOwned{oid: ID_SHA_256, parameters: Some(Any::null())});

    assert_eq!( signed_data.encap_content_info.econtent_type, ID_ENVELOPED_DATA);
    let enveloped_data = signed_data.encap_content_info.econtent.unwrap().decode_as::<EnvelopedData>().unwrap();

    assert_eq!( enveloped_data.version, CmsVersion::V0);
    assert_eq!( enveloped_data.originator_info, None);
    let recip_infos = enveloped_data.recip_infos;
    assert_eq!( recip_infos.0.len(), 1);
    let recip_info = recip_infos.0.get(0).unwrap();
    
    let Ktri(ktri) = recip_info else { panic!( "Unhandled")};
    assert_eq!(ktri.version, CmsVersion::V0);
    assert_eq!(ktri.key_enc_alg.oid, ID_RSAES_OAEP);
    assert_eq!(ktri.key_enc_alg.oid, RsaOaepKem::<U256, U24, Sha256, Sha256>::OID);
    let rsa_oaep_params = ktri.key_enc_alg.parameters.as_ref().unwrap().decode_as::<RsaOaepParams>().unwrap();
    assert_eq!(rsa_oaep_params.hash, AlgorithmIdentifier::<AnyRef>{oid: ID_SHA_256, parameters: Some(Any::null().to_ref())} );
    assert_eq!(rsa_oaep_params.mask_gen.oid, ID_MGF_1);
    let mask_gen_parameters = rsa_oaep_params.mask_gen.parameters.unwrap();
    assert_eq!(mask_gen_parameters.oid, ID_SHA_256);
    assert_eq!(mask_gen_parameters.parameters, Some(Any::null().to_ref()));
    let _rid = &ktri.rid;

    // Encrypted symmetric key
    let encrypted_key = &ktri.enc_key;
    assert_eq!(encrypted_key.as_bytes().len(), 256);
    let decrypted_key = rsa_enc_priv.decrypt(rsa::Oaep::<Sha256>::new(), encrypted_key.as_bytes()).unwrap();
    
    let encrypted_content = enveloped_data.encrypted_content;
    //let content_enc_alg =  encrypted_content.content_enc_alg;
    assert_eq!(encrypted_content.content_enc_alg.oid, DES_EDE_3_CBC);
    let iv = encrypted_content.content_enc_alg.parameters.as_ref().unwrap().decode_as::<&OctetStringRef>().unwrap();
    assert_eq!(iv, OctetStringRef::new(&[162u8, 123, 180, 109, 28, 48, 110, 9]).unwrap());
    assert_eq!(encrypted_content.content_type, ID_DATA);

    let encrypted_content = encrypted_content.encrypted_content.as_ref().unwrap().as_bytes();

    let decryptor = cbc::Decryptor::<TdesEde3>::new_from_slices(&decrypted_key, iv.as_bytes()).unwrap();
    let decrypted_content = decryptor.decrypt_padded_vec::<Iso7816>(encrypted_content).unwrap();
    
    assert_eq! ( decrypted_content, hex!("308192020101305A3042310B3009060355040613024245310D300B060355040A13046E65786F312430220603550403131B6E65786F2D4B6579496E6A656374696F6E5365727665722D544D310214095D11A33F944E00347A39596603D31A3EAB6EA9041037233E890B0104E9BC943D0E45EAE5A7301F06092A864886F70D0107013112041042303031364B31544430304E30303030"));

    // Repeat using IES
    let mut decryptor4 = SimpleIes::<RsaOaepKem<U256, U24, Sha256, Sha256>, EncryptNoMac<cbc::Encryptor<TdesEde3>, cbc::Decryptor<TdesEde3>, Iso7816>>::from_key_decap(rsa_enc_priv);
    decryptor4.set_iv(iv.as_bytes().try_into().unwrap());
    let c0 = Array::try_from(encrypted_key.as_bytes()).unwrap();
    let result4 = decryptor4.try_open_detached(&c0, encrypted_content, &[].into()).unwrap();
    
    assert_eq! ( result4, hex!("308192020101305A3042310B3009060355040613024245310D300B060355040A13046E65786F312430220603550403131B6E65786F2D4B6579496E6A656374696F6E5365727665722D544D310214095D11A33F944E00347A39596603D31A3EAB6EA9041037233E890B0104E9BC943D0E45EAE5A7301F06092A864886F70D0107013112041042303031364B31544430304E30303030"));


}


//const ID_MLKEM768_ECDH_P256_SHA3_256:ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.6.59");

// https://datatracker.ietf.org/doc/draft-ietf-lamps-cms-composite-kem/
// ML-KEM 768, P256
#[test]
fn test_hybrid_cms_b_1() -> Result<(), common::Error>
{
    let pub_key = "-----BEGIN PUBLIC KEY-----\n\
        MIIE8jAKBggrBgEFBQcGOwOCBOIAjssyhemrdzqTE5MNKmCruyoBancRo6y8A5Aw\n\
        uDSZ2AwdyWZCWnG6R2sP0vlXCNglq7BvHQTF6BObo+tT+ZmJSnsy1YaSKuyf8yw3\n\
        vxyr1ScErsY0r2s1gfprFhYLUQNNoQd+YViNTAedvTBeQGJLgJOozEIFKiwHbvcu\n\
        ddc2qnVGqNW0SSjF5QoE/lcwgvpYpZosHRePTYhm87hCdQJldwB6PZmgxZqfyeh0\n\
        vXsB+KGw+XLJaOgb2vtl+Nmbm5cyUvOgHItyxQIadhO8iHEIubYzKdlOcDGiP1qE\n\
        lCiMNslC+TGcl4Ij2SBQgyfLGpw2jpd3xJxyqjFZeeGrgidfRdVRtUyqUbCGHsLH\n\
        ITFJz/h9vqe+S5N6vJmHMFCTHtu0CSiz5pK/RepjWKZiWhYdz1k9u8GWo4q3h8SH\n\
        MnQKoSJq3Fx84Kl/ghUNxXB//2w+a/ekHuUzK8QbyWIqm2RSHkOj91hApCMG0tMn\n\
        I0xoEqm/ewo3xZA5MJUZEdIkmoN+d5fLwVlUOHS0TWVrrCWAvttq4HySFMBU3vGd\n\
        qGQPv2ZLd+NgjzmRMwc3unQh4KIXBspNK+lJgyU57QaDWtVq/yoXjhw5YQlYmckb\n\
        NuIeTjpNDqfNxFSuziVQwZQ6VPm/63tjcxy9uMtxw5wTyqfAkyZVKdTLUdcMsJVF\n\
        8XE0r6xtCQrNsmWzqhK1kvOUQcITlZEonyN4uXdFweFwXImg/NSK6QUcjKi6iQeI\n\
        Gmiy2bKbUIgrIbhyUOZU1ad/vrF+dkBzrPei5BanHBLF5hYVoJcQ+hmg3cVsR1Ke\n\
        XaduFdh0UXPNPMiTrClLz/FMdfcbzbe2xdSXHqCsdIBKxGagT3p0H/uTW1WwheFr\n\
        DJKBDYBaZxVOwRqP16M7QIOTo8AqeXTOQMSxAdCAx7NR4SttZbQDrjwj1qCj5LQ9\n\
        0TW4vUmNsWkaTeQP0LC6f/J5vlEQeIu0vUuggkqmDdaKPwx35SOixjwEwiweXgi1\n\
        3bdn68py4/VVYPwXHZaDhakUurZcNEU91nwkrdG03DmbyBlIrwwIClgMwhmSbSGj\n\
        Mql2lCPPE/zBJAvL9lfDP3mpoEMB0iCZm6t2IfAN7NLOwFeBOUomqxcvs0OkdxFG\n\
        1Gk0hVEis4LHcje/1rBAX8i2Ige6H0AqY5e9X2OHHjVFNzoM8Mavo5trYEksanbG\n\
        aJmpADcX8wxjDPhq+VBethWo5Ik0aLW16qGY/jAX6ROrpeRobOiSYNnDLFWI38Mf\n\
        cZJuHbBajBe2gwQbTdadu0elr7fMuHd7OOB35vgH7qq0lgOg7LcB8rVgXBeHLsJp\n\
        AGS2XTYlKFRNieIo5NSRdkXNkIoHyFZWU9dNUwbKD0CYtxxlj3cKp4AFFHdzCTot\n\
        bFIfhoQQxIsZhbPOFCZKjtEQ+UVnjQN1y0E9uym1N7ZjW9OkjeCs0YaooyooNpu6\n\
        TOMKu3GjVsqmKvgxk3cIztUouTC2+BC0iYANMUxRbZIiqLGWTsa6rBulSqm5Hpu8\n\
        R/LBY0gljpYLFDQJiuYRNvOOIUYEO3ubd8fKY8swLGLNi/LoNwtb+HoJ8szpDsXh\n\
        TIalQ0MEsdePvv0LCZ+0N55b1MaFJZieRuCMVPkbeJGWGzb4WVohn4jrsslaNC6y\n\
        eZxiXOnPS7EDyzLv2PL/zhedCEbC4A==\n\
        -----END PUBLIC KEY-----";
    let pub_key_id = hex!("14F1D8FED21F6103676C752C97D0949537A96AB2");
    let shared_secret = hex!("9bd51d44ba390ff68176b763cee113007f112aac3c2ddbdde916e713762a389c");

    let ciphertext = hex!("54b75c945ff83194fbf312214749b114bf6838878b49403f5235be774ae6719d
        90531da9ab013a0f8a81dbd6510592f5fbcbe3b1bcf393793f517e758bbdd104
        67c1a72b14165233e386ea6b027e482824d33244cc7f810bf7d21cd28e007c84
        19087698be0dd7934653f35c8b0164c218dcbcbe28302a813e47a334c9565349
        0cf57602c798d63d393e9e6ebc219265aa6562632a618d4c3e4052b20c89f2f0
        4ea45554673d1be8911f83ca4a20ce86b59cf0a8c964e5b04707875d56011d48
        9291abf2370838dc608fe2e26e617d0ec2c2c643e51caf6716e64c2cc5a185c7
        2770ec4185487589156bb47e414180c6cedeacd8dad07ffa9091441fdaced553
        c482bd0c41d5b77649f0ed803d07d29682dc2c41d2047d18fddab96529b9f8a2
        f0ddd5e4b302fffd8ccbec03d9917ffa6b8d249117146c58fd89a135a96ece67
        0c58a559628a68012d4c9a43e5fffb427f0df30da745bb0e4eb334716bb82175
        10467b8b58e1be54b30c857522654cbb5787813cb1b2fb957a725f51612187b5
        8bb83353f8e56aa6af89c94edd656d92bf66913022fce8f85730617d8a166bbb
        24515559915cc472435950bce8c25219fef507a6527a6a3920c2deada7732902
        e2d2ae8c60bda518a65da66f93581b7e37042a10464675ab326f603be14e5b55
        25634adeb956512a84fdb809af2f37d20a9fd23f67eca7741b49d5b7d74f947a
        8b6dac68888b3e3802994c98cccb68c2a0e7927f15e5e7be1400983e22a4c9ef
        2babdf244525adde3b4d91e778e21e2bd32c5221f5433f28390128eabf3b181b
        85c2c1efd7fae946399bb8fe21de2aed0a3e72cab34d305509547df33a45d17d
        013a3ac08f0db69dbff0bae5a4b9c15ee8bdc4e2525b49e6865aeb752051935f
        8e2fb5daea912d118671102b8fb4675c3937b389a7c7068cb697b3798fffe9d6
        e64156493bb808d067a3eac418a7bf5819e25a740c8349914e5008340c381a07
        d870b14b9be9939d306bc702d46a58216df932d2bcb45a3f181bd84f4b9ba992
        f3a5f12a5db615ae0598a9c432cf5c0095187a849a93ca0d2d7deedb2db1ced5
        3c0d4ae5d2b37eb25e07992452e0188e2d72682f46f0167f0f6a680243eff2c4
        b5fcf0235852f99defa4d535a479176fa3a22587511581b3649fe410e302ec1b
        9061cb535c492ae57ac126cb49ea47de12a9097c5f8a869d84d4aae903f0bc6f
        53a60514cebe02fdc9a204a6be2a66567d589fcbaca36565a3e02d10b16920ea
        26b05c50be805d06ece3c9ee7db7eb207c33c1d4ac92ca294f1a0f8fac839fea
        0389fae43384a2daa7a4c1f5e92d622f8eb37ac0c55eb9df8d9713de03a0ef8b
        2d9306c8530f607d898ba88adb6ad982becd3b05cac32b7dfe767c826e5e8bdf
        40120f1a49e84cd11c4c09b07c27591a6032b372a7bd468b09ece07ee6eca6e9
        4559f14843dd9a97931e0c06d105aa2237e67a3c128d33ab61dc47986fdafb79
        7e60cb44453b4dfbcf7afdfe02f686c720fd65d5381827be62f3322acbc37213
        0443d6690e3ae3b17f263f9345998ca26317f757b86d0ad41531b114f5d57fa8
        2e5023e5176227d087f765e1421cef31be9c315866838017bb2aa58955bf52ce
        6e");
    let cms_ori = hex!("3010300b060960864801650304012d020120");
    let kek = hex!("0555324e4703e672404e2272c555438bd7d04feac1321e05ebae6c0a2336d529");
    let cek = hex!("3424cef0cbc2b67f58351abd1e87b3507a11c90adef7e1cdab8d20b0331b8105");

    let cms = "-----BEGIN CMS-----\n\
        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\n\
        l6KLp6sQ\n\
        -----END CMS-----";

    let private_key = "-----BEGIN PRIVATE KEY-----\n\
        MIGEAgEAMAoGCCsGAQUFBwY7BHOImiTrgVkiRNnS3EmMdxHUrh+EHeflRSSQaMrG\n\
        7NAvf0DDSVt58hvzJz/RuCOE4/8REOs/DZVr5gWO2jOyldClMDECAQEEIM/ctKyh\n\
        CrQyBNhBbpwS5ZkEO1mklf14j5NRtwj3obB+oAoGCCqGSM49AwEH\n\
        -----END PRIVATE KEY-----";

    let plaintext = b"Hello, world!";

    let private_key = pem::parse(private_key).unwrap();
    let private_key2 = PrivateKeyInfoRef::from_der(private_key.contents()).unwrap();
    assert_eq!( private_key2.version(), rsa::pkcs8::Version::V1);
    assert_eq!( private_key2.algorithm, AlgorithmIdentifier{oid:ID_MLKEM768_ECDH_P256_SHA3_256, parameters: None} );
    assert_eq!( private_key2.public_key, None);
    assert_eq!( private_key2.private_key.as_bytes().len(), 115);
    
    let (ml_kem_private_key, ec_private_key) = private_key2.private_key.as_bytes().split_at(64);
    let ml_key_decapsulator = <MlKem768 as Kem>::DecapsulationKey::new(ml_kem_private_key.try_into().unwrap());
    let ec_private_key = p256::SecretKey::from_sec1_der(ec_private_key).unwrap();
    let ec_key_decapsulator = <<EcdhKem::<NistP256, EcUncompressedEncoder<NistP256>> as Kem>::DecapsulationKey as TryKeyInit>::new_from_slice(&ec_private_key.to_bytes() ).unwrap();
    let decapsulator = <HybridKemMlKem768P256Sha3_256 as Kem>::DecapsulationKey::from_decapsulators(ml_key_decapsulator, ec_key_decapsulator);
    

    let public_key2 = SubjectPublicKeyInfo::<Any,BitString>::from_der(pem::parse(pub_key).unwrap().contents()).unwrap();
    assert_eq!( public_key2.algorithm, AlgorithmIdentifier{oid:ID_MLKEM768_ECDH_P256_SHA3_256, parameters: None} );
    assert_eq!( public_key2.subject_public_key.as_bytes().unwrap().len(), 1249);

    
    //let encapsulator = HybridKemMlKem768P256Sha3_256::from_bytes_encap(public_key2.subject_public_key.as_bytes().unwrap().try_into().unwrap());
    let encapsulator = HybridKemMlKem768P256Sha3_256::try_from_bytes_encap(public_key2.subject_public_key.as_bytes().unwrap().try_into().unwrap()).unwrap();
    
    assert!(encapsulator.to_bytes() == decapsulator.encapsulation_key().to_bytes());
    let shared_secret2 = decapsulator.try_decapsulate(&ciphertext.try_into().unwrap()).unwrap();

    assert_eq! ( shared_secret2, shared_secret);
    
    let kek2: Array<u8, U32> = Hkdf::<Sha256>::derive_secret_other(&shared_secret, &cms_ori);
    assert_eq!( &kek2, &kek );
   
    // Decode CMS
    let content_info = ContentInfo::from_der(pem::parse(cms)?.contents()).unwrap();
    assert_eq! ( content_info.content_type, ID_CT_AUTH_ENVELOPED_DATA);
    
    // Decode Auth EnvelopedData
    let auth_enveloped_data = content_info.content.decode_as::<AuthEnvelopedData>().unwrap();
    assert_eq!( auth_enveloped_data.mac.as_bytes().len(), 16);
    
    // Decode RecipientInfo
    let RecipientInfo::Ori(recip) = auth_enveloped_data.recip_infos.0.get(0).unwrap() else { panic!("Unhandled case")};
    assert_eq!(recip.ori_type, ID_ORI_KEM);
    let kem_recip_info = recip.ori_value.decode_as::<KemRecipientInfo>().unwrap();
    
    assert_eq!( kem_recip_info.version, CmsVersion::V0);
    assert_eq!( kem_recip_info.rid, RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(OctetString::new(pub_key_id).unwrap())));
    assert_eq!( kem_recip_info.kem, AlgorithmIdentifier{oid: ID_MLKEM768_ECDH_P256_SHA3_256, parameters: None});
    assert_eq!( kem_recip_info.kem.oid, HybridKemMlKem768P256Sha3_256::OID);
    assert_eq!( kem_recip_info.kdf, AlgorithmIdentifier{oid: ID_ALG_HKDF_WITH_SHA256, parameters: None});
    assert_eq!( kem_recip_info.kem_ct.as_ref().len(), 1153); 
    assert_eq!( kem_recip_info.kek_length, 32);
    assert_eq!( kem_recip_info.ukm, None);
    assert_eq!( kem_recip_info.wrap, AlgorithmIdentifier{oid: ID_AES_256_WRAP, parameters: None});
    assert_eq!( kem_recip_info.encrypted_key.as_ref().len(), 40); // Wrapped 16 byte key
    
    let ori = CmsOriForKemOtherInfo{ wrap: kem_recip_info.wrap, kek_length: kem_recip_info.kek_length, ukm: kem_recip_info.ukm };
    assert_eq! ( ori.to_der().unwrap(), cms_ori );

    // Decapsulate to get kek
    let shared_secret_calc = decapsulator.try_decapsulate(&kem_recip_info.kem_ct.as_bytes().try_into().unwrap()).unwrap();
    assert_eq! ( shared_secret_calc, shared_secret);

    let kek3 = Hkdf::<Sha256>::derive_secret_other(&shared_secret, &cms_ori);
    assert_eq!(kek3, kek);

    // Unwrap cek
    let kek2 = KwAes256::new(&kek3);
    let mut cek2 = Array::<u8,U32>::default(); //[0u8; 16];
    kek2.unwrap_key(kem_recip_info.encrypted_key.as_bytes(), &mut cek2)?;
    assert_eq! ( cek2, cek);

    // Decrypt content
    let auth_encrypted_content = auth_enveloped_data.auth_encrypted_content_info;
    assert_eq!( auth_encrypted_content.content_type, ID_DATA);
    assert_eq!( auth_encrypted_content.content_enc_alg.oid, ID_AES_256_GCM );

    let iv_params = auth_encrypted_content.content_enc_alg.parameters.unwrap().decode_as::<GcmParams>().unwrap();
    let ciphertext = auth_encrypted_content.encrypted_content.as_ref().unwrap().as_bytes();

    let decryptor = Aes256Gcm::new(&cek2);
    let mut buf = ciphertext.to_vec();
    buf.extend_from_slice(auth_enveloped_data.mac.as_bytes());
    decryptor.decrypt_in_place(iv_params.aes_nonce.as_bytes().try_into().unwrap(), &[], &mut buf).unwrap();

    assert_eq!( buf, plaintext);
    
    // Now test the IES API with the same keys and ciphertext
    type HybridKemWithKdf = KemWithKdf<HybridKemMlKem768P256Sha3_256, CombinerNoKeys, Hkdf::<Sha256>, U32>;

    let kdf2 = Hkdf::<Sha256>::new_with_add_info(&cms_ori);
    let decapsulator2 = <HybridKemWithKdf as Kem>::DecapsulationKey::from_decapsulator_and_kdf(decapsulator, kdf2);
    let decryptor4 = IesWithKeyWrap::<HybridKemWithKdf, Aes256, Aes256Gcm>::from_decapsulator(decapsulator2);
       
    let plaintext4 = decryptor4.open_detached(
            kem_recip_info.kem_ct.as_bytes().try_into().unwrap(), 
            kem_recip_info.encrypted_key.as_bytes().try_into().unwrap(), 
            ciphertext, 
            auth_enveloped_data.mac.as_bytes().try_into().unwrap(), 
            &iv_params.aes_nonce.as_bytes().try_into().unwrap()
        ).unwrap();

    assert_eq! ( plaintext4, plaintext);

    // Rewrap to confirm encapsulation and decapsulation works
    let kdf3 = Hkdf::<Sha256>::new_with_add_info(&cms_ori);
    let encapsulator2 = <HybridKemWithKdf as Kem>::EncapsulationKey::from_encapsulator_and_kdf(encapsulator, kdf3);
    let encryptor = IesWithKeyWrap::<HybridKemWithKdf, Aes256, Aes256Gcm>::from_encapsulator(encapsulator2);

    let (ek5, wk5, ciphertext6, tag6) = encryptor.seal_detached(&cek.into(), plaintext.as_slice(), &iv_params.aes_nonce.as_bytes().try_into().unwrap()).unwrap();

    let plaintext5 = decryptor4.open_detached(&ek5, &wk5, ciphertext6.as_slice(), &tag6, &iv_params.aes_nonce.as_bytes().try_into().unwrap()).unwrap();
    assert_eq! ( plaintext5, plaintext);
    
    Ok(())
}

