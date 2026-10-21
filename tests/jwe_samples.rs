use aead::{Payload, KeyInit, AeadInOut}; //AeadInPlace;
use aead::consts::{U16, U32, U256};

use aes_gcm::Aes256Gcm;
use aes_kw::KwAes256;
//use elliptic_curve::point::AffineCoordinates;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ies::Ies;
use ies::ies_types::{EciesJweP256A128CbcHs256, EciesP384A256KwJweA128CbcHs256};
use ies::{ies_types::{RsaesOaepJweA256Gcm,RsaesPkcs15IesJweA128CbcHS256}, rfc7518::A128CbcHS256};
use kdfs::hybrid_array::Array;
use kem::{TryDecapsulate};
use kems::EncapsulateDeterministic;
use kems::{KemExtensions, SetKdf};
use kems::kem_with_kdf::{JwaKdf};
use kems::jwe::{JweKemP256Sha256, JweKemP384Sha256};
use kems::rsakem::{RsaPkcs15Kem, RsaOaepKem};

//use ml_kem::kem::{Decapsulate};
use rsa::{RsaPrivateKey, RsaPublicKey, BoxedUint};
use serde_json::Value;
use sha1::Sha1;

mod common;


#[test]
fn test_rfc_7518_appendix_c_ec_es (){
    //     Appendix C.  Example ECDH-ES Key Agreement Computation
    //    This example uses ECDH-ES Key Agreement and the Concat KDF to derive
    //    the CEK in the manner described in Section 4.6.  In this example, the
    //    ECDH-ES Direct Key Agreement mode ("alg" value "ECDH-ES") is used to
    //    produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
    //    value "A128GCM").
    //    In this example, a producer Alice is encrypting content to a consumer
    //    Bob.  The producer (Alice) generates an ephemeral key for the key
    //    agreement computation.  Alice’s ephemeral key (in JWK format) used
    //    for the key agreement computation in this example (including the
    //    private part) is:
    let alice_priv_jwk = r#"
            {"kty":"EC",
            "crv":"P-256",
            "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
           }"#;
    let alice_priv_byte_array= BASE64_URL_SAFE_NO_PAD.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo").unwrap();
    //   The consumer’s (Bob’s) key (in JWK format) used for the key agreement
    //   computation in this example (including the private part) is:
    let bob_jwk= r#"{"kty":"EC",
            "crv":"P-256",
            "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
           }"#;

    //    Header Parameter values used in this example are as follows.  The
    //    "apu" (agreement PartyUInfo) Header Parameter value is the base64url
    //    encoding of the UTF-8 string "Alice" and the "apv" (agreement
    //    PartyVInfo) Header Parameter value is the base64url encoding of the
    //    UTF-8 string "Bob".  The "epk" (ephemeral public key) Header
    //    Parameter is used to communicate the producer’s (Alice’s) ephemeral
    //    public key value to the consumer (Bob).
    let epk2 = r#"{"alg":"ECDH-ES",
       "enc":"A128GCM",
       "apu":"QWxpY2U",
       "apv":"Qm9i",
       "epk":{"kty":"EC",
         "crv":"P-256",
         "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
         "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
        }
     }"#;
    //let eph_x = BASE64_URL_SAFE_NO_PAD.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0").unwrap();
    //let eph_y = BASE64_URL_SAFE_NO_PAD.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps").unwrap();
    // The resulting Concat KDF [NIST.800-56A] parameter values are:
    // Z
    // This is set to the ECDH-ES key agreement output.  (This value is
    // often not directly exposed by libraries, due to NIST security
    // requirements, and only serves as an input to a KDF.)  In this
    // example, Z is following the octet sequence (using JSON array
    // notation):
    // [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
    // 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
    // 140, 254, 144, 196].
    // keydatalen
    //    This value is 128 - the number of bits in the desired output key
    //    (because "A128GCM" uses a 128-bit key).
    // AlgorithmID
    //    This is set to the octets representing the 32-bit big-endian value
    //    7 - [0, 0, 0, 7] - the number of octets in the AlgorithmID content
    //    "A128GCM", followed, by the octets representing the ASCII string
    //    "A128GCM" - [65, 49, 50, 56, 71, 67, 77].
    // PartyUInfo
    //    This is set to the octets representing the 32-bit big-endian value
    //    5 - [0, 0, 0, 5] - the number of octets in the PartyUInfo content
    //    "Alice", followed, by the octets representing the UTF-8 string
    //    "Alice" - [65, 108, 105, 99, 101].
    // PartyVInfo
    //    This is set to the octets representing the 32-bit big-endian value
    //    3 - [0, 0, 0, 3] - the number of octets in the PartyUInfo content
    //    "Bob", followed, by the octets representing the UTF-8 string "Bob"
    //    - [66, 111, 98].
    // SuppPubInfo
    //    This is set to the octets representing the 32-bit big-endian value
    //    128 - [0, 0, 0, 128] - the keydatalen value.
    // SuppPrivInfo
    //    This is set to the empty octet sequence.
    // Concatenating the parameters AlgorithmID through SuppPubInfo results
    // in an OtherInfo value of:
    // [0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105,
    // 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128]
    // Concatenating the round number 1 ([0, 0, 0, 1]), Z, and the OtherInfo
    // value results in the Concat KDF round 1 hash input of:
    // [0, 0, 0, 1,
    // 158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38,
    // 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140,
    // 254, 144, 196,
    // 0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65, 108, 105, 99,
    // 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128]
    // The resulting derived key, which is the first 128 bits of the round 1
    // hash output is:
    let derived_key: [u8; 16] = [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26];
    // The base64url-encoded representation of this derived key is:
    //  VqqN6vgjbSBcIijNcacQGg

    // Encapsulate as per the sender, need the private key from alice to use as the ephemeral secret
    //let alice_priv_key = JwkEcKey::from_str(alice_priv_jwk).unwrap();
    let alice_json: Value = serde_json::from_str(alice_priv_jwk).unwrap();
    let alice_d = &alice_json["d"];
    let alice_eph_bytes = BASE64_URL_SAFE_NO_PAD.decode(alice_d.as_str().unwrap()).unwrap();
    assert! (alice_eph_bytes.as_ref() == alice_priv_byte_array);

    let bob_jwk: Value = serde_json::from_str(bob_jwk).unwrap();
    let bob_x= BASE64_URL_SAFE_NO_PAD.decode(bob_jwk["x"].as_str().unwrap()).unwrap();
    let bob_y= BASE64_URL_SAFE_NO_PAD.decode(bob_jwk["y"].as_str().unwrap()).unwrap();
    let bob_d= BASE64_URL_SAFE_NO_PAD.decode(bob_jwk["d"].as_str().unwrap()).unwrap();
    
    let epkx: Value = serde_json::from_str(epk2).unwrap();
    let enc = epkx["enc"].as_str().unwrap().as_bytes();
    let apu = BASE64_URL_SAFE_NO_PAD.decode(&epkx["apu"].as_str().unwrap()).unwrap();
    let apv = BASE64_URL_SAFE_NO_PAD.decode(epkx["apv"].as_str().unwrap()).unwrap();
    let _epx = BASE64_URL_SAFE_NO_PAD.decode(epkx["epk"]["x"].as_str().unwrap()).unwrap();
    
    // Encapsulate 
    let jwa_kdf_send =  JwaKdf::new(enc, &apu, &apv);
    let mut encapsulator = JweKemP256Sha256::<U16>::try_from_slice_encap(&[bob_x, bob_y].concat()).unwrap();
    encapsulator.set_kdf(jwa_kdf_send);
    let (c0_send, k_send) = encapsulator.encapsulate_deterministic(&alice_eph_bytes);
    assert_eq! ( k_send, derived_key );
    
    // Decapsulate at the receiver
    let jwa_kdf_recv = JwaKdf::new(enc, &apu, &apv);
    let mut decapsulator = JweKemP256Sha256::<U16>::try_from_slice_decap(&bob_d).unwrap();
    decapsulator.set_kdf(jwa_kdf_recv);

    let k_recv = decapsulator.try_decapsulate(&c0_send).unwrap();
    assert! ( k_recv == derived_key);
}





///
/// Example from RFC 7520, includes a plaintext to be encrypted
/// 
#[test]
fn test_rfc_7520_5_5_ecies () {
    let recip_jwk = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
        "y": "HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
        "d": "r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
      }"#;
      // Had to remove the kid and use fields because JwkEcKey wouldn't import them..
      //"kid": "meriadoc.brandybuck@buckland.example",
        // "use": "enc",
        
    let iv_base64 = "yc9N8v5sYyv3iGQT926IUg";
    let ephem_jwk = r#"{
        "kty": "EC",
        "crv": "P-256",
        "x": "mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
        "y": "8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
        "d": "AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM"
      }"#;
    let cek_base64 = "hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc";

    let jwe_protected_header = "{\
        \"alg\":\"ECDH-ES\",\
        \"kid\":\"meriadoc.brandybuck@buckland.example\",\
        \"epk\":{\
          \"kty\":\"EC\",\
          \"crv\":\"P-256\",\
          \"x\":\"mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA\",\
          \"y\":\"8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs\"\
        },\
        \"enc\":\"A128CBC-HS256\"\
      }";
    let jwe_protected_header_base64 = "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidW\
        NrbGFuZC5leGFtcGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYi\
        LCJ4IjoibVBVS1RfYkFXR0hJaGcwVHBqanFWc1AxclhXUXVfdndWT0hIdE5rZF\
        lvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlmR1RUMElqQnBGdzJTUzM0\
        RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ";

    let plaintext = "You can trust us to stick with you through thick and \
        thin\u{2013}to the bitter end. And you can trust us to \
        keep any secret of yours\u{2013}closer than you keep it \
        yourself. But you cannot trust us to let you face trouble \
        alone, and go off without a word. We are your friends, Frodo.";

    let expected_ciphertext = "BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9\
        IPIOSA9Bml4m7iDFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_e\
        vAPUmwlO-ZG45Mnq4uhM1fm_D9rBtWolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-\
        IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URUhArM79BY8soZU0lzwI\
        -sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65KqVw7\
        MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ61\
        95_JGG2m9Csg";

    let expected_tag = "WCCkNa-x4BeB9hIDIfFuhg";

    let recip_json: Value = serde_json::from_str(recip_jwk).unwrap();
    let recip_d = BASE64_URL_SAFE_NO_PAD.decode(&recip_json["d"].as_str().unwrap()).unwrap();
    let recip_x = BASE64_URL_SAFE_NO_PAD.decode(&recip_json["x"].as_str().unwrap()).unwrap();
    let recip_y = BASE64_URL_SAFE_NO_PAD.decode(&recip_json["y"].as_str().unwrap()).unwrap();
    
    let eph_json: Value = serde_json::from_str(ephem_jwk).unwrap();
    let eph_bytes = BASE64_URL_SAFE_NO_PAD.decode(&eph_json["d"].as_str().unwrap()).unwrap();

    let jwe_protected_header2: Value = serde_json::from_str(jwe_protected_header).unwrap();
    let enc2 = jwe_protected_header2["enc"].as_str().unwrap();
    
    //let enc = enc.as_str().unwrap().as_bytes();
    let epk_x = BASE64_URL_SAFE_NO_PAD.decode(jwe_protected_header2["epk"]["x"].as_str().unwrap().as_bytes()).unwrap();
    let epk_y = BASE64_URL_SAFE_NO_PAD.decode(jwe_protected_header2["epk"]["y"].as_str().unwrap().as_bytes()).unwrap();

    let mut encapsulator = JweKemP256Sha256::try_from_slice_encap(&[recip_x.as_slice(), recip_y.as_slice()].concat()).unwrap();
    encapsulator.set_kdf(JwaKdf::new(enc2.as_bytes(), b"", b""));

    let (c0_send, k_send ) = encapsulator.encapsulate_deterministic(&eph_bytes);
    assert_eq!( k_send.as_slice(), &BASE64_URL_SAFE_NO_PAD.decode(cek_base64).unwrap() );
    assert_eq!( c0_send.as_slice(), &[epk_x.as_slice(), epk_y.as_slice()].concat());

    assert! ( jwe_protected_header.as_bytes() == BASE64_URL_SAFE_NO_PAD.decode(jwe_protected_header_base64).unwrap());
    let iv = Array::try_from(BASE64_URL_SAFE_NO_PAD.decode(iv_base64).unwrap().as_slice()).unwrap();
    let res = A128CbcHS256::new(&k_send);
    
    let (ctx1, tag1) = res.encrypt_detached(&iv, Payload{msg: plaintext.as_bytes(), 
            aad: jwe_protected_header_base64.as_bytes() }).unwrap();

    assert! ( ctx1 == BASE64_URL_SAFE_NO_PAD.decode(expected_ciphertext).unwrap());
    assert! ( tag1.as_ref() == BASE64_URL_SAFE_NO_PAD.decode(expected_tag).unwrap());
    let rx = res.decrypt_detached(&iv, Payload{msg: &ctx1, aad: jwe_protected_header_base64.as_bytes()}, &tag1).unwrap();
    assert! ( rx == plaintext.as_bytes());

    let enc = "A128CBC-HS256"; //enc2.to_string();
    
    // Repeat using Ecies struct
    let mut hybrid_encryptor = EciesJweP256A128CbcHs256::try_from_slice_encap(&[recip_x.as_slice(), recip_y.as_slice()].concat()).unwrap();
    hybrid_encryptor.set_kdf ( JwaKdf::new(enc.as_bytes(), b"", b""));
    hybrid_encryptor.set_iv ( iv );
    let (c0_2, ctx2, tag2) = hybrid_encryptor.seal_detached_deterministic(
        &eph_bytes, Payload{msg: plaintext.as_bytes(), aad: jwe_protected_header_base64.as_bytes()}).unwrap();

    assert!( ctx2 == BASE64_URL_SAFE_NO_PAD.decode(expected_ciphertext).unwrap());
    assert!( tag2.as_ref() == BASE64_URL_SAFE_NO_PAD.decode(expected_tag).unwrap());

    // Decrypt using Ecies 
    let mut hybrid_decryptor = EciesJweP256A128CbcHs256::try_from_slice_decap(&recip_d).unwrap();
    hybrid_decryptor.set_kdf(JwaKdf::new(b"A128CBC-HS256", b"", b""));
    hybrid_decryptor.set_iv(iv);
    let result_dec_payload = hybrid_decryptor.try_open_detached( &c0_2, Payload{msg: &ctx2, aad: jwe_protected_header_base64.as_bytes()}, &tag1 ).unwrap();

    assert! ( result_dec_payload == plaintext.as_bytes());
}

/// Example from RFC 7520, includes a plaintext to be encrypted
/// 
/// 
/// 

#[test]
fn test_rfc_7520_5_13_ecies_and_rsa () {
    let cek_base64 = "zXayeJ4gvm8NJr3IUInyokTUO-LbQNKEhe_zWlYbdpQ";
    
    let rsa_private_jwk = r#"{
        "kty": "RSA",
        "kid": "frodo.baggins@hobbiton.example",
        "use": "enc",
        "n": "maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT
            HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx
            6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U
            NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c
            R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy
            pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA
            VotGlvMQ",
        "e": "AQAB",
        "d": "Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy
            bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO
            5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6
            Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP
            1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN
            miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v
            pzj85bQQ",
        "p": "2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE
            oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH
            7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ
            2VFmU",
        "q": "te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V
            F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb
            9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8
            d6Et0",
        "dp": "UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH
            QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV
            RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf
            lo0rYU",
        "dq": "iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb
            pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A
            CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14
            TkXlHE",
        "qi": "kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ
            lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7
            Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx
            2bQ_mM"
      }"#;

    let rsa_encrypted_key_base64 = "dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zjwj4w6Y5G4XJQsNNIBiqyvUUA\
        OcpL7S7-cFe7Pio7gV_Q06WmCSa-vhW6me4bWrBf7cHwEQJdXihidAYWVajJIa\
        KMXMvFRMV6iDlRr076DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-w\
        qjw0-b-S1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbeYS\
        rRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n5trGuExtp_-d\
        bHcGlihqc_wGgho9fLMK8JOArYLcMDNQ";

    let _rsa_protected_header = r#"{"alg":"RSA1_5","kid": "frodo.baggins@hobbiton.example"}"#;

    let recip_ec_private_key_jwk = r#"{
        "kty": "EC",
        "crv": "P-384",
        "x": "YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQL
            pe2FpxBmu2",
        "y": "A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-
            SkgaFL1ETP",
        "d": "iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0Idn
            YK2xDlZh-j"
        }"#;
          // removed "kid": "peregrin.took@tuckborough.example",
          // "use": "enc",
      
    let ec_ephem_private_key = r#"{
        "kty": "EC",
        "crv": "P-384",
        "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2Dt
            MRb25Ma2CX",
        "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw9
            1fzZ84pbfm",
        "d": "1DKHfTv-PiifVw2VBHM_ZiVcwOMxkOyANS_lQHJcrDxVY3jhVCvZPw
            MxJKIE793C"
      }"#;

    let ec_protected_header = r#"{
     "alg": "ECDH-ES+A256KW",
     "kid": "peregrin.took@tuckborough.example",
     "epk": {
       "kty": "EC",
       "crv": "P-384",
       "x": "Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2
           DtMRb25Ma2CX",
       "y": "VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMb
           w91fzZ84pbfm"
     }
   }"#;
   let ec_encrypted_cek = "ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHixJuw_elY4gSSId_w";

    let symmetric_protected_header = r#"{"enc":"A128CBC-HS256"}"#;
    let symmetric_protected_header_base64 = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";

    let iv_base64 = "VgEIHY20EnzUtZFl2RpB1g";
    let ciphertext_base64 = "ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK04SjdxQeSw2L9mu3a\
        _k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM9tBURMFqLByJ8vOYQX0oJW4\
        VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSaP6ga7-siYxStR7_G07Thd1jh-zGT0\
        wxM5g-VRORtq0K6AXpLlwEqRp7pkt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZu\
        kLpCbzhzMDLLw2-8I14FQrgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXM\
        Y9YQjorZ_P_JYG3ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2\
        ofDQdLChtazE";

   let authentication_tag_base64 = "BESYyFN7T09KY7i8zKs5_g";
    let plaintext = "You can trust us to stick with you through thick and thin–to the bitter end. And you can trust us to keep any secret of yours–closer than \
        you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.".as_bytes();

    // RSA - confirm CEK can be decrypted
    let key_json : Value = serde_json::from_str(&rsa_private_jwk.replace("\n","").replace(" ","")).unwrap();
    //let n = key_json["n"].as_str().unwrap();

    let ciphertext = BASE64_URL_SAFE_NO_PAD.decode(ciphertext_base64).unwrap();
    let iv = BASE64_URL_SAFE_NO_PAD.decode(iv_base64).unwrap();
    let symmetric_protected_header2 = BASE64_URL_SAFE_NO_PAD.decode(symmetric_protected_header_base64).unwrap();
    assert_eq!(symmetric_protected_header2.as_slice(), symmetric_protected_header.as_bytes());
    let tag = BASE64_URL_SAFE_NO_PAD.decode(authentication_tag_base64).unwrap();
    let cek = BASE64_URL_SAFE_NO_PAD.decode(cek_base64).unwrap();
    let rsa_encrypted_key = BASE64_URL_SAFE_NO_PAD.decode(rsa_encrypted_key_base64).unwrap();
    
    let p = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["p"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let q = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["q"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let e = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["e"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let rsa_private = RsaPrivateKey::from_p_q(p, q, e).unwrap();
    let rsa_public = RsaPublicKey::from(rsa_private.clone());

    let decap = RsaPkcs15Kem::<U256, U32>::from_private_key(rsa_private.clone());
    let c0 = Array::try_from(rsa_encrypted_key.as_slice()).unwrap();
    let cek_calc = decap.try_decapsulate(&c0).unwrap();
    assert! ( cek_calc.as_slice() == &cek);

    // Decrypt completely using RSA
    let mut decryptor2 = RsaesPkcs15IesJweA128CbcHS256::from_key_decap(rsa_private);
    decryptor2.set_iv(iv.as_slice().try_into().unwrap());
    let plaintext2 = decryptor2.try_open_detached(&c0, Payload{msg: &ciphertext, aad: symmetric_protected_header_base64.as_bytes()}, &tag.as_slice().try_into().unwrap()).unwrap();
    assert_eq!( plaintext, plaintext2.as_slice());

    // Encryptor doesn't result in the same C0 and encrypted secret, but can check that it decodes properly.
    let mut encryptor2 = RsaesPkcs15IesJweA128CbcHS256::from_key_encap(rsa_public);
    encryptor2.set_iv(iv.as_slice().try_into().unwrap());
    let (encapped_key, ciphertext2, tag2) = encryptor2.seal_detached(plaintext).unwrap();
    let plaintext22 = decryptor2.try_open_detached(&encapped_key, ciphertext2.as_slice(), &tag2).unwrap();
    assert_eq!(plaintext22.as_slice(), plaintext);

    // EC - confirm CEK can be decrypted
    let recip_jwk_json = recip_ec_private_key_jwk.replace("\n","").replace(" ","");
    
    let ec_key_json : Value = serde_json::from_str(&recip_jwk_json).unwrap();
    let recip_d = &BASE64_URL_SAFE_NO_PAD.decode(ec_key_json["d"].as_str().unwrap()).unwrap();
    let recip_x = &BASE64_URL_SAFE_NO_PAD.decode(ec_key_json["x"].as_str().unwrap()).unwrap();
    let recip_y = &BASE64_URL_SAFE_NO_PAD.decode(ec_key_json["y"].as_str().unwrap()).unwrap();
    let recip_xy = Array::try_from(&[recip_x.as_slice(), recip_y.as_slice()].concat()).unwrap(); //clone();

    let ec_ephem_json : Value = serde_json::from_str(&ec_ephem_private_key.replace("\n", "").replace(" ","")).unwrap();
    let ephem_d = &BASE64_URL_SAFE_NO_PAD.decode(ec_ephem_json["d"].as_str().unwrap()).unwrap();
    let ephem_x = &BASE64_URL_SAFE_NO_PAD.decode(ec_ephem_json["x"].as_str().unwrap()).unwrap();
    let ephem_y = &BASE64_URL_SAFE_NO_PAD.decode(ec_ephem_json["y"].as_str().unwrap()).unwrap();
    let c0_ec = Array::try_from(&[/*[4u8].as_slice(),*/ ephem_x.as_slice(), ephem_y.as_slice()].concat()).unwrap();

    let ec_protected_header: Value = serde_json::from_str(&ec_protected_header.replace("\n","").replace(" ","")).unwrap();
    let alg = ec_protected_header["alg"].as_str().unwrap().as_bytes();
    assert_eq!( alg, b"ECDH-ES+A256KW");
    let alg = b"ECDH-ES+A256KW"; // something we did made set_kdf require a 'static reference..

    let mut ec_decapsulator = JweKemP384Sha256::try_from_slice_decap(&BASE64_URL_SAFE_NO_PAD.decode(ec_key_json["d"].as_str().unwrap()).unwrap()).unwrap();
    ec_decapsulator.set_kdf(JwaKdf::new(alg, b"", b""));
  
    let kek_calc_ec = ec_decapsulator.try_decapsulate(&c0_ec).unwrap();

    let kek = KwAes256::new(&kek_calc_ec);
    let encrypted_cek = BASE64_URL_SAFE_NO_PAD.decode(ec_encrypted_cek).unwrap();
    let decrypted_cek = kek.unwrap_fixed_key::<U32>(&encrypted_cek.as_slice().try_into().unwrap()).unwrap();
    
    assert! ( decrypted_cek.as_slice() == cek.as_slice());

    ///////////////////////
    // Decrypt payload using cek
    let decryptor = A128CbcHS256::new(&decrypted_cek);
    let plaintext_calc = decryptor.decrypt_detached(&iv.as_slice().try_into().unwrap(), Payload{msg: &ciphertext, aad: symmetric_protected_header_base64.as_bytes()}, &Array::try_from(tag.as_slice()).unwrap()).unwrap();
    
    // Re-encrypt 
    let mut ec_encryptor = JweKemP384Sha256::try_from_slice_encap(&recip_xy).unwrap();
    ec_encryptor.set_kdf(JwaKdf::new(alg, b"", b""));
    
    let (c0_ec_2, k_ec_2): (Array<u8, _>, _) = ec_encryptor.encapsulate_deterministic(&ephem_d);
    assert! ( c0_ec_2 == c0_ec);
    assert! ( k_ec_2 == kek_calc_ec);
   
    let kek = KwAes256::new(&kek_calc_ec);
    let encrypted_cek_2 = kek.wrap_fixed_key(&Array::<u8,U32>::try_from(cek.as_slice()).unwrap());
    assert_eq!(encrypted_cek_2.as_slice(), encrypted_cek);

    let encryptor = A128CbcHS256::new(&cek_calc.0.into());
    let (ciphertext_calc, tag_calc) = encryptor.encrypt_detached(&Array::try_from(iv.as_slice()).unwrap(), Payload{msg: &plaintext_calc, aad: symmetric_protected_header_base64.as_bytes()}).unwrap();
    assert! ( ciphertext_calc == ciphertext);
    assert! ( tag_calc.as_slice() == tag.as_slice());


    // Decrypt using ECIES structures
    let mut decryptor = EciesP384A256KwJweA128CbcHs256::try_from_slice_decap(&recip_d).unwrap();
    decryptor.set_kdf(JwaKdf::new(alg, b"", b""));
    
    let plaintext = decryptor.open_detached(&c0_ec, &encrypted_cek.as_slice().try_into().unwrap(), Payload{msg: &ciphertext, aad: symmetric_protected_header_base64.as_bytes()}, &tag.as_slice().try_into().unwrap(), &iv.as_slice().try_into().unwrap()).unwrap();
    assert_eq!( plaintext, plaintext_calc);

    // Encrypt using ECIES 
    let mut encryptor = EciesP384A256KwJweA128CbcHs256::try_from_bytes_encap(&recip_xy).unwrap();
    encryptor.set_kdf(JwaKdf::new(alg, b"", b""));

    let (ek, ecek, ciphertext4) = encryptor.seal_detached_encapsulated_key_deterministic(&ephem_d, cek.as_slice().try_into().unwrap(), Payload{msg: &plaintext, aad: symmetric_protected_header_base64.as_bytes()}, iv.as_slice().try_into().unwrap()).unwrap();

    assert_eq! ( ek, c0_ec);
    assert_eq! ( ecek.as_slice(), encrypted_cek.as_slice());
    //assert_eq! ( tag4, tag_calc);
    assert_eq! ( ciphertext4, [ciphertext_calc.as_slice(), &tag_calc].concat());

}


#[test]
fn test_rfc_7516_a_1_rsaies () {
    let rsa_key = r#"{
    "kty": "RSA",
    "n": "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
         cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
         psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
         sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
         tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
         YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
    "e": "AQAB",
    "d": "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N
         WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9
         3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk
         qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl
         t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd
         VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
    "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-
         SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf
         fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
    "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm
         UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX
         IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
    "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL
         hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827
         rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
    "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj
         ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB
         UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
    "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7
         AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3
         eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
   }"#;

    let plaintext = [84u8, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
        111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
        101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
        101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
        110, 97, 116, 105, 111, 110, 46];

    let protected_header = r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#;
    let protected_header_base64 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";

    let cek = [177u8, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
        212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
        234, 64, 252];

    let encrypted_cek = [56u8, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
        22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
        82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
        145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
        74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
        13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
        173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
        89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
        243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
        41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
        215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
        63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
        193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
        206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
        104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
        89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
        172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
        117, 114, 135, 206];

    let _encryted_cek_base64 = "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
        ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
        Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
        mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
        1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
        6UklfCpIMfIjf7iGdXKHzg";

    let iv = [227u8, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
    let _iv_base64 = "48V1_ALb6US04U3b";

    let aad = [101u8, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81];

    let ciphertext = [229u8, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
        233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
        104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
        123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
        160, 109, 64, 63, 192];

    let tag =  [92u8, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145];
    let _tag_base64 = "XFBoMYUZodetZdvTiFvSkQ";

    let _ciphertext_base64 = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji
        SdiwkIr3ajwQzaBtQD_A";

    
    let key_json : Value = serde_json::from_str(&rsa_key.replace("\n","").replace(" ","")).unwrap();
    
    let p = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["p"].as_str().unwrap()).unwrap(),1024).unwrap();
    let q = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["q"].as_str().unwrap()).unwrap(),1024).unwrap();
    let e = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["e"].as_str().unwrap()).unwrap(),1024).unwrap();
    let rsa_private = RsaPrivateKey::from_p_q(p, q, e).unwrap();
    
    assert!( protected_header.as_bytes() == &BASE64_URL_SAFE_NO_PAD.decode(protected_header_base64).unwrap());

    // Start with decryption of the CEK
    let decap = RsaOaepKem::<U256,U32,Sha1,Sha1>::from_private_key(rsa_private.clone());
    let c0 = Array::try_from(encrypted_cek.as_slice()).unwrap();
    
    let cek_calc = decap.try_decapsulate(&c0).unwrap();

    assert! ( cek_calc.as_slice() == cek);

    // Confirm we can use the CEK to decrypt the payload
    let decryptor = Aes256Gcm::new(&cek_calc.0.into());
    
    let mut buffer = ciphertext.to_vec();
    buffer.extend_from_slice(&tag);
    decryptor.decrypt_in_place(&iv.into(), &aad, &mut buffer ).unwrap();
    
    assert! ( buffer == plaintext);
    
    // Repeat the decryption using integrated decryption
    let mut decryptor = RsaesOaepJweA256Gcm::from_key_decap(rsa_private.clone());
    decryptor.set_iv(iv.into());
    
    let pt1 = decryptor.try_open_detached(&c0, Payload{msg: &ciphertext, aad: &aad}, &tag.into()).unwrap();
    assert! ( pt1 == &plaintext);

    let mut encryptor = RsaesOaepJweA256Gcm::from_key_encap(rsa_private.to_public_key());
    encryptor.set_iv(iv.into());
    let (c0_2, ct_2,tag) = encryptor.seal_detached(Payload{msg:&plaintext, aad:&aad}).unwrap();
    // Rsa OAEP uses random masking which can't be specified, best we can do is validate is that it decrypts
    let pt2 = decryptor.try_open_detached(&c0_2, Payload{msg: &ct_2, aad: &aad}, &tag).unwrap();

    assert! ( pt2 == &plaintext);

}

#[test]
#[allow(non_snake_case, unused)]
fn test_rfc_7516_a_2_rsaies () {
    
    // let plaintext = [76u8, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
    //     112, 114, 111, 115, 112, 101, 114, 46];
    let plaintext = b"Live long and prosper.";

    let protected_header = r#"{"alg":"RSA1_5","enc":"A128CBC-HS256"}"#;
    let protected_header_base64 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
    let cek = [4u8, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
        44, 207];

    let rsa_key = r#"{"kty":"RSA",
      "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl
           UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre
           cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_
           7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI
           Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU
           7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
      "e":"AQAB",
      "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq
           1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry
           nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_
           0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj
           -VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj
           T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
      "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68
           ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEP
           krdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
      "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-y
           BhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN
           -3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
      "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuv
           ngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcra
           Hawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
      "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff
           7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_
           odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
      "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlC
           tUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZ
           B9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
     }"#;
     let encrypted_cek = [80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151,
        176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181,
        156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,
        116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,
        226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,
        212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,
        215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,
        66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,
        54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,
        250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,
        21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102,
        166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222,
        150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241,
        124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242,
        16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244,
        248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167,
        101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169,
        146, 114, 165, 204, 71, 136, 41, 252];

   let encrypted_cek_base64 = "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm
        1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc
        HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF
        NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8
        rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv
        -B3oWh2TbqmScqXMR4gp_A";

    let iv = [3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101];
    //let iv_base64 = "AxY8DCtDaGlsbGljb3RoZQ";

    let aad = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
        74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
        50, 73, 110, 48];

    let ciphertext = [40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
        112, 56, 102];
    //let ciphertext_base64 = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";

    let tag = [246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191];
    //let tag_base64 = "9hH0vgRfYgPnAHOd8stkvw";

    
    
    let key_json : Value = serde_json::from_str(&rsa_key.replace("\n","").replace(" ","")).unwrap();
    //let n = key_json["n"].as_str().unwrap();

    let p = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["p"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let q = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["q"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let e = BoxedUint::from_be_slice(&BASE64_URL_SAFE_NO_PAD.decode(key_json["e"].as_str().unwrap()).unwrap(), 1024).unwrap();
    let rsa_private = RsaPrivateKey::from_p_q(p, q, e).unwrap();


    /// Start with decryption of the cek
    let decap = RsaPkcs15Kem::<U256,U32>::from_private_key(rsa_private.clone());
    let c0 = Array::try_from(encrypted_cek.as_slice()).unwrap();
    let cek_calc = decap.try_decapsulate(&c0).unwrap();

    assert! ( cek_calc.as_slice() == cek);

    // Use the cek to decrypt the payload
    let decryptor = A128CbcHS256::new(&cek_calc.0.into());
    let pt1 = decryptor.decrypt_detached(&iv.into(), Payload{msg: &ciphertext, aad: &aad}, &tag.into() ).unwrap();
    
    assert! ( pt1 == plaintext);
    
    // using integrated encryption
    let mut decryptor = RsaesPkcs15IesJweA128CbcHS256::from_key_decap(rsa_private.clone());
    decryptor.set_iv(iv.into());
    let pt2 = decryptor.try_open_detached(&c0, Payload{msg: &ciphertext, aad: &aad}, &tag.into()).unwrap();

    assert! ( pt2 == plaintext);
    
    let mut encryptor = RsaesPkcs15IesJweA128CbcHS256::from_key_encap(rsa_private.to_public_key());
    encryptor.set_iv(iv.into());
    let (c0_2, ct_2,tag) = encryptor.seal_detached(Payload{msg:plaintext.as_slice(), aad:&aad}).unwrap();

    let pt3 = decryptor.try_open_detached(&c0_2, Payload{msg: &ct_2, aad: &aad}, &tag).unwrap();

    assert! ( &pt3 == plaintext);


}



