use aead::{Aead, KeyInit, Payload,AeadInOut};
use aes::{Aes256,Aes128};
use aes_kw::{AesKw, KwAes128};
use digest::consts::*;
use hex_literal::hex;
use kdfs::Label;
use kdfs::{Kdf, iso11770_6::Okdf1};
use kdfs::rfc5869_hkdf::Hkdf;
use kdfs::hybrid_array::Array;

use kems::{Capsulator, EncapsulateWithKeyWrap, eckem::{SeedAsScalar}, hybrid::{HybridKem, QsfCombiner2}, ml_kem::MlKemWrapper, x448kem::X448Capsulator, x25519kem::X25519Capsulator};
use kems::{EncodedSizeUser2, Decapsulate,GetEncapsulator, DecapsulateWithKeyWrap, OsRng, EncapsulateDeterministic2, kem_with_kdf::EcCombinerOpenPgp};
use kems::kem_with_kdf::{CombinerAllPubKeys, KemWithKdf};
use ml_kem::{MlKem768, MlKem1024};

use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

mod common;
//use common::PredictableRng;


#[test]
fn test_rfc_9580_a_8 () {
    let ephem_pub_key = hex!("87 cf 18 d5 f1 b5 3f 81 7c ce 5a 00 4c f3 93 cc 89 58 bd dc 06 5f 25 f8 4a f5 09 b1 7d d3 67 64");
    let ephem_prv_key = hex!("af 1e 43 c0 d1 23 ef e8 93 a7 d4 d3 90 f3 a7 61 e3 fa c3 3d fc 7f 3e da a8 30 c9 01 13 52 c7 79");

    let recip_pub_key = hex!("86 93 24 83 67 f9 e5 01 5d b9 22 f8 f4 80 95 dd a7 84 98 7f 2d 59 85 b1 2f ba d1 6c af 5e 44 35");
    let recip_prv_key = hex!("4d 60 0a 4f 79 4d 44 77 5c 57 a2 6e 0f ee fe d5 58 e9 af ff d6 ad 0d 58 2d 57 fb 2b a2 dc ed b8");

    //let raw_shared_secret = hex!("67 e3 0e 69 cd c7 ba b2 a2 68 0d 78 ac a4 6a 2f 8b 6e 2a e4 4d 39 8b dc 6f 92 c5 ad 4a 49 25 14");
    let derived_shared_secret = hex!("f6 6d ad cf f6 45 92 23 9b 25 45 39 b6 4f f6 07");
    
    let encrypted_session_key = hex!("de a3 55 43 79 56 61 79 01 e0 69 57 fb ca 8a 6a 47 a5 b5 15 3e 8d 3a b7");

    let decrypted_session_key = hex!("dd 70 8f 6f a1 ed 65 11 4d 68 d2 34 3e 7c 2f 1d");

    let message_key = hex!("45 12 f7 14 9d 86 33 41 52 7c 65 67 d5 bf fc 42");
    let message_iv = hex!("5f af 32 50 21 2f f9");

    let salt = hex!( "61 64 16 53 5b e0 b0 71 6d 60 e0 52 a5 6c 4c 40 7f 9e b3 6b 0e fa fe 9a d0 a0 df 9b 03 3c 69 a2");

    let chunk_0_encrypted = hex!( "1b a9 eb d2 c0 ec 95 bf 56 9d 25 c9 99 ee 4a 3d e1 70 58 f4 0d fa 8b 4c 68 2b e3 fb bb d7 b2 7e b0 f5 9b b5 00");//   5f 80 c7 c6 f4 03 88 c3 0a d4 06 ab 05 13 dc d6");
    let chunk_0_tag = hex! ("5f 80 c7 c6 f4 03 88 c3 0a d4 06 ab 05 13 dc d6");
    let final_tag = hex!("f9 fd 73 76 56 28 6e 11 77 d0 0f 88 8a db 31 c4");

    let chunk_0_plaintext = hex!("cb 13 62 00 00 00 00 00 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21");
    let chunk_0_padding = hex!("d5 0e c5 a2 93 07 29 91 62 81 47 d7 2c 8f 86 b7");

    let recipient_secret_key = StaticSecret::from(recip_prv_key);
    let recipient_public_key = PublicKey::from(&recipient_secret_key);

    assert! ( recipient_secret_key.as_bytes() == &recip_prv_key);
    assert! ( recipient_public_key.as_bytes() == &recip_pub_key);

    let en = KemWithKdf::<X25519Capsulator<SeedAsScalar>, CombinerAllPubKeys, EcCombinerOpenPgp<Hkdf<Sha256>>, U16>::from_public_key(recipient_public_key);

    let (ek, sk) = en.encapsulate_deterministic(&ephem_prv_key).unwrap();
    assert!( ek.as_ref() == ephem_pub_key );
    assert!( sk.as_slice() == derived_shared_secret );
    
    let kek = KwAes128::new(&sk);
    let decrypted_session_calc: Array<u8, U16> = kek.unwrap_fixed_key(&Array::from(encrypted_session_key)).unwrap();
    assert! ( decrypted_session_calc == decrypted_session_key);

    // AsymmKeyWrap
    //let decap2 = X25519Decapsulator::<KdfX25519OpenPgp<Hkdf<Sha256>>>::new(recipient_secret_key.clone());
    //let decap2 = X25519Capsulator::<KdfX25519OpenPgp<Hkdf<Sha256>>,U16>::new_decapsulator(recipient_secret_key);
    

    //let akw = AsymmKeyWrapUsingEncapsulatorAndAesKw::<X25519EncapKey::<U16>,X25519Capsulator<_,U16>,Aes128>::new_unwrapper(decap2); 
    //let cek = akw.unwrap_from_components(&ephem_pub_key, &encrypted_session_key).unwrap();

    //let cek = decap2.try_decap_with_key_wrap::<Aes128, U16>(&ek, &encrypted_session_key).unwrap();
    //assert!( cek == decrypted_session_key.into());
   
    // Decrypt individual message
    let packet_id = 0xd2u8;
    let version_number = 0x02u8;
    let cipher_algorithm_id = 0x07u8;
    let aead_algorithm_id = 0x02u8;
    let chunk_size_octet = 0x06u8;

    let mut aad = vec![packet_id, version_number, cipher_algorithm_id, aead_algorithm_id, chunk_size_octet];
    
    let message_key_calc = Hkdf::<Sha256>::derive_secret_salt_other::<U23>(&decrypted_session_key, &salt, &aad).unwrap();
    let (key, nonce_part) = message_key_calc.split::<U16>();

    assert!( message_key_calc[0..16] == message_key);
    assert!( message_key_calc[16..] == message_iv);

    //let key = Aes128::generate_key().unwrap();

    //let mut cipher = ocb3::Ocb3::<Aes128, U15>::new(&Array::from_slice(&message_key_calc[0..16]));
    let cipher = ocb3::Ocb3::<Aes128, U15>::new(&key);
    //let cipher = Ocb3::<aes_old::Aes128, U15>::new_from_slice(&message_key_calc[0..16]).unwrap();
    //let mut nonce = GenericArray::default();
    let mut nonce = Array::default();
    nonce[0..7].copy_from_slice(&nonce_part);
    
    let mut buffer = chunk_0_encrypted.to_vec();
    //cipher.decrypt_in_place_detached(&nonce, &aad, &mut buffer, &chunk_0_tag.into()).unwrap();
    cipher.decrypt_inout_detached(&nonce, &aad, buffer.as_mut_slice().into(), &chunk_0_tag.into()).unwrap();

    assert! ( buffer[0..chunk_0_plaintext.len()] == chunk_0_plaintext);
    assert! ( buffer[chunk_0_plaintext.len()..] == chunk_0_padding);

    // Handle final tag
    nonce[14] = 0x1; // Block number
    aad.extend((buffer.len() as u64).to_be_bytes());
    //let final_tag_calc = cipher.encrypt_in_place_detached(&nonce, &aad, &mut []).unwrap();
    let final_tag_calc = cipher.encrypt_inout_detached(&nonce, &aad, [].as_mut_slice().into()).unwrap();

    //assert! ( final_tag_calc == final_tag.into());
    assert! ( final_tag_calc == final_tag);

}



// fn test_gpg_decrypt_x25519 ()
// {
    
//     let encrypted = hex!("\
//         84 5e 03 54 37 c6 ba 6e  f7 43 f9 12 01 07 40   \
//                                                       da \
//         19 a4 91 e9 af bd 4e ec  1a 3a c9 d0 7c 5a b0 18  \
//         d6 a3 6e b2 96 a7 4d bb  7d 71 58 4f 94 44 0c 
//                                                       30  \
//         e9 03 79 3e f2 b3 49 42  2c fb 2a 8f dc 11 c6 70 \
//         3a 28 55 c9 71 ba 09 9d  06 f4 9c a5 71 e7 92 04 \
//         4f 7a 32 eb 99 c7 01 0b  19 06 06 5c 80 58 07 8c \
        
//         d4 51 01 09 02 10 
//                           ad 61  21 8d d9 5e 1b 0f b3 67 \
//         f6 da 24 87 58 b1 da 5f  ef fe 7c 13 b1 b6 cb 85 \
//         41 81 ee 31 32 7d fe 30  82 26 d6 03 c8 46 91 b9 \
//         fb 11 65 94 8d 70 b1 fc  3d 53 f7 8b a3 3d 98 8f \
//         fd c9 91 13 cc 14 6c 94  28 c6 cd 94 7b 98 78 a1 \
//         4e be 15");
    
//     let encrypted2 = hex!("
//         84 5e 03                                          \
//                  54 37 c6 ba 6e  f7 43 f9 12 01 07 40 53  \
//         8b 51 11 ee b0 c4 38 65  30 de ec dd 86 a9 a8 a6  \
//         32 10 59 c5 6b 50 6f f1  d2 29 37 55 f3 02 76     \
//                                                       30  \
//         f6 ef 58 9d fe a4 6d 9f  d9 a0 95 e8 7d d7 7d 71  \
//         f7 fc 90 1a ce 08 1f 90  e0 79 bb 24 f3 95 e6 9e  \
//         02 9c 65 0e ec 51 35 54  a1 12 e9 aa a1 bd 94 d0  \
//                                                           \
//         d4 51 01                                          \
//                  09 02 10                                 \
//                           9c bc  69 3b 75 44 f0 0b 47 db  \
//         ed eb 19 68 89 eb f9 d1  45 d2 53 43 1e 95 94 64 \
//         a7 b6 9b 23 44 20 2a 6e  2d 1d 21 dc 65 f2 db 41  \
//         65 22 b2 9d 84 3a ee 0a  a4 8b 3a c4 8f 86 7f ff \
//         23 1c 6c bf 79 be cf 9a  0f b3 84 6b 9a 04 4c 1b \
//         81 1b 8f ");


//         // 84 - Public Key Encrypted Session Key
//         //    5e  - Length
//         //       03  - Version                                       
//         //          54 37 c6 ba 6e  f7 43 f9                -- Key ID
//         //                                   12             -- Public Key Algorithm (ECDH public key algorithm)
//         //                                      01 07 
//         //                                            40    -- Ephemeral Public Key Prefix
//         //                                               53 -- Ephemeral Public Key 
//         // 8b 51 11 ee b0 c4 38 65  30 de ec dd 86 a9 a8 a6 
//         // 32 10 59 c5 6b 50 6f f1  d2 29 37 55 f3 02 76    
//         //                                               30 -- Encrypted CEK Length
//         // f6 ef 58 9d fe a4 6d 9f  d9 a0 95 e8 7d d7 7d 71 -- Encrypted CEK
//         // f7 fc 90 1a ce 08 1f 90  e0 79 bb 24 f3 95 e6 9e 
//         // 02 9c 65 0e ec 51 35 54  a1 12 e9 aa a1 bd 94 d0 
//         //                                                  
//         // d4                                               -- SEIPD, Symmetric Integrity 
//         //    51                                            -- Length 
//         //       01                                         -- Version 
//         //          09                                      -- Cipher ID, (AES with 256 bit key)
//         //             02                                   -- AEAD ID (OCB)
//         //                10                                -- Chunk Size
//         //                   9c bc  69 3b 75 44 f0 0b 47 db 
//         // ed eb 19 68 89 eb f9 d1  45 d2 53 43 1e 95 94 64 
//         // a7 b6 9b 23 44 20 2a 6e  2d 1d 21 dc 65 f2 db 41  
//         // 65 22 b2 9d 84 3a ee 0a  a4 8b 3a c4 8f 86 7f ff
//         // 23 1c 6c bf 79 be cf 9a  0f b3 84 6b 9a 04 4c 1b
//         // 81 1b 8f
// }


fn parse_open_gpg_packets ( contents: &[u8] ) 
{
    let mut pos = 0usize;
    let mut contains_header = true;
    let mut continues ;
    let mut packet_id = 0;

    while contents.len() > pos {

        let mut pos2 = pos;
        if contains_header {
            packet_id = contents[pos2];
            println! ( "[{pos2}] packet id = {packet_id:02X?}");
            pos2 += 1;
        }
        
        let (packet_len, lenlen )= match contents[pos2] {
            0..192 => { continues = false;
                        (contents[pos2] as usize, 1) },
            192..224 => { continues = false;
                        ((((contents[pos2] as usize) - 192) << 8) + (contents[pos2+1] as usize) + 192, 2 )},
            224..255 => { continues = true;
                        println! ( "Partial length received" );
                            (1 << (contents[pos2] & 0x1F), 1 )
                        },
            255 => todo!(),
        };
        println! ( " [{pos2}] packet len = {packet_len}");
        pos2 += lenlen;
        
        
        if contains_header {
        //let packet_contents = &contents[pos+2+lenlen..pos+1+lenlen+packet_len];
    
        //println! ( "PacketID={:02X?}, len={} PacketVersion={:02X?}", packet_id, packet_len, packet_version);
    
            match packet_id & 0x3F {
                0x1 => {
                    let packet_version = contents[pos2];
                    println! ( " [{pos2}] packet version = {packet_version}");
                    pos2 += 1;
                    let following_size = contents[pos2] as usize;
                    println! ( " [{pos2}] Public Key Encrypted Session Key Packet FollowingSize={}", contents[pos2]);
                    pos2 +=1 ;
                    if following_size >= 1 {
                        println! ( " [{pos2}] KeyVersion={:02X?}", contents[pos2]);
                        pos2 += 1;
                        println! ( " [{pos2}] KeyFingerprint=({}){:02X?}",following_size-1, &contents[pos2..pos2+following_size-1]);
                        pos2 += following_size - 1;
                    }
                    let algorithm = contents[pos2];
                    println! ( " [{pos2}] Algorithm={} (35=ML-KEM-768+X25519, 36=ML-KEM-1024+X448)", contents[pos2]);
                    pos2 += 1;
                    if algorithm == 35 /* ML-KEM 768 + X25519 */
                    {
                        println! ( " [{pos2}] X25519 Ciphertext = {:02X?}", &contents[pos2..pos2+32]);
                        pos2 += 32;
                        println! ( " [{pos2}] ML-KEM 768 Ciphertext = {:02X?}", &contents[pos2..pos2+1088]);
                        pos2 += 1088;
                        println! ( " [{pos2}] Remaining Length = {}", contents[pos2]);
                        pos2 += 1;
                        // println! ( " [{pos2}] Algorithm ID = {:02X?}", contents[pos2]);
                        // pos2 += 1;
                        println! ( " [{pos2}] Wrapped session key = {:02X?}", &contents[pos2..pos+lenlen+packet_len-1]);
                    }
                    else if algorithm == 36  /* ML-KEM 1024 + X448 */
                    {
                        println! ( " [{pos2}] X448 Ciphertext = {:02X?}", &contents[pos2..pos2+56]);
                        pos2 += 56;
                        println! ( " [{pos2}] ML-KEM 1024 Ciphertext = {:02X?}", &contents[pos2..pos2+1568]);
                        pos2 += 1568;
                        println! ( " [{pos2}] Remaining Length = {}", contents[pos2]);
                        pos2 += 1;
                        // println! ( " [{pos2}] Algorithm ID = {:02X?}", contents[pos2]);
                        // pos2 += 1;
                        println! ( " [{pos2}] Wrapped session key = {:02X?}", &contents[pos2..pos+lenlen+packet_len-1]);
                    }
                    else {
                        let session_key = &contents[pos2..pos+lenlen+packet_len+1];
                        println! ( " [{pos2}] Encrypted Session Key=({}){:02X?}", session_key.len(), session_key);
                    }
                }
                0x2 => println! ( "[{pos2}] Signature Packet Type={:02X?}", &contents[pos2..pos2+packet_len-1]),
                0x4 => println! ( "[{pos2}] One-Pass Signature Packet={:02X?}", &contents[pos2..pos2+packet_len-1]),

                0x5 | 0x7 => {
                    let packet_version = contents[pos2];
                    println! ( " [{pos2}] packet version = {packet_version}");
                    pos2 += 1;
                    println! ( " [{pos2}] Secret Key Packet CreationTime={:02X?}", &contents[pos2..pos2+4]);
                    pos2 += 4;
                    println! ( " [{pos2}] Algo={:02X?}", contents[pos2]);
                    pos2 += 1;
                    println! ( " [{pos2}] PubLen={:02X?}", &contents[pos2..pos2+4]);
                    let pub_len = u32::from_be_bytes(contents[pos2..pos2+4].try_into().unwrap()) as usize;
                    pos2 += 4;
                    println! ( " [{pos2}] PubKey=({}){:02X?}", pub_len, &contents[pos2..pos2+pub_len]);
                    pos2 += pub_len;
                    println! ( " [{pos2}] SecretKeyProtection={:02X?}", contents[pos2]);
                    pos2 += 1;
                    let private_key = &contents[pos2..pos+1+lenlen+packet_len];
                    println! ( " [{pos2}] PrvKey=({}){:02X?}", private_key.len(), private_key );
                },      
                0x6 | 0xE => {
                    let packet_version = contents[pos2];
                    println! ( " [{pos2}] packet version = {packet_version}");
                    pos2 += 1;
                    println! ( " [{pos2}] Public Key Packet CreationTime={:02X?}", &contents[pos2..pos2+4]);
                    pos2 += 4;
                    println! ( " [{pos2}] Algo={:02X?}", contents[pos2]);
                    pos2 += 1;
                    println! ( " [{pos2}] PubLen={:02X?}", &contents[pos2..pos2+4]);
                    let pub_len = u32::from_be_bytes(contents[pos2..pos2+4].try_into().unwrap()) as usize;
                    pos2 += 4;
                    println! ( " [{pos2}] PubKey=({}){:02X?}", pub_len, &contents[pos2..pos2+pub_len]);
                }          
                //0x7 => {
                //     println! ( "Secret Subkey Packet {:02X?}", packet_contents);
                // }
                0xB => {
                    println! ( " [{pos2}] Literal Data Packet Format={:02X?} (x62=Binary, x75=unicode)", &contents[pos2]);
                    pos2 += 1;
                    let filename_len = contents[pos2] as usize;
                    println! ( " [{pos2}] Filename Len={:02X?}", contents[pos2]);
                    pos2 += 1;
                    if filename_len > 0 {
                        println! ( " [{pos2}] Filename={:02X?}", &contents[pos2..pos2+filename_len]);
                        pos2 += filename_len;
                    }
                    println! ( " [{pos2}] Date={:02X?}", &contents[pos2..pos2+4]);
                    pos2 += 4;
                    println! ( " [{pos2}] Literal Data={:02X?}", &contents[pos2..pos+lenlen+packet_len+1])

                },  
                0xD => println! ( " [{pos2}] User ID Packet {:02X?}", &contents[pos2..pos+packet_len-1] ),
            
                // 0xE => {
                //     println! ( " [{pos2}] Public Subkey Packet {:02X?}", &contents[pos2..pos+packet_len-1])
                // },
                0x12 => {
                    let packet_version = contents[pos2];
                    println! ( " [{pos2}] packet version = {packet_version}");
                    pos2 += 1;
                    println! ( " [{pos2}] Symmetrically Encrypted and Integrity Protected Data Packet");
                    println! ( " [{pos2}] Symmetric Cipher Algorithm Id={:02X?} 09=AES-256", contents[pos2]);
                    pos2 += 1;
                    println! ( " [{pos2}] AEAD Algorithm Id={:02X?} 01=EAC, 02=OCB, 03=GCM", contents[pos2]);
                    pos2 += 1;
                    println! ( " [{pos2}] Chunk Size={:02X?}", contents[pos2]);
                    pos2 += 1;
                    println! ( " [{pos2}] Salt={:02X?}", &contents[pos2..pos2+32]);
                    pos2 += 32;

                    let len = packet_len + pos + 1 + lenlen - pos2;
                    println! ( " [{pos2}] Encrypted Data and Tag=({}){:02X?}", len, &contents[pos2..pos2+len]);
                    //pos2 += len;
                }
                _ => todo!(),

            }
        }
        else {
            println! ( " [{}] continuation.. {:02X?}", pos2, &contents[pos2..pos2+packet_len]);
            //pos2 += packet_len;
        }

        if continues {
            contains_header = false;
        } else {
            contains_header = true;
        }
        pos = pos + 1 + lenlen + packet_len;
    }
}

// https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/




pub struct OpenPgpLabelMlKem768X25519;
impl Label for OpenPgpLabelMlKem768X25519 {
    const LABEL: &'static[u8] = &hex!("23  4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31 15");
}

#[test]
fn test_pqc_a_1_1() -> Result<(), pem::PemError>
{
    
    let private_key_base64 = "\
        -----BEGIN PGP PRIVATE KEY BLOCK-----\n\
        xUsGZ3SFgBsAAAAg3LSTXMTIYPje/3KOQ480cxsp1t0/1w2687B8uqUTCvwArfra\n\
        hBTuKijHaDe4/1ZcaYn7Z67De15iWPC/vGa3J4DCngYfGwgAAAA/BYJndIWAAwsJ\n\
        BwIVCAIWAAKbAwIeCSKhBseJ4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34A+lH\n\
        BScJAgcCAAAAADQ7EIBsYsSttPe/Uf3gEmjU8NG0Ej59FY8N8de0aowAompVXg4Q\n\
        T9j1IsjmU28Ex/k1PTewAx5OoeQpQbJ4jjH+R/OZ730kkv+c+1mea5dpJdINzS5Q\n\
        UUMgdXNlciAoVGVzdCBLZXkpIDxwcWMtdGVzdC1rZXlAZXhhbXBsZS5jb20+wosG\n\
        ExsIAAAALAWCZ3SFgAIZASKhBseJ4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34\n\
        A+lHAAAAAD4xEPlvPfA18bTluf3pkoZII9dcKltRjMIkbZqDg5el9xpB50br+7lg\n\
        CeQ4FOlsdrb9u7+twdm46fd6pR74naBnq6puYgsQnlLpTfnWqX6BB7sHx8RrBmd0\n\
        hYAjAAAEwCIVC0MM9yTsGbi+Vd+byq3jJwhXETaUBKV1yAI0Q7BfXkJC3YN0sGUL\n\
        B1LIvZBSlFEx/9op4ncn+0J9IKeKzuu449mu2UdNA/XK+5wl+sGGdTVNrJq3s7R/\n\
        BktVNWBMG0t+eYBtItQaxwYucsOntcO344uH1BA+ZHIALxsHN6KrZPCeqfF9ppTB\n\
        8UAlvVR0JATPtyyuxFw6MUex06GlYzirMXafH8jK5KqZJbjBKWwPo7bIsBBbLpqk\n\
        9yQxb7YYJ6VQMGkitrRwWNwQxTGDTee8/FyUMIYklGMewmG65RkKrBMKICsBX7lD\n\
        1cQ7fisEp7Y+WoOVqass6FuOWKJLIhyrg+A93oUsNBhGz/iEgJehP2g8AQPNMnO+\n\
        IicgIwQdV+YJRreWKvQosYMHxtopQRWKRXmmrGKPFYeozvoo6qR+JImvIDgy0gV/\n\
        eEun8iVoQbxuBXPIQXJOicOFPiWjXisG/0G3rOyRE9o0ivlxZPku2qKayfFtMwxb\n\
        NWg54ieV/uRfrjRRHOnL0SaxigY8N0FIwaTB4uMeyqphG+Ri7nSgnLVxaES9/tzN\n\
        iKlgsuAuC5k7E+XPAonGy9Ikm+oHJ9hg0XKNzvyNR/uwWhB2WFmFDRB3ldVE3/wh\n\
        LLe7yPmptIFWZ3J2LaaFqTyUhoNW6spRkUWeNMgo3MxRS3QgmBGXqou6/7RT2tdV\n\
        rWIY8WJO5SmMnZcrJ6oX3qKYgFiJJgCTuUegr/cNNJNLE/shyedkdxfG6jaQSzrL\n\
        xOWg0fBHtrd1snWWryCofwi7ray3HjNnKjNddfiChjWkLpu5H2dYM/CzdnmmOlk9\n\
        71vJgeZ6SrivUlwLTHDIkVqVr5F+iPXHU+Wd6hcUxrIH4eUXTJFIUYiamSqb35cg\n\
        AAzOBBS/DKwD46pOURchwRNRUbu47qiJE4AT6Ia0dTFkCSRezaJXBNe9+oisPDct\n\
        QTx/VZaktkvK4hc+DLwuMiQuQMoev0CgzLlr7XpxvCaEGYOiFTJydFtlhepmheZ3\n\
        k0puE5lY8AOJBEd1PKPEDzwqD0wOBxaMTEQGiPqH39ENs4q08BcOXjANqwtjxVot\n\
        JIurlBcxgsZ16RZOyiaRcCs358AMrExMScNfU+HBIONqxRkzCPOqn3sCMzQO+dwJ\n\
        uxNUoEYDcUAtYos8+1BdaHvGaeNMY3EuxQWeAJQEN4dpYfe29qlcYOwcHRtYosmL\n\
        c7OaHMQ7wnCzdJeyiHobAIgVZGZvAyW6w9cTlQd2pTdsDgSmO8or69gYPKxsmLei\n\
        b3JoytejtBhnaexyfeCFhksHzJlu48l65fDFE3h5Pmqj8vRGfFik2qbIzrU11ala\n\
        /IiJD7RnwTQCYuO++yKBa7rC1qXCXBFZixBwwTavHeEAPNnMmWxDfna2frNnFKRo\n\
        dDaTM7o76Gs7rgTIeLAzQfZih1yAJpSwjEcVDZdIRaRTrkK/4PJzVHGb4wwkOwfL\n\
        oPEBCMuAYTxfqJVEgdBi6pUsPaEOQzkUeIeOVgoFnMhP3+N22fMWkCBc/LYOThtP\n\
        XFWtHkq5jmmj+aiuyGOaadccBKWTvxloBly25QADfbYI2oImtVu1JDjFCf6PQ74U\n\
        WSEf9EvmTgsMQq/TPICLDUyoTkteLTQAwE2+uDYPxbo85xlZ2/yGneciXS8MvfqB\n\
        z8ZOI/y0C3xRsn7ZFZ2nEAaP9RUboQSSkc/gerixe47HC7X+MP6h7UAy49+ndvRO\n\
        6AHx2zZzPiDlZ0NgX3p6Aem45zjfMT7+wosGGBsIAAAALAWCZ3SFgAKbDCKhBseJ\n\
        4X2dvcp7PIM6PAY/6wNT+ArZEf4nho+wZF34A+lHAAAAAMitELFBvWMJM18SWIqP\n\
        kabwnOQbeR9GdZt2dJZF0YO8qGRmLO+T7GIaYj9TlzHonA3y01AAlYdfvolBM2gL\n\
        pujFf59V4t3iZxgQfgvs0+vrcSsE\n\
        -----END PGP PRIVATE KEY BLOCK-----\n";

    let public_key_base64 = "\
        -----BEGIN PGP PUBLIC KEY BLOCK-----\n\
        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\n\
        -----END PGP PUBLIC KEY BLOCK-----\n";

    let message_base64 = "\
        -----BEGIN PGP MESSAGE-----\n\
        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\n\
        ngqFrEkdOzaOHiIZarV74y3G3wZyzXobjp+dpA==\n\
        -----END PGP MESSAGE-----\n";

    //The hex-encoded mlkemKeyShare input to multiKeyCombine is
    let _ml_kem_key_share = hex!("b0e45408d8c713f3941cd27276f879e557df013e05bcf43e37d4c60266a4b797");

    //The hex-encoded ecdhKeyShare input to multiKeyCombine is
    let _x25519_key_share = hex!("9d994741e0db5eacee44cb028c2ec48b1346feae2576aaac383bbcd64138c932");

    //The hex-encoded output of multiKeyCombine is
    let shared_secret = hex!("5bf078bf7977109db6dead92d3578b62d0ab0487ef84e8e0af08f4b4b229e590");

    //The hex-encoded session key is
    let session_key = hex!("94a3b8c9784463bb96b682cddf549adb23579b75bcb646f989d7cfe3e6e14435");

    let private_key_bin = pem::parse(private_key_base64)?;
    let public_key_bin = pem::parse(public_key_base64)?;
    let message_bin = pem::parse(message_base64)?;

    let private_key_contents = private_key_bin.contents();
    let pub_key_bytes = &private_key_contents[439..439+1216];
    let priv_key_bytes = &private_key_contents[1656..1656+96];
    
    let public_key_contents = public_key_bin.contents();
    let pub_key_bytes2 = &public_key_contents[406..406+1216];
    
    assert_eq!( pub_key_bytes, pub_key_bytes2);
    let message_contents = message_bin.contents();
    parse_open_gpg_packets(message_contents);
    
    let ciphertext = &message_contents[39..39+32+1088];
    let wrapped_key = &message_contents[1160..1160+40];
    let salt = &message_contents[1207..1207+32];
    let encrypted_data_and_tag = &message_contents[1239..];

    pub type HybridCapsulatorOpenPgpMlKem768X25519 = HybridKem::<
            X25519Capsulator<SeedAsScalar>,
            MlKemWrapper<MlKem768>,
            QsfCombiner2<Okdf1<sha3::Sha3_256>,OpenPgpLabelMlKem768X25519>,
            SeedAsScalar>;

    let decapsulator = HybridCapsulatorOpenPgpMlKem768X25519::from_bytes_decap(priv_key_bytes.try_into().unwrap());
    let encapsulator = HybridCapsulatorOpenPgpMlKem768X25519::from_bytes_encap(pub_key_bytes2.try_into().unwrap());

    assert_eq!( decapsulator.get_encapsulator().as_bytes(), encapsulator.as_bytes());

    let shared_secret2 = decapsulator.decapsulate(ciphertext.try_into().unwrap()).unwrap();
    assert_eq!( shared_secret2, shared_secret );

    let wrapping_key = AesKw::<Aes256>::new_from_slice(&shared_secret2).unwrap();
    let cek: Array<u8, U32> = wrapping_key.unwrap_fixed_key(wrapped_key.try_into().unwrap()).unwrap();
    assert_eq! ( session_key, cek );

    //let cek2 = decapsulator.decapsulate_with_key_wrap::<AesKw::<Aes256>>(ciphertext.into(), wrapped_key.try_into().unwrap()).unwrap();
    let cek2 = <<HybridCapsulatorOpenPgpMlKem768X25519 as Capsulator>::Decapsulator as DecapsulateWithKeyWrap<_,_,AesKw<Aes256>,U32>>::decapsulate_and_unwrap(&decapsulator, ciphertext.try_into().unwrap(), wrapped_key.try_into().unwrap()).unwrap();
    println! ( "cek={:02X?}", cek2);


    let packet_id = 0xD2u8;
    let version_number = 0x02u8;
    let cipher_algorithm_id = 0x09u8;
    let aead_algorithm_id = 0x2u8;
    let chunk_size_octet = 0x0Cu8; 
    let aad = [packet_id, version_number, cipher_algorithm_id, aead_algorithm_id, chunk_size_octet];

    let key_and_nonce: Array<u8, U39> = Hkdf::<Sha256>::derive_secret_salt_other(&cek, salt, &aad).unwrap();
    
    let mut nonce = Array::default();
    nonce[0..7].copy_from_slice(&key_and_nonce[32..39]);

    let decryption_key = ocb3::Ocb3::<Aes256, U15>::new_from_slice(&key_and_nonce[0..32]).unwrap();
    
    // ignore last tag..
    let plaintext = decryption_key.decrypt(&nonce, Payload{msg: &encrypted_data_and_tag[..encrypted_data_and_tag.len()-16], aad: &aad}).unwrap();

    assert_eq! ( &plaintext[64..64+8], b"Testing\n");

    let cek3 = Array::default();
    let (ct, ek) = <<HybridCapsulatorOpenPgpMlKem768X25519 as Capsulator>::Encapsulator as EncapsulateWithKeyWrap<_,_,AesKw<Aes256>,U32>>::encapsulate_and_wrap(&encapsulator, &mut OsRng, &cek3).unwrap();
    let cek4 = <<HybridCapsulatorOpenPgpMlKem768X25519 as Capsulator>::Decapsulator as DecapsulateWithKeyWrap<_,_,AesKw<Aes256>,U32>>::decapsulate_and_unwrap(&decapsulator, &ct, &ek).unwrap();

    assert_eq!( cek3, cek4);
    

    Ok(())
}

pub struct OpenPgpLabelMlKem1025X448;
impl Label for OpenPgpLabelMlKem1025X448 {
    const LABEL: &'static[u8] = &hex!("24 4F 70 65 6E 50 47 50 43 6F 6D 70 6F 73 69 74 65 4B 44 46 76 31 15");
}

#[test]
fn test_pqc_a_4() ->Result<(), pem::PemError>
{
    // The hex-encoded mlkemKeyShare input to multiKeyCombine is
    let _mlkem_key_share = hex!("f18f161e617b8ce5968f109aadea1e7e1511d10165768d36127ba913c00637d2");

   // The hex-encoded ecdhKeyShare input to multiKeyCombine is 
   let _ecdh_key_share = hex!("732860c8114ae84a964664b1f607785d11bc7d24d5324510adad89bd52db7ee0df9982ad0d1669bdd05556330c86f2dae9e2edea42e05bc5");

   //The hex-encoded output of multiKeyCombine is
   let shared_secret = hex!("ef1e32906f67d39bc800d90cabb0033c77ca6dce8ffca3e96d9c7348e2e8c16e");

   //The hex-encoded session key is
   let session_key = hex!("0588ce40b038aac353d1cf8c67a674b412985105794821013ef154f786c4d89d");

    let private_key_bin = pem::parse(A_4_1_PRIVATE_KEY_BASE64)?;
    let private_key_bin = private_key_bin.contents();
    //parse_open_gpg_packets(private_key_bin);
    let pub_key_bytes = &private_key_bin[12503..12503+1624];
    let priv_key_bytes = &private_key_bin[14128..14128+120];

    let public_key_bin2 = pem::parse(A_4_2_PUBLIC_KEY_BLOCK)?;
    let public_key_bin2 = public_key_bin2.contents();
    //parse_open_gpg_packets(public_key_bin2);
    let pub_key_bytes2 = &public_key_bin2[12413..12413+1624];

    assert_eq!( pub_key_bytes, pub_key_bytes2);

    pub type HybridCapsulatorOpenPgpMlKem1024X448 = HybridKem::<
            X448Capsulator<SeedAsScalar>,
            MlKemWrapper<MlKem1024>,
            QsfCombiner2<Okdf1<sha3::Sha3_256>,OpenPgpLabelMlKem1025X448>,
            SeedAsScalar>;

    let decapsulator = HybridCapsulatorOpenPgpMlKem1024X448::from_bytes_decap(priv_key_bytes.try_into().unwrap());
    let encapsulator = HybridCapsulatorOpenPgpMlKem1024X448::from_bytes_encap(pub_key_bytes2.try_into().unwrap());

    assert_eq!( decapsulator.get_encapsulator().as_bytes(), encapsulator.as_bytes());

    let message_bin = pem::parse(A_4_2_MESSAGE_KEY_BLOCK)?;
    let message_bin = message_bin.contents();
    parse_open_gpg_packets(message_bin);

    let ciphertext = &message_bin[39..39+56+1568];
    let wrapped_key = &message_bin[1664..1664+40];
    let salt = &message_bin[1710..1710+32];
    let encrypted_data_and_tag1 = &message_bin[1742..1742+4060];
    let encrypted_data_and_tag2 = &message_bin[5804..];
    
    let encrypted_data_and_tag = [encrypted_data_and_tag1, encrypted_data_and_tag2].concat();

    let shared_secret2 = decapsulator.decapsulate(ciphertext.try_into().unwrap()).unwrap();
    assert_eq!( shared_secret2, shared_secret );

    let wrapping_key = AesKw::<Aes256>::new_from_slice(&shared_secret2).unwrap();
    let cek: Array<u8, U32> = wrapping_key.unwrap_fixed_key(wrapped_key.try_into().unwrap()).unwrap();
    assert_eq! ( session_key, cek );

    let cek2 = <<HybridCapsulatorOpenPgpMlKem1024X448 as Capsulator>::Decapsulator as DecapsulateWithKeyWrap<_,_,AesKw<Aes256>,U32>>::decapsulate_and_unwrap(&decapsulator, ciphertext.try_into().unwrap(), wrapped_key.try_into().unwrap()).unwrap();
    assert_eq!(cek2, session_key);
    
    let packet_id = 0xD2u8;
    let version_number = 0x02u8;
    let cipher_algorithm_id = 0x09u8;
    let aead_algorithm_id = 0x2u8;
    let chunk_size_octet = 0x0Cu8; 
    let aad = [packet_id, version_number, cipher_algorithm_id, aead_algorithm_id, chunk_size_octet];

    let key_and_nonce: Array<u8, U39> = Hkdf::<Sha256>::derive_secret_salt_other(&cek, salt, &aad).unwrap();
    let (key, nonce_left) = key_and_nonce.split::<U32>();
    
    let chunk_number = 0u64;
    let chunk_number_as_ha: Array<u8, U8> = Array::from(chunk_number.to_be_bytes());
    let nonce = nonce_left.concat(chunk_number_as_ha);
    
    
    // let mut nonce = Array::default();
    // nonce[0..7].copy_from_slice(&key_and_nonce[32..39]);

    //let decryption_key = ocb3::Ocb3::<Aes256, U15>::new_from_slice(&key_and_nonce[0..32]).unwrap();
    let decryption_key = ocb3::Ocb3::<Aes256, U15>::new(&key);
    
    // ignore last tag..
    let plaintext = decryption_key.decrypt(&nonce, Payload{msg: &encrypted_data_and_tag[..encrypted_data_and_tag.len()-16], aad: &aad}).unwrap();

    //parse_open_gpg_packets(&plaintext);
    assert_eq! ( &plaintext[80..80+8], b"Testing\n");

    println! ( "original Length = {}", A_4_2_MESSAGE_KEY_BLOCK.as_bytes().len());
    
    Ok(())
}

const A_4_1_PRIVATE_KEY_BASE64: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
   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\n\
   AAAAAAAAAAAAAAAAAAAAAAAAAAUMFRwiKDA1\n\
   -----END PGP PRIVATE KEY BLOCK-----";

   const A_4_2_PUBLIC_KEY_BLOCK: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
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
BQwVHCIoMDU=
-----END PGP PUBLIC KEY BLOCK-----"#;


const A_4_2_MESSAGE_KEY_BLOCK: &str = r#"-----BEGIN PGP MESSAGE-----
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
r9dO/yldgvycbQA=
-----END PGP MESSAGE-----"#;