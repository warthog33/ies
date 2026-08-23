use aead::{Aead, KeyInit};
use cipher::Array;
use ies::ies_types::{EcdhSm2X963KdfSm2, EciesSm2};

use kems::{KemExtensions, EncapsulateDeterministic};
//use ecies_kem::ecies::ecies_types::EciesSm2;
use kems::eckem::{EcdhEncapsulator};
//use ecies_kem::{Open, Seal};
use elliptic_curve::consts::*;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::ToSec1Point;
use hex_literal::hex;
//use kem::{Encapsulator,EncappedKey};
//
//use kems::Encapsulate;
use kems::FromKey;    
//use elliptic_curve::generic_array::GenericArray;
use ies::hash_encrypt::HashEncryption;

use sm2::Sm2;
use ies::Ies;
//mod common;
//use common::PredictableRng;

// Key Exchange Protocol
// Public Key cryptographic algorithm SM2 based on elliptic curves
// Part 5: Parameter definition
// THis key exchange protocol is different to ECDH - could be a variant of MQV with two ephemeral and two static key pairs. 
// Doesn't look like it can be mapped to a KEM
#[test]
#[allow(non_snake_case, unused)]
fn rfc_draft_shen_sm2_key_exchange_example_1 ()
{
    use kems::{eckem::{EcdhKem}, kem_with_kdf::{CombinerNoKeys, KemWithKdf}};

    let dA = hex!( "81EB26E9 41BB5AF1 6DF11649 5F906952 72AE2CD6 3D6C4AE1 678418BE 48230029");
    let dA2 = sm2::SecretKey::from_bytes(&dA.into()).unwrap();

    let xA = hex!("160E1289 7DF4EDB6 1DD812FE B96748FB D3CCF4FF E26AA6F6 DB9540AF 49C94232");
    let yA = hex!("4A7DAD08 BB9A4595 31694BEB 20AA489D 6649975E 1BFCF8C4 741B78B4 B223007F"); 
    // hash value 𝑍𝐴 = 𝐻256(𝐸𝑁𝑇𝐿𝐴 ∥ 𝐼𝐷𝐴 ∥ 𝑎 ∥ 𝑏 ∥ 𝑥𝐺 ∥ 𝑦𝐺 ∥ 𝑥𝐴 ∥ 𝑦𝐴)
    // 𝑍𝐴 : 3B85A571 79E11E7E 513AA622 991F2CA7 4D1807A0 BD4D4B38 F90987A1 7AC245B1
    assert! ( dA2.public_key().as_affine().x() == xA );
    assert! ( dA2.public_key().to_sec1_point(false).y().unwrap() == &yA );

    // The private key dB:
    let dB = hex!("78512991 7D45A9EA 5437A593 56B82338 EAADDA6C EB199088 F14AE10D EFA229B5");
    let dB2 = sm2::SecretKey::from_bytes(&dB.into()).unwrap();
    let xB = hex!("6AE848C5 7C53C7B1 B5FA99EB 2286AF07 8BA64C64 591B8B56 6F7357D5 76F16DFB");
    let yB = hex!("EE489D77 1621A27B 36C5C799 2062E9CD 09A92643 86F3FBEA 54DFF693 05621C4D");
    
    assert! ( dB2.public_key().as_affine().x() == xB );
    assert! ( dB2.public_key().to_sec1_point(false).y().unwrap() == &yB );
    // hash value 𝑍𝐵 = 𝐻256(𝐸𝑁𝑇𝐿𝐵 ∥ 𝐼𝐷𝐵 ∥ 𝑎 ∥ 𝑏 ∥ 𝑥𝐺 ∥ 𝑦𝐺 ∥ 𝑥𝐵 ∥ 𝑦𝐵)
    // 𝑍𝐵 : 79C988D6 3229D97E F19FE02C A1056E01 E6A7411E D24694AA 8F834F4A 4AB022F7

    let r = hex!("D4DE1547 4DB74D06 491C440D 305E0124 00990F3E 390C7E87 153C12DB 2EA60BB3");
    //let mut pred_rng = PredictableRng::new(&r);

    //let encapsulator = EcdhEncapsulator::<_, EcCombinerNoPubKeys::<X963Kdf<sm3::Sm3>>, U16, EcUncompressedEncoder<sm2::Sm2>>::from_key(dA2.public_key());
    let encapsulator = EcdhSm2X963KdfSm2::from_public_key(dA2.public_key());
    let (ek, sk) = encapsulator.encapsulate_deterministic (&r);

    let x1 = hex!("64CED1BD BC99D590 049B434D 0FD73428 CF608A5D B8FE5CE0 7F150269 40BAE40E");
    let y1 = hex!("376629C7 AB21E7DB 26092249 9DDB118F 07CE8EAA E3E7720A FEF6A5CC 062070C0");

    assert_eq! ( ek[1..33], x1);
    assert_eq! ( ek[33..65], y1);
    
    //Hash value ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
    //ZA:E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31

    //Hash value ZB=H256(ENTLB || IDB || a || b || xG || yG || xB || yB)
    //ZB:6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67

    // The intermediate value during key exchange processing A1-A3:
    // random number rA:
    // 83A2C9C8 B96E5AF7 0BD480B4 72409A9A 327257F1 EBB73F5B 073354B2 48668563
    // point RA=[rA]G=(x1, y1):
    // x-coordinate x1:
    // 6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0
    // y-coordinate y1:
    // 0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A

    // The intermediate value during key exchange processing B1-B9:
    // random number rB:
    // 33FE2194 0342161C 55619C4A 0C060293 D543C80A F19748CE 176D8347 7DE71C80
    // point RB=[rB]G=(x2, y2):
    // x-coordinate x2:
    // 1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // y-coordinate y2:
    // 54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4
    // x2~=2^127+(x2 AND (2^127-1)):
    // B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // tB=(dB+x2~*rB) modn:
    // 2B2E11CB F03641FC 3D939262 FC0B652A 70ACAA25 B5369AD3 8B375C02 65490C9F
    // x1~=2^127+(x1 AND (2^127-1)):
    // E856C095 05324A6D 23150C40 8F162BF0
    // point [x1~]RA=(xA0, yA0):


    // x-coordinate xA0:
    // 2079015F 1A2A3C13 2B67CA90 75BB2803 1D6F2239 8DD8331E 72529555 204B495B
    // y-coordinate yA0:
    // 6B3FE6FB 0F5D5664 DCA16128 B5E7FCFD AFA5456C 1E5A914D 1300DB61 F37888ED
    // point PA+[x1~]RA=(xA1, yA1):
    // x-coordinate xA1:
    // 1C006A3B FF97C651 B7F70D0D E0FC09D2 3AA2BE7A 8E9FF7DA F32673B4 16349B92
    // y-coordinate yA1:
    // 5DC74F8A CC114FC6 F1A75CB2 86864F34 7F9B2CF2 9326A270 79B7D37A FC1C145B
    // point V=[h*tB](PA+[x1~]RA)=(xV, yV):
    // x-coordinate xV:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // y-coordinate yV:
    // 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    // KB=KDF(xV || yV || ZA || ZB, klen):
    // xV || yV || ZA || ZB:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // klen=128
    // shared secret key KB:
    // 55B0AC62 A6B927BA 23703832 C853DED4
    // option SB=Hash(0x02 || yV || Hash(xV || ZA || ZB || x1 || y1 || x2 || y2)):
    // xV || ZA || ZB || x1 || y1 || x2 || y2:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // 6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0
    // 0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A
    // 1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // 54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4
    // Hash(xV || ZA || ZB || x1 || y1 || x2 || y2):
    // FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // 0x02 || yV || Hash(xV || ZA || ZB || x1 || y1 || x2 || y2):
    // 02 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    //    FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // option SB:
    // 284C8F19 8F141B50 2E81250F 1581C7E9 EEB4CA69 90F9E02D F388B454 71F5BC5C

    // The intermediate value during key exchange processing A4-A10:
    // x1~=2^127+(x1 AND (2^127-1)):
    // E856C095 05324A6D 23150C40 8F162BF0
    // tA=(dA+x1~*rA) modn:
    // 236CF0C7 A177C65C 7D55E12D 361F7A6C 174A7869 8AC099C0 874AD065 8A4743DC
    // x2~=2^127+(x2 AND (2^127-1)):
    // B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // point [x2~]RB=(xB0, yB0):


    // x-coordinate xB0:
    // 66864274 6BFC066A 1E731ECF FF51131B DC81CF60 9701CB8C 657B25BF 55B7015D
    // y-coordinate yB0:
    // 1988A7C6 81CE1B50 9AC69F49 D72AE60E 8B71DB6C E087AF84 99FEEF4C CD523064
    // point PB+[x2~]RB=(xB1, yB1):
    // x-coordinate xB1:
    // 7D2B4435 10886AD7 CA3911CF 2019EC07 078AFF11 6E0FC409 A9F75A39 01F306CD
    // y-coordinate yB1:
    // 331F0C6C 0FE08D40 5FFEDB30 7BC255D6 8198653B DCA68B9C BA100E73 197E5D24
    // point U=[h*tA](PB+[x2~]RB)=(xU, yU):
    // x-coordinate xU:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // y-coordinate yU:
    // 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    // KA=KDF(xU || yU || ZA || ZB, klen):
    // xU || yU || ZA || ZB:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // klen=128
    // shared secret key KA:
    // 55B0AC62 A6B927BA 23703832 C853DED4
    // option S1=Hash(0x02 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2)):
    // xU || ZA || ZB || x1 || y1 || x2 || y2:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // 6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0
    // 0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A
    // 1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // 54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4
    // Hash(xU || ZA || ZB || x1 || y1 || x2 || y2):
    // FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // 0x02 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2):
    // 02 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    //    FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // option S1:
    // 284C8F19 8F141B50 2E81250F 1581C7E9 EEB4CA69 90F9E02D F388B454 71F5BC5C
    // option SA=Hash(0x03 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2)):
    // xU || ZA || ZB || x1 || y1 || x2 || y2:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // 6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0
    // 0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A
    // 1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // 54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4


    // Hash(xU || ZA || ZB || x1 || y1 || x2 || y2):
    // FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // 0x03 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2):
    // 03 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    //    FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // option SA:
    // 23444DAF 8ED75343 66CB901C 84B3BDBB 63504F40 65C1116C 91A4C006 97E6CF7A

    // The intermediate value during key exchange processing B10:
    // option S2=Hash(0x03 || yV || Hash(xV || ZA || ZB || x1 || y1 || x2 || y2)):
    // xV || ZA || ZB || x1 || y1 || x2 || y2:
    // 47C82653 4DC2F6F1 FBF28728 DD658F21 E174F481 79ACEF29 00F8B7F5 66E40905
    // E4D1D0C3 CA4C7F11 BC8FF8CB 3F4C02A7 8F108FA0 98E51A66 8487240F 75E20F31
    // 6B4B6D0E 276691BD 4A11BF72 F4FB501A E309FDAC B72FA6CC 336E6656 119ABD67
    // 6CB56338 16F4DD56 0B1DEC45 8310CBCC 6856C095 05324A6D 23150C40 8F162BF0
    // 0D6FCF62 F1036C0A 1B6DACCF 57399223 A65F7D7B F2D9637E 5BBBEB85 7961BF1A
    // 1799B2A2 C7782953 00D9A232 5C686129 B8F2B533 7B3DCF45 14E8BBC1 9D900EE5
    // 54C9288C 82733EFD F7808AE7 F27D0E73 2F7C73A7 D9AC98B7 D8740A91 D0DB3CF4
    // Hash(xV || ZA || ZB || x1 || y1 || x2 || y2):
    // FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // 0x03 || yV || Hash(xV || ZA || ZB || x1 || y1 || x2 || y2):
    // 03 2AF86EFE 732CF12A D0E09A1F 2556CC65 0D9CCCE3 E249866B BB5C6846 A4C4A295
    //    FF49D95B D45FCE99 ED54A8AD 7A709110 9F513944 42916BD1 54D1DE43 79D97647
    // option S2:
    // 23444DAF 8ED75343 66CB901C 84B3BDBB 63504F40 65C1116C 91A4C006 97E6CF7A
}



#[test]
#[allow(non_snake_case, unused)]
// GM/T 0003 Part 5
// Annex C Example of message encryption and decryption
fn text_annex_c () {
    use kems::{eckem::{EcRawEncoder}};

    let dB = hex!("3945208F 7B2144B1 3F36E38A C6D39F95 88939369 2860B51A 42FB81EF 4DF7C5B8");
    let dB2 = sm2::SecretKey::from_bytes(&dB.into()).unwrap();
    let xB = hex!("09F9DF31 1E5421A1 50DD7D16 1E4BC5C6 72179FAD 1833FC07 6BB08FF3 56F35020");
    let yB = hex!("CCEA490C E26775A5 2DC6EA71 8CC1AA60 0AED05FB F35E084A 6632F607 2DA9AD13");
    let message = b"encryption standard";
    
    assert! ( dB2.public_key().as_affine().x() == xB );
    assert! ( dB2.public_key().to_sec1_point(false).y().unwrap() == &yB );
    
    let k = hex!("59276E27 D506861A 16680F3A D9C02DCC EF3CC1FA 3CDBE4CE 6D54B80D EAC1BC21");
    let c1 = hex!( "04 04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73
                                 E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0");
    let c2 = hex!("21886C A989CA9C 7D580873 07CA9309 2D651EFA");
    let c3 = hex!("59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766");
    let ciphertext = hex!( "04" // 04 is mentioned in the text, but absent from the worked example
            "04EBFC71 8E8D1798 62043226 8E77FEB6 415E2EDE 0E073C0F 4F640ECD 2E149A73" // C1.x
            "E858F9D8 1E5430A5 7B36DAAB 8F950A3C 64E6EE6A 63094D99 283AFF76 7E124DF0" // C1.y
            "21886CA9 89CA9C7D 58087307 CA93092D 651EFA" // C2 - encryrpted message
            "59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766 "); // C3 - MAC

    //let mut pred_rng = PredictableRng::new(&k);

    let x2 = hex!("335E18D7 51E51F04 0E27D468 138B7AB1 DC86AD7F 981D7D41 6222FD6A B3ED230D");
    let y2 = hex!("AB743EBC FB22D64F 7B6AB791 F70658F2 5B48FA93 E54064FD BFBED3F0 BD847AC9");

    // Use kem first
    let encapsulator = EcdhEncapsulator::<_, EcRawEncoder<Sm2>>::from_key(dB2.public_key());
    
    //let (ek, sk) = encapsulator.try_encap (&mut pred_rng, &dB2.public_key()).unwrap();
    //let (ek, sk) = encapsulator.encapsulate (&mut pred_rng).unwrap();
    let (ek, sk) = encapsulator.encapsulate_deterministic (&k);
    assert_eq! ( ek.as_slice(), &c1[1..]);
    assert! ( &sk[0..32] == &x2);
    assert! ( &sk[32..] == &y2);

    // Then do key derivation and encryption
    let aead = HashEncryption::<sm3::Sm3,U64>::new(&sk.0.into());
    let ciphertext_calc = <HashEncryption::<sm3::Sm3,U64> as Aead>::encrypt(&aead, &Array::default(), message.as_ref()).unwrap();
    //aead.encrypt(&Array::default(), message.as_ref()).unwrap();

    assert! ( ciphertext_calc[0..19] == c2);
    assert! ( ciphertext_calc[19..] == c3);

    // Use hybrid encryptor structs
    let sm3ecies = EciesSm2::from_key_encap(dB2.public_key());
    let ciphertext3 = sm3ecies.seal_deterministic ( &k, message.as_ref()).unwrap();

    assert! ( &ciphertext3 == &ciphertext[1..]);

    // Use hybrid decryptor structs
    let sm3ecies2 = EciesSm2::from_key_decap(dB2);
    let plaintext2 = sm3ecies2.open ( ciphertext3.as_ref() ).unwrap();

    assert! ( &plaintext2 == &message);
}



#[test]
fn test_sm3_encryption () {
    let message = b"encryption standard";
    
    let k = hex!("335E18D7 51E51F04 0E27D468 138B7AB1 DC86AD7F 981D7D41 6222FD6A B3ED230D 
        AB743EBC FB22D64F 7B6AB791 F70658F2 5B48FA93 E54064FD BFBED3F0 BD847AC9");

    let ciphertext = hex!( 
            "21886CA9 89CA9C7D 58087307 CA93092D 651EFA" // C2 - encryrpted message
            "59983C18 F809E262 923C53AE C295D303 83B54E39 D609D160 AFCB1908 D0BD8766 "); // C3 - MAC

    let encryptor = HashEncryption::<sm3::Sm3,U64>::new(&Array::from(k));
    //let nonce = GenericArray::<u8, U0>::default();
    let nonce = Array::<u8, U0>::default();
    let ciphertext2 = encryptor.encrypt(&nonce, message.as_ref()).unwrap();

    println! ( "ciphertext_calc=({}){:02X?}", ciphertext2.len(), ciphertext2);

    assert! ( ciphertext.as_slice() == &ciphertext2);

    let decryptor = HashEncryption::<sm3::Sm3,U64>::new(&
        
    k.into());
    let plaintext2 = decryptor.decrypt(&nonce, ciphertext.as_ref()).unwrap();

    assert! ( &plaintext2 == message.as_slice());

}