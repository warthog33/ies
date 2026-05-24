use std::marker::PhantomData;
use std::ops::{Add, Sub};
//use typenum::Sum;

use aead::consts::U0;
//use aead::consts::{U0};
//use aes::{Aes128, Aes256};
//use cipher::block_padding::Pkcs7;
//use cipher::typenum::{IsEqual, NonZero};
use aead::{self, Aead, AeadCore, Payload, Tag, Error, KeyInit, KeySizeUser};
use digest::Mac;
//use digest::typenum::Unsigned;
use cipher::{BlockModeDecrypt, BlockModeEncrypt, BlockSizeUser, IvSizeUser, KeyIvInit, StreamCipher};
use cipher::typenum::Unsigned;
use cipher::inout::block_padding::Padding;
use kdfs::hybrid_array::{Array, ArraySize};
// use hybrid_array::typenum::Unsigned;
// use hybrid_array::{Array, ArraySize};
use kems::generic_array::typenum::Sum;
//use generic_array::GenericArray;
//use p256::U32;

//use crypto_common::KeySizeUser;



///
/// Implementation of an Authenticaiton Encryption with Associated Data using a block cipher and a MAC function
/// It was implemented primarily to support the AES_CBC_HMAC_SHA2 algorithms specified in JWE, RFC 7518
/// Lengths for the MAC key and MAC output are set to the same as for the encryption key.
///
/// 
/// Sample from Appendix 1 of RFC 7518
/// ```
/// use aead::{Payload, KeyInit};
/// use hex_literal::hex;
/// use ies::encrypt_then_mac::{EncryptThenMac};
/// use ies::rfc7518::A128CbcHS256;
/// use cbc::{Encryptor, Decryptor};
/// use aes::Aes128;
/// use sha2::Sha256;
/// use cipher::inout::block_padding::{Pkcs7, Padding};
/// use hmac::Hmac;
///  
/// let K = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
///         10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
/// let P = hex!("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
///         6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
///         69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
///         74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
///         65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
///         6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
///         20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
///         75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");
/// let IV = hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");
/// let A = hex!("54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
///         69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
///         4b 65 72 63 6b 68 6f 66 66 73");
/// let E = hex!("c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79
///         a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9
///         a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2
///         fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36
///         09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8
///         6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b
///         38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f
///         bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5
///         4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db");
/// 
/// let T = hex!("65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4");
///
/// let cipher = EncryptThenMac::<Encryptor::<Aes128>, Decryptor::<Aes128>, Hmac::<Sha256>, Pkcs7>::new(&K.into());
/// let (E_calc, T_calc) = cipher.encrypt_detached(&IV.into(), Payload{msg: &P, aad: &A}).unwrap();
/// assert! ( &E_calc == E.as_slice());
/// assert! ( T_calc == T );
/// 
/// let P_calc = cipher.decrypt_detached(&IV.into(), Payload{msg: &E, aad: &A}, &T.into());
/// assert! ( P_calc == Ok(P.to_vec()));
/// 
/// let cipher2 = A128CbcHS256::new(&K.into());
/// let (E_calc, T_calc) = cipher2.encrypt_detached(&IV.into(), Payload{msg: &P, aad: &A}).unwrap();
/// assert! ( &E_calc == E.as_slice());
/// assert! ( T_calc == T );
/// 
/// let P_calc = cipher2.decrypt_detached(&IV.into(), Payload{msg: &E, aad: &A}, &T.into());
/// assert! ( P_calc == Ok(P.to_vec()));
/// ```
pub struct EncryptThenMac <E,D,M,P>
    where E: KeySizeUser,
    <E as cipher::KeySizeUser>::KeySize: ArraySize,
{
    //enc_key: GenericArray<u8, E::KeySize>,
    enc_key: Array<u8, E::KeySize>,
    //mac_key: GenericArray<u8, E::KeySize>,
    mac_func: M,
    //enc_func: E,
    //dec_func: D,
    //phantom: PhantomData<M>,
    phantom2: PhantomData<P>,
    phantom3: PhantomData<D>,
}

///
/// Generic Array lengths as required by AeadCore
/// 
impl<E,D,M,P> AeadCore for EncryptThenMac<E,D,M,P> 
where E: BlockSizeUser + KeySizeUser + IvSizeUser,
    <E as cipher::KeySizeUser>::KeySize: ArraySize
{
    type NonceSize = <E as IvSizeUser>::IvSize;
    type TagSize = <E as KeySizeUser>::KeySize; //aead::consts::U16;
    //type CiphertextOverhead = <E as BlockSizeUser>::BlockSize;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

///
/// Key is split into an encryption and a mac key, therefore the
/// overall key size is twice as large as the encryption key
/// 
impl<E,D,M,P> KeySizeUser for EncryptThenMac<E,D,M,P> 
where E: BlockSizeUser + KeyIvInit,
    E::KeySize: Add,
    <E::KeySize as Add>::Output: ArraySize,
    // E::KeySize: Mul<U2>,
    // <E::KeySize as Mul<U2>>::Output: ArraySize,
    // <E as cipher::KeySizeUser>::KeySize: ArraySize,
{
    //type KeySize = <E::KeySize as Mul<U2>>::Output;
    type KeySize = Sum<E::KeySize, E::KeySize>;
}

///
/// Function to intitialize the AEAD construction using a two part key, first part is the Mac
/// key and the second part the encryption key
/// 
impl<E,D,M,P> KeyInit for EncryptThenMac<E,D,M,P>
where E: BlockModeEncrypt + KeyIvInit,
    E::KeySize: Add,
    <E::KeySize as Add>::Output: ArraySize + Sub<E::KeySize>,
    <<<E as cipher::KeySizeUser>::KeySize as Add>::Output as Sub<E::KeySize>>::Output: ArraySize,
    
    //D: KeyInit,
    // E::KeySize: Mul<U2>,
    // <E::KeySize as Mul<U2>>::Output: ArraySize,
    // <E as cipher::KeySizeUser>::KeySize: hybrid_array::ArraySize,
    M: KeyInit,
    //<<E as cipher::KeySizeUser>::KeySize as Mul<U2>>::Output: ArraySize
{
    fn new(key: &aead::Key<Self>) -> Self {
        //let (mac_key,enc_key) = key.split_at(E::KeySize::USIZE);
        let (mac_key,enc_key) = key.split_ref::<E::KeySize>();

        Self { 
            mac_func: M::new_from_slice(mac_key.as_slice()).unwrap(), 
            //mac_func: M::new(mac_key), 
            //enc_func: E::new_from_slice(enc_key).unwrap(),
            //dec_func: D::new_from_slice(enc_key).unwrap(),
            //enc_key: GenericArray::from_slice(enc_key).clone(), 
            //enc_key: Array::from_slice(enc_key).clone(), 
            enc_key: Array::try_from(enc_key.as_slice()).unwrap(), 
            //enc_key: enc_key.clone(),
            //mac_key: GenericArray::from_slice(mac_key).clone(), phantom: PhantomData, 
            phantom2: PhantomData, phantom3: PhantomData }
    }
}


impl<E,D,M,P> EncryptThenMac<E,D,M,P>
where E:  BlockModeEncrypt + KeyIvInit,
    D: BlockModeDecrypt + KeyIvInit,
    M: Mac + KeyInit + Clone,
    //P: Padding<E::BlockSize> + Padding<D::BlockSize>,
    P: Padding,
    <E as cipher::KeySizeUser>::KeySize: ArraySize,
    
{
    ///
    /// MAC function as used by HS128 in JWE
    /// 
    fn calc_mac (&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> M{
        //let mut macgen = <M as KeyInit>::new_from_slice(&self.mac_key).unwrap();
        let mut macgen = self.mac_func.clone();
            
        macgen.update(aad);
        macgen.update(nonce);
        macgen.update(ciphertext);
        let le = (aad.len() * 8 )as u64;
        macgen.update(&le.to_be_bytes());

        return macgen;
    }
    
    ///
    /// Encrypt the message using the Block Encryption with padding
    /// MAC the encrypted message
    /// returns the encrypted message as a vector and the MAC as a generic array
    /// 
    /// The existing AEAD traits for detached messages assume the plaintext is equal to the ciphertext, which doesn't
    /// work with block encryptions with padding
    /// 
    pub fn encrypt_detached<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<(Vec<u8>, Tag<Self>)> {

        let plaintext_and_aad = plaintext.into();
        
        let encryptor = <E as KeyIvInit>::new(&self.enc_key, nonce);
        //let ciphertext = encryptor.encrypt_padded_vec_mut::<P>(plaintext_and_aad.msg);
        let ciphertext = encryptor.encrypt_padded_vec::<P>(plaintext_and_aad.msg);
        let tag = Self::calc_mac(&self, ciphertext.as_ref(), nonce, plaintext_and_aad.aad);
        let truncated_tag = Tag::<Self>::try_from(&tag.finalize().into_bytes()[0..<E as KeySizeUser>::KeySize::USIZE]).unwrap();
        //let tag_ha = tag.finalize().into_bytes();
        //let (truncated_tag, _) = tag_ha.split_ref::<E::KeySize>(); //[0..<E as KeySizeUser>::KeySize::USIZE]).clone();
        Ok((ciphertext, truncated_tag))
    }

    ///
    /// Verifies the MAC on the encrypted message
    /// Decrypt the message using the Block Encryption with padding
    /// returns the decrypted message as a vector
    /// 
    /// The existing AEAD traits for detached messages assume the plaintext size is equal to the ciphertext size, which doesn't
    /// work with block encryptions with padding
    /// 
    pub fn decrypt_detached<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
        tag: &Tag<Self>,
    ) -> aead::Result<Vec<u8>> 
    // where E::KeySize: IsEqual<D::KeySize>, //<D::KeySize>,
    //     <E::KeySize as IsEqual<D::KeySize>>::Output: NonZero,
    {

        let ciphertext_and_aad = ciphertext.into();

        let tag_calc = self.calc_mac(ciphertext_and_aad.msg, nonce, ciphertext_and_aad.aad);
        tag_calc.verify_truncated_left(tag.as_ref()).map_err(|_e|Error)?;
       
        let decryptor = <D as KeyIvInit>::new_from_slices(&self.enc_key, &nonce).map_err(|_e|Error)?;
        //let decryptor = <D as KeyIvInit>::new(&self.enc_key, &nonce).map_err(|_e|Error)?;
        //return decryptor.decrypt_padded_vec_mut::<P>(ciphertext_and_aad.msg).map_err(|_v|Error);
        return decryptor.decrypt_padded_vec::<P>(ciphertext_and_aad.msg).map_err(|_v|Error);
    }
}


///
/// Implementation of the prime AEAD traits from RustCrypto
/// These functions assume the tag is appended to the ciphertext, which is not how 
/// JWE uses these functions
/// 
impl<E,D,M,P> Aead for EncryptThenMac<E,D,M,P>
where E:  BlockModeEncrypt + KeyIvInit,
    D: BlockModeDecrypt + KeyIvInit,
    M: Mac + KeyInit + Clone,
    //P: Padding<E::BlockSize> + Padding<D::BlockSize>,
    P: Padding,
    <E as cipher::KeySizeUser>::KeySize: ArraySize,
{
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {

        let (mut ciphertext, tag) = self.encrypt_detached(nonce, plaintext)?;
        ciphertext.extend( tag);
        return Ok(ciphertext);
    }
    
    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {

        let ciphertext_tag_and_aad = ciphertext.into();
        let (ciphertext_in, tag_in) = ciphertext_tag_and_aad.msg.split_at_checked ( ciphertext_tag_and_aad.msg.len()- <E as KeySizeUser>::KeySize::USIZE).ok_or(Error)?;
        let tag_in_ha = Array::try_from(tag_in).unwrap();
        return self.decrypt_detached(nonce, Payload{msg: ciphertext_in, aad: ciphertext_tag_and_aad.aad}, &tag_in_ha);
    }
}




pub struct EncryptNoMac<E,D,P> 
where E: KeySizeUser,
<E as cipher::KeySizeUser>::KeySize: ArraySize
{
    key: Array<u8, E::KeySize>,
    phantom2: PhantomData<P>,
    phantom3: PhantomData<D>,
}

impl<E: KeySizeUser, D, P> AeadCore for EncryptNoMac<E,D,P>  
where E: KeyIvInit ,
<E as cipher::KeySizeUser>::KeySize: ArraySize

{
    type NonceSize = E::IvSize;
    type TagSize = U0;
    //type CiphertextOverhead = U0;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;

}

impl<E, D, P> Aead for EncryptNoMac<E,D,P> 
    //where E: KeySizeUser + BlockSizeUser + KeyIvInit + BlockEncryptMut,
    where E: KeySizeUser + BlockSizeUser + KeyIvInit + BlockModeEncrypt,
        //D: KeyIvInit + BlockDecryptMut,
        D: KeyIvInit + BlockModeDecrypt,
        //P: Padding<E::BlockSize> + Padding<D::BlockSize>,
        P: Padding,
        <E as cipher::KeySizeUser>::KeySize: ArraySize
{
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        plaintext: impl Into<aead::Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        let plaintext_tag_and_aad = plaintext.into();
        let encryptor = <E as KeyIvInit>::new_from_slices(&self.key, &nonce).map_err(|_e|Error)?;
        //let result = encryptor.encrypt_padded_vec_mut::<P>(&plaintext_tag_and_aad.msg);
        let result = encryptor.encrypt_padded_vec::<P>(&plaintext_tag_and_aad.msg);
        Ok(result)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        ciphertext: impl Into<aead::Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        let ciphertext_tag_and_aad = ciphertext.into();
        //let decryptor = D::new(&self.key, nonce);
        let decryptor = <D as KeyIvInit>::new_from_slices(&self.key, &nonce).map_err(|_e|Error)?;
        //let result = decryptor.decrypt_padded_vec_mut::<P>(&ciphertext_tag_and_aad.msg).map_err(|_v| Error)?;
        let result = decryptor.decrypt_padded_vec::<P>(&ciphertext_tag_and_aad.msg).map_err(|_v| Error)?;
        Ok(result)
    }
}
impl<E: KeySizeUser, D, P> KeySizeUser for EncryptNoMac<E,D,P> 
where <E as cipher::KeySizeUser>::KeySize: ArraySize

{
    type KeySize = E::KeySize;
}
impl<E: KeySizeUser, D, P> KeyInit for EncryptNoMac<E,D,P> 
where <E as cipher::KeySizeUser>::KeySize: ArraySize
{
    fn new(key: &aead::Key<Self>) -> Self {
        Self{key: key.clone(), phantom2: PhantomData, phantom3: PhantomData}
    }
}



pub struct StreamNoMac<C> 
where C: KeySizeUser,
<C as cipher::KeySizeUser>::KeySize: ArraySize,
{
    key: Array<u8, C::KeySize>,
}
impl<C: KeySizeUser> AeadCore for StreamNoMac<C>  
where C: KeyIvInit ,
<C as cipher::KeySizeUser>::KeySize: ArraySize
{
    type NonceSize = C::IvSize;
    type TagSize = U0;
    //type CiphertextOverhead = U0;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}
impl<C: KeySizeUser> KeySizeUser for StreamNoMac<C> 
where <C as cipher::KeySizeUser>::KeySize: ArraySize
{
    type KeySize = C::KeySize;
}
impl<C: KeySizeUser> KeyInit for StreamNoMac<C> 
where <C as cipher::KeySizeUser>::KeySize: ArraySize
{
    fn new(key: &aead::Key<Self>) -> Self {
        Self{key: key.clone()}
    }
}
impl<C> Aead for StreamNoMac<C> 
    where C: KeySizeUser + KeyIvInit + StreamCipher,
    <C as cipher::KeySizeUser>::KeySize: ArraySize
{
    fn encrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        plaintext: impl Into<aead::Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        let plaintext_tag_and_aad = plaintext.into();
        let mut encryptor = <C as KeyIvInit>::new_from_slices(&self.key, &nonce).map_err(|_e|Error)?;
        let mut result = plaintext_tag_and_aad.msg.to_vec();
        encryptor.apply_keystream(&mut result);
        Ok(result)
    }

    fn decrypt<'msg, 'aad>(
        &self,
        nonce: &aead::Nonce<Self>,
        ciphertext: impl Into<aead::Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        self.encrypt(nonce, ciphertext)
    }
}





#[cfg(test)]
#[cfg(all(feature = "rustcrypto-aes", feature="rustcrypto-sha2", feature ="rustcrypto-hmac", feature="rustcrypto-cbc"))]
#[allow(non_snake_case, unused)]
mod test
{
    use aead::{KeyInit, Payload};
    use hex_literal::hex;
    use crate::rfc7518::{A128CbcHS256, A192CbcHS384, A256CbcHS512};
    
    #[test]
    fn b_1_test_cases_AES_128_CBC_HMAC_SHA_256() 
    {
        //AES_128_CBC_HMAC_SHA_256

        let K = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");

        let MAC_KEY = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");

        let ENC_KEY = hex!("10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");

        let P = hex!("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
                6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
                69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
                74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
                65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
                6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
                20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
                75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");

        let IV = hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");

        let A = hex!("54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
                69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
                4b 65 72 63 6b 68 6f 66 66 73");

        let AL = hex!("00 00 00 00 00 00 01 50");

        let E = hex!("c8 0e df a3 2d df 39 d5 ef 00 c0 b4 68 83 42 79
                a2 e4 6a 1b 80 49 f7 92 f7 6b fe 54 b9 03 a9 c9
                a9 4a c9 b4 7a d2 65 5c 5f 10 f9 ae f7 14 27 e2
                fc 6f 9b 3f 39 9a 22 14 89 f1 63 62 c7 03 23 36
                09 d4 5a c6 98 64 e3 32 1c f8 29 35 ac 40 96 c8
                6e 13 33 14 c5 40 19 e8 ca 79 80 df a4 b9 cf 1b
                38 4c 48 6f 3a 54 c5 10 78 15 8e e5 d7 9d e5 9f
                bd 34 d8 48 b3 d6 95 50 a6 76 46 34 44 27 ad e5
                4b 88 51 ff b5 98 f7 f8 00 74 b9 47 3c 82 e2 db");

        let M = hex!("65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4
                e6 e5 45 82 47 65 15 f0 ad 9f 75 a2 b7 1c 73 ef");

        let T = hex!("65 2c 3f a3 6b 0a 7c 5b 32 19 fa b3 a3 0b c1 c4");

        let cipher = A128CbcHS256::new(&K.into());
        let (E_calc, T_calc) = cipher.encrypt_detached(&IV.into(), Payload{msg: &P, aad: &A}).unwrap();
        assert! ( &E_calc == E.as_slice());
        assert! ( T_calc == T );

        let P_calc = cipher.decrypt_detached(&IV.into(), Payload{msg: &E, aad: &A}, &T.into());
        assert! ( P_calc == Ok(P.to_vec()));

    }




    #[test]
    fn b_2_test_cases_AES_192_CBC_HMAC_SHA_384 ()
    {
        let  K = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f");

        let   MAC_KEY = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17");

        let ENC_KEY = hex!("18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27
                28 29 2a 2b 2c 2d 2e 2f");

        let  P = hex!("41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
                6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
                69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
                74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
                65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
                6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
                20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
                75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");

        let  IV =hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");

        let  A = hex!("54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
                69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
                4b 65 72 63 6b 68 6f 66 66 73");

        let  AL = hex!("00 00 00 00 00 00 01 50");

        let  E =  hex!(" ea 65 da 6b 59 e6 1e db 41 9b e6 2d 19 71 2a e5
                d3 03 ee b5 00 52 d0 df d6 69 7f 77 22 4c 8e db
                00 0d 27 9b dc 14 c1 07 26 54 bd 30 94 42 30 c6
                57 be d4 ca 0c 9f 4a 84 66 f2 2b 22 6d 17 46 21
                4b f8 cf c2 40 0a dd 9f 51 26 e4 79 66 3f c9 0b
                3b ed 78 7a 2f 0f fc bf 39 04 be 2a 64 1d 5c 21
                05 bf e5 91 ba e2 3b 1d 74 49 e5 32 ee f6 0a 9a
                c8 bb 6c 6b 01 d3 5d 49 78 7b cd 57 ef 48 49 27
                f2 80 ad c9 1a c0 c4 e7 9c 7b 11 ef c6 00 54 e3");

        let  M = hex!("84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20
                75 16 80 39 cc c7 33 d7 45 94 f8 86 b3 fa af d4
                86 f2 5c 71 31 e3 28 1e 36 c7 a2 d1 30 af de 57");

        let  T = hex!("84 90 ac 0e 58 94 9b fe 51 87 5d 73 3f 93 ac 20
                75 16 80 39 cc c7 33 d7");

        let cipher = A192CbcHS384::new(&K.into());
        let (E_calc, T_calc) = cipher.encrypt_detached(&IV.into(), Payload{msg: &P, aad: &A}).unwrap();
        assert! ( &E_calc == E.as_slice());
        assert! ( T_calc == T );

        let P_calc = cipher.decrypt_detached(&IV.into(), Payload{msg: &E, aad: &A}, &T.into());
        assert! ( P_calc == Ok(P.to_vec()));
    }

    #[test]
    fn b_3_test_cases_AES_256_CBC_HMAC_SHA_512 () 
    {


        let  K =  hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
                30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f");

        let   MAC_KEY = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");

        let   ENC_KEY = hex!("20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f
                30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f");

        let  P = hex!(" 41 20 63 69 70 68 65 72 20 73 79 73 74 65 6d 20
                6d 75 73 74 20 6e 6f 74 20 62 65 20 72 65 71 75
                69 72 65 64 20 74 6f 20 62 65 20 73 65 63 72 65
                74 2c 20 61 6e 64 20 69 74 20 6d 75 73 74 20 62
                65 20 61 62 6c 65 20 74 6f 20 66 61 6c 6c 20 69
                6e 74 6f 20 74 68 65 20 68 61 6e 64 73 20 6f 66
                20 74 68 65 20 65 6e 65 6d 79 20 77 69 74 68 6f
                75 74 20 69 6e 63 6f 6e 76 65 6e 69 65 6e 63 65");

        let  IV = hex!("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04");

        let  A = hex!(" 54 68 65 20 73 65 63 6f 6e 64 20 70 72 69 6e 63
                69 70 6c 65 20 6f 66 20 41 75 67 75 73 74 65 20
                4b 65 72 63 6b 68 6f 66 66 73");

        let  AL = hex!("00 00 00 00 00 00 01 50");

        let  E =  hex!("4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd
                3d d8 d5 d3 02 42 35 26 91 2d a0 37 ec bc c7 bd
                82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2
                e6 d1 2a 13 74 b7 7f 07 75 53 df 82 94 10 44 6b
                36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1
                1a 09 cc f5 37 0d c8 0b fe cb ad 28 c7 3f 09 b3
                a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e
                31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b
                be 26 38 d0 9d d7 a4 93 09 30 80 6d 07 03 b1 f6");

        let  M = hex!(" 4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
                2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5
                fd 30 a5 65 c6 16 ff b2 f3 64 ba ec e6 8f c4 07
                53 bc fc 02 5d de 36 93 75 4a a1 f5 c3 37 3b 9c");

        let  T = hex!("4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf
                2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 61 95 5b c5");

        let cipher = A256CbcHS512::new(&K.into());
        let (E_calc, T_calc) = cipher.encrypt_detached(&IV.into(), Payload{msg: &P, aad: &A}).unwrap();
        assert! ( &E_calc == E.as_slice());
        assert! ( T_calc == T );

        let P_calc = cipher.decrypt_detached(&IV.into(), Payload{msg: &E, aad: &A}, &T.into());
        assert! ( P_calc == Ok(P.to_vec()));
    }

}
