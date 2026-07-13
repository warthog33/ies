use crypto_secretbox::XSalsa20Poly1305;

pub struct XSalsa20Poly1305Wrapper ( XSalsa20Poly1305 );

impl aead::AeadCore for XSalsa20Poly1305Wrapper {
    type NonceSize = <XSalsa20Poly1305 as crypto_secretbox::AeadCore>::NonceSize;
    type TagSize = <XSalsa20Poly1305 as crypto_secretbox::AeadCore>::TagSize;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix; 
}
impl aead::KeySizeUser for XSalsa20Poly1305Wrapper
{
    type KeySize = <XSalsa20Poly1305 as crypto_secretbox::KeySizeUser>::KeySize;
}

impl aead::KeyInit for XSalsa20Poly1305Wrapper
{
    fn new(key: &aead::Key<Self>) -> Self {
        let key = generic_array_old::GenericArray::from_slice(&key);
        let encryptor = <XSalsa20Poly1305 as crypto_secretbox::KeyInit>::new(key);
        Self(encryptor)
    }
}
impl aead::AeadInOut for XSalsa20Poly1305Wrapper {
    fn decrypt_in_place(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut dyn aead::Buffer,
        ) -> aead::Result<()> {
        let nonce = generic_array_old::GenericArray::from_slice(&nonce);
        //let nonce = &nonce.from().unwrap();
        let mut buffer2 = buffer.as_ref().to_vec();

        <XSalsa20Poly1305 as crypto_secretbox::AeadInPlace>::decrypt_in_place(&self.0, nonce, associated_data, &mut buffer2).map_err(|_e|aead::Error)?;
        buffer.truncate(0);
        buffer.extend_from_slice(&buffer2).unwrap();
        Ok(())
    }
    fn decrypt_inout_detached(
            &self,
            _nonce: &aead::Nonce<Self>,
            _associated_data: &[u8],
            _buffer: cipher::InOutBuf<'_, '_, u8>,
            _tag: &aead::Tag<Self>,
        ) -> aead::Result<()> {
        todo!()
    }
    fn encrypt_in_place(
            &self,
            nonce: &aead::Nonce<Self>,
            associated_data: &[u8],
            buffer: &mut dyn aead::Buffer,
        ) -> aead::Result<()> {
        let nonce = generic_array_old::GenericArray::from_slice(&nonce);
        let mut buffer2 = buffer.as_ref().to_vec();
        <XSalsa20Poly1305 as crypto_secretbox::AeadInPlace>::encrypt_in_place(&self.0, nonce, associated_data, &mut buffer2).map_err(|_e|aead::Error)?;
        buffer.truncate(0);
        buffer.extend_from_slice(&buffer2).unwrap();
        Ok(())
    }
    fn encrypt_inout_detached(
            &self,
            _nonce: &aead::Nonce<Self>,
            _associated_data: &[u8],
            _buffer: cipher::InOutBuf<'_, '_, u8>,
        ) -> aead::Result<aead::Tag<Self>> {
        todo!()
    }
}
