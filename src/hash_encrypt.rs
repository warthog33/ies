use std::marker::PhantomData;

//use aead::consts::{B0, B1, U64};
use aead::{Aead, AeadCore, Error, Payload};
use cipher::{BlockSizeUser, KeySizeUser, ParBlocksSizeUser, StreamCipher, StreamCipherBackend, StreamCipherCore, StreamCipherCoreWrapper};
use crypto_common::typenum::{U32, Unsigned};
use digest::{Mac, Digest, FixedOutputReset, KeyInit, MacMarker, OutputSizeUser, Update, FixedOutput};
use kdfs::hybrid_array::{Array, ArraySize};

//struct HashStreamCipherBackend<D: Digest + FixedOutputReset, L: ArraySize> {
struct HashStreamCipherBackend<D, L: ArraySize> {
    hasher: D,
    key: Array<u8, L>,
    block_count: u32,
}

impl<D: Digest+ FixedOutputReset, L: ArraySize> BlockSizeUser for HashStreamCipherBackend<D,L>
//where D::OutputSize: BlockSizes
{
    type BlockSize = D::OutputSize;
}

impl<D: Digest+ FixedOutputReset, L: ArraySize> ParBlocksSizeUser for HashStreamCipherBackend<D, L>
//where D::OutputSize: BlockSizes
{
    type ParBlocksSize = D::OutputSize; // Not sure what this should be
}

impl<D: Digest + FixedOutputReset, L: ArraySize> StreamCipherBackend for HashStreamCipherBackend<D, L>
//where D::OutputSize: BlockSizes
{
    fn gen_ks_block(&mut self, block: &mut cipher::Block<Self>) {
        Digest::update ( &mut self.hasher, &self.key.as_slice());
        Digest::update ( &mut self.hasher, self.block_count.to_be_bytes());
        *block = self.hasher.finalize_reset();
        self.block_count += 1;
    }
}


// Implementation of a stream cipher core struct to use with the above backend
//pub struct HashStreamCipherCore<D: Digest + FixedOutputReset, L: ArraySize>
pub struct HashStreamCipherCore<D, L: ArraySize>
{
    backend: HashStreamCipherBackend<D, L>,
}

//impl<D: Digest + FixedOutputReset, L: ArraySize> BlockSizeUser for HashStreamCipherCore<D,L>
impl<D: FixedOutputReset, L: ArraySize> BlockSizeUser for HashStreamCipherCore<D,L>
//where D::OutputSize: BlockSizes,
{
    //type BlockSize = U32; 
    type BlockSize = D::OutputSize;
}

impl<D: Digest + FixedOutputReset, L: ArraySize> KeySizeUser for HashStreamCipherCore<D,L>
{
    type KeySize = L;
}
impl<D: Digest + FixedOutputReset, L: ArraySize> KeyInit for HashStreamCipherCore<D,L>
{
    fn new(key: &aead::Key<Self>) -> Self {
        return HashStreamCipherCore{ backend: HashStreamCipherBackend{hasher: D::new(), key: key.clone(), block_count:1 }};
    }
}

//impl<D: Digest+ FixedOutputReset, L: ArraySize> StreamCipherCore for HashStreamCipherCore<D, L>
impl<D: Digest + FixedOutputReset, L: ArraySize> StreamCipherCore for HashStreamCipherCore<D, L>
//where D::OutputSize: BlockSizes
//where D: Digest<OutputSize = U32>
{
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
    
    //fn process_with_backend(&mut self, f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>) {
    fn process_with_backend(&mut self, f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut self.backend)
        //todo!()
    }
}


///
/// Implementation of the HashEncryption algorithm where a key is repeatedly hashed to generate a 
/// key stream
/// 
pub struct HashEncryption <D: Digest, L: ArraySize>
{
    key: Array<u8, L>,
    phantom: PhantomData<D>,
}

impl<D: Digest, L: ArraySize> AeadCore for HashEncryption<D,L> 
{
    type NonceSize = aead::consts::U0;
    type TagSize = aead::consts::U0;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<D: Digest, L: ArraySize> KeySizeUser for HashEncryption<D,L>
{
    type KeySize = L;
}
impl<D: Digest, L: ArraySize> KeyInit for HashEncryption<D,L>
{
    fn new(key: &aead::Key<Self>) -> Self {
        HashEncryption{key: key.clone(), phantom: PhantomData }
    }
}


///
/// Implementation of an AEAD cipher which uses a hash function and a secret key to create a stream cipher
/// A seperate call to the hash encryption is used to create and verify an authentication tag
/// 
impl<D: Digest + FixedOutputReset, L: ArraySize> Aead for HashEncryption<D,L>
    // where HashStreamCipherCore::<D,L>: StreamCipher,
    //     <HashStreamCipherCore::<D,L> as BlockSizeUser>::BlockSize: BlockSizes,
    where D: Digest<OutputSize = U32> // Not sure why, but it currently is a necessary bound
// where <D as OutputSizeUser>::OutputSize: cipher::typenum::NonZero ,
//      <D as OutputSizeUser>::OutputSize: Cmp<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>, B0>, B0>, B0>> 


// where <D as OutputSizeUser>::OutputSize: cipher::typenum::Cmp<aead::consts::U256> ,
//     <D as OutputSizeUser>::OutputSize: cipher::typenum::NonZero,
    // T: StreamCipherCore,
    // T::BlockSize: BlockSizes,
//where D::OutputSize: BlockSizes
{
    fn encrypt<'msg, 'aad>(
        &self,
        _nonce: &aead::Nonce<Self>,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> 

    
    {
        let plaintext2 : Payload = plaintext.into();
        let mut cipher = StreamCipherCoreWrapper::<HashStreamCipherCore::<D,L>>::new(&self.key);
        let mut result = plaintext2.msg.to_vec();
        cipher.apply_keystream(&mut result);

        let mut mac_funct2 = <HashMac::<D, L>>::new(&self.key);
        Update::update ( &mut mac_funct2, plaintext2.msg);

        result.extend_from_slice ( &mac_funct2.finalize_fixed() );
        return Ok(result);
    }

    fn decrypt<'msg, 'aad>(
        &self,
        _nonce: &aead::Nonce<Self>,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> aead::Result<Vec<u8>> {
        let ciphertext: Payload = ciphertext.into();
        if ciphertext.msg.len() < D::OutputSize::USIZE {
            return Err(Error)
        }
        let (msg, mac_recv) = ciphertext.msg.split_at(ciphertext.msg.len() - D::OutputSize::USIZE);
        
        let mut cipher = StreamCipherCoreWrapper::<HashStreamCipherCore<D,L>>::new(&self.key);
        let mut plaintext = msg.to_vec();
        cipher.apply_keystream(&mut plaintext);
        
        let mut mac_funct = HashMac::<D,L>::new(&self.key);
        Update::update( &mut mac_funct,  &plaintext);
        
        if let Err(_error) = mac_funct.verify_slice(mac_recv) {
            return Err(Error)
        }
        return Ok(plaintext)
    }
}




///
/// Keyed hash MAC. The first half of the key is hashed, then the message and finally the second key half
/// 
struct HashMac<D: Digest, L: ArraySize> {
    key: Array<u8,L>,
    hasher: D,
}
impl<D: Digest, L: ArraySize> OutputSizeUser for HashMac<D, L>
{
    type OutputSize = D::OutputSize;
}
impl<D: Digest, L: ArraySize> KeySizeUser for HashMac<D, L>
{
    type KeySize = L;
}
impl<D: Digest, L: ArraySize> FixedOutput for HashMac<D, L>
{
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        self.hasher.chain_update(&self.key[<Self as KeySizeUser>::KeySize::USIZE/2..]).finalize_into(out)
    }
}

impl<D: Digest, L: ArraySize> KeyInit for HashMac<D, L>
{
    fn new(key: &aead::Key<Self>) -> Self {
        let mut hasher = D::new();
        hasher.update ( &key[0..Self::KeySize::USIZE/2]);
        return HashMac{key: key.clone(), hasher}
    }
}
impl<D: Digest, L: ArraySize> Update for HashMac<D, L>
{
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }
}
impl<D: Digest, L: ArraySize> MacMarker for HashMac<D,L> 
{}
