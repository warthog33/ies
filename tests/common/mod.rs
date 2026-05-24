//use cipher::{block_padding::UnpadError, InvalidLength};
use cipher::{InvalidLength};
// use elliptic_curve::bigint::ArrayEncoding;
// use elliptic_curve::Curve;
// use kems::generic_array::GenericArray;
// #[cfg(all(feature = "rustcrypto"))]
// use p256::{NistP256, U32};
// #[cfg(all(feature = "rustcrypto"))]
// use p384::U48;
//use kems::{CryptoRng, RngCore};

// pub struct PredictableRng<'a> { rng_material: &'a [u8]}

// #[allow(dead_code)]
// impl PredictableRng<'_> {
//     pub fn new ( material: &'_ [u8]) -> PredictableRng<'_> {
//         PredictableRng { rng_material: material }
//     }
// }
// impl CryptoRng for PredictableRng<'_> {}
// impl RngCore for PredictableRng<'_> {
//     fn next_u32(&mut self) -> u32 {
//         todo!()
//     }

//     fn next_u64(&mut self) -> u64 {
//         todo!()
//     }

//     fn fill_bytes(&mut self, dest: &mut [u8]) {
//         dest.copy_from_slice(&self.rng_material[..dest.len()]);
//     }

//     fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), kems::rand_core::Error> {
//         self.fill_bytes(_dest);
//         Ok(())
//     }
    
//     // fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), elliptic_curve::rand_core::Error> {
//     //     todo!()
//     // }
// }


// pub struct PredictableRngForHybrid { 
//     material: Vec<u8>,
// }

// impl CryptoRng for PredictableRngForHybrid {}
// impl RngCore for PredictableRngForHybrid {
//     fn next_u32(&mut self) -> u32 {
//         todo!()
//     }

//     fn next_u64(&mut self) -> u64 {
//         todo!()
//     }

//     fn fill_bytes(&mut self, dest: &mut [u8]) {
//         dest.copy_from_slice(&self.material[0..dest.len()]);
//         //self.material = self.material[dest.len()..].to_vec();
//         self.material.drain(0..dest.len());
//     }

//     fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), kems::rand_core::Error> {
//         todo!()
//     }
    
//     // fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), elliptic_curve::rand_core::Error> {
//     //     todo!()
//     // }
// }

// #[allow(dead_code)]
// #[cfg(all(feature = "rustcrypto"))]
// impl PredictableRngForHybrid {
//     pub fn new3 ( seed: &[u8]) -> PredictableRngForHybrid {
//         // let mut hasher = sha3::Shake256::default();
//         // hasher.update(seed);
//         // let mut reader = hasher.finalize_xof();
        
//         // let mut expanded = [0u8; 80];
//         // reader.read(&mut expanded);

//         let mut material = seed[0..32].to_vec();

//         let ec_material = derive_ec_key_wide_reduction_p256 ( &seed[32..80] );
//         material.extend_from_slice(&ec_material);

//         PredictableRngForHybrid { material }
//     }
//     pub fn new2 ( seed: &[u8]) -> Self {
//         Self { material: seed.to_vec() }
//     }

//     pub fn add(&mut self,  material: &[u8] ) {
//         self.material.extend_from_slice(material);
//     }
// }

// #[cfg(all(feature = "rustcrypto"))]
// pub(crate) fn derive_ec_key_wide_reduction_p256 ( seed: &[u8] ) -> GenericArray<u8, U32> {
//     let ba = Array::<u8,U48>::try_from(seed).unwrap();
//         let xx = elliptic_curve::bigint::U384::from_be_byte_array(ba);
//         let order = NistP256::ORDER;
//         let yy: Array<u8,_> = order.to_be_byte_array();
//         let mut order_vec = [0u8; 16].to_vec();
//         order_vec.extend_from_slice(&yy);
//         let long_order = elliptic_curve::bigint::U384::from_be_byte_array(Array::try_from(&order_vec).unwrap());
//         //let non_zero_order = elliptic_curve::bigint::NonZero::from_uint(long_order);
//         let non_zero_order = long_order.to_nz().unwrap();
//         let sj = xx.rem(&non_zero_order);
//         *GenericArray::from_slice(&sj.to_be_byte_array()[16..48])
// }

#[allow(unused)]
#[derive(Debug)]
pub enum Error{ Error1}



impl From<pem::PemError> for Error {
    fn from(_err: pem::PemError) -> Error {
        return Error::Error1;
    }
}

impl From<der::Error> for Error {
    fn from(_err: der::Error) -> Error {
        return Error::Error1;
    }
}
impl From<ies::Error> for Error {
    fn from(_err: ies::Error) -> Error {
        return Error::Error1;
    }
}
impl From<aes_kw::Error> for Error {
    fn from(_err: aes_kw::Error) -> Error {
        return Error::Error1;
    }
}
impl From<aead::Error> for Error {
    fn from(_err: aead::Error) -> Error {
        return Error::Error1;
    }
}
// impl From<ecies_kem::Error> for Error {
//     fn from(_err: ecies_kem::Error) -> Error {
//         return Error::Error1;
//     }
// }
impl From<elliptic_curve::Error> for Error {
    fn from(_err: elliptic_curve::Error) -> Error {
        return Error::Error1;
    }
}
impl From<elliptic_curve::pkcs8::Error> for Error {
    fn from(_err: elliptic_curve::pkcs8::Error) -> Error {
        return Error::Error1;
    }
}
// impl From<UnpadError> for Error {
//     fn from(_err: UnpadError) -> Error {
//         return Error::Error1;
//     }
// }
impl From<InvalidLength> for Error {
    fn from(_err: InvalidLength) -> Error {
        return Error::Error1;
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(_err: std::array::TryFromSliceError) -> Error {
        return Error::Error1
    }
}

// impl From<rsa::pkcs8::Error> for Error {
//     fn from(_err: rsa::pkcs8::Error) -> Error {
//         return Error::Error1
//     }
// }