use cipher::{InvalidLength};

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