// use bcder::encode::{PrimitiveContent, Values};

// use crate::commons::crypto::signers::error::SignerError;

// /// Helper function to create X.509 RSA Public Key bytes from a given RSA modulus and exponent.
// pub fn rsa_public_key_bytes_from_parts(modulus: &[u8], public_exponent: &[u8]) -> Result<bytes::Bytes, SignerError> {
//     let modulus = bcder::Unsigned::from_slice(modulus).map_err(|_| SignerError::DecodeError)?;
//     let public_exp = bcder::Unsigned::from_slice(public_exponent).map_err(|_| SignerError::DecodeError)?;
//     let rsa_public_key = bcder::encode::sequence((modulus.encode(), public_exp.encode()));

//     let mut bytes: Vec<u8> = Vec::new();
//     rsa_public_key
//         .write_encoded(bcder::Mode::Der, &mut bytes)
//         .map_err(|_| SignerError::DecodeError)?;

//     Ok(bytes::Bytes::from(bytes))
// }
