// licence: Apache 2.0

//! # sealed_box library
//! 
//! This library provides a set of functions to encrypt and decrypt content using the
//! Rust implementation of [NaCl’s](https://nacl.cr.yp.to/) 
//! [crypto_box](https://nacl.cr.yp.to/box.html) primitive.
//!

#![warn(missing_docs)]

use anyhow::Error;
use blake2::{Blake2s256, Digest, digest::{Update, generic_array::GenericArray}};
use crypto_box::{aead::Aead, ChaChaBox, SecretKey, PublicKey};

/// Public key size
const PUBLIC_KEY_SIZE: usize = 32;

/// Seal box
pub fn seal_box(
    message: &[u8],
    public_key: &[u8],
    secret_key: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let sk = if let Some(secret_key) = secret_key {
        SecretKey::from_slice(secret_key)?
    } else {
        SecretKey::generate(&mut rand::rngs::OsRng)
    };
    let pk = PublicKey::from(&sk);
    let rk = PublicKey::from_slice(public_key)?;
    let nonce = &Blake2s256::new().chain(&pk.as_bytes()).chain(&rk.as_bytes()).finalize()[..24];
    let cipher = encrypt_box(message, &rk, &sk, nonce)?;
    Ok([pk.as_bytes().to_vec(), cipher].concat())
}

/// Encrypt box.
fn encrypt_box(
    message: &[u8],
    public_key: &PublicKey,
    secret_key: &SecretKey,
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = GenericArray::from_slice(nonce);
    Ok(ChaChaBox::new(public_key, secret_key).encrypt(nonce, message)
        .map_err(|_| SealedBoxError::Aead)?)
}

/// Unseal box.
pub fn unseal_box(
    cipher: &[u8],
    secret_key: &SecretKey,
) -> Result<Vec<u8>, Error> {
    if cipher.len() < PUBLIC_KEY_SIZE {
        Err(SealedBoxError::BoxToSmall.into())
    } else {
        let pk_bytes: [u8; PUBLIC_KEY_SIZE] = cipher[..PUBLIC_KEY_SIZE].try_into()
            .expect("slice with incorrect length");
        let pk = PublicKey::from_slice(&pk_bytes)?;
        let rk = PublicKey::from(secret_key);
        let nonce = &Blake2s256::new().chain(&pk.as_bytes()).chain(&rk.as_bytes()).finalize()[..24];
        let message = decrypt_box(&cipher[PUBLIC_KEY_SIZE..], &pk, &secret_key, nonce)?;
        Ok(message)    
    }
}

/// Decrypt box.
fn decrypt_box(
    cipher: &[u8],
    public_key: &PublicKey,
    secret_key: &SecretKey,
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = GenericArray::from_slice(nonce);
    Ok(ChaChaBox::new(public_key, secret_key).decrypt(nonce, cipher)
        .map_err(|_| SealedBoxError::Aead)?)
}

/// Error por AEAD
#[derive(Debug,)]
pub enum SealedBoxError {
    /// AEAD error
    Aead,
    /// Box size error
    BoxToSmall,
}

impl std::fmt::Display for SealedBoxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           SealedBoxError::Aead => f.write_str("Aead error"),
           SealedBoxError::BoxToSmall => f.write_str("Box to small"),
        }
    }
}

impl std::error::Error for SealedBoxError {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal() {
        let message = b"Hello world!";
        
        let fsk = SecretKey::from_slice(b"0123456789abcdef0123456789abcdef").unwrap();
        let fpk = PublicKey::from(&fsk);

        let cipher = seal_box(message, fpk.as_bytes(), Some(b"fedcba9876543210fedcba9876543210")).unwrap();
        let message2 = unseal_box(&cipher, &fsk).unwrap();
        assert_eq!(message, &message2[..]);

        let cipher = seal_box(message, fpk.as_bytes(), None).unwrap();
        let message2 = unseal_box(&cipher, &fsk).unwrap();
        assert_eq!(message, &message2[..]);

        let result = unseal_box(b"size small", &fsk);
        if result.is_err() {
            let err_str = format!("{:?}", result.err().unwrap());
            assert_eq!(err_str, "Box to small");
        }



    }

}
