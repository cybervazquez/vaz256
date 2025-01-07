// VAZ256™ - A hybrid post-quantum digital signature scheme
// Copyright (C) 2025 Fran Luis Vazquez Alonso
//
// The name "VAZ256" is a trademark of Fran Luis Vazquez Alonso
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


use crate::dilithium5::{
    Dilithium5PublicKey,
    Dilithium5Signature,
    Dilithium5Keypair,
};
use crate::fips202::{shake256};
use crate::zeroize::Zeroize;
use rand::{RngCore, rngs::OsRng};
use crate::hex;

/// Constants defining the sizes of various components
pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const DILITHIUM5_SIGNATURE_SIZE: usize = 4595;
pub const DILITHIUM5_PUBLIC_KEY_SIZE: usize = 2592;
pub const SIGNATURE_SIZE: usize = DILITHIUM5_SIGNATURE_SIZE + DILITHIUM5_PUBLIC_KEY_SIZE;

/// Possible errors that can occur during VAZ256 operations
#[derive(Debug, PartialEq)]
pub enum VAZ256Error {
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    PublicKeyMismatch,
    DeserializationError,
    InvalidLength,
    HexDecodingError,
}

pub type VAZ256Result<T> = Result<T, VAZ256Error>;

/// Secret key wrapper with automatic secure memory wiping
#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize(); // Securely wipe secret key from memory when dropped
    }
}

/// Public key structure containing a 32-byte Shake256 hash
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    key: [u8; PUBLIC_KEY_SIZE],
}

/// Complete signature containing both Dilithium signature and public key
pub struct Signature {
    dilithium_signature: Dilithium5Signature,
    dilithium_public_key: Dilithium5PublicKey,
}

impl SecretKey {
    /// Creates a new SecretKey from raw bytes
    fn new(secret: [u8; SECRET_KEY_SIZE]) -> Self {
        Self(secret)
    }

    /// Returns a reference to the underlying bytes
    fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.0
    }

    /// Converts the secret key to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Creates a SecretKey from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> VAZ256Result<Self> {
        let decoded = hex::decode(hex_str)
            .map_err(|_| VAZ256Error::HexDecodingError)?;
        
        if decoded.len() != SECRET_KEY_SIZE {
            return Err(VAZ256Error::InvalidLength);
        }

        let mut secret = [0u8; SECRET_KEY_SIZE];
        secret.copy_from_slice(&decoded);
        Ok(Self::new(secret))
    }
}

impl PublicKey {
    /// Converts the public key to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }

    /// Creates a PublicKey from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> VAZ256Result<Self> {
        let decoded = hex::decode(hex_str)
            .map_err(|_| VAZ256Error::HexDecodingError)?;
        
        if decoded.len() != PUBLIC_KEY_SIZE {
            return Err(VAZ256Error::InvalidLength);
        }

        let mut key = [0u8; PUBLIC_KEY_SIZE];
        key.copy_from_slice(&decoded);
        Ok(Self { key })
    }
}

/// Generates a new keypair using system randomness
pub fn keygen() -> VAZ256Result<(SecretKey, PublicKey)> {
    let mut secret = [0u8; SECRET_KEY_SIZE];
    OsRng.fill_bytes(&mut secret);
    
    let keypair = Dilithium5Keypair::generate(Some(&secret));
    // Hash the Dilithium public key to create the compact public key
    let public_bytes = keypair.public.to_bytes();
    let mut key = [0u8; PUBLIC_KEY_SIZE];
    shake256(&mut key, PUBLIC_KEY_SIZE, &public_bytes, public_bytes.len());
    
    Ok((
        SecretKey::new(secret),
        PublicKey { key }
    ))
}

/// Signs a message using the secret key
pub fn sign(message: &[u8], vaz256_sk: &SecretKey) -> VAZ256Result<Signature> {
    let keypair = Dilithium5Keypair::generate(Some(vaz256_sk.as_bytes()));
    
    let dilithium_signature = keypair.sign(message);
    
    Ok(Signature {
        dilithium_signature,
        dilithium_public_key: keypair.public,
    })
}

/// Verifies a signature against a message and public key
pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> VAZ256Result<()> {
    // Verify that the signature's public key matches the expected public key hash
    let pk_bytes = signature.dilithium_public_key.to_bytes();
    let mut pk_hash = [0u8; PUBLIC_KEY_SIZE];
    shake256(&mut pk_hash, PUBLIC_KEY_SIZE, &pk_bytes, pk_bytes.len());
    
    if pk_hash != public_key.key {
        return Err(VAZ256Error::PublicKeyMismatch);
    }
    // Verify the Dilithium signature
    if !signature.dilithium_public_key.verify(message, &signature.dilithium_signature) {
        return Err(VAZ256Error::VerificationFailed);
    }
    
    Ok(())
}

impl Signature {
    /// Converts the signature to raw bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_SIZE);
        bytes.extend_from_slice(&self.dilithium_signature);
        bytes.extend_from_slice(&self.dilithium_public_key.to_bytes());
        bytes
    }
    
    /// Converts the signature to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
    
    /// Creates a Signature from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> VAZ256Result<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(VAZ256Error::InvalidLength);
        }
        
        let mut dilithium_sig = [0u8; DILITHIUM5_SIGNATURE_SIZE];
        dilithium_sig.copy_from_slice(&bytes[..DILITHIUM5_SIGNATURE_SIZE]);
        
        let dilithium_pk = Dilithium5PublicKey::from_bytes(
            &bytes[DILITHIUM5_SIGNATURE_SIZE..DILITHIUM5_SIGNATURE_SIZE + DILITHIUM5_PUBLIC_KEY_SIZE]
        );
        
        Ok(Self {
            dilithium_signature: dilithium_sig,
            dilithium_public_key: dilithium_pk,
        })
    }
    
    /// Creates a Signature from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> VAZ256Result<Self> {
        let decoded = hex::decode(hex_str)
            .map_err(|_| VAZ256Error::HexDecodingError)?;
        Self::from_bytes(&decoded)
    }
}

// Test module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let (sk, pk) = keygen().unwrap();
        let message = b"test message";
        
        let signature = sign(message, &sk).unwrap();
        assert!(verify(message, &signature, &pk).is_ok());
    }

    #[test]
    fn test_hex_conversion() {
        let (sk, pk) = keygen().unwrap();
        let message = b"test message";
        let signature = sign(message, &sk).unwrap();

        // Test SecretKey hex conversion
        let sk_hex = sk.to_hex();
        let sk_recovered = SecretKey::from_hex(&sk_hex).unwrap();
        assert_eq!(sk.as_bytes(), sk_recovered.as_bytes());

        // Test PublicKey hex conversion
        let pk_hex = pk.to_hex();
        let pk_recovered = PublicKey::from_hex(&pk_hex).unwrap();
        assert_eq!(pk, pk_recovered);

        // Test Signature hex conversion
        let sig_hex = signature.to_hex();
        let sig_recovered = Signature::from_hex(&sig_hex).unwrap();
        assert!(verify(message, &sig_recovered, &pk).is_ok());
    }

    #[test]
    fn test_wrong_message() {
        let (sk, pk) = keygen().unwrap();
        
        let signature = sign(b"original", &sk).unwrap();
        assert!(verify(b"modified", &signature, &pk).is_err());
    }
}