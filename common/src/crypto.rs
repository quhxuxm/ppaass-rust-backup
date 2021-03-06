use std::path::Path;

use bytes::{BufMut, Bytes, BytesMut};
use crypto::{aessafe, blowfish};
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor};
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{FromPrivateKey, FromPublicKey};

use crate::error::PpaassCommonError;

const BLOWFISH_CHUNK_LENGTH: usize = 8;
const AES_CHUNK_LENGTH: usize = 16;
const RSA_BIT_SIZE: usize = 2048;

/// The util to do RSA encryption and decryption.
#[derive(Debug)]
pub(crate) struct RsaCrypto {
    /// The private used to do decryption
    private_key: &'static str,
    /// The public used to do encryption
    public_key: &'static str,
}

impl RsaCrypto {
    pub fn new(public_key: &'static str, private_key: &'static str) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    pub(crate) fn encrypt(&self, target: &[u8]) -> Result<Bytes, PpaassCommonError> {
        let public_key = RsaPublicKey::from_public_key_pem(self.public_key)
            .map_err(|source| PpaassCommonError::FailToParseRsaKey { source })?;
        let mut rng = OsRng;
        public_key
            .encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, target)
            .map_err(|source| PpaassCommonError::FailToEncryptDataWithRsa { source })
            .map(|v| v.into())
    }

    pub(crate) fn decrypt(&self, target: &[u8]) -> Result<Bytes, PpaassCommonError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(self.private_key)
            .map_err(|source| PpaassCommonError::FailToParseRsaKey { source })?;
        private_key
            .decrypt(PaddingScheme::PKCS1v15Encrypt, target)
            .map_err(|source| PpaassCommonError::FailToEncryptDataWithRsa { source })
            .map(|v| v.into())
    }
}

pub(crate) fn encrypt_with_aes(encryption_token: &[u8], target: &[u8]) -> Bytes {
    let mut result = BytesMut::new();
    let aes_encryptor = aessafe::AesSafe256Encryptor::new(encryption_token);
    let target_chunks = target.chunks(AES_CHUNK_LENGTH);
    for current_chunk in target_chunks {
        let chunk_to_encrypt = &mut [0u8; AES_CHUNK_LENGTH];
        for (i, b) in current_chunk.iter().enumerate() {
            chunk_to_encrypt[i] = *b;
        }
        let chunk_encrypted = &mut [0u8; AES_CHUNK_LENGTH];
        aes_encryptor.encrypt_block(chunk_to_encrypt, chunk_encrypted);
        result.put_slice(chunk_encrypted);
    }
    result.into()
}

pub(crate) fn decrypt_with_aes(encryption_token: &[u8], target: &[u8]) -> Bytes {
    let mut result = BytesMut::new();
    let aes_decryptor = aessafe::AesSafe256Decryptor::new(encryption_token);
    let target_chunks = target.chunks(AES_CHUNK_LENGTH);
    for (_, current_chunk) in target_chunks.into_iter().enumerate() {
        let chunk_to_decrypt = &mut [0u8; AES_CHUNK_LENGTH];
        for (i, b) in current_chunk.iter().enumerate() {
            chunk_to_decrypt[i] = *b;
        }
        let chunk_decrypted = &mut [0u8; AES_CHUNK_LENGTH];
        aes_decryptor.decrypt_block(chunk_to_decrypt, chunk_decrypted);
        result.put_slice(chunk_decrypted);
    }
    result.into()
}

pub(crate) fn encrypt_with_blowfish(encryption_token: &[u8], target: &[u8]) -> Bytes {
    let mut result = BytesMut::new();
    let blowfish_encryption = blowfish::Blowfish::new(encryption_token);
    let target_chunks = target.chunks(BLOWFISH_CHUNK_LENGTH);
    for current_chunk in target_chunks {
        let chunk_to_encrypt = &mut [0u8; BLOWFISH_CHUNK_LENGTH];
        for (i, b) in current_chunk.iter().enumerate() {
            chunk_to_encrypt[i] = *b;
        }
        let chunk_encrypted = &mut [0u8; BLOWFISH_CHUNK_LENGTH];
        blowfish_encryption.encrypt_block(chunk_to_encrypt, chunk_encrypted);
        result.put_slice(chunk_encrypted);
    }
    result.into()
}

pub(crate) fn decrypt_with_blowfish(encryption_token: &[u8], target: &[u8]) -> Bytes {
    let mut result = BytesMut::new();
    let blowfish_encryption = blowfish::Blowfish::new(encryption_token);
    let target_chunks = target.chunks(BLOWFISH_CHUNK_LENGTH);
    for (_, current_chunk) in target_chunks.into_iter().enumerate() {
        let chunk_to_decrypt = &mut [0u8; BLOWFISH_CHUNK_LENGTH];
        for (i, b) in current_chunk.iter().enumerate() {
            chunk_to_decrypt[i] = *b;
        }
        let chunk_decrypted = &mut [0u8; BLOWFISH_CHUNK_LENGTH];
        blowfish_encryption.decrypt_block(chunk_to_decrypt, chunk_decrypted);
        result.put_slice(chunk_decrypted);
    }
    result.into()
}
