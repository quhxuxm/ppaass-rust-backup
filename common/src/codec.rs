use bytes::{Bytes, BytesMut};
use lz4::block::{compress, decompress};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::common::{PpaassMessage, PpaassMessagePayloadEncryptionType};
use crate::crypto::{decrypt_with_aes, decrypt_with_blowfish, encrypt_with_aes, encrypt_with_blowfish, RsaCrypto};
use crate::error::PpaassCommonError;

pub struct PpaassMessageCryptoCodec {
    rsa_crypto: RsaCrypto,
    length_delimited_codec: LengthDelimitedCodec,
}

impl PpaassMessageCryptoCodec {
    pub fn new(
        public_key: String, private_key: String, ) -> Self {
        Self {
            rsa_crypto: RsaCrypto::new(public_key, private_key),
            length_delimited_codec: LengthDelimitedCodec::new(),
        }
    }
}
/// Decode a  RSA encrypted and Blowfish/AES encrypted PpaassMessage to original PpaassMessage
/// from the input
impl Decoder for PpaassMessageCryptoCodec {
    type Item = PpaassMessage;
    type Error = PpaassCommonError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length_delimited_decode_result = self.length_delimited_codec.decode(src)?;
        let length_delimited_decode_result = match length_delimited_decode_result {
            None => return Ok(None),
            Some(r) => r,
        };
        let lz4_bytes = length_delimited_decode_result.to_vec();
        let lz4_decompress_result = decompress(lz4_bytes.as_slice(), None)?;
        let mut encrypted_ppaass_message: PpaassMessage = lz4_decompress_result.try_into()?;
        let original_payload = match encrypted_ppaass_message.payload_encryption_type() {
            PpaassMessagePayloadEncryptionType::Plain => {
                encrypted_ppaass_message.take_payload()
            }
            PpaassMessagePayloadEncryptionType::Blowfish => {
                let rsa_encrypted_encryption_token = encrypted_ppaass_message.take_payload_encryption_token();
                let original_encryption_token = self.rsa_crypto.decrypt(rsa_encrypted_encryption_token.as_slice())?;
                let encrypted_payload = encrypted_ppaass_message.take_payload();
                decrypt_with_blowfish(original_encryption_token.as_slice(), encrypted_payload.as_slice())
            }
            PpaassMessagePayloadEncryptionType::AES => {
                let rsa_encrypted_encryption_token = encrypted_ppaass_message.take_payload_encryption_token();
                let original_encryption_token = self.rsa_crypto.decrypt(rsa_encrypted_encryption_token.as_slice())?;
                let encrypted_payload = encrypted_ppaass_message.take_payload();
                decrypt_with_aes(original_encryption_token.as_slice(), encrypted_payload.as_slice())
            }
        };
        Ok(Some(PpaassMessage::new(
            encrypted_ppaass_message.take_user_token(),
            encrypted_ppaass_message.take_payload_encryption_token(),
            encrypted_ppaass_message.take_payload_encryption_type(),
            original_payload,
        )))
    }
}

/// Encode a original PpaassMessage to the output with RSA encrypted and Blowfish/AES encrypted PpaassMessage
impl Encoder<PpaassMessage> for PpaassMessageCryptoCodec {
    type Error = PpaassCommonError;

    fn encode(&mut self, mut original_message: PpaassMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let original_payload_encryption_token = original_message.take_payload_encryption_token();
        let rsa_encrypted_payload_encryption_token = self.rsa_crypto.encrypt(original_payload_encryption_token.as_slice())?;
        let encrypted_payload = match original_message.payload_encryption_type() {
            PpaassMessagePayloadEncryptionType::Plain => {
                original_message.take_payload()
            }
            PpaassMessagePayloadEncryptionType::Blowfish => {
                let original_payload = original_message.take_payload();
                encrypt_with_blowfish(original_payload_encryption_token.as_slice(), original_payload.as_slice())
            }
            PpaassMessagePayloadEncryptionType::AES => {
                let original_payload = original_message.take_payload();
                encrypt_with_aes(original_payload_encryption_token.as_slice(), original_payload.as_slice())
            }
        };
        let encrypted_message = PpaassMessage::new_with_random_encryption_type(
            original_message.take_user_token(), rsa_encrypted_payload_encryption_token, encrypted_payload);
        let result_bytes: Vec<u8> = encrypted_message.into();
        let lz4_compressed_bytes = compress(result_bytes.as_slice(), None, true)?;
        self.length_delimited_codec.encode(Bytes::from(lz4_compressed_bytes), dst)?;
        Ok(())
    }
}
