use bytes::{Bytes, BytesMut};
use log::debug;
use lz4::block::{compress, decompress};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::common::{PpaassMessage, PpaassMessagePayloadEncryptionType, PpaassMessageTakeResult};
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
        let encrypted_ppaass_message: PpaassMessage = lz4_decompress_result.try_into()?;
        debug!("Decode ppaass message from input(encrypted): {:?}", encrypted_ppaass_message);
        let PpaassMessageTakeResult {
            payload_encryption_token: rsa_encrypted_payload_encryption_token,
            payload_encryption_type,
            user_token,
            payload: encrypted_payload,
            ..
        } = encrypted_ppaass_message.take();
        let original_payload = match payload_encryption_type {
            PpaassMessagePayloadEncryptionType::Plain => {
                encrypted_payload
            }
            PpaassMessagePayloadEncryptionType::Blowfish => {
                let original_encryption_token = self.rsa_crypto.decrypt(rsa_encrypted_payload_encryption_token.as_slice())?;
                decrypt_with_blowfish(original_encryption_token.as_slice(), encrypted_payload.as_slice())
            }
            PpaassMessagePayloadEncryptionType::AES => {
                let original_encryption_token = self.rsa_crypto.decrypt(rsa_encrypted_payload_encryption_token.as_slice())?;
                decrypt_with_aes(original_encryption_token.as_slice(), encrypted_payload.as_slice())
            }
        };
        let result = PpaassMessage::new(
            user_token,
            rsa_encrypted_payload_encryption_token,
            payload_encryption_type,
            original_payload,
        );
        debug!("Decode ppaass message from input(decrypted): {:?}", result);
        Ok(Some(result))
    }
}

impl Encoder<PpaassMessage> for PpaassMessageCryptoCodec {
    type Error = PpaassCommonError;

    fn encode(&mut self, original_message: PpaassMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug!("Encode ppaass message to output(decrypted): {:?}", original_message);
        let PpaassMessageTakeResult {
            user_token,
            payload_encryption_type,
            payload_encryption_token,
            payload,
            ..
        } = original_message.take();
        let rsa_encrypted_payload_encryption_token = self.rsa_crypto.encrypt(payload_encryption_token.as_slice())?;
        let encrypted_payload = match payload_encryption_type {
            PpaassMessagePayloadEncryptionType::Plain => {
                payload
            }
            PpaassMessagePayloadEncryptionType::Blowfish => {
                encrypt_with_blowfish(payload_encryption_token.as_slice(), payload.as_slice())
            }
            PpaassMessagePayloadEncryptionType::AES => {
                encrypt_with_aes(payload_encryption_token.as_slice(), payload.as_slice())
            }
        };
        let encrypted_message = PpaassMessage::new_with_random_encryption_type(
            user_token, rsa_encrypted_payload_encryption_token, encrypted_payload);
        debug!("Encode ppaass message to output(encrypted): {:?}", encrypted_message);
        let result_bytes: Vec<u8> = encrypted_message.into();
        let lz4_compressed_bytes = compress(result_bytes.as_slice(), None, true)?;
        self.length_delimited_codec.encode(Bytes::from(lz4_compressed_bytes), dst)?;
        Ok(())
    }
}
