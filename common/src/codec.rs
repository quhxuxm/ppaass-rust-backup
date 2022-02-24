use bytes::{Buf, Bytes, BytesMut};
use lz4::block::{compress, decompress};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};
use tracing::debug;

use crate::common::{PpaassMessage, PpaassMessagePayloadEncryptionType, PpaassMessageSplitResult};
use crate::crypto::{
    decrypt_with_aes, decrypt_with_blowfish, encrypt_with_aes, encrypt_with_blowfish, RsaCrypto,
};
use crate::error::PpaassCommonError;

pub struct PpaassMessageCodec {
    rsa_crypto: RsaCrypto,
    length_delimited_codec: LengthDelimitedCodec,
    compress: bool,
}

impl PpaassMessageCodec {
    pub fn new(
        public_key: &'static str,
        private_key: &'static str,
        max_frame_size: usize,
        compress: bool,
    ) -> Self {
        let mut length_delimited_codec_builder = LengthDelimitedCodec::builder();
        length_delimited_codec_builder.max_frame_length(max_frame_size);
        length_delimited_codec_builder.length_field_length(8);
        let length_delimited_codec = length_delimited_codec_builder.new_codec();
        Self {
            rsa_crypto: RsaCrypto::new(public_key, private_key),
            length_delimited_codec,
            compress,
        }
    }
}

impl Decoder for PpaassMessageCodec {
    type Item = PpaassMessage;
    type Error = PpaassCommonError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let length_delimited_decode_result = self.length_delimited_codec.decode(src)?;
        let length_delimited_decode_result = match length_delimited_decode_result {
            None => return Ok(None),
            Some(r) => r,
        };
        let encrypted_ppaass_message: PpaassMessage = if self.compress {
            let lz4_bytes = length_delimited_decode_result.to_vec();
            let lz4_decompress_result = decompress(lz4_bytes.as_slice(), None)?;
            lz4_decompress_result.try_into()?
        } else {
            length_delimited_decode_result.to_vec().try_into()?
        };
        debug!(
            "Decode ppaass message from input(encrypted): {:?}",
            encrypted_ppaass_message
        );
        let PpaassMessageSplitResult {
            payload_encryption_token: rsa_encrypted_payload_encryption_token,
            payload_encryption_type,
            user_token,
            payload: encrypted_payload,
            ref_id,
            ..
        } = encrypted_ppaass_message.split();
        let original_payload = match payload_encryption_type {
            PpaassMessagePayloadEncryptionType::Plain => encrypted_payload,
            PpaassMessagePayloadEncryptionType::Blowfish => {
                let original_encryption_token = self
                    .rsa_crypto
                    .decrypt(rsa_encrypted_payload_encryption_token.as_slice())?;
                decrypt_with_blowfish(
                    original_encryption_token.as_slice(),
                    encrypted_payload.chunk(),
                )
            }
            PpaassMessagePayloadEncryptionType::Aes => {
                let original_encryption_token = self
                    .rsa_crypto
                    .decrypt(rsa_encrypted_payload_encryption_token.as_slice())?;
                decrypt_with_aes(
                    original_encryption_token.as_slice(),
                    encrypted_payload.chunk(),
                )
            }
        };
        let result = PpaassMessage::new(
            ref_id,
            user_token,
            rsa_encrypted_payload_encryption_token,
            payload_encryption_type,
            original_payload,
        );
        debug!("Decode ppaass message from input(decrypted): {:?}", result);
        Ok(Some(result))
    }
}

impl Encoder<PpaassMessage> for PpaassMessageCodec {
    type Error = PpaassCommonError;

    fn encode(
        &mut self,
        original_message: PpaassMessage,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        debug!(
            "Encode ppaass message to output(decrypted): {:?}",
            original_message
        );
        let PpaassMessageSplitResult {
            ref_id,
            user_token,
            payload_encryption_type,
            payload_encryption_token,
            payload,
            ..
        } = original_message.split();
        let rsa_encrypted_payload_encryption_token = self
            .rsa_crypto
            .encrypt(payload_encryption_token.as_slice())?;
        let encrypted_payload = match payload_encryption_type {
            PpaassMessagePayloadEncryptionType::Plain => payload,
            PpaassMessagePayloadEncryptionType::Blowfish => {
                encrypt_with_blowfish(payload_encryption_token.as_slice(), payload.chunk())
            }
            PpaassMessagePayloadEncryptionType::Aes => {
                encrypt_with_aes(payload_encryption_token.as_slice(), payload.chunk())
            }
        };
        let encrypted_message = PpaassMessage::new_with_random_encryption_type(
            ref_id,
            user_token,
            rsa_encrypted_payload_encryption_token,
            encrypted_payload,
        );
        debug!(
            "Encode ppaass message to output(encrypted): {:?}",
            encrypted_message
        );
        let result_bytes: Bytes = encrypted_message.into();

        self.length_delimited_codec.encode(
            if self.compress {
                Bytes::from(compress(result_bytes.chunk(), None, true)?)
            } else {
                result_bytes
            },
            dst,
        )?;
        Ok(())
    }
}
