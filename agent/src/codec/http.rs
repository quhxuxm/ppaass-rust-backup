use bytecodec::bytes::{BytesEncoder, RemainingBytesDecoder};
use bytecodec::io::IoDecodeExt;
use bytecodec::EncodeExt;
use bytes::{Buf, BufMut, BytesMut};
use httpcodec::{BodyDecoder, BodyEncoder, Request, RequestDecoder, Response, ResponseEncoder};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::PpaassAgentError;

pub(crate) struct HttpCodec {
    request_decoder: RequestDecoder<BodyDecoder<RemainingBytesDecoder>>,
    response_encoder: ResponseEncoder<BodyEncoder<BytesEncoder>>,
}

impl Default for HttpCodec {
    fn default() -> Self {
        let request_decoder = RequestDecoder::<BodyDecoder<RemainingBytesDecoder>>::default();
        let response_encoder = ResponseEncoder::<BodyEncoder<BytesEncoder>>::default();
        HttpCodec {
            request_decoder,
            response_encoder,
        }
    }
}

impl Decoder for HttpCodec {
    type Item = Request<Vec<u8>>;
    type Error = PpaassAgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decode_result = self.request_decoder.decode_exact(src.chunk())?;
        Ok(Some(decode_result))
    }
}

impl Encoder<Response<Vec<u8>>> for HttpCodec {
    type Error = PpaassAgentError;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encode_result = self.response_encoder.encode_into_bytes(item)?;
        dst.put_slice(encode_result.as_slice());
        Ok(())
    }
}
