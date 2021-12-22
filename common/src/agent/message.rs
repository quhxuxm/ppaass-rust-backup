use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::*;

/// The agent message body type
#[derive(Debug)]
pub enum PpaassAgentMessagePayloadType {
    TcpConnect,
    TcpData,
    UdpAssociate,
    UdpData,
}

impl From<PpaassAgentMessagePayloadType> for u8 {
    fn from(value: PpaassAgentMessagePayloadType) -> Self {
        match value {
            PpaassAgentMessagePayloadType::TcpConnect => 1,
            PpaassAgentMessagePayloadType::TcpData => 2,
            PpaassAgentMessagePayloadType::UdpAssociate => 3,
            PpaassAgentMessagePayloadType::UdpData => 4,
        }
    }
}

impl TryFrom<u8> for PpaassAgentMessagePayloadType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PpaassAgentMessagePayloadType::TcpConnect),
            2 => Ok(PpaassAgentMessagePayloadType::TcpData),
            3 => Ok(PpaassAgentMessagePayloadType::UdpAssociate),
            4 => Ok(PpaassAgentMessagePayloadType::UdpData),
            _ => Err(PpaassCommonError::FailToParsePpaassAgentMessagePayloadType(value))
        }
    }
}

/// The agent message payload
#[derive(Debug)]
pub struct PpaassAgentMessagePayload {
    /// The user token
    user_token: Vec<u8>,
    /// The source address
    source_address: PpaassAddress,
    /// The target address
    target_address: PpaassAddress,
    /// The payload type
    payload_type: PpaassAgentMessagePayloadType,
    /// The data
    data: Vec<u8>,
}

impl PpaassAgentMessagePayload {
    pub fn new(user_token: Vec<u8>,
               source_address: PpaassAddress,
               target_address: PpaassAddress,
               payload_type: PpaassAgentMessagePayloadType,
               data: Vec<u8>) -> Self {
        PpaassAgentMessagePayload { user_token, source_address, target_address, payload_type, data }
    }
}

impl PpaassAgentMessagePayload {
    pub fn user_token(&self) -> &Vec<u8> {
        &self.user_token
    }
    pub fn source_address(&self) -> &PpaassAddress {
        &self.source_address
    }
    pub fn target_address(&self) -> &PpaassAddress {
        &self.target_address
    }
    pub fn payload_type(&self) -> &PpaassAgentMessagePayloadType {
        &self.payload_type
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

impl From<PpaassAgentMessagePayload> for Vec<u8> {
    fn from(value: PpaassAgentMessagePayload) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(value.payload_type.into());
        let user_token_length = value.user_token.len();
        result.put_u64(user_token_length as u64);
        result.put_slice(value.user_token.as_slice());
        let source_address: Vec<u8> = value.source_address.into();
        let source_address_length = source_address.len();
        result.put_u64(source_address_length as u64);
        result.put_slice(source_address.as_slice());
        let target_address: Vec<u8> = value.target_address.into();
        let target_address_length = target_address.len();
        result.put_u64(target_address_length as u64);
        result.put_slice(target_address.as_slice());
        result.put_u64(value.data.len() as u64);
        result.put_slice(value.data.as_slice());
        result.to_vec()
    }
}

impl TryFrom<Vec<u8>> for PpaassAgentMessagePayload {
    type Error = PpaassCommonError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::from(value);
        let payload_type: PpaassAgentMessagePayloadType = bytes.get_u8().try_into()?;
        let user_token_length = bytes.get_u64() as usize;
        let user_token_bytes = bytes.copy_to_bytes(user_token_length);
        let user_token = user_token_bytes.to_vec();
        let source_address_length = bytes.get_u64() as usize;
        let source_address_bytes = bytes.copy_to_bytes(source_address_length);
        let source_address = source_address_bytes.to_vec().try_into()?;
        let target_address_length = bytes.get_u64() as usize;
        let target_address_bytes = bytes.copy_to_bytes(target_address_length);
        let target_address = target_address_bytes.to_vec().try_into()?;
        let data_length = bytes.get_u64() as usize;
        let data_bytes = bytes.copy_to_bytes(data_length);
        let data = data_bytes.to_vec();
        Ok(Self {
            payload_type,
            user_token,
            source_address,
            target_address,
            data,
        })
    }
}

