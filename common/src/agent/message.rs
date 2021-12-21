use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::*;

/// The agent message body type
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
    type Error = PpaassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PpaassAgentMessagePayloadType::TcpConnect),
            2 => Ok(PpaassAgentMessagePayloadType::TcpData),
            3 => Ok(PpaassAgentMessagePayloadType::UdpAssociate),
            4 => Ok(PpaassAgentMessagePayloadType::UdpData),
            _ => Err(PpaassError::FailToParsePpaassAgentMessagePayloadType(value))
        }
    }
}

/// The agent message payload
pub struct PpaassAgentMessagePayload {
    /// The user token
    pub user_token: Vec<u8>,
    /// The source address
    pub source_address: PpaassAddress,
    /// The target address
    pub target_address: PpaassAddress,
    /// The payload type
    pub payload_type: PpaassAgentMessagePayloadType,
    /// The data
    pub data: Vec<u8>,
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
    type Error = PpaassError;

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

