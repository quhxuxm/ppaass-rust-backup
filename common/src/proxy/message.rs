use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::*;

/// The proxy message payload type
pub enum PpaassProxyMessagePayloadType {
    TcpConnectSuccess,
    TcpConnectFail,
    TcpDataSuccess,
    TcpDataFail,
    UdpAssociateSuccess,
    UdpAssociateFail,
    UdpDataSuccess,
    UdpDataFail,
}

impl From<PpaassProxyMessagePayloadType> for u8 {
    fn from(value: PpaassProxyMessagePayloadType) -> Self {
        match value {
            PpaassProxyMessagePayloadType::TcpConnectSuccess => 1,
            PpaassProxyMessagePayloadType::TcpConnectFail => 2,
            PpaassProxyMessagePayloadType::TcpDataSuccess => 3,
            PpaassProxyMessagePayloadType::TcpDataFail => 4,
            PpaassProxyMessagePayloadType::UdpAssociateSuccess => 5,
            PpaassProxyMessagePayloadType::UdpAssociateFail => 6,
            PpaassProxyMessagePayloadType::UdpDataSuccess => 7,
            PpaassProxyMessagePayloadType::UdpDataFail => 8,
        }
    }
}

impl TryFrom<u8> for PpaassProxyMessagePayloadType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PpaassProxyMessagePayloadType::TcpConnectSuccess),
            2 => Ok(PpaassProxyMessagePayloadType::TcpConnectFail),
            3 => Ok(PpaassProxyMessagePayloadType::TcpDataSuccess),
            4 => Ok(PpaassProxyMessagePayloadType::TcpDataFail),
            5 => Ok(PpaassProxyMessagePayloadType::UdpAssociateSuccess),
            6 => Ok(PpaassProxyMessagePayloadType::UdpAssociateFail),
            7 => Ok(PpaassProxyMessagePayloadType::UdpDataSuccess),
            8 => Ok(PpaassProxyMessagePayloadType::UdpDataFail),
            _ => Err(PpaassCommonError::FailToParsePpaassProxyMessagePayloadType(value))
        }
    }
}

/// The proxy message payload
pub struct PpaassProxyMessagePayload {
    /// The user token
    user_token: Vec<u8>,
    /// The source address
    source_address: PpaassAddress,
    /// The target address
    target_address: PpaassAddress,
    /// The payload type
    payload_type: PpaassProxyMessagePayloadType,
    /// The data
    data: Vec<u8>,
}

impl PpaassProxyMessagePayload {
    pub fn new(user_token: Vec<u8>,
               source_address: PpaassAddress,
               target_address: PpaassAddress,
               payload_type: PpaassProxyMessagePayloadType,
               data: Vec<u8>) -> Self {
        PpaassProxyMessagePayload { user_token, source_address, target_address, payload_type, data }
    }
}

impl PpaassProxyMessagePayload {
    pub fn user_token(&self) -> &Vec<u8> {
        &self.user_token
    }
    pub fn source_address(&self) -> &PpaassAddress {
        &self.source_address
    }
    pub fn target_address(&self) -> &PpaassAddress {
        &self.target_address
    }
    pub fn payload_type(&self) -> &PpaassProxyMessagePayloadType {
        &self.payload_type
    }
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

impl From<PpaassProxyMessagePayload> for Vec<u8> {
    fn from(value: PpaassProxyMessagePayload) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(value.payload_type.into());
        let user_token_length = value.user_token.len();
        result.put_u64(user_token_length as u64);
        result.put_slice(value.user_token.as_slice());
        let source_address: Vec<u8> = value.source_address.into();
        result.put_u64(source_address.len() as u64);
        result.put_slice(source_address.as_slice());
        let target_address: Vec<u8> = value.target_address.into();
        result.put_u64(target_address.len() as u64);
        result.put_slice(target_address.as_slice());
        result.put_u64(value.data.len() as u64);
        result.put_slice(value.data.as_slice());
        result.to_vec()
    }
}

impl TryFrom<Vec<u8>> for PpaassProxyMessagePayload {
    type Error = PpaassCommonError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::from(value);
        let payload_type: PpaassProxyMessagePayloadType = bytes.get_u8().try_into()?;
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

