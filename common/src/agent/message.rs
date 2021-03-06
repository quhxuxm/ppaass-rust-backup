use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::*;

/// The agent message body type
#[derive(Debug, Copy, Clone)]
pub enum PpaassAgentMessagePayloadType {
    TcpConnect,
    TcpConnectionClose,
    TcpData,
    UdpAssociate,
    UdpData,
}

impl From<PpaassAgentMessagePayloadType> for u8 {
    fn from(value: PpaassAgentMessagePayloadType) -> Self {
        match value {
            PpaassAgentMessagePayloadType::TcpConnect => 10,
            PpaassAgentMessagePayloadType::TcpData => 11,
            PpaassAgentMessagePayloadType::TcpConnectionClose => 12,
            PpaassAgentMessagePayloadType::UdpAssociate => 20,
            PpaassAgentMessagePayloadType::UdpData => 21,
        }
    }
}

impl TryFrom<u8> for PpaassAgentMessagePayloadType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(PpaassAgentMessagePayloadType::TcpConnect),
            11 => Ok(PpaassAgentMessagePayloadType::TcpData),
            12 => Ok(PpaassAgentMessagePayloadType::TcpConnectionClose),
            20 => Ok(PpaassAgentMessagePayloadType::UdpAssociate),
            21 => Ok(PpaassAgentMessagePayloadType::UdpData),
            _ => Err(PpaassCommonError::FailToParsePpaassAgentMessagePayloadType(value))
        }
    }
}

/// The agent message payload
#[derive(Debug)]
pub struct PpaassAgentMessagePayload {
    /// The source address
    source_address: PpaassAddress,
    /// The target address
    target_address: PpaassAddress,
    /// The payload type
    payload_type: PpaassAgentMessagePayloadType,
    /// The data
    data: Bytes,
}

#[derive(Debug)]
pub struct PpaassAgentMessagePayloadSplitResult {
    /// The source address
    pub source_address: PpaassAddress,
    /// The target address
    pub target_address: PpaassAddress,
    /// The payload type
    pub payload_type: PpaassAgentMessagePayloadType,
    /// The data
    pub data: Bytes,
}

impl PpaassAgentMessagePayload {
    pub fn new(source_address: PpaassAddress,
        target_address: PpaassAddress,
        payload_type: PpaassAgentMessagePayloadType,
        data: Bytes) -> Self {
        PpaassAgentMessagePayload { source_address, target_address, payload_type, data }
    }

    pub fn split(self) -> PpaassAgentMessagePayloadSplitResult {
        PpaassAgentMessagePayloadSplitResult {
            source_address: self.source_address,
            target_address: self.target_address,
            payload_type: self.payload_type,
            data: self.data,
        }
    }
}

impl From<PpaassAgentMessagePayload> for Bytes {
    fn from(value: PpaassAgentMessagePayload) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(value.payload_type.into());
        let source_address: Vec<u8> = value.source_address.into();
        let source_address_length = source_address.len();
        result.put_u64(source_address_length as u64);
        result.put_slice(source_address.as_slice());
        let target_address: Vec<u8> = value.target_address.into();
        let target_address_length = target_address.len();
        result.put_u64(target_address_length as u64);
        result.put_slice(target_address.as_slice());
        result.put_u64(value.data.len() as u64);
        result.put(value.data);
        result.into()
    }
}

impl TryFrom<Bytes> for PpaassAgentMessagePayload {
    type Error = PpaassCommonError;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        let mut bytes =value;
        let payload_type: PpaassAgentMessagePayloadType = bytes.get_u8().try_into()?;
        let source_address_length = bytes.get_u64() as usize;
        let source_address_bytes = bytes.copy_to_bytes(source_address_length);
        let source_address = source_address_bytes.to_vec().try_into()?;
        let target_address_length = bytes.get_u64() as usize;
        let target_address_bytes = bytes.copy_to_bytes(target_address_length);
        let target_address = target_address_bytes.to_vec().try_into()?;
        let data_length = bytes.get_u64() as usize;
        let data = bytes.copy_to_bytes(data_length);
        Ok(Self {
            payload_type,
            source_address,
            target_address,
            data,
        })
    }
}

