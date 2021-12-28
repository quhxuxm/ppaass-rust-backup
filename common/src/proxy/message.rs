use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::*;

/// The proxy message payload type
#[derive(Debug)]
pub enum PpaassProxyMessagePayloadType {
    TcpConnectSuccess,
    TcpConnectFail,
    TcpConnectionClose,
    TcpData,
    TcpDataRelayFail,
    UdpAssociateSuccess,
    UdpAssociateFail,
    UdpDataRelayFail,
}

impl From<PpaassProxyMessagePayloadType> for u8 {
    fn from(value: PpaassProxyMessagePayloadType) -> Self {
        match value {
            PpaassProxyMessagePayloadType::TcpConnectSuccess => 10,
            PpaassProxyMessagePayloadType::TcpConnectFail => 11,
            PpaassProxyMessagePayloadType::TcpData => 12,
            PpaassProxyMessagePayloadType::TcpDataRelayFail => 13,
            PpaassProxyMessagePayloadType::TcpConnectionClose => 14,
            PpaassProxyMessagePayloadType::UdpAssociateSuccess => 21,
            PpaassProxyMessagePayloadType::UdpAssociateFail => 22,
            PpaassProxyMessagePayloadType::UdpDataRelayFail => 23,
        }
    }
}

impl TryFrom<u8> for PpaassProxyMessagePayloadType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(PpaassProxyMessagePayloadType::TcpConnectSuccess),
            11 => Ok(PpaassProxyMessagePayloadType::TcpConnectFail),
            12 => Ok(PpaassProxyMessagePayloadType::TcpData),
            13 => Ok(PpaassProxyMessagePayloadType::TcpDataRelayFail),
            14 => Ok(PpaassProxyMessagePayloadType::TcpConnectionClose),
            21 => Ok(PpaassProxyMessagePayloadType::UdpAssociateSuccess),
            22 => Ok(PpaassProxyMessagePayloadType::UdpAssociateFail),
            23 => Ok(PpaassProxyMessagePayloadType::UdpDataRelayFail),
            _ => Err(PpaassCommonError::FailToParsePpaassProxyMessagePayloadType(value))
        }
    }
}

/// The proxy message payload
#[derive(Debug)]
pub struct PpaassProxyMessagePayload {
    /// The source address
    source_address: PpaassAddress,
    /// The target address
    target_address: PpaassAddress,
    /// The payload type
    payload_type: PpaassProxyMessagePayloadType,
    /// The data
    data: Vec<u8>,
}
#[derive(Debug)]
pub struct PpaassProxyMessagePayloadSplitResult {
    /// The source address
    pub source_address: PpaassAddress,
    /// The target address
    pub target_address: PpaassAddress,
    /// The payload type
    pub payload_type: PpaassProxyMessagePayloadType,
    /// The data
    pub data: Vec<u8>,
}
impl PpaassProxyMessagePayload {
    pub fn new(source_address: PpaassAddress,
        target_address: PpaassAddress,
        payload_type: PpaassProxyMessagePayloadType,
        data: Vec<u8>) -> Self {
        PpaassProxyMessagePayload { source_address, target_address, payload_type, data }
    }

    pub fn split(self) -> PpaassProxyMessagePayloadSplitResult {
        PpaassProxyMessagePayloadSplitResult {
            source_address: self.source_address,
            target_address: self.target_address,
            payload_type: self.payload_type,
            data: self.data,
        }
    }
}

impl From<PpaassProxyMessagePayload> for Vec<u8> {
    fn from(value: PpaassProxyMessagePayload) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(value.payload_type.into());
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
            source_address,
            target_address,
            data,
        })
    }
}

