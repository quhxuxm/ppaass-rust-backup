use bytes::{Buf, BufMut, Bytes, BytesMut};
use uuid::Uuid;

pub use crate::agent::*;
use crate::common::PpaassAddressType::{Domain, IpV4, IpV6};
pub use crate::error::*;
pub use crate::proxy::*;

/// The address type in Ppaass common
#[derive(Debug)]
pub enum PpaassAddressType {
    IpV4,
    IpV6,
    Domain,
}

impl TryFrom<u8> for PpaassAddressType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(IpV4),
            2 => Ok(IpV6),
            3 => Ok(Domain),
            _ => Err(PpaassCommonError::FailToParsePpaassAddressType(value))
        }
    }
}

impl From<PpaassAddressType> for u8 {
    fn from(value: PpaassAddressType) -> Self {
        match value {
            IpV4 => 1,
            IpV6 => 2,
            Domain => 3
        }
    }
}

/// The address
#[derive(Debug)]
pub struct PpaassAddress {
    host: Vec<u8>,
    port: u16,
    address_type: PpaassAddressType,
}

impl TryFrom<Vec<u8>> for PpaassAddress {
    type Error = PpaassCommonError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut value = Bytes::from(value);
        let address_type_byte = value.get_u8();
        let address_type = PpaassAddressType::try_from(address_type_byte)?;
        match address_type {
            IpV4 => {
                let mut host = Vec::<u8>::new();
                for i in 0..4 {
                    host.push(value.get_u8());
                }
                let port = value.get_u16();
                Ok(
                    Self {
                        host,
                        port,
                        address_type,
                    })
            }
            IpV6 => {
                let mut host = Vec::<u8>::new();
                for i in 0..16 {
                    host.push(value.get_u8());
                }
                let port = value.get_u16();
                Ok(
                    Self {
                        host,
                        port,
                        address_type,
                    })
            }
            Domain => {
                let domain_name_length = value.get_u64();
                let mut host = Vec::<u8>::new();
                for i in 0..domain_name_length {
                    host.push(value.get_u8());
                }
                let port = value.get_u16();
                Ok(
                    Self {
                        host,
                        port,
                        address_type,
                    })
            }
        }
    }
}

impl From<PpaassAddress> for Vec<u8> {
    fn from(address: PpaassAddress) -> Self {
        let mut result = BytesMut::new();
        match address.address_type {
            IpV4 => {
                result.put_u8(IpV4.into());
                result.put_slice(address.host.as_slice());
                result.put_u16(address.port);
                result.to_vec()
            }
            IpV6 => {
                result.put_u8(IpV6.into());
                result.put_slice(address.host.as_slice());
                result.put_u16(address.port);
                result.to_vec()
            }
            Domain => {
                result.put_u8(Domain.into());
                let domain_name_length = address.host.len();
                result.put_u64(domain_name_length as u64);
                result.put_slice(address.host.as_slice());
                result.put_u16(address.port);
                result.to_vec()
            }
        }
    }
}

impl PpaassAddress {
    /// Create a new address
    pub fn new(host: Vec<u8>, port: u16, address_type: PpaassAddressType) -> Self {
        Self {
            host,
            port,
            address_type,
        }
    }
}

/// The body encryption type
#[derive(Debug)]
pub enum PpaassMessagePayloadEncryptionType {
    Plain,
    Blowfish,
    AES,
}

impl PpaassMessagePayloadEncryptionType {
    fn random() -> Self {
        // let value = rand::random::<u8>() %3;
        // value.try_into().unwrap()
        Self::Blowfish
    }
}

impl From<PpaassMessagePayloadEncryptionType> for u8 {
    fn from(value: PpaassMessagePayloadEncryptionType) -> Self {
        match value {
            PpaassMessagePayloadEncryptionType::Plain => 0,
            PpaassMessagePayloadEncryptionType::Blowfish => 1,
            PpaassMessagePayloadEncryptionType::AES => 2,
        }
    }
}

impl TryFrom<u8> for PpaassMessagePayloadEncryptionType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PpaassMessagePayloadEncryptionType::Plain),
            1 => Ok(PpaassMessagePayloadEncryptionType::Blowfish),
            2 => Ok(PpaassMessagePayloadEncryptionType::AES),
            _ => Err(PpaassCommonError::FailToParsePpaassMessagePayloadEncryptionType(value))
        }
    }
}

/// The message
#[derive(Debug)]
pub struct PpaassMessage {
    /// The message id
    id: Vec<u8>,
    /// The user token
    user_token: Vec<u8>,
    /// The payload encryption token
    payload_encryption_token: Vec<u8>,
    /// The payload encryption type
    payload_encryption_type: PpaassMessagePayloadEncryptionType,
    /// The payload
    payload: Vec<u8>,
}

#[derive(Debug)]
pub struct PpaassMessageTakeResult {
    /// The message id
    pub id: Vec<u8>,
    /// The user token
    pub user_token: Vec<u8>,
    /// The payload encryption token
    pub payload_encryption_token: Vec<u8>,
    /// The payload encryption type
    pub payload_encryption_type: PpaassMessagePayloadEncryptionType,
    /// The payload
    pub payload: Vec<u8>,
}

impl PpaassMessage {
    pub fn new_with_random_encryption_type(user_token: Vec<u8>, payload_encryption_token: Vec<u8>,
                                           payload: Vec<u8>) -> Self {
        let id: Vec<u8> = Uuid::new_v4().as_bytes().to_vec();
        let payload_encryption_type = PpaassMessagePayloadEncryptionType::random();
        Self {
            id,
            user_token,
            payload_encryption_token,
            payload_encryption_type,
            payload,
        }
    }
    pub fn new(user_token: Vec<u8>, payload_encryption_token: Vec<u8>,
               payload_encryption_type: PpaassMessagePayloadEncryptionType,
               payload: Vec<u8>) -> Self {
        let id: Vec<u8> = Uuid::new_v4().as_bytes().to_vec();
        Self {
            id,
            user_token,
            payload_encryption_token,
            payload_encryption_type,
            payload,
        }
    }

    pub fn take(self) -> PpaassMessageTakeResult {
        PpaassMessageTakeResult {
            id: self.id,
            user_token: self.user_token,
            payload_encryption_type: self.payload_encryption_type,
            payload_encryption_token: self.payload_encryption_token,
            payload: self.payload,
        }
    }
}

impl PpaassMessage {
    pub fn id(&self) -> &Vec<u8> {
        &self.id
    }
    pub fn user_token(&self) -> &Vec<u8> {
        &self.user_token
    }
    pub fn payload_encryption_token(&self) -> &Vec<u8> {
        &self.payload_encryption_token
    }
    pub fn payload_encryption_type(&self) -> &PpaassMessagePayloadEncryptionType {
        &self.payload_encryption_type
    }
    pub fn payload(&self) -> &Vec<u8> {
        &self.payload
    }
}

impl From<PpaassMessage> for Vec<u8> {
    fn from(value: PpaassMessage) -> Self {
        let mut result = BytesMut::new();
        let id_length = value.id.len();
        result.put_u64(id_length as u64);
        result.put_slice(value.id.as_slice());
        let user_token_length = value.id.len();
        result.put_u64(user_token_length as u64);
        result.put_slice(value.user_token.as_slice());
        let encryption_token_length = value.payload_encryption_token.len();
        result.put_u64(encryption_token_length as u64);
        result.put_slice(value.payload_encryption_token.as_slice());
        result.put_u8(value.payload_encryption_type.into());
        result.put_u64(value.payload.len() as u64);
        result.put_slice(value.payload.as_slice());
        result.to_vec()
    }
}

impl TryFrom<Vec<u8>> for PpaassMessage {
    type Error = PpaassCommonError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut bytes = Bytes::from(value);
        let id_length = bytes.get_u64();
        let id_bytes = bytes.copy_to_bytes(id_length as usize);
        let id: Vec<u8> = id_bytes.to_vec();
        let user_token_length = bytes.get_u64();
        let user_token_bytes = bytes.copy_to_bytes(user_token_length as usize);
        let user_token: Vec<u8> = user_token_bytes.to_vec();
        let payload_encryption_token_length = bytes.get_u64();
        let payload_encryption_token_bytes = bytes.copy_to_bytes(payload_encryption_token_length as usize);
        let payload_encryption_token = payload_encryption_token_bytes.to_vec();
        let payload_encryption_type: PpaassMessagePayloadEncryptionType = bytes.get_u8().try_into()?;
        let payload_length = bytes.get_u64() as usize;
        let payload = bytes.copy_to_bytes(payload_length).to_vec();
        Ok(Self {
            id,
            user_token,
            payload_encryption_type,
            payload_encryption_token,
            payload,
        })
    }
}
