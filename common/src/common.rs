use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub use crate::agent::*;
use crate::common::PpaassAddressType::{Domain, IpV4, IpV6};
pub use crate::error::*;
use crate::generate_uuid;
pub use crate::proxy::*;

/// The address type in Ppaass common
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
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
#[derive(Debug, Clone)]
pub struct PpaassAddress {
    host: Vec<u8>,
    port: u16,
    address_type: PpaassAddressType,
}

impl TryFrom<String> for PpaassAddress {
    type Error = PpaassCommonError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let address_parts = value.as_str().split(":").collect::<Vec<&str>>();
        if address_parts.len() != 2 {
            return Err(PpaassCommonError::FailToParsePpaassAddressFromString(value));
        }
        let host_str = address_parts[0];
        let (host, address_type) = match Ipv4Addr::from_str(host_str) {
            Ok(t) => {
                (t.octets().into(), PpaassAddressType::IpV4)
            }
            Err(e) => {
                match Ipv6Addr::from_str(host_str) {
                    Ok(t) => {
                        (t.octets().into(), PpaassAddressType::IpV6)
                    }
                    Err(e) => {
                        (host_str.as_bytes().into(), PpaassAddressType::Domain)
                    }
                }
            }
        };
        let port = match address_parts[1].parse::<u16>() {
            Err(e) => {
                return Err(PpaassCommonError::FailToParsePpaassAddressFromString(value));
            }
            Ok(p) => p
        };
        Ok(Self {
            host,
            port,
            address_type,
        })
    }
}

impl TryFrom<PpaassAddress> for SocketAddr {
    type Error = PpaassCommonError;

    fn try_from(value: PpaassAddress) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&PpaassAddress> for SocketAddr {
    type Error = PpaassCommonError;

    fn try_from(value: &PpaassAddress) -> Result<Self, Self::Error> {
        match value.address_type {
            PpaassAddressType::IpV4 => {
                if value.host.len() < 4 {
                    return Err(PpaassCommonError::FailToParsePpaassIpv4Address);
                }
                let mut ipv4_byte_array: [u8; 4] = [0; 4];
                ipv4_byte_array.clone_from_slice(&value.host[..4]);
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ipv4_byte_array)), value.port))
            }
            PpaassAddressType::IpV6 => {
                if value.host.len() < 16 {
                    return Err(PpaassCommonError::FailToParsePpaassIpv6Address);
                }
                let mut ipv6_byte_array: [u8; 16] = [0; 16];
                ipv6_byte_array.clone_from_slice(&value.host[..16]);
                Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ipv6_byte_array)), value.port()))
            }
            PpaassAddressType::Domain => {
                let socket_addresses = format!("{}:{}", String::from_utf8(value.host.to_vec()).map_err(|e|
                    PpaassCommonError::FailToParsePpaassDomainAddress)?, value.port).to_socket_addrs().map_err(|e| PpaassCommonError::FailToParsePpaassDomainAddress)?;
                let socket_addresses: Vec<_> = socket_addresses.collect();
                if socket_addresses.is_empty() {
                    return Err(PpaassCommonError::FailToParsePpaassDomainAddress);
                }
                Ok(socket_addresses[0])
            }
        }
    }
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

    pub fn host(&self) -> &Vec<u8> {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn address_type(&self) -> &PpaassAddressType {
        &self.address_type
    }
}

/// The body encryption type
#[derive(Debug)]
pub enum PpaassMessagePayloadEncryptionType {
    Plain,
    Blowfish,
    Aes,
}

impl PpaassMessagePayloadEncryptionType {
    pub fn random() -> Self {
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
            PpaassMessagePayloadEncryptionType::Aes => 2,
        }
    }
}

impl TryFrom<u8> for PpaassMessagePayloadEncryptionType {
    type Error = PpaassCommonError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PpaassMessagePayloadEncryptionType::Plain),
            1 => Ok(PpaassMessagePayloadEncryptionType::Blowfish),
            2 => Ok(PpaassMessagePayloadEncryptionType::Aes),
            _ => Err(PpaassCommonError::FailToParsePpaassMessagePayloadEncryptionType(value))
        }
    }
}

/// The message
#[derive(Debug)]
pub struct PpaassMessage {
    /// The message id
    id: String,
    /// The message id that this message reference to
    ref_id: String,
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
pub struct PpaassMessageSplitResult {
    /// The message id
    pub id: String,
    /// The message id that this message reference to
    pub ref_id: String,
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
    pub fn new_with_random_encryption_type(ref_id: String, user_token: Vec<u8>, payload_encryption_token: Vec<u8>,
        payload: Vec<u8>) -> Self {
        let id = generate_uuid();
        let payload_encryption_type = PpaassMessagePayloadEncryptionType::random();
        Self {
            id,
            ref_id,
            user_token,
            payload_encryption_token,
            payload_encryption_type,
            payload,
        }
    }
    pub fn new(ref_id: String, user_token: Vec<u8>, payload_encryption_token: Vec<u8>,
        payload_encryption_type: PpaassMessagePayloadEncryptionType,
        payload: Vec<u8>) -> Self {
        let id = generate_uuid();
        Self {
            id,
            ref_id,
            user_token,
            payload_encryption_token,
            payload_encryption_type,
            payload,
        }
    }

    pub fn split(self) -> PpaassMessageSplitResult {
        PpaassMessageSplitResult {
            id: self.id,
            ref_id: self.ref_id,
            user_token: self.user_token,
            payload_encryption_type: self.payload_encryption_type,
            payload_encryption_token: self.payload_encryption_token,
            payload: self.payload,
        }
    }
}

impl PpaassMessage {
    pub fn id(&self) -> &String {
        &self.id
    }
    pub fn ref_id(&self) -> &String {
        &self.ref_id
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
        let id_length = value.id.as_bytes().len();
        result.put_u64(id_length as u64);
        result.put_slice(value.id.as_bytes());
        let ref_id_length = value.ref_id.as_bytes().len();
        result.put_u64(ref_id_length as u64);
        result.put_slice(value.ref_id.as_bytes());
        let user_token_length = value.user_token.len();
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
        let id = String::from_utf8(id_bytes.to_vec())?;
        let ref_id_length = bytes.get_u64();
        let ref_id_bytes = bytes.copy_to_bytes(ref_id_length as usize);
        let ref_id = String::from_utf8(ref_id_bytes.to_vec())?;
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
            ref_id,
            user_token,
            payload_encryption_type,
            payload_encryption_token,
            payload,
        })
    }
}

