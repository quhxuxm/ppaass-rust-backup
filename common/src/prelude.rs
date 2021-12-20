use bytes::{Buf, BufMut, Bytes, BytesMut};

pub use crate::agent::*;
pub use crate::error::*;
use crate::prelude::PpaassAddressType::{Domain, IpV4, IpV6};
pub use crate::proxy::*;

/// The address type in Ppaass common
pub enum PpaassAddressType {
    IpV4,
    IpV6,
    Domain,
}

impl TryFrom<u8> for PpaassAddressType {
    type Error = PpaassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(IpV4),
            2 => Ok(IpV6),
            3 => Ok(Domain),
            _ => Err(PpaassError::FailToParsePpaassAddressType)
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
pub struct PpaassAddress {
    pub host: Vec<u8>,
    pub port: u16,
    pub address_type: PpaassAddressType,
}

impl TryFrom<Vec<u8>> for PpaassAddress {
    type Error = PpaassError;

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
pub enum PpaassMessageBodyEncryptionType {
    Plain,
    Blowfish,
    AES,
}

impl From<PpaassMessageBodyEncryptionType> for u8 {
    fn from(value: PpaassMessageBodyEncryptionType) -> Self {
        match value {
            PpaassMessageBodyEncryptionType::Blowfish => 1,
            PpaassMessageBodyEncryptionType::AES => 2,
            PpaassMessageBodyEncryptionType::Plain => 0
        }
    }
}