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

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        let address_type_byte = value.pop().ok_or(PpaassError::FailToParsePpaassAddressType)?;
        let address_type = PpaassAddressType::try_from(address_type_byte)?;
        match address_type {
            IpV4 => {
                let mut host = Vec::<u8>::new();
                for i in 0..4 {
                    host.push(value.pop().ok_or(PpaassError::FailToParsePpaassIpv4Address)?);
                }
                let port = u16::from_le_bytes([value.pop().ok_or(PpaassError::FailToParsePpaassIpv4Address)?,
                    value.pop().ok_or(PpaassError::FailToParsePpaassIpv4Address)?]);
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
                    host.push(value.pop().ok_or(PpaassError::FailToParsePpaassIpv6Address)?);
                }
                let port = u16::from_le_bytes([value.pop().ok_or(PpaassError::FailToParsePpaassIpv6Address)?,
                    value.pop().ok_or(PpaassError::FailToParsePpaassIpv6Address)?]);
                Ok(
                    Self {
                        host,
                        port,
                        address_type,
                    })
            }
            Domain => {
                let domain_name_length = value.pop().ok_or(PpaassError::FailToParsePpaassDomainAddress)?;
                let mut host = Vec::<u8>::new();
                for i in 0..domain_name_length {
                    host.push(value.pop().ok_or(PpaassError::FailToParsePpaassDomainAddress)?);
                }
                let port = u16::from_le_bytes([value.pop().ok_or(PpaassError::FailToParsePpaassDomainAddress)?,
                    value.pop().ok_or(PpaassError::FailToParsePpaassDomainAddress)?]);
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
        let mut result = Vec::<u8>::new();
        match address.address_type {
            IpV4 => {
                result.push(IpV4.into());
                result.extend(address.host);
                result.extend(address.port.to_le_bytes());
                result
            }
            IpV6 => {
                result.push(IpV6.into());
                result.extend(address.host);
                result.extend(address.port.to_le_bytes());
                result
            }
            Domain => {
                result.push(Domain.into());
                let domain_name_length = address.host.len();
                result.push(domain_name_length as u8);
                result.extend(address.host);
                result.extend(address.port.to_le_bytes());
                result
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