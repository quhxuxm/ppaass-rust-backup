use std::fmt::{Debug, Display, Formatter};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::PpaassAgentError;

#[derive(Debug, Copy, Clone)]
pub(crate) enum Socks5AuthMethod {
    NoAuthenticationRequired,
    GSSAPI,
    UsernameAndPassword,
    IanaAssigned,
    ReservedForPrivateMethods,
    NoAcceptableMethods,
}

impl From<u8> for Socks5AuthMethod {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Socks5AuthMethod::NoAuthenticationRequired,
            0x01 => Socks5AuthMethod::GSSAPI,
            0x02 => Socks5AuthMethod::UsernameAndPassword,
            0x03 => Socks5AuthMethod::IanaAssigned,
            0x80 => Socks5AuthMethod::ReservedForPrivateMethods,
            0xFF => Socks5AuthMethod::NoAcceptableMethods,
            _ => Socks5AuthMethod::NoAuthenticationRequired,
        }
    }
}

impl From<Socks5AuthMethod> for u8 {
    fn from(value: Socks5AuthMethod) -> Self {
        match value {
            Socks5AuthMethod::NoAuthenticationRequired => 0x00,
            Socks5AuthMethod::GSSAPI => 0x01,
            Socks5AuthMethod::UsernameAndPassword => 0x02,
            Socks5AuthMethod::IanaAssigned => 0x03,
            Socks5AuthMethod::ReservedForPrivateMethods => 0x80,
            Socks5AuthMethod::NoAcceptableMethods => 0xFF,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Socks5ConnectRequestType {
    Connect,
    Bind,
    UdpAssociate,
}

impl TryFrom<u8> for Socks5ConnectRequestType {
    type Error = PpaassAgentError;
    fn try_from(v: u8) -> Result<Self, PpaassAgentError> {
        match v {
            0x01 => Ok(Socks5ConnectRequestType::Connect),
            0x02 => Ok(Socks5ConnectRequestType::Bind),
            0x03 => Ok(Socks5ConnectRequestType::UdpAssociate),
            _ => Err(PpaassAgentError::FailToParseSocks5ConnectRequestType(v)),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum Socks5ConnectResponseStatus {
    Succeeded,
    Failure,
    ConnectionNotAllowedByRuleSet,
    NetworkUnReachable,
    HostUnReachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned,
}

impl From<u8> for Socks5ConnectResponseStatus {
    fn from(v: u8) -> Self {
        match v {
            0x00 => Socks5ConnectResponseStatus::Succeeded,
            0x01 => Socks5ConnectResponseStatus::Failure,
            0x02 => Socks5ConnectResponseStatus::ConnectionNotAllowedByRuleSet,
            0x03 => Socks5ConnectResponseStatus::NetworkUnReachable,
            0x04 => Socks5ConnectResponseStatus::HostUnReachable,
            0x05 => Socks5ConnectResponseStatus::ConnectionRefused,
            0x06 => Socks5ConnectResponseStatus::TtlExpired,
            0x07 => Socks5ConnectResponseStatus::CommandNotSupported,
            0x08 => Socks5ConnectResponseStatus::AddressTypeNotSupported,
            0x09 => Socks5ConnectResponseStatus::Unassigned,
            _ => Socks5ConnectResponseStatus::Failure,
        }
    }
}

impl From<Socks5ConnectResponseStatus> for u8 {
    fn from(value: Socks5ConnectResponseStatus) -> Self {
        match value {
            Socks5ConnectResponseStatus::Succeeded => 0x00,
            Socks5ConnectResponseStatus::Failure => 0x01,
            Socks5ConnectResponseStatus::ConnectionNotAllowedByRuleSet => 0x02,
            Socks5ConnectResponseStatus::NetworkUnReachable => 0x03,
            Socks5ConnectResponseStatus::HostUnReachable => 0x04,
            Socks5ConnectResponseStatus::ConnectionRefused => 0x05,
            Socks5ConnectResponseStatus::TtlExpired => 0x06,
            Socks5ConnectResponseStatus::CommandNotSupported => 0x07,
            Socks5ConnectResponseStatus::AddressTypeNotSupported => 0x08,
            Socks5ConnectResponseStatus::Unassigned => 0x09,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Socks5AddrType {
    IpV4,
    IpV6,
    Domain,
}

impl TryFrom<u8> for Socks5AddrType {
    type Error = PpaassAgentError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Socks5AddrType::IpV4),
            0x04 => Ok(Socks5AddrType::IpV6),
            0x03 => Ok(Socks5AddrType::Domain),
            _ => Err(PpaassAgentError::FailToParseSocks5AddrType(v)),
        }
    }
}

impl From<Socks5AddrType> for u8 {
    fn from(value: Socks5AddrType) -> Self {
        match value {
            Socks5AddrType::IpV4 => 0x01,
            Socks5AddrType::IpV6 => 0x04,
            Socks5AddrType::Domain => 0x03,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Socks5AuthRequest {
    version: u8,
    method_number: u8,
    methods: Vec<Socks5AuthMethod>,
}

impl Socks5AuthRequest {
    pub fn new(method_number: u8, methods: Vec<Socks5AuthMethod>) -> Self {
        Socks5AuthRequest {
            version: 5,
            method_number,
            methods,
        }
    }
    pub fn get_version(&self) -> u8 {
        self.version
    }
    pub fn get_method_number(&self) -> u8 {
        self.method_number
    }
    pub fn get_methods(&self) -> &Vec<Socks5AuthMethod> {
        &self.methods
    }
}

#[derive(Debug)]
pub(crate) struct Socks5AuthResponse {
    version: u8,
    method: Socks5AuthMethod,
}

impl Socks5AuthResponse {
    pub fn new(method: Socks5AuthMethod) -> Self {
        Socks5AuthResponse {
            version: 5u8,
            method,
        }
    }
    pub fn get_version(&self) -> u8 {
        self.version
    }
    pub fn get_method(&self) -> Socks5AuthMethod {
        self.method
    }
}

#[derive(Debug)]
pub(crate) struct Socks5ConnectRequest {
    version: u8,
    request_type: Socks5ConnectRequestType,
    addr_type: Socks5AddrType,
    dst_host: Vec<u8>,
    dst_port: u16,
}

impl Socks5ConnectRequest {
    pub fn new(
        request_type: Socks5ConnectRequestType,
        addr_type: Socks5AddrType,
        dst_host: Vec<u8>,
        dst_port: u16,
    ) -> Self {
        Socks5ConnectRequest {
            version: 5,
            request_type,
            addr_type,
            dst_host,
            dst_port,
        }
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn request_type(&self) -> Socks5ConnectRequestType {
        self.request_type
    }
    pub fn addr_type(&self) -> Socks5AddrType {
        self.addr_type
    }

    pub fn dst_host(&self) -> &Vec<u8> {
        &self.dst_host
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
}

#[derive(Debug)]
pub(crate) struct Socks5ConnectResponse {
    version: u8,
    status: Socks5ConnectResponseStatus,
    addr_type: Option<Socks5AddrType>,
    bind_host: Option<Vec<u8>>,
    bind_port: Option<u16>,
}

impl Socks5ConnectResponse {
    pub fn new(
        status: Socks5ConnectResponseStatus,
        addr_type: Socks5AddrType,
        bind_host: Vec<u8>,
        bind_port: u16,
    ) -> Self {
        Socks5ConnectResponse {
            version: 5,
            status,
            addr_type: Some(addr_type),
            bind_host: Some(bind_host),
            bind_port: Some(bind_port),
        }
    }

    pub fn new_status_only(status: Socks5ConnectResponseStatus) -> Self {
        Socks5ConnectResponse {
            version: 5,
            status,
            addr_type: None,
            bind_host: None,
            bind_port: None,
        }
    }

    pub fn get_version(&self) -> u8 {
        self.version
    }
    pub fn get_status(&self) -> Socks5ConnectResponseStatus {
        self.status
    }
    pub fn get_addr_type(&self) -> Option<Socks5AddrType> {
        self.addr_type
    }

    pub fn get_bind_host(&self) -> Option<&Vec<u8>> {
        self.bind_host.as_ref()
    }

    pub fn get_bind_port(&self) -> Option<u16> {
        self.bind_port
    }
}

#[derive(Debug)]
pub(crate) struct Socks5UdpDataRequest {
    frag: u8,
    addr_type: Socks5AddrType,
    dst_addr: Vec<u8>,
    dst_port: u16,
    data: Vec<u8>,
}

impl Socks5UdpDataRequest {
    pub fn frag(&self) -> u8 {
        self.frag
    }

    pub fn addr_type(&self) -> Socks5AddrType {
        self.addr_type
    }

    pub fn dst_addr(&self) -> &Vec<u8> {
        &self.dst_addr
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn from(bytes: Vec<u8>) -> Result<Self, PpaassAgentError> {
        let mut bytes_obj = Bytes::from(bytes);
        bytes_obj.get_u16();
        let frag = bytes_obj.get_u8();
        let addr_type_u8 = bytes_obj.get_u8();
        let addr_type: Socks5AddrType = addr_type_u8.try_into()?;
        let host = match addr_type {
            Socks5AddrType::IpV4 => {
                let mut ipv4_addr = Vec::new();
                (0..4).for_each(|i| {
                    ipv4_addr.push(bytes_obj.get_u8());
                });
                ipv4_addr
            }
            Socks5AddrType::IpV6 => {
                let mut ipv6_addr = Vec::new();
                (0..16).for_each(|i| {
                    ipv6_addr.push(bytes_obj.get_u8());
                });
                ipv6_addr
            }
            Socks5AddrType::Domain => {
                let domain_name_length = bytes_obj.get_u8();
                let mut domain_name = Vec::new();
                (0..domain_name_length).for_each(|i| {
                    domain_name.push(bytes_obj.get_u8());
                });
                domain_name
            }
        };
        let port = bytes_obj.get_u16();
        let data = bytes_obj.chunk().to_vec();
        Ok(Self {
            frag,
            addr_type,
            dst_addr: host,
            dst_port: port,
            data,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Socks5UdpDataResponse {
    frag: u8,
    addr_type: Socks5AddrType,
    dst_addr: Vec<u8>,
    dst_port: u16,
    data: Vec<u8>,
}

impl Socks5UdpDataResponse {
    pub fn new(
        frag: u8,
        addr_type: Socks5AddrType,
        dst_addr: Vec<u8>,
        dst_port: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            frag,
            addr_type,
            dst_addr,
            dst_port,
            data,
        }
    }
}

impl Into<Vec<u8>> for Socks5UdpDataResponse {
    fn into(self) -> Vec<u8> {
        let mut result = BytesMut::new();
        result.put_u16(0);
        result.put_u8(self.frag);
        match self.addr_type {
            Socks5AddrType::IpV4 => {
                result.put_u8(Socks5AddrType::IpV4.into());
                for i in 0..4 {
                    result.put_u8(self.dst_addr[i]);
                }
            }
            Socks5AddrType::IpV6 => {
                result.put_u8(Socks5AddrType::IpV6.into());
                for i in 0..16 {
                    result.put_u8(self.dst_addr[i]);
                }
            }
            Socks5AddrType::Domain => {
                result.put_u8(Socks5AddrType::Domain.into());
                result.put_u8(self.dst_addr.len() as u8);
                result.put_slice(self.dst_addr.as_slice());
            }
        }
        result.put_u16(self.dst_port);
        result.put_slice(self.data.as_slice());
        result.to_vec()
    }
}
