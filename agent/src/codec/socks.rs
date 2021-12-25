use std::io::{Error, ErrorKind};

use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::PpaassAgentError;
use crate::protocol::socks::{Socks5AddrType, Socks5AuthMethod, Socks5AuthRequest, Socks5AuthResponse, Socks5ConnectRequest, Socks5ConnectRequestType, Socks5ConnectResponse};
use crate::protocol::socks::message::{
    Socks5AddrType, Socks5AuthMethod, Socks5AuthRequest, Socks5AuthResponse, Socks5ConnectRequest,
    Socks5ConnectRequestType, Socks5ConnectResponse,
};

pub struct Socks5AuthCodec {}

impl Default for Socks5AuthCodec {
    fn default() -> Self {
        Socks5AuthCodec {}
    }
}

impl Decoder for Socks5AuthCodec {
    type Item = Socks5AuthRequest;
    type Error = PpaassAgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let version = src[0];
        if version != 5 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Fail to decode socks 5 authenticate command as the version is not 5.",
            ));
        }
        let methods_number = src[1];
        if methods_number as usize <= 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Fail to decode socks 5 authenticate command as the methods number is invalid.",
            ));
        }
        if src.len() < (2 + methods_number) as usize {
            return Ok(None);
        }
        let mut methods = Vec::<Socks5AuthMethod>::new();
        (0..methods_number).for_each(|i| {
            let method_byte = src[(2 + i) as usize];
            methods.push(Socks5AuthMethod::from(method_byte));
        });
        Ok(Some(Socks5AuthRequest::new(methods_number, methods)))
    }
}

impl Encoder<Socks5AuthResponse> for Socks5AuthCodec {
    type Error = Error;

    fn encode(&mut self, item: Socks5AuthResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.get_version());
        dst.put_u8(item.get_method().into());
        return Ok(());
    }
}

pub struct Socks5ConnectCodec {}

impl Default for Socks5ConnectCodec {
    fn default() -> Self {
        Socks5ConnectCodec {}
    }
}

impl Decoder for Socks5ConnectCodec {
    type Item = Socks5ConnectRequest;
    type Error = PpaassAgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let version = src[0];
        if version != 5 {
            return Err(anyhow!(
                "Can not decode incoming socks command because of the version is not 5"
            )
                .into());
        }
        let request_type: Socks5ConnectRequestType = src[1].try_into()?;
        let addr_type: Socks5AddrType = src[3].try_into()?;
        let mut host_bytes_number = 0usize;
        let host = match addr_type {
            Socks5AddrType::IpV4 => {
                host_bytes_number = 4;
                if src.len() < 4 + host_bytes_number {
                    return Ok(None);
                }
                let mut ipv4_addr = Vec::new();
                (0..host_bytes_number).for_each(|i| {
                    ipv4_addr.push(src[4 + i]);
                });
                ipv4_addr
            }
            Socks5AddrType::IpV6 => {
                host_bytes_number = 16;
                if src.len() < 4 + host_bytes_number {
                    return Ok(None);
                }
                let mut ipv6_addr = Vec::new();
                (0..host_bytes_number).for_each(|i| {
                    ipv6_addr.push(src[4 + i]);
                });
                ipv6_addr
            }
            Socks5AddrType::Domain => {
                if src.len() < 4 + 1 {
                    return Ok(None);
                }
                let domain_name_length = src[4];
                host_bytes_number = (domain_name_length as usize);
                if src.len() < 4 + 1 + host_bytes_number {
                    return Ok(None);
                }
                let mut domain_name = Vec::new();
                (0..host_bytes_number).for_each(|i| {
                    domain_name.push(src[5 + i]);
                });
                host_bytes_number = host_bytes_number + 1;
                domain_name
            }
        };
        if src.len() < 4 + host_bytes_number + 2 {
            return Ok(None);
        }
        let port_bytes: [u8; 2] = [src[4 + host_bytes_number], src[4 + host_bytes_number + 1]];
        let port = u16::from_be_bytes(port_bytes);
        if port as usize <= 0 {
            return Err(
                anyhow!("Fail to decode socks 5 connect command as port is invalid.",).into(),
            );
        }
        Ok(Some(Socks5ConnectRequest::new(
            request_type,
            addr_type,
            host,
            port,
        )))
    }
}

impl Encoder<Socks5ConnectResponse> for Socks5ConnectCodec {
    type Error = PpaassAgentError;

    fn encode(
        &mut self,
        item: Socks5ConnectResponse,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.put_u8(item.get_version());
        dst.put_u8(item.get_status().into());
        dst.put_u8(0);
        if item.get_addr_type() == None {
            return Ok(());
        }
        dst.put_u8(item.get_addr_type().unwrap().into());
        if item.get_bind_host().is_none() {
            return Ok(());
        }
        if item.get_addr_type().unwrap() == Socks5AddrType::Domain {
            dst.put_u8(item.get_bind_host().as_ref().unwrap().len() as u8);
        }
        dst.put_slice(item.get_bind_host().as_ref().unwrap().as_slice());
        if item.get_bind_port().is_none() {
            return Ok(());
        }
        dst.put_u16(item.get_bind_port().unwrap());
        Ok(())
    }
}
