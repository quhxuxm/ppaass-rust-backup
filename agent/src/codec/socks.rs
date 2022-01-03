use std::io::{Error, ErrorKind};

use bytes::{Buf, BufMut, BytesMut};
use log::info;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::PpaassAgentError;
use crate::protocol::socks::{
    Socks5AddrType, Socks5AuthMethod, Socks5AuthRequest, Socks5AuthResponse, Socks5ConnectRequest,
    Socks5ConnectRequestType, Socks5ConnectResponse,
};

pub(crate) struct Socks5AuthCodec {
    transport_id: String,
}

impl Socks5AuthCodec {
    pub(crate) fn new(transport_id: String) -> Self {
        Self { transport_id }
    }
}
impl Decoder for Socks5AuthCodec {
    type Item = Socks5AuthRequest;
    type Error = PpaassAgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        info!(
            "Socks5 authenticate command, transport: [{}], command: {:?}",
            self.transport_id,  src.to_vec()
        );
        if src.len() < 2 {
            return Ok(None);
        }
        let version = src.get_u8();
        if version != 5 {
            return Err(PpaassAgentError::FailToDecodeSocks5Protocol);
        }
        let methods_number = src.get_u8();
        let mut methods = Vec::<Socks5AuthMethod>::new();
        for i in 0..methods_number {
            methods.push(Socks5AuthMethod::from(src.get_u8()));
        }
        Ok(Some(Socks5AuthRequest::new(methods_number, methods)))
    }
}

impl Encoder<Socks5AuthResponse> for Socks5AuthCodec {
    type Error = Error;

    fn encode(&mut self, item: Socks5AuthResponse, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.put_u8(item.get_version());
        dst.put_u8(item.get_method().into());
        Ok(())
    }
}

pub(crate) struct Socks5ConnectCodec {
    transport_id: String,
}

impl Socks5ConnectCodec {
    pub(crate) fn new(transport_id: String) -> Self {
        Self { transport_id }
    }
}

impl Decoder for Socks5ConnectCodec {
    type Item = Socks5ConnectRequest;
    type Error = PpaassAgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        info!(
            "Socks5 connect command, transport: [{}], command: {:?}",
            self.transport_id, src.to_vec()
        );
        if src.len() < 4 {
            return Ok(None);
        }
        let version = src.get_u8();
        if version != 5 {
            return Err(PpaassAgentError::FailToDecodeSocks5Protocol);
        }
        let request_type: Socks5ConnectRequestType = src.get_u8().try_into()?;
        src.get_u8();
        let addr_type: Socks5AddrType = src.get_u8().try_into()?;
        let host = match addr_type {
            Socks5AddrType::IpV4 => {
                let mut host_bytes = Vec::<u8>::new();
                for i in 0..4 {
                    host_bytes.push(src.get_u8());
                }
                host_bytes
            }
            Socks5AddrType::IpV6 => {
                let mut host_bytes = Vec::<u8>::new();
                for i in 0..16 {
                    host_bytes.push(src.get_u8());
                }
                host_bytes
            }
            Socks5AddrType::Domain => {
                let domain_name_length = src.get_u8();
                let mut host_bytes = Vec::<u8>::new();
                for i in 0..domain_name_length {
                    host_bytes.push(src.get_u8());
                }
                host_bytes
            }
        };
        let port = src.get_u16();
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
