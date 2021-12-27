use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

use ppaass_common::common::PpaassAddress;

use crate::error::PpaassAgentError;

#[derive(Debug, Copy, Clone)]
pub(crate) enum TransportStatus {
    New,
    Authenticated,
    Connected,
    Relaying,
    Closed,
}

pub(crate) struct TransportSnapshot {
    id: String,
    status: TransportStatus,
    client_read_bytes: usize,
    client_write_bytes: usize,
    proxy_read_bytes: usize,
    proxy_write_bytes: usize,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Option<Vec<u8>>,
    client_remote_address: SocketAddr,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
    snapshot_sender: Sender<TransportSnapshot>,
}

#[async_trait]
pub(crate) trait Transport where Self: Send {
    async fn start(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String,
        rsa_private_key: String) -> Result<()>;

    fn take_snapshot(&self) -> TransportSnapshot;
}

pub(crate) struct ProxyAddress {
    host: String,
    port: u16,
}
impl TryFrom<String> for ProxyAddress {
    type Error = PpaassAgentError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let trimmed_proxy_address = value.trim();
        let proxy_address_parts: Vec<&str> = trimmed_proxy_address.split(":").collect();
        if proxy_address_parts.len() != 2 {
            return Err(PpaassAgentError::FailToParseProxyAddress(value));
        }
        let host = proxy_address_parts[0].to_string();
        let port = proxy_address_parts[1].parse::<u16>().map_err(|e| {
            PpaassAgentError::FailToParseProxyAddress(value)
        })?;
        Ok(Self {
            host,
            port,
        })
    }
}

impl From<ProxyAddress> for String {
    fn from(value: ProxyAddress) -> Self {
        format!("{}:{}", value.host, value.port)
    }
}

