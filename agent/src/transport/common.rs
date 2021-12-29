use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;

use ppaass_common::common::PpaassAddress;

use crate::error::PpaassAgentError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TransportStatus {
    New,
    Authenticated,
    Connected,
    Relaying,
    Closed,
}

#[derive(Debug)]
pub(crate) enum TransportSnapshotType{
    HTTP, SOCKS5
}

#[derive(Debug)]
pub(crate) struct TransportSnapshot {
    pub id: String,
    pub snapshot_type:TransportSnapshotType,
    pub status: TransportStatus,
    pub client_read_bytes: usize,
    pub client_write_bytes: usize,
    pub proxy_read_bytes: usize,
    pub proxy_write_bytes: usize,
    pub start_time: u128,
    pub end_time: Option<u128>,
    pub user_token: Vec<u8>,
    pub client_remote_address: Option<SocketAddr>,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
}

#[async_trait]
pub(crate) trait Transport where Self: Send {
    async fn start(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String,
        rsa_private_key: String) -> Result<()>;

    fn take_snapshot(&self) -> TransportSnapshot;

    fn id(&self) -> String;

    async fn close(&mut self) -> Result<()>;
}

