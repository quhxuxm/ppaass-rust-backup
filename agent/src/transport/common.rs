use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed};

use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::PpaassAddress;
use ppaass_common::generate_uuid;

use crate::config::AGENT_SERVER_CONFIG;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum TransportStatus {
    New,
    Authenticated,
    TcpConnected,
    Relaying,
    Closed,
    UdpAssociated,
}

#[derive(Debug)]
pub(crate) enum TransportSnapshotType {
    HTTP,
    SOCKS5,
}

#[derive(Debug)]
pub(crate) struct TransportMetaInfo {
    pub id: String,
    pub status: TransportStatus,
    pub start_time: i64,
    pub end_time: Option<i64>,
    pub user_token: Vec<u8>,
    pub client_remote_address: Option<SocketAddr>,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
}

impl TransportMetaInfo {
    pub(crate) fn new() -> Result<Self> {
        let user_token = AGENT_SERVER_CONFIG
            .user_token()
            .clone()
            .context("Can not get user token from configuration.")?;
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            start_time: Utc::now().timestamp_millis(),
            end_time: None,
            user_token: user_token.into_bytes(),
            client_remote_address: None,
            source_address: None,
            target_address: None,
        })
    }

    fn split(self) -> TransportMetaInfo {
        TransportMetaInfo { ..self }
    }
}

impl Display for TransportMetaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportMetaInfo")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field(
                "user_token",
                &String::from_utf8(self.user_token.clone()).unwrap_or_else(|e| format!("{:#?}", e)),
            )
            .field("client_remote_address", &self.client_remote_address)
            .field("source_address", &self.source_address)
            .field("target_address", &self.target_address)
            .finish()
    }
}

#[async_trait]
pub(crate) trait Transport
where
    Self: Send,
{
    fn create_proxy_framed(
        rsa_public_key: &'static str,
        rsa_private_key: &'static str,
        proxy_stream: TcpStream,
        max_frame_size: usize,
        compress: bool,
    ) -> Framed<TcpStream, PpaassMessageCodec> {
        let ppaass_message_codec =
            PpaassMessageCodec::new(rsa_public_key, rsa_private_key, max_frame_size, compress);
        ppaass_message_codec.framed(proxy_stream)
    }

    async fn start(&mut self, client_tcp_stream: TcpStream) -> Result<()>;

    async fn close(&mut self) -> Result<()>;
}
