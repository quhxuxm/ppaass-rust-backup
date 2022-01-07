use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};

use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::PpaassAddress;
use ppaass_common::generate_uuid;

use crate::config::AgentConfiguration;

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
    pub start_time: u128,
    pub end_time: Option<u128>,
    pub user_token: Vec<u8>,
    pub client_remote_address: Option<SocketAddr>,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
    pub snapshot_sender: Sender<TransportSnapshot>,
    pub configuration: Arc<AgentConfiguration>,
}

impl TransportMetaInfo {
    pub(crate) fn new(
        configuration: Arc<AgentConfiguration>,
        snapshot_sender: Sender<TransportSnapshot>,
    ) -> Result<Self> {
        let user_token = configuration
            .user_token()
            .clone()
            .context("Can not get user token from configuration.")?;
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            start_time: {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_millis()
            },
            end_time: None,
            user_token: user_token.into_bytes(),
            client_remote_address: None,
            source_address: None,
            target_address: None,
            snapshot_sender,
            configuration,
        })
    }

    fn split(self) -> TransportMetaInfo {
        TransportMetaInfo { ..self }
    }
}

impl Display for TransportMetaInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub(crate) struct TransportSnapshot {
    pub id: String,
    pub snapshot_type: TransportSnapshotType,
    pub status: TransportStatus,
    pub start_time: u128,
    pub end_time: Option<u128>,
    pub user_token: Vec<u8>,
    pub client_remote_address: Option<SocketAddr>,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
}

#[async_trait]
pub(crate) trait Transport
where
    Self: Send,
{
    fn create_proxy_framed(
        rsa_public_key: String,
        rsa_private_key: String,
        proxy_stream: TcpStream,
        max_frame_size: usize,
        compress: bool,
    ) -> Framed<TcpStream, PpaassMessageCodec> {
        let ppaass_message_codec =
            PpaassMessageCodec::new(rsa_public_key, rsa_private_key, max_frame_size, compress);
        let mut proxy_framed = ppaass_message_codec.framed(proxy_stream);
        proxy_framed
    }

    async fn start(
        &mut self,
        client_tcp_stream: TcpStream,
        rsa_public_key: String,
        rsa_private_key: String,
    ) -> Result<()>;

    fn take_snapshot(&self) -> TransportSnapshot;
    async fn close(&mut self) -> Result<()>;
}
