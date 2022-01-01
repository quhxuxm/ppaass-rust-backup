use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed};

use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::PpaassAddress;

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
        buffer_size: usize,
    ) -> Framed<TcpStream, PpaassMessageCodec> {
        let ppaass_message_codec =
            PpaassMessageCodec::new(rsa_public_key, rsa_private_key, buffer_size);
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

    fn id(&self) -> String;

    async fn close(&mut self) -> Result<()>;
}
