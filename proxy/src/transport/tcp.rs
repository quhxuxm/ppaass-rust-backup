use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

use anyhow::{anyhow, Context};
use anyhow::Result;
use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed, FramedRead};
use uuid::Uuid;

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{PpaassAddressType, PpaassMessageSplitResult};

use crate::error::PpaassProxyError;

type PpaassMessageFramed = Framed<TcpStream, PpaassMessageCodec>;

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum TcpTransportStatus {
    New,
    Initialized,
    Relaying,
    Closing,
    Closed,
}

pub(crate) struct TcpTransport {
    id: String,
    status: TcpTransportStatus,
    source_read_bytes: u128,
    source_write_bytes: u128,
    target_read_bytes: u128,
    target_write_bytes: u128,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Vec<u8>,
    source_edge: Option<TcpStream>,
    target_edge: Option<TcpStream>,
}

impl TcpTransport {
    pub fn new(user_token: Vec<u8>, source_edge: TcpStream) -> Result<Self> {
        let id = Uuid::new_v4().to_string();
        Ok(Self {
            id,
            status: TcpTransportStatus::New,
            source_read_bytes: 0,
            source_write_bytes: 0,
            target_read_bytes: 0,
            target_write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis()
            },
            end_time: None,
            user_token,
            source_edge: Some(source_edge),
            target_edge: None,
        })
    }

    pub fn increase_source_read_bytes(&mut self, increase: u128) {
        self.source_read_bytes += increase;
    }

    pub fn increase_source_write_bytes(&mut self, increase: u128) {
        self.source_write_bytes += increase;
    }

    pub fn increase_target_read_bytes(&mut self, increase: u128) {
        self.target_read_bytes += increase;
    }

    pub fn increase_target_write_bytes(&mut self, increase: u128) {
        self.target_write_bytes += increase;
    }

    /// # Run the transport step by step:
    /// New->Initialized->Relaying->Closing->Closed
    /// * New status: A transport is created with a source edge assigned.
    /// * Initialized status: A transport is initialized with a target edge assigned also.
    /// * Relaying status: A transport start to relay data.
    /// * Closing status: A transport is closing.
    /// * Closed status: A transport is closed.
    pub async fn start(mut self) -> Result<()> {
        let source_edge_stream = self.source_edge.take().context("")?;
        let ppaass_message_codec = PpaassMessageCodec::new("".to_string(), "".to_string());
        let source_edge_framed = ppaass_message_codec.framed(source_edge_stream);
        // Initialize the target edge stream
        let source_edge_framed = self.init(source_edge_framed).await?;
        if source_edge_framed.is_none() {
            return Ok(());
        }
        let source_edge_framed = source_edge_framed.context("Fail to unwrap ppaass message from the source edge.")?;
        // Start relay data
        let source_edge_framed = self.relay(source_edge_framed).await?;
        //Relay complete
        self.close(source_edge_framed).await?;
        Ok(())
    }

    async fn init(&mut self, mut source_edge_framed: PpaassMessageFramed) -> Result<Option<PpaassMessageFramed>> {
        if self.status != TcpTransportStatus::New {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::New, self.status).into());
        }
        let init_message = source_edge_framed.next().await;
        if init_message.is_none() {
            return Ok(None);
        }
        let init_message = init_message.context("Fail to unwrap ppaass message from source edge.")??;
        let PpaassMessageSplitResult {
            id,
            user_token,
            payload_encryption_token,
            payload_encryption_type,
            payload
        } = init_message.split();
        let agent_message_body: PpaassAgentMessagePayload = payload.try_into()?;
        match agent_message_body.payload_type() {
            PpaassAgentMessagePayloadType::TcpConnect => {
                let target_address = agent_message_body.target_address();
                match target_address.address_type() {
                    PpaassAddressType::IpV4 => {
                        let target_socket_addr = SocketAddr::new(target_address.host().parse()?, target_address.port());
                        TcpStream::connect();
                    }
                    PpaassAddressType::IpV6 => {
                        TcpStream::connect();
                    }
                    PpaassAddressType::Domain => {
                        TcpStream::connect();
                    }
                }

            }
            status => {
                let id = String::from_utf8(id)?;
                return Err(PpaassProxyError::ReceiveInvalidAgentMessage(id, PpaassAgentMessagePayloadType::TcpConnect, *status).into());
            }
        }
        self.status = TcpTransportStatus::Initialized;
        Ok(Some(source_edge_framed))
    }

    async fn relay(&mut self, mut source_edge_framed: PpaassMessageFramed) -> Result<PpaassMessageFramed> {
        if self.status != TcpTransportStatus::Initialized {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::Initialized, self.status).into());
        }
        self.status = TcpTransportStatus::Relaying;
        Ok(source_edge_framed)
    }

    async fn close(mut self, mut source_edge_framed: PpaassMessageFramed) -> Result<()> {
        self.status = TcpTransportStatus::Closing;
        self.end_time = {
            Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis())
        };
        if let Some(mut source_edge_stream) = self.source_edge.take() {
            source_edge_stream.shutdown().await?;
        }
        if let Some(mut target_edge_stream) = self.target_edge.take() {
            target_edge_stream.shutdown().await?;
        }
        self.status = TcpTransportStatus::Closed;
        Ok(())
    }
}
