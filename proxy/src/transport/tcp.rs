use std::net::SocketAddr;
use std::time::SystemTime;

use anyhow::Context;
use anyhow::Result;
use futures::StreamExt;
use futures_util::SinkExt;
use log::{debug, error};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};
use uuid::Uuid;

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{PpaassAddress, PpaassMessage, PpaassMessageSplitResult, PpaassProxyMessagePayload, PpaassProxyMessagePayloadType};

use crate::error::PpaassProxyError;

type AgentStreamFramed = Framed<TcpStream, PpaassMessageCodec>;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TcpTransportStatus {
    New,
    Initialized,
    Relaying,
    Closing,
    Closed,
}

#[derive(Debug)]
pub struct TcpTransportSnapshot {
    pub id: String,
    pub status: TcpTransportStatus,
    pub agent_read_bytes: usize,
    pub agent_write_bytes: usize,
    pub target_read_bytes: usize,
    pub target_write_bytes: usize,
    pub start_time: u128,
    pub end_time: Option<u128>,
    pub user_token: Option<Vec<u8>>,
    pub agent_remote_address: SocketAddr,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
}

#[derive(Debug)]
pub struct TcpTransport {
    id: String,
    status: TcpTransportStatus,
    agent_read_bytes: usize,
    agent_write_bytes: usize,
    target_read_bytes: usize,
    target_write_bytes: usize,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Option<Vec<u8>>,
    agent_remote_address: SocketAddr,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
    snapshot_sender: Sender<TcpTransportSnapshot>,
}

impl TcpTransport {
    pub fn new(agent_remote_address: SocketAddr, snapshot_sender: Sender<TcpTransportSnapshot>) -> Result<Self> {
        let id = Uuid::new_v4().to_string();
        Ok(Self {
            id,
            status: TcpTransportStatus::New,
            agent_read_bytes: 0,
            agent_write_bytes: 0,
            target_read_bytes: 0,
            target_write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis()
            },
            end_time: None,
            user_token: None,
            agent_remote_address,
            source_address: None,
            target_address: None,
            snapshot_sender,
        })
    }

    /// # Run the transport step by step:
    /// New->Initialized->Relaying->Closing->Closed
    /// * New status: A transport is created with a source edge assigned.
    /// * Initialized status: A transport is initialized with a target edge assigned also.
    /// * Relaying status: A transport start to relay data.
    /// * Closing status: A transport is closing.
    /// * Closed status: A transport is closed.
    pub async fn start(&mut self, agent_stream: TcpStream) -> Result<()> {
        let transport_snapshot = self.take_snapshot();
        self.snapshot_sender.send(transport_snapshot).await?;
        let ppaass_message_codec = PpaassMessageCodec::new("".to_string(), "".to_string());
        let agent_stream_framed = ppaass_message_codec.framed(agent_stream);
        // Initialize the target edge stream
        let init_result = self.init(agent_stream_framed).await?;
        if init_result.is_none() {
            return Ok(());
        }
        let (agent_stream_framed, target_stream) = init_result.context("Fail to unwrap ppaass message from the source edge.")?;
        // Start relay data
        self.relay(agent_stream_framed, target_stream).await?;
        Ok(())
    }

    async fn init(&mut self, mut agent_stream_framed: AgentStreamFramed) -> Result<Option<(AgentStreamFramed, TcpStream)>> {
        if self.status != TcpTransportStatus::New {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::New, self.status).into());
        }
        let init_message = agent_stream_framed.next().await;
        if init_message.is_none() {
            return Ok(None);
        }
        let init_message = init_message.context("Fail to unwrap ppaass message from source edge.")??;
        debug!("Receive agent message: {:#?}", init_message);
        let PpaassMessageSplitResult {
            id: agent_message_id_bytes,
            user_token,
            payload,
            ..
        } = init_message.split();
        let agent_message_id = String::from_utf8(agent_message_id_bytes.clone())?;
        let agent_message_body: PpaassAgentMessagePayload = payload.try_into()?;
        let target_stream: TcpStream;
        match agent_message_body.payload_type() {
            PpaassAgentMessagePayloadType::TcpConnect => {
                let target_address: SocketAddr = agent_message_body.target_address().clone().try_into()?;
                let target_stream_connect_result = TcpStream::connect(target_address).await;
                if let Err(e) = target_stream_connect_result {
                    error!("Fail connect to target, transport: [{}], agent message id: [{}], target address: [{}], because of error: {:#?}", agent_message_id, self.id, target_address, e);
                    let tcp_connect_fail_message_payload = PpaassProxyMessagePayload::new(
                        agent_message_body.source_address().clone(),
                        agent_message_body.target_address().clone(),
                        PpaassProxyMessagePayloadType::TcpConnectFail,
                        vec![],
                    );
                    let tcp_connect_fail_message = PpaassMessage::new_with_random_encryption_type(
                        agent_message_id_bytes.clone(),
                        user_token.clone(),
                        Uuid::new_v4().as_bytes().to_vec(),
                        tcp_connect_fail_message_payload.into(),
                    );
                    agent_stream_framed.send(tcp_connect_fail_message).await?;
                    agent_stream_framed.flush().await?;
                    return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                }
                target_stream = target_stream_connect_result.unwrap();
                let tcp_connect_success_message_payload = PpaassProxyMessagePayload::new(
                    agent_message_body.source_address().clone(),
                    agent_message_body.target_address().clone(),
                    PpaassProxyMessagePayloadType::TcpConnectSuccess,
                    vec![],
                );
                let tcp_connect_success_message = PpaassMessage::new_with_random_encryption_type(
                    agent_message_id_bytes.clone(),
                    user_token.clone(),
                    Uuid::new_v4().as_bytes().to_vec(),
                    tcp_connect_success_message_payload.into(),
                );
                agent_stream_framed.send(tcp_connect_success_message).await?;
                agent_stream_framed.flush().await?;
                self.user_token = Some(user_token.clone());
                self.source_address = Some(agent_message_body.source_address().clone());
                self.target_address = Some(agent_message_body.target_address().clone());
                self.status = TcpTransportStatus::Initialized;
                let transport_snapshot = self.take_snapshot();
                self.snapshot_sender.send(transport_snapshot).await?;
            }
            status => {
                return Err(PpaassProxyError::ReceiveInvalidAgentMessage(
                    agent_message_id,
                    PpaassAgentMessagePayloadType::TcpConnect,
                    *status).into());
            }
        }
        Ok(Some((agent_stream_framed, target_stream)))
    }

    async fn relay(&mut self, mut agent_edge_framed: AgentStreamFramed, target_stream: TcpStream) -> Result<()> {
        if self.status != TcpTransportStatus::Initialized {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::Initialized, self.status).into());
        }
        self.status = TcpTransportStatus::Relaying;
        let transport_snapshot = self.take_snapshot();
        self.snapshot_sender.send(transport_snapshot).await?;
        let user_token = self.user_token.clone().take().context("Can not unwrap user token.")?;
        let user_token_for_target_to_proxy_relay = user_token.clone();
        let source_address = self.source_address.clone().take().context("Can not unwrap source edge address")?;
        let source_address_for_target_to_proxy_relay = source_address.clone();
        let target_address = self.target_address.clone().take().context("Can not unwrap target edge address")?;
        let target_address_for_target_to_proxy_relay = target_address.clone();
        let (mut target_read, mut target_write) = target_stream.into_split();
        let (mut agent_write_part, mut agent_read_part) = agent_edge_framed.split();
        let from_proxy_to_target_relay = tokio::spawn(async move {
            let mut proxy_to_target_write_bytes = 0usize;
            let mut agent_to_proxy_read_bytes = 0usize;
            loop {
                let agent_tcp_data_message = agent_read_part.next().await;
                if agent_tcp_data_message.is_none() {
                    return (agent_to_proxy_read_bytes, proxy_to_target_write_bytes);
                }
                let agent_tcp_data_message = agent_tcp_data_message.unwrap();
                if let Err(e) = agent_tcp_data_message {
                    error!("Fail to decode agent message because of error: {:#?}", e);
                    return (agent_to_proxy_read_bytes, proxy_to_target_write_bytes);
                }
                let agent_tcp_data_message = agent_tcp_data_message.unwrap();
                let PpaassMessageSplitResult {
                    id,
                    payload,
                    ..
                } = agent_tcp_data_message.split();
                let agent_message_payload: Result<PpaassAgentMessagePayload, _> = payload.try_into();
                if let Err(e) = agent_message_payload {
                    error!("Fail to parse agent message payload because of error: {:#?}", e);
                    return (agent_to_proxy_read_bytes, proxy_to_target_write_bytes);
                };
                let agent_message_payload = agent_message_payload.unwrap();
                match target_write.write(agent_message_payload.data().as_slice()).await {
                    Err(e) => {
                        error!("Fail to send agent data from proxy to target because of error: {:#?}", e);
                        return (agent_to_proxy_read_bytes, proxy_to_target_write_bytes);
                    }
                    Ok(n) => {
                        proxy_to_target_write_bytes += n;
                        agent_to_proxy_read_bytes += n;
                    }
                }
                if let Err(e) = target_write.flush().await {
                    error!("Fail to flush agent data from proxy to target because of error: {:#?}", e);
                    return (agent_to_proxy_read_bytes, proxy_to_target_write_bytes);
                }
            }
        });
        let from_target_to_proxy_relay = tokio::spawn(async move {
            let mut target_to_proxy_read_bytes = 0usize;
            let mut proxy_to_agent_write_bytes = 0usize;
            loop {
                let mut target_read_buf = Vec::<u8>::with_capacity(64 * 1024);
                let read_size = match target_read.read_buf(&mut target_read_buf).await {
                    Err(e) => {
                        return (target_to_proxy_read_bytes, proxy_to_agent_write_bytes);
                    }
                    Ok(size) => size
                };
                if read_size == 0 && (target_read_buf.len() == target_read_buf.capacity()) {
                    return (target_to_proxy_read_bytes, proxy_to_agent_write_bytes);
                }
                target_to_proxy_read_bytes += read_size;
                let tcp_data_success_message_payload = PpaassProxyMessagePayload::new(
                    source_address_for_target_to_proxy_relay.clone(),
                    target_address_for_target_to_proxy_relay.clone(),
                    PpaassProxyMessagePayloadType::TcpData,
                    target_read_buf,
                );
                let tcp_data_success_message = PpaassMessage::new_with_random_encryption_type(
                    vec![],
                    user_token_for_target_to_proxy_relay.clone(),
                    Uuid::new_v4().as_bytes().to_vec(),
                    tcp_data_success_message_payload.into(),
                );
                if let Err(e) = agent_write_part.send(tcp_data_success_message).await {
                    error!("Fail to send target data from proxy to client because of error: {:#?}", e);
                    return (target_to_proxy_read_bytes, proxy_to_agent_write_bytes);
                };
                if let Err(e) = agent_write_part.flush().await {
                    error!("Fail to flush target data from proxy to client because of error: {:#?}", e);
                    return (target_to_proxy_read_bytes, proxy_to_agent_write_bytes);
                };
                proxy_to_agent_write_bytes += read_size;
            };
        });
        let (target_to_proxy_read_bytes, proxy_to_agent_write_bytes) = from_target_to_proxy_relay.await?;
        self.target_read_bytes += target_to_proxy_read_bytes;
        self.agent_write_bytes += proxy_to_agent_write_bytes;
        let (agent_to_proxy_read_bytes, proxy_to_target_write_bytes) = from_proxy_to_target_relay.await?;
        self.agent_read_bytes += agent_to_proxy_read_bytes;
        self.target_write_bytes += proxy_to_target_write_bytes;
        let transport_snapshot = self.take_snapshot();
        self.snapshot_sender.send(transport_snapshot).await?;
        Ok(())
    }

    pub async fn close(mut self) -> Result<()> {
        self.status = TcpTransportStatus::Closing;
        self.end_time = {
            Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis())
        };
        self.status = TcpTransportStatus::Closed;
        let transport_snapshot = self.take_snapshot();
        self.snapshot_sender.send(transport_snapshot).await?;
        Ok(())
    }

    pub fn take_snapshot(&self) -> TcpTransportSnapshot {
        TcpTransportSnapshot {
            id: self.id.clone(),
            user_token: self.user_token.clone(),
            status: self.status,
            agent_remote_address: self.agent_remote_address.clone(),
            source_address: self.source_address.clone(),
            target_address: self.target_address.clone(),
            agent_read_bytes: self.agent_read_bytes,
            agent_write_bytes: self.agent_write_bytes,
            target_read_bytes: self.target_read_bytes,
            target_write_bytes: self.target_write_bytes,
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn status(&self) -> TcpTransportStatus {
        self.status
    }
    pub fn agent_read_bytes(&self) -> usize {
        self.agent_read_bytes
    }
    pub fn agent_write_bytes(&self) -> usize {
        self.agent_write_bytes
    }
    pub fn target_read_bytes(&self) -> usize {
        self.target_read_bytes
    }
    pub fn target_write_bytes(&self) -> usize {
        self.target_write_bytes
    }
    pub fn start_time(&self) -> u128 {
        self.start_time
    }
    pub fn end_time(&self) -> Option<u128> {
        self.end_time
    }
    pub fn user_token(&self) -> &Option<Vec<u8>> {
        &self.user_token
    }
    pub fn agent_remote_address(&self) -> SocketAddr {
        self.agent_remote_address
    }
    pub fn source_address(&self) -> &Option<PpaassAddress> {
        &self.source_address
    }
    pub fn target_address(&self) -> &Option<PpaassAddress> {
        &self.target_address
    }
}
