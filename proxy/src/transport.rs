use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use anyhow::Result;
use bytes::BufMut;
use futures::StreamExt;
use futures_util::SinkExt;
use log::{debug, error, info};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::Sender;
use tokio_util::codec::Framed;

use ppaass_common::agent::{
    PpaassAgentMessagePayload, PpaassAgentMessagePayloadSplitResult, PpaassAgentMessagePayloadType,
};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{
    PpaassAddress, PpaassAddressType, PpaassMessage, PpaassMessageSplitResult,
    PpaassProxyMessagePayload, PpaassProxyMessagePayloadType,
};
use ppaass_common::generate_uuid;

use crate::config::{
    ProxyConfiguration, DEFAULT_TCP_BUFFER_SIZE, DEFAULT_TCP_MAX_FRAME_SIZE,
    DEFAULT_UDP_BUFFER_SIZE,
};
use crate::error::PpaassProxyError;

type AgentStreamFramed = Framed<TcpStream, PpaassMessageCodec>;
const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];

#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum TransportStatus {
    New,
    Initialized,
    Relaying,
    Closed,
}

#[derive(Debug)]
pub(crate) struct TransportSnapshot {
    pub id: String,
    pub status: TransportStatus,
    pub start_time: u128,
    pub end_time: Option<u128>,
    pub user_token: Option<Vec<u8>>,
    pub agent_remote_address: SocketAddr,
    pub source_address: Option<PpaassAddress>,
    pub target_address: Option<PpaassAddress>,
}

#[derive(Debug)]
pub(crate) struct Transport {
    id: String,
    status: TransportStatus,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Option<Vec<u8>>,
    agent_remote_address: SocketAddr,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
    snapshot_sender: Sender<TransportSnapshot>,
    configuration: Arc<ProxyConfiguration>,
}

struct InitResult {
    agent_stream_framed: AgentStreamFramed,
    target_tcp_stream: Option<TcpStream>,
    target_udp_socket: Option<UdpSocket>,
}

impl Transport {
    pub fn new(
        agent_remote_address: SocketAddr,
        snapshot_sender: Sender<TransportSnapshot>,
        configuration: Arc<ProxyConfiguration>,
    ) -> Result<Self> {
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            start_time: {
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_millis()
            },
            end_time: None,
            user_token: None,
            agent_remote_address,
            source_address: None,
            target_address: None,
            snapshot_sender,
            configuration,
        })
    }

    async fn publish_transport_snapshot(&self) -> Result<()> {
        let transport_snapshot = self.take_snapshot();
        //        self.snapshot_sender.send(transport_snapshot).await?;
        Ok(())
    }

    /// # Run the transport step by step:
    /// New->Initialized->Relaying->Closing->Closed
    /// * New status: A transport is created with a source edge assigned.
    /// * Initialized status: A transport is initialized with a target edge assigned also.
    /// * Relaying status: A transport start to relay data.
    /// * Closing status: A transport is closing.
    /// * Closed status: A transport is closed.
    pub async fn start(
        &mut self,
        agent_stream: TcpStream,
        rsa_public_key: impl Into<String>,
        rsa_private_key: impl Into<String>,
    ) -> Result<()> {
        self.publish_transport_snapshot().await?;
        let ppaass_message_codec = PpaassMessageCodec::new(
            rsa_public_key.into(),
            rsa_private_key.into(),
            self.configuration
                .max_frame_size()
                .unwrap_or(DEFAULT_TCP_MAX_FRAME_SIZE),
        );
        let agent_stream_framed = Framed::with_capacity(
            agent_stream,
            ppaass_message_codec,
            self.configuration
                .buffer_size()
                .unwrap_or(DEFAULT_TCP_BUFFER_SIZE),
        );
        // Initialize the target edge stream
        let init_result = self.init(agent_stream_framed).await?;
        if init_result.is_none() {
            return Ok(());
        }
        let InitResult {
            agent_stream_framed,
            target_tcp_stream,
            target_udp_socket,
        } = init_result.context("Fail to unwrap init result.")?;
        // Start relay data
        match target_udp_socket {
            None => match target_tcp_stream {
                None => {
                    return Err(PpaassProxyError::UnknownError.into());
                }
                Some(target_tcp_stream) => {
                    self.tcp_relay(agent_stream_framed, target_tcp_stream)
                        .await?;
                }
            },
            Some(target_udp_socket) => {
                self.udp_relay(agent_stream_framed, target_udp_socket)
                    .await?;
            }
        }
        Ok(())
    }

    async fn init(
        &mut self,
        mut agent_stream_framed: AgentStreamFramed,
    ) -> Result<Option<InitResult>> {
        if self.status != TransportStatus::New {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(
                self.id.clone(),
                TransportStatus::New,
                self.status,
            )
            .into());
        }
        let init_message = agent_stream_framed.next().await;
        if init_message.is_none() {
            return Ok(None);
        }
        let init_message =
            init_message.context("Fail to unwrap ppaass message from source edge.")??;
        debug!("Receive agent message: {:#?}", init_message);
        let PpaassMessageSplitResult {
            id: agent_message_id,
            user_token,
            payload,
            ..
        } = init_message.split();
        let agent_message_body: PpaassAgentMessagePayload = payload.try_into()?;
        let PpaassAgentMessagePayloadSplitResult {
            source_address: agent_message_source_address,
            /// The target address
                target_address: agent_message_target_address,
            /// The payload type
                payload_type: agent_message_payload_type,
            /// The data
                data: agent_message_data,
        } = agent_message_body.split();
        let target_tcp_stream: TcpStream;
        return match agent_message_payload_type {
            PpaassAgentMessagePayloadType::TcpConnect => {
                let target_socket_address: SocketAddr =
                    agent_message_target_address.clone().try_into()?;
                let target_stream_connect_result = TcpStream::connect(target_socket_address).await;
                if let Err(e) = target_stream_connect_result {
                    error!("Fail connect to target, transport: [{}], agent message id: [{}], target address: [{}], because of error: {:#?}", agent_message_id, self.id, target_socket_address, e);
                    let tcp_connect_fail_message_payload = PpaassProxyMessagePayload::new(
                        agent_message_source_address.clone(),
                        agent_message_target_address.clone(),
                        PpaassProxyMessagePayloadType::TcpConnectFail,
                        vec![],
                    );
                    let tcp_connect_fail_message = PpaassMessage::new_with_random_encryption_type(
                        agent_message_id.clone(),
                        user_token.clone(),
                        generate_uuid().as_bytes().to_vec(),
                        tcp_connect_fail_message_payload.into(),
                    );
                    if let Err(ppaass_error) =
                        agent_stream_framed.send(tcp_connect_fail_message).await
                    {
                        error!("Fail to send connect fail message to agent because of error, transport: [{}], error: {:#?}", self.id, ppaass_error);
                        return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                    }
                    if let Err(unknwon_error) = agent_stream_framed.flush().await {
                        error!("Fail to send connect fail message to agent because of error, transport: [{}], error: {:#?}", self.id, unknwon_error);
                        return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                    }
                    return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                }
                target_tcp_stream = target_stream_connect_result.unwrap();
                let tcp_connect_success_message_payload = PpaassProxyMessagePayload::new(
                    agent_message_source_address.clone(),
                    agent_message_target_address.clone(),
                    PpaassProxyMessagePayloadType::TcpConnectSuccess,
                    vec![],
                );
                let tcp_connect_success_message = PpaassMessage::new_with_random_encryption_type(
                    agent_message_id.clone(),
                    user_token.clone(),
                    generate_uuid().as_bytes().to_vec(),
                    tcp_connect_success_message_payload.into(),
                );
                if let Err(ppaass_error) =
                    agent_stream_framed.send(tcp_connect_success_message).await
                {
                    error!("Fail to send connect success message to agent because of error, transport: [{}], error: {:#?}", self.id, ppaass_error);
                    return Err(PpaassProxyError::UnknownError.into());
                }
                if let Err(unknwon_error) = agent_stream_framed.flush().await {
                    error!("Fail to send connect success message to agent because of error, transport: [{}], error: {:#?}", self.id, unknwon_error);
                    return Err(PpaassProxyError::UnknownError.into());
                }
                self.user_token = Some(user_token.clone());
                self.source_address = Some(agent_message_source_address.clone());
                self.target_address = Some(agent_message_target_address.clone());
                self.status = TransportStatus::Initialized;
                self.publish_transport_snapshot().await?;
                Ok(Some(InitResult {
                    agent_stream_framed,
                    target_tcp_stream: Some(target_tcp_stream),
                    target_udp_socket: None,
                }))
            }
            PpaassAgentMessagePayloadType::UdpAssociate => {
                let local_ip = IpAddr::from(LOCAL_ADDRESS);
                let udp_address = SocketAddr::new(local_ip, 0);
                let target_udp_socket = UdpSocket::bind(udp_address).await?;
                let udp_bind_address = target_udp_socket.local_addr()?;
                let udp_bind_port = udp_bind_address.port();
                let udp_associate_success_message_payload = PpaassProxyMessagePayload::new(
                    agent_message_source_address.clone(),
                    //For udp associate the target address is useless, just return a fake one
                    PpaassAddress::new(vec![0, 0, 0, 0], 0, PpaassAddressType::IpV4),
                    PpaassProxyMessagePayloadType::UdpAssociateSuccess,
                    vec![],
                );
                let udp_associate_success_message = PpaassMessage::new_with_random_encryption_type(
                    agent_message_id.clone(),
                    user_token.clone(),
                    generate_uuid().as_bytes().to_vec(),
                    udp_associate_success_message_payload.into(),
                );
                if let Err(ppaass_error) = agent_stream_framed
                    .send(udp_associate_success_message)
                    .await
                {
                    error!("Fail to send udp associate success message to agent because of error, transport: [{}], error: {:#?}", self.id, ppaass_error);
                    return Err(PpaassProxyError::UnknownError.into());
                }
                if let Err(unknwon_error) = agent_stream_framed.flush().await {
                    error!("Fail to send udp associate success message to agent because of error, transport: [{}], error: {:#?}", self.id, unknwon_error);
                    return Err(PpaassProxyError::UnknownError.into());
                }
                self.user_token = Some(user_token.clone());
                self.source_address = Some(agent_message_source_address.clone());
                self.target_address = Some(agent_message_target_address.clone());
                self.status = TransportStatus::Initialized;
                Ok(Some(InitResult {
                    agent_stream_framed,
                    target_tcp_stream: None,
                    target_udp_socket: Some(target_udp_socket),
                }))
            }
            status => Err(PpaassProxyError::ReceiveInvalidAgentMessage(
                agent_message_id,
                PpaassAgentMessagePayloadType::TcpConnect,
                status,
            )
            .into()),
        };
    }

    async fn udp_relay(
        &mut self,
        agent_stream_framed: AgentStreamFramed,
        target_udp_socket: UdpSocket,
    ) -> Result<()> {
        if self.status != TransportStatus::Initialized {
            return Err(PpaassProxyError::InvalidUdpTransportStatus(
                self.id.clone(),
                TransportStatus::Initialized,
                self.status,
            )
            .into());
        }
        let transport_id_for_target_to_proxy_relay = self.id.clone();
        let transport_id_for_proxy_to_target_relay = self.id.clone();
        let user_token = self
            .user_token
            .as_ref()
            .context("Fail to unwrap user token")?
            .clone();
        let user_token_for_target_to_proxy_relay = user_token.clone();
        let (mut agent_write_part, mut agent_read_part) = agent_stream_framed.split();
        let target_udp_socket = Arc::new(target_udp_socket);
        let target_udp_socket_for_proxy_to_target_relay = target_udp_socket.clone();
        let target_udp_socket_for_target_to_proxy_relay = target_udp_socket.clone();
        let proxy_to_target_relay = tokio::spawn(async move {
            loop {
                let agent_udp_data_message = agent_read_part.next().await;
                if agent_udp_data_message.is_none() {
                    info!(
                        "Nothing to read from agent, tcp transport: [{}]",
                        transport_id_for_proxy_to_target_relay
                    );
                    continue;
                }
                let agent_udp_data_message = agent_udp_data_message.unwrap();
                if let Err(e) = agent_udp_data_message {
                    error!("Fail to decode agent udp message because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                    return;
                }
                let agent_udp_data_message = agent_udp_data_message.unwrap();
                let PpaassMessageSplitResult {
                    id: agent_message_id,
                    payload: agent_message_payload_bytes,
                    ..
                } = agent_udp_data_message.split();
                let agent_message_payload: Result<PpaassAgentMessagePayload, _> =
                    agent_message_payload_bytes.try_into();
                if let Err(e) = agent_message_payload {
                    error!("Fail to decode agent message payload because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                    continue;
                }
                let agent_message_payload = agent_message_payload.unwrap();
                let PpaassAgentMessagePayloadSplitResult {
                    payload_type: agent_message_payload_type,
                    data: agent_message_payload_data,
                    source_address: agent_message_source_address,
                    target_address: agent_message_target_address,
                } = agent_message_payload.split();
                match agent_message_payload_type {
                    PpaassAgentMessagePayloadType::UdpData => {
                        let target_udp_socket_address: Result<SocketAddr, _> =
                            agent_message_target_address.try_into();

                        let target_udp_socket_address = match target_udp_socket_address {
                            Err(e) => {
                                error!("Fail to parse target udp socket address because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                                continue;
                            }
                            Ok(r) => r,
                        };

                        if let Err(e) = target_udp_socket_for_proxy_to_target_relay
                            .send_to(
                                agent_message_payload_data.as_slice(),
                                target_udp_socket_address,
                            )
                            .await
                        {
                            error!("Fail to send udp data to target because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                            continue;
                        }
                    }
                    _ => {
                        error!("Fail to send udp data to target because of invalid message payload type, transport: [{}]",transport_id_for_proxy_to_target_relay);
                        continue;
                    }
                }
            }
        });
        let target_to_proxy_buffer_size = self
            .configuration
            .buffer_size()
            .unwrap_or(DEFAULT_TCP_BUFFER_SIZE);
        let source_address_for_target_to_proxy_relay = match self.source_address.clone().take() {
            None => return Ok(()),
            Some(r) => r,
        };
        let target_to_proxy_relay = tokio::spawn(async move {
            loop {
                let source_address_for_target_to_proxy_relay =
                    source_address_for_target_to_proxy_relay.clone();
                let mut buf = [0u8; DEFAULT_UDP_BUFFER_SIZE];
                let udp_relay_recv_result = target_udp_socket_for_target_to_proxy_relay
                    .recv_from(&mut buf)
                    .await;
                if let Err(e) = udp_relay_recv_result {
                    error!("Fail to receive udp message from target because of error, transport: [{}], error: {:#?}", transport_id_for_target_to_proxy_relay, e);
                    continue;
                }
                let udp_relay_recv_result = udp_relay_recv_result.unwrap();
                let (data_size, target_origin_address) = udp_relay_recv_result;
                let udp_data_diagram = buf[..data_size].to_vec();
                let target_address: PpaassAddress = target_origin_address.into();
                let udp_data_message_payload = PpaassProxyMessagePayload::new(
                    //For udp data the source address is the client address to accept the udp package
                    source_address_for_target_to_proxy_relay,
                    target_address,
                    PpaassProxyMessagePayloadType::UdpData,
                    udp_data_diagram,
                );
                let udp_data_message = PpaassMessage::new_with_random_encryption_type(
                    "".to_string(),
                    user_token_for_target_to_proxy_relay.clone(),
                    generate_uuid().as_bytes().to_vec(),
                    udp_data_message_payload.into(),
                );
                if let Err(e) = agent_write_part.send(udp_data_message).await {
                    continue;
                }
                if let Err(e) = agent_write_part.flush().await {
                    continue;
                }
            }
        });
        proxy_to_target_relay.await?;
        target_to_proxy_relay.await?;
        Ok(())
    }

    async fn tcp_relay(
        &mut self,
        agent_stream_framed: AgentStreamFramed,
        target_tcp_stream: TcpStream,
    ) -> Result<()> {
        if self.status != TransportStatus::Initialized {
            error!("Invalid tcp transport status, tcp transport: [{}], current status: [{:?}], expect status: [{:?}]", self.id,
            self.status, TransportStatus::Initialized);
            return Err(PpaassProxyError::InvalidTcpTransportStatus(
                self.id.clone(),
                TransportStatus::Initialized,
                self.status,
            )
            .into());
        }
        self.status = TransportStatus::Relaying;
        self.publish_transport_snapshot().await?;
        let user_token = self
            .user_token
            .as_ref()
            .context("Fail to unwrap user token")?
            .clone();
        let user_token_for_target_to_proxy_relay = user_token.clone();
        let source_address = self
            .source_address
            .clone()
            .take()
            .context("Can not unwrap source edge address")?;
        let source_address_for_target_to_proxy_relay = source_address.clone();
        let target_address = self
            .target_address
            .clone()
            .take()
            .context("Can not unwrap target edge address")?;
        let target_address_for_target_to_proxy_relay = target_address.clone();
        let (mut target_read, mut target_write) = target_tcp_stream.into_split();
        let (mut agent_write_part, mut agent_read_part) = agent_stream_framed.split();
        let transport_id_for_target_to_proxy_relay = self.id.clone();
        let transport_id_for_proxy_to_target_relay = self.id.clone();
        let proxy_to_target_relay = tokio::spawn(async move {
            loop {
                info!(
                    "Begin to loop for tcp relay from proxy to target for tcp transport: [{}]",
                    transport_id_for_proxy_to_target_relay
                );
                let agent_tcp_data_message = agent_read_part.next().await;
                let agent_tcp_data_message = match agent_tcp_data_message {
                    None => {
                        info!(
                            "Nothing to read from agent, tcp transport: [{}]",
                            transport_id_for_proxy_to_target_relay
                        );
                        return;
                    }
                    Some(result) => match result {
                        Err(e) => {
                            error!("Fail to decode agent tcp message because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                            return;
                        }
                        Ok(r) => r,
                    },
                };
                let PpaassMessageSplitResult {
                    id: agent_message_id,
                    payload: agent_message_payload,
                    ..
                } = agent_tcp_data_message.split();
                let agent_message_payload: PpaassAgentMessagePayload = match agent_message_payload
                    .try_into()
                {
                    Err(e) => {
                        error!("Fail to parse agent message payload because of error, transport:[{}], error: {:#?}", transport_id_for_proxy_to_target_relay,e);
                        return;
                    }
                    Ok(r) => r,
                };
                let PpaassAgentMessagePayloadSplitResult {
                    data: agent_message_payload_data,
                    payload_type: agent_message_payload_type,
                    ..
                } = agent_message_payload.split();
                match agent_message_payload_type {
                    PpaassAgentMessagePayloadType::TcpData => {
                        if let Err(e) = target_write
                            .write(agent_message_payload_data.as_slice())
                            .await
                        {
                            error!("Fail to send agent data from proxy to target because of error, transport:[{}], error: {:#?}",
                                    transport_id_for_proxy_to_target_relay, e);
                            return;
                        }
                        if let Err(e) = target_write.flush().await {
                            error!("Fail to flush agent data from proxy to target because of error, transport:[{}], error: {:#?}",
                                transport_id_for_proxy_to_target_relay, e);
                            return;
                        }
                    }
                    PpaassAgentMessagePayloadType::TcpConnectionClose => {
                        info!(
                            "Close agent connection, transport:[{}]",
                            transport_id_for_proxy_to_target_relay
                        );
                        return;
                    }
                    payload_type => {
                        error!(
                            "Invalid payload type received, received payload type: [{:?}]",
                            payload_type
                        );
                        return;
                    }
                }
            }
        });
        let target_to_proxy_buffer_size = self
            .configuration
            .buffer_size()
            .unwrap_or(DEFAULT_TCP_BUFFER_SIZE);
        let target_to_proxy_relay = tokio::spawn(async move {
            loop {
                info!(
                    "Begin the loop for tcp relay from target to proxy for tcp transport: [{}]",
                    transport_id_for_target_to_proxy_relay
                );
                let mut target_read_buf = Vec::<u8>::with_capacity(target_to_proxy_buffer_size);
                let read_size = match target_read.read_buf(&mut target_read_buf).await {
                    Err(e) => {
                        error!("Fail to read target data because of error, tcp transport: [{}] error: {:#?}", transport_id_for_target_to_proxy_relay, e);
                        return;
                    }
                    Ok(size) => size,
                };
                if read_size == 0 && target_read_buf.remaining_mut() > 0 {
                    info!(
                        "Nothing to read from target, tcp transport: [{}]",
                        transport_id_for_target_to_proxy_relay
                    );
                    let tcp_connection_close_message_payload = PpaassProxyMessagePayload::new(
                        source_address_for_target_to_proxy_relay.clone(),
                        target_address_for_target_to_proxy_relay.clone(),
                        PpaassProxyMessagePayloadType::TcpConnectionClose,
                        target_read_buf,
                    );
                    let tcp_connection_close_message =
                        PpaassMessage::new_with_random_encryption_type(
                            "".to_string(),
                            user_token_for_target_to_proxy_relay.clone(),
                            generate_uuid().as_bytes().to_vec(),
                            tcp_connection_close_message_payload.into(),
                        );
                    if let Err(e) = agent_write_part.send(tcp_connection_close_message).await {
                        error!("Fail to send connection close from proxy to client because of error, tcp transport: [{}], error: {:#?}",
                            transport_id_for_target_to_proxy_relay, e);
                        return;
                    };
                    if let Err(e) = agent_write_part.flush().await {
                        error!("Fail to flush connection close from proxy to client because of error, tcp transport: [{}], error: {:#?}",
                            transport_id_for_target_to_proxy_relay,e);
                        return;
                    };
                    return;
                }
                debug!(
                    "Receive target data for tcp transport: [{}]\n{}\n",
                    transport_id_for_target_to_proxy_relay,
                    String::from_utf8_lossy(&target_read_buf)
                );
                let tcp_data_success_message_payload = PpaassProxyMessagePayload::new(
                    source_address_for_target_to_proxy_relay.clone(),
                    target_address_for_target_to_proxy_relay.clone(),
                    PpaassProxyMessagePayloadType::TcpData,
                    target_read_buf,
                );
                let tcp_data_success_message = PpaassMessage::new_with_random_encryption_type(
                    "".to_string(),
                    user_token_for_target_to_proxy_relay.clone(),
                    generate_uuid().as_bytes().to_vec(),
                    tcp_data_success_message_payload.into(),
                );
                if let Err(e) = agent_write_part.send(tcp_data_success_message).await {
                    error!(
                        "Fail to send target data from proxy to client because of error: {:#?}",
                        e
                    );
                    return;
                };
                if let Err(e) = agent_write_part.flush().await {
                    error!(
                        "Fail to flush target data from proxy to client because of error: {:#?}",
                        e
                    );
                    return;
                };
            }
        });
        target_to_proxy_relay.await?;
        proxy_to_target_relay.await?;
        self.publish_transport_snapshot().await?;
        Ok(())
    }

    pub async fn close(mut self) -> Result<()> {
        self.end_time = {
            Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_millis(),
            )
        };
        self.status = TransportStatus::Closed;
        self.publish_transport_snapshot().await?;
        Ok(())
    }

    pub fn take_snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            id: self.id.clone(),
            user_token: self.user_token.clone(),
            status: self.status,
            agent_remote_address: self.agent_remote_address,
            source_address: self.source_address.clone(),
            target_address: self.target_address.clone(),
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
    pub fn id(&self) -> &str {
        &self.id
    }
}
