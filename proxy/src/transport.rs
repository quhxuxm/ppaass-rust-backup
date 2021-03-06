use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use bytes::BufMut;
use chrono::Utc;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use tokio::io::{AsyncWriteExt, split};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

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
    AGENT_PUBLIC_KEY, DEFAULT_TCP_BUFFER_SIZE, DEFAULT_TCP_MAX_FRAME_SIZE, DEFAULT_UDP_BUFFER_SIZE,
    PROXY_PRIVATE_KEY, PROXY_SERVER_CONFIG,
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

pub(crate) struct Transport {
    id: String,
    status: TransportStatus,
    start_time: i64,
    end_time: Option<i64>,
    user_token: Option<Vec<u8>>,
    agent_remote_address: SocketAddr,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
}

impl Debug for Transport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("start_time", &self.start_time)
            .field("end_time", &self.end_time)
            .field("user_token", &self.user_token)
            .field("agent_remote_address", &self.agent_remote_address)
            .field("source_address", &self.source_address)
            .field("target_address", &self.target_address)
            .finish()
    }
}

impl Display for Transport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

struct InitResult {
    agent_stream_framed: AgentStreamFramed,
    target_tcp_stream: Option<TcpStream>,
    target_udp_socket: Option<UdpSocket>,
}

impl Transport {
    pub fn new(agent_remote_address: SocketAddr) -> Result<Self> {
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            start_time: Utc::now().timestamp_millis(),
            end_time: None,
            user_token: None,
            agent_remote_address,
            source_address: None,
            target_address: None,
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
        let ppaass_message_codec = PpaassMessageCodec::new(
            &(*AGENT_PUBLIC_KEY),
            &(*PROXY_PRIVATE_KEY),
            PROXY_SERVER_CONFIG
                .max_frame_size()
                .unwrap_or(DEFAULT_TCP_MAX_FRAME_SIZE),
            PROXY_SERVER_CONFIG.compress().unwrap_or(false),
        );
        let agent_stream_framed = Framed::with_capacity(
            agent_stream,
            ppaass_message_codec,
            PROXY_SERVER_CONFIG
                .buffer_size()
                .unwrap_or(DEFAULT_TCP_BUFFER_SIZE),
        );
        // Initialize the target edge stream
        let init_result = self.init(agent_stream_framed).await?;
        let InitResult {
            agent_stream_framed,
            target_tcp_stream,
            target_udp_socket,
        } = match init_result {
            None => return Ok(()),
            Some(r) => r,
        };
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
        return match agent_message_payload_type {
            PpaassAgentMessagePayloadType::TcpConnect => {
                let target_socket_address: SocketAddr =
                    agent_message_target_address.clone().try_into()?;
                let mut target_tcp_stream = match TcpStream::connect(target_socket_address).await {
                    Err(e) => {
                        error!("Fail connect to target, transport: [{}], agent message id: [{}], target address: [{}], because of error: {:#?}", agent_message_id, self, target_socket_address, e);
                        let tcp_connect_fail_message_payload = PpaassProxyMessagePayload::new(
                            agent_message_source_address.clone(),
                            agent_message_target_address.clone(),
                            PpaassProxyMessagePayloadType::TcpConnectFail,
                            Bytes::new(),
                        );
                        let tcp_connect_fail_message =
                            PpaassMessage::new_with_random_encryption_type(
                                agent_message_id.clone(),
                                user_token.clone(),
                                generate_uuid().into(),
                                tcp_connect_fail_message_payload.into(),
                            );
                        if let Err(ppaass_error) =
                            agent_stream_framed.send(tcp_connect_fail_message).await
                        {
                            error!("Fail to send connect fail message to agent because of error, transport: [{}], error: {:#?}", self, ppaass_error);
                            return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                        }
                        if let Err(unknwon_error) = agent_stream_framed.flush().await {
                            error!("Fail to send connect fail message to agent because of error, transport: [{}], error: {:#?}", self, unknwon_error);
                            return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                        }
                        return Err(PpaassProxyError::ConnectToTargetFail(e).into());
                    }
                    Ok(r) => {
                        r.set_nodelay(true)?;
                        r
                    }
                };

                let tcp_connect_success_message_payload = PpaassProxyMessagePayload::new(
                    agent_message_source_address.clone(),
                    agent_message_target_address.clone(),
                    PpaassProxyMessagePayloadType::TcpConnectSuccess,
                    Bytes::new(),
                );
                let tcp_connect_success_message = PpaassMessage::new_with_random_encryption_type(
                    agent_message_id.clone(),
                    user_token.clone(),
                    generate_uuid().into(),
                    tcp_connect_success_message_payload.into(),
                );
                if let Err(ppaass_error) =
                    agent_stream_framed.send(tcp_connect_success_message).await
                {
                    error!("Fail to send connect success message to agent because of error, transport: [{}], error: {:#?}", self, ppaass_error);
                    target_tcp_stream.shutdown().await?;
                    return Err(PpaassProxyError::UnknownError.into());
                }
                if let Err(unknwon_error) = agent_stream_framed.flush().await {
                    error!("Fail to send connect success message to agent because of error, transport: [{}], error: {:#?}", self, unknwon_error);
                    target_tcp_stream.shutdown().await?;
                    return Err(PpaassProxyError::UnknownError.into());
                }
                self.user_token = Some(user_token.clone());
                self.source_address = Some(agent_message_source_address.clone());
                self.target_address = Some(agent_message_target_address.clone());
                self.status = TransportStatus::Initialized;
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
                    Bytes::new(),
                );
                let udp_associate_success_message = PpaassMessage::new_with_random_encryption_type(
                    agent_message_id.clone(),
                    user_token.clone(),
                    generate_uuid().into(),
                    udp_associate_success_message_payload.into(),
                );
                if let Err(ppaass_error) = agent_stream_framed
                    .send(udp_associate_success_message)
                    .await
                {
                    error!("Fail to send udp associate success message to agent because of error, transport: [{}], error: {:#?}", self, ppaass_error);
                    return Err(PpaassProxyError::UnknownError.into());
                }
                if let Err(unknwon_error) = agent_stream_framed.flush().await {
                    error!("Fail to send udp associate success message to agent because of error, transport: [{}], error: {:#?}", self, unknwon_error);
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
        self.status = TransportStatus::Relaying;
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
                let agent_udp_data_message = match agent_read_part.next().await {
                    None => {
                        info!(
                            "Nothing to read from agent, tcp transport: [{}]",
                            transport_id_for_proxy_to_target_relay
                        );
                        continue;
                    }
                    Some(agent_udp_data_message) => match agent_udp_data_message {
                        Err(e) => {
                            error!("Fail to decode agent udp message because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                            return;
                        }
                        Ok(r) => r,
                    },
                };
                let PpaassMessageSplitResult {
                    id: agent_message_id,
                    payload: agent_message_payload_bytes,
                    ..
                } = agent_udp_data_message.split();
                let agent_message_payload: PpaassAgentMessagePayload =
                    match agent_message_payload_bytes.try_into() {
                        Err(e) => {
                            error!("Fail to decode agent message payload because of error, transport: [{}], error: {:#?}",transport_id_for_proxy_to_target_relay,  e);
                            continue;
                        }
                        Ok(r) => r,
                    };
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
                                agent_message_payload_data.chunk(),
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
        let source_address_for_target_to_proxy_relay = match self.source_address.clone().take() {
            None => return Ok(()),
            Some(r) => r,
        };
        let target_to_proxy_relay = tokio::spawn(async move {
            loop {
                let source_address_for_target_to_proxy_relay =
                    source_address_for_target_to_proxy_relay.clone();
                let mut buf = BytesMut::with_capacity(DEFAULT_UDP_BUFFER_SIZE);
                let udp_relay_recv_result = match target_udp_socket_for_target_to_proxy_relay
                    .recv_from(&mut buf)
                    .await
                {
                    Err(e) => {
                        error!("Fail to receive udp message from target because of error, transport: [{}], error: {:#?}", transport_id_for_target_to_proxy_relay, e);
                        continue;
                    }
                    Ok(r) => r,
                };
                let (data_size, target_origin_address) = udp_relay_recv_result;
                let udp_data_diagram = buf.split_to(data_size);
                let target_address: PpaassAddress = target_origin_address.into();
                let udp_data_message_payload = PpaassProxyMessagePayload::new(
                    //For udp data the source address is the client address to accept the udp package
                    source_address_for_target_to_proxy_relay,
                    target_address,
                    PpaassProxyMessagePayloadType::UdpData,
                    udp_data_diagram.into(),
                );
                let udp_data_message = PpaassMessage::new_with_random_encryption_type(
                    "".to_string(),
                    user_token_for_target_to_proxy_relay.clone(),
                    generate_uuid().into(),
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
            error!("Invalid tcp transport status, tcp transport: [{}], current status: [{:?}], expect status: [{:?}]", self,
            self.status, TransportStatus::Initialized);
            return Err(PpaassProxyError::InvalidTcpTransportStatus(
                self.id.clone(),
                TransportStatus::Initialized,
                self.status,
            )
            .into());
        }
        self.status = TransportStatus::Relaying;
        let user_token = self
            .user_token
            .as_ref()
            .context("Fail to unwrap user token")?
            .clone();
        let user_token_t2p = user_token.clone();
        let source_address = self
            .source_address
            .clone()
            .take()
            .context("Can not unwrap source edge address")?;
        let source_address_t2p = source_address.clone();
        let target_address = self
            .target_address
            .clone()
            .take()
            .context("Can not unwrap target edge address")?;
        let target_address_t2p = target_address.clone();
        let target_address_p2t = target_address.clone();
        let (mut target_read, mut target_write) = split(target_tcp_stream);
        let (mut agent_write_part, mut agent_read_part) = agent_stream_framed.split();
        let transport_id_t2p = self.id.clone();
        let transport_id_p2t = self.id.clone();
        let (
            agent_connection_closed_notifier_sender,
            mut agent_connection_closed_notifier_receiver,
        ) = tokio::sync::mpsc::channel::<bool>(1);
        let target_to_proxy_buffer_size = PROXY_SERVER_CONFIG
            .buffer_size()
            .unwrap_or(DEFAULT_TCP_BUFFER_SIZE);
        tokio::spawn(async move {
            loop {
                info!(
                    "Begin to loop for tcp relay from proxy to target for tcp transport: [{}]",
                    transport_id_p2t
                );
                let agent_tcp_data_message = agent_read_part.next().await;
                let agent_tcp_data_message = match agent_tcp_data_message {
                    None => {
                        info!(
                            "Nothing to read from agent, tcp transport: [{}], target address: [{}]",
                            transport_id_p2t, target_address_p2t
                        );
                        return;
                    }
                    Some(result) => match result {
                        Err(e) => {
                            error!("Fail to decode agent tcp message because of error, transport: [{}], target address:[{}]. error: {:#?}",
                                transport_id_p2t, target_address_p2t, e);
                            if let Err(e) = target_write.shutdown().await {
                                error!("Fail to shutdown target tcp stream because of error, transport: [{}], target address:[{}]. error: {:#?}",
                                transport_id_p2t, target_address_p2t, e);
                            };
                            if let Err(e) = agent_connection_closed_notifier_sender.send(true).await
                            {
                                error!("Fail to send agent connection closed notification because of error, transport: [{}], error: {:#?}", transport_id_p2t, e)
                            };
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
                        error!("Fail to parse agent message payload because of error, transport:[{}], target address: [{}], error: {:#?}",
                            transport_id_p2t,target_address_p2t,e);
                        if let Err(e) = target_write.shutdown().await {
                            error!("Fail to shutdown target tcp stream because of error, transport: [{}], target address:[{}]. error: {:#?}",
                                transport_id_p2t, target_address_p2t, e);
                        };
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
                        if let Err(e) = target_write.write(agent_message_payload_data.chunk()).await
                        {
                            error!("Fail to send agent data from proxy to target because of error, transport:[{}], target address: [{}], error: {:#?}",
                                    transport_id_p2t, target_address_p2t, e);
                            return;
                        }

                        if let Err(e) = target_write.flush().await {
                            error!("Fail to flush agent data from proxy to target because of error, transport:[{}], target address: [{}], error: {:#?}",
                                transport_id_p2t, target_address_p2t, e);
                            return;
                        }
                    }
                    PpaassAgentMessagePayloadType::TcpConnectionClose => {
                        info!(
                            "Close agent connection, transport:[{}], target address: [{}]",
                            transport_id_p2t, target_address_p2t
                        );
                        agent_connection_closed_notifier_sender.send(true).await;
                        return;
                    }
                    payload_type => {
                        error!(
                            "Invalid payload type received, received payload type: [{:?}], transport: [{}], target address: [{}]",
                            payload_type, transport_id_p2t, target_address_p2t
                        );
                        return;
                    }
                }
            }
        });
        tokio::spawn(async move {
            loop {
                info!(
                    "Begin the loop for tcp relay from target to proxy for tcp transport: [{}], target address: [{}]",
                    transport_id_t2p, target_address_t2p
                );
                if let Ok(true) = agent_connection_closed_notifier_receiver.try_recv() {
                    error!("Agent connection closed, transport:[{}]", transport_id_t2p);
                    return;
                }
                let mut target_read_buf = BytesMut::with_capacity(target_to_proxy_buffer_size);
                let read_size = match target_read.read_buf(&mut target_read_buf).await {
                    Err(e) => {
                        error!("Fail to read target data because of error, tcp transport: [{}], target address: [{}], error: {:#?}",
                            transport_id_t2p, target_address_t2p, e);
                        return;
                    }
                    Ok(size) => size,
                };
                if read_size == 0 && target_read_buf.remaining_mut() > 0 {
                    info!(
                        "Nothing to read from target, tcp transport: [{}], target address: [{}]",
                        transport_id_t2p, target_address_t2p
                    );
                    let tcp_connection_close_message_payload = PpaassProxyMessagePayload::new(
                        source_address_t2p.clone(),
                        target_address_t2p.clone(),
                        PpaassProxyMessagePayloadType::TcpConnectionClose,
                        target_read_buf.into(),
                    );
                    let tcp_connection_close_message =
                        PpaassMessage::new_with_random_encryption_type(
                            "".to_string(),
                            user_token_t2p.clone(),
                            generate_uuid().into(),
                            tcp_connection_close_message_payload.into(),
                        );
                    if let Err(e) = agent_write_part.send(tcp_connection_close_message).await {
                        error!("Fail to send connection close from proxy to client because of error, tcp transport: [{}], target address: [{}], error: {:#?}",
                            transport_id_t2p, target_address_t2p, e);
                        return;
                    };
                    if let Err(e) = agent_write_part.flush().await {
                        error!("Fail to flush connection close from proxy to client because of error, tcp transport: [{}], target address: [{}], error: {:#?}",
                            transport_id_t2p,target_address_t2p, e);
                        return;
                    };
                    return;
                }
                info!(
                    "Receive target data for tcp transport: [{}], target address: [{}], data size: [{}]",
                    transport_id_t2p,
                    target_address_t2p,
                    read_size
                );
                debug!(
                    "Receive target data for tcp transport: [{}], target address: [{}], data:\n{}\n",
                    transport_id_t2p,
                    target_address_t2p,
                    String::from_utf8(target_read_buf.to_vec())
                        .unwrap_or_else(|e| format!("{:#?}", e))
                );
                let tcp_data_success_message_payload = PpaassProxyMessagePayload::new(
                    source_address_t2p.clone(),
                    target_address_t2p.clone(),
                    PpaassProxyMessagePayloadType::TcpData,
                    target_read_buf.into(),
                );
                let tcp_data_success_message = PpaassMessage::new_with_random_encryption_type(
                    "".to_string(),
                    user_token_t2p.clone(),
                    generate_uuid().into(),
                    tcp_data_success_message_payload.into(),
                );
                if let Err(e) = agent_write_part.send(tcp_data_success_message).await {
                    error!("Fail to send target data from proxy to client because of error, tcp transport: [{}], target address: [{}], error: {:#?}",
                                transport_id_t2p,  target_address_t2p, e);
                    return;
                };
                if let Err(e) = agent_write_part.flush().await {
                    error!(
                        "Fail to flush target data from proxy to client because of error, tcp transport: [{}], target address: [{}], error: {:#?}",
                        transport_id_t2p, target_address_t2p,e
                    );
                    return;
                };
            }
        });
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn status(&self) -> TransportStatus {
        self.status
    }
    pub fn start_time(&self) -> i64 {
        self.start_time
    }
    pub fn end_time(&self) -> Option<i64> {
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

impl Drop for Transport {
    fn drop(&mut self) {
        self.end_time = Some(Utc::now().timestamp_millis());
        self.status = TransportStatus::Closed;
        info!("Graceful close agent tcp transport: [{}]", self.id);
    }
}
