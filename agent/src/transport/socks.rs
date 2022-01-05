use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::BufMut;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{
    PpaassAddress, PpaassAddressType, PpaassMessage, PpaassMessagePayloadEncryptionType,
    PpaassMessageSplitResult, PpaassProxyMessagePayloadSplitResult, PpaassProxyMessagePayloadType,
};
use ppaass_common::generate_uuid;
use ppaass_common::proxy::PpaassProxyMessagePayload;

use crate::codec::socks::{Socks5AuthCodec, Socks5ConnectCodec};
use crate::common::ProxyAddress;
use crate::config::{
    AgentConfiguration, DEFAULT_TCP_BUFFER_SIZE, DEFAULT_TCP_MAX_FRAME_SIZE,
    DEFAULT_UDP_BUFFER_SIZE,
};
use crate::error::PpaassAgentError;
use crate::protocol::socks::{
    Socks5AddrType, Socks5AuthMethod, Socks5AuthResponse, Socks5ConnectRequestType,
    Socks5ConnectResponse, Socks5ConnectResponseStatus, Socks5UdpDataRequest,
    Socks5UdpDataResponse, UdpDiagram,
};
use crate::transport::common::{
    Transport, TransportSnapshot, TransportSnapshotType, TransportStatus,
};

const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];
pub(crate) struct Socks5Transport {
    id: String,
    status: TransportStatus,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Vec<u8>,
    client_remote_address: Option<SocketAddr>,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
    snapshot_sender: Sender<TransportSnapshot>,
    configuration: Arc<AgentConfiguration>,
}

type PpaassMessageFramed = Framed<TcpStream, PpaassMessageCodec>;
type Socks5ConnectFramed<'a> = Framed<&'a mut TcpStream, Socks5ConnectCodec>;
struct InitResult {
    client_tcp_stream: Option<TcpStream>,
    agent_bind_udp_socket: Option<Arc<UdpSocket>>,
    proxy_framed: PpaassMessageFramed,
    connect_message_id: String,
    source_address: PpaassAddress,
    target_address: PpaassAddress,
}

#[async_trait]
impl Transport for Socks5Transport {
    async fn start(
        &mut self,
        client_tcp_stream: TcpStream,
        rsa_public_key: String,
        rsa_private_key: String,
    ) -> Result<()> {
        let client_tcp_stream = self.authenticate(client_tcp_stream).await?;
        let init_result = self
            .init(client_tcp_stream, rsa_public_key, rsa_private_key)
            .await?;
        return match init_result {
            None => Ok(()),
            Some(connect_result) => {
                self.relay(connect_result).await?;
                Ok(())
            }
        };
    }

    fn take_snapshot(&self) -> TransportSnapshot {
        TransportSnapshot {
            id: self.id.clone(),
            snapshot_type: TransportSnapshotType::SOCKS5,
            status: self.status.clone(),
            start_time: self.start_time,
            end_time: self.end_time,
            user_token: self.user_token.clone(),
            client_remote_address: self.client_remote_address.clone(),
            source_address: self.source_address.clone(),
            target_address: self.target_address.clone(),
        }
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        self.status = TransportStatus::Closed;
        self.end_time = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis(),
        );
        info!("Graceful close socks5 transport [{}]", self.id);
        Ok(())
    }
}

impl Socks5Transport {
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

    async fn authenticate(&mut self, mut client_tcp_stream: TcpStream) -> Result<TcpStream> {
        if self.status != TransportStatus::New {
            return Err(PpaassAgentError::InvalidTransportStatus(
                self.id.clone(),
                TransportStatus::TcpConnected,
                self.status,
            )
            .into());
        }
        let socks5_auth_codec = Socks5AuthCodec::new(self.id.clone());
        let mut client_tcp_framed = socks5_auth_codec.framed(&mut client_tcp_stream);
        let socks5_auth_command = client_tcp_framed.next().await;
        match socks5_auth_command {
            None => {
                info!(
                    "Nothing to read for socks5 authenticate process, socks5 transport: [{}]",
                    self.id
                );
                return Ok(client_tcp_stream);
            }
            Some(command) => {
                match command {
                    Err(e) => {
                        error!("Fail to decode socks5 auth command, sock5 transport: [{}], error: {:#?}", self.id, e);
                        return Err(e.into());
                    }
                    Ok(_socks5_auth_request) => {
                        let auth_response =
                            Socks5AuthResponse::new(Socks5AuthMethod::NoAuthenticationRequired);
                        if let Err(e) = client_tcp_framed.send(auth_response).await {
                            error!("Fail to send socks5 authenticate response to client because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                            return Err(PpaassAgentError::IoError(e).into());
                        }
                        if let Err(e) = client_tcp_framed.flush().await {
                            error!("Fail to flush socks5 authenticate response to client because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                            return Err(PpaassAgentError::IoError(e).into());
                        }
                    }
                }
            }
        }
        self.status = TransportStatus::Authenticated;
        Ok(client_tcp_stream)
    }

    async fn init(
        &mut self,
        mut client_tcp_stream: TcpStream,
        rsa_public_key: String,
        rsa_private_key: String,
    ) -> Result<Option<InitResult>> {
        if self.status != TransportStatus::Authenticated {
            return Err(PpaassAgentError::InvalidTransportStatus(
                self.id.clone(),
                TransportStatus::TcpConnected,
                self.status,
            )
            .into());
        }
        let client_socket_address = client_tcp_stream.peer_addr()?;
        let socks5_connect_codec = Socks5ConnectCodec::new(self.id.clone());
        let mut client_tcp_framed = socks5_connect_codec.framed(&mut client_tcp_stream);
        let socks5_connect_cmd = client_tcp_framed.next().await;
        let socks5_connect_cmd = match socks5_connect_cmd {
            None => {
                info!(
                    "Nothing to read for socks5 connect process, socks5 transport: [{}]",
                    self.id
                );
                return Ok(None);
            }
            Some(result) => result,
        };
        let socks5_connect_cmd = match socks5_connect_cmd {
            Err(e) => {
                error!(
                    "Fail to decode socks5 connect command, sock5 transport: [{}], error: {:#?}",
                    self.id, e
                );
                return Err(e.into());
            }
            Ok(result) => result,
        };
        let client_socket_address = client_socket_address;
        let source_address: PpaassAddress = client_socket_address.into();
        let target_address = match socks5_connect_cmd.addr_type() {
            Socks5AddrType::IpV4 => PpaassAddress::new(
                socks5_connect_cmd.dst_host().to_vec(),
                socks5_connect_cmd.dst_port(),
                PpaassAddressType::IpV4,
            ),
            Socks5AddrType::IpV6 => PpaassAddress::new(
                socks5_connect_cmd.dst_host().to_vec(),
                socks5_connect_cmd.dst_port(),
                PpaassAddressType::IpV6,
            ),
            Socks5AddrType::Domain => PpaassAddress::new(
                socks5_connect_cmd.dst_host().to_vec(),
                socks5_connect_cmd.dst_port(),
                PpaassAddressType::Domain,
            ),
        };
        match socks5_connect_cmd.request_type() {
            Socks5ConnectRequestType::Bind => {
                Err(PpaassAgentError::UnsupportedSocks5Command.into())
            }
            Socks5ConnectRequestType::Connect => {
                let proxy_stream = match self.connect_to_proxy().await? {
                    None => {
                        error!("Can not connect to proxy, socks5 transport: [{}]", self.id);
                        return Err(PpaassAgentError::FailToConnectProxy.into());
                    }
                    Some(result) => result,
                };
                let connect_message_payload = PpaassAgentMessagePayload::new(
                    source_address.clone(),
                    target_address.clone(),
                    PpaassAgentMessagePayloadType::TcpConnect,
                    vec![],
                );
                let connect_message = PpaassMessage::new(
                    "".to_string(),
                    self.user_token.clone(),
                    generate_uuid().into_bytes(),
                    PpaassMessagePayloadEncryptionType::random(),
                    connect_message_payload.into(),
                );
                let mut proxy_framed = Self::create_proxy_framed(
                    rsa_public_key,
                    rsa_private_key,
                    proxy_stream,
                    self.configuration
                        .max_frame_size()
                        .unwrap_or(DEFAULT_TCP_MAX_FRAME_SIZE),
                );
                if let Err(e) = proxy_framed.send(connect_message).await {
                    error!("Fail to send connect to proxy, because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                    Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                    return Err(PpaassAgentError::FailToConnectProxy.into());
                }
                if let Err(e) = proxy_framed.flush().await {
                    error!("Fail to flush connect to proxy, because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                    Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                    return Err(PpaassAgentError::FailToConnectProxy.into());
                }
                let proxy_connect_response = proxy_framed.next().await;
                let proxy_message = match proxy_connect_response {
                    None => {
                        error!("Fail to read proxy connect response message for socks 5 transport [{}], target: [{}], None received from proxy", self.id, target_address);
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        return Err(PpaassAgentError::FailToConnectProxy.into());
                    }
                    Some(response) => match response {
                        Err(e) => {
                            error!("Fail to read proxy connect response message for socks 5 transport [{}], target: [{}], error: {:#?}", self.id, target_address, e);
                            Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                            return Err(PpaassAgentError::FailToConnectProxy.into());
                        }
                        Ok(r) => {
                            info!("Success receive proxy connect response message for socks 5 transport: [{}], target:[{}]", self.id, target_address);
                            r
                        }
                    },
                };

                let PpaassMessageSplitResult {
                    id: proxy_message_id,
                    payload: proxy_message_payload,
                    ..
                } = proxy_message.split();
                let proxy_message_payload: PpaassProxyMessagePayload =
                    proxy_message_payload.try_into()?;
                let PpaassProxyMessagePayloadSplitResult {
                    payload_type: proxy_message_payload_type,
                    ..
                } = proxy_message_payload.split();
                match proxy_message_payload_type {
                    PpaassProxyMessagePayloadType::TcpConnectFail => {
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        Err(PpaassAgentError::FailToConnectProxy.into())
                    }
                    PpaassProxyMessagePayloadType::TcpConnectSuccess => {
                        let socks5_connect_success_response = Socks5ConnectResponse::new(
                            Socks5ConnectResponseStatus::Succeeded,
                            socks5_connect_cmd.addr_type(),
                            socks5_connect_cmd.dst_host().to_vec(),
                            socks5_connect_cmd.dst_port(),
                        );
                        client_tcp_framed
                            .send(socks5_connect_success_response)
                            .await?;
                        client_tcp_framed.flush().await?;
                        self.status = TransportStatus::TcpConnected;
                        Ok(Some(InitResult {
                            client_tcp_stream: Some(client_tcp_stream),
                            agent_bind_udp_socket: None,
                            connect_message_id: proxy_message_id,
                            proxy_framed,
                            source_address,
                            target_address,
                        }))
                    }
                    PpaassProxyMessagePayloadType::TcpConnectionClose => Ok(None),
                    _ => {
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        Err(PpaassAgentError::FailToConnectProxy.into())
                    }
                }
            }
            Socks5ConnectRequestType::UdpAssociate => {
                let proxy_stream = match self.connect_to_proxy().await? {
                    None => {
                        error!("Can not connect to proxy, socks5 transport: [{}]", self.id);
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        return Err(PpaassAgentError::FailToConnectProxy.into());
                    }
                    Some(result) => result,
                };
                let mut proxy_framed = Self::create_proxy_framed(
                    rsa_public_key,
                    rsa_private_key,
                    proxy_stream,
                    self.configuration
                        .max_frame_size()
                        .unwrap_or(DEFAULT_TCP_MAX_FRAME_SIZE),
                );
                let udp_source_address = PpaassAddress::new(
                    source_address.host().to_vec(),
                    socks5_connect_cmd.dst_port(),
                    *source_address.address_type(),
                );
                info!(
                    "Udp associate, client use this address to receive udp message, socks5 transport: [{}], udp source address : {:?}",
                    self.id, udp_source_address
                );
                //The socks5 udp associate request do not contains target address, use a fake one.
                let udp_target_address =
                    PpaassAddress::new(vec![0, 0, 0, 0], 0, PpaassAddressType::IpV4);
                let udp_associate_message_payload = PpaassAgentMessagePayload::new(
                    udp_source_address.clone(),
                    udp_target_address.clone(),
                    PpaassAgentMessagePayloadType::UdpAssociate,
                    vec![],
                );
                let udp_associate_message = PpaassMessage::new(
                    "".to_string(),
                    self.user_token.clone(),
                    generate_uuid().into_bytes(),
                    PpaassMessagePayloadEncryptionType::random(),
                    udp_associate_message_payload.into(),
                );
                if let Err(e) = proxy_framed.send(udp_associate_message).await {
                    error!("Fail to send udp associate to proxy, because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                    Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                    return Err(PpaassAgentError::FailToAssociateUdpOnProxy.into());
                }
                if let Err(e) = proxy_framed.flush().await {
                    error!("Fail to flush udp associate to proxy, because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                    Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                    return Err(PpaassAgentError::FailToAssociateUdpOnProxy.into());
                }
                let proxy_udp_associate_response = proxy_framed.next().await;

                let proxy_message = match proxy_udp_associate_response {
                    None => {
                        error!("Fail to read proxy connect response message for socks 5 transport [{}], target: [{}], None received from proxy", self.id, target_address);
                        return Err(PpaassAgentError::FailToConnectProxy.into());
                    }
                    Some(response) => match response {
                        Err(e) => {
                            error!("Fail to read proxy connect response message for socks 5 transport [{}], target: [{}], error: {:#?}", self.id, target_address, e);
                            Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                            return Err(PpaassAgentError::FailToConnectProxy.into());
                        }
                        Ok(r) => {
                            info!("Success receive proxy connect response message for socks 5 transport: [{}], target:[{}]", self.id, target_address);
                            r
                        }
                    },
                };
                let PpaassMessageSplitResult {
                    id: proxy_message_id,
                    payload: proxy_message_payload,
                    ..
                } = proxy_message.split();
                let proxy_message_payload: PpaassProxyMessagePayload =
                    proxy_message_payload.try_into()?;
                let PpaassProxyMessagePayloadSplitResult {
                    payload_type: proxy_message_payload_type,
                    ..
                } = proxy_message_payload.split();
                match proxy_message_payload_type {
                    PpaassProxyMessagePayloadType::UdpAssociateFail => {
                        error!("Fail to associate udp socket because of proxy associate udp fail, socks5 transport: [{}]", self.id);
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        Err(PpaassAgentError::FailToAssociateUdpOnProxy.into())
                    }
                    PpaassProxyMessagePayloadType::UdpAssociateSuccess => {
                        let agent_bind_udp_socket =
                            UdpSocket::bind(SocketAddr::new(IpAddr::from(LOCAL_ADDRESS), 0)).await;
                        let agent_bind_udp_socket = match agent_bind_udp_socket {
                            Err(e) => {
                                error!("Fail to bind agent udp socket because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                                Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                                return Err(PpaassAgentError::FailToAssociateUdpOnAgent.into());
                            }
                            Ok(result) => result,
                        };
                        let agent_bind_udp_socket_address = agent_bind_udp_socket.local_addr()?;
                        let agent_bind_udp_socket_address: PpaassAddress =
                            agent_bind_udp_socket_address.into();
                        info!(
                            "Udp associate, agent use this address to receive udp message, socks5 transport: [{}], message : {:?}",
                            self.id, agent_bind_udp_socket_address
                        );
                        let socks5_udp_associate_success_response = Socks5ConnectResponse::new(
                            Socks5ConnectResponseStatus::Succeeded,
                            Socks5AddrType::IpV4,
                            agent_bind_udp_socket_address.host().to_vec(),
                            agent_bind_udp_socket_address.port(),
                        );
                        client_tcp_framed
                            .send(socks5_udp_associate_success_response)
                            .await?;
                        client_tcp_framed.flush().await?;
                        self.status = TransportStatus::UdpAssociated;
                        Ok(Some(InitResult {
                            client_tcp_stream: Some(client_tcp_stream),
                            agent_bind_udp_socket: Some(Arc::new(agent_bind_udp_socket)),
                            connect_message_id: proxy_message_id,
                            proxy_framed,
                            source_address: udp_source_address,
                            target_address: udp_target_address,
                        }))
                    }
                    payload_type => {
                        error!("Fail to associate udp socket because of wrong proxy message payload type, socks5 transport: [{}], payload type: {:#?}", self.id, payload_type);
                        Self::send_socks5_failure_response(&mut client_tcp_framed).await?;
                        Err(PpaassAgentError::FailToAssociateUdpOnProxy.into())
                    }
                }
            }
        }
    }

    async fn send_socks5_failure_response<'a>(
        client_tcp_framed: &'a mut Socks5ConnectFramed<'a>,
    ) -> Result<()> {
        let connect_error_response =
            Socks5ConnectResponse::new_status_only(Socks5ConnectResponseStatus::Failure);
        client_tcp_framed.send(connect_error_response).await?;
        client_tcp_framed.flush().await?;
        Ok(())
    }

    async fn connect_to_proxy(&mut self) -> Result<Option<TcpStream>> {
        let proxy_addresses = self
            .configuration
            .proxy_addresses()
            .clone()
            .context("Proxy address did not configure properly")?;
        let mut proxy_addresses_iter = proxy_addresses.iter();
        let proxy_stream: Option<TcpStream> = loop {
            let proxy_address = match proxy_addresses_iter.next() {
                None => break None,
                Some(r) => r,
            };
            let proxy_address: ProxyAddress = match proxy_address.to_string().try_into() {
                Err(e) => {
                    error!("Fail to parse proxy address because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                    continue;
                }
                Ok(address) => address,
            };
            let proxy_address_string: String = proxy_address.into();
            match TcpStream::connect(proxy_address_string.clone()).await {
                Err(e) => {
                    error!("Fail connect to proxy address: [{}] because of error, socks5 transport: [{}], error: {:#?}", self.id,
                                                        proxy_address_string, e);
                    continue;
                }
                Ok(stream) => {
                    info!(
                        "Success connect to proxy address, socks5 transport:[{}], proxy: [{}]",
                        self.id, proxy_address_string
                    );
                    break Some(stream);
                }
            }
        };
        Ok(proxy_stream)
    }

    async fn relay(&mut self, init_result: InitResult) -> Result<()> {
        match self.status {
            TransportStatus::TcpConnected => {
                self.do_tcp_relay(init_result).await?;
            }
            TransportStatus::UdpAssociated => {
                self.do_udp_relay(init_result).await?;
            }
            _ => {
                return Err(PpaassAgentError::InvalidTransportStatus(
                    self.id.clone(),
                    TransportStatus::TcpConnected,
                    self.status,
                )
                .into());
            }
        }
        Ok(())
    }
    async fn do_udp_relay(&mut self, init_result: InitResult) -> Result<()> {
        let InitResult {
            connect_message_id,
            proxy_framed,
            source_address: udp_client_source_address,
            target_address,
            client_tcp_stream,
            agent_bind_udp_socket,
        } = init_result;
        let transport_id_for_client_to_proxy_relay = self.id.clone();
        let transport_id_for_proxy_to_client_relay = self.id.clone();
        let user_token_for_client_to_proxy_relay = self.user_token.clone();
        let user_token_for_proxy_to_client_relay = self.user_token.clone();
        let (mut proxy_framed_write, mut proxy_framed_read) = proxy_framed.split();
        let agent_bind_udp_socket =
            agent_bind_udp_socket.context("Can not unwrap client udp socket to send message")?;
        let agent_bind_udp_socket_c2p = agent_bind_udp_socket.clone();
        let agent_bind_udp_socket_p2c = agent_bind_udp_socket.clone();
        let client_to_proxy_relay = tokio::spawn(async move {
            loop {
                let mut buf = [0u8; DEFAULT_UDP_BUFFER_SIZE];
                let (data_size, client_udp_message_address) = match agent_bind_udp_socket_c2p
                    .recv_from(&mut buf)
                    .await
                {
                    Ok(result) => {
                        info!(
                                "Receive client udp message from origin: {}, socks5 transport: [{}],  client socket address: {:?}",
                                result.1,transport_id_for_client_to_proxy_relay, agent_bind_udp_socket_c2p
                            );
                        result
                    }
                    Err(e) => {
                        error!("Fail to receive udp message from client for relay in socks 5 transport, socks5 transport: [{}], client udp socket:{:?}, error:{:#?}",
                                transport_id_for_client_to_proxy_relay, agent_bind_udp_socket_c2p, e );
                        return;
                    }
                };
                let udp_data_diagram = buf[..data_size].to_vec();
                let socks5_udp_data_request: Socks5UdpDataRequest = match udp_data_diagram
                    .try_into()
                {
                    Ok(result) => result,
                    Err(e) => {
                        error!("Fail to decode udp message bytes from client for relay in socks 5 transport, transport: [{}], error:{:#?}",
                                transport_id_for_client_to_proxy_relay, e );
                        continue;
                    }
                };
                let source_address_for_proxy: PpaassAddress = client_udp_message_address.into();
                let udp_message_target_address: PpaassAddress =
                    match socks5_udp_data_request.addr_type() {
                        Socks5AddrType::IpV4 => PpaassAddress::new(
                            socks5_udp_data_request.dst_addr().to_vec(),
                            socks5_udp_data_request.dst_port(),
                            PpaassAddressType::IpV4,
                        ),
                        Socks5AddrType::IpV6 => PpaassAddress::new(
                            socks5_udp_data_request.dst_addr().to_vec(),
                            socks5_udp_data_request.dst_port(),
                            PpaassAddressType::IpV6,
                        ),
                        Socks5AddrType::Domain => PpaassAddress::new(
                            socks5_udp_data_request.dst_addr().to_vec(),
                            socks5_udp_data_request.dst_port(),
                            PpaassAddressType::Domain,
                        ),
                    };
                let udp_data_message_body = PpaassAgentMessagePayload::new(
                    source_address_for_proxy,
                    udp_message_target_address,
                    PpaassAgentMessagePayloadType::UdpData,
                    socks5_udp_data_request.data().to_vec(),
                );
                let udp_data_message = PpaassMessage::new(
                    connect_message_id.clone(),
                    user_token_for_client_to_proxy_relay.clone(),
                    generate_uuid().into_bytes(),
                    PpaassMessagePayloadEncryptionType::random(),
                    udp_data_message_body.into(),
                );
                if let Err(e) = proxy_framed_write.send(udp_data_message).await {
                    error!(
                        "Fail to send udp data from agent to proxy because of error,transport: [{}], error: {:#?}",
                        transport_id_for_client_to_proxy_relay, e
                    );
                    continue;
                }
                if let Err(e) = proxy_framed_write.flush().await {
                    error!(
                        "Fail to flush udp data from agent to proxy because of error,transport: [{}], error: {:#?}",
                        transport_id_for_client_to_proxy_relay, e
                    );
                    continue;
                }
            }
        });
        let proxy_to_client_relay = tokio::spawn(async move {
            loop {
                let proxy_udp_message = match proxy_framed_read.next().await {
                    None => continue,
                    Some(r) => r,
                };
                let proxy_udp_message = match proxy_udp_message {
                    Err(e) => {
                        error!("Fail to decode proxy message for udp relay in socks 5 transport, transport: [{}], error: {:#?}", transport_id_for_proxy_to_client_relay, e);
                        return;
                    }
                    Ok(result) => result,
                };
                let PpaassMessageSplitResult {
                    id: proxy_message_id,
                    payload: proxy_message_payload_bytes,
                    ..
                } = proxy_udp_message.split();
                let proxy_message_payload: PpaassProxyMessagePayload =
                    match proxy_message_payload_bytes.try_into() {
                        Err(e) => {
                            error!("Receive error from proxy for udp relay in socks 5 transport, transport: [{}], error: {:#?}", transport_id_for_proxy_to_client_relay, e);
                            continue;
                        }
                        Ok(result) => result,
                    };
                let PpaassProxyMessagePayloadSplitResult {
                    payload_type: proxy_message_payload_type,
                    data: proxy_message_payload_data,
                    source_address: proxy_message_payload_source_address,
                    target_address: proxy_message_payload_target_address,
                } = proxy_message_payload.split();
                info!(
                    "Receive data from target, socks5 transport: [{}], data: \n{}\n",
                    transport_id_for_proxy_to_client_relay,
                    String::from_utf8(proxy_message_payload_data.clone())
                        .unwrap_or_else(|e| format!("{:#?}", e))
                );
                match proxy_message_payload_type {
                    PpaassProxyMessagePayloadType::UdpData => {
                        let socks5_udp_data_response =
                            match proxy_message_payload_target_address.address_type() {
                                PpaassAddressType::IpV4 => Socks5UdpDataResponse::new(
                                    0,
                                    Socks5AddrType::IpV4,
                                    proxy_message_payload_target_address.host().to_vec(),
                                    proxy_message_payload_target_address.port(),
                                    proxy_message_payload_data,
                                ),
                                PpaassAddressType::IpV6 => Socks5UdpDataResponse::new(
                                    0,
                                    Socks5AddrType::IpV6,
                                    proxy_message_payload_target_address.host().to_vec(),
                                    proxy_message_payload_target_address.port(),
                                    proxy_message_payload_data,
                                ),
                                PpaassAddressType::Domain => Socks5UdpDataResponse::new(
                                    0,
                                    Socks5AddrType::Domain,
                                    proxy_message_payload_target_address.host().to_vec(),
                                    proxy_message_payload_target_address.port(),
                                    proxy_message_payload_data,
                                ),
                            };
                        let socks5_udp_data_response_bytes: Vec<u8> =
                            socks5_udp_data_response.into();

                        let udp_client_socket_address = PpaassAddress::new(
                            proxy_message_payload_target_address.host().to_vec(),
                            proxy_message_payload_source_address.port(),
                            *proxy_message_payload_target_address.address_type(),
                        );
                        let udp_client_socket_address: SocketAddr = match udp_client_socket_address
                            .try_into()
                        {
                            Err(e) => {
                                error!("Fail to convert the source address in proxy message because of error, socks5 transport: [{}], error: {:#?}",
                                    transport_id_for_proxy_to_client_relay, e);
                                continue;
                            }
                            Ok(result) => result,
                        };
                        info!(
                            "Send target message to client, socks 5 transport: [{}], client udp socket: {:?}, send to client address: {:?}",
                            transport_id_for_proxy_to_client_relay, agent_bind_udp_socket_p2c, udp_client_socket_address
                        );
                        if let Err(e) = agent_bind_udp_socket_p2c
                            .send_to(
                                socks5_udp_data_response_bytes.as_slice(),
                                udp_client_socket_address,
                            )
                            .await
                        {
                            error!("Fail to send udp data from proxy to client for socks 5 transport, socks5 transport: [{}], error: {:#?}", transport_id_for_proxy_to_client_relay, e);
                            continue;
                        };
                    }
                    PpaassProxyMessagePayloadType::UdpDataRelayFail => {
                        error!("Fail to relay udp data from proxy to target for socks 5 transport, socks5 transport: [{}], message to relay:[{}]",
                                    transport_id_for_proxy_to_client_relay, proxy_message_id);
                        continue;
                    }
                    _ => {
                        error!("Wrong status receive from proxy when relay udp message in socks 5 transport, socks5 transport: [{}], message to relay:[{}]",
                                    transport_id_for_proxy_to_client_relay, proxy_message_id);
                        continue;
                    }
                }
            }
        });
        client_to_proxy_relay.await?;
        proxy_to_client_relay.await?;
        Ok(())
    }
    async fn do_tcp_relay(&mut self, init_result: InitResult) -> Result<()> {
        let InitResult {
            connect_message_id,
            proxy_framed,
            source_address,
            target_address,
            mut client_tcp_stream,
            ..
        } = init_result;
        let (mut proxy_framed_write, mut proxy_framed_read) = proxy_framed.split();
        self.status = TransportStatus::Relaying;
        let user_token = self.user_token.clone();
        let (mut client_tcp_stream_read, mut client_tcp_stream_write) = client_tcp_stream
            .take()
            .context("Fail to unwrap client tcp stream")?
            .into_split();
        let transport_id_for_proxy_to_client_relay = self.id.clone();
        let transport_id_for_client_to_proxy_relay = self.id.clone();
        let connect_message_id_for_client_to_proxy_relay = connect_message_id.clone();
        let connect_message_id_for_proxy_to_client_relay = connect_message_id.clone();
        let client_to_proxy_relay = tokio::spawn(async move {
            loop {
                let mut read_buf = Vec::<u8>::with_capacity(DEFAULT_TCP_BUFFER_SIZE);
                let data_size = match client_tcp_stream_read.read_buf(&mut read_buf).await {
                    Err(e) => {
                        error!(
                            "Fail to read data from agent client because of error, error: {:#?}",
                            e
                        );
                        return;
                    }
                    Ok(r) => r,
                };
                if data_size == 0 && read_buf.remaining_mut() > 0 {
                    let connection_close_message_body = PpaassAgentMessagePayload::new(
                        source_address.clone(),
                        target_address.clone(),
                        PpaassAgentMessagePayloadType::TcpConnectionClose,
                        read_buf,
                    );
                    let connection_close_message = PpaassMessage::new(
                        connect_message_id_for_client_to_proxy_relay.clone(),
                        user_token.clone(),
                        generate_uuid().into_bytes(),
                        PpaassMessagePayloadEncryptionType::random(),
                        connection_close_message_body.into(),
                    );
                    if let Err(e) = proxy_framed_write.send(connection_close_message).await {
                        error!("Fail to send connection close from agent to proxy because of error, error: {:#?}", e);
                        break;
                    }
                    if let Err(e) = proxy_framed_write.flush().await {
                        error!("Fail to flush connection close from agent to proxy because of error, error: {:#?}", e);
                        break;
                    }
                    return;
                }
                let data_message_body = PpaassAgentMessagePayload::new(
                    source_address.clone(),
                    target_address.clone(),
                    PpaassAgentMessagePayloadType::TcpData,
                    read_buf,
                );
                let data_message = PpaassMessage::new(
                    connect_message_id_for_client_to_proxy_relay.clone(),
                    user_token.clone(),
                    generate_uuid().into_bytes(),
                    PpaassMessagePayloadEncryptionType::random(),
                    data_message_body.into(),
                );
                if let Err(e) = proxy_framed_write.send(data_message).await {
                    error!(
                        "Fail to send data from agent to proxy because of error, error: {:#?}",
                        e
                    );
                    break;
                }
                if let Err(e) = proxy_framed_write.flush().await {
                    error!(
                        "Fail to flush data from agent to proxy because of error, error: {:#?}",
                        e
                    );
                    break;
                }
            }
        });
        let proxy_to_client_relay = tokio::spawn(async move {
            loop {
                debug!(
                    "Begin the loop to read from proxy for socks 5 transport: [{}]",
                    transport_id_for_proxy_to_client_relay
                );
                let proxy_message = match proxy_framed_read.next().await {
                    None => {
                        info!(
                            "Noting read from proxy for socks 5 transport: [{}]",
                            transport_id_for_proxy_to_client_relay
                        );
                        return;
                    }
                    Some(r) => r,
                };
                let proxy_message = match proxy_message {
                    Err(e) => {
                        error!("Fail to read data from proxy because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                        return;
                    }
                    Ok(r) => r,
                };
                let PpaassMessageSplitResult { payload, .. } = proxy_message.split();
                let payload: Result<PpaassProxyMessagePayload, _> = payload.try_into();
                let payload = match payload {
                    Err(e) => {
                        error!("Fail to read data from proxy because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                        return;
                    }
                    Ok(r) => r,
                };
                let PpaassProxyMessagePayloadSplitResult {
                    payload_type: proxy_message_payload_type,
                    data: proxy_message_data,
                    ..
                } = payload.split();
                match proxy_message_payload_type {
                    PpaassProxyMessagePayloadType::TcpDataRelayFail => {
                        error!("Fail to read data from proxy because of proxy give data relay fail, socks 5 transport: [{}]", transport_id_for_proxy_to_client_relay);
                        continue;
                    }
                    PpaassProxyMessagePayloadType::TcpData => {
                        debug!(
                            "Receive target data for http transport: [{}]\n{}\n",
                            transport_id_for_proxy_to_client_relay,
                            String::from_utf8_lossy(&proxy_message_data)
                        );
                        if let Err(e) = client_tcp_stream_write.write(&proxy_message_data).await {
                            error!("Fail to send data from agent to client because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                            return;
                        }
                        if let Err(e) = client_tcp_stream_write.flush().await {
                            error!("Fail to flush data from agent to client because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                            return;
                        }
                    }
                    PpaassProxyMessagePayloadType::TcpConnectionClose => {
                        info!(
                            "Socks 5 transport:[{}] close",
                            transport_id_for_proxy_to_client_relay
                        );
                        return;
                    }
                    other_payload_type => {
                        error!("Fail to read data from proxy because of proxy give invalid type: {:?}, socks 5 transport:[{}]", other_payload_type, transport_id_for_proxy_to_client_relay);
                        continue;
                    }
                }
            }
        });
//        client_to_proxy_relay.await?;
//        proxy_to_client_relay.await?;
        Ok(())
    }
}
