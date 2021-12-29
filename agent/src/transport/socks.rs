use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::BufMut;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{PpaassAddress, PpaassAddressType, PpaassMessage, PpaassMessagePayloadEncryptionType, PpaassMessageSplitResult, PpaassProxyMessagePayloadSplitResult, PpaassProxyMessagePayloadType};
use ppaass_common::generate_uuid;
use ppaass_common::proxy::PpaassProxyMessagePayload;

use crate::codec::socks::{Socks5AuthCodec, Socks5ConnectCodec};
use crate::common::ProxyAddress;
use crate::config::AgentConfiguration;
use crate::error::PpaassAgentError;
use crate::protocol::socks::{Socks5AddrType, Socks5AuthMethod, Socks5AuthResponse, Socks5ConnectRequestType, Socks5ConnectResponse, Socks5ConnectResponseStatus};
use crate::transport::common::{Transport, TransportSnapshot, TransportSnapshotType, TransportStatus};

pub(crate) struct Socks5Transport {
    id: String,
    status: TransportStatus,
    client_read_bytes: usize,
    client_write_bytes: usize,
    proxy_read_bytes: usize,
    proxy_write_bytes: usize,
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

struct ConnectResult {
    client_tcp_stream: TcpStream,
    proxy_framed: PpaassMessageFramed,
    connect_message_id: String,
    source_address: PpaassAddress,
    target_address: PpaassAddress,
}

#[async_trait]
impl Transport for Socks5Transport {
    async fn start(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String, rsa_private_key: String) -> Result<()> {
        let client_tcp_stream = self.authenticate(client_tcp_stream).await?;
        let connect_result = self.connect(client_tcp_stream, rsa_public_key, rsa_private_key).await?;
        return match connect_result {
            None => {
                Ok(())
            }
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
            client_read_bytes: self.client_read_bytes,
            client_write_bytes: self.client_write_bytes,
            proxy_read_bytes: self.proxy_read_bytes,
            proxy_write_bytes: self.proxy_write_bytes,
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
        self.end_time = Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis());
        info!("Graceful close socks5 transport [{}]", self.id);
        Ok(())
    }
}

impl Socks5Transport {
    pub(crate) fn new(configuration: Arc<AgentConfiguration>, snapshot_sender: Sender<TransportSnapshot>) -> Result<Self> {
        let user_token = configuration.user_token().clone().context("Can not get user token from configuration.")?;
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            client_read_bytes: 0,
            client_write_bytes: 0,
            proxy_read_bytes: 0,
            proxy_write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis()
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
            return Err(PpaassAgentError::InvalidTransportStatus(self.id.clone(), TransportStatus::Connected, self.status).into());
        }
        let socks5_auth_codec = Socks5AuthCodec::default();
        let mut client_tcp_framed = socks5_auth_codec.framed(&mut client_tcp_stream);
        let socks5_auth_command = client_tcp_framed.next().await;
        match socks5_auth_command {
            None => {
                info!("Nothing to read for socks5 authenticate process, socks5 transport: [{}]", self.id);
                return Ok(client_tcp_stream);
            }
            Some(command) => {
                match command {
                    Err(e) => {
                        error!("Fail to decode socks5 auth command, sock5 transport: [{}], error: {:#?}", self.id, e);
                        return Err(e.into());
                    }
                    Ok(_socks5_auth_request) => {
                        let auth_response = Socks5AuthResponse::new(Socks5AuthMethod::NoAuthenticationRequired);
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

    async fn connect(&mut self, mut client_tcp_stream: TcpStream, rsa_public_key: String, rsa_private_key: String) -> Result<Option<ConnectResult>> {
        if self.status != TransportStatus::Authenticated {
            return Err(PpaassAgentError::InvalidTransportStatus(self.id.clone(), TransportStatus::Connected, self.status).into());
        }
        let client_socket_address = client_tcp_stream.peer_addr()?;
        let socks5_connect_codec = Socks5ConnectCodec::default();
        let mut client_tcp_framed = socks5_connect_codec.framed(&mut client_tcp_stream);
        let socks5_connect_cmd = client_tcp_framed.next().await;
        match socks5_connect_cmd {
            None => {
                info!("Nothing to read for socks5 connect process, socks5 transport: [{}]", self.id);
                return Ok(None);
            }
            Some(socks5_connect_cmd) => {
                match socks5_connect_cmd {
                    Err(e) => {
                        error!("Fail to decode socks5 connect command, sock5 transport: [{}], error: {:#?}", self.id, e);
                        return Err(e.into());
                    }
                    Ok(socks5_connect_cmd) => {
                        let client_socket_address = client_socket_address;
                        let source_address: PpaassAddress = client_socket_address.into();
                        let target_address = match socks5_connect_cmd.addr_type() {
                            Socks5AddrType::IpV4 => {
                                PpaassAddress::new(socks5_connect_cmd.dst_host().to_vec(), socks5_connect_cmd.dst_port(), PpaassAddressType::IpV4)
                            }
                            Socks5AddrType::IpV6 => {
                                PpaassAddress::new(socks5_connect_cmd.dst_host().to_vec(), socks5_connect_cmd.dst_port(), PpaassAddressType::IpV6)
                            }
                            Socks5AddrType::Domain => {
                                PpaassAddress::new(socks5_connect_cmd.dst_host().to_vec(), socks5_connect_cmd.dst_port(), PpaassAddressType::Domain)
                            }
                        };
                        match socks5_connect_cmd.request_type() {
                            Socks5ConnectRequestType::Connect => {
                                let proxy_addresses = self.configuration.proxy_addresses().clone().context("Proxy address did not configure properly")?;
                                let mut proxy_addresses_iter = proxy_addresses.iter();
                                let proxy_stream: Option<TcpStream> = loop {
                                    let proxy_address = proxy_addresses_iter.next();
                                    match proxy_address {
                                        None => break None,
                                        Some(proxy_address) => {
                                            let proxy_address: ProxyAddress = match proxy_address.to_string().try_into() {
                                                Err(e) => {
                                                    error!("Fail to parse proxy address because of error, socks5 transport: [{}], error: {:#?}", self.id, e);
                                                    continue;
                                                }
                                                Ok(address) => address
                                            };
                                            let proxy_address_string: String = proxy_address.into();
                                            match TcpStream::connect(proxy_address_string.clone()).await {
                                                Err(e) => {
                                                    error!("Fail connect to proxy address: [{}] because of error, socks5 transport: [{}], error: {:#?}", self.id,
                                                        proxy_address_string, e);
                                                    continue;
                                                }
                                                Ok(stream) => {
                                                    info!("Success connect to proxy address: [{}]", proxy_address_string);
                                                    break Some(stream);
                                                }
                                            }
                                        }
                                    }
                                };
                                match proxy_stream {
                                    None => {
                                        error!("Can not connect to proxy, socks5 transport: [{}]", self.id);
                                        return Err(PpaassAgentError::ConnectToProxyFail.into());
                                    }
                                    Some(proxy_stream) => {
                                        let connect_message_payload = PpaassAgentMessagePayload::new(
                                            source_address.clone(), target_address.clone(), PpaassAgentMessagePayloadType::TcpConnect, vec![],
                                        );
                                        let connect_message = PpaassMessage::new(
                                            "".to_string(), self.user_token.clone(),
                                            generate_uuid().into_bytes(), PpaassMessagePayloadEncryptionType::random(),
                                            connect_message_payload.into(),
                                        );
                                        let ppaass_message_codec = PpaassMessageCodec::new(rsa_public_key,
                                            rsa_private_key);
                                        let mut proxy_framed = ppaass_message_codec.framed(proxy_stream);
                                        proxy_framed.send(connect_message).await?;
                                        proxy_framed.flush().await?;
                                        let mut proxy_connect_response = proxy_framed.next().await;
                                        let mut retry_times = 0;
                                        let proxy_message = loop {
                                            match proxy_connect_response {
                                                None => {
                                                    tokio::time::sleep(Duration::from_secs(10)).await;
                                                    if retry_times > 2 {
                                                        info!("Retry 3 times to read proxy message for http transport [{}] but still fail.", self.id);
                                                        let connect_error_response = Socks5ConnectResponse::new_status_only(Socks5ConnectResponseStatus::Failure);
                                                        client_tcp_framed.send(connect_error_response).await?;
                                                        client_tcp_framed.flush().await?;
                                                        return Err(PpaassAgentError::ConnectToProxyFail.into());
                                                    }
                                                    retry_times += 1;
                                                    info!("Retry to read proxy message for http transport [{}] ...", self.id);
                                                    proxy_connect_response = proxy_framed.next().await;
                                                    continue;
                                                }
                                                Some(response) => {
                                                    match response {
                                                        Err(e) => {
                                                            let connect_error_response = Socks5ConnectResponse::new_status_only(Socks5ConnectResponseStatus::Failure);
                                                            client_tcp_framed.send(connect_error_response).await?;
                                                            client_tcp_framed.flush().await?;
                                                            return Err(PpaassAgentError::ConnectToProxyFail.into());
                                                        }
                                                        Ok(response) => {
                                                            break response;
                                                        }
                                                    }
                                                }
                                            }
                                        };
                                        let PpaassMessageSplitResult {
                                            id: proxy_message_id,
                                            payload: proxy_message_payload,
                                            ..
                                        } = proxy_message.split();
                                        let proxy_message_payload: PpaassProxyMessagePayload = proxy_message_payload.try_into()?;
                                        let PpaassProxyMessagePayloadSplitResult {
                                            payload_type: proxy_message_payload_type,
                                            ..
                                        } = proxy_message_payload.split();
                                        match proxy_message_payload_type {
                                            PpaassProxyMessagePayloadType::TcpConnectFail => {
                                                let connect_error_response = Socks5ConnectResponse::new_status_only(Socks5ConnectResponseStatus::Failure);
                                                client_tcp_framed.send(connect_error_response).await?;
                                                client_tcp_framed.flush().await?;
                                                Err(PpaassAgentError::ConnectToProxyFail.into())
                                            }
                                            PpaassProxyMessagePayloadType::TcpConnectSuccess => {
                                                let socks5_connect_success_response = Socks5ConnectResponse::new(
                                                    Socks5ConnectResponseStatus::Succeeded,
                                                    socks5_connect_cmd.addr_type(),
                                                    socks5_connect_cmd.dst_host().to_vec(),
                                                    socks5_connect_cmd.dst_port(),
                                                );
                                                client_tcp_framed.send(socks5_connect_success_response).await?;
                                                client_tcp_framed.flush().await?;
                                                self.status = TransportStatus::Connected;
                                                Ok(Some(ConnectResult {
                                                    client_tcp_stream,
                                                    connect_message_id: proxy_message_id,
                                                    proxy_framed,
                                                    source_address,
                                                    target_address,
                                                }))
                                            }
                                            PpaassProxyMessagePayloadType::TcpConnectionClose => {
                                                Ok(None)
                                            }
                                            _ => {
                                                let connect_error_response = Socks5ConnectResponse::new_status_only(Socks5ConnectResponseStatus::Failure);
                                                client_tcp_framed.send(connect_error_response).await?;
                                                client_tcp_framed.flush().await?;
                                                Err(PpaassAgentError::ConnectToProxyFail.into())
                                            }
                                        }
                                    }
                                }
                            }
                            Socks5ConnectRequestType::Bind => {
                                Ok(None)
                            }
                            Socks5ConnectRequestType::UdpAssociate => {
                                Ok(None)
                            }
                        }
                    }
                }
            }
        }
    }

    async fn relay(&mut self, connect_result: ConnectResult) -> Result<()> {
        if self.status != TransportStatus::Connected {
            return Err(PpaassAgentError::InvalidTransportStatus(self.id.clone(), TransportStatus::Connected, self.status).into());
        }
        let ConnectResult {
            connect_message_id,
            proxy_framed,
            source_address,
            target_address,
            client_tcp_stream,
            ..
        } = connect_result;
        let (mut proxy_framed_write, mut proxy_framed_read) = proxy_framed.split();
        self.status = TransportStatus::Relaying;
        let user_token = self.user_token.clone();
        let (mut client_tcp_stream_read, mut client_tcp_stream_write) = client_tcp_stream.into_split();
        let transport_id_for_proxy_to_client_relay = self.id.clone();
        let transport_id_for_client_to_proxy_relay = self.id.clone();
        let connect_message_id_for_client_to_proxy_relay = connect_message_id.clone();
        let connect_message_id_for_proxy_to_client_relay = connect_message_id.clone();
        let client_to_proxy_relay = tokio::spawn(async move {
            let mut client_read_bytes = 0;
            let mut proxy_write_bytes = 0;
            loop {
                let mut read_buf = Vec::<u8>::with_capacity(1024 * 64);
                match client_tcp_stream_read.read_buf(&mut read_buf).await {
                    Err(e) => {
                        error!("Fail to read data from agent client because of error, error: {:#?}", e);
                        return (client_read_bytes, proxy_write_bytes);
                    }
                    Ok(data_size) => {
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
                            return (client_read_bytes, proxy_write_bytes);
                        }
                        client_read_bytes += data_size;
                    }
                }
                let read_buf_size = read_buf.len();
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
                    error!("Fail to send data from agent to proxy because of error, error: {:#?}", e);
                    break;
                }
                if let Err(e) = proxy_framed_write.flush().await {
                    error!("Fail to flush data from agent to proxy because of error, error: {:#?}", e);
                    break;
                }
                proxy_write_bytes += read_buf_size;
            }
            (client_read_bytes, proxy_write_bytes)
        });
        let proxy_to_client_relay = tokio::spawn(async move {
            let mut client_write_bytes = 0;
            let mut proxy_read_bytes = 0;
            loop {
                info!("Begin the loop to read from proxy for socks 5 transport: [{}]", transport_id_for_proxy_to_client_relay);
                let proxy_message = proxy_framed_read.next().await;
                match proxy_message {
                    None => {
                        info!("Noting read from proxy for socks 5 transport: [{}]", transport_id_for_proxy_to_client_relay);
                        return (proxy_read_bytes, client_write_bytes);
                    }
                    Some(proxy_message) => {
                        match proxy_message {
                            Err(e) => {
                                error!("Fail to read data from proxy because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                                return (proxy_read_bytes, client_write_bytes);
                            }
                            Ok(proxy_message) => {
                                let PpaassMessageSplitResult {
                                    payload,
                                    ..
                                } = proxy_message.split();
                                let payload: Result<PpaassProxyMessagePayload, _> = payload.try_into();
                                match payload {
                                    Err(e) => {
                                        error!("Fail to read data from proxy because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                                        return (proxy_read_bytes, client_write_bytes);
                                    }
                                    Ok(payload) => {
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
                                                proxy_read_bytes += proxy_message_data.len();
                                                debug!("Receive target data for http transport: [{}]\n{}\n", transport_id_for_proxy_to_client_relay, String::from_utf8_lossy(&proxy_message_data));
                                                if let Err(e) = client_tcp_stream_write.write(&proxy_message_data).await {
                                                    error!("Fail to send data from agent to client because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                                                    return (proxy_read_bytes, client_write_bytes);
                                                }
                                                if let Err(e) = client_tcp_stream_write.flush().await {
                                                    error!("Fail to flush data from agent to client because of error, socks 5 transport:[{}], error: {:#?}",transport_id_for_proxy_to_client_relay, e);
                                                    return (proxy_read_bytes, client_write_bytes);
                                                }
                                                client_write_bytes += proxy_message_data.len();
                                            }
                                            PpaassProxyMessagePayloadType::TcpConnectionClose => {
                                                info!("Socks 5 transport:[{}] close",transport_id_for_proxy_to_client_relay);
                                                return (proxy_read_bytes, client_write_bytes);
                                            }
                                            other_payload_type => {
                                                error!("Fail to read data from proxy because of proxy give invalid type: {:?}, socks 5 transport:[{}]", other_payload_type, transport_id_for_proxy_to_client_relay);
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (client_read_bytes, proxy_write_bytes) = client_to_proxy_relay.await?;
        self.client_read_bytes += client_read_bytes;
        self.proxy_write_bytes += proxy_write_bytes;
        let (proxy_read_bytes, client_write_bytes) = proxy_to_client_relay.await?;
        self.proxy_read_bytes += proxy_read_bytes;
        self.client_write_bytes += client_write_bytes;
        Ok(())
    }
}
