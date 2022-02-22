use std::net::IpAddr;

use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use bytecodec::bytes::BytesEncoder;
use bytecodec::EncodeExt;
use bytes::BufMut;
use chrono::Utc;
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use httpcodec::{BodyEncoder, HttpVersion, ReasonPhrase, RequestEncoder, Response, StatusCode};
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed};
use tracing::{debug, error, info};
use url::Url;

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{
    PpaassAddress, PpaassAddressType, PpaassMessage, PpaassMessagePayloadEncryptionType,
    PpaassMessageSplitResult, PpaassProxyMessagePayloadSplitResult,
};
use ppaass_common::generate_uuid;
use ppaass_common::proxy::{PpaassProxyMessagePayload, PpaassProxyMessagePayloadType};

use crate::codec::http::HttpCodec;
use crate::common::ProxyAddress;
use crate::config::{
    AGENT_PRIVATE_KEY, AGENT_SERVER_CONFIG, DEFAULT_TCP_BUFFER_SIZE, DEFAULT_TCP_MAX_FRAME_SIZE,
    PROXY_PUBLIC_KEY,
};
use crate::error::PpaassAgentError;
use crate::transport::common::{Transport, TransportMetaInfo, TransportStatus};

type HttpFramed<'a> = Framed<&'a mut TcpStream, HttpCodec>;
type PpaassMessageFramed = Framed<TcpStream, PpaassMessageCodec>;

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;
const OK_CODE: u16 = 200;
const ERROR_CODE: u16 = 400;
const ERROR_REASON: &str = " ";
const CONNECTION_ESTABLISHED: &str = "Connection Established";

pub(crate) struct HttpTransport {
    meta_info: TransportMetaInfo,
}

struct InitResult {
    client_tcp_stream: TcpStream,
    proxy_framed: PpaassMessageFramed,
    http_init_message: Option<Vec<u8>>,
    connect_message_id: String,
    source_address: PpaassAddress,
    target_address: PpaassAddress,
}

#[async_trait]
impl Transport for HttpTransport {
    async fn start(&mut self, client_tcp_stream: TcpStream) -> Result<()> {
        let init_result = self.init(client_tcp_stream).await?;
        return match init_result {
            None => Ok(()),
            Some(init_result) => {
                self.relay(init_result).await?;
                Ok(())
            }
        };
    }

    async fn close(&mut self) -> Result<()> {
        self.meta_info.status = TransportStatus::Closed;
        self.meta_info.end_time = Some(Utc::now().timestamp_millis());
        info!("Graceful close http transport [{}]", self.meta_info);
        Ok(())
    }
}

impl HttpTransport {
    pub fn new(meta_info: TransportMetaInfo) -> Self {
        Self { meta_info }
    }

    async fn send_error_to_client(mut client_http_framed: HttpFramed<'_>) -> Result<()> {
        let bad_request_status_code = StatusCode::new(ERROR_CODE).unwrap();
        let error_response_reason = ReasonPhrase::new(ERROR_REASON).unwrap();
        let connect_error_response = Response::new(
            HttpVersion::V1_1,
            bad_request_status_code,
            error_response_reason,
            vec![],
        );
        client_http_framed.send(connect_error_response).await?;
        client_http_framed.flush().await?;
        Ok(())
    }

    async fn init(&mut self, mut client_tcp_stream: TcpStream) -> Result<Option<InitResult>> {
        let transport_id = self.meta_info.id.clone();
        let client_address = client_tcp_stream.peer_addr()?;
        let http_codec = HttpCodec::default();
        let mut client_stream_framed = http_codec.framed(&mut client_tcp_stream);
        let http_message = match client_stream_framed.next().await {
            None => {
                return Ok(None);
            }
            Some(r) => r,
        };
        let http_message = match http_message {
            Err(e) => {
                Self::send_error_to_client(client_stream_framed).await?;
                return Err(e.into());
            }
            Ok(r) => r,
        };
        let request_target = http_message.request_target().to_string();
        let request_method = http_message.method();
        let (request_url, http_data) = match request_method.as_str().to_lowercase().as_str() {
            CONNECT_METHOD => (
                format!("{}{}{}", HTTPS_SCHEMA, SCHEMA_SEP, request_target),
                None,
            ),
            _ => {
                let mut http_data_encoder = RequestEncoder::<BodyEncoder<BytesEncoder>>::default();
                let encode_result = http_data_encoder.encode_into_bytes(http_message);
                (request_target, Some(encode_result?))
            }
        };
        let parsed_request_url = Url::parse(request_url.as_str())?;
        let target_port = match parsed_request_url.port() {
            None => match parsed_request_url.scheme() {
                HTTPS_SCHEMA => HTTPS_DEFAULT_PORT,
                _ => HTTP_DEFAULT_PORT,
            },
            Some(port) => port,
        };
        let target_host = match parsed_request_url.host() {
            None => {
                Self::send_error_to_client(client_stream_framed).await?;
                return Err(PpaassAgentError::FailToParseTargetHostFromHttpRequest.into());
            }
            Some(h) => h.to_string(),
        };
        let proxy_addresses = AGENT_SERVER_CONFIG
            .proxy_addresses()
            .clone()
            .context("Proxy address did not configure properly")?;
        let mut proxy_addresses_iter = proxy_addresses.iter();
        let proxy_stream: Option<TcpStream> = loop {
            let proxy_address = proxy_addresses_iter.next();
            match proxy_address {
                None => break None,
                Some(proxy_address) => {
                    let proxy_address: ProxyAddress = match proxy_address.to_string().try_into() {
                        Err(e) => {
                            error!("Fail to parse proxy address because of error: {:#?}", e);
                            continue;
                        }
                        Ok(address) => address,
                    };
                    let proxy_address_string: String = proxy_address.into();
                    match TcpStream::connect(&proxy_address_string).await {
                        Err(e) => {
                            error!(
                                "Fail connect to proxy: [{}] because of error, http transport:[{}], error: {:#?}",
                                self.meta_info, proxy_address_string, e
                            );
                            continue;
                        }
                        Ok(stream) => {
                            info!(
                                "Success connect to proxy, http transport:[{}], proxy: [{}]",
                                self.meta_info, proxy_address_string
                            );
                            stream.set_nodelay(true)?;
                            break Some(stream);
                        }
                    }
                }
            }
        };
        let (proxy_stream, target_host, target_port, http_init_message) = match proxy_stream {
            None => {
                error!(
                    "None of the proxy address is connectable, http transport:[{}]",
                    transport_id
                );
                Self::send_error_to_client(client_stream_framed).await?;
                return Err(PpaassAgentError::FailToConnectProxy.into());
            }
            Some(proxy_stream) => match http_data {
                None => (proxy_stream, target_host, target_port, None),
                Some(data) => (proxy_stream, target_host, target_port, Some(data)),
            },
        };
        let client_ip = match client_address.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        let client_port = client_address.port();
        let mut proxy_framed = Self::create_proxy_framed(
            &*PROXY_PUBLIC_KEY,
            &*AGENT_PRIVATE_KEY,
            proxy_stream,
            AGENT_SERVER_CONFIG
                .max_frame_size()
                .unwrap_or(DEFAULT_TCP_MAX_FRAME_SIZE),
            AGENT_SERVER_CONFIG.compress().unwrap_or(false),
        );
        let source_address = PpaassAddress::new(client_ip, client_port, PpaassAddressType::IpV4);
        let target_address: PpaassAddress =
            format!("{}:{}", target_host, target_port).try_into()?;
        let connect_message_payload = PpaassAgentMessagePayload::new(
            source_address.clone(),
            target_address.clone(),
            PpaassAgentMessagePayloadType::TcpConnect,
            vec![],
        );
        let connect_message = PpaassMessage::new(
            "".to_string(),
            self.meta_info.user_token.clone(),
            generate_uuid().into_bytes(),
            PpaassMessagePayloadEncryptionType::random(),
            connect_message_payload.into(),
        );
        proxy_framed.send(connect_message).await?;
        proxy_framed.flush().await?;
        let proxy_connect_response = proxy_framed.next().await;
        let proxy_message = match proxy_connect_response {
            None => {
                error!("Fail to read proxy connect response message for http transport: [{}], target:[{}] , None received from proxy", transport_id, target_address);
                Self::send_error_to_client(client_stream_framed).await?;
                return Err(PpaassAgentError::FailToConnectProxy.into());
            }
            Some(response) => match response {
                Err(e) => {
                    error!("Fail to read proxy connect response message for http transport: [{}], target:[{}]  , error: {:#?}", transport_id, target_address, e);
                    Self::send_error_to_client(client_stream_framed).await?;
                    return Err(PpaassAgentError::FailToConnectProxy.into());
                }
                Ok(r) => {
                    info!("Success receive proxy connect response message for http transport: [{}], target:[{}]", transport_id, target_address);
                    r
                }
            },
        };
        let PpaassMessageSplitResult {
            id: proxy_message_id,
            ref_id: _proxy_message_ref_id,
            payload: proxy_message_payload,
            ..
        } = proxy_message.split();
        let message_payload: PpaassProxyMessagePayload = proxy_message_payload.try_into()?;
        let PpaassProxyMessagePayloadSplitResult {
            payload_type: proxy_message_payload_type,
            ..
        } = message_payload.split();
        return match proxy_message_payload_type {
            PpaassProxyMessagePayloadType::TcpConnectSuccess => {
                match http_init_message {
                    None => {
                        let http_connect_success_response = Response::new(
                            HttpVersion::V1_1,
                            StatusCode::new(OK_CODE).unwrap(),
                            ReasonPhrase::new(CONNECTION_ESTABLISHED).unwrap(),
                            vec![],
                        );
                        client_stream_framed
                            .send(http_connect_success_response)
                            .await?;
                        client_stream_framed.flush().await?;
                    }
                    Some(_) => {
                        debug!("Http request do not need return connection established, http transport: [{}]", transport_id)
                    }
                }
                self.meta_info.status = TransportStatus::TcpConnected;
                self.meta_info.source_address = Some(source_address.clone());
                self.meta_info.target_address = Some(target_address.clone());
                return Ok(Some(InitResult {
                    client_tcp_stream,
                    proxy_framed,
                    http_init_message,
                    connect_message_id: proxy_message_id,
                    source_address,
                    target_address,
                }));
            }
            PpaassProxyMessagePayloadType::TcpConnectFail => {
                Self::send_error_to_client(client_stream_framed).await?;
                Err(PpaassAgentError::FailToConnectProxy.into())
            }
            PpaassProxyMessagePayloadType::TcpConnectionClose => {
                Self::send_error_to_client(client_stream_framed).await?;
                return Ok(None);
            }
            _status => {
                Self::send_error_to_client(client_stream_framed).await?;
                Err(PpaassAgentError::FailToConnectProxy.into())
            }
        };
    }

    async fn relay(&mut self, init_result: InitResult) -> Result<()> {
        if self.meta_info.status != TransportStatus::TcpConnected {
            return Err(PpaassAgentError::InvalidTransportStatus(
                self.meta_info.id.clone(),
                TransportStatus::TcpConnected,
                self.meta_info.status,
            )
            .into());
        }
        let InitResult {
            http_init_message,
            connect_message_id,
            proxy_framed,
            source_address,
            target_address,
            client_tcp_stream,
            ..
        } = init_result;
        let (mut proxy_framed_write, mut proxy_framed_read) = proxy_framed.split();
        self.meta_info.status = TransportStatus::Relaying;
        let user_token = self.meta_info.user_token.clone();
        let (mut client_tcp_stream_read, mut client_tcp_stream_write) = split(client_tcp_stream);
        let transport_id_p2c = self.meta_info.id.clone();
        let transport_id_c2p = self.meta_info.id.clone();
        let connect_message_id_c2p = connect_message_id.clone();
        let (
            client_connection_closed_notifier_sender,
            mut client_connection_closed_notifier_receiver,
        ) = tokio::sync::mpsc::channel::<bool>(1);
        tokio::spawn(async move {
            if let Some(message) = http_init_message {
                let init_data_message_body = PpaassAgentMessagePayload::new(
                    source_address.clone(),
                    target_address.clone(),
                    PpaassAgentMessagePayloadType::TcpData,
                    message,
                );
                let init_data_message = PpaassMessage::new(
                    connect_message_id,
                    user_token.clone(),
                    generate_uuid().into_bytes(),
                    PpaassMessagePayloadEncryptionType::random(),
                    init_data_message_body.into(),
                );
                if let Err(e) = proxy_framed_write.send(init_data_message).await {
                    error!("Fail to send data from agent to proxy because of error (init data), error: {:#?}", e);
                    return;
                }
                if let Err(e) = proxy_framed_write.flush().await {
                    error!("Fail to flush data from agent to proxy because of error (init data), error: {:#?}", e);
                    return;
                }
            }
            loop {
                let mut read_buf = Vec::<u8>::with_capacity(DEFAULT_TCP_BUFFER_SIZE);
                let data_size = match client_tcp_stream_read.read_buf(&mut read_buf).await {
                    Err(e) => {
                        error!(
                            "Fail to read data from agent client because of error, error: {:#?}",
                            e
                        );
                        if let Err(e) = client_connection_closed_notifier_sender.send(true).await {
                            error!("Fail to send client connection closed notification because of error, socks 5 transport: [{}], error: {:#?}", transport_id_c2p, e)
                        };
                        let connection_close_message_body = PpaassAgentMessagePayload::new(
                            source_address.clone(),
                            target_address.clone(),
                            PpaassAgentMessagePayloadType::TcpConnectionClose,
                            vec![],
                        );
                        let connection_close_message = PpaassMessage::new(
                            connect_message_id_c2p.clone(),
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
                        connect_message_id_c2p.clone(),
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
                    connect_message_id_c2p.clone(),
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
        tokio::spawn(async move {
            loop {
                debug!(
                    "Begin the loop to read from proxy for http transport: [{}]",
                    transport_id_p2c
                );
                if let Ok(true) = client_connection_closed_notifier_receiver.try_recv() {
                    error!(
                        "Client connection closed, http transport:[{}]",
                        transport_id_p2c
                    );
                    return;
                }
                let proxy_message = match proxy_framed_read.next().await {
                    None => {
                        info!(
                            "Noting read from proxy for http transport: [{}]",
                            transport_id_p2c
                        );
                        return;
                    }
                    Some(r) => r,
                };
                let proxy_message = match proxy_message {
                    Err(e) => {
                        error!("Fail to read data from proxy because of error, http transport:[{}], error: {:#?}",transport_id_p2c, e);
                        return;
                    }
                    Ok(r) => r,
                };
                let PpaassMessageSplitResult { payload, .. } = proxy_message.split();
                let payload: Result<PpaassProxyMessagePayload, _> = payload.try_into();
                let payload = match payload {
                    Err(e) => {
                        error!("Fail to read data from proxy because of error, http transport:[{}], error: {:#?}",transport_id_p2c, e);
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
                        error!("Fail to read data from proxy because of proxy give data relay fail, http transport: [{}]", transport_id_p2c);
                        continue;
                    }
                    PpaassProxyMessagePayloadType::TcpData => {
                        debug!(
                            "Receive target data for http transport: [{}]\n{}\n",
                            transport_id_p2c,
                            String::from_utf8_lossy(&proxy_message_data)
                        );
                        if let Err(e) = client_tcp_stream_write.write(&proxy_message_data).await {
                            error!("Fail to send data from agent to client because of error, http transport:[{}], error: {:#?}",transport_id_p2c, e);
                            return;
                        }
                        if let Err(e) = client_tcp_stream_write.flush().await {
                            error!("Fail to flush data from agent to client because of error, http transport:[{}], error: {:#?}",transport_id_p2c, e);
                            return;
                        }
                    }
                    PpaassProxyMessagePayloadType::TcpConnectionClose => {
                        info!("Http transport:[{}] close", transport_id_p2c);
                        return;
                    }
                    other_payload_type => {
                        error!("Fail to read data from proxy because of proxy give invalid type: {:?}, http transport:[{}]", other_payload_type, transport_id_p2c);
                        continue;
                    }
                }
            }
        });
        Ok(())
    }
}
