use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytecodec::bytes::BytesEncoder;
use bytecodec::EncodeExt;
use futures_util::{SinkExt, StreamExt};
use httpcodec::{BodyEncoder, RequestEncoder};
use log::{error, info};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};
use url::Url;

use ppaass_common::agent::{PpaassAgentMessagePayload, PpaassAgentMessagePayloadType};
use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::{PpaassAddress, PpaassAddressType, PpaassMessage, PpaassMessagePayloadEncryptionType, PpaassMessageSplitResult};
use ppaass_common::generate_uuid;
use ppaass_common::proxy::{PpaassProxyMessagePayload, PpaassProxyMessagePayloadType};

use crate::codec::http::HttpCodec;
use crate::config::AgentConfiguration;
use crate::error::PpaassAgentError;
use crate::transport::common::{ProxyAddress, Transport, TransportSnapshot, TransportStatus};

type HttpFramed = Framed<TcpStream, HttpCodec>;
type PpaassMessageFramed = Framed<TcpStream, PpaassMessageCodec>;

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;

pub(crate) struct HttpTransport {
    id: String,
    status: TransportStatus,
    agent_read_bytes: usize,
    agent_write_bytes: usize,
    target_read_bytes: usize,
    target_write_bytes: usize,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Vec<u8>,
    agent_remote_address: Option<SocketAddr>,
    source_address: Option<PpaassAddress>,
    target_address: Option<PpaassAddress>,
    snapshot_sender: Sender<TransportSnapshot>,
    configuration: Arc<AgentConfiguration>,
}

#[async_trait]
impl Transport for HttpTransport {
    async fn start(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String,
        rsa_private_key: String) -> Result<()> {
        let init_result = self.init(client_tcp_stream, rsa_public_key, rsa_private_key).await;
        let (client_stream_framed, proxy_framed, init_message) = match init_result {
            Err(_) => {
                self.close().await?;
                return Err(PpaassAgentError::ConnectToProxyFail.into());
            }
            Ok(result) => result
        };
        let proxy_framed = proxy_framed.context("Can not unwrap proxy framed from init result")?;
        self.relay(client_stream_framed, proxy_framed, init_message).await?;
        self.close().await?;
        Ok(())
    }

    fn take_snapshot(&self) -> TransportSnapshot {
        todo!()
    }
}

impl HttpTransport {
    pub(crate) fn new(configuration: Arc<AgentConfiguration>, snapshot_sender: Sender<TransportSnapshot>) -> Result<Self> {
        let user_token = configuration.user_token().clone().context("Can not get user token from configuration.")?;
        Ok(Self {
            id: generate_uuid(),
            status: TransportStatus::New,
            agent_read_bytes: 0,
            agent_write_bytes: 0,
            target_read_bytes: 0,
            target_write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_millis()
            },
            end_time: None,
            user_token: user_token.into_bytes(),
            agent_remote_address: None,
            source_address: None,
            target_address: None,
            snapshot_sender,
            configuration,
        })
    }
    async fn init(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String,
        rsa_private_key: String) -> Result<(HttpFramed, Option<PpaassMessageFramed>, Option<Vec<u8>>)> {
        let client_address = client_tcp_stream.peer_addr()?;
        let http_codec = HttpCodec::default();
        let mut client_stream_framed = http_codec.framed(client_tcp_stream);
        let http_message = client_stream_framed.next().await;
        let (proxy_stream, target_host, target_port, http_init_message) = match http_message {
            None => {
                return Ok((client_stream_framed, None, None));
            }
            Some(message) => {
                match message {
                    Err(e) => {
                        return Ok((client_stream_framed, None, None));
                    }
                    Ok(http_request) => {
                        let request_target = http_request.request_target().to_string();
                        let request_method = http_request.method();
                        let (request_url, http_data) = match request_method.as_str().to_lowercase().as_str() {
                            CONNECT_METHOD => {
                                (format!("{}{}{}", HTTPS_SCHEMA, SCHEMA_SEP, request_target), None)
                            }
                            _ => {
                                let mut http_data_encoder = RequestEncoder::<BodyEncoder<BytesEncoder>>::default();
                                let encode_result = http_data_encoder.encode_into_bytes(http_request);
                                (request_target, Some(encode_result?))
                            }
                        };
                        let parsed_request_url = Url::parse(request_url.as_str())?;
                        let target_port = match parsed_request_url.port() {
                            None => {
                                match parsed_request_url.scheme() {
                                    HTTPS_SCHEMA => HTTPS_DEFAULT_PORT,
                                    _ => HTTP_DEFAULT_PORT
                                }
                            }
                            Some(port) => port
                        };
                        let target_host = match parsed_request_url.host() {
                            None => {
                                return Err(PpaassAgentError::FailToParseTargetHostFromHttpRequest.into());
                            }
                            Some(h) => {
                                h.to_string()
                            }
                        };
                        let proxy_addresses = self.configuration.proxy_addresses().clone().context("Proxy address did not configure properly")?;
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
                                        Ok(addr) => addr
                                    };
                                    let proxy_address_string: String = proxy_address.into();
                                    match TcpStream::connect(proxy_address_string.clone()).await {
                                        Err(e) => {
                                            error!("Fail connect to proxy address: [{}] because of error: {:#?}", proxy_address_string, e);
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
                                error!("None of the proxy address is connectable");
                                return Err(PpaassAgentError::ConnectToProxyFail.into());
                            }
                            Some(proxy_stream) => {
                                match http_data {
                                    None => (proxy_stream, target_host, target_port, None),
                                    Some(data) => (proxy_stream, target_host, target_port, Some(data)),
                                }
                            }
                        }
                    }
                }
            }
        };
        let client_ip = match client_address.ip() {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        let client_port = client_address.port();
        let ppaass_message_codec = PpaassMessageCodec::new(rsa_public_key,
            rsa_private_key);
        let mut proxy_framed = ppaass_message_codec.framed(proxy_stream);
        let source_address = PpaassAddress::new(client_ip, client_port, PpaassAddressType::IpV4);
        let target_address: PpaassAddress = format!("{}:{}", target_host, target_port).try_into()?;
        let connect_message_payload = PpaassAgentMessagePayload::new(
            source_address, target_address, PpaassAgentMessagePayloadType::TcpConnect, vec![],
        );
        let connect_message = PpaassMessage::new(
            vec![], self.user_token.clone(),
            generate_uuid().into_bytes(), PpaassMessagePayloadEncryptionType::random(),
            connect_message_payload.into(),
        );
        proxy_framed.send(connect_message).await?;
        proxy_framed.flush().await?;
        let proxy_connect_response = proxy_framed.next().await;
        let proxy_message = loop {
            match proxy_connect_response {
                None => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
                Some(response) => {
                    match response {
                        Err(e) => {
                            return Err(PpaassAgentError::ConnectToProxyFail.into());
                        }
                        Ok(r) => {
                            break r;
                        }
                    }
                }
            }
        };
        let PpaassMessageSplitResult {
            payload,
            ..
        } = proxy_message.split();
        let message_payload: PpaassProxyMessagePayload = payload.try_into()?;
        return match message_payload.payload_type() {
            PpaassProxyMessagePayloadType::TcpConnectSuccess => {
                self.status = TransportStatus::Connected;
                Ok((client_stream_framed, Some(proxy_framed), http_init_message))
            }
            _status => {
                Err(PpaassAgentError::ConnectToProxyFail.into())
            }
        };
    }

    async fn relay(&mut self, client_stream_framed: HttpFramed, proxy_stream_framed: PpaassMessageFramed, init_message: Option<Vec<u8>>) -> Result<()> {
        todo!()
    }

    async fn close(&mut self) -> Result<()> {
        todo!()
    }
}
