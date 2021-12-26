use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{Decoder, Framed};
use url::Url;

use ppaass_common::codec::PpaassMessageCodec;
use ppaass_common::common::PpaassAddress;

use crate::codec::http::HttpCodec;
use crate::error::PpaassAgentError;
use crate::transport::common::{Transport, TransportSnapshot, TransportStatus};

type HttpFramed = Framed<TcpStream, HttpCodec>;

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";

pub(crate) struct HttpTransport {
    id: String,
    status: TransportStatus,
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
    snapshot_sender: Sender<TransportSnapshot>,
}

#[async_trait]
impl Transport for HttpTransport {
    async fn start(&mut self, client_tcp_stream: TcpStream, rsa_public_key: String,
                   rsa_private_key: String) -> Result<()> {
        let http_codec = HttpCodec::default();
        let client_stream_framed = http_codec.framed(client_tcp_stream);
        let client_stream_framed = self.connect(client_stream_framed, rsa_public_key, rsa_private_key).await?;
        self.relay(client_stream_framed).await?;
        self.close().await?;
        Ok(())
    }

    fn take_snapshot(&self) -> TransportSnapshot {
        todo!()
    }
}

impl HttpTransport {
    async fn connect(&mut self, mut client_stream_framed: HttpFramed, rsa_public_key: String,
                     rsa_private_key: String) -> Result<HttpFramed> {
        let ppaass_message_codec = PpaassMessageCodec::new(rsa_public_key,
                                                           rsa_private_key);
        let http_message = client_stream_framed.next().await;
        match http_message {
            None => {
                return Ok(client_stream_framed);
            }
            Some(message) => {
                match message {
                    Err(e) => {
                        return Ok(client_stream_framed);
                    }
                    Ok(http_request) => {
                        let request_target = http_request.request_target();
                        let request_method = http_request.method();
                        let request_url = match request_method.as_str().to_lowercase().as_str() {
                            "connect" => {
                                format!("{}{}{}", HTTPS_SCHEMA, SCHEMA_SEP, request_target.as_str())
                            }
                            _ => {
                                request_target.as_str().to_string()
                            }
                        };
                        let parsed_request_url = Url::parse(request_url.as_str())?;
                        let target_port = match parsed_request_url.port() {
                            None => {
                                match parsed_request_url.scheme() {
                                    HTTPS_SCHEMA => 443,
                                    _ => 80
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

                        TcpStream::connect()
                    }
                }
            }
        }
        return Ok(client_stream_framed);
    }
    async fn relay(&mut self, client_stream_framed: HttpFramed) -> Result<()> {
        todo!()
    }

    async fn close(&mut self) -> Result<()> {
        todo!()
    }
}