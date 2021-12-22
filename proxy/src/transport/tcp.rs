use std::time::SystemTime;

use anyhow::{anyhow, Context};
use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use uuid::Uuid;

use ppaass_common::codec::PpaassMessageCryptoCodec;

use crate::error::PpaassProxyError;

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
    pub fn new(user_token: Vec<u8>, source_edge: TcpStream) -> Result<Self, PpaassProxyError> {
        let id = Uuid::new_v4().to_string();
        Ok(Self {
            id,
            status: TcpTransportStatus::New,
            source_read_bytes: 0,
            source_write_bytes: 0,
            target_read_bytes: 0,
            target_write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| PpaassProxyError::Other {
                    source: e.into()
                })?.as_millis()
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
    pub async fn run(&mut self) -> Result<()> {
        // Initialize the target edge stream
        self.init().await?;
        // Start relay data
        self.relay().await?;
        //Relay complete
        self.close().await?;
        Ok(())
    }

    async fn init(&mut self) -> Result<()> {
        if self.status != TcpTransportStatus::New {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::New, self.status).into());
        }
        let source_edge_framed = &mut Framed::with_capacity(
            self.source_edge.as_mut().context("Can not unwrap source edge.")?,
            PpaassMessageCryptoCodec::new("".to_string(), "".to_string()),
            1024,
        );
        source_edge_framed.split();
        self.status = TcpTransportStatus::Initialized;
        todo!()
    }

    async fn relay(&mut self) -> Result<()> {
        if self.status != TcpTransportStatus::Initialized {
            return Err(PpaassProxyError::InvalidTcpTransportStatus(self.id.clone(), TcpTransportStatus::Initialized, self.status).into());
        }
        self.status = TcpTransportStatus::Relaying;
        todo!()
    }

    async fn close(&mut self) -> Result<()> {
        self.status = TcpTransportStatus::Closing;
        self.end_time = {
            Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| PpaassProxyError::Other {
                source: e.into()
            })?.as_millis())
        };
        if let Some(mut source_edge_stream) = self.source_edge.take() {
            source_edge_stream.shutdown().await.map_err(|e| PpaassProxyError::Other {
                source: e.into()
            })?;
        }
        if let Some(mut target_edge_stream) = self.target_edge.take() {
            target_edge_stream.shutdown().await.map_err(|e| PpaassProxyError::Other {
                source: e.into()
            })?;
        }
        self.status = TcpTransportStatus::Closed;
        Ok(())
    }
}
