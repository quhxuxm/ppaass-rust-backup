use std::time::{Instant, SystemTime};

use tokio::net::{TcpStream, UdpSocket};
use uuid::Uuid;

use ppaass_common::common::PpaassMessage;
use ppaass_common::error::PpaassError;

pub(crate) enum AgentTcpTransportStatus {
    New,
    Closed,
    Connected,
    Relaying,
}

pub(crate) struct AgentTcpTransport {
    id: Vec<u8>,
    status: AgentTcpTransportStatus,
    read_bytes: u128,
    write_bytes: u128,
    start_time: u128,
    end_time: Option<u128>,
    user_token: Vec<u8>,
    tcp_stream: TcpStream,
}

impl AgentTcpTransport {
    pub fn new(user_token: Vec<u8>, tcp_stream: TcpStream) -> Result<Self, PpaassError> {
        let id = Uuid::new_v4().as_bytes().to_vec();
        Ok(Self {
            id,
            status: AgentTcpTransportStatus::New,
            read_bytes: 0,
            write_bytes: 0,
            start_time: {
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| PpaassError::Other {
                    source: Box::new(e)
                })?.as_millis()
            },
            end_time: None,
            user_token,
            tcp_stream,
        })
    }

    pub fn increase_read_bytes(&mut self, increase: u128) {
        self.read_bytes += increase;
    }

    pub fn increase_write_bytes(&mut self, increase: u128) {
        self.write_bytes += increase;
    }

    pub fn read_frame(&mut self) -> Result<PpaassMessage, PpaassError> {
        Framed
        todo!()
    }

    pub fn write_frame(&mut self, message: PpaassMessage) {
        todo!()
    }

    pub fn close(&mut self) -> Result<(), PpaassError> {
        self.status = AgentTcpTransportStatus::Closed;
        self.end_time = {
            Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|e| PpaassError::Other {
                source: Box::new(e)
            })?.as_millis())
        };
        Ok(())
    }
}


pub(crate) struct UdpTransport {
    id: Vec<u8>,
    read_bytes: u64,
    write_bytes: u64,
    start_time: u64,
    end_time: u64,
    user_token: Vec<u8>,
    udp_socket: UdpSocket,
}