use ppaass_common::common::{PpaassAddress, PpaassAddressType};

use crate::transport::{Transport, TransportStatus};

#[derive(Hash, Debug, Clone, Eq, PartialEq)]
pub(crate) enum TransportTrafficType {
    AgentRead,
    AgentWrite,
    TargetRead,
    TargetWrite,
}

#[derive(Debug, Clone)]
pub(crate) struct TransportTraffic {
    pub transport_id: String,
    pub traffic_type: TransportTrafficType,
    pub bytes: usize,
}

impl TransportTraffic {
    pub fn new(transport_id: String, traffic_type: TransportTrafficType, bytes: usize) -> Self {
        Self {
            transport_id,
            traffic_type,
            bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransportSnapshot {
    pub id: String,
    pub status: TransportStatus,
    pub start_time: u128,
    pub end_time: u128,
    pub user_token: Vec<u8>,
    pub agent_remote_address: PpaassAddress,
    pub source_address: PpaassAddress,
    pub target_address: PpaassAddress,
}

impl TransportSnapshot {
    pub fn take_snapshot(transport: &Transport) -> TransportSnapshot {
        TransportSnapshot {
            id: transport.id().to_string().clone(),
            user_token: transport
                .user_token()
                .as_ref()
                .unwrap_or(vec![].as_ref())
                .clone(),
            status: transport.status().clone(),
            agent_remote_address: transport.agent_remote_address().into(),
            source_address: transport
                .source_address()
                .as_ref()
                .unwrap_or(&PpaassAddress::new(vec![], 0, PpaassAddressType::IpV4))
                .clone(),
            target_address: transport
                .target_address()
                .as_ref()
                .unwrap_or(&PpaassAddress::new(vec![], 0, PpaassAddressType::IpV4))
                .clone(),
            start_time: transport.start_time(),
            end_time: transport.end_time().unwrap_or(0),
        }
    }
}
