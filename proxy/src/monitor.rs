use std::net::SocketAddr;

use log::error;
use tokio::sync::broadcast::Sender;

use ppaass_common::common::{PpaassAddress, PpaassAddressType};

use crate::transport::{Transport, TransportStatus};

#[derive(Debug, Clone)]
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

pub(crate) struct TransportMonitor {
    transport_snapshot_sender: Sender<TransportSnapshot>,
    transport_traffic_sender: Sender<TransportTraffic>,
}

impl TransportMonitor {
    pub fn new(
        transport_snapshot_sender: Sender<TransportSnapshot>,
        transport_traffic_sender: Sender<TransportTraffic>,
    ) -> Self {
        Self {
            transport_snapshot_sender,
            transport_traffic_sender,
        }
    }

    pub fn publish_transport_snapshot(&self, transport: &Transport) {
        let snapshot = TransportSnapshot::take_snapshot(transport);
        if let Err(e) = self.transport_snapshot_sender.send(snapshot) {
            error!(
                "Fail to send transport snapshot to monitor: {:#?}, error: {:#?}",
                snapshot, e
            );
        }
    }

    pub fn publish_transport_traffic(
        &self,
        transport_id: String,
        traffic_type: TransportTrafficType,
        bytes: usize,
    ) {
        let traffic = TransportTraffic::new(transport_id, traffic_type, bytes);
        if let Err(e) = self.transport_traffic_sender.send(traffic) {
            error!(
                "Fail to send transport traffic to monitor: {:#?}, error: {:#?}",
                traffic, e
            );
        }
    }
}
