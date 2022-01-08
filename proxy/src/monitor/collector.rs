use log::error;
use tokio::sync::mpsc::Sender;

use crate::monitor::data::{TransportSnapshot, TransportTraffic, TransportTrafficType};
use crate::transport::Transport;

pub(crate) struct TransportInfoCollector {
    transport_snapshot_sender: Sender<TransportSnapshot>,
    transport_traffic_sender: Sender<TransportTraffic>,
}

impl TransportInfoCollector {
    pub fn new(
        transport_snapshot_sender: Sender<TransportSnapshot>,
        transport_traffic_sender: Sender<TransportTraffic>,
    ) -> Self {
        Self {
            transport_snapshot_sender,
            transport_traffic_sender,
        }
    }

    pub async fn publish_transport_snapshot(&self, transport: &Transport) {
        let snapshot = TransportSnapshot::take_snapshot(transport);
        if let Err(e) = self.transport_snapshot_sender.send(snapshot).await {
            error!(
                "Fail to send transport snapshot to monitor because of error: {:#?}",
                e
            );
        }
    }

    pub async fn publish_transport_traffic(
        &self,
        transport_id: String,
        traffic_type: TransportTrafficType,
        bytes: usize,
    ) {
        let traffic = TransportTraffic::new(transport_id, traffic_type, bytes);
        if let Err(e) = self.transport_traffic_sender.send(traffic).await {
            error!(
                "Fail to send transport traffic to monitor because of error: {:#?}",
                e
            );
        }
    }
}
