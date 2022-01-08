use std::sync::Arc;

use log::trace;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::Receiver;

use crate::monitor::data::{TransportSnapshot, TransportTraffic};

pub(crate) struct TransportInfoAggregator {
    transport_snapshot_receiver: Receiver<TransportSnapshot>,
    transport_traffic_receiver: Receiver<TransportTraffic>,
    monitor_runtime: Arc<Runtime>,
}

impl TransportInfoAggregator {
    pub fn new(
        transport_snapshot_receiver: Receiver<TransportSnapshot>,
        transport_traffic_receiver: Receiver<TransportTraffic>,
        monitor_runtime: Arc<Runtime>,
    ) -> Self {
        Self {
            transport_snapshot_receiver,
            transport_traffic_receiver,
            monitor_runtime,
        }
    }

    pub fn start(self) {
        let mut transport_snapshot_receiver = self.transport_snapshot_receiver;
        let mut transport_traffic_receiver = self.transport_traffic_receiver;
        self.monitor_runtime.spawn(async move {
            loop {
                match transport_snapshot_receiver.recv().await {
                    None => {
                        continue;
                    }
                    Some(transport_snapshot) => {
                        trace!("{:?}", transport_snapshot);
                    }
                };
            }
        });
        self.monitor_runtime.spawn(async move {
            loop {
                match transport_traffic_receiver.recv().await {
                    None => {
                        continue;
                    }
                    Some(transport_traffic) => {
                        trace!("{:?}", transport_traffic);
                    }
                };
            }
        });
    }
}
