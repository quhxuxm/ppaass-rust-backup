use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, trace};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::Receiver;

use ppaass_common::common::PpaassAddress;
use crate::config::ProxyConfiguration;

use crate::monitor::data::{TransportSnapshot, TransportTraffic, TransportTrafficType};
use crate::transport::TransportStatus;

#[derive(Debug)]
pub(crate) struct TransportAggregateInfo {
    pub id: String,
    pub status: TransportStatus,
    pub start_time: u128,
    pub end_time: u128,
    pub user_token: Vec<u8>,
    pub agent_remote_address: PpaassAddress,
    pub source_address: PpaassAddress,
    pub target_address: PpaassAddress,
    pub traffic: HashMap<TransportTrafficType, usize>,
}

pub(crate) struct TransportInfoAggregator {
    transport_snapshot_receiver: Receiver<TransportSnapshot>,
    transport_traffic_receiver: Receiver<TransportTraffic>,
    transport_infos: HashMap<String, TransportAggregateInfo>,
    configuration: Arc<ProxyConfiguration>,
}

impl TransportInfoAggregator {
    pub fn new(
        transport_snapshot_receiver: Receiver<TransportSnapshot>,
        transport_traffic_receiver: Receiver<TransportTraffic>,
        configuration: Arc<ProxyConfiguration>,
    ) -> Self {
        Self {
            transport_snapshot_receiver,
            transport_traffic_receiver,
            transport_infos: HashMap::new(),
            configuration
        }
    }

    pub async fn start(mut self) {
        if let Some(false) = self.configuration.enable_monitor() {
            return;
        }
        let mut transport_snapshot_receiver = self.transport_snapshot_receiver;
        let mut transport_traffic_receiver = self.transport_traffic_receiver;
        let mut loop_interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            loop {
                match transport_snapshot_receiver.try_recv() {
                    Err(e) => match e {
                        TryRecvError::Empty => {
                            debug!("Nothing received for transport snapshot.");
                            break;
                        }
                        TryRecvError::Disconnected => {
                            debug!("Transport snapshot channel disconnected.")
                        }
                    },
                    Ok(transport_snapshot) => {
                        self.transport_infos
                            .entry(transport_snapshot.id.clone())
                            .and_modify(|transport_aggregate_info| {
                                transport_aggregate_info.status = transport_snapshot.status;
                                transport_aggregate_info.end_time = transport_snapshot.end_time;
                            })
                            .or_insert_with(|| TransportAggregateInfo {
                                id: transport_snapshot.id,
                                status: transport_snapshot.status,
                                start_time: transport_snapshot.start_time,
                                end_time: transport_snapshot.end_time,
                                user_token: transport_snapshot.user_token,
                                agent_remote_address: transport_snapshot.agent_remote_address,
                                source_address: transport_snapshot.source_address,
                                target_address: transport_snapshot.target_address,
                                traffic: HashMap::new(),
                            });
                    }
                }
            }
            loop {
                match transport_traffic_receiver.try_recv() {
                    Err(e) => match e {
                        TryRecvError::Empty => {
                            debug!("Nothing received for transport traffic.");
                            break;
                        }
                        TryRecvError::Disconnected => {
                            debug!("Transport traffic channel disconnected.")
                        }
                    },
                    Ok(transport_traffic) => {
                        self.transport_infos
                            .entry(transport_traffic.transport_id.clone())
                            .and_modify(|transport_aggregate_info| {
                                transport_aggregate_info
                                    .traffic
                                    .entry(transport_traffic.traffic_type)
                                    .and_modify(|traffic_bytes| {
                                        *traffic_bytes += transport_traffic.bytes;
                                    })
                                    .or_insert(transport_traffic.bytes);
                            });
                    }
                }
            }

            if !self.transport_infos.is_empty() {
                println!("###########################################");
                let mut entries_to_display: Vec<_> = self.transport_infos.iter().collect();
                entries_to_display.sort_by(|a, b| {
                    let a_tuple = *a;
                    let b_tuple = *b;
                    match a_tuple.1.start_time.checked_sub(b_tuple.1.start_time) {
                        None => Ordering::Less,
                        Some(0) => Ordering::Equal,
                        _ => Ordering::Greater,
                    }
                });
                for v in entries_to_display {
                    println!("{:?}", v.1);
                }
                println!("###########################################");
            }
            let mut remove_keys: Vec<String> = vec![];
            self.transport_infos.values().for_each(|v| {
                if v.status == TransportStatus::Closed {
                    remove_keys.push(v.id.clone());
                }
            });
            remove_keys.iter().for_each(|k| {
                self.transport_infos.remove(k);
            });
            loop_interval.tick().await;
        }
    }
}
